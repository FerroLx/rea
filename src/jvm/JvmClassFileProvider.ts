import { createHash } from "node:crypto";
import {
  completedJarInspection,
  finishJarInspection,
  JarInspection,
  type JarRequest,
} from "./jarInspection.js";

import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type {
  JvmDebugMetadataExecution,
  JvmDebugMetadataPort,
} from "../application/jvm/JvmDebugMetadataPort.js";
import {
  ArtifactReaderFailure,
  type ArtifactEntry,
} from "../artifacts/ArtifactReader.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ZipArtifactReader } from "../artifacts/ZipArtifactReader.js";
import type { StableRegularFileDescriptor } from "../filesystem/RegularFile.js";
import {
  peekArtifactMagic,
  readStableArtifact,
} from "../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import { parseJavaClassFile } from "../domain/jvm/javaClassFile.js";
import { projectDebugOutput } from "../domain/jvm/javaDebugMetadata.js";
import {
  buildJavaDebugMetadataResult,
  normalizeJarEntryPath,
  type InspectJvmDebugMetadataInput,
  type JavaDebugMetadataResult,
} from "../domain/jvm/javaDebugMetadataReport.js";
import { err, ok, type Result } from "../domain/result.js";
import { hashStableRootArtifactHandle } from "../artifacts/inventory/hashStableRootArtifact.js";
import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import {
  assertArtifactReadActive,
  bindArtifactFileCleanup,
  withArtifactRegularFile,
} from "../artifacts/ArtifactFileOperation.js";
import {
  classifyJarEntry,
  parseVersionedJarEntry,
  resolveJarSelection,
} from "./jarClassEntry.js";
import {
  isJarManifestName,
  isMultiReleaseManifest,
  JDK_DEFAULT_MAX_MANIFEST_BYTES,
} from "./jarManifest.js";
import { JVM_LIMITS, JVM_PROVIDER_IDENTITY } from "./JvmClassFileRelease.js";
import {
  jvmClassFileFailure,
  jvmCleanupError,
  mapParseError,
} from "./jvmFailures.js";

const OPERATION = "inspect_jvm_debug_metadata";

const sha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

/** Local-file-header, empty-archive, and spanned signatures all open with "PK". */
const looksLikeZip = (bytes: Uint8Array): boolean =>
  bytes.length >= 2 && bytes[0] === 0x50 && bytes[1] === 0x4b;

/** The smallest class-file major version (JDK 1.1); nothing valid is lower. */
const MIN_CLASS_MAJOR_VERSION = 45;

/**
 * 0xCAFEBABE is both the class-file magic and the Mach-O universal (fat) magic.
 * A fat header's bytes 4-7 are `nfat_arch` (a small count), so a u2 at offset 6
 * below the smallest class major version means this is a Mach-O universal
 * binary, not a class file.
 */
const looksLikeMachOUniversal = (bytes: Uint8Array): boolean =>
  bytes.length >= 8 &&
  bytes[0] === 0xca &&
  bytes[1] === 0xfe &&
  bytes[2] === 0xba &&
  bytes[3] === 0xbe &&
  ((bytes[6]! << 8) | bytes[7]!) < MIN_CLASS_MAJOR_VERSION;

const execution = (
  result: JavaDebugMetadataResult,
  path: string,
  subjectSha256: string,
  format: "file" | "zip",
): JvmDebugMetadataExecution =>
  createAnalysisExecution(result, JVM_PROVIDER_IDENTITY, {
    subject: { path, format, sha256: subjectSha256 },
    locations: [{ kind: "artifact-path", path }],
    limitations: result.limitations,
  });

/** Read exactly the selected class-file bytes and decode compiler-emitted debug metadata. */
export class JvmClassFileProvider implements JvmDebugMetadataPort {
  /** Handles whose close failed stay owned here and are retried by `close()`. */
  readonly #resources = new ArtifactResourceScope();

  /**
   * Retry retained cleanup without discarding owners that still cannot close.
   * A retained-owner failure becomes a ProviderCleanupError bound to those
   * exact leases, so it resolves once a later close() releases them; any other
   * failure is not a cleanup fact and propagates unchanged.
   */
  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      if (
        !(cause instanceof ArtifactReaderFailure) ||
        cause.cleanup === undefined
      )
        throw cause;
      const error = jvmCleanupError(cause.cleanup, cause);
      bindArtifactFileCleanup(cause, error);
      throw error;
    }
  }

  async inspect(
    input: InspectJvmDebugMetadataInput,
    options?: ExecutionOptions,
  ): Promise<Result<JvmDebugMetadataExecution, AnalysisError>> {
    try {
      if (options?.signal?.aborted)
        return err(
          new AnalysisCancelledError(OPERATION, {
            cause: options.signal.reason,
          }),
        );
      return await this.#resources.run(() =>
        input.entry === undefined
          ? this.#inspectClassFile(input, options)
          : this.#inspectJarEntry({
              jar: input.path,
              entry: normalizeJarEntryPath(input.entry),
              input,
              signal: options?.signal,
            }),
      );
    } catch (cause: unknown) {
      return err(jvmClassFileFailure(cause, input.path, options?.signal));
    }
  }

  async #inspectClassFile(
    input: InspectJvmDebugMetadataInput,
    options?: ExecutionOptions,
  ): Promise<Result<JvmDebugMetadataExecution, AnalysisError>> {
    // Classify by magic before admitting the whole file under the class-file
    // byte budget: an archive (most APKs/JARs exceed that budget) must be
    // steered to `entry` selection, not rejected as oversized or "not a class
    // file". The peek reads only the leading bytes, regardless of total size.
    const magic = await peekArtifactMagic(
      input.path,
      8,
      options?.signal,
      undefined,
      this.#resources,
    );
    if (looksLikeZip(magic))
      return err(
        new AnalysisUnsupportedTargetError(
          OPERATION,
          input.path,
          "The selected file is a ZIP/JAR archive, not a single .class file.",
          {
            remediationAction:
              "Pass entry to select a class member inside the JAR, e.g. entry=com/example/Foo.class (and release for a multi-release override).",
          },
        ),
      );
    if (looksLikeMachOUniversal(magic))
      return err(
        new AnalysisUnsupportedTargetError(
          OPERATION,
          input.path,
          "The selected file begins with 0xCAFEBABE but its version is too small for a class file; this is a Mach-O universal (fat) binary.",
          {
            remediationAction:
              "Use inspect_macho for Mach-O binaries; this tool reads JVM .class files.",
          },
        ),
      );
    const selected = await readStableArtifact(
      input.path,
      JVM_LIMITS.inputBytes,
      options?.signal,
      undefined,
      this.#resources,
    );
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(OPERATION, { cause: options.signal.reason }),
      );
    const parsed = parseJavaClassFile(selected.bytes, {
      retainedAttributeBudget: JVM_LIMITS.maxDebugEntries,
    });
    if (!parsed.ok) return err(mapParseError(parsed.error, input.path));
    const tooMany = this.#rejectIfTooManyEntries(parsed.value, input.path, [
      input.path,
    ]);
    if (tooMany) return err(tooMany);
    const result = buildJavaDebugMetadataResult(parsed.value, {
      path: input.path,
      sha256: selected.sha256,
      bytes: selected.bytes.length,
    });
    const tooLarge = this.#rejectIfOversized(result, input.path);
    if (tooLarge) return err(tooLarge);
    return ok(execution(result, input.path, selected.sha256, "file"));
  }

  /**
   * Admit the JAR once (no-follow) through the shared descriptor owner, so
   * admission, the final close, failed-close retention and late cancellation
   * all flow through one typed outcome. The member reads and the archive digest
   * use that same descriptor, so the Evidence sha256 identifies exactly the
   * bytes a member was read from.
   */
  async #inspectJarEntry(
    request: JarRequest,
  ): Promise<Result<JvmDebugMetadataExecution, AnalysisError>> {
    let inspection: JarInspection;
    try {
      inspection = await withArtifactRegularFile(
        request.jar,
        this.#resources,
        request.signal,
        (source) => this.#readJar(source, request),
        "reject",
      );
    } catch (cause: unknown) {
      const completed = completedJarInspection(cause);
      if (completed === undefined) throw cause;
      return finishJarInspection(request, completed, cause);
    }
    return finishJarInspection(request, inspection, undefined);
  }

  /**
   * Read one member under the admitted descriptor. Every outcome, including a
   * thrown read failure, becomes this inspection's result so the descriptor
   * close can never replace it; the ZIP reader is released through a lease the
   * provider scope retains if its close fails.
   */
  async #readJar(
    source: StableRegularFileDescriptor,
    request: JarRequest,
  ): Promise<JarInspection> {
    const { jar, signal } = request;
    const { initial } = source;
    if (initial.size > JVM_LIMITS.archiveBytes)
      return new JarInspection(
        err(
          new AnalysisResourceConstraintError(
            OPERATION,
            "file-size",
            `Selected JAR exceeds ${String(JVM_LIMITS.archiveBytes)} bytes: ${jar}`,
            { maximum_archive_bytes: JVM_LIMITS.archiveBytes },
          ),
        ),
      );
    const reader = new ZipArtifactReader(
      jar,
      "zip",
      JVM_LIMITS.archiveMetadataBytes,
      source,
      {
        // Name members as JarFile names them (UTF-8), and refuse the archive
        // wherever JarFile refuses to open it (an invalid name, or any
        // encrypted record), whichever member is requested.
        view: "jdk",
        // Only the manifest and the selected class are decompressed, so only
        // they are charged; an unrelated large member cannot refuse the read.
        expansion: "opened",
      },
    );
    const readerLease = new AnalysisCleanupLease(() => reader.close());
    let result: Result<JvmDebugMetadataExecution, AnalysisError>;
    try {
      result = await this.#readJarMember(request, reader, source);
    } catch (cause: unknown) {
      result = err(jvmClassFileFailure(cause, jar, signal));
    }
    const released = await this.#resources.release({
      kind: "lease",
      resource: jar,
      lease: readerLease,
    });
    return new JarInspection(
      result,
      released.kind === "released"
        ? undefined
        : { cause: released.cause, lease: readerLease },
    );
  }

  async #readJarMember(
    { jar, entry, input, signal }: JarRequest,
    reader: ZipArtifactReader,
    { handle, initial }: StableRegularFileDescriptor,
  ): Promise<Result<JvmDebugMetadataExecution, AnalysisError>> {
    const selected = await this.#selectJarMember(reader, {
      jar,
      entry,
      input,
      signal,
    });
    if (!selected.ok) return selected;
    assertArtifactReadActive(signal);
    const classBytes = await this.#readEntryBytes(
      reader,
      selected.value.member,
      signal,
    );
    const parsed = parseJavaClassFile(classBytes, {
      retainedAttributeBudget: JVM_LIMITS.maxDebugEntries,
    });
    if (!parsed.ok) return err(mapParseError(parsed.error, jar));
    const tooMany = this.#rejectIfTooManyEntries(parsed.value, jar, [
      jar,
      entry,
    ]);
    if (tooMany) return err(tooMany);
    // Hash only after a member is selected and parsed: a refused call never
    // pays the full-archive (up to 512 MiB) digest.
    const jarDigest = await hashStableRootArtifactHandle(
      jar,
      handle,
      initial,
      signal,
    );
    const result = buildJavaDebugMetadataResult(
      parsed.value,
      { path: jar, sha256: jarDigest.sha256, bytes: jarDigest.bytes },
      {
        container: "jar",
        selectedEntry: {
          entry,
          release: selected.value.release,
          sha256: sha256(classBytes),
          bytes: classBytes.length,
        },
      },
    );
    // The ZIP reader owns member-name interpretation; keep its notes (e.g.
    // a Unicode Path name) and the manifest decision's notes visible.
    const withMemberNotes =
      selected.value.limitations.length === 0
        ? result
        : {
            ...result,
            limitations: [...result.limitations, ...selected.value.limitations],
          };
    const tooLarge = this.#rejectIfOversized(withMemberNotes, jar);
    if (tooLarge) return err(tooLarge);
    return ok(execution(withMemberNotes, jar, jarDigest.sha256, "zip"));
  }

  /**
   * Enumerate the archive once, honor the Multi-Release manifest, and resolve
   * the caller's entry/release to exactly one member — refusing an inert
   * versioned selection, an absent release, or an ambiguous duplicate.
   */
  async #selectJarMember(
    reader: ZipArtifactReader,
    { jar, entry, input, signal }: JarRequest,
  ): Promise<
    Result<
      {
        readonly member: ArtifactEntry;
        readonly release: number | null;
        /** Reader notes on the member and any note on the manifest decision. */
        readonly limitations: readonly string[];
      },
      AnalysisError
    >
  > {
    const requestedRelease = input.release;
    let manifestEntry: ArtifactEntry | undefined;
    const byRelease = new Map<number | null, ArtifactEntry[]>();
    for await (const member of reader.entries(signal)) {
      // The JDK finds members by stored name and ignores external attributes,
      // so every kind is matched here; an unreadable match (a symlink the
      // reader does not read) is reported as such, never absent. The JDK view
      // has already refused an archive holding any encrypted record.
      // The manifest matches in any ASCII case and the last such member wins;
      // a `./`-prefixed name is not the manifest.
      if (isJarManifestName(member.storedPath ?? member.path)) {
        manifestEntry = member;
        continue;
      }
      // Class entries match on the stored name too: a `./`-prefixed member is
      // an inert resource for the JDK, never the entry or its override.
      const candidate = classifyJarEntry(
        member.storedPath ?? member.path,
        entry,
      );
      if (candidate === undefined) continue;
      const members = byRelease.get(candidate.release) ?? [];
      members.push(member);
      byRelease.set(candidate.release, members);
    }
    // The full stored-name scan found no member for the entry at any
    // release, so no manifest can make one selectable: the entry is
    // definitely absent, even when the manifest itself is unreadable.
    if (byRelease.size === 0)
      return err(
        this.#selectionError(
          { reason: "not-found", available: [] },
          jar,
          entry,
          requestedRelease,
        ),
      );
    // Without a requested release, a present base entry is selected whatever
    // the manifest says, so an unreadable manifest must not block it. A
    // versioned spelling of the entry needs it to know what the member means.
    const versionedEntry = parseVersionedJarEntry(entry);
    const needsManifest =
      requestedRelease !== undefined ||
      !byRelease.has(null) ||
      versionedEntry !== undefined;
    const manifest = needsManifest
      ? await this.#readManifest(reader, manifestEntry, signal)
      : ({ kind: "not-read" } as const);
    if (manifest.kind === "unknown")
      return err(
        new AnalysisUnsupportedTargetError(
          OPERATION,
          jar,
          `${manifest.reason}; REA cannot read it, so whether ${jar} is a multi-release JAR is unknown and its META-INF/versions entries cannot be resolved.`,
        ),
      );
    const multiRelease = manifest.kind === "multi-release";
    const manifestNotes =
      manifest.kind === "not-multi-release" && manifest.note !== undefined
        ? [manifest.note]
        : [];
    if (!multiRelease && requestedRelease !== undefined)
      return err(
        this.#inputError(
          "release",
          `${jar} is not a multi-release JAR (${manifestNotes[0] ?? "no Multi-Release: true manifest attribute"}); META-INF/versions entries are inert, so only the base entry is selectable.`,
        ),
      );
    // In a multi-release JAR a META-INF/versions/<N>/ member is the release-N
    // override of its base entry; reading it as the base would report
    // release null for version-N bytes, so one identity form is required.
    if (multiRelease && versionedEntry !== undefined)
      return err(
        this.#inputError(
          "entry",
          `${entry} is the multi-release version ${String(versionedEntry.release)} override in ${jar}; select it as entry=${versionedEntry.entry} with release=${String(versionedEntry.release)}.`,
        ),
      );
    // Outside a multi-release JAR, versioned entries never load; drop them.
    const effective = new Map<number | null, ArtifactEntry[]>();
    if (multiRelease) for (const [r, m] of byRelease) effective.set(r, m);
    else {
      const base = byRelease.get(null);
      if (base !== undefined) effective.set(null, base);
    }
    const candidates = [...effective.entries()].map(([release, members]) => ({
      release,
      path: members[0]!.storedPath ?? members[0]!.path,
    }));
    const selection = resolveJarSelection(candidates, requestedRelease);
    if (!selection.ok)
      return err(this.#selectionError(selection, jar, entry, requestedRelease));
    const selectedMembers = effective.get(selection.release) ?? [];
    if (selectedMembers.length !== 1)
      return err(
        this.#inputError(
          "entry",
          `${jar} holds ${String(selectedMembers.length)} members at the selected entry and release; the identity is ambiguous, so no member is chosen.`,
        ),
      );
    const member = selectedMembers[0]!;
    if (member.kind !== "file")
      return err(
        new AnalysisUnsupportedTargetError(
          OPERATION,
          jar,
          `The selected entry ${entry} is stored as a ZIP ${member.kind}, which REA does not read as member bytes; its debug metadata is unavailable, not absent.`,
        ),
      );
    return ok({
      member,
      release: selection.release,
      limitations: [...member.limitations, ...manifestNotes],
    });
  }

  /**
   * Decide the JDK's multi-release status from the last manifest member. A
   * manifest REA cannot read leaves that status unknown, never false.
   */
  async #readManifest(
    reader: ZipArtifactReader,
    manifest: ArtifactEntry | undefined,
    signal: AbortSignal | undefined,
  ): Promise<
    | { readonly kind: "multi-release" }
    | { readonly kind: "not-multi-release"; readonly note?: string }
    | { readonly kind: "unknown"; readonly reason: string }
  > {
    if (manifest === undefined) return { kind: "not-multi-release" };
    const name = JSON.stringify(manifest.storedPath ?? manifest.path);
    if (manifest.kind !== "file")
      return {
        kind: "unknown",
        reason: `The JAR manifest member ${name} is stored as a ZIP ${manifest.kind}, which the JDK reads as a file but REA does not read`,
      };
    if (
      manifest.declaredSize !== null &&
      manifest.declaredSize > JDK_DEFAULT_MAX_MANIFEST_BYTES
    )
      return {
        kind: "not-multi-release",
        note: `the JAR manifest ${name} declares ${String(manifest.declaredSize)} bytes, over the JDK's default jdk.jar.maxSignatureFileSize of ${String(JDK_DEFAULT_MAX_MANIFEST_BYTES)} bytes, so JarFile.isMultiRelease() is false at default settings`,
      };
    return {
      kind: isMultiReleaseManifest(
        await this.#readEntryBytes(reader, manifest, signal),
      )
        ? "multi-release"
        : "not-multi-release",
    };
  }

  #inputError(field: "entry" | "release", message: string): AnalysisInputError {
    return new AnalysisInputError(OPERATION, undefined, [
      { path: [field], reason: "invalid_value", message },
    ]);
  }

  /** Buffer one archive member, bounded by the class-file input budget. */
  async #readEntryBytes(
    reader: ZipArtifactReader,
    member: ArtifactEntry,
    signal: AbortSignal | undefined,
  ): Promise<Uint8Array> {
    const stream = await reader.open(member, signal);
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of stream) {
      if (signal?.aborted) {
        stream.destroy();
        throw new ArtifactReaderFailure("cancelled", "JAR read cancelled", {
          cause: signal.reason,
        });
      }
      if (!Buffer.isBuffer(chunk)) {
        stream.destroy();
        throw new ArtifactReaderFailure(
          "format",
          "JAR entry did not yield bytes",
        );
      }
      size += chunk.length;
      if (size > JVM_LIMITS.inputBytes) {
        stream.destroy();
        throw new ArtifactReaderFailure(
          "limit",
          `Selected class entry exceeds ${String(JVM_LIMITS.inputBytes)} bytes`,
          {
            boundary: "file-size",
            limit: { key: "max_input_bytes", maximum: JVM_LIMITS.inputBytes },
          },
        );
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks, size);
  }

  /**
   * Refuse before building the report, ahead of the (potentially ~50x)
   * expansion into entry objects: too many projected objects, too many
   * debug-relevant attributes, or a projected serialization (counting every
   * repeated constant-pool string) past the inline output budget. The
   * pre-count reads only table headers and allocates nothing.
   */
  #rejectIfTooManyEntries(
    classFile: Parameters<typeof projectDebugOutput>[0],
    path: string,
    echoed: readonly string[],
  ): AnalysisResourceConstraintError | undefined {
    const projection = projectDebugOutput(
      classFile,
      JVM_LIMITS.maxDebugEntries,
      {
        entries: JVM_LIMITS.maxDebugEntries,
        encodedBytes: JVM_LIMITS.outputBytes,
      },
    );
    if (projection.attributeBudgetExceeded)
      return new AnalysisResourceConstraintError(
        OPERATION,
        "capacity",
        `${path} declares more than ${String(JVM_LIMITS.maxDebugEntries)} debug-relevant attributes; refused before materialising them.`,
        { max_retained_attributes: JVM_LIMITS.maxDebugEntries },
      );
    if (projection.entries > JVM_LIMITS.maxDebugEntries)
      return new AnalysisResourceConstraintError(
        OPERATION,
        "memory",
        `${path} declares ${String(projection.entries)} debug-table entries, over the ${String(JVM_LIMITS.maxDebugEntries)} limit; refused before allocation.`,
        { maximum_debug_entries: JVM_LIMITS.maxDebugEntries },
      );
    // Caller-selected strings (path, entry name) are echoed verbatim too.
    const encodedBytes = echoed.reduce(
      (total, value) => total + Buffer.byteLength(JSON.stringify(value)),
      projection.encodedBytes,
    );
    if (encodedBytes > JVM_LIMITS.outputBytes)
      return new AnalysisResourceConstraintError(
        OPERATION,
        "capacity",
        `${path} would project to about ${String(encodedBytes)} bytes of debug metadata, over the ${String(JVM_LIMITS.outputBytes)}-byte output budget; refused before building it.`,
        { maximum_output_bytes: JVM_LIMITS.outputBytes },
      );
    return undefined;
  }

  #rejectIfOversized(
    result: JavaDebugMetadataResult,
    path: string,
  ): AnalysisResourceConstraintError | undefined {
    // Input bounds do not bound the projected result; a crafted class can
    // declare millions of table entries. Refuse past the inline output budget
    // instead of emitting oversized Evidence (mirrors the Go/Rust readers).
    if (
      Buffer.byteLength(JSON.stringify(result), "utf8") <=
      JVM_LIMITS.outputBytes
    )
      return undefined;
    return new AnalysisResourceConstraintError(
      OPERATION,
      "transport",
      `Decoded debug metadata for ${path} exceeds the inline output budget; no partial success is returned.`,
      { maximum_output_bytes: JVM_LIMITS.outputBytes },
    );
  }

  #selectionError(
    selection: {
      readonly reason: "not-found" | "release-absent";
      readonly available: readonly number[];
    },
    jar: string,
    entry: string,
    requestedRelease: number | undefined,
  ): AnalysisInputError {
    const versions =
      selection.available.length === 0
        ? "none (base only)"
        : selection.available.join(", ");
    const message =
      selection.reason === "not-found"
        ? `No class entry ${entry} exists in ${jar}.`
        : requestedRelease === undefined
          ? `${jar} has no base entry ${entry}; it exists only as multi-release overrides, so a release is required. Available versions: ${versions}.`
          : `Entry ${entry} is not available for release ${String(requestedRelease)} in ${jar}; available multi-release versions: ${versions}.`;
    return new AnalysisInputError(OPERATION, undefined, [
      {
        path: [selection.reason === "not-found" ? "entry" : "release"],
        reason: "invalid_value",
        message,
      },
    ]);
  }
}
