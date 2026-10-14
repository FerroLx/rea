import { createHash } from "node:crypto";

import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type {
  DexDebugMetadataExecution,
  DexDebugMetadataPort,
} from "../application/dex/DexDebugMetadataPort.js";
import type { ArtifactEntry } from "../artifacts/ArtifactReader.js";
import {
  looksLikeZip,
  normalizeArchiveMemberPath,
  readArchiveMember,
} from "../artifacts/archiveMember.js";
import { hashStableRootArtifactHandle } from "../artifacts/inventory/hashStableRootArtifact.js";
import {
  peekArtifactMagic,
  readStableArtifact,
} from "../artifacts/readStableArtifact.js";
import { ZipArtifactReader } from "../artifacts/ZipArtifactReader.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import {
  assembleClassDetail,
  summarizeDex,
} from "../domain/dex/dexDebugMetadata.js";
import {
  buildDexClassDetailResult,
  buildDexSummaryResult,
  type DexDebugMetadataResult,
  type DexSummaryMember,
  type InspectDexDebugMetadataInput,
} from "../domain/dex/dexDebugMetadataReport.js";
import { parseDexFile, type DexFile } from "../domain/dex/dexFile.js";
import { err, ok, type Result } from "../domain/result.js";
import { zipPackageFormatForPath } from "../domain/zipPackageFormat.js";
import { openRegularFile } from "../filesystem/RegularFile.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { dexFileFailure, mapDexParseError } from "./dexFailures.js";
import { dexMemberOrder, isRootDexMember } from "./dexEntry.js";
import { DEX_LIMITS, DEX_PROVIDER_IDENTITY } from "./DexFileRelease.js";

const OPERATION = "inspect_dex_debug_metadata";

const sha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

/** A selected DEX member that has been read and framed. */
interface DecodedMember {
  readonly entry: string | null;
  readonly sha256: string;
  readonly bytes: number;
  readonly buffer: Uint8Array;
  readonly dex: DexFile;
}

const execution = (
  result: DexDebugMetadataResult,
  path: string,
  subjectSha256: string,
  format: "file" | "apk" | "zip",
): DexDebugMetadataExecution =>
  createAnalysisExecution(result, DEX_PROVIDER_IDENTITY, {
    subject: { path, format, sha256: subjectSha256 },
    locations: [{ kind: "artifact-path", path }],
    limitations: result.limitations,
  });

/** Read exactly the selected DEX bytes and report compiler-emitted debug metadata. */
export class DexFileProvider implements DexDebugMetadataPort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectDexDebugMetadataInput,
    options?: ExecutionOptions,
  ): Promise<Result<DexDebugMetadataExecution, AnalysisError>> {
    try {
      if (options?.signal?.aborted)
        return err(new AnalysisCancelledError(OPERATION));
      if (input.entry !== undefined)
        return await this.#inspectArchive(input.path, input, options);
      const magic = await peekArtifactMagic(input.path, 8, options?.signal);
      return looksLikeZip(magic)
        ? await this.#inspectArchive(input.path, input, options)
        : await this.#inspectLooseDex(input.path, input, options);
    } catch (cause: unknown) {
      return err(dexFileFailure(cause, input.path));
    }
  }

  async #inspectLooseDex(
    path: string,
    input: InspectDexDebugMetadataInput,
    options?: ExecutionOptions,
  ): Promise<Result<DexDebugMetadataExecution, AnalysisError>> {
    const selected = await readStableArtifact(
      path,
      DEX_LIMITS.inputBytes,
      options?.signal,
    );
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const parsed = parseDexFile(selected.bytes);
    if (!parsed.ok) return err(mapDexParseError(parsed.error, path));
    return this.#assemble(
      [
        {
          entry: null,
          sha256: selected.sha256,
          bytes: selected.bytes.length,
          buffer: selected.bytes,
          dex: parsed.value,
        },
      ],
      input,
      {
        artifact: {
          path,
          sha256: selected.sha256,
          bytes: selected.bytes.length,
        },
        container: "dex-file",
        format: "file",
      },
    );
  }

  async #inspectArchive(
    path: string,
    input: InspectDexDebugMetadataInput,
    options?: ExecutionOptions,
  ): Promise<Result<DexDebugMetadataExecution, AnalysisError>> {
    const handle = await openRegularFile(path, {
      symlinks: "reject",
      signal: options?.signal,
    });
    const owner = new OwnedFileHandle(handle);
    try {
      const initial = await handle.stat();
      if (initial.size > DEX_LIMITS.archiveBytes)
        return err(
          new AnalysisResourceConstraintError(
            OPERATION,
            "file-size",
            `Selected archive exceeds ${String(DEX_LIMITS.archiveBytes)} bytes: ${path}`,
            { maximum_archive_bytes: DEX_LIMITS.archiveBytes },
          ),
        );
      const zipFormat = zipPackageFormatForPath(path) ?? "zip";
      const reader = new ZipArtifactReader(
        path,
        zipFormat,
        DEX_LIMITS.archiveMetadataBytes,
        { handle, initial },
      );
      try {
        const selected = await this.#selectDexMembers(
          reader,
          input.entry,
          path,
          options?.signal,
        );
        if (!selected.ok) return err(selected.error);
        const decoded = await this.#readMembers(
          reader,
          selected.value,
          path,
          options?.signal,
        );
        if (!decoded.ok) return err(decoded.error);
        const digest = await hashStableRootArtifactHandle(
          path,
          handle,
          initial,
          options?.signal,
        );
        const format = zipFormat === "apk" ? "apk" : "zip";
        return this.#assemble(decoded.value, input, {
          artifact: { path, sha256: digest.sha256, bytes: digest.bytes },
          container: format,
          format,
        });
      } finally {
        await reader.close();
      }
    } finally {
      await owner.close();
    }
  }

  /** Choose the archive's DEX members: the explicit entry, or every root classes*.dex. */
  async #selectDexMembers(
    reader: ZipArtifactReader,
    entry: string | undefined,
    path: string,
    signal: AbortSignal | undefined,
  ): Promise<
    Result<{ entry: string; member: ArtifactEntry }[], AnalysisError>
  > {
    const requested =
      entry === undefined ? undefined : normalizeArchiveMemberPath(entry);
    const matches: { entry: string; member: ArtifactEntry }[] = [];
    for await (const member of reader.entries(signal)) {
      if (member.kind !== "file") continue;
      if (requested !== undefined) {
        if (member.path === requested)
          matches.push({ entry: member.path, member });
      } else if (isRootDexMember(member.path) && !member.encrypted) {
        matches.push({ entry: member.path, member });
      }
    }
    if (requested !== undefined)
      return this.#resolveRequested(matches, requested, path);
    if (matches.length === 0)
      return err(
        this.#inputError(
          "entry",
          `${path} holds no root classes*.dex member; select a .dex with entry.`,
        ),
      );
    if (matches.length > DEX_LIMITS.maxDexMembers)
      return err(
        new AnalysisResourceConstraintError(
          OPERATION,
          "capacity",
          `${path} holds ${String(matches.length)} dex members, over the ${String(DEX_LIMITS.maxDexMembers)} limit; select one with entry.`,
          { maximum_dex_members: DEX_LIMITS.maxDexMembers },
        ),
      );
    matches.sort((a, b) => dexMemberOrder(a.entry) - dexMemberOrder(b.entry));
    return ok(matches);
  }

  #resolveRequested(
    matches: readonly { entry: string; member: ArtifactEntry }[],
    requested: string,
    path: string,
  ): Result<{ entry: string; member: ArtifactEntry }[], AnalysisError> {
    if (matches.length === 0)
      return err(
        this.#inputError("entry", `No member ${requested} exists in ${path}.`),
      );
    if (matches.length > 1)
      return err(
        this.#inputError(
          "entry",
          `${path} holds ${String(matches.length)} members named ${requested}; the identity is ambiguous.`,
        ),
      );
    const only = matches[0]!;
    if (only.member.encrypted)
      return err(
        new AnalysisUnsupportedTargetError(
          OPERATION,
          path,
          `The selected member ${requested} is encrypted and cannot be read without a key; unavailable, not absent.`,
        ),
      );
    return ok([only]);
  }

  async #readMembers(
    reader: ZipArtifactReader,
    members: readonly { entry: string; member: ArtifactEntry }[],
    path: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<DecodedMember[], AnalysisError>> {
    const decoded: DecodedMember[] = [];
    for (const { entry, member } of members) {
      if (signal?.aborted) return err(new AnalysisCancelledError(OPERATION));
      const buffer = await readArchiveMember(
        reader,
        member,
        DEX_LIMITS.inputBytes,
        signal,
      );
      const parsed = parseDexFile(buffer);
      if (!parsed.ok)
        return err(mapDexParseError(parsed.error, `${path}!${entry}`));
      decoded.push({
        entry,
        sha256: sha256(buffer),
        bytes: buffer.length,
        buffer,
        dex: parsed.value,
      });
    }
    return ok(decoded);
  }

  /** Decide summary vs class-detail over the decoded members and build the result. */
  #assemble(
    members: readonly DecodedMember[],
    input: InspectDexDebugMetadataInput,
    context: {
      readonly artifact: { path: string; sha256: string; bytes: number };
      readonly container: DexDebugMetadataResult["container"];
      readonly format: "file" | "apk" | "zip";
    },
  ): Result<DexDebugMetadataExecution, AnalysisError> {
    const { artifact, container, format } = context;
    const result: Result<DexDebugMetadataResult, AnalysisError> =
      input.class_descriptor === undefined
        ? ok(
            buildDexSummaryResult(
              artifact,
              container,
              this.#summaries(members),
            ),
          )
        : this.#classDetail(
            members,
            input.class_descriptor,
            artifact,
            container,
          );
    if (!result.ok) return result;
    const tooLarge = this.#rejectIfOversized(result.value, artifact.path);
    if (tooLarge) return err(tooLarge);
    return ok(execution(result.value, artifact.path, artifact.sha256, format));
  }

  #summaries(members: readonly DecodedMember[]): DexSummaryMember[] {
    return members.map((m) => ({
      entry: m.entry,
      sha256: m.sha256,
      bytes: m.bytes,
      summary: summarizeDex(m.dex, m.buffer),
    }));
  }

  #classDetail(
    members: readonly DecodedMember[],
    descriptor: string,
    artifact: { path: string; sha256: string; bytes: number },
    container: DexDebugMetadataResult["container"],
  ): Result<DexDebugMetadataResult, AnalysisError> {
    const found = members.flatMap((m) => {
      const detail = assembleClassDetail(m.dex, m.buffer, descriptor);
      return detail === null ? [] : [{ entry: m.entry, detail }];
    });
    if (found.length === 0)
      return err(
        this.#inputError(
          "class_descriptor",
          `No class ${descriptor} exists in the selected DEX member(s).`,
        ),
      );
    if (found.length > 1)
      return err(
        this.#inputError(
          "class_descriptor",
          `Class ${descriptor} appears in ${String(found.length)} dex members; select one with entry.`,
        ),
      );
    return ok(buildDexClassDetailResult(artifact, container, found[0]!));
  }

  #rejectIfOversized(
    result: DexDebugMetadataResult,
    path: string,
  ): AnalysisResourceConstraintError | undefined {
    if (
      Buffer.byteLength(JSON.stringify(result), "utf8") <=
      DEX_LIMITS.outputBytes
    )
      return undefined;
    return new AnalysisResourceConstraintError(
      OPERATION,
      "transport",
      `Decoded DEX detail for ${path} exceeds the inline output budget; select a narrower class.`,
      { maximum_output_bytes: DEX_LIMITS.outputBytes },
    );
  }

  #inputError(
    field: "entry" | "class_descriptor",
    message: string,
  ): AnalysisInputError {
    return new AnalysisInputError(OPERATION, undefined, [
      { path: [field], reason: "invalid_value", message },
    ]);
  }
}
