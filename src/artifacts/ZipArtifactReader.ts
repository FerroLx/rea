import { assertArtifactReadActive } from "./ArtifactFileOperation.js";
import type { FileHandle } from "node:fs/promises";
import { PassThrough, type Readable } from "node:stream";
import { once } from "node:events";

import {
  ERR_AMBIGUOUS_ARCHIVE,
  ERR_BAD_FORMAT,
  ERR_CENTRAL_DIRECTORY_NOT_FOUND,
  ERR_ENCRYPTED_CENTRAL_DIRECTORY,
  ERR_ENTRY_DATA_OUT_OF_BOUNDS,
  ERR_EOCDR_LOCATOR_ZIP64_NOT_FOUND,
  ERR_EOCDR_NOT_FOUND,
  ERR_EXTRAFIELD_ZIP64_NOT_FOUND,
  ERR_INVALID_COMPRESSED_DATA,
  ERR_INVALID_CRC32,
  ERR_INVALID_UNCOMPRESSED_SIZE,
  ERR_LOCAL_FILE_HEADER_NOT_FOUND,
  ERR_OVERLAPPING_ENTRY,
  ERR_SPLIT_ZIP_FILE,
  ERR_UNSUPPORTED_COMPRESSION,
  ERR_UNSUPPORTED_ENCRYPTION,
  ERR_UNSUPPORTED_UINT64,
  Reader,
  WARNING_TRAILING_CENTRAL_DIRECTORY_DATA,
  ZipReader,
  type Entry,
  type FileEntry,
} from "@zip.js/zip.js";

import {
  ArtifactReaderFailure,
  copyArtifactEntry,
  sameArtifactEntry,
  type ArtifactEntry,
  type ArtifactReader,
} from "./ArtifactReader.js";
import type { ZipPackageFormat } from "../domain/zipPackageFormat.js";
import { jdkCentralDirectoryRefusal } from "./JdkZipCentralDirectory.js";
import {
  ARTIFACT_EXPANSION_RATIO,
  artifactExpansionBudgetBytes,
  MINIMUM_ARTIFACT_EXPANDED_BYTES,
} from "../domain/artifactExpansionBudget.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import {
  NonRegularFileReadError,
  RegularFileAdmissionFailure,
  openRegularFile,
  sameRegularFileState,
  type StableRegularFileDescriptor,
} from "../filesystem/RegularFile.js";

const ZIP_UTF8_DECODER = new TextDecoder("utf-8", {
  fatal: true,
  ignoreBOM: true,
});

class NodeFileReader extends Reader<string> {
  #handle: FileHandle | undefined;
  #owner: OwnedFileHandle | undefined;
  #initPromise: Promise<void> | undefined;
  readonly #ownsHandle: boolean;

  constructor(
    private readonly path: string,
    private readonly maximumReadBytes?: number,
    private readonly admitted?: StableRegularFileDescriptor,
  ) {
    super(path);
    this.#ownsHandle = admitted === undefined;
  }

  override init(): Promise<void> {
    this.#initPromise ??= this.#initialize();
    return this.#initPromise;
  }

  async #initialize(): Promise<void> {
    let source: StableRegularFileDescriptor;
    try {
      source =
        this.admitted ??
        (await openRegularFile(this.path, { symlinks: "reject" }));
      this.#handle = source.handle;
      if (this.#ownsHandle) this.#owner = new OwnedFileHandle(source.handle);
    } catch (cause: unknown) {
      if (cause instanceof RegularFileAdmissionFailure) {
        this.#owner = cause.owner;
        const primary =
          cause.cause instanceof NonRegularFileReadError
            ? new ArtifactReaderFailure(
                "format",
                `ZIP source is not a regular file: ${this.path}`,
                { cause: cause.cause },
              )
            : cause.cause;
        throw ArtifactReaderFailure.withCleanup(
          primary,
          ArtifactReaderFailure.cleanupObservation(
            cause.cleanupCause,
            this.path,
          ),
        );
      }
      if (cause instanceof NonRegularFileReadError)
        throw new ArtifactReaderFailure(
          "format",
          `ZIP source is not a regular file: ${this.path}`,
          { cause },
        );
      throw cause;
    }
    if (this.admitted !== undefined) {
      const metadata = await source.handle.stat();
      if (!sameRegularFileState(source.initial, metadata))
        throw new ArtifactReaderFailure(
          "integrity",
          `ZIP source identity changed before reading: ${this.path}`,
        );
    }
    this.size = source.initial.size;
  }

  override async readUint8Array(
    index: number,
    length: number,
  ): Promise<Uint8Array> {
    const handle = this.#handle;
    if (handle === undefined) throw new Error("ZIP reader is not initialized");
    const readBytes = Math.min(length, this.size - index);
    // A central-directory offset can point past EOF. Type that malformed ZIP
    // read before a negative size reaches Buffer.alloc and becomes an I/O error.
    if (readBytes < 0)
      throw new ArtifactReaderFailure(
        "format",
        `ZIP archive is malformed: read at ${index} extends beyond the ${this.size}-byte archive`,
      );
    if (
      this.maximumReadBytes !== undefined &&
      readBytes > this.maximumReadBytes
    )
      throw new ArtifactReaderFailure(
        "limit",
        `ZIP metadata read requires ${readBytes} bytes, exceeding the ${this.maximumReadBytes}-byte read budget`,
        {
          boundary: "memory",
          limit: {
            key: "max_metadata_read_bytes",
            maximum: this.maximumReadBytes,
          },
        },
      );
    const bytes = Buffer.alloc(readBytes);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        offset,
        bytes.length - offset,
        index + offset,
      );
      if (bytesRead === 0)
        throw new ArtifactReaderFailure(
          "integrity",
          `ZIP source ended before its admitted extent: ${this.path}`,
        );
      offset += bytesRead;
    }
    return bytes;
  }

  async closeHandle(): Promise<void> {
    if (!this.#ownsHandle) return;
    await this.#initPromise?.catch(() => undefined);
    if (this.#owner === undefined) return;
    await this.#owner.close();
    this.#owner = undefined;
    this.#handle = undefined;
  }
}

/**
 * Whose reading of the archive this reader reproduces.
 * `zip-legacy` follows the ZIP specification: unflagged member names are CP437
 * (as Python's zipfile reads them) and an encrypted member is enumerated but
 * cannot be opened. `jdk` is OpenJDK 25's `ZipFile`/`JarFile` view at the
 * default charset, and fails enumeration as `format` wherever the JDK refuses
 * to open the whole archive for one central-directory record: every name and
 * entry comment is UTF-8 whatever the flag says, so one that is not valid
 * UTF-8 is refused ("invalid CEN header (bad entry name or comment)"), and so
 * is every other record `ZipFile.Source.checkAndAddEntry` rejects (see
 * {@link jdkCentralDirectoryRefusal}), whichever member it names. Checks the
 * JDK makes only on the local header or member data are not made here.
 */
export type ZipArchiveView = "zip-legacy" | "jdk";

/**
 * When declared plaintext is charged to the archive's decompression budget.
 * `enumerated` charges every readable member as it is listed, so a consumer
 * that reads every member learns the total before writing anything. `opened`
 * charges each member when it is opened, so a consumer that reads a few named
 * members is bounded by what it decompresses, not by unrelated members.
 */
export type ZipExpansionAccounting = "enumerated" | "opened";

export interface ZipArtifactReaderOptions {
  readonly view?: ZipArchiveView;
  readonly expansion?: ZipExpansionAccounting;
}

/** Lazy Zip64-capable reader with CRC and overlap verification on every read. */
export class ZipArtifactReader implements ArtifactReader {
  readonly format: ZipPackageFormat;
  readonly #view: ZipArchiveView;
  readonly #expansion: ZipExpansionAccounting;
  readonly #source: NodeFileReader;
  readonly #reader: ZipReader<string>;
  readonly #entries = new Map<
    string,
    { readonly source: Entry; readonly metadata: ArtifactEntry }
  >();
  /** Declared plaintext of the members opened so far, in `opened` accounting. */
  #openedBytes = 0;
  /** Optionally bound each metadata read before allocating its backing buffer. */
  constructor(
    path: string,
    format: ZipPackageFormat,
    maximumMetadataReadBytes?: number,
    admitted?: StableRegularFileDescriptor,
    {
      view = "zip-legacy",
      expansion = "enumerated",
    }: ZipArtifactReaderOptions = {},
  ) {
    this.format = format;
    this.#view = view;
    this.#expansion = expansion;
    this.#source = new NodeFileReader(path, maximumMetadataReadBytes, admitted);
    this.#reader = new ZipReader(this.#source, {
      checkSignature: true,
      checkOverlappingEntry: true,
      // Unflagged names use the ZIP legacy encoding (CP437); the UTF-8 flag
      // remains authoritative, and a validated Unicode Path extra field names
      // the logical path while `storedPath` keeps the raw central-directory name.
      filenameEncoding: "cp437",
      // REA applies its own provider-neutral path validation in scanReader and
      // must preserve that typed failure instead of zip.js rejecting first.
      filenameValidation: "tolerant",
    });
  }

  async *entries(signal?: AbortSignal): AsyncIterable<ArtifactEntry> {
    let index = 0;
    // A traversal owns its accounting, including overlapping or repeated passes.
    let declaredFileBytes = 0;
    for await (const entry of typedZipFailures(
      this.#reader.getEntriesGenerator({
        decodeText:
          this.#view === "jdk" ? decodeJdkEntryText : decodeZipEntryText,
      }),
    )) {
      assertArtifactReadActive(signal);
      // The JDK refuses the whole archive for one record it rejects, so no
      // member of it is enumerated in that view.
      const refusal =
        this.#view === "jdk" ? jdkCentralDirectoryRefusal(entry) : undefined;
      if (refusal !== undefined)
        throw new ArtifactReaderFailure(
          "format",
          `ZIP member ${JSON.stringify(entry.filename)} has a central-directory record the JDK rejects, so the JDK refuses to open the archive ("${refusal}")`,
        );
      // ZIP member identity is its directory occurrence, not its filename.
      // Logical path uniqueness belongs to the artifact inventory boundary.
      const metadata = projectZipEntry(entry, index++, this.#view);
      if (metadata === undefined) continue;
      if (this.#expansion === "enumerated" && chargeable(metadata)) {
        declaredFileBytes += metadata.declaredSize;
        this.#assertWithinExpansionBudget(declaredFileBytes, "entries declare");
      }
      const stored = this.#entries.get(metadata.adapterKey);
      if (stored !== undefined && !sameArtifactEntry(metadata, stored.metadata))
        throw new ArtifactReaderFailure(
          "integrity",
          `ZIP member identity changed during enumeration: ${entry.filename}`,
        );
      if (stored === undefined)
        this.#entries.set(metadata.adapterKey, {
          source: entry,
          metadata: copyArtifactEntry(metadata),
        });
      yield metadata;
    }
    // The JDK reads the central directory as whole records and refuses one
    // that runs past it, bytes left after the last record, or a digital
    // signature record there ("invalid CEN header (bad header size)"); zip.js
    // tolerates each, noting the first two as trailing directory data.
    if (
      this.#view === "jdk" &&
      (this.#reader.digitalSignature !== undefined ||
        (this.#reader.warnings ?? []).some(
          (warning) =>
            warning.reason === WARNING_TRAILING_CENTRAL_DIRECTORY_DATA,
        ))
    )
      throw new ArtifactReaderFailure(
        "format",
        `ZIP central directory does not end exactly at its last record, so the JDK refuses to open the archive ("invalid CEN header (bad header size)")`,
      );
  }

  open(entry: ArtifactEntry, signal?: AbortSignal): Promise<Readable> {
    assertArtifactReadActive(signal);
    const stored = this.#entries.get(entry.adapterKey);
    if (stored === undefined || !sameArtifactEntry(entry, stored.metadata))
      return Promise.reject(
        new ArtifactReaderFailure(
          "integrity",
          "ZIP entry metadata does not match this reader's inventory",
        ),
      );
    const source = stored.source;
    // zip.js types attribute-marked directories without `getData`, but attaches
    // it to every member; the projected kind decides what is a regular file.
    if (stored.metadata.kind !== "file" || !("getData" in source))
      return Promise.reject(
        new ArtifactReaderFailure("format", "ZIP entry is not a regular file"),
      );
    if (source.encrypted)
      return Promise.reject(
        new ArtifactReaderFailure(
          "unavailable",
          "Encrypted ZIP entry is unsupported",
        ),
      );
    if (this.#expansion === "opened") {
      // A size that is not a safe byte count cannot be bounded, so it is
      // charged as exceeding the budget rather than skipped.
      const declared = chargeable(stored.metadata)
        ? stored.metadata.declaredSize
        : Number.POSITIVE_INFINITY;
      try {
        this.#assertWithinExpansionBudget(
          this.#openedBytes + declared,
          "opened members declare",
        );
      } catch (cause: unknown) {
        return Promise.reject(cause as Error);
      }
      this.#openedBytes += declared;
    }
    return Promise.resolve(extractStream(source, signal));
  }

  /** zip.js enforces each member's declared output size, so this sum bounds streamed work. */
  #assertWithinExpansionBudget(declaredBytes: number, subject: string): void {
    const budget = artifactExpansionBudgetBytes(this.#source.size);
    if (declaredBytes <= budget) return;
    throw new ArtifactReaderFailure(
      "limit",
      `ZIP ${subject} ${String(declaredBytes)} uncompressed bytes, exceeding this archive's ${String(budget)}-byte decompression budget (${String(MINIMUM_ARTIFACT_EXPANDED_BYTES)}-byte minimum, ${String(ARTIFACT_EXPANSION_RATIO)}x archive size); a small archive cannot expand this far`,
      {
        boundary: "capacity",
        limit: { key: "max_decompressed_bytes", maximum: budget },
      },
    );
  }

  async close(): Promise<void> {
    // best-effort cleanup: zip-reader close must not mask prior extraction state.
    await this.#reader.close().catch(() => undefined);
    await this.#source.closeHandle();
  }

  provenance(): readonly [] {
    return [];
  }
}

/** A readable file member whose declared plaintext is a countable byte size. */
const chargeable = (
  metadata: ArtifactEntry,
): metadata is ArtifactEntry & { readonly declaredSize: number } =>
  metadata.kind === "file" &&
  !metadata.encrypted &&
  metadata.declaredSize !== null &&
  Number.isSafeInteger(metadata.declaredSize) &&
  metadata.declaredSize >= 0;

const projectZipEntry = (
  entry: Entry,
  index: number,
  view: ZipArchiveView,
): ArtifactEntry | undefined => {
  const storedName = zipStoredName(entry, view);
  const sourcePath = zipEntryPath(entry, storedName);
  // Only a trailing "/" on the raw stored central-directory name makes a ZIP
  // member a directory, as for the JDK's ZipEntry.isDirectory, Python's
  // zipfile and ART's libziparchive, none of which read the Info-ZIP Unicode
  // Path field; a Unicode Path name cannot turn a stored file into a directory
  // or a stored directory into a file. Unix-mode or MS-DOS directory
  // attributes on any other name are reported, and the member stays readable.
  // Because such a member is a file, inventory validation then fails closed
  // where a file cannot stand: an attribute-only directory `foo` beside a
  // child `foo/bar` is a prefix conflict, and one named `.` or the empty name
  // is a path that is not normalized.
  const directoryName = storedName.endsWith("/");
  const attributeDirectory = !directoryName && hasDirectoryAttributes(entry);
  const kind = entry.symlink ? "symlink" : directoryName ? "directory" : "file";
  const path = sourcePath.replace(/^(?:\.\/)+/u, "");
  // Root directory markers carry no inventory occurrence. A file with this
  // spelling is still passed to the shared path validator and rejected there.
  if (kind === "directory" && (path === "" || path === ".")) return undefined;
  return {
    path,
    ...(path === sourcePath ? {} : { sourcePath }),
    kind,
    declaredSize: kind === "directory" ? null : entry.uncompressedSize,
    compressedSize: kind === "directory" ? null : entry.compressedSize,
    executable: entry.executable,
    encrypted: entry.encrypted,
    byteOffset: null,
    declaredIntegrity: null,
    unpacked: false,
    limitations: [
      ...(kind === "symlink" ? ["Archive symlink target was not read."] : []),
      ...(kind === "file" && attributeDirectory
        ? [
            `ZIP member ${JSON.stringify(storedName)} has directory external attributes (0x${(entry.externalFileAttributes >>> 0).toString(16).padStart(8, "0")}) but no trailing "/" in its stored name; it is read as a regular file, as the JDK and Python's zipfile read it.`,
          ]
        : []),
      ...(sourcePath === storedName
        ? []
        : [
            `ZIP member stored name ${JSON.stringify(storedName)} differs from its Info-ZIP Unicode Path extra field name ${JSON.stringify(sourcePath)}; the logical path uses the Unicode Path name, while lookups by stored name (e.g. the JDK or ART) see ${JSON.stringify(storedName)}.`,
          ]),
      ...(path === sourcePath
        ? []
        : [
            `ZIP member name ${JSON.stringify(sourcePath)} has a leading current-directory prefix omitted from its logical path.`,
          ]),
      ...legacyNameLimitations(entry, view),
    ],
    adapterKey: `zip-entry:${index}`,
    ...(path === storedName ? {} : { storedPath: storedName }),
  };
};

/**
 * Preserve source bytes when an unflagged legacy name may use another code
 * page. A reader taking the JDK's view decoded the name as strict UTF-8, so no
 * CP437 fallback happened.
 */
const legacyNameLimitations = (
  entry: Entry,
  view: ZipArchiveView,
): readonly string[] => {
  if (
    view === "jdk" ||
    entry.filenameUTF8 ||
    entry.extraFieldUnicodePath?.valid === true
  )
    return [];
  const bytes = entry.rawFilename;
  if (!bytes.some((byte) => byte >= 0x80)) return [];
  const hex = Buffer.from(bytes).toString("hex");
  return [
    `ZIP name uses CP437 fallback; source encoding unverified; raw hex: ${hex}.`,
  ];
};

const decodeZipEntryText = (
  bytes: Uint8Array,
  encoding: string,
  type: "filename" | "comment",
): string | undefined => {
  if (type !== "filename") return undefined;
  if (encoding === "utf-8")
    return decodeStrictZipUtf8(bytes, "ZIP filename is not valid UTF-8");
  return encoding === "cp437" ? decodeCp437(bytes) : undefined;
};

/** The JDK's view: names and entry comments are strict UTF-8, flag or not. */
const decodeJdkEntryText = (
  bytes: Uint8Array,
  _encoding: string,
  type: "filename" | "comment",
): string =>
  decodeStrictZipUtf8(
    bytes,
    `ZIP member ${type === "filename" ? "name" : "comment"} is not valid UTF-8; the JDK refuses to open such an archive`,
  );

/** CP437 characters for bytes 0x80-0xFF. */
const CP437_HIGH_HALF =
  "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u00A0";

/**
 * Decode a legacy ZIP name with the Unicode CP437 mapping, which Python's
 * zipfile also uses: bytes below 0x80 are ASCII. zip.js shows 0x01-0x1F and
 * 0x7F as IBM PC display glyphs, which turns the macOS folder icon file
 * `Icon\r` into `Icon♪`.
 */
const decodeCp437 = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) =>
    byte < 0x80
      ? String.fromCharCode(byte)
      : CP437_HIGH_HALF.charAt(byte - 0x80),
  ).join("");

/**
 * The central-directory name exactly as stored, decoded by the same rule as an
 * unextended name: UTF-8 when the language-encoding flag is set or the reader
 * takes the JDK's view, else CP437. zip.js replaces `filename` with a valid
 * Unicode Path extra field name, so the stored name is decoded from
 * `rawFilename` here.
 */
const zipStoredName = (entry: Entry, view: ZipArchiveView): string =>
  view === "jdk" || entry.bitFlag?.languageEncodingFlag === true
    ? decodeStrictZipUtf8(entry.rawFilename, "ZIP filename is not valid UTF-8")
    : decodeCp437(entry.rawFilename);

/** The logical name: a valid Info-ZIP Unicode Path field, else the stored name. */
const zipEntryPath = (entry: Entry, storedName: string): string => {
  const field = entry.extraFieldUnicodePath;
  if (field?.valid !== true) return storedName;
  return decodeStrictZipUtf8(
    field.data.subarray(5),
    "ZIP Unicode Path extra field is not valid UTF-8",
  );
};

const decodeStrictZipUtf8 = (bytes: Uint8Array, message: string): string => {
  try {
    // Keep the adapter's path semantics aligned with zip.js's default decoder:
    // a leading U+FEFF is part of a member name, not a transport signature.
    return ZIP_UTF8_DECODER.decode(bytes);
  } catch (cause: unknown) {
    throw new ArtifactReaderFailure("format", message, { cause });
  }
};

const extractStream = (entry: FileEntry, signal?: AbortSignal): Readable => {
  const output = new PassThrough();
  const controller = new AbortController();
  const onAbort = (): void => {
    controller.abort(signal?.reason);
    // AbortSignal listeners dispatch synchronously, so this destroy wins the race
    // against `getData` rejecting with its own AbortError. That ordering is what
    // keeps the caller-visible failure typed as `cancelled`.
    output.destroy(
      new ArtifactReaderFailure("cancelled", "ZIP operation cancelled", {
        cause: signal?.reason,
      }),
    );
  };
  signal?.addEventListener("abort", onAbort, { once: true });
  // `close` covers both a consumer walking away mid-entry and normal completion
  // after `end()`; aborting then is harmless because `getData` has already
  // resolved, and it releases the producer in the abandoned-consumer case.
  output.once("close", () => {
    signal?.removeEventListener("abort", onAbort);
    controller.abort();
  });
  const writable = new WritableStream<Uint8Array>({
    write: async (chunk) => {
      assertArtifactReadActive(signal);
      if (!output.write(Buffer.from(chunk)))
        await once(output, "drain", { signal: controller.signal });
    },
    close: () => {
      output.end();
    },
    abort: (reason) => {
      output.destroy(toError(typedZipFailure(reason)));
    },
  });
  void entry
    .getData(writable, {
      signal: controller.signal,
      checkSignature: true,
      checkOverlappingEntry: true,
      onprogress: () => assertArtifactReadActive(signal),
    })
    .catch((cause: unknown) => output.destroy(toError(typedZipFailure(cause))));
  return output;
};

/** zip.js reports archive faults as plain errors identified by message. */
const ZIP_FAILURE_REASONS: ReadonlyMap<string, "format" | "unavailable"> =
  new Map([
    ...[
      ERR_AMBIGUOUS_ARCHIVE,
      ERR_BAD_FORMAT,
      ERR_CENTRAL_DIRECTORY_NOT_FOUND,
      ERR_ENTRY_DATA_OUT_OF_BOUNDS,
      ERR_EOCDR_LOCATOR_ZIP64_NOT_FOUND,
      ERR_EOCDR_NOT_FOUND,
      ERR_EXTRAFIELD_ZIP64_NOT_FOUND,
      ERR_INVALID_COMPRESSED_DATA,
      ERR_INVALID_CRC32,
      ERR_INVALID_UNCOMPRESSED_SIZE,
      ERR_LOCAL_FILE_HEADER_NOT_FOUND,
      ERR_OVERLAPPING_ENTRY,
      ERR_UNSUPPORTED_UINT64,
    ].map((message) => [message, "format"] as const),
    ...[
      ERR_ENCRYPTED_CENTRAL_DIRECTORY,
      ERR_SPLIT_ZIP_FILE,
      ERR_UNSUPPORTED_COMPRESSION,
      ERR_UNSUPPORTED_ENCRYPTION,
    ].map((message) => [message, "unavailable"] as const),
  ]);

/** Type a zip.js archive fault so consumers do not report it as file I/O. */
const typedZipFailure = (cause: unknown): unknown => {
  if (!(cause instanceof Error) || cause instanceof ArtifactReaderFailure)
    return cause;
  const reason = ZIP_FAILURE_REASONS.get(cause.message);
  if (reason === undefined) return cause;
  return new ArtifactReaderFailure(
    reason,
    reason === "format"
      ? `ZIP archive is malformed: ${cause.message}`
      : `ZIP archive uses an unsupported feature: ${cause.message}`,
    { cause },
  );
};

async function* typedZipFailures<T>(
  source: AsyncIterable<T>,
): AsyncIterable<T> {
  try {
    yield* source;
  } catch (cause: unknown) {
    throw typedZipFailure(cause);
  }
}

/**
 * Directory external attributes, as zip.js reads them, without zip.js's
 * `directory` flag, which also counts a trailing "/" on the Unicode Path name.
 */
const hasDirectoryAttributes = (entry: Entry): boolean =>
  ((entry.unixMode ?? 0) & 0o170000) === 0o040000 ||
  ((entry.unixExternalUpper ?? 0) & 0o170000) === 0o040000 ||
  (entry.msDosCompatible && entry.msdosAttributes?.directory === true);

const toError = (cause: unknown): Error =>
  cause instanceof Error ? cause : new Error("ZIP extraction failed");
