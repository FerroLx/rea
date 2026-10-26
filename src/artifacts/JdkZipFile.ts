import { Readable } from "node:stream";
import { createInflateRaw } from "node:zlib";

import { assertArtifactReadActive } from "./ArtifactFileOperation.js";
import { ArtifactReaderFailure } from "./ArtifactReader.js";
import {
  describeJdkZipException,
  jdkZipDataOffset,
  readJdkZipDirectory,
  type JdkZipDirectory,
  type JdkZipException,
  type JdkZipRecord,
  type JdkZipSource,
} from "./JdkZipCentralDirectory.js";
import {
  ARTIFACT_EXPANSION_RATIO,
  artifactExpansionBudgetBytes,
  MINIMUM_ARTIFACT_EXPANDED_BYTES,
} from "../domain/artifactExpansionBudget.js";
import {
  sameRegularFileState,
  type StableRegularFileDescriptor,
} from "../filesystem/RegularFile.js";

/** One member as `ZipFile.entries()` lists it. */
export interface JdkZipMember {
  /** Position in central-directory order; the member's identity in this file. */
  readonly index: number;
  /** The stored name, exactly as `ZipEntry.getName()` returns it. */
  readonly name: string;
  /** `ZipEntry.isDirectory()`: only a trailing `/` makes a directory. */
  readonly directory: boolean;
  /** `ZipEntry.getSize()`, a signed `long`. */
  readonly size: bigint;
}

/**
 * A JDK exception thrown while reading a member, e.g. a local header without
 * its signature or deflated data that ends early. `JarFile` throws it from the
 * same read, so callers can apply the JDK's handling of an `IOException`.
 */
export class JdkZipReadFailure extends ArtifactReaderFailure {
  constructor(
    readonly jdk: JdkZipException,
    message: string,
  ) {
    super("format", message);
  }
}

const READ_CHUNK_BYTES = 64 * 1024;

/**
 * Positional reads on the admitted descriptor. A read the file cannot satisfy
 * inside its admitted length means the file changed, never end of file.
 */
const descriptorSource = (
  path: string,
  { handle, initial }: StableRegularFileDescriptor,
): JdkZipSource => ({
  length: initial.size,
  readFully: async (position, length) => {
    const bytes = Buffer.alloc(length);
    for (let offset = 0; offset < length;) {
      const { bytesRead } = await handle.read(
        bytes,
        offset,
        length - offset,
        position + offset,
      );
      if (bytesRead === 0)
        throw new ArtifactReaderFailure(
          "integrity",
          `JAR ended before its admitted extent: ${path}`,
        );
      offset += bytesRead;
    }
    return bytes;
  },
});

/**
 * A local JAR opened as OpenJDK 25's `java.util.zip.ZipFile` opens it, through
 * one admitted descriptor the caller owns. Every archive fact, refusal and
 * member read comes from {@link readJdkZipDirectory} and the JDK's member
 * stream; no other ZIP parser is consulted. It holds no resources of its own.
 */
export class JdkZipFile {
  readonly members: readonly JdkZipMember[];
  readonly #path: string;
  readonly #source: JdkZipSource;
  readonly #directory: JdkZipDirectory;
  /** Plaintext produced by reads of this file, charged to its expansion budget. */
  #producedBytes = 0;

  private constructor(
    path: string,
    source: JdkZipSource,
    directory: JdkZipDirectory,
  ) {
    this.#path = path;
    this.#source = source;
    this.#directory = directory;
    this.members = directory.records.map((record, index) => ({
      index,
      name: record.name,
      directory: record.name.endsWith("/"),
      size: record.size,
    }));
  }

  /**
   * Open `path` through its admitted descriptor. The JDK's refusal to open the
   * archive is a `format` failure that quotes the JDK exception; a central
   * directory over `maximumCenBytes` is a `limit` failure.
   */
  static async open(
    path: string,
    admitted: StableRegularFileDescriptor,
    maximumCenBytes: number,
    signal: AbortSignal | undefined,
  ): Promise<JdkZipFile> {
    assertArtifactReadActive(signal);
    if (!sameRegularFileState(admitted.initial, await admitted.handle.stat()))
      throw new ArtifactReaderFailure(
        "integrity",
        `JAR identity changed before reading: ${path}`,
      );
    const source = descriptorSource(path, admitted);
    const directory = await readJdkZipDirectory(source, maximumCenBytes);
    assertArtifactReadActive(signal);
    if (directory.ok) return new JdkZipFile(path, source, directory.value);
    const failure = directory.error;
    if (failure.kind === "metadata-limit")
      throw new ArtifactReaderFailure(
        "limit",
        `JAR central directory needs ${String(failure.required)} bytes, exceeding the ${String(failure.maximum)}-byte read budget`,
        {
          boundary: "memory",
          limit: { key: "max_metadata_read_bytes", maximum: failure.maximum },
        },
      );
    throw new ArtifactReaderFailure(
      "format",
      `The JDK refuses to open ${path} as a ZIP/JAR archive (${describeJdkZipException(failure)})`,
    );
  }

  /**
   * The member's bytes as `ZipFile.getInputStream` delivers them: its
   * compressed size from the central directory, read from past its local
   * header, stopping early at end of file, and inflated when deflated. No
   * CRC, local-header size or method is checked, as the JDK checks none.
   * Produced bytes are charged to the archive's expansion budget.
   */
  async *read(
    member: JdkZipMember,
    signal: AbortSignal | undefined,
  ): AsyncGenerator<Uint8Array> {
    const record = this.#directory.records[member.index];
    if (record === undefined || this.members[member.index] !== member)
      throw new ArtifactReaderFailure(
        "integrity",
        "JAR member does not belong to this archive",
      );
    assertArtifactReadActive(signal);
    const start = await jdkZipDataOffset(this.#source, this.#directory, record);
    if (!start.ok) throw this.#readFailure(record, start.error);
    const stored = this.#storedBytes(start.value, record, signal);
    const plain = record.method === 0 ? stored : this.#inflate(record, stored);
    for await (const chunk of plain) {
      assertArtifactReadActive(signal);
      this.#charge(chunk.length);
      yield chunk;
    }
  }

  /** `ZipFileInputStream.read`: up to the compressed size, or end of file. */
  async *#storedBytes(
    start: bigint,
    record: JdkZipRecord,
    signal: AbortSignal | undefined,
  ): AsyncGenerator<Uint8Array> {
    const length = BigInt(this.#source.length);
    let position = start;
    let remaining = record.compressedSize;
    while (remaining > 0n && position < length) {
      assertArtifactReadActive(signal);
      const span = [BigInt(READ_CHUNK_BYTES), remaining, length - position];
      const size = Number(span.reduce((a, b) => (b < a ? b : a)));
      yield await this.#source.readFully(Number(position), size);
      position += BigInt(size);
      remaining -= BigInt(size);
    }
  }

  /**
   * `ZipFileInflaterInputStream`: raw inflate that stops at the end of the
   * deflate stream, ignoring bytes after it, and fails when the input ends
   * first ("Unexpected end of ZLIB input stream") or is not valid deflate data
   * (zlib's message, which the JDK reports in a `ZipException`).
   */
  async *#inflate(
    record: JdkZipRecord,
    input: AsyncGenerator<Uint8Array>,
  ): AsyncGenerator<Uint8Array> {
    const inflater = createInflateRaw();
    const source = Readable.from(input);
    source.on("error", (cause: unknown) => inflater.destroy(cause as Error));
    source.pipe(inflater);
    try {
      for await (const chunk of inflater) yield chunk as Buffer;
    } catch (cause: unknown) {
      if (cause instanceof ArtifactReaderFailure) throw cause;
      const code = (cause as { readonly code?: unknown }).code;
      if (code === "Z_BUF_ERROR")
        throw this.#readFailure(record, {
          kind: "jdk-exception",
          exception: "java.io.EOFException",
          message: "Unexpected end of ZLIB input stream",
        });
      if (code === "Z_DATA_ERROR" || code === "Z_NEED_DICT")
        throw this.#readFailure(record, {
          kind: "jdk-exception",
          exception: "java.util.zip.ZipException",
          message: (cause as Error).message,
        });
      throw cause;
    } finally {
      source.destroy();
      inflater.destroy();
    }
  }

  #charge(bytes: number): void {
    this.#producedBytes += bytes;
    const budget = artifactExpansionBudgetBytes(this.#source.length);
    if (this.#producedBytes <= budget) return;
    throw new ArtifactReaderFailure(
      "limit",
      `JAR members read so far expand to ${String(this.#producedBytes)} bytes, exceeding this archive's ${String(budget)}-byte decompression budget (${String(MINIMUM_ARTIFACT_EXPANDED_BYTES)}-byte minimum, ${String(ARTIFACT_EXPANSION_RATIO)}x archive size)`,
      {
        boundary: "capacity",
        limit: { key: "max_decompressed_bytes", maximum: budget },
      },
    );
  }

  #readFailure(record: JdkZipRecord, jdk: JdkZipException): JdkZipReadFailure {
    return new JdkZipReadFailure(
      jdk,
      `The JDK cannot read member ${JSON.stringify(record.name)} of ${this.#path} (${describeJdkZipException(jdk)})`,
    );
  }
}
