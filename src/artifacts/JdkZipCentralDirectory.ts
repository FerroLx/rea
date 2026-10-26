/**
 * OpenJDK 25's `java.util.zip.ZipFile` view of an archive, reproduced from
 * `ZipFile.Source.findEND`, `initCEN`, `checkAndAddEntry`, `checkExtraFields`
 * and `countCENHeaders`, and `ZipFileInputStream.checkZIP64`/`initDataOffset`
 * (checked against the JDK 25.0.4 bytecode and `new JarFile(...)` on crafted
 * archives). This module owns every fact the JDK derives from the END record,
 * the zip64 END record and the central directory: where the directory is,
 * which records it holds, where a member's data starts, and whether the JDK
 * refuses the archive and with what message. It reads raw bytes through a
 * caller-supplied source and never consults another ZIP parser.
 *
 * Long arithmetic is done in `bigint`, so 64-bit zip64 values, which the JDK
 * reads as signed `long`s, compare exactly as they do in Java.
 */
import { err, ok, type Result } from "../domain/result.js";

/** Positional reads over the archive, with `RandomAccessFile.readFully` semantics. */
export interface JdkZipSource {
  /** The archive length (`RandomAccessFile.length()`). */
  readonly length: number;
  /** Exactly `length` bytes at a non-negative `position` inside the file. */
  readFully(position: number, length: number): Promise<Uint8Array>;
}

/** An exception the JDK throws while opening the archive or reading a member. */
export interface JdkZipException {
  readonly kind: "jdk-exception";
  readonly exception: "java.util.zip.ZipException" | "java.io.EOFException";
  /** The JDK's message, or `null` when it has none (a bare `EOFException`). */
  readonly message: string | null;
}

/** The central directory is larger than the caller lets REA read. */
export interface JdkZipMetadataLimit {
  readonly kind: "metadata-limit";
  readonly required: number;
  readonly maximum: number;
}

export type JdkZipOpenFailure = JdkZipException | JdkZipMetadataLimit;

/** One central-directory record the JDK indexed. */
export interface JdkZipRecord {
  /** The record's offset in the central directory (the JDK's `pos`). */
  readonly cenPos: number;
  /** The stored name, decoded as `JarFile` decodes it (strict UTF-8). */
  readonly name: string;
  readonly method: 0 | 8;
  /** The uncompressed size: CENLEN, or its zip64 value (a signed `long`). */
  readonly size: bigint;
  /** The compressed bytes the JDK streams: CENSIZ, or its zip64 value. */
  readonly compressedSize: bigint;
  /** The local header's offset from the first local header: CENOFF, or its zip64 value. */
  readonly localHeaderOffset: bigint;
}

/** What `ZipFile` holds after a successful open. */
export interface JdkZipDirectory {
  /** File position of the first local header (`locpos`). */
  readonly locpos: bigint;
  /** Records in central-directory order. */
  readonly records: readonly JdkZipRecord[];
}

const CENSIG = 0x02014b50;
const LOCSIG = 0x04034b50;
const ZIP64_LOCSIG = 0x07064b50;
const ZIP64_ENDSIG = 0x06064b50;
const ENDHDR = 22;
const CENHDR = 46;
const LOCHDR = 30;
const ZIP64_LOCHDR = 20;
const ZIP64_ENDHDR = 56;
const READBLOCKSZ = 128;
const END_MAXLEN = 0xffff + ENDHDR;
/** `ArraysSupport.SOFT_MAX_ARRAY_LENGTH`, the JDK's `MAX_CEN_SIZE`. */
const MAX_CEN_SIZE = 2_147_483_639n;
const ZIP64_MAGICVAL = 0xffffffffn;
const ZIP64_MAGICCOUNT = 0xffff;
const EXTID_ZIP64 = 0x0001;

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const u16 = (b: Uint8Array, at: number): number => b[at]! | (b[at + 1]! << 8);
const u32 = (b: Uint8Array, at: number): number =>
  (b[at]! | (b[at + 1]! << 8) | (b[at + 2]! << 16) | (b[at + 3]! << 24)) >>> 0;
/** `ZipUtils.get64S`: a little-endian 64-bit value as a signed `long`. */
const s64 = (b: Uint8Array, at: number): bigint =>
  new DataView(b.buffer, b.byteOffset + at, 8).getBigInt64(0, true);

const zipException = (message: string): JdkZipException => ({
  kind: "jdk-exception",
  exception: "java.util.zip.ZipException",
  message,
});

/** `RandomAccessFile.readFully` running past the end of the file. */
export const JDK_EOF_EXCEPTION: JdkZipException = {
  kind: "jdk-exception",
  exception: "java.io.EOFException",
  message: null,
};

/**
 * `readFullyAt` at a `long` position, or `undefined` where the JDK's read
 * throws: past the end of the file (`EOFException`), or at a negative
 * position (an `IOException` from `seek`).
 */
const readAt = async (
  source: JdkZipSource,
  position: bigint,
  length: number,
): Promise<Uint8Array | undefined> =>
  position < 0n || position + BigInt(length) > BigInt(source.length)
    ? undefined
    : source.readFully(Number(position), length);

interface End {
  readonly centot: bigint;
  readonly cenlen: bigint;
  readonly cenoff: bigint;
  readonly endpos: bigint;
}

/** The zip64 END record a locator names, when its values agree with END's. */
const withZip64End = async (source: JdkZipSource, end: End): Promise<End> => {
  // The JDK catches every IOException here, so a failed read keeps END.
  if (end.endpos < BigInt(ZIP64_LOCHDR)) return end;
  const loc64 = await readAt(
    source,
    end.endpos - BigInt(ZIP64_LOCHDR),
    ZIP64_LOCHDR,
  );
  if (loc64 === undefined || u32(loc64, 0) !== ZIP64_LOCSIG) return end;
  const end64pos = s64(loc64, 8);
  const end64 = await readAt(source, end64pos, ZIP64_ENDHDR);
  if (end64 === undefined || u32(end64, 0) !== ZIP64_ENDSIG) return end;
  const cenlen64 = s64(end64, 40);
  const cenoff64 = s64(end64, 48);
  const centot64 = s64(end64, 32);
  if (
    (cenlen64 !== end.cenlen && end.cenlen !== ZIP64_MAGICVAL) ||
    (cenoff64 !== end.cenoff && end.cenoff !== ZIP64_MAGICVAL) ||
    (centot64 !== end.centot && end.centot !== BigInt(ZIP64_MAGICCOUNT))
  )
    return end;
  return {
    cenlen: cenlen64,
    cenoff: cenoff64,
    centot: centot64,
    endpos: end64pos,
  };
};

/**
 * `findEND`: scan backwards in 128-byte blocks for the last END signature
 * whose comment reaches the end of the file, or whose directory and first
 * local header both start with their signatures; then prefer a consistent
 * zip64 END record named by a locator just before it, which is always
 * permitted to be present.
 */
const findEnd = async (
  source: JdkZipSource,
): Promise<Result<End, JdkZipException>> => {
  const ziplen = source.length;
  if (ziplen <= 0) return err(zipException("zip file is empty"));
  const minHDR = Math.max(ziplen - END_MAXLEN, 0);
  const minPos = minHDR - (READBLOCKSZ - ENDHDR);
  const tailStart = Math.max(minPos, 0);
  const tail = await source.readFully(tailStart, ziplen - tailStart);
  // Bytes before the start of the file read as NUL, as the JDK pretends.
  const byteAt = (position: number): number =>
    position < tailStart ? 0 : tail[position - tailStart]!;
  for (
    let pos = ziplen - READBLOCKSZ;
    pos >= minPos;
    pos -= READBLOCKSZ - ENDHDR
  ) {
    for (let i = READBLOCKSZ - ENDHDR; i >= 0; i -= 1) {
      const p = pos + i;
      if (
        byteAt(p) !== 0x50 ||
        byteAt(p + 1) !== 0x4b ||
        byteAt(p + 2) !== 0x05 ||
        byteAt(p + 3) !== 0x06
      )
        continue;
      const endbuf = tail.subarray(p - tailStart, p - tailStart + ENDHDR);
      const candidate: End = {
        centot: BigInt(u16(endbuf, 10)),
        cenlen: BigInt(u32(endbuf, 12)),
        cenoff: BigInt(u32(endbuf, 16)),
        endpos: BigInt(p),
      };
      const comlen = u16(endbuf, 20);
      if (p + ENDHDR + comlen !== ziplen) {
        // A comment that does not reach the end: accept the record only if
        // the directory and the first local header it names are in place.
        // Both positions lie before END, so these reads cannot run past EOF.
        const cenpos = candidate.endpos - candidate.cenlen;
        const locpos = cenpos - candidate.cenoff;
        if (cenpos < 0n || locpos < 0n) continue;
        const cen = await source.readFully(Number(cenpos), 4);
        if (u32(cen, 0) !== CENSIG) continue;
        const loc = await source.readFully(Number(locpos), 4);
        if (u32(loc, 0) !== LOCSIG) continue;
      }
      if (
        comlen > 0 &&
        (await readAt(source, BigInt(p + ENDHDR), comlen)) === undefined
      )
        return err(JDK_EOF_EXCEPTION);
      return ok(await withZip64End(source, candidate));
    }
  }
  return err(zipException("zip END header not found"));
};

/** A record's CEN size, offset and disk fields, before any zip64 value. */
interface CenFields {
  readonly csize: bigint;
  readonly size: bigint;
  readonly locoff: bigint;
  readonly diskNo: number;
}

const cenFields = (cen: Uint8Array, pos: number): CenFields => ({
  csize: BigInt(u32(cen, pos + 20)),
  size: BigInt(u32(cen, pos + 24)),
  locoff: BigInt(u32(cen, pos + 42)),
  diskNo: u16(cen, pos + 34),
});

const anyEscape = ({ csize, size, locoff, diskNo }: CenFields): boolean =>
  csize === ZIP64_MAGICVAL ||
  size === ZIP64_MAGICVAL ||
  locoff === ZIP64_MAGICVAL ||
  diskNo === ZIP64_MAGICCOUNT;

/** `checkZip64ExtraFieldValues` for the zip64 block at `start`. */
const zip64Refusal = (
  cen: Uint8Array,
  start: number,
  blockSize: number,
  fields: CenFields,
): string | undefined => {
  const invalidSize =
    "Invalid CEN header (invalid zip64 extra data field size)";
  if (blockSize === 0) return anyEscape(fields) ? invalidSize : undefined;
  const { csize, size, locoff, diskNo } = fields;
  const expected =
    (csize === ZIP64_MAGICVAL ? 8 : 0) +
    (size === ZIP64_MAGICVAL ? 8 : 0) +
    (locoff === ZIP64_MAGICVAL ? 8 : 0) +
    (diskNo === ZIP64_MAGICCOUNT ? 4 : 0);
  if (expected !== blockSize) return invalidSize;
  // The exact size leaves eight bytes for each escaped value, so the JDK's
  // "missing size" branches cannot be reached once it passes.
  let off = start;
  for (const [escaped, message] of [
    [size === ZIP64_MAGICVAL, "Invalid zip64 extra block size value"],
    [
      csize === ZIP64_MAGICVAL,
      "Invalid zip64 extra block compressed size value",
    ],
    [locoff === ZIP64_MAGICVAL, "Invalid zip64 extra block LOC OFFSET value"],
  ] as const) {
    if (!escaped) continue;
    if (s64(cen, off) < 0n) return message;
    off += 8;
  }
  return undefined;
};

/** `checkExtraFields` for the record at `pos`, whose extra data starts at `start`. */
const extraFieldRefusal = (
  cen: Uint8Array,
  pos: number,
  start: number,
  length: number,
): string | undefined => {
  // `length` is a u16 and the header-size check keeps it inside the CEN, so
  // the JDK's "invalid extra field length" and "extra data field size too
  // long" refusals cannot be reached here.
  const end = start + length;
  for (let off = start; off + 4 <= end;) {
    const tag = u16(cen, off);
    const blockSize = u16(cen, off + 2);
    off += 4;
    if (off + blockSize > end)
      return `Invalid CEN header (invalid extra data field size for tag: 0x${tag.toString(16).padStart(4, "0")} at ${String(pos)})`;
    if (tag === EXTID_ZIP64) {
      const refusal = zip64Refusal(cen, off, blockSize, cenFields(cen, pos));
      if (refusal !== undefined) return refusal;
    }
    off += blockSize;
  }
  return undefined;
};

const decodeUtf8 = (bytes: Uint8Array): string | undefined => {
  try {
    return UTF8.decode(bytes);
  } catch {
    return undefined;
  }
};

/**
 * `ZipFileInputStream.checkZIP64`: the first zip64 block replaces, in order,
 * each escaped size or offset while it holds eight more bytes.
 */
const streamValues = (
  cen: Uint8Array,
  pos: number,
  extraStart: number,
  extraLength: number,
): Pick<JdkZipRecord, "size" | "compressedSize" | "localHeaderOffset"> => {
  let { size, csize, locoff } = cenFields(cen, pos);
  if (
    size === ZIP64_MAGICVAL ||
    csize === ZIP64_MAGICVAL ||
    locoff === ZIP64_MAGICVAL
  ) {
    const end = extraStart + extraLength;
    for (let off = extraStart; off + 4 < end;) {
      const tag = u16(cen, off);
      let blockSize = u16(cen, off + 2);
      off += 4;
      if (off + blockSize > end) break;
      if (tag !== EXTID_ZIP64) {
        off += blockSize;
        continue;
      }
      const take = (current: bigint): bigint => {
        if (current !== ZIP64_MAGICVAL || blockSize < 8 || off + 8 > end)
          return current;
        const value = s64(cen, off);
        blockSize -= 8;
        off += 8;
        return value;
      };
      size = take(size);
      csize = take(csize);
      locoff = take(locoff);
      break;
    }
  }
  return { size, compressedSize: csize, localHeaderOffset: locoff };
};

type CheckedRecord = JdkZipRecord & { readonly next: number };

/** `checkAndAddEntry` for the record at `pos`, in the JDK's check order. */
const checkRecord = (
  cen: Uint8Array,
  pos: number,
): Result<CheckedRecord, JdkZipException> => {
  if (u32(cen, pos) !== CENSIG)
    return err(zipException("invalid CEN header (bad signature)"));
  const method = u16(cen, pos + 10);
  if ((u16(cen, pos + 8) & 1) !== 0)
    return err(zipException("invalid CEN header (encrypted entry)"));
  if (method !== 0 && method !== 8)
    return err(
      zipException(
        `invalid CEN header (bad compression method: ${String(method)})`,
      ),
    );
  const entryPos = pos + CENHDR;
  const nlen = u16(cen, pos + 28);
  const elen = u16(cen, pos + 30);
  const clen = u16(cen, pos + 32);
  const headerSize = CENHDR + nlen + clen + elen;
  if (headerSize > 0xffff || pos > cen.length - headerSize)
    return err(zipException("invalid CEN header (bad header size)"));
  // `jdk.util.zip.disableZip64ExtraFieldValidation` is off by default.
  const extraRefusal =
    elen > 0
      ? extraFieldRefusal(cen, pos, entryPos + nlen, elen)
      : anyEscape(cenFields(cen, pos))
        ? "Invalid CEN header (invalid zip64 extra len size)"
        : undefined;
  if (extraRefusal !== undefined) return err(zipException(extraRefusal));
  // JarFile decodes every name and comment as UTF-8, flagged or not.
  const name = decodeUtf8(cen.subarray(entryPos, entryPos + nlen));
  const commentStart = entryPos + nlen + elen;
  if (
    name === undefined ||
    (clen > 0 &&
      decodeUtf8(cen.subarray(commentStart, commentStart + clen)) === undefined)
  )
    return err(zipException("invalid CEN header (bad entry name or comment)"));
  return ok({
    cenPos: pos,
    name,
    method,
    ...streamValues(cen, pos, entryPos + nlen, elen),
    next: entryPos + nlen + clen + elen,
  });
};

/** `countCENHeaders`: count records by their sizes alone, for a short ENDTOT. */
const countRecords = (cen: Uint8Array): Result<number, JdkZipException> => {
  let count = 0;
  for (let p = 0; p <= cen.length - CENHDR; count += 1) {
    const headerSize =
      CENHDR + u16(cen, p + 28) + u16(cen, p + 30) + u16(cen, p + 32);
    if (p > cen.length - headerSize)
      return err(zipException("invalid CEN header (bad header size)"));
    p += headerSize;
  }
  return ok(count);
};

/** `initCEN`'s record loop, restarting with the counted total when ENDTOT is short. */
const indexRecords = (
  cen: Uint8Array,
  declaredTotal: number,
): Result<readonly JdkZipRecord[], JdkZipException> => {
  let total = declaredTotal;
  for (;;) {
    const records: JdkZipRecord[] = [];
    let pos = 0;
    let recount = false;
    while (pos <= cen.length - CENHDR) {
      if (records.length >= total) {
        recount = true;
        break;
      }
      const record = checkRecord(cen, pos);
      if (!record.ok) return record;
      const { next, ...indexed } = record.value;
      records.push(indexed);
      pos = next;
    }
    if (!recount)
      return pos === cen.length
        ? ok(records)
        : err(zipException("invalid CEN header (bad header size)"));
    const counted = countRecords(cen);
    if (!counted.ok) return counted;
    total = counted.value;
  }
};

/**
 * Open the archive as `new ZipFile(file)` does: find END, validate it, read
 * the central directory and check every record in order. Work and memory are
 * linear in the directory, which `maximumCenBytes` bounds; a larger one is a
 * `metadata-limit` failure, reported after the END checks the JDK makes first.
 */
export const readJdkZipDirectory = async (
  source: JdkZipSource,
  maximumCenBytes: number,
): Promise<Result<JdkZipDirectory, JdkZipOpenFailure>> => {
  const found = await findEnd(source);
  if (!found.ok) return found;
  const end = found.value;
  if (end.endpos === 0n) return ok({ locpos: 0n, records: [] });
  if (end.cenlen > end.endpos)
    return err(zipException("invalid END header (bad central directory size)"));
  const cenpos = end.endpos - end.cenlen;
  const locpos = cenpos - end.cenoff;
  if (locpos < 0n)
    return err(
      zipException("invalid END header (bad central directory offset)"),
    );
  if (end.cenlen > MAX_CEN_SIZE)
    return err(
      zipException("invalid END header (central directory size too large)"),
    );
  // Java's long division truncates toward zero, as bigint division does.
  if (end.centot < 0n || end.centot > end.cenlen / BigInt(CENHDR))
    return err(
      zipException("invalid END header (total entries count too large)"),
    );
  const cenlen = Number(end.cenlen);
  if (cenlen > maximumCenBytes)
    return err({
      kind: "metadata-limit",
      required: cenlen,
      maximum: maximumCenBytes,
    });
  const cen = await readAt(source, cenpos, cenlen);
  if (cen === undefined) return err(JDK_EOF_EXCEPTION);
  const records = indexRecords(cen, Number(end.centot));
  return records.ok ? ok({ locpos, records: records.value }) : records;
};

/**
 * `ZipFileInputStream.initDataOffset`: the file position of a record's data,
 * past its local header's name and extra field. Nothing else in the local
 * header is read, so its flags, sizes and method never matter.
 */
export const jdkZipDataOffset = async (
  source: JdkZipSource,
  directory: JdkZipDirectory,
  record: JdkZipRecord,
): Promise<Result<bigint, JdkZipException>> => {
  const position = directory.locpos + record.localHeaderOffset;
  const loc = await readAt(source, position, LOCHDR);
  if (loc === undefined) return err(JDK_EOF_EXCEPTION);
  if (u32(loc, 0) !== LOCSIG)
    return err(zipException("ZipFile invalid LOC header (bad signature)"));
  return ok(
    position + BigInt(LOCHDR) + BigInt(u16(loc, 26)) + BigInt(u16(loc, 28)),
  );
};

/** `Throwable.toString()` for a JDK exception, as a stack trace names it. */
export const describeJdkZipException = ({
  exception,
  message,
}: JdkZipException): string =>
  message === null ? exception : `${exception}: ${message}`;
