import type { Entry } from "@zip.js/zip.js";

const CEN_HEADER_BYTES = 46;
const MAX_16 = 0xffff;
const MAX_32 = 0xffffffff;

/** Which record values are the zip64 escape (0xFFFFFFFF, or 0xFFFF for the disk). */
interface Zip64Escapes {
  readonly uncompressedSize: boolean;
  readonly compressedSize: boolean;
  readonly offset: boolean;
  readonly diskNumberStart: boolean;
}

/**
 * zip.js replaces exactly the escaped record values with their zip64 values
 * and records each replacement on `extraFieldZip64`; an unreplaced value is
 * still the record's own.
 */
const zip64Escapes = (entry: Entry): Zip64Escapes => {
  const replaced = entry.extraFieldZip64;
  const escaped = (property: keyof Zip64Escapes, escape: number): boolean =>
    replaced?.[property] !== undefined || entry[property] === escape;
  return {
    uncompressedSize: escaped("uncompressedSize", MAX_32),
    compressedSize: escaped("compressedSize", MAX_32),
    offset: escaped("offset", MAX_32),
    diskNumberStart: escaped("diskNumberStart", MAX_16),
  };
};

const anyEscape = (escapes: Zip64Escapes): boolean =>
  escapes.uncompressedSize ||
  escapes.compressedSize ||
  escapes.offset ||
  escapes.diskNumberStart;

const u16 = (bytes: Uint8Array, at: number): number =>
  bytes[at]! | (bytes[at + 1]! << 8);

/**
 * `checkZip64ExtraFieldValues`: a zip64 block holds exactly the escaped
 * values. Its values themselves need no check here: zip.js refuses any above
 * `Number.MAX_SAFE_INTEGER`, which covers every value the JDK reads as a
 * negative `long` (zip.js is stricter there than the JDK).
 */
const zip64Refusal = (
  size: number,
  escapes: Zip64Escapes,
): string | undefined => {
  const expected =
    (escapes.uncompressedSize ? 8 : 0) +
    (escapes.compressedSize ? 8 : 0) +
    (escapes.offset ? 8 : 0) +
    (escapes.diskNumberStart ? 4 : 0);
  // An empty block is accepted when nothing is escaped.
  if (size === 0 ? expected === 0 : size === expected) return undefined;
  return "Invalid CEN header (invalid zip64 extra data field size)";
};

const extraFieldRefusal = (entry: Entry): string | undefined => {
  const extra = entry.rawExtraField;
  const escapes = zip64Escapes(entry);
  if (extra.length === 0)
    return anyEscape(escapes)
      ? "Invalid CEN header (invalid zip64 extra len size)"
      : undefined;
  // A trailing run shorter than a 4-byte field header is not examined.
  for (let at = 0; at + 4 <= extra.length;) {
    const tag = u16(extra, at);
    const size = u16(extra, at + 2);
    at += 4;
    if (at + size > extra.length)
      return `Invalid CEN header (invalid extra data field size for tag: 0x${tag.toString(16).padStart(4, "0")})`;
    if (tag === 0x0001) {
      const refusal = zip64Refusal(size, escapes);
      if (refusal !== undefined) return refusal;
    }
    at += size;
  }
  return undefined;
};

/**
 * The per-record central-directory refusals of OpenJDK 25's
 * `ZipFile.Source.checkAndAddEntry` (with its default zip64 extra-field
 * validation) that zip.js does not already make while enumerating. Each one
 * makes the JDK refuse to open the whole archive, whichever member is
 * requested. Checked against JDK 25 bytecode and crafted archives:
 *
 * - the encryption flag (bit 0) is set;
 * - the compression method is neither 0 (stored) nor 8 (deflated);
 * - the record's header size, 46 + name + extra + comment, exceeds 0xFFFF
 *   (JDK 21 does not check this);
 * - an extra field's declared size runs past the extra data;
 * - a zip64 extra field (tag 0x0001) whose size is not exactly the sum of the
 *   values the record marks as 0xFFFFFFFF/0xFFFF (an empty one is accepted
 *   when nothing is marked);
 * - a record with no extra data at all that marks a value as 0xFFFFFFFF/0xFFFF.
 *
 * zip.js already refuses a bad record signature and a zip64 value the JDK
 * reads as negative (it refuses any value above `Number.MAX_SAFE_INTEGER`),
 * and this reader's JDK view decodes names and comments as strict UTF-8, so
 * none of those is repeated here.
 * Returns the JDK's message for the first refusal, or `undefined`.
 */
export const jdkCentralDirectoryRefusal = (
  entry: Entry,
): string | undefined => {
  if (entry.encrypted) return "invalid CEN header (encrypted entry)";
  // An AES extra field replaces zip.js's method; the JDK reads the record's.
  const method =
    entry.extraFieldAES?.originalCompressionMethod ?? entry.compressionMethod;
  if (method !== 0 && method !== 8)
    return `invalid CEN header (bad compression method: ${String(method)})`;
  const headerSize =
    CEN_HEADER_BYTES +
    entry.rawFilename.length +
    entry.rawExtraField.length +
    entry.rawComment.length;
  if (headerSize > MAX_16) return "invalid CEN header (bad header size)";
  return extraFieldRefusal(entry);
};
