/**
 * Decode "modified UTF-8" into a JavaScript string. This is the encoding used by
 * both the JVM class-file constant pool (JVMS §4.4.7) and the DEX
 * `string_data_item` (Dalvik Executable format): U+0000 is encoded as the
 * two-byte `C0 80`, and supplementary characters are encoded as a CESU-8
 * surrogate pair (two three-byte sequences), never as a four-byte sequence.
 *
 * Returns `null` on any malformed sequence — a stray continuation byte used as
 * a lead, a lead that promises continuation bytes the buffer does not hold, or a
 * four-byte (0xF0+) lead that modified UTF-8 never emits. Callers attach their
 * own positional context to the failure.
 */
const isContinuation = (byte: number | undefined): boolean =>
  byte !== undefined && (byte & 0xc0) === 0x80;

export const decodeModifiedUtf8 = (bytes: Uint8Array): string | null => {
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const a = bytes[i]!;
    if (a === 0 || a >= 0xf0) return null;
    if (a < 0x80) {
      out += String.fromCharCode(a);
      i += 1;
    } else if (a < 0xe0) {
      // A 2-byte sequence leads with 110xxxxx (>= 0xc0); 0x80-0xbf are
      // continuation bytes and are never valid as a lead. (0xc0 0x80 remains
      // the encoding of U+0000 and stays accepted.)
      if (a < 0xc0 || i + 1 >= bytes.length || !isContinuation(bytes[i + 1]))
        return null;
      const b = bytes[i + 1]!;
      out += String.fromCharCode(((a & 0x1f) << 6) | (b & 0x3f));
      i += 2;
    } else {
      if (
        i + 2 >= bytes.length ||
        !isContinuation(bytes[i + 1]) ||
        !isContinuation(bytes[i + 2])
      )
        return null;
      const b = bytes[i + 1]!;
      const c = bytes[i + 2]!;
      out += String.fromCharCode(
        ((a & 0x0f) << 12) | ((b & 0x3f) << 6) | (c & 0x3f),
      );
      i += 3;
    }
  }
  return out;
};
