/**
 * "Modified UTF-8", the encoding used by both the JVM class-file constant pool
 * (JVMS §4.4.7) and the DEX `string_data_item` (Dalvik Executable format):
 * U+0000 is encoded as the two-byte `C0 80`, and supplementary characters are
 * encoded as a CESU-8 surrogate pair (two three-byte sequences), never as a
 * four-byte sequence.
 */

/**
 * Progress of one validation pass over modified-UTF8 bytes, kept between
 * {@link continueModifiedUtf8Scan} calls so a long string can be checked in
 * bounded steps: the offset reached, the UTF-16 code units decoded so far, and
 * an upper bound on the UTF-8 bytes `JSON.stringify` emits for them (quotes
 * included).
 */
export interface ModifiedUtf8Scan {
  at: number;
  units: number;
  jsonBytes: number;
}

export const startModifiedUtf8Scan = (): ModifiedUtf8Scan => ({
  at: 0,
  units: 0,
  jsonBytes: 2,
});

const isContinuation = (byte: number | undefined): boolean =>
  byte !== undefined && (byte & 0xc0) === 0x80;

/**
 * Validate modified-UTF8 in place, allocating nothing, from `scan.at` to the
 * first sequence boundary at or past `until`. Returns `false` on any malformed
 * sequence — a stray continuation byte used as a lead, a lead that promises
 * continuation bytes the buffer does not hold, a four-byte (0xF0+) lead that
 * modified UTF-8 never emits, or an overlong (non-shortest) form, which both
 * the JVM and ART's DEX verifier reject. A sequence is read against the whole
 * of `bytes`, so a step boundary inside one is not a fault; the scan is done
 * when `scan.at` reaches `bytes.length`. Callers attach their own positional
 * context.
 *
 * The JSON bound charges control characters 6 (`\u00XX`), quote/backslash 2,
 * and a 3-byte sequence 6 in case it is a lone surrogate (`\udXXX`). It is
 * sound for accepted bytes because overlong forms are rejected: a control
 * character can only arrive as one byte, or U+0000 as 0xC0 0x80.
 */
export const continueModifiedUtf8Scan = (
  bytes: Uint8Array,
  scan: ModifiedUtf8Scan,
  until: number,
): boolean => {
  const stop = Math.min(until, bytes.length);
  let { at: i, units, jsonBytes } = scan;
  while (i < stop) {
    const a = bytes[i]!;
    if (a === 0 || a >= 0xf0) return false;
    if (a < 0x80) {
      jsonBytes += a < 0x20 ? 6 : a === 0x22 || a === 0x5c ? 2 : 1;
      i += 1;
    } else if (a < 0xe0) {
      // A 2-byte sequence leads with 110xxxxx (>= 0xc0); 0x80-0xbf are
      // continuation bytes and are never valid as a lead. (0xc0 0x80 remains
      // the modified-UTF8 encoding of U+0000 and stays accepted.)
      if (a < 0xc0 || !isContinuation(bytes[i + 1])) return false;
      // Shortest form only (JVMS §4.4.7): a 2-byte sequence encodes
      // U+0080..U+07FF, or U+0000 as exactly 0xC0 0x80. An overlong form
      // (e.g. 0xC0 0x81 for U+0001) is rejected, as the JVM rejects it.
      const unit = ((a & 0x1f) << 6) | (bytes[i + 1]! & 0x3f);
      const nul = a === 0xc0 && bytes[i + 1] === 0x80;
      if (unit < 0x80 && !nul) return false;
      jsonBytes += nul ? 6 : 2;
      i += 2;
    } else {
      if (!isContinuation(bytes[i + 1]) || !isContinuation(bytes[i + 2]))
        return false;
      // Shortest form only: a 3-byte sequence encodes U+0800..U+FFFF.
      if (a === 0xe0 && bytes[i + 1]! < 0xa0) return false;
      jsonBytes += a === 0xed ? 6 : 3;
      i += 3;
    }
    units += 1;
  }
  scan.at = i;
  scan.units = units;
  scan.jsonBytes = jsonBytes;
  return true;
};

const DECODE_CHUNK = 8192;

/**
 * Decode modified-UTF8 that {@link continueModifiedUtf8Scan} accepted, into
 * one flat string of its `units` code units. Code units are
 * written to a typed array and converted in bounded chunks: per-character
 * concatenation would build a rope of tens of thousands of nodes per string.
 * Lone surrogates are preserved exactly (a UTF-16 TextDecoder would replace
 * them).
 */
export const decodeValidModifiedUtf8 = (
  bytes: Uint8Array,
  units: number,
): string => {
  const out = new Uint16Array(units);
  let u = 0;
  let i = 0;
  while (i < bytes.length) {
    const a = bytes[i]!;
    if (a < 0x80) {
      out[u] = a;
      i += 1;
    } else if (a < 0xe0) {
      out[u] = ((a & 0x1f) << 6) | (bytes[i + 1]! & 0x3f);
      i += 2;
    } else {
      out[u] =
        ((a & 0x0f) << 12) |
        ((bytes[i + 1]! & 0x3f) << 6) |
        (bytes[i + 2]! & 0x3f);
      i += 3;
    }
    u += 1;
  }
  let text = "";
  for (let at = 0; at < units; at += DECODE_CHUNK)
    text += String.fromCharCode(...out.subarray(at, at + DECODE_CHUNK));
  return text;
};

/**
 * Encode text as modified UTF-8: U+0000 as `C0 80`, other BMP units as 1–3
 * bytes, and each surrogate of a supplementary character separately (CESU-8).
 */
export const encodeModifiedUtf8 = (text: string): Uint8Array => {
  const bytes: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit !== 0 && unit < 0x80) bytes.push(unit);
    else if (unit < 0x800) bytes.push(0xc0 | (unit >> 6), 0x80 | (unit & 0x3f));
    else
      bytes.push(
        0xe0 | (unit >> 12),
        0x80 | ((unit >> 6) & 0x3f),
        0x80 | (unit & 0x3f),
      );
  }
  return Uint8Array.from(bytes);
};
