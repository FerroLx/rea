import { describe, expect, it } from "vitest";

import { decodeModifiedUtf8 } from "./modifiedUtf8.js";

describe("decodeModifiedUtf8", () => {
  it("decodes ASCII", () => {
    expect(decodeModifiedUtf8(Uint8Array.from([0x41, 0x42]))).toBe("AB");
  });

  it("decodes the two-byte C0 80 encoding of U+0000", () => {
    expect(decodeModifiedUtf8(Uint8Array.from([0xc0, 0x80]))).toBe("\u0000");
  });

  it("decodes a two-byte BMP character", () => {
    // U+00E9 é -> C3 A9
    expect(decodeModifiedUtf8(Uint8Array.from([0xc3, 0xa9]))).toBe("é");
  });

  it("decodes a CESU-8 supplementary pair to its UTF-16 surrogates", () => {
    // U+1F600 -> surrogates D83D DE00, each a three-byte sequence
    const bytes = Uint8Array.from([0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]);
    expect(decodeModifiedUtf8(bytes)).toBe("😀");
  });

  it("rejects a stray continuation byte used as a lead", () => {
    expect(decodeModifiedUtf8(Uint8Array.from([0x80, 0x80]))).toBeNull();
  });

  it("rejects a four-byte (0xF0+) lead that modified UTF-8 never emits", () => {
    expect(
      decodeModifiedUtf8(Uint8Array.from([0xf0, 0x9f, 0x98, 0x80])),
    ).toBeNull();
  });

  it("rejects a truncated multi-byte sequence", () => {
    expect(decodeModifiedUtf8(Uint8Array.from([0xe0, 0x80]))).toBeNull();
  });
});
