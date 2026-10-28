import { describe, expect, it } from "vitest";

import {
  continueModifiedUtf8Scan,
  decodeValidModifiedUtf8,
  encodeModifiedUtf8,
  type ModifiedUtf8Scan,
  startModifiedUtf8Scan,
} from "./modifiedUtf8.js";

/** Validate in one call; the scan, or null when rejected. */
const scanAll = (bytes: Uint8Array): ModifiedUtf8Scan | null => {
  const scan = startModifiedUtf8Scan();
  return continueModifiedUtf8Scan(bytes, scan, bytes.length) ? scan : null;
};
const modifiedUtf8Units = (bytes: Uint8Array): number | null =>
  scanAll(bytes)?.units ?? null;
/** Validate, then decode, as the DEX string resolver does. */
const decodeModifiedUtf8 = (bytes: Uint8Array): string | null => {
  const scan = scanAll(bytes);
  return scan === null ? null : decodeValidModifiedUtf8(bytes, scan.units);
};

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

describe("modified UTF-8 hardening shared by the JVM and DEX readers", () => {
  it("rejects overlong forms, as the JVM and ART's DEX verifier do", () => {
    for (const overlong of [
      [0xc0, 0x81],
      [0xc1, 0xbf],
      [0xe0, 0x81, 0x81],
      [0xe0, 0x9f, 0xbf],
    ])
      expect(decodeModifiedUtf8(Uint8Array.from(overlong))).toBeNull();
  });

  it("keeps U+0000 as 0xC0 0x80 and the shortest 2- and 3-byte forms", () => {
    expect(decodeModifiedUtf8(Uint8Array.from([0xc0, 0x80]))).toBe("\u0000");
    expect(decodeModifiedUtf8(Uint8Array.from([0xc2, 0x80]))).toBe("\u0080");
    expect(decodeModifiedUtf8(Uint8Array.from([0xe0, 0xa0, 0x80]))).toBe(
      "\u0800",
    );
  });

  it("preserves a lone surrogate exactly and decodes long strings flat", () => {
    expect(decodeModifiedUtf8(Uint8Array.from([0xed, 0xa0, 0x80]))).toBe(
      "\ud800",
    );
    const long = Uint8Array.from({ length: 20_000 }, () => 0x61);
    expect(decodeModifiedUtf8(long)).toBe("a".repeat(20_000));
  });
});

describe("encodeModifiedUtf8", () => {
  it("round-trips through the decoder, including NUL and supplementary text", () => {
    for (const text of [
      "Lcom/example/Foo;",
      "a\u0000b",
      "\u00fc\u4e2d",
      "\ud83d\ude00",
    ]) {
      const encoded = encodeModifiedUtf8(text);
      expect(decodeModifiedUtf8(encoded)).toBe(text);
      expect(modifiedUtf8Units(encoded)).toBe(text.length);
    }
    expect([...encodeModifiedUtf8("\u0000")]).toEqual([0xc0, 0x80]);
  });
});

describe("continueModifiedUtf8Scan in steps", () => {
  /** Validate in `step`-byte steps, as a paused DEX string scan does. */
  const stepped = (bytes: Uint8Array, step: number) => {
    const scan = startModifiedUtf8Scan();
    let steps = 0;
    while (scan.at < bytes.length) {
      const before = scan.at;
      if (!continueModifiedUtf8Scan(bytes, scan, before + step)) return null;
      // Each step stops at the first sequence boundary at or past its end.
      expect(scan.at).toBeGreaterThanOrEqual(
        Math.min(bytes.length, before + step),
      );
      expect(scan.at - (before + step)).toBeLessThan(3);
      steps += 1;
    }
    return { ...scan, steps };
  };

  it("counts the same units and JSON bound when sequences straddle a step end", () => {
    const step = 16_384;
    // A 2-byte (é), 3-byte (中) and surrogate (😀 as two 3-byte) sequence
    // placed so each straddles the step boundary at 16,384.
    for (const tail of ["\u00e9", "\u4e2d", "\ud83d\ude00", '"\\\u0000']) {
      for (const lead of [step - 2, step - 1, step]) {
        const text = "a".repeat(lead) + tail + "z".repeat(40);
        const bytes = encodeModifiedUtf8(text);
        const whole = scanAll(bytes)!;
        const paced = stepped(bytes, step);
        expect(paced).not.toBeNull();
        expect(paced!.units).toBe(text.length);
        expect(paced!.units).toBe(whole.units);
        expect(paced!.jsonBytes).toBe(whole.jsonBytes);
        expect(paced!.steps).toBe(2);
      }
    }
  });

  it("rejects a sequence truncated at a step end that is also the end of the bytes", () => {
    const step = 16_384;
    for (const cut of [
      [0xc3], // 2-byte lead, no continuation
      [0xe4, 0xb8], // 3-byte lead, one continuation
    ]) {
      const bytes = Uint8Array.from([
        ...new Array<number>(step - cut.length).fill(0x61),
        ...cut,
      ]);
      expect(stepped(bytes, step)).toBeNull();
      expect(scanAll(bytes)).toBeNull();
    }
  });

  it("rejects a malformed continuation found only in the step after the boundary", () => {
    const step = 16_384;
    const bytes = Uint8Array.from([
      ...new Array<number>(step - 1).fill(0x61),
      0xe4,
      0xb8,
      0x41, // not a continuation byte
    ]);
    expect(stepped(bytes, step)).toBeNull();
    expect(scanAll(bytes)).toBeNull();
  });
});
