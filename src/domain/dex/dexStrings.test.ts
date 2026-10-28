import { describe, expect, it } from "vitest";

import type { DexHeader } from "./dexFile.js";
import { encodeModifiedUtf8 } from "../modifiedUtf8.js";
import { DexStringResolver } from "./dexStrings.js";

const STRING_IDS_OFF = 40;
const TYPE_IDS_OFF = 48;
const DATA0 = 64; // "Hello"
const DATA1 = 80; // "Lcom/Foo;"

/** A buffer holding two strings and one type id that points at the second. */
const fixture = (): { bytes: Uint8Array; header: DexHeader } => {
  const bytes = new Uint8Array(128);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(STRING_IDS_OFF + 0, DATA0, true); // string_ids[0] -> DATA0
  dv.setUint32(STRING_IDS_OFF + 4, DATA1, true); // string_ids[1] -> DATA1
  dv.setUint32(TYPE_IDS_OFF + 0, 1, true); // type_ids[0] -> string 1
  const write = (at: number, utf16: number, text: string): void => {
    bytes[at] = utf16; // uleb128 (single byte for small sizes)
    bytes.set(
      [...text].map((c) => c.charCodeAt(0)),
      at + 1,
    );
    bytes[at + 1 + text.length] = 0x00; // NUL terminator
  };
  write(DATA0, 5, "Hello");
  write(DATA1, 9, "Lcom/Foo;");
  const header: DexHeader = {
    version: "035",
    fileSize: bytes.length,
    stringIdsSize: 2,
    stringIdsOff: STRING_IDS_OFF,
    typeIdsSize: 1,
    typeIdsOff: TYPE_IDS_OFF,
    protoIdsSize: 0,
    protoIdsOff: 0,
    fieldIdsSize: 0,
    methodIdsSize: 0,
    methodIdsOff: 0,
    classDefsSize: 0,
    classDefsOff: 0,
    dataSize: 0,
    dataOff: 0,
  };
  return { bytes, header };
};

describe("DexStringResolver", () => {
  it("resolves a string by index", () => {
    const { bytes, header } = fixture();
    expect(new DexStringResolver(bytes, header).string(0)).toBe("Hello");
  });

  it("resolves a type descriptor through the type pool", () => {
    const { bytes, header } = fixture();
    expect(new DexStringResolver(bytes, header).typeDescriptor(0)).toBe(
      "Lcom/Foo;",
    );
  });

  it("returns null for NO_INDEX and out-of-range indices", () => {
    const { bytes, header } = fixture();
    const r = new DexStringResolver(bytes, header);
    expect(r.string(-1)).toBeNull();
    expect(r.string(99)).toBeNull();
    expect(r.typeDescriptor(5)).toBeNull();
  });

  it("returns null when the declared utf16_size disagrees with the bytes", () => {
    const { bytes, header } = fixture();
    bytes[DATA0] = 9; // claim 9 code units for a 5-char string
    expect(new DexStringResolver(bytes, header).string(0)).toBeNull();
  });

  it("returns null for an unterminated string_data_item", () => {
    const { bytes, header } = fixture();
    bytes.fill(0x41, DATA1 + 1); // overwrite the NUL and the rest with 'A'
    expect(new DexStringResolver(bytes, header).string(1)).toBeNull();
  });
});

describe("DexStringResolver.typeIdentity", () => {
  it("matches, differs, or reports an undecodable descriptor as unreadable", () => {
    const { bytes, header } = fixture();
    const resolver = new DexStringResolver(bytes, header);
    expect(resolver.typeIdentity(0, encodeModifiedUtf8("Lcom/Foo;"))).toBe(
      "match",
    );
    expect(resolver.typeIdentity(0, encodeModifiedUtf8("Lcom/Bar;"))).toBe(
      "different",
    );
    // An overlong (invalid) encoding is unknown whatever was requested.
    bytes[DATA1 + 1] = 0xc1;
    bytes[DATA1 + 2] = 0x8c;
    for (const request of ["Lcom/Foo;", "Lcom/Zzz;"])
      expect(
        new DexStringResolver(bytes, header).typeIdentity(
          0,
          encodeModifiedUtf8(request),
        ),
      ).toBe("unreadable");
  });
});

/** A buffer whose one string runs `length` bytes, unterminated when `nul` is false. */
const longString = (length: number, nul: boolean, fill = 0x61) => {
  const bytes = new Uint8Array(64 + 3 + length + 1);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(STRING_IDS_OFF, DATA0, true);
  bytes.set(
    [0x80 | (length & 0x7f), 0x80 | ((length >> 7) & 0x7f), length >> 14],
    DATA0,
  );
  bytes.fill(fill, DATA0 + 3, DATA0 + 3 + length);
  if (!nul) bytes.fill(0x61, DATA0 + 3 + length);
  const header: DexHeader = {
    ...fixture().header,
    stringIdsSize: 1,
    fileSize: bytes.length,
    typeIdsSize: 0,
  };
  let charged = 0;
  const state = { spent: false };
  const resolver = new DexStringResolver(
    bytes,
    header,
    (units) => (charged += units),
    () => state.spent,
  );
  return { bytes, resolver, state, charged: () => charged };
};

describe("DexStringResolver charges each string once", () => {
  it("charges an unterminated string once across validity, a re-ask and its JSON bound", () => {
    const { resolver, charged } = longString(100_000, false);
    expect(resolver.validity(0)).toBe(false);
    const once = charged();
    expect(once).toBeGreaterThanOrEqual(100_000);
    expect(resolver.validity(0)).toBe(false);
    expect(resolver.jsonBound(0)).toBe(4);
    expect(resolver.string(0)).toBeNull();
    expect(charged()).toBe(once);
  });

  it("returns a string known invalid as null without scanning or charging it again", () => {
    const { bytes, resolver, charged } = longString(100_000, true);
    bytes[DATA0 + 3 + 99_999] = 0xff; // never valid modified UTF-8
    expect(resolver.validity(0)).toBe(false);
    const once = charged();
    expect(resolver.string(0)).toBeNull();
    expect(resolver.jsonBound(0)).toBe(4);
    expect(charged()).toBe(once);
  });

  it("decodes a valid string without validating it a second time", () => {
    const { resolver, charged } = longString(100_000, true);
    expect(resolver.validity(0)).toBe(true);
    const scanned = charged();
    expect(resolver.string(0)).toBe("a".repeat(100_000));
    // The decode itself is charged; no second validation pass is.
    expect(charged() - scanned).toBe(100_000);
  });

  it("does not memoise an id as unreadable while the budget is spent", () => {
    const { resolver, state } = longString(10, true);
    state.spent = true;
    expect(resolver.validity(0)).toBe(false);
    expect(resolver.string(0)).toBeNull();
    state.spent = false;
    expect(resolver.validity(0)).toBe(true);
    expect(resolver.string(0)).toBe("a".repeat(10));
  });
});

describe("DexStringResolver keeps paused scans", () => {
  const length = 100_000;
  /** `count` long strings, asked round-robin with a pause after every step. */
  const roundRobin = (count: number) => {
    const stride = length + 8;
    const bytes = new Uint8Array(DATA0 + count * stride + 8);
    const idsOff = DATA0 + count * stride;
    const ids = new Uint8Array(count * 4);
    for (let i = 0; i < count; i += 1) {
      const offset = DATA0 + i * stride;
      bytes.set(
        [0x80 | (length & 0x7f), 0x80 | ((length >> 7) & 0x7f), length >> 14],
        offset,
      );
      bytes.fill(0x61 + (i % 26), offset + 3, offset + 3 + length);
      new DataView(ids.buffer).setUint32(i * 4, offset, true);
    }
    const all = new Uint8Array(idsOff + ids.length);
    all.set(bytes.subarray(0, idsOff));
    all.set(ids, idsOff);
    const header: DexHeader = {
      ...fixture().header,
      stringIdsSize: count,
      stringIdsOff: idsOff,
      fileSize: all.length,
      typeIdsSize: 0,
    };
    let charged = 0;
    const resolver = new DexStringResolver(
      all,
      header,
      (units) => (charged += units),
      () => false,
      () => true,
    );
    const answers: (boolean | undefined)[] = new Array<undefined>(count).fill(
      undefined,
    );
    let rounds = 0;
    for (; rounds < 1_000 && answers.includes(undefined); rounds += 1)
      for (let i = 0; i < count; i += 1)
        if (answers[i] === undefined) {
          const v = resolver.validity(i);
          if (typeof v === "boolean") answers[i] = v;
        }
    return { answers, charged, ideal: count * 2 * length, rounds };
  };

  it("finishes interleaved long strings within the kept set, charging each once", () => {
    const run = roundRobin(16);
    expect(run.answers.every((v) => v === true)).toBe(true);
    expect(run.charged).toBe(run.ideal);
  });

  it("still finishes every string when more are interleaved than it keeps", () => {
    const run = roundRobin(17);
    expect(run.answers.every((v) => v === true)).toBe(true);
    // Only the string that found the set full is rescanned, one step per
    // round until a slot frees.
    expect(run.charged).toBeLessThan(run.ideal * 1.1);
  });
});
