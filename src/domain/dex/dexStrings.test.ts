import { describe, expect, it } from "vitest";

import type { DexHeader } from "./dexFile.js";
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
    methodIdsSize: 0,
    methodIdsOff: 0,
    classDefsSize: 0,
    classDefsOff: 0,
    dataSize: 0,
    dataOff: 0,
    sizeMismatch: false,
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
