/**
 * Dependency-free structural reader for Android DEX files (Dalvik Executable
 * format). Scope: frame the file — magic/version, the fixed header, the id-table
 * locations, each `class_def_item`, and, on demand, a class's `class_data_item`
 * and a method's `code_item` down to its `debug_info_off`. Interpretation of the
 * `debug_info_item` state machine and the string pool is layered on top of this
 * reader (see dexDebugInfo.ts / dexStrings.ts), not performed here.
 *
 * Every length- or offset-driven read is bounded against the buffer before use;
 * malformed or truncated input yields a tagged {@link DexFileParseError} via
 * {@link Result}, never a throw or an unchecked allocation. DEX is little-endian
 * (ART rejects reverse-endian too), so a reverse `endian_tag` is refused, not
 * byte-swapped. Addresses in DEX are 16-bit code units, not bytes.
 */
import { type Result, err, ok } from "../result.js";

/** The unversioned DEX magic prefix; the 3 following ASCII digits are the version. */
const DEX_MAGIC_PREFIX = [0x64, 0x65, 0x78, 0x0a] as const; // "dex\n"
const ENDIAN_CONSTANT = 0x12345678;
const REVERSE_ENDIAN_CONSTANT = 0x78563412;
const HEADER_SIZE_V40 = 0x70;

/** NO_INDEX sentinel for `source_file_idx` and other u4 index fields (DEX spec). */
export const DEX_NO_INDEX = 0xffffffff;

/**
 * Versions this reader decodes. 036 was withdrawn (libdexfile rejects it); 041
 * (Android 15+) introduces a wider container header and is refused for now;
 * compact dex (`cdex`) is a separate on-device format and is refused.
 */
const SUPPORTED_VERSIONS: ReadonlySet<string> = new Set([
  "035",
  "037",
  "038",
  "039",
  "040",
]);

/** Why framing failed. Offsets are byte positions into the supplied buffer. */
export type DexFileParseError =
  | { readonly kind: "bad-magic"; readonly offset: number }
  | { readonly kind: "compact-dex"; readonly offset: number }
  | { readonly kind: "reverse-endian"; readonly offset: number }
  | { readonly kind: "unsupported-version"; readonly version: string }
  | {
      readonly kind: "bad-header";
      readonly offset: number;
      readonly detail: string;
    }
  | {
      readonly kind: "truncated";
      readonly offset: number;
      readonly need: number;
      readonly have: number;
    }
  | {
      readonly kind: "budget-exceeded";
      readonly offset: number;
      readonly resource: "class-defs" | "class-data" | "leb128";
      readonly declared: number;
      readonly remaining: number;
    }
  | {
      readonly kind: "invalid-index";
      readonly offset: number;
      readonly index: number;
      readonly bound: number;
    };

/** Sequential, bounds-checked little-endian cursor with LEB128 support. */
export class DexCursor {
  offset: number;
  private readonly view: DataView;
  constructor(
    private readonly bytes: Uint8Array,
    start = 0,
  ) {
    this.offset = start;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  private short(n: number): DexFileParseError | null {
    return this.remaining < n
      ? {
          kind: "truncated",
          offset: this.offset,
          need: n,
          have: this.remaining,
        }
      : null;
  }

  u1(): Result<number, DexFileParseError> {
    const s = this.short(1);
    if (s) return err(s);
    const v = this.bytes[this.offset]!;
    this.offset += 1;
    return ok(v);
  }

  u2(): Result<number, DexFileParseError> {
    const s = this.short(2);
    if (s) return err(s);
    const v = this.view.getUint16(this.offset, true);
    this.offset += 2;
    return ok(v);
  }

  u4(): Result<number, DexFileParseError> {
    const s = this.short(4);
    if (s) return err(s);
    const v = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return ok(v);
  }

  /** Unsigned LEB128, capped at 5 bytes; a longer run is rejected rather than wrapped. */
  uleb128(): Result<number, DexFileParseError> {
    let result = 0;
    let shift = 0;
    for (let i = 0; i < 5; i += 1) {
      const b = this.u1();
      if (!b.ok) return b;
      result |= (b.value & 0x7f) << shift;
      if ((b.value & 0x80) === 0) return ok(result >>> 0);
      shift += 7;
    }
    return err({
      kind: "budget-exceeded",
      offset: this.offset,
      resource: "leb128",
      declared: 5,
      remaining: this.remaining,
    });
  }

  /** Signed LEB128, capped at 5 bytes, sign-extended from the final continuation. */
  sleb128(): Result<number, DexFileParseError> {
    let result = 0;
    let shift = 0;
    for (let i = 0; i < 5; i += 1) {
      const b = this.u1();
      if (!b.ok) return b;
      result |= (b.value & 0x7f) << shift;
      shift += 7;
      if ((b.value & 0x80) === 0) {
        if (shift < 32 && (b.value & 0x40) !== 0) result |= -(1 << shift);
        return ok(result);
      }
    }
    return err({
      kind: "budget-exceeded",
      offset: this.offset,
      resource: "leb128",
      declared: 5,
      remaining: this.remaining,
    });
  }

  /** `uleb128p1`: the encoded ULEB128 value minus one, so 0 encodes -1 (NO_INDEX). */
  uleb128p1(): Result<number, DexFileParseError> {
    const v = this.uleb128();
    return v.ok ? ok(v.value - 1) : v;
  }

  skip(n: number): Result<void, DexFileParseError> {
    const s = this.short(n);
    if (s) return err(s);
    this.offset += n;
    return ok(undefined);
  }
}

/** The fixed DEX header fields this reader needs to reach code and debug info. */
export interface DexHeader {
  readonly version: string;
  readonly fileSize: number;
  readonly stringIdsSize: number;
  readonly stringIdsOff: number;
  readonly typeIdsSize: number;
  readonly typeIdsOff: number;
  readonly protoIdsSize: number;
  readonly protoIdsOff: number;
  readonly methodIdsSize: number;
  readonly methodIdsOff: number;
  readonly classDefsSize: number;
  readonly classDefsOff: number;
  readonly dataSize: number;
  readonly dataOff: number;
  /** True when `file_size` disagrees with the buffer length (reported, not fatal). */
  readonly sizeMismatch: boolean;
}

/** A `class_def_item`: only the fields debug inspection needs are retained. */
export interface DexClassDef {
  readonly classIdx: number;
  readonly accessFlags: number;
  readonly superclassIdx: number;
  /** Index into the string pool, or {@link DEX_NO_INDEX} when absent. */
  readonly sourceFileIdx: number;
  /** Offset of the `class_data_item`, or 0 when the class has no members. */
  readonly classDataOff: number;
}

/** A framed DEX file: its header and every `class_def_item`. */
export interface DexFile {
  readonly header: DexHeader;
  readonly classDefs: readonly DexClassDef[];
}

/** One method within a `class_data_item` (indices resolved from their deltas). */
export interface DexEncodedMethod {
  readonly methodIdx: number;
  readonly accessFlags: number;
  /** Offset of the `code_item`, or 0 for abstract/native methods. */
  readonly codeOff: number;
}

/** The decoded members of a `class_data_item` relevant to debug inspection. */
export interface DexClassData {
  readonly directMethods: readonly DexEncodedMethod[];
  readonly virtualMethods: readonly DexEncodedMethod[];
}

/** The `code_item` header, down to the fields needed to reach its debug info. */
export interface DexCodeItem {
  readonly registersSize: number;
  readonly insSize: number;
  readonly outsSize: number;
  readonly triesSize: number;
  /** Offset of the `debug_info_item`, or 0 when the method carries none. */
  readonly debugInfoOff: number;
  /** Instruction count in 16-bit code units (not bytes). */
  readonly insnsSize: number;
}

const readVersion = (bytes: Uint8Array): string =>
  String.fromCharCode(bytes[4]!, bytes[5]!, bytes[6]!);

/** Frame a DEX file: validate the header, then read every `class_def_item`. */
export const parseDexFile = (
  bytes: Uint8Array,
): Result<DexFile, DexFileParseError> => {
  if (bytes.length < HEADER_SIZE_V40)
    return err({
      kind: "truncated",
      offset: 0,
      need: HEADER_SIZE_V40,
      have: bytes.length,
    });

  // Compact dex ("cdex") shares the first three bytes; distinguish before magic.
  if (bytes[0] === 0x63 && bytes[1] === 0x64 && bytes[2] === 0x65)
    return err({ kind: "compact-dex", offset: 0 });
  for (let i = 0; i < DEX_MAGIC_PREFIX.length; i += 1)
    if (bytes[i] !== DEX_MAGIC_PREFIX[i])
      return err({ kind: "bad-magic", offset: 0 });
  if (bytes[7] !== 0x00) return err({ kind: "bad-magic", offset: 7 });

  const version = readVersion(bytes);
  if (!SUPPORTED_VERSIONS.has(version))
    return err({ kind: "unsupported-version", version });

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const endian = view.getUint32(40, true);
  if (endian === REVERSE_ENDIAN_CONSTANT)
    return err({ kind: "reverse-endian", offset: 40 });
  if (endian !== ENDIAN_CONSTANT)
    return err({
      kind: "bad-header",
      offset: 40,
      detail: `endian_tag ${endian.toString(16)} is neither the standard nor reverse constant`,
    });

  const headerSize = view.getUint32(36, true);
  if (headerSize !== HEADER_SIZE_V40)
    return err({
      kind: "bad-header",
      offset: 36,
      detail: `header_size ${String(headerSize)} is not 0x70`,
    });

  const fileSize = view.getUint32(32, true);
  const header: DexHeader = {
    version,
    fileSize,
    stringIdsSize: view.getUint32(56, true),
    stringIdsOff: view.getUint32(60, true),
    typeIdsSize: view.getUint32(64, true),
    typeIdsOff: view.getUint32(68, true),
    protoIdsSize: view.getUint32(72, true),
    protoIdsOff: view.getUint32(76, true),
    methodIdsSize: view.getUint32(88, true),
    methodIdsOff: view.getUint32(92, true),
    classDefsSize: view.getUint32(96, true),
    classDefsOff: view.getUint32(100, true),
    dataSize: view.getUint32(104, true),
    dataOff: view.getUint32(108, true),
    sizeMismatch: fileSize !== bytes.length,
  };

  // Each class_def_item is a fixed 32 bytes; reject an impossible count up front.
  if (header.classDefsSize * 32 > bytes.length - header.classDefsOff)
    return err({
      kind: "budget-exceeded",
      offset: header.classDefsOff,
      resource: "class-defs",
      declared: header.classDefsSize,
      remaining: Math.max(0, bytes.length - header.classDefsOff),
    });

  const classDefs: DexClassDef[] = [];
  for (let i = 0; i < header.classDefsSize; i += 1) {
    const base = header.classDefsOff + i * 32;
    classDefs.push({
      classIdx: view.getUint32(base, true),
      accessFlags: view.getUint32(base + 4, true),
      superclassIdx: view.getUint32(base + 8, true),
      sourceFileIdx: view.getUint32(base + 16, true),
      classDataOff: view.getUint32(base + 24, true),
    });
  }

  return ok({ header, classDefs });
};

const readEncodedMethods = (
  cursor: DexCursor,
  count: number,
): Result<DexEncodedMethod[], DexFileParseError> => {
  // Each encoded_method is at least three ULEB128 bytes; a declared count that
  // could not fit in the remaining buffer is refused before allocating, so a
  // crafted class_data cannot force an unbounded method array.
  if (count > cursor.remaining / 3)
    return err({
      kind: "budget-exceeded",
      offset: cursor.offset,
      resource: "class-data",
      declared: count,
      remaining: cursor.remaining,
    });
  const methods: DexEncodedMethod[] = [];
  let methodIdx = 0; // indices are cumulative deltas within each list
  for (let i = 0; i < count; i += 1) {
    const diff = cursor.uleb128();
    if (!diff.ok) return diff;
    const access = cursor.uleb128();
    if (!access.ok) return access;
    const codeOff = cursor.uleb128();
    if (!codeOff.ok) return codeOff;
    methodIdx += diff.value;
    methods.push({
      methodIdx,
      accessFlags: access.value,
      codeOff: codeOff.value,
    });
  }
  return ok(methods);
};

/** Decode a `class_data_item`, skipping fields and returning the method lists. */
export const parseClassData = (
  bytes: Uint8Array,
  offset: number,
): Result<DexClassData, DexFileParseError> => {
  if (offset <= 0 || offset >= bytes.length)
    return err({
      kind: "invalid-index",
      offset,
      index: offset,
      bound: bytes.length,
    });
  const cursor = new DexCursor(bytes, offset);
  const staticFields = cursor.uleb128();
  if (!staticFields.ok) return staticFields;
  const instanceFields = cursor.uleb128();
  if (!instanceFields.ok) return instanceFields;
  const directMethods = cursor.uleb128();
  if (!directMethods.ok) return directMethods;
  const virtualMethods = cursor.uleb128();
  if (!virtualMethods.ok) return virtualMethods;

  // Skip both encoded_field lists (each entry: field_idx_diff uleb, access uleb).
  for (let i = 0; i < staticFields.value + instanceFields.value; i += 1) {
    if (!cursor.uleb128().ok || !cursor.uleb128().ok)
      return err({
        kind: "truncated",
        offset: cursor.offset,
        need: 1,
        have: cursor.remaining,
      });
  }

  const direct = readEncodedMethods(cursor, directMethods.value);
  if (!direct.ok) return direct;
  const virtual = readEncodedMethods(cursor, virtualMethods.value);
  if (!virtual.ok) return virtual;
  return ok({ directMethods: direct.value, virtualMethods: virtual.value });
};

/** Read a `code_item` header at `offset`, exposing its `debug_info_off`. */
export const parseCodeItem = (
  bytes: Uint8Array,
  offset: number,
): Result<DexCodeItem, DexFileParseError> => {
  if (offset <= 0 || offset + 16 > bytes.length)
    return err({
      kind: "invalid-index",
      offset,
      index: offset,
      bound: bytes.length,
    });
  const cursor = new DexCursor(bytes, offset);
  const registersSize = cursor.u2();
  if (!registersSize.ok) return registersSize;
  const insSize = cursor.u2();
  if (!insSize.ok) return insSize;
  const outsSize = cursor.u2();
  if (!outsSize.ok) return outsSize;
  const triesSize = cursor.u2();
  if (!triesSize.ok) return triesSize;
  const debugInfoOff = cursor.u4();
  if (!debugInfoOff.ok) return debugInfoOff;
  const insnsSize = cursor.u4();
  if (!insnsSize.ok) return insnsSize;
  return ok({
    registersSize: registersSize.value,
    insSize: insSize.value,
    outsSize: outsSize.value,
    triesSize: triesSize.value,
    debugInfoOff: debugInfoOff.value,
    insnsSize: insnsSize.value,
  });
};
