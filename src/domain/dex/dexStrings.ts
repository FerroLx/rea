/**
 * Resolve names and type descriptors from a DEX file's string and type id pools
 * (Dalvik Executable format). A `string_id_item` is a u4 offset to a
 * `string_data_item` (`uleb128 utf16_size` then NUL-terminated modified UTF-8);
 * a `type_id_item` is a u4 index into the string pool. All lookups are bounded
 * and return `null` for an out-of-range index (including NO_INDEX = -1) or a
 * malformed/uncross-checked string, never a throw or a guess.
 */
import {
  continueModifiedUtf8Scan,
  decodeValidModifiedUtf8,
  type ModifiedUtf8Scan,
  startModifiedUtf8Scan,
} from "../modifiedUtf8.js";
import {
  DEX_MAX_PARAMETERS,
  DEX_PAUSED,
  type DexParameterList,
} from "./dexDebugInfo.js";
import { DEX_NO_INDEX, DexCursor, type DexHeader } from "./dexFile.js";

/**
 * Entries kept per memo. Memoisation is an optimisation, not a working set:
 * past the cap a value is recomputed, never retained, so a DEX with millions of
 * distinct strings or protos cannot grow these maps without bound.
 */
const MEMO_LIMIT = 65_536;

/** Decoded UTF-16 code units retained across the string memo. */
const RETAINED_CHARS_LIMIT = 4 * 1024 * 1024;

/** Proto parameter entries retained across the proto memo (each up to 255). */
const RETAINED_PARAMS_LIMIT = 1024 * 1024;

/**
 * Bytes one string scan examines between pause checks, so a multi-megabyte
 * string_data overshoots a work slice by at most this much.
 */
const SCAN_STEP = 16 * 1024;

/**
 * Charges `units` of work (bytes scanned or decoded) to the caller's budget.
 * The resolver never refuses on its own; the caller checks its budget and
 * refuses the whole call once it is spent.
 */
export type DexStringCharge = (units: number) => void;

/** A resolver answer, or {@link DEX_PAUSED} when a scan stopped for a pause. */
export type DexPausable<T> = T | typeof DEX_PAUSED;

interface StringHead {
  readonly dataOffset: number;
  /** First modified-UTF-8 byte, after the `utf16_size` uleb128. */
  readonly start: number;
  readonly utf16Size: number;
}

interface RawString extends StringHead {
  readonly bytes: Uint8Array;
}

/**
 * What one validation pass establishes about a string_data: the JSON bytes it
 * serialises to (at least 4) when it decodes to its declared UTF-16 size, or
 * {@link UNREADABLE}, whose `null` serialises to 4. A plain number, so
 * checking many tiny strings allocates nothing per string.
 */
type StringFacts = number;

const UNREADABLE: StringFacts = 0;

const validFacts = (jsonBytes: number): StringFacts => Math.max(4, jsonBytes);

/** The one string scan in progress, kept across pauses. */
interface StringScan extends StringHead {
  /** Where the terminator search resumes, until `bytes` is known. */
  searched: number;
  bytes: Uint8Array | null;
  readonly utf8: ModifiedUtf8Scan;
}

const NEVER = (): boolean => false;

/**
 * The resolver is the owner of string identity for one DEX file. Strings are
 * memoised by their `string_data` offset, so many ids aliasing one long string
 * share a single decoded copy; retained decoded text is capped; and every scan
 * and decode is charged to the caller's work budget. A string's validity and
 * JSON bound come from one scan, charged once, which pauses between
 * {@link SCAN_STEP}-byte steps when the caller's slice is due and continues
 * where it stopped on the next call.
 */
export class DexStringResolver {
  private readonly view: DataView;
  readonly #strings = new Map<number, string | null>();
  /** Facts per `string_data` offset, so a string is scanned and charged once. */
  readonly #facts = new Map<number, StringFacts>();
  #scan: StringScan | null = null;
  #retainedChars = 0;
  #retainedParams = 0;
  constructor(
    private readonly bytes: Uint8Array,
    readonly header: DexHeader,
    private readonly charge: DexStringCharge = () => undefined,
    /** True once the caller's budget is spent: no new scan or decode starts. */
    private readonly spent: () => boolean = () => false,
    /** True when the caller's work slice is due: a long scan pauses. */
    private readonly pauseDue: () => boolean = NEVER,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  #remember<K, V>(memo: Map<K, V>, key: K, value: V): void {
    if (memo.size < MEMO_LIMIT) memo.set(key, value);
  }

  /**
   * Resolve a string-pool index to its text, or `null` when absent/malformed.
   * Validity comes from the string's one scan ({@link validity}); only a
   * valid string is decoded, and its bytes are not validated again.
   */
  string(index: number): string | null {
    const raw = this.#raw(index);
    if (raw === null) return null;
    const cached = this.#strings.get(raw.dataOffset);
    if (cached !== undefined || this.#strings.has(raw.dataOffset))
      return cached ?? null;
    if (this.spent() || this.#settled(index) === UNREADABLE) return null;
    this.charge(raw.bytes.length);
    const decoded = decodeValidModifiedUtf8(raw.bytes, raw.utf16Size);
    if (this.#retainedChars + decoded.length <= RETAINED_CHARS_LIMIT) {
      this.#retainedChars += decoded.length;
      this.#remember(this.#strings, raw.dataOffset, decoded);
    }
    return decoded;
  }

  /**
   * Whether `string(index)` would resolve to a string, checked without
   * allocating the decoded text (charged like a decode). Pauses mid-scan when
   * the caller's slice is due; call again with the same index to continue.
   */
  readonly validity = (index: number): DexPausable<boolean> => {
    const facts = this.#check(index, this.pauseDue);
    return facts === DEX_PAUSED ? facts : facts !== UNREADABLE;
  };

  /** {@link validity} of a type id's descriptor string. */
  readonly typeValidity = (index: number): DexPausable<boolean> => {
    const stringIdx = this.#typeStringIndex(index);
    return stringIdx === null ? false : this.validity(stringIdx);
  };

  /**
   * Upper bound on the JSON bytes `string(index)` serialises to (4 for `null`),
   * computed from the raw bytes without decoding and memoised per string.
   */
  jsonBound(index: number): number {
    const facts = this.#settled(index);
    return facts === UNREADABLE ? 4 : facts;
  }

  /** JSON bound of a type id's descriptor string. */
  typeJsonBound(index: number): number {
    const stringIdx = this.#typeStringIndex(index);
    return stringIdx === null ? 4 : this.jsonBound(stringIdx);
  }

  /**
   * The memoised facts of `index`, or the string still to scan. An id that
   * cannot be read, or whose string is unterminated, is memoised as such; a
   * spent budget is not, because the caller refuses the whole call.
   */
  #lookup(index: number): StringFacts | StringHead {
    let head: StringHead | null | undefined = this.#rawMemo.get(index);
    if (head === null) return UNREADABLE;
    if (head === undefined) {
      if (this.spent()) return UNREADABLE;
      head = this.#head(index);
      if (head === null) {
        this.#remember(this.#rawMemo, index, null);
        return UNREADABLE;
      }
    }
    return this.#facts.get(head.dataOffset) ?? head;
  }

  /**
   * The string's facts, scanning it in {@link SCAN_STEP}-byte steps and
   * pausing after a step when `pauseDue`. A paused scan is kept and the next
   * call for the same string continues it, so nothing is charged twice.
   *
   * One scan is kept at a time. Every caller asks again for the reference that
   * paused before asking for anything else (the walk re-reads the unit, and
   * {@link DexStringResolver} callers settle one check at a time), so a kept
   * scan is only replaced if a caller abandons it; returning to that string
   * later would then scan and charge it again.
   */
  #check(index: number, pauseDue: () => boolean): DexPausable<StringFacts> {
    const found = this.#lookup(index);
    if (typeof found === "number") return found;
    let scan = this.#scan;
    if (scan?.dataOffset === found.dataOffset) {
      this.#scan = null;
      // A continued scan steps before its first pause check: every call
      // makes progress.
      const settled = this.#run(index, scan, 1);
      if (settled !== null) return settled;
    } else {
      const first = this.#begin(index, found);
      if (typeof first === "number") return first;
      scan = first;
    }
    for (;;) {
      if (pauseDue()) {
        this.#scan = scan;
        return DEX_PAUSED;
      }
      const settled = this.#run(index, scan, 1);
      if (settled !== null) return settled;
    }
  }

  /**
   * {@link validity}'s facts, scanned to the end without pausing. A kept scan
   * of the same string is continued; one of another string is left alone.
   */
  #settled(index: number): StringFacts {
    const found = this.#lookup(index);
    if (typeof found === "number") return found;
    let scan: StringScan;
    if (this.#scan?.dataOffset === found.dataOffset) {
      scan = this.#scan;
      this.#scan = null;
    } else {
      const first = this.#begin(index, found);
      if (typeof first === "number") return first;
      scan = first;
    }
    return this.#run(index, scan, null) ?? UNREADABLE;
  }

  /**
   * Run up to `steps` steps of `scan` (all of them when null): its facts once
   * settled, or null to go on. A spent budget ends it as unreadable, unmemoised:
   * the caller refuses the whole call.
   */
  #run(
    index: number,
    scan: StringScan,
    steps: number | null,
  ): StringFacts | null {
    for (let n = 0; steps === null || n < steps; n += 1) {
      if (this.spent()) return UNREADABLE;
      const settled = this.#step(index, scan);
      if (settled !== null) return this.#record(scan.dataOffset, settled);
    }
    return null;
  }

  #record(dataOffset: number, facts: StringFacts): StringFacts {
    this.#remember(this.#facts, dataOffset, facts);
    return facts;
  }

  /**
   * The first step of a new scan. A string short enough to locate and
   * validate within one step settles here without allocating a saved scan;
   * a longer one returns the scan to continue.
   */
  #begin(index: number, head: StringHead): StringFacts | StringScan {
    if (this.spent()) return UNREADABLE;
    let text = "bytes" in head ? (head as RawString).bytes : null;
    let searched = head.start;
    if (text === null) {
      // A plain loop: most strings are short, and a native search would
      // allocate a window per string.
      const limit = Math.min(this.bytes.length, head.start + SCAN_STEP);
      let end = head.start;
      while (end < limit && this.bytes[end] !== 0x00) end += 1;
      this.charge(end - head.start);
      searched = end;
      if (end < limit) text = this.#located(index, head, end);
      else if (limit >= this.bytes.length)
        return this.#record(head.dataOffset, this.#unterminated(index));
    }
    // Locating and validating together stay within one step.
    if (text !== null && 2 * text.length <= SCAN_STEP) {
      const utf8 = this.#scratch;
      utf8.at = 0;
      utf8.units = 0;
      utf8.jsonBytes = 2;
      this.charge(text.length);
      const facts =
        continueModifiedUtf8Scan(text, utf8, text.length) &&
        utf8.units === head.utf16Size
          ? validFacts(utf8.jsonBytes)
          : UNREADABLE;
      return this.#record(head.dataOffset, facts);
    }
    return {
      dataOffset: head.dataOffset,
      start: head.start,
      utf16Size: head.utf16Size,
      searched,
      bytes: text,
      utf8: startModifiedUtf8Scan(),
    };
  }

  readonly #scratch: ModifiedUtf8Scan = startModifiedUtf8Scan();

  /** Record a located string's raw bytes; returns them. */
  #located(index: number, head: StringHead, end: number): Uint8Array {
    const bytes = this.bytes.subarray(head.start, end);
    if (this.#rawMemo.size < MEMO_LIMIT)
      this.#rawMemo.set(index, {
        dataOffset: head.dataOffset,
        start: head.start,
        utf16Size: head.utf16Size,
        bytes,
      });
    return bytes;
  }

  /** An unterminated string: its id is memoised as unreadable. */
  #unterminated(index: number): StringFacts {
    this.#remember(this.#rawMemo, index, null);
    return UNREADABLE;
  }

  /**
   * One bounded step of `scan`: find the NUL terminator, then validate the
   * modified UTF-8 before it. Returns the facts once settled, null to go on.
   */
  #step(index: number, scan: StringScan): StringFacts | null {
    if (scan.bytes === null) {
      const limit = Math.min(this.bytes.length, scan.searched + SCAN_STEP);
      const found = this.bytes.subarray(scan.searched, limit).indexOf(0x00);
      const end = found < 0 ? limit : scan.searched + found;
      this.charge(end - scan.searched);
      scan.searched = end;
      if (found < 0)
        return limit < this.bytes.length ? null : this.#unterminated(index);
      scan.bytes = this.#located(index, scan, end);
      return null;
    }
    const text = scan.bytes;
    const from = scan.utf8.at;
    if (!continueModifiedUtf8Scan(text, scan.utf8, from + SCAN_STEP)) {
      this.charge(text.length - from);
      return UNREADABLE;
    }
    this.charge(scan.utf8.at - from);
    if (scan.utf8.at < text.length) return null;
    // A length that disagrees with the declared UTF-16 size is malformed.
    return scan.utf8.units === scan.utf16Size
      ? validFacts(scan.utf8.jsonBytes)
      : UNREADABLE;
  }

  /** The string's modified-UTF8 bytes (a view) and declared UTF-16 size, memoised. */
  #raw(index: number): RawString | null {
    const memo = this.#rawMemo.get(index);
    if (memo !== undefined || this.#rawMemo.has(index)) return memo ?? null;
    // A spent budget means the caller will refuse the whole call; starting
    // another (possibly member-sized) scan would only waste the time, and the
    // id is not memoised as unreadable.
    if (this.spent()) return null;
    const raw = this.#locate(index);
    this.#remember(this.#rawMemo, index, raw);
    return raw;
  }

  readonly #rawMemo = new Map<number, RawString | null>();

  /** A string id's data offset and declared size, read in O(1). */
  #head(index: number): StringHead | null {
    if (
      index < 0 ||
      index === DEX_NO_INDEX ||
      index >= this.header.stringIdsSize
    )
      return null;
    const idOffset = this.header.stringIdsOff + index * 4;
    if (idOffset + 4 > this.bytes.length) return null;
    const dataOffset = this.view.getUint32(idOffset, true);
    if (dataOffset <= 0 || dataOffset >= this.bytes.length) return null;
    const cursor = new DexCursor(this.bytes, dataOffset);
    const utf16Size = cursor.uleb128();
    if (!utf16Size.ok) return null;
    return { dataOffset, start: cursor.offset, utf16Size: utf16Size.value };
  }

  #locate(index: number): RawString | null {
    const head = this.#head(index);
    if (head === null) return null;
    // Modified UTF-8 runs to a NUL terminator; find it within the buffer.
    const found = this.bytes.subarray(head.start).indexOf(0x00);
    const end = found < 0 ? this.bytes.length : head.start + found;
    this.charge(end - head.start);
    if (found < 0) return null; // unterminated
    return { ...head, bytes: this.bytes.subarray(head.start, end) };
  }

  /**
   * Compare a type's descriptor with `wanted` (modified-UTF-8 bytes) without
   * decoding it: `unreadable` when the descriptor cannot be located or is not
   * valid modified UTF-8 of its declared length. Pauses like {@link validity}.
   */
  typeIdentity(
    index: number,
    wanted: Uint8Array,
  ): DexPausable<"match" | "different" | "unreadable"> {
    const stringIdx = this.#typeStringIndex(index);
    if (stringIdx === null) return "unreadable";
    // An undecodable descriptor is an unknown identity, never "different".
    const valid = this.validity(stringIdx);
    if (valid !== true) return valid === false ? "unreadable" : valid;
    const raw = this.#raw(stringIdx);
    if (raw === null) return "unreadable";
    if (raw.bytes.length !== wanted.length) return "different";
    for (let i = 0; i < wanted.length; i++)
      if (raw.bytes[i] !== wanted[i]) return "different";
    return "match";
  }

  /** Resolve a type-pool index to its descriptor string (e.g. `Lcom/example/Foo;`). */
  typeDescriptor(index: number): string | null {
    const stringIdx = this.#typeStringIndex(index);
    return stringIdx === null ? null : this.string(stringIdx);
  }

  #typeStringIndex(index: number): number | null {
    if (index < 0 || index === DEX_NO_INDEX || index >= this.header.typeIdsSize)
      return null;
    const idOffset = this.header.typeIdsOff + index * 4;
    if (idOffset + 4 > this.bytes.length) return null;
    return this.view.getUint32(idOffset, true);
  }

  /** Bounded u4 read, or null past the end. */
  #u4(at: number): number | null {
    return at >= 0 && at + 4 <= this.bytes.length
      ? this.view.getUint32(at, true)
      : null;
  }

  /** A method's `proto_idx`, or null when the method or proto is out of range. */
  methodProtoIndex(methodIndex: number): number | null {
    if (methodIndex < 0 || methodIndex >= this.header.methodIdsSize)
      return null;
    const protoAt = this.header.methodIdsOff + methodIndex * 8 + 2;
    if (protoAt + 2 > this.bytes.length) return null;
    const protoIndex = this.view.getUint16(protoAt, true);
    return protoIndex < this.header.protoIdsSize ? protoIndex : null;
  }

  /** `method_id_item` = { class_idx u2, proto_idx u2, name_idx u4 }. */
  methodName(methodIndex: number): string | null {
    if (methodIndex < 0 || methodIndex >= this.header.methodIdsSize)
      return null;
    const nameIdx = this.#u4(this.header.methodIdsOff + methodIndex * 8 + 4);
    return nameIdx === null ? null : this.string(nameIdx);
  }

  /**
   * The JVM-form descriptor of a method, e.g. `(Ljava/lang/String;I)V`, built
   * from its `proto_id_item` { shorty_idx u4, return_type_idx u4,
   * parameters_off u4 } and the `type_list` at `parameters_off`.
   */
  /**
   * The string and type ids a method's name and descriptor read: the name's
   * string id (null when out of range), and the return type then each
   * parameter type (null when the proto cannot be read; a parameter list that
   * is oversized or runs past the file contributes what was read).
   */
  #methodRefs(methodIndex: number): {
    readonly name: number | null;
    readonly types: readonly number[] | null;
  } {
    const name = this.#u4(this.header.methodIdsOff + methodIndex * 8 + 4);
    const protoIndex = this.methodProtoIndex(methodIndex);
    if (protoIndex === null) return { name, types: null };
    const protoBase = this.header.protoIdsOff + protoIndex * 12;
    const returnTypeIdx = this.#u4(protoBase + 4);
    const parametersOff = this.#u4(protoBase + 8);
    if (returnTypeIdx === null || parametersOff === null)
      return { name, types: null };
    const types = [returnTypeIdx];
    if (parametersOff === 0) return { name, types };
    const size = this.#u4(parametersOff);
    if (size === null || size > DEX_MAX_PARAMETERS) return { name, types };
    for (let i = 0; i < size; i += 1) {
      const at = parametersOff + 4 + i * 2;
      if (at + 2 > this.bytes.length) break;
      types.push(this.view.getUint16(at, true));
    }
    return { name, types };
  }

  /**
   * The string ids {@link methodJsonBound} reads, so a caller can check them
   * one at a time ({@link validity}, pausing) before the bound is taken.
   */
  methodStrings(methodIndex: number): number[] {
    if (methodIndex < 0 || methodIndex >= this.header.methodIdsSize) return [];
    const { name, types } = this.#methodRefs(methodIndex);
    const strings = name === null ? [] : [name];
    for (const type of types ?? []) {
      const stringIdx = this.#typeStringIndex(type);
      if (stringIdx !== null) strings.push(stringIdx);
    }
    return strings;
  }

  /**
   * Upper bound on the JSON bytes of `methodDescriptor(methodIndex)` (and of
   * `methodName`), computed from the proto's type ids and memoised string
   * bounds without building the descriptor, so a caller can refuse before a
   * proto repeating one long type up to 255 times is joined.
   */
  methodJsonBound(methodIndex: number): number {
    if (methodIndex < 0 || methodIndex >= this.header.methodIdsSize) return 8;
    const { name, types } = this.#methodRefs(methodIndex);
    let total = (name === null ? 4 : this.jsonBound(name)) + 4;
    for (const type of types ?? []) total += this.typeJsonBound(type);
    return total;
  }

  methodDescriptor(methodIndex: number): string | null {
    if (methodIndex < 0 || methodIndex >= this.header.methodIdsSize)
      return null;
    // method_id_item: class_idx u2 @0, proto_idx u2 @2, name_idx u4 @4.
    const protoAt = this.header.methodIdsOff + methodIndex * 8 + 2;
    if (protoAt + 2 > this.bytes.length) return null;
    const protoIndex = this.view.getUint16(protoAt, true);
    if (protoIndex >= this.header.protoIdsSize) return null;
    const protoBase = this.header.protoIdsOff + protoIndex * 12;
    const returnTypeIdx = this.#u4(protoBase + 4);
    const parametersOff = this.#u4(protoBase + 8);
    if (returnTypeIdx === null || parametersOff === null) return null;
    const returnDescriptor = this.typeDescriptor(returnTypeIdx);
    if (returnDescriptor === null) return null;
    const params = this.#typeList(parametersOff);
    if (params === null) return null;
    return `(${params.join("")})${returnDescriptor}`;
  }

  /**
   * A method's proto parameter types, in declaration order, each with whether it
   * is wide (long/double — occupies two registers but one parameter slot). Used
   * to seed the implicit parameter locals that a debug_info_item starts at
   * address 0. Returns null when the method or proto cannot be resolved.
   */
  methodParameters(methodIndex: number): DexParameterList | null {
    if (methodIndex < 0 || methodIndex >= this.header.methodIdsSize)
      return null;
    const protoAt = this.header.methodIdsOff + methodIndex * 8 + 2;
    if (protoAt + 2 > this.bytes.length) return null;
    const protoIndex = this.view.getUint16(protoAt, true);
    if (protoIndex >= this.header.protoIdsSize) return null;
    const parametersOff = this.#u4(
      this.header.protoIdsOff + protoIndex * 12 + 8,
    );
    if (parametersOff === null) return null;
    // Keyed by the type_list itself: protos (and so methods) sharing a
    // parameter list decode it once, so total work follows the type_list
    // bytes present in the file rather than methods x parameters.
    const cached = this.#protoParams.get(parametersOff);
    if (cached !== undefined || this.#protoParams.has(parametersOff))
      return cached ?? null;
    const params = this.#typeListParameters(parametersOff);
    const size = params?.typeIdx.length ?? 0;
    this.charge(size + 1);
    // Bounded by retained parameter entries, not just lists: one list can
    // expand to 255 entries.
    if (this.#retainedParams + size <= RETAINED_PARAMS_LIMIT) {
      this.#retainedParams += size;
      this.#remember(this.#protoParams, parametersOff, params);
    }
    return params;
  }

  readonly #protoParams = new Map<number, DexParameterList | null>();

  #typeListParameters(parametersOff: number): DexParameterList | null {
    if (parametersOff === 0)
      return { typeIdx: new Uint16Array(0), wide: new Uint8Array(0) };
    const size = this.#u4(parametersOff);
    // A proto with more parameters than a method's 255 argument registers can
    // hold is malformed; refuse before allocating its list.
    if (size === null || size > DEX_MAX_PARAMETERS) return null;
    if (parametersOff + 4 + size * 2 > this.bytes.length) return null;
    const typeIdx = new Uint16Array(size);
    const wide = new Uint8Array(size);
    for (let i = 0; i < size; i += 1) {
      typeIdx[i] = this.view.getUint16(parametersOff + 4 + i * 2, true);
      wide[i] = this.#isWideType(typeIdx[i]!) ? 1 : 0;
    }
    return { typeIdx, wide };
  }

  /**
   * Whether a type is `J` or `D` (two registers), read from the raw descriptor
   * bytes: only the one-byte strings qualify, so no descriptor is decoded.
   */
  #isWideType(typeIdx: number): boolean {
    // Memoised per type id (0 unknown, 1 narrow, 2 wide): type ids are 16-bit
    // here, so 64 KiB answers every repeat without a map lookup or rescan.
    const known = this.#wideByType[typeIdx];
    if (known !== undefined && known !== 0) return known === 2;
    const wide = this.#resolveWide(typeIdx);
    if (typeIdx < this.#wideByType.length)
      this.#wideByType[typeIdx] = wide ? 2 : 1;
    return wide;
  }

  readonly #wideByType = new Uint8Array(0x10000);

  #resolveWide(typeIdx: number): boolean {
    const stringIdx = this.#typeStringIndex(typeIdx);
    const raw = stringIdx === null ? null : this.#raw(stringIdx);
    if (raw === null || raw.utf16Size !== 1 || raw.bytes.length !== 1)
      return false;
    return raw.bytes[0] === 0x4a || raw.bytes[0] === 0x44; // 'J' | 'D'
  }

  /** A `type_list` { size u4, list[size] of u2 type_idx }, resolved to descriptors. */
  #typeList(offset: number): string[] | null {
    if (offset === 0) return []; // no parameters
    const size = this.#u4(offset);
    if (size === null || size > DEX_MAX_PARAMETERS) return null;
    const descriptors: string[] = [];
    for (let i = 0; i < size; i += 1) {
      const at = offset + 4 + i * 2;
      if (at + 2 > this.bytes.length) return null;
      const descriptor = this.typeDescriptor(this.view.getUint16(at, true));
      if (descriptor === null) return null;
      descriptors.push(descriptor);
    }
    return descriptors;
  }
}
