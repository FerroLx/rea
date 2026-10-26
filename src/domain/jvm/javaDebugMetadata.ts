/**
 * Decode the compiler-emitted debug attributes relevant to debugging readiness
 * (JVMS §4.7.10–4.7.14) from a framed {@link JavaClassFile}:
 * `SourceFile`, `SourceDebugExtension`, `LineNumberTable`, `LocalVariableTable`
 * and `LocalVariableTypeTable`.
 *
 * This module interprets attribute `info` bytes that {@link parseJavaClassFile}
 * framed but left undecoded. It never executes Java, resolves source URLs, or
 * claims that any source matches a declared `SourceFile`. `SourceDebugExtension`
 * stays opaque — only its presence and size are reported. Facts are preserved
 * on partial failure: a table that runs short is reported `malformed` with the
 * entries recovered before the short read, not discarded.
 */
import {
  ByteCursor,
  type ConstantPoolEntry,
  type JavaClassFile,
  type JavaMember,
  attributeBudget,
  constantUtf8JsonBound,
  frameAttributes,
  RETAINED_ATTRIBUTES,
  resolveConstantUtf8,
} from "./javaClassFile.js";
import {
  JAVA_5_MAJOR_VERSION,
  isLegalFieldDescriptor,
  isLegalFieldName,
} from "./javaDescriptor.js";
import {
  decodeInstructionBoundaries,
  SPLIT_VERIFIER_MAJOR_VERSION,
} from "./javaBytecode.js";

/**
 * Whether a named attribute was found and whether it decoded cleanly.
 * `unread` means the table could not be looked for: an earlier sibling
 * attribute in the same `Code` attribute was malformed, so framing stopped
 * before reaching it, or the method repeats its `Code` attribute so no body is
 * chosen. It is unknown, never `absent`.
 */
export type AttributePresence = "absent" | "present" | "malformed" | "unread";

/** A decoded debug table with the entries recovered and how fully it was read. */
export interface DebugTable<T> {
  readonly presence: AttributePresence;
  /** The attribute's self-declared entry count, or 0 when the attribute is absent. */
  readonly declaredCount: number;
  readonly entries: readonly T[];
}

export interface LineNumberEntry {
  readonly startPc: number;
  readonly lineNumber: number;
  /** `startPc` is not an index into the method's code array (JVMS §4.7.12). */
  readonly outOfRange: boolean;
}

/**
 * Where a local-variable scope `[startPc, startPc+length)` lies in its code.
 * - `aligned`: inside the code, starting at an instruction and ending at one
 *   or at `code_length` (checked from class version 51, as HotSpot does).
 * - `in-code`: inside the code; instruction boundaries are not checked
 *   because HotSpot does not check them below class version 51.
 * - `misaligned`: inside the code, but the start or end falls inside an
 *   instruction; HotSpot rejects the class (class version 51 and later).
 * - `out-of-range`: starts at or after `code_length`, or ends past it.
 * - `unknown`: inside the code, but the instruction stream does not decode,
 *   so its boundaries are unknown (HotSpot's verifier rejects that method).
 */
export type LocalScope =
  | "aligned"
  | "in-code"
  | "misaligned"
  | "out-of-range"
  | "unknown";

export interface LocalVariableEntry {
  readonly startPc: number;
  readonly length: number;
  readonly nameIndex: number;
  readonly name: string | null;
  readonly descriptorIndex: number;
  readonly descriptor: string | null;
  /** The local-variable array slot; wide (long/double) locals occupy this slot and the next. */
  readonly slot: number;
  readonly scope: LocalScope;
}

export interface LocalVariableTypeEntry {
  readonly startPc: number;
  readonly length: number;
  readonly nameIndex: number;
  readonly name: string | null;
  readonly signatureIndex: number;
  readonly signature: string | null;
  readonly slot: number;
  readonly scope: LocalScope;
}

/** Overall debugging-readiness of one method's body. */
export type MethodDebugState =
  // Line and local-variable tables both decoded; or line numbers decoded and
  // max_locals is 0, so no local can exist and a LocalVariableTable is not
  // applicable (javac -g emits none for such a method).
  | "present"
  // One table present, the other absent. With max_locals > 0 an absent
  // LocalVariableTable may also mean the method has only compiler-synthetic
  // locals, which javac -g does not name.
  | "partial"
  | "stripped" // a body exists but carries neither table (e.g. javac -g:none)
  | "malformed" // a present table failed to decode fully
  | "not-applicable"; // no Code attribute (native/abstract, or no body)

export interface MethodDebugMetadata {
  readonly name: string | null;
  readonly descriptor: string | null;
  readonly state: MethodDebugState;
  readonly hasCode: boolean;
  /** The Code attribute's max_locals, or null with no (readable) Code header. */
  readonly maxLocals: number | null;
  readonly lineNumbers: DebugTable<LineNumberEntry>;
  readonly localVariables: DebugTable<LocalVariableEntry>;
  readonly localVariableTypes: DebugTable<LocalVariableTypeEntry>;
  /**
   * Slots that appear in more than one `LocalVariableTable` entry. Reuse is
   * legal and does not imply error, but a reused slot may denote different
   * variables across disjoint scope ranges, so it is surfaced, not collapsed.
   */
  readonly reusedSlots: readonly number[];
}

export interface ClassDebugMetadata {
  readonly sourceFile: {
    readonly presence: Exclude<AttributePresence, "unread">;
    readonly name: string | null;
  };
  readonly sourceDebugExtension: {
    readonly presence: Exclude<AttributePresence, "unread">;
    /**
     * Byte length of the opaque extension, or 0 unless `present` (a repeated
     * extension is `malformed`). The bytes are never interpreted here.
     */
    readonly byteLength: number;
  };
  readonly methods: readonly MethodDebugMetadata[];
}

type NamedAttribute = {
  readonly name: string;
  readonly info: Uint8Array;
};

/**
 * The one occurrence of an attribute JVMS permits at most once (Code,
 * SourceFile, SourceDebugExtension). A repeated occurrence is `duplicate`:
 * HotSpot rejects the class, and which occurrence is meant is unknown, so no
 * occurrence is chosen.
 */
type SingleAttribute =
  | { readonly kind: "absent" }
  | { readonly kind: "one"; readonly info: Uint8Array }
  | { readonly kind: "duplicate" };

const singleAttribute = (
  attributes: readonly NamedAttribute[],
  name: string,
): SingleAttribute => {
  const found = attributes.filter((a) => a.name === name);
  if (found.length === 0) return { kind: "absent" };
  return found.length === 1
    ? { kind: "one", info: found[0]!.info }
    : { kind: "duplicate" };
};

/**
 * Every matching attribute's info, in order. JVMS §4.7.12–14 permit multiple
 * LineNumberTable / LocalVariableTable / LocalVariableTypeTable attributes in
 * one Code attribute; the full table is their union.
 */
const collectAttributes = (
  attributes: readonly NamedAttribute[],
  name: string,
): readonly Uint8Array[] =>
  attributes.filter((a) => a.name === name).map((a) => a.info);

/**
 * Decode a fixed-stride table, merging every occurrence of a repeatable
 * attribute into one table. Reads up to each occurrence's self-declared count,
 * stopping early if its buffer runs short; a short read, trailing bytes, or an
 * entry that violates its attribute's constraints (`valid`) marks the whole
 * table `malformed` while keeping every entry decoded.
 */
const decodeTable = <T>(
  infos: readonly Uint8Array[],
  stride: number,
  decodeEntry: (cursor: ByteCursor) => T,
  valid: (entry: T) => boolean = () => true,
): DebugTable<T> => {
  if (infos.length === 0)
    return { presence: "absent", declaredCount: 0, entries: [] };
  const entries: T[] = [];
  let declaredCount = 0;
  let malformed = false;
  for (const info of infos) {
    const cursor = new ByteCursor(info);
    const countResult = cursor.u2();
    if (!countResult.ok) {
      malformed = true;
      continue;
    }
    declaredCount += countResult.value;
    let short = false;
    for (let i = 0; i < countResult.value; i += 1) {
      if (cursor.remaining < stride) {
        short = true;
        break;
      }
      const entry = decodeEntry(cursor);
      if (!valid(entry)) malformed = true;
      entries.push(entry);
    }
    // A short read, or trailing bytes past the declared entries, is malformed
    // rather than silently ignored (JVMS fixes attribute_length exactly).
    if (short || cursor.remaining !== 0) malformed = true;
  }
  return {
    presence: malformed ? "malformed" : "present",
    declaredCount,
    entries,
  };
};

const u2 = (cursor: ByteCursor): number => {
  const result = cursor.u2();
  // Guarded by the `remaining >= stride` check in decodeTable before each entry.
  return result.ok ? result.value : 0;
};

const decodeLineNumberTable = (
  infos: readonly Uint8Array[],
  codeLength: number,
): DebugTable<LineNumberEntry> =>
  decodeTable(
    infos,
    4,
    (cursor) => {
      const startPc = u2(cursor);
      return {
        startPc,
        lineNumber: u2(cursor),
        outOfRange: startPc >= codeLength,
      };
    },
    // HotSpot rejects the class ("Invalid pc in LineNumberTable").
    (entry) => !entry.outOfRange,
  );

/** Classifies a local-variable scope against one method's code. */
type ScopeClassifier = (startPc: number, length: number) => LocalScope;

/**
 * Build one method's scope classifier. HotSpot's class-file parser rejects a
 * scope outside the code ("Invalid start_pc" / "Invalid length"); from class
 * version 51 its verifier also rejects one whose start, or whose end short of
 * `code_length`, is not an instruction start ("Illegal local variable table
 * start_pc" / "length"), for `LocalVariableTable` rows directly and for
 * `LocalVariableTypeTable` rows through the row each must match. The code is
 * decoded at most once, on the first in-range scope, and never for a class
 * below version 51 or a method without one.
 */
const scopeClassifier = (
  code: Uint8Array,
  majorVersion: number,
): ScopeClassifier => {
  const checksBoundaries = majorVersion >= SPLIT_VERIFIER_MAJOR_VERSION;
  let boundaries: ReturnType<typeof decodeInstructionBoundaries> | undefined;
  return (startPc, length) => {
    const end = startPc + length;
    if (startPc >= code.length || end > code.length) return "out-of-range";
    if (!checksBoundaries) return "in-code";
    boundaries ??= decodeInstructionBoundaries(code);
    if (!boundaries.ok) return "unknown";
    return boundaries.value.startsAt(startPc) &&
      (end === code.length || boundaries.value.startsAt(end))
      ? "aligned"
      : "misaligned";
  };
};

/** Only a scope known to lie on the code's instructions, or in it below 51, is valid. */
const scopeValid = (scope: LocalScope): boolean =>
  scope === "aligned" || scope === "in-code";

const decodeLocalVariableTable = (
  infos: readonly Uint8Array[],
  pool: readonly ConstantPoolEntry[],
  scopeOf: ScopeClassifier,
  maxLocals: number,
  majorVersion: number,
): DebugTable<LocalVariableEntry> =>
  decodeTable(
    infos,
    10,
    (cursor) => {
      const startPc = u2(cursor);
      const length = u2(cursor);
      const nameIndex = u2(cursor);
      const descriptorIndex = u2(cursor);
      const slot = u2(cursor);
      return {
        startPc,
        length,
        nameIndex,
        name: resolveConstantUtf8(pool, nameIndex),
        descriptorIndex,
        descriptor: resolveConstantUtf8(pool, descriptorIndex),
        slot,
        scope: scopeOf(startPc, length),
      };
    },
    // HotSpot rejects an out-of-code or misaligned scope as it rejects an
    // out-of-frame slot or an illegal descriptor; an unknown scope is never
    // reported valid.
    (entry) =>
      scopeValid(entry.scope) &&
      legalLocalName(entry.name, majorVersion) &&
      entry.descriptor !== null &&
      isLegalFieldDescriptor(entry.descriptor, majorVersion) &&
      slotInFrame(
        entry.slot +
          (entry.descriptor === "J" || entry.descriptor === "D" ? 1 : 0),
        maxLocals,
      ),
  );

/**
 * JVMS §4.7.13: a local's slot, and for a `J` or `D` local also the next slot,
 * must index the frame's `max_locals` local variables. HotSpot rejects a class
 * that violates this ("Invalid index ... in LocalVariableTable"), so the table
 * is malformed while the raw slot is kept.
 */
const slotInFrame = (lastSlot: number, maxLocals: number): boolean =>
  lastSlot < maxLocals;

/**
 * JVMS §4.7.13–14: name_index and descriptor/signature_index must each name a
 * CONSTANT_Utf8 entry. An index that does not (0, out of range, or another
 * constant kind) is kept as `null` and makes the table malformed, as does a
 * name HotSpot rejects as an illegal field name.
 */
const legalLocalName = (name: string | null, majorVersion: number): boolean =>
  name !== null && isLegalFieldName(name, majorVersion);

const decodeLocalVariableTypeTable = (
  infos: readonly Uint8Array[],
  pool: readonly ConstantPoolEntry[],
  scopeOf: ScopeClassifier,
  maxLocals: number,
  majorVersion: number,
): DebugTable<LocalVariableTypeEntry> =>
  decodeTable(
    infos,
    10,
    (cursor) => {
      const startPc = u2(cursor);
      const length = u2(cursor);
      const nameIndex = u2(cursor);
      const signatureIndex = u2(cursor);
      const slot = u2(cursor);
      return {
        startPc,
        length,
        nameIndex,
        name: resolveConstantUtf8(pool, nameIndex),
        signatureIndex,
        signature: resolveConstantUtf8(pool, signatureIndex),
        slot,
        scope: scopeOf(startPc, length),
      };
    },
    // A signature names no wide primitive, so only the entry's own slot is
    // checked, and HotSpot does not check the signature's grammar.
    (entry) =>
      legalLocalName(entry.name, majorVersion) &&
      entry.signature !== null &&
      scopeValid(entry.scope) &&
      slotInFrame(entry.slot, maxLocals),
  );

/** Advance past the fixed Code header and exception table to its sub-attributes, keeping max_locals and the code array. */
const seekCodeSubAttributes = (
  attribute: Uint8Array,
): {
  readonly cursor: ByteCursor;
  readonly maxLocals: number;
  /** The `code` array, a view of the attribute; its length is `code_length`. */
  readonly code: Uint8Array;
} | null => {
  const cursor = new ByteCursor(attribute);
  if (!cursor.u2().ok) return null; // max_stack
  const maxLocals = cursor.u2();
  if (!maxLocals.ok) return null;
  const codeLength = cursor.u4();
  if (!codeLength.ok) return null;
  const code = cursor.slice(codeLength.value);
  if (!code.ok) return null;
  const exceptionTableLength = cursor.u2();
  if (
    !exceptionTableLength.ok ||
    !cursor.slice(exceptionTableLength.value * 8).ok
  )
    return null;
  return { cursor, maxLocals: maxLocals.value, code: code.value };
};

const computeReusedSlots = (
  entries: readonly LocalVariableEntry[],
): number[] => {
  const counts = new Map<number, number>();
  for (const entry of entries)
    counts.set(entry.slot, (counts.get(entry.slot) ?? 0) + 1);
  return [...counts.entries()]
    .filter(([, count]) => count > 1)
    .map(([slot]) => slot)
    .sort((a, b) => a - b);
};

const classifyMethod = (
  hasCode: boolean,
  maxLocals: number,
  lineNumbers: DebugTable<LineNumberEntry>,
  localVariables: DebugTable<LocalVariableEntry>,
  localVariableTypes: DebugTable<LocalVariableTypeEntry>,
  majorVersion: number,
): MethodDebugState => {
  if (!hasCode) return "not-applicable";
  if (
    lineNumbers.presence === "malformed" ||
    localVariables.presence === "malformed" ||
    // Before version 49 the JVM ignores LocalVariableTypeTable as an
    // unknown attribute, so its table cannot make the method malformed.
    (localVariableTypes.presence === "malformed" &&
      majorVersion >= JAVA_5_MAJOR_VERSION)
  ) {
    return "malformed";
  }
  const hasLine = lineNumbers.presence === "present";
  // With max_locals 0 no local (not even `this` or a parameter) exists, so an
  // absent LocalVariableTable is not missing debug information.
  if (maxLocals === 0 && localVariables.presence === "absent")
    return hasLine ? "present" : "stripped";
  const hasLocals = localVariables.presence === "present";
  if (hasLine && hasLocals) return "present";
  if (!hasLine && !hasLocals) return "stripped";
  return "partial";
};

/** JVMS §4.7.3: `code_length` must be greater than zero and less than 65536. */
const MAX_CODE_LENGTH = 65_535;

/** Decode one method's debug tables from its `Code` attribute, if any. */
export const decodeMethodDebugMetadata = (
  method: JavaMember,
  pool: readonly ConstantPoolEntry[],
  majorVersion: number,
): MethodDebugMetadata => {
  const codeAttribute = singleAttribute(method.attributes, "Code");
  const absentTable = <T>(
    presence: "absent" | "unread" = "absent",
  ): DebugTable<T> => ({
    presence,
    declaredCount: 0,
    entries: [],
  });
  if (codeAttribute.kind === "duplicate")
    // More than one body: none is chosen, so no table can be looked for.
    return {
      name: method.name,
      descriptor: method.descriptor,
      state: "malformed",
      hasCode: true,
      maxLocals: null,
      lineNumbers: absentTable("unread"),
      localVariables: absentTable("unread"),
      localVariableTypes: absentTable("unread"),
      reusedSlots: [],
    };
  if (codeAttribute.kind === "absent") {
    return {
      name: method.name,
      descriptor: method.descriptor,
      state: "not-applicable",
      hasCode: false,
      maxLocals: null,
      lineNumbers: absentTable(),
      localVariables: absentTable(),
      localVariableTypes: absentTable(),
      reusedSlots: [],
    };
  }

  const seeked = seekCodeSubAttributes(codeAttribute.info);
  // Keep every table framed before a malformed sibling; tables framing never
  // reached are `unread`, not `absent`.
  const framed = seeked
    ? frameAttributes(seeked.cursor, pool, RETAINED_ATTRIBUTES.code)
    : null;
  const attributes = framed?.attributes ?? [];
  // JVMS fixes attribute_length exactly: bytes left after the declared
  // sub-attributes mean the Code attribute is malformed (as in decodeTable),
  // and any sub-attribute they hide is unknown, so absent tables are unread.
  // A code_length outside 1..65535 makes HotSpot reject the method too.
  const codeMalformed =
    seeked === null ||
    seeked.code.length < 1 ||
    seeked.code.length > MAX_CODE_LENGTH ||
    (framed?.error ?? null) !== null ||
    seeked.cursor.remaining !== 0;
  const code = seeked?.code ?? new Uint8Array(0);
  const codeLength = code.length;
  const maxLocals = seeked?.maxLocals ?? 0;
  // One classifier per method: both local tables share its single decode.
  const scopeOf = scopeClassifier(code, majorVersion);
  const orUnread = <T>(table: DebugTable<T>): DebugTable<T> =>
    codeMalformed && table.presence === "absent"
      ? { ...table, presence: "unread" }
      : table;

  const lineNumbers = orUnread(
    decodeLineNumberTable(
      collectAttributes(attributes, "LineNumberTable"),
      codeLength,
    ),
  );
  const localVariables = orUnread(
    decodeLocalVariableTable(
      collectAttributes(attributes, "LocalVariableTable"),
      pool,
      scopeOf,
      maxLocals,
      majorVersion,
    ),
  );
  const localVariableTypes = orUnread(
    decodeLocalVariableTypeTable(
      collectAttributes(attributes, "LocalVariableTypeTable"),
      pool,
      scopeOf,
      maxLocals,
      majorVersion,
    ),
  );

  const state = codeMalformed
    ? "malformed"
    : classifyMethod(
        true,
        seeked.maxLocals,
        lineNumbers,
        localVariables,
        localVariableTypes,
        majorVersion,
      );

  return {
    name: method.name,
    descriptor: method.descriptor,
    state,
    hasCode: true,
    maxLocals: seeked?.maxLocals ?? null,
    lineNumbers,
    localVariables,
    localVariableTypes,
    reusedSlots: computeReusedSlots(localVariables.entries),
  };
};

/** Fixed byte strides of the repeatable debug tables (JVMS §4.7.12–14). */
const DEBUG_TABLE_STRIDES: ReadonlyArray<readonly [string, number]> = [
  ["LineNumberTable", 4],
  ["LocalVariableTable", 10],
  ["LocalVariableTypeTable", 10],
];

/** Serialized overhead per projected object (keys, numbers, punctuation). */
const METHOD_OVERHEAD = 320;
const LINE_ENTRY_OVERHEAD = 72;
const LOCAL_ENTRY_OVERHEAD = 160;

/** What {@link decodeClassDebugMetadata} would materialise, projected without materialising it. */
export interface DebugOutputProjection {
  /** Projected objects: one per method plus every debug-table entry. */
  readonly entries: number;
  /** Estimated serialized bytes, counting every repeated constant-pool string. */
  readonly encodedBytes: number;
  /** Set when framing the debug tables exceeded the retained-attribute budget. */
  readonly attributeBudgetExceeded: boolean;
}

/**
 * Project the size of the debug-metadata report before building it. Reads each
 * table's `count` prefix and its constant-pool indices in place — no entry
 * objects — and charges every reference with the JSON-encoded length of the
 * string it names, so a name shared by thousands of entries is counted
 * thousands of times (`JSON.stringify` would expand it that many times).
 * String sizes are upper bounds computed once per constant from its bytes,
 * without decoding, and the walk stops once `stopAbove` is exceeded.
 * Code sub-attributes are framed against `attributeLimit`.
 */
export const projectDebugOutput = (
  cls: JavaClassFile,
  attributeLimit: number,
  stopAbove: { readonly entries: number; readonly encodedBytes: number } = {
    entries: Number.POSITIVE_INFINITY,
    encodedBytes: Number.POSITIVE_INFINITY,
  },
): DebugOutputProjection => {
  // Bounded from the bytes, never decoded: a refused class decodes nothing.
  // Each constant's bound is computed once; a name shared by millions of rows
  // is scanned once, not once per row.
  const bounds = new Map<number, number>();
  const stringBytes = (index: number): number => {
    let bound = bounds.get(index);
    if (bound === undefined) {
      bound = constantUtf8JsonBound(cls.constantPool, index);
      bounds.set(index, bound);
    }
    return bound;
  };
  const budget = attributeBudget(attributeLimit);
  let entries = cls.methods.length;
  let encodedBytes = 4096;
  // Stop as soon as either running total passes the caller's limit: the
  // answer is already "refuse", and finishing the walk is wasted work.
  const over = (): boolean =>
    entries > stopAbove.entries || encodedBytes > stopAbove.encodedBytes;
  for (const method of cls.methods) {
    if (over()) break;
    encodedBytes +=
      METHOD_OVERHEAD +
      stringBytes(method.nameIndex) +
      stringBytes(method.descriptorIndex);
    const code = singleAttribute(method.attributes, "Code");
    if (code.kind !== "one") continue;
    const seeked = seekCodeSubAttributes(code.info);
    if (seeked === null) continue;
    const framed = frameAttributes(
      seeked.cursor,
      cls.constantPool,
      RETAINED_ATTRIBUTES.code,
      budget,
    );
    if (framed.error?.kind === "retained-attribute-budget")
      return { entries, encodedBytes, attributeBudgetExceeded: true };
    for (const [name, stride] of DEBUG_TABLE_STRIDES)
      for (const info of collectAttributes(framed.attributes, name)) {
        if (info.length < 2) continue;
        const declared = (info[0]! << 8) | info[1]!;
        const count = Math.min(
          declared,
          Math.floor((info.length - 2) / stride),
        );
        entries += count;
        if (stride === 4) {
          encodedBytes += count * LINE_ENTRY_OVERHEAD;
          continue;
        }
        // name_index and descriptor/signature_index sit at +4 and +6.
        for (let i = 0; i < count && !over(); i += 1) {
          const at = 2 + i * stride;
          encodedBytes +=
            LOCAL_ENTRY_OVERHEAD +
            stringBytes((info[at + 4]! << 8) | info[at + 5]!) +
            stringBytes((info[at + 6]! << 8) | info[at + 7]!);
        }
      }
  }
  return { entries, encodedBytes, attributeBudgetExceeded: false };
};

/** Decode class-level debug attributes and every method's debug tables. */
export const decodeClassDebugMetadata = (
  cls: JavaClassFile,
): ClassDebugMetadata => {
  const sourceFileAttribute = singleAttribute(cls.attributes, "SourceFile");
  let sourceFile: ClassDebugMetadata["sourceFile"] =
    sourceFileAttribute.kind === "duplicate"
      ? { presence: "malformed", name: null }
      : { presence: "absent", name: null };
  if (sourceFileAttribute.kind === "one") {
    const sourceFileInfo = sourceFileAttribute.info;
    const cursor = new ByteCursor(sourceFileInfo);
    const indexResult = cursor.u2();
    // SourceFile_attribute is a single u2 index that must name a
    // CONSTANT_Utf8 entry (JVMS §4.7.10): any other length or target is
    // malformed, not a present attribute with an unknown name.
    const name =
      indexResult.ok && sourceFileInfo.length === 2
        ? resolveConstantUtf8(cls.constantPool, indexResult.value)
        : null;
    sourceFile =
      name === null
        ? { presence: "malformed", name: null }
        : { presence: "present", name };
  }

  const sde = singleAttribute(cls.attributes, "SourceDebugExtension");
  const sourceDebugExtension: ClassDebugMetadata["sourceDebugExtension"] =
    sde.kind === "one"
      ? { presence: "present", byteLength: sde.info.length }
      : {
          presence: sde.kind === "absent" ? "absent" : "malformed",
          byteLength: 0,
        };

  return {
    sourceFile,
    sourceDebugExtension,
    methods: cls.methods.map((method) =>
      decodeMethodDebugMetadata(method, cls.constantPool, cls.majorVersion),
    ),
  };
};
