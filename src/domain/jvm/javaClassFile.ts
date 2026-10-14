/**
 * Dependency-free structural reader for JVM `.class` files (JVMS §4).
 *
 * Scope: frame the class file — magic, version, constant pool, access flags,
 * this/super class, interfaces, fields, methods, and each attribute's name plus
 * its raw `info` bytes. Interpretation of specific attributes (SourceFile,
 * LineNumberTable, LocalVariableTable, LocalVariableTypeTable,
 * SourceDebugExtension) is layered on top of this reader, not performed here.
 *
 * Every length-prefixed read is bounded against the buffer before allocation;
 * malformed or truncated input yields a tagged {@link JavaClassFileParseError}
 * via {@link Result}, never a thrown parse or an unchecked allocation.
 */
import { decodeModifiedUtf8 } from "../modifiedUtf8.js";
import { type Result, err, ok } from "../result.js";

/** Constant-pool tags consumed by this reader (JVMS Table 4.4-B). */
export const CONSTANT_TAG = {
  utf8: 1,
  integer: 3,
  float: 4,
  long: 5,
  double: 6,
  class: 7,
  string: 8,
  fieldref: 9,
  methodref: 10,
  interfaceMethodref: 11,
  nameAndType: 12,
  methodHandle: 15,
  methodType: 16,
  dynamic: 17,
  invokeDynamic: 18,
  module: 19,
  package: 20,
} as const;

/** A single constant-pool slot. Only fields later lookups need are retained; other tags stay opaque by tag. */
export type ConstantPoolEntry =
  | { readonly tag: 1; readonly kind: "utf8"; readonly value: string }
  | { readonly tag: 7; readonly kind: "class"; readonly nameIndex: number }
  | {
      readonly tag: 12;
      readonly kind: "name-and-type";
      readonly nameIndex: number;
      readonly descriptorIndex: number;
    }
  | {
      readonly kind: "opaque";
      readonly tag: number;
    }
  /** The unusable second slot consumed by a long/double entry (JVMS §4.4.5). */
  | { readonly kind: "unusable" };

/** A raw attribute: its resolved name and the exact `info` byte range, left undecoded. */
export interface JavaAttribute {
  readonly nameIndex: number;
  /** Resolved Utf8 name, or `null` when `nameIndex` is not a Utf8 constant. */
  readonly name: string | null;
  /** View over the class-file buffer; not copied. */
  readonly info: Uint8Array;
}

/** A field or method member with its access flags, identity indices, and raw attributes. */
export interface JavaMember {
  readonly accessFlags: number;
  readonly nameIndex: number;
  readonly name: string | null;
  readonly descriptorIndex: number;
  readonly descriptor: string | null;
  readonly attributes: readonly JavaAttribute[];
}

/** A framed class file. Index 0 of `constantPool` is a placeholder; real entries are 1-based (JVMS §4.1). */
export interface JavaClassFile {
  readonly minorVersion: number;
  readonly majorVersion: number;
  readonly constantPool: readonly ConstantPoolEntry[];
  readonly accessFlags: number;
  readonly thisClassIndex: number;
  readonly superClassIndex: number;
  readonly interfaceIndices: readonly number[];
  readonly fields: readonly JavaMember[];
  readonly methods: readonly JavaMember[];
  readonly attributes: readonly JavaAttribute[];
}

/** Why framing failed. Offsets are byte positions into the supplied buffer. */
export type JavaClassFileParseError =
  | { readonly kind: "bad-magic"; readonly offset: number }
  | {
      readonly kind: "truncated";
      readonly offset: number;
      readonly need: number;
      readonly have: number;
    }
  | {
      readonly kind: "unsupported-constant-tag";
      readonly offset: number;
      readonly tag: number;
    }
  | { readonly kind: "invalid-utf8"; readonly offset: number }
  | {
      readonly kind: "budget-exceeded";
      readonly offset: number;
      readonly resource: "interfaces" | "fields" | "methods" | "attributes";
      readonly declared: number;
      readonly remaining: number;
    };

const CLASS_FILE_MAGIC = 0xcafebabe;

/** Sequential, bounds-checked big-endian cursor over the class-file bytes. */
export class ByteCursor {
  offset = 0;
  constructor(private readonly bytes: Uint8Array) {}

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  private ensure(n: number): JavaClassFileParseError | null {
    if (this.remaining < n) {
      return {
        kind: "truncated",
        offset: this.offset,
        need: n,
        have: this.remaining,
      };
    }
    return null;
  }

  u1(): Result<number, JavaClassFileParseError> {
    const short = this.ensure(1);
    if (short) return err(short);
    const value = this.bytes[this.offset]!;
    this.offset += 1;
    return ok(value);
  }

  u2(): Result<number, JavaClassFileParseError> {
    const short = this.ensure(2);
    if (short) return err(short);
    const value =
      (this.bytes[this.offset]! << 8) | this.bytes[this.offset + 1]!;
    this.offset += 2;
    return ok(value);
  }

  u4(): Result<number, JavaClassFileParseError> {
    const short = this.ensure(4);
    if (short) return err(short);
    const value =
      this.bytes[this.offset]! * 0x1000000 +
      ((this.bytes[this.offset + 1]! << 16) |
        (this.bytes[this.offset + 2]! << 8) |
        this.bytes[this.offset + 3]!);
    this.offset += 4;
    return ok(value);
  }

  /** Return a view over `n` bytes and advance; no copy. */
  slice(n: number): Result<Uint8Array, JavaClassFileParseError> {
    const short = this.ensure(n);
    if (short) return err(short);
    const view = this.bytes.subarray(this.offset, this.offset + n);
    this.offset += n;
    return ok(view);
  }
}

/** Fixed `info` byte sizes for constant tags whose body is not length-prefixed. */
const FIXED_CONSTANT_SIZE: Readonly<Record<number, number>> = {
  [CONSTANT_TAG.integer]: 4,
  [CONSTANT_TAG.float]: 4,
  [CONSTANT_TAG.long]: 8,
  [CONSTANT_TAG.double]: 8,
  [CONSTANT_TAG.class]: 2,
  [CONSTANT_TAG.string]: 2,
  [CONSTANT_TAG.fieldref]: 4,
  [CONSTANT_TAG.methodref]: 4,
  [CONSTANT_TAG.interfaceMethodref]: 4,
  [CONSTANT_TAG.nameAndType]: 4,
  [CONSTANT_TAG.methodHandle]: 3,
  [CONSTANT_TAG.methodType]: 2,
  [CONSTANT_TAG.dynamic]: 4,
  [CONSTANT_TAG.invokeDynamic]: 4,
  [CONSTANT_TAG.module]: 2,
  [CONSTANT_TAG.package]: 2,
};

/** Resolve a constant-pool index to its Utf8 string, or `null` when it is not a Utf8 entry. */
export const resolveConstantUtf8 = (
  pool: readonly ConstantPoolEntry[],
  index: number,
): string | null => {
  const entry = pool[index];
  return entry && entry.kind === "utf8" ? entry.value : null;
};

const parseConstantPool = (
  cursor: ByteCursor,
): Result<ConstantPoolEntry[], JavaClassFileParseError> => {
  const countResult = cursor.u2();
  if (!countResult.ok) return countResult;
  const count = countResult.value;
  // Constant pool is indexed 1..count-1; slot 0 is a reserved placeholder.
  const pool: ConstantPoolEntry[] = [{ kind: "opaque", tag: 0 }];
  for (let index = 1; index < count; index += 1) {
    const tagResult = cursor.u1();
    if (!tagResult.ok) return tagResult;
    const tag = tagResult.value;
    const tagOffset = cursor.offset - 1;
    if (tag === CONSTANT_TAG.utf8) {
      const lenResult = cursor.u2();
      if (!lenResult.ok) return lenResult;
      const bytesResult = cursor.slice(lenResult.value);
      if (!bytesResult.ok) return bytesResult;
      const text = decodeModifiedUtf8(bytesResult.value);
      if (text === null)
        return err({ kind: "invalid-utf8", offset: tagOffset });
      pool.push({ tag: 1, kind: "utf8", value: text });
      continue;
    }
    if (tag === CONSTANT_TAG.class) {
      const nameIndex = cursor.u2();
      if (!nameIndex.ok) return nameIndex;
      pool.push({ tag: 7, kind: "class", nameIndex: nameIndex.value });
      continue;
    }
    if (tag === CONSTANT_TAG.nameAndType) {
      const nameIndex = cursor.u2();
      if (!nameIndex.ok) return nameIndex;
      const descriptorIndex = cursor.u2();
      if (!descriptorIndex.ok) return descriptorIndex;
      pool.push({
        tag: 12,
        kind: "name-and-type",
        nameIndex: nameIndex.value,
        descriptorIndex: descriptorIndex.value,
      });
      continue;
    }
    const fixed = FIXED_CONSTANT_SIZE[tag];
    if (fixed === undefined) {
      return err({ kind: "unsupported-constant-tag", offset: tagOffset, tag });
    }
    const skip = cursor.slice(fixed);
    if (!skip.ok) return skip;
    pool.push({ kind: "opaque", tag });
    // Long and Double occupy two pool slots; the next is unusable (JVMS §4.4.5).
    if (tag === CONSTANT_TAG.long || tag === CONSTANT_TAG.double) {
      pool.push({ kind: "unusable" });
      index += 1;
    }
  }
  return ok(pool);
};

/** Read an `attributes_count`-prefixed attribute list from the cursor's current position. */
export const parseAttributes = (
  cursor: ByteCursor,
  pool: readonly ConstantPoolEntry[],
): Result<JavaAttribute[], JavaClassFileParseError> => {
  const countResult = cursor.u2();
  if (!countResult.ok) return countResult;
  const count = countResult.value;
  const attributes: JavaAttribute[] = [];
  for (let i = 0; i < count; i += 1) {
    const nameIndex = cursor.u2();
    if (!nameIndex.ok) return nameIndex;
    const lengthResult = cursor.u4();
    if (!lengthResult.ok) return lengthResult;
    if (lengthResult.value > cursor.remaining) {
      return err({
        kind: "budget-exceeded",
        offset: cursor.offset,
        resource: "attributes",
        declared: lengthResult.value,
        remaining: cursor.remaining,
      });
    }
    const info = cursor.slice(lengthResult.value);
    if (!info.ok) return info;
    attributes.push({
      nameIndex: nameIndex.value,
      name: resolveConstantUtf8(pool, nameIndex.value),
      info: info.value,
    });
  }
  return ok(attributes);
};

const parseMembers = (
  cursor: ByteCursor,
  pool: readonly ConstantPoolEntry[],
  resource: "fields" | "methods",
): Result<JavaMember[], JavaClassFileParseError> => {
  const countResult = cursor.u2();
  if (!countResult.ok) return countResult;
  const count = countResult.value;
  // Each member is at least 8 bytes before its attributes; reject an impossible count up front.
  if (count * 8 > cursor.remaining) {
    return err({
      kind: "budget-exceeded",
      offset: cursor.offset,
      resource,
      declared: count,
      remaining: cursor.remaining,
    });
  }
  const members: JavaMember[] = [];
  for (let i = 0; i < count; i += 1) {
    const accessFlags = cursor.u2();
    if (!accessFlags.ok) return accessFlags;
    const nameIndex = cursor.u2();
    if (!nameIndex.ok) return nameIndex;
    const descriptorIndex = cursor.u2();
    if (!descriptorIndex.ok) return descriptorIndex;
    const attributes = parseAttributes(cursor, pool);
    if (!attributes.ok) return attributes;
    members.push({
      accessFlags: accessFlags.value,
      nameIndex: nameIndex.value,
      name: resolveConstantUtf8(pool, nameIndex.value),
      descriptorIndex: descriptorIndex.value,
      descriptor: resolveConstantUtf8(pool, descriptorIndex.value),
      attributes: attributes.value,
    });
  }
  return ok(members);
};

/** Frame a `.class` file. The returned attribute `info` views share the input buffer. */
export const parseJavaClassFile = (
  bytes: Uint8Array,
): Result<JavaClassFile, JavaClassFileParseError> => {
  const cursor = new ByteCursor(bytes);

  const magic = cursor.u4();
  if (!magic.ok) return magic;
  if (magic.value !== CLASS_FILE_MAGIC) {
    return err({ kind: "bad-magic", offset: 0 });
  }

  const minorVersion = cursor.u2();
  if (!minorVersion.ok) return minorVersion;
  const majorVersion = cursor.u2();
  if (!majorVersion.ok) return majorVersion;

  const pool = parseConstantPool(cursor);
  if (!pool.ok) return pool;

  const accessFlags = cursor.u2();
  if (!accessFlags.ok) return accessFlags;
  const thisClassIndex = cursor.u2();
  if (!thisClassIndex.ok) return thisClassIndex;
  const superClassIndex = cursor.u2();
  if (!superClassIndex.ok) return superClassIndex;

  const interfaceCount = cursor.u2();
  if (!interfaceCount.ok) return interfaceCount;
  if (interfaceCount.value * 2 > cursor.remaining) {
    return err({
      kind: "budget-exceeded",
      offset: cursor.offset,
      resource: "interfaces",
      declared: interfaceCount.value,
      remaining: cursor.remaining,
    });
  }
  const interfaceIndices: number[] = [];
  for (let i = 0; i < interfaceCount.value; i += 1) {
    const ref = cursor.u2();
    if (!ref.ok) return ref;
    interfaceIndices.push(ref.value);
  }

  const fields = parseMembers(cursor, pool.value, "fields");
  if (!fields.ok) return fields;
  const methods = parseMembers(cursor, pool.value, "methods");
  if (!methods.ok) return methods;
  const attributes = parseAttributes(cursor, pool.value);
  if (!attributes.ok) return attributes;

  return ok({
    minorVersion: minorVersion.value,
    majorVersion: majorVersion.value,
    constantPool: pool.value,
    accessFlags: accessFlags.value,
    thisClassIndex: thisClassIndex.value,
    superClassIndex: superClassIndex.value,
    interfaceIndices,
    fields: fields.value,
    methods: methods.value,
    attributes: attributes.value,
  });
};
