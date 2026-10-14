/**
 * Resolve names and type descriptors from a DEX file's string and type id pools
 * (Dalvik Executable format). A `string_id_item` is a u4 offset to a
 * `string_data_item` (`uleb128 utf16_size` then NUL-terminated modified UTF-8);
 * a `type_id_item` is a u4 index into the string pool. All lookups are bounded
 * and return `null` for an out-of-range index (including NO_INDEX = -1) or a
 * malformed/uncross-checked string, never a throw or a guess.
 */
import { decodeModifiedUtf8 } from "../modifiedUtf8.js";
import { DEX_NO_INDEX, DexCursor, type DexHeader } from "./dexFile.js";

export class DexStringResolver {
  private readonly view: DataView;
  constructor(
    private readonly bytes: Uint8Array,
    private readonly header: DexHeader,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  /** Resolve a string-pool index to its text, or `null` when absent/malformed. */
  string(index: number): string | null {
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
    // Modified UTF-8 runs to a NUL terminator; find it within the buffer.
    let end = cursor.offset;
    while (end < this.bytes.length && this.bytes[end] !== 0x00) end += 1;
    if (end >= this.bytes.length) return null; // unterminated
    const decoded = decodeModifiedUtf8(this.bytes.subarray(cursor.offset, end));
    // A length that disagrees with the declared UTF-16 size is malformed.
    if (decoded === null || decoded.length !== utf16Size.value) return null;
    return decoded;
  }

  /** Resolve a type-pool index to its descriptor string (e.g. `Lcom/example/Foo;`). */
  typeDescriptor(index: number): string | null {
    if (index < 0 || index === DEX_NO_INDEX || index >= this.header.typeIdsSize)
      return null;
    const idOffset = this.header.typeIdsOff + index * 4;
    if (idOffset + 4 > this.bytes.length) return null;
    return this.string(this.view.getUint32(idOffset, true));
  }

  /** Bounded u4 read, or null past the end. */
  #u4(at: number): number | null {
    return at >= 0 && at + 4 <= this.bytes.length
      ? this.view.getUint32(at, true)
      : null;
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

  /** A `type_list` { size u4, list[size] of u2 type_idx }, resolved to descriptors. */
  #typeList(offset: number): string[] | null {
    if (offset === 0) return []; // no parameters
    const size = this.#u4(offset);
    if (size === null) return null;
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
