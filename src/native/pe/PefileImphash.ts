import { createHash } from "node:crypto";
import { setImmediate } from "node:timers/promises";

import { peOrdinalName } from "../../domain/native/peOrdinalNames.js";
import type { PeImageLayout } from "./PeImageLayout.js";
import { PeWorkExhausted, type PeWork } from "./PeImportTables.js";

/**
 * The import hash exactly as pefile 2024.8.26 computes it, as its own owner.
 *
 * REA reports imports as the Windows loader binds them (the lookup table).
 * Threat intelligence pivots on pefile's imphash, and pefile reads imports
 * differently: anti-abuse heuristics can discard a lookup table and read the
 * address table instead, a global symbol cap ends the walk, and unreadable or
 * invalid entries drop descriptors or names. This module reproduces
 * `parse_import_directory`, `parse_imports`, `get_import_table`,
 * `get_string_at_rva`, `get_data` and `get_imphash` for the import table only,
 * so the hash pivots against pefile and VirusTotal; it reports nothing else.
 */

const MAX_IMPORT_SYMBOLS = 0x2000;
const MAX_REPEATED_ADDRESSES = 15;
const MAX_ADDRESS_SPREAD = 128 * 2 ** 20;
const ADDR_4GB = 2n ** 32n;
const MAX_DLL_LENGTH = 0x200;
const MAX_IMPORT_NAME_LENGTH = 0x200;
const DESCRIPTOR_SIZE = 20;
const YIELD_INTERVAL = 4096;

/** pefile `allowed_filename` + path separators (`is_valid_dos_filename`). */
const DOS_FILENAME = /^[A-Za-z0-9!#$%&'()\-@^_`{}~+,.;=[\]:\\/]*$/;
/** pefile `is_valid_function_name` (letters, digits and `._?@$()<>`). */
const FUNCTION_NAME = /^[A-Za-z0-9._?@$()<>]*$/;

class PefileFormatError extends Error {}

interface Extent {
  readonly rva: number;
  readonly end: number;
  readonly offset: number;
  readonly rawEnd: number;
}

interface Walk {
  readonly bytes: Buffer;
  readonly layout: PeImageLayout;
  readonly work: PeWork;
  /** pefile's section extents, computed once. */
  readonly extents: readonly Extent[];
  /** pefile's `len(self.header)`, which is not SizeOfHeaders. */
  readonly headerLength: number;
  /** pefile's `__total_import_symbols`, shared by every table read. */
  symbols: number;
  sinceYield: number;
}

const charge = (walk: Walk, units: number): void => {
  walk.work.remaining -= units;
  if (walk.work.remaining < 0) throw new PeWorkExhausted(walk.work.limit);
};

const tick = async (walk: Walk): Promise<void> => {
  walk.sinceYield += 1;
  if (walk.sinceYield < YIELD_INTERVAL) return;
  walk.sinceYield = 0;
  await setImmediate();
  walk.work.signal?.throwIfAborted();
};

/**
 * pefile's section extents (`get_VirtualAddress_adj`,
 * `get_PointerToRawData_adj`, `contains_rva`): the virtual address rounded
 * down to the section alignment (the file alignment when that is below a
 * page), the raw pointer rounded down to 0x200 (kept when it equals the
 * virtual address under a sub-page alignment), the raw-or-virtual size (the
 * virtual size when the raw data runs past the file) capped at the next
 * section in table order, and reads ending at the unadjusted raw end.
 */
const sectionExtents = (bytes: Buffer, layout: PeImageLayout): Extent[] => {
  const pe = bytes.readUInt32LE(60);
  const sectionAlignment = bytes.readUInt32LE(pe + 24 + 32);
  const fileAlignment = bytes.readUInt32LE(pe + 24 + 36);
  const alignment =
    sectionAlignment < 0x1000 ? fileAlignment : sectionAlignment;
  // pefile sorts its sections by VirtualAddress (stable) before every
  // lookup, and caps each at the next one in that order.
  const sections = [...layout.sections].sort((a, b) => a.rva - b.rva);
  return sections.map((section, index) => {
    const virtualAddress =
      alignment !== 0 && section.rva % alignment !== 0
        ? alignment * Math.floor(section.rva / alignment)
        : section.rva;
    const pointer =
      sectionAlignment < 0x1000 && section.offset === section.rva
        ? section.rva
        : section.offset & ~0x1ff;
    let size =
      bytes.length - pointer < section.size
        ? section.virtualSize
        : Math.max(section.size, section.virtualSize);
    const next = sections[index + 1]?.rva;
    if (
      next !== undefined &&
      next > section.rva &&
      virtualAddress + size > next
    )
      size = next - virtualAddress;
    return {
      rva: virtualAddress,
      end: virtualAddress + size,
      offset: pointer,
      rawEnd: section.offset + section.size,
    };
  });
};

/**
 * pefile's header window: the bytes up to the end of the section table, or up
 * to the lowest 0x200-aligned raw pointer of a section when that is further.
 */
const pefileHeaderLength = (bytes: Buffer, layout: PeImageLayout): number => {
  const pe = bytes.readUInt32LE(60);
  const optionalSize = bytes.readUInt16LE(pe + 20);
  const tableEnd = pe + 24 + optionalSize + layout.sections.length * 40;
  const pointers = layout.sections
    .map((section) => section.offset)
    .filter((offset) => offset > 0)
    .map((offset) => offset & ~0x1ff);
  const lowest = pointers.length === 0 ? 0 : Math.min(...pointers);
  return Math.min(
    bytes.length,
    lowest === 0 || lowest < tableEnd ? tableEnd : lowest,
  );
};

/** pefile's section lookup (first section containing the RVA). */
const sectionOf = (walk: Walk, rva: number): Extent | undefined =>
  walk.extents.find((extent) => extent.rva <= rva && rva < extent.end);

/** pefile `PE.get_data(rva, length)`: section bytes, else header, else raw file. */
const dataAt = (walk: Walk, rva: number, length: number): Buffer => {
  const section = sectionOf(walk, rva);
  if (section !== undefined) {
    const offset = rva - section.rva + section.offset;
    const end = Math.min(offset + length, section.rawEnd);
    return walk.bytes.subarray(offset, Math.max(offset, end));
  }
  if (rva < walk.headerLength)
    return walk.bytes.subarray(rva, Math.min(rva + length, walk.headerLength));
  if (rva < walk.bytes.length) return walk.bytes.subarray(rva, rva + length);
  throw new PefileFormatError("data at RVA can't be fetched");
};

/** pefile `get_string_at_rva`: up to `max` bytes, cut at the first NUL. */
const stringAt = (walk: Walk, rva: number, max: number): string => {
  const section = sectionOf(walk, rva);
  let raw: Buffer;
  if (section !== undefined) {
    const offset = rva - section.rva + section.offset;
    const end = Math.min(offset + max, section.rawEnd);
    raw = walk.bytes.subarray(offset, Math.max(offset, end));
  } else raw = walk.bytes.subarray(rva, rva + max);
  charge(walk, raw.length + 1);
  const nul = raw.indexOf(0);
  return raw.toString("latin1", 0, nul === -1 ? raw.length : nul);
};

/** pefile `get_import_table`: `null` for unreadable data, `[]` when discarded. */
const importTable = async (
  walk: Walk,
  start: number,
  maxLength: number | null,
): Promise<bigint[] | null> => {
  const width = walk.layout.format === "pe32-plus" ? 8 : 4;
  const ordinalFlag = width === 8 ? 1n << 63n : 1n << 31n;
  const table: bigint[] = [];
  const seen32 = { set: new Set<bigint>(), min: -1n, max: -1n };
  const seen64 = { set: new Set<bigint>(), min: -1n, max: -1n };
  const spread = (s: typeof seen32): bigint =>
    s.min === -1n ? 0n : s.max - s.min;
  let repeated = 0;
  let rva = start;
  while (rva !== 0) {
    await tick(walk);
    charge(walk, 1);
    if (maxLength !== null && rva >= start + maxLength) break;
    if (walk.symbols > MAX_IMPORT_SYMBOLS) break;
    walk.symbols += 1;
    if (repeated >= MAX_REPEATED_ADDRESSES) return [];
    if (
      spread(seen32) > BigInt(MAX_ADDRESS_SPREAD) ||
      spread(seen64) > BigInt(MAX_ADDRESS_SPREAD)
    )
      return [];
    let data: Buffer;
    try {
      data = dataAt(walk, rva, width);
    } catch {
      return null;
    }
    if (data.length !== width) return null;
    const value =
      width === 8 ? data.readBigUInt64LE(0) : BigInt(data.readUInt32LE(0));
    if (value !== 0n && value >= BigInt(start) && value <= BigInt(rva)) break;
    if (value !== 0n) {
      if ((value & ordinalFlag) !== 0n) {
        if ((value & 0x7fffffffn) > 0xffffn) return [];
      } else {
        const s = value >= ADDR_4GB ? seen64 : seen32;
        if (s.set.has(value)) repeated += 1;
        s.set.add(value);
        if (s.min === -1n || value < s.min) s.min = value;
        if (s.max === -1n || value > s.max) s.max = value;
      }
    }
    if (value === 0n) break;
    rva += width;
    table.push(value);
  }
  return table;
};

/** One listed symbol: a lowercase-able name, or an ordinal to look up. */
type Listed = { readonly name: string } | { readonly ordinal: number };

/** pefile `parse_imports`; throws PefileFormatError where pefile aborts. */
const parseImports = async (
  walk: Walk,
  originalFirstThunk: number,
  firstThunk: number,
  maxLength: number,
): Promise<Listed[]> => {
  const ilt = await importTable(walk, originalFirstThunk, maxLength);
  const iat = await importTable(walk, firstThunk, maxLength);
  if ((iat === null || iat.length === 0) && (ilt === null || ilt.length === 0))
    return [];
  const table = ilt !== null && ilt.length > 0 ? ilt : iat;
  if (table === null) return [];
  const width = walk.layout.format === "pe32-plus" ? 8 : 4;
  const ordinalFlag = width === 8 ? 1n << 63n : 1n << 31n;
  const mask = width === 8 ? 0x7fffffffffffffffn : 0x7fffffffn;
  const listed: Listed[] = [];
  for (const entry of table) {
    await tick(walk);
    let ordinal: number | null = null;
    let name: string | null = null;
    if ((entry & ordinalFlag) !== 0n) ordinal = Number(entry & 0xffffn);
    else {
      const hintRva = Number(entry & mask);
      try {
        if (dataAt(walk, hintRva, 2).length < 2)
          throw new PefileFormatError("short hint");
        const read = stringAt(walk, hintRva + 2, MAX_IMPORT_NAME_LENGTH);
        name = FUNCTION_NAME.test(read) ? read : "*invalid*";
      } catch (cause) {
        if (!(cause instanceof PefileFormatError)) throw cause;
      }
    }
    if (ordinal === null && name === null)
      throw new PefileFormatError("Invalid entries, aborting parsing.");
    if (name === "*invalid*") continue;
    if (ordinal !== null && ordinal !== 0) listed.push({ ordinal });
    else if (name !== null && name !== "") listed.push({ name });
  }
  return listed;
};

/** pefile's imphash library name: `*invalid*`, or lowercased minus dll/ocx/sys. */
const libraryName = (dll: string): string => {
  const lower = dll.toLowerCase();
  const dot = lower.lastIndexOf(".");
  return dot !== -1 && ["dll", "ocx", "sys"].includes(lower.slice(dot + 1))
    ? lower.slice(0, dot)
    : lower;
};

/**
 * pefile's imphash of the import table, or null when pefile lists no import
 * (it returns "" then; REA reports null).
 */
export const pefileImphash = async (
  bytes: Buffer,
  layout: PeImageLayout,
  work: PeWork,
): Promise<string | null> => {
  const directory = layout.dataDirectory(1);
  if (directory === null || directory.rva === 0) return null;
  const walk: Walk = {
    bytes,
    layout,
    work,
    extents: sectionExtents(bytes, layout),
    headerLength: pefileHeaderLength(bytes, layout),
    symbols: 0,
    sinceYield: 0,
  };
  const parts: string[] = [];
  let errors = 0;
  let rva = directory.rva;
  for (;;) {
    await tick(walk);
    charge(walk, 1);
    let descriptor: Buffer;
    try {
      descriptor = dataAt(walk, rva, DESCRIPTOR_SIZE);
    } catch {
      break;
    }
    if (descriptor.length < DESCRIPTOR_SIZE) break;
    if (descriptor.every((byte) => byte === 0)) break;
    const originalFirstThunk = descriptor.readUInt32LE(0);
    const nameRva = descriptor.readUInt32LE(12);
    const firstThunk = descriptor.readUInt32LE(16);
    const fileOffset = descriptor.byteOffset - bytes.byteOffset;
    rva += DESCRIPTOR_SIZE;
    let maxLength = bytes.length - fileOffset;
    if (rva > originalFirstThunk || rva > firstThunk)
      maxLength = Math.max(rva - originalFirstThunk, rva - firstThunk);
    let listed: Listed[] = [];
    try {
      listed = await parseImports(
        walk,
        originalFirstThunk,
        firstThunk,
        maxLength,
      );
    } catch (cause) {
      if (!(cause instanceof PefileFormatError)) throw cause;
    }
    if (errors > 5) break;
    if (listed.length === 0) {
      errors += 1;
      continue;
    }
    const read = stringAt(walk, nameRva, MAX_DLL_LENGTH);
    const dll = DOS_FILENAME.test(read) ? read : "*invalid*";
    if (dll === "") continue;
    const library = libraryName(dll);
    for (const symbol of listed) {
      const name =
        "name" in symbol ? symbol.name : peOrdinalName(dll, symbol.ordinal);
      parts.push(`${library}.${name.toLowerCase()}`);
    }
  }
  return parts.length === 0
    ? null
    : createHash("md5").update(parts.join(",")).digest("hex");
};
