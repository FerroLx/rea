import { setImmediate } from "node:timers/promises";

import { peOrdinalName } from "../../domain/native/peOrdinalNames.js";
import type { PeImageLayout } from "./PeImageLayout.js";

/**
 * Streaming, bounded walkers for a PE image's import (directory 1), delay-load
 * import (13) and export (0) tables. Each walker visits one entry at a time and
 * never materialises a whole table; every descriptor, thunk, name byte and
 * export entry is charged to one call-wide work budget, and the walk yields to
 * the event loop periodically so cancellation can fire. A structure that cannot
 * be read is reported as unreadable (unknown), never as absent.
 */

/** Work units allowed per byte of the image (each unit is backed by input bytes). */
export const PE_WORK_UNITS_PER_BYTE = 4;
/** Longest DLL, function or forwarder name read before it is treated as malformed. */
export const PE_NAME_MAX_BYTES = 512;
/** Entries between cooperative yields (and cancellation checks). */
const YIELD_INTERVAL = 4096;

export interface PeWork {
  remaining: number;
  readonly limit: number;
  readonly signal: AbortSignal | undefined;
  /** Entries since the last yield. */
  sinceYield: number;
}

export const peWork = (
  imageBytes: number,
  signal: AbortSignal | undefined,
): PeWork => {
  const limit = Math.max(1024 * 1024, PE_WORK_UNITS_PER_BYTE * imageBytes);
  return { remaining: limit, limit, signal, sinceYield: 0 };
};

/** Thrown when the call-wide work budget is spent; mapped to a capacity refusal. */
export class PeWorkExhausted extends Error {
  constructor(readonly limit: number) {
    super(`PE import analysis needs more than ${String(limit)} work units.`);
    this.name = "PeWorkExhausted";
  }
}

const charge = (work: PeWork, units: number): void => {
  work.remaining -= units;
  if (work.remaining < 0) throw new PeWorkExhausted(work.limit);
};

/** Yield every few thousand entries so an abort can be observed mid-walk. */
/**
 * Count one entry; true when a yield is due. Synchronous, so the per-entry
 * cost is a counter rather than a promise and microtask.
 */
const stepDue = (work: PeWork): boolean => {
  work.sinceYield += 1;
  if (work.sinceYield < YIELD_INTERVAL) return false;
  work.sinceYield = 0;
  return true;
};

/** Yield to the event loop and honour cancellation. */
const yieldWork = async (work: PeWork): Promise<void> => {
  await setImmediate();
  work.signal?.throwIfAborted();
};

/** Read a NUL-terminated ASCII name at `rva`, or null when unmapped/unterminated/too long. */
const readName = (
  bytes: Buffer,
  layout: PeImageLayout,
  rva: number,
  work: PeWork,
  truncate = false,
): string | null => {
  const span = layout.availableBytes(rva);
  if (span === null) return null;
  // Search only the bounded window: an unterminated name must not scan the
  // rest of the file once per reference.
  const limit = Math.min(span.length, PE_NAME_MAX_BYTES + 1);
  const length = bytes.subarray(span.offset, span.offset + limit).indexOf(0);
  charge(work, length === -1 ? limit : length + 1);
  if (length !== -1)
    return bytes.toString("latin1", span.offset, span.offset + length);
  // Import names are read like pefile's get_string_at_rva: the first 512
  // bytes when no terminator follows, so such a name cannot hide its imports.
  return truncate
    ? bytes.toString(
        "latin1",
        span.offset,
        span.offset + Math.min(span.length, PE_NAME_MAX_BYTES),
      )
    : null;
};

type ThunkSpan = { readonly offset: number; readonly length: number };

/**
 * The first of `candidates` (RVAs, 0/null = absent) that is mapped and whose
 * first thunk is non-zero, as its file span; `"empty"` when none is but one is
 * mapped and starts with its terminator (an import list with no entries, as
 * ARM64X images emit for EC-only imports); null when none is mapped.
 */
const firstPopulatedTable = (
  bytes: Buffer,
  layout: PeImageLayout,
  candidates: readonly (number | null)[],
  thunkWidth: number,
): ThunkSpan | "empty" | null => {
  let empty = false;
  for (const rva of candidates) {
    if (rva === null || rva === 0) continue;
    const span = layout.availableBytes(rva);
    if (span === null || span.length < thunkWidth) continue;
    const first =
      thunkWidth === 8
        ? bytes.readBigUInt64LE(span.offset) !== 0n
        : bytes.readUInt32LE(span.offset) !== 0;
    if (first) return span;
    empty = true;
  }
  return empty ? "empty" : null;
};

/**
 * Whether two thunk arrays import different symbols, read in place up to the
 * first terminator of either. Entries are compared by meaning (the same
 * ordinal, or the same name), so an address table pointing at its own copies
 * of identical hint/name entries is not a disagreement.
 */
const tablesDisagree = (
  bytes: Buffer,
  layout: PeImageLayout,
  lookup: { readonly offset: number; readonly length: number },
  address: { readonly offset: number; readonly length: number },
  width: number,
  dll: string,
  work: PeWork,
): boolean => {
  const read = (span: typeof lookup, t: number): bigint =>
    width === 8
      ? bytes.readBigUInt64LE(span.offset + t * width)
      : BigInt(bytes.readUInt32LE(span.offset + t * width));
  const same = (a: PeImportedSymbol, b: PeImportedSymbol): boolean =>
    (a.kind === "ordinal" && b.kind === "ordinal" && a.ordinal === b.ordinal) ||
    (a.kind === "name" && b.kind === "name" && a.name === b.name);
  const entries = Math.floor(Math.min(lookup.length, address.length) / width);
  for (let t = 0; t < entries; t++) {
    charge(work, 1);
    const a = read(lookup, t);
    const b = read(address, t);
    if (a === 0n || b === 0n) return a !== b;
    if (
      a !== b &&
      !same(
        thunkSymbol(bytes, layout, a, width, dll, work),
        thunkSymbol(bytes, layout, b, width, dll, work),
      )
    )
      return true;
  }
  // One array ran out of mapped bytes before both terminated.
  return lookup.length !== address.length;
};

/** Decode one non-zero thunk value as an ordinal, a hint/name or unreadable. */
const thunkSymbol = (
  bytes: Buffer,
  layout: PeImageLayout,
  value: bigint,
  width: number,
  dll: string,
  work: PeWork,
): PeImportedSymbol => {
  const ordinalFlag = width === 8 ? 1n << 63n : 1n << 31n;
  if ((value & ordinalFlag) !== 0n) {
    const ordinal = Number(value & 0xffffn);
    const resolved = peOrdinalName(dll, ordinal);
    return {
      kind: "ordinal",
      ordinal,
      resolved,
      resolvedFromTable: resolved !== `ord${String(ordinal)}`,
    };
  }
  const hintRva = Number(value & 0x7fffffffn);
  const hintSpan = layout.availableBytes(hintRva);
  const name =
    hintSpan === null || hintSpan.length < 3
      ? null
      : readName(bytes, layout, hintRva + 2, work, true);
  return hintSpan === null || name === null
    ? { kind: "unreadable", rva: hintRva }
    : { kind: "name", name, hint: bytes.readUInt16LE(hintSpan.offset) };
};

/** Stream every entry of a thunk array up to its terminator. */
const walkThunks = async (
  bytes: Buffer,
  layout: PeImageLayout,
  span: { readonly offset: number; readonly length: number },
  width: number,
  work: PeWork,
  dll: string,
  visit: (symbol: PeImportedSymbol) => void,
): Promise<void> => {
  const entries = Math.floor(span.length / width);
  for (let t = 0; t < entries; t++) {
    charge(work, 1);
    if (stepDue(work)) await yieldWork(work);
    const value =
      width === 8
        ? bytes.readBigUInt64LE(span.offset + t * width)
        : BigInt(bytes.readUInt32LE(span.offset + t * width));
    if (value === 0n) return;
    visit(thunkSymbol(bytes, layout, value, width, dll, work));
  }
};

export type PeImportedSymbol =
  | { readonly kind: "name"; readonly name: string; readonly hint: number }
  | {
      readonly kind: "ordinal";
      readonly ordinal: number;
      /** pefile-compatible resolved name (`ord<N>` when the DLL has no table). */
      readonly resolved: string;
      readonly resolvedFromTable: boolean;
    }
  /** A thunk whose name could not be read: unknown, not absent. */
  | { readonly kind: "unreadable"; readonly rva: number };

export interface PeImportVisit {
  readonly table: "import" | "delay";
  /** Descriptor index in table order (first appearance order). */
  readonly descriptor: number;
  readonly dll: string | null;
  readonly symbol: PeImportedSymbol;
  /**
   * `lookup`: what the loader binds. `address`: an entry of an unbound
   * descriptor's FirstThunk table that disagrees with its lookup table; the
   * loader never binds it, but tools that read the address table (pefile,
   * VirusTotal) report it, so the disagreement is itself evidence.
   */
  readonly source: "lookup" | "address";
}

/** A descriptor the loader loads: its DLL is a dependency, even with no entries. */
export interface PeImportDependency {
  readonly table: "import" | "delay";
  readonly descriptor: number;
  readonly dll: string;
}

export interface PeImportWalkFacts {
  readonly descriptors: number;
  readonly unreadableDescriptors: number;
  readonly thunks: number;
  /** v0 (VA-based) delay descriptors whose VAs fall outside the image. */
  readonly delayVaUnmapped: number;
  /** The walk gave up after too many unusable descriptors (as pefile does). */
  readonly truncatedAfterErrors: boolean;
  /** Unbound import descriptors whose lookup and address tables disagree. */
  readonly tableDisagreements: number;
}

/** pefile stops an import walk once more than this many descriptors failed. */
const MAX_UNUSABLE_DESCRIPTORS = 5;

const DESCRIPTOR_SIZE = { import: 20, delay: 32 } as const;

/** Resolve a delay-load field: an RVA when the dlattrRva bit is set, else a VA. */
const delayField = (
  value: number,
  rvaBased: boolean,
  layout: PeImageLayout,
): number | null => {
  if (value === 0) return 0;
  if (rvaBased) return value;
  const rva = BigInt(value) - layout.imageBase;
  return rva >= 0n && rva < 0x100000000n ? Number(rva) : null;
};

/**
 * Walk the import or delay-load import table, visiting every imported symbol in
 * descriptor and thunk order (the order pefile and the import hash use).
 */
export const walkImports = async (
  bytes: Buffer,
  layout: PeImageLayout,
  table: "import" | "delay",
  work: PeWork,
  visit: (entry: PeImportVisit) => void,
  /** Called once per loaded descriptor, before its symbols are visited. */
  dependency: (entry: PeImportDependency) => void,
): Promise<PeImportWalkFacts> => {
  const directory = layout.dataDirectory(table === "import" ? 1 : 13);
  const facts = {
    descriptors: 0,
    unreadableDescriptors: 0,
    thunks: 0,
    delayVaUnmapped: 0,
    truncatedAfterErrors: false,
    tableDisagreements: 0,
  };
  if (directory === null || directory.rva === 0) return facts;
  const span = layout.availableBytes(directory.rva);
  if (span === null) {
    facts.unreadableDescriptors += 1;
    return facts;
  }
  const size = DESCRIPTOR_SIZE[table];
  // The loader (and pefile) ignore the directory's Size and read descriptors
  // up to the all-zero terminator, so only the mapped bytes and the work budget
  // bound the walk: a small declared Size must not hide imports that load.
  const maxDescriptors = Math.floor(span.length / size);
  const thunkWidth = layout.format === "pe32-plus" ? 8 : 4;
  // pefile's rule: an unusable descriptor is skipped (later valid ones are
  // still surfaced, so one planted bad descriptor cannot hide them), and the
  // walk gives up once more than MAX_UNUSABLE_DESCRIPTORS have failed, which
  // also bounds a table that lacks its all-zero terminator.
  let unusable = 0;
  for (let index = 0; index < maxDescriptors; index++) {
    charge(work, 1);
    if (stepDue(work)) await yieldWork(work);
    const at = span.offset + index * size;
    if (bytes.subarray(at, at + size).every((byte) => byte === 0)) break;
    if (unusable > MAX_UNUSABLE_DESCRIPTORS) {
      facts.truncatedAfterErrors = true;
      break;
    }
    facts.descriptors += 1;
    let nameRva: number;
    // What the loader binds: an import descriptor's OriginalFirstThunk when it
    // is set (FirstThunk only when it is 0); a delay descriptor's pINT, or its
    // pIAT when the pINT holds nothing (the delay IAT normally holds stubs).
    let candidates: readonly (number | null)[];
    let addressTable: number | null = null;
    if (table === "import") {
      nameRva = bytes.readUInt32LE(at + 12);
      const lookup = bytes.readUInt32LE(at);
      const address = bytes.readUInt32LE(at + 16);
      candidates = lookup !== 0 ? [lookup] : [address];
      // An unbound descriptor's FirstThunk mirrors its lookup table until the
      // loader overwrites it; a bound one holds addresses.
      if (lookup !== 0 && address !== 0 && bytes.readUInt32LE(at + 4) === 0)
        addressTable = address;
    } else {
      const rvaBased = (bytes.readUInt32LE(at) & 1) === 1;
      const name = delayField(bytes.readUInt32LE(at + 4), rvaBased, layout);
      if (name === null) {
        facts.delayVaUnmapped += 1;
        unusable += 1;
        continue;
      }
      nameRva = name;
      candidates = [
        delayField(bytes.readUInt32LE(at + 16), rvaBased, layout),
        delayField(bytes.readUInt32LE(at + 12), rvaBased, layout),
      ];
    }
    const lookup = firstPopulatedTable(bytes, layout, candidates, thunkWidth);
    const addressSpan =
      addressTable === null
        ? null
        : firstPopulatedTable(bytes, layout, [addressTable], thunkWidth);
    const thunks = typeof lookup === "object" ? lookup : null;
    const address = typeof addressSpan === "object" ? addressSpan : null;
    // A descriptor counts toward the failure limit only when no table is
    // mapped; an unreadable DLL name merely drops it. Counting names too would
    // let planted nameless decoys end the walk early, and a mapped table that
    // starts with its terminator is a dependency with no entries, not damage.
    if (lookup === null && addressSpan === null) {
      facts.unreadableDescriptors += 1;
      unusable += 1;
      continue;
    }
    const dll =
      nameRva === 0 ? null : readName(bytes, layout, nameRva, work, true);
    if (dll === null || dll === "") {
      facts.unreadableDescriptors += 1;
      continue;
    }
    dependency({ table, descriptor: index, dll });
    if (thunks !== null) {
      const maxThunks = Math.floor(thunks.length / thunkWidth);
      let terminated = false;
      for (let t = 0; t < maxThunks; t++) {
        charge(work, 1);
        if (stepDue(work)) await yieldWork(work);
        const at = thunks.offset + t * thunkWidth;
        const value =
          thunkWidth === 8
            ? bytes.readBigUInt64LE(at)
            : BigInt(bytes.readUInt32LE(at));
        if (value === 0n) {
          terminated = true;
          break;
        }
        facts.thunks += 1;
        visit({
          table,
          descriptor: index,
          dll,
          symbol: thunkSymbol(bytes, layout, value, thunkWidth, dll, work),
          source: "lookup",
        });
      }
      // A lookup table that runs out of section without a terminator is damaged.
      if (!terminated) facts.unreadableDescriptors += 1;
    }
    // An unbound descriptor's address table that differs from its lookup table
    // (including a populated one behind an empty lookup table) is reported
    // with its provenance: the loader never binds it, but it is what pefile
    // and VirusTotal show.
    if (
      address !== null &&
      (thunks === null ||
        tablesDisagree(bytes, layout, thunks, address, thunkWidth, dll, work))
    ) {
      facts.tableDisagreements += 1;
      await walkThunks(
        bytes,
        layout,
        address,
        thunkWidth,
        work,
        dll,
        (symbol) =>
          visit({ table, descriptor: index, dll, symbol, source: "address" }),
      );
    }
  }
  return facts;
};

export type PeExportVisit =
  | {
      readonly kind: "function";
      readonly ordinal: number;
      readonly name: string | null;
      readonly rva: number;
    }
  | {
      readonly kind: "forwarder";
      readonly ordinal: number;
      readonly name: string | null;
      /** `DLL.Function` or `DLL.#ordinal`, as declared. */
      readonly target: string | null;
    };

export interface PeExportWalkFacts {
  readonly present: boolean;
  readonly dllName: string | null;
  /** Function slots examined. */
  readonly functions: number;
  /** Exported entries visited: one per name, plus each unnamed used slot. */
  readonly entries: number;
  /** Visited entries carrying a name (several names may share one slot). */
  readonly named: number;
  readonly forwarders: number;
  readonly unreadable: number;
}

/**
 * Walk the export directory, visiting every exported function slot (by
 * ordinal) with its name when one maps to it, and forwarders as forwarders.
 */
export const walkExports = async (
  bytes: Buffer,
  layout: PeImageLayout,
  work: PeWork,
  visit: (entry: PeExportVisit) => void,
): Promise<PeExportWalkFacts> => {
  const directory = layout.dataDirectory(0);
  const empty = {
    present: false,
    dllName: null,
    functions: 0,
    entries: 0,
    named: 0,
    forwarders: 0,
    unreadable: 0,
  };
  if (directory === null || directory.rva === 0) return empty;
  const header = layout.availableBytes(directory.rva);
  if (header === null || header.length < 40)
    return { ...empty, present: true, unreadable: 1 };
  const at = header.offset;
  const dllName = readName(bytes, layout, bytes.readUInt32LE(at + 12), work);
  const base = bytes.readUInt32LE(at + 16);
  const functionCount = bytes.readUInt32LE(at + 20);
  const nameCount = bytes.readUInt32LE(at + 24);
  const functionsSpan = layout.availableBytes(bytes.readUInt32LE(at + 28));
  const namesSpan = layout.availableBytes(bytes.readUInt32LE(at + 32));
  const ordinalsSpan = layout.availableBytes(bytes.readUInt32LE(at + 36));
  // Counts are bounded by the bytes their arrays actually occupy.
  const functions = Math.min(
    functionCount,
    Math.floor((functionsSpan?.length ?? 0) / 4),
  );
  const names = Math.min(
    nameCount,
    Math.floor((namesSpan?.length ?? 0) / 4),
    Math.floor((ordinalsSpan?.length ?? 0) / 2),
  );
  let unreadable =
    (functions < functionCount ? 1 : 0) + (names < nameCount ? 1 : 0);
  // Name indices per function slot; a sparse map bounded by `names`. Several
  // names may alias one slot, and each is a separate export (as in pefile).
  const nameOf = new Map<number, number[]>();
  for (let i = 0; i < names; i++) {
    charge(work, 1);
    if (stepDue(work)) await yieldWork(work);
    const slot = bytes.readUInt16LE((ordinalsSpan?.offset ?? 0) + i * 2);
    if (slot >= functions) {
      unreadable += 1;
      continue;
    }
    const aliases = nameOf.get(slot);
    if (aliases === undefined) nameOf.set(slot, [i]);
    else aliases.push(i);
  }
  const exportEnd = directory.rva + directory.size;
  let forwarders = 0;
  let entries = 0;
  let named = 0;
  for (let slot = 0; slot < functions; slot++) {
    charge(work, 1);
    if (stepDue(work)) await yieldWork(work);
    const rva = bytes.readUInt32LE((functionsSpan?.offset ?? 0) + slot * 4);
    if (rva === 0) continue; // an unused ordinal slot
    const ordinal = base + slot;
    // An RVA inside the export directory is a forwarder string, not code.
    const forwarded = rva >= directory.rva && rva < exportEnd;
    const target = forwarded ? readName(bytes, layout, rva, work) : null;
    if (forwarded) forwarders += 1;
    for (const nameIndex of nameOf.get(slot) ?? [null]) {
      const name =
        nameIndex === null
          ? null
          : readName(
              bytes,
              layout,
              bytes.readUInt32LE((namesSpan?.offset ?? 0) + nameIndex * 4),
              work,
            );
      entries += 1;
      if (name !== null) named += 1;
      if (forwarded) visit({ kind: "forwarder", ordinal, name, target });
      else visit({ kind: "function", ordinal, name, rva });
    }
  }
  return {
    present: true,
    dllName,
    functions,
    entries,
    named,
    forwarders,
    unreadable,
  };
};
