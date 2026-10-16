import { setImmediate } from "node:timers/promises";

import {
  PE_IMPORTS_LIMITATIONS,
  type PeImportsResult,
} from "../../domain/native/peImports.js";
import {
  BINARY_IMPORT_TAXONOMY_VERSION,
  DEFAULT_IMPORT_CATEGORIES,
  type ImportConfidence,
  importTaxonomyEntry,
  RESOLVER_APIS,
} from "../../domain/native/binaryImportTaxonomy.js";
import { decodePeMachine } from "../../domain/peMachine.js";
import { type PeImageLayout, readPeImageLayout } from "./PeImageLayout.js";
import {
  type PeExportVisit,
  type PeImportedSymbol,
  PeWorkExhausted,
  peWork,
  type PeWork,
  walkExports,
  walkImports,
} from "./PeImportTables.js";
import { pefileImphash } from "./PefileImphash.js";

/** Matched APIs listed per capability (the total is always reported). */
const CAPABILITY_SAMPLE = 8;
/** DLLs listed in the summary (all are counted). */
const DLL_SAMPLE = 64;
/** Runtime-resolution string hits listed (all are counted). */
const STRING_SAMPLE = 8;
/** Identifier lengths considered by the string scan (shortest taxonomy name is "send"). */
const MIN_API_STRING = 6;
const MAX_API_STRING = 64;
/** Inline output ceiling; detail past it is refused, not truncated. */
export const PE_IMPORTS_OUTPUT_BYTES = 8 * 1024 * 1024;
/** Projected serialized bytes per detail symbol, before its strings (JSON-escaped at most 2x). */
const DETAIL_SYMBOL_BYTES = 96;

/** Thrown when the detail tables would exceed the inline output budget. */
export class PeOutputExceeded extends Error {
  constructor(readonly projectedBytes: number) {
    super(
      `The import/export detail would serialise to more than ${String(PE_IMPORTS_OUTPUT_BYTES)} bytes.`,
    );
    this.name = "PeOutputExceeded";
  }
}

/** "Few imports" for the resolver-heavy packing indicator. */
const FEW_IMPORTS = 10;
/** A section with no raw data and at least this virtual size is a packer tell. */
const LARGE_VIRTUAL = 0x10000;
/** Bytes scanned between cooperative yields. */
/** DLL names kept for import-table disagreements. */
const DISAGREEMENT_SAMPLE = 16;
const SCAN_YIELD_BYTES = 1024 * 1024;

const TIER_RANK: Record<ImportConfidence, number> = {
  strong: 0,
  medium: 1,
  weak: 2,
};

const IMAGE_FILE_DLL = 0x2000;
const SCN_CNT_CODE = 0x20;
const SCN_MEM_EXECUTE = 0x20000000;
const SCN_MEM_WRITE = 0x80000000;

const isApiSet = (dll: string): boolean => /^(api|ext)-ms-/i.test(dll);

/** The name a symbol contributes to capability matching. */
const symbolName = (symbol: PeImportedSymbol): string | null =>
  symbol.kind === "name"
    ? symbol.name
    : symbol.kind === "ordinal"
      ? symbol.resolved
      : null;

const charge = (work: PeWork, units: number): void => {
  work.remaining -= units;
  if (work.remaining < 0) throw new PeWorkExhausted(work.limit);
};

/**
 * Shannon entropy (bits per byte) of a byte range. One linear pass over bytes
 * that exist, so it is bounded by the file size and not charged to the
 * table-walk budget (which guards amplification, not size).
 */
const entropy = async (
  bytes: Uint8Array,
  signal: AbortSignal | undefined,
): Promise<number> => {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  // Counted per MiB, polling for cancellation between slices.
  for (let from = 0; from < bytes.length; from += SCAN_YIELD_BYTES) {
    const to = Math.min(bytes.length, from + SCAN_YIELD_BYTES);
    for (let at = from; at < to; at++) counts[bytes[at]!]! += 1;
    if (to < bytes.length) {
      await setImmediate();
      signal?.throwIfAborted();
    }
  }
  let total = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const p = count / bytes.length;
    total -= p * Math.log2(p);
  }
  return Math.round(total * 1000) / 1000;
};

interface CapabilityAccumulator {
  attack: readonly string[];
  total: number;
  apis: PeImportsResult["capabilities"][number]["apis"];
}

/**
 * Find taxonomy API names written as ASCII or UTF-16LE identifiers in the
 * image's raw section data that are NOT imported (an imported name is part of
 * the import set by definition) and not exported or forwarded.
 */
const scanApiStrings = async (
  bytes: Buffer,
  layout: PeImageLayout,
  excluded: ReadonlySet<string>,
  work: PeWork,
): Promise<PeImportsResult["runtime_resolution"]["api_strings"]> => {
  let count = 0;
  const sample: PeImportsResult["runtime_resolution"]["api_strings"]["sample"] =
    [];
  const seen = new Set<string>();
  /** Report a taxonomy name; false when `api` is not one. */
  const report = (
    api: string,
    offset: number,
    encoding: "ascii" | "utf16le",
  ): boolean => {
    if (importTaxonomyEntry(api) === undefined) return false;
    if (excluded.has(api)) return true;
    count += 1;
    // Sample distinct APIs, so one repeated name cannot fill it.
    if (sample.length < STRING_SAMPLE && !seen.has(api)) {
      seen.add(api);
      sample.push({ api, offset, encoding });
    }
    return true;
  };
  const isIdent = (byte: number): boolean =>
    (byte >= 0x30 && byte <= 0x39) ||
    (byte >= 0x41 && byte <= 0x5a) ||
    (byte >= 0x61 && byte <= 0x7a) ||
    byte === 0x5f;
  /**
   * Report a UTF-16LE run. An ASCII string's last character followed by its
   * NUL terminator also reads as one UTF-16 unit, so a run directly after an
   * ASCII identifier byte is retried without that absorbed first character.
   */
  const flushUtf16 = (chars: string, runStart: number): void => {
    if (chars.length < MIN_API_STRING || chars.length > MAX_API_STRING) return;
    if (report(chars, runStart, "utf16le")) return;
    if (
      runStart > 0 &&
      isIdent(bytes[runStart - 1]!) &&
      chars.length > MIN_API_STRING
    )
      report(chars.slice(1), runStart + 2, "utf16le");
  };
  for (const section of layout.sections) {
    if (section.size === 0) continue;
    const start = section.offset;
    const end = section.offset + section.size;
    // Three linear passes (ASCII and UTF-16LE at both alignments) over bytes
    // that exist: bounded by the file size, polled for cancellation, and not
    // charged to the table-walk budget.
    // Polled by bytes scanned, so one long identifier run cannot delay it.
    let nextYield = start + SCAN_YIELD_BYTES;
    let run = start;
    for (let at = start; at <= end; at++) {
      if (at >= nextYield) {
        nextYield = at + SCAN_YIELD_BYTES;
        await setImmediate();
        work.signal?.throwIfAborted();
      }
      if (at < end && isIdent(bytes[at]!)) continue;
      const length = at - run;
      if (length >= MIN_API_STRING && length <= MAX_API_STRING)
        report(bytes.toString("latin1", run, at), run, "ascii");
      run = at + 1;
    }
    for (const alignment of [0, 1]) {
      let runStart = start + alignment;
      let chars = "";
      let nextYield = start + SCAN_YIELD_BYTES;
      for (let at = start + alignment; at + 1 < end; at += 2) {
        if (at >= nextYield) {
          nextYield = at + SCAN_YIELD_BYTES;
          await setImmediate();
          work.signal?.throwIfAborted();
        }
        const low = bytes[at]!;
        if (
          bytes[at + 1] === 0 &&
          isIdent(low) &&
          chars.length <= MAX_API_STRING
        ) {
          chars += String.fromCharCode(low);
          continue;
        }
        flushUtf16(chars, runStart);
        chars = "";
        runStart = at + 2;
      }
      flushUtf16(chars, runStart);
      await setImmediate();
      work.signal?.throwIfAborted();
    }
  }
  return { count, sample };
};

/**
 * Analyse one PE image's import surface. Throws `PeWorkExhausted` past the
 * call-wide work budget and an `ArtifactReaderFailure` for an unreadable image;
 * the caller maps both.
 */
export const analysePeImports = async (
  bytes: Buffer,
  artifact: PeImportsResult["artifact"],
  options: {
    readonly categories: readonly string[] | undefined;
    readonly detail: boolean;
    readonly signal: AbortSignal | undefined;
  },
): Promise<PeImportsResult> => {
  const layout = readPeImageLayout(bytes);
  const work = peWork(bytes.length, options.signal);
  const categories = new Set(options.categories ?? DEFAULT_IMPORT_CATEGORIES);

  const counts = {
    dlls: 0,
    imports: 0,
    by_name: 0,
    by_ordinal: 0,
    ordinal_unresolved: 0,
    unreadable: 0,
    delay_dlls: 0,
    delay_imports: 0,
    delay_va_unmapped: 0,
    exports: 0,
    exports_named: 0,
    forwarders: 0,
    exports_unreadable: 0,
  };
  const dlls = new Map<
    string,
    { name: string; imports: number; delay: boolean; order: number }
  >();
  const capabilities = new Map<string, CapabilityAccumulator>();
  const imported = new Set<string>();
  const resolverImports = new Set<string>();
  /** Address-table-only descriptors, keyed by table and index (DLL name). */
  const disagreeingDescriptors = new Map<string, string>();
  let tableDisagreements = 0;
  const recordCapability = (
    name: string,
    dll: string,
    via: "import" | "delay" | "address_table",
  ): void => {
    const entry = importTaxonomyEntry(name);
    if (entry === undefined) return;
    imported.add(name);
    if (via !== "address_table" && RESOLVER_APIS.has(name))
      resolverImports.add(name);
    if (!categories.has(entry.category)) return;
    const cap = capabilities.get(entry.category) ?? {
      attack: entry.attack,
      total: 0,
      apis: [],
    };
    cap.total += 1;
    cap.apis.push({
      api: name,
      dll,
      via,
      confidence: entry.confidence,
      argument_dependent: entry.argumentDependent === true,
    });
    // Keep only the strongest few, deterministically.
    cap.apis.sort(
      (a, b) =>
        TIER_RANK[a.confidence] - TIER_RANK[b.confidence] ||
        a.dll.localeCompare(b.dll) ||
        a.api.localeCompare(b.api),
    );
    if (cap.apis.length > CAPABILITY_SAMPLE) cap.apis.pop();
    capabilities.set(entry.category, cap);
  };
  const addressTableHit = (symbol: PeImportedSymbol, dll: string): void => {
    const name = symbolName(symbol);
    if (name !== null) recordCapability(name, dll, "address_table");
  };
  // The per-DLL key is computed once per run of symbols from the same DLL.
  let lastDll: string | null = null;
  let lastKey = "";
  const walkLimitations: string[] = [];
  const detailImports: NonNullable<PeImportsResult["detail"]>["imports"] = [];
  // Detail size is projected while it is collected and refused past the
  // output budget, before the report exists.
  let detailBytes = 0;

  for (const table of ["import", "delay"] as const) {
    lastDll = null; // the cached key includes the table
    let lastDescriptor = -1;
    const facts = await walkImports(bytes, layout, table, work, (visit) => {
      const dll = visit.dll ?? "";
      if (visit.source === "address") {
        // Never bound by the loader: only a disagreement fact and capability
        // evidence, not an import.
        if (disagreeingDescriptors.size < DISAGREEMENT_SAMPLE + 1)
          disagreeingDescriptors.set(
            `${table}:${String(visit.descriptor)}`,
            dll,
          );
        addressTableHit(visit.symbol, dll);
        return;
      }
      if (dll !== lastDll) {
        lastDll = dll;
        lastKey = `${table}:${dll.toLowerCase()}`;
      }
      const key = lastKey;
      const known = dlls.get(key);
      if (known === undefined)
        dlls.set(key, {
          name: dll,
          imports: 1,
          delay: table === "delay",
          order: dlls.size,
        });
      else known.imports += 1;
      if (table === "import") counts.imports += 1;
      else counts.delay_imports += 1;
      const { symbol } = visit;
      if (symbol.kind === "name") counts.by_name += 1;
      else if (symbol.kind === "ordinal") {
        counts.by_ordinal += 1;
        if (!symbol.resolvedFromTable) counts.ordinal_unresolved += 1;
      } else counts.unreadable += 1;
      const name = symbolName(symbol);
      if (name !== null) recordCapability(name, dll, table);
      if (options.detail) {
        detailBytes +=
          DETAIL_SYMBOL_BYTES + 2 * (name?.length ?? 0) + 2 * dll.length;
        if (detailBytes > PE_IMPORTS_OUTPUT_BYTES)
          throw new PeOutputExceeded(detailBytes);
        if (visit.descriptor !== lastDescriptor) {
          detailImports.push({ dll, table, symbols: [] });
          lastDescriptor = visit.descriptor;
        }
        detailImports.at(-1)!.symbols.push(
          symbol.kind === "name"
            ? { kind: "name", name: symbol.name, hint: symbol.hint }
            : symbol.kind === "ordinal"
              ? {
                  kind: "ordinal",
                  ordinal: symbol.ordinal,
                  resolved: symbol.resolved,
                  resolved_from_table: symbol.resolvedFromTable,
                }
              : { kind: "unreadable", rva: symbol.rva },
        );
      }
    });
    counts.unreadable += facts.unreadableDescriptors;
    tableDisagreements += facts.tableDisagreements;
    if (facts.truncatedAfterErrors)
      walkLimitations.push(
        `The ${table === "import" ? "import" : "delay-load import"} table was read only until more than five descriptors proved unusable (pefile's rule); later descriptors were not examined.`,
      );
    if (table === "delay") counts.delay_va_unmapped = facts.delayVaUnmapped;
  }
  for (const key of dlls.keys())
    if (key.startsWith("delay:")) counts.delay_dlls += 1;
    else counts.dlls += 1;

  const excluded = new Set(imported);
  const exportEntries: PeExportVisit[] = [];
  const exportFacts = await walkExports(bytes, layout, work, (visit) => {
    if (visit.name !== null) excluded.add(visit.name);
    if (visit.kind === "forwarder" && visit.target !== null) {
      const dot = visit.target.lastIndexOf(".");
      excluded.add(dot === -1 ? visit.target : visit.target.slice(dot + 1));
    }
    if (options.detail) {
      detailBytes +=
        DETAIL_SYMBOL_BYTES +
        2 * (visit.name?.length ?? 0) +
        (visit.kind === "forwarder" ? 2 * (visit.target?.length ?? 0) : 0);
      if (detailBytes > PE_IMPORTS_OUTPUT_BYTES)
        throw new PeOutputExceeded(detailBytes);
      exportEntries.push(visit);
    }
  });
  counts.exports = exportFacts.entries;
  counts.exports_named = exportFacts.named;
  counts.forwarders = exportFacts.forwarders;
  counts.exports_unreadable = exportFacts.unreadable;

  const apiStrings = await scanApiStrings(bytes, layout, excluded, work);

  // Packing indicators: facts, never a verdict.
  const sectionAt = (rva: number) =>
    layout.sections.find(
      (s) =>
        rva >= s.rva &&
        rva - s.rva < (s.virtualSize === 0 ? s.size : s.virtualSize),
    );
  const entrySection =
    layout.entryPoint === 0 ? undefined : sectionAt(layout.entryPoint);
  let maxEntropy: { section: string; entropy: number } | null = null;
  for (const section of layout.sections) {
    if (section.size === 0) continue;
    const value = await entropy(
      bytes.subarray(section.offset, section.offset + section.size),
      options.signal,
    );
    if (maxEntropy === null || value > maxEntropy.entropy)
      maxEntropy = { section: section.name, entropy: value };
    await setImmediate();
    options.signal?.throwIfAborted();
  }
  // pefile's view of the import table, owned by its emulation: threat
  // intelligence pivots on it even where it differs from what the loader binds.
  const imphash = await pefileImphash(bytes, layout, work);
  const importCount = counts.imports + counts.delay_imports;
  const overlay =
    layout.overlay.size === 0
      ? null
      : {
          offset: layout.overlay.offset,
          bytes: layout.overlay.size,
          entropy: await entropy(
            bytes.subarray(
              layout.overlay.offset,
              layout.overlay.offset + layout.overlay.size,
            ),
            options.signal,
          ),
        };

  const machine = decodePeMachine(layout.machine);
  const dotnet = layout.dataDirectory(14);
  const orderedDlls = [...dlls.entries()].sort(
    (a, b) => a[1].order - b[1].order,
  );
  const result: PeImportsResult = {
    artifact,
    format: {
      kind: "pe",
      pe32_plus: layout.format === "pe32-plus",
      machine: layout.machine,
      architecture:
        machine === undefined || machine.nativeOsOverride
          ? "unknown"
          : machine.architecture,
      subsystem: layout.subsystem,
      is_dll: (layout.characteristics & IMAGE_FILE_DLL) !== 0,
      is_dotnet: dotnet !== null && dotnet.rva !== 0,
      timestamp: layout.timestamp,
      entry_point_rva: layout.entryPoint,
    },
    taxonomy_version: BINARY_IMPORT_TAXONOMY_VERSION,
    imphash,
    counts,
    categories_scanned: [...categories].sort(),
    capabilities: [...capabilities.entries()]
      .map(([category, cap]) => ({
        category,
        attack: [...cap.attack],
        confidence: cap.apis[0]?.confidence ?? "weak",
        total: cap.total,
        apis: cap.apis,
      }))
      .sort(
        (a, b) =>
          TIER_RANK[a.confidence] - TIER_RANK[b.confidence] ||
          (a.attack[0] ?? "").localeCompare(b.attack[0] ?? "") ||
          a.category.localeCompare(b.category),
      ),
    dlls: orderedDlls.slice(0, DLL_SAMPLE).map(([, value]) => ({
      name: value.name,
      imports: value.imports,
      delay: value.delay,
      api_set: isApiSet(value.name),
    })),
    import_table_disagreements: {
      count: tableDisagreements,
      dlls: [...disagreeingDescriptors.values()].slice(0, DISAGREEMENT_SAMPLE),
    },
    dlls_truncated: orderedDlls.length > DLL_SAMPLE,
    runtime_resolution: {
      resolver_imports: [...resolverImports].sort(),
      api_strings: apiStrings,
    },
    packing: {
      import_count: importCount,
      few_imports_with_resolvers:
        importCount <= FEW_IMPORTS && resolverImports.size > 0,
      entry_point_section: entrySection?.name ?? null,
      entry_outside_code:
        layout.entryPoint !== 0 &&
        (entrySection === undefined ||
          (entrySection.characteristics & (SCN_CNT_CODE | SCN_MEM_EXECUTE)) ===
            0),
      writable_executable_sections: layout.sections
        .filter(
          (s) =>
            (s.characteristics & SCN_MEM_WRITE) !== 0 &&
            (s.characteristics & SCN_MEM_EXECUTE) !== 0,
        )
        .map((s) => s.name),
      zero_raw_large_virtual_sections: layout.sections
        .filter((s) => s.size === 0 && s.virtualSize >= LARGE_VIRTUAL)
        .map((s) => s.name),
      max_section_entropy: maxEntropy,
      overlay,
    },
    detail: options.detail
      ? {
          imports: detailImports,
          exports: {
            dll_name: exportFacts.dllName,
            entries: exportEntries.map((entry) =>
              entry.kind === "function"
                ? {
                    kind: "function",
                    ordinal: entry.ordinal,
                    name: entry.name,
                    rva: entry.rva,
                  }
                : {
                    kind: "forwarder",
                    ordinal: entry.ordinal,
                    name: entry.name,
                    target: entry.target,
                  },
            ),
          },
        }
      : null,
    runtime_execution: "not-performed",
    limitations: [...PE_IMPORTS_LIMITATIONS, ...walkLimitations],
  };
  return result;
};
