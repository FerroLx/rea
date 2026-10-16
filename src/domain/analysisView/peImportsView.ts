import { analysisViewInputError } from "./analysisViewErrors.js";
import { z } from "zod";
import type { AnalysisError } from "../analysisErrorBase.js";
import { peImportsResultSchema } from "../native/peImports.js";
import { err, ok, type Result } from "../result.js";
import { parseAnalysisViewResult } from "./analysisViewParent.js";
import type {
  AnalysisViewParent,
  AnalysisViewRequest,
  UnsignedAnalysisView,
} from "./analysisView.js";
import {
  boundedViewMessages,
  completeWithinViewCoverage,
  pageViewCoverage,
} from "./analysisViewCoverage.js";

const shape = peImportsResultSchema.shape;
const uint = z.number().int().nonnegative();

/**
 * Triage facts without the import, delay-import and export tables. Artifact
 * identity and limitations are carried once by the view itself.
 */
export const peImportsSummarySchema = peImportsResultSchema
  .omit({
    artifact: true,
    imports: true,
    delay_imports: true,
    exports: true,
    limitations: true,
  })
  .extend({
    bytes: uint,
    /** The export directory's own DLL name; entries page as `exports`. */
    export_dll_name: z.string().nullable(),
  });

/** Stable pages of the retained tables, one row per symbol or export entry. */
export const peImportsViewRequestSchema = z.strictObject({
  kind: z.literal("pe-imports"),
  collection: z.enum(["imports", "delay_imports", "exports"]),
  offset: z.number().int().nonnegative().default(0),
  limit: z.number().int().positive().default(64),
});

const symbolRow = z.strictObject({
  /** Zero-based descriptor index in its table; one DLL may have several. */
  descriptor: uint,
  dll: z.string(),
  symbol: shape.imports.element.shape.symbols.element,
});

export const peImportsViewRowsSchema = z.union([
  z.array(symbolRow),
  shape.exports.shape.entries,
]);

type Report = z.output<typeof peImportsResultSchema>;
type SymbolRow = z.output<typeof symbolRow>;

const symbolTotal = (table: Report["imports"]): number =>
  table.reduce((total, descriptor) => total + descriptor.symbols.length, 0);

/** Rows [offset, offset + limit) without flattening the whole table. */
const symbolPage = (
  table: Report["imports"],
  offset: number,
  limit: number,
): SymbolRow[] => {
  const rows: SymbolRow[] = [];
  let skipped = 0;
  for (const [descriptor, entry] of table.entries()) {
    if (rows.length >= limit) break;
    const count = entry.symbols.length;
    if (skipped + count <= offset) {
      skipped += count;
      continue;
    }
    const from = Math.max(0, offset - skipped);
    for (const symbol of entry.symbols.slice(from, from + limit - rows.length))
      rows.push({ descriptor, dll: entry.dll, symbol });
    skipped += count;
  }
  return rows;
};

/** Project retained PE import Evidence without rereading the image. */
export const projectPeImportsView = (
  parent: AnalysisViewParent,
  view: AnalysisViewRequest,
): Result<UnsignedAnalysisView, AnalysisError> => {
  if (view.kind !== "summary" && view.kind !== "pe-imports")
    return err(
      analysisViewInputError([
        {
          path: ["view"],
          reason: "invalid_value",
          message:
            "PE import Evidence supports summary and pe-imports views (collection imports, delay_imports or exports).",
        },
      ]),
    );
  const parsed = parseAnalysisViewResult(peImportsResultSchema, parent);
  if (!parsed.ok) return parsed;
  const report = parsed.value;
  const shared = {
    parent_evidence_id: parent.evidenceId,
    parent_operation: "inspect_pe_imports" as const,
    parent_digest: parent.evidenceId.slice(3),
    artifact: { path: report.artifact.path, sha256: report.artifact.sha256 },
    limitations: boundedViewMessages(
      [...parent.limitations, ...report.limitations],
      parent.evidenceId,
      "limitations",
    ),
    unknowns: [
      "Runtime-resolved APIs (GetProcAddress, hashing, syscalls) and the image's runtime behaviour are not observed.",
    ],
  };
  const totals = {
    imports: symbolTotal(report.imports),
    delay_imports: symbolTotal(report.delay_imports),
    exports: report.exports.entries.length,
  };
  if (view.kind === "summary") {
    const {
      artifact,
      imports: _imports,
      delay_imports: _delay,
      exports,
      limitations: _limitations,
      ...facts
    } = report;
    const rows = totals.imports + totals.delay_imports + totals.exports;
    return ok({
      kind: "summary",
      view,
      ...shared,
      summary: {
        ...facts,
        bytes: artifact.bytes,
        export_dll_name: exports.dll_name,
      },
      coverage: completeWithinViewCoverage(rows, rows),
    });
  }
  const rows =
    view.collection === "exports"
      ? report.exports.entries.slice(view.offset, view.offset + view.limit)
      : symbolPage(report[view.collection], view.offset, view.limit);
  return ok({
    kind: "pe-imports",
    view,
    ...shared,
    rows,
    coverage: pageViewCoverage(
      view.offset,
      rows.length,
      totals[view.collection],
    ),
  });
};
