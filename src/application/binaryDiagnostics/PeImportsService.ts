import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { PeImportsPort } from "./PeImportsPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  peImportsResultSchema,
  inspectPeImportsInputSchema,
} from "../../domain/native/peImports.js";
import {
  DEFAULT_IMPORT_CATEGORIES,
  OPT_IN_IMPORT_CATEGORIES,
} from "../../domain/native/binaryImportTaxonomy.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

const OPERATION = "inspect_pe_imports";
const KNOWN_CATEGORIES = new Set([
  ...DEFAULT_IMPORT_CATEGORIES,
  ...OPT_IN_IMPORT_CATEGORIES,
]);

/** Shared caller validation, output checks and Evidence provenance for CLI/MCP. */
export class PeImportsService {
  constructor(readonly provider: PeImportsPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectPeImportsInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    if (!isAbsolute(input.data.path))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const unknown = (input.data.categories ?? []).filter(
      (category) => !KNOWN_CATEGORIES.has(category),
    );
    if (unknown.length > 0)
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["categories"],
            reason: "invalid_value",
            message: `Unknown categories: ${unknown.join(", ")}. Known: ${[...KNOWN_CATEGORIES].sort().join(", ")}.`,
          },
        ]),
      );
    const result = await this.provider.inspect(input.data, options);
    if (!result.ok) return result;
    const report = peImportsResultSchema.safeParse(result.value);
    if (!report.success || report.data.artifact.path !== input.data.path)
      return err(
        new AnalysisOutputError(
          OPERATION,
          "PE import scanner returned malformed output or changed artifact identity.",
        ),
      );
    const value = report.data;
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.artifact.path,
          format: "pe",
          sha256: value.artifact.sha256,
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: {
            path: input.data.path,
            ...(input.data.categories === undefined
              ? {}
              : { categories: input.data.categories }),
          },
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [{ kind: "artifact-path", path: value.artifact.path }],
        },
      ),
      options?.signal,
    );
  }
}
