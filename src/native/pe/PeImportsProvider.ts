import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { analysisErrorWithCleanupFailure } from "../../domain/analysisErrorCleanup.js";
import type { PeImportsPort } from "../../application/binaryDiagnostics/PeImportsPort.js";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import { ArtifactOperationError } from "../../domain/artifactOperationError.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import type { InspectPeImportsInput } from "../../domain/native/peImports.js";
import { err, ok } from "../../domain/result.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { PE_IMPORTS_PROVIDER } from "../../application/InvestigationProviders.js";
import {
  analysePeImports,
  PE_IMPORT_TABLES_OUTPUT_BYTES,
  PeOutputExceeded,
} from "./PeImportAnalysis.js";
import { PeWorkExhausted } from "./PeImportTables.js";

const OPERATION = "inspect_pe_imports";
/** One bounded, identity-checked read of the image (matches inspect_pe_resources' default). */
export const PE_IMPORTS_MAX_FILE_BYTES = 64 * 1024 * 1024;

/** In-process import scanner over one bounded, identity-checked regular file. */
export class PeImportsProvider implements PeImportsPort {
  readonly identity = PE_IMPORTS_PROVIDER;
  readonly #resources = new ArtifactResourceScope();

  close(): Promise<void> {
    return this.#resources.close();
  }

  async inspect(input: InspectPeImportsInput, options?: ExecutionOptions) {
    try {
      const snapshot = await this.#resources.run(() =>
        readStableArtifact(
          input.path,
          PE_IMPORTS_MAX_FILE_BYTES,
          options?.signal,
          undefined,
          this.#resources,
        ),
      );
      return ok(
        await analysePeImports(
          snapshot.bytes,
          {
            path: input.path,
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.length,
          },
          {
            categories: input.categories,
            signal: options?.signal,
          },
        ),
      );
    } catch (cause) {
      return err(peImportsFailure(cause, input, options?.signal));
    }
  }
}

const primaryFailure = (
  cause: unknown,
  input: InspectPeImportsInput,
  signal: AbortSignal | undefined,
) => {
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(
      OPERATION,
      input.path,
      cause.message,
      {
        cause,
      },
    );
  if (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled")
    return new AnalysisCancelledError(OPERATION, { cause });
  if (signal?.aborted) return new AnalysisCancelledError(OPERATION, { cause });
  if (cause instanceof PeWorkExhausted)
    return new AnalysisResourceConstraintError(
      OPERATION,
      "cpu",
      `${cause.message} A well-formed image stays far below this budget, which is proportional to its size.`,
      { max_work_units: cause.limit },
      { cause },
    );
  if (cause instanceof PeOutputExceeded)
    return new AnalysisResourceConstraintError(
      OPERATION,
      "capacity",
      cause.message,
      { max_output_bytes: PE_IMPORT_TABLES_OUTPUT_BYTES },
      { cause },
    );
  if (cause instanceof ArtifactReaderFailure) {
    if (cause.reason === "limit")
      return new AnalysisResourceConstraintError(
        OPERATION,
        "memory",
        cause.message,
        { max_file_bytes: PE_IMPORTS_MAX_FILE_BYTES },
        { cause },
      );
    if (cause.reason === "path" || cause.reason === "format")
      return new AnalysisInputError(OPERATION, { cause }, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
  }
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, input.path, cause.code, {
        cause,
      });
    if (cause.code === "ENOENT" || cause.code === "ENOTDIR")
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected PE image could not be read (${cause.code}): ${input.path}.`,
        },
      ]);
  }
  return new ArtifactOperationError(
    OPERATION,
    cause instanceof ArtifactReaderFailure ? cause.reason : "io",
    undefined,
    cause instanceof Error ? cause.message : "PE import inspection failed.",
    { cause },
  );
};

const peImportsFailure = (
  cause: unknown,
  input: InspectPeImportsInput,
  signal: AbortSignal | undefined,
) => {
  const primary = primaryFailure(cause, input, signal);
  if (!(cause instanceof ArtifactReaderFailure) || cause.cleanup === undefined)
    return primary;
  const cleanup = new ProviderCleanupError(
    PE_IMPORTS_PROVIDER.id,
    cause.cleanup.resources,
    { reason: cause.cleanup.reason },
    { operation: OPERATION, cause },
  );
  return analysisErrorWithCleanupFailure(primary, cleanup, OPERATION);
};
