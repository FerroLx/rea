import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import type { DexFileParseError } from "../domain/dex/dexFile.js";
import { DEX_LIMITS } from "./DexFileRelease.js";

const OPERATION = "inspect_dex_debug_metadata";

const inputError = (
  reason: "invalid_format" | "invalid_value",
  message: string,
): AnalysisInputError =>
  new AnalysisInputError(OPERATION, undefined, [
    { path: ["path"], reason, message },
  ]);

/** Map a tagged DEX parse failure to the shared analysis error algebra. */
export const mapDexParseError = (
  error: DexFileParseError,
  path: string,
): AnalysisError => {
  switch (error.kind) {
    case "bad-magic":
      return new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        "The selected file does not begin with the DEX magic (dex\\n0NN).",
        {
          remediationAction:
            "Select a .dex file, or pass entry to select a classesN.dex inside an APK/ZIP.",
        },
      );
    case "compact-dex":
      return new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        "This is a compact dex (cdex) extracted from a vdex; it is a device-optimized format.",
        {
          remediationAction:
            "Provide a canonical .dex (e.g. from the APK), not an on-device odex/vdex/cdex.",
        },
      );
    case "reverse-endian":
      return new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        "This DEX declares the reverse-endian tag, which ART itself rejects; it is not read.",
      );
    case "unsupported-version":
      return new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        `DEX format version ${error.version} is not supported (reads 035, 037-040).`,
      );
    case "bad-header":
      return inputError(
        "invalid_format",
        `Malformed DEX header: ${error.detail}.`,
      );
    case "truncated":
      return inputError(
        "invalid_format",
        `DEX ended before a structure completed at byte ${String(error.offset)}.`,
      );
    case "budget-exceeded":
      return inputError(
        "invalid_value",
        `Declared ${error.resource} count (${String(error.declared)}) exceeds the remaining ${String(error.remaining)} bytes at byte ${String(error.offset)}.`,
      );
    case "invalid-index":
      return inputError(
        "invalid_value",
        `DEX offset ${String(error.index)} is outside the file bound ${String(error.bound)}.`,
      );
  }
};

/** Preserve lifecycle failures and distinguish cancellation, access, integrity and limits. */
export const dexFileFailure = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  const cleanup =
    cause instanceof ArtifactReaderFailure && cause.cleanup !== undefined
      ? { cleanup: cause.cleanup }
      : {};
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, { cause, ...cleanup });
  if (cause instanceof ArtifactReaderFailure && cause.reason === "limit")
    return new AnalysisResourceConstraintError(
      OPERATION,
      "file-size",
      reason,
      { max_input_bytes: DEX_LIMITS.inputBytes },
      {
        cause,
        ...cleanup,
        remediationAction:
          "The size budget is fixed; select a smaller artifact.",
      },
    );
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, path, reason, {
      cause,
      ...cleanup,
    });
  if (
    cause instanceof Error &&
    "code" in cause &&
    (cause.code === "EACCES" || cause.code === "EPERM")
  )
    return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
      cause,
      ...cleanup,
    });
  // After input validation the only work is reading the file and an in-process
  // parse, so a remaining thrown error is an artifact-read problem.
  return new AnalysisInputError(OPERATION, { cause, ...cleanup }, [
    { path: ["path"], reason: "invalid_value", message: reason },
  ]);
};
