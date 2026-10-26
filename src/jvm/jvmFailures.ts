import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { completedStableArtifact } from "../artifacts/readStableArtifact.js";
import type { ArtifactLimitBoundary } from "../domain/artifactOperationError.js";
import {
  ArtifactFileCleanupFailure,
  artifactFileCancellationCause,
  bindArtifactFileCleanup,
} from "../artifacts/ArtifactFileOperation.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { fileSnapshotPartialObservationSchema } from "../domain/fileSnapshotObservation.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import {
  AnalysisError,
  type AnalysisPartialObservation,
} from "../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import type { JavaClassFileParseError } from "../domain/jvm/javaClassFile.js";
import { JVM_PROVIDER_IDENTITY } from "./JvmClassFileRelease.js";

const OPERATION = "inspect_jvm_debug_metadata";

/** Map a tagged class-file parse failure to the shared analysis error algebra. */
export const mapParseError = (
  error: JavaClassFileParseError,
  path: string,
): AnalysisError => {
  switch (error.kind) {
    case "bad-magic":
      return new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        "The selected file does not begin with the 0xCAFEBABE class-file magic.",
        {
          remediationAction:
            "Select a single compiled .class file; archives and other formats are not class files.",
        },
      );
    case "truncated":
      return new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_format",
          message: `Class file ended before a structure completed at byte ${String(error.offset)}.`,
        },
      ]);
    case "trailing-bytes":
      return new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_format",
          message: `Class file has ${String(error.count)} extra bytes after its structure ends at byte ${String(error.offset)}; the JVM rejects such a class.`,
        },
      ]);
    case "unsupported-constant-tag":
      return new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Unsupported constant-pool tag ${String(error.tag)} at byte ${String(error.offset)}.`,
        },
      ]);
    case "invalid-utf8":
      return new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Malformed modified-UTF8 constant at byte ${String(error.offset)}.`,
        },
      ]);
    case "invalid-constant-pool":
      return new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_format",
          message:
            error.reason === "zero-count"
              ? `Class file declares a constant_pool_count of 0 at byte ${String(error.offset)}; the JVM rejects such a class.`
              : `Class file places a long or double constant in the constant pool's final slot at byte ${String(error.offset)}, so its second slot lies outside the pool; the JVM rejects such a class.`,
        },
      ]);
    case "invalid-attribute-name":
      return new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_format",
          message: `Attribute name index ${String(error.index)} at byte ${String(error.offset)} does not name a CONSTANT_Utf8 entry; the JVM rejects such a class.`,
        },
      ]);
    case "budget-exceeded":
      return new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Declared ${error.resource} count (${String(error.declared)}) exceeds the remaining ${String(error.remaining)} bytes at byte ${String(error.offset)}.`,
        },
      ]);
    case "retained-attribute-budget":
      return new AnalysisResourceConstraintError(
        OPERATION,
        "capacity",
        `The class declares more than ${String(error.limit)} debug-relevant attributes (at byte ${String(error.offset)}); refused before materialising them.`,
        { max_retained_attributes: error.limit },
      );
  }
};

/**
 * Map a read or analysis failure (mirrors the Rust reader). A failed descriptor
 * close keeps the read's primary failure (or the caller's cancellation), adds
 * the cleanup as a ProviderCleanupError in one aggregate, and binds the exact
 * retained leases so the error resolves once the provider's close() releases
 * them.
 */
export const jvmClassFileFailure = (
  cause: unknown,
  path: string,
  signal?: AbortSignal,
): AnalysisError => {
  const primary =
    cause instanceof ArtifactFileCleanupFailure &&
    cause.fileCleanupFailure.outcome.kind === "failed"
      ? primaryFailure(cause.fileCleanupFailure.outcome.cause, path, signal)
      : cause instanceof ArtifactFileCleanupFailure && signal?.aborted
        ? new AnalysisCancelledError(OPERATION, { cause: signal.reason })
        : primaryFailure(cause, path, signal);
  // A loose class file whose stable read and hash completed before its close
  // failed or was cancelled keeps that digest and size, as the other
  // stable-read providers do.
  const snapshot = completedStableArtifact(cause);
  if (snapshot !== undefined)
    primary.retainPartialObservation(
      fileSnapshotPartialObservationSchema.parse({
        kind: "file-snapshot-hash",
        path,
        sha256: snapshot.sha256,
        bytes: snapshot.bytes.length,
      }),
    );
  if (!(cause instanceof ArtifactReaderFailure) || cause.cleanup === undefined)
    return primary;
  const error = analysisErrorWithCleanupFailure(
    primary,
    jvmCleanupError(cause.cleanup, cause),
    OPERATION,
  );
  bindArtifactFileCleanup(cause, error);
  return error;
};

/** The provider-owned cleanup fact for resources that remain retained. */
export const jvmCleanupError = (
  cleanup: { readonly reason: string; readonly resources: readonly string[] },
  cause: unknown,
  partialObservation?: AnalysisPartialObservation,
): ProviderCleanupError =>
  new ProviderCleanupError(
    JVM_PROVIDER_IDENTITY.id,
    cleanup.resources,
    { reason: cleanup.reason },
    {
      cause,
      operation: OPERATION,
      ...(partialObservation === undefined ? {} : { partialObservation }),
    },
  );

const INPUT_ERROR_CODES = new Set([
  "ENOENT",
  "ENOTDIR",
  "ELOOP",
  "ENAMETOOLONG",
  "EISDIR",
  "ENOTFILE",
]);

/** Distinguish cancellation, caller input, access, integrity and limits from execution failures. */
const primaryFailure = (
  cause: unknown,
  path: string,
  signal: AbortSignal | undefined,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  // A cancelled wait may surface the caller's own abort reason unwrapped.
  if (signal?.aborted && cause === signal.reason)
    return new AnalysisCancelledError(OPERATION, { cause });
  if (cause instanceof ArtifactReaderFailure) return readerFailure(cause, path);
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
        cause,
      });
    if (INPUT_ERROR_CODES.has(String(cause.code)))
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected artifact could not be read (${String(cause.code)}): ${cause.message}`,
        },
      ]);
  }
  return executionFailure(cause, path);
};

/** Every reader bound REA applies here is fixed; say what would fit it. */
const LIMIT_REMEDIATION: Readonly<Record<ArtifactLimitBoundary, string>> = {
  "file-size":
    "The class-file size budget is fixed; select a smaller artifact.",
  memory:
    "The JAR's central directory exceeds REA's fixed metadata read budget; this archive cannot be inspected as is.",
  capacity:
    "The JAR members REA reads (its manifest and the selected class) expand past REA's fixed decompression budget for an archive of this size; this archive cannot be inspected as is.",
};

const readerFailure = (
  cause: ArtifactReaderFailure,
  path: string,
): AnalysisError => {
  switch (cause.reason) {
    case "cancelled":
      return new AnalysisCancelledError(OPERATION, {
        cause: artifactFileCancellationCause(cause),
      });
    case "limit":
      // Report the bound the reader actually hit (class-file size, ZIP
      // metadata read, or decompression budget), never a substitute.
      return new AnalysisResourceConstraintError(
        OPERATION,
        cause.boundary ?? "memory",
        cause.message,
        cause.limit === undefined
          ? null
          : { [cause.limit.key]: cause.limit.maximum },
        {
          cause,
          retryable: false,
          remediationAction: LIMIT_REMEDIATION[cause.boundary ?? "memory"],
        },
      );
    case "integrity":
      return new AnalysisArtifactChangedError(OPERATION, path, cause.message, {
        cause,
      });
    case "path":
    case "format":
      return new AnalysisInputError(OPERATION, { cause }, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
    case "io":
    case "unavailable":
      return executionFailure(cause, path);
  }
};

/** Local I/O and lifecycle faults are the reader's execution failures, not caller input. */
const executionFailure = (cause: unknown, path: string): AnalysisError =>
  new ProviderAdapterError(JVM_PROVIDER_IDENTITY.id, OPERATION, {
    cause,
    diagnostics: {
      path,
      reason: cause instanceof Error ? cause.message : String(cause),
    },
  });
