import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import type { JvmDebugMetadataExecution } from "../application/jvm/JvmDebugMetadataPort.js";
import { AnalysisCleanupLeaseGroup } from "../artifacts/AnalysisCleanupLease.js";
import {
  ArtifactFileCancelled,
  ArtifactFileCleanupFailure,
} from "../artifacts/ArtifactFileOperation.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import {
  createJavaDebugMetadataEvidence,
  type InspectJvmDebugMetadataInput,
} from "../domain/jvm/javaDebugMetadataReport.js";
import { err, type Result } from "../domain/result.js";
import { jvmCleanupError } from "./jvmFailures.js";

const OPERATION = "inspect_jvm_debug_metadata";

/** One caller-selected JAR member inspection. */
export interface JarRequest {
  readonly jar: string;
  /** The normalized member path. */
  readonly entry: string;
  readonly input: InspectJvmDebugMetadataInput;
  readonly signal: AbortSignal | undefined;
}

/**
 * A finished JAR read. The archive is read through the admitted descriptor
 * alone, so its close is the only cleanup the inspection waits on.
 */
export class JarInspection {
  constructor(
    readonly result: Result<JvmDebugMetadataExecution, AnalysisError>,
  ) {}
}

/** The completed inspection carried by a failed or cancelled final close. */
export const completedJarInspection = (
  cause: unknown,
): JarInspection | undefined => {
  const value =
    cause instanceof ArtifactFileCleanupFailure &&
    cause.fileCleanupFailure.outcome.kind === "completed"
      ? cause.fileCleanupFailure.outcome.value
      : cause instanceof ArtifactFileCancelled
        ? cause.fileCancellation.outcome.value
        : undefined;
  return value instanceof JarInspection ? value : undefined;
};

/**
 * Classify a completed JAR inspection after its final close. A primary failure
 * keeps precedence over late cancellation; a completed result is retained as
 * the error's observation under cancellation or unconfirmed cleanup. A
 * descriptor cleanup failure is bound to its exact leases, so the error
 * resolves after close() releases them; an unknown owner leaves it unresolved.
 */
export const finishJarInspection = (
  { input, signal }: JarRequest,
  inspection: JarInspection,
  closeOutcome: unknown,
): Result<JvmDebugMetadataExecution, AnalysisError> => {
  const fileCleanup =
    closeOutcome instanceof ArtifactFileCleanupFailure
      ? closeOutcome
      : undefined;
  const cancelled = signal?.aborted === true;
  const { result } = inspection;
  if (fileCleanup === undefined) {
    if (!result.ok || !cancelled) return result;
    return err(
      new AnalysisCancelledError(OPERATION, {
        cause: signal.reason,
        partialObservation: createJavaDebugMetadataEvidence(
          input,
          result.value,
        ),
      }),
    );
  }
  const cleanupFacts = {
    reason: fileCleanup.cleanup?.reason ?? "",
    resources: [...new Set(fileCleanup.cleanup?.resources ?? [])],
  };
  const cleanupCause = fileCleanup;
  const evidence = result.ok
    ? createJavaDebugMetadataEvidence(input, result.value)
    : undefined;
  const error = result.ok
    ? cancelled
      ? analysisErrorWithCleanupFailure(
          new AnalysisCancelledError(OPERATION, {
            cause: signal.reason,
            partialObservation: evidence,
          }),
          jvmCleanupError(cleanupFacts, cleanupCause),
          OPERATION,
        )
      : jvmCleanupError(cleanupFacts, cleanupCause, evidence)
    : analysisErrorWithCleanupFailure(
        result.error,
        jvmCleanupError(cleanupFacts, cleanupCause),
        OPERATION,
      );
  if (fileCleanup.cleanupLeases !== undefined)
    new AnalysisCleanupLeaseGroup(error, [...fileCleanup.cleanupLeases]);
  return err(error);
};
