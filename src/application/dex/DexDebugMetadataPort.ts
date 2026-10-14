import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectDexDebugMetadataInput } from "../../domain/dex/dexDebugMetadataReport.js";
import type { EvidenceSubjectTarget } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";

/** Successful DEX inspection identifies the selected local file: a .dex or its APK/ZIP. */
export type DexDebugMetadataExecution = Omit<AnalysisExecution, "subject"> & {
  readonly subject: EvidenceSubjectTarget & {
    readonly format: "file" | "apk" | "zip";
  };
};

/** Replaceable offline DEX reader, independent of target execution, adb, and network clients. */
export interface DexDebugMetadataPort {
  /** Retry removal of any retained resources; failures preserve ownership for another attempt. */
  close(): Promise<void>;
  inspect(
    input: InspectDexDebugMetadataInput,
    options?: ExecutionOptions,
  ): Promise<Result<DexDebugMetadataExecution, AnalysisError>>;
}
