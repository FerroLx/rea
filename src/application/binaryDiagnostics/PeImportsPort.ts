import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  PeImportsResult,
  InspectPeImportsInput,
} from "../../domain/native/peImports.js";
import type { Result } from "../../domain/result.js";

/** Stable read and import-table decoding, independent of any disassembler. */
export interface PeImportsPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  inspect(
    input: InspectPeImportsInput,
    options?: ExecutionOptions,
  ): Promise<Result<PeImportsResult, AnalysisError>>;
}
