import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  BinaryImportsResult,
  InspectBinaryImportsInput,
} from "../../domain/native/binaryImports.js";
import type { Result } from "../../domain/result.js";

/** Stable read and import-table decoding, independent of any disassembler. */
export interface BinaryImportsPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  inspect(
    input: InspectBinaryImportsInput,
    options?: ExecutionOptions,
  ): Promise<Result<BinaryImportsResult, AnalysisError>>;
}
