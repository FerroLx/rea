import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { DexDebugMetadataService } from "../application/dex/DexDebugMetadataService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { err } from "../domain/result.js";
import { dexDebugMetadataModule } from "../composition/dex.js";
import type { Logger } from "pino";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Bind the named DEX contract to shared validation and session Evidence recording. */
export const registerDexTools = (
  server: EvidenceMcpServer,
  service: Pick<DexDebugMetadataService, "inspect">,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = dexDebugMetadataModule.contract;
  const handler = createEvidenceToolHandler(
    server,
    async (rawInput, options) => {
      const parsed = contract.inputSchema.safeParse(rawInput);
      if (!parsed.success)
        return err(
          analysisInputErrorFromIssues(
            contract.name,
            parsed.error.issues,
            rawInput,
            { cause: parsed.error },
          ),
        );
      return service.inspect(parsed.data, options);
    },
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    handler(contract),
  );
};
