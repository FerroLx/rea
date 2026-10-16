import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { PeImportsService } from "../application/binaryDiagnostics/PeImportsService.js";
import type { EvidenceLookup } from "../application/EvidenceInputResolver.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import {
  requireAnalysisViewRetention,
  summarizeRetainedAnalysis,
} from "../application/analysisView/AnalysisViewService.js";
import { toolContract } from "../contracts/toolContracts.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { err } from "../domain/result.js";
import type { Logger } from "pino";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/**
 * Register the explicit-file PE import-surface workflow. Detail selects only
 * delivery: summary retains the complete Evidence in this session and returns
 * its summary view; the tables page through inspect_analysis_view.
 */
export const registerPeImportsTool = (
  server: EvidenceMcpServer,
  service: PeImportsService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
  evidenceById?: EvidenceLookup,
): void => {
  const contract = toolContract("inspect_pe_imports");
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
      const { detail, ...input } = parsed.data;
      const retention = { recordEvidence, evidenceById };
      if (detail === "summary") {
        const ready = requireAnalysisViewRetention(contract.name, retention);
        if (!ready.ok) return ready;
      }
      const inspected = await service.inspect(input, options);
      return detail === "summary" && inspected.ok
        ? summarizeRetainedAnalysis(inspected.value, retention)
        : inspected;
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
