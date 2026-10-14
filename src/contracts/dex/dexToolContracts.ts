import {
  dexDebugMetadataResultSchema,
  inspectDexDebugMetadataInputSchema,
} from "../../domain/dex/dexDebugMetadataReport.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Static Android DEX debug-readiness inspection of a selected local .dex or APK member. */
export const INSPECT_DEX_DEBUG_METADATA_CONTRACT = {
  name: "inspect_dex_debug_metadata",
  ...toolContractMetadata("inspect_dex_debug_metadata"),
  kind: "artifact-provider",
  description:
    "Inspect compiler-emitted debug metadata in a selected local Android DEX, to judge debugging readiness before attaching a debugger or reading a decompilation. Reads source_file_idx and the debug_info_item (line positions, local-variable scopes, parameter names) and reports, per DEX member, whether debugging survives: a whole-file readiness summary by default (methods with code, with debug_info and with parameter names; line positions; local declarations; distinct source-file names; readiness present, partial or stripped), or, when class_descriptor (e.g. Lcom/example/Foo;) is given, full per-method detail with names, JVM-form descriptors and locals (name, type, signature, register, scope, out_of_range). Pass path alone for a standalone .dex; pass an APK/ZIP to summarize every root classes*.dex, or add entry (e.g. classes2.dex) to select one member. No Android code executes; no device or adb is involved; odex/vdex/oat/cdex are refused. Line positions are compiler-emitted and may be R8-renumbered synthetic lines needing a mapping.txt, not asserted source lines. SHA-256 identifies the exact selected bytes, not authenticity.",
  inputSchema: inspectDexDebugMetadataInputSchema,
  outputSchema: evidenceResultOf(dexDebugMetadataResultSchema),
  examples: [
    {
      title: "Summarize debug readiness across an APK's DEX members",
      input: { path: "/artifacts/app.apk" },
    },
    {
      title:
        "Inspect one class inside a selected DEX for full per-method detail",
      input: {
        path: "/artifacts/classes.dex",
        class_descriptor: "Lcom/example/Service;",
      },
    },
  ],
} as const satisfies ToolContract;

/** Keep the public catalog in its existing order, using its named contract. */
export const DEX_TOOL_CONTRACTS = [
  INSPECT_DEX_DEBUG_METADATA_CONTRACT,
] as const;
