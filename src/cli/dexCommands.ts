import { z } from "incur";
import { resolve } from "node:path";
import type { Logger } from "pino";

import { dexDebugMetadataModule } from "../composition/dex.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected DEX artifact through the shared workflow. */
export const registerDexCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  const service = dexDebugMetadataModule.create(environment);
  cli.command(dexDebugMetadataModule.cliCommand, {
    description:
      "Inspect compiler-emitted debug metadata in a selected local Android .dex, or a classes*.dex inside an APK/ZIP",
    args: z.object({
      path: z
        .string()
        .describe("Local .dex artifact, or an .apk/.zip when --entry is given"),
    }),
    options: z.object({
      entry: z
        .string()
        .optional()
        .describe(
          "DEX member to select inside the archive, e.g. classes2.dex; omit to summarize every classes*.dex",
        ),
      "class-descriptor": z
        .string()
        .optional()
        .describe(
          "Drill into one class for per-method detail, e.g. Lcom/example/Foo;",
        ),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        try {
          return await logCliCommand(
            logger,
            dexDebugMetadataModule.cliCommand,
            async () => {
              const result = await service.inspect(
                {
                  path: resolve(args.path),
                  ...(options.entry === undefined
                    ? {}
                    : { entry: options.entry }),
                  ...(options["class-descriptor"] === undefined
                    ? {}
                    : { class_descriptor: options["class-descriptor"] }),
                },
                { signal },
              );
              return result.ok
                ? result.value
                : projectAnalysisError(result.error);
            },
          );
        } finally {
          await service.close();
        }
      }),
  });
};
