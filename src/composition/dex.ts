import { DexDebugMetadataService } from "../application/dex/DexDebugMetadataService.js";
import { DexFileProvider } from "../dex/DexFileProvider.js";
import { INSPECT_DEX_DEBUG_METADATA_CONTRACT } from "../contracts/dex/dexToolContracts.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";

/** Compose the in-process DEX reader without acquisition or import-time I/O. */
export const createDexDebugMetadataService = (): DexDebugMetadataService =>
  new DexDebugMetadataService(new DexFileProvider());

/**
 * Static descriptor binding the one DEX debug-metadata operation for CLI/MCP.
 * Construction performs no acquisition or target I/O.
 */
export const dexDebugMetadataModule = {
  contract: INSPECT_DEX_DEBUG_METADATA_CONTRACT,
  cliCommand: CLI_COMMANDS.inspectDexDebugMetadata,
  create(
    _environment: Readonly<NodeJS.ProcessEnv>,
    injected?: DexDebugMetadataService,
  ): Pick<DexDebugMetadataService, "inspect" | "close"> {
    const service = injected ?? createDexDebugMetadataService();
    return {
      inspect: service.inspect.bind(service),
      close: service.close.bind(service),
    };
  },
} as const;
