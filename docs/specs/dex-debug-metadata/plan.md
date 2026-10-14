# Implementation plan

Land as its own slice on `feat/dex-debug-metadata`, stacked on the JVM branch
(`feat/2377-jvm-debug-metadata`) because it reuses shared helpers that branch
introduced (`peekArtifactMagic`, the admit-once descriptor) and extracts more.

1. **Shared extraction.** Move the modified-UTF8 decoder (DEX `string_data_item`
   is MUTF-8 too) out of the JVM framer into `src/domain/modifiedUtf8.ts`, and
   the zip-magic sniff / member-path normalize / bounded member reader into
   `src/artifacts/archiveMember.ts`; refactor the JVM provider to consume both.
2. **Domain.** `dexFile.ts` (bounded framing + LEB128), `dexDebugInfo.ts` (the
   `debug_info_item` state machine with implicit-parameter seeding),
   `dexStrings.ts` (string/type/method/proto resolution),
   `dexDebugMetadata.ts` (summary tally + readiness + per-class detail),
   `dexDebugMetadataReport.ts` (schema + input + projections).
3. **Adapter.** `DexFileProvider.ts` (loose `.dex` + APK multidex, admit-once),
   `dexEntry.ts`, `dexFailures.ts`, `DexFileRelease.ts`.
4. **Application.** `DexDebugMetadataPort.ts` + `DexDebugMetadataService.ts`.
5. **Wiring.** Contract, composition, CLI (`inspect-dex-debug-metadata`), MCP
   registration, effect audit, `TOOL_CONTRACTS`, `createServer`, product catalog.
6. **Tests.** Domain + adapter units (hand-built DEX fixtures, no committed
   binaries); `verify:dex` real lane (d8/dexdump); conformance.
7. **Review.** Independent (Fable) review; fix findings.
8. **Docs.** This spec dir + the analyst guide + the docs index link.
