/** Identity of REA's in-process DEX reader (no external engine, no device). */
export const DEX_PROVIDER_IDENTITY = {
  id: "dex-file",
  name: "REA DEX reader",
  version: null,
} as const;

export const DEX_LIMITS = {
  /** A single `.dex` far exceeding this is rejected before allocation (real dex ~tens of MiB). */
  inputBytes: 64 * 1024 * 1024,
  /** Ceiling on a selected APK/ZIP's size (its digest is streamed, not retained). */
  archiveBytes: 512 * 1024 * 1024,
  /** Ceiling on an archive's central-directory metadata read. */
  archiveMetadataBytes: 16 * 1024 * 1024,
  /** Inline result ceiling; a decoded result past this is refused, not truncated. */
  outputBytes: 8 * 1024 * 1024,
  /** Cap on root `classes*.dex` members summarized for an archive; refuse past it. */
  maxDexMembers: 64,
} as const;
