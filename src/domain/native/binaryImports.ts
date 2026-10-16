import { z } from "zod";

import { localPathStringSchema } from "../localPath.js";

/**
 * `inspect_binary_imports`: static import/export facts of a local executable,
 * grouped into behaviour categories with ATT&CK technique IDs and confidence
 * tiers, plus runtime-resolution hints and packing indicators. Facts for an
 * automated triage step; never a verdict. PE today, ELF later.
 */

const uint = z.number().int().nonnegative();
const digest = z.string().regex(/^[0-9a-f]{64}$/);

export const inspectBinaryImportsInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to a PE image (.exe, .dll, .sys)",
  ),
  categories: z
    .array(z.string().min(1).max(64))
    .max(64)
    .optional()
    .describe(
      "Behaviour categories to report (default: the sensitive set; add file_enumeration to opt in)",
    ),
  detail: z
    .enum(["summary", "imports"])
    .optional()
    .describe(
      'Default "summary"; "imports" also returns the full import and export tables',
    ),
});
export type InspectBinaryImportsInput = z.infer<
  typeof inspectBinaryImportsInputSchema
>;

const confidence = z.enum(["strong", "medium", "weak"]);

const capabilityApi = z.strictObject({
  api: z.string(),
  dll: z.string(),
  /**
   * `address_table`: found only in an unbound descriptor's FirstThunk table,
   * which disagrees with the lookup table the loader binds. Never bound, but
   * what pefile/VirusTotal report; the disagreement itself is evasion evidence.
   */
  via: z.enum(["import", "delay", "address_table"]),
  confidence,
  argument_dependent: z.boolean(),
});

const capability = z.strictObject({
  category: z.string(),
  attack: z.array(z.string()),
  /** Strongest tier among the matched APIs. */
  confidence,
  /** Matched imports in this category (all of them, not just the sample). */
  total: uint,
  /** Up to 8 matched APIs, strongest first. */
  apis: z.array(capabilityApi),
});

const importedSymbol = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("name"), name: z.string(), hint: uint }),
  z.strictObject({
    kind: z.literal("ordinal"),
    ordinal: uint,
    /** pefile-compatible name (`ord<N>` when the DLL has no ordinal table). */
    resolved: z.string(),
    resolved_from_table: z.boolean(),
  }),
  z.strictObject({ kind: z.literal("unreadable"), rva: uint }),
]);

const exportEntry = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("function"),
    ordinal: uint,
    name: z.string().nullable(),
    rva: uint,
  }),
  z.strictObject({
    kind: z.literal("forwarder"),
    ordinal: uint,
    name: z.string().nullable(),
    target: z.string().nullable(),
  }),
]);

export const binaryImportsResultSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: uint,
  }),
  format: z.strictObject({
    kind: z.literal("pe"),
    pe32_plus: z.boolean(),
    /** COFF machine as declared (always reported, even when undecoded). */
    machine: uint,
    architecture: z.string(),
    subsystem: uint,
    is_dll: z.boolean(),
    /** A CLI (.NET) header is present: behaviour lives in managed metadata. */
    is_dotnet: z.boolean(),
    timestamp: uint,
    entry_point_rva: uint,
  }),
  taxonomy_version: z.string(),
  /**
   * The import hash exactly as pefile 2024.8.26 computes it (import table only,
   * delay imports excluded), from an emulation of pefile's import parsing; it
   * can cover a different table than the imports REA reports (see
   * import_table_disagreements). Null when pefile would list no import.
   */
  imphash: z
    .string()
    .regex(/^[0-9a-f]{32}$/)
    .nullable(),
  counts: z.strictObject({
    dlls: uint,
    imports: uint,
    by_name: uint,
    by_ordinal: uint,
    ordinal_unresolved: uint,
    unreadable: uint,
    delay_dlls: uint,
    delay_imports: uint,
    delay_va_unmapped: uint,
    exports: uint,
    exports_named: uint,
    forwarders: uint,
    exports_unreadable: uint,
  }),
  categories_scanned: z.array(z.string()),
  capabilities: z.array(capability),
  /** DLLs in first-appearance order (up to 64); `api_set` marks api-ms-/ext-ms- names. */
  dlls: z.array(
    z.strictObject({
      name: z.string(),
      imports: uint,
      delay: z.boolean(),
      api_set: z.boolean(),
    }),
  ),
  dlls_truncated: z.boolean(),
  /**
   * Unbound import descriptors whose FirstThunk (address) table differs from
   * the OriginalFirstThunk (lookup) table the loader binds. Compilers emit
   * identical tables, so a disagreement is crafted; its address-table entries
   * appear in capabilities with via "address_table", not in counts or dlls.
   */
  import_table_disagreements: z.strictObject({
    count: uint,
    /** Up to 16 DLL names, in table order. */
    dlls: z.array(z.string()),
  }),
  runtime_resolution: z.strictObject({
    /** Imported APIs that resolve other APIs at runtime. */
    resolver_imports: z.array(z.string()),
    /**
     * Taxonomy API names found as strings outside the import set: possibly
     * resolved at runtime. Weak evidence, never an import.
     */
    api_strings: z.strictObject({
      count: uint,
      sample: z.array(
        z.strictObject({
          api: z.string(),
          offset: uint,
          encoding: z.enum(["ascii", "utf16le"]),
        }),
      ),
    }),
  }),
  packing: z.strictObject({
    import_count: uint,
    few_imports_with_resolvers: z.boolean(),
    entry_point_section: z.string().nullable(),
    entry_outside_code: z.boolean(),
    writable_executable_sections: z.array(z.string()),
    zero_raw_large_virtual_sections: z.array(z.string()),
    max_section_entropy: z
      .strictObject({ section: z.string(), entropy: z.number() })
      .nullable(),
    overlay: z
      .strictObject({ offset: uint, bytes: uint, entropy: z.number() })
      .nullable(),
  }),
  /** Set only with detail "imports". */
  detail: z
    .strictObject({
      imports: z.array(
        z.strictObject({
          dll: z.string(),
          table: z.enum(["import", "delay"]),
          symbols: z.array(importedSymbol),
        }),
      ),
      exports: z.strictObject({
        dll_name: z.string().nullable(),
        entries: z.array(exportEntry),
      }),
    })
    .nullable(),
  runtime_execution: z.literal("not-performed"),
  limitations: z.array(z.string()),
});
export type BinaryImportsResult = z.infer<typeof binaryImportsResultSchema>;

export const BINARY_IMPORTS_LIMITATIONS: readonly string[] = [
  "Static import-table facts only: no code executes and no instruction is analysed. Capabilities mean the binary imports APIs consistent with a behaviour, not that it performs it.",
  "Confidence tiers weigh signals: weak APIs are imported by ordinary software and the C runtime; argument_dependent APIs depend on arguments static analysis cannot see.",
  "APIs resolved at runtime (GetProcAddress, hashing, syscalls) are not imports; api_strings is a weak, separate hint, and obfuscated names are not found.",
  "Imports are what the Windows loader binds (the lookup table); imphash is pefile's, which can come from a different table on crafted images (import_table_disagreements), so the two can describe different symbols.",
  "Section entropy and the other packing indicators are facts, not evidence of packing on their own: compressed resources, installers and .NET images also raise them.",
];
