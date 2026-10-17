import { z } from "zod";

import { localPathStringSchema } from "../localPath.js";

/**
 * `inspect_pe_imports`: static import/export facts of a local executable,
 * grouped into behaviour categories with ATT&CK technique IDs and confidence
 * tiers, plus runtime-resolution hints and packing indicators. Facts for an
 * automated triage step; never a verdict. PE today, ELF later.
 */

const uint = z.number().int().nonnegative();
const digest = z.string().regex(/^[0-9a-f]{64}$/);

export const inspectPeImportsInputSchema = z.strictObject({
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
});
export type InspectPeImportsInput = z.infer<typeof inspectPeImportsInputSchema>;

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

/** One taxonomy API name found as a string outside the import set. */
const apiStringHit = z.strictObject({
  api: z.string(),
  /** File offset of the string's first byte. */
  offset: uint,
  encoding: z.enum(["ascii", "utf16le"]),
});

/**
 * Most API-string hits retained in the complete result. Each hit serializes to
 * at most 128 bytes (a 64-character identifier, a file offset and an encoding),
 * so the list is reserved 1 MiB of the 8 MiB complete-result ceiling; hits past
 * it are counted (`omitted`), never listed.
 */
export const PE_API_STRING_HITS_MAX = 8192;

const winCertificateTypes = [
  "X509",
  "PKCS_SIGNED_DATA",
  "RESERVED_1",
  "TS_STACK_SIGNED",
] as const;

/**
 * Signer facts read from a PKCS_SIGNED_DATA entry's SignedData, located by the
 * first SignerInfo's issuer and serial number. Read, never verified.
 */
const authenticodeSigner = z.discriminatedUnion("status", [
  z.strictObject({
    status: z.literal("extracted"),
    /** SHA-256 of the signer certificate's DER encoding. */
    certificate_sha256: digest,
    /** X.509 names as Node.js renders them; null when it cannot parse them. */
    subject: z.string().nullable(),
    issuer: z.string().nullable(),
    /** The certificate serial number as upper-case hex, without DER sign padding. */
    serial_number: z.string(),
    /** Certificates embedded in the SignedData (chain and timestamp certificates included). */
    certificates: uint,
    /** SignerInfos declared; Authenticode requires exactly one. */
    signer_infos: uint,
    /** The signed content type OID (Authenticode: 1.3.6.1.4.1.311.2.1.4). */
    content_type: z.string(),
  }),
  z.strictObject({ status: z.literal("unreadable"), reason: z.string() }),
  /** Not a PKCS_SIGNED_DATA entry: its contents are not examined. */
  z.strictObject({ status: z.literal("not-examined") }),
]);

const winCertificate = z.strictObject({
  /** File offset of the WIN_CERTIFICATE header. */
  offset: uint,
  /** dwLength: header and certificate bytes, before 8-byte alignment. */
  length: uint,
  revision: uint,
  type: uint,
  type_name: z.enum([...winCertificateTypes, "unknown"]),
  signer: authenticodeSigner,
});

const notVerified = {
  /** The signature, image digest and certificate chain are never checked. */
  verification: z.literal("not-performed"),
  /** Publisher trust, revocation and chain building are never assessed. */
  trust: z.literal("not-assessed"),
};

/** The security data directory's VirtualAddress is a file offset, not an RVA. */
const certificateTable = z.strictObject({ offset: uint, size: uint });

/**
 * Authenticode certificate table facts from IMAGE_DIRECTORY_ENTRY_SECURITY.
 * `malformed` keeps the declared table and every entry read before the defect;
 * it never means unsigned.
 */
const authenticode = z.discriminatedUnion("status", [
  /** No security directory, or one with zero offset and size. */
  z.strictObject({ status: z.literal("absent") }),
  z.strictObject({
    status: z.literal("present"),
    table: certificateTable,
    entries: z.array(winCertificate),
    /** Entries past the first 64, counted but not listed. */
    entries_omitted: uint,
    /** File bytes after the table's end: outside it, but not covered by it. */
    bytes_after_table: uint,
    ...notVerified,
  }),
  z.strictObject({
    status: z.literal("malformed"),
    table: certificateTable,
    reason: z.string(),
    entries: z.array(winCertificate),
    entries_omitted: uint,
    ...notVerified,
  }),
]);

/** One descriptor's symbols (ordinals resolved as pefile does, `ord<N>` otherwise). */
const importDescriptor = z.strictObject({
  dll: z.string(),
  symbols: z.array(importedSymbol),
});

export const peImportsResultSchema = z.strictObject({
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
  /**
   * Loaded DLLs in first-appearance order (up to 64); `api_set` marks
   * api-ms-/ext-ms- names. A descriptor whose import list is empty (as ARM64X
   * images emit for EC-only imports) is still a dependency, with 0 imports.
   */
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
   * appear in capabilities with via "address_table", never in counts, dll import totals or the tables.
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
      /** Every hit found, listed or not. */
      count: uint,
      /** Up to 8 hits of distinct APIs, in scan order; all listed hits page as `api_strings`. */
      sample: z.array(apiStringHit),
      /** Hits counted past PE_API_STRING_HITS_MAX and absent from the `api_strings` list. */
      omitted: uint,
    }),
  }),
  authenticode,
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
    /**
     * File bytes after the last section's raw data, excluding a well-formed
     * certificate table (`authenticode.status` "present"): `offset` is the
     * first such byte, `bytes` and `entropy` cover only those bytes. Null when
     * nothing but the certificate table follows the sections.
     */
    overlay: z
      .strictObject({
        offset: uint,
        bytes: uint,
        entropy: z.number(),
        /** Certificate-table bytes inside the overlay, excluded above. */
        certificate_table_bytes: uint,
      })
      .nullable(),
  }),
  /** Import-table descriptors the loader binds, in table order. */
  imports: z.array(importDescriptor),
  /** Delay-load descriptors, in table order. */
  delay_imports: z.array(importDescriptor),
  /**
   * Every listed API-string hit (up to PE_API_STRING_HITS_MAX), in scan order:
   * section by section, ASCII, then UTF-16LE at even and odd alignment.
   */
  api_strings: z.array(apiStringHit),
  exports: z.strictObject({
    dll_name: z.string().nullable(),
    entries: z.array(exportEntry),
  }),
  runtime_execution: z.literal("not-performed"),
  limitations: z.array(z.string()),
});
export type PeImportsResult = z.infer<typeof peImportsResultSchema>;

export const PE_IMPORTS_LIMITATIONS: readonly string[] = [
  "Static import-table facts only: no code executes and no instruction is analysed. Capabilities mean the binary imports APIs consistent with a behaviour, not that it performs it.",
  "Confidence tiers weigh signals: weak APIs are imported by ordinary software and the C runtime; argument_dependent APIs depend on arguments static analysis cannot see.",
  "APIs resolved at runtime (GetProcAddress, hashing, syscalls) are not imports; api_strings is a weak, separate hint, and obfuscated names are not found.",
  "Imports are what the Windows loader binds (the lookup table); imphash is pefile's, which can come from a different table on crafted images (import_table_disagreements), so the two can describe different symbols.",
  "Section entropy and the other packing indicators are facts, not evidence of packing on their own: compressed resources, installers and .NET images also raise them.",
];

/** Stated whenever a certificate table is declared. */
export const PE_AUTHENTICODE_LIMITATION =
  "Authenticode facts are read from the certificate table only: the signature, the image digest and the certificate chain are not cryptographically verified, and trust (chain to a root, revocation, publisher reputation) is not assessed. Nested signatures and timestamps inside unsigned attributes are not examined.";
