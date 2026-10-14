/**
 * Public contract shape for `inspect_dex_debug_metadata` and the projection from
 * decoded DEX facts into that JSON. The domain owns the schema so CLI and MCP
 * present identical, validated facts. Two modes: a whole-file (per-dex-member)
 * readiness `summary`, and full per-method `class-detail` for one selected class.
 */
import { z } from "zod";

import type { EvidenceSubjectTarget } from "../evidence.js";
import { localPathStringSchema } from "../localPath.js";
import type { DexClassDetail, DexSummary } from "./dexDebugMetadata.js";

const digest = z.string().regex(/^[a-f0-9]{64}$/);

/** A DEX type descriptor in internal form, e.g. `Lcom/example/Foo;`. */
const CLASS_DESCRIPTOR = /^L[^;]+;$/;

/** All artifacts are explicitly selected local files; references never trigger acquisition. */
export const inspectDexDebugMetadataInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute selected local .dex artifact, or an APK/ZIP when entry is given",
  ),
  entry: z
    .string()
    .min(1)
    .optional()
    .describe(
      "DEX member to select inside an APK/ZIP at path, e.g. classes2.dex; omit to summarize every classes*.dex",
    ),
  class_descriptor: z
    .string()
    .regex(
      CLASS_DESCRIPTOR,
      "Expected a type descriptor in Lpackage/Name; form",
    )
    .optional()
    .describe(
      "Drill into one class for full per-method detail, e.g. Lcom/example/Foo;; omit for the readiness summary",
    ),
});
export type InspectDexDebugMetadataInput = z.infer<
  typeof inspectDexDebugMetadataInputSchema
>;

const readiness = z.enum(["present", "partial", "stripped"]);

const summarySchema = z.strictObject({
  dex_version: z.string(),
  class_count: z.number().int().nonnegative(),
  methods_with_code: z.number().int().nonnegative(),
  methods_with_debug_info: z.number().int().nonnegative(),
  methods_with_parameter_names: z.number().int().nonnegative(),
  line_positions: z.number().int().nonnegative(),
  local_declarations: z.number().int().nonnegative(),
  set_file_events: z.number().int().nonnegative(),
  source_file_present: z.number().int().nonnegative(),
  distinct_source_files: z.strictObject({
    count: z.number().int().nonnegative(),
    sample: z.array(z.string()),
  }),
  readiness,
});

const memberSummarySchema = z.strictObject({
  entry: z.string().nullable(),
  sha256: digest,
  bytes: z.number().int().nonnegative(),
  summary: summarySchema,
});

const localSchema = z.strictObject({
  register: z.number().int().nonnegative(),
  name: z.string().nullable(),
  type: z.string().nullable(),
  signature: z.string().nullable(),
  start_address: z.number().int(),
  end_address: z.number().int(),
  out_of_range: z.boolean(),
});

const methodDetailSchema = z.strictObject({
  name: z.string().nullable(),
  descriptor: z.string().nullable(),
  state: z.enum([
    "present",
    "partial",
    "stripped",
    "malformed",
    "not-applicable",
  ]),
  has_code: z.boolean(),
  line_count: z.number().int().nonnegative(),
  parameter_names: z.array(z.string().nullable()),
  locals: z.array(localSchema),
  set_file_events: z.number().int().nonnegative(),
});

const classDetailSchema = z.strictObject({
  entry: z.string().nullable(),
  descriptor: z.string().nullable(),
  source_file: z.string().nullable(),
  methods: z.array(methodDetailSchema),
});

export const dexDebugMetadataResultSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: z.number().int().nonnegative(),
  }),
  container: z.enum(["dex-file", "apk", "zip"]),
  mode: z.enum(["summary", "class-detail"]),
  /** One per summarized DEX member (just one for a loose .dex or a selected entry). */
  members: z.array(memberSummarySchema),
  /** Set only in class-detail mode. */
  class_detail: classDetailSchema.nullable(),
  runtime_execution: z.literal("not-performed"),
  limitations: z.array(z.string()),
});
export type DexDebugMetadataResult = z.infer<
  typeof dexDebugMetadataResultSchema
>;

export const DEX_DEBUG_METADATA_LIMITATIONS: readonly string[] = [
  "Static DEX inspection only. No Android code executes; positions, registers and names are read from compiler-emitted debug_info, not from a decompiler or a live process.",
  "Line positions are compiler-emitted and may be R8/ProGuard-renumbered synthetic lines that require a mapping.txt to retrace; they are not asserted source lines.",
  'A single distinct source-file name across classes (e.g. "SourceFile") indicates -renamesourcefileattribute; readiness is a conservative derived label over observed tallies.',
  "SHA-256 identifies the exact selected bytes; it does not establish authenticity or which compiler produced the artifact. Only canonical .dex is read; odex/vdex/oat/cdex are refused.",
];

const projectSummary = (
  summary: DexSummary,
): z.infer<typeof summarySchema> => ({
  dex_version: summary.dexVersion,
  class_count: summary.classCount,
  methods_with_code: summary.methodsWithCode,
  methods_with_debug_info: summary.methodsWithDebugInfo,
  methods_with_parameter_names: summary.methodsWithParameterNames,
  line_positions: summary.linePositions,
  local_declarations: summary.localDeclarations,
  set_file_events: summary.setFileEvents,
  source_file_present: summary.sourceFilePresent,
  distinct_source_files: {
    count: summary.distinctSourceFiles.count,
    sample: [...summary.distinctSourceFiles.sample],
  },
  readiness: summary.readiness,
});

export interface DexArtifactIdentity {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

export interface DexSummaryMember {
  readonly entry: string | null;
  readonly sha256: string;
  readonly bytes: number;
  readonly summary: DexSummary;
}

/** Project a whole-file (per-member) readiness summary. */
export const buildDexSummaryResult = (
  artifact: DexArtifactIdentity,
  container: DexDebugMetadataResult["container"],
  members: readonly DexSummaryMember[],
): DexDebugMetadataResult => ({
  artifact,
  container,
  mode: "summary",
  members: members.map((m) => ({
    entry: m.entry,
    sha256: m.sha256,
    bytes: m.bytes,
    summary: projectSummary(m.summary),
  })),
  class_detail: null,
  runtime_execution: "not-performed",
  limitations: [...DEX_DEBUG_METADATA_LIMITATIONS],
});

/** Project full per-method detail for one selected class. */
export const buildDexClassDetailResult = (
  artifact: DexArtifactIdentity,
  container: DexDebugMetadataResult["container"],
  found: { readonly entry: string | null; readonly detail: DexClassDetail },
): DexDebugMetadataResult => ({
  artifact,
  container,
  mode: "class-detail",
  members: [],
  class_detail: {
    entry: found.entry,
    descriptor: found.detail.descriptor,
    source_file: found.detail.sourceFile,
    methods: found.detail.methods.map((m) => ({
      name: m.name,
      descriptor: m.descriptor,
      state: m.state,
      has_code: m.hasCode,
      line_count: m.lineCount,
      parameter_names: [...m.parameterNames],
      locals: m.locals.map((l) => ({
        register: l.register,
        name: l.name,
        type: l.type,
        signature: l.signature,
        start_address: l.startAddress,
        end_address: l.endAddress,
        out_of_range: l.outOfRange,
      })),
      set_file_events: m.setFileEvents,
    })),
  },
  runtime_execution: "not-performed",
  limitations: [...DEX_DEBUG_METADATA_LIMITATIONS],
});

/** The returned artifact identity must match the caller-selected local file. */
export const dexDebugMetadataMatchesSubject = (
  artifact: DexDebugMetadataResult["artifact"],
  subject: EvidenceSubjectTarget,
): boolean =>
  artifact.sha256 === subject.sha256 &&
  artifact.path === subject.path &&
  (subject.format === "file" ||
    subject.format === "apk" ||
    subject.format === "zip");
