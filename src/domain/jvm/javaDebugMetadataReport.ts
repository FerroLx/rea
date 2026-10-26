/**
 * Public contract shape for `inspect_jvm_debug_metadata` and the projection from
 * the decoded domain facts into that JSON. The domain owns this result schema so
 * CLI and MCP present identical, validated facts.
 */
import { z } from "zod";

import { localPathStringSchema } from "../localPath.js";
import {
  createEvidence,
  type Evidence,
  type EvidenceLocation,
  type EvidenceProvider,
  type EvidenceSubjectTarget,
} from "../evidence.js";
import type { JsonValue } from "../jsonValue.js";
import { type JavaClassFile, resolveConstantUtf8 } from "./javaClassFile.js";
import {
  decodeClassDebugMetadata,
  type LocalScope,
} from "./javaDebugMetadata.js";
import { buildJavaDebugMetadataEvidence } from "./javaDebugMetadataEvidence.js";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const presence = z.enum(["absent", "present", "malformed"]);
/** A debug table may also be `unread`: a malformed sibling stopped framing before it. */
const tablePresence = z.enum(["absent", "present", "malformed", "unread"]);

/** All artifacts are explicitly selected local files; references never trigger acquisition. */
export const inspectJvmDebugMetadataInputSchema = z
  .strictObject({
    path: localPathStringSchema.describe(
      "Absolute selected local .class artifact, or a .jar when entry is given",
    ),
    entry: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Class member path to select inside a JAR at path, e.g. com/example/Foo.class",
      ),
    release: z
      .number()
      .int()
      .nonnegative()
      .optional()
      .describe(
        "Multi-release JAR version whose override of entry to select; omit for the base entry",
      ),
  })
  .superRefine((value, ctx) => {
    // A multi-release override only has meaning when selecting a JAR entry.
    if (value.release !== undefined && value.entry === undefined)
      ctx.addIssue({
        code: "custom",
        path: ["release"],
        message:
          "release is only meaningful together with entry (a JAR member).",
      });
  });
export type InspectJvmDebugMetadataInput = z.infer<
  typeof inspectJvmDebugMetadataInputSchema
>;

/**
 * Normalize a caller-supplied entry once, before any match: backslashes become
 * `/`, then leading `/` characters and leading `./` segments are removed.
 * Interior segments (`a/./b`, `..`) are left unchanged. This rule applies only
 * to the caller's spelling: members are matched on their stored ZIP names, as
 * the JDK's `JarFile.getEntry` does, so `./Foo.class` and `Foo.class` both
 * select the member stored as `Foo.class`, while a member stored as
 * `./Foo.class` is an inert resource that never matches. The report's
 * `selected_entry.entry` is this normalized form.
 */
export const normalizeJarEntryPath = (entry: string): string =>
  entry
    .replace(/\\/g, "/")
    .replace(/^\/+/, "")
    .replace(/^(?:\.\/)+/u, "");

const lineNumberEntry = z.strictObject({
  start_pc: z.number().int().nonnegative(),
  line_number: z.number().int().nonnegative(),
  out_of_range: z.boolean(),
});
/** Where a local's scope lies in its method's code; see {@link LocalScope}. */
const localScope = z.enum([
  "aligned",
  "in-code",
  "misaligned",
  "out-of-range",
  "unknown",
] as const satisfies readonly LocalScope[]);
const localVariableEntry = z.strictObject({
  start_pc: z.number().int().nonnegative(),
  length: z.number().int().nonnegative(),
  name: z.string().nullable(),
  descriptor: z.string().nullable(),
  slot: z.number().int().nonnegative(),
  scope: localScope,
});
const localVariableTypeEntry = z.strictObject({
  start_pc: z.number().int().nonnegative(),
  length: z.number().int().nonnegative(),
  name: z.string().nullable(),
  signature: z.string().nullable(),
  slot: z.number().int().nonnegative(),
  scope: localScope,
});
const table = <Entry extends z.ZodTypeAny>(entry: Entry) =>
  z.strictObject({
    presence: tablePresence,
    declared_count: z.number().int().nonnegative(),
    entries: z.array(entry),
  });

const method = z.strictObject({
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
  /** The Code attribute's max_locals; null without a readable Code header. */
  max_locals: z.number().int().nonnegative().nullable(),
  line_number_table: table(lineNumberEntry),
  local_variable_table: table(localVariableEntry),
  local_variable_type_table: table(localVariableTypeEntry),
  reused_slots: z.array(z.number().int().nonnegative()),
});

/** Validated normalized result; preserves explicit unknowns and examined coverage. */
export const javaDebugMetadataResultSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: z.number().int().nonnegative(),
  }),
  container: z.enum(["class-file", "jar"]),
  /** The selected JAR member, or null when the artifact is a loose class file. */
  selected_entry: z
    .strictObject({
      entry: z.string().min(1),
      /** The multi-release version selected, or null for the base entry. */
      release: z.number().int().nonnegative().nullable(),
      sha256: digest,
      bytes: z.number().int().nonnegative(),
    })
    .nullable(),
  class: z.strictObject({
    internal_name: z.string().nullable(),
    major_version: z.number().int().nonnegative(),
    minor_version: z.number().int().nonnegative(),
  }),
  source_file: z.strictObject({ presence, name: z.string().nullable() }),
  source_debug_extension: z.strictObject({
    presence,
    byte_length: z.number().int().nonnegative(),
  }),
  methods: z.array(method),
  coverage: z.strictObject({
    total: z.number().int().nonnegative(),
    present: z.number().int().nonnegative(),
    partial: z.number().int().nonnegative(),
    stripped: z.number().int().nonnegative(),
    malformed: z.number().int().nonnegative(),
    not_applicable: z.number().int().nonnegative(),
  }),
  runtime_execution: z.literal("not-performed"),
  limitations: z.array(z.string()),
});
export type JavaDebugMetadataResult = z.infer<
  typeof javaDebugMetadataResultSchema
>;

export const JVM_DEBUG_METADATA_LIMITATIONS: readonly string[] = [
  "Static class-file inspection only. No Java executes; bytecode offsets, local slots and line numbers are read from compiler-emitted attributes, not decompiler output.",
  "Debug metadata may be absent, stripped, partial or malformed. A reused local slot can denote different variables across scope ranges; entries are preserved, not merged.",
  "SourceDebugExtension is reported by presence and byte length only; its bytes are neither returned nor interpreted (no source-map dialect is parsed), and supplied source is never claimed to match a SourceFile name.",
  "SHA-256 identifies the exact selected bytes; it does not establish authenticity or that a specific compiler produced the artifact.",
];

const resolveThisClassName = (cls: JavaClassFile): string | null => {
  const entry = cls.constantPool[cls.thisClassIndex];
  return entry && entry.kind === "class"
    ? resolveConstantUtf8(cls.constantPool, entry.nameIndex)
    : null;
};

/** The selected JAR member when the artifact is an archive, else a loose class file. */
export type JavaDebugMetadataSource =
  | { readonly container: "class-file" }
  | {
      readonly container: "jar";
      readonly selectedEntry: {
        readonly entry: string;
        readonly release: number | null;
        readonly sha256: string;
        readonly bytes: number;
      };
    };

/** Project a framed class file into the validated public result. */
export const buildJavaDebugMetadataResult = (
  classFile: JavaClassFile,
  artifact: {
    readonly path: string;
    readonly sha256: string;
    readonly bytes: number;
  },
  source: JavaDebugMetadataSource = { container: "class-file" },
): JavaDebugMetadataResult => {
  const evidence = buildJavaDebugMetadataEvidence(
    decodeClassDebugMetadata(classFile),
  );
  return {
    artifact,
    container: source.container,
    selected_entry:
      source.container === "jar"
        ? {
            entry: source.selectedEntry.entry,
            release: source.selectedEntry.release,
            sha256: source.selectedEntry.sha256,
            bytes: source.selectedEntry.bytes,
          }
        : null,
    class: {
      internal_name: resolveThisClassName(classFile),
      major_version: classFile.majorVersion,
      minor_version: classFile.minorVersion,
    },
    source_file: {
      presence: evidence.sourceFile.presence,
      name: evidence.sourceFile.name,
    },
    source_debug_extension: {
      presence: evidence.sourceDebugExtension.presence,
      byte_length: evidence.sourceDebugExtension.byteLength,
    },
    methods: evidence.methods.map((m) => ({
      name: m.name,
      descriptor: m.descriptor,
      state: m.state,
      has_code: m.hasCode,
      max_locals: m.maxLocals,
      line_number_table: {
        presence: m.lineNumbers.presence,
        declared_count: m.lineNumbers.declaredCount,
        entries: m.lineNumbers.entries.map((e) => ({
          start_pc: e.startPc,
          line_number: e.lineNumber,
          out_of_range: e.outOfRange,
        })),
      },
      local_variable_table: {
        presence: m.localVariables.presence,
        declared_count: m.localVariables.declaredCount,
        entries: m.localVariables.entries.map((e) => ({
          start_pc: e.startPc,
          length: e.length,
          name: e.name,
          descriptor: e.descriptor,
          slot: e.slot,
          scope: e.scope,
        })),
      },
      local_variable_type_table: {
        presence: m.localVariableTypes.presence,
        declared_count: m.localVariableTypes.declaredCount,
        entries: m.localVariableTypes.entries.map((e) => ({
          start_pc: e.startPc,
          length: e.length,
          name: e.name,
          signature: e.signature,
          slot: e.slot,
          scope: e.scope,
        })),
      },
      reused_slots: [...m.reusedSlots],
    })),
    coverage: {
      total: evidence.coverage.total,
      present: evidence.coverage.present,
      partial: evidence.coverage.partial,
      stripped: evidence.coverage.stripped,
      malformed: evidence.coverage.malformed,
      not_applicable: evidence.coverage.notApplicable,
    },
    runtime_execution: "not-performed",
    limitations: [...JVM_DEBUG_METADATA_LIMITATIONS],
  };
};

/**
 * The report answers exactly the caller's selection: the selected path and
 * subject, a loose class file (`file`) iff no entry was requested, and
 * otherwise a JAR (`zip`) whose selected member is the normalized entry at the
 * requested release (the base, `null`, when none was requested). Guards the
 * application boundary against a provider answering a different selection
 * under the caller's parameters.
 */
export const javaDebugMetadataAnswersSelection = (
  report: JavaDebugMetadataResult,
  subject: EvidenceSubjectTarget,
  input: InspectJvmDebugMetadataInput,
): boolean => {
  if (
    report.artifact.path !== input.path ||
    report.artifact.sha256 !== subject.sha256 ||
    report.artifact.path !== subject.path
  )
    return false;
  if (input.entry === undefined)
    return (
      subject.format === "file" &&
      report.container === "class-file" &&
      report.selected_entry === null
    );
  return (
    subject.format === "zip" &&
    report.container === "jar" &&
    report.selected_entry?.entry === normalizeJarEntryPath(input.entry) &&
    report.selected_entry.release === (input.release ?? null)
  );
};

/**
 * Evidence for one completed inspection, echoing exactly the caller's
 * selection. Shared by the workflow's success and the provider's completed
 * observation retained under late cancellation or failed cleanup.
 */
export const createJavaDebugMetadataEvidence = (
  input: InspectJvmDebugMetadataInput,
  observed: {
    readonly subject: EvidenceSubjectTarget;
    readonly provider: EvidenceProvider;
    readonly result: JsonValue;
    readonly rawResult: JsonValue | null;
    readonly locations: readonly EvidenceLocation[];
    readonly limitations: readonly string[];
  },
): Evidence =>
  createEvidence(observed.subject, observed.provider, {
    operation: "inspect_jvm_debug_metadata",
    parameters: {
      path: input.path,
      ...(input.entry === undefined ? {} : { entry: input.entry }),
      ...(input.release === undefined ? {} : { release: input.release }),
    },
    result: observed.result,
    ...(observed.rawResult === null ? {} : { rawResult: observed.rawResult }),
    confidence: "observed",
    locations: observed.locations,
    limitations: observed.limitations,
  });
