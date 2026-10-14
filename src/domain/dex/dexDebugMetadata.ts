/**
 * Assemble debugging-readiness facts from a framed DEX file: a whole-file
 * summary (tallies + a conservative readiness label) and, for one selected
 * class, full per-method detail with names/types/scopes resolved from the string
 * and type pools. Positions/locals are decoded one method at a time and then
 * discarded for the summary, so peak memory stays bounded regardless of class
 * count; identical `debug_info_off`s (d8/R8 share them) are decoded once.
 */
import {
  type DexClassDef,
  type DexEncodedMethod,
  type DexFile,
  parseClassData,
  parseCodeItem,
} from "./dexFile.js";
import {
  absentMethodDebug,
  decodeDebugInfo,
  type DexMethodDebug,
} from "./dexDebugInfo.js";
import { DexStringResolver } from "./dexStrings.js";

export type DexMethodState =
  | "present" // positions and locals both decoded
  | "partial" // one present, the other absent
  | "stripped" // code exists but carries no debug_info
  | "malformed" // a present debug_info failed to decode fully
  | "not-applicable"; // abstract/native: no code_item

export interface DexLocalResolved {
  readonly register: number;
  readonly name: string | null;
  readonly type: string | null;
  readonly signature: string | null;
  readonly startAddress: number;
  readonly endAddress: number;
  readonly outOfRange: boolean;
}

export interface DexMethodDetail {
  readonly name: string | null;
  readonly descriptor: string | null;
  readonly state: DexMethodState;
  readonly hasCode: boolean;
  readonly lineCount: number;
  readonly parameterNames: readonly (string | null)[];
  readonly locals: readonly DexLocalResolved[];
  readonly setFileEvents: number;
}

export interface DexClassDetail {
  readonly descriptor: string | null;
  readonly sourceFile: string | null;
  readonly methods: readonly DexMethodDetail[];
}

export type DexReadiness = "present" | "partial" | "stripped";

export interface DexSummary {
  readonly dexVersion: string;
  readonly classCount: number;
  readonly methodsWithCode: number;
  readonly methodsWithDebugInfo: number;
  readonly methodsWithParameterNames: number;
  readonly linePositions: number;
  readonly localDeclarations: number;
  readonly setFileEvents: number;
  readonly sourceFilePresent: number;
  readonly distinctSourceFiles: {
    readonly count: number;
    readonly sample: readonly string[];
  };
  readonly readiness: DexReadiness;
}

const SOURCE_FILE_SAMPLE_CAP = 16;

const methodState = (
  hasCode: boolean,
  debug: DexMethodDebug,
): DexMethodState => {
  if (!hasCode) return "not-applicable";
  if (debug.malformed) return "malformed";
  const hasLines = debug.positions.length > 0;
  const hasLocals = debug.locals.length > 0;
  if (!debug.present || (!hasLines && !hasLocals)) return "stripped";
  return hasLines && hasLocals ? "present" : "partial";
};

const methodDebugOf = (
  bytes: Uint8Array,
  method: DexEncodedMethod,
): {
  readonly debug: ReturnType<typeof decodeDebugInfo>;
  readonly insns: number;
} => {
  if (method.codeOff === 0) return { debug: absentMethodDebug(), insns: 0 };
  const code = parseCodeItem(bytes, method.codeOff);
  if (!code.ok) return { debug: absentMethodDebug(), insns: 0 };
  const debug =
    code.value.debugInfoOff === 0
      ? absentMethodDebug()
      : decodeDebugInfo(bytes, code.value.debugInfoOff, code.value.insnsSize);
  return { debug, insns: code.value.insnsSize };
};

const detailOf = (
  bytes: Uint8Array,
  method: DexEncodedMethod,
  resolver: DexStringResolver,
): DexMethodDetail => {
  const hasCode = method.codeOff !== 0;
  const { debug } = methodDebugOf(bytes, method);
  return {
    name: resolver.methodName(method.methodIdx),
    descriptor: resolver.methodDescriptor(method.methodIdx),
    state: methodState(hasCode, debug),
    hasCode,
    lineCount: debug.positions.length,
    parameterNames: debug.parameterNames.map((idx) => resolver.string(idx)),
    locals: debug.locals.map((local) => ({
      register: local.register,
      name: resolver.string(local.nameIdx),
      type: resolver.typeDescriptor(local.typeIdx),
      signature: resolver.string(local.signatureIdx),
      startAddress: local.startAddress,
      endAddress: local.endAddress,
      outOfRange: local.outOfRange,
    })),
    setFileEvents: debug.setFileEvents,
  };
};

const methodsOf = (
  bytes: Uint8Array,
  classDef: DexClassDef,
): readonly DexEncodedMethod[] => {
  if (classDef.classDataOff === 0) return [];
  const data = parseClassData(bytes, classDef.classDataOff);
  return data.ok
    ? [...data.value.directMethods, ...data.value.virtualMethods]
    : [];
};

/** Full per-method detail for the one class whose descriptor matches, or null. */
export const assembleClassDetail = (
  dex: DexFile,
  bytes: Uint8Array,
  classDescriptor: string,
): DexClassDetail | null => {
  const resolver = new DexStringResolver(bytes, dex.header);
  const classDef = dex.classDefs.find(
    (def) => resolver.typeDescriptor(def.classIdx) === classDescriptor,
  );
  if (classDef === undefined) return null;
  return {
    descriptor: resolver.typeDescriptor(classDef.classIdx),
    sourceFile: resolver.string(classDef.sourceFileIdx),
    methods: methodsOf(bytes, classDef).map((m) =>
      detailOf(bytes, m, resolver),
    ),
  };
};

const classifyReadiness = (
  localDeclarations: number,
  parameterNames: number,
  linePositions: number,
): DexReadiness => {
  if (localDeclarations === 0 && parameterNames === 0) return "stripped";
  return linePositions > 0 && localDeclarations > 0 ? "present" : "partial";
};

/** Whole-file tally and a conservative readiness label; decodes once per debug_info_off. */
export const summarizeDex = (dex: DexFile, bytes: Uint8Array): DexSummary => {
  const resolver = new DexStringResolver(bytes, dex.header);
  const seen = new Map<
    number,
    { lines: number; locals: number; params: boolean; setFile: number }
  >();
  let methodsWithCode = 0;
  let methodsWithDebugInfo = 0;
  let methodsWithParameterNames = 0;
  let linePositions = 0;
  let localDeclarations = 0;
  let setFileEvents = 0;
  let sourceFilePresent = 0;
  const sources = new Set<string>();

  for (const classDef of dex.classDefs) {
    const source = resolver.string(classDef.sourceFileIdx);
    if (source !== null) {
      sourceFilePresent += 1;
      sources.add(source); // distinct count; a single value signals -renamesourcefileattribute
    }
    for (const method of methodsOf(bytes, classDef)) {
      if (method.codeOff === 0) continue;
      methodsWithCode += 1;
      const code = parseCodeItem(bytes, method.codeOff);
      if (!code.ok || code.value.debugInfoOff === 0) continue;
      methodsWithDebugInfo += 1;
      let decoded = seen.get(code.value.debugInfoOff);
      if (decoded === undefined) {
        const debug = decodeDebugInfo(
          bytes,
          code.value.debugInfoOff,
          code.value.insnsSize,
        );
        decoded = {
          lines: debug.positions.length,
          locals: debug.locals.length,
          params: debug.parameterNames.some((idx) => idx >= 0),
          setFile: debug.setFileEvents,
        };
        seen.set(code.value.debugInfoOff, decoded);
      }
      linePositions += decoded.lines;
      localDeclarations += decoded.locals;
      setFileEvents += decoded.setFile;
      if (decoded.params) methodsWithParameterNames += 1;
    }
  }

  return {
    dexVersion: dex.header.version,
    classCount: dex.classDefs.length,
    methodsWithCode,
    methodsWithDebugInfo,
    methodsWithParameterNames,
    linePositions,
    localDeclarations,
    setFileEvents,
    sourceFilePresent,
    distinctSourceFiles: {
      count: sources.size,
      sample: [...sources].slice(0, SOURCE_FILE_SAMPLE_CAP),
    },
    readiness: classifyReadiness(
      localDeclarations,
      methodsWithParameterNames,
      linePositions,
    ),
  };
};
