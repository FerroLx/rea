/**
 * Assemble debugging-readiness facts from a framed DEX file: a whole-file
 * summary (tallies + a conservative readiness label) and, for one selected
 * class, full per-method detail with names/types/scopes resolved from the string
 * and type pools.
 *
 * Every decode of one DEX member is charged to that member's
 * {@link DexWorkBudget}, so many methods cannot multiply the per-method guard.
 * Decoding is synchronous, so the walk hands the event loop back to the host
 * after each slice of work ({@link DexWork.yieldNow}) and observes cancellation
 * there, including inside one long debug stream. The summary only counts (no per-position or per-local allocation) and
 * decodes each distinct debug stream + parameter layout once. The class detail
 * projects its serialized size from memoised per-string bounds while it
 * decodes, and refuses before materialising a report past the caller's output
 * limit.
 */
import { encodeModifiedUtf8 } from "../modifiedUtf8.js";
import {
  type DexClassDef,
  type DexEncodedMethod,
  type DexFile,
  DexClassDataReader,
  readClassDef,
  parseCodeItem,
} from "./dexFile.js";
import {
  absentMethodDebug,
  DEX_PAUSED,
  DexDebugInfoWalk,
  startDebugInfo,
  type DexDecodeOptions,
  DEX_THIS_NAME,
  type DexMethodDebug,
  type DexWorkBudget,
  chargeWork,
  dexParameterWords,
} from "./dexDebugInfo.js";
import { type Result, err, ok } from "../result.js";
import { type DexPausable, DexStringResolver } from "./dexStrings.js";

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

/** One class's detail; it is identified by the descriptor it was matched by. */
export interface DexClassDetail {
  readonly sourceFile: string | null;
  readonly methods: readonly DexMethodDetail[];
}

export type DexReadiness = "present" | "partial" | "stripped" | "unknown";

export interface DexSummary {
  readonly dexVersion: string;
  readonly classCount: number;
  readonly methodsWithCode: number;
  readonly methodsWithDebugInfo: number;
  readonly methodsWithParameterNames: number;
  readonly linePositions: number;
  /** Every local dexdump lists, including implicit `this`/parameter locals. */
  readonly localDeclarations: number;
  /** Locals the debug streams declare themselves (DBG_START_LOCAL*). */
  readonly explicitLocalDeclarations: number;
  readonly setFileEvents: number;
  readonly sourceFilePresent: number;
  readonly distinctSourceFiles: {
    /**
     * Distinct valid `source_file_idx` string_ids. Malformed input can encode
     * one text under two string_ids, which count twice.
     */
    readonly count: number;
    /** Up to {@link SOURCE_FILE_SAMPLE_CAP} distinct texts. */
    readonly sample: readonly string[];
  };
  /** Structures that could not be read (their debug metadata is unknown). */
  readonly unreadable: {
    readonly classData: number;
    readonly codeItems: number;
    readonly debugInfo: number;
  };
  readonly readiness: DexReadiness;
}

const SOURCE_FILE_SAMPLE_CAP = 3;
/** Longest source-file name (JSON bytes) included in the sample; longer ones are counted only. */
const SOURCE_FILE_SAMPLE_MAX_BYTES = 1024;

/** Why a summary or detail was refused before completing. */
export type DexWorkError =
  | { readonly kind: "work-budget-exceeded"; readonly limit: number }
  | { readonly kind: "cancelled" }
  | { readonly kind: "malformed-class-data"; readonly classDataOff: number }
  /** class_defs whose identity could not be read: presence is unknown. */
  | { readonly kind: "unreadable-class-identity"; readonly count: number }
  /** More than one class_def declares the class (ART rejects the DEX). */
  | { readonly kind: "duplicate-class-definition"; readonly count: number }
  | {
      readonly kind: "output-budget-exceeded";
      readonly projectedBytes: number;
      readonly limit: number;
    };

/** One member's work accounting and the host's cooperative-scheduling hooks. */
export interface DexWork {
  readonly budget: DexWorkBudget;
  /** Observed after each yield; a synchronous slice cannot see a new abort. */
  readonly cancelled: () => boolean;
  /** Hand control back to the host's event loop (supplied by the adapter). */
  readonly yieldNow: () => Promise<void>;
  /** Work units decoded between yields. */
  readonly sliceUnits: number;
}

/**
 * Pauses a synchronous walk after each slice of work so the host can serve
 * other requests and deliver cancellation, then reports whether to stop.
 */
class DexPacer {
  #mark: number;
  constructor(private readonly work: DexWork) {
    this.#mark = work.budget.remaining;
  }

  /**
   * The budget's remaining work at or below which a slice is due: the one rule
   * behind {@link due} and {@link pauseAt}. It moves only in {@link pause}, so
   * a walk reads it once per resume instead of calling back per opcode.
   */
  get threshold(): number {
    return this.#mark - this.work.sliceUnits;
  }

  /** A slice of work has been spent since the last pause. */
  get due(): boolean {
    return this.work.budget.remaining <= this.threshold;
  }

  async pause(): Promise<DexWorkError | null> {
    await this.work.yieldNow();
    this.#mark = this.work.budget.remaining;
    return outOfWork(this.work);
  }

  /** {@link due} as a callback, for string scans that pause mid-string. */
  readonly pauseDue = (): boolean => this.due;

  /** {@link threshold} as a callback, for walks that pause from inside a stream. */
  readonly pauseAt = (): number => this.threshold;
}

/**
 * Run a resumable step (a debug walk, or a string check) to its end. One that
 * fits in the current slice finishes synchronously; a longer one pauses
 * between slices, so the host can yield and deliver cancellation, and the
 * result is a promise.
 */
const settle = <T>(
  step: () => DexPausable<T>,
  pacer: DexPacer,
): T | Promise<Result<T, DexWorkError>> => {
  const first = step();
  return first === DEX_PAUSED ? afterPause(step, pacer) : first;
};

/** Continue a step that paused: yield, then resume it until it settles. */
const afterPause = async <T>(
  step: () => DexPausable<T>,
  pacer: DexPacer,
): Promise<Result<T, DexWorkError>> => {
  for (;;) {
    const stop = await pacer.pause();
    if (stop !== null) return err(stop);
    const next = step();
    if (next !== DEX_PAUSED) return ok(next);
  }
};

/** Finish a method's decode, pausing inside a long stream. */
const settleDecode = (
  decode: DexMethodDebug | DexDebugInfoWalk,
  pacer: DexPacer,
): DexMethodDebug | Promise<Result<DexMethodDebug, DexWorkError>> => {
  if (!(decode instanceof DexDebugInfoWalk)) return decode;
  // The common case settles at once, without allocating a continuation.
  const first = decode.resume();
  return first === DEX_PAUSED
    ? afterPause(() => decode.resume(), pacer)
    : first;
};

/** Apply `finish` to a settled decode, synchronously when it settled at once. */
const afterDecode = (
  settled: DexMethodDebug | Promise<Result<DexMethodDebug, DexWorkError>>,
  finish: (debug: DexMethodDebug) => DexWorkError | null,
): DexWorkError | null | Promise<DexWorkError | null> =>
  settled instanceof Promise
    ? settled.then((r) => (r.ok ? finish(r.value) : r.error))
    : finish(settled);

const methodState = (
  hasCode: boolean,
  debug: DexMethodDebug,
): DexMethodState => {
  if (!hasCode) return "not-applicable";
  if (debug.malformed) return "malformed";
  const hasLines = debug.positionCount > 0;
  // Implicit `this`/parameter locals are synthesised from the method layout
  // whenever a stream exists (an R8 release keeps streams for lines); only
  // declared locals or named parameters show local debug info survived.
  const hasLocals =
    debug.explicitLocalCount > 0 ||
    debug.parameterNames.some((idx) => idx >= 0);
  if (!debug.present || (!hasLines && !hasLocals)) return "stripped";
  return hasLines && hasLocals ? "present" : "partial";
};

/** `ACC_STATIC`: a static method has no implicit `this` parameter. */
const ACC_STATIC = 0x8;

/** A method's code_item facts that decoding and the summary memo key need. */
interface MethodCode {
  readonly debugInfoOff: number;
  readonly insnsSize: number;
  readonly firstRegister: number;
  readonly registersSize: number;
}

/** The method's code_item facts, or null with no code or no debug_info. O(1). */
const methodCode = (
  bytes: Uint8Array,
  method: DexEncodedMethod,
): MethodCode | null | "unreadable" => {
  if (method.codeOff === 0) return null;
  const code = parseCodeItem(bytes, method.codeOff);
  // An unreadable code_item leaves debug metadata unknown, never absent.
  if (!code.ok) return "unreadable";
  // Incoming arguments occupy the top of the frame, so they cannot outnumber it.
  if (code.value.insSize > code.value.registersSize) return "unreadable";
  if (code.value.debugInfoOff === 0) return null;
  return {
    debugInfoOff: code.value.debugInfoOff,
    insnsSize: code.value.insnsSize,
    firstRegister: code.value.registersSize - code.value.insSize,
    registersSize: code.value.registersSize,
  };
};

/**
 * Decode a method's debug_info with its implicit parameter locals (and `this`)
 * seeded at address 0 from the code_item register layout and the proto, as the
 * DEX format and dexdump/ART do. Parameters are resolved only here, when a
 * decode actually runs.
 */
const decodeMethodDebug = (
  bytes: Uint8Array,
  method: DexEncodedMethod,
  code: MethodCode | null | "unreadable",
  classTypeIdx: number,
  resolver: DexStringResolver,
  options: DexDecodeOptions,
): DexMethodDebug | DexDebugInfoWalk => {
  if (code === null) return absentMethodDebug();
  const malformed = { ...absentMethodDebug(), present: true, malformed: true };
  if (code === "unreadable") return malformed;
  const paramTypes = resolver.methodParameters(method.methodIdx);
  // Without the proto, `this` and the parameters cannot be seeded and the
  // stream's parameter count cannot be checked: unknown, never complete.
  if (paramTypes === null) return malformed;
  // ins_size must be the receiver plus one word per parameter (two for
  // long/double); otherwise `this` and the parameters would be seeded into
  // registers the method does not use.
  const words =
    ((method.accessFlags & ACC_STATIC) === 0 ? 1 : 0) +
    dexParameterWords(paramTypes);
  if (words !== code.registersSize - code.firstRegister) return malformed;
  return startDebugInfo(
    bytes,
    code.debugInfoOff,
    code.insnsSize,
    {
      firstRegister: code.firstRegister,
      registersSize: code.registersSize,
      accessFlags: method.accessFlags,
      thisTypeIdx: classTypeIdx,
      paramTypes,
      stringValid: resolver.validity,
      typeValid: resolver.typeValidity,
    },
    options,
  );
};

/**
 * Step through a class_data, pausing after each slice of work, and hand each
 * method to `visit`. Every field and method is charged to the member's budget,
 * because many class_defs may share one (or overlapping) class_data. Returns
 * the first stop reason, `"unreadable"` when the framing fails, or null at the
 * end.
 */
const walkClassMethods = async (
  reader: DexClassDataReader,
  work: DexWork,
  pacer: DexPacer,
  visit: (
    method: DexEncodedMethod,
  ) => DexWorkError | null | Promise<DexWorkError | null>,
): Promise<DexWorkError | "unreadable" | null> => {
  const charge = (): boolean => chargeWork(work.budget);
  for (;;) {
    if (pacer.due) {
      const paused = await pacer.pause();
      if (paused !== null) return paused;
    }
    const step = reader.step(charge);
    if (step === "end") return null;
    if (step === "failed") {
      const failure = reader.failure;
      // A spent budget is reported as such, not as damage.
      return failure?.kind === "budget-exceeded" && failure.resource === "work"
        ? (outOfWork(work) ?? "unreadable")
        : "unreadable";
    }
    if (step === "method") {
      const visited = visit(reader.method);
      const stop = visited instanceof Promise ? await visited : visited;
      if (stop !== null) return stop;
    }
  }
};

/**
 * A class's methods, read one at a time and never materialised. The whole
 * class_data is validated first (paced like the method pass), so a malformed
 * class contributes nothing rather than a partial list; the reader returned is
 * positioned at its start. A stop during validation is the error.
 */
const classMethods = async (
  dex: DexFile,
  bytes: Uint8Array,
  classDef: DexClassDef,
  work: DexWork,
  pacer: DexPacer,
): Promise<
  Result<DexClassDataReader | "no-class-data" | "unreadable", DexWorkError>
> => {
  if (classDef.classDataOff === 0) return ok("no-class-data");
  const open = () =>
    DexClassDataReader.open(bytes, classDef.classDataOff, dex.header);
  const check = open();
  if (!check.ok) return ok("unreadable");
  const valid = await walkClassMethods(check.value, work, pacer, () => null);
  if (valid === "unreadable") return ok("unreadable");
  if (valid !== null) return err(valid);
  const reader = open();
  return ok(reader.ok ? reader.value : "unreadable");
};

/**
 * Charge one class_def visit and pause when a slice is due. Every visit costs a
 * unit, so a table of class_defs that carry no source file and no class_data
 * still advances the pacer and yields to the host.
 */
const visitClass = async (
  work: DexWork,
  pacer: DexPacer,
): Promise<DexWorkError | null> => {
  chargeWork(work.budget);
  return pacer.due ? await pacer.pause() : outOfWork(work);
};

const outOfWork = (work: DexWork): DexWorkError | null =>
  work.cancelled()
    ? { kind: "cancelled" }
    : work.budget.remaining <= 0
      ? { kind: "work-budget-exceeded", limit: work.budget.limit }
      : null;

/** Distinct (stream, layout) tallies kept for reuse; bounds the summary's memo. */
const MEMO_LIMIT = 65_536;

/** Serialized overhead per projected object (keys, numbers, punctuation). */
const METHOD_OVERHEAD = 320;
const LOCAL_OVERHEAD = 192;

/**
 * Find the class_def whose type descriptor matches, scanning the whole table in
 * place. Every descriptor read is charged by the resolver, and the scan checks
 * the work budget per class and pauses after each slice, so an absent class in
 * a crafted table cannot cost unbounded work before the answer. A definition
 * whose identity cannot be read might be the requested class, so absence or
 * uniqueness is then unknown, never asserted; a second matching definition is
 * malformed.
 */
const findClassDef = async (
  dex: DexFile,
  bytes: Uint8Array,
  resolver: DexStringResolver,
  classDescriptor: string,
  work: DexWork,
  pacer: DexPacer,
): Promise<Result<DexClassDef | undefined, DexWorkError>> => {
  // Compared as raw modified-UTF-8 bytes: no class name is decoded.
  const wanted = encodeModifiedUtf8(classDescriptor);
  let match: DexClassDef | undefined;
  let matches = 0;
  let unreadable = 0;
  for (let i = 0; i < dex.header.classDefsSize; i += 1) {
    // Checked per class: one descriptor read can cost as much as its string.
    const stop = await visitClass(work, pacer);
    if (stop !== null) return err(stop);
    const def = readClassDef(bytes, dex.header, i);
    // Awaited only when the descriptor's scan paused.
    const checked = settle(
      () => resolver.typeIdentity(def.classIdx, wanted),
      pacer,
    );
    const identity = checked instanceof Promise ? await checked : ok(checked);
    if (!identity.ok) return identity;
    if (identity.value === "unreadable") unreadable += 1;
    else if (identity.value === "match") {
      matches += 1;
      match ??= def;
    }
  }
  const spent = outOfWork(work);
  if (spent !== null) return err(spent);
  if (matches > 1)
    return err({ kind: "duplicate-class-definition", count: matches });
  if (unreadable > 0)
    return err({ kind: "unreadable-class-identity", count: unreadable });
  return ok(match);
};

/** The member's string resolver, charging its budget and pausing with its pacer. */
const resolverFor = (
  dex: DexFile,
  bytes: Uint8Array,
  work: DexWork,
  pacer: DexPacer,
): DexStringResolver =>
  new DexStringResolver(
    bytes,
    dex.header,
    (units) => {
      work.budget.remaining -= units;
    },
    () => work.budget.remaining <= 0,
    pacer.pauseDue,
  );

/**
 * Full per-method detail for the one class whose descriptor matches (`null`
 * when absent). Methods are visited one at a time; locals are collected under
 * a cap derived from the output limit (each serialises to at least
 * {@link LOCAL_OVERHEAD} bytes) and every emitted string is charged its
 * memoised JSON bound, so an oversized class is refused before its report is
 * built.
 */
export const assembleClassDetail = async (
  dex: DexFile,
  bytes: Uint8Array,
  classDescriptor: string,
  work: DexWork,
  outputLimit: number,
): Promise<Result<DexClassDetail | null, DexWorkError>> => {
  const pacer = new DexPacer(work);
  const resolver = resolverFor(dex, bytes, work, pacer);
  const found = await findClassDef(
    dex,
    bytes,
    resolver,
    classDescriptor,
    work,
    pacer,
  );
  // An absent class is only an answer when the lookup stayed within budget.
  if (!found.ok) return found;
  const classDef = found.value;
  if (classDef === undefined) return ok(null);
  // The source file is scanned (paced) before its bound is read.
  const sourceChecked = settle(
    () => resolver.validity(classDef.sourceFileIdx),
    pacer,
  );
  if (sourceChecked instanceof Promise) {
    const paused = await sourceChecked;
    if (!paused.ok) return paused;
  }
  let projected =
    1024 +
    resolver.typeJsonBound(classDef.classIdx) +
    resolver.jsonBound(classDef.sourceFileIdx);
  const overBudget = (): DexWorkError => ({
    kind: "output-budget-exceeded",
    projectedBytes: projected,
    limit: outputLimit,
  });
  // Checked before any method is visited: a methodless class never reaches the
  // per-method check, and its source_file must not be decoded past the limit.
  if (projected > outputLimit) return err(overBudget());
  const methods: DexMethodDetail[] = [];
  const walk = await classMethods(dex, bytes, classDef, work, pacer);
  if (!walk.ok) return walk;
  // The class exists but its member list is unreadable: unknown, not empty.
  const malformed = (): DexWorkError => ({
    kind: "malformed-class-data",
    classDataOff: classDef.classDataOff,
  });
  if (walk.value === "unreadable") return err(malformed());
  const visit = (
    method: DexEncodedMethod,
  ): DexWorkError | null | Promise<DexWorkError | null> => {
    const stop = outOfWork(work);
    if (stop !== null) return stop;
    // The name and descriptor strings are scanned (paced) before
    // recordMethod takes their bounds; `next` keeps progress across pauses.
    const strings = resolver.methodStrings(method.methodIdx);
    let next = 0;
    const checked = settle(() => {
      for (; next < strings.length; next += 1)
        if (resolver.validity(strings[next]!) === DEX_PAUSED) return DEX_PAUSED;
      return true;
    }, pacer);
    return checked instanceof Promise
      ? checked.then((r) => (r.ok ? decodeAndRecord(method) : r.error))
      : decodeAndRecord(method);
  };
  const decodeAndRecord = (
    method: DexEncodedMethod,
  ): DexWorkError | null | Promise<DexWorkError | null> => {
    // Checked again: those scans may have spent the budget, and the refusal
    // must not depend on whether they paused.
    const spent = outOfWork(work);
    if (spent !== null) return spent;
    const decode = decodeMethodDebug(
      bytes,
      method,
      methodCode(bytes, method),
      classDef.classIdx,
      resolver,
      {
        budget: work.budget,
        collectLocals: true,
        maxLocals: Math.max(
          0,
          Math.floor((outputLimit - projected) / LOCAL_OVERHEAD),
        ),
        pauseAt: pacer.pauseAt,
      },
    );
    return afterDecode(settleDecode(decode, pacer), (debug) =>
      recordMethod(method, debug),
    );
  };
  const recordMethod = (
    method: DexEncodedMethod,
    debug: DexMethodDebug,
  ): DexWorkError | null => {
    const after = outOfWork(work);
    if (after !== null) return after;
    // Bound the name and descriptor from type ids before building them.
    projected += METHOD_OVERHEAD + resolver.methodJsonBound(method.methodIdx);
    if (projected > outputLimit) return overBudget();
    const name = resolver.methodName(method.methodIdx);
    const descriptor = resolver.methodDescriptor(method.methodIdx);
    // Each name plus its array separator.
    for (const idx of debug.parameterNames)
      projected += resolver.jsonBound(idx) + 1;
    if (debug.localLimitExceeded)
      projected += (debug.localCount - debug.locals.length) * LOCAL_OVERHEAD;
    else
      for (const local of debug.locals)
        projected +=
          LOCAL_OVERHEAD +
          (local.nameIdx === DEX_THIS_NAME
            ? 6
            : resolver.jsonBound(local.nameIdx)) +
          resolver.typeJsonBound(local.typeIdx) +
          resolver.jsonBound(local.signatureIdx);
    if (debug.localLimitExceeded || projected > outputLimit)
      return overBudget();
    const hasCode = method.codeOff !== 0;
    const detail: DexMethodDetail = {
      name,
      descriptor,
      state: methodState(hasCode, debug),
      hasCode,
      lineCount: debug.positionCount,
      parameterNames: debug.parameterNames.map((idx) => resolver.string(idx)),
      locals: debug.locals.map((local) => ({
        register: local.register,
        name:
          local.nameIdx === DEX_THIS_NAME
            ? "this"
            : resolver.string(local.nameIdx),
        type: resolver.typeDescriptor(local.typeIdx),
        signature: resolver.string(local.signatureIdx),
        startAddress: local.startAddress,
        endAddress: local.endAddress,
        outOfRange: local.outOfRange,
      })),
      setFileEvents: debug.setFileEvents,
    };
    // The decodes above run within the budget or not at all; one that could
    // not be covered (or an abort that arrived meanwhile) refuses the call
    // rather than reporting a name as absent.
    const decoded = outOfWork(work);
    if (decoded !== null) return decoded;
    methods.push(detail);
    return null;
  };
  if (walk.value !== "no-class-data") {
    const stop = await walkClassMethods(walk.value, work, pacer, visit);
    if (stop === "unreadable") return err(malformed());
    if (stop !== null) return err(stop);
  }
  const spent = outOfWork(work);
  if (spent !== null) return err(spent);
  const sourceFile = resolver.string(classDef.sourceFileIdx);
  // Checked after the last decodes: one the budget could not cover refuses
  // rather than completing. When they filled a slice, the host is yielded to
  // first, so an abort raised while they ran is observed.
  const decoded = pacer.due ? await pacer.pause() : outOfWork(work);
  if (decoded !== null) return err(decoded);
  return ok({ sourceFile, methods });
};

/**
 * Whole-member readiness with the same vocabulary as a method's state: line
 * positions and local-variable evidence both observed is `present`, exactly
 * one is `partial`, neither is `stripped`. Declared locals or named parameters
 * are local evidence (implicit `this` and unnamed parameter locals are
 * synthesised from the layout, so they are not). When something could not be
 * read and the observed evidence does not already settle the label, it stays
 * `unknown`.
 */
const classifyReadiness = (
  hasLines: boolean,
  hasLocals: boolean,
  unreadable: number,
): DexReadiness => {
  if (hasLines && hasLocals) return "present";
  if (unreadable > 0) return "unknown";
  return hasLines || hasLocals ? "partial" : "stripped";
};

/** What the summary keeps from one decoded method. */
interface MethodTally {
  readonly present: boolean;
  readonly positions: number;
  readonly locals: number;
  readonly explicitLocals: number;
  readonly setFileEvents: number;
  readonly hasParameterNames: boolean;
  readonly malformed: boolean;
}

/**
 * Whole-file tally and a conservative readiness label. Methods are decoded in
 * counts-only mode, and methods that share a debug stream and the same implicit
 * parameter layout (d8/R8 share streams) reuse one decode: the result depends
 * only on that key.
 */
export const summarizeDex = async (
  dex: DexFile,
  bytes: Uint8Array,
  work: DexWork,
): Promise<Result<DexSummary, DexWorkError>> => {
  const pacer = new DexPacer(work);
  const resolver = resolverFor(dex, bytes, work, pacer);
  const tallies = new Map<string, MethodTally>();
  let methodsWithCode = 0;
  let methodsWithDebugInfo = 0;
  let methodsWithParameterNames = 0;
  let linePositions = 0;
  let localDeclarations = 0;
  let explicitLocalDeclarations = 0;
  let setFileEvents = 0;
  let sourceFilePresent = 0;
  // Distinct source files are counted with two bitmaps over the string-id
  // space (each string_id is at least 4 bytes, so this is at most 1/32 of the
  // file) and only the bounded sample is decoded and kept.
  const idSpace = Math.min(
    dex.header.stringIdsSize,
    Math.floor(bytes.length / 4),
  );
  const seenSource = new Uint8Array(Math.ceil(idSpace / 8));
  const validSource = new Uint8Array(Math.ceil(idSpace / 8));
  let distinctSources = 0;
  const sourceSample: string[] = [];

  let unreadableClassData = 0;
  let unreadableCodeItems = 0;
  let malformedDebugInfo = 0;
  for (let c = 0; c < dex.header.classDefsSize; c += 1) {
    const stop = await visitClass(work, pacer);
    if (stop !== null) return err(stop);
    const classDef = readClassDef(bytes, dex.header, c);
    const idx = classDef.sourceFileIdx;
    if (idx >= 0 && idx < idSpace) {
      const at = idx >>> 3;
      const bit = 1 << (idx & 7);
      if ((seenSource[at]! & bit) === 0) {
        seenSource[at]! |= bit;
        // Validity is checked without decoding; only short names are
        // decoded into the bounded sample, so a multi-megabyte name is
        // counted but never materialised.
        const checked = settle(() => resolver.validity(idx), pacer);
        const valid = checked instanceof Promise ? await checked : ok(checked);
        if (!valid.ok) return valid;
        if (valid.value) {
          validSource[at]! |= bit;
          // A single distinct value signals -renamesourcefileattribute.
          distinctSources += 1;
          if (
            sourceSample.length < SOURCE_FILE_SAMPLE_CAP &&
            resolver.jsonBound(idx) <= SOURCE_FILE_SAMPLE_MAX_BYTES
          ) {
            const source = resolver.string(idx);
            // Two string_ids can decode to one text; sample it once.
            if (source !== null && !sourceSample.includes(source))
              sourceSample.push(source);
          }
        }
      }
      if ((validSource[at]! & bit) !== 0) sourceFilePresent += 1;
    }
    const walk = await classMethods(dex, bytes, classDef, work, pacer);
    if (!walk.ok) return walk;
    if (walk.value === "no-class-data") continue;
    if (walk.value === "unreadable") {
      unreadableClassData += 1;
      continue;
    }
    const tallyMethod = (debug: DexMethodDebug): MethodTally => ({
      present: debug.present,
      positions: debug.positionCount,
      locals: debug.localCount,
      explicitLocals: debug.explicitLocalCount,
      setFileEvents: debug.setFileEvents,
      hasParameterNames: debug.parameterNames.some((idx) => idx >= 0),
      malformed: debug.malformed,
    });
    const count = (tally: MethodTally): null => {
      if (tally.malformed) malformedDebugInfo += 1;
      if (!tally.present) return null;
      methodsWithDebugInfo += 1;
      linePositions += tally.positions;
      localDeclarations += tally.locals;
      explicitLocalDeclarations += tally.explicitLocals;
      setFileEvents += tally.setFileEvents;
      if (tally.hasParameterNames) methodsWithParameterNames += 1;
      return null;
    };
    const visit = (
      method: DexEncodedMethod,
    ): DexWorkError | null | Promise<DexWorkError | null> => {
      if (method.codeOff === 0) return null;
      methodsWithCode += 1;
      const code = methodCode(bytes, method);
      if (code === null) return null;
      if (code === "unreadable") {
        unreadableCodeItems += 1;
        return null;
      }
      // O(1) key: the implicit parameter layout is fixed by the proto, so its
      // index stands in for the (up to 255) parameter types.
      const isStatic = (method.accessFlags & ACC_STATIC) !== 0;
      const key = `${String(code.debugInfoOff)}:${String(code.insnsSize)}:${String(code.firstRegister)}:${String(code.registersSize)}:${isStatic ? "s" : `i${String(classDef.classIdx)}`}:${String(resolver.methodProtoIndex(method.methodIdx))}`;
      const memo = tallies.get(key);
      if (memo !== undefined) return count(memo);
      const decode = decodeMethodDebug(
        bytes,
        method,
        code,
        classDef.classIdx,
        resolver,
        { budget: work.budget, collectLocals: false, pauseAt: pacer.pauseAt },
      );
      return afterDecode(settleDecode(decode, pacer), (debug) => {
        const spent = outOfWork(work);
        if (spent !== null) return spent;
        const tally = tallyMethod(debug);
        // The memo is an optimisation, not a working set: past its cap a
        // repeat is decoded again (still charged), never retained.
        if (tallies.size < MEMO_LIMIT) tallies.set(key, tally);
        return count(tally);
      });
    };
    const ended = await walkClassMethods(walk.value, work, pacer, visit);
    // Validated framing cannot fail on the method pass; stay unknown if it does.
    if (ended === "unreadable") unreadableClassData += 1;
    else if (ended !== null) return err(ended);
  }
  const spent = outOfWork(work);
  if (spent !== null) return err(spent);

  return ok({
    dexVersion: dex.header.version,
    classCount: dex.header.classDefsSize,
    methodsWithCode,
    methodsWithDebugInfo,
    methodsWithParameterNames,
    linePositions,
    localDeclarations,
    explicitLocalDeclarations,
    setFileEvents,
    sourceFilePresent,
    distinctSourceFiles: {
      count: distinctSources,
      sample: sourceSample,
    },
    unreadable: {
      classData: unreadableClassData,
      codeItems: unreadableCodeItems,
      debugInfo: malformedDebugInfo,
    },
    readiness: classifyReadiness(
      linePositions > 0,
      explicitLocalDeclarations > 0 || methodsWithParameterNames > 0,
      unreadableClassData + unreadableCodeItems + malformedDebugInfo,
    ),
  });
};
