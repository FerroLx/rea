import { describe, expect, it } from "vitest";

import { dexWorkBudget } from "./dexDebugInfo.js";
import {
  assembleClassDetail,
  type DexWork,
  type DexWorkError,
  summarizeDex,
} from "./dexDebugMetadata.js";
import { type DexFile, parseDexFile } from "./dexFile.js";
import type { Result } from "../result.js";
import {
  debuggableDex,
  uleb,
  ulebp1,
} from "../../../tests/fixtures/dexFile.js";

const work = (limit = 1_000_000, cancelled = false): DexWork => ({
  budget: dexWorkBudget(limit),
  cancelled: () => cancelled,
  yieldNow: () => Promise.resolve(),
  sliceUnits: 1 << 18,
});
const OUTPUT_LIMIT = 8 * 1024 * 1024;

/** The class detail of the fixture's one class, shaped like {@link summarizeDex}. */
const detailRun = (dex: DexFile, bytes: Uint8Array, work: DexWork) =>
  assembleClassDetail(dex, bytes, "Lcom/example/Foo;", work, OUTPUT_LIMIT);

describe("dexDebugMetadata assembly", () => {
  it("summarizes a debuggable dex with resolved tallies and readiness", async () => {
    const parsed = parseDexFile(debuggableDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const result = await summarizeDex(parsed.value, debuggableDex(), work());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const summary = result.value;
    expect(summary.classCount).toBe(1);
    expect(summary.methodsWithCode).toBe(1);
    expect(summary.methodsWithDebugInfo).toBe(1);
    expect(summary.methodsWithParameterNames).toBe(1);
    expect(summary.linePositions).toBe(1);
    expect(summary.localDeclarations).toBe(1);
    expect(summary.sourceFilePresent).toBe(1);
    expect(summary.distinctSourceFiles).toEqual({
      count: 1,
      sample: ["Foo.java"],
    });
    expect(summary.readiness).toBe("present");
  });

  it("resolves full per-method detail for a selected class", async () => {
    const parsed = parseDexFile(debuggableDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const result = await assembleClassDetail(
      parsed.value,
      debuggableDex(),
      "Lcom/example/Foo;",
      work(),
      OUTPUT_LIMIT,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const detail = result.value;
    expect(detail).not.toBeNull();
    if (detail === null) return;
    expect(detail.sourceFile).toBe("Foo.java");
    expect(detail.methods).toHaveLength(1);
    const method = detail.methods[0]!;
    expect(method.name).toBe("run");
    expect(method.descriptor).toBe("(I)V");
    expect(method.state).toBe("present");
    expect(method.parameterNames).toEqual(["x"]);
    expect(method.locals).toHaveLength(1);
    expect(method.locals[0]).toMatchObject({
      register: 0,
      name: "x",
      type: "I",
      outOfRange: false,
    });
  });

  it("returns null for a class descriptor not present", async () => {
    const parsed = parseDexFile(debuggableDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const result = await assembleClassDetail(
      parsed.value,
      debuggableDex(),
      "LNope;",
      work(),
      OUTPUT_LIMIT,
    );
    expect(result).toEqual({ ok: true, value: null });
  });
});

describe("dexDebugMetadata work and output bounds", () => {
  it("refuses once the member's work budget is spent", async () => {
    const parsed = parseDexFile(debuggableDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(await summarizeDex(parsed.value, debuggableDex(), work(1))).toEqual({
      ok: false,
      error: { kind: "work-budget-exceeded", limit: 1 },
    });
  });

  it("stops when the caller cancels", async () => {
    const parsed = parseDexFile(debuggableDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(
      await summarizeDex(parsed.value, debuggableDex(), work(1_000_000, true)),
    ).toEqual({ ok: false, error: { kind: "cancelled" } });
  });

  it("refuses a class detail past the output limit before building it", async () => {
    const parsed = parseDexFile(debuggableDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const result = await assembleClassDetail(
      parsed.value,
      debuggableDex(),
      "Lcom/example/Foo;",
      work(),
      1200,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("output-budget-exceeded");
  });
});

describe("dexDebugMetadata unreadable structures", () => {
  it("reports unreadable class_data and reads readiness as unknown, not stripped", async () => {
    const bytes = debuggableDex();
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const classDefsOff = view.getUint32(100, true);
    view.setUint32(classDefsOff + 24, bytes.length + 100, true); // class_data_off past the file
    const parsed = parseDexFile(bytes);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const result = await summarizeDex(parsed.value, bytes, work());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.unreadable.classData).toBe(1);
    expect(result.value.readiness).toBe("unknown");
  });

  it("reads class_data at the end of the file or cut off mid-header as unreadable", async () => {
    for (const back of [0, 1, 2]) {
      const bytes = debuggableDex();
      const view = new DataView(
        bytes.buffer,
        bytes.byteOffset,
        bytes.byteLength,
      );
      const classDefsOff = view.getUint32(100, true);
      // At EOF, or one/two bytes before it: too few bytes for the four counts.
      bytes.fill(0, bytes.length - back);
      view.setUint32(classDefsOff + 24, bytes.length - back, true);
      const parsed = parseDexFile(bytes);
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;
      const result = await summarizeDex(parsed.value, bytes, work());
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.unreadable.classData).toBe(1);
      expect(result.value.readiness).toBe("unknown");
    }
  });
});

/** Byte offsets of the fixture's class_def, class_data, code_item and debug_info. */
const layoutOf = (bytes: Uint8Array) => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const classDefsOff = view.getUint32(100, true);
  const classDataOff = view.getUint32(classDefsOff + 24, true);
  const codeOff = classDataOff - 24; // 16-byte header + 4 code units
  return {
    view,
    classDefsOff,
    classDataOff,
    codeOff,
    debugInfoOff: codeOff - 5,
  };
};

/** The fixture with a second class_def (a copy whose class_idx is `classIdx`). */
const withSecondClassDef = (classIdx: number): Uint8Array => {
  const base = debuggableDex();
  const { classDefsOff } = layoutOf(base);
  const bytes = new Uint8Array(base.length + 32);
  bytes.set(base);
  bytes.set(base.subarray(classDefsOff, classDefsOff + 32), base.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(base.length, classIdx, true);
  view.setUint32(32, bytes.length, true); // file_size
  view.setUint32(96, 2, true); // class_defs_size
  return bytes;
};

const summaryOf = async (bytes: Uint8Array) => {
  const parsed = parseDexFile(bytes);
  if (!parsed.ok) throw new Error("fixture must frame");
  const result = await summarizeDex(parsed.value, bytes, work());
  if (!result.ok) throw new Error(result.error.kind);
  return result.value;
};

const detailOf = async (bytes: Uint8Array, limit = OUTPUT_LIMIT) => {
  const parsed = parseDexFile(bytes);
  if (!parsed.ok) throw new Error("fixture must frame");
  return await assembleClassDetail(
    parsed.value,
    bytes,
    "Lcom/example/Foo;",
    work(),
    limit,
  );
};

describe("dexDebugMetadata fails closed on unverifiable facts", () => {
  it("reports an unreadable class identity as unknown, never as absent", async () => {
    const result = await detailOf(withSecondClassDef(0xfffe));
    expect(result).toEqual({
      ok: false,
      error: { kind: "unreadable-class-identity", count: 1 },
    });
  });

  it("refuses a class declared by two class_defs as ambiguous", async () => {
    const result = await detailOf(withSecondClassDef(0));
    expect(result).toEqual({
      ok: false,
      error: { kind: "duplicate-class-definition", count: 2 },
    });
  });

  it("refuses an oversized methodless class before decoding its source file", async () => {
    const bytes = debuggableDex();
    const { view, classDefsOff } = layoutOf(bytes);
    view.setUint32(classDefsOff + 24, 0, true); // no class_data
    const result = await detailOf(bytes, 1030);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("output-budget-exceeded");
  });

  it("treats instructions running past the member as an unreadable code_item", async () => {
    const bytes = debuggableDex();
    const { view, codeOff } = layoutOf(bytes);
    view.setUint32(codeOff + 12, 0x7fff_ffff, true); // insns_size
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.codeItems).toBe(1);
    expect(summary.linePositions).toBe(0);
    expect(summary.readiness).toBe("unknown");
  });

  it("marks a parameter-name count that disagrees with the proto malformed", async () => {
    const bytes = debuggableDex();
    const { debugInfoOff } = layoutOf(bytes);
    bytes[debugInfoOff + 1] = 0; // parameters_size 0 for a one-parameter proto
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.debugInfo).toBe(1);
    expect(summary.methodsWithParameterNames).toBe(0);
    expect(summary.readiness).toBe("unknown");
  });

  it("does not count a local declaration that fails validation", async () => {
    const bytes = debuggableDex();
    const { debugInfoOff } = layoutOf(bytes);
    bytes[debugInfoOff + 3] = 0x03; // DBG_START_LOCAL
    bytes[debugInfoOff + 4] = 0x05; // register 5 of a 1-register frame
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.debugInfo).toBe(1);
    expect(summary.explicitLocalDeclarations).toBe(0);
  });
});

describe("dexDebugMetadata checks the references a stream depends on", () => {
  it("reads a method whose proto parameters are out of the file as unknown, not complete", async () => {
    const bytes = debuggableDex();
    const view = new DataView(bytes.buffer);
    const protoIdsOff = view.getUint32(76, true);
    view.setUint32(protoIdsOff + 8, bytes.length + 100, true); // parameters_off
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.debugInfo).toBe(1);
    expect(summary.readiness).toBe("unknown");
    const detail = await detailOf(bytes);
    if (!detail.ok || detail.value === null) throw new Error("class must read");
    expect(detail.value.methods[0]?.state).toBe("malformed");
  });

  it("does not count a parameter name outside the string pool as evidence", async () => {
    const bytes = debuggableDex();
    const { debugInfoOff } = layoutOf(bytes);
    bytes[debugInfoOff + 2] = 127; // parameter name_idx 126 of 6 strings
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.debugInfo).toBe(1);
    expect(summary.methodsWithParameterNames).toBe(0);
    expect(summary.readiness).toBe("unknown");
    const detail = await detailOf(bytes);
    if (!detail.ok || detail.value === null) throw new Error("class must read");
    expect(detail.value.methods[0]?.state).toBe("malformed");
  });

  it("does not count a parameter name whose string data is unreadable as evidence", async () => {
    const bytes = debuggableDex();
    const view = new DataView(bytes.buffer);
    const stringIdsOff = view.getUint32(60, true);
    // string_id 2 ("x", the parameter name) stays in the pool, but its data
    // lies past the end of the file; ART's verifier rejects such a file.
    view.setUint32(stringIdsOff + 2 * 4, bytes.length + 0x1000, true);
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.debugInfo).toBe(1);
    expect(summary.methodsWithParameterNames).toBe(0);
    expect(summary.readiness).toBe("unknown");
    const detail = await detailOf(bytes);
    if (!detail.ok || detail.value === null) throw new Error("class must read");
    expect(detail.value.methods[0]?.state).toBe("malformed");
  });

  it("counts a valid stream longer than two million opcodes in full", async () => {
    const bytes = debuggableDex(2_000_000);
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    const result = await summarizeDex(parsed.value, bytes, work(8_000_000));
    if (!result.ok) throw new Error(result.error.kind);
    expect(result.value.linePositions).toBe(2_000_001);
    expect(result.value.unreadable.debugInfo).toBe(0);
    expect(result.value.readiness).toBe("present");
  });
});

describe("dexDebugMetadata validates the frame and class identities", () => {
  it("marks a method whose ins_size disagrees with its proto malformed", async () => {
    const bytes = debuggableDex();
    const { view, codeOff } = layoutOf(bytes);
    view.setUint16(codeOff + 2, 0, true); // ins_size 0 for a one-int static method
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.debugInfo).toBe(1);
    expect(summary.readiness).toBe("unknown");
  });

  it("treats more incoming arguments than registers as an unreadable code_item", async () => {
    const bytes = debuggableDex();
    const { view, codeOff } = layoutOf(bytes);
    view.setUint16(codeOff + 2, 2, true); // ins_size 2 of a 1-register frame
    expect((await summaryOf(bytes)).unreadable.codeItems).toBe(1);
  });

  it("matches a class by its modified-UTF-8 bytes, not a near miss", async () => {
    const result = await detailOf(debuggableDex());
    expect(result.ok && result.value?.sourceFile).toBe("Foo.java");
    const parsed = parseDexFile(debuggableDex());
    if (!parsed.ok) throw new Error("fixture must frame");
    for (const near of ["Lcom/example/Foo", "Lcom/example/Fo\u00f6;", ""])
      expect(
        await assembleClassDetail(
          parsed.value,
          debuggableDex(),
          near,
          work(),
          OUTPUT_LIMIT,
        ),
      ).toEqual({ ok: true, value: null });
  });
});

describe("dexDebugMetadata readiness vocabulary", () => {
  it("labels a member with line positions but no local evidence partial", async () => {
    const bytes = debuggableDex();
    const { debugInfoOff } = layoutOf(bytes);
    bytes[debugInfoOff + 2] = 0; // parameter name NO_INDEX (an R8 release)
    const summary = await summaryOf(bytes);
    expect(summary.linePositions).toBe(1);
    expect(summary.explicitLocalDeclarations).toBe(0);
    expect(summary.methodsWithParameterNames).toBe(0);
    expect(summary.readiness).toBe("partial");
  });

  it("labels a member with local evidence but no line positions partial", async () => {
    const bytes = debuggableDex();
    const { debugInfoOff } = layoutOf(bytes);
    bytes[debugInfoOff + 3] = 0x00; // END_SEQUENCE before the position
    const summary = await summaryOf(bytes);
    expect(summary.linePositions).toBe(0);
    expect(summary.readiness).toBe("partial");
  });

  it("keeps a partial member unknown when an unreadable structure could settle it", async () => {
    const bytes = withSecondClassDef(0);
    const { view, debugInfoOff } = layoutOf(bytes);
    bytes[debugInfoOff + 2] = 0; // lines only
    view.setUint32(bytes.length - 32 + 24, bytes.length + 100, true); // second class_data unreadable
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.classData).toBe(1);
    expect(summary.readiness).toBe("unknown");
  });
});

describe("dexDebugMetadata cooperative scheduling", () => {
  const pacedWork = (onYield: () => void, state: { aborted: boolean }) => ({
    budget: dexWorkBudget(1_000_000),
    cancelled: () => state.aborted,
    yieldNow: () => {
      onYield();
      return Promise.resolve();
    },
    sliceUnits: 1,
  });

  it("yields to the host between slices and observes an abort delivered there", async () => {
    const bytes = debuggableDex();
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    const state = { aborted: false };
    let yields = 0;
    const work = pacedWork(() => {
      yields += 1;
      state.aborted = true;
    }, state);
    expect(await summarizeDex(parsed.value, bytes, work)).toEqual({
      ok: false,
      error: { kind: "cancelled" },
    });
    expect(yields).toBe(1);
  });

  it("yields during a class lookup and observes an abort delivered there", async () => {
    const bytes = withSecondClassDef(7);
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    const state = { aborted: false };
    let yields = 0;
    const work = pacedWork(() => {
      yields += 1;
      state.aborted = true;
    }, state);
    expect(
      await assembleClassDetail(
        parsed.value,
        bytes,
        "Lcom/example/Foo;",
        work,
        OUTPUT_LIMIT,
      ),
    ).toEqual({ ok: false, error: { kind: "cancelled" } });
    expect(yields).toBe(1);
  });

  it("charges class_defs with no source file and no class_data, so a long scan yields", async () => {
    const base = debuggableDex();
    const { classDefsOff } = layoutOf(base);
    const extra = 64;
    const bytes = new Uint8Array(base.length + extra * 32);
    bytes.set(base);
    const view = new DataView(bytes.buffer);
    for (let i = 0; i < extra; i += 1) {
      const at = base.length + i * 32;
      bytes.set(base.subarray(classDefsOff, classDefsOff + 32), at);
      view.setUint32(at + 16, 0xffff_ffff, true); // source_file_idx NO_INDEX
      view.setUint32(at + 24, 0, true); // class_data_off 0
    }
    view.setUint32(32, bytes.length, true); // file_size
    view.setUint32(96, extra + 1, true); // class_defs_size
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    let yields = 0;
    const result = await summarizeDex(parsed.value, bytes, {
      ...pacedWork(() => (yields += 1), { aborted: false }),
      sliceUnits: 8,
    });
    expect(result.ok).toBe(true);
    expect(yields).toBeGreaterThanOrEqual(extra / 8);
  });

  it("pauses inside one long debug stream, so its slices stay short and an abort lands mid-stream", async () => {
    const positions = 200_000;
    const sliceUnits = 1_000;
    const bytes = debuggableDex(positions);
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    for (const run of [summarizeDex, detailRun] as const) {
      const budget = dexWorkBudget(1_000_000);
      const state = { aborted: false };
      let mark = budget.remaining;
      let longest = 0;
      let yields = 0;
      const result = await run(parsed.value, bytes, {
        budget,
        cancelled: () => state.aborted,
        yieldNow: () => {
          longest = Math.max(longest, mark - budget.remaining);
          mark = budget.remaining;
          yields += 1;
          if (yields === 3) state.aborted = true;
          return Promise.resolve();
        },
        sliceUnits,
      });
      expect(result).toEqual({ ok: false, error: { kind: "cancelled" } });
      // The walk checks before every opcode, so a slice overshoots by one unit.
      expect(longest).toBeLessThanOrEqual(sliceUnits + 1);
      expect(1_000_000 - budget.remaining).toBeLessThan(positions / 10);
    }
  });

  it("completes unchanged when the host keeps yielding without an abort", async () => {
    const bytes = debuggableDex();
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    let yields = 0;
    const result = await summarizeDex(
      parsed.value,
      bytes,
      pacedWork(() => (yields += 1), { aborted: false }),
    );
    expect(result.ok && result.value.readiness).toBe("present");
    expect(yields).toBeGreaterThan(0);
  });
});

/**
 * The fixture with `count` distinct `length`-byte ASCII strings appended as
 * string ids 6.., and its method's debug stream replaced by the original
 * header (line 10, parameter `x`), `events(ids)`, one position and the end.
 */
const withLongStrings = (
  count: number,
  length: number,
  events: (ids: readonly number[]) => number[],
): Uint8Array => {
  const base = debuggableDex();
  const { view: baseView, codeOff } = layoutOf(base);
  const stringIdsOff = baseView.getUint32(60, true);
  const stringsSize = baseView.getUint32(56, true);
  const ids = Array.from({ length: count }, (_, i) => stringsSize + i);
  const stringBytes = uleb(length).length + length + 1;
  const idsOff = base.length + count * stringBytes;
  const alignedIdsOff = idsOff + ((4 - (idsOff % 4)) % 4);
  const stream = [
    ...uleb(10),
    ...uleb(1),
    ...ulebp1(2),
    ...events(ids),
    0x0e,
    0x00,
  ];
  const streamOff = alignedIdsOff + (stringsSize + count) * 4;
  const bytes = new Uint8Array(streamOff + stream.length);
  bytes.set(base);
  const view = new DataView(bytes.buffer);
  for (let i = 0; i < count; i += 1) {
    const at = base.length + i * stringBytes;
    const head = uleb(length);
    bytes.set(head, at);
    bytes.fill(0x61 + (i % 26), at + head.length, at + head.length + length);
    view.setUint32(alignedIdsOff + (stringsSize + i) * 4, at, true);
  }
  bytes.set(
    base.subarray(stringIdsOff, stringIdsOff + stringsSize * 4),
    alignedIdsOff,
  );
  bytes.set(stream, streamOff);
  view.setUint32(32, bytes.length, true); // file_size
  view.setUint32(56, stringsSize + count, true); // string_ids_size
  view.setUint32(60, alignedIdsOff, true); // string_ids_off
  view.setUint32(codeOff + 8, streamOff, true); // debug_info_off
  return bytes;
};

/** One DBG_SET_FILE per id. */
const setFiles = (ids: readonly number[]): number[] =>
  ids.flatMap((id) => [0x09, ...ulebp1(id)]);

/**
 * Run `run` with a small slice, recording the most work done between two
 * yields; `abortAt` aborts at that yield.
 */
const pacedRun = async <T>(
  run: (work: DexWork) => Promise<T>,
  sliceUnits: number,
  abortAt = Number.POSITIVE_INFINITY,
  limit = 50_000_000,
) => {
  const budget = dexWorkBudget(limit);
  const state = { aborted: false };
  let mark = budget.remaining;
  let longest = 0;
  let yields = 0;
  const result = await run({
    budget,
    cancelled: () => state.aborted,
    yieldNow: () => {
      longest = Math.max(longest, mark - budget.remaining);
      mark = budget.remaining;
      yields += 1;
      if (yields === abortAt) state.aborted = true;
      return Promise.resolve();
    },
    sliceUnits,
  });
  longest = Math.max(longest, mark - budget.remaining);
  return { result, longest, spent: budget.limit - budget.remaining };
};

describe("dexDebugMetadata paces long string checks", () => {
  const LENGTH = 100_000;
  const SLICE = 1_000;
  /** Bytes a string scan examines between pause checks. */
  const SCAN_STEP = 16_384;
  const runs = (
    bytes: Uint8Array,
  ): readonly ((work: DexWork) => Promise<Result<unknown, DexWorkError>>)[] => {
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    return [
      (work: DexWork) => summarizeDex(parsed.value, bytes, work),
      (work: DexWork) => detailRun(parsed.value, bytes, work),
    ];
  };

  it("pauses inside the name checks of one opcode run, so an abort lands mid-string", async () => {
    // Eight SET_FILE events naming distinct long strings fit in far fewer
    // opcodes than any opcode-count interval, but scanning them is ~1.6M units.
    const bytes = withLongStrings(8, LENGTH, setFiles);
    for (const run of runs(bytes)) {
      const paced = await pacedRun(run, SLICE, 3);
      expect(paced.result).toEqual({ ok: false, error: { kind: "cancelled" } });
      expect(paced.longest).toBeLessThan(LENGTH / 4);
      expect(paced.spent).toBeLessThan(LENGTH);
    }
  });

  it("pauses while checking one long source-file name", async () => {
    const bytes = withLongStrings(1, 4 * LENGTH, () => []);
    const { classDefsOff, view } = layoutOf(bytes);
    view.setUint32(classDefsOff + 16, 6, true); // source_file_idx -> long string
    const paced = await pacedRun(runs(bytes)[0]!, SLICE);
    expect(paced.result.ok).toBe(true);
    // A scan pauses after each 16 KiB step.
    expect(paced.longest).toBeLessThanOrEqual(SLICE + SCAN_STEP);
  });

  it("does not re-validate a long, invalid source-file name when the detail reports it", async () => {
    const bytes = withLongStrings(1, 4 * LENGTH, () => []);
    const { classDefsOff, view } = layoutOf(bytes);
    view.setUint32(classDefsOff + 16, 6, true); // source_file_idx -> long string
    bytes[
      view.getUint32(view.getUint32(60, true) + 24, true) + 3 + 4 * LENGTH - 1
    ] = 0xff;
    const paced = await pacedRun(runs(bytes)[1]!, SLICE);
    expect(paced.result.ok).toBe(true);
    expect(paced.longest).toBeLessThanOrEqual(SLICE + SCAN_STEP);
    const whole = await pacedRun(runs(bytes)[1]!, 1 << 30);
    expect(paced.result).toEqual(whole.result);
    expect(paced.spent).toBe(whole.spent);
  });

  it("refuses a source-file decode the budget cannot cover instead of completing over it", async () => {
    const bytes = withLongStrings(1, 4 * LENGTH, () => []);
    const { classDefsOff, view } = layoutOf(bytes);
    view.setUint32(classDefsOff + 16, 6, true); // source_file_idx -> long string
    // Enough to scan the name (located and validated: 2 x its length) but
    // not to decode it as well.
    const limit = 2.5 * 4 * LENGTH;
    const refused = await pacedRun(runs(bytes)[1]!, 1 << 30, Infinity, limit);
    expect(refused.result).toEqual({
      ok: false,
      error: { kind: "work-budget-exceeded", limit },
    });
    const whole = await pacedRun(runs(bytes)[1]!, 1 << 30);
    expect(whole.result.ok).toBe(true);
  });

  it("observes an abort raised while the final source-file decode ran", async () => {
    const bytes = withLongStrings(1, 4 * LENGTH, () => []);
    const { classDefsOff, view } = layoutOf(bytes);
    view.setUint32(classDefsOff + 16, 6, true); // source_file_idx -> long string
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    // The abort arrives with the decode's charge (one charge of the whole
    // name), as a host abort would while that synchronous decode runs.
    let aborted = false;
    let remaining = 50_000_000;
    const budget = {
      limit: 50_000_000,
      get remaining() {
        return remaining;
      },
      set remaining(value: number) {
        if (remaining - value >= 4 * LENGTH) aborted = true;
        remaining = value;
      },
    };
    const result = await detailRun(parsed.value, bytes, {
      budget,
      cancelled: () => aborted,
      yieldNow: () => Promise.resolve(),
      sliceUnits: 1 << 30,
    });
    expect(aborted).toBe(true);
    expect(result).toEqual({ ok: false, error: { kind: "cancelled" } });
  });

  it("pauses while checking a long method name in the detail, so an abort lands there", async () => {
    const bytes = withLongStrings(1, 4 * LENGTH, () => []);
    const { view } = layoutOf(bytes);
    view.setUint32(view.getUint32(92, true) + 4, 6, true); // method name -> long string
    bytes[
      view.getUint32(view.getUint32(60, true) + 24, true) + 3 + 4 * LENGTH - 1
    ] = 0xff;
    const detail = runs(bytes)[1]!;
    const paced = await pacedRun(detail, SLICE);
    expect(paced.result.ok).toBe(true);
    expect(paced.longest).toBeLessThanOrEqual(SLICE + SCAN_STEP);
    const aborted = await pacedRun(detail, SLICE, 3);
    expect(aborted.result).toEqual({ ok: false, error: { kind: "cancelled" } });
    expect(aborted.spent).toBeLessThan(LENGTH);
    // A budget spent inside the name check is refused at the same charge
    // whether or not the check paused.
    const refused = [SLICE, 1 << 30].map(
      async (slice) => await pacedRun(detail, slice, Infinity, 2 * LENGTH),
    );
    const [small, large] = await Promise.all(refused);
    expect(small!.result).toEqual({
      ok: false,
      error: { kind: "work-budget-exceeded", limit: 2 * LENGTH },
    });
    expect(large!.result).toEqual(small!.result);
    expect(large!.spent).toBe(small!.spent);
  });

  it("pauses while checking one long class descriptor during a lookup", async () => {
    const bytes = withLongStrings(1, 4 * LENGTH, () => []);
    const { view } = layoutOf(bytes);
    view.setUint32(view.getUint32(68, true), 6, true); // type 0 -> long string
    const paced = await pacedRun(runs(bytes)[1]!, SLICE);
    expect(paced.result).toEqual({ ok: true, value: null });
    expect(paced.longest).toBeLessThan(LENGTH);
  });

  it("decodes the same result, charging each string once, however often it pauses", async () => {
    const bytes = withLongStrings(7, LENGTH, (ids) => [
      ...setFiles(ids.slice(0, 4)),
      // START_LOCAL_EXTENDED v0 name/type/signature, then the names again.
      0x04,
      ...uleb(0),
      ...ulebp1(ids[4]!),
      ...ulebp1(1),
      ...ulebp1(ids[5]!),
      0x0e,
      0x03,
      ...uleb(0),
      ...ulebp1(ids[6]!),
      ...ulebp1(1),
      ...setFiles(ids),
    ]);
    const longest: number[] = [];
    for (const run of runs(bytes)) {
      const whole = await pacedRun(run, 1 << 30);
      const paced = await pacedRun(run, SLICE);
      expect(paced.result).toEqual(whole.result);
      expect(paced.result.ok).toBe(true);
      expect(paced.spent).toBe(whole.spent);
      longest.push(paced.longest);
    }
    // The summary only checks strings; the detail also decodes the names it
    // reports, bounded by the output limit rather than paced.
    expect(longest[0]).toBeLessThan(LENGTH / 4);
  });
});

/**
 * The fixture's class re-pointed at an appended class_data declaring `methods`
 * direct methods without code, with the header claiming `methodIds` method ids.
 */
const withCodelessMethods = (
  methods: number,
  methodIds: number,
  diff = 1,
): Uint8Array => {
  const base = debuggableDex();
  const classData = [
    ...uleb(0),
    ...uleb(0),
    ...uleb(methods),
    ...uleb(0),
    ...Array.from({ length: methods }, (_, i) => [
      ...uleb(i === 0 ? 0 : diff),
      ...uleb(1),
      ...uleb(0),
    ]).flat(),
  ];
  const bytes = new Uint8Array(base.length + classData.length);
  bytes.set(base);
  bytes.set(classData, base.length);
  const { view, classDefsOff } = layoutOf(bytes);
  view.setUint32(classDefsOff + 24, base.length, true); // class_data_off
  view.setUint32(32, bytes.length, true); // file_size
  view.setUint32(88, methodIds, true); // method_ids_size
  return bytes;
};

describe("dexDebugMetadata class_data validation", () => {
  it("paces the class_data validation pass, not only the method pass", async () => {
    const methods = 4096;
    const bytes = withCodelessMethods(methods, methods);
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    const budget = dexWorkBudget(1_000_000);
    let usedAtFirstYield: number | null = null;
    const result = await summarizeDex(parsed.value, bytes, {
      budget,
      cancelled: () => usedAtFirstYield !== null,
      yieldNow: () => {
        usedAtFirstYield ??= budget.limit - budget.remaining;
        return Promise.resolve();
      },
      sliceUnits: 64,
    });
    expect(result).toEqual({ ok: false, error: { kind: "cancelled" } });
    // The abort lands one slice into validating the class's methods.
    expect(usedAtFirstYield).toBeGreaterThanOrEqual(64);
    expect(usedAtFirstYield).toBeLessThan(methods);
  });

  it("reads a method list that repeats an index past the id table's size, as ART accepts", async () => {
    // ART's CheckOrder rejects only a decreasing index: three direct methods
    // all naming method id 0 are verifiable though the table has one entry.
    const summary = await summaryOf(withCodelessMethods(3, 1, 0));
    expect(summary.unreadable.classData).toBe(0);
  });

  it("treats a method index past the method id table as unreadable class_data", async () => {
    const bytes = withCodelessMethods(2, 1);
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.classData).toBe(1);
    expect(summary.readiness).toBe("unknown");
    expect(await detailOf(bytes)).toEqual({
      ok: false,
      error: {
        kind: "malformed-class-data",
        classDataOff: debuggableDex().length,
      },
    });
  });
});

describe("dexDebugMetadata distinct source files", () => {
  it("counts distinct string_ids but samples each text once", async () => {
    const bytes = withSecondClassDef(0);
    const { view } = layoutOf(bytes);
    const stringIdsOff = view.getUint32(60, true);
    // string_id 2 re-pointed at the data of string_id 0 ("Foo.java").
    view.setUint32(stringIdsOff + 8, view.getUint32(stringIdsOff, true), true);
    view.setUint32(bytes.length - 32 + 16, 2, true); // second source_file_idx
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    const result = await summarizeDex(parsed.value, bytes, work());
    if (!result.ok) throw new Error(result.error.kind);
    expect(result.value.distinctSourceFiles).toEqual({
      count: 2,
      sample: ["Foo.java"],
    });
  });
});
