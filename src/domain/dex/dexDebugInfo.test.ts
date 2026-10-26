import { describe, expect, it } from "vitest";

import {
  DEX_PAUSED,
  type DexDebugInfoWalk,
  type DexMethodDebug,
  type DexParameterLayout,
  dexWorkBudget,
  startDebugInfo,
} from "./dexDebugInfo.js";
import {
  dexParameterList,
  sleb,
  uleb,
  ulebp1,
} from "../../../tests/fixtures/dexFile.js";

// Opcodes
const END_SEQUENCE = 0x00;
const ADVANCE_LINE = 0x02;
const START_LOCAL = 0x03;
const END_LOCAL = 0x05;
const RESTART_LOCAL = 0x06;
const SET_FILE = 0x09;
const ADVANCE_PC = 0x01;
const EMIT_HERE = 0x0e; // special opcode: line += 0, address += 0, emit a position

/** Decode a whole stream in one call, passing over any due pause. */
const decodeDebugInfo = (
  bytes: Uint8Array,
  offset: number,
  insnsSize: number,
  layout?: DexParameterLayout,
): DexMethodDebug => {
  const walk: DexMethodDebug | DexDebugInfoWalk = startDebugInfo(
    bytes,
    offset,
    insnsSize,
    layout,
  );
  if (!("resume" in walk)) return walk;
  let result = walk.resume();
  while (result === DEX_PAUSED) result = walk.resume();
  return result;
};

/** Assemble a debug_info_item at offset 1 (offset 0 is reserved for "absent"). */
const stream = (...body: number[]): Uint8Array =>
  Uint8Array.from([0xff, ...body]);

describe("decodeDebugInfo", () => {
  it("decodes parameter names, a position, and a closed local scope", () => {
    const bytes = stream(
      ...uleb(1), // line_start
      ...uleb(1), // parameters_size
      ...ulebp1(5), // parameter name_idx = 5
      START_LOCAL,
      ...uleb(1), // register
      ...ulebp1(10), // name_idx
      ...ulebp1(11), // type_idx
      EMIT_HERE, // position @ address 0, line 1
      ADVANCE_PC,
      ...uleb(2), // the scope covers addresses 0-1
      END_LOCAL,
      ...uleb(1), // register
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 10);
    expect(d.present).toBe(true);
    expect(d.malformed).toBe(false);
    expect(d.parameterNames).toEqual([5]);
    expect(d.positionCount).toBe(1);
    expect(d.locals).toHaveLength(1);
    expect(d.locals[0]).toMatchObject({
      register: 1,
      nameIdx: 10,
      typeIdx: 11,
      signatureIdx: -1,
      startAddress: 0,
      endAddress: 2,
      outOfRange: false,
    });
  });

  it("skips a zero-length scope, as dexdump does", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      START_LOCAL,
      ...uleb(1),
      ...ulebp1(10),
      ...ulebp1(11),
      END_LOCAL, // ends at its own start address
      ...uleb(1),
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 10);
    expect(d.localCount).toBe(0);
    expect(d.explicitLocalCount).toBe(0);
  });

  it("counts a declaration only when a scope covers an in-code instruction", () => {
    const zeroLength = Array.from({ length: 50 }, () => [
      START_LOCAL,
      ...uleb(1),
      ...ulebp1(10),
      ...ulebp1(11),
      END_LOCAL,
      ...uleb(1),
    ]).flat();
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      ...zeroLength,
      START_LOCAL, // a real scope over addresses 0-1, ended and restarted
      ...uleb(2),
      ...ulebp1(10),
      ...ulebp1(11),
      ADVANCE_PC,
      ...uleb(2),
      END_LOCAL,
      ...uleb(2),
      0x06, // DBG_RESTART_LOCAL: the same declaration, not a new one
      ...uleb(2),
      ADVANCE_PC,
      ...uleb(10), // past insns_size
      START_LOCAL, // declared past the code: covers no instruction
      ...uleb(3),
      ...ulebp1(10),
      ...ulebp1(11),
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4);
    expect(d.explicitLocalCount).toBe(1);
    expect(d.explicitLocalCount).toBeLessThanOrEqual(d.localCount);
  });

  it("runs an unterminated local scope to insns_size", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      START_LOCAL,
      ...uleb(2),
      ...ulebp1(3),
      ...ulebp1(4),
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 7);
    expect(d.malformed).toBe(false);
    expect(d.locals[0]).toMatchObject({ startAddress: 0, endAddress: 7 });
  });

  it("counts a SET_FILE redirect and the position after it", () => {
    const bytes = stream(
      ...uleb(5),
      ...uleb(0),
      SET_FILE,
      ...ulebp1(7),
      EMIT_HERE,
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4);
    expect(d.setFileEvents).toBe(1);
    expect(d.positionCount).toBe(1);
    expect(d.malformed).toBe(false);
  });

  it("preserves a position but marks malformed when a line goes non-positive", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      ADVANCE_LINE,
      ...sleb(-5),
      EMIT_HERE, // line 1 - 5 + 0 = -4
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4);
    expect(d.positionCount).toBe(1);
    expect(d.malformed).toBe(true);
  });

  it("marks malformed when the stream ends without DBG_END_SEQUENCE", () => {
    const bytes = stream(...uleb(1), ...uleb(0), EMIT_HERE); // no END_SEQUENCE
    const d = decodeDebugInfo(bytes, 1, 4);
    expect(d.malformed).toBe(true);
    expect(d.positionCount).toBe(1);
  });
});

describe("decodeDebugInfo bounds and semantics", () => {
  it("counts only positions inside the method's code", () => {
    // Special opcode 0x1e: address += 1, line += 1 (a shared R8 stream runs on).
    const ADVANCE_BOTH = 0x0a + 15 + 1;
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      EMIT_HERE,
      ADVANCE_BOTH,
      ADVANCE_BOTH,
      ADVANCE_BOTH,
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 2);
    expect(d.positionCount).toBe(2);
  });

  it("separates declared locals from implicit parameter locals", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(1),
      ...ulebp1(-1 + 0), // one unnamed parameter (name index NO_INDEX)
      START_LOCAL,
      ...uleb(1), // a register other than the seeded parameter's
      ...ulebp1(10),
      ...ulebp1(11),
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4, {
      firstRegister: 0,
      accessFlags: 0x8,
      thisTypeIdx: 0,
      paramTypes: dexParameterList([{ typeIdx: 3, wide: false }]),
    });
    expect(d.explicitLocalCount).toBe(1);
    expect(d.localCount).toBeGreaterThan(d.explicitLocalCount);
  });

  it("refuses a parameter list longer than 255 before allocating it", () => {
    const d = decodeDebugInfo(stream(...uleb(1), ...uleb(256)), 1, 4);
    expect(d.malformed).toBe(true);
    expect(d.parameterNames).toEqual([]);
  });
});

describe("decodeDebugInfo register bound", () => {
  it("treats a local in a register past registers_size as malformed", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      START_LOCAL,
      ...uleb(70_000),
      ...ulebp1(10),
      ...ulebp1(11),
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4, {
      firstRegister: 0,
      registersSize: 4,
      accessFlags: 0x8,
      thisTypeIdx: 0,
      paramTypes: dexParameterList([]),
    });
    expect(d.malformed).toBe(true);
    expect(d.localCount).toBe(0);
  });
});

describe("decodeDebugInfo pool references", () => {
  const layout = {
    firstRegister: 0,
    registersSize: 4,
    accessFlags: 0x8,
    thisTypeIdx: 0,
    paramTypes: dexParameterList([]),
    stringValid: (idx: number) => idx < 8,
    typeValid: (idx: number) => idx < 4,
  };
  const startLocal = (nameIdx: number, typeIdx: number): Uint8Array =>
    stream(
      ...uleb(1),
      ...uleb(0),
      START_LOCAL,
      ...uleb(1),
      ...ulebp1(nameIdx),
      ...ulebp1(typeIdx),
      END_SEQUENCE,
    );

  it("accepts local and source-file references inside the pools", () => {
    expect(decodeDebugInfo(startLocal(7, 3), 1, 4, layout).malformed).toBe(
      false,
    );
  });

  it("marks a local name or type outside its pool malformed, as ART's verifier does", () => {
    expect(decodeDebugInfo(startLocal(8, 3), 1, 4, layout).malformed).toBe(
      true,
    );
    expect(decodeDebugInfo(startLocal(7, 4), 1, 4, layout).malformed).toBe(
      true,
    );
  });

  it("marks an in-pool reference the pools report unreadable malformed", () => {
    const unreadable = { ...layout, stringValid: (idx: number) => idx !== 5 };
    expect(decodeDebugInfo(startLocal(5, 3), 1, 4, unreadable).malformed).toBe(
      true,
    );
    const badType = { ...layout, typeValid: (idx: number) => idx !== 3 };
    expect(decodeDebugInfo(startLocal(7, 3), 1, 4, badType).malformed).toBe(
      true,
    );
  });

  it("marks a DBG_SET_FILE name outside the string pool malformed", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      SET_FILE,
      ...ulebp1(8),
      END_SEQUENCE,
    );
    expect(decodeDebugInfo(bytes, 1, 4, layout).malformed).toBe(true);
  });
});

describe("decodeDebugInfo sloppy local events", () => {
  it("tolerates ending a register with no live local, as ART's decoder does", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      END_LOCAL,
      ...uleb(4),
      EMIT_HERE,
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4);
    expect(d.malformed).toBe(false);
    expect(d.positionCount).toBe(1);
    expect(d.localCount).toBe(0);
  });

  it("keeps a live local's start when it is restarted, as ART's decoder does", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      START_LOCAL,
      ...uleb(1),
      ...ulebp1(10),
      ...ulebp1(11),
      ADVANCE_PC,
      ...uleb(2),
      RESTART_LOCAL, // superfluous: register 1 is still live
      ...uleb(1),
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4);
    expect(d.malformed).toBe(false);
    expect(d.locals).toEqual([
      expect.objectContaining({ register: 1, startAddress: 0, endAddress: 4 }),
    ]);
    expect(d.explicitLocalCount).toBe(1);
  });

  it("restarts a never-declared register without a name, and not as evidence", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      ADVANCE_PC,
      ...uleb(1),
      RESTART_LOCAL,
      ...uleb(2),
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4);
    expect(d.malformed).toBe(false);
    expect(d.locals).toEqual([
      expect.objectContaining({
        register: 2,
        nameIdx: -1,
        typeIdx: -1,
        startAddress: 1,
        endAddress: 4,
      }),
    ]);
    expect(d.explicitLocalCount).toBe(0);
  });

  it("marks an end or restart outside the method's frame malformed, as ART does", () => {
    const layout = {
      firstRegister: 0,
      registersSize: 2,
      accessFlags: 0x8,
      thisTypeIdx: 0,
      paramTypes: dexParameterList([]),
    };
    for (const op of [END_LOCAL, RESTART_LOCAL]) {
      const bytes = stream(
        ...uleb(1),
        ...uleb(0),
        op,
        ...uleb(2),
        END_SEQUENCE,
      );
      expect(decodeDebugInfo(bytes, 1, 4, layout).malformed).toBe(true);
    }
  });
});

describe("decodeDebugInfo faulted streams", () => {
  const layout = {
    firstRegister: 0,
    registersSize: 4,
    accessFlags: 0x8,
    thisTypeIdx: 0,
    paramTypes: dexParameterList([]),
  };

  it("keeps locals that ended before a fault and drops those still live, as ART does", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      START_LOCAL,
      ...uleb(0),
      ...ulebp1(10),
      ...ulebp1(11),
      START_LOCAL,
      ...uleb(1),
      ...ulebp1(12),
      ...ulebp1(11),
      ADVANCE_PC,
      ...uleb(1),
      END_LOCAL,
      ...uleb(0), // closes register 0's local before the fault
      ADVANCE_PC,
      ...uleb(1),
      END_LOCAL,
      ...uleb(4), // past registers_size: the fault
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4, layout);
    expect(d.malformed).toBe(true);
    expect(d.locals).toEqual([
      expect.objectContaining({ register: 0, startAddress: 0, endAddress: 1 }),
    ]);
    expect(d.localCount).toBe(1);
    expect(d.explicitLocalCount).toBe(1);
  });

  it("drops still-live locals when the stream runs short", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      START_LOCAL,
      ...uleb(0),
      ...ulebp1(10),
      ...ulebp1(11),
      ADVANCE_PC,
      ...uleb(1),
    );
    const d = decodeDebugInfo(bytes, 1, 4, layout);
    expect(d.malformed).toBe(true);
    expect(d.locals).toEqual([]);
    expect(d.localCount).toBe(0);
  });
});

describe("DexDebugInfoWalk terminal state", () => {
  it("returns the same result when resumed after it finished", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      EMIT_HERE,
      END_SEQUENCE,
      EMIT_HERE, // bytes after END_SEQUENCE belong to no stream
      EMIT_HERE,
      END_SEQUENCE,
    );
    const walk = startDebugInfo(bytes, 1, 4);
    if (!("resume" in walk)) throw new Error("expected a walk");
    const first = walk.resume();
    const second = walk.resume();
    expect(first).not.toBe(DEX_PAUSED);
    expect(second).toBe(first);
    expect(second === DEX_PAUSED ? -1 : second.positionCount).toBe(1);
  });
});

describe("DexDebugInfoWalk paused reference checks", () => {
  /** A check that pauses on its first call for each index, then passes. */
  const pausingOnce = (calls: Map<number, number>) => (idx: number) => {
    const seen = calls.get(idx) ?? 0;
    calls.set(idx, seen + 1);
    return seen === 0 ? DEX_PAUSED : true;
  };
  const bytes = stream(
    ...uleb(1),
    ...uleb(1),
    ...ulebp1(5), // parameter name
    0x04, // START_LOCAL_EXTENDED v1 name 6, type 2, signature 7
    ...uleb(1),
    ...ulebp1(6),
    ...ulebp1(2),
    ...ulebp1(7),
    EMIT_HERE,
    SET_FILE,
    ...ulebp1(6),
    END_SEQUENCE,
  );
  const layout = {
    firstRegister: 3,
    registersSize: 4,
    accessFlags: 0x8,
    thisTypeIdx: 0,
    paramTypes: dexParameterList([{ typeIdx: 1, wide: false }]),
  };
  const run = (extra: Partial<DexParameterLayout>) => {
    const budget = dexWorkBudget(1_000);
    const walk = startDebugInfo(
      bytes,
      1,
      4,
      { ...layout, ...extra },
      {
        budget,
      },
    );
    if (!("resume" in walk)) throw new Error("expected a walk");
    let pauses = 0;
    let result = walk.resume();
    while (result === DEX_PAUSED) {
      pauses += 1;
      result = walk.resume();
    }
    return { result, pauses, spent: budget.limit - budget.remaining };
  };

  it("re-reads the unit without re-checking or re-charging what already passed", () => {
    const strings = new Map<number, number>();
    const types = new Map<number, number>();
    const paused = run({
      stringValid: pausingOnce(strings),
      typeValid: pausingOnce(types),
    });
    const whole = run({ stringValid: () => true, typeValid: () => true });
    expect(paused.pauses).toBe(4);
    expect(paused.result).toEqual(whole.result);
    expect(paused.spent).toBe(whole.spent);
    // Name 6 passed before type 2 paused, so the re-read skips it; SET_FILE
    // checks it once more as its own reference.
    expect(Object.fromEntries(strings)).toEqual({ 5: 2, 6: 3, 7: 2 });
    expect(Object.fromEntries(types)).toEqual({ 2: 2 });
  });
});
