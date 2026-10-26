import { describe, expect, it } from "vitest";

import { decodeInstructionBoundaries } from "./javaBytecode.js";

const starts = (code: readonly number[]): number[] => {
  const decoded = decodeInstructionBoundaries(Uint8Array.from(code));
  if (!decoded.ok) throw new Error(JSON.stringify(decoded.error));
  return code.flatMap((_, pc) => (decoded.value.startsAt(pc) ? [pc] : []));
};

const failure = (code: readonly number[]) => {
  const decoded = decodeInstructionBoundaries(Uint8Array.from(code));
  if (decoded.ok) throw new Error("expected the stream not to decode");
  return decoded.error;
};

const s4 = (value: number): number[] => [
  (value >>> 24) & 0xff,
  (value >>> 16) & 0xff,
  (value >>> 8) & 0xff,
  value & 0xff,
];

describe("decodeInstructionBoundaries", () => {
  it("marks instruction starts, never operand bytes", () => {
    // iload_0; bipush 100; iadd; istore_1; iload_1; ireturn (javac's `a + 100`).
    expect(starts([0x1a, 0x10, 0x64, 0x60, 0x3c, 0x1b, 0xac])).toEqual([
      0, 1, 3, 4, 5, 6,
    ]);
    // invokeinterface (5), invokedynamic (5), multianewarray (4), goto_w (5).
    expect(
      starts([
        0xb9, 0, 1, 1, 0, 0xba, 0, 2, 0, 0, 0xc5, 0, 3, 1, 0xc8, 0, 0, 0, 0,
      ]),
    ).toEqual([0, 5, 10, 14]);
  });

  it("treats wide and the opcode it modifies as one instruction", () => {
    // wide iinc 14, 1000 (6); wide iload 300 (4); wide ret 2 (4); return.
    expect(
      starts([
        0xc4, 0x84, 0, 14, 0x03, 0xe8, 0xc4, 0x15, 0x01, 0x2c, 0xc4, 0xa9, 0, 2,
        0xb1,
      ]),
    ).toEqual([0, 6, 10, 14]);
  });

  it.each([0, 1, 2, 3])(
    "aligns switch operands from the code start (switch at pc %i)",
    (pc) => {
      const prefix = Array<number>(pc).fill(0x00); // nop
      const padding = Array<number>((4 - ((pc + 1) % 4)) % 4).fill(0);
      const table = [0xaa, ...padding, ...s4(0), ...s4(1), ...s4(2)];
      const tableswitch = [...table, ...s4(0), ...s4(0), 0xb1];
      expect(starts([...prefix, ...tableswitch])).toEqual([
        ...prefix.map((_, i) => i),
        pc,
        pc + table.length + 8,
      ]);
      const lookup = [0xab, ...padding, ...s4(0), ...s4(1)];
      const lookupswitch = [...lookup, ...s4(7), ...s4(0), 0xb1];
      expect(starts([...prefix, ...lookupswitch])).toEqual([
        ...prefix.map((_, i) => i),
        pc,
        pc + lookup.length + 8,
      ]);
    },
  );

  it.each([
    ["breakpoint", 0xca],
    ["a reserved opcode", 0xcb],
    ["impdep1", 0xfe],
    ["impdep2", 0xff],
  ])("refuses %s as an illegal opcode", (_label, opcode) => {
    expect(failure([0x00, opcode, 0xb1])).toEqual({
      kind: "illegal-opcode",
      pc: 1,
      opcode,
    });
  });

  it("refuses an instruction that runs past code_length", () => {
    expect(failure([0x1b, 0x10])).toEqual({
      kind: "truncated-instruction",
      pc: 1,
    });
    expect(failure([0xc4])).toEqual({ kind: "truncated-instruction", pc: 0 });
    expect(failure([0xc4, 0x84, 0, 1])).toEqual({
      kind: "truncated-instruction",
      pc: 0,
    });
    // tableswitch 1..1000 needs 4,000 jump bytes the code does not hold.
    expect(failure([0xaa, 0, 0, 0, ...s4(0), ...s4(1), ...s4(1000)])).toEqual({
      kind: "truncated-instruction",
      pc: 0,
    });
    // lookupswitch whose fixed operands are cut off.
    expect(failure([0xab, 0, 0, 0, ...s4(0)])).toEqual({
      kind: "truncated-instruction",
      pc: 0,
    });
  });

  it("refuses wide before an opcode it cannot modify", () => {
    expect(failure([0xc4, 0x60, 0xb1])).toEqual({
      kind: "illegal-wide-opcode",
      pc: 0,
    });
  });

  it("refuses a tableswitch with high < low and a negative lookupswitch count", () => {
    expect(failure([0xaa, 0, 0, 0, ...s4(0), ...s4(5), ...s4(1)])).toEqual({
      kind: "invalid-switch",
      pc: 0,
    });
    expect(failure([0xab, 0, 0, 0, ...s4(0), ...s4(-1)])).toEqual({
      kind: "invalid-switch",
      pc: 0,
    });
  });
});
