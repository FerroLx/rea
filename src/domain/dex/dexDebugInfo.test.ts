import { describe, expect, it } from "vitest";

import { decodeDebugInfo } from "./dexDebugInfo.js";

const uleb = (value: number): number[] => {
  const out: number[] = [];
  let v = value >>> 0;
  do {
    let b = v & 0x7f;
    v >>>= 7;
    if (v !== 0) b |= 0x80;
    out.push(b);
  } while (v !== 0);
  return out;
};
const ulebp1 = (value: number): number[] => uleb(value + 1);
const sleb = (value: number): number[] => {
  const out: number[] = [];
  let more = true;
  let v = value;
  while (more) {
    let b = v & 0x7f;
    v >>= 7;
    if ((v === 0 && (b & 0x40) === 0) || (v === -1 && (b & 0x40) !== 0))
      more = false;
    else b |= 0x80;
    out.push(b);
  }
  return out;
};

// Opcodes
const END_SEQUENCE = 0x00;
const ADVANCE_LINE = 0x02;
const START_LOCAL = 0x03;
const END_LOCAL = 0x05;
const SET_FILE = 0x09;
const EMIT_HERE = 0x0e; // special opcode: line += 0, address += 0, emit a position

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
      END_LOCAL,
      ...uleb(1), // register
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 10);
    expect(d.present).toBe(true);
    expect(d.malformed).toBe(false);
    expect(d.parameterNames).toEqual([5]);
    expect(d.positions).toEqual([{ address: 0, line: 1, sourceFileIdx: null }]);
    expect(d.locals).toHaveLength(1);
    expect(d.locals[0]).toMatchObject({
      register: 1,
      nameIdx: 10,
      typeIdx: 11,
      signatureIdx: -1,
      startAddress: 0,
      endAddress: 0,
      outOfRange: false,
    });
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

  it("marks malformed when a local is ended on an empty register", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      END_LOCAL,
      ...uleb(4),
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4);
    expect(d.malformed).toBe(true);
  });

  it("attaches a SET_FILE source index to subsequent positions", () => {
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
    expect(d.positions[0]).toEqual({ address: 0, line: 5, sourceFileIdx: 7 });
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
    expect(d.positions[0]!.line).toBe(-4);
    expect(d.malformed).toBe(true);
  });

  it("marks malformed when the stream ends without DBG_END_SEQUENCE", () => {
    const bytes = stream(...uleb(1), ...uleb(0), EMIT_HERE); // no END_SEQUENCE
    const d = decodeDebugInfo(bytes, 1, 4);
    expect(d.malformed).toBe(true);
    expect(d.positions).toHaveLength(1);
  });
});
