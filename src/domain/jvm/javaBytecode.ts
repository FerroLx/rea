/**
 * Instruction boundaries of a method's `code` array (JVMS §4.7.3, §6.5).
 *
 * HotSpot's type-checking verifier marks where each instruction starts before
 * it verifies a method, and rejects a `LocalVariableTable` scope whose start,
 * or whose end short of `code_length`, is not such a start ("Illegal local
 * variable table start_pc" / "... length"). That verifier is final from class
 * version 51; a version 50 class that fails it is re-verified by the old
 * inference verifier, which does not check scopes, so the rule binds only from
 * version 51. This module owns that decoding; it reads instruction lengths
 * only and never interprets operands beyond what a length needs. Where HotSpot
 * cannot decode the stream it rejects the method ("Bad instruction"), so such
 * a stream has no boundaries here either.
 */
import { err, ok, type Result } from "../result.js";

/** The first class version whose verification has no failover (JDK 7). */
export const SPLIT_VERIFIER_MAJOR_VERSION = 51;

/** Why the instruction stream does not decode into instructions. */
export type BytecodeDecodeError =
  | {
      /** No JVM instruction has this opcode (0xca and above included). */
      readonly kind: "illegal-opcode";
      readonly pc: number;
      readonly opcode: number;
    }
  | {
      /** The instruction at `pc` extends past `code_length`. */
      readonly kind: "truncated-instruction";
      readonly pc: number;
    }
  | {
      /** A `wide` prefix modifies an opcode `wide` cannot modify. */
      readonly kind: "illegal-wide-opcode";
      readonly pc: number;
    }
  | {
      /** A `tableswitch` with `high < low`, or a `lookupswitch` with `npairs < 0`. */
      readonly kind: "invalid-switch";
      readonly pc: number;
    }
  | {
      /**
       * `jsr`, `jsr_w`, `ret` or `wide ret` in a class of version 51 or later,
       * where the type-checking verifier has no rule for them (OpenJDK 21/25:
       * "Bad instruction" / "Bad wide instruction").
       */
      readonly kind: "subroutine-instruction";
      readonly pc: number;
      readonly opcode: number;
    };

/** The instruction starts of one decoded `code` array. */
export interface InstructionBoundaries {
  /** Whether an instruction (a `wide` prefix included) starts at `pc`. */
  readonly startsAt: (pc: number) => boolean;
}

const JSR = 0xa8;
const RET = 0xa9;
const JSR_W = 0xc9;
const TABLESWITCH = 0xaa;
const LOOKUPSWITCH = 0xab;
const WIDE = 0xc4;
const IINC = 0x84;

/**
 * Fixed lengths of opcodes 0x00 to 0xc9 (`jsr_w`), with 0 for the three whose
 * length depends on their operands. Every other opcode is illegal in a class
 * file, including `breakpoint` (0xca) and the implementation-reserved codes.
 */
const FIXED_LENGTHS: readonly number[] = (() => {
  const lengths = Array<number>(0xca).fill(1);
  const set = (from: number, to: number, length: number): void => {
    for (let opcode = from; opcode <= to; opcode += 1) lengths[opcode] = length;
  };
  set(0x10, 0x10, 2); // bipush
  set(0x11, 0x11, 3); // sipush
  set(0x12, 0x12, 2); // ldc
  set(0x13, 0x14, 3); // ldc_w, ldc2_w
  set(0x15, 0x19, 2); // iload .. aload
  set(0x36, 0x3a, 2); // istore .. astore
  set(IINC, IINC, 3);
  set(0x99, 0xa8, 3); // if<cond>, if_icmp<cond>, if_acmp<cond>, goto, jsr
  set(0xa9, 0xa9, 2); // ret
  set(TABLESWITCH, LOOKUPSWITCH, 0);
  set(0xb2, 0xb8, 3); // get/put field/static, invokevirtual/special/static
  set(0xb9, 0xba, 5); // invokeinterface, invokedynamic
  set(0xbb, 0xbb, 3); // new
  set(0xbc, 0xbc, 2); // newarray
  set(0xbd, 0xbd, 3); // anewarray
  set(0xc0, 0xc1, 3); // checkcast, instanceof
  set(WIDE, WIDE, 0);
  set(0xc5, 0xc5, 4); // multianewarray
  set(0xc6, 0xc7, 3); // ifnull, ifnonnull
  set(0xc8, 0xc9, 5); // goto_w, jsr_w
  return lengths;
})();

/** Opcodes `wide` may modify besides `iinc`: the local loads, stores and `ret`. */
const isWideLocalOpcode = (opcode: number): boolean =>
  (opcode >= 0x15 && opcode <= 0x19) ||
  (opcode >= 0x36 && opcode <= 0x3a) ||
  opcode === 0xa9;

const s4 = (code: Uint8Array, at: number): number =>
  (code[at]! << 24) |
  (code[at + 1]! << 16) |
  (code[at + 2]! << 8) |
  code[at + 3]!;

/**
 * The length of the variable-length instruction at `pc`, or an error. Switch
 * operands are 4-byte aligned from the start of the code array; the padding
 * bytes are skipped, not read.
 */
const variableLength = (
  code: Uint8Array,
  pc: number,
  opcode: number,
): Result<number, BytecodeDecodeError> => {
  if (opcode === WIDE) {
    if (pc + 1 >= code.length)
      return err({ kind: "truncated-instruction", pc });
    const modified = code[pc + 1]!;
    if (modified === IINC) return ok(6);
    return isWideLocalOpcode(modified)
      ? ok(4)
      : err({ kind: "illegal-wide-opcode", pc });
  }
  const operands = pc + 1 + ((4 - ((pc + 1) % 4)) % 4);
  const fixedOperands = opcode === TABLESWITCH ? 12 : 8;
  // HotSpot (`Bytecodes::special_length_at`) refuses a switch whose fixed
  // operands reach `code_length`, even one that would end exactly there (a
  // lookupswitch with no pairs); a well-formed tableswitch always has jump
  // offsets after them.
  if (operands + fixedOperands >= code.length)
    return err({ kind: "truncated-instruction", pc });
  if (opcode === TABLESWITCH) {
    const low = s4(code, operands + 4);
    const high = s4(code, operands + 8);
    if (high < low) return err({ kind: "invalid-switch", pc });
    return ok(operands - pc + 12 + (high - low + 1) * 4);
  }
  const pairs = s4(code, operands + 4);
  if (pairs < 0) return err({ kind: "invalid-switch", pc });
  return ok(operands - pc + 8 + pairs * 8);
};

/**
 * Decode a `code` array into its instruction starts in one pass. Work and the
 * returned bitmap are linear in `code.length` (at most 65,535 bytes per
 * method), so decoding every method of a class is bounded by the class-file
 * input budget. A stream that does not decode into whole instructions is an
 * error: its boundaries, and so any scope check against them, are unknown.
 * From `majorVersion` 51 the subroutine instructions are such an error too.
 */
export const decodeInstructionBoundaries = (
  code: Uint8Array,
  majorVersion: number,
): Result<InstructionBoundaries, BytecodeDecodeError> => {
  const noSubroutines = majorVersion >= SPLIT_VERIFIER_MAJOR_VERSION;
  const starts = new Uint8Array(code.length);
  let pc = 0;
  while (pc < code.length) {
    const opcode = code[pc]!;
    const fixed = FIXED_LENGTHS[opcode];
    if (fixed === undefined) return err({ kind: "illegal-opcode", pc, opcode });
    const subroutine =
      opcode === JSR ||
      opcode === RET ||
      opcode === JSR_W ||
      (opcode === WIDE && code[pc + 1] === RET);
    if (noSubroutines && subroutine)
      return err({ kind: "subroutine-instruction", pc, opcode });
    let length = fixed;
    if (length === 0) {
      const measured = variableLength(code, pc, opcode);
      if (!measured.ok) return measured;
      length = measured.value;
    }
    if (pc + length > code.length)
      return err({ kind: "truncated-instruction", pc });
    starts[pc] = 1;
    pc += length;
  }
  return ok({
    startsAt: (at) => at >= 0 && at < starts.length && starts[at] === 1,
  });
};
