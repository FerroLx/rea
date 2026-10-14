/**
 * Decode a DEX `debug_info_item` (Dalvik Executable format) — the state machine
 * that encodes a method's source positions (line numbers) and local-variable
 * scopes, plus its parameter names. This is the DEX analogue of the JVM
 * LineNumberTable / LocalVariableTable, but it is an event stream, not a table.
 *
 * Facts are preserved on partial failure: a stream that runs short, drives a
 * line non-positive, or closes/restarts an empty register is marked `malformed`
 * while keeping every position and local recovered before the fault. Names are
 * left as string-pool indices here (`-1` = NO_INDEX); resolution is layered on
 * top. Addresses are 16-bit code units, bounded by the method's `insns_size`.
 */
import { DexCursor } from "./dexFile.js";

const DBG_END_SEQUENCE = 0x00;
const DBG_ADVANCE_PC = 0x01;
const DBG_ADVANCE_LINE = 0x02;
const DBG_START_LOCAL = 0x03;
const DBG_START_LOCAL_EXTENDED = 0x04;
const DBG_END_LOCAL = 0x05;
const DBG_RESTART_LOCAL = 0x06;
const DBG_SET_PROLOGUE_END = 0x07;
const DBG_SET_EPILOGUE_BEGIN = 0x08;
const DBG_SET_FILE = 0x09;
const DBG_FIRST_SPECIAL = 0x0a;
const DBG_LINE_BASE = -4;
const DBG_LINE_RANGE = 15;

/** One source position; `sourceFileIdx` is set only when DBG_SET_FILE redirected it. */
export interface DexLinePosition {
  readonly address: number;
  readonly line: number;
  readonly sourceFileIdx: number | null;
}

/** A local-variable scope. Name/type/signature are string-pool indices (`-1` = none). */
export interface DexLocalEntry {
  readonly register: number;
  readonly nameIdx: number;
  readonly typeIdx: number;
  readonly signatureIdx: number;
  readonly startAddress: number;
  readonly endAddress: number;
  /** The scope lies outside `[0, insns_size)` in code units. */
  readonly outOfRange: boolean;
}

/** The decoded debug info for one method. */
export interface DexMethodDebug {
  readonly present: boolean;
  readonly malformed: boolean;
  readonly lineStart: number;
  /** Parameter name indices in declaration order (`-1` = unnamed/stripped). */
  readonly parameterNames: readonly number[];
  readonly positions: readonly DexLinePosition[];
  readonly locals: readonly DexLocalEntry[];
  readonly setFileEvents: number;
}

/** A method with no `debug_info_item` (debug_info_off == 0). */
export const absentMethodDebug = (): DexMethodDebug => ({
  present: false,
  malformed: false,
  lineStart: 0,
  parameterNames: [],
  positions: [],
  locals: [],
  setFileEvents: 0,
});

interface LiveLocal {
  readonly nameIdx: number;
  readonly typeIdx: number;
  readonly signatureIdx: number;
  readonly startAddress: number;
}

/** `true` keeps the walk going; `false` records a fault and stops it. */
type Step = boolean;

/** Mutable walk over one `debug_info_item`; one handler per opcode group. */
class DebugInfoWalk {
  private readonly cursor: DexCursor;
  private readonly positions: DexLinePosition[] = [];
  private readonly locals: DexLocalEntry[] = [];
  private readonly live = new Map<number, LiveLocal>();
  private readonly lastByRegister = new Map<number, LiveLocal>();
  private readonly parameterNames: number[] = [];
  private line = 0;
  private lineStart = 0;
  private address = 0;
  private setFileEvents = 0;
  private currentFileIdx: number | null = null;
  private malformed = false;

  constructor(
    bytes: Uint8Array,
    offset: number,
    private readonly insnsSize: number,
  ) {
    this.cursor = new DexCursor(bytes, offset);
  }

  private pushLocal(register: number, local: LiveLocal, end: number): void {
    this.locals.push({
      register,
      nameIdx: local.nameIdx,
      typeIdx: local.typeIdx,
      signatureIdx: local.signatureIdx,
      startAddress: local.startAddress,
      endAddress: end,
      outOfRange: local.startAddress >= this.insnsSize || end > this.insnsSize,
    });
  }

  private header(): Step {
    const lineStart = this.cursor.uleb128();
    if (!lineStart.ok) return false;
    this.line = lineStart.value;
    this.lineStart = lineStart.value;
    const paramsSize = this.cursor.uleb128();
    if (!paramsSize.ok) return false;
    for (let i = 0; i < paramsSize.value; i += 1) {
      const nameIdx = this.cursor.uleb128p1();
      if (!nameIdx.ok) return false;
      this.parameterNames.push(nameIdx.value);
    }
    return true;
  }

  private startLocal(extended: boolean): Step {
    const reg = this.cursor.uleb128();
    const nameIdx = this.cursor.uleb128p1();
    const typeIdx = this.cursor.uleb128p1();
    let signatureIdx = -1;
    if (extended) {
      const sig = this.cursor.uleb128p1();
      if (!sig.ok) return false;
      signatureIdx = sig.value;
    }
    if (!reg.ok || !nameIdx.ok || !typeIdx.ok) return false;
    const existing = this.live.get(reg.value);
    if (existing) this.pushLocal(reg.value, existing, this.address); // implicit end
    const local: LiveLocal = {
      nameIdx: nameIdx.value,
      typeIdx: typeIdx.value,
      signatureIdx,
      startAddress: this.address,
    };
    this.live.set(reg.value, local);
    this.lastByRegister.set(reg.value, local);
    return true;
  }

  private endLocal(): Step {
    const reg = this.cursor.uleb128();
    if (!reg.ok) return false;
    const existing = this.live.get(reg.value);
    if (!existing) return false; // end of an empty register
    this.pushLocal(reg.value, existing, this.address);
    this.live.delete(reg.value);
    return true;
  }

  private restartLocal(): Step {
    const reg = this.cursor.uleb128();
    if (!reg.ok) return false;
    const previous = this.lastByRegister.get(reg.value);
    if (this.live.has(reg.value) || previous === undefined) return false;
    const local: LiveLocal = { ...previous, startAddress: this.address };
    this.live.set(reg.value, local);
    this.lastByRegister.set(reg.value, local);
    return true;
  }

  private setFile(): Step {
    const nameIdx = this.cursor.uleb128p1();
    if (!nameIdx.ok) return false;
    this.currentFileIdx = nameIdx.value === -1 ? null : nameIdx.value;
    this.setFileEvents += 1;
    return true;
  }

  private special(op: number): void {
    const adjusted = op - DBG_FIRST_SPECIAL;
    this.line += DBG_LINE_BASE + (adjusted % DBG_LINE_RANGE);
    this.address += Math.floor(adjusted / DBG_LINE_RANGE);
    this.positions.push({
      address: this.address,
      line: this.line,
      sourceFileIdx: this.currentFileIdx,
    });
    if (this.line <= 0) this.malformed = true;
  }

  /** Dispatch one non-terminal opcode; returns false to stop on a fault. */
  private dispatch(op: number): Step {
    if (op === DBG_ADVANCE_PC) {
      const d = this.cursor.uleb128();
      if (!d.ok) return false;
      this.address += d.value;
      return true;
    }
    if (op === DBG_ADVANCE_LINE) {
      const d = this.cursor.sleb128();
      if (!d.ok) return false;
      this.line += d.value;
      return true;
    }
    if (op === DBG_START_LOCAL) return this.startLocal(false);
    if (op === DBG_START_LOCAL_EXTENDED) return this.startLocal(true);
    if (op === DBG_END_LOCAL) return this.endLocal();
    if (op === DBG_RESTART_LOCAL) return this.restartLocal();
    if (op === DBG_SET_FILE) return this.setFile();
    if (op === DBG_SET_PROLOGUE_END || op === DBG_SET_EPILOGUE_BEGIN)
      return true;
    this.special(op);
    return true;
  }

  private result(malformed: boolean): DexMethodDebug {
    return {
      present: true,
      malformed,
      lineStart: this.lineStart,
      parameterNames: this.parameterNames,
      positions: this.positions,
      locals: this.locals,
      setFileEvents: this.setFileEvents,
    };
  }

  private closeLiveAtEnd(): void {
    for (const [reg, local] of this.live)
      this.pushLocal(reg, local, this.insnsSize);
    this.live.clear();
  }

  run(): DexMethodDebug {
    if (!this.header()) return this.result(true);
    for (let guard = 0; guard < 2_000_000; guard += 1) {
      const op = this.cursor.u1();
      if (!op.ok) break;
      if (op.value === DBG_END_SEQUENCE) {
        this.closeLiveAtEnd();
        return this.result(this.malformed || this.line <= 0);
      }
      if (!this.dispatch(op.value)) break;
    }
    // Ran off the end without DBG_END_SEQUENCE, or a fault above.
    this.closeLiveAtEnd();
    return this.result(true);
  }
}

/**
 * Walk the `debug_info_item` at `offset`. `insnsSize` (code units) bounds local
 * scopes and flags out-of-range entries. Never throws; a structural or semantic
 * fault sets `malformed` and stops, preserving what was recovered.
 */
export const decodeDebugInfo = (
  bytes: Uint8Array,
  offset: number,
  insnsSize: number,
): DexMethodDebug => {
  if (offset <= 0 || offset >= bytes.length)
    return { ...absentMethodDebug(), present: true, malformed: true };
  return new DebugInfoWalk(bytes, offset, insnsSize).run();
};
