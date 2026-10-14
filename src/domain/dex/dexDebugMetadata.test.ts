import { describe, expect, it } from "vitest";

import { assembleClassDetail, summarizeDex } from "./dexDebugMetadata.js";
import { DEX_NO_INDEX, parseDexFile } from "./dexFile.js";

/**
 * A growing little-endian DEX builder. Sections are appended in dependency
 * order, each section's absolute offset is recorded, and the fixed header is
 * patched last. Produces one class `Lcom/example/Foo;` (source `Foo.java`) with
 * one method `run` descriptor `(I)V` whose code_item carries a debug_info_item
 * with one parameter name, one line position, and one local `x` of type `I`.
 */
class DexBuilder {
  private readonly b: number[] = [];
  u1(v: number): this {
    this.b.push(v & 0xff);
    return this;
  }
  u2(v: number): this {
    this.b.push(v & 0xff, (v >> 8) & 0xff);
    return this;
  }
  u4(v: number): this {
    this.b.push(v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff);
    return this;
  }
  uleb(v: number): this {
    let n = v >>> 0;
    do {
      let x = n & 0x7f;
      n >>>= 7;
      if (n !== 0) x |= 0x80;
      this.b.push(x);
    } while (n !== 0);
    return this;
  }
  ulebp1(v: number): this {
    return this.uleb(v + 1);
  }
  ascii(text: string): this {
    for (const c of text) this.b.push(c.charCodeAt(0));
    return this;
  }
  at(): number {
    return this.b.length;
  }
  setU4(at: number, v: number): void {
    this.b[at] = v & 0xff;
    this.b[at + 1] = (v >> 8) & 0xff;
    this.b[at + 2] = (v >> 16) & 0xff;
    this.b[at + 3] = (v >>> 24) & 0xff;
  }
  bytes(): Uint8Array {
    return Uint8Array.from(this.b);
  }
}

const STRINGS = ["Foo.java", "run", "x", "Lcom/example/Foo;", "I", "V"];

const buildDex = (): Uint8Array => {
  const d = new DexBuilder();
  for (let i = 0; i < 112; i += 1) d.u1(0); // header placeholder

  // string_data_items
  const stringDataOff = STRINGS.map((s) => {
    const off = d.at();
    d.uleb(s.length).ascii(s).u1(0);
    return off;
  });
  // string_ids
  const stringIdsOff = d.at();
  for (const off of stringDataOff) d.u4(off);
  // type_ids: type0->str3, type1->str4, type2->str5
  const typeIdsOff = d.at();
  for (const s of [3, 4, 5]) d.u4(s);
  // type_list for (I): size 1, type_idx 1
  const typeListOff = d.at();
  d.u4(1).u2(1);
  // proto_ids: one proto (shorty 0, return type 2=V, params type_list)
  const protoIdsOff = d.at();
  d.u4(0).u4(2).u4(typeListOff);
  // method_ids: class_idx 0, proto_idx 0, name_idx 1 ("run")
  const methodIdsOff = d.at();
  d.u2(0).u2(0).u4(1);
  // debug_info_item — static run(int): the one param "x" is an implicit local
  // seeded at register 0; no explicit DBG_START_LOCAL needed.
  const debugInfoOff = d.at();
  d.uleb(10).uleb(1).ulebp1(2); // line_start 10, 1 param, name "x"
  d.u1(0x0e).u1(0x00); // special emit (position at line 10), END_SEQUENCE
  // code_item: registers 1, ins 1, outs 0, tries 0, debug_info_off, insns 4
  const codeOff = d.at();
  d.u2(1).u2(1).u2(0).u2(0).u4(debugInfoOff).u4(4);
  for (let i = 0; i < 4; i += 1) d.u2(0); // insns
  // class_data: 0 static,0 instance,1 direct,0 virtual; method diff 0,
  // access 0x9 (public|static), code_off.
  const classDataOff = d.at();
  d.uleb(0).uleb(0).uleb(1).uleb(0).uleb(0).uleb(0x9).uleb(codeOff);
  // class_def: class_idx 0, access, superclass NO_INDEX, interfaces 0,
  // source_file_idx 0 ("Foo.java"), annotations 0, class_data_off, static 0
  const classDefsOff = d.at();
  d.u4(0).u4(1).u4(DEX_NO_INDEX).u4(0).u4(0).u4(0).u4(classDataOff).u4(0);

  // patch header
  d.setU4(0, 0x0a786564); // "dex\n" little-endian
  d.setU4(4, 0x00353330); // "035\0"
  d.setU4(32, d.at()); // file_size
  d.setU4(36, 0x70); // header_size
  d.setU4(40, 0x12345678); // endian_tag
  d.setU4(56, STRINGS.length);
  d.setU4(60, stringIdsOff);
  d.setU4(64, 3); // type_ids_size
  d.setU4(68, typeIdsOff);
  d.setU4(72, 1); // proto_ids_size
  d.setU4(76, protoIdsOff);
  d.setU4(88, 1); // method_ids_size
  d.setU4(92, methodIdsOff);
  d.setU4(96, 1); // class_defs_size
  d.setU4(100, classDefsOff);
  return d.bytes();
};

describe("dexDebugMetadata assembly", () => {
  it("summarizes a debuggable dex with resolved tallies and readiness", () => {
    const parsed = parseDexFile(buildDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const summary = summarizeDex(parsed.value, buildDex());
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

  it("resolves full per-method detail for a selected class", () => {
    const parsed = parseDexFile(buildDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const detail = assembleClassDetail(
      parsed.value,
      buildDex(),
      "Lcom/example/Foo;",
    );
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

  it("returns null for a class descriptor not present", () => {
    const parsed = parseDexFile(buildDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(assembleClassDetail(parsed.value, buildDex(), "LNope;")).toBeNull();
  });
});
