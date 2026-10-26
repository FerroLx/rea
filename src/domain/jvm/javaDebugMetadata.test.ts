import { describe, expect, it } from "vitest";

import { jvmDebugClass } from "../../../tests/fixtures/jvmDebugClass.js";
import { CONSTANT_TAG, parseJavaClassFile } from "./javaClassFile.js";
import {
  projectDebugOutput,
  decodeClassDebugMetadata,
} from "./javaDebugMetadata.js";

class Blob {
  readonly parts: number[] = [];
  u1(v: number): this {
    this.parts.push(v & 0xff);
    return this;
  }
  u2(v: number): this {
    this.parts.push((v >> 8) & 0xff, v & 0xff);
    return this;
  }
  u4(v: number): this {
    this.parts.push(
      (v >>> 24) & 0xff,
      (v >> 16) & 0xff,
      (v >> 8) & 0xff,
      v & 0xff,
    );
    return this;
  }
  utf8(text: string): this {
    const bytes = [...text].map((c) => c.charCodeAt(0));
    return this.u2(bytes.length).raw(bytes);
  }
  raw(bytes: readonly number[]): this {
    this.parts.push(...bytes);
    return this;
  }
  attr(nameIndex: number, info: readonly number[]): this {
    return this.u2(nameIndex).u4(info.length).raw(info);
  }
  bytes(): Uint8Array {
    return Uint8Array.from(this.parts);
  }
}

/**
 * Shared pool (1-based): 1 "run", 2 "()V", 3 "Code", 4 "LineNumberTable",
 * 5 "LocalVariableTable", 6 "x", 7 "I", 8 "SourceFile", 9 "Example.java",
 * 10 "Example", 11 Class->10, 12 "SourceDebugExtension".
 */
const pool = (): Blob =>
  new Blob()
    .u4(0xcafebabe)
    .u2(0) // minor
    .u2(52) // major (Java 8)
    .u2(13)
    .u1(CONSTANT_TAG.utf8)
    .utf8("run")
    .u1(CONSTANT_TAG.utf8)
    .utf8("()V")
    .u1(CONSTANT_TAG.utf8)
    .utf8("Code")
    .u1(CONSTANT_TAG.utf8)
    .utf8("LineNumberTable")
    .u1(CONSTANT_TAG.utf8)
    .utf8("LocalVariableTable")
    .u1(CONSTANT_TAG.utf8)
    .utf8("x")
    .u1(CONSTANT_TAG.utf8)
    .utf8("I")
    .u1(CONSTANT_TAG.utf8)
    .utf8("SourceFile")
    .u1(CONSTANT_TAG.utf8)
    .utf8("Example.java")
    .u1(CONSTANT_TAG.utf8)
    .utf8("Example")
    .u1(CONSTANT_TAG.class)
    .u2(10)
    .u1(CONSTANT_TAG.utf8)
    .utf8("SourceDebugExtension");

const lineNumberTable = (entries: readonly [number, number][]): number[] => {
  const b = new Blob().u2(entries.length);
  for (const [pc, line] of entries) b.u2(pc).u2(line);
  return b.parts;
};

const localVariableTable = (
  entries: readonly { startPc: number; length: number; slot: number }[],
): number[] => {
  const b = new Blob().u2(entries.length);
  for (const e of entries) b.u2(e.startPc).u2(e.length).u2(6).u2(7).u2(e.slot);
  return b.parts;
};

const codeAttrInfo = (
  subAttrs: readonly number[],
  maxLocals = 1,
  code: readonly number[] = [0xb1], // return
): number[] =>
  new Blob()
    .u2(1) // max_stack
    .u2(maxLocals)
    .u4(code.length) // code_length
    .raw(code)
    .u2(0) // exception_table_length
    .raw(subAttrs).parts;

/** access_flags, this/super, no interfaces/fields, one `run()V` method, class attrs. */
const classWith = (methodAttrs: Blob, classAttrs: Blob): Uint8Array => {
  const b = pool()
    .u2(0x0021) // access_flags
    .u2(11) // this_class
    .u2(0) // super_class
    .u2(0) // interfaces
    .u2(0) // fields
    .u2(1) // methods_count
    .u2(0x0001)
    .u2(1)
    .u2(2); // method run ()V
  b.raw(methodAttrs.parts);
  b.raw(classAttrs.parts);
  return b.bytes();
};

const subAttrs = (count: number, body: Blob): Blob =>
  new Blob().u2(count).raw(body.parts);

describe("decodeClassDebugMetadata", () => {
  it("reports a fully debuggable method as present with decoded tables", () => {
    const code = codeAttrInfo(
      subAttrs(
        2,
        new Blob()
          .attr(4, lineNumberTable([[0, 5]]))
          .attr(5, localVariableTable([{ startPc: 0, length: 1, slot: 0 }])),
      ).parts,
    );
    const cls = parseJavaClassFile(
      classWith(
        new Blob().u2(1).attr(3, code),
        new Blob().u2(1).attr(8, [0, 9]),
      ),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const meta = decodeClassDebugMetadata(cls.value);
    expect(meta.sourceFile).toEqual({
      presence: "present",
      name: "Example.java",
    });
    const method = meta.methods[0]!;
    expect(method.state).toBe("present");
    expect(method.lineNumbers.entries).toEqual([
      { startPc: 0, lineNumber: 5, outOfRange: false },
    ]);
    expect(method.localVariables.entries[0]).toMatchObject({
      slot: 0,
      name: "x",
      descriptor: "I",
    });
  });

  it("merges multiple LineNumberTable attributes into one table (JVMS §4.7.12)", () => {
    // A Code attribute may carry the table split across several attributes;
    // the full table is their union, not just the first.
    const code = codeAttrInfo(
      subAttrs(
        2,
        new Blob().attr(4, lineNumberTable([[0, 1]])).attr(
          4,
          lineNumberTable([
            [0, 2],
            [0, 3],
          ]),
        ),
      ).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const method = decodeClassDebugMetadata(cls.value).methods[0]!;
    expect(method.lineNumbers.presence).toBe("present");
    expect(method.lineNumbers.declaredCount).toBe(3);
    expect(method.lineNumbers.entries).toEqual([
      { startPc: 0, lineNumber: 1, outOfRange: false },
      { startPc: 0, lineNumber: 2, outOfRange: false },
      { startPc: 0, lineNumber: 3, outOfRange: false },
    ]);
  });

  it("flags a local-variable scope that lies outside the method code length", () => {
    // codeAttrInfo sets code_length = 1.
    const code = codeAttrInfo(
      subAttrs(
        1,
        new Blob().attr(
          5,
          localVariableTable([
            { startPc: 0, length: 1, slot: 0 }, // within [0,1]
            { startPc: 0, length: 5, slot: 1 }, // extends past code_length
          ]),
        ),
      ).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const entries = decodeClassDebugMetadata(cls.value).methods[0]!
      .localVariables.entries;
    expect(entries[0]!.scope).toBe("aligned");
    expect(entries[1]!.scope).toBe("out-of-range");
    // HotSpot rejects the class ("Invalid length"): flagged and kept, malformed.
    const method = decodeClassDebugMetadata(cls.value).methods[0]!;
    expect(method.localVariables.presence).toBe("malformed");
    expect(method.state).toBe("malformed");
  });
});

describe("decodeClassDebugMetadata — states and edge cases", () => {
  it("surfaces reused local slots without collapsing the entries", () => {
    const code = codeAttrInfo(
      subAttrs(
        1,
        new Blob().attr(
          5,
          localVariableTable([
            { startPc: 0, length: 1, slot: 1 },
            { startPc: 0, length: 1, slot: 1 },
          ]),
        ),
      ).parts,
      2, // max_locals: slot 1 is in the frame
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const method = decodeClassDebugMetadata(cls.value).methods[0]!;
    expect(method.localVariables.entries).toHaveLength(2);
    expect(method.reusedSlots).toEqual([1]);
    expect(method.state).toBe("partial"); // locals present, line table absent
  });

  it("classifies a body with no debug tables as stripped", () => {
    const code = codeAttrInfo(subAttrs(0, new Blob()).parts);
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    expect(decodeClassDebugMetadata(cls.value).methods[0]!.state).toBe(
      "stripped",
    );
  });

  it("classifies a method with no Code attribute as not-applicable", () => {
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(0), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const method = decodeClassDebugMetadata(cls.value).methods[0]!;
    expect(method.hasCode).toBe(false);
    expect(method.state).toBe("not-applicable");
  });

  it("marks a line table malformed when it declares more entries than its bytes hold", () => {
    // declares 5 entries but supplies only one (4 bytes)
    const shortTable = new Blob().u2(5).u2(0).u2(7).parts;
    const code = codeAttrInfo(
      subAttrs(1, new Blob().attr(4, shortTable)).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const method = decodeClassDebugMetadata(cls.value).methods[0]!;
    expect(method.lineNumbers.presence).toBe("malformed");
    expect(method.lineNumbers.declaredCount).toBe(5);
    expect(method.lineNumbers.entries).toEqual([
      { startPc: 0, lineNumber: 7, outOfRange: false },
    ]); // partial fact kept
    expect(method.state).toBe("malformed");
  });

  it("keeps SourceDebugExtension opaque, reporting only presence and size", () => {
    const sde = [..."SMAP"].map((c) => c.charCodeAt(0));
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(0), new Blob().u2(1).attr(12, sde)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const meta = decodeClassDebugMetadata(cls.value);
    expect(meta.sourceDebugExtension).toEqual({
      presence: "present",
      byteLength: 4,
    });
  });

  it("reports an absent SourceFile rather than inventing one", () => {
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(0), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    expect(decodeClassDebugMetadata(cls.value).sourceFile).toEqual({
      presence: "absent",
      name: null,
    });
  });

  it("marks a SourceFile whose length is not exactly u2 as malformed", () => {
    // A 3-byte SourceFile attribute (JVMS fixes it at a single u2 index).
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(0), new Blob().u2(1).attr(8, [0, 9, 0])),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    expect(decodeClassDebugMetadata(cls.value).sourceFile).toEqual({
      presence: "malformed",
      name: null,
    });
  });
});

describe("projectDebugOutput", () => {
  it("sums declared table entries plus one per method, without decoding them", () => {
    const code = codeAttrInfo(
      subAttrs(
        2,
        new Blob()
          .attr(
            4,
            lineNumberTable([
              [0, 5],
              [1, 6],
              [2, 7],
            ]),
          )
          .attr(5, localVariableTable([{ startPc: 0, length: 1, slot: 0 }])),
      ).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    // 1 method + 3 line entries + 1 local entry
    expect(projectDebugOutput(cls.value, 1000).entries).toBe(5);
  });

  it("clamps a lying declared count to the bytes actually present", () => {
    // Declared count 1000, but only two 4-byte entries follow; capacity wins.
    const lyingTable = new Blob().u2(1000).u2(0).u2(5).u2(1).u2(6).parts;
    const code = codeAttrInfo(
      subAttrs(1, new Blob().attr(4, lyingTable)).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    expect(projectDebugOutput(cls.value, 1000).entries).toBe(1 + 2); // method + clamped entries
  });

  it("charges every reference to a shared name, as serialization would expand it", () => {
    const projected = (locals: number) => {
      const code = codeAttrInfo(
        subAttrs(
          1,
          new Blob().attr(
            5,
            localVariableTable(
              Array.from({ length: locals }, (_, slot) => ({
                startPc: 0,
                length: 1,
                slot,
              })),
            ),
          ),
        ).parts,
      );
      const cls = parseJavaClassFile(
        classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
      );
      if (!cls.ok) throw new Error("fixture must parse");
      return projectDebugOutput(cls.value, 1000).encodedBytes;
    };
    // Each extra entry re-references "x" and "I": overhead + "\"x\"" + "\"I\"".
    expect(projected(3) - projected(1)).toBe(2 * (160 + 3 + 3));
  });

  it("stops walking once a running total passes the caller's limit", () => {
    const code = codeAttrInfo(
      subAttrs(
        1,
        new Blob().attr(
          5,
          localVariableTable(
            Array.from({ length: 50 }, (_, slot) => ({
              startPc: 0,
              length: 1,
              slot,
            })),
          ),
        ),
      ).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const full = projectDebugOutput(cls.value, 1000);
    expect(full.entries).toBe(51);
    const stopped = projectDebugOutput(cls.value, 1000, {
      entries: Number.POSITIVE_INFINITY,
      encodedBytes: 5000,
    });
    // Over the limit, but well short of the full walk.
    expect(stopped.encodedBytes).toBeGreaterThan(5000);
    expect(stopped.encodedBytes).toBeLessThan(full.encodedBytes);
  });

  it("stops framing at the retained-attribute budget", () => {
    const code = codeAttrInfo(
      subAttrs(
        3,
        new Blob()
          .attr(4, lineNumberTable([]))
          .attr(4, lineNumberTable([]))
          .attr(4, lineNumberTable([])),
      ).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    expect(projectDebugOutput(cls.value, 2).attributeBudgetExceeded).toBe(true);
    expect(projectDebugOutput(cls.value, 3).attributeBudgetExceeded).toBe(
      false,
    );
  });
});

describe("Code sub-attribute recovery", () => {
  it("keeps a table framed before a malformed sibling and marks unreached tables unread", () => {
    const code = codeAttrInfo(
      new Blob()
        .u2(2)
        .attr(4, lineNumberTable([[0, 5]]))
        // A sibling whose declared length runs past the Code attribute.
        .u2(5)
        .u4(9999).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const method = decodeClassDebugMetadata(cls.value).methods[0]!;
    expect(method.state).toBe("malformed");
    expect(method.lineNumbers.presence).toBe("present");
    expect(method.lineNumbers.entries).toEqual([
      { startPc: 0, lineNumber: 5, outOfRange: false },
    ]);
    expect(method.localVariables.presence).toBe("unread");
    expect(method.localVariableTypes.presence).toBe("unread");
  });
});

const decodeOnly = (methodAttrs: Blob, classAttrs = new Blob().u2(0)) => {
  const cls = parseJavaClassFile(classWith(methodAttrs, classAttrs));
  if (!cls.ok) throw new Error(`fixture did not frame: ${cls.error.kind}`);
  return decodeClassDebugMetadata(cls.value);
};

describe("decodeClassDebugMetadata — readiness without locals", () => {
  const linesOnly = (maxLocals: number) =>
    codeAttrInfo(
      subAttrs(1, new Blob().attr(4, lineNumberTable([[0, 3]]))).parts,
      maxLocals,
    );

  it("treats line numbers with max_locals 0 as present: no local can be named", () => {
    const method = decodeOnly(new Blob().u2(1).attr(3, linesOnly(0)))
      .methods[0]!;
    expect(method.maxLocals).toBe(0);
    expect(method.localVariables.presence).toBe("absent");
    expect(method.state).toBe("present");
  });

  it("keeps line numbers without a LocalVariableTable partial when locals exist", () => {
    const method = decodeOnly(new Blob().u2(1).attr(3, linesOnly(1)))
      .methods[0]!;
    expect(method.maxLocals).toBe(1);
    expect(method.state).toBe("partial");
  });

  it("classifies a max_locals 0 body with no line numbers as stripped", () => {
    const code = codeAttrInfo(subAttrs(0, new Blob()).parts, 0);
    const method = decodeOnly(new Blob().u2(1).attr(3, code)).methods[0]!;
    expect(method.state).toBe("stripped");
  });

  it("reports max_locals as unknown without a Code attribute", () => {
    expect(decodeOnly(new Blob().u2(0)).methods[0]!.maxLocals).toBeNull();
  });
});

describe("decodeClassDebugMetadata — constant references", () => {
  const lvtWith = (nameIndex: number, descriptorIndex: number): number[] =>
    new Blob().u2(1).u2(0).u2(1).u2(nameIndex).u2(descriptorIndex).u2(0).parts;

  it("marks a SourceFile naming a non-Utf8 constant malformed", () => {
    // Pool index 11 is a CONSTANT_Class, not a CONSTANT_Utf8.
    const metadata = decodeOnly(
      new Blob().u2(0),
      new Blob().u2(1).attr(8, [0, 11]),
    );
    expect(metadata.sourceFile).toEqual({ presence: "malformed", name: null });
  });

  it.each([
    ["a non-Utf8 name", 11, 7],
    ["a zero descriptor index", 6, 0],
  ])(
    "marks a LocalVariableTable entry with %s malformed and keeps it",
    (_case, nameIndex, descriptorIndex) => {
      const code = codeAttrInfo(
        subAttrs(1, new Blob().attr(5, lvtWith(nameIndex, descriptorIndex)))
          .parts,
      );
      const method = decodeOnly(new Blob().u2(1).attr(3, code)).methods[0]!;
      expect(method.localVariables.presence).toBe("malformed");
      expect(method.localVariables.entries).toHaveLength(1);
      expect(method.state).toBe("malformed");
    },
  );
});

describe("decodeClassDebugMetadata — line-number ranges", () => {
  it("flags a line entry whose start_pc is not an index into the code array", () => {
    const code = codeAttrInfo(
      subAttrs(
        1,
        new Blob().attr(
          4,
          lineNumberTable([
            [0, 1],
            [99, 2],
          ]),
        ),
      ).parts,
    );
    const method = decodeOnly(new Blob().u2(1).attr(3, code)).methods[0]!;
    expect(method.lineNumbers.entries).toEqual([
      { startPc: 0, lineNumber: 1, outOfRange: false },
      { startPc: 99, lineNumber: 2, outOfRange: true },
    ]);
    // HotSpot rejects the class ("Invalid pc in LineNumberTable").
    expect(method.lineNumbers.presence).toBe("malformed");
    expect(method.state).toBe("malformed");
  });
});

describe("decodeClassDebugMetadata — repeated single attributes", () => {
  it("reports a method with two Code attributes as malformed without choosing a body", () => {
    const stripped = codeAttrInfo(subAttrs(0, new Blob()).parts);
    const withLines = codeAttrInfo(
      subAttrs(1, new Blob().attr(4, lineNumberTable([[0, 1]]))).parts,
    );
    const method = decodeOnly(
      new Blob().u2(2).attr(3, stripped).attr(3, withLines),
    ).methods[0]!;
    expect(method.state).toBe("malformed");
    expect(method.hasCode).toBe(true);
    expect(method.maxLocals).toBeNull();
    expect(method.lineNumbers.presence).toBe("unread");
    expect(method.localVariables.presence).toBe("unread");
  });

  it("reports two SourceFile attributes as malformed, not the first name", () => {
    const metadata = decodeOnly(
      new Blob().u2(0),
      new Blob().u2(2).attr(8, [0, 9]).attr(8, [0, 10]),
    );
    expect(metadata.sourceFile).toEqual({ presence: "malformed", name: null });
  });

  it("reports two SourceDebugExtension attributes as malformed", () => {
    const metadata = decodeOnly(
      new Blob().u2(0),
      new Blob().u2(2).attr(12, [0x41]).attr(12, [0x42, 0x43]),
    );
    expect(metadata.sourceDebugExtension).toEqual({
      presence: "malformed",
      byteLength: 0,
    });
  });
});

describe("decodeClassDebugMetadata — Code attribute length", () => {
  it("refuses trailing bytes after a Code attribute's sub-attributes", () => {
    const code = codeAttrInfo([
      ...subAttrs(1, new Blob().attr(4, lineNumberTable([[0, 1]]))).parts,
      0xde,
      0xad,
    ]);
    const method = decodeOnly(new Blob().u2(1).attr(3, code)).methods[0]!;
    expect(method.state).toBe("malformed");
    // The framed table is kept; tables the stray bytes may hide are unknown.
    expect(method.lineNumbers.presence).toBe("present");
    expect(method.localVariables.presence).toBe("unread");
  });
});

describe("decodeClassDebugMetadata — HotSpot load checks", () => {
  // HotSpot: "Invalid method Code length".
  it.each([
    ["0", []],
    ["65536", new Array<number>(65_536).fill(0)],
  ])("marks a method whose code_length is %s malformed", (_label, code) => {
    const body = codeAttrInfo(subAttrs(0, new Blob()).parts, 1, code);
    const method = decodeOnly(new Blob().u2(1).attr(3, body)).methods[0]!;
    expect(method.state).toBe("malformed");
    expect(method.lineNumbers.presence).toBe("unread");
  });

  it("keeps a 65535-byte body readable", () => {
    const body = codeAttrInfo(
      subAttrs(0, new Blob()).parts,
      1,
      new Array<number>(65_535).fill(0),
    );
    expect(decodeOnly(new Blob().u2(1).attr(3, body)).methods[0]!.state).toBe(
      "stripped",
    );
  });

  // HotSpot: "Invalid code attribute name index"; an unnamed sibling cannot
  // be ruled out as debug metadata, so the absent tables are unknown.
  it("marks a method with an unnamed Code sub-attribute malformed", () => {
    const body = codeAttrInfo(new Blob().u2(1).attr(0, []).parts);
    const method = decodeOnly(new Blob().u2(1).attr(3, body)).methods[0]!;
    expect(method.state).toBe("malformed");
    expect(method.lineNumbers.presence).toBe("unread");
    expect(method.localVariables.presence).toBe("unread");
  });

  const lvt = (nameIndex: number, descriptorIndex: number): number[] =>
    new Blob().u2(1).u2(0).u2(1).u2(nameIndex).u2(descriptorIndex).u2(0).parts;

  // HotSpot: "Illegal field signature" / "Illegal field name". Pool 6 is `x`
  // (no field descriptor), 9 is `Example.java` (a `.` is illegal in a name).
  it.each([
    ["a descriptor that is not a field descriptor", 6, 6],
    ["a name containing a dot", 9, 7],
  ])(
    "marks a LocalVariableTable entry with %s malformed",
    (_label, nameIndex, descriptorIndex) => {
      const body = codeAttrInfo(
        subAttrs(1, new Blob().attr(5, lvt(nameIndex, descriptorIndex))).parts,
      );
      const method = decodeOnly(new Blob().u2(1).attr(3, body)).methods[0]!;
      expect(method.localVariables.presence).toBe("malformed");
      expect(method.localVariables.entries).toHaveLength(1);
      expect(method.state).toBe("malformed");
    },
  );

  const decodeFixture = (bytes: Uint8Array) => {
    const cls = parseJavaClassFile(bytes);
    if (!cls.ok) throw new Error(`fixture did not frame: ${cls.error.kind}`);
    return decodeClassDebugMetadata(cls.value).methods[0]!;
  };

  // Before version 49 HotSpot ignores LocalVariableTypeTable as an unknown
  // attribute and loads the class, so no defect in it changes the state.
  it.each([
    ["an out-of-frame slot", { slot: 2, descriptor: "I" }],
    ["a non-Utf8 name", { slot: 0, descriptor: "I", nameIndex: 10 }],
  ] as const)(
    "keeps a version 48 method present despite a type-table row with %s",
    (_label, row) => {
      const method = decodeFixture(
        jvmDebugClass({ majorVersion: 48, typedLocals: [row] }),
      );
      expect(method.localVariableTypes.presence).toBe("malformed");
      expect(method.state).toBe("present");
    },
  );

  it("marks the same type-table row malformed from version 49", () => {
    const method = decodeFixture(
      jvmDebugClass({
        majorVersion: 49,
        typedLocals: [{ slot: 0, descriptor: "I", nameIndex: 10 }],
      }),
    );
    expect(method.state).toBe("malformed");
  });
});

describe("decodeClassDebugMetadata — local scopes and instruction boundaries", () => {
  const decodeFixture = (bytes: Uint8Array) => {
    const cls = parseJavaClassFile(bytes);
    if (!cls.ok) throw new Error(`fixture did not frame: ${cls.error.kind}`);
    return decodeClassDebugMetadata(cls.value).methods[0]!;
  };
  // bipush 5 (pc 0-1); pop (pc 2); return (pc 3): pc 1 is an operand byte.
  const BIPUSH_POP_RETURN = [0x10, 0x05, 0x57, 0xb1];
  const local = (startPc: number, length: number) =>
    ({ slot: 0, descriptor: "J", startPc, length }) as const;

  // HotSpot 21/25 (version 51+): "Illegal local variable table start_pc 1"
  // and "Illegal local variable table length 1".
  it.each([
    ["start", local(1, 3)],
    ["end", local(0, 1)],
    ["empty scope's start", local(1, 0)],
  ])(
    "reports a scope whose %s falls inside an instruction as misaligned from version 51",
    (_label, row) => {
      for (const majorVersion of [51, 52, 69]) {
        const method = decodeFixture(
          jvmDebugClass({
            majorVersion,
            code: BIPUSH_POP_RETURN,
            locals: [row],
          }),
        );
        expect(method.localVariables.entries[0]!.scope).toBe("misaligned");
        expect(method.localVariables.presence).toBe("malformed");
        expect(method.state).toBe("malformed");
      }
    },
  );

  it("accepts scopes that start and end on instructions or at code_length", () => {
    const method = decodeFixture(
      jvmDebugClass({
        code: BIPUSH_POP_RETURN,
        locals: [local(0, 4)],
        typedLocals: [{ slot: 0, descriptor: "I", startPc: 2, length: 1 }],
      }),
    );
    expect(method.localVariables.entries[0]!.scope).toBe("aligned");
    expect(method.localVariableTypes.entries[0]!.scope).toBe("aligned");
    expect(method.state).toBe("present");
  });

  it("rejects a misaligned type-table row when the method has local-variable rows", () => {
    // HotSpot merges the type table into a non-empty LocalVariableTable, so a
    // misaligned row is rejected: through its misaligned twin or as unmatched.
    const method = decodeFixture(
      jvmDebugClass({
        code: BIPUSH_POP_RETURN,
        locals: [local(0, 4)],
        typedLocals: [{ slot: 0, descriptor: "I", startPc: 1, length: 3 }],
      }),
    );
    expect(method.localVariableTypes.entries[0]!.scope).toBe("misaligned");
    expect(method.localVariableTypes.presence).toBe("malformed");
    expect(method.state).toBe("malformed");
  });

  // OpenJDK 21/25 load and verify these: with no LocalVariableTable row the
  // type table is never merged, so the verifier never sees its scopes.
  it.each([
    ["absent", null],
    ["present with no rows", []],
  ] as const)(
    "keeps a misaligned type-table row valid when the LocalVariableTable is %s",
    (_label, locals) => {
      const method = decodeFixture(
        jvmDebugClass({
          code: BIPUSH_POP_RETURN,
          locals,
          typedLocals: [{ slot: 0, descriptor: "I", startPc: 1, length: 3 }],
        }),
      );
      expect(method.localVariableTypes.entries[0]!.scope).toBe("misaligned");
      expect(method.localVariableTypes.presence).toBe("present");
      expect(method.state).not.toBe("malformed");
    },
  );

  it("still rejects an out-of-range type-table row without LocalVariableTable rows", () => {
    // HotSpot's parser: "Invalid start_pc 87 in LocalVariableTypeTable".
    const method = decodeFixture(
      jvmDebugClass({
        code: BIPUSH_POP_RETURN,
        locals: null,
        typedLocals: [{ slot: 0, descriptor: "I", startPc: 87, length: 1 }],
      }),
    );
    expect(method.localVariableTypes.entries[0]!.scope).toBe("out-of-range");
    expect(method.state).toBe("malformed");
  });

  it("treats subroutine instructions as undecodable from version 51", () => {
    // jsr +4; return; astore_1; ret 1: HotSpot "Bad instruction: a8" at 51+.
    const code = [0xa8, 0, 4, 0xb1, 0x4c, 0xa9, 1];
    const at = (majorVersion: number) =>
      decodeFixture(
        jvmDebugClass({ majorVersion, code, locals: [local(0, code.length)] }),
      );
    expect(at(52).localVariables.entries[0]!.scope).toBe("unknown");
    expect(at(52).state).toBe("malformed");
    expect(at(50).localVariables.entries[0]!.scope).toBe("in-code");
    expect(at(50).state).toBe("present");
  });

  // Version 50 fails over to the inference verifier, which does not check
  // scopes; version 49 never uses the type-checking verifier.
  it.each([49, 50])(
    "does not check boundaries in a version %i class",
    (majorVersion) => {
      const method = decodeFixture(
        jvmDebugClass({
          majorVersion,
          code: BIPUSH_POP_RETURN,
          locals: [local(1, 3)],
        }),
      );
      expect(method.localVariables.entries[0]!.scope).toBe("in-code");
      expect(method.state).toBe("present");
    },
  );

  it("leaves line numbers inside an instruction valid, as HotSpot does", () => {
    const method = decodeFixture(
      jvmDebugClass({
        code: BIPUSH_POP_RETURN,
        linePc: 1,
        locals: [local(0, 4)],
      }),
    );
    expect(method.lineNumbers.presence).toBe("present");
    expect(method.state).toBe("present");
  });

  it("reports an in-code scope over an undecodable stream as unknown, never present", () => {
    // 0xcb is no JVM instruction; HotSpot's verifier rejects the method.
    const method = decodeFixture(
      jvmDebugClass({ code: [0x00, 0xcb, 0xb1], locals: [local(0, 3)] }),
    );
    expect(method.localVariables.entries[0]!.scope).toBe("unknown");
    expect(method.localVariables.presence).toBe("malformed");
    expect(method.state).toBe("malformed");
  });
});
