/** A local-variable row of the fixture method's debug tables. */
export interface JvmFixtureLocal {
  readonly slot: number;
  /** `I` (one slot) or `J` (a wide local occupying `slot` and `slot + 1`). */
  readonly descriptor: "I" | "J";
  readonly startPc?: number;
  readonly length?: number;
  /** Pool index of the row's name (default 6, `x`); 10 is a CONSTANT_Class. */
  readonly nameIndex?: number;
}

/**
 * Build a class `Example` with one static method `run(J)V` whose Code
 * attribute (by default code_length 1, `return`; `code` replaces the bytecode)
 * carries a LineNumberTable, the given LocalVariableTable rows and,
 * optionally, LocalVariableTypeTable rows.
 * `trailingBytes` appends bytes after the class-file structure; `majorVersion`
 * sets the class-file version (default 52).
 */
export const jvmDebugClass = (
  options: {
    readonly maxLocals?: number;
    readonly locals?: readonly JvmFixtureLocal[];
    readonly typedLocals?: readonly JvmFixtureLocal[];
    readonly linePc?: number;
    readonly trailingBytes?: number;
    readonly majorVersion?: number;
    readonly code?: readonly number[];
  } = {},
): Buffer => {
  const out: number[] = [];
  const u1 = (value: number): void => {
    out.push(value & 0xff);
  };
  const u2 = (value: number): void => {
    out.push((value >> 8) & 0xff, value & 0xff);
  };
  const u4 = (value: number): void => {
    out.push(
      (value >>> 24) & 0xff,
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff,
    );
  };
  // 1 run, 2 (J)V, 3 Code, 4 LineNumberTable, 5 LocalVariableTable, 6 x,
  // 7 I, 8 J, 9 Example, 10 Class->9, 11 LocalVariableTypeTable,
  // 12 java/lang/Object, 13 Class->12.
  const utf8 = [
    "run",
    "(J)V",
    "Code",
    "LineNumberTable",
    "LocalVariableTable",
    "x",
    "I",
    "J",
    "Example",
  ];
  u4(0xcafebabe);
  u2(0);
  u2(options.majorVersion ?? 52);
  u2(14);
  for (const text of utf8) {
    u1(1);
    u2(text.length);
    for (const c of text) u1(c.charCodeAt(0));
  }
  u1(7);
  u2(9);
  u1(1);
  u2("LocalVariableTypeTable".length);
  for (const c of "LocalVariableTypeTable") u1(c.charCodeAt(0));
  u1(1);
  u2("java/lang/Object".length);
  for (const c of "java/lang/Object") u1(c.charCodeAt(0));
  u1(7);
  u2(12);
  u2(0x0021); // access_flags
  u2(10); // this_class
  u2(13); // super_class
  u2(0); // interfaces
  u2(0); // fields
  u2(1); // methods
  u2(0x0008); // static
  u2(1);
  u2(2);
  u2(1); // one attribute: Code
  const table = (
    nameIndex: number,
    rows: readonly JvmFixtureLocal[],
  ): number[] => {
    const body: number[] = [];
    const b2 = (value: number): void => {
      body.push((value >> 8) & 0xff, value & 0xff);
    };
    b2(rows.length);
    for (const row of rows) {
      b2(row.startPc ?? 0);
      b2(row.length ?? 1);
      b2(row.nameIndex ?? 6);
      b2(row.descriptor === "J" ? 8 : 7);
      b2(row.slot);
    }
    return [
      (nameIndex >> 8) & 0xff,
      nameIndex & 0xff,
      0,
      0,
      (body.length >> 8) & 0xff,
      body.length & 0xff,
      ...body,
    ];
  };
  const linePc = options.linePc ?? 0;
  const subAttributes = [
    // LineNumberTable: one row, pc -> line 1.
    0,
    4,
    0,
    0,
    0,
    6,
    0,
    1,
    (linePc >> 8) & 0xff,
    linePc & 0xff,
    0,
    1,
    ...table(5, options.locals ?? [{ slot: 0, descriptor: "J" }]),
    ...(options.typedLocals === undefined
      ? []
      : table(11, options.typedLocals)),
  ];
  const bytecode = options.code ?? [0xb1]; // return
  const code = [
    0,
    1, // max_stack
    ((options.maxLocals ?? 2) >> 8) & 0xff,
    (options.maxLocals ?? 2) & 0xff,
    (bytecode.length >>> 24) & 0xff,
    (bytecode.length >> 16) & 0xff,
    (bytecode.length >> 8) & 0xff,
    bytecode.length & 0xff, // code_length
    ...bytecode,
    0,
    0, // exception_table_length
    0,
    options.typedLocals === undefined ? 2 : 3,
    ...subAttributes,
  ];
  u2(3);
  u4(code.length);
  out.push(...code);
  u2(0); // class attributes
  return Buffer.concat([
    Buffer.from(out),
    Buffer.alloc(options.trailingBytes ?? 0),
  ]);
};
