import { createHash } from "node:crypto";
import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";

import { toolContract } from "../../src/contracts/toolContracts.js";
import { jvmDebugClass } from "../fixtures/jvmDebugClass.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { parseMcpToolError } from "../fixtures/mcpToolError.js";
import { storedZip } from "../fixtures/storedZip.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest, type TestCli } from "../support/cli/cliFixture.js";

const TOOL = "inspect_jvm_debug_metadata";

/** Run one selection over CLI and MCP and require the same outcome from both. */
const inspectBoth = async (
  cli: TestCli,
  call: Awaited<ReturnType<typeof connectLocalToolsMcp>>["call"],
  input: { readonly path: string; readonly entry?: string },
): Promise<
  | { readonly ok: true; readonly evidence: unknown }
  | { readonly ok: false; readonly error: unknown }
> => {
  const viaCli = await cli.run({
    arguments: [
      "inspect-jvm-debug-metadata",
      input.path,
      ...(input.entry === undefined ? [] : ["--entry", input.entry]),
      "--json",
    ],
  });
  const viaMcp = await call(TOOL, input);
  if (viaCli.exitCode !== 0) {
    expect(parseMcpToolError(viaMcp).error).toMatchObject(
      viaCli.json as object,
    );
    return { ok: false, error: viaCli.json };
  }
  const evidence = toolContract(TOOL).outputSchema.parse(viaCli.json);
  expect(viaMcp.isError, JSON.stringify(viaMcp)).not.toBe(true);
  expect(viaMcp.structuredContent).toEqual(evidence);
  return { ok: true, evidence };
};

cliTest(
  "refuses a class file with bytes after its structure over CLI and MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-jvm-trailing-");
    const path = join(root, "Example.class");
    await writeFile(path, jvmDebugClass({ trailingBytes: 3 }));
    const { client, call } = await connectLocalToolsMcp();
    const outcome = await inspectBoth(cli, call, { path });
    expect(outcome).toMatchObject({
      ok: false,
      error: {
        code: "invalid_request",
        details: {
          issues: [
            {
              path: ["path"],
              reason: "invalid_format",
              message: expect.stringContaining("3 extra bytes") as string,
            },
          ],
        },
      },
    });
    await client.ping();
  },
  30000,
);

cliTest(
  "reports a local outside max_locals as malformed over CLI and MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-jvm-slots-");
    const { client, call } = await connectLocalToolsMcp();
    // run(J)V with max_locals 2: the long parameter fills slots 0 and 1.
    const cases = [
      {
        name: "valid",
        options: {},
        state: "present",
        lvt: "present",
        lvtt: "absent",
      },
      // HotSpot: "Invalid index 1 in LocalVariableTable" (a J's second slot).
      {
        name: "wide-second-slot",
        options: { locals: [{ slot: 1, descriptor: "J" }] },
        state: "malformed",
        lvt: "malformed",
        lvtt: "absent",
      },
      // HotSpot: "Invalid index 2 in LocalVariableTypeTable".
      {
        name: "typed-slot",
        options: { typedLocals: [{ slot: 2, descriptor: "I" }] },
        state: "malformed",
        lvt: "present",
        lvtt: "malformed",
      },
      // Before version 49 HotSpot ignores LocalVariableTypeTable and loads
      // these classes: the table is still judged by the same rules, but it
      // never changes the method's state.
      {
        name: "typed-slot-v48",
        options: {
          majorVersion: 48,
          typedLocals: [{ slot: 2, descriptor: "I" }],
        },
        state: "present",
        lvt: "present",
        lvtt: "malformed",
      },
      {
        name: "typed-name-v48",
        options: {
          majorVersion: 48,
          typedLocals: [{ slot: 0, descriptor: "I", nameIndex: 10 }],
        },
        state: "present",
        lvt: "present",
        lvtt: "malformed",
      },
    ] as const;
    for (const { name, options, state, lvt, lvtt } of cases) {
      const path = join(root, `${name}.class`);
      await writeFile(path, jvmDebugClass(options));
      const outcome = await inspectBoth(cli, call, { path });
      if (!outcome.ok) throw new Error(JSON.stringify(outcome.error));
      expect(outcome.evidence).toMatchObject({
        normalized_result: {
          methods: [
            {
              state,
              max_locals: 2,
              local_variable_table: { presence: lvt },
              local_variable_type_table: { presence: lvtt },
            },
          ],
        },
      });
    }
    await client.ping();
  },
  30000,
);

cliTest(
  "reports debug positions outside the code as malformed over CLI and MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-jvm-pcs-");
    const { client, call } = await connectLocalToolsMcp();
    // code_length is 1. HotSpot: "Invalid pc in LineNumberTable" and
    // "Invalid length 2 in LocalVariableTable".
    const cases = [
      {
        name: "line-pc",
        options: { linePc: 1 },
        line: "malformed",
        lvt: "present",
      },
      {
        name: "scope-length",
        options: { locals: [{ slot: 0, descriptor: "J", length: 2 }] },
        line: "present",
        lvt: "malformed",
      },
    ] as const;
    for (const { name, options, line, lvt } of cases) {
      const path = join(root, `${name}.class`);
      await writeFile(path, jvmDebugClass(options));
      const outcome = await inspectBoth(cli, call, { path });
      if (!outcome.ok) throw new Error(JSON.stringify(outcome.error));
      expect(outcome.evidence).toMatchObject({
        normalized_result: {
          methods: [
            {
              state: "malformed",
              line_number_table: { presence: line },
              local_variable_table: { presence: lvt },
            },
          ],
        },
      });
    }
    await client.ping();
  },
  30000,
);

cliTest(
  "reports a local scope inside an instruction as malformed from version 51 over CLI and MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-jvm-boundaries-");
    const { client, call } = await connectLocalToolsMcp();
    // bipush 5; pop; return: a scope starting at pc 1 starts in bipush's
    // operand. HotSpot 21/25 verify a version 51+ class and refuse it
    // ("Illegal local variable table start_pc 1"); a version 50 class fails
    // over to the old verifier and loads. A line number at pc 1 is accepted.
    const code = [0x10, 0x05, 0x57, 0xb1];
    const cases = [
      { majorVersion: 52, state: "malformed", scope: "misaligned" },
      { majorVersion: 50, state: "present", scope: "in-code" },
    ] as const;
    for (const { majorVersion, state, scope } of cases) {
      const path = join(root, `v${String(majorVersion)}.class`);
      await writeFile(
        path,
        jvmDebugClass({
          majorVersion,
          code,
          linePc: 1,
          locals: [{ slot: 0, descriptor: "J", startPc: 1, length: 3 }],
        }),
      );
      const outcome = await inspectBoth(cli, call, { path });
      if (!outcome.ok) throw new Error(JSON.stringify(outcome.error));
      expect(outcome.evidence).toMatchObject({
        normalized_result: {
          methods: [
            {
              state,
              line_number_table: { presence: "present" },
              local_variable_table: {
                presence: state,
                entries: [{ start_pc: 1, length: 3, scope }],
              },
            },
          ],
        },
      });
    }
    await client.ping();
  },
  30000,
);

cliTest(
  "judges type-table scopes and subroutines as HotSpot verifies them over CLI and MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-jvm-type-scopes-");
    const { client, call } = await connectLocalToolsMcp();
    const bipushPopReturn = [0x10, 0x05, 0x57, 0xb1];
    const typed = [
      { slot: 0, descriptor: "I", startPc: 1, length: 3 },
    ] as const;
    // OpenJDK 21/25 load and verify a misaligned LocalVariableTypeTable row
    // when the method has no LocalVariableTable row: the type table is only
    // merged into, and verified with, a non-empty LocalVariableTable.
    const cases = [
      {
        name: "type-only",
        options: { code: bipushPopReturn, locals: null, typedLocals: typed },
        state: "partial",
        lvtt: "present",
        scope: "misaligned",
      },
      {
        name: "type-with-empty-locals",
        options: { code: bipushPopReturn, locals: [], typedLocals: typed },
        state: "present",
        lvtt: "present",
        scope: "misaligned",
      },
      // jsr +4; return; astore_1; ret 1 at version 52: "Bad instruction: a8".
      {
        name: "subroutine",
        options: {
          code: [0xa8, 0, 4, 0xb1, 0x4c, 0xa9, 1],
          locals: null,
          typedLocals: [{ slot: 0, descriptor: "I", startPc: 0, length: 7 }],
        },
        state: "malformed",
        lvtt: "malformed",
        scope: "unknown",
      },
    ] as const;
    for (const { name, options, state, lvtt, scope } of cases) {
      const path = join(root, `${name}.class`);
      await writeFile(path, jvmDebugClass(options));
      const outcome = await inspectBoth(cli, call, { path });
      if (!outcome.ok) throw new Error(JSON.stringify(outcome.error));
      expect(outcome.evidence).toMatchObject({
        normalized_result: {
          methods: [
            {
              state,
              local_variable_type_table: {
                presence: lvtt,
                entries: [{ scope }],
              },
            },
          ],
        },
      });
    }
    await client.ping();
  },
  30000,
);

cliTest(
  "names unflagged JAR members as the JDK does (UTF-8) over CLI and MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-jvm-names-");
    const { client, call } = await connectLocalToolsMcp();
    const ascii = (text: string): Uint8Array => Buffer.from(text, "latin1");
    // Unflagged UTF-8 bytes C3 A9: JarFile.getEntry("é.class") finds it.
    const utf8 = join(root, "utf8.jar");
    await writeFile(
      utf8,
      storedZip([
        { name: Buffer.from("é.class", "utf8"), bytes: jvmDebugClass() },
      ]),
    );
    const found = await inspectBoth(cli, call, {
      path: utf8,
      entry: "é.class",
    });
    if (!found.ok) throw new Error(JSON.stringify(found.error));
    expect(found.evidence).toMatchObject({
      normalized_result: { selected_entry: { entry: "é.class" } },
    });
    // The name was decoded as UTF-8, so no CP437 fallback note applies.
    expect(JSON.stringify(found.evidence)).not.toContain("CP437");
    // An unflagged CP437 0x82 ("é") is invalid UTF-8: JarFile refuses the
    // whole archive ("invalid CEN header (bad entry name or comment)"), so
    // the valid sibling is not selectable either.
    const cp437 = join(root, "cp437.jar");
    await writeFile(
      cp437,
      storedZip([
        { name: ascii("Example.class"), bytes: jvmDebugClass() },
        { name: Uint8Array.of(0x82, ...ascii(".txt")), bytes: ascii("x") },
      ]),
    );
    const refused = await inspectBoth(cli, call, {
      path: cp437,
      entry: "Example.class",
    });
    expect(refused).toMatchObject({
      ok: false,
      error: {
        code: "invalid_request",
        details: {
          issues: [
            {
              reason: "invalid_format",
              message: expect.stringContaining(
                "invalid CEN header (bad entry name or comment)",
              ) as string,
            },
          ],
        },
      },
    });
    await client.ping();
  },
  30000,
);

cliTest(
  "reads JAR members by their bytes, whatever they declare, over CLI and MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-jvm-zip-limit-");
    const { client, call } = await connectLocalToolsMcp();
    // A member declaring 300 MiB is past the 256 MiB minimum decompression
    // budget of a small archive. OpenJDK 21/25 JarFile reads Example.class
    // whatever an unrelated member declares, and reads the class's own bytes
    // whatever it declares itself: the budget charges bytes REA produces.
    const declaresMore = 300 * 1024 * 1024;
    const example = {
      name: Buffer.from("Example.class"),
      bytes: jvmDebugClass(),
    };
    const archives = {
      unrelated: storedZip([
        example,
        {
          name: Buffer.from("big.bin"),
          bytes: Buffer.from("x"),
          declaredSize: declaresMore,
        },
      ]),
      selected: storedZip([{ ...example, declaredSize: declaresMore }]),
    };
    for (const [name, bytes] of Object.entries(archives)) {
      const path = join(root, `${name}-declares-more.jar`);
      await writeFile(path, bytes);
      const read = await inspectBoth(cli, call, {
        path,
        entry: "Example.class",
      });
      if (!read.ok) throw new Error(JSON.stringify(read.error));
      expect(read.evidence).toMatchObject({
        normalized_result: {
          selected_entry: {
            entry: "Example.class",
            sha256: createHash("sha256").update(example.bytes).digest("hex"),
          },
        },
      });
    }
    await client.ping();
  },
  30000,
);

cliTest(
  "opens a JAR wherever OpenJDK 25 JarFile opens it, and only there, over CLI and MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-jvm-end-");
    const { client, call } = await connectLocalToolsMcp();
    const members = [
      {
        name: Buffer.from("META-INF/MANIFEST.MF"),
        bytes: Buffer.from("Manifest-Version: 1.0\r\n\r\n"),
      },
      { name: Buffer.from("Example.class"), bytes: jvmDebugClass() },
      { name: Buffer.from("other.txt"), bytes: Buffer.from("x") },
    ];
    const opens = {
      // ZipFile.initCEN recounts the records when ENDTOT is too small.
      "endtot-1-of-3": storedZip(members, { endTotal: 1 }),
      // A zip64 END and locator whose END holds real values, as Commons
      // Compress writes with Zip64Mode.Always.
      "zip64-end-without-markers": storedZip(members, { zip64End: {} }),
      // The JDK ignores END's disk numbers.
      "end-disk-1": storedZip(members, { endDisk: 1 }),
      // Only the central directory's facts matter: a local-header-only
      // encryption flag and a wrong CRC are never read.
      "local-flag-and-crc": storedZip([
        { ...members[1]!, localFlags: 1, crc: 1 },
      ]),
    };
    for (const [name, bytes] of Object.entries(opens)) {
      const path = join(root, `${name}.jar`);
      await writeFile(path, bytes);
      const read = await inspectBoth(cli, call, {
        path,
        entry: "Example.class",
      });
      if (!read.ok) throw new Error(`${name}: ${JSON.stringify(read.error)}`);
    }
    const refused = {
      "end-offset-past-start": [
        storedZip(members, { directoryOffsetDelta: 10 }),
        "java.util.zip.ZipException: invalid END header (bad central directory offset)",
      ],
      "end-comment-past-eof": [
        storedZip(members, { commentLength: 5 }),
        "java.io.EOFException",
      ],
      "endtot-past-cenlen": [
        storedZip(members, { endTotal: 4 }),
        "java.util.zip.ZipException: invalid END header (total entries count too large)",
      ],
    } as const;
    for (const [name, [bytes, refusal]] of Object.entries(refused)) {
      const path = join(root, `${name}.jar`);
      await writeFile(path, bytes);
      expect(
        await inspectBoth(cli, call, { path, entry: "Example.class" }),
        name,
      ).toMatchObject({
        ok: false,
        error: {
          code: "invalid_request",
          details: {
            issues: [
              {
                path: ["path"],
                reason: "invalid_format",
                message: expect.stringContaining(refusal) as string,
              },
            ],
          },
        },
      });
    }
    await client.ping();
  },
  60000,
);

cliTest(
  "refuses a JAR holding any encrypted record, as JarFile does, over CLI and MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-jvm-encrypted-");
    const { client, call } = await connectLocalToolsMcp();
    // OpenJDK 21/25: new JarFile(...) throws "invalid CEN header (encrypted
    // entry)" when any central-directory record sets flag bit 0, so neither
    // the requested class nor any other member is readable.
    const manifest = Buffer.from("Manifest-Version: 1.0\r\n\r\n");
    for (const encrypted of ["other.txt", "META-INF/MANIFEST.MF"]) {
      const path = join(root, `${encrypted.replaceAll("/", "-")}.jar`);
      await writeFile(
        path,
        storedZip(
          [
            { name: "META-INF/MANIFEST.MF", bytes: manifest },
            { name: "Example.class", bytes: jvmDebugClass() },
            { name: "other.txt", bytes: Buffer.from("x") },
          ].map(({ name, bytes }) => ({
            name: Buffer.from(name),
            bytes,
            ...(name === encrypted ? { flags: 0x0001 } : {}),
          })),
        ),
      );
      const outcome = await inspectBoth(cli, call, {
        path,
        entry: "Example.class",
      });
      expect(outcome).toMatchObject({
        ok: false,
        error: {
          code: "invalid_request",
          details: {
            issues: [
              {
                path: ["path"],
                reason: "invalid_format",
                message: expect.stringContaining(
                  "invalid CEN header (encrypted entry)",
                ) as string,
              },
            ],
          },
        },
      });
    }
    await client.ping();
  },
  30000,
);

cliTest(
  "refuses a JAR whose central directory JarFile rejects over CLI and MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-jvm-cen-");
    const { client, call } = await connectLocalToolsMcp();
    const example = {
      name: Buffer.from("Example.class"),
      bytes: jvmDebugClass(),
    };
    const other = { name: Buffer.from("other.txt"), bytes: Buffer.from("x") };
    const extraField = (tag: number, size: number): Buffer => {
      const field = Buffer.alloc(4 + size);
      field.writeUInt16LE(tag, 0);
      field.writeUInt16LE(size, 2);
      return field;
    };
    // Each refused by OpenJDK 25 `new JarFile(...)` with the quoted message.
    const cases = [
      {
        name: "unrelated-method-9",
        members: [example, { ...other, method: 9 }],
        message: "bad compression method: 9",
      },
      {
        name: "selected-method-9",
        members: [{ ...example, method: 9 }],
        message: "bad compression method: 9",
      },
      {
        // 46 + 9-byte name + 65,491-byte extra field > 0xFFFF.
        name: "header-too-big",
        members: [
          example,
          { ...other, centralExtra: extraField(0xcafe, 65_487) },
        ],
        message: "bad header size",
      },
      {
        name: "extra-field-overrun",
        members: [
          example,
          { ...other, centralExtra: extraField(0xcafe, 9).subarray(0, 6) },
        ],
        message: "invalid extra data field size for tag: 0xcafe",
      },
      {
        name: "zip64-escape-without-extra",
        members: [example, { ...other, declaredCompressedSize: 0xffffffff }],
        message: "invalid zip64 extra len size",
      },
      {
        name: "zip64-block-not-escaped",
        members: [example, { ...other, centralExtra: extraField(0x0001, 8) }],
        message: "invalid zip64 extra data field size",
      },
    ] as const;
    for (const { name, members, message } of cases) {
      const path = join(root, `${name}.jar`);
      await writeFile(path, storedZip(members));
      const outcome = await inspectBoth(cli, call, {
        path,
        entry: "Example.class",
      });
      expect(outcome, name).toMatchObject({
        ok: false,
        error: {
          code: "invalid_request",
          details: {
            issues: [
              {
                path: ["path"],
                reason: "invalid_format",
                message: expect.stringContaining(message) as string,
              },
            ],
          },
        },
      });
    }
    // The same archive with a central directory that does not end at its
    // last record: "invalid CEN header (bad header size)".
    const trailing = storedZip([example]);
    const end = trailing.length - 22;
    const directorySize = trailing.readUInt32LE(end + 12);
    const padded = Buffer.concat([
      trailing.subarray(0, end),
      Buffer.alloc(4),
      trailing.subarray(end),
    ]);
    padded.writeUInt32LE(directorySize + 4, end + 4 + 12);
    const paddedPath = join(root, "directory-trailing-bytes.jar");
    await writeFile(paddedPath, padded);
    expect(
      await inspectBoth(cli, call, {
        path: paddedPath,
        entry: "Example.class",
      }),
    ).toMatchObject({
      ok: false,
      error: {
        details: {
          issues: [
            {
              reason: "invalid_format",
              message: expect.stringContaining("bad header size") as string,
            },
          ],
        },
      },
    });
    await client.ping();
  },
  60000,
);

cliTest.skipIf(process.platform === "win32")(
  "reads the file a symlink-relative path names, not its lexical rewrite",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-jvm-caller-path-");
    await mkdir(join(root, "real", "inner"), { recursive: true });
    await symlink(join(root, "real", "inner"), join(root, "link"));
    // POSIX resolves `link/..` after following the link: real/Example.class.
    const bytes = jvmDebugClass();
    await writeFile(join(root, "real", "Example.class"), bytes);
    const result = await cli.run({
      arguments: [
        "inspect-jvm-debug-metadata",
        `${root}/link/../Example.class`,
        "--json",
      ],
    });
    expect(result.exitCode, result.stdout).toBe(0);
    const evidence = toolContract(TOOL).outputSchema.parse(result.json);
    expect(evidence.subject).toMatchObject({
      local_path: `${root}/link/../Example.class`,
      digest: {
        sha256: createHash("sha256").update(bytes).digest("hex"),
      },
    });
  },
  30000,
);
