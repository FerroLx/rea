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
              message: expect.stringContaining("not valid UTF-8") as string,
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
  "charges only the JAR members it decompresses to the ZIP budget over CLI and MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-jvm-zip-limit-");
    const { client, call } = await connectLocalToolsMcp();
    // A member declaring 300 MiB is past the 256 MiB minimum decompression
    // budget of a small archive. JarFile reads Example.class whatever an
    // unrelated member declares, and REA only decompresses the manifest and
    // the selected class.
    const big = {
      name: Buffer.from("big.bin"),
      bytes: Buffer.from("x"),
      declaredSize: 300 * 1024 * 1024,
    };
    const unrelated = join(root, "unrelated-large.jar");
    await writeFile(
      unrelated,
      storedZip([
        { name: Buffer.from("Example.class"), bytes: jvmDebugClass() },
        big,
      ]),
    );
    const read = await inspectBoth(cli, call, {
      path: unrelated,
      entry: "Example.class",
    });
    if (!read.ok) throw new Error(JSON.stringify(read.error));
    expect(read.evidence).toMatchObject({
      normalized_result: { selected_entry: { entry: "Example.class" } },
    });
    // The selected member itself declaring that much is refused before it is
    // decompressed, with the bound it exceeds.
    const selected = join(root, "selected-large.jar");
    await writeFile(
      selected,
      storedZip([{ ...big, name: Buffer.from("Example.class") }]),
    );
    const outcome = await inspectBoth(cli, call, {
      path: selected,
      entry: "Example.class",
    });
    expect(outcome).toMatchObject({
      ok: false,
      error: {
        code: "resource_constraint",
        details: {
          resource: "capacity",
          reported_limits: { max_decompressed_bytes: 256 * 1024 * 1024 },
        },
      },
    });
    expect(
      (outcome as { error: { details: { reported_limits: object } } }).error
        .details.reported_limits,
    ).not.toHaveProperty("max_input_bytes");
    await client.ping();
  },
  30000,
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
