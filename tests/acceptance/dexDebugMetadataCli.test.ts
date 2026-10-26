import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { INSPECT_DEX_DEBUG_METADATA_CONTRACT } from "../../src/contracts/dex/dexToolContracts.js";
import { DEX_LIMITS } from "../../src/dex/DexFileRelease.js";
import { refusalMark } from "../../src/dex/dexDisplayText.js";
import {
  debuggableDex,
  SYMLINK_ATTRIBUTES,
  zipArchive,
} from "../fixtures/dexFile.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest, type TestCli } from "../support/cli/cliFixture.js";

const TOOL = INSPECT_DEX_DEBUG_METADATA_CONTRACT.name;
const CLASS = "Lcom/example/Foo;";

const evidenceOf = (value: unknown) =>
  INSPECT_DEX_DEBUG_METADATA_CONTRACT.outputSchema.parse(value);

/** The marks a note puts beside a member `entry` would refuse (owning formatter). */
const LINK_MARK = refusalMark({
  occurrences: 1,
  symlink: true,
  encrypted: false,
});
const ENCRYPTED_MARK = refusalMark({
  occurrences: 1,
  symlink: false,
  encrypted: true,
});
const TWICE_MARK = refusalMark({
  occurrences: 2,
  symlink: false,
  encrypted: false,
});

cliTest(
  "summarizes, selects a member and drills into a class through the public CLI",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-cli-");
    const apk = join(root, "app.apk");
    await writeFile(
      apk,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        { name: "classes2.dex", bytes: debuggableDex() },
      ]),
    );

    const summary = await cli.run({
      arguments: ["inspect-dex-debug-metadata", apk, "--json"],
    });
    expect(summary.exitCode, summary.stderr).toBe(0);
    const summaryResult = evidenceOf(summary.json).normalized_result;
    if (summaryResult.mode !== "summary") throw new Error("Expected summary");
    expect(summaryResult.container).toBe("apk");
    expect(summaryResult.members.map((member) => member.entry)).toEqual([
      "classes.dex",
      "classes2.dex",
    ]);
    expect(summaryResult.members[0]?.summary.readiness).toBe("present");

    const entry = await cli.run({
      arguments: [
        "inspect-dex-debug-metadata",
        apk,
        "--entry",
        "classes2.dex",
        "--class-descriptor",
        CLASS,
        "--json",
      ],
    });
    expect(entry.exitCode, entry.stderr).toBe(0);
    const detail = evidenceOf(entry.json).normalized_result;
    if (detail.mode !== "class-detail") throw new Error("Expected detail");
    expect(detail.class_detail).toMatchObject({
      entry: "classes2.dex",
      descriptor: CLASS,
      source_file: "Foo.java",
      methods: [
        {
          name: "run",
          descriptor: "(I)V",
          state: "present",
          parameter_names: ["x"],
        },
      ],
    });

    const ambiguous = await cli.run({
      arguments: [
        "inspect-dex-debug-metadata",
        apk,
        "--class-descriptor",
        CLASS,
        "--json",
      ],
    });
    expect(ambiguous.exitCode).toBe(1);
    expect(ambiguous.json).toMatchObject({ code: "invalid_request" });
  },
);

cliTest(
  "selects a ./-stored member by either spelling and reports its stored name over CLI and MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-dot-");
    const apk = join(root, "dot.apk");
    await writeFile(
      apk,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        { name: "./classes2.dex", bytes: debuggableDex() },
      ]),
    );
    const { call } = await connectLocalToolsMcp();
    for (const entry of ["classes2.dex", "./classes2.dex"])
      for (const classDescriptor of [undefined, CLASS]) {
        const viaCli = await cli.run({
          arguments: [
            "inspect-dex-debug-metadata",
            apk,
            "--entry",
            entry,
            ...(classDescriptor === undefined
              ? []
              : ["--class-descriptor", classDescriptor]),
            "--json",
          ],
        });
        expect(viaCli.exitCode, viaCli.stdout + viaCli.stderr).toBe(0);
        const result = evidenceOf(viaCli.json).normalized_result;
        expect(
          result.mode === "summary"
            ? result.members.map((member) => member.entry)
            : [result.class_detail.entry],
        ).toEqual(["./classes2.dex"]);
        const viaMcp = await call(TOOL, {
          path: apk,
          entry,
          ...(classDescriptor === undefined
            ? {}
            : { class_descriptor: classDescriptor }),
        });
        expect(viaMcp.isError, JSON.stringify(viaMcp.content)).not.toBe(true);
        expect(evidenceOf(viaMcp.structuredContent).normalized_result).toEqual(
          result,
        );
      }
  },
);

cliTest(
  "prefers the exactly stored spelling, names spellings when none is exact, and refuses a ZIP directory as unavailable",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-spell-");
    const apk = join(root, "both.apk");
    await writeFile(
      apk,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        { name: "classes2.dex", bytes: debuggableDex() },
        { name: "./classes2.dex", bytes: debuggableDex(5) },
      ]),
    );
    const select = (path: string, entry: string) =>
      cli.run({
        arguments: [
          "inspect-dex-debug-metadata",
          path,
          "--entry",
          entry,
          "--json",
        ],
      });
    for (const [entry, positions] of [
      ["classes2.dex", 1],
      ["./classes2.dex", 6],
    ] as const) {
      const selected = await select(apk, entry);
      expect(selected.exitCode, selected.stdout + selected.stderr).toBe(0);
      const result = evidenceOf(selected.json).normalized_result;
      if (result.mode !== "summary") throw new Error("Expected summary");
      expect(result.members).toMatchObject([
        { entry, summary: { line_positions: positions } },
      ]);
    }
    const neither = await select(apk, "././classes2.dex");
    expect(neither.exitCode).toBe(1);
    expect(neither.json).toMatchObject({ code: "invalid_request" });
    expect(JSON.stringify(neither.json)).toContain(
      String.raw`stored as \"classes2.dex\", \"./classes2.dex\"`,
    );

    const directory = join(root, "dir.apk");
    await writeFile(
      directory,
      await zipArchive([{ name: "classes.dex/", bytes: new Uint8Array() }]),
    );
    const refused = await select(directory, "classes.dex/");
    expect(refused.exitCode).toBe(1);
    // Refused as unavailable (not a summary that omits the member), naming it.
    expect(refused.json).toMatchObject({ code: "unsupported_target" });
    expect(refused.json).not.toHaveProperty("normalized_result");
    expect(JSON.stringify(refused.json)).toContain("classes.dex/");
  },
);

const inspect = (cli: TestCli, path: string, entry?: string) =>
  cli.run({
    arguments: [
      "inspect-dex-debug-metadata",
      path,
      ...(entry === undefined ? [] : ["--entry", entry]),
      "--json",
    ],
  });

/** Every refusal message and limitation the CLI printed, joined. */
const prose = (json: unknown): string => JSON.stringify(json);

cliTest(
  "refuses a symbolic-link-mode DEX member as unavailable, never as absent or a shorter run",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-link-");
    const link = {
      bytes: debuggableDex(),
      externalFileAttributes: SYMLINK_ATTRIBUTES,
    };
    // ART ignores the unix mode and loads classes2.dex, so classes3.dex too.
    const inRun = join(root, "in-run.apk");
    await writeFile(
      inRun,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        { name: "classes2.dex", ...link },
        { name: "classes3.dex", bytes: debuggableDex() },
      ]),
    );
    const auto = await inspect(cli, inRun);
    expect(auto.exitCode, auto.stdout).toBe(1);
    // The whole run is refused, naming the link member: never a summary of
    // classes.dex alone, which would read classes2.dex as absent.
    expect(auto.json).toMatchObject({ code: "unsupported_target" });
    expect(auto.json).not.toHaveProperty("normalized_result");
    expect(prose(auto.json)).toContain("(classes2.dex)");
    for (const entry of ["classes2.dex", "./classes2.dex"]) {
      const selected = await inspect(cli, inRun, entry);
      expect(selected.exitCode, selected.stdout).toBe(1);
      expect(selected.json).toMatchObject({ code: "unsupported_target" });
      expect(selected.json).not.toHaveProperty("normalized_result");
      expect(prose(selected.json)).toContain("classes2.dex");
    }

    const onlyLink = join(root, "only-link.apk");
    await writeFile(
      onlyLink,
      await zipArchive([{ name: "classes.dex", ...link }]),
    );
    const lone = await inspect(cli, onlyLink);
    expect(lone.json).toMatchObject({ code: "unsupported_target" });
    expect(prose(lone.json)).not.toContain("holds no classes.dex");

    // ART looks up the exact stored name, which is the link, not the ./ twin.
    const twin = join(root, "twin.apk");
    await writeFile(
      twin,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        { name: "classes2.dex", ...link },
        { name: "./classes2.dex", bytes: debuggableDex(5) },
      ]),
    );
    const exact = await inspect(cli, twin, "classes2.dex");
    expect(exact.json).toMatchObject({ code: "unsupported_target" });
    const dotted = await inspect(cli, twin, "./classes2.dex");
    expect(dotted.exitCode, dotted.stdout).toBe(0);
    const result = evidenceOf(dotted.json).normalized_result;
    if (result.mode !== "summary") throw new Error("Expected summary");
    expect(result.members).toMatchObject([
      { entry: "./classes2.dex", summary: { line_positions: 6 } },
    ]);
    const neither = await inspect(cli, twin, "././classes2.dex");
    expect(neither.json).toMatchObject({ code: "invalid_request" });
    // Both stored spellings are named, the link one with its refusal mark.
    expect(prose(neither.json)).toContain(
      JSON.stringify(`"classes2.dex"${LINK_MARK}, "./classes2.dex"`).slice(
        1,
        -1,
      ),
    );
  },
);

cliTest(
  "marks skipped symbolic-link members as unreadable and never advises selecting them",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-link-note-");
    const link = {
      bytes: debuggableDex(),
      externalFileAttributes: SYMLINK_ATTRIBUTES,
    };
    const noteOf = async (
      members: Parameters<typeof zipArchive>[0],
    ): Promise<string> => {
      const apk = join(
        root,
        `${String(members.length)}-${String(Math.random()).slice(2)}.apk`,
      );
      await writeFile(apk, await zipArchive(members));
      const summary = await inspect(cli, apk);
      expect(summary.exitCode, summary.stdout).toBe(0);
      return evidenceOf(summary.json).normalized_result.limitations.join(" ");
    };
    const mark = LINK_MARK.trimStart();
    // After a gap, under its exact name: entry would refuse it as a link.
    const afterGap = await noteOf([
      { name: "classes.dex", bytes: debuggableDex() },
      { name: "classes3.dex", ...link },
    ]);
    expect(afterGap).toContain(`also holds classes3.dex ${mark}, which`);
    expect(afterGap).not.toContain("with entry");
    // Under a ./ spelling Android does not auto-load.
    const dotted = await noteOf([
      { name: "./classes.dex", ...link },
      { name: "classes.dex", bytes: debuggableDex() },
    ]);
    expect(dotted).toContain(`also holds ./classes.dex ${mark}, which`);
    expect(dotted).not.toContain("with entry");
    // Beside a readable skipped member, only that one is advised.
    const mixed = await noteOf([
      { name: "classes.dex", bytes: debuggableDex() },
      { name: "classes3.dex", ...link },
      { name: "classes4.dex", bytes: debuggableDex() },
    ]);
    expect(mixed).toContain(
      `also holds classes3.dex ${mark}, classes4.dex, which`,
    );
    expect(mixed).toContain("with entry.");
  },
);

cliTest(
  "marks skipped members entry would refuse as ambiguous or encrypted and advises only selectable ones",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-refused-note-");
    let count = 0;
    const archive = async (
      members: Parameters<typeof zipArchive>[0],
    ): Promise<string> => {
      count += 1;
      const apk = join(root, `${String(count)}.apk`);
      await writeFile(apk, await zipArchive(members));
      return apk;
    };
    const noteOf = async (apk: string): Promise<string> => {
      const summary = await inspect(cli, apk);
      expect(summary.exitCode, summary.stdout).toBe(0);
      return evidenceOf(summary.json).normalized_result.limitations.join(" ");
    };
    const base = { name: "classes.dex", bytes: debuggableDex() };
    const twice = [
      { name: "classes3.dex", bytes: debuggableDex() },
      { name: "classes3.dex", bytes: debuggableDex(5) },
    ];
    const duplicated = await archive([base, ...twice]);
    const ambiguous = await noteOf(duplicated);
    expect(ambiguous).toContain(`also holds classes3.dex${TWICE_MARK}, which`);
    expect(ambiguous).not.toContain("with entry");
    const refusedAmbiguous = await inspect(cli, duplicated, "classes3.dex");
    expect(refusedAmbiguous.json).toMatchObject({ code: "invalid_request" });

    const locked = await archive([
      base,
      { name: "classes3.dex", bytes: debuggableDex(), password: "secret" },
    ]);
    const encrypted = await noteOf(locked);
    expect(encrypted).toContain(
      `also holds classes3.dex${ENCRYPTED_MARK}, which`,
    );
    expect(encrypted).not.toContain("with entry");
    const refusedEncrypted = await inspect(cli, locked, "classes3.dex");
    expect(refusedEncrypted.json).toMatchObject({ code: "unsupported_target" });

    const mixed = await noteOf(
      await archive([
        base,
        ...twice,
        { name: "classes4.dex", bytes: debuggableDex() },
      ]),
    );
    expect(mixed).toContain(
      `also holds classes3.dex${TWICE_MARK}, classes4.dex, which`,
    );
    expect(mixed).toContain("with entry.");

    // Fill the name budget to within 10 bytes, ending with `last`, then store
    // `last` again as a link and as a file: its mark no longer fits, so it is
    // counted, never shown again unmarked as if selectable.
    const longName = (index: number, prefixes: number): string =>
      `${"./".repeat(prefixes)}classes${String(index)}.dex`;
    const fillers: string[] = [];
    let room = DEX_LIMITS.namedMembersBytes - ("classes.dex".length + 2);
    for (let index = 10; room > 172; index += 1) {
      fillers.push(longName(index, 70));
      room -= fillers.at(-1)!.length + 2;
    }
    // classesNN.dex is 13 characters; the rest is whole `./` prefixes.
    const last = longName(
      fillers.length + 10,
      Math.floor((room - 2 - 10 - 13) / 2),
    );
    const left = room - (last.length + 2);
    // Less than the shortest mark, " (stored 2 times; ambiguous)".
    expect(left).toBeGreaterThanOrEqual(0);
    expect(left).toBeLessThan(28);
    expect(last.length).toBeLessThanOrEqual(DEX_LIMITS.nameDisplayChars);
    const crowded = await noteOf(
      await archive([
        base,
        ...fillers.map((name) => ({ name, bytes: debuggableDex() })),
        { name: last, bytes: debuggableDex() },
        {
          name: last,
          bytes: debuggableDex(),
          externalFileAttributes: SYMLINK_ATTRIBUTES,
        },
        { name: last, bytes: debuggableDex() },
      ]),
    );
    expect(crowded).toContain(`${fillers.at(-1)!}, 3 more canonical DEX`);
    expect(crowded).not.toContain(last);
  },
);

cliTest(
  "refuses a name duplicated by a link member as ambiguous, whether auto-loaded or selected",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-link-twin-");
    const link = {
      bytes: debuggableDex(),
      externalFileAttributes: SYMLINK_ATTRIBUTES,
    };
    for (const [members, name] of [
      [
        [
          { name: "classes.dex", bytes: debuggableDex() },
          { name: "classes.dex", ...link },
        ],
        "classes.dex",
      ],
      [
        [
          { name: "classes.dex", bytes: debuggableDex() },
          { name: "classes2.dex", bytes: debuggableDex() },
          { name: "classes2.dex", ...link },
        ],
        "classes2.dex",
      ],
    ] as const) {
      const apk = join(root, `${name}.apk`);
      await writeFile(apk, await zipArchive([...members]));
      for (const entry of [undefined, name]) {
        const refused = await inspect(cli, apk, entry);
        expect(refused.exitCode, refused.stdout).toBe(1);
        expect(refused.json).toMatchObject({ code: "invalid_request" });
        expect(refused.json).not.toHaveProperty("normalized_result");
        // Names the duplicated member and how many times it is stored.
        expect(prose(refused.json)).toContain("2 members");
        expect(prose(refused.json)).toContain(name);
      }
    }
  },
);

cliTest(
  "refuses an entry that names nothing and bounds caller names in refusals by characters",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-names-");
    const apk = join(root, "app.apk");
    await writeFile(
      apk,
      await zipArchive([{ name: "classes.dex", bytes: debuggableDex() }]),
    );
    for (const entry of ["./", "././"]) {
      const empty = await inspect(cli, apk, entry);
      expect(empty.exitCode, empty.stdout).toBe(1);
      expect(empty.json).toMatchObject({ code: "invalid_request" });
      expect(prose(empty.json)).toContain(
        String.raw`The entry ${JSON.stringify(JSON.stringify(entry)).slice(1, -1)} names no archive member`,
      );
    }
    const missing = await inspect(cli, apk, "classes9.dex");
    expect(prose(missing.json)).toContain(
      String.raw`No member \"classes9.dex\" exists`,
    );
    // 200 astral characters: the marker counts characters, not UTF-16 units.
    const astral = await inspect(cli, apk, `${"\u{1F600}".repeat(200)}.dex`);
    expect(astral.json).toMatchObject({ code: "invalid_request" });
    expect(prose(astral.json)).toContain(
      "(name shortened: 82 of 204 characters shown)",
    );
  },
);

cliTest(
  "looks up a long class_descriptor whole but shows it bounded in the refusal over MCP",
  async () => {
    const root = await createTestTempDirectory("rea-dex-descriptor-");
    const apk = join(root, "app.apk");
    await writeFile(
      apk,
      await zipArchive([{ name: "classes.dex", bytes: debuggableDex() }]),
    );
    const { call } = await connectLocalToolsMcp();
    const descriptor = `L${"a".repeat(1024 * 1024)};`;
    const notFound = await call(TOOL, {
      path: apk,
      class_descriptor: descriptor,
    });
    expect(notFound.isError).toBe(true);
    const text = JSON.stringify(notFound.content);
    expect(text.length).toBeLessThan(16 * 1024);
    expect(text).toContain("invalid_request");
    expect(text).toContain("name shortened: 160 of 1048578 characters shown");
  },
);

cliTest(
  "binds entry to the exact stored spelling: after a crowd, three times, and when encrypted",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-exact-");
    const crowd = join(root, "crowd.apk");
    await writeFile(
      crowd,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        ...Array.from({ length: 5 }, () => ({
          name: "./classes2.dex",
          bytes: debuggableDex(5),
        })),
        { name: "classes2.dex", bytes: debuggableDex(2) },
      ]),
    );
    const late = await inspect(cli, crowd, "classes2.dex");
    expect(late.exitCode, late.stdout).toBe(0);
    const result = evidenceOf(late.json).normalized_result;
    if (result.mode !== "summary") throw new Error("Expected summary");
    expect(result.members).toMatchObject([
      { entry: "classes2.dex", summary: { line_positions: 3 } },
    ]);

    const thrice = join(root, "thrice.apk");
    await writeFile(
      thrice,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        ...Array.from({ length: 3 }, () => ({
          name: "classes2.dex",
          bytes: debuggableDex(),
        })),
      ]),
    );
    const repeated = await inspect(cli, thrice, "classes2.dex");
    expect(repeated.json).toMatchObject({ code: "invalid_request" });
    expect(repeated.json).not.toHaveProperty("normalized_result");
    expect(prose(repeated.json)).toContain(
      String.raw`3 members stored as \"classes2.dex\"`,
    );

    const locked = join(root, "locked.apk");
    await writeFile(
      locked,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        { name: "classes2.dex", bytes: debuggableDex(), password: "secret" },
        { name: "./classes2.dex", bytes: debuggableDex(5) },
      ]),
    );
    const encrypted = await inspect(cli, locked, "classes2.dex");
    expect(encrypted.json).toMatchObject({ code: "unsupported_target" });
    expect(encrypted.json).not.toHaveProperty("normalized_result");
    expect(prose(encrypted.json)).toContain(String.raw`\"classes2.dex\"`);
    const plain = await inspect(cli, locked, "./classes2.dex");
    expect(plain.exitCode, plain.stdout).toBe(0);
  },
);

cliTest(
  "names members within a count and byte budget and counts the rest accurately",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-budget-");
    // 131 canonical names after a gap: 128 named (classes.dex among them).
    const gap = join(root, "gap.apk");
    await writeFile(
      gap,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        ...Array.from({ length: 130 }, (_, i) => ({
          name: `classes${String(i + 3)}.dex`,
          bytes: debuggableDex(),
        })),
      ]),
    );
    const capped = await inspect(cli, gap);
    expect(capped.exitCode, capped.stdout).toBe(0);
    const note = evidenceOf(capped.json).normalized_result.limitations.join(
      " ",
    );
    expect(note).toContain("classes129.dex, 3 more canonical DEX member(s)");
    expect(note).not.toContain("classes130.dex");

    // Spellings past the byte budget are counted as members, not spellings:
    // the last spelling is stored three times.
    const spelled = (prefixes: number): string =>
      `${"./".repeat(prefixes)}classes2.dex`;
    const crowd = join(root, "crowd.apk");
    await writeFile(
      crowd,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        ...Array.from({ length: 60 }, (_, i) => ({
          name: spelled(i + 1),
          bytes: debuggableDex(),
        })),
        ...Array.from({ length: 3 }, () => ({
          name: spelled(61),
          bytes: debuggableDex(),
        })),
      ]),
    );
    const refused = await inspect(cli, crowd, "classes2.dex");
    expect(refused.json).toMatchObject({ code: "invalid_request" });
    const message = prose(refused.json);
    expect(message).toContain(
      String.raw`holds 63 members named \"classes2.dex\"`,
    );
    const more =
      /, (\d+) more member\(s\) under spellings not named here\)/u.exec(
        message,
      );
    // Every quoted spelling, less the requested name itself.
    const named = message.split(String.raw`classes2.dex\"`).length - 2;
    expect(Number(more?.[1]) + named).toBe(63);
    expect(message).not.toContain(JSON.stringify(spelled(61)).slice(1, -1));
  },
);

cliTest(
  "bounds the bytes of named members and reader notes from long stored names",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-long-");
    const long = (index: number, prefixes: number): string =>
      `${"./".repeat(prefixes)}classes${index === 0 ? "" : String(index + 1)}.dex`;
    // 40 spellings of classes2.dex, each ~20 KB: ~800 KB of names before.
    const spellings = join(root, "spellings.apk");
    await writeFile(
      spellings,
      await zipArchive(
        Array.from({ length: 40 }, (_, i) => ({
          name: long(1, 10_000 + i),
          bytes: debuggableDex(),
        })),
      ),
    );
    const refused = await inspect(cli, spellings, "classes2.dex");
    expect(refused.json).toMatchObject({ code: "invalid_request" });
    expect(refused.stdout.length).toBeLessThan(16 * 1024);
    expect(refused.stdout).toContain("name shortened");
    expect(refused.stdout).toContain(
      "more member(s) under spellings not named here",
    );

    // Long non-exact canonical names: the skipped-members note stays small.
    const skipped = join(root, "skipped.apk");
    await writeFile(
      skipped,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        ...Array.from({ length: 40 }, (_, i) => ({
          name: long(i + 1, 10_000),
          bytes: debuggableDex(),
        })),
      ]),
    );
    const summary = await inspect(cli, skipped);
    expect(summary.exitCode, summary.stdout.slice(0, 400)).toBe(0);
    expect(summary.stdout.length).toBeLessThan(64 * 1024);
    expect(summary.stdout).toContain("more canonical DEX member(s)");

    // Long Unicode Path names on every auto-loaded member: reader notes are
    // shortened, budgeted, and the rest counted.
    const noted = join(root, "noted.apk");
    await writeFile(
      noted,
      await zipArchive(
        Array.from({ length: 20 }, (_, i) => ({
          name: long(i, 0),
          bytes: debuggableDex(),
          unicodePath: `${"x".repeat(20_000)}${String(i)}.dex`,
        })),
      ),
    );
    const read = await inspect(cli, noted);
    expect(read.exitCode, read.stdout.slice(0, 400)).toBe(0);
    expect(read.stdout.length).toBeLessThan(96 * 1024);
    const limitations = evidenceOf(read.json).normalized_result.limitations;
    expect(limitations.join(" ")).toContain("note shortened");
    expect(limitations.at(-1)).toMatch(
      /^\d+ further archive-reader note\(s\) on \d+ member\(s\) read were omitted to bound the output/u,
    );
  },
);

cliTest("refuses a non-DEX file through the public CLI", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-dex-cli-bad-");
  const path = join(root, "bad.dex");
  await writeFile(path, new Uint8Array(256).fill(0x41));
  const result = await cli.run({
    arguments: ["inspect-dex-debug-metadata", path, "--json"],
  });
  expect(result.exitCode).toBe(1);
  expect(result.json).toMatchObject({
    code: "unsupported_target",
    details: { operation: TOOL },
  });
});

cliTest(
  "refuses short non-DEX input as non-DEX and reports truncation only after DEX magic",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-cli-short-");
    const text = new TextEncoder().encode(
      "REA triage decoy.\nThis is plain UTF-8 text, shorter than a DEX header.\n",
    );
    const refuse = async (path: string, entry?: string) => {
      const result = await cli.run({
        arguments: [
          "inspect-dex-debug-metadata",
          path,
          ...(entry === undefined ? [] : ["--entry", entry]),
          "--json",
        ],
      });
      expect(result.exitCode, result.stderr).toBe(1);
      // An invalid_request carries its reason in details.issues, not message.
      return {
        ...(result.json as { code: string }),
        text: JSON.stringify(result.json),
      };
    };

    const notDex: [string, Uint8Array][] = [
      ["empty.dex", new Uint8Array(0)],
      ["one.dex", new Uint8Array([0x50])],
      ["three.dex", new Uint8Array([0xca, 0xfe, 0xba])],
      ["cde.dex", new TextEncoder().encode("cde")],
      ["decoy.bin", text],
    ];
    for (const [name, bytes] of notDex) {
      const path = join(root, name);
      await writeFile(path, bytes);
      const refused = await refuse(path);
      expect(refused).toMatchObject({ code: "unsupported_target" });
      expect(refused.text).toContain("does not begin with the DEX magic");
      expect(refused.text).not.toContain("DEX ended before");
    }

    const prefix = join(root, "prefix.dex");
    await writeFile(prefix, debuggableDex().subarray(0, 6));
    const truncated = await refuse(prefix);
    expect(truncated).toMatchObject({ code: "invalid_request" });
    expect(truncated.text).toContain("DEX ended before");
    expect(truncated.text).toContain("112 bytes needed there, 6 present");

    const apk = join(root, "short.apk");
    await writeFile(
      apk,
      await zipArchive([
        { name: "classes.dex", bytes: text },
        { name: "classes2.dex", bytes: debuggableDex().subarray(0, 6) },
      ]),
    );
    const member = await refuse(apk);
    expect(member).toMatchObject({ code: "unsupported_target" });
    expect(member.text).toContain(
      `${apk}!classes.dex does not begin with the DEX magic`,
    );
    const memberPrefix = await refuse(apk, "classes2.dex");
    expect(memberPrefix).toMatchObject({ code: "invalid_request" });
    expect(memberPrefix.text).toContain(
      `${apk}!classes2.dex: DEX ended before`,
    );
  },
);

cliTest(
  "answers the CLI's selection identically over stdio MCP, refuses malformed input, and keeps serving after a cancelled call",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-mcp-");
    const dex = join(root, "a.dex");
    await writeFile(dex, debuggableDex());
    const { call } = await connectLocalToolsMcp();

    const viaCli = await cli.run({
      arguments: ["inspect-dex-debug-metadata", dex, "--json"],
    });
    expect(viaCli.exitCode, viaCli.stderr).toBe(0);
    const viaMcp = await call(TOOL, { path: dex });
    expect(viaMcp.isError).not.toBe(true);
    expect(evidenceOf(viaMcp.structuredContent).normalized_result).toEqual(
      evidenceOf(viaCli.json).normalized_result,
    );

    const bad = join(root, "bad.dex");
    await writeFile(bad, new Uint8Array(256).fill(0x41));
    const refused = await call(TOOL, { path: bad });
    expect(refused.isError).toBe(true);
    expect(JSON.stringify(refused.content)).toContain("unsupported_target");

    const long = join(root, "long.dex");
    await writeFile(long, debuggableDex(1_500_000));
    const controller = new AbortController();
    const cancelled = call(TOOL, { path: long }, { signal: controller.signal });
    setImmediate(() => controller.abort(new Error("caller cancelled")));
    await expect(cancelled).rejects.toThrow();
    // The server settled the cancelled call and still answers.
    const after = await call(TOOL, { path: long });
    expect(after.isError).not.toBe(true);
    const result = evidenceOf(after.structuredContent).normalized_result;
    if (result.mode !== "summary") throw new Error("Expected summary");
    expect(result.members[0]?.summary.line_positions).toBe(1_500_001);
  },
);
