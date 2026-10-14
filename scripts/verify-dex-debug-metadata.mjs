#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  access,
  mkdir,
  mkdtemp,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Ajv2020 } from "ajv/dist/2020.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

const execute = promisify(execFile);
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, v]) => typeof v === "string"),
);

const probe = async (candidate, flag) => {
  try {
    await execute(candidate, [flag]);
    return true;
  } catch {
    return false;
  }
};
const resolveJdkTool = async (tool) => {
  const home = environment.JAVA_HOME;
  if (home !== undefined && isAbsolute(home)) {
    const candidate = join(home, "bin", tool);
    if (await probe(candidate, "-version")) return candidate;
  }
  return (await probe(tool, "-version")) ? tool : undefined;
};
const sdkRoots = [
  environment.ANDROID_HOME,
  environment.ANDROID_SDK_ROOT,
  join(homedir(), "Android", "Sdk"),
  join(homedir(), "Library", "Android", "sdk"),
].filter((r) => typeof r === "string" && r.length > 0);
const resolveSdkTool = async (name) => {
  for (const root of sdkRoots) {
    try {
      const versions = (await readdir(join(root, "build-tools")))
        .sort()
        .reverse();
      for (const v of versions) {
        const candidate = join(root, "build-tools", v, name);
        try {
          await access(candidate, constants.X_OK);
          return candidate;
        } catch {
          /* next version */
        }
      }
    } catch {
      /* next root */
    }
  }
  return undefined;
};

const javac = await resolveJdkTool("javac");
const d8 = await resolveSdkTool("d8");
const dexdump = await resolveSdkTool("dexdump");
if (javac === undefined || d8 === undefined || dexdump === undefined) {
  if (process.argv.includes("--require-tools"))
    throw new Error("DEX real lane requires javac + Android SDK d8 + dexdump.");
  console.log(
    JSON.stringify({
      status: "skipped",
      reason:
        "DEX real lane requires javac and the Android SDK (d8 + dexdump); not all found.",
    }),
  );
  process.exit(0);
}

const entrypoint =
  process.argv.slice(2).find((arg) => !arg.startsWith("--")) ??
  fileURLToPath(new URL("./rea.mjs", import.meta.url));

/** Independent oracle: dexdump's own view of positions and locals in a dex. */
const dexdumpFacts = async (dexPath) => {
  const { stdout } = await execute(dexdump, ["-d", dexPath], {
    env: environment,
    timeout: 120_000,
    maxBuffer: 256 * 1024 * 1024,
  });
  return {
    linePositions: (stdout.match(/[0-9a-f]+ line=/g) ?? []).length,
    localEntries: (stdout.match(/reg=[0-9]+/g) ?? []).length,
    // Local names dexdump resolves, e.g. `reg=5 this LDebuggable;` -> "this".
    localNames: new Set(
      (stdout.match(/reg=\d+ (\S+) /g) ?? []).map((m) =>
        m.replace(/reg=\d+ /, "").trim(),
      ),
    ),
  };
};

const inspectCli = async (path, extra = {}) => {
  const args = [entrypoint, "inspect-dex-debug-metadata", path];
  if (extra.entry !== undefined) args.push("--entry", extra.entry);
  if (extra.class_descriptor !== undefined)
    args.push("--class-descriptor", extra.class_descriptor);
  args.push("--format", "json");
  try {
    return JSON.parse(
      (
        await execute(process.execPath, args, {
          env: environment,
          timeout: 180_000,
          maxBuffer: 256 * 1024 * 1024,
        })
      ).stdout,
    );
  } catch (cause) {
    if (typeof cause.code === "number" && typeof cause.stdout === "string")
      return JSON.parse(cause.stdout);
    throw cause;
  }
};

const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-dex-verifier-"));
const client = new Client({
  name: "dex-debug-metadata-verifier",
  version: "1",
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
let cases = 0;
const failures = [];

try {
  await client.connect(transport);
  const advertised = (await client.listTools()).tools.find(
    ({ name }) => name === "inspect_dex_debug_metadata",
  );
  assert.ok(
    advertised?.outputSchema,
    "DEX tool must advertise an output schema",
  );
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  assert.ok(ajv.validateSchema(advertised.inputSchema), "input schema invalid");
  assert.ok(
    ajv.validateSchema(advertised.outputSchema),
    "output schema invalid",
  );

  const inspectBoth = async (path, extra = {}) => {
    const cliValue = await inspectCli(path, extra);
    assert.equal(
      cliValue.category,
      undefined,
      JSON.stringify(cliValue).slice(0, 400),
    );
    const cli = parseEvidence(cliValue);
    const reply = await client.callTool({
      name: "inspect_dex_debug_metadata",
      arguments: { path, ...extra },
    });
    assert.notEqual(reply.isError, true, mcpTextValue(reply));
    assert.ok(
      ajv.validate(advertised.outputSchema, reply.structuredContent),
      JSON.stringify(ajv.errors),
    );
    const mcp = parseEvidence(reply.structuredContent);
    assert.equal(
      cli.evidence_id,
      mcp.evidence_id,
      "CLI and MCP evidence differ",
    );
    assert.deepEqual(cli, mcp);
    cases += 2;
    return mcp.normalized_result;
  };

  // Compile one class with and without debug info, then dex each set.
  const source = `import java.util.*;
class Debuggable {
  int compute(int a, long b) { int x = a + 1; for (int i = 0; i < a; i++) { x += i; } return x; }
  int identity(int a) { return a; }
}
`;
  const src = join(workspace, "Debuggable.java");
  await writeFile(src, source);
  const gDir = join(workspace, "g");
  const noneDir = join(workspace, "none");
  await mkdir(gDir);
  await mkdir(noneDir);
  await execute(javac, ["-g", "-d", gDir, src], { env: environment });
  await execute(javac, ["-g:none", "-d", noneDir, src], { env: environment });
  await execute(d8, ["--output", gDir, join(gDir, "Debuggable.class")], {
    env: environment,
    timeout: 180_000,
  });
  await execute(d8, ["--output", noneDir, join(noneDir, "Debuggable.class")], {
    env: environment,
    timeout: 180_000,
  });
  const gDex = join(gDir, "classes.dex");
  const noneDex = join(noneDir, "classes.dex");

  // -g dex: readiness present, locals, and dexdump agrees locals exist.
  const gSummary = await inspectBoth(gDex);
  const gm = gSummary.members[0];
  assert.equal(
    gm.summary.readiness,
    "present",
    "debug dex should read present",
  );
  assert.ok(gm.summary.local_declarations > 0, "debug dex should have locals");
  assert.ok(
    gm.summary.line_positions > 0,
    "debug dex should have line positions",
  );
  const gOracle = await dexdumpFacts(gDex);
  assert.ok(
    gOracle.localEntries > 0,
    "dexdump should see locals in the debug dex",
  );
  assert.ok(
    gOracle.linePositions > 0,
    "dexdump should see positions in the debug dex",
  );

  // -g:none dex: readiness stripped, no locals; dexdump agrees none exist.
  const noneSummary = await inspectBoth(noneDex);
  const nm = noneSummary.members[0];
  assert.equal(
    nm.summary.readiness,
    "stripped",
    "stripped dex should read stripped",
  );
  assert.equal(
    nm.summary.local_declarations,
    0,
    "stripped dex should have no locals",
  );
  const noneOracle = await dexdumpFacts(noneDex);
  assert.equal(
    noneOracle.localEntries,
    0,
    "dexdump should see no locals in the stripped dex",
  );

  // Per-class detail resolves names, descriptor, locals, and the source file.
  const detail = await inspectBoth(gDex, { class_descriptor: "LDebuggable;" });
  assert.equal(detail.mode, "class-detail");
  assert.equal(detail.class_detail.source_file, "Debuggable.java");
  const compute = detail.class_detail.methods.find((m) => m.name === "compute");
  assert.ok(compute, "compute method should resolve by name");
  assert.equal(compute.descriptor, "(IJ)I", "descriptor should be JVM-form");
  // The implicit `this` and both parameters must be present as locals — the
  // exact regression a counts-only check misses. Cross-check against dexdump:
  // the names REA reports for compute must all be names dexdump also resolves.
  const names = new Set(compute.locals.map((l) => l.name));
  for (const required of ["this", "a", "b"])
    assert.ok(names.has(required), `compute locals must include ${required}`);
  for (const name of names)
    if (name !== null)
      assert.ok(
        gOracle.localNames.has(name),
        `REA local ${name} must be a name dexdump also resolves`,
      );
  // `this` is the parameter the old decoder dropped entirely.
  assert.ok(gOracle.localNames.has("this"), "dexdump should resolve `this`");
  cases += 1;

  // Archive (APK) selection: summarize all, and select one member by entry.
  const apk = join(workspace, "app.apk");
  await execute("jar", ["--create", "--file", apk, "-C", gDir, "classes.dex"], {
    env: environment,
  });
  const apkSummary = await inspectBoth(apk);
  assert.equal(apkSummary.container, "apk");
  assert.equal(apkSummary.members[0].entry, "classes.dex");
  const picked = await inspectBoth(apk, { entry: "classes.dex" });
  assert.equal(picked.members[0].entry, "classes.dex");

  // A missing entry is a clean input error (CLI).
  const miss = await inspectCli(apk, { entry: "classes9.dex" });
  assert.equal(
    miss.category,
    "invalid_input",
    JSON.stringify(miss).slice(0, 300),
  );
  cases += 1;
} catch (cause) {
  failures.push(cause);
}

for (const close of [
  () => client.close(),
  () => transport.close(),
  () => rm(workspace, { recursive: true, force: true }),
]) {
  try {
    await close();
  } catch (cause) {
    failures.push(cause);
  }
}

if (failures.length > 0)
  throw new AggregateError(failures, "DEX debug-metadata verification failed.");
console.log(
  JSON.stringify(
    {
      status: "passed",
      cases,
      toolchain: "android-d8-dexdump",
      entrypoint,
      verifier: await completeVerifierRun(run),
    },
    null,
    2,
  ),
);
