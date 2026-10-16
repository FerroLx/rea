#!/usr/bin/env node
/**
 * Real-toolchain lane for inspect_binary_imports. mingw-w64 builds x86 and x64
 * PE fixtures with known imports (by name, by ordinal from a NONAME import
 * library, delay-load), a DLL with named, ordinal-only and forwarded exports,
 * and a runtime-resolution sample. Every import, delay import, export and the
 * import hash are compared exactly with Python pefile (the imphash reference)
 * and the imported DLL set with llvm-readobj, through both the CLI and MCP, with
 * the advertised output schema validated. The fixtures are never executed.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import Ajv2020 from "ajv/dist/2020.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

const execute = promisify(execFile);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);

const require = async (command, args, purpose) => {
  try {
    await execute(command, args, { timeout: 30_000 });
    return command;
  } catch (cause) {
    throw new Error(
      `verify:binary-imports needs ${command} on PATH (${purpose}); it is only a fixture producer or oracle, not a REA runtime dependency.`,
      { cause },
    );
  }
};

const firstAvailable = async (candidates, args, purpose) => {
  for (const candidate of candidates)
    try {
      await execute(candidate, args, { timeout: 30_000 });
      return candidate;
    } catch {
      // try the next candidate
    }
  throw new Error(
    `verify:binary-imports needs one of ${candidates.join(", ")} on PATH (${purpose}).`,
  );
};

const python = process.env.REA_VERIFY_PEFILE_PYTHON ?? "python3";
if (process.env.REA_VERIFY_PEFILE_PYTHON !== undefined && !isAbsolute(python))
  throw new Error("REA_VERIFY_PEFILE_PYTHON must be an absolute Python path.");

const gcc64 = await require("x86_64-w64-mingw32-gcc", [
  "--version",
], "x64 fixtures");
const gcc32 = await require("i686-w64-mingw32-gcc", [
  "--version",
], "x86 fixtures");
const dlltool64 = await require("x86_64-w64-mingw32-dlltool", [
  "--version",
], "ordinal and delay-load import libraries");
const dlltool32 = await require("i686-w64-mingw32-dlltool", [
  "--version",
], "x86 import libraries");
const readobj = await firstAvailable(
  ["llvm-readobj", "llvm-readobj-21", "llvm-readobj-19", "llvm-readobj-18"],
  ["--version"],
  "independent import oracle",
);
await require(python, ["-I", "-c", "import pefile"], "pefile import oracle");

const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-binary-imports-verifier-"));
const client = new Client({ name: "binary-imports-verifier", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
let cases = 0;
const failures = [];

const PEFILE_ORACLE = `
import json, sys, pefile
pe = pefile.PE(sys.argv[1])
def sym(i):
    if i.import_by_ordinal:
        return "#%d=%s" % (i.ordinal, i.name.decode() if i.name else "ord%d" % i.ordinal)
    return i.name.decode()
imports = [[e.dll.decode(), sym(i)] for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) for i in e.imports]
delay = [[e.dll.decode(), sym(i)] for e in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []) for i in e.imports]
exports = []
if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
    for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        exports.append([s.ordinal, s.name.decode() if s.name else None, s.forwarder.decode() if s.forwarder else None])
print(json.dumps({"imports": imports, "delay": delay, "exports": exports, "imphash": pe.get_imphash() or None}))
`;
const pefile = async (path) =>
  JSON.parse(
    (
      await execute(python, ["-I", "-c", PEFILE_ORACLE, path], {
        timeout: 60_000,
      })
    ).stdout,
  );
const readobjDlls = async (path) =>
  [
    ...(
      await execute(readobj, ["--coff-imports", path], { timeout: 60_000 })
    ).stdout.matchAll(/Name: (\S+)/g),
  ]
    .map((m) => m[1].toLowerCase())
    .filter((name) => /\.(dll|exe|sys|drv)$/.test(name));

const inspectCli = async (path, extra = []) => {
  try {
    return JSON.parse(
      (
        await execute(
          process.execPath,
          [entrypoint, "inspect-binary-imports", path, "--json", ...extra],
          { env: environment, timeout: 120_000, maxBuffer: 64 * 1024 * 1024 },
        )
      ).stdout,
    );
  } catch (cause) {
    if (typeof cause.stdout === "string" && cause.stdout.length > 0)
      return JSON.parse(cause.stdout);
    throw cause;
  }
};

// pefile lists named exports in name-table order, then ordinal-only ones;
// REA lists by ordinal. Compare the facts, not either iteration order.
const byOrdinal = (rows) =>
  [...rows].sort(
    (a, b) => a[0] - b[0] || String(a[1]).localeCompare(String(b[1])),
  );

const write = (name, text) => writeFile(join(workspace, name), text);
const at = (name) => join(workspace, name);

try {
  await client.connect(transport);
  const advertised = (await client.listTools()).tools.find(
    ({ name }) => name === "inspect_binary_imports",
  );
  assert.ok(advertised?.outputSchema, "tool must advertise an output schema");
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  assert.ok(ajv.validateSchema(advertised.inputSchema), "input schema invalid");
  assert.ok(
    ajv.validateSchema(advertised.outputSchema),
    "output schema invalid",
  );

  /** CLI and MCP must return identical, schema-valid Evidence. */
  const inspectBoth = async (path) => {
    const cli = parseEvidence(await inspectCli(path, ["--detail", "imports"]));
    const reply = await client.callTool({
      name: "inspect_binary_imports",
      arguments: { path, detail: "imports" },
    });
    assert.notEqual(reply.isError, true, mcpTextValue(reply));
    assert.ok(
      ajv.validate(advertised.outputSchema, reply.structuredContent),
      JSON.stringify(ajv.errors),
    );
    const mcp = parseEvidence(reply.structuredContent);
    assert.deepEqual(cli, mcp, "CLI and MCP evidence differ");
    return mcp.normalized_result;
  };

  /** Every import/delay/export and the imphash must equal pefile's; DLL sets equal llvm-readobj's. */
  const compare = async (path, label) => {
    const report = await inspectBoth(path);
    const oracle = await pefile(path);
    const flatten = (table) =>
      report.detail.imports
        .filter((group) => group.table === table)
        .flatMap((group) =>
          group.symbols.map((s) => [
            group.dll,
            s.kind === "name"
              ? s.name
              : s.kind === "ordinal"
                ? `#${s.ordinal}=${s.resolved}`
                : "?",
          ]),
        );
    assert.deepEqual(
      flatten("import"),
      oracle.imports,
      `${label}: imports differ from pefile`,
    );
    assert.deepEqual(
      flatten("delay"),
      oracle.delay,
      `${label}: delay imports differ from pefile`,
    );
    assert.equal(
      report.imphash,
      oracle.imphash,
      `${label}: imphash differs from pefile`,
    );
    assert.deepEqual(
      byOrdinal(
        report.detail.exports.entries.map((e) => [
          e.ordinal,
          e.name,
          e.kind === "forwarder" ? e.target : null,
        ]),
      ),
      byOrdinal(oracle.exports),
      `${label}: exports differ from pefile`,
    );
    const ours = [
      ...new Set(
        report.detail.imports
          .filter((g) => g.table === "import")
          .map((g) => g.dll.toLowerCase()),
      ),
    ].sort();
    assert.deepEqual(
      ours,
      [...new Set(await readobjDlls(path))].sort(),
      `${label}: DLLs differ from llvm-readobj`,
    );
    cases += 2;
    return report;
  };

  // A DLL with named, ordinal-only (NONAME) and forwarded exports.
  await write(
    "fixlib.c",
    `__declspec(dllexport) int named_export(void) { return 1; }
int ordinal_export(void) { return 2; }
`,
  );
  await write(
    "fixlib.def",
    `LIBRARY fixlib.dll
EXPORTS
  named_export @1
  ordinal_export @7 NONAME
  forwarded = kernel32.GetTickCount @9
`,
  );
  // An import library that imports ws2_32's socket by ordinal 23 (NONAME),
  // so pefile's ordinal table resolves it.
  await write(
    "ws2ord.def",
    "LIBRARY ws2_32.dll\nEXPORTS\n  socket @23 NONAME\n",
  );
  // The program: by-name imports across DLLs, an ordinal import, a delay-load
  // import, and a runtime-resolution sample. It is only compiled, never run.
  await write(
    "app.c",
    `#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <urlmon.h>
int ordinal_export(void);
int named_export(void);
int socket(int, int, int);
int main(void) {
  HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 0);
  LPVOID m = VirtualAllocEx(p, NULL, 16, MEM_COMMIT, PAGE_READWRITE);
  WriteProcessMemory(p, m, "x", 1, NULL);
  CreateRemoteThread(p, NULL, 0, NULL, NULL, 0, NULL);
  URLDownloadToFileW(NULL, L"u", L"f", 0, NULL);
  FARPROC f = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtLoadDriver");
  return ordinal_export() + named_export() + socket(0, 0, 0) + (f != NULL);
}
`,
  );

  for (const [arch, gcc, dlltool] of [
    ["x64", gcc64, dlltool64],
    ["x86", gcc32, dlltool32],
  ]) {
    const dir = (name) => at(`${arch}-${name}`);
    await execute(gcc, [
      "-shared",
      "-o",
      dir("fixlib.dll"),
      at("fixlib.c"),
      at("fixlib.def"),
    ]);
    await execute(dlltool, [
      "-d",
      at("fixlib.def"),
      "-D",
      "fixlib.dll",
      "-l",
      dir("libfixlib.a"),
    ]);
    await execute(dlltool, [
      "-d",
      at("fixlib.def"),
      "-D",
      "fixlib.dll",
      "-y",
      dir("libfixlib_delay.a"),
    ]);
    await execute(dlltool, [
      "-d",
      at("ws2ord.def"),
      "-D",
      "ws2_32.dll",
      "-l",
      dir("libws2ord.a"),
    ]);
    await execute(gcc, [
      "-O0",
      "-o",
      dir("app.exe"),
      at("app.c"),
      dir("libfixlib.a"),
      dir("libws2ord.a"),
      "-lurlmon",
    ]);
    await execute(gcc, [
      "-O0",
      "-o",
      dir("app-delay.exe"),
      at("app.c"),
      dir("libfixlib_delay.a"),
      dir("libws2ord.a"),
      "-lurlmon",
    ]);

    const dll = await compare(dir("fixlib.dll"), `${arch} fixlib.dll`);
    assert.equal(dll.format.is_dll, true);
    assert.ok(
      dll.counts.forwarders >= 1,
      `${arch}: the forwarder export must be reported`,
    );

    const app = await compare(dir("app.exe"), `${arch} app.exe`);
    const capability = (category) =>
      app.capabilities.find((c) => c.category === category);
    assert.equal(capability("process_injection")?.confidence, "strong");
    assert.equal(capability("download")?.confidence, "strong");
    const ws2 = app.detail.imports
      .flatMap((g) => g.symbols)
      .find((s) => s.kind === "ordinal" && s.ordinal === 23);
    assert.equal(
      ws2?.resolved,
      "socket",
      `${arch}: ws2_32 ordinal 23 must resolve to socket`,
    );
    assert.equal(ws2?.resolved_from_table, true);
    const unresolved = app.detail.imports
      .flatMap((g) => g.symbols)
      .find((s) => s.kind === "ordinal" && s.ordinal === 7);
    assert.equal(
      unresolved?.resolved,
      "ord7",
      `${arch}: an ordinal without a table stays ord<N>`,
    );
    assert.deepEqual(
      app.runtime_resolution.resolver_imports.includes("GetProcAddress"),
      true,
    );
    assert.ok(
      app.runtime_resolution.api_strings.sample.some(
        (s) => s.api === "NtLoadDriver",
      ),
      `${arch}: NtLoadDriver must be reported as a runtime-resolution string`,
    );

    const delayed = await compare(
      dir("app-delay.exe"),
      `${arch} app-delay.exe`,
    );
    assert.ok(
      delayed.counts.delay_imports > 0,
      `${arch}: delay-load imports must be read`,
    );
    assert.equal(delayed.counts.delay_va_unmapped, 0);
  }

  // Error surfaces: a non-PE file and an unknown category are clean input errors.
  await write("not-pe.bin", "definitely not a portable executable");
  const notPe = await inspectCli(at("not-pe.bin"));
  assert.equal(
    notPe.category,
    "invalid_input",
    JSON.stringify(notPe).slice(0, 300),
  );
  const badCategory = await inspectCli(at("x64-app.exe"), [
    "--categories",
    "bogus",
  ]);
  assert.equal(badCategory.category, "invalid_input");
  cases += 2;
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
  throw new AggregateError(failures, "Binary imports verification failed.");
console.log(
  JSON.stringify(
    {
      status: "passed",
      cases,
      toolchain: "mingw-w64 + pefile + llvm-readobj",
      entrypoint,
      verifier: await completeVerifierRun(run),
    },
    null,
    2,
  ),
);
