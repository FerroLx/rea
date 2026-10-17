#!/usr/bin/env node
/**
 * Real-toolchain lane for inspect_pe_imports. mingw-w64 builds x86 and x64
 * PE fixtures with known imports (by name, by ordinal from a NONAME import
 * library, delay-load), a DLL with named, ordinal-only and forwarded exports,
 * and a runtime-resolution sample. Every import, delay import, export and the
 * import hash are compared exactly with Python pefile (the imphash reference)
 * and the imported DLL set with llvm-readobj, through both the CLI and MCP, with
 * the advertised output schema validated. A copy of each program carries an
 * OpenSSL-produced PKCS #7 SignedData as a WIN_CERTIFICATE; its security
 * directory, entries and overlay are compared with pefile and its signer
 * certificate with OpenSSL. The fixtures are never executed.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
      `verify:pe-imports needs ${command} on PATH (${purpose}); it is only a fixture producer or oracle, not a REA runtime dependency.`,
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
    `verify:pe-imports needs one of ${candidates.join(", ")} on PATH (${purpose}).`,
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
const openssl = await require("openssl", ["version"], "SignedData producer");

const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-pe-imports-verifier-"));
const client = new Client({ name: "pe-imports-verifier", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
let cases = 0;
const failures = [];

const PEFILE_ORACLE = `
import json, struct, sys, pefile
pe = pefile.PE(sys.argv[1])
directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
certificates = []
at, end = directory.VirtualAddress, directory.VirtualAddress + directory.Size
while directory.Size and at + 8 <= end:
    length, revision, kind = struct.unpack_from("<IHH", pe.__data__, at)
    certificates.append([at, length, revision, kind])
    if length < 8:
        break
    at += (length + 7) & ~7
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
print(json.dumps({"imports": imports, "delay": delay, "exports": exports, "imphash": pe.get_imphash() or None,
    "security": [directory.VirtualAddress, directory.Size], "certificates": certificates,
    "overlay": pe.get_overlay_data_start_offset(), "bytes": len(pe.__data__)}))
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
          [entrypoint, "inspect-pe-imports", path, "--json", ...extra],
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
    ({ name }) => name === "inspect_pe_imports",
  );
  assert.ok(advertised?.outputSchema, "tool must advertise an output schema");
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  assert.ok(ajv.validateSchema(advertised.inputSchema), "input schema invalid");
  assert.ok(
    ajv.validateSchema(advertised.outputSchema),
    "output schema invalid",
  );

  const callValid = async (args) => {
    const reply = await client.callTool({
      name: "inspect_pe_imports",
      arguments: args,
    });
    assert.notEqual(reply.isError, true, mcpTextValue(reply));
    assert.ok(
      ajv.validate(advertised.outputSchema, reply.structuredContent),
      JSON.stringify(ajv.errors),
    );
    return parseEvidence(reply.structuredContent);
  };

  /** Page one retained collection to exhaustion through inspect_analysis_view. */
  const pageAll = async (evidenceId, collection) => {
    const rows = [];
    for (let offset = 0; offset !== null;) {
      const reply = await client.callTool({
        name: "inspect_analysis_view",
        arguments: {
          source: { kind: "retained-evidence", evidence_id: evidenceId },
          view: { kind: "pe-imports", collection, offset, limit: 7 },
        },
      });
      assert.notEqual(reply.isError, true, mcpTextValue(reply));
      const view = parseEvidence(reply.structuredContent).normalized_result;
      rows.push(...view.rows);
      offset = view.coverage.next_offset;
    }
    return rows;
  };

  /**
   * CLI and MCP must return identical, schema-valid complete Evidence; the
   * summary must carry the same triage facts and its retained tables must
   * page back to the complete ones.
   */
  const inspectBoth = async (path) => {
    const cli = parseEvidence(await inspectCli(path));
    const mcp = await callValid({ path });
    assert.deepEqual(cli, mcp, "CLI and MCP evidence differ");
    const report = mcp.normalized_result;
    const summary = (await callValid({ path, detail: "summary" }))
      .normalized_result;
    assert.equal(summary.parent_operation, "inspect_pe_imports");
    assert.equal(summary.summary.imphash, report.imphash);
    assert.deepEqual(summary.summary.capabilities, report.capabilities);
    assert.deepEqual(summary.summary.counts, report.counts);
    assert.deepEqual(
      summary.summary.runtime_resolution,
      report.runtime_resolution,
    );
    assert.deepEqual(summary.summary.authenticode, report.authenticode);
    assert.equal(
      report.api_strings.length,
      report.runtime_resolution.api_strings.count -
        report.runtime_resolution.api_strings.omitted,
    );
    assert.deepEqual(
      await pageAll(summary.parent_evidence_id, "api_strings"),
      report.api_strings,
      "paged api_strings differ from the complete list",
    );
    assert.deepEqual(
      await pageAll(summary.parent_evidence_id, "exports"),
      report.exports.entries,
      "paged exports differ from the complete table",
    );
    for (const collection of ["imports", "delay_imports"])
      assert.deepEqual(
        (await pageAll(summary.parent_evidence_id, collection)).map((row) => [
          row.dll,
          row.symbol,
        ]),
        report[collection].flatMap((group) =>
          group.symbols.map((symbol) => [group.dll, symbol]),
        ),
        `paged ${collection} differ from the complete table`,
      );
    return report;
  };

  /** Every import/delay/export and the imphash must equal pefile's; DLL sets equal llvm-readobj's. */
  const compare = async (path, label) => {
    const report = await inspectBoth(path);
    const oracle = await pefile(path);
    const flatten = (table) =>
      report[table === "import" ? "imports" : "delay_imports"].flatMap(
        (group) =>
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
        report.exports.entries.map((e) => [
          e.ordinal,
          e.name,
          e.kind === "forwarder" ? e.target : null,
        ]),
      ),
      byOrdinal(oracle.exports),
      `${label}: exports differ from pefile`,
    );
    // The security directory is a file offset; pefile reads it as declared.
    const [tableOffset, tableSize] = oracle.security;
    if (tableOffset === 0 && tableSize === 0)
      assert.deepEqual(report.authenticode, { status: "absent" });
    else {
      assert.equal(report.authenticode.status, "present", label);
      assert.deepEqual(report.authenticode.table, {
        offset: tableOffset,
        size: tableSize,
      });
      assert.deepEqual(
        report.authenticode.entries.map((e) => [
          e.offset,
          e.length,
          e.revision,
          e.type,
        ]),
        oracle.certificates,
        `${label}: WIN_CERTIFICATE entries differ from pefile's directory`,
      );
      assert.equal(report.authenticode.verification, "not-performed");
      assert.equal(report.authenticode.trust, "not-assessed");
    }
    // pefile's overlay starts after section data and non-security
    // directories; REA's excludes a well-formed certificate table.
    const certificateEnd = tableOffset + tableSize;
    if (oracle.overlay === null) assert.equal(report.packing.overlay, null);
    else if (
      report.authenticode.status === "present" &&
      oracle.overlay === tableOffset &&
      certificateEnd === oracle.bytes
    )
      assert.equal(
        report.packing.overlay,
        null,
        `${label}: a tail certificate table is not an overlay`,
      );
    else assert.equal(report.packing.overlay?.offset, oracle.overlay, label);
    const ours = [
      ...new Set(report.imports.map((g) => g.dll.toLowerCase())),
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

  // A self-signed signer and an OpenSSL PKCS #7 SignedData over placeholder
  // content: structure for the certificate table, not an Authenticode digest.
  await execute(openssl, [
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-nodes",
    "-keyout",
    at("signer.key"),
    "-out",
    at("signer.pem"),
    "-subj",
    "/O=REA Verify/CN=REA Lane Signer",
    "-days",
    "2",
  ]);
  await write("content.bin", "rea lane content");
  await execute(openssl, [
    "cms",
    "-sign",
    "-binary",
    "-nodetach",
    "-outform",
    "DER",
    "-md",
    "sha256",
    "-nosmimecap",
    "-signer",
    at("signer.pem"),
    "-inkey",
    at("signer.key"),
    "-econtent_type",
    "1.3.6.1.4.1.311.2.1.4",
    "-in",
    at("content.bin"),
    "-out",
    at("signed.der"),
  ]);
  const signedData = await readFile(at("signed.der"));
  const signerDer = (
    await execute(
      openssl,
      ["x509", "-in", at("signer.pem"), "-outform", "DER"],
      {
        encoding: "buffer",
      },
    )
  ).stdout;
  const signerSha256 = createHash("sha256").update(signerDer).digest("hex");
  /** Append one WIN_CERTIFICATE at an 8-byte boundary and declare it. */
  const sign = async (from, to) => {
    const image = await readFile(from);
    const tableAt = Math.ceil(image.length / 8) * 8;
    const entry = Buffer.alloc(8 + Math.ceil(signedData.length / 8) * 8);
    entry.writeUInt32LE(8 + signedData.length, 0);
    entry.writeUInt16LE(0x200, 4);
    entry.writeUInt16LE(2, 6);
    signedData.copy(entry, 8);
    const optional = image.readUInt32LE(60) + 24;
    const security =
      optional + (image.readUInt16LE(optional) === 0x20b ? 112 : 96) + 32;
    image.writeUInt32LE(tableAt, security);
    image.writeUInt32LE(entry.length, security + 4);
    await writeFile(
      to,
      Buffer.concat([image, Buffer.alloc(tableAt - image.length), entry]),
    );
  };

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
    const ws2 = [...app.imports, ...app.delay_imports]
      .flatMap((g) => g.symbols)
      .find((s) => s.kind === "ordinal" && s.ordinal === 23);
    assert.equal(
      ws2?.resolved,
      "socket",
      `${arch}: ws2_32 ordinal 23 must resolve to socket`,
    );
    assert.equal(ws2?.resolved_from_table, true);
    const unresolved = [...app.imports, ...app.delay_imports]
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

    await sign(dir("app.exe"), dir("app-signed.exe"));
    const signed = await compare(
      dir("app-signed.exe"),
      `${arch} app-signed.exe`,
    );
    const signer = signed.authenticode.entries?.[0]?.signer;
    assert.equal(signer?.status, "extracted", JSON.stringify(signer));
    assert.equal(
      signer.certificate_sha256,
      signerSha256,
      `${arch}: signer certificate differs from OpenSSL's DER`,
    );
    assert.match(signer.subject ?? "", /CN=REA Lane Signer/);
    assert.equal(signer.content_type, "1.3.6.1.4.1.311.2.1.4");
    assert.deepEqual(signed.capabilities, app.capabilities);

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
  throw new AggregateError(failures, "PE imports verification failed.");
console.log(
  JSON.stringify(
    {
      status: "passed",
      cases,
      toolchain: "mingw-w64 + pefile + llvm-readobj + openssl",
      entrypoint,
      verifier: await completeVerifierRun(run),
    },
    null,
    2,
  ),
);
