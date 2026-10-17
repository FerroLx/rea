import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { peImportsResultSchema } from "../../../src/domain/native/peImports.js";
import {
  craftedSignedData,
  FIXTURE_SIGNED_DATA,
  FIXTURE_SIGNER_SHA256,
  peImportFixture,
  winCertificate,
} from "../../../src/native/pe/PeImports.fixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { cliTest, type TestCli } from "../../support/cli/cliFixture.js";

const contract = toolContract("inspect_pe_imports");
const viewContract = toolContract("inspect_analysis_view");

const fixture = () =>
  peImportFixture({
    imports: [
      ["KERNEL32.dll", ["Sleep", "WriteProcessMemory", "CreateRemoteThread"]],
      ["USER32.dll", ["GetDC"]],
    ],
    exports: [
      { name: "Alpha", slot: 0 },
      { name: "Beta", slot: 0 },
      { name: "Gamma", slot: 1 },
    ],
    // More API-string hits than the summary samples, one name repeated.
    data: Buffer.from(
      [
        "socket",
        "connect",
        "WSAStartup",
        "OpenProcessToken",
        "VirtualAllocEx",
        "NtLoadDriver",
        "URLDownloadToFileW",
        "RegSetValueExW",
        "socket",
        "OpenProcessToken",
      ]
        .map((name) => `${name}\0`)
        .join(""),
      "latin1",
    ),
    certificateTable: { table: winCertificate(FIXTURE_SIGNED_DATA) },
  });

const callEvidence = async (
  client: Client,
  arguments_: Record<string, unknown>,
) => {
  const response = await client.callTool({
    name: contract.name,
    arguments: arguments_,
  });
  expect(response.isError).not.toBe(true);
  return contract.outputSchema.parse(response.structuredContent);
};

const view = async (
  client: Client,
  evidenceId: string,
  request: Record<string, unknown>,
) => {
  const response = await client.callTool({
    name: viewContract.name,
    arguments: {
      source: { kind: "retained-evidence", evidence_id: evidenceId },
      view: request,
    },
  });
  expect(response.isError).not.toBe(true);
  return viewContract.outputSchema.parse(response.structuredContent)
    .normalized_result;
};

/** CLI and MCP complete delivery are the same Evidence; omitted detail means complete. */
const expectCompleteAcrossAdapters = async (
  cli: TestCli,
  client: Client,
  path: string,
  bytes: Buffer,
) => {
  const result = await cli.run({
    arguments: ["inspect-pe-imports", path, "--json"],
  });
  expect(result.exitCode).toBe(0);
  const evidence = contract.outputSchema.parse(result.json);
  expect(evidence.subject?.digest).toMatchObject({
    sha256: createHash("sha256").update(bytes).digest("hex"),
  });
  const report = peImportsResultSchema.parse(evidence.normalized_result);
  expect(report.imports).toEqual([
    {
      dll: "KERNEL32.dll",
      symbols: [
        { kind: "name", name: "Sleep", hint: 0 },
        { kind: "name", name: "WriteProcessMemory", hint: 0 },
        { kind: "name", name: "CreateRemoteThread", hint: 0 },
      ],
    },
    { dll: "USER32.dll", symbols: [{ kind: "name", name: "GetDC", hint: 0 }] },
  ]);
  expect(report.delay_imports).toEqual([]);
  expect(report.exports.entries.map(({ name }) => name)).toEqual([
    "Alpha",
    "Beta",
    "Gamma",
  ]);
  expect(report.api_strings).toHaveLength(10);
  expect(report.runtime_resolution.api_strings).toMatchObject({
    count: 10,
    omitted: 0,
  });
  expect(report.authenticode).toMatchObject({
    status: "present",
    table: { size: winCertificate(FIXTURE_SIGNED_DATA).length },
    entries: [
      {
        length: 8 + FIXTURE_SIGNED_DATA.length,
        type_name: "PKCS_SIGNED_DATA",
        signer: {
          status: "extracted",
          certificate_sha256: FIXTURE_SIGNER_SHA256,
        },
      },
    ],
    verification: "not-performed",
    trust: "not-assessed",
  });
  // The certificate table is the file's tail, not an unexplained overlay.
  expect(report.packing.overlay).toBeNull();
  expect(evidence.parameters).toEqual({ path });
  for (const arguments_ of [{ path }, { path, detail: "complete" }]) {
    const mcp = await callEvidence(client, arguments_);
    expect(mcp.evidence_id).toBe(evidence.evidence_id);
    expect(mcp.normalized_result).toEqual(evidence.normalized_result);
  }
  return report;
};

/** Summary retains the complete Evidence and pages its tables without rereading. */
const expectSummaryAndPages = async (
  client: Client,
  path: string,
  report: ReturnType<typeof peImportsResultSchema.parse>,
) => {
  const summary = await callEvidence(client, { path, detail: "summary" });
  const projected = summary.normalized_result;
  if (!("kind" in projected) || projected.kind !== "summary")
    throw new Error("summary detail must return a summary view");
  expect(projected.parent_operation).toBe("inspect_pe_imports");
  expect(projected.artifact).toEqual({
    path,
    sha256: report.artifact.sha256,
  });
  const {
    artifact,
    imports: _imports,
    delay_imports: _delay,
    exports,
    api_strings: _strings,
    limitations,
    ...facts
  } = report;
  expect(projected.summary).toEqual({
    ...facts,
    bytes: artifact.bytes,
    export_dll_name: exports.dll_name,
  });
  expect(projected.limitations).toEqual(expect.arrayContaining(limitations));
  expect(
    projected.summary.capabilities.map(({ category }) => category),
  ).toContain("process_injection");
  const parent = projected.parent_evidence_id;

  const imports = await view(client, parent, {
    kind: "pe-imports",
    collection: "imports",
    offset: 2,
    limit: 2,
  });
  expect(imports).toMatchObject({
    kind: "pe-imports",
    parent_operation: "inspect_pe_imports",
    rows: [
      {
        descriptor: 0,
        dll: "KERNEL32.dll",
        symbol: { kind: "name", name: "CreateRemoteThread", hint: 0 },
      },
      {
        descriptor: 1,
        dll: "USER32.dll",
        symbol: { kind: "name", name: "GetDC", hint: 0 },
      },
    ],
    coverage: { status: "page", total: 4, next_offset: null, exhausted: true },
  });
  const exportsPage = await view(client, parent, {
    kind: "pe-imports",
    collection: "exports",
    offset: 0,
    limit: 2,
  });
  expect(exportsPage).toMatchObject({
    rows: report.exports.entries.slice(0, 2),
    coverage: { total: 3, next_offset: 2, exhausted: false },
  });
  // Every API-string hit pages back, beyond the summary's sample.
  const strings = [];
  for (let offset: number | null = 0; offset !== null;) {
    const page = await view(client, parent, {
      kind: "pe-imports",
      collection: "api_strings",
      offset,
      limit: 4,
    });
    if (page.kind !== "pe-imports")
      throw new Error("expected a pe-imports page");
    strings.push(...page.rows);
    offset = page.coverage.next_offset;
  }
  expect(strings).toEqual(report.api_strings);
  expect(projected.summary.runtime_resolution.api_strings.sample.length).toBe(
    8,
  );
  const delay = await view(client, parent, {
    kind: "pe-imports",
    collection: "delay_imports",
  });
  expect(delay).toMatchObject({
    rows: [],
    coverage: { status: "empty", total: 0, exhausted: true },
  });
  const wrongKind = await client.callTool({
    name: viewContract.name,
    arguments: {
      source: { kind: "retained-evidence", evidence_id: parent },
      view: { kind: "facet", facet: "linkage" },
    },
  });
  expect(wrongKind.isError).toBe(true);
};

/**
 * A signature with a 300 KB serial and long names stays a fixed-size fact in
 * complete and summary delivery, and bytes parked in a non-signature
 * certificate-table entry stay in the overlay.
 */
const expectBoundedAuthenticodeAcrossAdapters = async (
  cli: TestCli,
  client: Client,
  root: string,
) => {
  const serial = Buffer.concat([
    Buffer.from([0x7f]),
    Buffer.alloc(300_000, 0xcd),
  ]);
  const { signedData, certificate } = craftedSignedData({
    serial,
    subject: "S".repeat(4000),
    issuer: "I".repeat(4000),
  });
  const signature = winCertificate(signedData);
  const parked = winCertificate(
    Buffer.from("HIDDEN_INSIDE_FAKE_CERT_TABLE_".repeat(60)),
    { type: 0x1000 },
  );
  const bytes = peImportFixture({
    certificateTable: { table: Buffer.concat([signature, parked]) },
  });
  const path = join(root, "crafted-signature.exe");
  await writeFile(path, bytes);
  const result = await cli.run({
    arguments: ["inspect-pe-imports", path, "--json"],
  });
  expect(result.exitCode).toBe(0);
  const evidence = contract.outputSchema.parse(result.json);
  const report = peImportsResultSchema.parse(evidence.normalized_result);
  expect(report.authenticode).toMatchObject({
    status: "present",
    entries: [
      {
        type_name: "PKCS_SIGNED_DATA",
        signer: {
          status: "extracted",
          certificate_sha256: createHash("sha256")
            .update(certificate)
            .digest("hex"),
          subject: `OU=${"S".repeat(1021)}`,
          issuer: `OU=${"I".repeat(1021)}`,
          serial_number: `7F${"CD".repeat(31)}`,
          serial_number_octets: serial.length,
          content_type: "1.3.6.1.4.1.311.2.1.4",
          truncated: ["subject", "issuer", "serial_number"],
        },
      },
      {
        type: 0x1000,
        type_name: "unknown",
        signer: { status: "not-examined" },
      },
    ],
  });
  expect(JSON.stringify(report.authenticode).length).toBeLessThan(4096);
  expect(report.packing.overlay).toMatchObject({
    offset: bytes.length - parked.length,
    bytes: parked.length,
    certificate_table_bytes: signature.length,
  });
  expect(report.packing.overlay?.entropy).toBeGreaterThan(3);
  const response = await client.callTool({
    name: contract.name,
    arguments: { path, detail: "summary" },
  });
  expect(response.isError).not.toBe(true);
  expect(JSON.stringify(response.structuredContent).length).toBeLessThan(
    32 * 1024,
  );
  const summary = contract.outputSchema.parse(
    response.structuredContent,
  ).normalized_result;
  if (!("kind" in summary) || summary.kind !== "summary")
    throw new Error("summary detail must return a summary view");
  expect(summary.summary.authenticode).toEqual(report.authenticode);
  expect(summary.summary.packing.overlay).toEqual(report.packing.overlay);
};

const expectInputFailuresAcrossAdapters = async (
  cli: TestCli,
  client: Client,
  root: string,
) => {
  const malformed = join(root, "malformed.exe");
  await writeFile(malformed, Buffer.from("not a PE image"));
  for (const [path, reason] of [
    [join(root, "missing.exe"), "invalid_value"],
    [malformed, "invalid_format"],
  ] as const) {
    const result = await cli.run({
      arguments: ["inspect-pe-imports", path, "--json"],
    });
    expect(result.exitCode).toBe(1);
    expect(result.json).toMatchObject({
      code: "invalid_request",
      category: "invalid_input",
      details: {
        operation: "inspect_pe_imports",
        issues: [{ path: ["path"], reason }],
      },
    });
    for (const detail of ["complete", "summary"]) {
      const response = await client.callTool({
        name: contract.name,
        arguments: { path, detail },
      });
      expect(parseMcpToolError(response)).toEqual({ error: result.json });
    }
  }
  const valid = join(root, "valid.exe");
  for (const arguments_ of [
    { path: valid, detail: "imports" },
    { path: "relative.exe" },
    { path: valid, categories: ["bogus"] },
    { path: valid, extra: true },
  ]) {
    const rejected = await client.callTool({
      name: contract.name,
      arguments: arguments_,
    });
    expect(rejected.isError, JSON.stringify(arguments_)).toBe(true);
    expect(
      contract.outputSchema.safeParse(rejected.structuredContent).success,
    ).toBe(false);
  }
  const renamed = await cli.run({
    arguments: ["inspect-binary-imports", valid, "--json"],
  });
  expect(renamed.exitCode).not.toBe(0);
};

cliTest(
  "triages PE imports through compiled CLI and real stdio MCP with complete and summary delivery",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-pe-imports-acceptance-");
    const bytes = fixture();
    const path = join(root, "valid.exe");
    await writeFile(path, bytes);
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [resolve("scripts/rea.mjs"), "mcp"],
      cwd: process.cwd(),
      env: { PATH: process.env.PATH ?? "", REA_LOG_LEVEL: "silent" },
      stderr: "pipe",
    });
    const client = new Client({ name: "pe-imports-acceptance", version: "1" });
    try {
      await client.connect(transport);
      const inventory = await client.listTools();
      const names = inventory.tools.map(({ name }) => name);
      expect(names).toContain(contract.name);
      expect(names).not.toContain("inspect_binary_imports");
      const session = await client.callTool({
        name: "binary_session",
        arguments: {},
      });
      expect(JSON.stringify(session.structuredContent)).toContain(
        "inspect_pe_imports",
      );
      const report = await expectCompleteAcrossAdapters(
        cli,
        client,
        path,
        bytes,
      );
      await expectSummaryAndPages(client, path, report);
      await expectBoundedAuthenticodeAcrossAdapters(cli, client, root);
      await expectInputFailuresAcrossAdapters(cli, client, root);
      expect(await readFile(path)).toEqual(bytes);
      await client.ping();
    } finally {
      try {
        await client.close();
      } finally {
        await transport.close();
      }
    }
  },
  30_000,
);
