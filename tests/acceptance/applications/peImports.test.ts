import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { peImportsResultSchema } from "../../../src/domain/native/peImports.js";
import { peImportFixture } from "../../../src/native/pe/PeImports.fixture.js";
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
