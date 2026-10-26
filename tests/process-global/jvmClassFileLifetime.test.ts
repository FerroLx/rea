import { createHash } from "node:crypto";
import { writeFile, type FileHandle } from "node:fs/promises";
import { join } from "node:path";

import { Uint8ArrayReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const fault = vi.hoisted(() => ({
  path: "",
  /** Handles (by open order for `path`) whose close is denied. */
  denied: new Set<number>(),
  handles: [] as FileHandle[],
  /** Called on the first stat of the handle at this open index. */
  onFirstStat: undefined as { index: number; run: () => void } | undefined,
  /** Called before the close of the handle at this open index. */
  onClose: undefined as { index: number; run: () => void } | undefined,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...original,
    open: async (...arguments_: Parameters<typeof original.open>) => {
      const handle = await original.open(...arguments_);
      if (String(arguments_[0]) !== fault.path) return handle;
      const index = fault.handles.length;
      fault.handles.push(handle);
      const close = handle.close.bind(handle);
      const stat = handle.stat.bind(handle);
      let stats = 0;
      handle.stat = (async (...rest: Parameters<typeof stat>) => {
        stats += 1;
        if (stats === 1 && fault.onFirstStat?.index === index)
          fault.onFirstStat.run();
        return stat(...rest);
      }) as typeof handle.stat;
      handle.close = async () => {
        if (fault.onClose?.index === index) fault.onClose.run();
        if (fault.denied.has(index))
          throw new Error("controlled JVM descriptor close failure");
        await close();
      };
      return handle;
    },
  };
});

import { JvmClassFileProvider } from "../../src/jvm/JvmClassFileProvider.js";
import { JvmDebugMetadataService } from "../../src/application/jvm/JvmDebugMetadataService.js";
import { AnalysisError } from "../../src/domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../../src/domain/analysisErrorCore.js";
import { projectAnalysisError } from "../../src/domain/analysisErrorProjection.js";
import { ProviderAdapterError } from "../../src/domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../src/domain/providerCleanupError.js";
import { createServer } from "../../src/server/createServer.js";
import { createTestBinarySession } from "../fixtures/binarySession.js";
import { javaClassFile } from "../fixtures/javaClassFile.js";
import { parseMcpToolError } from "../fixtures/mcpToolError.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { mcpTest } from "../support/mcp/mcpFixture.js";

const ENTRY = "Hello.class";

beforeEach(() => {
  fault.path = "";
  fault.denied.clear();
  fault.handles = [];
  fault.onFirstStat = undefined;
  fault.onClose = undefined;
});

afterEach(() => {
  vi.restoreAllMocks();
});

const looseClass = async () => {
  const root = await createTestTempDirectory("rea-jvm-lifetime-");
  const path = join(root, "Hello.class");
  await writeFile(path, javaClassFile());
  fault.path = path;
  return path;
};

const jarFile = async () => {
  const root = await createTestTempDirectory("rea-jvm-lifetime-");
  const path = join(root, "app.jar");
  const writer = new ZipWriter(new Uint8ArrayWriter());
  await writer.add(ENTRY, new Uint8ArrayReader(javaClassFile()));
  await writeFile(path, await writer.close());
  fault.path = path;
  return path;
};

/**
 * The loose path peeks the magic through one descriptor and reads through a
 * second; the JAR path admits exactly one descriptor for the whole inspection.
 */
const shapes = [
  ["loose .class", looseClass, (path: string) => ({ path }), 1],
  ["JAR entry", jarFile, (path: string) => ({ path, entry: ENTRY }), 0],
] as const;

it.each(shapes)(
  "%s: a failed final close keeps the result's facts, retains the handle, and clears after close()",
  async (shape, select, inputFor, finalIndex) => {
    const path = await select();
    const provider = new JvmClassFileProvider();
    fault.denied.add(finalIndex);
    const result = await provider.inspect(inputFor(path));
    if (result.ok) throw new Error("Expected unconfirmed cleanup");
    const error = result.error;
    expect(error.cleanupIncomplete).toBe(true);
    expect(error.cleanupResources).toEqual([path]);
    expect(fault.handles[finalIndex]?.fd).toBeGreaterThanOrEqual(0);
    const projected = projectAnalysisError(error);
    expect(projected.code).toBe("cleanup_incomplete");
    if (shape === "JAR entry") {
      // The member was fully read and decoded: the Evidence is retained.
      expect(error).toBeInstanceOf(ProviderCleanupError);
      expect(error.partialObservation).toMatchObject({
        operation: "inspect_jvm_debug_metadata",
        parameters: { path, entry: ENTRY },
        normalized_result: { selected_entry: { entry: ENTRY } },
      });
    } else {
      // The stable read completed but its close did not confirm, so the
      // primary is an execution failure of the read, not caller input; the
      // completed digest and size are retained.
      expect(projected.details).toMatchObject({
        diagnostics: { primary_error: { code: "execution_failure" } },
      });
      expect(error.partialObservation).toEqual({
        kind: "file-snapshot-hash",
        path,
        sha256: createHash("sha256").update(javaClassFile()).digest("hex"),
        bytes: javaClassFile().length,
      });
    }

    // close() while the handle still cannot close: a bound cleanup error.
    const whileFailing = await provider.close().then(
      () => undefined,
      (cause: unknown) => cause,
    );
    expect(whileFailing).toBeInstanceOf(ProviderCleanupError);
    expect((whileFailing as AnalysisError).cleanupIncomplete).toBe(true);
    expect(error.cleanupIncomplete).toBe(true);

    fault.denied.clear();
    await provider.close();
    expect(fault.handles.every((handle) => handle.fd === -1)).toBe(true);
    expect(error.cleanupIncomplete).toBe(false);
    expect((whileFailing as AnalysisError).cleanupIncomplete).toBe(false);

    // A closed provider admits no new work; that is not a caller input error.
    const afterClose = await provider.inspect(inputFor(path));
    expect(afterClose.ok).toBe(false);
    if (afterClose.ok) return;
    expect(afterClose.error).toBeInstanceOf(ProviderAdapterError);
    expect(projectAnalysisError(afterClose.error).code).toBe(
      "execution_failure",
    );
  },
);

it.each(shapes)(
  "%s: cancellation during the confirmed final close keeps the abort reason",
  async (shape, select, inputFor, finalIndex) => {
    const path = await select();
    const provider = new JvmClassFileProvider();
    const controller = new AbortController();
    const reason = new Error("cancel during the final descriptor close");
    fault.onClose = { index: finalIndex, run: () => controller.abort(reason) };
    try {
      const result = await provider.inspect(inputFor(path), {
        signal: controller.signal,
      });
      if (result.ok) throw new Error("Expected late cancellation");
      expect(result.error).toBeInstanceOf(AnalysisCancelledError);
      expect(result.error.cause).toBe(reason);
      expect(result.error.cleanupIncomplete).toBe(false);
      if (shape === "JAR entry")
        expect(result.error.partialObservation).toMatchObject({
          parameters: { path, entry: ENTRY },
        });
      else
        expect(result.error.partialObservation).toMatchObject({
          kind: "file-snapshot-hash",
          path,
          bytes: javaClassFile().length,
        });
      expect(fault.handles.every((handle) => handle.fd === -1)).toBe(true);
    } finally {
      await provider.close();
    }
  },
);

it.each(shapes)(
  "%s: cancellation with a failed final close keeps the reason and the retained owner",
  async (_shape, select, inputFor, finalIndex) => {
    const path = await select();
    const provider = new JvmClassFileProvider();
    const controller = new AbortController();
    const reason = new Error("cancel during a failed descriptor close");
    fault.onClose = { index: finalIndex, run: () => controller.abort(reason) };
    fault.denied.add(finalIndex);
    const result = await provider.inspect(inputFor(path), {
      signal: controller.signal,
    });
    if (result.ok) throw new Error("Expected cancellation");
    const aggregate = result.error.cause as AggregateError;
    expect(aggregate.errors[0]).toBeInstanceOf(AnalysisCancelledError);
    expect((aggregate.errors[0] as Error).cause).toBe(reason);
    expect(result.error.cleanupIncomplete).toBe(true);
    fault.denied.clear();
    fault.onClose = undefined;
    await provider.close();
    expect(result.error.cleanupIncomplete).toBe(false);
    expect(fault.handles.every((handle) => handle.fd === -1)).toBe(true);
  },
);

it("JAR entry: a missing-entry refusal survives a failed archive close", async () => {
  const path = await jarFile();
  const provider = new JvmClassFileProvider();
  fault.denied.add(0);
  const result = await provider.inspect({ path, entry: "Nope.class" });
  if (result.ok) throw new Error("Expected refusal");
  const aggregate = result.error.cause as AggregateError;
  expect(aggregate.errors[0]).toBeInstanceOf(AnalysisInputError);
  expect((aggregate.errors[0] as Error & { issues: unknown }).issues).toEqual([
    expect.objectContaining({
      message: expect.stringContaining("No class entry Nope.class"),
    }),
  ]);
  expect(result.error.cleanupIncomplete).toBe(true);
  fault.denied.clear();
  await provider.close();
  expect(result.error.cleanupIncomplete).toBe(false);
});

it("JAR entry: an admission failure keeps its primary when the descriptor close also fails", async () => {
  const path = await jarFile();
  const provider = new JvmClassFileProvider();
  const primary = Object.assign(new Error("controlled admission denial"), {
    code: "EACCES",
  });
  fault.onFirstStat = {
    index: 0,
    run: () => {
      throw primary;
    },
  };
  fault.denied.add(0);
  const result = await provider.inspect({ path, entry: ENTRY });
  if (result.ok) throw new Error("Expected admission failure");
  const projected = projectAnalysisError(result.error);
  expect(projected.code).toBe("cleanup_incomplete");
  expect(projected.details).toMatchObject({
    diagnostics: { primary_error: { code: "access_denied" } },
  });
  fault.denied.clear();
  await provider.close();
  expect(result.error.cleanupIncomplete).toBe(false);
  expect(fault.handles.every((handle) => handle.fd === -1)).toBe(true);
});

it("JAR entry: cancellation during admission is typed cancellation with the caller's reason", async () => {
  const path = await jarFile();
  const provider = new JvmClassFileProvider();
  const controller = new AbortController();
  const reason = new Error("cancel during JAR admission");
  fault.onFirstStat = { index: 0, run: () => controller.abort(reason) };
  try {
    const result = await provider.inspect(
      { path, entry: ENTRY },
      { signal: controller.signal },
    );
    if (result.ok) throw new Error("Expected cancellation");
    expect(result.error).toBeInstanceOf(AnalysisCancelledError);
    expect(result.error.cause).toBe(reason);
    expect(fault.handles.every((handle) => handle.fd === -1)).toBe(true);
  } finally {
    await provider.close();
  }
});

it("service: late cancellation keeps the abort reason and the validated Evidence", async () => {
  const path = await jarFile();
  const service = new JvmDebugMetadataService(new JvmClassFileProvider());
  const controller = new AbortController();
  const reason = new Error("cancel after the provider completed");
  fault.onClose = { index: 0, run: () => controller.abort(reason) };
  try {
    const result = await service.inspect(
      { path, entry: ENTRY },
      { signal: controller.signal },
    );
    if (result.ok) throw new Error("Expected late cancellation");
    expect(result.error).toBeInstanceOf(AnalysisCancelledError);
    expect(result.error.cause).toBe(reason);
    expect(result.error.partialObservation).toMatchObject({
      operation: "inspect_jvm_debug_metadata",
      parameters: { path, entry: ENTRY },
    });
  } finally {
    await service.close();
  }
});

mcpTest(
  "MCP keeps JAR Evidence through a failed archive close and recovers on server close",
  async ({ mcp }) => {
    const path = await jarFile();
    const session = createTestBinarySession(() => {
      throw new Error("Unexpected native provider");
    });
    const server = createServer(
      { kind: "session", session },
      {
        jvmDebugMetadata: new JvmDebugMetadataService(
          new JvmClassFileProvider(),
        ),
      },
    );
    const client = await mcp.connect(server);
    fault.denied.add(0);
    try {
      const response = await client.callTool({
        name: "inspect_jvm_debug_metadata",
        arguments: { path, entry: ENTRY },
      });
      const { error } = parseMcpToolError(response);
      expect(error.code).toBe("cleanup_incomplete");
      expect(error.details).toMatchObject({
        resources: [path],
        partial_observation: {
          kind: "retained-evidence",
          evidence_id: expect.stringMatching(/^ev_/),
        },
      });
      expect(fault.handles[0]?.fd).toBeGreaterThanOrEqual(0);
      fault.denied.clear();
      await server.close();
      expect(fault.handles[0]?.fd).toBe(-1);
    } finally {
      fault.denied.clear();
      await server.close();
      await session.close();
    }
  },
);
