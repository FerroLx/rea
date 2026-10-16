import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { analysePeImports } from "./PeImportAnalysis.js";
import { peImportFixture } from "./PeImports.fixture.js";

const analyse = (bytes: Buffer, detail = false) =>
  analysePeImports(
    bytes,
    {
      path: "/fixture.exe",
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.length,
    },
    { categories: undefined, detail, signal: undefined },
  );

const INJECTION = [
  "KERNEL32.dll",
  ["Sleep", "WriteProcessMemory", "CreateRemoteThread"],
] as const;

describe("PE import analysis", () => {
  it("reads descriptors to the terminator whatever the directory Size declares", async () => {
    const exact = await analyse(peImportFixture({ imports: [INJECTION] }));
    // A declared Size of one descriptor must not hide what the loader loads.
    const understated = await analyse(
      peImportFixture({
        imports: [["USER32.dll", ["GetDC"]], INJECTION],
        importDirectorySize: 20,
      }),
    );
    expect(understated.counts.imports).toBe(4);
    expect(understated.capabilities.map((c) => c.category)).toContain(
      "process_injection",
    );
    expect(exact.counts.imports).toBe(3);
  });

  it("keeps the table-walk budget for tables, not for scanning section bytes", async () => {
    // 3000 imports in a section-heavy image without an overlay.
    const names = Array.from(
      { length: 3000 },
      (_, i) => `Function${String(i)}`,
    );
    const report = await analyse(
      peImportFixture({
        imports: [["fixture.dll", names]],
        sectionBytes: 400 * 1024,
      }),
    );
    expect(report.counts.imports).toBe(3000);
  });

  it("reports every exported name, including aliases of one function", async () => {
    const report = await analyse(
      peImportFixture({
        exports: [
          { name: "Alpha", slot: 0 },
          { name: "Beta", slot: 0 },
          { name: "Gamma", slot: 1 },
        ],
      }),
      true,
    );
    expect(report.counts.exports).toBe(3);
    expect(report.counts.exports_named).toBe(3);
    expect(
      report.detail?.exports.entries.map((e) => [e.ordinal, e.name]),
    ).toEqual([
      [1, "Alpha"],
      [1, "Beta"],
      [2, "Gamma"],
    ]);
  });

  it("finds a UTF-16 API name directly after an ASCII string's terminator", async () => {
    const data = Buffer.concat([
      Buffer.from("SomeAsciiThread\0", "latin1"),
      Buffer.from("WriteProcessMemory", "utf16le"),
      Buffer.alloc(2),
    ]);
    const report = await analyse(peImportFixture({ data }));
    expect(report.runtime_resolution.api_strings.sample).toContainEqual(
      expect.objectContaining({
        api: "WriteProcessMemory",
        encoding: "utf16le",
      }),
    );
  });
});
