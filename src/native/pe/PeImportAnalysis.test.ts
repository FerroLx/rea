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

  it("skips an unusable descriptor and still surfaces later ones, as pefile does", async () => {
    // [benign DLL][descriptor naming no DLL and no thunks][injection DLL]
    const bytes = peImportFixture({
      imports: [["msvcrt.dll", ["printf"]], ["advapi32.dll", []], INJECTION],
    });
    const descriptorsAt = 0x400;
    bytes.fill(0, descriptorsAt + 20, descriptorsAt + 40);
    bytes.writeUInt32LE(0x7fff0000, descriptorsAt + 20 + 12); // Name unmapped
    const report = await analyse(bytes);
    expect(report.counts.unreadable).toBe(1);
    expect(report.counts.imports).toBe(4);
    expect(report.capabilities.map((c) => c.category)).toContain(
      "process_injection",
    );
    expect(report.imphash).toMatch(/^[0-9a-f]{32}$/);
  });

  it("gives up after more than five unusable descriptors when no terminator follows", async () => {
    const bytes = peImportFixture({ imports: [INJECTION] });
    bytes.fill(0xaa, 0x400 + 20); // no all-zero descriptor ever follows
    const report = await analyse(bytes);
    // The first descriptor's name is overwritten too: dropped without counting
    // toward the limit (pefile); the next six have no usable thunks and do.
    expect(report.counts.unreadable).toBe(7);
    expect(report.limitations.at(-1)).toContain("more than five descriptors");
  });

  it("does not let nameless decoy descriptors end the walk (pefile counts only empty thunks)", async () => {
    const bytes = peImportFixture({
      imports: [
        ...Array.from(
          { length: 6 },
          (_, i) => [`decoy${String(i)}.dll`, ["printf"]] as const,
        ),
        INJECTION,
      ],
    });
    for (let i = 0; i < 6; i++)
      bytes.writeUInt32LE(0x7fff0000, 0x400 + i * 20 + 12); // Name unmapped
    const report = await analyse(bytes);
    expect(report.counts.unreadable).toBe(6);
    expect(report.capabilities.map((c) => c.category)).toContain(
      "process_injection",
    );
    // pefile 2024.8.26 on the same bytes.
    expect(report.imphash).toBe("f912da22ec1b66d09c386ee92da61a68");
  });

  it("hashes a DLL name outside pefile's filename charset as *invalid*", async () => {
    const report = await analyse(
      peImportFixture({
        imports: [["ker\u0001nel.dll", ["WriteProcessMemory"]]],
      }),
    );
    // pefile 2024.8.26 on the same bytes.
    expect(report.imphash).toBe("380339ab1085cc666c191cdf275d4ade");
  });

  it("flags an address table that disagrees with the empty lookup table the loader binds", async () => {
    const bytes = peImportFixture({ imports: [INJECTION] });
    bytes.writeUInt32LE(0x2000 + 20, 0x400); // OFT -> the all-zero terminator
    const report = await analyse(bytes);
    // The loader binds nothing; the address table is evidence, not imports.
    expect(report.counts.imports).toBe(0);
    expect(report.import_table_disagreements).toEqual({
      count: 1,
      dlls: ["KERNEL32.dll"],
    });
    const injection = report.capabilities.find(
      (c) => c.category === "process_injection",
    );
    expect(injection?.apis.every((api) => api.via === "address_table")).toBe(
      true,
    );
    // pefile 2024.8.26 (which hashes the address table) on the same bytes.
    expect(report.imphash).toBe("f912da22ec1b66d09c386ee92da61a68");
  });

  it("does not flag tables that import the same symbols through separate entries", async () => {
    const report = await analyse(peImportFixture({ imports: [INJECTION] }));
    expect(report.import_table_disagreements.count).toBe(0);
  });

  it("keeps a descriptor whose DLL name has no terminator within 512 bytes", async () => {
    const report = await analyse(
      peImportFixture({
        imports: [
          ["A".repeat(600), ["WriteProcessMemory", "CreateRemoteThread"]],
        ],
      }),
    );
    expect(report.counts.imports).toBe(2);
    // pefile 2024.8.26 on the same bytes (the name truncated to 512).
    expect(report.imphash).toBe("3597690c8ad7fbfc9f8129219ab36be3");
  });
});
