import { describe, expect, it } from "vitest";

import { readPeImageLayout } from "./PeImageLayout.js";
import { pefileImphash } from "./PefileImphash.js";
import { peWork } from "./PeImportTables.js";
import { peImportFixture } from "./PeImports.fixture.js";

const imphashOf = (bytes: Buffer) =>
  pefileImphash(
    bytes,
    readPeImageLayout(bytes),
    peWork(bytes.length, undefined),
  );

/**
 * A PE32 image whose import descriptor lies in the headers at RVA 0x3f0,
 * straddling pefile's header window (0x400: the lowest 0x200-aligned raw
 * pointer) while fitting inside SizeOfHeaders (0x500).
 */
const descriptorStraddlingHeaderWindow = (): Buffer => {
  const bytes = Buffer.alloc(0x700);
  bytes.writeUInt16LE(0x5a4d, 0);
  bytes.writeUInt32LE(0x80, 60);
  bytes.writeUInt32LE(0x4550, 0x80);
  bytes.writeUInt16LE(0x14c, 0x84);
  bytes.writeUInt16LE(1, 0x86);
  bytes.writeUInt16LE(224, 0x94);
  bytes.writeUInt16LE(0x102, 0x96);
  const optional = 0x98;
  bytes.writeUInt16LE(0x10b, optional);
  bytes.writeUInt32LE(0x400000, optional + 28);
  bytes.writeUInt32LE(0x1000, optional + 32);
  bytes.writeUInt32LE(0x200, optional + 36);
  bytes.writeUInt32LE(0x2000, optional + 56);
  bytes.writeUInt32LE(0x500, optional + 60); // SizeOfHeaders
  bytes.writeUInt32LE(16, optional + 92);
  bytes.writeUInt32LE(0x3f0, optional + 96 + 8); // import directory RVA
  bytes.writeUInt32LE(40, optional + 96 + 12);
  const section = optional + 224;
  bytes.write(".idata", section, "ascii");
  bytes.writeUInt32LE(0x200, section + 8);
  bytes.writeUInt32LE(0x1000, section + 12);
  bytes.writeUInt32LE(0x200, section + 16);
  bytes.writeUInt32LE(0x500, section + 20);
  // Descriptor at 0x3f0 -> thunks, hint/name and DLL name in the section.
  bytes.writeUInt32LE(0x1010, 0x3f0); // OriginalFirstThunk
  bytes.writeUInt32LE(0x1040, 0x3f0 + 12); // Name
  bytes.writeUInt32LE(0x1010, 0x3f0 + 16); // FirstThunk
  bytes.writeUInt32LE(0x1020, 0x510);
  bytes.write("Sleep", 0x522, "latin1");
  bytes.write("KERNEL32.dll", 0x540, "latin1");
  return bytes;
};

describe("pefileImphash", () => {
  it("hashes a plain import table like pefile", async () => {
    // pefile 2024.8.26 on the same bytes.
    expect(
      await imphashOf(
        peImportFixture({
          imports: [
            [
              "KERNEL32.dll",
              ["Sleep", "WriteProcessMemory", "CreateRemoteThread"],
            ],
          ],
        }),
      ),
    ).toBe("f912da22ec1b66d09c386ee92da61a68");
  });

  it("reads header bytes only within pefile's header window, not SizeOfHeaders", async () => {
    // pefile truncates the descriptor at 0x400 and lists no import.
    expect(await imphashOf(descriptorStraddlingHeaderWindow())).toBeNull();
  });
});
