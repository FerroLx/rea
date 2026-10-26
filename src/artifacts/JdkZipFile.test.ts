import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createDeflateRaw, deflateRawSync } from "node:zlib";

import { describe, expect, it } from "vitest";

import {
  storedZip,
  type StoredZipMember,
} from "../../tests/fixtures/storedZip.js";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { openRegularFile } from "../filesystem/RegularFile.js";
import { JdkZipFile, JdkZipReadFailure } from "./JdkZipFile.js";

const withJar = async <T>(
  bytes: Uint8Array,
  use: (file: JdkZipFile) => Promise<T>,
): Promise<T> => {
  const directory = await createTestTempDirectory("rea-jdk-zip-");
  const path = join(directory, "archive.jar");
  await writeFile(path, bytes);
  const admitted = await openRegularFile(path, { symlinks: "reject" });
  try {
    return await use(await JdkZipFile.open(path, admitted, 1 << 20, undefined));
  } finally {
    await admitted.handle.close();
  }
};

const readAll = async (file: JdkZipFile, name: string): Promise<Buffer> => {
  const member = file.members.find((candidate) => candidate.name === name);
  if (member === undefined) throw new Error(`no member ${name}`);
  const chunks: Uint8Array[] = [];
  for await (const chunk of file.read(member, undefined)) chunks.push(chunk);
  return Buffer.concat(chunks);
};

const deflated = (
  name: string,
  plain: Buffer,
  compressed: Uint8Array = deflateRawSync(plain),
): StoredZipMember => ({
  name: Buffer.from(name),
  bytes: compressed,
  method: 8,
  declaredSize: plain.length,
});

// Each expectation is what ZipFile.getInputStream delivers on OpenJDK 25.
describe("JdkZipFile member reads (ZipFile.getInputStream)", () => {
  it("reads stored and deflated members", async () => {
    const plain = Buffer.from("deflated ".repeat(100));
    const bytes = storedZip([
      { name: Buffer.from("a.txt"), bytes: Buffer.from("stored") },
      deflated("b.txt", plain),
    ]);
    await withJar(bytes, async (file) => {
      expect((await readAll(file, "a.txt")).toString()).toBe("stored");
      expect((await readAll(file, "b.txt")).equals(plain)).toBe(true);
    });
  });

  it("ignores the CRC and local-header flags, which the JDK never checks", async () => {
    const bytes = storedZip([
      {
        name: Buffer.from("a.txt"),
        bytes: Buffer.from("stored"),
        crc: 1,
        localFlags: 1,
      },
    ]);
    await withJar(bytes, async (file) => {
      expect((await readAll(file, "a.txt")).toString()).toBe("stored");
    });
  });

  it("ignores bytes after the end of the deflate stream", async () => {
    const plain = Buffer.from("payload");
    const compressed = Buffer.concat([
      deflateRawSync(plain),
      Buffer.from("junk"),
    ]);
    await withJar(
      storedZip([deflated("b.txt", plain, compressed)]),
      async (file) => {
        expect((await readAll(file, "b.txt")).equals(plain)).toBe(true);
      },
    );
  });

  it.each([
    [
      "a local header without its signature",
      (bytes: Buffer) => bytes.writeUInt32LE(0, 0),
      [{ name: Buffer.from("a.txt"), bytes: Buffer.from("stored") }],
      "java.util.zip.ZipException: ZipFile invalid LOC header (bad signature)",
    ],
    [
      "deflated data that ends early",
      () => undefined,
      [
        deflated(
          "a.txt",
          Buffer.from("x".repeat(64)),
          deflateRawSync(Buffer.from("x".repeat(64))).subarray(0, 2),
        ),
      ],
      "java.io.EOFException: Unexpected end of ZLIB input stream",
    ],
  ] as const)(
    "fails as the JDK does on %s",
    async (_label, corrupt, members, refusal) => {
      const bytes = storedZip(members);
      corrupt(bytes);
      await withJar(bytes, async (file) => {
        const failure = await readAll(file, "a.txt").catch(
          (cause: unknown) => cause,
        );
        expect(failure).toBeInstanceOf(JdkZipReadFailure);
        expect((failure as JdkZipReadFailure).message).toContain(refusal);
      });
    },
  );

  it("refuses output past the archive's decompression budget", async () => {
    // 257 MiB of zeros deflate to a few hundred KiB, past the 256 MiB floor.
    const plainBytes = 257 * 1024 * 1024;
    const deflater = createDeflateRaw();
    const compressed: Buffer[] = [];
    deflater.on("data", (chunk: Buffer) => compressed.push(chunk));
    const zero = Buffer.alloc(1024 * 1024);
    for (let written = 0; written < plainBytes; written += zero.length)
      if (!deflater.write(zero))
        await new Promise((resolve) => deflater.once("drain", resolve));
    const ended = new Promise((resolve) => deflater.once("end", resolve));
    deflater.end();
    await ended;
    const member = {
      name: Buffer.from("big.bin"),
      bytes: Buffer.concat(compressed),
      method: 8,
      declaredSize: 0,
    };
    await withJar(storedZip([member]), async (file) => {
      const failure = await readAll(file, "big.bin").catch(
        (cause: unknown) => cause,
      );
      expect(failure).toMatchObject({
        reason: "limit",
        limit: { key: "max_decompressed_bytes", maximum: 256 * 1024 * 1024 },
      });
    });
  }, 60_000);
});
