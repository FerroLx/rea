import { describe, expect, it } from "vitest";

import {
  storedZip,
  type StoredZipLayout,
  type StoredZipMember,
} from "../../tests/fixtures/storedZip.js";
import {
  describeJdkZipException,
  readJdkZipDirectory,
  type JdkZipSource,
} from "./JdkZipCentralDirectory.js";

const memory = (bytes: Uint8Array): JdkZipSource => ({
  length: bytes.length,
  readFully: (position, length) =>
    Promise.resolve(bytes.subarray(position, position + length)),
});

const member = (
  name: string,
  overrides: Partial<StoredZipMember> = {},
): StoredZipMember => ({
  name: Buffer.from(name),
  bytes: Buffer.from(`${name} bytes`),
  ...overrides,
});

const MEMBERS = [
  member("META-INF/MANIFEST.MF"),
  member("Example.class"),
  member("other.txt"),
];

const open = (
  members: readonly StoredZipMember[] = MEMBERS,
  layout: StoredZipLayout = {},
) => readJdkZipDirectory(memory(storedZip(members, layout)), 1 << 20);

/** The JDK's refusal as `Throwable.toString()`, or the names it indexed. */
const outcome = async (
  members?: readonly StoredZipMember[],
  layout?: StoredZipLayout,
): Promise<string | readonly string[]> => {
  const directory = await open(members, layout);
  if (directory.ok) return directory.value.records.map(({ name }) => name);
  return directory.error.kind === "jdk-exception"
    ? describeJdkZipException(directory.error)
    : directory.error.kind;
};

const NAMES = ["META-INF/MANIFEST.MF", "Example.class", "other.txt"];

// Every expectation is OpenJDK 25's `new JarFile(...)` outcome on the same
// bytes (written out and probed with JDK 25.0.4).
describe("readJdkZipDirectory END handling (findEND / initCEN)", () => {
  it.each([
    ["the declared entry count", {}],
    ["an ENDTOT of 1 for 3 records (recounted)", { endTotal: 1 }],
    ["an ENDTOT of 0 for 3 records (recounted)", { endTotal: 0 }],
    ["END disk numbers of 1, which the JDK ignores", { endDisk: 1 }],
    ["END disk numbers of 0xFFFF", { endDisk: 0xffff }],
    ["a zip64 END and locator whose END holds real values", { zip64End: {} }],
    ["an END comment that reaches the end", { comment: Buffer.from("hi") }],
  ] as const)("indexes every record with %s", async (_label, layout) => {
    expect(await outcome(MEMBERS, layout)).toEqual(NAMES);
  });

  it("indexes the records an over-counted ENDTOT still fits", async () => {
    // Names long enough that 4 * 46 <= cenlen, as the JDK's check requires.
    const long = [member("x".repeat(60)), member("Example.class")];
    expect(await outcome(long, { endTotal: 3 })).toEqual([
      "x".repeat(60),
      "Example.class",
    ]);
  });

  it.each([
    [
      "an ENDTOT larger than cenlen / 46",
      { endTotal: 4 },
      "java.util.zip.ZipException: invalid END header (total entries count too large)",
    ],
    [
      "a zip64 END whose directory size disagrees with the directory",
      { zip64End: { sizeDelta: 10 } },
      "java.util.zip.ZipException: invalid CEN header (bad signature)",
    ],
    [
      "a directory offset past the start of the file",
      { directoryOffsetDelta: 10 },
      "java.util.zip.ZipException: invalid END header (bad central directory offset)",
    ],
    [
      "an END comment length past the end of the file",
      { commentLength: 5 },
      "java.io.EOFException",
    ],
    [
      "an END more than 64 KiB before the end",
      { trailer: Buffer.alloc(70_000) },
      "java.util.zip.ZipException: zip END header not found",
    ],
    [
      "a digital signature record inside the central directory",
      { directoryTrailer: Buffer.from([0x50, 0x4b, 5, 5, 0, 0]) },
      "java.util.zip.ZipException: invalid CEN header (bad header size)",
    ],
    [
      "46 zero bytes after the last record",
      { directoryTrailer: Buffer.alloc(46) },
      "java.util.zip.ZipException: invalid CEN header (bad signature)",
    ],
  ] as const)("refuses %s", async (_label, layout, refusal) => {
    expect(await outcome(MEMBERS, layout)).toBe(refusal);
  });

  it("refuses an empty file", async () => {
    const directory = await readJdkZipDirectory(memory(new Uint8Array()), 1);
    expect(directory).toEqual({
      ok: false,
      error: {
        kind: "jdk-exception",
        exception: "java.util.zip.ZipException",
        message: "zip file is empty",
      },
    });
  });

  it("bounds the directory it reads after the END checks pass", async () => {
    const bytes = storedZip(MEMBERS);
    expect(await readJdkZipDirectory(memory(bytes), 64)).toMatchObject({
      ok: false,
      error: { kind: "metadata-limit", maximum: 64 },
    });
  });
});

describe("readJdkZipDirectory record checks (checkAndAddEntry)", () => {
  const field = (tag: number, data: readonly number[]): Buffer =>
    Buffer.from([
      tag & 0xff,
      tag >> 8,
      data.length & 0xff,
      data.length >> 8,
      ...data,
    ]);

  it.each([
    [
      "an AES extra field over method 99 (the record's method is read)",
      member("other.txt", {
        method: 99,
        centralExtra: field(0x9901, [2, 0, 0x41, 0x45, 3, 8, 0]),
      }),
      "invalid CEN header (bad compression method: 99)",
    ],
    [
      "an extra field overrunning the record, naming its directory offset",
      // The record starts after 46 + 20 and 46 + 13 bytes of earlier records.
      member("other.txt", {
        centralExtra: Buffer.from([0xfe, 0xca, 9, 0, 1, 2]),
      }),
      "Invalid CEN header (invalid extra data field size for tag: 0xcafe at 125)",
    ],
    [
      "a bad name together with a bad extra field, the extra field first",
      member("", {
        name: Buffer.from([0x82, 0x2e, 0x74]),
        centralExtra: Buffer.from([0xfe, 0xca, 9, 0, 1, 2]),
      }),
      "Invalid CEN header (invalid extra data field size for tag: 0xcafe at 125)",
    ],
    [
      "a name that is not UTF-8",
      member("", { name: Buffer.from([0x82, 0x2e, 0x74]) }),
      "invalid CEN header (bad entry name or comment)",
    ],
    [
      "a zip64 marker on a record with no extra data",
      member("other.txt", { declaredCompressedSize: 0xffffffff }),
      "Invalid CEN header (invalid zip64 extra len size)",
    ],
    [
      "a zip64 block holding more than the marked values",
      member("other.txt", {
        declaredSize: 0xffffffff,
        centralExtra: field(0x0001, [...Array<number>(16).fill(0)]),
      }),
      "Invalid CEN header (invalid zip64 extra data field size)",
    ],
    [
      "a zip64 size the JDK reads as a negative long",
      member("other.txt", {
        declaredSize: 0xffffffff,
        centralExtra: field(0x0001, [1, 0, 0, 0, 0, 0, 0, 0x80]),
      }),
      "Invalid zip64 extra block size value",
    ],
    [
      "an encrypted record, before its compression method",
      member("other.txt", { flags: 1, method: 99 }),
      "invalid CEN header (encrypted entry)",
    ],
  ] as const)("refuses %s", async (_label, last, refusal) => {
    expect(await outcome([...MEMBERS.slice(0, 2), last])).toBe(
      `java.util.zip.ZipException: ${refusal}`,
    );
  });

  it("reads zip64 values from the record's zip64 block", async () => {
    const directory = await open([
      member("other.txt", {
        declaredSize: 0xffffffff,
        centralExtra: field(0x0001, [9, 0, 0, 0, 0, 0, 0, 0]),
      }),
    ]);
    if (!directory.ok) throw new Error(JSON.stringify(directory.error));
    expect(directory.value.records[0]).toMatchObject({ size: 9n });
  });
});
