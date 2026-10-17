import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { PE_AUTHENTICODE_OUTPUT_BYTES } from "./PeAuthenticode.js";
import { analysePeImports } from "./PeImportAnalysis.js";
import {
  craftedSignedData,
  FIXTURE_SIGNED_DATA,
  FIXTURE_SIGNER_SHA256,
  peImportFixture,
  winCertificate,
} from "./PeImports.fixture.js";

const analyse = (bytes: Buffer) =>
  analysePeImports(
    bytes,
    {
      path: "/fixture.exe",
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.length,
    },
    { categories: undefined, signal: undefined },
  );

describe("PE Authenticode certificate table", () => {
  it("reads an Authenticode certificate table at its file offset and excludes it from the overlay", async () => {
    const table = winCertificate(FIXTURE_SIGNED_DATA);
    const bytes = peImportFixture({ certificateTable: { table } });
    const report = await analyse(bytes);
    const offset = bytes.length - table.length;
    expect(report.authenticode).toEqual({
      status: "present",
      table: { offset, size: table.length },
      entries: [
        {
          offset,
          length: 8 + FIXTURE_SIGNED_DATA.length,
          revision: 0x200,
          type: 2,
          type_name: "PKCS_SIGNED_DATA",
          signer: {
            status: "extracted",
            certificate_sha256: FIXTURE_SIGNER_SHA256,
            subject: "O=REA Tests\nCN=REA Fixture Signer",
            issuer: "O=REA Tests\nCN=REA Fixture Root",
            serial_number: "C0FFEE01",
            serial_number_octets: 4,
            certificates: 2,
            signer_infos: 1,
            content_type: "1.3.6.1.4.1.311.2.1.4",
            truncated: [],
          },
        },
      ],
      entries_omitted: 0,
      bytes_after_table: 0,
      verification: "not-performed",
      trust: "not-assessed",
    });
    // The table is the file's whole overlay: nothing unexplained remains.
    expect(report.packing.overlay).toBeNull();
    expect(report.limitations).toContainEqual(
      expect.stringContaining("not cryptographically verified"),
    );
  });

  it("reports data appended after the certificate table as the overlay", async () => {
    const table = winCertificate(FIXTURE_SIGNED_DATA);
    const trailing = Buffer.alloc(100, 0x41);
    const bytes = peImportFixture({ certificateTable: { table, trailing } });
    const report = await analyse(bytes);
    expect(report.authenticode).toMatchObject({
      status: "present",
      bytes_after_table: 100,
    });
    expect(report.packing.overlay).toEqual({
      offset: bytes.length - 100,
      bytes: 100,
      entropy: 0,
      certificate_table_bytes: table.length,
    });
  });

  it("reports an unsigned image as absent without a verification caveat", async () => {
    const report = await analyse(peImportFixture({}));
    expect(report.authenticode).toEqual({ status: "absent" });
    expect(report.limitations.join(" ")).not.toContain("Authenticode");
  });

  it.each([
    ["a table past the end of the file", { size: 0x10000 }, "leaves the", 1],
    ["an offset with a zero size", { size: 0 }, "zero offset or size", 0],
    ["a size with a zero offset", { offset: 0 }, "zero offset or size", 0],
  ] as const)(
    "reports %s as malformed, never absent, and keeps it in the overlay",
    async (_label, override, reason, entries) => {
      const table = winCertificate(FIXTURE_SIGNED_DATA);
      const bytes = peImportFixture({
        certificateTable: { table, ...override },
      });
      const report = await analyse(bytes);
      expect(report.authenticode).toMatchObject({
        status: "malformed",
        reason: expect.stringContaining(reason),
        verification: "not-performed",
        trust: "not-assessed",
      });
      if (report.authenticode.status === "malformed")
        expect(report.authenticode.entries).toHaveLength(entries);
      expect(report.packing.overlay).toMatchObject({
        certificate_table_bytes: 0,
      });
    },
  );

  it.each([
    ["below its 8-byte header", 4],
    ["past the certificate table", 0x10000],
  ] as const)(
    "reports a WIN_CERTIFICATE whose dwLength is %s as malformed",
    async (reason, length) => {
      const table = Buffer.concat([
        winCertificate(FIXTURE_SIGNED_DATA),
        winCertificate(Buffer.alloc(8), { length }),
      ]);
      const report = await analyse(
        peImportFixture({ certificateTable: { table } }),
      );
      expect(report.authenticode).toMatchObject({
        status: "malformed",
        reason: expect.stringContaining(reason),
        entries: [{ type_name: "PKCS_SIGNED_DATA" }],
      });
    },
  );

  it("reports a truncated WIN_CERTIFICATE header as malformed", async () => {
    const table = winCertificate(FIXTURE_SIGNED_DATA);
    const report = await analyse(
      peImportFixture({
        certificateTable: {
          table: Buffer.concat([table, Buffer.alloc(4)]),
          size: table.length + 4,
        },
      }),
    );
    expect(report.authenticode).toMatchObject({
      status: "malformed",
      reason: expect.stringContaining("truncated"),
    });
  });
});

describe("PE Authenticode signer", () => {
  it("lists non-PKCS entries without examining them and keeps unreadable SignedData explicit", async () => {
    const table = Buffer.concat([
      winCertificate(Buffer.from("x509 bytes"), { type: 1, revision: 0x100 }),
      winCertificate(FIXTURE_SIGNED_DATA.subarray(0, 200)),
      winCertificate(Buffer.alloc(4), { type: 9 }),
    ]);
    const report = await analyse(
      peImportFixture({ certificateTable: { table } }),
    );
    if (report.authenticode.status !== "present")
      throw new Error("expected a present certificate table");
    expect(
      report.authenticode.entries.map((entry) => [
        entry.type_name,
        entry.revision,
        entry.signer.status,
      ]),
    ).toEqual([
      ["X509", 0x100, "not-examined"],
      ["PKCS_SIGNED_DATA", 0x200, "unreadable"],
      ["unknown", 0x200, "not-examined"],
    ]);
  });

  it("reports a SignerInfo whose certificate is not embedded as unreadable", async () => {
    const serial = Buffer.from("020500c0ffee01", "hex");
    const signedData = Buffer.from(FIXTURE_SIGNED_DATA);
    // The last occurrence is the SignerInfo's IssuerAndSerialNumber.
    signedData[signedData.lastIndexOf(serial) + serial.length - 1] = 0x02;
    const report = await analyse(
      peImportFixture({
        certificateTable: { table: winCertificate(signedData) },
      }),
    );
    expect(report.authenticode).toMatchObject({
      status: "present",
      entries: [
        {
          signer: {
            status: "unreadable",
            reason: expect.stringContaining("No embedded certificate"),
          },
        },
      ],
    });
  });
});

/** UTF-8 bytes of a value's JSON encoding. */
const jsonBytes = (value: unknown): number =>
  Buffer.byteLength(JSON.stringify(value));

describe("PE Authenticode output bounds", () => {
  // Each code point escapes to its widest JSON form: a control character
  // Node.js renders as "\\01", a quote, and multi-byte UTF-8.
  const wide = '\u0001"\u00e9\u{1f600}'.repeat(2000);

  it("bounds the serial, names and content type while the certificate digest stays exact", async () => {
    const serial = Buffer.concat([
      Buffer.from([0x7f]),
      Buffer.alloc(300_000, 0xcd),
    ]);
    const { signedData, certificate } = craftedSignedData({
      serial,
      subject: wide,
      issuer: "x".repeat(5000),
      // 200 arcs of 1.2.<127>...: far past the rendered bound.
      contentType: Buffer.concat([
        Buffer.from([0x2a]),
        Buffer.alloc(200, 0x7f),
      ]),
    });
    const report = await analyse(
      peImportFixture({
        certificateTable: { table: winCertificate(signedData) },
      }),
    );
    if (report.authenticode.status !== "present")
      throw new Error("expected a present certificate table");
    const signer = report.authenticode.entries[0]?.signer;
    if (signer?.status !== "extracted")
      throw new Error("expected an extracted signer");
    expect(signer.certificate_sha256).toBe(
      createHash("sha256").update(certificate).digest("hex"),
    );
    expect(signer.serial_number).toBe(`7F${"CD".repeat(31)}`);
    expect(signer.serial_number_octets).toBe(serial.length);
    expect(signer.truncated).toEqual([
      "subject",
      "issuer",
      "serial_number",
      "content_type",
    ]);
    expect(signer.subject?.startsWith('OU=\\01\\"\u00e9\u{1f600}')).toBe(true);
    expect(jsonBytes(signer.subject)).toBeLessThanOrEqual(1026);
    expect(jsonBytes(signer.subject)).toBeGreaterThan(1000);
    expect(signer.issuer).toBe(`OU=${"x".repeat(1021)}`);
    expect(signer.content_type).toMatch(/^1\.2(\.127)+$/);
    expect(signer.content_type.length).toBeLessThanOrEqual(128);
    expect(jsonBytes(report.authenticode)).toBeLessThan(4096);
  });

  it("keeps a table of maximal entries within the reserved output", async () => {
    const { signedData } = craftedSignedData({
      serial: Buffer.alloc(33, 0x7f),
      subject: wide,
      issuer: wide,
      contentType: Buffer.concat([
        Buffer.from([0x2a]),
        Buffer.alloc(200, 0x7f),
      ]),
    });
    const entries = 20;
    const report = await analyse(
      peImportFixture({
        certificateTable: {
          table: Buffer.concat(
            Array.from({ length: entries }, () => winCertificate(signedData)),
          ),
        },
      }),
    );
    if (report.authenticode.status !== "present")
      throw new Error("expected a present certificate table");
    expect(report.authenticode.entries).toHaveLength(16);
    expect(report.authenticode.entries_omitted).toBe(entries - 16);
    expect(
      report.authenticode.entries.every(
        ({ signer }) =>
          signer.status === "extracted" && signer.truncated.length === 4,
      ),
    ).toBe(true);
    expect(jsonBytes(report.authenticode)).toBeLessThanOrEqual(
      PE_AUTHENTICODE_OUTPUT_BYTES,
    );
  });
});

describe("PE overlay around the certificate table", () => {
  it("excludes only SignedData entries and keeps other table bytes in the overlay", async () => {
    const hidden = Buffer.from("HIDDEN_INSIDE_FAKE_CERT_TABLE_".repeat(60));
    const signature = winCertificate(FIXTURE_SIGNED_DATA);
    const fake = winCertificate(hidden, { type: 0x1000 });
    const garbage = winCertificate(Buffer.alloc(16, 0xaa));
    const bytes = peImportFixture({
      certificateTable: { table: Buffer.concat([signature, fake, garbage]) },
    });
    const report = await analyse(bytes);
    const tableAt =
      bytes.length - signature.length - fake.length - garbage.length;
    expect(report.authenticode.status).toBe("present");
    // The unknown-type entry and the PKCS_SIGNED_DATA entry that is not DER
    // are not signatures: their headers and bytes stay in the overlay.
    expect(report.packing.overlay).toMatchObject({
      offset: tableAt + signature.length,
      bytes: fake.length + garbage.length,
      certificate_table_bytes: signature.length,
    });
    expect(report.packing.overlay?.entropy).toBeGreaterThan(3);
  });

  it("keeps non-zero bytes after the SignedData inside its entry in the overlay", async () => {
    const parked = Buffer.alloc(40, 0x5a);
    const entry = winCertificate(Buffer.concat([FIXTURE_SIGNED_DATA, parked]));
    const bytes = peImportFixture({ certificateTable: { table: entry } });
    const report = await analyse(bytes);
    const signatureBytes = 8 + FIXTURE_SIGNED_DATA.length;
    expect(report.authenticode).toMatchObject({
      status: "present",
      entries: [{ signer: { status: "extracted" } }],
    });
    expect(report.packing.overlay).toEqual({
      offset: bytes.length - entry.length + signatureBytes,
      bytes: entry.length - signatureBytes,
      entropy: expect.any(Number),
      certificate_table_bytes: signatureBytes,
    });
  });
});
