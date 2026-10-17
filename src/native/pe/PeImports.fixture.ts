interface ImportFixture {
  /** DLL name and the API names imported from it, in table order. */
  readonly imports?: readonly (readonly [string, readonly string[]])[];
  /**
   * Overrides the import data directory's declared Size (default: the exact
   * descriptor table including its terminator).
   */
  readonly importDirectorySize?: number;
  /**
   * Export names; names sharing a slot number alias one function. A slot with
   * a `forwarder` (`DLL.Function`) points into the export directory.
   */
  readonly exports?: readonly {
    readonly name: string;
    readonly slot: number;
    readonly forwarder?: string;
  }[];
  /** Extra bytes appended to the section (e.g. strings), at its end. */
  readonly data?: Buffer;
  /** Minimum section raw size (zero padding), to model large images. */
  readonly sectionBytes?: number;
  /** Declared SizeOfHeaders (default 0x400, the section's raw offset). */
  readonly sizeOfHeaders?: number;
  /**
   * Declared PointerToRawData, leaving the section's bytes at 0x400 (where a
   * sector-rounding loader reads them); the file is padded to stay in range.
   */
  readonly rawPointer?: number;
  /** Declared FileAlignment (default 0x200). */
  readonly fileAlignment?: number;
  /** File offset of the section's bytes (default 0x400). */
  readonly contentOffset?: number;
  /** Add a load configuration declaring CHPE metadata (a hybrid image). */
  readonly chpeMetadata?: boolean;
  /** COFF machine (default i386). */
  readonly machine?: number;
  /** Declare a CLI (.NET) header directory entry (its contents are not read). */
  readonly cliHeader?: boolean;
  /**
   * A certificate table appended after the section data (8-byte aligned), with
   * optional bytes after it; `offset`/`size` override the declared security
   * directory (a file offset and size).
   */
  readonly certificateTable?: {
    readonly table: Buffer;
    readonly trailing?: Buffer;
    readonly offset?: number;
    readonly size?: number;
  };
}

/**
 * A PKCS #7 SignedData produced by OpenSSL 3 (`openssl cms -sign -binary
 * -nodetach -md sha256 -nosmimecap -econtent_type 1.3.6.1.4.1.311.2.1.4`) with
 * an EC P-256 leaf "O=REA Tests, CN=REA Fixture Signer" (serial 0x00C0FFEE01)
 * issued by an embedded "CN=REA Fixture Root". Its content is not an image
 * digest: it exercises structure, never verification.
 */
export const FIXTURE_SIGNED_DATA = Buffer.from(
  "MIIEtgYJKoZIhvcNAQcCoIIEpzCCBKMCAQMxDTALBglghkgBZQMEAgEwIwYKKwYBBAGCNwIB" +
    "BKAVBBNyZWEgZml4dHVyZSBjb250ZW50oIIDVTCCAZgwggE9oAMCAQICBQDA/+4BMAoGCCqG" +
    "SM49BAMCMC8xEjAQBgNVBAoMCVJFQSBUZXN0czEZMBcGA1UEAwwQUkVBIEZpeHR1cmUgUm9v" +
    "dDAgFw0yNjEwMTcxMjE4MDRaGA8yMTI2MDkyMzEyMTgwNFowMTESMBAGA1UECgwJUkVBIFRl" +
    "c3RzMRswGQYDVQQDDBJSRUEgRml4dHVyZSBTaWduZXIwWTATBgcqhkjOPQIBBggqhkjOPQMB" +
    "BwNCAAQa3JtpPYTz5A3DqdkfVeB9HIsHTnLTNRGDNJLzOWIm4auWCspJqYRnm+cGfa+eJbPt" +
    "jxCk0ifhklB6ErRE1ZXNo0IwQDAdBgNVHQ4EFgQU4Z8f+J+ktVN25PvPkCjeOlHldh0wHwYD" +
    "VR0jBBgwFoAU7PwigFvBwHFS5zf4WxZg7ZYIw/kwCgYIKoZIzj0EAwIDSQAwRgIhAKnaRjVt" +
    "E5s2oKfxLdwo0uvXcYotP0P2DkjxrylOWeFyAiEA0hjgdrs8oNccAMp5akDfGqVRg7xqEupt" +
    "50TxZuhjJucwggG1MIIBW6ADAgECAhRlGGmTzx2VVvJtu3sYk8XIw8XX8TAKBggqhkjOPQQD" +
    "AjAvMRIwEAYDVQQKDAlSRUEgVGVzdHMxGTAXBgNVBAMMEFJFQSBGaXh0dXJlIFJvb3QwIBcN" +
    "MjYxMDE3MTIxODA0WhgPMjEyNjA5MjMxMjE4MDRaMC8xEjAQBgNVBAoMCVJFQSBUZXN0czEZ" +
    "MBcGA1UEAwwQUkVBIEZpeHR1cmUgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKH1" +
    "oNkgKxa4bwYQdp6Rs77o/MIDaH1zty4TlSlQ0lzIh7So4O93rwmbM7pze+ajBicBGKcUmalA" +
    "Ai2pSSUVJc6jUzBRMB0GA1UdDgQWBBTs/CKAW8HAcVLnN/hbFmDtlgjD+TAfBgNVHSMEGDAW" +
    "gBTs/CKAW8HAcVLnN/hbFmDtlgjD+TAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gA" +
    "MEUCIBftgqFFrDdohP8MfnDGd6Nw3qtbJNv6c81Om6lLQjTbAiEAwjGClYiEdNkW89PnLeW/" +
    "xqpSoLSTLoFFYKafwmJClHkxggEPMIIBCwIBATA4MC8xEjAQBgNVBAoMCVJFQSBUZXN0czEZ" +
    "MBcGA1UEAwwQUkVBIEZpeHR1cmUgUm9vdAIFAMD/7gEwCwYJYIZIAWUDBAIBoGowGQYJKoZI" +
    "hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MTAxNzEyMTgwNFowLwYJ" +
    "KoZIhvcNAQkEMSIEIDP2xWOOe8spvjPgfZM8QmiGZIbOXPXFCauCfX7tRAj9MAoGCCqGSM49" +
    "BAMCBEcwRQIhAMynWbOisGCWujKnbzgP7ee7mtDfka7NblAZUIsqzPYlAiBCYF5TBjYhhjCz" +
    "KQztFMCEuzPB1rYaHcl5j9hUSp7amQ==",
  "base64",
);
/** SHA-256 of the fixture leaf certificate's DER (from `openssl x509 -outform DER`). */
export const FIXTURE_SIGNER_SHA256 =
  "0f3e2b9f4b1f676dfbea49c1689820c3a05840f92fc7765805ce205cbba147e5";

const derLength = (length: number): Buffer => {
  if (length < 0x80) return Buffer.from([length]);
  const octets: number[] = [];
  for (let rest = length; rest > 0; rest = Math.floor(rest / 256))
    octets.unshift(rest % 256);
  return Buffer.from([0x80 | octets.length, ...octets]);
};
const der = (tag: number, ...parts: readonly Buffer[]): Buffer => {
  const content = Buffer.concat(parts);
  return Buffer.concat([
    Buffer.from([tag]),
    derLength(content.length),
    content,
  ]);
};
const derOid = (hex: string): Buffer => der(0x06, Buffer.from(hex, "hex"));
/** A Name of one organizationalUnitName RDN. */
const derName = (value: string): Buffer =>
  der(
    0x30,
    der(0x31, der(0x30, derOid("55040b"), der(0x0c, Buffer.from(value)))),
  );

/**
 * A structurally valid PKCS #7 SignedData whose one SignerInfo names an
 * embedded, unsigned certificate (`certificate`, its DER) by issuer and
 * serial. The certificate reuses the fixture leaf's P-256 key; its signature
 * is a placeholder, since nothing is verified. `serial` is the INTEGER's
 * content octets and `contentType` the encapsulated OID's content octets.
 */
export const craftedSignedData = ({
  serial,
  subject,
  issuer,
  contentType = Buffer.from("2b060104018237020104", "hex"),
}: {
  readonly serial: Buffer;
  readonly subject: string;
  readonly issuer: string;
  readonly contentType?: Buffer;
}): { readonly signedData: Buffer; readonly certificate: Buffer } => {
  const ecdsaSha256 = der(0x30, derOid("2a8648ce3d040302"));
  const sha256 = der(0x30, derOid("608648016503040201"));
  const time = der(0x17, Buffer.from("260101000000Z"));
  const serialNumber = der(0x02, serial);
  const issuerName = derName(issuer);
  const spki = Buffer.from(
    "3059301306072a8648ce3d020106082a8648ce3d030107034200041adc9b693d84f3e4" +
      "0dc3a9d91f55e07d1c8b074e72d33511833492f3396226e1ab960aca49a984679be7" +
      "067dafbe25b3ed8f10a4d227e192507a12b444d595cd",
    "hex",
  );
  const certificate = der(
    0x30,
    der(
      0x30,
      der(0xa0, der(0x02, Buffer.from([2]))),
      serialNumber,
      ecdsaSha256,
      issuerName,
      der(0x30, time, time),
      derName(subject),
      spki,
    ),
    ecdsaSha256,
    der(0x03, Buffer.from([0, 0])),
  );
  const signerInfo = der(
    0x30,
    der(0x02, Buffer.from([1])),
    der(0x30, issuerName, serialNumber),
    sha256,
    ecdsaSha256,
    der(0x04, Buffer.from([0])),
  );
  const signedData = der(
    0x30,
    derOid("2a864886f70d010702"),
    der(
      0xa0,
      der(
        0x30,
        der(0x02, Buffer.from([1])),
        der(0x31, sha256),
        der(0x30, der(0x06, contentType)),
        der(0xa0, certificate),
        der(0x31, signerInfo),
      ),
    ),
  );
  return { signedData, certificate };
};

/** One WIN_CERTIFICATE (dwLength, wRevision, wCertificateType), padded to 8 bytes. */
export const winCertificate = (
  payload: Buffer,
  {
    type = 2,
    revision = 0x200,
    length,
  }: {
    readonly type?: number;
    readonly revision?: number;
    readonly length?: number;
  } = {},
): Buffer => {
  const header = Buffer.alloc(8);
  header.writeUInt32LE(length ?? 8 + payload.length, 0);
  header.writeUInt16LE(revision, 4);
  header.writeUInt16LE(type, 6);
  const entry = Buffer.concat([header, payload]);
  return Buffer.concat([entry, Buffer.alloc((8 - (entry.length % 8)) % 8)]);
};

/**
 * A hand-authored PE32 image with one `.idata` section at RVA 0x2000 holding
 * import descriptors, thunks and hint/name entries, an optional export
 * directory and optional trailing data; independent of the production decoder.
 */
export const peImportFixture = ({
  imports = [],
  importDirectorySize,
  exports = [],
  data = Buffer.alloc(0),
  sectionBytes = 0,
  sizeOfHeaders,
  rawPointer,
  fileAlignment = 0x200,
  contentOffset = 0x400,
  chpeMetadata = false,
  machine = 0x14c,
  cliHeader = false,
  certificateTable,
}: ImportFixture) => {
  const SECTION_RVA = 0x2000;
  const RAW = 0x400;
  const chunks: Buffer[] = [];
  let cursor = 0;
  const allocate = (size: number, alignment = 4): number => {
    const padding = (alignment - (cursor % alignment)) % alignment;
    if (padding > 0) chunks.push(Buffer.alloc(padding));
    cursor += padding;
    const at = cursor;
    cursor += size;
    return at;
  };
  const put = (buffer: Buffer, alignment = 4): number => {
    const at = allocate(buffer.length, alignment);
    chunks.push(buffer);
    return at;
  };
  const cString = (text: string): number =>
    put(Buffer.from(`${text}\0`, "latin1"), 2);

  // Descriptors first, patched once their thunks and names exist.
  const descriptors = Buffer.alloc((imports.length + 1) * 20);
  const descriptorsAt = put(descriptors);
  imports.forEach(([dll, names], index) => {
    const nameEntries = names.map((name) => {
      const entry = Buffer.alloc(2 + name.length + 1 + ((name.length + 1) % 2));
      entry.write(name, 2, "latin1");
      return SECTION_RVA + put(entry, 2);
    });
    const thunks = Buffer.alloc((names.length + 1) * 4);
    nameEntries.forEach((rva, i) => thunks.writeUInt32LE(rva, i * 4));
    const lookupAt = put(thunks);
    const addressAt = put(Buffer.from(thunks));
    const dllAt = cString(dll);
    const at = index * 20;
    descriptors.writeUInt32LE(SECTION_RVA + lookupAt, at);
    descriptors.writeUInt32LE(SECTION_RVA + dllAt, at + 12);
    descriptors.writeUInt32LE(SECTION_RVA + addressAt, at + 16);
  });

  let exportDirectory: { rva: number; size: number } | null = null;
  if (exports.length > 0) {
    const sorted = [...exports].sort((a, b) => a.name.localeCompare(b.name));
    const functionCount = Math.max(...exports.map(({ slot }) => slot)) + 1;
    const header = Buffer.alloc(40);
    const headerAt = put(header);
    const functions = Buffer.alloc(functionCount * 4);
    for (let slot = 0; slot < functionCount; slot++)
      functions.writeUInt32LE(0x1000 + slot * 16, slot * 4);
    const functionsAt = put(functions);
    const nameRvas = sorted.map(({ name }) => SECTION_RVA + cString(name));
    const names = Buffer.alloc(sorted.length * 4);
    nameRvas.forEach((rva, i) => names.writeUInt32LE(rva, i * 4));
    const namesAt = put(names);
    const ordinals = Buffer.alloc(sorted.length * 2);
    sorted.forEach(({ slot }, i) => ordinals.writeUInt16LE(slot, i * 2));
    const ordinalsAt = put(ordinals, 2);
    const dllAt = cString("fixture.dll");
    for (const { slot, forwarder } of exports)
      if (forwarder !== undefined)
        functions.writeUInt32LE(SECTION_RVA + cString(forwarder), slot * 4);
    header.writeUInt32LE(SECTION_RVA + dllAt, 12);
    header.writeUInt32LE(1, 16); // ordinal base
    header.writeUInt32LE(functionCount, 20);
    header.writeUInt32LE(sorted.length, 24);
    header.writeUInt32LE(SECTION_RVA + functionsAt, 28);
    header.writeUInt32LE(SECTION_RVA + namesAt, 32);
    header.writeUInt32LE(SECTION_RVA + ordinalsAt, 36);
    exportDirectory = { rva: SECTION_RVA + headerAt, size: cursor - headerAt };
  }
  let loadConfig: { rva: number; size: number } | null = null;
  if (chpeMetadata) {
    // IMAGE_LOAD_CONFIG_DIRECTORY32 up to CHPEMetadataPointer (offset 124).
    const config = Buffer.alloc(128);
    config.writeUInt32LE(config.length, 0);
    config.writeUInt32LE(0x400000 + SECTION_RVA, 124);
    loadConfig = { rva: SECTION_RVA + put(config), size: config.length };
  }
  put(data, 1);

  const content = Buffer.concat(chunks);
  const rawSize =
    Math.ceil(Math.max(content.length, sectionBytes) / 512) * 512 || 512;
  const bytes = Buffer.alloc(
    Math.max(contentOffset, rawPointer ?? RAW) + rawSize,
  );
  bytes.writeUInt16LE(0x5a4d, 0);
  bytes.writeUInt32LE(0x80, 60);
  bytes.writeUInt32LE(0x4550, 0x80);
  bytes.writeUInt16LE(machine, 0x84);
  bytes.writeUInt16LE(1, 0x86); // one section
  bytes.writeUInt16LE(224, 0x94);
  bytes.writeUInt16LE(0x102, 0x96); // executable, 32-bit
  const optional = 0x98;
  bytes.writeUInt16LE(0x10b, optional);
  bytes.writeUInt32LE(0x400000, optional + 28); // ImageBase
  bytes.writeUInt32LE(0x1000, optional + 32); // SectionAlignment
  bytes.writeUInt32LE(fileAlignment, optional + 36);
  bytes.writeUInt32LE(SECTION_RVA + rawSize, optional + 56); // SizeOfImage
  bytes.writeUInt32LE(sizeOfHeaders ?? RAW, optional + 60); // SizeOfHeaders
  bytes.writeUInt16LE(3, optional + 68); // console subsystem
  bytes.writeUInt32LE(16, optional + 92);
  const directories = optional + 96;
  if (exportDirectory !== null) {
    bytes.writeUInt32LE(exportDirectory.rva, directories);
    bytes.writeUInt32LE(exportDirectory.size, directories + 4);
  }
  if (imports.length > 0) {
    bytes.writeUInt32LE(SECTION_RVA + descriptorsAt, directories + 8);
    bytes.writeUInt32LE(
      importDirectorySize ?? descriptors.length,
      directories + 12,
    );
  }
  if (cliHeader) {
    bytes.writeUInt32LE(SECTION_RVA, directories + 112);
    bytes.writeUInt32LE(72, directories + 116);
  }
  if (loadConfig !== null) {
    bytes.writeUInt32LE(loadConfig.rva, directories + 80);
    bytes.writeUInt32LE(loadConfig.size, directories + 84);
  }
  const section = optional + 224;
  bytes.write(".idata", section, "ascii");
  bytes.writeUInt32LE(rawSize, section + 8);
  bytes.writeUInt32LE(SECTION_RVA, section + 12);
  bytes.writeUInt32LE(rawSize, section + 16);
  bytes.writeUInt32LE(rawPointer ?? RAW, section + 20);
  bytes.writeUInt32LE(0xc0000040, section + 36); // initialised data, R/W
  content.copy(bytes, contentOffset);
  return certificateTable === undefined
    ? bytes
    : withCertificateTable(bytes, directories, certificateTable);
};

/** Append a certificate table at an 8-byte boundary and declare it. */
const withCertificateTable = (
  bytes: Buffer,
  directories: number,
  {
    table,
    trailing,
    offset,
    size,
  }: NonNullable<ImportFixture["certificateTable"]>,
): Buffer => {
  const tableAt = Math.ceil(bytes.length / 8) * 8;
  // IMAGE_DIRECTORY_ENTRY_SECURITY: a file offset, not an RVA.
  bytes.writeUInt32LE(offset ?? tableAt, directories + 32);
  bytes.writeUInt32LE(size ?? table.length, directories + 36);
  return Buffer.concat([
    bytes,
    Buffer.alloc(tableAt - bytes.length),
    table,
    trailing ?? Buffer.alloc(0),
  ]);
};
