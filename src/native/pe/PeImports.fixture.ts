interface ImportFixture {
  /** DLL name and the API names imported from it, in table order. */
  readonly imports?: readonly (readonly [string, readonly string[]])[];
  /**
   * Overrides the import data directory's declared Size (default: the exact
   * descriptor table including its terminator).
   */
  readonly importDirectorySize?: number;
  /** Export names; names sharing a slot number alias one function. */
  readonly exports?: readonly {
    readonly name: string;
    readonly slot: number;
  }[];
  /** Extra bytes appended to the section (e.g. strings), at its end. */
  readonly data?: Buffer;
  /** Minimum section raw size (zero padding), to model large images. */
  readonly sectionBytes?: number;
}

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
    header.writeUInt32LE(SECTION_RVA + dllAt, 12);
    header.writeUInt32LE(1, 16); // ordinal base
    header.writeUInt32LE(functionCount, 20);
    header.writeUInt32LE(sorted.length, 24);
    header.writeUInt32LE(SECTION_RVA + functionsAt, 28);
    header.writeUInt32LE(SECTION_RVA + namesAt, 32);
    header.writeUInt32LE(SECTION_RVA + ordinalsAt, 36);
    exportDirectory = { rva: SECTION_RVA + headerAt, size: 40 };
  }
  put(data, 1);

  const content = Buffer.concat(chunks);
  const rawSize =
    Math.ceil(Math.max(content.length, sectionBytes) / 512) * 512 || 512;
  const bytes = Buffer.alloc(RAW + rawSize);
  bytes.writeUInt16LE(0x5a4d, 0);
  bytes.writeUInt32LE(0x80, 60);
  bytes.writeUInt32LE(0x4550, 0x80);
  bytes.writeUInt16LE(0x14c, 0x84); // i386
  bytes.writeUInt16LE(1, 0x86); // one section
  bytes.writeUInt16LE(224, 0x94);
  bytes.writeUInt16LE(0x102, 0x96); // executable, 32-bit
  const optional = 0x98;
  bytes.writeUInt16LE(0x10b, optional);
  bytes.writeUInt32LE(0x400000, optional + 28); // ImageBase
  bytes.writeUInt32LE(0x1000, optional + 32); // SectionAlignment
  bytes.writeUInt32LE(0x200, optional + 36); // FileAlignment
  bytes.writeUInt32LE(SECTION_RVA + rawSize, optional + 56); // SizeOfImage
  bytes.writeUInt32LE(RAW, optional + 60); // SizeOfHeaders
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
  const section = optional + 224;
  bytes.write(".idata", section, "ascii");
  bytes.writeUInt32LE(rawSize, section + 8);
  bytes.writeUInt32LE(SECTION_RVA, section + 12);
  bytes.writeUInt32LE(rawSize, section + 16);
  bytes.writeUInt32LE(RAW, section + 20);
  bytes.writeUInt32LE(0xc0000040, section + 36); // initialised data, R/W
  content.copy(bytes, RAW);
  return bytes;
};
