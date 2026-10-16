import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";

export const peFailure = (message: string): never => {
  throw new ArtifactReaderFailure("format", message);
};

export const requirePeRange = (
  bytes: Buffer,
  offset: number,
  length: number,
): void => {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(length) ||
    offset < 0 ||
    length < 0 ||
    offset > bytes.length - length
  )
    peFailure(
      `PE range ${String(offset)} + ${String(length)} leaves the artifact.`,
    );
};

/** One section header's placement facts. */
export interface PeSection {
  /** Raw 8-byte name, NUL-trimmed (not a long-name string-table reference). */
  readonly name: string;
  readonly rva: number;
  readonly virtualSize: number;
  readonly offset: number;
  readonly size: number;
  readonly characteristics: number;
}

/** A data directory entry as declared. */
export interface PeDataDirectory {
  readonly rva: number;
  readonly size: number;
}

// RVA ownership follows the declared virtual extent. Raw size describes
// initialized file bytes and can include file-alignment padding; loaders may
// map page-rounded tails, but those bytes are outside the declared section.
export const virtualExtent = (section: PeSection): number =>
  section.virtualSize === 0 ? section.size : section.virtualSize;

/**
 * The single engine-free owner of PE header admission and RVA-to-file mapping.
 * It validates the MZ/PE headers, the optional header and section table, and
 * rejects overlapping raw ranges; then it maps an RVA either to an exact
 * interval (`map`) or, for null-terminated structures whose length is unknown
 * up front, to the file-backed bytes available from it within its one owning
 * section (`availableBytes`). Ambiguous or missing mappings are failures,
 * never guesses.
 */
export const readPeImageLayout = (bytes: Buffer) => {
  requirePeRange(bytes, 0, 64);
  if (bytes.readUInt16LE(0) !== 0x5a4d) peFailure("Expected an MZ PE image.");
  const pe = bytes.readUInt32LE(60);
  requirePeRange(bytes, pe, 24);
  if (bytes.readUInt32LE(pe) !== 0x4550) peFailure("Expected a PE signature.");
  const machine = bytes.readUInt16LE(pe + 4);
  const sectionCount = bytes.readUInt16LE(pe + 6);
  const timestamp = bytes.readUInt32LE(pe + 8);
  const optionalSize = bytes.readUInt16LE(pe + 20);
  const characteristics = bytes.readUInt16LE(pe + 22);
  const optional = pe + 24;
  requirePeRange(bytes, optional, optionalSize);
  if (optionalSize < 64) peFailure("Truncated PE optional header.");
  const magic = bytes.readUInt16LE(optional);
  if (magic !== 0x10b && magic !== 0x20b)
    peFailure("Unsupported PE optional header magic.");
  const pe32Plus = magic === 0x20b;
  const countAt = pe32Plus ? 108 : 92;
  const directoriesAt = countAt + 4;
  if (optionalSize < directoriesAt)
    peFailure("Truncated PE data directory count.");
  const directoryCount = bytes.readUInt32LE(optional + countAt);
  if (directoryCount > Math.floor((optionalSize - directoriesAt) / 8))
    peFailure("PE directory count exceeds its optional header.");
  const entryPoint = bytes.readUInt32LE(optional + 16);
  // ImageBase is a u4 at +28 (PE32) or a u8 at +24 (PE32+).
  const imageBase = pe32Plus
    ? bytes.readBigUInt64LE(optional + 24)
    : BigInt(bytes.readUInt32LE(optional + 28));
  const subsystem = bytes.readUInt16LE(optional + 68);
  const headerSize = bytes.readUInt32LE(optional + 60);
  const table = optional + optionalSize;
  requirePeRange(bytes, table, sectionCount * 40);
  if (headerSize < table + sectionCount * 40 || headerSize > bytes.length)
    peFailure("Invalid PE SizeOfHeaders.");
  const sections: PeSection[] = [];
  for (let index = 0; index < sectionCount; index++) {
    const at = table + index * 40;
    const nameBytes = bytes.subarray(at, at + 8);
    const nul = nameBytes.indexOf(0);
    const section: PeSection = {
      name: nameBytes.subarray(0, nul === -1 ? 8 : nul).toString("latin1"),
      rva: bytes.readUInt32LE(at + 12),
      virtualSize: bytes.readUInt32LE(at + 8),
      offset: bytes.readUInt32LE(at + 20),
      size: bytes.readUInt32LE(at + 16),
      characteristics: bytes.readUInt32LE(at + 36),
    };
    if (section.rva + virtualExtent(section) > 0x100000000)
      peFailure("PE section RVA range overflows.");
    if (section.size > 0) {
      requirePeRange(bytes, section.offset, section.size);
      if (section.offset < headerSize)
        peFailure("PE section raw bytes overlap headers.");
    }
    sections.push(section);
  }
  const backed = sections
    .filter(({ size }) => size > 0)
    .sort((left, right) => left.offset - right.offset);
  for (let index = 1; index < backed.length; index++) {
    const previous = backed[index - 1];
    const current = backed[index];
    if (
      previous !== undefined &&
      current !== undefined &&
      current.offset < previous.offset + previous.size
    )
      peFailure("PE sections have overlapping raw file ranges.");
  }

  const containingSections = (rva: number): PeSection[] =>
    sections.filter(
      (section) =>
        rva >= section.rva && rva - section.rva < virtualExtent(section),
    );

  /** Map an exact RVA interval; `subject` names it in failures (e.g. "Resource"). */
  const map = (rva: number, size: number, subject = "PE"): number => {
    const lower = subject.toLowerCase();
    if (rva + size > 0x100000000) peFailure(`${subject} RVA range overflows.`);
    const containing = containingSections(rva);
    // An empty interval reads no bytes, so the Windows loader also resolves it
    // exactly at a section's virtual end. A section starting at that RVA still
    // owns it.
    const candidates =
      size === 0 && containing.length === 0
        ? sections.filter(
            (section) =>
              virtualExtent(section) > 0 &&
              rva - section.rva === virtualExtent(section),
          )
        : containing;
    if (rva < headerSize) {
      if (
        sections.some(
          (section) =>
            section.rva < rva + size &&
            section.rva + virtualExtent(section) > rva,
        ) ||
        size > headerSize - rva
      )
        peFailure(`Ambiguous ${lower} header RVA mapping.`);
      requirePeRange(bytes, rva, size);
      return rva;
    }
    if (candidates.length !== 1)
      peFailure(`${subject} RVA has missing or overlapping section mappings.`);
    const section = candidates[0];
    if (section === undefined) return peFailure(`Missing ${lower} section.`);
    const within = rva - section.rva;
    if (size > virtualExtent(section) - within)
      peFailure(`${subject} range leaves its section's virtual size.`);
    if (within > section.size || size > section.size - within)
      peFailure(`${subject} range is not entirely file-backed in one section.`);
    // A second section starting inside the requested interval is ambiguous too.
    if (
      sections.some(
        (other) =>
          other !== section &&
          other.rva < rva + size &&
          other.rva + virtualExtent(other) > rva,
      )
    )
      peFailure(`${subject} interval intersects overlapping virtual sections.`);
    const offset = section.offset + within;
    requirePeRange(bytes, offset, size);
    return offset;
  };

  /**
   * The file offset of `rva` and the file-backed bytes available from it in its
   * single owning section (or the headers), for walking a null-terminated
   * string or a terminator-ended array whose length is not known up front.
   * `null` when the RVA is unmapped, ambiguous, or not file-backed.
   */
  const availableBytes = (
    rva: number,
  ): { readonly offset: number; readonly length: number } | null => {
    if (!Number.isSafeInteger(rva) || rva < 0 || rva >= 0x100000000)
      return null;
    if (rva < headerSize) {
      if (
        sections.some(
          (section) =>
            section.rva <= rva && rva < section.rva + virtualExtent(section),
        )
      )
        return null;
      return { offset: rva, length: headerSize - rva };
    }
    const containing = containingSections(rva);
    if (containing.length !== 1) return null;
    const section = containing[0];
    if (section === undefined) return null;
    const within = rva - section.rva;
    const backed = Math.min(section.size, virtualExtent(section)) - within;
    if (backed <= 0) return null;
    // Stop where another (overlapping) virtual section begins.
    let length = backed;
    for (const other of sections)
      if (other !== section && other.rva > rva && other.rva - rva < length)
        length = other.rva - rva;
    return { offset: section.offset + within, length };
  };

  const dataDirectory = (index: number): PeDataDirectory | null => {
    if (index < 0 || index >= directoryCount) return null;
    const at = optional + directoriesAt + index * 8;
    return { rva: bytes.readUInt32LE(at), size: bytes.readUInt32LE(at + 4) };
  };

  // Raw file bytes after the last section's raw data: an overlay.
  const rawEnd = backed.reduce(
    (end, section) => Math.max(end, section.offset + section.size),
    headerSize,
  );

  return {
    format: pe32Plus ? ("pe32-plus" as const) : ("pe32" as const),
    machine,
    timestamp,
    characteristics,
    subsystem,
    entryPoint,
    imageBase,
    headerSize,
    sections: sections as readonly PeSection[],
    directoryCount,
    directoriesAt: optional + directoriesAt,
    overlay: { offset: rawEnd, size: Math.max(0, bytes.length - rawEnd) },
    dataDirectory,
    map,
    availableBytes,
  };
};

export type PeImageLayout = ReturnType<typeof readPeImageLayout>;
