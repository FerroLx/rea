import { crc32 } from "node:zlib";

/** One stored (uncompressed) member with its exact raw name bytes. */
export interface StoredZipMember {
  readonly name: Uint8Array;
  readonly bytes: Uint8Array;
  /** General-purpose flags; bit 11 (0x0800) is the language-encoding flag. */
  readonly flags?: number;
  /** Declared uncompressed size in the central directory, if not the real one. */
  readonly declaredSize?: number;
  /** Declared compressed size in the central directory, if not the real one. */
  readonly declaredCompressedSize?: number;
  /** Compression method declared in both headers (default 0, stored). */
  readonly method?: number;
  /** Central-directory extra field bytes (the local header carries none). */
  readonly centralExtra?: Uint8Array;
  /** Central-directory comment bytes. */
  readonly centralComment?: Uint8Array;
  /** General-purpose flags in the local header only, if not `flags`. */
  readonly localFlags?: number;
  /** CRC-32 written to both headers, if not the real one. */
  readonly crc?: number;
}

/** How the archive's END (and optional zip64 END) records describe it. */
export interface StoredZipLayout {
  /** ENDTOT and the entries-on-this-disk count, if not the real count. */
  readonly endTotal?: number;
  /** END's disk number and central-directory disk, if not 0. */
  readonly endDisk?: number;
  /** Added to END's central-directory size. */
  readonly directorySizeDelta?: number;
  /** Added to END's central-directory offset. */
  readonly directoryOffsetDelta?: number;
  /** Bytes appended inside the central directory after its last record. */
  readonly directoryTrailer?: Uint8Array;
  /** END comment bytes. */
  readonly comment?: Uint8Array;
  /** END's comment length, if not the comment's real length. */
  readonly commentLength?: number;
  /** Bytes appended after END. */
  readonly trailer?: Uint8Array;
  /**
   * Write a zip64 END record and locator before END, as Commons Compress's
   * `Zip64Mode.Always` does; END keeps its real values (no 0xFFFF markers).
   * `sizeDelta` is added to the zip64 record's directory size.
   */
  readonly zip64End?: { readonly sizeDelta?: number };
}

/**
 * Write a ZIP whose member names are exactly the given bytes, so a test can
 * choose names and flags a ZIP library would normalize away.
 */
export const storedZip = (
  members: readonly StoredZipMember[],
  layout: StoredZipLayout = {},
): Buffer => {
  const local: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const member of members) {
    const crc = member.crc ?? crc32(member.bytes);
    const flags = member.flags ?? 0;
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(member.localFlags ?? flags, 6);
    header.writeUInt16LE(member.method ?? 0, 8);
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(member.bytes.length, 18);
    header.writeUInt32LE(member.bytes.length, 22);
    header.writeUInt16LE(member.name.length, 26);
    const record = Buffer.alloc(46);
    record.writeUInt32LE(0x02014b50, 0);
    record.writeUInt16LE(20, 4);
    record.writeUInt16LE(20, 6);
    record.writeUInt16LE(flags, 8);
    record.writeUInt16LE(member.method ?? 0, 10);
    record.writeUInt32LE(crc, 16);
    record.writeUInt32LE(
      member.declaredCompressedSize ?? member.bytes.length,
      20,
    );
    record.writeUInt32LE(member.declaredSize ?? member.bytes.length, 24);
    record.writeUInt16LE(member.name.length, 28);
    const extra = member.centralExtra ?? new Uint8Array(0);
    const comment = member.centralComment ?? new Uint8Array(0);
    record.writeUInt16LE(extra.length, 30);
    record.writeUInt16LE(comment.length, 32);
    record.writeUInt32LE(offset, 42);
    local.push(header, Buffer.from(member.name), Buffer.from(member.bytes));
    central.push(
      record,
      Buffer.from(member.name),
      Buffer.from(extra),
      Buffer.from(comment),
    );
    offset += 30 + member.name.length + member.bytes.length;
  }
  const directory = Buffer.concat([
    ...central,
    Buffer.from(layout.directoryTrailer ?? new Uint8Array(0)),
  ]);
  const total = layout.endTotal ?? members.length;
  const zip64: Buffer[] = [];
  if (layout.zip64End !== undefined) {
    const record = Buffer.alloc(56);
    record.writeUInt32LE(0x06064b50, 0);
    record.writeBigUInt64LE(44n, 4);
    record.writeUInt16LE(45, 12);
    record.writeUInt16LE(45, 14);
    record.writeBigUInt64LE(BigInt(total), 24);
    record.writeBigUInt64LE(BigInt(total), 32);
    record.writeBigUInt64LE(
      BigInt(directory.length + (layout.zip64End.sizeDelta ?? 0)),
      40,
    );
    record.writeBigUInt64LE(BigInt(offset), 48);
    const locator = Buffer.alloc(20);
    locator.writeUInt32LE(0x07064b50, 0);
    locator.writeBigUInt64LE(BigInt(offset + directory.length), 8);
    locator.writeUInt32LE(1, 16);
    zip64.push(record, locator);
  }
  const comment = Buffer.from(layout.comment ?? new Uint8Array(0));
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(layout.endDisk ?? 0, 4);
  end.writeUInt16LE(layout.endDisk ?? 0, 6);
  end.writeUInt16LE(total, 8);
  end.writeUInt16LE(total, 10);
  end.writeUInt32LE(directory.length + (layout.directorySizeDelta ?? 0), 12);
  end.writeUInt32LE(offset + (layout.directoryOffsetDelta ?? 0), 16);
  end.writeUInt16LE(layout.commentLength ?? comment.length, 20);
  return Buffer.concat([
    ...local,
    directory,
    ...zip64,
    end,
    comment,
    Buffer.from(layout.trailer ?? new Uint8Array(0)),
  ]);
};
