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
}

/**
 * Write a ZIP whose member names are exactly the given bytes, so a test can
 * choose names and flags a ZIP library would normalize away.
 */
export const storedZip = (members: readonly StoredZipMember[]): Buffer => {
  const local: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const member of members) {
    const crc = crc32(member.bytes);
    const flags = member.flags ?? 0;
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(flags, 6);
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
    record.writeUInt16LE(extra.length, 30);
    record.writeUInt32LE(offset, 42);
    local.push(header, Buffer.from(member.name), Buffer.from(member.bytes));
    central.push(record, Buffer.from(member.name), Buffer.from(extra));
    offset += 30 + member.name.length + member.bytes.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(members.length, 8);
  end.writeUInt16LE(members.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, directory, end]);
};
