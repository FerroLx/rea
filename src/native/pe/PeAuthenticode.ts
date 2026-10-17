import { createHash, X509Certificate } from "node:crypto";

import type { PeImportsResult } from "../../domain/native/peImports.js";
import type { PeImageLayout } from "./PeImageLayout.js";

type Authenticode = PeImportsResult["authenticode"];
type WinCertificate = Extract<
  Authenticode,
  { status: "present" }
>["entries"][number];
type Signer = WinCertificate["signer"];
type Truncated = Extract<Signer, { status: "extracted" }>["truncated"][number];

/** IMAGE_DIRECTORY_ENTRY_SECURITY. */
const SECURITY_DIRECTORY = 4;
const WIN_CERTIFICATE_HEADER = 8;
/**
 * WIN_CERTIFICATE entries listed; real images carry one (further signatures
 * nest inside its unsigned attributes). Later entries are counted.
 */
const ENTRY_SAMPLE = 16;
/**
 * Serial-number octets rendered. RFC 5280 4.1.2.2 caps conforming serials at
 * 20 octets; the margin covers non-conforming CAs, and longer values keep
 * their octet count.
 */
const SERIAL_OCTETS_MAX = 32;
/** UTF-8 bytes of a JSON-escaped subject or issuer string kept per name. */
const NAME_BYTES_MAX = 1024;
/** Characters of the dotted content-type OID kept. */
const OID_CHARS_MAX = 128;
/**
 * Serialized bytes one listed entry can reach: two names at NAME_BYTES_MAX, a
 * 64-character serial, a 128-character OID, a digest, every truncation marker
 * and 32-bit integers, with keys and punctuation.
 */
const ENTRY_OUTPUT_BYTES = 3 * 1024;
/**
 * Most bytes `authenticode` can serialize to: listed entries plus the table,
 * counts and a fixed-form reason. The complete result reserves it.
 */
export const PE_AUTHENTICODE_OUTPUT_BYTES =
  ENTRY_SAMPLE * ENTRY_OUTPUT_BYTES + 1024;
const TYPE_NAMES: Readonly<Record<number, WinCertificate["type_name"]>> = {
  1: "X509",
  2: "PKCS_SIGNED_DATA",
  3: "RESERVED_1",
  4: "TS_STACK_SIGNED",
};
const NOT_VERIFIED = {
  verification: "not-performed",
  trust: "not-assessed",
} as const;

/** 1.2.840.113549.1.7.2 (PKCS #7 signedData). */
const SIGNED_DATA_OID = Buffer.from("2a864886f70d010702", "hex");

class DerFailure extends Error {}

/** One DER TLV: its tag, the whole element and its content. */
interface Tlv {
  readonly tag: number;
  readonly start: number;
  readonly content: number;
  readonly end: number;
}

/**
 * Read one definite-length DER element inside [at, limit). Indefinite lengths,
 * multi-byte tags and lengths past the enclosing element are failures.
 */
const readTlv = (bytes: Buffer, at: number, limit: number): Tlv => {
  if (at + 2 > limit) throw new DerFailure("truncated DER element");
  const tag = bytes[at]!;
  if ((tag & 0x1f) === 0x1f) throw new DerFailure("multi-byte DER tag");
  const first = bytes[at + 1]!;
  let content = at + 2;
  let length = first;
  if (first === 0x80) throw new DerFailure("indefinite BER length");
  if (first > 0x80) {
    const width = first & 0x7f;
    if (width > 4 || content + width > limit)
      throw new DerFailure("unsupported or truncated DER length");
    length = 0;
    for (let index = 0; index < width; index++)
      length = length * 256 + bytes[content + index]!;
    content += width;
  }
  if (length > limit - content)
    throw new DerFailure("DER element leaves its container");
  return { tag, start: at, content, end: content + length };
};

const expectTag = (
  bytes: Buffer,
  at: number,
  limit: number,
  tag: number,
  what: string,
): Tlv => {
  const tlv = readTlv(bytes, at, limit);
  if (tlv.tag !== tag) throw new DerFailure(`expected ${what}`);
  return tlv;
};

/** Children of a constructed element, in order. */
const children = (bytes: Buffer, parent: Tlv): Tlv[] => {
  const out: Tlv[] = [];
  for (let at = parent.content; at < parent.end;) {
    const child = readTlv(bytes, at, parent.end);
    out.push(child);
    at = child.end;
  }
  return out;
};

/** Dotted OID, cut at the last whole arc within OID_CHARS_MAX characters. */
const decodeOid = (
  bytes: Buffer,
  tlv: Tlv,
): { text: string; truncated: boolean } => {
  let text = "";
  let value = 0;
  for (let at = tlv.content; at < tlv.end; at++) {
    const byte = bytes[at]!;
    value = value * 128 + (byte & 0x7f);
    if (value > Number.MAX_SAFE_INTEGER / 128)
      throw new DerFailure("OID arc overflows");
    if ((byte & 0x80) === 0) {
      let arc: string;
      if (text === "") {
        const top = value < 40 ? 0 : value < 80 ? 1 : 2;
        arc = `${String(top)}.${String(value - top * 40)}`;
      } else arc = `.${String(value)}`;
      if (text.length + arc.length > OID_CHARS_MAX)
        return { text, truncated: true };
      text += arc;
      value = 0;
    }
  }
  if (text === "" || (bytes[tlv.end - 1]! & 0x80) !== 0)
    throw new DerFailure("malformed OID");
  return { text, truncated: false };
};

const same = (bytes: Buffer, left: Tlv, right: Tlv): boolean =>
  bytes
    .subarray(left.start, left.end)
    .equals(bytes.subarray(right.start, right.end));

/** The issuer Name and serial INTEGER of a Certificate's TBSCertificate. */
const certificateIdentity = (
  bytes: Buffer,
  certificate: Tlv,
): { serial: Tlv; issuer: Tlv } => {
  const tbs = expectTag(
    bytes,
    certificate.content,
    certificate.end,
    0x30,
    "TBSCertificate",
  );
  const fields = children(bytes, tbs);
  const at = fields[0]?.tag === 0xa0 ? 1 : 0;
  const serial = fields[at];
  const issuer = fields[at + 2];
  if (serial?.tag !== 0x02 || issuer?.tag !== 0x30)
    throw new DerFailure("malformed TBSCertificate");
  return { serial, issuer };
};

/**
 * An INTEGER's value octets (without the DER sign-padding byte) and the first
 * SERIAL_OCTETS_MAX of them as upper-case hex.
 */
const serialNumber = (
  bytes: Buffer,
  integer: Tlv,
): { hex: string; octets: number } => {
  const padded =
    integer.end - integer.content > 1 &&
    bytes[integer.content] === 0 &&
    bytes[integer.content + 1]! >= 0x80;
  const from = integer.content + (padded ? 1 : 0);
  return {
    hex: bytes
      .subarray(from, Math.min(integer.end, from + SERIAL_OCTETS_MAX))
      .toString("hex")
      .toUpperCase(),
    octets: integer.end - from,
  };
};

/** The longest whole-code-point prefix whose JSON escaping fits NAME_BYTES_MAX. */
const boundedName = (value: string): { text: string; truncated: boolean } => {
  // A UTF-16 code unit escapes to at most 6 bytes ("\u001f").
  if (value.length * 6 <= NAME_BYTES_MAX)
    return { text: value, truncated: false };
  let bytes = 0;
  let end = 0;
  for (const point of value) {
    bytes += Buffer.byteLength(JSON.stringify(point)) - 2;
    if (bytes > NAME_BYTES_MAX)
      return { text: value.slice(0, end), truncated: true };
    end += point.length;
  }
  return { text: value, truncated: false };
};

/** A name Node.js renders, bounded; null when it cannot render it. */
const nodeName = (
  read: () => string,
): { text: string | null; truncated: boolean } => {
  try {
    return boundedName(read());
  } catch {
    return { text: null, truncated: false };
  }
};

/**
 * A PKCS_SIGNED_DATA entry's signer, and where its ContentInfo ends when it
 * parsed as SignedData (null otherwise).
 */
interface SignerRead {
  readonly signer: Signer;
  readonly signedDataEnd: number | null;
}

/**
 * Locate the signer certificate of a PKCS #7 SignedData by its first
 * SignerInfo's IssuerAndSerialNumber. Linear in the entry's bytes; it reads
 * structure only and checks no signature or digest.
 */
const readSigner = (bytes: Buffer, from: number, to: number): SignerRead => {
  let signedDataEnd: number | null = null;
  const result = (signer: Signer): SignerRead => ({ signer, signedDataEnd });
  try {
    const info = expectTag(bytes, from, to, 0x30, "ContentInfo");
    const oid = expectTag(bytes, info.content, info.end, 0x06, "contentType");
    if (!bytes.subarray(oid.content, oid.end).equals(SIGNED_DATA_OID))
      throw new DerFailure("ContentInfo is not PKCS #7 signedData");
    const explicit = expectTag(bytes, oid.end, info.end, 0xa0, "[0] content");
    const signed = expectTag(
      bytes,
      explicit.content,
      explicit.end,
      0x30,
      "SignedData",
    );
    const fields = children(bytes, signed);
    // version, digestAlgorithms, encapContentInfo, [0] certificates?, [1] crls?, signerInfos
    const encapsulated = fields[2];
    if (fields[0]?.tag !== 0x02 || encapsulated?.tag !== 0x30)
      throw new DerFailure("malformed SignedData");
    signedDataEnd = info.end;
    const contentType = expectTag(
      bytes,
      encapsulated.content,
      encapsulated.end,
      0x06,
      "encapsulated contentType",
    );
    const certificates =
      fields.find((field, index) => index > 2 && field.tag === 0xa0) ?? null;
    const signerInfos = fields.at(-1);
    if (signerInfos?.tag !== 0x31 || signerInfos === encapsulated)
      throw new DerFailure("SignedData has no signerInfos SET");
    const signers = children(bytes, signerInfos);
    const first = signers[0];
    if (first === undefined)
      return result({
        status: "unreadable",
        reason: "SignedData has no SignerInfo.",
      });
    const sid = children(
      bytes,
      expectTag(bytes, first.start, first.end, 0x30, "SignerInfo"),
    )[1];
    if (sid?.tag !== 0x30 && sid?.tag !== 0x80)
      throw new DerFailure("malformed SignerInfo identifier");
    if (sid.tag === 0x80)
      return result({
        status: "unreadable",
        reason:
          "The SignerInfo identifies its signer by subjectKeyIdentifier, which is not matched.",
      });
    const [issuer, serial] = children(bytes, sid);
    if (issuer?.tag !== 0x30 || serial?.tag !== 0x02)
      throw new DerFailure("malformed IssuerAndSerialNumber");
    const embedded = certificates === null ? [] : children(bytes, certificates);
    // An unreadable certificate elsewhere in the set does not hide the signer.
    const leaf = embedded.find((candidate) => {
      if (candidate.tag !== 0x30) return false;
      try {
        const identity = certificateIdentity(bytes, candidate);
        return (
          same(bytes, identity.serial, serial) &&
          same(bytes, identity.issuer, issuer)
        );
      } catch (cause) {
        if (cause instanceof DerFailure) return false;
        throw cause;
      }
    });
    if (leaf === undefined)
      return result({
        status: "unreadable",
        reason:
          "No embedded certificate matches the SignerInfo's issuer and serial number.",
      });
    const der = bytes.subarray(leaf.start, leaf.end);
    let parsed: X509Certificate | null = null;
    try {
      parsed = new X509Certificate(der);
    } catch {
      parsed = null;
    }
    const unnamed = { text: null, truncated: false };
    const subject = parsed === null ? unnamed : nodeName(() => parsed.subject);
    const issuerName =
      parsed === null ? unnamed : nodeName(() => parsed.issuer);
    const number = serialNumber(bytes, serial);
    const type = decodeOid(bytes, contentType);
    const truncated: Truncated[] = [];
    if (subject.truncated) truncated.push("subject");
    if (issuerName.truncated) truncated.push("issuer");
    if (number.octets > SERIAL_OCTETS_MAX) truncated.push("serial_number");
    if (type.truncated) truncated.push("content_type");
    return result({
      status: "extracted",
      certificate_sha256: createHash("sha256").update(der).digest("hex"),
      subject: subject.text,
      issuer: issuerName.text,
      serial_number: number.hex,
      serial_number_octets: number.octets,
      certificates: embedded.length,
      signer_infos: signers.length,
      content_type: type.text,
      truncated,
    });
  } catch (cause) {
    if (cause instanceof DerFailure)
      return result({
        status: "unreadable",
        reason: `SignedData is not readable DER: ${cause.message}.`,
      });
    throw cause;
  }
};

/** A file range [offset, end). */
export interface PeFileExtent {
  readonly offset: number;
  readonly end: number;
}

export interface PeAuthenticodeRead {
  readonly facts: Authenticode;
  /**
   * Certificate-table ranges that hold a signature, in file order: each
   * listed PKCS_SIGNED_DATA entry whose content parsed as SignedData, from its
   * header to its ContentInfo's end plus the zero bytes that follow it up to
   * the entry's quadword alignment. Other bytes in the table are not a
   * signature, and a malformed table yields none.
   */
  readonly signatures: readonly PeFileExtent[];
}

/** The end of the zero run in [from, limit). */
const zeroRunEnd = (bytes: Buffer, from: number, limit: number): number => {
  let at = from;
  while (at < limit && bytes[at] === 0) at++;
  return at;
};

/**
 * Authenticode certificate-table facts. The security directory's
 * VirtualAddress is a file offset; the table and every WIN_CERTIFICATE in it
 * are bounds-checked against the file. A defect yields `malformed` with the
 * entries read before it, never `absent`. Nothing is verified. The facts
 * serialize to at most PE_AUTHENTICODE_OUTPUT_BYTES.
 */
export const readPeAuthenticode = (
  bytes: Buffer,
  layout: PeImageLayout,
): PeAuthenticodeRead => {
  const directory = layout.dataDirectory(SECURITY_DIRECTORY);
  if (directory === null || (directory.rva === 0 && directory.size === 0))
    return { facts: { status: "absent" }, signatures: [] };
  const table = { offset: directory.rva, size: directory.size };
  const entries: WinCertificate[] = [];
  const signatures: PeFileExtent[] = [];
  let omitted = 0;
  const malformed = (reason: string): PeAuthenticodeRead => ({
    facts: {
      status: "malformed",
      table,
      reason,
      entries,
      entries_omitted: omitted,
      ...NOT_VERIFIED,
    },
    // Each extent is bounded by its own validated dwLength, so signatures read
    // before the defect stay excluded from the overlay; the defect does not.
    signatures,
  });
  if (table.offset === 0 || table.size === 0)
    return malformed(
      "The security directory declares a zero offset or size but not both.",
    );
  const declaredEnd = table.offset + table.size;
  const end = Math.min(declaredEnd, bytes.length);
  let at = table.offset;
  while (at < end) {
    if (end - at < WIN_CERTIFICATE_HEADER)
      return malformed(
        `A WIN_CERTIFICATE header at file offset ${String(at)} is truncated.`,
      );
    const length = bytes.readUInt32LE(at);
    const revision = bytes.readUInt16LE(at + 4);
    const type = bytes.readUInt16LE(at + 6);
    if (length < WIN_CERTIFICATE_HEADER)
      return malformed(
        `The WIN_CERTIFICATE at file offset ${String(at)} declares dwLength ${String(length)}, below its 8-byte header.`,
      );
    if (length > end - at)
      return malformed(
        `The WIN_CERTIFICATE at file offset ${String(at)} declares dwLength ${String(length)}, past the ${declaredEnd > bytes.length ? "file" : "certificate table"}.`,
      );
    // Entries are quadword aligned; the last one's padding may be absent.
    const next = Math.min(end, at + length + ((8 - (length % 8)) % 8));
    if (entries.length < ENTRY_SAMPLE) {
      const read =
        type === 2
          ? readSigner(bytes, at + WIN_CERTIFICATE_HEADER, at + length)
          : null;
      entries.push({
        offset: at,
        length,
        revision,
        type,
        type_name: TYPE_NAMES[type] ?? "unknown",
        signer: read?.signer ?? { status: "not-examined" },
      });
      if (read !== null && read.signedDataEnd !== null)
        signatures.push({
          offset: at,
          end: zeroRunEnd(bytes, read.signedDataEnd, next),
        });
    } else omitted += 1;
    at = next;
  }
  if (declaredEnd > bytes.length)
    return malformed(
      `The certificate table (file offset ${String(table.offset)}, ${String(table.size)} bytes) leaves the ${String(bytes.length)}-byte file.`,
    );
  return {
    facts: {
      status: "present",
      table,
      entries,
      entries_omitted: omitted,
      bytes_after_table: bytes.length - declaredEnd,
      ...NOT_VERIFIED,
    },
    signatures,
  };
};
