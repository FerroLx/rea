import { createHash, X509Certificate } from "node:crypto";

import type { PeImportsResult } from "../../domain/native/peImports.js";
import type { PeImageLayout } from "./PeImageLayout.js";

type Authenticode = PeImportsResult["authenticode"];
type WinCertificate = Extract<
  Authenticode,
  { status: "present" }
>["entries"][number];
type Signer = WinCertificate["signer"];

/** IMAGE_DIRECTORY_ENTRY_SECURITY. */
const SECURITY_DIRECTORY = 4;
const WIN_CERTIFICATE_HEADER = 8;
/** WIN_CERTIFICATE entries listed; real images carry one. */
const ENTRY_SAMPLE = 64;
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

const decodeOid = (bytes: Buffer, tlv: Tlv): string => {
  const arcs: number[] = [];
  let value = 0;
  for (let at = tlv.content; at < tlv.end; at++) {
    const byte = bytes[at]!;
    value = value * 128 + (byte & 0x7f);
    if (value > Number.MAX_SAFE_INTEGER / 128)
      throw new DerFailure("OID arc overflows");
    if ((byte & 0x80) === 0) {
      if (arcs.length === 0) {
        const top = value < 40 ? 0 : value < 80 ? 1 : 2;
        arcs.push(top, value - top * 40);
      } else arcs.push(value);
      value = 0;
    }
  }
  if (arcs.length === 0 || (bytes[tlv.end - 1]! & 0x80) !== 0)
    throw new DerFailure("malformed OID");
  return arcs.join(".");
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

/** An INTEGER's value as upper-case hex, without its DER sign-padding byte. */
const integerHex = (bytes: Buffer, integer: Tlv): string => {
  const padded =
    integer.end - integer.content > 1 &&
    bytes[integer.content] === 0 &&
    bytes[integer.content + 1]! >= 0x80;
  return bytes
    .subarray(integer.content + (padded ? 1 : 0), integer.end)
    .toString("hex")
    .toUpperCase();
};

const nodeName = (read: () => string): string | null => {
  try {
    return read();
  } catch {
    return null;
  }
};

/**
 * Locate the signer certificate of a PKCS #7 SignedData by its first
 * SignerInfo's IssuerAndSerialNumber. Linear in the entry's bytes; it reads
 * structure only and checks no signature or digest.
 */
const readSigner = (bytes: Buffer, from: number, to: number): Signer => {
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
      return { status: "unreadable", reason: "SignedData has no SignerInfo." };
    const sid = children(
      bytes,
      expectTag(bytes, first.start, first.end, 0x30, "SignerInfo"),
    )[1];
    if (sid?.tag !== 0x30 && sid?.tag !== 0x80)
      throw new DerFailure("malformed SignerInfo identifier");
    if (sid.tag === 0x80)
      return {
        status: "unreadable",
        reason:
          "The SignerInfo identifies its signer by subjectKeyIdentifier, which is not matched.",
      };
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
      return {
        status: "unreadable",
        reason:
          "No embedded certificate matches the SignerInfo's issuer and serial number.",
      };
    const der = bytes.subarray(leaf.start, leaf.end);
    let parsed: X509Certificate | null = null;
    try {
      parsed = new X509Certificate(der);
    } catch {
      parsed = null;
    }
    return {
      status: "extracted",
      certificate_sha256: createHash("sha256").update(der).digest("hex"),
      subject: parsed === null ? null : nodeName(() => parsed.subject),
      issuer: parsed === null ? null : nodeName(() => parsed.issuer),
      serial_number: integerHex(bytes, serial),
      certificates: embedded.length,
      signer_infos: signers.length,
      content_type: decodeOid(bytes, contentType),
    };
  } catch (cause) {
    if (cause instanceof DerFailure)
      return {
        status: "unreadable",
        reason: `SignedData is not readable DER: ${cause.message}.`,
      };
    throw cause;
  }
};

/**
 * Authenticode certificate-table facts. The security directory's
 * VirtualAddress is a file offset; the table and every WIN_CERTIFICATE in it
 * are bounds-checked against the file. A defect yields `malformed` with the
 * entries read before it, never `absent`. Nothing is verified.
 */
export const readPeAuthenticode = (
  bytes: Buffer,
  layout: PeImageLayout,
): Authenticode => {
  const directory = layout.dataDirectory(SECURITY_DIRECTORY);
  if (directory === null || (directory.rva === 0 && directory.size === 0))
    return { status: "absent" };
  const table = { offset: directory.rva, size: directory.size };
  const entries: WinCertificate[] = [];
  let omitted = 0;
  const malformed = (reason: string): Authenticode => ({
    status: "malformed",
    table,
    reason,
    entries,
    entries_omitted: omitted,
    ...NOT_VERIFIED,
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
    if (entries.length < ENTRY_SAMPLE)
      entries.push({
        offset: at,
        length,
        revision,
        type,
        type_name: TYPE_NAMES[type] ?? "unknown",
        signer:
          type === 2
            ? readSigner(bytes, at + WIN_CERTIFICATE_HEADER, at + length)
            : { status: "not-examined" },
      });
    else omitted += 1;
    // Entries are quadword aligned; the last one's padding may be absent.
    at += length + ((8 - (length % 8)) % 8);
  }
  if (declaredEnd > bytes.length)
    return malformed(
      `The certificate table (file offset ${String(table.offset)}, ${String(table.size)} bytes) leaves the ${String(bytes.length)}-byte file.`,
    );
  return {
    status: "present",
    table,
    entries,
    entries_omitted: omitted,
    bytes_after_table: bytes.length - declaredEnd,
    ...NOT_VERIFIED,
  };
};
