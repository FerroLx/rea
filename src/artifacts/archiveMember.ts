/**
 * Shared helpers for selecting and reading one member from a ZIP-family archive
 * (JAR, APK, AAB, plain ZIP). Used by every provider that admits an archive and
 * reads a single entry, so the magic sniff, member-path normalization, and the
 * bounded buffering live in one place rather than being copied per provider.
 */
import { ArtifactReaderFailure, type ArtifactEntry } from "./ArtifactReader.js";
import type { ZipArtifactReader } from "./ZipArtifactReader.js";

/** Local-file-header, empty-archive, and spanned ZIP signatures all open with "PK". */
export const looksLikeZip = (bytes: Uint8Array): boolean =>
  bytes.length >= 2 && bytes[0] === 0x50 && bytes[1] === 0x4b;

/**
 * Canonicalize a caller-supplied archive member path to the internal form ZIP
 * entries use: forward slashes, no leading slash. A member is identified by
 * exactly this string, so normalization happens once before any match.
 */
export const normalizeArchiveMemberPath = (entry: string): string =>
  entry.replace(/\\/g, "/").replace(/^\/+/, "");

/**
 * Buffer one archive member, bounded by `maximumBytes`. Mirrors the admission a
 * streaming reader would apply: it destroys the stream and throws a tagged
 * {@link ArtifactReaderFailure} on cancellation, a non-byte chunk, or a member
 * that exceeds the budget, so a decompression bomb cannot be fully buffered.
 */
export const readArchiveMember = async (
  reader: ZipArtifactReader,
  member: ArtifactEntry,
  maximumBytes: number,
  signal: AbortSignal | undefined,
): Promise<Uint8Array> => {
  const stream = await reader.open(member, signal);
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    if (signal?.aborted) {
      stream.destroy();
      throw new ArtifactReaderFailure("cancelled", "archive read cancelled");
    }
    if (!Buffer.isBuffer(chunk)) {
      stream.destroy();
      throw new ArtifactReaderFailure(
        "format",
        "archive entry did not yield bytes",
      );
    }
    size += chunk.length;
    if (size > maximumBytes) {
      stream.destroy();
      throw new ArtifactReaderFailure(
        "limit",
        `Selected archive entry exceeds ${String(maximumBytes)} bytes`,
      );
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
};
