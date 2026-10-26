/**
 * Multi-release JAR member selection (JAR File Specification, Multi-Release
 * JARs). A class entry `E` may exist as the base `E` and as versioned overrides
 * `META-INF/versions/<N>/E`. Selection is explicit and never silently combines
 * metadata across versions: an omitted release uses the base, and a requested
 * release must match a present versioned entry or the selection is refused with
 * the available alternatives.
 */

/** `release: null` denotes the base (unversioned) entry. */
export interface JarEntryCandidate {
  readonly release: number | null;
  readonly path: string;
}

export type JarSelection =
  | {
      readonly ok: true;
      readonly path: string;
      readonly release: number | null;
    }
  | {
      readonly ok: false;
      readonly reason: "not-found" | "release-absent";
      readonly available: readonly number[];
    };

const META_INF_PREFIX = "META-INF/";
const VERSIONS_PREFIX = `${META_INF_PREFIX}versions/`;

/** The largest version the JDK's ZIP index can represent (`Integer.MAX_VALUE`). */
const MAX_JAR_VERSION = 2 ** 31 - 1;

/**
 * Split a `META-INF/versions/<N>/<entry>` path into its release and entry.
 * `<N>` must be what the JDK can name in a lookup: decimal digits without a
 * leading zero, from 9 to `Integer.MAX_VALUE`. Any other directory (non-numeric,
 * lower, zero-padded or overflowing) is an inert resource, never a release, and
 * yields `undefined`. REA lists every such release present; a running JDK only
 * consults versions up to its own feature release.
 *
 * `JarFile.getEntry` never versions a name under `META-INF/` (matched case
 * sensitively): it always returns the base member, so a
 * `META-INF/versions/<N>/META-INF/...` path overrides nothing and is a plain
 * member reachable only by its own name (checked against OpenJDK 21 and 25).
 */
export const parseVersionedJarEntry = (
  path: string,
): { readonly release: number; readonly entry: string } | undefined => {
  if (!path.startsWith(VERSIONS_PREFIX)) return undefined;
  const rest = path.slice(VERSIONS_PREFIX.length);
  const slash = rest.indexOf("/");
  if (slash <= 0) return undefined;
  const version = rest.slice(0, slash);
  if (!/^[1-9][0-9]{0,9}$/u.test(version)) return undefined;
  const release = Number(version);
  if (release < 9 || release > MAX_JAR_VERSION) return undefined;
  const entry = rest.slice(slash + 1);
  return entry === "" || entry.startsWith(META_INF_PREFIX)
    ? undefined
    : { release, entry };
};

/**
 * Classify an archive member's stored name for the requested class entry: the
 * base entry, a versioned override, or unrelated (`undefined`).
 */
export const classifyJarEntry = (
  storedName: string,
  entry: string,
): JarEntryCandidate | undefined => {
  if (storedName === entry) return { release: null, path: storedName };
  const versioned = parseVersionedJarEntry(storedName);
  return versioned?.entry === entry
    ? { release: versioned.release, path: storedName }
    : undefined;
};

/** Resolve which candidate to read for the requested release, or refuse explicitly. */
export const resolveJarSelection = (
  candidates: readonly JarEntryCandidate[],
  requestedRelease: number | undefined,
): JarSelection => {
  if (candidates.length === 0)
    return { ok: false, reason: "not-found", available: [] };
  const available = candidates
    .flatMap((c) => (c.release === null ? [] : [c.release]))
    .sort((a, b) => a - b);
  const base = candidates.find((c) => c.release === null);
  if (requestedRelease === undefined) {
    if (base !== undefined) return { ok: true, path: base.path, release: null };
    // Only versioned entries exist; require an explicit release rather than
    // guessing a version.
    return { ok: false, reason: "release-absent", available };
  }
  const match = candidates.find((c) => c.release === requestedRelease);
  if (match !== undefined)
    return { ok: true, path: match.path, release: requestedRelease };
  // The caller named a release that is not present; never silently fall back.
  return { ok: false, reason: "release-absent", available };
};
