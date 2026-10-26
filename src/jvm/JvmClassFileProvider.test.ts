import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  TextReader,
  Uint8ArrayReader,
  Uint8ArrayWriter,
  ZipWriter,
} from "@zip.js/zip.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { JvmClassFileProvider } from "./JvmClassFileProvider.js";
import type { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { CONSTANT_TAG } from "../domain/jvm/javaClassFile.js";

/** Minimal valid class named com/example/Foo at the given major version. */
const minimalClass = (major: number): Uint8Array => {
  const parts: number[] = [];
  const u1 = (v: number) => parts.push(v & 0xff);
  const u2 = (v: number) => parts.push((v >> 8) & 0xff, v & 0xff);
  const u4 = (v: number) =>
    parts.push((v >>> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
  const utf8 = (text: string) => {
    const b = [...text].map((c) => c.charCodeAt(0));
    u2(b.length);
    parts.push(...b);
  };
  u4(0xcafebabe);
  u2(0); // minor
  u2(major);
  u2(6); // constant_pool_count
  u1(CONSTANT_TAG.utf8);
  utf8("<init>");
  u1(CONSTANT_TAG.utf8);
  utf8("()V");
  u1(CONSTANT_TAG.utf8);
  utf8("Code");
  u1(CONSTANT_TAG.utf8);
  utf8("com/example/Foo");
  u1(CONSTANT_TAG.class);
  u2(4);
  u2(0x0021); // access_flags
  u2(5); // this_class
  u2(0); // super_class
  u2(0); // interfaces
  u2(0); // fields
  u2(1); // methods_count
  u2(0x0001);
  u2(1);
  u2(2);
  u2(1);
  u2(3);
  u4(0); // <init>()V, one empty Code attr
  u2(0); // class attributes_count
  return Uint8Array.from(parts);
};

const ENTRY = "com/example/Foo.class";

const buildZip = async (
  files: readonly { name: string; bytes?: Uint8Array; text?: string }[],
): Promise<Uint8Array> => {
  const writer = new ZipWriter(new Uint8ArrayWriter());
  for (const file of files)
    await writer.add(
      file.name,
      file.text === undefined
        ? new Uint8ArrayReader(file.bytes!)
        : new TextReader(file.text),
    );
  return writer.close();
};

const MR_MANIFEST = "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n";
const PLAIN_MANIFEST = "Manifest-Version: 1.0\r\n\r\n";

let dir: string;
const provider = new JvmClassFileProvider();

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "rea-jvm-jar-"));
});
afterAll(async () => {
  await provider.close();
  await rm(dir, { recursive: true, force: true });
});

const writeJar = async (name: string, bytes: Uint8Array): Promise<string> => {
  const path = join(dir, name);
  await writeFile(path, bytes);
  return path;
};

const mrJar = async (): Promise<string> =>
  writeJar(
    "mr.jar",
    await buildZip([
      { name: "META-INF/MANIFEST.MF", text: MR_MANIFEST },
      { name: ENTRY, bytes: minimalClass(52) },
      {
        name: "META-INF/versions/17/com/example/Foo.class",
        bytes: minimalClass(61),
      },
    ]),
  );

describe("JvmClassFileProvider JAR entry selection", () => {
  it("selects the base entry when no release is requested", async () => {
    const result = await provider.inspect({
      path: await mrJar(),
      entry: ENTRY,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const r = result.value.result as Record<string, unknown>;
    expect(r.container).toBe("jar");
    expect((r.selected_entry as { release: number | null }).release).toBeNull();
    expect((r.class as { internal_name: string }).internal_name).toBe(
      "com/example/Foo",
    );
  });

  it("selects the explicit multi-release override, distinct from the base", async () => {
    const path = await mrJar();
    const base = await provider.inspect({ path, entry: ENTRY });
    const v17 = await provider.inspect({ path, entry: ENTRY, release: 17 });
    expect(base.ok && v17.ok).toBe(true);
    if (!base.ok || !v17.ok) return;
    const v17r = v17.value.result as {
      selected_entry: { release: number; sha256: string };
    };
    const baser = base.value.result as { selected_entry: { sha256: string } };
    expect(v17r.selected_entry.release).toBe(17);
    expect(v17r.selected_entry.sha256).not.toBe(baser.selected_entry.sha256);
  });

  it("refuses a release that is not present", async () => {
    const result = await provider.inspect({
      path: await mrJar(),
      entry: ENTRY,
      release: 11,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
  });

  it("reports a missing entry as an input error", async () => {
    const result = await provider.inspect({
      path: await mrJar(),
      entry: "com/example/Nope.class",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
  });

  it("refuses a versioned selection when the JAR is not multi-release", async () => {
    const path = await writeJar(
      "plain.jar",
      await buildZip([
        { name: "META-INF/MANIFEST.MF", text: PLAIN_MANIFEST },
        { name: ENTRY, bytes: minimalClass(52) },
        {
          name: "META-INF/versions/17/com/example/Foo.class",
          bytes: minimalClass(61),
        },
      ]),
    );
    const versioned = await provider.inspect({
      path,
      entry: ENTRY,
      release: 17,
    });
    expect(versioned.ok).toBe(false);
    if (versioned.ok) return;
    expect(versioned.error._tag).toBe("AnalysisInputError");
    // The base entry is still selectable on a non-multi-release JAR.
    const base = await provider.inspect({ path, entry: ENTRY });
    expect(base.ok).toBe(true);
  });
});

describe("JvmClassFileProvider JAR safety and format", () => {
  it("fails cleanly when entry is given but the path is not an archive", async () => {
    const loose = await writeJar("Loose.class", minimalClass(52));
    const result = await provider.inspect({ path: loose, entry: ENTRY });
    expect(result.ok).toBe(false);
  });

  it("guides the caller to entry selection when a JAR is given without entry", async () => {
    const result = await provider.inspect({ path: await mrJar() });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisUnsupportedTargetError");
    const remediation = (result.error as { remediationAction?: string })
      .remediationAction;
    expect(remediation).toContain("entry");
  });

  it("normalizes a leading slash and backslashes in the requested entry", async () => {
    const path = await mrJar();
    const backslashed = await provider.inspect({
      path,
      entry: "\\com\\example\\Foo.class",
    });
    expect(backslashed.ok).toBe(true);
    if (!backslashed.ok) return;
    const r = backslashed.value.result as {
      selected_entry: { entry: string };
    };
    expect(r.selected_entry.entry).toBe(ENTRY);
  });

  // The JDK looks members up by stored name, so a `./`-prefixed member is an
  // inert resource (audit z21/z37/z38): it neither shadows the real entry,
  // makes it ambiguous, nor supplies a release.
  it("treats './'-prefixed members as inert resources and reads the stored entry", async () => {
    const path = await writeJar(
      "dotslash.jar",
      await buildZip([
        { name: "META-INF/MANIFEST.MF", text: MR_MANIFEST },
        { name: `./${ENTRY}`, bytes: minimalClass(50) },
        { name: ENTRY, bytes: minimalClass(52) },
        {
          name: `./META-INF/versions/17/${ENTRY}`,
          bytes: minimalClass(61),
        },
      ]),
    );
    for (const entry of [ENTRY, `./${ENTRY}`]) {
      const result = await provider.inspect({ path, entry });
      if (!result.ok) throw result.error;
      const r = result.value.result as {
        selected_entry: { entry: string; release: number | null };
        class: { major_version: number };
      };
      expect(r.selected_entry).toMatchObject({ entry: ENTRY, release: null });
      expect(r.class.major_version).toBe(52);
    }
    const versioned = await provider.inspect({
      path,
      entry: ENTRY,
      release: 17,
    });
    expect(versioned.ok).toBe(false);
    if (versioned.ok) return;
    expect((versioned.error as AnalysisInputError).issues).toEqual([
      expect.objectContaining({
        path: ["release"],
        message: expect.stringContaining("not available for release 17"),
      }),
    ]);
    const onlyPrefixed = await provider.inspect({
      path: await writeJar(
        "dotslash-only.jar",
        await buildZip([{ name: `./${ENTRY}`, bytes: minimalClass(52) }]),
      ),
      entry: ENTRY,
    });
    expect(onlyPrefixed.ok).toBe(false);
    if (onlyPrefixed.ok) return;
    expect((onlyPrefixed.error as AnalysisInputError).issues).toEqual([
      expect.objectContaining({ path: ["entry"] }),
    ]);
  });

  it.each([
    ["the requested class", ENTRY],
    ["an unrelated member", "other.txt"],
    ["the manifest", "META-INF/MANIFEST.MF"],
  ])(
    "refuses the whole JAR when %s is encrypted, as JarFile does",
    async (_label, encrypted) => {
      // OpenJDK 21/25: new JarFile(...) throws "invalid CEN header (encrypted
      // entry)" for any encrypted central-directory record.
      const writer = new ZipWriter(new Uint8ArrayWriter());
      for (const name of ["META-INF/MANIFEST.MF", ENTRY, "other.txt"])
        await writer.add(
          name,
          name === ENTRY
            ? new Uint8ArrayReader(minimalClass(52))
            : new TextReader(PLAIN_MANIFEST),
          name === encrypted ? { password: "secret" } : {},
        );
      const path = await writeJar(
        `encrypted-${encrypted.replaceAll("/", "-")}.jar`,
        await writer.close(),
      );
      const result = await provider.inspect({ path, entry: ENTRY });
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect((result.error as AnalysisInputError).issues).toEqual([
        expect.objectContaining({
          path: ["path"],
          reason: "invalid_format",
          message: expect.stringContaining(
            "invalid CEN header (encrypted entry)",
          ),
        }),
      ]);
    },
  );

  it("steers a Mach-O universal binary (shared 0xCAFEBABE magic) to inspect_macho", async () => {
    // Fat header: magic CAFEBABE, nfat_arch = 2 -> u2@6 = 2, below any class major.
    const fat = Uint8Array.from([
      0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    ]);
    const path = await writeJar("universal.bin", fat);
    const result = await provider.inspect({ path });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisUnsupportedTargetError");
    const remediation = (result.error as { remediationAction?: string })
      .remediationAction;
    expect(remediation).toContain("inspect_macho");
  });

  it("refuses to follow a symlinked JAR", async () => {
    const real = await mrJar();
    const link = join(dir, "link.jar");
    await symlink(real, link);
    const result = await provider.inspect({ path: link, entry: ENTRY });
    expect(result.ok).toBe(false);
  });
});

describe("JvmClassFileProvider multi-release identity", () => {
  const VERSIONED = `META-INF/versions/17/${ENTRY}`;

  it("never selects a META-INF/versions/<N>/META-INF/ member as an override", async () => {
    // OpenJDK 21/25 JarFile.getEntry("META-INF/Foo.class") returns the base
    // member in a multi-release JAR; the versioned spelling is a plain member.
    const base = "META-INF/Foo.class";
    const nested = `META-INF/versions/17/${base}`;
    const path = await writeJar(
      "meta-inf-override.jar",
      await buildZip([
        { name: "META-INF/MANIFEST.MF", text: MR_MANIFEST },
        { name: base, bytes: minimalClass(52) },
        { name: nested, bytes: minimalClass(61) },
      ]),
    );
    const v17 = await provider.inspect({ path, entry: base, release: 17 });
    expect(v17.ok).toBe(false);
    if (v17.ok) return;
    expect((v17.error as AnalysisInputError).issues).toEqual([
      expect.objectContaining({
        path: ["release"],
        message: expect.stringContaining("none (base only)"),
      }),
    ]);
    const literal = await provider.inspect({ path, entry: nested });
    if (!literal.ok) throw literal.error;
    expect(literal.value.result).toMatchObject({
      selected_entry: { entry: nested, release: null },
      class: { major_version: 61 },
    });
  });

  it("refuses a versioned member path in a multi-release JAR and names entry + release", async () => {
    const result = await provider.inspect({
      path: await mrJar(),
      entry: VERSIONED,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
    expect((result.error as AnalysisInputError).issues).toEqual([
      expect.objectContaining({
        path: ["entry"],
        message: expect.stringContaining(`entry=${ENTRY} with release=17`),
      }),
    ]);
  });

  it("reads a versioned path in a non-multi-release JAR as the inert member it is", async () => {
    const path = await writeJar(
      "inert.jar",
      await buildZip([
        { name: "META-INF/MANIFEST.MF", text: PLAIN_MANIFEST },
        { name: VERSIONED, bytes: minimalClass(61) },
      ]),
    );
    const result = await provider.inspect({ path, entry: VERSIONED });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(
      (result.value.result as { selected_entry: { release: number | null } })
        .selected_entry.release,
    ).toBeNull();
  });

  it("says a release is required when only versioned overrides exist", async () => {
    const path = await writeJar(
      "versioned-only.jar",
      await buildZip([
        { name: "META-INF/MANIFEST.MF", text: MR_MANIFEST },
        { name: VERSIONED, bytes: minimalClass(61) },
      ]),
    );
    const result = await provider.inspect({ path, entry: ENTRY });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect((result.error as AnalysisInputError).issues).toEqual([
      expect.objectContaining({
        path: ["release"],
        message: expect.stringContaining("a release is required"),
      }),
    ]);
  });

  // The JDK finds the manifest by its stored name in any ASCII case (audit
  // m4: OpenJDK 25 multi-release true) and never through a `./` prefix (m17:
  // multi-release false), so REA must not match on the reader's logical path.
  const jarWithManifestAt = async (file: string, manifestName: string) =>
    writeJar(
      file,
      await buildZip([
        { name: manifestName, text: MR_MANIFEST },
        { name: ENTRY, bytes: minimalClass(52) },
        { name: VERSIONED, bytes: minimalClass(61) },
      ]),
    );

  it("honors a manifest stored under a different ASCII case", async () => {
    const result = await provider.inspect({
      path: await jarWithManifestAt(
        "lower-manifest.jar",
        "meta-inf/manifest.mf",
      ),
      entry: ENTRY,
      release: 17,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const r = result.value.result as {
      selected_entry: { release: number | null };
      class: { major_version: number };
    };
    expect(r.selected_entry.release).toBe(17);
    expect(r.class.major_version).toBe(61);
  });

  it("ignores a manifest stored with a ./ prefix", async () => {
    const result = await provider.inspect({
      path: await jarWithManifestAt(
        "dot-manifest.jar",
        "./META-INF/MANIFEST.MF",
      ),
      entry: ENTRY,
      release: 17,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect((result.error as AnalysisInputError).issues).toEqual([
      expect.objectContaining({
        path: ["release"],
        message: expect.stringContaining("is not a multi-release JAR"),
      }),
    ]);
  });
});

describe("JvmClassFileProvider manifest member attributes", () => {
  const VERSIONED = `META-INF/versions/17/${ENTRY}`;

  /** A multi-release JAR whose manifest carries the given external attributes. */
  const jarWithManifestAttributes = async (
    file: string,
    options: { externalFileAttributes: number; msDosCompatible?: boolean },
  ): Promise<string> => {
    const writer = new ZipWriter(new Uint8ArrayWriter());
    await writer.add("META-INF/MANIFEST.MF", new TextReader(MR_MANIFEST), {
      ...options,
    });
    await writer.add(ENTRY, new Uint8ArrayReader(minimalClass(52)));
    await writer.add(VERSIONED, new Uint8ArrayReader(minimalClass(61)));
    return writeJar(file, await writer.close());
  };

  // The JDK ignores external attributes: only a trailing "/" makes a name a
  // directory (audit z09/z10: OpenJDK 25 multi-release true).
  it.each([
    ["Unix directory mode", { externalFileAttributes: 0o040755 * 0x10000 }],
    [
      "MS-DOS directory attribute",
      { externalFileAttributes: 0x10, msDosCompatible: true },
    ],
  ])("honors a manifest stored with a %s", async (_label, options) => {
    const result = await provider.inspect({
      path: await jarWithManifestAttributes("dir-attr-manifest.jar", options),
      entry: ENTRY,
      release: 17,
    });
    if (!result.ok) throw result.error;
    const r = result.value.result as {
      selected_entry: { release: number | null };
      class: { major_version: number };
    };
    expect(r.selected_entry.release).toBe(17);
    expect(r.class.major_version).toBe(61);
  });

  it("reports multi-release status as unknown, not absent, for a symlink-moded manifest", async () => {
    const result = await provider.inspect({
      path: await jarWithManifestAttributes("symlink-manifest.jar", {
        externalFileAttributes: 0o120777 * 0x10000,
      }),
      entry: ENTRY,
      release: 17,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisUnsupportedTargetError");
    expect(result.error.message).toContain("is stored as a ZIP symlink");
    expect(result.error.message).toContain("multi-release JAR is unknown");
  });

  // The stored-name scan already proves no release holds the entry, so an
  // unreadable manifest cannot turn a definite absence into an unknown.
  it.each([
    ["without a release", undefined],
    ["with a release", 17],
  ])(
    "reports a missing entry as not found %s, whatever an unreadable manifest says",
    async (_label, release) => {
      const result = await provider.inspect({
        path: await jarWithManifestAttributes("symlink-manifest-missing.jar", {
          externalFileAttributes: 0o120777 * 0x10000,
        }),
        entry: "com/example/Missing.class",
        ...(release === undefined ? {} : { release }),
      });
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect((result.error as AnalysisInputError).issues).toEqual([
        expect.objectContaining({
          path: ["entry"],
          message: expect.stringContaining(
            "No class entry com/example/Missing.class exists",
          ),
        }),
      ]);
    },
  );

  it("refuses a symlink-moded class member as unavailable, not absent", async () => {
    const writer = new ZipWriter(new Uint8ArrayWriter());
    await writer.add(ENTRY, new Uint8ArrayReader(minimalClass(52)), {
      externalFileAttributes: 0o120777 * 0x10000,
    });
    const result = await provider.inspect({
      path: await writeJar("symlink-class.jar", await writer.close()),
      entry: ENTRY,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisUnsupportedTargetError");
    expect(result.error.message).toContain("unavailable, not absent");
  });
});

describe("JvmClassFileProvider manifest size", () => {
  const VERSIONED = `META-INF/versions/17/${ENTRY}`;

  /** A multi-release manifest padded, after its main section, to `size` bytes. */
  const paddedManifest = (size: number): string => {
    const head = `${MR_MANIFEST}Name: x\r\nX: `;
    const tail = "\r\n\r\n";
    return `${head}${"x".repeat(size - head.length - tail.length)}${tail}`;
  };

  // JarFile.getBytes refuses a manifest over jdk.jar.maxSignatureFileSize
  // (default 16,000,000 bytes) and isMultiRelease() then returns false
  // (audit z39 true at the limit, z40 false one byte over).
  it.each([
    [16_000_000, 17],
    [16_000_001, null],
  ])(
    "decides multi-release as the JDK does for a %i-byte manifest",
    async (size, release) => {
      const path = await writeJar(
        `manifest-${String(size)}.jar`,
        await buildZip([
          { name: "META-INF/MANIFEST.MF", text: paddedManifest(size) },
          { name: ENTRY, bytes: minimalClass(52) },
          { name: VERSIONED, bytes: minimalClass(61) },
        ]),
      );
      const result = await provider.inspect({
        path,
        entry: ENTRY,
        release: 17,
      });
      if (release !== null) {
        if (!result.ok) throw result.error;
        expect(
          (result.value.result as { selected_entry: { release: number } })
            .selected_entry.release,
        ).toBe(release);
        return;
      }
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect((result.error as AnalysisInputError).issues).toEqual([
        expect.objectContaining({
          path: ["release"],
          message: expect.stringContaining(
            "over the JDK's default jdk.jar.maxSignatureFileSize of 16000000 bytes",
          ),
        }),
      ]);
    },
  );
});
