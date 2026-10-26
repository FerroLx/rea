import { describe, expect, it } from "vitest";

import {
  classifyJarEntry,
  parseVersionedJarEntry,
  resolveJarSelection,
} from "./jarClassEntry.js";

describe("classifyJarEntry", () => {
  it("recognizes the base entry", () => {
    expect(
      classifyJarEntry("com/example/Foo.class", "com/example/Foo.class"),
    ).toEqual({ release: null, path: "com/example/Foo.class" });
  });

  it("recognizes a versioned override and its release", () => {
    expect(
      classifyJarEntry(
        "META-INF/versions/17/com/example/Foo.class",
        "com/example/Foo.class",
      ),
    ).toEqual({
      release: 17,
      path: "META-INF/versions/17/com/example/Foo.class",
    });
  });

  it("ignores unrelated members and malformed version segments", () => {
    expect(
      classifyJarEntry("com/example/Bar.class", "com/example/Foo.class"),
    ).toBeUndefined();
    expect(
      classifyJarEntry(
        "META-INF/versions/x/com/example/Foo.class",
        "com/example/Foo.class",
      ),
    ).toBeUndefined();
    expect(
      classifyJarEntry(
        "META-INF/versions/17/com/example/Other.class",
        "com/example/Foo.class",
      ),
    ).toBeUndefined();
  });
});

describe("resolveJarSelection", () => {
  const base = { release: null, path: "Foo.class" } as const;
  const v17 = { release: 17, path: "META-INF/versions/17/Foo.class" } as const;
  const v21 = { release: 21, path: "META-INF/versions/21/Foo.class" } as const;

  it("selects the base entry when no release is requested", () => {
    expect(resolveJarSelection([base, v17], undefined)).toEqual({
      ok: true,
      path: "Foo.class",
      release: null,
    });
  });

  it("selects the exact requested release, never a neighbor", () => {
    expect(resolveJarSelection([base, v17, v21], 17)).toEqual({
      ok: true,
      path: "META-INF/versions/17/Foo.class",
      release: 17,
    });
  });

  it("refuses a requested release that is absent, listing alternatives", () => {
    expect(resolveJarSelection([base, v17, v21], 11)).toEqual({
      ok: false,
      reason: "release-absent",
      available: [17, 21],
    });
  });

  it("requires an explicit release when only versioned entries exist", () => {
    expect(resolveJarSelection([v17, v21], undefined)).toEqual({
      ok: false,
      reason: "release-absent",
      available: [17, 21],
    });
  });

  it("reports not-found when the entry is absent entirely", () => {
    expect(resolveJarSelection([], undefined)).toEqual({
      ok: false,
      reason: "not-found",
      available: [],
    });
  });
});

describe("parseVersionedJarEntry", () => {
  it("accepts the versions a JDK lookup can name: 9 to Integer.MAX_VALUE", () => {
    expect(parseVersionedJarEntry("META-INF/versions/9/a/Foo.class")).toEqual({
      release: 9,
      entry: "a/Foo.class",
    });
    expect(
      parseVersionedJarEntry("META-INF/versions/2147483647/a/Foo.class"),
    ).toEqual({ release: 2147483647, entry: "a/Foo.class" });
  });

  it("never presents other directories as releases", () => {
    for (const version of [
      "8", // below the first multi-release version
      "017", // zero-padded: the JDK never builds this name
      "2147483648", // beyond Integer.MAX_VALUE
      "99999999999", // audit m24: inert for the JDK at every release
      "1e3",
      "+17",
      "17 ",
      "",
    ])
      expect(
        parseVersionedJarEntry(`META-INF/versions/${version}/a/Foo.class`),
      ).toBeUndefined();
    expect(parseVersionedJarEntry("META-INF/versions/17/")).toBeUndefined();
    expect(
      parseVersionedJarEntry("meta-inf/versions/17/a/Foo.class"),
    ).toBeUndefined();
  });

  it("never versions a META-INF/ name, as JarFile.getEntry does not", () => {
    // OpenJDK 21/25: getEntry("META-INF/Foo.class") returns the base member
    // even beside META-INF/versions/17/META-INF/Foo.class; only a name outside
    // META-INF/ (matched case sensitively) is looked up per version.
    expect(
      classifyJarEntry(
        "META-INF/versions/17/META-INF/Foo.class",
        "META-INF/Foo.class",
      ),
    ).toBeUndefined();
    expect(
      parseVersionedJarEntry("META-INF/versions/17/META-INF/x/Foo.class"),
    ).toBeUndefined();
    expect(
      parseVersionedJarEntry("META-INF/versions/17/meta-inf/Foo.class"),
    ).toEqual({ release: 17, entry: "meta-inf/Foo.class" });
  });
});
