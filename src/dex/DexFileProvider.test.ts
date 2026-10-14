import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Uint8ArrayReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { DexFileProvider } from "./DexFileProvider.js";
import { DEX_NO_INDEX } from "../domain/dex/dexFile.js";

/** Compact DEX fixture: class Lcom/example/Foo; method run (I)V with a local x:I. */
class DexBuilder {
  private readonly b: number[] = [];
  u1(v: number) {
    this.b.push(v & 0xff);
    return this;
  }
  u2(v: number) {
    this.b.push(v & 0xff, (v >> 8) & 0xff);
    return this;
  }
  u4(v: number) {
    this.b.push(v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff);
    return this;
  }
  uleb(v: number) {
    let n = v >>> 0;
    do {
      let x = n & 0x7f;
      n >>>= 7;
      if (n !== 0) x |= 0x80;
      this.b.push(x);
    } while (n !== 0);
    return this;
  }
  ulebp1(v: number) {
    return this.uleb(v + 1);
  }
  ascii(t: string) {
    for (const c of t) this.b.push(c.charCodeAt(0));
    return this;
  }
  at() {
    return this.b.length;
  }
  setU4(at: number, v: number) {
    this.b[at] = v & 0xff;
    this.b[at + 1] = (v >> 8) & 0xff;
    this.b[at + 2] = (v >> 16) & 0xff;
    this.b[at + 3] = (v >>> 24) & 0xff;
  }
  bytes() {
    return Uint8Array.from(this.b);
  }
}

const STRINGS = ["Foo.java", "run", "x", "Lcom/example/Foo;", "I", "V"];

const minimalDex = (): Uint8Array => {
  const d = new DexBuilder();
  for (let i = 0; i < 112; i += 1) d.u1(0);
  const dataOff = STRINGS.map((s) => {
    const off = d.at();
    d.uleb(s.length).ascii(s).u1(0);
    return off;
  });
  const stringIdsOff = d.at();
  for (const off of dataOff) d.u4(off);
  const typeIdsOff = d.at();
  for (const s of [3, 4, 5]) d.u4(s);
  const typeListOff = d.at();
  d.u4(1).u2(1);
  const protoIdsOff = d.at();
  d.u4(0).u4(2).u4(typeListOff);
  const methodIdsOff = d.at();
  d.u2(0).u2(0).u4(1);
  // static run(int): the single param "x" is an implicit local seeded at reg 0.
  const debugOff = d.at();
  d.uleb(10).uleb(1).ulebp1(2); // line_start 10, 1 param name "x"
  d.u1(0x0e).u1(0x00); // emit position, END_SEQUENCE
  const codeOff = d.at();
  d.u2(1).u2(1).u2(0).u2(0).u4(debugOff).u4(4);
  for (let i = 0; i < 4; i += 1) d.u2(0);
  const classDataOff = d.at();
  d.uleb(0).uleb(0).uleb(1).uleb(0).uleb(0).uleb(0x9).uleb(codeOff); // access public|static
  const classDefsOff = d.at();
  d.u4(0).u4(1).u4(DEX_NO_INDEX).u4(0).u4(0).u4(0).u4(classDataOff).u4(0);
  d.setU4(0, 0x0a786564);
  d.setU4(4, 0x00353330);
  d.setU4(32, d.at());
  d.setU4(36, 0x70);
  d.setU4(40, 0x12345678);
  d.setU4(56, STRINGS.length);
  d.setU4(60, stringIdsOff);
  d.setU4(64, 3);
  d.setU4(68, typeIdsOff);
  d.setU4(72, 1);
  d.setU4(76, protoIdsOff);
  d.setU4(88, 1);
  d.setU4(92, methodIdsOff);
  d.setU4(96, 1);
  d.setU4(100, classDefsOff);
  return d.bytes();
};

const buildApk = async (
  members: readonly { name: string; bytes: Uint8Array }[],
): Promise<Uint8Array> => {
  const writer = new ZipWriter(new Uint8ArrayWriter());
  for (const m of members)
    await writer.add(m.name, new Uint8ArrayReader(m.bytes));
  return writer.close();
};

let dir: string;
const provider = new DexFileProvider();

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "rea-dex-"));
});
afterAll(async () => {
  await provider.close();
  await rm(dir, { recursive: true, force: true });
});

const write = async (name: string, bytes: Uint8Array): Promise<string> => {
  const path = join(dir, name);
  await writeFile(path, bytes);
  return path;
};

describe("DexFileProvider loose .dex", () => {
  it("summarizes a loose dex with readiness present", async () => {
    const result = await provider.inspect({
      path: await write("a.dex", minimalDex()),
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const r = result.value.result as Record<string, unknown>;
    expect(r.container).toBe("dex-file");
    expect(r.mode).toBe("summary");
    const members = r.members as {
      entry: null;
      summary: { readiness: string };
    }[];
    expect(members).toHaveLength(1);
    expect(members[0]!.entry).toBeNull();
    expect(members[0]!.summary.readiness).toBe("present");
  });

  it("returns full per-method detail for a selected class", async () => {
    const result = await provider.inspect({
      path: await write("b.dex", minimalDex()),
      class_descriptor: "Lcom/example/Foo;",
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const r = result.value.result as {
      mode: string;
      class_detail: {
        source_file: string;
        methods: {
          name: string;
          descriptor: string;
          locals: { name: string | null; type: string | null }[];
        }[];
      };
    };
    expect(r.mode).toBe("class-detail");
    expect(r.class_detail.source_file).toBe("Foo.java");
    const method = r.class_detail.methods[0]!;
    expect(method.name).toBe("run");
    expect(method.descriptor).toBe("(I)V");
    // The implicit parameter local is seeded and resolved (regression guard).
    expect(method.locals).toContainEqual(
      expect.objectContaining({ name: "x", type: "I" }),
    );
  });

  it("refuses a class descriptor not present", async () => {
    const result = await provider.inspect({
      path: await write("c.dex", minimalDex()),
      class_descriptor: "LNope;",
    });
    expect(result.ok).toBe(false);
  });
});

describe("DexFileProvider APK selection", () => {
  it("summarizes every root classes*.dex when no entry is given", async () => {
    const apk = await write(
      "app.apk",
      await buildApk([
        { name: "classes.dex", bytes: minimalDex() },
        { name: "classes2.dex", bytes: minimalDex() },
        { name: "res/raw/note.txt", bytes: Uint8Array.from([1, 2, 3]) },
      ]),
    );
    const result = await provider.inspect({ path: apk });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const r = result.value.result as {
      container: string;
      members: { entry: string }[];
    };
    expect(r.container).toBe("apk");
    expect(r.members.map((m) => m.entry)).toEqual([
      "classes.dex",
      "classes2.dex",
    ]);
  });

  it("selects one dex member by entry", async () => {
    const apk = await write(
      "one.apk",
      await buildApk([{ name: "classes.dex", bytes: minimalDex() }]),
    );
    const result = await provider.inspect({ path: apk, entry: "classes.dex" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const r = result.value.result as { members: { entry: string }[] };
    expect(r.members[0]!.entry).toBe("classes.dex");
  });

  it("reports a missing entry as an input error", async () => {
    const apk = await write(
      "miss.apk",
      await buildApk([{ name: "classes.dex", bytes: minimalDex() }]),
    );
    const result = await provider.inspect({ path: apk, entry: "classes9.dex" });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
  });

  it("steers a non-dex, non-zip file to a useful refusal", async () => {
    const result = await provider.inspect({
      path: await write("x.bin", Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8])),
    });
    expect(result.ok).toBe(false);
  });
});
