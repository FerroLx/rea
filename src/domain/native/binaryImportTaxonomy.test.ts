import { describe, expect, it } from "vitest";

import {
  BINARY_IMPORT_TAXONOMY,
  DEFAULT_IMPORT_CATEGORIES,
  importTaxonomyEntry,
  OPT_IN_IMPORT_CATEGORIES,
  RESOLVER_APIS,
} from "./binaryImportTaxonomy.js";

describe("binary import taxonomy", () => {
  it("lists each API once, so one import has one meaning", () => {
    const apis = BINARY_IMPORT_TAXONOMY.map((entry) => entry.api);
    expect(new Set(apis).size).toBe(apis.length);
  });

  it("uses well-formed ATT&CK technique IDs", () => {
    for (const entry of BINARY_IMPORT_TAXONOMY)
      for (const id of entry.attack) expect(id).toMatch(/^T\d{4}(\.\d{3})?$/);
  });

  it("assigns every category to the default or the opt-in set", () => {
    const known = new Set([
      ...DEFAULT_IMPORT_CATEGORIES,
      ...OPT_IN_IMPORT_CATEGORIES,
    ]);
    for (const entry of BINARY_IMPORT_TAXONOMY)
      expect(known.has(entry.category)).toBe(true);
  });

  it("maps credential stores to T1555, not credential dumping", () => {
    expect(importTaxonomyEntry("CredEnumerateW")?.attack).toEqual(["T1555"]);
    expect(importTaxonomyEntry("MiniDumpWriteDump")).toMatchObject({
      attack: ["T1003.001"],
      argumentDependent: true,
    });
  });

  it("marks every resolver API as a weak dynamic-resolution entry", () => {
    for (const api of RESOLVER_APIS)
      expect(importTaxonomyEntry(api)).toMatchObject({
        category: "dynamic_resolution",
        confidence: "weak",
      });
  });
});
