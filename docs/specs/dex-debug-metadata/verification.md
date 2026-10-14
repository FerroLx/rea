# Verification

Branch `feat/dex-debug-metadata`, stacked on `feat/2377-jvm-debug-metadata`.

## Domain + adapter (landed)

- 30 unit/adapter tests: `dexFile` framing (header/version 035/037-040; 036/041/
  cdex/reverse-endian refusals; LEB128; `class_defs` and `class_data` bounds),
  `dexDebugInfo` state machine (parameter seeding, SET_FILE, RESTART, implicit
  end, run-to-`insns_size`, malformed), shared `modifiedUtf8` (C0 80, CESU-8),
  `dexStrings` (NUL-bounded, `utf16_size` cross-check), `dexDebugMetadata`
  assembly (summary tally + readiness + per-class detail), and `DexFileProvider`
  (loose summary/detail, APK multidex summarize-all, entry selection, missing
  entry, non-dex steer).
- `tsc --noEmit` clean; `oxlint` clean on the change set bar one non-blocking
  `max-params` warning on `registerDexTools` (identical to the JVM sibling).
- MCP catalog check, 214 conformance tests (incl. advertised-schema validity and
  target-content provenance), and the effect-wording gate pass.

## Real-toolchain lane (landed)

`npm run verify:dex` (Android SDK d8 + dexdump, JDK javac) compiles an owned
fixture with `-g` and `-g:none`, dexes each, and cross-checks REA against
`dexdump`: the `-g` dex reads `present` with locals (dexdump confirms), the
`-g:none` dex reads `stripped` with zero locals (dexdump confirms), per-class
detail resolves `compute`/`(IJ)I` and its locals, and the local **names**
(`this`, `a`, `b`) REA reports are names dexdump also resolves. An APK built from
the dex exercises summarize-all and entry selection and a missing-entry input
error. All through the built CLI and the stdio MCP in Evidence parity, advertised
schema validated. 12 cases; skips cleanly without the SDK.

Real APKs via the CLI: `retro-probe.apk` (debug) → 11 members, readiness
`present`; the robokiller R8 release → readiness `stripped`, 0 locals, lines
kept — the debug-vs-release signal.

## Independent (Fable) review — resolved (landed)

A full independent review on the Fable model found a blocking correctness bug
and several follow-ups, all fixed:

- BLOCKER — the decoder never seeded a method's implicit parameter locals (and
  `this`), so it dropped every parameter + `this` from the local tables and
  flagged valid `DBG_END_LOCAL`/`RESTART` on a parameter register as malformed,
  stopping the walk early and losing line positions. Fixed by seeding the
  implicit locals from the code_item register layout + proto before the walk.
  Measured on a real debug APK: `classes.dex` locals 57,505 → 155,804 and
  `line_positions` 198,768 → **204,456, now exactly dexdump's count** (the gap
  was this bug, not a strict-vs-lenient LEB difference).
- `line == 0` tolerated (d8 synthetic methods); only a negative line is malformed.
- Per-class `class_data` method count bounded structurally before allocation.
- The summary decode cache keyed on `debug_info_off` was dropped (seeding makes
  each decode method-specific).
- The real lane now cross-checks local tuples (`this` + parameter names) against
  dexdump — the check that would have caught the blocker.

Verified correct by the review: header/version gating, LEB128/NO_INDEX,
special-opcode math, `string_data_item` bounds + `utf16_size` cross-check,
`type_list`/proto descriptors, 16-bit code-unit addressing, admit-once
descriptor + hash-after-selection + output budget, inward layering, shared-helper
extraction, Result/tagged-error algebra, Evidence identity re-validation, and the
fail-closed scope (no adb/dynamic leakage).

## Pending (follow-ups, not blocking)

- `distinct_source_files` can include d8's synthetic source name
  (`D8$$SyntheticClass`); the `-renamesourcefileattribute` heuristic still holds.
  Documented in the guide.
- Discoverability parity (README capability row, reverse-engineer skill source,
  `architecture.mermaid`) — shared with the JVM tool.
- A duplicate-class-across-members and a malformed/truncated-DEX adapter case in
  the real lane (unit-covered today).

## Limits

No Android code executes; no device/adb; `odex`/`vdex`/`oat`/`cdex` refused.
Line positions may be R8-renumbered synthetic lines needing `mapping.txt`.
Real-toolchain validation covers Linux + JDK + Android build-tools 36 only.
