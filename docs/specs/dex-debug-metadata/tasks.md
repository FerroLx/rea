# Tasks

- [x] Confirm scope: static `.dex`/APK inspection, in-scope, no device/adb/JDWP.
- [x] Extract shared modified-UTF8 and archive-member helpers; refactor JVM to consume them.
- [x] Dependency-free DEX framing (bounded, `Result`-based; version/endian/cdex gating).
- [x] Decode the `debug_info_item` state machine, seeding implicit parameter + `this` locals.
- [x] Resolve names/types/descriptors from the string/type/proto pools (bounded).
- [x] Assemble the summary (tallies + readiness) and per-class detail.
- [x] Public schema + input (`path`, `entry?`, `class_descriptor?`) + projections.
- [x] Provider (loose `.dex` + APK multidex, admit-once, ambiguity/encrypted refusals), service.
- [x] CLI/MCP contract, catalog registration, effect audit, composition/server wiring.
- [x] Unit + adapter tests; `verify:dex` d8/dexdump real lane (cross-checks local tuples).
- [x] Resolve independent (Fable) review findings (implicit-parameter seeding blocker et al.).
- [x] Analyst guide + spec dir + docs index link.
- [ ] Discoverability parity with other tools (README capability row, reverse-engineer
      skill source, architecture.mermaid) — shared follow-up with the JVM tool.
- [ ] `npm run check:pr` and full guards at PR time (pre-existing unrelated lint errors
      in `artifactComparison.test.ts` / `ManagedCilDecoding.test.ts`, and the `README_tr`
      link drift, are not from this branch).
