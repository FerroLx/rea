# Inspect Android DEX source-line & local-variable debug metadata

Sibling of the JVM work (`docs/specs/2377-jvm-debug-metadata`). No upstream issue
number is assigned yet; this slug stands in until one is.

## Outcome and scope

Read compiler-emitted debug metadata from one caller-selected local `.dex`, or
DEX member(s) inside an APK/ZIP, so an analyst can judge debugging readiness
**before** attaching a debugger or reading a decompilation. No Android code
executes; no device or `adb` is involved; this is static format inspection
within existing offline-artifact authority, not a new runtime provider and not
decompilation.

The tool reads `class_def_item.source_file_idx` and the `code_item`
`debug_info_item` (parameter names, the line-position state machine, and the
local-variable scope events), resolving names and types from the string/type/
proto pools. Only canonical `.dex` is read; `odex`/`vdex`/`oat`/`cdex` and
reverse-endian or unsupported/withdrawn versions (036, 041) are refused.

## Inspection contract

Two output modes, because a DEX holds thousands of classes:

- **summary** (default; one per root `classes*.dex` in an archive): per-member
  `dex_version`, `class_count`, method tallies, `line_positions`,
  `local_declarations`, `set_file_events`, `source_file_present`,
  `distinct_source_files` (count + bounded sample), and a derived `readiness`
  (`present | partial | stripped`).
- **class-detail** (`class_descriptor` = `Lpkg/Name;`): per method `name`,
  JVM-form `descriptor`, `state`, parameter names, and `locals` with
  name/type/signature/`register`/scope (`start_address`/`end_address` in 16-bit
  code units)/`out_of_range`.

A method's incoming parameters — and `this` for an instance method — are
implicit locals seeded live at address 0 (named from `parameter_names`, typed
from the proto), exactly as the DEX format and `dexdump`/ART decode them;
dropping them or flagging their `DBG_END_LOCAL`/`RESTART` as malformed would
corrupt the debug-build signal. Unresolved values stay explicit: an unresolved
name/type is `null`; `readiness` is a derived label over observed tallies, never
a guarantee. Line positions may be R8-renumbered synthetic lines needing
`mapping.txt`; a single `distinct_source_files` value signals
`-renamesourcefileattribute`.

In an archive the requested member is selected explicitly by `entry`, or every
root `classes*.dex` is summarized; a duplicate member, or a `class_descriptor`
present in more than one member, is refused as ambiguous rather than guessed.

## Authority and overlap

Reads the supplied artifact only: no process, network, device, `adb`, UI or
mutation effects, no acquisition, no foreign-code execution. `runtime_execution`
is always `not-performed`. Acquisition from a device remains the existing
`pull_adb_*` tools' job; a live debugger (JDWP) is explicitly out of scope and
would need a maintainer scope decision. Debug-metadata identity stays separate
from any decompiler output.

## Resource admission

Every length and offset is bounded against the buffer before allocation: the
DEX header, id-table and `class_defs` counts, a `class_data` method count
(structurally, so a crafted count cannot force an unbounded array), the
`string_data_item` NUL scan with a `utf16_size` cross-check, and LEB128 capped
at 5 bytes. The archive is admitted once through a no-follow descriptor; members
are read under a per-member byte budget (a decompression bomb cannot be
buffered) and the archive digest is read through the same descriptor only after
a member is selected. The summary decodes one method at a time and discards it,
so peak memory is bounded regardless of class count. The projected result is
bounded by an inline output budget. Token usage and peak memory are unmeasured.

## Verification

`npm run verify:dex` compiles an owned Java fixture with `-g` and `-g:none`,
dexes each with the Android SDK's `d8`, and cross-checks the decoded facts —
including the implicit `this` and parameter locals — against `dexdump`, then
exercises the CLI and stdio MCP in Evidence parity with a validated advertised
schema. Unit tests cover framing (versions/endian/cdex refusals, LEB128), the
`debug_info_item` state machine (seeding, SET_FILE, RESTART, run-to-end,
malformed), string/proto resolution, the summary/detail assembly, and the
provider (loose/APK multidex, entry selection, encrypted/missing refusals).
Independent (Fable) review before handoff.

Format reference: Dalvik Executable (DEX) format —
https://source.android.com/docs/core/runtime/dex-format
