# Android DEX debug metadata

REA reads compiler-emitted debug metadata from a selected local Android DEX so an
analyst can judge **debugging readiness before attaching a debugger or reading a
decompilation**. The reader is in-process and dependency-free: it decodes the
DEX `debug_info_item` and string/type pools only, never executes Android code,
never involves a device or `adb`, and refuses device-optimized formats
(`odex`/`vdex`/`oat`/`cdex`). Acquisition from a device is the existing
`pull_adb_*` tools' job — this tool reads a caller-selected local file.

CLI and MCP share one workflow and return artifact-bound Evidence inline.

## Answer an analyst question

```sh
# Summarize debug readiness across the DEX members an APK auto-loads:
rea inspect-dex-debug-metadata /path/app.apk
# A standalone .dex:
rea inspect-dex-debug-metadata /path/classes.dex
# Select one dex member inside the archive:
rea inspect-dex-debug-metadata /path/app.apk --entry classes2.dex
# Drill into one class for full per-method detail:
rea inspect-dex-debug-metadata /path/classes.dex --class-descriptor 'Lcom/example/Service;'
```

## Two output modes

Unlike a JVM `.class` (one class), a DEX holds thousands of classes, so the tool
works at two granularities:

- **Summary (default).** One entry per DEX member (for an APK, the members
  Android auto-loads: `classes.dex`, `classes2.dex`, … up to the first missing
  name; select any other `.dex` with `entry`). Each reports `dex_version`,
  `class_count`, method tallies (`methods_with_code`, `methods_with_debug_info`,
  `methods_with_parameter_names`), `line_positions`, `local_declarations`,
  `explicit_local_declarations`, `set_file_events`, `source_file_present`,
  `distinct_source_files` (the count of distinct source-file string ids + up to
  3 distinct sample names), and a derived `readiness`.
- **Per-class detail (`--class-descriptor Lpkg/Name;`).** Full per-method
  `name`, JVM-form `descriptor`, `state`, and `locals` (name, type, signature,
  `register`, scope `start_address`/`end_address` in 16-bit code units,
  `out_of_range`), with parameter names. The implicit `this` and the method's
  parameters are reported as locals, exactly as `dexdump` does.

## Readiness is a derived label

`readiness` is a conservative label over what the debug streams themselves
carry, not a guarantee. It uses the same vocabulary as a method's `state`, over
two kinds of evidence: line positions, and local evidence (declared locals or
named parameters):

- `present` — both line positions and local evidence.
- `partial` — exactly one of them. The classic R8/ProGuard or `d8 --release`
  build keeps line tables but drops local names, so it reads `partial`.
- `stripped` — neither.
- `unknown` — some class data, code items or debug streams could not be read
  (counted in `unreadable`) and the evidence observed does not already
  establish `present`, so the label stays open. A damaged file never reads as
  `stripped` or `partial`.
  Whenever `unreadable` is non-zero, every other count is a lower bound over
  what could be read.

`local_declarations` counts every local `dexdump` lists, including the implicit
`this` and parameter locals that are synthesised from a method's register
layout whenever it has a debug stream. Because a release build keeps streams
for its line tables, those implicit locals appear even when no local debug info
survived, so `readiness` and the per-method `state` use
`explicit_local_declarations` (locals the stream declares with
`DBG_START_LOCAL`, counted once a scope covers an instruction of the method, so
it never exceeds `local_declarations`) and named parameters instead.

`line_positions` counts positions inside each method's code (`address <
insns_size`). R8 shares one debug stream across many methods, so a stream can
run past a method's code; those rows belong to no instruction of that method and
are not counted. `dexdump` additionally stops printing at the start of a
method's last instruction, so on R8 output that ends in a multi-unit
instruction or a data payload it lists slightly fewer rows (0.2–0.7% on the
members of a real release APK); on debug builds and d8 output the counts are
equal. Local scopes of zero length cover no instruction and are not counted. This
matches `dexdump` on compiler output, where they arise when kotlinc re-declares
a generic parameter's register at address 0 (verified exact on 15 real members).
On hand-crafted streams with zero-length scopes elsewhere, `dexdump` may list
rows REA omits.

Sloppy local events are tolerated as ART's decoder tolerates them:
`DBG_END_LOCAL` on a register with no live local and `DBG_RESTART_LOCAL` on a
register that is still live change nothing, and `DBG_RESTART_LOCAL` on a
register never declared starts a local with no name or type (counted in
`local_declarations`, as `dexdump` lists it, but not as a declaration). An end
or restart naming a register outside the method's frame is malformed, as ART
rejects it.

A stream that faults (runs short, names a register outside the frame, or
references an unreadable name or type) makes the method `malformed`. Every
position before the fault is kept, and so is every local scope that ended
before it. Locals still live at the fault are dropped and not counted, because
ART's decoder emits nothing after a fault and their end was never recovered.
`dexdump` decodes positions in a separate pass that ignores local events, so on
such a stream it can list positions after the fault that REA does not count;
its locals match. A negative line is not a fault: the method is `malformed`,
but decoding continues to the end of the stream.

Decoding is bounded by a per-member work budget and runs in slices: after
each slice the reader yields to the event loop, so other MCP requests are
served and a cancellation takes effect within one slice, not after the whole
member. A single long debug stream also pauses between slices, and so does
checking one long string that a stream, class lookup or source file names.

## What the facts do and do not mean

Line positions are compiler-emitted; under R8 they are frequently **renumbered
synthetic lines that need a `mapping.txt` to retrace**, not asserted source
lines. A single `distinct_source_files` value (e.g. `"SourceFile"`) signals
`-renamesourcefileattribute`; note that d8 can also introduce a synthetic source
name (`D8$$SyntheticClass`), so the distinct count is not purely the real
source-file cardinality. SHA-256 identifies the exact selected bytes, not
authenticity or which compiler produced the artifact.

Malformed or truncated DEX is reported through the tagged error algebra rather
than throwing. Reverse-endian files and unsupported/withdrawn versions
(036, 041) are refused with distinct reasons; a compact dex (`cdex`) is refused
with guidance to supply a canonical `.dex`. Every length and offset is bounded
against the buffer before allocation; a crafted `class_data` method count is
refused structurally; archive members are read under a size budget so a
decompression bomb cannot be buffered; the archive is admitted once through a
no-follow descriptor and hashed only after a member is selected.

Limits and refusals a caller can meet:

- **Multidex selection.** Without `entry`, an APK/ZIP contributes the members
  Android auto-loads, matched by their exact stored names: `classes.dex`,
  `classes2.dex`, … up to the first missing name. A member stored as
  `./classes.dex`, `classes1.dex`, a zero-padded name, or one after a gap is not
  auto-loaded; select it with `entry`. As in ART, both read the raw stored
  name and ignore an Info-ZIP Unicode Path name: `entry` matches the stored
  name (a leading `./` is optional) and each member is reported under its
  stored name. When several stored spellings match (`classes2.dex` and
  `./classes2.dex`), the one stored exactly as `entry` is spelled is read;
  with none exact, the request is refused and names the stored spellings. An
  `entry` stored as a ZIP directory (`classes.dex/`) is refused as unavailable,
  not absent. What the archive reader notes about a member it reads (a
  differing Unicode Path name, directory attributes on a file) is carried into
  `limitations`, each note shortened past 1,024 UTF-16 code units and all within
  8 KiB; further notes are counted. Canonical members Android would not load
  are named in `limitations` and on any selection refusal. A named member
  `entry` would refuse is marked: a name stored more than once ("stored N
  times; ambiguous"), a symbolic-link member, or an encrypted one ("encrypted;
  REA does not read it"); the note advises `entry` only while a member it
  could select remains. Members counted but not named are taken as
  selectable only if they were plain files when seen; whether each is stored
  only once was not retained, so the note then says a selection may still be
  refused. Named members and spellings stop at 128 names or
  4 KiB, marks included, and the rest are counted as members; a name (or
  caller `class_descriptor`) longer than 160 UTF-16 code units is shortened
  in that prose by its two ends, with a marker counting characters,
  while the reported `entry` stays the exact stored name and the lookup uses
  the caller's value whole. An `entry` that is empty once its leading `./`
  segments are removed is refused as invalid. More than 64 auto-loaded members
  is refused; select one with `entry`.
- **`file_size` framing.** A header `file_size` larger than the bytes present,
  or smaller than the 0x70-byte header, is refused. When it is smaller than the
  member, analysis reads only the first `file_size` bytes (as ART on Android 15+
  does) and says how many bytes were not read; SHA-256 and size still cover the
  selected bytes.
- **Unknown, never absent.** An unreadable `class_def` identity, a second
  definition of the requested class, malformed `class_data` or an inconsistent
  `code_item` leaves the answer unknown (an explicit refusal or `unknown`
  readiness), never "absent" or "stripped". So does a method whose proto
  parameter list cannot be read, or a `debug_info_item` whose parameter name,
  local name, type or signature, or `DBG_SET_FILE` name lies outside the
  member's string or type pool, or names a string whose data cannot be read,
  as ART's verifier rejects both: such a name is never counted as surviving
  debug evidence.
- **Completed members survive a later failure.** When summarising several
  members, a refusal of a later member, a cancellation or a failed read still
  returns the members already summarised, as the failure's
  `partial_observation` (`kind: "dex-debug-metadata-members"`): each with its
  entry, SHA-256, size and summary, plus the member that was being analysed
  and how many were never read. The archive's own SHA-256 is not computed
  then. A class lookup retains nothing, because a match is an answer only
  once every member was checked for a second definition.
- **No ART verifier.** REA decodes `class_data` but does not run ART's
  verifier: an index repeated across lists (an instance and a static field, a
  virtual and a direct method), access flags inconsistent with a member's list,
  and code-presence rules (abstract or native methods with code, concrete ones
  without) are not checked, so a `class_data` ART would reject can still be
  reported.
- **Archive name validation (known difference).** ART's `IsValidEntryName`
  refuses a whole APK when any central-directory name contains NUL or is not
  valid UTF-8, whether or not the name sets the UTF-8 flag. REA refuses the
  APK only for a name that sets the UTF-8 flag and is not valid UTF-8 ("ZIP
  filename is not valid UTF-8"); it decodes an unflagged name as CP437 and
  tolerates NUL, so it reads DEX members of an APK ART would refuse.
- **Symbolic-link members (known difference).** ART ignores a member's unix
  mode and loads a `classes*.dex` stored with a symbolic-link mode as DEX
  bytes. REA recognises a link member from external attributes carrying a
  symbolic-link mode (the shared reader does not consult the made-by host) and
  does not read it: such a member inside the auto-loaded run refuses the
  summary, and selecting it with `entry` is refused, each as unavailable rather
  than absent. A link member Android skips is named with a
  "symbolic-link mode; REA does not read it" mark and is never advised for
  `entry`. A name stored both as a link and as a file is ambiguous, refused
  alike with or without `entry`.
- **Budgets.** Decoding work is proportional to each member's size; the result
  and its repeated `limitations` (the copy the Evidence carries beside it) are
  bounded to 8 MiB, projected before the report is built; the rest of the
  Evidence envelope is not counted. Exceeding either is refused,
  naming the member. Size refusals report their own bound: the 64 MiB DEX
  member, the 512 MiB archive, the 16 MiB archive-metadata read, or the
  archive's decompression budget.

Verified by the `verify:dex` real lane, which compiles an owned Java fixture with
`-g` and `-g:none`, dexes each with the Android SDK's `d8`, and cross-checks the
decoded facts — including the `this` and parameter locals — against `dexdump`,
then exercises the CLI and MCP in Evidence parity.
