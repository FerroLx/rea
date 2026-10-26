# JVM class-file debug metadata

REA reads compiler-emitted debug metadata from one caller-selected local `.class`
file so an analyst can judge **debugging readiness before attaching a debugger**.
The reader is in-process and dependency-free: it decodes class-file attributes
only, never executes Java, never resolves a source URL, and never claims that
supplied source matches a declared `SourceFile`. Decompiler line numbers are not
compiler-emitted source positions and are never substituted for them.

CLI and MCP share one workflow and return artifact-bound Evidence inline.

## Answer an analyst question

```sh
rea inspect-jvm-debug-metadata /path/Example.class
# Select one class entry inside a JAR:
rea inspect-jvm-debug-metadata /path/app.jar --entry com/example/Service.class
# Select a multi-release override explicitly:
rea inspect-jvm-debug-metadata /path/app.jar --entry com/example/Service.class --release 17
```

The MCP method is `inspect_jvm_debug_metadata`. Pass the absolute local `path`
(a `.class` file, or a `.jar` with `entry`); for a multi-release JAR add
`release` to select an override:

```json
{
  "name": "inspect_jvm_debug_metadata",
  "arguments": {
    "path": "/path/app.jar",
    "entry": "com/example/Service.class",
    "release": 17
  }
}
```

A JAR entry is selected explicitly: an omitted `release` reads the base entry,
and a requested `release` must match a present `META-INF/versions/<N>/` override
or the call is refused with the available versions — metadata is never combined
across versions. When only overrides exist, an omitted `release` is refused as
requiring one. In a multi-release JAR, an `entry` spelled as
`META-INF/versions/<N>/<path>` is refused with the equivalent `entry` plus
`release`, so `selected_entry.release` always names the version read; in a JAR
that is not multi-release such a member is an inert resource and is read as
itself. Members are matched by their stored ZIP names, as the JDK's
`JarFile.getEntry` matches them: the requested `entry` may use `\` separators
or a leading `/` or `./`, but a member stored with a leading `./` is an inert
resource that never supplies the entry, an override, or an ambiguity. Stored
names are decoded as the JDK's `JarFile` decodes them: as UTF-8 whether or not
the ZIP language-encoding flag is set. A JAR holding a member name or entry
comment that is not valid UTF-8 is refused as invalid input, because the JDK
refuses to open it ("invalid CEN header (bad entry name or comment)"). So is,
whichever member is requested, a JAR holding any other central-directory
record OpenJDK 25's `ZipFile` refuses to index, and REA names the JDK's
message: a record flagged as encrypted ("encrypted entry"), one whose
compression method is neither stored (0) nor deflated (8) ("bad compression
method"), one whose header (46 bytes plus name, extra field and comment)
exceeds 65,535 bytes ("bad header size"), an extra field whose declared size
runs past the record's extra data, a zip64 extra field whose size is not
exactly what the record's `0xFFFFFFFF`/`0xFFFF` markers call for, or such a
marker on a record with no extra data. A central directory that does not end
exactly at its last record (a record running past it, trailing bytes, or a
digital-signature record) is refused too ("bad header size"). OpenJDK 21 does
not make the header-size and zip64 extra-field checks.

REA is stricter than `JarFile` in a few cases, where it refuses the JAR as
invalid input rather than answering: a member REA reads (the manifest or the
selected class) whose local header disagrees with its central-directory record
(an encryption flag, sizes or compression method set in only one of them) or
whose CRC-32 does not match its bytes, and any record whose zip64 size or
offset exceeds 2^53 − 1. OpenJDK 21 and 25 open these archives and read the
members.

A JAR is multi-release exactly when the JDK's `JarFile.isMultiRelease()` would
say so (OpenJDK 25, default settings): the manifest is the member stored as
`META-INF/MANIFEST.MF` in any ASCII case (a `./`-prefixed name is not the
manifest), its bytes contain `Multi-Release: true` ignoring ASCII case, and its
main section parses as `java.util.jar.Attributes` does with a last
`Multi-Release` value of `true` ignoring case and untrimmed. Any parse failure
in the main section, such as a missing space after a colon, an invalid
attribute name, a byte-order mark, or a line longer than the JDK's line buffer,
makes the JAR not multi-release, as does a manifest declaring more than the
JDK's default `jdk.jar.maxSignatureFileSize` of 16,000,000 bytes. Like the JDK,
REA ignores ZIP external attributes: only a trailing `/` makes a member a
directory, so a manifest or class member marked as a directory by Unix-mode or
MS-DOS attributes is read as a file. A manifest REA cannot read, such as one
stored as a symlink, leaves the multi-release status
unknown: a call that needs it is refused as unsupported rather than treating the
JAR as not multi-release. A release is a
`META-INF/versions/<N>/` directory whose `<N>` is a decimal number from 9 to
2147483647 without leading zeros; other directories are inert resources. REA
lists every such release present, while a running JDK only consults versions
up to its own feature release. As in `JarFile.getEntry`, an entry under
`META-INF/` is never versioned: `META-INF/versions/<N>/META-INF/...` overrides
nothing and is a plain member selected by its own name.

## Interpret the result

The normalized result binds every fact to exact identity:

- `artifact` — the selected local file's `path`, exact-byte `sha256`, and
  `bytes` (the `.class` file, or the `.jar` for a JAR entry). The reader does
  not mutate the selected bytes; `sha256` identifies them, not authenticity or
  the producing compiler.
- `container` — `class-file` or `jar`. `selected_entry` is `null` for a loose
  class file, or the selected `entry`, `release` (null for base), `sha256`, and
  `bytes` of the class bytes read from the JAR.
- `class` — `internal_name` (the JVM binary name from the constant pool, e.g.
  `com/example/Foo`; not decompiler output), `major_version`, `minor_version`.
- `source_file` — `presence` (`present` | `absent` | `malformed`) and the
  declared `name` when present.
- `source_debug_extension` — `presence` and `byte_length` only. The bytes are
  neither returned nor interpreted; no source-map dialect is parsed.
- `methods[]` — each with `name`, `descriptor`, debugging `state`, `max_locals`
  (from the `Code` attribute; `null` without a readable `Code` header), and the
  three decoded tables:
  - `line_number_table` — `start_pc` → `line_number` entries, and
    `out_of_range` (`start_pc` is not an index into the method's code array).
  - `local_variable_table` — `start_pc`, `length`, `name`, `descriptor`, `slot`,
    and `scope`, where the scope `[start_pc, start_pc+length)` lies in the code:
    `aligned` (it starts at an instruction and ends at one or at the code's
    end), `in-code` (inside the code; instruction boundaries are not checked
    below class version 51, as HotSpot does not check them there),
    `misaligned` (its start or end falls inside an instruction), `out-of-range`
    (outside the method's code length), or `unknown` (the instruction stream
    does not decode, so its boundaries are unknown).
  - `local_variable_type_table` — as above with a generic `signature`.
  - `reused_slots` — slots that appear in more than one local-variable entry.
    Reuse is legal; a reused slot may denote different variables across disjoint
    scope ranges, so entries are preserved rather than merged.
- `coverage` — method counts per state, derived from examined methods.

### Method debugging state

| `state`          | Meaning                                                                                                                                                                                                                            |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `present`        | both line and local-variable tables decoded; or line numbers decoded and `max_locals` is 0                                                                                                                                         |
| `partial`        | one table present, the other absent                                                                                                                                                                                                |
| `stripped`       | a body exists but carries neither table (e.g. `javac -g:none`)                                                                                                                                                                     |
| `malformed`      | a present table failed to decode or violates one of the HotSpot constraints listed below; entries are kept. A `local_variable_type_table` in a class below version 49 does not count, because HotSpot ignores it there (see below) |
| `not-applicable` | no `Code` attribute (native/abstract, or no body)                                                                                                                                                                                  |

A method with `max_locals` 0 has no local at all (not even `this` or a
parameter), so `javac -g` emits no `LocalVariableTable` for it; that absent table
is reported as `absent` but does not make the method `partial`. When
`max_locals` is greater than 0, `partial` with an absent local-variable table can
also mean the method has only compiler-synthetic locals, which `javac -g` does
not name.

A `SourceFile`, or a local-variable entry, whose constant-pool index does not
name a `CONSTANT_Utf8` entry violates JVMS §4.7.10/§4.7.13–14: the attribute is
reported `malformed`, and the entry is kept with a `null` name, descriptor, or
signature.

JVMS permits `Code`, `SourceFile` and `SourceDebugExtension` at most once
(HotSpot rejects a repeat). A repeated `SourceFile` or `SourceDebugExtension` is
`malformed` with no name or length chosen; a method with more than one `Code`
attribute is `malformed`, with `max_locals` `null` and every table `unread`,
because which body is meant is unknown.

A table entry HotSpot rejects the class for also makes its table `malformed`,
with the raw values kept: a line `start_pc` flagged `out_of_range`, a
local-variable `scope` that is `out-of-range` or `misaligned`, a local-variable
`slot` at or past `max_locals` (for a `J` or
`D` `LocalVariableTable` descriptor, the second slot `slot + 1` too), a
local-variable name HotSpot rejects as a field name, or a `LocalVariableTable`
descriptor that is not a legal field descriptor (JVMS §4.3.2, such as `Q`, `V`,
or more than 255 array dimensions). From class version 49 a name is an
unqualified name (no `.`, `;`, `[` or `/`); older classes use Java identifier
rules, which REA checks exactly for ASCII and accepts for any non-ASCII
character. A `LocalVariableTypeTable` signature is not checked for grammar, as
HotSpot does not check it.

HotSpot's type-checking verifier, final from class version 51, rejects a
`LocalVariableTable` scope whose `start_pc`, or whose end short of the code
length, falls inside an instruction rather than at its first byte ("Illegal
local variable table start_pc" / "length"). A `wide` prefix and the opcode it
modifies are one instruction, and `tableswitch`/`lookupswitch` padding is
aligned from the start of the code array. A `LocalVariableTypeTable` scope is
checked only through the `LocalVariableTable` row it must match (see below):
a misaligned type-table row reports `scope: "misaligned"`, and it is the
matching row's own misalignment, or the lack of any matching row, that makes a
table `malformed`; with no `LocalVariableTable` row it is never checked, as
HotSpot loads such a class. A type-table scope outside the code is rejected
either way. A version 50 class that fails this check is re-verified by the older verifier,
which loads it, so below version 51 scopes are only checked against the code
length (`in-code`). Line-number positions have no boundary rule: HotSpot
accepts a `start_pc` inside an instruction. REA decodes each method's
instruction lengths once, only when a local scope needs them, so a method
with no local scope inside its code is not decoded, and bytecode HotSpot's
verifier rejects there (such as `jsr` from version 51, or a `breakpoint`
opcode) does not change its `state`, which describes its debug tables. An
instruction
stream that does not decode (an illegal opcode, an instruction past the code's
end, `wide` before an opcode it cannot modify, a switch with `high < low` or a
negative pair count, a switch whose fixed operands reach the code's end, or,
from class version 51, `jsr`, `jsr_w`, `ret` or `wide ret`), which HotSpot's
verifier also rejects, leaves every
in-code scope `unknown` and its table `malformed`, never `present`. Like every
check on this page, this follows a JVM that verifies the class, as it does by
default for classes outside the boot class path.

HotSpot reads `LocalVariableTypeTable` only from class version 49 and ignores it
as an unknown attribute in older classes. REA still decodes it there and reports
its `presence` by the same rules, so `malformed` keeps meaning that its bytes or
entries are invalid, but in a class older than version 49 it never changes the
method's `state`.

When a method's `LocalVariableTable` attributes declare at least one row,
HotSpot's class-file parser matches the tables (`copy_localvariable_table`),
keying each row by `start_pc`, `length`, name constant index and slot: from
class version 49 a repeated `LocalVariableTable` key makes that table
`malformed` ("Duplicated LocalVariableTable attribute entry"), and a
`LocalVariableTypeTable` row with no matching key ("LVTT entry ... does not
match any LVT entry"), or a second row matching the same key ("Duplicated
LocalVariableTypeTable attribute entry"), makes the type table `malformed`.
With no `LocalVariableTable` row the tables are not matched, as HotSpot does
not match them.

A method whose `Code` attribute declares a `code_length` outside 1 to 65,535,
or holds a sub-attribute whose name index does not name a `CONSTANT_Utf8`
entry, is `malformed`, as HotSpot rejects it; tables that could not be ruled out
are `unread`.

A table whose declared entry count exceeds its bytes is reported `malformed` with
the entries recovered before the short read. A `Code` attribute with bytes left after its declared
sub-attributes is malformed too. When a later sibling inside the
same `Code` attribute is malformed, or such stray bytes follow, tables framed before it are kept and tables
that were never reached are `unread` (unknown), not `absent`; absent, malformed, partial, and
ambiguous (reused-slot) cases stay distinct and are never collapsed into
"absent".

## Scope and limits

Static class-file inspection only. No Java executes; no source URL is resolved;
supplied source bytes are never claimed to match a `SourceFile` name. Debug
metadata identity stays separate from any decompiler output. Standalone `.class`
inspection is independent of the Android/JADX lane and of the JVM runtime
(JDWP) proposal. A malformed or truncated class file is reported through the
tagged error algebra rather than throwing. A single class file far over the
input budget is refused before allocation. Only the attributes this reader
consumes are materialised (others are framed and skipped), under a shared
budget. Before any entry is built, a projection counts debug-table entries and
the encoded size of every constant-pool string each entry references, so a class
with too many entries, or whose shared long names would expand past the inline
output budget, is refused without building the report; the exact serialized
size is checked again afterwards. A local-variable scope whose `[start_pc, start_pc+length)`
lies outside the method's code length is surfaced as declared with `scope:
"out-of-range"`, and a line entry whose `start_pc` is at or past it with
`out_of_range: true`, never silently corrected. A class file with bytes after its last attribute is
refused as invalid input, as HotSpot refuses it, as is a class whose
`constant_pool_count` is 0, whose last constant-pool slot holds a `long` or
`double` (its second slot would lie outside the pool), or whose field, method
or class attribute has a name index that does not name a `CONSTANT_Utf8`
entry. A JAR whose central directory
exceeds the metadata read budget, or whose manifest and selected class (the
only members REA decompresses) declare more uncompressed bytes than its
decompression budget allows, is refused with that bound named in
`reported_limits` (`max_metadata_read_bytes` or `max_decompressed_bytes`);
other members' declared sizes are not charged, as the JDK does not read them.

Verified by the `verify:jvm` real lane, which compiles owned `javac` fixtures
with `-g` and `-g:none` and cross-checks the decoded facts against `javap` —
`SourceFile`, `LineNumberTable` entry counts, and `LocalVariableTable` /
`LocalVariableTypeTable` presence and method descriptors (not individual
pc→line pairs or slot scopes) — then exercises the CLI and MCP in parity against
real application bytecode.
