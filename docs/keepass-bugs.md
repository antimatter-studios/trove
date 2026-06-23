# Upstream bugs found via the cross-tool conformance matrix

The conformance matrix in [`crates/keepass-spec-tests`](../crates/keepass-spec-tests/)
mints `.kdbx` vaults with one tool and reads them back with another, across the
`keepass` Rust crate (0.12.5 and 0.13.10), `keepassxc-cli`, and the `trove` CLI.
Several mismatches it surfaced are genuine **upstream bugs** rather than
expected behavior. Each is recorded in the matrix's `expect()` table as an
`Xfail` (so the suite stays green and *notices* if the bug is later fixed — an
`Xfail` that starts passing turns red), and documented here for upstreaming.

Each entry lists the **product**, the **affected versions**, the **symptom**,
the **root cause** (with the exact source location), how to **reproduce**, and a
**suggested fix**. Bugs A and B are present in the *current* `keepass` 0.13.10
and are the best PR candidates.

Crate source referenced below is the published crate, e.g.
`~/.cargo/registry/src/*/keepass-0.13.10/`.

---

## Bug A — KDBX-3.1 reader collapses every attachment to id 0

- **Product:** `keepass` crate (keepass-rs)
- **Affected versions:** 0.12.5 **and** 0.13.10 (current)
- **Severity:** high — silent data loss / corruption: a vault written by
  KeePassXC/KeePass2 in KDBX 3.1 with **two or more attachments** loses or
  misreads them when opened with the crate. KDBX 4 (header-stored attachments)
  is unaffected.

### Symptom
Open a KDBX-3.1 database that has ≥2 binary attachments (across the whole DB).
Entries end up with the wrong attachment bytes, or with no attachment at all.

### Root cause
`src/format/xml_db/mod.rs`, the loop that converts the XML `<Meta><Binaries>`
pool into database attachments:

```rust
// convert XML attachments (KDBX3-style) to database attachments
if let Some(binaries) = self.meta.binaries.take() {
    for binary in binaries.binaries {
        let id = crate::db::AttachmentId::next_free(&db);   // <-- BUG
        let data = binary.xml_to_db(inner_decryptor)?;
        attachments.insert(id, crate::db::Attachment { id, entries: HashSet::new(), data });
    }
}
```

`AttachmentId::next_free(&db)` is computed against `db.attachments`, but this
loop inserts into the **local** `attachments` map (assigned into `db` only
afterwards). So `db.attachments` is empty for every iteration and `next_free`
returns the **same id** each time → all pooled binaries collide on one id in the
`HashMap` (only one survives). It also **ignores `binary.id`** — the XML
`@ID` attribute that each entry's `<Binary><Value Ref="N"/></Binary>` points at —
so entry→attachment references no longer resolve.

The KDBX-4 header path immediately above does it correctly, using the index:

```rust
for (i, header_attachment) in header_attachments.iter().enumerate() {
    let attachment = crate::db::Attachment { id: crate::db::AttachmentId::new(i), .. };
    attachments.insert(attachment.id, attachment);
}
```

### Suggested fix
Use the XML-declared id (`binary.id`) so pool ids match the `Ref`s entries use:

```rust
for binary in binaries.binaries {
    let id = crate::db::AttachmentId::new(binary.id);   // was: next_free(&db)
    let data = binary.xml_to_db(inner_decryptor)?;
    attachments.insert(id, crate::db::Attachment { id, entries: HashSet::new(), data });
}
```

(The entry-side `Ref` lookup must resolve against the same `binary.id` space —
verify the entry deserialization maps `Value Ref="N"` → `AttachmentId::new(N)`.)

### Reproduce in the matrix
Producer `keepassxc-cli` (writes KDBX 3.1) → consumer `keepass` crate, fixture
**`attachments`** (3 entries, 4 attachments total). See the
`producer = Keepassxc, consumer = Crate*, total_attachments >= 2` arm of
`expect()` in [`tests/matrix/mod.rs`](../crates/keepass-spec-tests/tests/matrix/mod.rs).

---

## Bug B — KDBX-3.1 reader can't open a vault containing a zero-byte attachment

- **Product:** `keepass` crate (keepass-rs)
- **Affected versions:** 0.12.5 **and** 0.13.10 (current)
- **Severity:** high — the **entire database fails to open** (not just the one
  attachment) with `Error parsing XML inside KDBX: missing field $value`.

### Symptom
A KDBX-3.1 database with an attachment whose contents are empty (0 bytes) cannot
be opened at all. KeePassXC writes an empty attachment as a self-closing element
`<Binary ID="n" Compressed="True"/>` (no text node).

### Root cause
`src/format/xml_db/meta.rs`, the `Binary` pool element:

```rust
pub struct Binary {
    #[serde(rename = "$value")]
    pub value: String,          // <-- no #[serde(default)]
    #[serde(rename = "@ID")]
    pub id: usize,
    ...
}
```

`value` (the base64 text) has no `#[serde(default)]`, so when the element has no
text child (the empty-attachment case) deserialization fails with
`missing field $value`, aborting the whole open.

### Suggested fix
Default the value to an empty string when the text node is absent:

```rust
#[serde(rename = "$value", default)]
pub value: String,
```

An empty `value` then base64-decodes to an empty `Vec<u8>`, i.e. a valid
zero-byte attachment. (The sibling `StringValue` in `entry.rs` already handles
the empty case on both serialize and deserialize; `Binary` should match.)

### Reproduce in the matrix
Producer `keepassxc-cli` → consumer `keepass` crate, fixture
**`scale-zero-and-many-attachments`** (contains a 0-byte attachment). See the
`has_empty_attachment` arm of `expect()` in
[`tests/matrix/mod.rs`](../crates/keepass-spec-tests/tests/matrix/mod.rs).

---

## Bug C — empty numeric `<Meta>` elements rejected by KeePassXC (fixed upstream)

- **Product:** `keepass` crate (keepass-rs)
- **Affected versions:** 0.12.5 (**fixed in 0.13.10**)
- **Severity:** high (while present) — *no* crate-written vault could be opened
  in KeePassXC at all.

### Symptom
KeePassXC refuses any 0.12.5-written `.kdbx` with
`Error while reading the database: Invalid number value` — even an empty vault.

### Root cause
0.12.5 serializes unset numeric `<Meta>` fields as **empty elements**:
`<MaintenanceHistoryDays/>`, `<HistoryMaxItems/>`, `<HistoryMaxSize/>`,
`<MasterKeyChangeRec/>`, `<MasterKeyChangeForce/>`, and writes
`<RecycleBinEnabled>null</RecycleBinEnabled>`. KeePassXC's strict reader runs
`toInt("")` on the first numeric element and bails.

### Fix (already upstream)
0.13.10's `Meta` serialization uses `#[serde(skip_serializing_if = "Option::is_none")]`
on the numeric fields, so unset numerics are **omitted** rather than emitted
empty. Recorded here because the matrix would have caught it pre-release, and it
motivates trove's planned 0.12.5 → 0.13.10 upgrade.

### Reproduce in the matrix
Producer `keepass` crate **0.12.5** → consumer `keepassxc-cli`, *any* fixture.

---

## Bug D — entry `<Tags>` separator changed between crate versions

- **Product:** `keepass` crate (keepass-rs)
- **Affected versions:** writer 0.13.10 ↔ reader 0.12.5
- **Severity:** medium — tags written by 0.13.10 read back as a single mangled
  tag under 0.12.5.

### Symptom
0.13.10 serializes an entry's tags joined with `;` (e.g. `work;ssh;prod`). 0.12.5
reads `<Tags>` without splitting on `;`, yielding a single tag
`"work;ssh;prod"`. KeePassXC and 0.13.10 both split correctly; 0.12.5 → 0.13.10
is fine. Only 0.13.10 → 0.12.5 breaks.

### Root cause / fix (to confirm upstream)
A separator/splitting inconsistency in `<Tags>` handling across the two crate
versions. The KDBX convention accepts `;` and `,` as tag separators; the reader
should split on both. (Likely already moot once trove pins a single crate
version, but worth a defensive split-on-`[;,]` in the reader.)

### Reproduce in the matrix
Producer `keepass` 0.13.10 → consumer `keepass` 0.12.5, fixtures **`tags-basic`**
and **`tags-and-custom`**.

---

## Not bugs (documented so they aren't mistaken for bugs)

- **KeePassXC resolves `{REF:...}` placeholders on `show`.** A custom field whose
  value is a literal reference comes back *resolved* (empty when the target
  doesn't exist), not literal. This is correct KeePass reference behavior; the
  literal is preserved in storage (the crate reads it verbatim). Use
  `export -f xml` if you need the unresolved literal from keepassxc.
- **`keepass` 0.13.10 writes KDBX 4.1 only.** It can't *save* a forced KDBX 4.0
  (`DatabaseVersion::KDB4(0)` → `UnsupportedVersion`); 0.12.5 saves 4.0. A
  limitation/feature-gap, not a correctness bug. KeePassXC reads both 4.0 and 4.1.
- **`keepassxc-cli` cannot write KDBX 4 on import/create.** It always emits KDBX
  3.1, which is why Bugs A and B (3.1-reader bugs) are reachable from a
  keepassxc-produced vault at all.
