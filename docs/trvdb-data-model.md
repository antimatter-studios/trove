# trvdb data model

Status: **sketch for review** (#238, tracked in #439). This is the record model
for trvdb, trove's opt-in native format. It is not the byte-level spec: framing,
encodings and algorithm choices belong to `docs/trvdb-spec.md` (#241). Its job
is to shape the backend trait (#239) from two formats instead of one, so the
operations table at the end is the part to review the `DatabaseBackend` method
list against.

kdbx4 stays the default format. A database becomes trvdb only through
`trove convert` (#244).

## Working assumption: the 2026-09-29 direction

Until the spec says otherwise, trvdb is built in two stages.

1. **kdbx body behind a `TRVDB` prologue.** The file starts with `TRVDB\0` and
   a version, followed by a trove header (keyslots, algorithm parameters,
   header MAC), followed by an ordinary kdbx4 body. The kdbx body is encrypted
   under a random container key instead of a master password. keepass-rs keeps
   doing the parsing, writing, merge and history work. trove-owned records live
   inside that body. Saves still rewrite the whole file.
2. **Record-oriented container only where a feature needs it.** Each record is
   encrypted and stored on its own, so an edit writes only the records it
   changed. Delta sync (#230) is the feature that forces this; nothing else in
   this document does.

Each record type below says which stage can hold it.

## Identity rules

| Kind | Identity | Used by |
| --- | --- | --- |
| UUID | 128-bit random, as kdbx4 | database, group, entry, keyslot |
| Content address | keyed hash of the plaintext (see open question 3) | value, blob |
| Event hash | hash of the event's canonical encoding | write-log event, field version |
| Key fingerprint | hash of the member's public key | member identity, admin key |
| Name + generation | access-group name plus a counter | wrapped group key |

"Group" in this document means a folder in the tree, as in kdbx. A set of
members sharing a sealing key is an **access group** (see open question 8).

## Record types

### Database meta

One per database. Identity: the database UUID (today's `Trove.DatabaseUUID`
custom data item).

- Name, description, default username, custom icons, colour.
- Recycle bin: enabled flag and the bin group's UUID.
- Settings documents for the database (`Trove.*.settings`), as today.
- Required-features set: feature names a reader must know before it may write
  (#256 item 1).
- Retention policy for field history (count, age, size), admin-signed (#245).
- Admin key fingerprint, bound into every signature and sealed record (#233).
- Current write-log head(s).
- Public custom data from other tools, carried verbatim.

Stage 1: kdbx `Meta` plus `CustomData`. kdbx4 has the same record without the
policy, admin and log fields; its history limits are `HistoryMaxItems` and
`HistoryMaxSize`.

### Group

Identity: UUID. Parent: one group UUID (the root has none).

- Name, notes, icon, tags, sibling order.
- Times: creation, `last_modification`, `last_access`, expiry,
  `location_changed`, usage count.
- Settings documents (`Trove.*.settings` in custom data).
- Optional seal: name and parentage sealed to an access group (#246). The UUID
  and times stay in the clear (open question 7).

Stage 1: kdbx `Group`. kdbx4 has the same record, never sealed.

### Entry

Identity: UUID. Parent: one group UUID.

- Times as for groups, plus expiry flag and time.
- Icon, tags, colours, override URL, auto-type settings, custom data.
- Field heads: field name → latest field version.
- Attachments: name → blob reference.

No history list: an entry's history is the set of its field versions. On
kdbx4 the entry carries the field values themselves and a `History` list of
whole-entry snapshots, capped at 10 items / 6 MiB by default.

Stage 1: kdbx `Entry`, with field heads and blob references in entry
`CustomData` or a trove extension area (open question 1).

### Field version

One per write to one field of one entry. Identity: event hash of its canonical
encoding. Relationships: entry UUID, field name, parent version(s), value
address (or tombstone), write-log event that created it.

- Protected flag (as kdbx).
- Sealed-to access group and key generation, when sealed.
- Time and author member.
- Kind: value, tombstone (field deleted), purged.

Concurrent edits on two copies produce two versions with the same parent; the
next write names both as parents. kdbx4 has no equivalent: a field's history is
derived by projecting it out of entry snapshots (`entry_revisions`).

Stage 1 can hold it (whole-file rewrite on every save). A record container
makes appending cheap.

### Content-addressed value

Identity: content address. Shared by every field version, in any entry, that
holds the same plaintext under the same sealing scope.

- Ciphertext under the container key, or under an access-group key when
  sealed.
- Length.
- Purged marker: an admin purge erases the ciphertext and keeps the address,
  so the field version and its log event still verify (#245).

kdbx4 stores each value inline in the entry and again in every history
snapshot.

### Tombstone

Two kinds, both kept:

- **Deleted object**, copied from kdbx4: UUID of a deleted entry or group plus
  deletion time. Merge uses it to stop a deleted record coming back.
- **Field tombstone**: a field version of kind tombstone. Undelete appends a new
  version equal to the last live one.

kdbx4 has deleted objects only; a removed field simply disappears from the
entry.

### Blob reference and blob

A blob reference sits on an entry (and on field versions for history).
Identity of the blob: content address.

- Reference: attachment name, content address, size, protected flag, per-blob
  key wrapped under the container key or an access-group key.
- Blob: the encrypted bytes, stored outside the main file, shared by every
  reference with the same address.
- Garbage collection removes blobs no live entry or retained version
  references, and runs with history pruning.

kdbx4 stores attachment bytes in the inner-header binary pool and references
them by index (`<Binary Ref="N"/>`). Every save rewrites them.

Placement: outside both containers (a directory beside the database), so it
does not need the record container. Scope is a human decision (#247).

### Write-log event

Identity: event hash. Relationships: parent event hash(es), author member,
changed record IDs, linked field versions.

- Kind: write, delete, purge, grant, revoke, reveal (honest-client read log),
  patch (admin bridge over a broken span), restore, rollback.
- Timestamp, author fingerprint, admin fingerprint.
- Changed record IDs, never values.
- Signature by the author over the canonical encoding.

Two parents when two copies both appended. kdbx4 has nothing; the
trove-on-kdbx profile (#256) can keep a log in `CustomData` at the cost of size.

Stage 1 can hold it (whole-file rewrite). A record container makes appends
cheap and is required for delta sync of the log.

### Member identity

Identity: public key fingerprint. Relationships: keyslots, wrapped group keys,
permission entries, events they authored.

- Signing public key and encryption public key (a member's trove-held OpenPGP
  key can be both, #231).
- Display name, status (active, revoked), the event that enrolled and the one
  that revoked them.

kdbx4 has no identities: anyone with the composite key is the same user. On
the trove-on-kdbx profile the registry lives in Meta `CustomData`.

### Keyslot

Identity: UUID. Relationships: one member (optional for a plain password slot,
open question 4).

- Kind: password (Argon2id over a composite key of password, optional keyfile,
  optional challenge-response) or public key.
- KDF parameters (password slots).
- Container key wrapped under the slot's key.

kdbx4 has exactly one implicit slot: the composite key derives the master key
directly. Revoking a slot means rotating the container key and re-wrapping for
everyone left.

Placement: in the trove header, outside the kdbx body, because it is needed to
decrypt the body. Covered by the header MAC.

### Wrapped group key (keyring)

Identity: access-group name + generation + member fingerprint.

- The access group's symmetric key for that generation, wrapped to the member's
  public key (or inside their keyslot).
- Retired generations, kept wrapped to current members only if history is not
  re-sealed on rotation (open question 10).

kdbx4 has no keyring; the trove-on-kdbx profile keeps it in Meta `CustomData`
(#232).

Stage 1: inside the kdbx body.

### Permission map

Identity: scope (database, group UUID or entry UUID) + sequence number.

- Rules: member or access group → rights (read, write, use, admin).
- Admin signature over the canonical encoding, admin fingerprint.
- Inheritance from group to entry.

kdbx4 has no permissions. The trove-on-kdbx profile keeps the map in `CustomData`
(Meta for the database, Entry for per-entry rules).

Stage 1: inside the kdbx body.

### Relationships

```
Header ── Keyslot* ──wraps──> container key ──decrypts──> body
                └─(member)──> Member ──< WrappedGroupKey >── access group
Meta ── Group (tree by parent UUID) ── Entry
                                        ├─ field head ──> FieldVersion ──> Value
                                        │                     │  └─ parents ──> FieldVersion
                                        │                     └─ created by ──> Event
                                        └─ attachment ──> BlobRef ──> Blob (out of band)
Event ──parents──> Event;  Event ──author──> Member
PermissionMap ──scope──> Meta | Group | Entry;  signed by admin Member
DeletedObject ──> UUID of a removed Group or Entry
```

## Where the model differs from kdbx4

| Difference | trvdb | What kdbx4 does instead |
| --- | --- | --- |
| Per-field history | One version per field write, values deduplicated by content address across versions and entries | Whole-entry snapshots in `History`, capped by `HistoryMaxItems` / `HistoryMaxSize`; field history derived from snapshots |
| Record-oriented encryption | Each record encrypted on its own (stage 2), so an edit writes only changed records | One HMAC'd block stream over one compressed XML document; any edit rewrites and re-encrypts the file, with a fresh master seed |
| Sealed metadata | Titles, group names and parentage, usernames can be sealed to an access group | Everything is under the one master key; only values can be sealed, as opaque `CustomData` tokens (#232) |
| Signed write log | In-file, hash-linked, signed events; verified on open, merge and sync | Timestamps only, no author; nothing detects a rollback or a rewrite |
| Out-of-band blobs | Encrypted blobs beside the file, addressed by content hash, transferred only when missing | Binary pool inside the file, rewritten on every save |
| Identity and keyring records | Members, keyslots, wrapped group keys and the permission map are first-class records | One shared composite key; trove-on-kdbx smuggles identities and keys through `CustomData` |

## Copied from kdbx4 unchanged

- **Argon2id and the composite key** (password, keyfile, challenge-response),
  now per password keyslot. YubiKey unlock keeps working.
- **The times model**: `last_modification` and `location_changed` drive merge
  exactly as in kdbx4.
- **UUID keys** for databases, groups and entries. Converting keeps every UUID.
- **Deleted-object tombstones** with the same merge meaning.
- **Recycle bin**: a group named by UUID in meta, delete moves there first,
  deleting inside the bin destroys.
- **Protected-value flags** on fields and attachments, with the same defaults
  (`Password` and `otp` protected).
- **otpauth URIs** in the `otp` field.
- **`{REF:…}` field references**, stored verbatim. trove-core does not resolve
  them today (it resolves its own `trove://` references); trvdb changes neither.

## Operations

One row per public method of `Database` in `crates/trove-core/src/lib.rs`,
`revisions.rs` and `settings.rs`, then the capability-gated operations. The
Reads and Writes columns name the trvdb records above. "Event" is left out of
Writes: on trvdb every write also appends one write-log event and checks the
permission map.

"kdbx4" says whether kdbx4 supports the operation. "Trait note" flags methods
whose current signature or shape is kdbx-specific, or that need not be backend
methods at all (computed from other calls in `Database`).

### Lifecycle and credentials

| Method | Reads | Writes | kdbx4 | Trait note |
| --- | --- | --- | --- | --- |
| `create` | | Header, Keyslot, Meta, root Group | yes | `DatabaseFormat::create`, takes `Credential` |
| `create_with_key` | | as `create` | yes | as `create` |
| `create_with_challenge_response` | | as `create` | yes | as `create` |
| `open` | Header, Keyslot, all body records | | yes | `DatabaseFormat::open`; format from `sniff` |
| `open_with_key` | as `open` | | yes | as `open` |
| `open_with_challenge_response` | as `open` | | yes | as `open` |
| `reload` | as `open` | | yes | backend method |
| `changed_on_disk` | file stamp | | yes | file-level, stays in `Database` |
| `save` | file stamp, on-disk copy (merge) | every dirty record | yes | backend method; trvdb writes the lowest minor in use |
| `take_merged_on_save` | merge summary | | yes | stays in `Database` |
| `path` | | | yes | stays in `Database` |
| `current_password` | Credential | | yes | assumes one credential; trvdb has one per keyslot |
| `current_keyfile` | Credential | | yes | as `current_password` |
| `rekey` | Keyslot | Header, Keyslot | yes | trvdb: replace the caller's own slot; container key unchanged |
| `set_argon2_params` | Header | Header (KDF parameters) | yes | trvdb: per keyslot KDF; kdbx4: the body KDF in the kdbx header |
| `db_info` | Header, Meta, counts | | yes | `DbInfo` fields are kdbx-shaped (version, cipher, compression, kdf) |
| `generate_trove_uuid` | | | yes | not a backend method |
| `database_metadata` | Meta | | yes | backend method |
| `set_database_metadata` | Meta | Meta | yes | backend method |

### Entries and fields

| Method | Reads | Writes | kdbx4 | Trait note |
| --- | --- | --- | --- | --- |
| `add_entry` | Group | Entry, Group (created path) | yes | backend method |
| `list_entries` | Entry, Group | | yes | backend method (iterate) |
| `describe` | Entry, Group, FieldVersion, Value | | yes | derivable from iterate + get |
| `get_entry` | Entry, Group | | yes | backend method |
| `find_by_title` | Entry, Group | | yes | derivable |
| `get_field` | Entry, FieldVersion, Value | | yes | backend method |
| `set_field` | Entry | Entry, FieldVersion, Value | yes | backend method |
| `remove_field` | Entry | Entry, FieldVersion (tombstone) | yes | backend method |
| `fields_with_prefix` | Entry | | yes | derivable from field names |
| `custom_field_names` | Entry | | yes | backend method (field names) |
| `get_entry_tags` | Entry | | yes | backend method |
| `set_entry_tags` | Entry | Entry | yes | same as `set_tags`; one trait method |
| `set_tags` | Entry | Entry | yes | as `set_entry_tags` |
| `set_entry_icon` | Entry, Meta (icons) | Entry | yes | backend method |
| `set_entry_expiry` | Entry | Entry | yes | backend method |
| `delete_entry` | Entry | DeletedObject; Entry removed | yes | backend method |
| `recycle_entry` | Entry, Meta (bin) | Entry (moved) or DeletedObject | yes | composed from move + delete + bin lookup |
| `move_entry` | Entry, Group | Entry (parent, `location_changed`) | yes | backend method |
| `move_entry_to_path` | Entry, Group | Entry (parent, title) | yes | composed |
| `copy_entry` | Entry, FieldVersion, Value, BlobRef | Entry, FieldVersion, BlobRef (values and blobs shared by address) | yes | backend method; trvdb copies no bytes |
| `strip_materialize` | Entry, BlobRef | Entry, FieldVersion (tombstones), BlobRef | yes | composed from field and attachment calls |
| `totp_now` | Entry, `otp` field | | yes | derivable from `get_field` |
| `totp_at` | as `totp_now` | | yes | derivable |
| `set_totp_uri` | Entry | Entry, FieldVersion, Value | yes | derivable from `set_field` |
| `resolve_ref` | Entry, Group, FieldVersion, Value | | yes | derivable |

### Attachments

| Method | Reads | Writes | kdbx4 | Trait note |
| --- | --- | --- | --- | --- |
| `attach_binary` | Entry | BlobRef, Blob (or inline Value below the threshold) | yes | backend method |
| `read_binary` | BlobRef, Blob | | yes | backend method; trvdb can fail per blob (missing, tampered) |
| `rename_attachment` | Entry, BlobRef, settings | BlobRef, FieldVersion, settings | yes | rename is backend; settings rewrite is composed |
| `remove_binary` | Entry | BlobRef removed (blob left to GC) | yes | backend method |

### Groups

| Method | Reads | Writes | kdbx4 | Trait note |
| --- | --- | --- | --- | --- |
| `list_groups` | Group | | yes | backend method (iterate) |
| `group_exists` | Group | | yes | derivable |
| `add_group` | Group | Group | yes | backend method |
| `remove_group` | Group, Entry, Meta (bin) | Group/Entry moved, or DeletedObject | yes | backend method |
| `set_group_tags` | Group | Group | yes | backend method |
| `set_group_order` | Group | Group (sibling order) | yes | backend method |
| `recycle_bin_path` | Meta, Group | | yes | backend method |
| `plan_group_transfer` | Group, Entry | | yes | derivable |
| `copy_group` | Group, Entry, FieldVersion, BlobRef | Group, Entry, FieldVersion, BlobRef | yes | composed from copy_entry + add_group |
| `move_group_to_path` | Group | Group (parent, name) | yes | backend method |

### Search

| Method | Reads | Writes | kdbx4 | Trait note |
| --- | --- | --- | --- | --- |
| `search_entries` | Entry, Group, unprotected Values | | yes | derivable; trvdb cannot match sealed fields without the key |
| `search_entries_with` | Entry, Group, unprotected Values, BlobRef names | | yes | as `search_entries` |

### Merge and sync

| Method | Reads | Writes | kdbx4 | Trait note |
| --- | --- | --- | --- | --- |
| `merge_from` | all records of both sides | any record; DeletedObject; Event (merge) | yes | backend method; same format only, cross-format refuses and names `trove convert` |
| `sync_with` | all records of both sides | both copies | yes | backend method; whole-file on kdbx4 and trvdb stage 1 |

### Revisions (`revisions.rs`)

| Method | Reads | Writes | kdbx4 | Trait note |
| --- | --- | --- | --- | --- |
| `revision_summaries` | Entry | | yes | backend method |
| `entry_revisions` | Entry history (kdbx4); FieldVersion (trvdb) | | yes | `index: Option<usize>` assumes a snapshot list; trvdb rebuilds snapshots from field versions |
| `entry_version` | as `entry_revisions`, BlobRef | | yes | `EntryVersion` holds a `keepass::db::Entry`; needs a trove-owned type before the trait |
| `apply_entry_version` | Entry, Group | Entry, Group, FieldVersion, BlobRef; removes DeletedObject | yes | as `entry_version` |
| `save_entry_version` | as `apply_entry_version` | as `apply_entry_version` + save | yes | composed (apply + save + rollback) |

### Settings (`settings.rs`)

Settings documents stay where they are today on both formats: entry
attachments (`*.settings`) and group or Meta custom data
(`Trove.*.settings`). None of these need their own trait method.

| Method | Reads | Writes | kdbx4 | Trait note |
| --- | --- | --- | --- | --- |
| `settings_document` | BlobRef | | yes | composed from `read_binary` |
| `set_settings_document` | BlobRef | BlobRef | yes | composed from attachment calls |
| `ensure_settings_item` | BlobRef | BlobRef | yes | composed |
| `store_settings` | BlobRef, Entry fields | BlobRef, FieldVersion (legacy fields removed) | yes | composed |
| `upsert_settings_item` | BlobRef | BlobRef | yes | composed |
| `forget_attachment_settings` | BlobRef | BlobRef | yes | composed |
| `group_settings` | Group / Meta custom data | | yes | needs a custom-data get on Group and Meta |
| `set_group_settings` | Group / Meta custom data | Group / Meta custom data | yes | needs a custom-data set on Group and Meta |
| `entry_settings` | BlobRef, Entry fields | | yes | composed |
| `effective_settings` | Entry, Group, Meta custom data | | yes | composed |
| `settings_chain` | Group, Meta custom data | | yes | composed |
| `legacy_settings` | Entry fields | | yes | composed |
| `legacy_settings_fields` | Entry fields | | yes | composed |

### Capability-gated operations

Default trait implementations return `Error::Unsupported`. Cap names as in #240.

| Operation | Cap | Reads | Writes | kdbx4 | Issue |
| --- | --- | --- | --- | --- | --- |
| `history(id, Some(field))` | `field-history` | FieldVersion, Value | | derived from snapshots only; true per-field history unsupported | #245 |
| restore field version | `field-history` | FieldVersion | FieldVersion, Value | unsupported | #245, #227 |
| purge value | `field-history` | Value, PermissionMap | Value (ciphertext erased), Event | unsupported | #245 |
| `seal_field` / unseal | — (values) | WrappedGroupKey, Value | FieldVersion, Value | planned via `CustomData` tokens (#232), not built | #232 |
| seal title, group, username | `sealed-metadata` | WrappedGroupKey | Group, Entry | unsupported | #246 |
| write-log verify | `write-log` | Event, FieldVersion, Member | | unsupported | #234 |
| write-log acknowledge | `write-log` | Event, Member (admin) | Event (patch) | unsupported | #234 |
| blob put / get / gc | `blob-store` | BlobRef, Blob, FieldVersion | Blob | unsupported (scope open, #247) | #247 |
| delta sync | `delta-sync` | every record changed since the common point | changed records only | unsupported; `sync` stays whole-file and says so | #230 |
| add / remove keyslot | — | Keyslot | Header, Keyslot; rotates container key on removal | unsupported (one composite key) | #256 |
| members, keyring, permissions | — | Member, WrappedGroupKey, PermissionMap | same, admin-signed | not built; trove-on-kdbx via `CustomData` | #231, #232, #233 |

### Review notes for #239

- The trait needs far fewer methods than `Database` has. Search, TOTP,
  `resolve_ref`, path helpers, settings and most `revisions.rs` calls compose
  from a core of: iterate, get/set entry, get/set/remove field, field names,
  attachment get/put/remove/rename, group add/remove/move/order/tags, custom
  data get/set on Group and Meta, meta get/set, merge, save, reload, info.
- `create*` and `open*` become `DatabaseFormat::create` / `open` taking one
  `Credential`.
- kdbx types leak through `EntryVersion` (a `keepass::db::Entry`), `DbInfo`
  field meanings and the `Option<usize>` history index. These need trove-owned
  shapes before the trait can be format-neutral.
- `current_password`, `current_keyfile` and `rekey` assume one credential per
  database. On trvdb they apply to the caller's own keyslot.

## Placement by stage

| Record | Stage 1 (kdbx body behind prologue) | Needs record container |
| --- | --- | --- |
| Database meta | kdbx `Meta` + `CustomData` | no |
| Group, entry | kdbx `Group`, `Entry` | no |
| Deleted object | kdbx `DeletedObjects` | no |
| Field version, value | trove extension data in the body | no (cheaper with it) |
| Blob reference | in the entry | no |
| Blob | outside the file | no |
| Write-log event | trove extension data in the body | no (cheaper with it) |
| Member, wrapped group key, permission map | trove extension data in the body | no |
| Keyslot | trove header, outside the body | no |
| Any record exchanged by delta sync | — | **yes** (#230) |

## Open questions

These need a maintainer decision or belong in the spec (#241). Each names the
issue that owns it.

1. **Where trove's records live in stage 1.** Inside the kdbx body as
   `CustomData` (simple, and what #256 describes) or in a TLV extension area
   with the critical and preserve bits (#241). `CustomData` gives no critical
   bit, so an old reader could rewrite records it does not understand. (#241)
2. **How the random container key opens the kdbx body.** keepass-rs takes a
   composite key and always runs the body KDF. Options: pass the container key
   as a raw 32-byte keyfile with minimal KDF parameters, or patch the fork to
   accept a derived key. (#241, #243)
3. **Content-address hash.** An unkeyed hash of a secret lets anyone holding
   the file confirm a guess offline and see which entries share a password.
   Proposal: a keyed hash under a per-database key, and dedup only within one
   sealing scope (access group + generation), so equality across access groups
   is not visible. (#241, #245)
4. **Password-only members and signatures.** The write log needs a signing key
   per author. Does a password keyslot get a generated keypair stored inside
   it, or must every member bring a public key? (#231, #234)
5. **Field version identity.** Event hash (proposed above) or a UUID plus
   sequence number. The hash makes tampering visible; the sequence number is
   simpler to merge. (#241)
6. **Merge granularity.** kdbx4 merges whole entries by `last_modification`.
   Per-field versions allow field-level merge, which keeps both sides' edits to
   different fields. That improves on kdbx4 but departs from "copy the times
   model outright". Field-level or entry-level? (#241, #245)
7. **What stays in the clear for merge and sync** when metadata is sealed. At
   least UUIDs, parent UUIDs, times and tombstones; are field names and
   attachment names clear or sealed? (#246)
8. **Terminology.** "Group" already means a folder. This doc calls a set of
   members sharing a key an "access group"; #232 calls it an "ACL group". Pick
   one before the spec. (#241)
9. **Settings documents on trvdb.** This doc keeps them as attachments and
   custom data, unchanged. Promoting them to records would make them sealable
   and signable separately, at the cost of a second code path. (#241)
10. **Rotation and history.** On revocation, re-seal every historical version
    (#245 says so) or keep retired group keys wrapped to current members
    (#232 leaves both open). Re-sealing rewrites every version; keeping retired
    keys leaves old values readable to anyone who kept a retired key. (#245)
11. **Blob store scope.** trvdb only, or a kdbx4 sidecar too. Already a human
    decision in #439. (#247)
