# Colleague feature ideas — 2026-08-12

Four ideas, checked against the code and the KDBX format. Short version: #1 is
mostly already in the format and half-wired in trove, #2 already ships in one
direction, #3 needs a server to be honest, and #1 turns out to be a
*prerequisite* for #2 rather than an independent feature.

Three of the four are already on the roadmap in [status.md](status.md) (#27,
#14/#15, #16) — the colleague converged on them independently, which is a decent
signal. What's new is the dependency ordering.

---

## 1. Versioned values (each write doesn't wipe the previous one)

**KeePassXC does support this.** KDBX4 entries carry a `<History>` element
holding full snapshots of previous entry states. KeePassXC snapshots on every
edit, shows them in the entry's *History* tab, and lets you diff/restore/delete
them. `Database Settings → History` exposes the caps. So this isn't a gap in the
format or in KeePassXC — it's a gap in trove.

**Where trove stands.** trove already writes the *policy* but never the *data*:

- [lib.rs:1233-1237](../crates/trove-core/src/lib.rs#L1233-L1237) backfills
  `history_max_items = 10` and `history_max_size = 6 MiB` into `<Meta>`.
- [`set_field`](../crates/trove-core/src/lib.rs#L505-L520) then mutates through
  plain `entry_mut()` and overwrites the old value in place. No snapshot.

So every trove edit destroys the previous value, in a vault that advertises a
10-item history. KeePassXC-written history *is* preserved across a trove save
(keepass-rs round-trips the element) — trove just never adds to it.

**The lift is small.** keepass-rs 0.13.16 already ships the mechanism:
`EntryMut::track_changes()` / `edit_tracking()` return an `EntryTrack` whose
`Drop` clones the pre-edit entry into `entry.history` and bumps
`last_modification`. Switching the mutating paths (`set_field`,
`attach_binary`, `remove_binary`, `remove_field`, `move_entry`, `set_totp_uri`)
from `edit`/`entry_mut` to the tracking variant is the bulk of it.

Two things the library won't do for us:

- **Pruning.** `History::add_entry` just `insert(0, …)` — it never enforces
  `HistoryMaxItems`/`HistoryMaxSize`. trove has to prune, or vaults grow without
  bound and KeePassXC's caps get quietly violated.
- **Orphaned attachments.** Attachment back-references are keyed
  `(entry_id, history_index)`, so a versioned attachment's old blob stays alive
  in the binary pool as long as a history entry points at it. Pruning history
  must drop attachments whose last reference went away.

**On "hide a trove-only version system behind the KeePassXC-visible value":**
that instinct is already satisfied by native history, and a custom scheme would
be strictly worse. Native history is invisible in KeePassXC's normal entry view
(it's behind a tab), so you already get "shows the same values, versions
underneath". A trove-private encoding — `value.v1`, `value.v2`, a packed JSON
blob in Notes, a hidden group — would instead: show up as visible junk custom
fields in KeePassXC, escape its history caps, bloat every read of the entry, and
confuse the merge algorithm (see #2). The format already won this argument.

**Sizes.** The colleague's instinct is right — 6 MiB *per entry* is the
KeePassXC default trove already sets, and a keypair or a kubeconfig is a few KB,
so that's hundreds of versions per entry before pruning bites. If we start
versioning larger config blobs, raise the per-entry cap rather than inventing an
out-of-band store (that's roadmap #28, a separate problem).

---

## 2. Sync one vault against another (laptop copy ↔ Google Drive copy)

**Half of this already ships.** `trove merge <SOURCE>` exists today:

- CLI: [main.rs:444](../crates/trove-cli/src/main.rs#L444), handler
  [`cmd_merge`](../crates/trove-cli/src/main.rs#L3348)
- Core: [`Vault::merge_from`](../crates/trove-core/src/lib.rs#L917) — KDBX
  standard three-way semantics, last-write-wins by modification time, the same
  algorithm `keepassxc-cli merge` applies, so either tool can reconcile the same
  pair. It refuses two unrelated vaults (different root UUID) instead of
  panicking, and reports created/updated/relocated/deleted counts.

**What's missing for what the colleague is describing:**

- It's one-directional: source is read-only, only `--vault` is written. No
  push-back, so "sync between them" is two manual invocations plus a file copy.
- No `trove sync` verb, no lock coordination, no conflict *detail* (just counts).
- Cloud caveat: Google Drive syncs the encrypted `.kdbx` as an opaque blob, so
  simultaneous edits produce Drive "conflicted copy" files rather than anything
  mergeable at the storage layer. The workable shape is: local vault is
  authoritative, `trove sync <remote.kdbx>` merges remote→local, then writes
  local→remote atomically, with a sidecar lock to serialize clients.

This is roadmap #14 (sync engine, backing-store agnostic) and #15 (optional
self-hosted server).

**The important bit — #1 is a prerequisite for #2.** The KDBX merge algorithm
resolves conflicts *using entry history*: keepass-rs merges the two histories and
raises `DuplicateHistoryEntries` when two snapshots share a timestamp but
diverged. Because trove writes no history, merging two trove-edited copies has
nothing to reconcile — last-write-wins picks the newer mtime and the other
person's edit disappears with no record it ever existed. Shipping sync before
history means shipping silent data loss. So #27 should move ahead of #14 on the
roadmap, not because it's user-visible, but because it's load-bearing.

---

## 3. Users, groups, ACLs, and an access audit log

**Correction to an earlier version of this doc.** I first wrote that ACLs can
only ever be advisory in a KDBX file. That's wrong, and the objection only holds
for a vault where everything is encrypted under the single master key. Add a
*second* encryption layer inside the field values, keyed per ACL group, and read
access becomes cryptographically enforced. This is the 1Password / Bitwarden
shape (per-vault or per-organization keys, wrapped to each member's public key)
and it works on top of KDBX.

### The scheme, made concrete

- **Identity**: each member has a keypair. trove already stores and serves SSH
  and OpenPGP keypairs through its agents, so a member's existing trove-held
  OpenPGP key can *be* their identity — no new key type to invent.
- **Group key**: each ACL group (`prod-admins`) has a symmetric key, wrapped once
  per member public key.
- **Keyring storage**: KDBX4 `<CustomData>` — a `HashMap<String, CustomDataItem>`
  present on Meta, Group and Entry, holding String *or* Binary values with a
  last-modified timestamp. It is the format's sanctioned third-party extension
  slot and KeePassXC preserves it across saves. Meta-level for the database
  keyring, entry-level for "which group seals which field". trove doesn't touch
  `CustomData` today, so the namespace is clear.
- **Sealed values**: an ACL'd field holds an opaque token
  (`trove-sealed:v1:<group>:<nonce>:<ct>`, AEAD under the group key) instead of
  plaintext. trove unwraps the group key with your private key and decrypts;
  everyone else sees the token.

**What this genuinely buys**: a member without the group key cannot read the
value — not through trove, not through KeePassXC, not with a hex editor. That is
a real ACL, enforced by cryptography rather than by UI.

### What the crypto still doesn't give you

These are design constraints to write down, not reasons to avoid it:

1. **Writes are detectable, not preventable.** Anyone who can open the container
   can overwrite a sealed field's ciphertext, delete the entry, or drop someone's
   wrap from the keyring — without being able to read anything. Signing sealed
   values (writer's key) and the keyring (an admin key) makes tampering
   *evident*, but nothing offline can *refuse* the write. Prevention needs a
   party that can say no, i.e. the server (#15).
2. **Revocation means rotation, and isn't retroactive.** Removing Alice = mint a
   new group key, re-seal every value in the group, re-wrap to the remaining
   members. Alice still holds the old group key and any copy of the file she
   kept, so every secret she could read must be rotated *at the source* — change
   the AWS password, not just the vault. 1Password has exactly this property. The
   docs need to say so, or "remove user" reads as more than it is.
3. **Metadata stays readable to anyone with file access.** Entry titles, the
   group tree, usernames, URLs, timestamps, and which fields are sealed to which
   group all remain under the single master key. Everyone sees that
   `prod/aws-root` exists and when it last changed. Sealing titles too is
   possible, but then KeePassXC shows a vault of opaque garbage names and the
   interop story dies — 1Password doesn't have this problem only because it
   doesn't need to produce a KeePass-readable file.
4. **Read auditing is still impossible offline.** This part of the original
   objection survives untouched, and it's independent of the crypto: a read is a
   local decrypt, producing no record anywhere the other members can see.
   *Writes* can be logged credibly (signed, and they land in the shared file).
   "What keys is each user accessing" cannot be answered without a mediator, so
   that half of the ask still needs #15.
5. **The container credential is shared.** Everyone needs *some* way to open the
   kdbx itself. Wrapping the master key per user (roadmap #16) means KeePassXC
   can no longer open the file at all, since it expects a password or keyfile. So
   realistically: one shared container credential, with per-group sealing on top
   — the ACL is about the sealed fields, not about opening the file.

### The interop cost — the actual product decision

A sealed field is opaque to KeePassXC *even for a member*, because KeePassXC
doesn't know the scheme. So sealing an entry makes it trove-only in practice, and
disables KeePassXC's password-health reports, HIBP checks, browser autofill, and
TOTP on those fields. That argues for sealing per-field and per-entry rather than
vault-wide, and for being loud in the UI about what's sealed.

### Interactions with #1 and #2

- **History**: snapshots hold values sealed under whatever group key was current
  at the time, so rotating a key either requires re-sealing history (expensive,
  and it rewrites the timestamps merge depends on) or retaining retired group
  keys wrapped to current members. Without that, revocation doesn't cover
  history. Needs deciding alongside the pruning design.
- **Merge**: a member who *can't* read a field can still merge its ciphertext,
  since merge only needs timestamps. Sync works without read access — a genuinely
  nice property of this design.

Note "audit" already means something else in trove: `analyze --hibp` and the
generate/estimate commands audit *password strength*. There is no access-logging
surface in the codebase today.

Either way this changes [threat-model.md:130](threat-model.md#L130), which
currently says trove has no server and therefore needn't assume an honest one.
Read-ACLs don't need that assumption; write-prevention and read-auditing do.

---

## 4. A native trove format, with kdbx4 as one supported backend

Every constraint the three sections above ran into came from one requirement:
*the file must stay a valid kdbx4 that KeePassXC can read*. Per-entry-only
history, the 10-item/6 MiB caps, opaque sealed fields, unavoidable metadata
exposure, whole-file sync — all of it is the format, not the idea. So making the
format pluggable is the move that unblocks the rest, and keeping kdbx4 read/write
costs little once the seam exists.

### The seam already exists

- **All 33 `keepass::` references live in one file**,
  [trove-core/src/lib.rs](../crates/trove-core/src/lib.rs). trove-cli, troved and
  trove-desktop contain zero — they already talk only to `Vault`'s public methods.
  Extracting a `VaultBackend` trait is a refactor of one file, not a rewrite.
- [`VaultInner`](../crates/trove-core/src/lib.rs#L154-L169) — path, password,
  keyfile, challenge-response, `keepass::Database` — is the entire KDBX-shaped
  state, and it's already `pub(crate)`. That struct becomes the KDBX backend.
- The shared types generalise cleanly:
  [`DbInfo`](../crates/trove-core/src/lib.rs#L119-L127) is already stringly-typed
  (`version`, `cipher`, `kdf`), and `MergeSummary` is format-neutral counts.
- One real leak to fix: `pub use keepass::ChallengeResponseKey`
  ([lib.rs:152](../crates/trove-core/src/lib.rs#L152)) puts a keepass type in
  trove's public API. Needs a trove-owned equivalent.

This mirrors what the project already decided one level up for key operations —
[agent-routing.md](agent-routing.md) frames trove as a *router* over plural
backends, and [multi-vault.md](multi-vault.md) notes that "which vault owns this
key" generalises to "which *backend* owns this key". Storage format is the same
pattern on a third axis: format (kdbx4 / native), backing store (file / S3 / git,
roadmap #14), key-operation backend (vault / smartcard / platform agent).

Note this is a different axis from **multi-vault**, which already ships phase 1:
that's several kdbx *files* unlocked at once, not several formats.

### Capabilities, not a lowest common denominator

The one design rule that decides whether this is worth doing. If the trait is the
*intersection* of what both formats support, the native format buys nothing and
KDBX's limits become trove's limits everywhere. So the trait carries a capability
query, and commands needing an absent capability **fail loudly** — "this vault is
kdbx4; per-field history needs the trove format, see `trove convert`" — rather
than silently degrading to something weaker. Silent degradation in a secrets tool
is how people end up believing a value is sealed when it isn't.

### Where the native format should deviate

Each of these is a constraint hit earlier in this document, not a wishlist item:

1. **Per-field history**, not whole-entry snapshots — removes the granularity
   gotcha and the caps awkwardness. With a content-addressed value store,
   identical values dedup across versions *and* entries for free.
2. **Record-oriented encryption → real delta sync.** kdbx4 is a single HMAC'd
   block stream over one gzipped XML document, so a one-character edit rewrites
   the whole file. That is *why* Google Drive re-uploads everything and produces
   whole-file conflicts. Encrypt per record and roadmap #14 becomes genuine
   incremental sync instead of whole-file merge with a nicer UI. Probably the
   single biggest win here.
3. **Sealed metadata** — titles, group tree, usernames can be sealed too, because
   there's no KeePassXC left to keep readable.
4. **Append-only signed write log**, in-file — the credible "who changed what"
   from §3 without needing a server.
5. **Out-of-band blob store** for attachments — roadmap #28 falls out of (2), so
   large keys and config files stop bloating the main file.
6. **Identity and group keyring as first-class records** rather than smuggled
   through `CustomData`.

### Where it should copy kdbx4 outright

The "inspiration" half matters as much as the deviation. These are solved, and
re-deriving them is how you introduce subtle merge bugs:

- **Argon2id + composite key** (password / keyfile / challenge-response). Proven,
  and it keeps YubiKey unlock working unchanged.
- **The times model** — `last_modification`, `location_changed` — and UUID-keyed
  entries and groups. The merge algorithm rests on exactly these.
- **Deleted-object tombstones.** Essential for correct merge, easy to get wrong.
- **Recycle-bin semantics, protected-value flags, otpauth URIs, `{REF:…}`
  syntax.** No reason to deviate; deviating costs interop for nothing.

### The honest costs

- **Lock-in, and the credibility that rests on not having it.** trove's pitch is
  that your secrets sit in a standard file any tool can open. A native format is
  lock-in unless kdbx4 stays a first-class, tested, *supported* backend — not a
  legacy path — and unless `trove convert` is lossless where the feature sets
  overlap and loud about what's dropped where they don't.
- **You become your own spec and your own auditor.**
  [keepass-spec-tests](../crates/keepass-spec-tests/) exists precisely to prove
  KDBX correctness against *other people's* implementations (it pins keepass
  0.12.5 and tests against `keepassxc-cli`). A native format has no external
  implementation to test against. Mitigation: write the spec as a document
  *first*, review it before any code exists, then property-test round-trips and
  fuzz the parser. The spec doc is the real deliverable.
- **A new container format is the highest-risk code in the project.** Prefer
  boring composable primitives, or an existing container, over hand-rolled AEAD
  framing.
- **Double surface area, permanently.** Every future feature is either
  implemented twice or explicitly "kdbx4: unsupported".

### A path that isn't a big bang

1. **Extract `VaultBackend` + `Caps`, KDBX as the only impl.** Pure refactor, no
   behaviour change, provable by the existing test suite. Everything below then
   happens without touching the CLI, daemon or desktop again.
2. **Ship entry history on the KDBX backend** (§1 — nearly free, keepass-rs
   already has it). Useful immediately, and it exercises the capability plumbing
   against a real feature.
3. **Write the native format spec.** Review before implementing.
4. **Implement the native backend + `trove convert` both ways**, with a lossiness
   report.
5. **Then the features kdbx4 can't express**: per-field history, sealed metadata,
   signed write log, delta sync.

### Decided: kdbx4 stays the default, `trvdb1` is opt-in

**kdbx4 remains the default format.** You move a vault to the native format —
working name `trvdb1` — when, and only when, you want a feature kdbx4 can't
express. This keeps the no-lock-in promise as the *default experience* rather
than a fallback, and it means most users never meet the second format at all.

Four consequences that follow directly:

**1. Never auto-convert. Refuse and name the command.** The moment someone uses a
trvdb1-only feature on a kdbx4 vault, the tempting behaviour is to silently
upgrade the file. That would break KeePassXC's ability to open a vault the user
may be sharing with colleagues, possibly mid-sync, without consent — the exact
promise the default is protecting. So: refuse, and say what to run.

**2. The error message is now a product surface.** With kdbx4 as the default,
most users meet trvdb1 for the first time *via an error*. `Error::Unsupported`
therefore has to carry the capability, the current format, and the exact command:

```
per-field history needs the trvdb1 format; this vault is kdbx4.
  convert with:  trove convert ~/vault.kdbx --to trvdb1
  what you lose: KeePassXC can no longer open it (trove convert --to kdbx4 reverses this)
```

**3. Conversion must be reversible, and lossiness stated before it happens.**
"No lock-in" survives as: *you can always get back to a standard file, and we
tell you what that costs.* So `trove convert --to kdbx4` from a trvdb1 vault
reports what it will drop — per-field history collapsed to entry snapshots,
sealed metadata unsealed or dropped, signed log discarded — and asks, rather than
discovering it halfway through. Dry-run by default is worth considering.

**4. Capabilities need to be discoverable without hitting an error.** `db-info`
should print the format and what it supports, and something like
`trove formats` should show the matrix. Users on the default format need a way to
answer "what am I missing?" by asking, not by failing.

### One push-back: put the version in the header, not the name

`trvdb1` reads naturally *because* `kdbx4` does — but note that kdbx4 is one
format named `kdbx` with a version field in its header (3.1, 4.0, 4.1), which is
why the ecosystem can say "kdbx4" informally while the file extension, magic
bytes and tooling never churn. If `1` is baked into the format's identity, then
trvdb2 churns the extension, the magic bytes, the `--format` flag and every doc
that mentions it.

Suggest: format is **`trvdb`**, extension `.trvdb`, magic `TRVDB\0` followed by a
`u16` version; the CLI and docs say "trvdb1" informally exactly the way people
say "kdbx4". Costs nothing now, saves a migration later.

### Encapsulating format versions

With the version in the header rather than the name, the format needs an explicit
compatibility contract. kdbx4 provides both the pattern to copy and a scar trove
already carries.

**Fixed header prologue, forever.** `TRVDB\0` + `u16` major + `u16` minor at
offset zero, parseable without knowing the version. Those bytes never move. This
is what lets a reader make an informed refusal instead of guessing.

**The compatibility rule, copied from kdbx:**

- **Minor bump = backward compatible.** A reader that knows major *N* opens any
  minor of *N*, ignoring what it doesn't recognise.
- **Major bump = breaking.** Refuse, and say so precisely.

**Write the lowest minor that expresses the features actually in use.** This is
the part that goes beyond kdbx, and it comes straight from trove's own scar:
[lib.rs:327-333](../crates/trove-core/src/lib.rs#L327-L333) force-writes KDBX 4.1
because the 0.13 writer *only* emits 4.1 and would reject a 4.0 file outright. If
trvdb writes "newest I know" unconditionally, a vault using no v1.3 features
becomes unreadable to a v1.2 reader for no reason. Emitting the minimum needed is
what makes new versions genuinely encapsulated rather than merely documented.

**Self-describing records with two flag bits.** Every record and field is
length-prefixed TLV — the length is what makes skipping possible at all — and
carries two independent bits:

| Bit | Unknown to this reader → |
| --- | --- |
| **critical** | refuse to open (don't silently ignore) |
| **preserve** | retain verbatim when rewriting the file |

Both matter, for different reasons. **Critical** is the security-relevant one: a
future "this field is sealed" marker must *not* be skippable, or an old reader
displays ciphertext as if it were the value — or worse, overwrites a sealed field
it couldn't read. **Preserve** stops an older trove from silently destroying data
it didn't understand when it opens, edits and saves a newer vault. PNG's
critical/ancillary + copy-safe bits and TLS's extension model are the precedents;
the four combinations are all meaningful.

**Crypto agility on a separate axis.** kdbx4 gets this right: cipher UUID plus
KDF parameters live in a VariantDictionary, so adding a new AEAD or KDF doesn't
bump the container version. Copy that, or every algorithm change becomes a
breaking format change.

**The version bytes must be authenticated.** Header, version and algorithm
parameters all have to be covered by the AEAD/MAC. Otherwise an attacker edits
the version field to select weaker parameters and you've built a downgrade attack.
kdbx4 HMACs its header for exactly this reason — easy to overlook, expensive to
retrofit.

**Refusal has to be actionable.** Today `UnsupportedVersion` maps to the bare
string "unsupported kdbx version"
([lib.rs:1189-1190](../crates/trove-core/src/lib.rs#L1189-L1190)). The trvdb
version should say: this vault is trvdb 2.x, this build reads up to 1.x, upgrade
to trove ≥ X.

**How to test forward-compatibility before the future exists.**
[keepass-spec-tests](../crates/keepass-spec-tests/) already does the backward half
for kdbx — a version matrix pinning old producers (keepass 0.12.5) to prove
cross-version reads. Do the same for trvdb from v1: keep a committed corpus of
files written by every past version and assert the current reader handles them
all. For the forward direction, **synthesize a "future" file** by hand — one with
an unknown non-critical field and an unknown critical field — and assert the
current reader skips the first and refuses the second. That's how the contract
stays real rather than aspirational.

And the extension stays `.trvdb` across every version.

### What this ordering buys: a both-formats tier

Because kdbx4 is the default, features split into two tiers, and the split is
exactly the `Caps` matrix:

| Works on both | trvdb1 only |
| --- | --- |
| Entry history (§1 — kdbx4 has it natively) | Per-field history |
| Merge / sync | Delta sync |
| Sealed fields via `CustomData` | Sealed *metadata* (titles, tree) |
| Attachments, TOTP, refs | Signed write log, blob store |

The left column is worth building first: it delivers value to everyone without
asking anyone to leave the standard format.

---

## 5. Security testing

Yes — but "penetration test suite" is the wrong shape, and it's worth being
precise because the wrong frame leads to building the wrong thing. Pentesting
probes a *deployed, networked* system for exploitable configuration and logic.
trove is a local library, a daemon on a Unix socket, and a CLI. It has no server
to attack (until roadmap #15, at which point real pentesting genuinely applies —
another reason to keep that decision deliberate).

For software of this shape the equivalent is five things, and trove already does
three of them better than most projects.

### What already exists

- **`cargo audit`** as a CI job, plus `clippy -D warnings` across the workspace.
- **Three libfuzzer targets** in [crates/troved/fuzz](../crates/troved/fuzz/) —
  `ssh_wire_parse`, `ssh_wire_round_trip`, `assuan_line_parse` — covering the two
  hand-rolled parsers that read bytes from any process which can reach the
  daemon's sockets. Kept out of the workspace on purpose (libfuzzer needs
  nightly), with **proptests as the stable-CI safety net** for the same parsers.
  That's a genuinely well-reasoned setup.
- **[threat-model.md](threat-model.md)** with an explicit adversary list, asset
  list, surface list, and an 11-row Mitigations-and-Gaps table.
- **[keepass-spec-tests](../crates/keepass-spec-tests/)** including
  `broken_files.rs` — malformed-input handling against a curated corpus, and
  differential testing against other implementations.

### Gap 1 — fuzzing is manual, local, and non-regressing

The targets are only ever run by hand, and the README says corpora aren't checked
in (there's ~840K sitting in the working tree, unshared). Two consequences: the
coverage earned by a long run is lost when the machine is wiped, and a crash
found and fixed today can silently regress tomorrow.

Two cheap fixes, the first being the high-value one:

1. **Commit minimized corpora as regression fixtures, and add a stable-Rust test
   that replays every corpus file through the parser** asserting no panic. No
   nightly needed — it's just bytes into `parse_request`. This converts every
   fuzz finding into a permanent CI regression test, which is the thing that
   actually stops repeat bugs.
2. **A scheduled CI job** (nightly cron, not per-PR) running each target for a
   bounded time and failing on new artifacts.

### Gap 2 — untrusted-input surfaces that aren't fuzzed

The two fuzzed parsers are the ones trove hand-wrote, which is the right
instinct, but they aren't the only things eating attacker-controlled bytes:

- **kdbx parsing.** Upstream's code, but trove ships it, and a vault handed to
  you, a merge source, or a file synced down from Drive is untrusted input.
  `broken_files.rs` covers a curated set — that's not the same as fuzzing.
- **Keyfile parsing** — XML v1/v2, raw-32, hex-64, arbitrary-file SHA-256. Four
  formats, all reading a file an attacker may have chosen.
- **The IPC control protocol.** `serde_json` is well-fuzzed upstream; the
  *semantic* layer above it — session-token handling, entry addressing, RPC
  argument validation — is trove's own.
- **`otpauth` URI parsing** and the `{REF:…}` resolver.

### Gap 3 — the threat model isn't executable

This is the closest thing to what "pentest suite" should mean here, and it's the
highest-value item on the page. threat-model.md's table makes specific, checkable
claims: agent socket is `0600`, materialized files are `0600`, tmpfs by default
on Linux, idle-lock defaults to 900s, TTL plus wipe-on-lock, refusal of system
directories, `Zeroize` on drop, `SO_PEERCRED` on Unix.

Those are **prose**, and prose drifts from code silently. One test per claimed
mitigation — a `security_claims` suite that fails loudly the moment a claim stops
being true — turns the threat model into a contract. The table's own admitted gaps
double as the TODO list: no `prctl(PR_SET_DUMPABLE, 0)` yet, and on Windows
there's no `SO_PEERCRED` so the pipe ACL is the only control
([threat-model.md:62](threat-model.md#L62)).

Worth adding alongside: **leakage tests** (secrets absent from error messages,
`ps`/cmdline, logs, and the clipboard after its timeout) and **constant-time
comparison** for session tokens and MACs.

### Gap 4 — everything designed above is new attack surface

Each feature in this document adds a surface, and the parser is the classic one:

- **trvdb1's parser** — write the fuzz target *alongside* the parser, not after.
  The spec should carry a "malicious input" section per record type.
- **Sealed values** — attacker-supplied ciphertext must fail closed, with no
  padding or error oracle. (§3's note about not building a decryption oracle is
  the same lesson trove already learned for RSA decrypt in
  [threat-model.md:58](threat-model.md#L58).)
- **Signed write log** — verification-bypass tests: truncation, reordering,
  substituted keys, stripped signatures.
- **Delta sync** — a malicious remote feeding crafted records.

### The thing tests can't do

A test suite prevents regressions of flaws you already thought of. It does not
find design flaws you didn't. We just designed a novel encrypted container format
with per-group key wrapping — precisely the category where external cryptographic
review pays for itself, and where "we wrote a lot of tests" is not a substitute.
For a secrets tool, an external audit is also the only thing that buys credibility
with users who will never read the code.

So: the suite is worth building, and it is not the whole answer. Budget for review
of the trvdb1 spec *before* it ships, while changing it is still cheap.

### Also worth doing

`cargo-deny` alongside `cargo audit` — it covers bans, licence policy and source
allowlists, not just advisories.

---

## Design sketch: the backend trait

There is already precedent in-repo. [`VaultLike`](../crates/troved/src/vaults.rs#L26-L40)
with generic `VaultSet<V = Vault>` and a `FakeVault` double is the same pattern
at narrower scope — introduced for testability (routing tests shouldn't run
Argon2), but the shape is right.

### Operations, not storage

The tempting alternative is a thin persistence trait — one shared in-memory
document model, backends that only load and save it. That fails for exactly the
reason this whole idea exists: the formats differ in their **model**, not their
encoding. Per-field history and sealed metadata are model differences. A shared
model means kdbx4's model wins, and we're back to a lowest common denominator
with extra indirection. So the trait is the *operations*, and each backend keeps
its own internal representation.

### Object safety decides the shape

troved holds a heterogeneous set of unlocked vaults, so it needs
`Box<dyn VaultBackend>`. That rules out generic methods and RPITIT, and — the
part that's easy to miss — **constructors can't live on the trait**, since
`open`/`create` return `Self`. They go on a small separate registry.

```rust
// Object-safe. One impl per format.
pub(crate) trait VaultBackend: Send {
    fn path(&self) -> &Path;
    fn save(&mut self) -> Result<()>;
    fn caps(&self) -> Caps;
    fn info(&self) -> DbInfo;

    // Core CRUD — every backend implements these. Shapes unchanged from
    // today's `Vault`, so the CLI/daemon/desktop call sites don't move.
    fn add_entry(&mut self, title: &str) -> Result<EntryId>;
    fn list_entries(&self) -> Vec<EntrySummary>;
    fn find_by_title(&self, title: &str) -> Option<EntryId>;
    fn get_field(&self, id: &EntryId, field: &str) -> Result<Option<String>>;
    fn set_field(&mut self, id: &EntryId, field: &str, value: &str) -> Result<()>;
    fn attach_binary(&mut self, id: &EntryId, name: &str, bytes: &[u8]) -> Result<()>;
    // … the rest of the existing surface

    // Capability-gated. Default impl refuses, so a new backend is correct
    // before it is complete, and a missing feature can never silently no-op.
    fn history(&self, id: &EntryId, field: Option<&str>) -> Result<Vec<Version>> {
        Err(Error::Unsupported { cap: Cap::History, format: self.info().version })
    }
    fn seal_field(&mut self, id: &EntryId, field: &str, group: &GroupId) -> Result<()> { … }
    fn merge_from(&mut self, src: &Path, cred: &Credential) -> Result<MergeSummary> { … }
}

// Not object-safe, and doesn't need to be — a static registry.
pub(crate) trait VaultFormat {
    fn sniff(header: &[u8]) -> bool;
    fn open(path: &Path, cred: &Credential) -> Result<Box<dyn VaultBackend>>;
    fn create(path: &Path, cred: &Credential) -> Result<Box<dyn VaultBackend>>;
}
```

`Credential` (password + keyfile bytes + optional challenge-response) is the
trove-owned type that retires the `pub use keepass::ChallengeResponseKey` leak at
[lib.rs:152](../crates/trove-core/src/lib.rs#L152).

### Detection, and where capabilities are enforced

- **Sniff magic bytes, don't trust the extension.** kdbx4 has a fixed 4-byte
  signature; the native format gets its own. `create` can't sniff anything, so it
  needs an explicit format choice (flag, or a config default).
- **Enforcement lives in the backend** — the method itself returns
  `Error::Unsupported`, so it cannot be bypassed by a caller that forgot to
  check. **`caps()` is for discovery**, so the CLI and GUI can hide or grey out
  affordances instead of offering something that is guaranteed to fail. Both, not
  either.

### Keep the trait private until there are two implementations

`trove-core` is published to crates.io, and its description is currently
"kdbx-compatible vault library" — so making `VaultBackend` public is a semver
commitment to a shape derived from exactly one implementation. Abstractions
written against a single example bake in that example's assumptions. Keep the
trait crate-private until the native backend exists and has stress-tested it;
publish it (and revisit that crate description) afterwards.

### What proves the refactor

306 tests today — 41 in trove-core, 67 in trove-cli, 198 in troved — and the
CLI/daemon suites exercise the public surface rather than internals. Step 1 is a
**pure** refactor: if any test needs changing, the refactor is wrong.

---

## Design sketch: reading history and picking a version

### The granularity gotcha

KDBX history snapshots the **whole entry**, not a field. There is no "history of
`Password`" in the file — you derive it by projecting that field out of every
snapshot and collapsing consecutive duplicates. Consequences:

- An entry with 10 snapshots may have changed `Password` only twice. Its field
  history is 2 long, not 10.
- Numbering therefore can't be the raw snapshot index, or users see gaps
  (`v3, v7, v9`) that mean nothing to them.

So there are two genuinely different views, and both are worth having:

| Command | View |
| --- | --- |
| `trove show <entry> --history` | Entry timeline: one row per snapshot, timestamp + which fields differ from the previous one |
| `trove show <entry> --attr Password --history` | Value timeline: only the snapshots where *that field* actually changed |

### Addressing a version

Three candidates, in order of how well they survive contact with sync:

- **Timestamp** — `--at 2026-08-01T14:22:03Z`, the snapshot's
  `last_modification`. Canonical: it's what the merge algorithm keys on, it's
  stable under pruning, and it names the same version on both copies of a synced
  vault. Verbose to type.
- **Relative index** — `--version 1` (0 = current, 1 = previous). Ergonomic, but
  shifts on every write, and shifts *differently* on two copies that have
  diverged. Fine as interactive sugar if it resolves to a timestamp immediately
  and the output echoes the timestamp back, so scripts learn the stable form.
- **A trove-minted counter** (`v1, v2, v3` stored in the entry) — no. Same
  problem as any trove-private field: two synced copies both mint `v4`, and it
  can't survive KeePassXC pruning the snapshot underneath it.

Proposal: `--at <TIMESTAMP>` is canonical, `--version <N>` is sugar, listings
print both.

### Read vs restore

Reads (non-mutating) reuse the existing surfaces with an `--at` selector:

```
trove show <entry> --attr Password --at <ts>     # print a past value
trove clip <entry> --attr Password --at <ts>     # ...to clipboard, existing auto-clear
trove get file <entry> --name id --at <ts>       # a past attachment
```

Restores (mutating) are a new verb, at both granularities:

```
trove restore <entry> --at <ts>                  # whole entry — KeePassXC-compatible
trove restore <entry> --attr Password --at <ts>  # single field — trove nicety
```

**Restore is itself a tracked write**, so it snapshots the current state before
overwriting. That makes restore non-destructive and undoable by restoring again —
which is roadmap #27's "global undo" falling out for free rather than needing to
be built.

### Secret hygiene — needs a decision

History holds **old passwords and old key material**, and old secrets are not
harmless: old passwords get reused, and an old SSH key still authenticates on
every host that didn't rotate. So:

1. A `--history` listing must never dump protected values. Timestamps and
   changed-field *names* only; revealing a specific version goes through the
   existing `--show-protected` convention, one version at a time.
2. History reads must route through the same daemon gating as `show` / `get`, not
   open the kdbx directly.

But a listing of bare timestamps is nearly useless for "pick the one we want".
Middle ground worth deciding on: show a short non-reversible fingerprint per
version (first 8 hex of a hash of the value) plus a marker for "same as current".
That's enough to recognise a value you remember without revealing it. The
alternative is timestamps only, and you pick by date.

### The honest limit

KDBX snapshots carry timestamps, not identity. There is no principal in the
format, so there is no *who changed this* column and no commit message — those
need the per-user identity from #16 first. Any attempt to fake it with a
trove-private "changed by" field inherits every interop problem above, and is
unverifiable anyway since any keyholder can write any name into it.

---

## 6. `send to` — moving entries between vaults as objects

**The codebase already names this gap.** `merge_from`'s own refusal text says:
*"merge reconciles diverged copies — to combine unrelated vaults, import entries
explicitly"*
([lib.rs:930-937](../crates/trove-core/src/lib.rs#L930-L937)). That explicit
import doesn't exist. So this isn't a merge variant, it's the operation merge
points at:

| | Reconciles | Identity |
| --- | --- | --- |
| **merge** | diverged copies of *one* vault | refuses different root UUIDs |
| **send** | one entry between *unrelated* vaults | crosses identity spaces |

### Multi-vault already provides the good path

Phase 1 multi-vault ships today — the daemon holds a `VaultSet` of unlocked
vaults. When source and target are both unlocked, `send` is a purely in-memory
transfer with **no second password prompt**. That makes it arguably the first
genuinely new user-facing capability multi-vault unlocks. Fallback: target not
unlocked → prompt for its credentials. Source and target must never be required
to share credentials.

### UUID: mint a new one, record provenance

An entry's UUID is its merge identity. Preserving it on send would put one
identity in two identity spaces, which confuses any later merge. Minting a fresh
one loses the "same secret" link and makes re-sending create duplicates.

Take both: **mint a new UUID**, and record source UUID + source vault id in
`CustomData` as provenance. Re-sending then finds the prior copy by provenance and
updates it instead of duplicating — idempotent, without polluting the merge
identity space. Same mechanism §3 uses for the group keyring.

### Copy vs move — never delete first

A move across two independently-encrypted files is a two-phase commit with no
transaction, and the two failure modes are not equally bad:

- target write succeeds, source delete fails → secret duplicated (recoverable)
- source delete succeeds, target write fails → **secret lost** (not)

So the order is fixed: copy → verify by reading it back out of the target → only
then remove from source, and that removal goes to the recycle bin, never
permanent. Default is copy; `--move` is explicit.

### What travels with the entry

- **Attachments** — copied into the target's binary pool under fresh ref ids.
- **History** — carrying it carries *old secrets* into another vault, possibly
  another trust domain. The safe default is to **flatten**, with `--with-history`
  as opt-in. Capability-checked: kdbx4 can hold entry history, trvdb can hold
  per-field history, so what survives depends on the target.
- **Group path** — the target may have no `Work/servers/`. Create it, or land at
  the root with `--to-group`.
- **`{REF:…}` fields — the real trap.** A KeePass field reference resolves by UUID
  *within one database*, so a sent entry arrives holding a dangling pointer and
  reads as empty or literal junk. Detect it and resolve to the literal value
  (`resolve_ref` already exists,
  [lib.rs:849](../crates/trove-core/src/lib.rs#L849)) or refuse — never send a
  reference silently.
- **Sealed fields** (§3) — sealed under a group key the target's members may not
  hold. Either re-seal to the target's keyring or unseal, which *downgrades
  confidentiality*. Must be an explicit choice, never a silent one.
- TOTP URIs, custom fields, icons — straightforward.

### It is an exfiltration primitive, so make it loud

This is the one operation that deliberately moves plaintext secrets across trust
boundaries. That's legitimate — it's the user's own data — but it earns friction:
name the entry and the target and confirm, never silently overwrite an entry
already in the target, and don't make bulk drains (`--all`) frictionless. The
resulting write lands in the target's history, which per §3 is the half of
auditing that's actually credible offline.

### The generalisation worth taking: send to a *person*

"Keys as objects" implies a second kind of destination. Sending to a **file**
requires that file's credentials. Sending to a **person** doesn't: encrypt the
entry to a recipient's public key and hand them an envelope they import. That
reuses §3's key-wrapping machinery exactly, needs no access to your vault at all,
and answers a question with no good answer today — *how do I give a colleague one
credential* — where the status quo is pasting it into a chat window.

### Cheap, and available now

`send` needs neither trvdb nor the backend trait. It needs multi-vault, which
ships. It *interacts* with history and sealing, so build it capability-checked
from the start rather than retrofitting later.

---

## Suggested ordering

Steps 1–3 are worth doing whether or not the native format happens, which is what
makes them the right place to start.

1. **Entry history on trove writes** — small, self-contained, uses an existing
   keepass-rs API, unblocks sync. Needs pruning + attachment-orphan handling.
2. **Sketch the native format's data model on paper** — *before* the trait, not
   after. It's cheap, and it's the only way the trait gets shaped by two formats
   instead of one. The full spec can come later; the model can't.
3. **Extract `VaultBackend` + `Caps`** — pure refactor of one file, kdbx4 as the
   sole implementation, kept crate-private, existing 306 tests prove it.
4. **`trove send <entry> --to <vault>`** — the missing cross-vault operation
   `merge_from` already points at. Needs only multi-vault (shipped), so it lands
   early and cheaply. Copy-then-verify-then-recycle; resolve `{REF:…}` on the way
   out; flatten history by default.
5. **`trove sync`** — two-way merge + atomic write-back + sidecar lock, on top of
   the existing `merge_from`. Still whole-file; delta sync needs the native
   format.
6. **Per-user identity** — member keypairs registered in the vault, reusing the
   OpenPGP keys trove already serves. Prerequisite for everything below.
7. **Native format spec, then implementation** — per-field history, sealed
   metadata, record-oriented encryption for delta sync, signed write log. Plus
   `trove convert` both ways with a lossiness report.
8. **Sealed fields + group keyring** — real read-ACLs, no server. On kdbx4 via
   `CustomData` (interop-visible as opaque tokens); native gets sealed metadata
   too. Ships with an honest README about rotation-on-revoke. Unlocks *send to a
   person* — an entry sealed to a recipient's public key, no shared vault needed.
9. **Read auditing and write *prevention*** — only alongside #15. These are the
   two pieces that genuinely require a mediator; scope them as server features
   rather than approximating them locally.
