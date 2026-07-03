# keepassxc-cli parity plan

Goal: close every gap where `keepassxc-cli` beats `trove`, prove each closure
with tests (including interop against the real `keepassxc-cli` binary), then
go beyond parity. Non-negotiable throughout: 100% `.kdbx` compatibility —
everything we write must be readable by KeePassXC and vice versa.

## Gap inventory (vs keepassxc-cli 2.7.x)

| # | Gap | keepassxc-cli surface | trove today |
|---|-----|----------------------|-------------|
| G1 | Generic entry CRUD | `add`, `edit`, `show`, `rm`, `mv`, `mkdir`, `rmdir`, `search`/`ls` | only ssh/gpg/file resources; no plain password entries, no edit/rm/mv/search |
| G2 | Keyfile unlock | `--key-file` on every command | password-only master key |
| G3 | TOTP | `show --totp`, `clip --totp` | none |
| G4 | Generation + audit | `generate`, `diceware`, `estimate`, `analyze` | `generate ssh` only |
| G5 | Clipboard | `clip` with auto-clear timeout | none |
| G6 | Vault ops | `merge`, `import`, `export`, `db-edit`, `db-info` | none |
| G7 | Hardware key | `--yubikey` challenge-response | none |

## Feature groups

### G1 — generic entry CRUD (foundation; everything else builds on it)

New CLI surface (offline `--vault` mode and daemon-session mode, same as the
existing ssh/gpg/file commands):

- `trove add password <ENTRY_PATH> [--username U] [--url URL] [--notes N]
  [--generate | --password-stdin-value]` — prompts for the secret by default;
  `--generate` mints one (see G4).
- `trove show <ENTRY_PATH> [--attributes A,B] [--show-protected] [--all]` —
  prints Title/UserName/URL/Notes by default, Password only with
  `--show-protected` (mirrors keepassxc-cli's safety default).
- `trove edit <ENTRY_PATH> [--title T] [--username U] [--url URL] [--notes N]
  [--password-prompt] [--set KEY=VALUE]...` — field-level edits incl. custom
  fields.
- `trove rm <ENTRY_PATH>` — moves to recycle bin group (KeePassXC behavior);
  `--permanent` deletes outright.
- `trove mv <ENTRY_PATH> <GROUP_PATH>` — move entry between groups.
- `trove mkdir <GROUP_PATH>` / `trove rmdir <GROUP_PATH>` (empty-only unless
  `--recursive`).
- `trove search <TERM> [--fields]` — case-insensitive substring over
  title/username/url/notes; never matches protected values.

trove-core additions: `remove_field`, `rename_entry`, `move_entry`,
`add_group`, `remove_group`, `recycle_entry` (creates/uses "Recycle Bin"
group with the KeePassXC UUID convention), `search_entries`.

### G2 — keyfile unlock

- Global `--key-file <PATH>` flag beside `--vault`; also honored by `unlock`
  (daemon stores the composite key material only in memory).
- Formats: KeePass XML v2 keyfile, legacy XML v1, raw 32-byte, hex-64, and
  arbitrary-file SHA-256 fallback — i.e. exactly the `keepass` crate's
  `DatabaseKey::with_keyfile` behavior, which matches KeePassXC.
- `trove init --key-file` can generate a fresh XML v2 keyfile.
- trove-core: `Vault::create/open` grow `_with_key` variants taking a
  `KeySource { password, keyfile }`.

### G3 — TOTP

- Storage format: the `otp` string field carrying an `otpauth://totp/...` URI —
  KeePassXC's native format, so codes render identically in both tools.
- `trove show <ENTRY> --totp` prints the current code (+ seconds remaining on
  a TTY); `trove add totp <ENTRY> --secret S | --uri URI` sets it.
- RFC 6238: SHA1/SHA256/SHA512, 6–8 digits, custom period. Steam variant
  (5-char alphabet) recognized via KeePassXC's `encoder=steam` convention.
- No new deps beyond a small RFC-4648 base32 decode + `hmac`/`sha1`/`sha2`
  (already transitively present via the keepass crate ecosystem; pinned).

### G4 — generation + audit

- `trove generate password [--length N] [--lower] [--upper] [--numeric]
  [--special] [--exclude CHARS] [--every-group]` — CSPRNG (`rand::rngs::OsRng`).
- `trove generate diceware [--words N]` — EFF long wordlist, embedded.
- `trove estimate [PASSWORD]` — zxcvbn entropy estimate (crate `zxcvbn`).
- `trove analyze --hibp <FILE>` — offline HIBP: SHA-1 the vault's passwords,
  binary-search the sorted `pwned-passwords` file. Never sends anything on
  the wire. (Online k-anonymity check is a beyond-parity opt-in, G9.)

### G5 — clipboard

- `trove clip <ENTRY_PATH> [ATTRIBUTE] [--totp] [--timeout SECS]` — copies,
  then a detached child clears the clipboard after the timeout (default 10 s)
  iff the clipboard still holds our value.
- Backends: `arboard` crate (macOS/Windows/X11); Wayland via `wl-copy` exec
  fallback; inside tmux/SSH fall back to OSC 52 escape.

### G6 — vault ops

- `trove merge <SOURCE> [--into TARGET]` — keepass crate `Database::merge`
  (KDBX-standard last-write-wins with history preservation); prints a
  MergeLog. Round-trip interop-tested against `keepassxc-cli merge`.
- `trove export [--format xml|csv]` / `trove import <xml|csv>` — KeePassXC
  column conventions for CSV; XML is the KDBX inner XML.
- `trove db-edit [--set-password] [--set-key-file] [--kdf argon2id]
  [--kdf-memory M] [--kdf-iterations I]` — rekey and KDF tuning.
- `trove db-info` — format version, cipher, KDF params, entry/group counts,
  recycle-bin status.

### G7 — YubiKey challenge-response (honest scope)

- Feature-flagged (`--features yubikey`), `ykoath`/`challenge-response` via
  the `yubico_manager` protocol KeePassXC uses (HMAC-SHA1 over slot 2).
- The key-derivation composition follows KeePassXC's documented scheme so a
  vault created by KeePassXC with YubiKey CR unlocks in trove and vice versa.
- CI/tests: protocol layer mocked (recorded challenge/response vectors);
  hardware path marked `#[ignore]` and runnable manually. We do NOT claim
  hardware-validated until a human runs it with a real key.

## Validation strategy (applies to every group)

1. **Unit tests** in the owning crate (`trove-core` for model ops, `trove-cli`
   for command plumbing) — every new public API and every CLI code path.
2. **Interop tests against real `keepassxc-cli`** in
   `crates/keepass-spec-tests` (new `interop_cli.rs` module, gated on the
   binary being present — CI installs it, devs get `#[ignore]`-with-message):
   - trove writes → keepassxc-cli reads (`show`, `ls`, `export`) asserts equal
   - keepassxc-cli writes → trove reads, asserts equal
   - both merge the same divergent pair → equivalent result sets
   - TOTP: same secret yields the same 6-digit code in the same 30 s window
3. **kdbx-compat regression** — the existing seeded round-trip matrix keeps
   running untouched; new field/attachment shapes get added to the matrix.
4. **CI** — new `interop` job in the test workflow: installs keepassxc (same
   recipe as the release gate), runs the interop suite on Linux + macOS.

## Landing strategy

One draft PR per feature group, in order G1 → G7 (G1 first — everything
depends on it; G2 second — touches the auth path all commands share). Each PR:
implementation + unit tests + interop tests + docs (`cli-reference.md`
section) + CHANGELOG entry. CI must be green before the PR is marked ready.

## Beyond parity (after the gaps close)

- **G8 `trove exec`** — `trove exec <ENTRY_GROUP> -- cmd args…`: child process
  gets secrets as env vars (no disk residue), à la `op run`.
- **G9 online HIBP (opt-in)** — k-anonymity range queries (5-char SHA-1
  prefix), never the full hash on the wire.
- **G10 `--json`** — machine-readable output on every read command.
- **G11 `trove git-credential`** — a git credential-helper subcommand backed
  by the daemon session.
- **G12 secret references** — `trove://group/entry/field` URIs resolvable in
  materialized templates.
