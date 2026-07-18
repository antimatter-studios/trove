# Changelog

All notable changes, per released version. trove is pre-1.0, so minor versions
may carry behavior changes. The most recent releases are also summarized in the
README; the full history and the pre-1.0 development milestones live here.

## v0.5.0 — 2026-07-04

Full `keepassxc-cli` command parity (the seven gaps in
`docs/parity-plan.md`, all proven against the real `keepassxc-cli` binary in
CI), plus beyond-parity features `keepassxc-cli` has no equivalent for. The
individual entries below are grouped by theme.

**Generic entry management (parity G1):** `add password`, `get password`,
`show` (`--attr`, `--show-protected`), `edit` (`--set`/`--unset`/
`--password-prompt`), `search`, `mkdir`, `mv`, `rm`, `rmdir` — offline and
daemon-routed, with KeePassXC recycle-bin semantics.

**Composite keys (parity G2, G7):** global `--key-file` (every KeePassXC
keyfile format) and `--yubikey <SLOT>[:SERIAL]` HMAC-SHA1 challenge-response
(behind `--features yubikey`, Linux-only for now).

**TOTP (parity G3):** `add totp` + `show --totp`, stored as KeePassXC's
`otpauth://` `otp` field; codes match keepassxc-cli in both directions.

**Generation + audit (parity G4):** `generate password`/`diceware`,
`estimate` (zxcvbn), `analyze --hibp` (offline breach check, exits 1 to gate
CI).

**Clipboard (parity G5):** `clip` with a hash-guarded detached auto-clear.

**Vault ops (parity G6):** `merge` (proven equivalent to keepassxc-cli's
merge), `export xml|csv` (re-importable), `db-edit` (rekey + Argon2 retune),
`db-info`. Fixed a latent bug: entry mutations now stamp
`LastModificationTime`/`LocationChanged`, so trove edits no longer silently
lose KDBX merges in any tool.

**Beyond parity:** `exec <scope> -- cmd` (secrets scoped to one process tree,
wiped on exit — the `op run` of kdbx); `--json` on `list`/`search`/`db-info`;
`git-credential` helper; `resolve trove://…` secret references.

**Also:** `TROVE_SPAWN_TIMEOUT_SECS` knob for the daemon auto-spawn wait;
`docs/security-review-2026-07-04.md`; unpredictable `exec` temp-dir names.

**Desktop app (new):** a Tauri 2 GUI (`trove-desktop/`) that links `trove-core`
directly — a three-pane vault browser that opens a `.kdbx` and reveals fields on
demand (secrets stay in the backend, never in the entry list). Brought into this
monorepo and shipped in the same release as macOS (universal), Linux
(`.deb`/AppImage) and Windows (NSIS) bundles.

### Detailed entries

- `trove git-credential <get|store|erase>` (beyond parity): a git credential
  helper backed by the vault. `git config credential.helper "trove --vault
  ~/v.kdbx git-credential"` — `git push` authenticates against an entry
  matched by URL host (and username when git sends one), with no plaintext
  `~/.git-credentials`. store/erase are accepted and ignored.
- `trove resolve trove://<entry>[/<field>]` (beyond parity): print one
  referenced secret (field defaults to Password), à la 1Password's `op://` —
  the primitive for config templating (`export DB=$(trove resolve …)`).
- `trove exec <SCOPE> -- cmd…` (beyond parity): run any command with secrets
  injected for exactly its lifetime — string secrets as env vars, file
  attachments materialized into a private 0700 per-run dir, everything wiped
  when the child exits, child exit code propagated. An entry's `Exec.Env`
  custom field names the variable (`Exec.Env=KUBECONFIG` on a kubeconfig
  attachment → `trove exec Infra -- bash` gives that shell a scoped,
  self-destructing kubeconfig); fallback `TROVE_<TITLE>_PASSWORD`/`_FILE`.
- `--json` on `list`, `search` and `db-info`: stable machine-readable output
  (summaries never carry secrets), making trove scriptable without text
  scraping — something keepassxc-cli has no equivalent for.
- YubiKey challenge-response unlock (keepassxc-cli parity G7), behind
  `--features yubikey`: global `--yubikey <SLOT>[:SERIAL]` composites an
  HMAC-SHA1 challenge-response with the password (and optional keyfile) —
  KeePassXC's scheme, same vault unlocks there with the same device. The
  device answers a fresh challenge on every save. Validated in CI (Linux)
  through the keepass crate's software `LocalChallenge` provider — the
  identical derivation minus USB; the hardware test ships `#[ignore]`d for
  manual runs. Linux-only for now: upstream keepass pins the nusb USB
  backend, which doesn't compile on macOS.
- Vault ops (keepassxc-cli parity G6), all offline-only: `trove merge`
  (KDBX-standard reconciliation of diverged copies — proven equivalent to
  keepassxc-cli's merge on the same pair; unrelated vaults refuse cleanly),
  `trove export --format xml|csv` (decrypted KeePass XML that keepassxc
  imports back, CSV with KeePassXC's exact header), `trove db-edit`
  (rekey password/keyfile, Argon2 retuning), `trove db-info`. XML *import*
  stays out of scope (no public parser in the keepass crate).
- Compatibility fix surfaced by the merge work: trove edits now stamp
  `LastModificationTime` (and moves stamp `LocationChanged`) like KeePassXC
  does. Previously trove-side changes could silently lose KDBX merges in
  any tool because their timestamps never advanced.
- Clipboard (keepassxc-cli parity G5): `trove clip <entry>` copies the
  password (or `--attr NAME`, or `--totp` for the current code) and
  auto-clears after `--timeout` seconds (default 10, 0 disables) via a
  detached clearer that wipes ONLY if the clipboard still holds our value —
  the comparison travels as a SHA-256 on argv, never the secret. Works
  offline and daemon-routed; macOS/Windows/X11/Wayland via arboard.
- Generation + audit (keepassxc-cli parity G4), all purely local:
  `trove generate password` (charset policy flags, `--exclude`, `--count`),
  `trove generate diceware` (EFF large wordlist, vendored, CC BY 3.0),
  `trove estimate` (zxcvbn; reads stdin so secrets stay out of history), and
  `trove analyze --hibp <FILE>` — offline breach check that binary-searches
  the sorted pwned-passwords dump on disk (never loaded, never on the wire)
  and exits 1 when breaches are found so CI can gate on it.
- TOTP (keepassxc-cli parity G3): `trove add totp` stores an `otpauth://` URI
  in the Protected `otp` field (KeePassXC's own format — validated before
  storing, whitespace-tolerant base32 `--secret` form included);
  `trove show <entry> --totp` prints the current code (RFC 6238,
  SHA1/256/512, 6–8 digits, custom period). Daemon mode adds code-gated
  `GetTotp`/`AddTotp` RPCs — only the ephemeral code ever crosses the wire.
  Interop proven against keepassxc-cli: identical codes both directions.
  (Steam's non-standard 5-char variant is out of scope.)
- Keyfile unlock (keepassxc-cli parity G2): global `--key-file <PATH>`
  composites the keyfile with the password wherever a vault is opened —
  offline commands, `init` (new vault locked with the pair), and `unlock`
  (the daemon holds the bytes so its re-saves keep the composite key; the
  wire `Unlock` RPC grew an optional base64 `keyfile` field). Every format
  KeePassXC accepts. Interop proven both directions against keepassxc-cli.
- Generic entry CRUD, closing the first keepassxc-cli parity gap
  (docs/parity-plan.md): `add password` (prompt / `--secret-stdin` /
  `--generate`), `get password`, `show` (`--attr`, `--show-protected`),
  `edit` (`--set`/`--unset`/`--password-prompt`), `search`, `mkdir`, `mv`,
  `rm`, `rmdir`. All work offline (`--vault`) and daemon-routed (new
  `ShowEntry`/`Search`/`GetField`/`AddPassword`/`EditEntry`/`RemoveEntry`/
  `MoveEntry`/`Mkdir`/`Rmdir` RPCs, session-gated like `add ssh`).
- `rm`/`rmdir` follow KeePassXC recycle-bin semantics: entries and groups move
  to a shared "Recycle Bin" (created on demand, `Meta/RecycleBinUUID`
  convention); a repeat remove — or `--permanent` — destroys.
- CRUD interop is proven against real `keepassxc-cli` in the conformance
  suite: trove-authored vaults read back field-for-field, keepassxc-authored
  vaults round-trip through every trove command, and trove-recycled entries
  appear in keepassxc's own Recycle Bin view.

## v0.4.0 — 2026-07-01

- `add file` / `add gpg` now target the vault unlocked in the running daemon by
  default (gated by `TROVE_SESSION`), consistent with `add ssh`. Pass
  `--vault <PATH>` to operate on a kdbx file directly (offline).
- `troved` takes a singleton `flock`, making orphaned/stale SSH- and GPG-agent
  sockets impossible.

## v0.3.0 — 2026-06-24

- `--vault <PATH>` is now a global offline selector (works before or after the
  subcommand); positional vault arguments dropped.
- `add ssh` requires a `<comment>` argument, recorded in `id.pub`.
- The vault's top-level group is named `Root` and treated as the default group.
- KDBX 4.0 → 4.1 heal on save, daemon lifecycle management, and `ssh`/`gpg` CLI
  wrappers.
- Upgraded to `keepass 0.13.10` (KeePassXC-readable vaults) with a cross-tool
  conformance suite and session-code provisioning.
- Windows support (named-pipe IPC) and the cross-platform release pipeline.
- Installed the github-guard git hooks.

## v0.2.0 — 2026-06-22

- `KeeAgent.settings` export, nested group support, daemon auto-spawn, RSA PEM
  import, and an idle-lock fix.
- Added the Install section (Homebrew + cargo) to the README.

## v0.1.0 — 2026-05-08

Initial tagged release: kdbx-compatible vault (`trove-core`), the `trove` CLI
and `troved` headless daemon with a line-JSON control socket, in-memory SSH and
GPG agents, real KDBX `<Binary>` attachments, file materialization (the founding
feature), idle-lock, and the daemon-aware CLI. The granular history is below.

## Pre-1.0 development milestones

Fine-grained feature log from before the tagged-release cadence (oldest first):

- **v0.0.1** — kdbx vault read/write ([crates/trove-core/src/lib.rs](crates/trove-core/src/lib.rs)), `trove` CLI scaffold (`init`, `list`, `add ssh`, `get ssh`), `troved` headless daemon with the line-JSON control socket, end-to-end SSH-key roundtrip.
- **v0.0.2** — SSH agent listener serving ed25519 keys over `SSH_AUTH_SOCK`. Keys live only in daemon memory; cleared on lock.
- **v0.0.3** — SSH agent algorithm coverage extended: RSA (>= 2048 bits, signs with rsa-sha2-256 / rsa-sha2-512 per RFC 8332), ECDSA P-256, ECDSA P-384.
- **v0.0.4** — GPG agent listener speaking the Assuan protocol; ed25519 OpenPGP signing works against `git commit -S`. Hand-rolled OpenPGP packet parser ([crates/troved/src/gpg_agent/keys.rs](crates/troved/src/gpg_agent/keys.rs)) avoids pulling in `rpgp`.
- **v0.0.5** — GPG `PKDECRYPT` for ECDH-on-Curve25519: AES-128/192/256 KW unwrap of the wrapped session key against gpg 2.5.x. RSA / NIST-curve / Ed448 still out of scope.
- **v0.0.6** — Real KDBX `<Binary>` attachments via a vendored fork of `keepass` 0.7.33 (since retired in v0.0.14); legacy `_SDPM_BIN_*` string-field fallback kept for read-compat with v0.0.1–v0.0.5 vaults (also retired in v0.0.14).
- **v0.0.7** — File materialization (the founding feature): `trove add file`, `Materialize.{Source,Target,Mode,TTL,AllowDiskBacked}` custom-field schema, in-process `trove materialize`, daemon-driven materialize-on-unlock + wipe-on-lock with optional TTL. Linux: refuses non-tmpfs targets unless `AllowDiskBacked=true`. macOS: soft allowlist (`/tmp`, `/private/tmp`, `$XDG_RUNTIME_DIR`) — APFS provides no real tmpfs, so this is a hint, not a guarantee.
- **v0.0.8** — Idle-lock. `IdleTracker` with a tokio driver task ([crates/troved/src/idle.rs](crates/troved/src/idle.rs)); auto-locks after configurable inactivity (default 900s). Activity = any control RPC except `ping`, any SSH agent message, any GPG Assuan command. New `set-idle-timeout` / `get-idle-timeout` RPCs and `TROVE_IDLE_TIMEOUT` env var.
- **v0.0.9** — GitHub Actions CI (`.github/workflows/ci.yml`): test matrix on Linux + macOS, clippy with `-D warnings`, fmt check, cargo-audit, MSRV check at Rust 1.75. Repo run through `cargo fmt --all`.
- **v0.0.10** — Documentation: README quickstart + [docs/architecture.md](docs/architecture.md) + [docs/threat-model.md](docs/threat-model.md) + [docs/cli-reference.md](docs/cli-reference.md).
- **v0.0.11** — Fuzz harnesses for the SSH agent wire decoder and Assuan line parser ([crates/troved/fuzz/](crates/troved/fuzz/), nightly-only) plus proptest property tests on stable. ~4.3M libfuzzer iterations on this machine, 0 crashes.
- **v0.0.12** — Clean-room kdbx spec test suite: round-trip matrix, malformed-input rejection, keyfile formats, binary pool, cross-tool (`keepassxc-cli`) interop. Programmatically generated fixtures from a seeded RNG; no GPL imports. Originally lived under `vendor/keepass/tests/`; relocated to [crates/keepass-spec-tests](crates/keepass-spec-tests/) in v0.0.14.
- **v0.0.13** — Daemon-aware CLI: `trove unlock`, `trove lock`, `trove status`, `trove idle set/get`, `trove materialize-status`. Replaces the `printf '{...}' | nc -U` incantations from v0.0.8 with proper subcommands.
- **v0.0.14** — Migrated off the vendored `keepass` 0.7.33 fork to the published `keepass = "0.12.5"`. Upstream's PR #294 already restructured attachments as first-class Database-owned objects with `EntryMut::add_attachment(name, Value::Unprotected(bytes))`, which is what our 3 patches were trying to enable. Local fork retired; legacy `_SDPM_BIN_*` migration code retired (no production v0.0.1–v0.0.5 vaults exist).
