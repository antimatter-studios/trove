# Status — what works, what doesn't, what's next

Snapshot of the project as of v0.0.10.2 (2026-05-08). Catalogues every advertised feature and assigns one of:

- **✅ works** — implemented end-to-end, has tests, real third-party tools accept the output
- **⚠️ partial** — implemented but with documented gaps that affect real-world use
- **❌ not implemented** — promised in the [feature exploration](../README.md#feature-exploration) but no code yet
- **🔜 planned next** — flagged for the immediate roadmap

Numbers right now: **154 tests passing, 0 failing.** Three crates plus one test crate. CI on Linux + macOS. Linux + macOS only; Windows is not supported.

---

## At a glance

The headless-daemon path works end-to-end on a password-only KeePassXC vault. You can store SSH and GPG keys, run `git push` and `git commit -S` against `sdpmd`, materialize config files (kubeconfig, `.env`, etc.) to tmpfs on unlock and have them wiped on lock. Idle-lock reclaims state after 15 minutes of inactivity. The kdbx layer uses the published `keepass = "0.12.5"` crate; the local fork is retired.

The biggest gaps blocking daily-driver use against a real KeePassXC vault are: **keyfile support** (many vaults use a keyfile in addition to a password), and **launchd/systemd packaging** (sdpmd has to be started by hand right now). Beyond that, most "advanced" KeePassXC features (history, tags, icons, recycle bin) are read-through but not write-through, and team/sync/mobile features are entirely on the roadmap.

---

## Works today

### Vault I/O — `crates/sdpm-core/`

| Feature | State | Notes |
|---|---|---|
| Open KDBX 4 file | ✅ | [Vault::open](../crates/sdpm-core/src/lib.rs) |
| Save KDBX 4 file (atomic + fsync) | ✅ | [Vault::save](../crates/sdpm-core/src/lib.rs); writes to `<path>.tmp.<pid>`, fsyncs, renames |
| Master key: password | ✅ | |
| Master key: keyfile | ❌ | DatabaseKey supports it upstream, not plumbed through |
| Master key: YubiKey challenge-response | ❌ | DatabaseKey supports it upstream, not plumbed through |
| KDBX 3 read | ❌ | Upstream supports it; we'd need to detect on open and not refuse |
| KDBX 3 write | ❌ | Upstream's writer is KDBX 4 only |
| Cipher: AES-256 | ✅ | Default; KeePassXC reads our output |
| Cipher: ChaCha20 | ⚠️ | Likely works (upstream supports); not in our test matrix |
| KDF: Argon2d / Argon2id | ✅ | Argon2d is the writer default |
| KDF: AES-KDF | ⚠️ | Read works; we don't write it (legacy) |
| Inner stream: ChaCha20 | ✅ | Default |
| Inner stream: Salsa20 | ⚠️ | KDBX 3 only; we don't write KDBX 3 |
| Real `<Binary>` attachments (KeePassXC interop) | ✅ | KeePassXC opens our vaults; non-UTF-8 bytes round-trip; verified in [crates/sdpm-core/tests/binary_attachments.rs](../crates/sdpm-core/tests/binary_attachments.rs) |

### Entry management

| Feature | State | Notes |
|---|---|---|
| Add entry to root group | ✅ | [Vault::add_entry](../crates/sdpm-core/src/lib.rs) |
| List entries (recursive) | ✅ | |
| Find entry by title | ✅ | |
| Get/set string field (Title/UserName/Password/URL/Notes/custom) | ✅ | |
| Attach binary (any size, any content) | ✅ | |
| Read attachment | ✅ | |
| Remove attachment by name | ✅ | |
| Delete entry | ✅ | |
| `fields_with_prefix` (used by materialization) | ✅ | |
| Add entry to a non-root group | ❌ | Always lands at root; need a `--group "/Path/To/Group"` flag |
| Create / rename / move groups | ❌ | |
| Entry history (versioning) | ❌ | Upstream parses and preserves it; we don't expose |
| Tags, icons, expiry, color | ⚠️ | Read-through (preserved on save); no API to set |
| Recycle bin | ⚠️ | Same — preserved but not exposed |

### CLI direct-file mode — `sdpm` (no daemon needed)

```sh
sdpm init <vault.kdbx>
sdpm list <vault.kdbx>
sdpm add ssh <vault> <title> --key <id_ed25519> [--user <name>]
sdpm get ssh <vault> <title> [--out <path>]
sdpm add gpg <vault> <title> --key <secret-key.gpg>
sdpm get gpg <vault> <title> [--out <path>]
sdpm add file <vault> <title> --src <local> --target <materialize-path> [--mode 0600] [--ttl 600] [--allow-disk-backed]
sdpm get file <vault> <title> [--out <path>]
sdpm materialize <vault>            # in-process; SIGINT-wipes
sdpm agent socket                   # prints SSH-agent socket path
sdpm gpg-agent socket               # prints GPG-agent socket path
```

All prompt for the master password unless `--password-stdin` is set.

### CLI daemon-aware mode — `sdpm` talking to `sdpmd`

```sh
sdpm unlock <vault.kdbx>      # populates SSH/GPG agents + materialize plan
sdpm lock                     # wipes everything (idempotent)
sdpm status                   # vault path, idle remaining, key counts
sdpm idle set <seconds>       # 0 disables auto-lock
sdpm idle get
sdpm materialize-status       # one line per active materialization
```

### SSH agent — `sdpmd` Unix socket

| Feature | State | Notes |
|---|---|---|
| ed25519 sign + identify | ✅ | Real `ssh-add -l` matches `ssh-keygen -lf` byte-for-byte |
| RSA ≥ 2048 sign + identify (SHA-1 / SHA-256 / SHA-512 from agent flags) | ✅ | |
| ECDSA P-256 / P-384 sign + identify | ✅ | |
| Auto-discovery: any attachment that parses as OpenSSH PEM | ✅ | v0.0.10.2 |
| Comment shown by `ssh-add -l` | ✅ | `<title>` if attachment is `id`, else `<title>:<attachment>` |
| Lock-on-idle removes keys from agent | ✅ | |
| `ssh-add -l` / `-L` against our socket | ✅ | |
| `ssh-add -t` (per-key lifetime) | ❌ | We honor only daemon-wide idle-lock |
| `ssh-add -d` (client-driven removal) | ❌ | Not exposed; sdpm controls the key list |
| `ssh-add -c` (confirm-before-use) | ❌ | |
| DSA / ECDSA P-521 | ❌ | Skipped with a warning |
| Encrypted private key | ❌ | Refused; we'd need a passphrase prompt during unlock |
| PuTTY `.ppk` format | ❌ | OpenSSH PEM only |

### GPG agent — `sdpmd` Assuan socket

| Feature | State | Notes |
|---|---|---|
| `git commit -S` end-to-end | ✅ | Real `gpg` against our socket; verified in [crates/sdpmd/tests/gpg_git_signing_e2e.rs](../crates/sdpmd/tests/gpg_git_signing_e2e.rs) |
| `gpg --decrypt` end-to-end | ✅ | ECDH-on-Curve25519 + AES-128/192/256 KW; verified in `gpg_decrypt_e2e.rs` |
| `gpg --list-keys` | ✅ | READKEY for primary + subkey |
| ed25519 EdDSA (algo 22) | ✅ | |
| cv25519 ECDH (algo 18) | ✅ | |
| Algo 27 (RFC-9580 native ed25519) | ❌ | Skipped with a warning |
| RSA / NIST-curve / Ed448 | ❌ | Skipped with a warning |
| Encrypted secret-key export | ❌ | Refused; export with `--passphrase ''` |
| GENKEY / IMPORT_KEY / PASSWD | ❌ | Out of scope |
| Pinentry / SETKEYDESC UI | ⚠️ | Stub-OK responses; no UI prompt because the vault is already unlocked |

### File materialization

| Feature | State | Notes |
|---|---|---|
| `Materialize.{Source,Target,Mode,TTL,AllowDiskBacked}` schema | ✅ | [crates/sdpmd/src/materialize/](../crates/sdpmd/src/materialize/) |
| Write file with explicit mode on unlock | ✅ | |
| Wipe on lock or TTL expiry (random overwrite + fsync + truncate + unlink) | ✅ | [crates/sdpmd/src/materialize/wipe.rs](../crates/sdpmd/src/materialize/wipe.rs) |
| Path safety (`..`, `/etc`, `/usr`, `/bin`, `/sbin`, `/var/log` rejected) | ✅ | |
| `~` and `$HOME` / `$XDG_RUNTIME_DIR` expansion | ✅ | |
| Refuse to clobber existing target | ✅ | |
| Refuse missing parent dir | ✅ | Deliberate — caller must create the dir |
| Linux tmpfs detection (`AllowDiskBacked=false`) | ✅ | Reads `/proc/mounts` longest-prefix |
| macOS tmpfs guarantee | ⚠️ | APFS has no tmpfs; soft allowlist for `/tmp`, `/private/tmp`, `$XDG_RUNTIME_DIR` only |
| Re-materialize when entries are added while vault is unlocked | ❌ | Currently needs lock+unlock cycle |
| Auto-create parent dir | ❌ | Deliberate; could be `--create-parents` opt-in later |

### Idle-lock — `crates/sdpmd/src/idle.rs`

| Feature | State | Notes |
|---|---|---|
| Default 15 min, env override (`SDPM_IDLE_TIMEOUT`), RPC override | ✅ | |
| Bumps on every control RPC except `ping` | ✅ | |
| Bumps on every SSH agent connection + message | ✅ | |
| Bumps on every GPG Assuan command | ✅ | |
| On expiry: drops vault, clears SSH+GPG keys, wipes materializations | ✅ | All four verified by integration test |

### Daemon control RPCs

| RPC | State |
|---|---|
| `ping`, `unlock`, `lock`, `shutdown` | ✅ |
| `list` (entries) | ✅ |
| `status` | ✅ |
| `materialize-status` | ✅ |
| `set-idle-timeout` / `get-idle-timeout` | ✅ |
| `add-entry` / `set-field` / `attach-binary` / `save-vault` | ❌ |
| Multiple vaults open at once | ❌ |
| Filter / search via daemon | ❌ |

---

## Daily-driver workability checklist

Concrete pre-flight for using this with your real KeePassXC vault, in order of likelihood-to-block:

1. **Master key composition.** Open KeePassXC → Database → Database Settings → Security tab. We currently support **password only**. Keyfile or YubiKey will fail at unlock.
2. **SSH key storage.** Per-entry `Attachments` tab. We discover keys by content (any attachment that parses as `-----BEGIN OPENSSH PRIVATE KEY-----`). KeeAgent's "external key file" pointer (no attachment, just a path) is not supported; the bytes have to be in the vault.
3. **Key formats.** OpenSSH PEM only. PuTTY `.ppk` not supported. Encrypted (passphrase-protected) private keys not supported — KeePassXC's typical convention is unencrypted-key-in-encrypted-vault, which is what we expect.
4. **Key algorithms.** ed25519 ✓, RSA-2048+ ✓, ECDSA P-256 ✓, ECDSA P-384 ✓. DSA, P-521, Ed448 ❌.
5. **Daemon lifecycle.** `sdpmd &` starts it; nothing keeps it running across reboots yet. No launchd / systemd unit.
6. **Vault format.** KDBX 4 ✓. KDBX 3 not supported on read or write.

If checks 1-4 pass, the workflow is:

```sh
cargo build --release
export PATH="$PWD/target/release:$PATH"
sdpmd &
sdpm unlock ~/Documents/Passwords.kdbx           # prompts for master password
export SSH_AUTH_SOCK="$(sdpm agent socket)"
ssh-add -L                                       # should list every supported key
ssh github.com                                   # signs against the daemon
```

For GPG signing:

```sh
ln -sf "$(sdpm gpg-agent socket)" "${GNUPGHOME:-$HOME/.gnupg}/S.gpg-agent"
git commit -S -m "signed with sdpmd"
```

---

## Roadmap, prioritized

### 🔜 Immediate (next 1-2 versions) — workability-blocking gaps

1. **Keyfile unlock** (v0.0.11.0). Plumb `DatabaseKey::with_keyfile(reader)` through `Vault::open` and the `unlock` RPC. CLI: `sdpm unlock <vault> --keyfile <path>`. ~30 minutes of work plus tests.
2. **YubiKey challenge-response unlock** (v0.0.11.1). Plumb `DatabaseKey::with_challenge_response_key`. Larger lift — requires the `challenge_response` feature on `keepass`, which pulls in `nusb`. CLI: `sdpm unlock <vault> --yubikey-slot <N>`.
3. **launchd plist + systemd unit file** (v0.0.12.0). Ship `packaging/launchd/com.semdatex.sdpmd.plist` and `packaging/systemd/sdpmd.service`. Daemon survives reboot / login.
4. **`sdpm doctor`** (v0.0.12.1). Pre-flight: daemon running, socket reachable, vault format detected, keyfile path resolvable, expected env vars set. Saves users from "why doesn't this work" trial-and-error.
5. **`sdpm import-ssh ~/.ssh`** (v0.0.13.0). Convenience: scan `~/.ssh/`, prompt per key, copy any user-confirmed keys into the vault as new entries with the right attachment naming. Lets users bootstrap a fresh sdpm vault from their existing keys without manual `sdpm add ssh` per key.
6. **Better `sdpm status`** (v0.0.13.1). Today reports counts; should also list per-entry: which keys are loaded into SSH agent, which materializations are live, with their target paths. `--verbose` surfaces non-loadable attachments and why.

### Short-term (next 1-2 months) — daily-use polish

7. **CLI through daemon for `list` / `add` / `get`** (v0.0.14.x). Today these open the kdbx file directly each time and require the password. After this, an unlocked vault is reused; no password reprompt. Requires expanding the control protocol with mutating RPCs (`add-entry`, `set-field`, `attach-binary`, `save-vault`) and a way to address an unlocked vault.
8. **`sdpm exec -- cmd`** (v0.0.15.0). Run a child process with selected entries' fields exported as env vars (à la `op run`). Per-entry `Exec.{Var,Field}` opt-in fields, similar shape to `Materialize.*`.
9. **Per-shell env injection** (`eval "$(sdpm env <profile>)"`). Builds on #8.
10. **Materialize templates** (v0.0.16.0). Entry holds a template + variable refs to other entries; renders a fully-populated config file on unlock. Useful for kubeconfig fragments, `~/.aws/credentials` profiles, etc.
11. **TOTP storage and read-through** (v0.0.17.0). Read existing KeePassXC TOTP fields; `sdpm totp <title>` prints the current code. No new schema.
12. **`sdpm agent identities --filter <glob>`** (later). Per-shell narrowing of which keys are exposed via SSH agent for the current session.

### Medium-term (next quarter) — features that change what the project is

13. **Sandboxed plugin host.** WASM, capability-scoped (read entry X, write to path Y). The single biggest reason power users stay on KeePass2. Big project.
14. **Sync engine, agnostic of backing store.** 3-way merge UI, delta sync, multi-client lock coordination. Backing store can be a filesystem, WebDAV, S3, Git, or an optional self-hosted server. Avoids OAuth adapters per provider.
15. **Self-hosted sync server (optional).** Vaultwarden-shaped, end-to-end encrypted. Paired with #14.
16. **Per-user-key sidecar.** A `vault.access` file alongside the kdbx that wraps the master key with each authorized user's public key. Lets multiple people share one vault file without sharing one master password. Sidecar; doesn't touch kdbx.
17. **SSO / OIDC unlock.** Optional gate on top of the master key. Useful for teams running Keycloak / Okta / Entra.
18. **GUI per platform.** SwiftUI Mac first (since that's where this is being developed). Win/Linux later or as Tauri. Daemon is the primary surface; GUI is a client.

### Long-term — feature-spec items still on the menu

19. **FUSE / virtual filesystem mount of the vault.** Linux + macOS. Read-only; tools that want a path get one only while the vault is unlocked.
20. **HIBP continuous monitoring + breach alerts.** Background-checked, surfaced via `sdpm health` and (later) GUI notifications.
21. **Cross-entry analytics.** Reused-password graph, weak-password clusters, age-of-secret reports.
22. **Browser native messaging without GUI.** A headless browser-extension proxy.
23. **First-party mobile sidecar protocol.** Not a mobile app — a spec KeePassDX/Strongbox can adopt for materialization metadata so phones don't lose information.
24. **1Password / Bitwarden import-export.** Lossless (or as close as the source format allows).
25. **Custom entry types with schemas** — API tokens, certs, recovery codes — beyond username/password/notes.
26. **Better Linux keyring integration** (Secret Service, kwallet, gnome-keyring) so other apps can drive sdpm transparently.
27. **History / versioning UI + global undo.**
28. **Large attachment handling.** Out-of-band binary pool so the kdbx itself stays small.

### Always-on background

- **Upstream contributions to `keepass-rs`.** The clean-room test suite in [crates/keepass-spec-tests](../crates/keepass-spec-tests/) is intended as a PR. The `sdpm-patches-v0.7.33` branch on https://github.com/antimatter-studios/keepass-rs holds the pre-migration state for reference.
- **Fuzz coverage for the kdbx parser.** Same shape as [crates/sdpmd/fuzz/](../crates/sdpmd/fuzz/). Lives in keepass-spec-tests when added.
- **Cross-implementation interop tests.** Generate a vault, open it with KeePassXC / KeePassDX / KeePass2 / pykeepass, assert successful read.

---

## Things I'm explicitly *not* committing to right now

To keep the project honest about scope:

- **Windows support.** Sockets and process model are Unix-shaped; would be a meaningful port.
- **A first-party mobile app.** KeePassDX and Strongbox already exist; building a third would multi-year-duplicate work.
- **A proprietary format.** Everything stays kdbx-compatible. If we need to extend, it's via custom fields, custom data, or sidecar files — never breaking-change kdbx.
- **Cloud-hosted vault.** The (planned) self-hosted server is opt-in; we won't run a SaaS.
- **Plugins without a sandbox.** KeePassXC's stated reason for refusing plugins (in-process native code with full vault access is a footgun) is correct. Plugins will only ship with capability-scoped sandboxing — see #13.

---

## Test count by area (v0.0.10.2)

| Crate / area | Tests | Notes |
|---|---|---|
| `sdpm-core` integration (vault round-trip, attachments) | 11 | |
| `sdpmd` lib unit (idle, ssh wire, assuan, pkdecrypt, materialize) | 66 | |
| `sdpmd` daemon e2e (ping/shutdown, ssh-add, ssh-sign, gpg-sign, gpg-decrypt, materialize, idle, status) | ~25 | spread across 9 test binaries |
| `sdpm-cli` integration | 2 | unlock+status against an in-process daemon |
| `keepass-spec-tests` (clean-room kdbx coverage) | 23 + 9 ignored | broken-files, round-trip, keyfile, binary pool, cross-tool |
| **Total** | **154 passing, 9 ignored** | |

Test-count growth has been linear with feature work; the project's quality posture is "every shipped feature has at least one e2e test that exercises it against real third-party tools where possible".
