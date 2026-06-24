# trove

A KeePassXC-compatible password manager that does the things upstream won't. **100% `.kdbx` format compatibility** is non-negotiable — you can open the same vault in KeePassXC, KeePassDX, Strongbox, or KeePass2 without losing data. We only extend; we never break.

## Founding idea

Treat the vault as more than passwords. Entries can carry **files** (kubeconfig, SSH keys, GPG keys, `.env`, TLS certs, signing keys) that **materialize to disk on unlock and are wiped on lock** — opt-in per entry, with a clear acknowledgement of the on-disk-exposure risk. The vault becomes the source of truth for "the secrets a developer machine needs to function."

## Install

### macOS / Linuxbrew (via Homebrew)

```sh
brew install antimatter-studios/tap/trove
```

That installs prebuilt `trove` + `troved` binaries from the [antimatter-studios/homebrew-tap](https://github.com/antimatter-studios/homebrew-tap) tap (macOS arm64/x86_64, Linux arm64/x86_64). The binaries are built and released by trove's own [release pipeline](.github/workflows/release.yml) — the tap just references them, so installs are a download, not a multi-minute compile.

### Windows

There are two ways to run trove on Windows:

- **Native** — download `trove-<version>-windows-x86_64.zip` from [Releases](https://github.com/antimatter-studios/trove/releases). The native build uses Windows **named pipes** instead of Unix-domain sockets for its control, ssh-agent and gpg-agent channels. (Homebrew is Unix-only, so there's no `brew` path on native Windows.)
- **WSL2** — run the Linux build inside WSL2 (a real Linux environment): install via Linuxbrew exactly as above, or grab a `linux-*` tarball. Inside WSL everything works as on Linux; bridging the agent to native-Windows clients (Git for Windows, Windows OpenSSH) needs a socket→named-pipe relay such as [npiperelay](https://github.com/jstarks/npiperelay).

### From source (cargo)

```sh
git clone https://github.com/antimatter-studios/trove
cd trove
cargo install --path crates/trove-cli
cargo install --path crates/troved
```

Both commands install into `~/.cargo/bin/` (or `$CARGO_INSTALL_ROOT` if set). Make sure that's on `$PATH`.

### From source (development build)

```sh
git clone https://github.com/antimatter-studios/trove
cd trove
cargo build --release
# Binaries land at ./target/release/trove and ./target/release/troved.
# Run from there directly, or copy / symlink onto PATH.
```

## Quickstart

Linux + macOS. The daemon (`troved`) is the long-running process; `trove` is a thin CLI client.

### 1. Create a vault and stash some secrets

```sh
# Create a fresh kdbx file. Prompts twice for the master password.
trove init my-vault.kdbx

# Store an SSH private key. Title is freeform; the key bytes go into a real
# KDBX <Binary> attachment named `id` so KeePassXC can read it too.
trove add ssh my-vault.kdbx github.com --key ~/.ssh/id_ed25519

# Store a GPG secret-key export (binary, NOT armored).
gpg --batch --pinentry-mode loopback --passphrase '' \
    --export-secret-keys --output /tmp/sec.gpg <KEYID>
trove add gpg my-vault.kdbx git-signing --key /tmp/sec.gpg
shred -u /tmp/sec.gpg

# Stash a config file and tag it for materialization on unlock. The default
# AllowDiskBacked=false means troved will refuse to write to a non-tmpfs path
# (Linux) / non-ephemeral path (macOS soft-allowlist).
trove add file my-vault.kdbx kubeconfig-prod \
    --src ./kubeconfig --target /tmp/kubeconfig --mode 0600

# Inspect what's in the vault.
trove list my-vault.kdbx
```

### 2. Run the daemon

```sh
troved &
# stderr will print:
#   listening on $XDG_RUNTIME_DIR/trove.sock     (control)
#   ssh-agent listening on .../trove-ssh.sock    (SSH agent)
#   gpg-agent listening on .../trove-gpg.sock    (GPG Assuan)
#   idle-lock timeout: 900 seconds
```

The daemon also responds to `TROVE_IDLE_TIMEOUT` (env var, seconds; `0` disables auto-lock) and `TROVE_SOCK` / `TROVE_SSH_SOCK` / `TROVE_GPG_SOCK` (override socket paths).

### 3. Wire up the SSH agent

```sh
export SSH_AUTH_SOCK="$(trove ssh-agent socket)"

# Unlock the vault — keys move into daemon memory, no extra config needed.
# Prompts for the master password; populates SSH keys, GPG keys, and the
# materialization plan in one shot.
trove unlock my-vault.kdbx

ssh-add -L          # should list every ed25519/RSA-3072+/P-256/P-384 key in the vault
ssh github.com      # signs against the daemon
```

For scripted use, `trove --password-stdin unlock my-vault.kdbx` reads the password from stdin instead of prompting. The control protocol is also available raw over the Unix socket if you need to drive the daemon from a non-Rust client; see [docs/cli-reference.md](docs/cli-reference.md).

### 4. Wire up the GPG agent

```sh
# Point gpg(1) at our socket. gpg insists on a fixed path under $GNUPGHOME.
ln -sf "$(trove gpg-agent socket)" "${GNUPGHOME:-$HOME/.gnupg}/S.gpg-agent"

# After `unlock` (above), git commit -S works against an ed25519 OpenPGP key.
git commit -S -m "signed with troved"
```

### 5. Materialize a file

The `unlock` RPC also runs every entry's materialization plan. With the `kubeconfig-prod` entry from step 1, after `unlock`:

```sh
ls -l /tmp/kubeconfig
# -rw-------  1 you  you  1234 ... /tmp/kubeconfig
KUBECONFIG=/tmp/kubeconfig kubectl get pods
```

Inspect what the daemon currently has on disk:

```sh
trove materialize-status
# kubeconfig-prod  /tmp/kubeconfig  ttl=- exists=true
```

`trove status` gives a fuller summary (vault path, idle remaining, key counts). For testing without the daemon, `trove materialize my-vault.kdbx` runs the same plan in-process and wipes everything on Ctrl-C.

### 6. Lock

```sh
# Manual lock — wipes materialized files, drops vault + SSH/GPG keys from memory.
trove lock

# Or do nothing — the daemon auto-locks after TROVE_IDLE_TIMEOUT seconds of
# no activity (default 900s). Activity = any control-RPC except `ping`,
# any SSH agent message, any GPG Assuan command.
# Adjust the timeout: `trove idle set 300` (5 minutes) or `trove idle set 0` to
# disable. Inspect with `trove idle get`.
```

See [docs/cli-reference.md](docs/cli-reference.md) for the full command + RPC surface, [docs/architecture.md](docs/architecture.md) for how the pieces fit together, and [docs/threat-model.md](docs/threat-model.md) for what this defends against. The kdbx-format test suite (round-trip matrix, malformed-input rejection, keyfile formats, binary pool) lives at [crates/keepass-spec-tests/tests/](crates/keepass-spec-tests/tests/), is regenerated programmatically from a seeded RNG on every run, and exercises the published `keepass = "0.12"` crate directly with no trove-core involvement; the test crate is a workspace member so `cargo test --workspace` runs it.

## Feature exploration

Grouped by theme. Not a roadmap — a menu.

Annotations:
- *(upstream refused)* — explicit upstream rejection on record (quoted below).
- *(upstream silent)* — request exists or is implied; no maintainer answer either way.
- *(no rejection — extension territory)* — fits naturally as a kdbx-compatible extension; not in scope upstream.

### File materialization (the headline feature)

- **Decrypt-to-disk entries** — entry has a target path, perms, owner; written on unlock, securely wiped on lock. *(no rejection — extension territory)*
- **`spm exec -- cmd`** — run a process with secrets injected as env vars or temp files (à la `op run`), no on-disk residue. *(upstream silent — see [#11206](https://github.com/keepassxreboot/keepassxc/issues/11206); third-party [`keepassxc-run`](https://github.com/kai2nenobu/keepassxc-run) fills the gap)*
- **FUSE / virtual filesystem mount** — mount the vault as a read-only filesystem; secrets exist only while the FS is mounted. *(upstream silent — closest is [#4847](https://github.com/keepassxreboot/keepassxc/issues/4847); third-party [`keepass-fuse`](https://github.com/JulianJacobi/keepass-fuse) exists)*
- **SSH agent + GPG agent bridge** — keys never touch disk; agent serves them while unlocked. (KeePassXC has narrow SSH support; extend it.)
- **Templated config rendering** — entry holds a template + variable refs to other entries; renders a fully-populated config file on unlock.
- **Per-shell env injection** — `eval "$(spm env myproject)"` exports a scoped set of secrets to the current shell.

### Sync & multi-device

- **First-class cloud sync adapters** — Dropbox / GDrive / iCloud / WebDAV / S3 / Git, built in, not "bring your own". *(upstream refused — [FAQ](https://keepassxc.org/docs/): "We prefer this approach, because it is simple, not tied to a specific cloud provider and keeps the complexity of our code low.")*
- **Self-hosted sync server** — Vaultwarden-style, speaks a kdbx-aware protocol, end-to-end encrypted. *(upstream silent on a server specifically; same FAQ stance applies by analogy)*
- **Visual 3-way merge** — interactive conflict resolution when two devices diverge.
- **Delta sync** — don't re-upload a 50 MB vault on every change.
- **Multi-client lock coordination** — know when another device has the vault open.

### Sharing & teams

- **Shared vaults with per-user keys** — multiple identities, each with their own key, decrypting shared entries. *(upstream refused — droidmonkey, [#3597](https://github.com/keepassxreboot/keepassxc/discussions/3597), 2025-04-27: "Honestly I have near zero appetite for this scheme and would likely never incorporate such a complex (and non-standard) change into our application." Also 2019: "This is not how encryption works.")*
- **Per-entry / per-group sharing** — beyond KeeShare's read-only awkwardness.
- **Org RBAC + audit log** — admin console, role-based access, who-accessed-what. *(upstream refused — droidmonkey, [#9526](https://github.com/keepassxreboot/keepassxc/discussions/9526), 2023-06-04: "We are an individual password manager. It just so happens you can share the database file between users and we try to accommodate that behavior.")*
- **SSO / OIDC unlock** for team contexts. *(upstream silent — open as [#6055](https://github.com/keepassxreboot/keepassxc/issues/6055) since Feb 2021)*

### Browser, CLI, automation

- **Headless daemon mode** — browser extension and CLI work without a GUI running. *(upstream refused — droidmonkey, [#12764](https://github.com/keepassxreboot/keepassxc/discussions/12764), 2025-11-30: "Likely not possible unless you modify the code.")*
- **Stable RPC / scripting API** — proper IPC for scripts and CI, not just `keepassxc-cli` flags.
- **Native messaging without GUI** — browser proxy that doesn't require the full app.

### Passkeys, TOTP, hardware

- **Passkey / WebAuthn storage and autofill** — at parity with Bitwarden/1Password.
- **HOTP / Steam / Yandex TOTP variants** out of the box.
- **FIDO2 hardware key as primary factor**, not just challenge-response. *(upstream silent — open as [#6801](https://github.com/keepassxreboot/keepassxc/issues/6801) since 2021; groundwork PR [#10311](https://github.com/keepassxreboot/keepassxc/pull/10311) exists)*

### Plugins & extensibility

- **Sandboxed plugin system** — WASM or subprocess-isolated, signed plugins, capability-scoped. The thing KeePass2 users won't give up. *(upstream refused — [FAQ](https://keepassxc.org/docs/): "KeePassXC does not support plugins at the moment and probably never will. … Plugins are inherently dangerous. Many KeePass2 plugins are barely maintained (if at all), some have known vulnerabilities that have never been (and probably never will be) fixed.")*
- **Custom entry types** — schemas beyond username/password (API tokens, certs, recovery codes, crypto keys).

### Audit, breach, health

- **Continuous HIBP monitoring** — scheduled background checks, not one-shot.
- **Breach notifications** — email / push when a watched entry leaks.
- **Cross-entry analytics** — reused-password graph, weak-password clusters, age-of-secret reports.

### Mobile

- **Companion mobile app** — at minimum, deep integration with KeePassDX/Strongbox so file-materialization features degrade gracefully on phones. *(upstream refused — [FAQ](https://keepassxc.org/docs/): "We don't have our own mobile app … porting it properly to mobile platforms would require a full rewrite.")*
- **Mobile autofill parity** with the desktop browser extension.

### Quality-of-life

- **History / versioning UI + global undo.**
- **Large attachment handling** — store attachments out-of-band, referenced from kdbx, so the vault stays small.
- **Lossless import/export** with 1Password and Bitwarden.
- **Better Linux keyring integration** (Secret Service, kwallet, gnome-keyring).

## Upstream's reasoning, evaluated

For each upstream rejection, is the justification valid? Are we right to ignore it, or are we about to do something stupid?

### Plugin system — *upstream right on the danger, wrong on the conclusion*

> "Plugins are inherently dangerous… known vulnerabilities that have never been (and probably never will be) fixed." — [FAQ](https://keepassxc.org/docs/)

**Valid concern.** KeePass2 plugins run as in-process native code with full access to the decrypted database. That genuinely is a footgun, and the historical record of unmaintained, vulnerable KeePass2 plugins is real.

**But the conclusion ("never") is lazy.** "Plugins are dangerous *the way KeePass2 does them*" is not the same as "plugins are dangerous." A WASM sandbox with capability-scoped APIs (read this entry, write to this path, talk to this host) is a fundamentally different threat model. Browsers, Figma, Zellij, Envoy, and 1Password's own integrations all show sandboxed extensibility working in practice. Refusing to engage with the sandboxed-plugin design is a maintenance-cost decision dressed up as a security decision.

**Our stance:** ship plugins, but only sandboxed and capability-scoped. Treat upstream's warning as a spec for what to avoid, not a reason to avoid the feature.

### Built-in cloud sync — *upstream mostly right*

> "We prefer this approach, because it is simple, not tied to a specific cloud provider and keeps the complexity of our code low." — [FAQ](https://keepassxc.org/docs/)

**Largely valid.** OAuth integrations to Dropbox/GDrive/OneDrive each carry their own auth flows, token refresh, rate-limit quirks, and breakage cycles. "Drop the file in your synced folder" works, doesn't need our code, and doesn't tie users to providers we picked.

**What upstream misses:** the gaps that BYO-sync *cannot* fix — visual 3-way merge, conflict UI, multi-client lock coordination, delta sync for large vaults. These are protocol/UX problems, not adapter problems.

**Our stance:** don't build OAuth adapters. *Do* build a sync engine that handles conflicts, deltas, and multi-client awareness on top of any backing store (filesystem, WebDAV, S3, our own server). Adapters are commodity; the merge UX is the actual value.

### Per-user keys / shared vault — *upstream technically right, but solving the wrong problem*

> "This is not how encryption works." / "Honestly I have near zero appetite for this scheme…" — droidmonkey, [#3597](https://github.com/keepassxreboot/keepassxc/discussions/3597)

**Technically valid.** kdbx rotates the master seed on every save. Layering per-user keys *inside* the kdbx envelope would be a non-standard format change and would break compatibility with every other kdbx client. droidmonkey is correct to refuse that.

**But the user need isn't "modify kdbx." It's "let two people share a vault without sharing one password."** That's solvable with a sidecar: an encrypted key-bundle file (per-user public-key wraps of the vault key) sitting next to the kdbx. The kdbx itself stays standard; the bundle is our extension. Other clients still open the file with the shared key as today.

**Our stance:** don't touch kdbx internals. Build per-user access as a sidecar (`vault.kdbx` + `vault.access`). Upstream's refusal to bend kdbx is correct; their conclusion that the feature can't exist is wrong.

### "We are an individual password manager" — *valid scope, not a valid technical objection*

> "We are an individual password manager." — droidmonkey, [#9526](https://github.com/keepassxreboot/keepassxc/discussions/9526)

**Valid as scope.** A maintainer choosing what their project is *for* is legitimate. Building team features (RBAC, audit, admin console) is a different product with different testing, threat modeling, and support burden.

**It's a scope statement, not an argument the feature is bad.** The need is real (every team using KeePassXC reinvents this awkwardly). Treating it as out-of-scope upstream and as in-scope downstream is exactly what forks are for.

**Our stance:** team features are explicitly in scope here. They live behind a flag so individual users aren't paying complexity tax for them.

### Mobile = full rewrite — *upstream right; we should not do this either*

> "Porting it properly to mobile platforms would require a full rewrite." — [FAQ](https://keepassxc.org/docs/)

**Valid.** KeePassXC is C++/Qt. iOS forbids JIT and has a hostile App Store review process; Android wants Kotlin/JNI. KeePassDX (Android, Kotlin) and Strongbox (iOS, Swift) already exist and are good. Building a third mobile app would be a multi-year project that duplicates work.

**Our stance:** no first-party mobile app. Instead, define a sidecar/protocol spec that KeePassDX and Strongbox can adopt for file-materialization metadata, so phones at minimum *don't lose* the data and *can* render the file types they understand (e.g. download attachments to a sandboxed location). Materialization-to-system-paths is a desktop concept; phones get a degraded but coherent experience.

### Headless daemon — *upstream's "modify the code" is a non-answer*

> "Likely not possible unless you modify the code." — droidmonkey, [#12764](https://github.com/keepassxreboot/keepassxc/discussions/12764)

**Not a real technical reason.** The browser-extension proxy talks to the GUI app over native messaging because that's how it was built — not because cryptographically or architecturally it must. A headless daemon serving the same native-messaging protocol is straightforward. droidmonkey's answer is a maintenance-scope reply, not an architectural objection.

**Our stance:** headless mode from day one. The CLI/daemon is the primary surface; the GUI is one of several clients of it.

### Cloud sync server (Vaultwarden-shape) — *no upstream argument; defaults to scope*

No explicit upstream rejection, but the "keep complexity low / not tied to a provider" line from the cloud-sync FAQ implicitly applies.

**Our stance:** optional, opt-in self-hosted server. Never required. The vault file always works without it. Server adds: presence/lock coordination, delta sync, per-user-key bundle distribution, audit log storage. Not OAuth, not a "cloud."

### `op run` / FUSE / SSO-OIDC / FIDO2-primary — *no upstream rejection; just nobody's done it*

These are tagged *(upstream silent)* — open issues with no maintainer push-back. Not philosophical objections, just unstaffed. Our judgement: implement on merit, no controversy here.

### Where upstream is *more right than we are giving them credit for*

Worth flagging risks to ourselves:

- **Plugins**, even sandboxed, expand the attack surface. Capability scoping, signed plugins, and a default-off posture are non-negotiable.
- **Self-hosted server** is a new piece of always-on attack surface. Optional, never required, end-to-end encrypted (server sees ciphertext only).

If we can't articulate why our mitigation is materially better than "don't do it," upstream's "don't do it" wins by default.

### Why file materialization is *less* dangerous than the status quo

It's tempting to argue file materialization weakens the "encrypted at rest" guarantee. That argument doesn't survive contact with how developers actually work.

**The status quo is plaintext-on-disk forever.** `~/.kube/config`, `~/.ssh/id_ed25519`, `~/.aws/credentials`, `~/.gnupg/`, every `.env` file, kubeconfigs for clusters the developer hasn't touched in two years — these sit unencrypted on every developer machine, often syncing to backups, often readable by every process running as that user, often surviving long after the credential should have been rotated. Nobody encrypts them because the friction of decrypt-on-use is too high to bother.

**Time-bounded materialization is a strict reduction.** A secret that exists on disk for 2 minutes during active use, then is wiped, leaks less than the same secret sitting in `~/.config/` for 18 months. Lock-on-idle, lock-on-screensaver, and lock-on-disconnect collapse the exposure window further. The threat-model comparison is not "encrypted vault vs. plaintext file." It's "plaintext file forever vs. plaintext file briefly, with a real chance the developer rotates it because rotation is now cheap."

**Residual concerns and their mitigations:**

- *Swap and hibernation* — write to `tmpfs` / memory-backed paths by default; refuse materialization to disk-backed paths unless the user opts in.
- *Crash dumps and journals* — same: prefer locations the OS doesn't snapshot.
- *Forgotten unlock sessions* — aggressive auto-lock (idle, lid-close, network event), and materialization TTL independent of vault lock state.
- *Backup tooling capturing the materialized path* — document which paths are unsafe (e.g. `~/Documents` on macOS with iCloud); ship sane defaults.
- *Process-readable while live* — unavoidable while the process is using it, same as today. Per-entry filesystem ACLs narrow the audience.

**The honest pitch:** we're not weakening the encrypted-at-rest model. We're attacking the much larger problem that developers' real secrets are *not* encrypted at rest today, because no tool made it cheap enough to be.

## Principles

1. **kdbx compatibility is sacred.** Extensions live in custom fields, custom data, or sidecar files — never in format-breaking changes.
2. **Local-first.** Sync and server features are optional; the app works fully offline.
3. **Explicit risk acknowledgement** for anything that puts secrets on disk, in env vars, or on the network.
4. **Sandbox plugins.** No "run arbitrary code as the password manager" footguns.
5. **Open formats for sidecars.** If we store something outside kdbx, the format is documented and inspectable.
6. **Headless first.** GUI is a client of the daemon, not the other way around.

## Status

Early but real — the headless-daemon path works end-to-end on Linux + macOS for SSH, GPG, and file materialization against a KeePassXC-compatible kdbx. Versions shipped, oldest first:

- **v0.0.1** — kdbx vault read/write ([crates/trove-core/src/lib.rs](crates/trove-core/src/lib.rs)), `trove` CLI scaffold (`init`, `list`, `add ssh`, `get ssh`), `troved` headless daemon with the line-JSON control socket, end-to-end SSH-key roundtrip.
- **v0.0.2.0** — SSH agent listener serving ed25519 keys over `SSH_AUTH_SOCK`. Keys live only in daemon memory; cleared on lock.
- **v0.0.2.1** — SSH agent algorithm coverage extended: RSA (>= 2048 bits, signs with rsa-sha2-256 / rsa-sha2-512 per RFC 8332), ECDSA P-256, ECDSA P-384.
- **v0.0.3.0** — GPG agent listener speaking the Assuan protocol; ed25519 OpenPGP signing works against `git commit -S`. Hand-rolled OpenPGP packet parser ([crates/troved/src/gpg_agent/keys.rs](crates/troved/src/gpg_agent/keys.rs)) avoids pulling in `rpgp`.
- **v0.0.3.1** — GPG `PKDECRYPT` for ECDH-on-Curve25519: AES-128/192/256 KW unwrap of the wrapped session key against gpg 2.5.x. RSA / NIST-curve / Ed448 still out of scope.
- **v0.0.4.0** — Real KDBX `<Binary>` attachments via a vendored fork of `keepass` 0.7.33 (since retired in v0.0.10); legacy `_SDPM_BIN_*` string-field fallback kept for read-compat with v0.0.1–v0.0.3.x vaults (also retired in v0.0.10).
- **v0.0.5.0** — File materialization (the founding feature): `trove add file`, `Materialize.{Source,Target,Mode,TTL,AllowDiskBacked}` custom-field schema, in-process `trove materialize`, daemon-driven materialize-on-unlock + wipe-on-lock with optional TTL. Linux: refuses non-tmpfs targets unless `AllowDiskBacked=true`. macOS: soft allowlist (`/tmp`, `/private/tmp`, `$XDG_RUNTIME_DIR`) — APFS provides no real tmpfs, so this is a hint, not a guarantee.
- **v0.0.6.0** — Idle-lock. `IdleTracker` with a tokio driver task ([crates/troved/src/idle.rs](crates/troved/src/idle.rs)); auto-locks after configurable inactivity (default 900s). Activity = any control RPC except `ping`, any SSH agent message, any GPG Assuan command. New `set-idle-timeout` / `get-idle-timeout` RPCs and `TROVE_IDLE_TIMEOUT` env var.
- **v0.0.7.0** — GitHub Actions CI (`.github/workflows/ci.yml`): test matrix on Linux + macOS, clippy with `-D warnings`, fmt check, cargo-audit, MSRV check at Rust 1.75. Repo run through `cargo fmt --all`.
- **v0.0.7.1** — Documentation: README quickstart + [docs/architecture.md](docs/architecture.md) + [docs/threat-model.md](docs/threat-model.md) + [docs/cli-reference.md](docs/cli-reference.md).
- **v0.0.7.2** — Fuzz harnesses for the SSH agent wire decoder and Assuan line parser ([crates/troved/fuzz/](crates/troved/fuzz/), nightly-only) plus proptest property tests on stable. ~4.3M libfuzzer iterations on this machine, 0 crashes.
- **v0.0.8.0** — Clean-room kdbx spec test suite: round-trip matrix, malformed-input rejection, keyfile formats, binary pool, cross-tool (`keepassxc-cli`) interop. Programmatically generated fixtures from a seeded RNG; no GPL imports. Originally lived under `vendor/keepass/tests/`; relocated to [crates/keepass-spec-tests](crates/keepass-spec-tests/) in v0.0.10.
- **v0.0.9.0** — Daemon-aware CLI: `trove unlock`, `trove lock`, `trove status`, `trove idle set/get`, `trove materialize-status`. Replaces the `printf '{...}' | nc -U` incantations from v0.0.6 with proper subcommands.
- **v0.0.10.0** — Migrated off the vendored `keepass` 0.7.33 fork to the published `keepass = "0.12.5"`. Upstream's PR #294 already restructured attachments as first-class Database-owned objects with `EntryMut::add_attachment(name, Value::Unprotected(bytes))`, which is what our 3 patches were trying to enable. Local fork retired; legacy `_SDPM_BIN_*` migration code retired (no production v0.0.1–v0.0.3.x vaults exist).

Linux + macOS only; Windows not supported. Vault unlock currently takes a password only — no keyfiles, no hardware tokens, no KDBX 3.

Still on the menu: per-user-key sidecar, sync engine, browser native messaging, plugin host, mobile sidecar protocol, GUI. Open to scope cuts — the feature exploration above is intentionally broader than what we'll build.
