# Architecture

A practical guide for someone reading the sdpm codebase for the first time. Aimed at "where does this thing live and why" rather than line-by-line API reference — read [crates/sdpm-core/src/lib.rs](../crates/sdpm-core/src/lib.rs) for that.

## Crate layout

```
SuperDuperPasswordManager/
├── crates/
│   ├── sdpm-core/      vault library (kdbx I/O, no networking)
│   ├── sdpm-cli/       `sdpm` binary — thin CLI client
│   └── sdpmd/          `sdpmd` binary + library — headless daemon
└── vendor/
    └── keepass/        vendored fork of the `keepass` crate
```

**[crates/sdpm-core](../crates/sdpm-core/)** — the vault library. Pure data layer. One public type, [Vault](../crates/sdpm-core/src/lib.rs), with sync methods (`open`, `save`, `add_entry`, `attach_binary`, `read_binary`, `set_field`, `get_field`, `list_entries`, ...). No async. No sockets. No process-level state. Knows nothing about SSH or GPG. The CLI and the daemon both depend on it; nothing depends on the CLI or the daemon.

**[crates/sdpm-cli](../crates/sdpm-cli/)** — the `sdpm` binary. Clap-driven. For most commands it opens the vault directly via `sdpm-core` and exits — the daemon is not required. Only the `agent socket` / `gpg-agent socket` helpers and the `materialize` command interact with daemon-shaped code at all. (The `materialize` command imports `sdpmd::materialize` as a library, sharing the same plan-and-write logic as the daemon, but it does not connect to a running `sdpmd`.)

**[crates/sdpmd](../crates/sdpmd/)** — the headless daemon. This is where secrets live in memory while the vault is unlocked. Owns three Unix sockets, four secret stores, and an idle-lock timer. Compiled both as a binary (`sdpmd`) and as a library (`sdpmd::*`) so the CLI and integration tests can import its modules.

**[vendor/keepass](../vendor/keepass/)** — vendored fork of the upstream `keepass` 0.7 crate, patched at the workspace level. See [Cargo.toml](../Cargo.toml)'s `[patch.crates-io]` block. Forked because upstream 0.7.33 parses `<Binary Ref="..."/>` references inside entries but discards them ("TODO reference into a binary field from the Meta") and panics on non-UTF-8 `Value::Bytes` during save. The fork makes binary attachments round-trip as real KDBX4 inner-header binaries, which restores bit-exact KeePassXC interop. Planned upstream contribution; in the meantime, the vendored copy unblocks shipping.

Why split it three ways at all? The daemon is a security-critical surface — it owns decrypted material in process memory. Keeping the cryptographic data path (sdpm-core) free of async, networking, and listener code makes it easier to audit. Keeping the CLI off the daemon's hot path (most subcommands open the kdbx directly) makes one-off operations work even if `sdpmd` is not running.

## Daemon model

`sdpmd` is the long-running process. The CLI is a thin client (mostly). On startup [crates/sdpmd/src/main.rs](../crates/sdpmd/src/main.rs):

1. Resolves three socket paths from env / `$XDG_RUNTIME_DIR` / `$TMPDIR` (see [crates/sdpmd/src/main.rs](../crates/sdpmd/src/main.rs), [crates/sdpmd/src/ssh_agent/mod.rs](../crates/sdpmd/src/ssh_agent/mod.rs), [crates/sdpmd/src/gpg_agent/mod.rs](../crates/sdpmd/src/gpg_agent/mod.rs)).
2. Removes any stale socket files left over from a previous run.
3. Binds all three; chmods them `0600`.
4. Spawns the SSH and GPG listener tasks.
5. Spawns the idle-tracker task.
6. Enters the control-socket accept loop.

```
                       ┌───────────────────────────────┐
   sdpm CLI    ──────► │ control socket (line-JSON)    │
   nc -U / etc.        │   $XDG_RUNTIME_DIR/sdpm.sock  │
                       │     ping/unlock/lock/list/    │
                       │     materialize-status/       │
                       │     set-idle-timeout/...      │
                       └───────────────┬───────────────┘
                                       │
                                       ▼
   ssh client    ──────► ┌──────────────────────────┐
   git/ssh                │  SSH agent socket        │  ←── handler.rs
   SSH_AUTH_SOCK=…        │  sdpm-ssh.sock (binary)  │      dispatches all
                          └──────────────────────────┘      three from one
                                                            shared SharedState
   gpg/git -S    ──────► ┌──────────────────────────┐
   S.gpg-agent            │  GPG agent socket        │
   symlink                │  sdpm-gpg.sock (Assuan)  │
                          └──────────────────────────┘
                                       │
                                       ▼
                       ┌───────────────────────────────┐
                       │ in-memory secret stores       │
                       │  - vault (Vault)              │
                       │  - SSH KeyStore               │
                       │  - GPG GpgKeyStore            │
                       │  - MaterializedStore          │
                       │  - IdleTracker (timer)        │
                       └───────────────────────────────┘
```

Three sockets, three protocols, one shared state machine.

| Socket | Path env | Protocol | Wire format | Owner |
| --- | --- | --- | --- | --- |
| Control | `SDPM_SOCK` / `$XDG_RUNTIME_DIR/sdpm.sock` | sdpm-internal | newline-delimited JSON, one request/response per line | [crates/sdpmd/src/protocol.rs](../crates/sdpmd/src/protocol.rs), [crates/sdpmd/src/handler.rs](../crates/sdpmd/src/handler.rs) |
| SSH agent | `SDPM_SSH_SOCK` / `$XDG_RUNTIME_DIR/sdpm-ssh.sock` | OpenSSH agent protocol | binary (length-prefixed) | [crates/sdpmd/src/ssh_agent/](../crates/sdpmd/src/ssh_agent/) |
| GPG agent | `SDPM_GPG_SOCK` / `$XDG_RUNTIME_DIR/sdpm-gpg.sock` | Assuan | ASCII line-oriented | [crates/sdpmd/src/gpg_agent/](../crates/sdpmd/src/gpg_agent/) |

The CLI is a thin client *for the parts that talk to the daemon*. For everything else (`init`, `list`, `add`, `get`, in-process `materialize`) the CLI opens the kdbx file directly via sdpm-core and never connects to `sdpmd`. This is deliberate: a developer who wants to add a single SSH key to a vault should not have to start a daemon to do it.

## State machine

There are two states — **vault locked** and **vault unlocked**. They flip on a single set of operations:

- `unlock` (control RPC): parse kdbx, populate stores, arm idle timer, return `ok`.
- `lock` (control RPC): wipe materialized files, drop vault, clear key stores, cancel idle timer.
- `shutdown` (control RPC): same as lock + tell main loop to exit.
- Idle timer fires: same set of operations as `lock`, no response. See [crates/sdpmd/src/main.rs](../crates/sdpmd/src/main.rs) `build_lock_callback`.

What's loaded into daemon memory on **unlock**:

1. Parsed `Vault` (a `keepass::Database` plus its master password). Lives behind `Arc<Mutex<Option<Vault>>>`.
2. SSH `LoadedKey` list — one per entry whose `id` attachment parses as a supported OpenSSH private key. ed25519, RSA >= 2048, ECDSA P-256, ECDSA P-384. Encrypted, weak, or unsupported keys are skipped with a warning.
3. GPG `LoadedGpgKey` list — one per ed25519 secret key found in any `gpg-priv` attachment. Other algorithms and encrypted secret keys are skipped.
4. `MaterializedFile` list — one per entry whose `Materialize.*` fields validate, with the bytes already on disk by the time `unlock` returns `ok`.

What's cleared on **lock** / **idle expiry** / **shutdown**:

- Materialized files are unlinked from disk before any other state changes (so a subsequent error during memory teardown still leaves the disk clean).
- Vault dropped (its `VaultInner::Drop` zeroes the cached password).
- SSH key vec cleared (`ssh_key::SigningKey` is `ZeroizeOnDrop`).
- GPG key vec cleared (cv25519 / ed25519 secret scalars zero on drop).
- Idle timer cancelled (atomics reset to "not running").

The `lock` and `shutdown` paths intentionally use the same wipe-then-drop sequence as the timer-fired path, just with a response. See [crates/sdpmd/src/handler.rs](../crates/sdpmd/src/handler.rs).

## The four delivery surfaces

Different secrets need different "shape of escape from the vault." Each surface has a different threat-model trade-off; pick whichever one your secret tolerates.

1. **File materialization** — write secret bytes to a path on the local filesystem. Used for kubeconfigs, `.env` files, TLS certs, and anything a downstream tool wants to `open(2)` by path. Wins big on compatibility (every tool reads files); loses on residue (disk artifacts can outlive the process). Mitigations: tmpfs-by-default on Linux, soft-allowlist on macOS, optional TTL, atomic wipe on lock. See [crates/sdpmd/src/materialize/](../crates/sdpmd/src/materialize/).

2. **SSH agent** — the secret never touches disk. The agent socket serves `RequestIdentities` and `SignRequest`; the daemon does the signing in memory. Best surface available for any tool that already speaks `SSH_AUTH_SOCK`. Trade-off: only works for SSH; some tools want a key file path and won't use an agent.

3. **GPG agent** — same shape as SSH agent, Assuan instead of OpenSSH binary protocol. Sign + ECDH-decrypt in daemon memory. Currently ed25519-only for sign, Curve25519-only for decrypt; partial cipher coverage on PKDECRYPT (AES-KW). RSA, NIST curves, Ed448 are out of scope.

4. **CLI direct retrieval** (`sdpm get ssh|gpg|file`) — open vault, read attachment, write to `--out` (or stdout). One-shot, no daemon involvement. Useful for scripted workflows that can't use any of the above. Same disk-residue risk as full materialization but without TTL or wipe-on-lock — the user is on their own to clean up.

The honest spectrum: SSH/GPG agents > materialization (with tmpfs + TTL) > materialization (disk-backed) > `sdpm get`. Use the leftmost option your tool will accept.

## kdbx format compatibility

`100% .kdbx format compatibility` is the project's hard constraint — you can open the same vault in KeePassXC or any other kdbx client without losing data. We extend; we never break.

We vendor a fork of `keepass` 0.7.33 ([vendor/keepass](../vendor/keepass/)) because upstream has two bugs in our use case:

1. `<Binary Ref="..."/>` references inside entries are parsed but discarded on read.
2. Saving a `Value::Bytes` whose contents aren't valid UTF-8 panics in the XML serializer.

Without (1), every binary attachment we write is dropped on the next `save`. Without (2), saving any vault containing a binary key causes a crash. The fork resolves both: real attachments are kept on the inner-header binary pool, references survive round-trip, and `Value::Bytes` is base64-encoded into the XML.

Plan: upstream the fix. Until then, the workspace `[patch.crates-io]` redirect makes the vendored crate transparent — nothing in our crates says `path = "../../vendor/keepass"` directly.

There is a legacy `_SDPM_BIN_<name>` string-field fallback for vaults written by sdpm v0.0.1 through v0.0.3.x: those versions, before the fork landed, base64-encoded attachments into protected string fields. [Vault::read_binary](../crates/sdpm-core/src/lib.rs) consults real attachments first and falls back to the legacy field; [Vault::attach_binary](../crates/sdpm-core/src/lib.rs) drops the legacy field on write so the vault migrates incrementally. No user action required.

## Threat model

Quick version (full version: [docs/threat-model.md](threat-model.md)).

**What we defend against:**

- The idle developer machine. Vault state + materialized files vanish after `SDPM_IDLE_TIMEOUT` (default 900s) of no activity.
- Casual local attackers. Sockets are `0600`; secret files default to `0600`; tmpfs-only target paths on Linux unless explicitly overridden.
- Accidental check-ins of secrets. The vault is the source of truth; tools read from materialized paths or from the agents, not from secrets sitting in the repo.
- Lost laptops (cold). Encrypted-at-rest kdbx, password-derived KDF.

**What we do NOT defend against:**

- Kernel-level attackers. We use process memory; a kernel that can read it can read our secrets.
- Physical RAM attacks (cold-boot etc.). Best-effort `Zeroize` on drop; not a guarantee against a determined attacker with physical RAM access.
- Other processes running as the same user. Anything that can `ptrace` us, read `/proc/self/mem`, or open our sockets (they are `0600`, owned by us — but a process running as us can still open them) sees what we see.
- Swap / hibernation when materializing to disk-backed paths. `AllowDiskBacked=true` is opt-in; the warning is on the user.
- macOS not having real tmpfs. APFS-backed `/tmp` and `/private/tmp` are not memory-only. The macOS soft-allowlist is a hint, not a guarantee.

## Why headless-first

The core architectural choice: **the daemon owns secret state; the GUI/CLI/browser are clients of it.** This is the inverse of KeePassXC, where the GUI owns state and the browser/CLI talk to the GUI.

Implications:

- **Scriptable.** A CI runner can `unlock` once, run a series of `kubectl` / `git` / `ssh` invocations, and `lock`. No pinentry prompt, no GUI dependency.
- **Automatable.** A laptop-lid-close handler can fire a `lock` RPC; a screensaver hook can fire `set-idle-timeout 60`. The daemon does not need to be aware of any specific desktop environment.
- **Headless-server-friendly.** Run the daemon on a build machine over SSH. The vault file lives on disk; `unlock` over the (daemon-local) control socket; SSH-forward `SDPM_SSH_SOCK` if you really want to (and you've thought about it).
- **GUI is a future client.** When we do build a GUI, it will speak the same control protocol as everything else. No special "GUI knows about the vault" code path; no second source of truth.

This is the part of the spec where we explicitly diverge from upstream. droidmonkey on the KeePassXC tracker: "Likely not possible unless you modify the code." Modifying the code is exactly what we did.

## Idle lock

[crates/sdpmd/src/idle.rs](../crates/sdpmd/src/idle.rs) implements `IdleTracker`. Single tokio task, lives for the lifetime of the daemon, alternates between **idle** (no timer running, parked on a `Notify`) and **running** (sleeping until `last_activity + timeout`).

`bump()` is the hot path: every SSH agent message, every GPG Assuan command, and every control RPC except `ping` calls it. To stay cheap it does one `AtomicI64::store(Relaxed)` and one `Notify::notify_one`. No allocation, no mutex, no syscall. `notify_one` coalesces, so a burst of activity wakes the driver task at most once.

What counts as activity:

| Event | Bumps? |
| --- | --- |
| Control RPC (any except `ping`) | yes |
| `ping` RPC | no — pings are keepalive heartbeats and counting them would let a stuck client trivially defeat the auto-lock |
| SSH agent connection accepted | yes |
| SSH agent message received | yes |
| GPG agent connection accepted | yes |
| GPG agent message received | yes |
| Idle (nothing happens) | no |

Configuration: `SDPM_IDLE_TIMEOUT` (env, seconds, `0` disables) or `set-idle-timeout` RPC. Default 900s. Reading the current state at runtime: `get-idle-timeout` RPC, returns `seconds` (configured) and `remaining` (countdown if a vault is unlocked, else `null`).

When the timer fires, the `IdleTracker` invokes the same `LockCallback` that the explicit `lock` RPC uses — wipe materialized files, drop vault, clear SSH+GPG stores. `eprintln!("idle lock after {N} seconds")` is the only signal.

## What's missing / known limitations

Honest list. None of these are show-stoppers; all of them are real.

- **`keepass-rs` vendoring.** Real attachments and non-UTF-8 bytes work because of the fork in [vendor/keepass](../vendor/keepass/). Until the fix is upstreamed and a release happens, every contributor needs the fork checked in. Plan: file the upstream PR, drop the patch when it lands.
- **macOS file materialization.** APFS has no tmpfs. The "tmpfs-or-refuse" guarantee Linux gives users with `AllowDiskBacked=false` becomes a soft allowlist on macOS. Documented in the error path; users should know.
- **Partial GPG decrypt cipher coverage.** PKDECRYPT works for ed25519+cv25519 keys produced by gpg 2.5.x with default ciphers (AES-128/192/256-KW). RSA, NIST-curve ECDH, Ed448, and other AEAD modes are out of scope and cleanly error out — but `gpg --decrypt` for a message encrypted with a non-supported scheme will fail.
- **No keyfile / hardware-token vault unlock.** Password only. KeePassXC supports both; we will eventually.
- **No KDBX 3 read.** KDBX 4 only. KDBX 3 vaults must be migrated by KeePassXC first.
- **No re-materialize on `add`-while-unlocked.** Adding a `file` entry to an open vault doesn't materialize it; you have to lock and unlock. Easy follow-up.
- **No GUI.** Daemon-only project today.
- **No sync, no per-user key sidecar.** Both are explicitly on the spec; neither is built.
- **No browser native messaging.** The headless-daemon design supports it; nothing implemented yet.

The shape of "ship the smallest thing that works, document the gaps, iterate" is intentional. The README pitch lists what we want to build; the [Status](../README.md#status) section lists what we have built. The gap between them is the roadmap.
