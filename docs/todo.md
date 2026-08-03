# TODO — open items

Working list of outstanding work. Companion to [status.md](status.md), which
catalogues what *is* built; this one tracks what still needs doing and why.

Ordered by leverage within each section.

---

## Bugs / investigations

### 1. `git commit -S` "No secret key" — ✅ RESOLVED (was never a gpg bug)
**Root cause: the test picked up the developer's global `~/.gitconfig`.** That
config set `gpg.program` to a wrapper script which re-exports its own
`GNUPGHOME`, discarding the isolated one the test sets. gpg then looked in a
keyring that didn't have the test key and correctly reported
`skipped "<FPR>": No secret key`.

GnuPG 2.5.x was a red herring, and so was the algorithm — the wrapper hit
ed25519 and RSA equally. Trove's agent signs fine under 2.5.21; captured Assuan
traces for a real gpg-agent and trove's are **identical** in the sign path.

Fixed by isolating `git` from user/system config in
`gpg_git_signing_e2e.rs` and `gpg_rsa_signing_e2e.rs` (`GIT_CONFIG_GLOBAL`,
`GIT_CONFIG_SYSTEM`, `GIT_CONFIG_NOSYSTEM`, plus a repo-local
`gpg.program=gpg`). The comment in the test blaming dev gpg builds has been
deleted; it was wrong.

Worth remembering: gpg 2.5 issues **no `KEYINFO`** in the sign path and uses
`HAVEKEY --list=1000` rather than per-grip `HAVEKEY`. Trove handles both.

### 1b. Two small agent gaps found along the way
- **No `KILLAGENT`** — `gpgconf --kill gpg-agent` gets `ERR Unknown_IPC_Command`
  from trove, so the tests' defensive kill of a stray real agent is a silent
  no-op. Implement it (reply `OK`, shut the connection) or document it.
- **`GETINFO version` returns a hard-coded `2.4.5`**, so gpg 2.5 logs
  `WARNING: server 'gpg-agent' is older than us`. Harmless today, but a
  version-gating footgun if gpg ever conditions behaviour on it.

### 1c. Daemon e2e tests share the default socket path
`TROVE_SOCK` defaults to `$TMPDIR/trove-0.sock`, so two `cargo test` runs on one
machine fight over it through the singleton flock — a second run dies partway
through `autospawn_e2e`. Hit for real when a parallel agent's worktree ran its
suite concurrently. `scripts/acceptance.sh` already isolates all three socket
paths into a temp dir; the cargo tests should do the same so concurrent runs
(CI matrix, parallel agents, a developer with two checkouts) don't collide.

### 2. `README.md` claims we broker for Git for Windows
Git for Windows bundles an MSYS2 ssh using Cygwin socket emulation, not native
named pipes — the claim is probably false. Prove it on a real machine or reword.
See [windows.md](windows.md).

---

## Features

### 3. Wire SSH forwarding into unlock/lock
The mechanism is built and verified (`ssh_agent::forward`), but has **zero call
sites** outside tests. Blocked on nothing except the parser below.

### 4. Widen the `KeeAgent.settings` parser
`keeagent::parse` returns only the attachment name, so four fields we already
*write* are unreadable. Once surfaced they drive item 3 with no new config:

| Field | Verdict |
|---|---|
| `RemoveAtDatabaseClose` | **deliberately not honoured** for our own agent — lock always drops the store, and honouring `false` would mean retaining a key past lock. Needed for the forwarding path only. |
| `UseLifetimeConstraintWhenSigning` + `LifetimeConstraintDuration` | **implement** — gives a per-key TTL narrower than the global idle-lock. Nothing blocking. |
| `UseConfirmConstraintWhenSigning` | **blocked** on having a UI to prompt with (see item 6). Implementable for forwarding today, since the external agent prompts. |

### 5. RSA `PKDECRYPT`
Signing works for RSA now; decryption doesn't. Blocks `pass`, `sops`,
`git-crypt`, and encrypted mail — all of which hammer the decrypt path.
Parsing is already done, so this is the RSA unwrap plus wiring into the
existing `PKDECRYPT` handler.

### 6. `troved::serve()` extraction → desktop hosts the daemon
`main.rs` is ~530 lines of setup the desktop can't reuse. Extracting a `serve()`
entry point lets trove-desktop bind the sockets in-process, which also makes the
desktop the natural pinentry for item 4's confirm constraint.

Needs a fallback: if a standalone `troved` already holds the singleton lock, the
desktop should degrade to being a *client* rather than refusing to start.

### 7. Export public keys into the user's gpg keyring on unlock
gpg won't ask any agent for a key it doesn't know about, so a vault-held key is
invisible until its public half is in the keyring. Our e2e tests hide this by
generating keys with gpg itself.

### 8. Windows: bind the well-known agent pipe
`\\.\pipe\openssh-ssh-agent` is usually free (the OpenSSH Authentication Agent
service ships disabled), so trove can own it with zero config and no key
material leaving troved. Best integration story of any platform.
Prerequisite: port `ssh_agent::forward` to named pipes for the fallback path.
See [windows.md](windows.md).

### 9. Explicit agent commands: `trove agent purge` / `trove agent lock`
Client-side `REMOVE_ALL_IDENTITIES` / `LOCK` against an external agent. Both hit
keys trove never added, so they must be deliberate user actions, never fired by
a vault lock.

---

## Spikes (answer a question before committing to work)

### 10. trove as an scdaemon — ✅ spiked, verdict **GO**
See [spike-scdaemon.md](spike-scdaemon.md). A software card served
`gpg --detach-sign` end to end, and critically **nothing was displaced** —
keygen, `--edit-key` and on-disk-key signing all kept working.

Remaining before this becomes real work:
- **10a. Test ed25519 on the card path.** Only RSA-2048 was proven, and ed25519
  is trove's default GPG key type. Do this before building anything.
- **10b. Test passthrough against real hardware.** Proxying was proven
  software-to-software only. Until a Yubikey/PIV badge is tested, "hardware users
  keep their token" is unverified — and only one scdaemon runs at a time, so
  getting this wrong breaks them.
- **10c. `PKDECRYPT` on the card path**, plus Linux/Windows and gpg 2.2 (the
  spike ran on 2.5.21, a dev build).

### 11. Verify the Keychain claim — ✅ done
Confirmed: wire-added keys leave nothing in the Keychain, because `ssh-agent`
has **no Keychain code at all** (it's in `ssh-add`, and doesn't even link
Security.framework). Evidence in [macos.md](macos.md).

### 12. Verify `CONSTRAIN_CONFIRM` on Apple's agent — ✅ done, with a catch
Apple's agent honours it, but **macOS ships no askpass binary**, so a
confirm-constrained key fails closed — `agent refused operation`, instantly, with
no prompt. Trove must detect an askpass before applying the constraint, or the
key silently becomes unusable. Feeds item 4.

---

## Deferred (decided, not forgotten)

- **Multi-vault phases 2–3** — dropping the vestigial `<VAULT>` positional and
  `--vault` disambiguation on read/write commands. Today an ambiguous title is
  refused with a message naming both vaults: safe, but not resolvable without
  locking one. See [multi-vault.md](multi-vault.md).
- **Agent routing** — the backend-registry generalisation. Build the seam, not
  the ecosystem; no registration protocol until a real second backend exists.
  See [agent-routing.md](agent-routing.md).
- **Key deconfliction across vaults** — union and last-wins for now. Revisit when
  a real conflict appears.
- **NIST/brainpool curves for OpenPGP** — long tail, skip until asked.
