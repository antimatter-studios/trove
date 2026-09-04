# macOS — platform notes

Status: **notes.** Some of this describes how trove behaves today, some is
future work. Each section says which. Companion to
[windows.md](windows.md) — the two platforms differ in ways that flip several
recommendations, so read them together before designing anything cross-platform.

## The one-paragraph version

macOS gives us a good SSH story and no GPG story. Apple ships an ssh-agent that
every process in your login session can reach, so the question for SSH is only
*how* to plug into it. Apple ships nothing for GPG — and the socket GnuPG's own
agent uses can't be taken or fronted, because gpg-agent automatically reclaims
it. The only viable GPG route is to plug in *underneath* gpg-agent as an
scdaemon. Materialized files are ours alone on every platform, but macOS can't
promise memory-backed storage the way Linux can.

---

## SSH

### How macOS finds an agent

`ssh` looks **only** at `$SSH_AUTH_SOCK`. There is no fallback path it probes.
Apple's `ssh-agent` is a launchd on-demand service, and launchd injects
`SSH_AUTH_SOCK` (something like `/private/tmp/com.apple.launchd.XXXX/Listeners`)
into every process in the login session — Finder-launched apps and terminals
alike. That is why "unlock in a GUI app, push from VS Code" works on macOS.

The consequence for trove: a process that didn't inherit our socket path can
never find trove's agent. Env vars are inherited at fork, so exporting
`SSH_AUTH_SOCK` in a shell never reaches an already-running editor.

This is the **opposite** of Windows, which has a well-known pipe name we can
simply bind. macOS has no such name for SSH.

### Two ways in, and when to use each

**1. `IdentityAgent` (preferred — nothing leaves troved).**

```
Host *
    IdentityAgent /path/to/trove-ssh.sock
```

Read from `~/.ssh/config`, not the environment, so it works regardless of what a
process inherited — including GUI-launched apps. Keys stay in troved, so
idle-lock, `lock --vault`, and wipe all keep working. Get the path from
`trove ssh-agent socket`.

**2. Forwarding into Apple's agent (the KeePassXC model).**

`crates/troved/src/ssh_agent/forward.rs` implements the client side of
`ADD_IDENTITY` / `ADD_ID_CONSTRAINED` / `REMOVE_IDENTITY`, verified against a
real `ssh-agent` in `crates/troved/tests/ssh_agent_forward_e2e.rs`. **Built, not
yet wired into unlock/lock.**

Zero configuration, reaches everything — but the private bytes leave troved. Once
Apple's agent holds a copy, our lock can only *ask* for its removal. Mitigations,
all KeePassXC-compatible and all read from `KeeAgent.settings`:

| Setting | Effect | Status |
|---|---|---|
| `AddAtDatabaseOpen` | forward this key on unlock | read today |
| `RemoveAtDatabaseClose` | remove it on lock | **written but ignored** |
| `UseLifetimeConstraintWhenSigning` + `LifetimeConstraintDuration` | agent expires the key by itself — survives troved being killed | **written but ignored** |
| `UseConfirmConstraintWhenSigning` | prompt on every *use* — strongest control over a key we no longer hold, but on a stock Mac it has no prompt to show and simply refuses (see below) | **written but ignored** |

Note the granularity: these are **per entry**, live in the vault, and round-trip
through KeePassXC — so a user can configure trove's agent behaviour from
KeePassXC's own UI. No new trove-specific config is needed.

### Keychain: not a risk on this path — verified

**Verified** on macOS 26.4.1 (OpenSSH_10.2p1), 2026-08-01, with throwaway keys
against both an isolated `ssh-agent` and Apple's real launchd agent. A key
forwarded with `forward::add_all` (`ADD_IDENTITY` / `ADD_ID_CONSTRAINED`) leaves
**nothing** in the Keychain and cannot be reloaded after the agent dies.

The reason is stronger than "the message carries no Keychain flag": **the agent
has no Keychain code at all.** All of it lives in the *client*:

```
$ strings -a /usr/bin/ssh-add | grep -i keychain
… openssh/keychain.m  keychain_read_passphrase  store_in_keychain
   remove_from_keychain  "SSH: %@"  com.apple.ssh.passphrases

$ strings -a /usr/bin/ssh-agent | grep -ic keychain
0
$ otool -L /usr/bin/ssh-agent | grep -c Security.framework
0                       # ssh-add links Security.framework; ssh-agent does not
```

So `ssh-add --apple-use-keychain <file>` stores a passphrase item (service
`com.apple.ssh.passphrases`, label `SSH: <path>`) *before* it ever talks to an
agent. Nothing arriving over the socket can trigger that path, because the
process on the other end of the socket cannot reach the Keychain.

The end-to-end check, in one agent lifetime:

```
# positive control: a file-backed, passphrase-protected key persisted on purpose
$ ssh-add --apple-use-keychain /tmp/xx.EEf3/kp
# then, in a brand-new agent:
$ ssh-add --apple-load-keychain
Identity added: /tmp/xx.EEf3/kp (trove-probe-KC-THROWAWAY)   # ← came back

# the trove path: forward::add_all → SSH_AGENTC_ADD_IDENTITY
$ ssh-add -l
256 SHA256:qq8u…r20 trove-probe-KC-THROWAWAY (ED25519)   # keychain-backed
256 SHA256:2Aav…S04 trove-probe-THROWAWAY    (ED25519)   # wire-added
# kill the agent, start a fresh one:
$ ssh-add --apple-load-keychain && ssh-add -l
256 SHA256:qq8u…r20 trove-probe-KC-THROWAWAY (ED25519)   # only the file-backed one
```

The wire-added key does not survive the agent. The file-backed one does — which
is what makes the negative result meaningful rather than a blind detector.

**Trap for anyone re-running this: `security dump-keychain` cannot see the
item.** On macOS 26 `ssh-add` stores the passphrase in the data-protection
keychain, which the legacy `security(1)` tool does not search. The item set from
`security dump-keychain` was byte-identical before and after
`--apple-use-keychain`, and `security find-generic-password -s "SSH:"` reported
"item could not be found" the whole time — while the passphrase was demonstrably
stored. Use `ssh-add --apple-load-keychain` (or `ssh-add -v`, which prints
`debug2: Passphrase not found in the keychain.` on a miss) as the detector.

### Agent-wide controls we do not implement

| Message | Effect | Why not automatic |
|---|---|---|
| `REMOVE_ALL_IDENTITIES` (19) | drop every key in the agent | hits keys trove never added |
| `LOCK` (22) / `UNLOCK` (23) | passphrase-gate the whole agent (`ssh-add -x` / `-X`) | same collateral damage, **and** trove would have to choose and store the passphrase — generate-and-discard bricks the agent |

If these ever land, they belong behind explicit commands (`trove agent purge`,
`trove agent lock`), never fired by a vault lock. Per-key `REMOVE_IDENTITY` is
the correct automatic behaviour.

### `CONSTRAIN_CONFIRM` on Apple's agent — verified, with a catch

**Verified** on macOS 26.4.1 (OpenSSH_10.2p1), 2026-08-01, against both an
isolated agent and Apple's real launchd agent, using throwaway keys.

Apple's agent **does honour the constraint**, and its confirm path is stock
upstream OpenSSH — `Allow use of key %s?` via `SSH_ASKPASS`, with the compiled-in
fallback still `/usr/X11R6/bin/ssh-askpass`. There is no Apple-native dialog:
`strings /usr/bin/ssh-agent` shows only the upstream prompt and askpass strings.

**The catch: macOS ships no askpass binary.** `/usr/X11R6/bin/ssh-askpass`,
`/usr/libexec/ssh-askpass` and friends do not exist, and the launchd agent's
environment has no `SSH_ASKPASS`. So on a stock GUI login session the constraint
does not produce a prompt — it makes the key **unusable**:

```
# Apple's real launchd agent, key added with forward::add_all(.., confirm=true)
$ ssh-add -T /tmp/xx.EEf3/k.pub
Agent signature failed for /tmp/xx.EEf3/k.pub: agent refused operation   # instant
# same agent, same code path, confirm=false → signs fine (exit 0)
```

It fails **closed**, instantly — no hang, no dialog, no silent signature. That is
the safe failure mode, but it is a hard "no", not a prompt.

With an askpass in the **agent's own** environment the prompt works exactly as
upstream (isolated agent started with `SSH_ASKPASS=… SSH_ASKPASS_REQUIRE=force`):

```
askpass invoked, argv[1] = "Allow use of key trove-probe-THROWAWAY?
                            Key fingerprint SHA256:2Aav…S04."
                SSH_ASKPASS_PROMPT = "confirm"
askpass exit 0 → ssh-add -T succeeds (exit 0)
askpass exit 1 → "agent refused operation" (exit 1)
```

The prompt shows the **key comment**, which for trove is the entry title — so a
useful title is what the user actually sees when deciding.

Consequences for `UseConfirmConstraintWhenSigning`:

- Honouring it is correct and safe; a compromised process cannot sign behind the
  user's back.
- But on a default Mac the key silently becomes useless, and the error
  (`agent refused operation`) says nothing about why. If trove sets this
  constraint it must tell the user they need an askpass helper, and check for one.
- The environment that matters is the **agent's**, not the client's. For the
  launchd agent that means `launchctl setenv SSH_ASKPASS …` *before* the agent
  starts — the running agent's environment is fixed at exec. **Untested**: doing
  so would have required killing the user's live agent.

---

## GPG

### macOS ships nothing

There is no Apple gpg-agent. GnuPG brings its own (Homebrew `gnupg`, GPG Suite),
and `gpg` auto-starts it via `gpgconf --launch gpg-agent`. So unlike SSH, there
is no platform service to defer to.

### How gpg finds its agent — never hardcode the path

`GNUPGHOME` is GnuPG's **own** env var, not a cross-vendor standard like XDG.
It defaults to `~/.gnupg` on Unix and `%APPDATA%\gnupg` on Windows. The
agent-socket filename `S.gpg-agent` is a GnuPG convention — but **one filename
hides three different mechanisms**:

| Platform | What is actually at `$GNUPGHOME/S.gpg-agent` |
|---|---|
| macOS | a real Unix socket (confirmed on this machine) |
| Linux, GnuPG ≥ 2.1.13 | usually a **redirect file** — text starting `%Assuan%` naming the real socket under `/run/user/$UID/gnupg/d.<hash>/` |
| Windows | no Unix sockets at all — libassuan emulates with a file holding a loopback TCP port + nonce |

So the authoritative answer is not the env var, it's **`gpgconf`**:

```sh
gpgconf --list-dirs agent-socket      # the agent socket, however this platform does it
gpgconf --list-dirs agent-ssh-socket  # gpg-agent's ssh-agent socket, if enabled
gpgconf --list-dirs homedir           # the effective GNUPGHOME
```

Two gotchas worth knowing:

- The path is **declared always but created only while the agent runs**. On a
  machine where gpg-agent isn't up, `gpgconf` names the socket and nothing is
  there. Don't treat absence as misconfiguration.
- On Linux, replacing that path with a symlink **destroys the redirect file**.
  gpg will still find our socket (it connects to the path), but the original
  redirect is gone until gpg-agent recreates it.

`GPG_AGENT_INFO` — the old `socket:pid:version` env var from GnuPG 1.x/2.0 — was
**removed in 2.1**. Don't reintroduce it.

> Fixed in [README.md](../README.md) and [cli-reference.md](cli-reference.md):
> the symlink instruction used to hardcode `${GNUPGHOME:-$HOME/.gnupg}/S.gpg-agent`
> and now uses `$(gpgconf --list-dirs agent-socket)`.

### How this compares to everyone else

Three patterns exist for "where does the helper socket live":

| Pattern | Examples | Weakness |
|---|---|---|
| **Env var names the socket** | `SSH_AUTH_SOCK`, `DBUS_SESSION_BUS_ADDRESS`, `DOCKER_HOST` | not inherited by already-running processes — the exact problem trove has with SSH |
| **Fixed well-known path** | gpg's `S.gpg-agent`, `/var/run/docker.sock`, Windows' `\\.\pipe\openssh-ssh-agent` | only one owner; taking it displaces the incumbent |
| **Service manager injects it** | launchd (macOS), systemd socket activation, `$XDG_RUNTIME_DIR` (freedesktop — Apple does not set it) | platform-specific |

GnuPG is the middle pattern *plus* a query tool, which makes it the most robust
of the three — and is why trove should always ask `gpgconf` rather than guess.

### gpg is already global — the problem SSH has does not exist here

`gpg` finds its agent at a **fixed path** (`$GNUPGHOME/S.gpg-agent`), not through
an env var. Every process running gpg as you looks there. The `ln -sf` in the
README already achieves what forwarding achieves for SSH. **A launchd service
would not add reach.**

Nor could we forward the SSH way: Assuan has no "hold this key for the session"
command. The only route into gpg-agent is `gpg --import`, which writes the secret
key to `~/.gnupg/private-keys-v1.d/` permanently — the opposite of unlock/lock.

### The cost of owning the socket

trove answers thirteen Assuan verbs: `BYE`, `RESET`, `OPTION`, `NOP`, `GETINFO`,
`KEYINFO`, `HAVEKEY`, `SETKEYDESC`, `SETHASH`, `PKSIGN`, `PKDECRYPT`, `READKEY`,
`SCD` (stub). While the symlink is in place, **everything else breaks** — key
generation, `--edit-key`, smartcard work, passphrase caching for keys trove
doesn't hold.

Today that's survivable because the symlink is a manual act you can undo. Any
launchd service would make the displacement permanent, automatic, and invisible.
**So do not ship a launchd gpg service before fixing the displacement.**

### Two ways to fix it — only one survives contact

**A. Route in front of it — investigated, and it does not work.** The idea was:
trove binds the socket, answers for keygrips it holds, forwards the rest to the
real gpg-agent. Three findings sink it:

- Only one process can own the path, and the real gpg-agent **auto-binds that
  exact path** — any `gpg` invocation runs `gpgconf --launch gpg-agent`, which
  starts it on the socket `gpgconf` reports. It doesn't stand aside; it races us
  for the path we took.
- The only way to move it is `--extra-socket`, which `gpg-agent --help`
  describes as "accept **some** commands via NAME" — a restricted socket
  intended for remote forwarding. So the functionality we wanted to preserve
  (`--gen-key`, `--edit-key`) is exactly what would *not* reach the real agent
  through the proxy. The proxy defeats its own purpose.
- Assuan is **stateful** — `PKSIGN` reads a keygrip and hash set by earlier
  commands on the same connection — so even the relay is a session-aware proxy,
  not a socket splice.

Conclusion: "own the socket" and "proxy in front of the socket" are the same
bet. Both require evicting an incumbent that automatically reclaims its place.

The general model this is an instance of is in [agent-routing.md](agent-routing.md).

**B. Layer underneath it — be an scdaemon.** The only remaining route, and the
one that works *with* the architecture instead of against it. gpg-agent keeps
the standard path and its full command set; it calls us when it needs a key it
doesn't hold — a designed-in extension point rather than a squat.

**What scdaemon is:** GnuPG's smartcard daemon — the component that talks to
Yubikeys, Nitrokeys and OpenPGP cards. It ships with GnuPG (on this machine:
`$(gpgconf --list-dirs libexecdir)/scdaemon`, listed by
`gpgconf --list-components` as "Smartcards"). The chain is
`gpg → gpg-agent → scdaemon → card`, and the point is that **the private key
never leaves the card** — the card signs and returns only a signature. That is
already trove's model, so trove can present itself as a *software* card.

`--scdaemon-program filename` in `gpg-agent.conf` replaces the card daemon
(verified in `man gpg-agent`), and `shadowed-private-key` entries in
`private-keys-v1.d` contain **public parameters only, no secrets** — which is
what makes this acceptable where `gpg --import` is not. So nothing else breaks
and we don't have to reimplement gpg-agent's surface.

**Gotcha for the spike:** gpg-agent calls scdaemon **only once**, so changing
`scdaemon-program` at runtime has no effect until it's killed —
`gpgconf --kill scdaemon` (or `--kill gpg-agent`). Set it in `gpg-agent.conf`
before the agent starts. `disable-scdaemon` is the off switch.

**Good news on scope.** scdaemon speaks two different things on its two sides:
Assuan IPC upward to gpg-agent, and APDUs over CCID/PC-SC downward to hardware.
trove would implement **only the upward side** — an IPC server in the same
protocol family we already handle. No APDUs, no USB, no card emulation.

**Catches:**

- **Only one scdaemon runs at a time, and it handles real hardware.** Verified on
  this machine, scdaemon supports `openpgp` (Yubikey's OpenPGP applet, Nitrokey,
  physical OpenPGP cards), `nks`, `dinsig`, `p15`, `geldkarte`, `sc-hsm` — plus
  **PIV** (corporate/government badge cards; the binary contains `app-piv.c` even
  though `man scdaemon`'s application list omits it). So `trove-scd` doesn't
  abstractly "displace smartcards" — **a user with a Yubikey or a work PIV badge
  loses it.** Proxying unknown cards through to the real scdaemon is therefore
  *required*, not optional, and "working" for the spike means `git commit -S`
  reaches trove **and** hardware still works.
- The card protocol is a different dialect, and a vault of N keys has to be
  modelled as **one** virtual card (presenting two serials desynchronised
  gpg-agent — see the spike).

**Spiked and verified — verdict GO** for a single-card, sign-only first cut. See
[spike-scdaemon.md](spike-scdaemon.md) for the captured Assuan conversation and
the gotchas. Headlines:

- gpg-agent does launch a substituted `scdaemon-program`, and a ~300-line
  software card served `gpg --detach-sign` end to end with `gpg --verify`
  returning `Good signature`.
- **Nothing was displaced** — keygen, `--edit-key`, and signing with ordinary
  on-disk keys all kept working with the fake card installed. That is the
  decisive advantage over owning or fronting the socket.
- gpg-agent **writes the `shadowed-private-key` itself** from `LEARN` +
  `READKEY`; no hand-crafting needed.
- Minimum command set for `gpg --sign`: `SERIALNO`, `KEYINFO`, `SETDATA`,
  `PKSIGN` (plus `LEARN`/`READKEY` to create the shadow key).
- `SETDATA` carries the full PKCS#1 `DigestInfo` — the card only pads and does
  the private-key operation, and gpg-agent verifies the result against the
  shadow pubkey.

Still **unverified**, and load-bearing:

- **No physical smartcard was available.** Proxying was proven software-to-
  software only, so "your Yubikey keeps working" remains a claim, not a result.
- **ed25519 on the card path is untested** (RSA-2048 only) — which matters,
  since ed25519 is trove's default GPG key type.
- `PKDECRYPT` on the card path, Linux/Windows behaviour, and gpg 2.2 (this was
  2.5.21, a dev build) are all untested.

Not to be confused with trove's existing `yubikey` feature, which is HMAC-SHA1
challenge-response for **unlocking the kdbx** — same device, unrelated mechanism.

### The blocker underneath either route

trove parses only **ed25519 (algo 22)** and **cv25519 (algo 18)**. RSA PGP keys
are silently skipped at load. Since `gpg --gen-key` defaulted to RSA for about
two decades, most people's existing key cannot be served at all — so git signing,
`pass`, `sops`, `git-crypt`, Maven, and Debian/RPM signing are all out of reach
regardless of which integration route we pick.

RSA support is the highest-leverage gpg work, and it needs no new crypto: the
`rsa` crate is already a dependency and `rsa_sign_wire_blob` already exists for
SSH. It's OpenPGP packet parsing plus wiring.

Second, smaller blocker: **the public key must be in the user's keyring** or gpg
never derives the keygrip and so never asks any agent for it. Our e2e test hides
this by generating the key with gpg itself.

Don't hardcode where that keyring lives — GnuPG has changed it twice:

| Era | Public keyring |
|---|---|
| GnuPG 1.x / 2.0 | `pubring.gpg` (raw packet stream) |
| GnuPG 2.1+ | `pubring.kbx` ("Keybox" format) |
| GnuPG 2.4+ with `use-keyboxd` | `public-keys.d/pubring.db` (SQLite), served by the **keyboxd** daemon over `S.keyboxd` |

This machine is the third case — `~/.gnupg/common.conf` contains `use-keyboxd`
and there is no `.kbx` file at all. As with the agent socket, ask rather than
guess: `gpgconf --list-dirs`, and `gpg --with-keygrip --list-keys` for what gpg
actually believes it has.

(`.kbx` is GnuPG's Keybox format and is unrelated to KeePass's `.kdbx` — the
similar letters are coincidence.)

---

## Materialized files

No platform counterpart — this is trove's own feature everywhere. But macOS is
weaker than Linux here, and the code is explicit about it.

Linux can verify a target is really memory-backed (tmpfs). macOS cannot, so
`is_ephemeral_macos_path` is a **soft allowlist** — `/private/tmp`, `/tmp`, and
`$XDG_RUNTIME_DIR`. Quoting the source:

> Returning `true` does NOT mean memory-backed. `/private/tmp` is APFS,
> snapshotted by Time Machine (configurably), and persists across boots in some
> cases.

So on macOS, "ephemeral" means "the OS calls it ephemeral and the user did the
best they could", not "this never touched a disk". Worth saying plainly in
user-facing warnings.

---

## Socket paths: the GUI/terminal divergence

Resolution order is `TROVE_SOCK` → `XDG_RUNTIME_DIR` → `${TMPDIR:-/tmp}`
(`crates/troved/src/daemons.rs`).

Two traps:

1. **A Finder-launched app and your terminal can disagree.** If your `.zshrc`
   sets `XDG_RUNTIME_DIR`, the terminal uses it and the GUI app (which never
   reads your shell profile) falls back to `TMPDIR`. They then talk to different
   sockets and neither sees the other's daemon. This matters directly for
   trove-desktop hosting the daemon — it needs a launch-context-independent path.
2. **The `UID` fallback is not what it looks like.** The `$TMPDIR` fallback uses
   `std::env::var("UID")`, but `UID` is a *shell* parameter and is not normally
   exported, so it resolves to `0` and the path becomes `trove-0.sock`. On macOS
   this stays user-isolated only because `TMPDIR` is already a per-user private
   directory. `cli-reference.md` documents the practical effect; set `TROVE_SOCK`
   explicitly on shared machines.

## Autospawn from a GUI

`troved_binary_path()` (`crates/trove-cli/src/daemon.rs`) looks for
`TROVE_DAEMON_BIN`, then a sibling of the current executable, then bare `troved`
on `$PATH`. Inside a Finder-launched `.app` none of those work: launchd's `PATH`
has no `/opt/homebrew/bin` or `~/.cargo/bin`.

This is moot if trove-desktop **hosts** the daemon in-process rather than
spawning one — which is the current plan — but it's a live trap for any code path
that shells out to `troved` from a bundled app.

---

## Suggested order

1. Wire the SSH forwarding that already exists into unlock/lock, driven by the
   `KeeAgent.settings` fields we already write (`AddAtDatabaseOpen`,
   `RemoveAtDatabaseClose`, lifetime, confirm).
2. ~~Verify the Keychain claim and `CONSTRAIN_CONFIRM` behaviour empirically.~~
   Done 2026-08-01 — Keychain is not reachable from the agent socket; confirm is
   honoured but fails closed for want of an askpass. If trove offers the confirm
   constraint on macOS it needs an askpass check and a clear message.
3. RSA support for OpenPGP keys — unblocks every gpg use case at once.
4. Public-key export into the user's keyring on unlock.
5. Spike the scdaemon route. There is **no fallback** — fronting the socket was
   investigated and doesn't work, so if scdaemon doesn't hold up, owning
   `S.gpg-agent` outright (today's behaviour, with its displacement cost) is all
   that's left.
6. Only then consider launchd socket activation — and only once GPG displacement
   is solved, since a service makes the displacement permanent and invisible.
