# Work report — agent integration, 2026-08-01/02

What changed, what it fixes, and what it cost. Companion to
[session-summary-2026-08-01.md](session-summary-2026-08-01.md), which records
the *design conversation*; this one records the *engineering*.

Open work is in [todo.md](todo.md).

---

## Headline

| | Before | After |
|---|---|---|
| Tests passing | 294 | **344** |
| Known failures | 1 (misdiagnosed for months) | **0** |
| clippy / fmt | clean | clean |
| Acceptance script | didn't exist | 24/24 |

Started as one question — *"why can't my Claude Code sessions use my github SSH
key?"* — and ended up touching the daemon's core state model, both agent
protocols, and the OpenPGP key parser.

---

## Features

### 1. Multi-vault daemon

The daemon held exactly one vault (`Option<Vault>`). It now holds a set.

- `unlock` is **additive** — a personal vault and a work vault serve at once.
- The SSH/GPG agents serve the **union**; agents key by public blob / keygrip,
  so different keys simply coexist.
- `lock --vault <path>` drops one vault; a bare `lock` still drops everything.
- `list` / `search` / `status` span the whole set.
- Title collisions across vaults are **refused with both vault names**, never
  guessed — returning the wrong vault's secret would be worse than an error.

New type `troved::vaults::VaultSet` with canonical-path keying, so `./v.kdbx`
and `/abs/v.kdbx` are one vault rather than two.

**Two things this surfaced that weren't in the design doc:**

- **The idle timer wasn't re-armed after a partial lock.** Harmless when locking
  always meant locking everything; with `lock --vault` it would have left the
  remaining vaults unlocked indefinitely.
- **Materialized files collide the opposite way from keys.** Keys are
  last-wins and harmless (same keypair, same signature). Files are **first-wins**:
  overwriting replaces data a live process is using, and locking either vault
  would then wipe a path the other still expects. `MaterializedFile` now carries
  its source vault.

### 2. RSA for OpenPGP — signing and decryption

Trove parsed only ed25519 and cv25519, silently skipping RSA keys at load. Since
`gpg --gen-key` defaulted to RSA until GnuPG 2.3, **most people's existing PGP
key could not be used at all**.

Now supported: OpenPGP algorithms 1/2/3 — packet parsing, keygrip, PKCS#1 v1.5
signing, decryption, and the `READKEY` public-key S-expression.

This unblocks git commit signing, release/distro/Maven artifact signing, and —
via decryption — `pass`, `sops`, `git-crypt` and encrypted mail.

### 3. SSH agent — the management half of the protocol

Trove answered only `REQUEST_IDENTITIES` and `SIGN_REQUEST`; everything else got
`SSH_AGENT_FAILURE`. So `ssh-add -d`, `-D`, `-x`, `-X` all failed against it.

Added server-side: `REMOVE_IDENTITY`, `REMOVE_ALL_IDENTITIES`, `LOCK`, `UNLOCK`.
Locked semantics match OpenSSH — identity listings come back *empty* rather than
failing (clients read a failure as "no agent"), signing fails, only `UNLOCK` is
honoured, and keys are hidden rather than discarded.

The lock passphrase is stored as a SHA-256 and compared in constant time; the
user supplies it via `ssh-add -x`, so trove never invents one.

This also matters for the Windows plan: binding the well-known agent pipe means
every client on the machine reaches for us, and half of what they'd send was
unanswered.

### 4. SSH key forwarding into the platform agent

The KeePassXC model — push keys into whatever agent `$SSH_AUTH_SOCK` names, so
processes that never inherited trove's socket path can still use them.

Driven entirely by **per-entry `KeeAgent.settings`** already in the vault, which
round-trip through KeePassXC's own UI — no new trove config:

| Setting | Behaviour |
|---|---|
| `AddAtDatabaseOpen` | forward this key on unlock |
| `RemoveAtDatabaseClose` | `REMOVE_IDENTITY` on lock; `false` applies **only** to the forwarded copy — trove's own agent always drops everything |
| `UseLifetimeConstraintWhenSigning` + duration | the other agent expires the key itself, surviving troved being killed |
| `UseConfirmConstraintWhenSigning` | prompt on every use |

Off entirely with `TROVE_SSH_FORWARD=0`, and inert when there's no external agent.

---

## Bugs found and fixed

### The one that had been wrong for months

`gpg_git_signing_e2e` failed with `skipped "<FPR>": No secret key`. The repo
blamed GnuPG development builds; I repeated that diagnosis in three documents and
used it to justify skipping an assertion.

**It was never a gpg bug.** The developer's global `~/.gitconfig` set
`gpg.program` to a wrapper that re-exports its own `GNUPGHOME`, discarding the
one the test sets. gpg looked in the wrong keyring and correctly reported a
missing key. Proven by `GIT_CONFIG_GLOBAL=/dev/null cargo test` passing on
unmodified source, and by captured Assuan traces showing trove's agent and a real
gpg-agent are **identical** in the sign path.

Both tests now isolate git from user/system config. The suite has no known
failures for the first time.

### Wire-format bugs, all the same root cause

libgcrypt's **signed-MPI convention** — a leading `0x00` when the top bit is set
— bit three times in three different places:

- **The RSA keygrip** is `SHA-1(0x00 ‖ n)`: the bare modulus, *no* S-expression
  framing, and `e` not involved. The spec-shaped guess (`(1:n<N>)(1:e<E>)`, by
  analogy with the ECC keygrips in the same file) was wrong in three ways at once.
- **`READKEY` emitted a 256-byte modulus**; a real gpg-agent sends **257**.
- **Ciphertext arrives at 257 bytes** for a 256-byte modulus. Code that only
  handled the *short* (unsigned) case broke immediately on a signed one.

Also: **RSA's `ADD_IDENTITY` payload puts the modulus before the exponent**, the
reverse of the SSH public-key blob.

Every one of these compiles, looks right, and fails silently on the wire.

### Others

- **`KEYINFO` reported protection `P`** (passphrase-needed) for keys held
  unprotected, and ignored `--data`. Now byte-identical to a real gpg-agent.
- **`parse_gpg_export` required an ed25519 key**, so an RSA-only export was
  rejected outright. Now accepts any signing-capable key.

---

## Security decisions

### `hazmat` removed

RSA decryption initially used `rsa::hazmat` for an unpadded private-key
operation, because gpg-agent must return the *whole padded* PKCS#1 block —
`g10/pubkey-enc.c` unpads it itself and insists on seeing the `0x02` block-type
byte.

That was rejected, correctly. The replacement decrypts through the crate's
**checked** PKCS#1 v1.5 path and re-wraps the recovered session key with fresh
random padding of the original length. gpg parses it to the same session key
(it scans past `PS` to the `0x00` separator; padding bytes are random by
definition), so compatibility is unaffected.

**This is strictly safer, not merely equivalent.** The raw version returned the
decryption of *any* input — a full decryption oracle. The checked version
rejects malformed ciphertext instead of answering it.

### Confirm constraint refuses rather than silently downgrading

`SSH_AGENT_CONSTRAIN_CONFIRM` makes an agent prompt before every use. Apple's
agent honours it — but **macOS ships no askpass binary at all**, so the
constraint produces a key that is *refused on every use* rather than confirmed.

If an entry asks for per-use approval and we can't deliver it, trove **does not
forward that key**. Downgrading to an unconstrained copy would hand the key out
*and* drop the control the user asked for; refusing leaves it served by trove's
own agent, costing only the forwarding convenience.

### Test keys were leaking into the developer's live agent

Once forwarding was wired in, `cargo test` inherited the developer's real
`SSH_AUTH_SOCK` — a canary caught **five** throwaway test keys landing in their
live agent. Fixed with a forced `TROVE_SSH_FORWARD=0` in `.cargo/config.toml`;
the tests that exercise forwarding clear it and point at a private agent of their
own.

---

## How things were verified

The consistent lesson: **spec-derived crypto and wire code compiles, looks
right, and is wrong.** Everything was proved against the real tool.

- RSA keygrip → pinned against gpg's own reported value, twice (committed
  fixture + freshly generated key). Independently re-derived by a second agent
  testing 8 candidate formulas — same answer.
- `ADD_IDENTITY` payloads → a real `ssh-agent` accepting ed25519/RSA/ECDSA.
- Agent management messages → real `ssh-add -d/-D/-x/-X`, including
  wrong-passphrase rejection.
- RSA decryption → real `gpg --encrypt` → trove → plaintext round-trip.
- Forwarding → 11 e2e tests asserting through `ssh-add` only.
- The whole user journey → `scripts/acceptance.sh`, 24 checks through the
  shipped binaries.

Notably, the acceptance script found **nothing** in the code: all 14 of its
initial failures were bugs in the script itself, including one assertion that
passed spuriously because an error message is also non-empty.

---

## Investigations that answered a question rather than shipping code

- **scdaemon spike → GO.** A software card served `gpg --detach-sign` end to
  end, and critically **nothing was displaced** — keygen, `--edit-key` and
  on-disk-key signing all kept working. Full findings in
  [spike-scdaemon.md](spike-scdaemon.md).
- **Keychain — confirmed clean**, for a stronger reason than assumed: Keychain
  code lives in `ssh-add`, not the agent, which doesn't even link
  Security.framework. A wire-added key *cannot* persist.
- **`CONSTRAIN_CONFIRM` on Apple's agent** — honoured, but fails closed (above).
- **Fronting `S.gpg-agent` — rejected with evidence.** gpg-agent auto-reclaims
  its socket, and `--extra-socket` accepts only *some* commands, so a proxy would
  block exactly what it existed to preserve.

---

## Documentation

New: [todo.md](todo.md), [macos.md](macos.md), [windows.md](windows.md),
[agent-routing.md](agent-routing.md), [spike-scdaemon.md](spike-scdaemon.md),
[session-summary-2026-08-01.md](session-summary-2026-08-01.md), this report.

Updated: `multi-vault.md` (phase 1 now implemented), `threat-model.md`,
`cli-reference.md`, `architecture.md`, `README.md`.

Everything unverified is marked as such rather than asserted.

---

## Corrections made to earlier claims

Recorded because each was stated confidently before being checked:

1. **The gpg failure was not a GnuPG 2.5.x bug** — see above.
2. **"`REMOVE_IDENTITY` ✅ built"** conflated the client and server sides; the
   server side didn't exist.
3. **"gpg derives keygrips from `pubring.kbx`"** — outdated. `.kbx` is a real
   GnuPG format (not a typo for KeePass's `.kdbx`), but modern GnuPG with
   `use-keyboxd` uses SQLite at `public-keys.d/pubring.db`.
4. **"The lock guarantee is weaker than KeePassXC's"** — overstated. Forwarding
   doesn't widen the ambient-process surface at all: same uid, same capability,
   different socket path.
5. **`hazmat` was defensible** — it worked, but the checked path is better and
   there was no good reason to accept the weaker option.

---

## Not done

- `troved::serve()` extraction → desktop hosts the daemon
- gpg public-key export into the user's keyring on unlock
- `trove agent purge` / `trove agent lock`
- Windows: bind the well-known agent pipe; port forwarding to named pipes
- scdaemon: ed25519 on the card path, and passthrough against **real hardware**
  (only software-to-software was proven — until a Yubikey is tested, "hardware
  users keep their token" is unverified)
- The OpenPGP packet parser is **not fuzzed**, unlike the SSH wire decoder and
  Assuan line parser. An inconsistency, not a deliberate exception.
- ~56 files still uncommitted — which is why two parallel agents branched from
  `main`, couldn't see this work, and rebuilt parts of it from scratch.
