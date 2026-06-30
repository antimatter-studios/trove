# Multi-vault unlock — design notes (future work)

Status: **design only, not implemented.** This captures the model worked out so
it isn't lost. Today trove holds at most one unlocked vault in the daemon; the
commands still take a `<VAULT>` positional. The notes below describe where we
want to go and why.

## Goal

Unlock several vaults at once (e.g. a personal vault and a company vault) and
have their keys serve from one place, while keeping the common single-vault case
ergonomic. Multiple unlocked vaults is the uncommon case — so the design favours
the single-vault path and only asks the user to disambiguate when there's
genuine ambiguity.

## The core realization: collisions only matter for title-addressed ops

SSH and GPG agents identify a key by its **public-key blob / keygrip**, never by
title or which vault it came from. So unlocking N vaults just loads the **union**
of their keys into one keyring:

- Different keys → the keyring grows; `ssh`/`git` pick whichever key a host
  accepts. No conflict.
- The *same* keypair in two vaults → a genuine collision, resolved **last-unlock
  wins**: the keyring is keyed by public blob, so the later vault's entry
  overwrites the earlier. The only observable difference is the **comment/label**
  shown in `ssh-add -l` — the signature is identical (it's the same key). The
  user manages this; it costs nothing.

So "dump every unlocked vault's keys into the agents" needs **no collision
handling at all** at the agent layer. Collisions only bite the commands that
address an entry **by title**: `get`, `add`, `remove`.

### Motivating example

Unlock a personal vault and a company vault. Different SSH keys coexist in the
agent — `ssh-add -L` lists both; nothing shadows. The only place "personal vs
company" needs attention is two keys **for the same host** (two `github.com`
accounts), and that's a pure-SSH concern solved with `~/.ssh/config` host
aliases (`IdentitiesOnly yes` + a `github-work` alias), not something trove does.

## `--vault` is the disambiguator, never a required positional

The `<VAULT>` positional goes away. A command operates on the unlocked set, and
`--vault <path>` selects/disambiguates only when needed:

| Command | No `--vault`, 0 unlocked | No `--vault`, 1 unlocked | No `--vault`, N unlocked | `--vault <path>` |
|---|---|---|---|---|
| `get <title>` | error: nothing unlocked | search the one vault | search all; **error on a title collision** | restrict to that vault |
| `add` / `remove` | error: nothing unlocked | target the one vault | **refuse — require `--vault`** | target that vault (must be unlocked) |
| `list` | error: nothing unlocked | list the one vault | list the union, annotated by vault | list that vault |
| `lock` | no-op | lock it | lock **all** | `lock --vault <path>` locks one |

`unlock <path>` and `init <path>` keep their positional — you're naming a file.
`unlock` becomes **additive**: each call loads that vault's keys into the keyring
rather than replacing the previous vault.

Rule of thumb: *agent/title ops need no vault; write/ambiguous ops take an
optional `--vault`.*

## The daemon owns the write

When `add`/`remove` mutate a vault, **the daemon performs the write**, not the
CLI. Rationale: re-saving a `.kdbx` re-encrypts it, which needs the master key.
The daemon already holds the decrypted vault **and** its key from `unlock`, so it
can mutate-in-memory and `save()` straight back to the file it already knows —
no prompt. If the CLI wrote the file itself it would have to re-derive the key
(re-ask for the master password on every `add`), and shipping the password back
over the socket would be a security regression.

Flow for `trove add ssh personal/github.com <keyfile>`:

1. CLI sends an `AddSsh` RPC (key bytes + entry path + optional `--vault`).
2. Daemon resolves the target from its open set (1 open → use it; N open + no
   `--vault` → refuse; `--vault` → that one, must be open).
3. Daemon adds the entry, loads the new key into the SSH agent, and `save()`s the
   vault back to that file's path.
4. Gated like `get`: `SO_PEERCRED` (Unix) + the session code.

The daemon is the source of truth for *which vaults are open and where they
live* (`Status` already reports the vault path; multi-vault reports the list).

## Entry names are paths, to segregate accounts

Entry names use a directory-like structure (`personal/github.com`,
`work/clientA/github.com`, `work/clientB/github.com`) so a user with multiple
identities for the same host can keep them in separate groups. trove already
supports nested groups, so this is just the entry path (group hierarchy +
title), addressed without the vault prefix.

## `add ssh` — private key as a **file**, validated

`trove add ssh <entry-path> <key-file>`:

- The key is a single **positional filename** — no `--key` flag, no inline-string
  form (a key string in `argv` leaks via `ps`/shell history, which contradicts
  trove's own threat model; a filename doesn't).
- **Validate on add.** Today `add ssh` stores the bytes unchecked, so a `.pub`
  file or an encrypted key is only discovered at `unlock` (where the daemon
  silently skips it). Parse with the agent's loader
  (`keys::parse_private_key`) before storing and give a precise error:
  - public key (`.pub`) → "that's a public key; pass the private key"
  - passphrase-encrypted → "decrypt it first (`ssh-keygen -p`)"
  - unsupported/weak → "DSA/P-521 unsupported" / "RSA < 2048 rejected"
  - unparseable → "couldn't parse as an SSH private key"
- Only the **private** key is stored. The public key is fully derivable from it
  (ed25519/ECDSA: `public = private·basepoint`; RSA: public params are a subset;
  and the OpenSSH private-key format embeds the public key anyway). The comment
  (`user@host` label) is the one thing not recoverable from the key — trove keeps
  that as the `--user` field / entry title.

## `get ssh` — emit the public part, the private part, or both

`get` returns the private bytes from the daemon (code-gated, as today); the CLI
derives the public locally (it links `troved`, so it reuses
`keys::parse_private_key(...).public_key()`). Works for ed25519/RSA/ECDSA.

```
trove get ssh personal/github.com                 # private key → stdout
trove get ssh personal/github.com --public        # authorized_keys line → stdout
trove get ssh personal/github.com --out ~/.ssh/id_ed25519
#   → ~/.ssh/id_ed25519      (private, 0600)
#   → ~/.ssh/id_ed25519.pub  (public,  0644)
```

So "upload to authorized_keys" → `--public`; "reconstruct an id_ed25519 file" →
`--out`. A public key isn't secret, so `--public` *could* later be served
ungated straight from the daemon (it already knows every loaded key's public
blob for the agent); the simple first version rides the gated private extraction
+ local derivation.

## The one open decision: session code with multiple vaults

Extraction (`get`) is gated by the one-time session code minted at `unlock`
(exported as `TROVE_SESSION`). With several vaults, the choice is:

- **One daemon-session code covering all unlocked vaults** (recommended):
  simplest — `get` checks the code, then searches/targets by title/`--vault`. One
  env var, one capability for "this shell may extract during this session".
- A code **per vault**: one `TROVE_SESSION` can't hold several, so this gets
  awkward fast.

Recommendation: one daemon-session code + `SO_PEERCRED`; `--vault` disambiguates
*which secret*, not *which credential*.

## Suggested phasing

1. Additive unlock → union into the SSH/GPG agents; `list`/`status` across all;
   `lock [--vault]`. (Biggest UX win, no write path, lowest risk.)
2. Drop the vestigial `<VAULT>` from `get`; add `--vault` disambiguation + the
   collision error; add `get --public` / `--out`.
3. Daemon-side `add`/`remove` (mutate in memory + `save()` to the known path),
   code-gated, with `--vault` targeting per the refuse-on-ambiguity rule; switch
   `add ssh` to the positional-file + validate-on-add behaviour.
