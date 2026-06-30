# Provisioning sessions — extracting secrets under a session code

How a consumer tool (e.g. a device provisioner like `inpace-config`) uses trove
to pull secrets repeatedly during a work session **without** turning "the vault
is unlocked" into "any process on the box can extract every secret."

Companion to [threat-model.md](threat-model.md) — this is the concrete answer to
adversary #4 (*the malicious package or process running as the user*), which the
threat model currently lists as out of scope. The **session code** described here
is the mechanism that moves that adversary from "out of scope" to "mitigated for
the duration of an unlock," for the *extraction* surface specifically.

> **Status:** **implemented.** `unlock` mints the session code, `get` routes
> extraction through the unlocked daemon gated on the code + `SO_PEERCRED`, and
> the code is invalidated on `lock`/idle-lock. See [Status](#status) at the
> bottom for the precise surface.

---

## The two kinds of secret access

A consumer needs trove secrets for two fundamentally different reasons, and they
have different security properties:

| Access | Example | Do the private bytes leave the vault? |
|---|---|---|
| **Authenticate** | SSH to a device using a build/bench key | **No** — signing happens in `troved`; the agent only proves possession |
| **Extract** | install a customer SSH key onto a device; sign a device cert from a CA | **Yes** — the tool needs the actual private bytes |

**Auth** rides the **ssh-agent** (`trove ssh-agent socket`): the key never leaves the
daemon, so unlock-once is already safe — any code with the agent socket can *use*
the key but never *read* it.

**Extraction** is the dangerous surface: `materialize` / `get` hand real private
bytes to the caller. That's what the **session code** gates.

## The session-code model

1. **`unlock` mints a one-time session code** — one per unlock, rotated every
   unlock, invalidated on `lock` / idle-lock. The operator enters the master
   password interactively; the code is the *capability* to extract during this
   unlock.
2. **`get` / `materialize` require `unlock` + the code.** Refused when the vault
   is locked; refused when the code is absent or wrong.
3. **The code is handed off invisibly**, never shown or typed. On an interactive
   terminal `unlock` launches the operator's own `$SHELL` with `TROVE_SESSION`
   already set, so they land in a session subshell where `get`/`add` just work —
   no `eval`, and the code touches only that subshell's environment, never disk
   (`exit` ends the session). When stdout is piped (`eval "$(trove unlock …)"` or
   a script) it instead prints `export TROVE_SESSION=…` on **stdout** with a
   human-readable notice on **stderr**. Either way the code lands in a shell env
   — not on screen, not in `ps`, not on disk.

### Three barriers, three adversaries

| Barrier | Stops |
|---|---|
| **stdout/stderr split + fd-handoff** (code via captured stdout, notice via stderr) | scraping the code from a log / pipeline / `ps` |
| **`SO_PEERCRED`** on the daemon socket (serve only the unlocking uid) | a *different user* on the box |
| **session code** required for extraction | a *same-user ambient process* — the malicious-package adversary |

None is a hard wall on its own (the master password remains the root capability —
a password holder can `unlock` and read the code). Together they make extraction
during an unlocked session require an attacker to *actively* steal the code from
your environment, not just passively benefit from the unlock — which is precisely
the gap a bare ssh-agent leaves open.

## Operator workflow

```console
# ── start a provisioning session (interactive: drops you into a session shell) ──
$ trove unlock ~/vault/semdatex.kdbx
Enter vault password: ********
trove: unlocked · session active in this shell — run add/get here, `exit` to end
#  → you are now in your own $SHELL with TROVE_SESSION set. Not on screen, not in
#    `ps`, never on disk. `exit` leaves the session.
#
#  Non-interactive / scripted use instead captures the export:
#     eval "$(trove unlock ~/vault/semdatex.kdbx)"

# ── the consumer tool runs normally; it uses the agent + the code for you ──
$ inpace config hub network 192.168.0.182 inPACE1 ~/clinics/00001.henrik-clinic.json
  ✓ ssh (build key)              # troved's agent served it; SO_PEERCRED → only your uid
  ✓ customer key installed       # tool used $TROVE_SESSION to materialize, install, then wipe
  ✓ clinic-ca.crt + device leaf  # leaf minted from the materialized CA, installed, CA wiped
#  the private bytes touched disk only for the seconds the tool used them

# ── a rogue process tries to cash in on the unlocked vault ──────────
$ trove get ssh ~/vault/semdatex.kdbx "henrik/customer"     # no code
trove: refused — session code required
$ sudo -u mallory trove get ssh …                           # different user
trove: refused — not the unlocking uid

# ── done ────────────────────────────────────────────────────────────
$ trove lock
trove: locked · agent keys dropped · materialized files wiped · code invalidated
```

The operator's whole interaction is: `eval "$(trove unlock …)"` once → run the
tool as many times as needed → `trove lock` (or let idle-lock fire). The code is
never seen, typed, or copied.

## For consumer-tool authors

A tool integrates along the two access lines:

- **Auth:** point ssh at the daemon's agent — `SSH_AUTH_SOCK="$(trove ssh-agent socket)"`.
  Don't pin `-i <keyfile> -o IdentitiesOnly=yes` for keys you expect from the
  agent (that bypasses it); let ssh consult the agent + `~/.ssh/config`.
- **Extraction:** read `TROVE_SESSION` from the env and pass it to
  `trove get`/`materialize`; write to a path, **use it, then remove it** (or let
  the materialization TTL wipe it). Keep the plaintext window to the few seconds
  you're actually reading the bytes.
- **Never** put the code (or the password) in `argv` — env or stdin only.

## Status

What ships today (cross-check [status.md](status.md)):

**Works today**
- `unlock` → daemon holds the vault; **ssh-agent** + **gpg-agent** serve keys.
- `unlock` **mints a one-time session code**, rotated every unlock, and prints
  `export TROVE_SESSION=…` on **stdout** (human notice on **stderr**).
- **`get ssh` / `get gpg` / `get file`** route extraction through the *unlocked
  daemon*, gated on the session code **and** `SO_PEERCRED` (served only to the
  unlocking uid). Refused when the vault is locked or the code is absent/wrong.
- **materialize** (plan-driven, on unlock; TTL; wiped on `lock`/SIGINT).
- **idle-lock**, **`lock`** (wipes materialized files, drops agent keys, and
  invalidates the session code).

**Behaviour change:** `get` no longer opens the vault one-shot with a fresh
password — it requires a running daemon with the vault unlocked. The `<vault>`
positional is retained for CLI compatibility but is vestigial; extraction always
serves the daemon's currently-unlocked vault. `get file` without `--name`
defaults to the `blob` attachment (it can't read `Materialize.Source` without a
vault open, which would defeat the gate).

**Not yet implemented**
- Binding the code to the unlocking *process* (today it's uid-bound, not
  pid-bound — any same-uid process holding the code can extract).
- A daemon-routed `materialize <entry>` on-demand verb (materialize is still
  plan-driven on unlock; `get` is the on-demand extraction path).
