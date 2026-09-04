# Remote agent access — using a vault key when you and the machine are in different countries

The ask: the laptop is in Berlin, you are not, and you want to tell an agent
"ssh into that box and restart the deployment" and have it use an SSH key that
lives in a trove vault — without the private bytes leaving the machine, and
without typing the master password into anything that isn't that machine's own
terminal.

Companion to [provisioning-sessions.md](provisioning-sessions.md) (the same
question for a *local* consumer tool) and [threat-model.md](threat-model.md).

**Status.** The "use" half is built and merged. The "unlock from afar" half is
not, and the design below is a proposal.

---

## What the answer turned out to be

An earlier draft of this document argued for containment: a scoped agent socket
per session, the agent running as a separate uid, per-signature approval. That
was rejected as the primary answer, and correctly — it isn't the product. Trove
is a KeePassXC-shaped password manager: you unlock once, and the machine's
applications can use your keys. Making the flagship key path require a second
uid and a confirmation prompt per signature would be a different, worse product.

So the shape is settled, and this document records it rather than relitigating:

- **Unlock forwards keys into the OS agent** (`ssh_agent/forward.rs`). Every
  application on the machine can then sign — your terminal, VS Code, anything
  launched from the Dock, and an agent process driving that machine remotely.
  Lock, idle-lock and shutdown take them back out.
- **Two gates decide *which* keys**, as in KeePassXC: forwarding is enabled
  (`TROVE_SSH_FORWARD` for the daemon, a setting for the desktop app), *and* the
  entry's `KeeAgent.settings` ask for agent loading.
- **Containment lives elsewhere** — in the signature, not in the socket. See
  "What actually bounds the exposure" below.

## Five problems wearing one coat

1. **Reach** — how does the request get to the machine holding the vault?
2. **Unlock** — a locked vault needs a factor, and the password can't travel.
3. **Use** — authenticate (signing) vs extract (private bytes leave).
4. **Approve** — who says yes, and can the requesting agent forge that yes?
5. **Audit** — what did the agent actually do with the key.

Only #2 is unbuilt and genuinely hard. #1 and #3 are done; #4 is answered by
declining to require it; #5 is small and unstarted.

## Reach: already solved for the case that motivated this

The motivating setup is an agent session executing *on* the Berlin machine,
driven from wherever you are. The request arrives through that agent's own
channel, so nothing needs to listen: no inbound port, no broker, no tunnel.

If you ever do need the key on a *different* machine, `ssh -R` the agent socket
to a host you control. That works today with no trove code, and its cost is
real: anyone who roots the jump host can sign as you while the tunnel is up.
An outbound rendezvous (troved dials a broker you own) is the alternative, and
it would give a daemon that currently has no network surface at all one — worth
building only if the tunnel recipe proves insufficient.

## Use: what works today

With forwarding on, unlocking anywhere — CLI, daemon, or the desktop app — puts
the vault's declared keys into the agent that `SSH_AUTH_SOCK` already names. A
remote-driven agent on that machine then uses them like any other program.

The private bytes do leave troved for the OS agent; that is the deliberate
trade, and [threat-model.md](threat-model.md) states it. What does *not* change:
the agent protocol has no read-key message, so a process that can use a
forwarded key still cannot export it.

**Extraction stays gated.** `get` and `materialize` hand out real private bytes
and require the session code plus `SO_PEERCRED` (see
[provisioning-sessions.md](provisioning-sessions.md)). A remote-originated
request must never obtain them: a forwarded signature is a bounded act, an
extraction is a permanent loss. If the daemon later grows a remote path, it must
mark those connections and refuse extraction on them.

## Gap: unlocking from afar without sending the password

The tempting shortcut is to type the master password into the remote session.
Don't. It is the root capability for the whole vault, forever, on every copy of
the file, and it would land in a transcript, in scrollback, and plausibly in a
log you don't own.

Nor does an environment variable help. `TROVE_PASSWORD` in a shell is readable
by any same-uid process (`/proc/<pid>/environ`, or a debugger on macOS),
inherited by every child — including everything an agent spawns — and survives
in shell history. It also solves nothing here: you have to be *at* the machine
to set it, and if you are, unlocking before you leave costs less.

**Split the unlock factor, keep half on the phone.** The composite key stays
what kdbx expects; the second factor is a sidecar:

- Share A sits on the machine, useless alone.
- Share B is released by a device you carry, behind biometry.
- Remote unlock: troved asks for B, the phone shows which vault and what
  triggered it, you approve, the daemon combines and zeroes B.

Two ways to land the phone in kdbx4's composite key without inventing a format:
as the **keyfile** (roadmap v0.0.11.0 already needs that plumbing), or as
**challenge-response** (roadmap #2 plumbs `with_challenge_response_key`; the app
becomes a soft hardware token). Challenge-response is better — a response to a
fresh challenge, so nothing replayable crosses the wire, where keyfile bytes are
bearer material that is equally valid tomorrow.

**The delivery mechanism doesn't need an app.** A passkey with the WebAuthn PRF
extension derives deterministic key material behind biometry from a web page, so
share B needs no App Store presence and no push infrastructure. A custom app
only earns its keep for agent-initiated unlocks where nobody is watching the
screen.

**Bind the approval to the request**: the daemon sends a nonce and what it is
asking for, the phone signs *that*, and the daemon accepts it once, within
seconds. Otherwise an approval captured for one unlock replays into another.

**Bound what an unlock buys.** A remote unlock should be able to say
`--window 300` and limit itself to one key. The idle timer exists; scoping does
not.

What does *not* work: every local-presence factor. A YubiKey touch or an
`sk-ssh-ed25519` key needs a finger on hardware attached to the signing
machine — which is in Berlin, and you are not.

## Approval: why there isn't a per-signature prompt

An approval prompt answerable on the machine is answerable by anything running
as you, agent included. To mean anything it must land on the device you carry —
and at that point it fires on every `git push`, which is unusable during the
incident work this feature exists for.

So: approve at *unlock*, not per signature. The per-entry
`UseConfirmConstraintWhenSigning` in `KeeAgent.settings` is honoured and passed
to the OS agent for anyone who wants the prompt on a specific key, but it is not
the mechanism this design leans on.

## What actually bounds the exposure

Ranked by how much they buy, which is roughly the reverse of how much they cost:

1. **Short-lived credentials at the destination.** An SSH CA certificate with a
   30-minute TTL and one principal — better, a forced command — means a
   capability abused inside the window still can't do arbitrary things to
   production. This is worth more than everything below it and is unbuilt.
2. **The per-entry gate.** Only entries that ask are forwarded, so an ops key
   can be marked and everything else left alone.
3. **The lifetime constraint.** Forwarded keys carry an expiry, so a troved that
   dies without locking still stops mattering. Keys with no stated duration
   inherit the idle-lock window.
4. **Signing and the hardened runtime** ([scripts/sign-macos.sh](../scripts/sign-macos.sh)).
   An unsigned daemon can be attached to by any same-uid process; a signed one
   with no `get-task-allow` cannot. This is what makes "the OS agent guards keys
   better than we do" an argument rather than an excuse.
5. **Extraction stays code-gated**, as above.

## Audit

Unlike the *read* auditing discussed in
[feature-ideas-2026-08-12.md](feature-ideas-2026-08-12.md) §3 — impossible
offline, because a read is a local decrypt — forwarding passes through the
daemon by construction. Recording what was forwarded, when, and to which agent
is cheap and currently not done.

## Known gaps in what shipped

- **Crash leftovers.** Nothing in the OS removes a key when the process that
  added it dies; `ssh-agent` doesn't track who added what. The lifetime
  constraint is the only backstop. Trove could record what it forwarded and reap
  it at next start — it doesn't yet.
- **Content-scanned keys are forwarded.** An entry with no `KeeAgent.settings`
  falls back to a content scan, and those keys are forwarded like declared ones.
  Stricter behaviour — forward only what explicitly opted in — is closer to
  KeePassXC and would make the app-level default safer still.
- **`trove session`.** A second terminal can't join an existing session: the
  code is minted at unlock and handed to that shell alone, and the desktop app
  serves no control socket, so a GUI unlock leaves nothing for `trove get` to
  talk to. The design settled on: `trove session` with no argument, hidden
  prompt, paste the code, spawn a subshell with `TROVE_SESSION` set — never in
  `argv` (visible in `ps`) and never in shell history. Make the code single-use
  so a captured clipboard or history line is spent.

## Limits worth writing on the tin

- A same-uid agent on an unlocked machine **is** you. The two gates decide which
  keys exist to be abused; they don't create a boundary.
- The approving device becomes a capability holder. Losing it must not lose the
  vault (the password still opens the file) and must be revocable.
- The machine has to be awake with troved or the desktop app running. Nothing
  here wakes it.
- None of this helps against an attacker who already has your uid and is willing
  to wait for you to approve something.
