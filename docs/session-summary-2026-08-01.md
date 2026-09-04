# Session summary — 2026-08-01

Agent integration: what was asked, what was decided, what shipped, and what's
still unanswered. Open work lives in [todo.md](todo.md); this is the reasoning
behind it.

---

## The question that started it

> "When I unlock my vault in a terminal, my Claude Code sessions still can't use
> my github SSH key. Should there be a `--global` flag?"

**Answer: the scope boundary wasn't where it looked.** Two surfaces, only one
scoped:

- **Auth (ssh-agent / gpg-agent) was already global.** No session-code check
  exists on the agent sockets — any process of the same uid that finds the socket
  can sign. `docs/provisioning-sessions.md` already said so.
- **Extraction (`get`, `add`, CRUD) is scoped** by `TROVE_SESSION` + uid.

So the Claude Code sessions weren't blocked by scoping — they never had
`SSH_AUTH_SOCK`. No `--global` flag was needed for the stated problem.

---

## Q&A trail

| Question | Answer |
|---|---|
| Does unlocking in Trove Desktop expose keys system-wide? | No — desktop talks to **no daemon at all**. It embeds trove-core and holds vaults in-process. |
| How does KeePassXC make keys visible to VS Code? | It doesn't run an agent. It pushes keys into your *existing* agent via `SSH_AGENTC_ADD_IDENTITY`. macOS launchd injects `SSH_AUTH_SOCK` into every login-session process, so everything sees it. |
| Is there a standard socket path ssh looks for? | On Unix, **no** — env var only. `IdentityAgent` in `~/.ssh/config` is the file-based equivalent and is immune to what a process inherited. |
| Does Apple run a gpg-agent? | No. macOS ships nothing for GPG. gpg brings its own, auto-started by `gpgconf --launch`. |
| Is troved a bad idea if we forward to the platform agent? | No. It's the **lifecycle owner**: gpg can't be delegated at all, materialization has no OS counterpart, idle-lock spans every sink, and the daemon holds the decrypted vault so writes don't re-prompt. Agents are sinks, not the point. |
| Is ssh-agent the only platform integration? | On macOS yes. Windows has a well-known *pipe*; Linux additionally has Secret Service (a different kind of integration). |
| Would a launchd service help gpg? | It would add **lifecycle**, not reach — gpg is already global via its fixed path. And it would make the displacement problem permanent and invisible. |
| Could other agents integrate *into* trove? | Yes, and routing-in is strictly safer than forwarding-out: no key material moves. |
| Is `$GNUPGHOME/S.gpg-agent` portable? | One filename, **three mechanisms** — real socket (macOS), redirect file (Linux 2.1+), TCP-port-and-nonce file (Windows). Ask `gpgconf --list-dirs agent-socket`; never hardcode. |
| Is `.kbx` a typo for `.kdbx`? | No — GnuPG "Keybox", unrelated to KeePass. But **this machine uses neither**: `use-keyboxd` with SQLite at `public-keys.d/pubring.db`. |
| Isn't gpg-agent static and inflexible? | Static at the *key* layer (no runtime injection), dynamic at the *passphrase* layer. It auto-expires after 600s by default; ssh-agent has **no** default expiry. By "does it forget on its own", gpg is the stricter one. |
| What is scdaemon? | GnuPG's smartcard daemon. Chain is `gpg → gpg-agent → scdaemon → card`, and the private key never leaves the card. That is already trove's model — so trove can be a *software card*. |
| Is the lock guarantee weaker than KeePassXC's? | **No, and I'd overstated it.** Forwarding doesn't widen the ambient-process surface at all: same uid, same capability, different socket path. We also attach a lifetime constraint by default; KeePassXC's is opt-in. |

---

## Decisions

1. **Multi-vault, not single-vault.** `unlock` is additive; agents serve the union.
2. **Keys union with last-wins; deconfliction deferred** until a real conflict appears.
3. **Materialized files are first-wins** — the opposite of keys. Overwriting would
   destroy data a live process is using, and locking either vault would wipe a
   file the other expects.
4. **KeePassXC is the compatibility target** for agent behaviour, extending the
   discipline `parity-plan.md` already applied to the CLI.
5. **Per-entry settings, not new trove config.** `KeeAgent.settings` already
   carries the switches and round-trips through KeePassXC's own UI.
6. **`RemoveAtDatabaseClose=false` will not be honoured** for trove's own agent —
   retaining a key past lock contradicts the daemon's whole purpose.
7. **Forwarding is opt-in and additive**, never a replacement: gpg can't follow
   that model, so trove's own agents stay primary.
8. **Windows inverts the macOS recommendation** — bind the well-known pipe (usually
   free) rather than forward. No key material leaves troved.
9. **scdaemon is the only viable GPG route.** Owning or fronting `S.gpg-agent`
   both fail; see below.
10. **Agent-wide `REMOVE_ALL` / `LOCK` against a foreign agent stay manual** — they
    hit keys trove never added, so they can't fire from a vault lock.

---

## Shipped this session

316 → **326 tests**, zero regressions, clippy + fmt clean.

- **Multi-vault daemon** — `VaultSet`, additive unlock, union keyrings,
  `lock --vault`, per-vault materialize with cross-vault target refusal.
  Also fixed: the idle timer wasn't re-armed after a partial lock, which would
  have left remaining vaults unlocked forever.
- **RSA for OpenPGP** — parse (algo 1/2/3), keygrip, PKCS#1 v1.5 signing, sexp
  encoders. Unblocks most existing PGP keys, which are RSA.
- **Agent management messages** — `REMOVE_IDENTITY`, `REMOVE_ALL_IDENTITIES`,
  `LOCK`/`UNLOCK` server-side; `CONSTRAIN_CONFIRM` client-side.
- **`KEYINFO` correctness fix** — we reported protection `P` (passphrase-needed)
  for keys held unprotected, and ignored `--data`. Now byte-matches real gpg-agent.
- **SSH forwarding mechanism** — built and verified against a real `ssh-agent`,
  but **not yet wired** into unlock/lock.
- **Docs** — [multi-vault](multi-vault.md), [agent-routing](agent-routing.md),
  [macos](macos.md), [windows](windows.md), [todo](todo.md).

### Two findings that only a real client could have caught

- **The RSA keygrip is `SHA-1(0x00 || n)`** — bare modulus, no S-expression
  framing, `e` not involved. The spec-shaped guess (`(1:n<N>)(1:e<E>)`, by
  analogy with the ECC grips in the same file) was wrong in three ways at once.
- **RSA's `ADD_IDENTITY` puts the modulus before the exponent** — the reverse of
  the SSH public-key blob.

Both would have compiled and passed a self-consistent round-trip test.

### Two corrections to things stated earlier in the session

- "`REMOVE_IDENTITY` ✅ built" conflated client and server sides; the server side
  didn't exist.
- "gpg derives keygrips from `pubring.kbx`" is outdated — see the keyboxd row above.

---

## How we plan to solve the open problems

**GPG integration → be an scdaemon.** Both alternatives were investigated and
rejected with evidence:
- *Own `S.gpg-agent`* — displaces the real agent; we answer 13 Assuan verbs, so
  keygen, `--edit-key` and smartcard work all break while the symlink exists.
- *Proxy in front of it* — gpg-agent **auto-reclaims** its socket on every gpg
  invocation, and the only relocation option (`--extra-socket`) accepts, per its
  own help text, only *some* commands. The proxy would block exactly the
  functionality it existed to preserve.

scdaemon works *with* the architecture: gpg-agent keeps the socket and its full
command set, and asks us for keys it doesn't hold. Shadow keys carry public
parameters only.

**Reaching processes that never inherited `SSH_AUTH_SOCK`** → `IdentityAgent`
first (keys stay in troved), forwarding second (KeePassXC model), and on Windows
bind the well-known pipe instead of either.

**Per-key control** → the four `KeeAgent.settings` fields we already write. The
parser needs widening; no new config surface.

---

## No answer yet

1. **`git commit -S` fails with "No secret key" on GnuPG 2.5.x.** Affects ed25519
   and RSA identically. Ruled out: socket routing, `HAVEKEY`, `KEYINFO` (ours is
   now byte-identical to a real agent's). The divergence is elsewhere in gpg 2.5's
   pre-sign path. Next: tee the Assuan conversation against a real agent and diff.
2. **Does Apple's agent honour `CONSTRAIN_CONFIRM`,** and what does it prompt
   with? The per-use-approval design leans on this.
3. **Are forwarded keys really Keychain-free?** Reasoning from the mechanism says
   yes (persistence is keyed to a file path; an `ADD_IDENTITY` key has none), but
   it hasn't been tested.
4. **Does gpg-agent accept a substitute scdaemon** for a software "card", and what
   command subset does it demand? Unverified — this is the spike.
5. **Does trove actually broker for Git for Windows?** The README claims it; the
   MSYS2 socket emulation suggests otherwise.
6. **Can `trove-scd` proxy unknown cards** through to the real scdaemon? Only one
   runs at a time, so without this a Yubikey or work PIV badge stops working.
