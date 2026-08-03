# Agent routing — design notes

Status: **design only, not implemented.** Captures the model worked out in
discussion so it isn't lost. Companion to [multi-vault.md](multi-vault.md)
(which is the same idea applied to vaults), and to [macos.md](macos.md) /
[windows.md](windows.md), which decide *where* routing is even possible.

## The idea in one paragraph

Today trove is a key **holder** that happens to speak two agent protocols.
The generalisation is trove as a key-operation **router**: requests arrive
addressed by key identity, and trove dispatches each to whichever backend owns
that key — its own unlocked vaults, the platform's agent, a smartcard daemon, or
something else later. Holding keys becomes one backend among several rather than
the whole job.

## Why routing beats forwarding

These are opposite directions, and they are not equally safe:

| | Direction | Key material | Lifecycle control |
|---|---|---|---|
| **Forwarding out** (KeePassXC model) | trove → their agent | **leaves troved** | lost; we can only *ask* for removal |
| **Routing in** | their backend → trove relays | **never moves** | retained by whoever holds it |

Routing never moves a secret. trove relays "sign this digest for this key" and
returns the signature. That makes it strictly the better primitive, and it is
why a router is worth building even though forwarding already works.

Forwarding stays useful for one thing routing can't fix: **reach**. On macOS
there's no well-known socket path, so processes that never inherited
`SSH_AUTH_SOCK` can't find trove no matter how good its routing is. See
[macos.md](macos.md).

## Why the two agents feel so different: store vs cache

Most of the friction in this document traces back to one design difference.

| | ssh-agent | gpg-agent |
|---|---|---|
| What it holds | the **decrypted key** | the **passphrase** |
| Where the key lives | agent memory only | encrypted on disk, always (`private-keys-v1.d/`) |
| Default expiry | **none** | **600s** (`--default-cache-ttl`; max 7200) |
| Add a key at runtime | yes — `ADD_IDENTITY` | **no such command** |
| "Lock it now" | `REMOVE_IDENTITY` | flush the cache (`gpg-connect-agent reloadagent /bye`) |

ssh-agent assumes **the agent's memory is the store**. gpg-agent assumes the
store is **durable and external** — on disk, backed up with your home directory —
and the agent is a cache in front of it.

Two consequences worth internalising:

- gpg-agent looks static because you can't hand it a key. But it is *not*
  inflexible: it self-expires by default, which ssh-agent does not. By "does it
  forget on its own", **gpg is the stricter of the two** — ssh-agent holds a
  plaintext key indefinitely unless someone sets a lifetime.
- **This is why scdaemon is the extension point.** GnuPG anticipated "the key
  isn't in my keyring"; it just assumed the answer would be hardware. trove would
  be a software card. The architecture isn't closed, its hook is simply in a
  different place than ssh's — which is easy to miss if you go looking for an
  `ADD_IDENTITY` equivalent.

What this genuinely costs trove: a key cannot exist *only while a vault is
unlocked* without either writing it to disk (unacceptable) or being an scdaemon
(viable, unbuilt). Shadow keys remain on-disk state even though they hold public
parameters only. And cache flushing is agent-wide, so it carries the same
collateral-damage problem as ssh's `REMOVE_ALL_IDENTITIES` — see
[macos.md](macos.md).

## The two protocols route very differently

**SSH is trivial.** `SIGN_REQUEST` carries the public-key blob and the data in
one message. Dispatch is a stateless lookup — whoever claims that blob gets the
request. No session state at all.

**GPG is stateful.** `PKSIGN` carries neither key nor data: it reads a keygrip
and a hash set by *earlier* commands on the same connection
(`crates/troved/src/gpg_agent/mod.rs`). A router therefore has to:

- track per-connection session state,
- choose the backend at the moment a keygrip is named (`HAVEKEY`, `KEYINFO`,
  `SIGKEY`, `SETKEY`),
- pin the rest of that operation to it,
- replay session-scoped commands (`OPTION`, `SETKEYDESC`, `RESET`) to whichever
  backend it lands on.

That's a session-aware proxy, not a socket splice. It is the bulk of the work.

## Where routing is actually possible

Routing only helps if clients can reach us. That differs per platform, and the
answers are already worked out in the platform docs:

| Platform | Protocol | Can trove be the front door? |
|---|---|---|
| Windows | SSH | **Yes** — the well-known pipe `\\.\pipe\openssh-ssh-agent` is usually free (the OpenSSH agent service ships disabled) |
| macOS / Linux | SSH | **No** — no well-known path exists; needs `IdentityAgent` or forwarding |
| any | GPG | **No** — investigated and rejected; gpg-agent auto-reclaims its socket, and `--extra-socket` accepts only *some* commands. Route from *underneath* instead, as an scdaemon. See [macos.md](macos.md) |

So the router lands first on Windows SSH, and on GPG only via the scdaemon route.

## Design rules to bake in now, even at N=1

We have exactly one concrete second backend today (the system agent). Build the
**seam**, not the ecosystem — but build the seam properly, because retrofitting N
backends onto a hardcoded single passthrough means rewriting the dispatch.

- **Backends are an ordered list, config-declared.** Not a hardcoded "the real
  agent". Backend 0 is trove's own vault set.
- **First-wins by declared order.** Deliberately *unlike* the vault key union in
  [multi-vault.md](multi-vault.md), which is last-wins. That's safe there because
  a colliding key is byte-identical — only the `ssh-add -l` comment differs.
  Different *backends* are different implementations, so predictability beats
  recency.
- **Per-backend timeout.** A wedged backend must not hang `git commit -S`
  forever.
- **Registration is config-declared, never discovered.** Delegating a signature
  is a capability grant. "Any process may register as a key provider" is a hole,
  not a feature.
- **Log what was dispatched where.** With one key source, "it signed" is enough
  diagnosis. With several, "which backend answered?" is the first question anyone
  will ask.

## What we already have that is nearly this

`union_agent_keys` in `crates/troved/src/handler.rs` is a miniature router
already: it walks every unlocked vault, collects keys, and dedups by public blob
(SSH) or keygrip (GPG) — the exact addressing a real router would use. Extending
"which vault owns this key" to "which *backend* owns this key" is the same shape
one level up.

## The YAGNI line

Do **not** build a registration protocol, plugin host, or discovery mechanism
until a real second backend exists. Note this fits the stance the
[README](../README.md) already takes on plugins — sandboxed and
capability-scoped. A keygrip-addressed sign relay is a far smaller API surface
than a general plugin host, which is what makes it defensible.

## Suggested phasing

1. **Extract dispatch as a seam.** One function that answers "which backend owns
   this key identity?", with an ordered list that currently holds one entry.
   No behaviour change.
2. **Windows SSH front door.** Bind the well-known pipe when free; route to
   trove's vaults, fall back to forwarding when the pipe is taken.
3. **GPG via scdaemon.** Only after the spike in [macos.md](macos.md) confirms
   the route works at all.
4. **Second backend** (the system agent as a routable target rather than a
   forwarding destination) — and only then revisit whether any registration
   mechanism is warranted.

## Open questions

- Does a backend get to *claim* keys ahead of time (enumerate on connect), or is
  dispatch lazy (ask each in order until one answers)? Enumeration is faster and
  allows `REQUEST_IDENTITIES` to be answered completely; lazy is simpler and
  tolerates backends that can't enumerate. Probably enumerate-with-refresh.
- What happens when a backend claims a key trove also holds? First-wins says
  trove answers, but the *listing* should probably still show it once, not twice.
- Do we expose routing state (`trove agent backends`)? With N backends this
  stops being optional — see the logging rule above.
