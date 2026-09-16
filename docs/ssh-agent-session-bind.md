# `session-bind@openssh.com` arrives before the identity listing — measured

Status: **measurement only.** Recorded because it settles a question that
decides the shape of key selection in the agent — and because the answer was
the opposite of what the protocol's own conventions suggested.

## The question

`sshd`'s `MaxAuthTries` defaults to 6, counted per connection, and every key the
agent lists is offered and counted — even though the publickey query phase
carries no signature. An agent holding more than six keys therefore locks you
out of a server whenever the key it wants sits past position six, and from the
fourth offer onward `sshd` is logging auth failures that `fail2ban` reads.

The agent normally has no idea which server `ssh` is talking to:
`SSH_AGENTC_REQUEST_IDENTITIES` carries no hostname and takes no filter. But
OpenSSH's `session-bind@openssh.com` extension hands the agent the server's host
key. Whether that is useful depends entirely on **when** it arrives:

- **Before** `REQUEST_IDENTITIES` — the agent can filter the list it returns, so
  only relevant keys are ever offered and the limit is never approached.
- **After** — useless for this. The agent could refuse to sign with the wrong
  key, but `ssh` would already have offered all of them, and offering is what
  burns the six.

`ssh-add -h` destination constraints gate *signing* rather than *listing*, which
hinted at the unhelpful ordering. The hint was wrong.

## Result

**`session-bind@openssh.com` arrives first, before `REQUEST_IDENTITIES`, on
every session connection, and separately on every hop.**

Measured on macOS (Darwin 25.4.0) with `OpenSSH_10.2p1, LibreSSL 3.3.6`, against
two throwaway `sshd` instances on `127.0.0.1:2222` (Ed25519 host key) and
`:2223` (RSA-2048 host key), through a logging proxy sitting in front of a real
`ssh-agent` holding one key.

### One hop

```
conn 1: #1 -> EXTENSION (27)  ext=session-bind@openssh.com  hostkey_algo=ssh-ed25519  is_forwarding=0
conn 1: #1 <- SUCCESS (6)
conn 1: #2 -> REQUEST_IDENTITIES (11)
conn 1: #2 <- IDENTITIES_ANSWER (12)  1 identities
conn 1: #3 -> SIGN_REQUEST (13)
conn 1: #3 <- SIGN_RESPONSE (14)
```

The bind is the **first** message on the connection. The agent knows the target
host key before it has to say what it holds.

### Two hops, distinct host keys

Run through an explicit `ProxyCommand` so both hops get their own options:

```
conn 5: #1 -> EXTENSION (27)  ext=session-bind@openssh.com  hostkey_algo=ssh-ed25519  is_forwarding=0
conn 5: #2 -> REQUEST_IDENTITIES (11)
conn 5: #3 -> SIGN_REQUEST (13)
conn 6: #1 -> EXTENSION (27)  ext=session-bind@openssh.com  hostkey_algo=ssh-rsa      is_forwarding=0
conn 6: #2 -> REQUEST_IDENTITIES (11)
conn 6: #3 -> SIGN_REQUEST (13)
```

Each hop opens its **own** agent connection and binds it to **its own** host key
before listing. Connection 5 is the jump host (Ed25519), connection 6 the
destination (RSA). This is the important one: per-hop filtering needs no second
socket and no `-o IdentityAgent`, so the objection that killed
`socket --filter=<fingerprint>` — that `ssh -J` cannot pass options to the `ssh`
it spawns — does not apply to filtering that happens inside one agent.

### Connections with no session

`ssh-add -l` sends `REQUEST_IDENTITIES` with no bind at all:

```
conn 2: #1 -> REQUEST_IDENTITIES (11)
conn 2: #1 <- IDENTITIES_ANSWER (12)  1 identities
```

So an unbound connection has to be served the full list. Filtering can only ever
apply to a connection that has bound itself, which is exactly the set of
connections that are about to authenticate.

Answering the extension with `SSH_AGENT_FAILURE` is also fine — a first probe
did exactly that and `ssh` carried on to authenticate normally. Implementing the
extension is optional; the client sends it either way.

## What this does and does not buy us

It buys the mechanism. It does not, on its own, buy "the right key with no
configuration at all", because the bind carries the server's **host key**, not
its hostname, and a host key says nothing about which of our keys it accepts.
Something still has to supply the mapping. Three candidates, cheapest first:

1. **`~/.ssh/known_hosts`** maps host keys to hostnames locally. Combined with an
   entry's URL or host attribute, that looks like a zero-configuration path —
   but it rests on a precondition nobody chose. `HashKnownHosts yes` is the
   default on Debian and Ubuntu, and a hashed entry is `|1|salt|hash` with the
   hostname destroyed; you cannot reverse it, only test a candidate hostname you
   already have, which is the wrong direction for "given this host key, what is
   it called". Any `ssh-keygen -H` run flips an unhashed file to hashed and takes
   the mapping away silently. It also needs entries to record where they are
   used, so "zero configuration" really means "zero configuration once two other
   things happen to be true".
2. **Learn it.** Remember which key produced a successful `SIGN_REQUEST` for a
   given host key, and filter on the remembered answer next time. Costs one
   unfiltered connection per host, which is the failure we are trying to avoid.
3. **Record it on the entry.** A host-key fingerprint field — the strongest of
   the three. Exact, no reverse lookup, and cheap to populate: `ssh-keyscan`
   fetches host keys with no authentication and no failed attempt, so the value
   can be filled in before anyone can be locked out. It has to be a **list**:
   one server presents several host keys, one per algorithm, and which one a
   client sees depends on `HostKeyAlgorithms` negotiation — so append on
   reinstall rather than replace.

There is also a failure-mode decision with no obvious default: when the filter
matches nothing, serve everything (fall back, and the lockout returns) or serve
nothing (fail fast with a clear message, and break anyone whose mapping is
merely incomplete).

## Bearing on `empty` / `add`

Filtering does not make `trove ssh-agent empty` / `add` redundant (see
[cli-reference.md](cli-reference.md)). Those give a **deterministic** agent — the
caller names the entries, and exactly those keys are offered. Filtering is a
heuristic sitting on top of a mapping that may be absent, stale or ambiguous,
and a first contact with an unknown host still lists everything. Worse, a filter
that matches nothing has two answers and both are bad: serve everything and the
lockout returns, serve nothing and an incomplete mapping breaks a machine that
worked yesterday. The two are complementary — `empty` + `add` is the explicit
escape hatch, host-key filtering is the better default for everyone who never
reaches for one.

## Reproducing

The probe is two short Python scripts — a fake agent that logs request types and
answers with N synthetic identities, and a proxy that logs and forwards to a real
agent so a real authentication completes. Both bind a **relative** socket path:
`AF_UNIX` caps at ~104 bytes on macOS and absolute scratch paths overrun it.
