# Spike: can Trove act as GnuPG's smartcard daemon (`scdaemon`)?

**Verdict: GO** — with named caveats (see [Verdict](#verdict)).

Throwaway experiment, 2026-08-01. Nothing in this repo was changed; all work happened in a
disposable `GNUPGHOME` under `/tmp`. This document is the only artefact.

Environment: macOS 26.4.1 (arm64), GnuPG **2.5.21** (Homebrew, a development series build),
libgcrypt 1.12.2. **No smartcard hardware was attached** — see
[What I could not prove](#what-i-could-not-prove).

---

## Background

Two earlier approaches were rejected with evidence: owning `$GNUPGHOME/S.gpg-agent` displaces
the real gpg-agent (Trove answers only 13 Assuan verbs, so keygen / `--edit-key` / smartcard
break), and proxying in front of it fails because gpg-agent reclaims its socket on every `gpg`
invocation.

This spike tested the remaining idea: gpg-agent's documented delegation hook for keys it does
not hold — `scdaemon`. `gpg-agent.conf`'s `scdaemon-program <path>` substitutes the card daemon,
and `shadowed-private-key` files in `private-keys-v1.d` hold **public parameters only**.

---

## What I proved

Every claim below was executed and observed; the supporting transcript is in
[Captured Assuan conversations](#captured-assuan-conversations).

1. **gpg-agent does launch a substituted `scdaemon-program`.** It is spawned as
   `<program> --multi-server --homedir <GNUPGHOME>` with **fd 0 and fd 1 wired to a pipe pair**
   (verified with `fstat`: `S_ISFIFO`, *not* a socket — so no `SCM_RIGHTS` fd-passing on the
   initial connection).

2. **A pure-software "card" is enough to satisfy `gpg --card-status`.** A ~300-line Python
   process answering Assuan on stdin/stdout made `gpg --card-status` print a plausible OpenPGP
   card.

3. **End-to-end signing works and verifies.** With the key present only as a
   `shadowed-private-key`, `gpg --detach-sign` routed to the software card, which performed
   PKCS#1 v1.5 padding plus the RSA private operation in Python, and `gpg --verify` reported
   `Good signature`. This is the core result.

4. **gpg-agent creates the `shadowed-private-key` file itself.** No hand-crafting is needed:
   answering `LEARN` and `READKEY` is sufficient, and gpg-agent writes the shadow file. (Note:
   it will **not** overwrite an existing on-disk private key — the real `.key` must be gone
   first.)

5. **Nothing is displaced.** With the fake card installed, `--quick-gen-key` (RSA *and*
   ed25519), signing with an ordinary on-disk key, and `--edit-key` all continued to work
   normally. The card is consulted only for `KEYINFO --list`. This is the decisive advantage
   over the two rejected approaches.

6. **The card can drive a user prompt.** Issuing `INQUIRE NEEDPIN <prompt>` from the card causes
   gpg-agent to run its pinentry flow and return the entered secret as `D <pin>` + `END`.
   Verified end-to-end (loopback pinentry). Trove could use this for per-signature approval or
   vault unlock.

7. **Concurrency works, and the extra socket is optional.**
   - If the card answers `GETINFO socket_name` with a path and serves Assuan there, gpg-agent
     opens *additional* connections to it. 6 concurrent `gpg --detach-sign` runs → **6/6 good**,
     5 socket sessions + 1 pipe session, 6 `PKSIGN`s served.
   - If the card **refuses** `GETINFO socket_name` (`ERR … Not supported`), gpg-agent falls back
     to serialising every client over the single pipe connection (log: `new connection to …
     daemon established (reusing)`). 4 concurrent signs → **4/4 good**.
   - So the socket server is a throughput optimisation, **not a requirement**. An MVP can ship
     pipe-only.

8. **A substituted scdaemon *can* proxy through to the real scdaemon (Q5).** Verified at two
   levels:
   - *Against the genuine binary*: the fake card spawned
     `/opt/homebrew/Cellar/gnupg/2.5.21/libexec/scdaemon --multi-server`, completed its Assuan
     handshake, and relayed `SERIALNO --all`, `GETINFO card_list`, `APDU`, and `READCERT`,
     receiving the real daemon's authentic no-card replies (`Card removed`, `Card not present`).
     Unknown commands passed through by default.
   - *Against a second software card* (to get past "no hardware"): Trove's card owned key A
     locally and proxied key B to a downstream daemon. Both `gpg --detach-sign -u A` and
     `-u B` produced **Good signature**, with the downstream serving exactly one `PKSIGN`.
   - **Bidirectional `INQUIRE` relay works**: a `NEEDPIN` raised by the *downstream* daemon was
     relayed up through Trove's card to gpg-agent's pinentry, and the reply relayed back down.
     Signature verified.

---

## Minimum viable command set

Determined empirically with a hot-reloadable deny list (denied commands returned
`ERR 67109139 Unknown IPC command`), then confirmed with a whitelist.

### To make `gpg --sign` succeed (shadow key already present)

| Command | Required? | Notes |
|---|---|---|
| `SERIALNO` | **Yes** | Denying it makes gpg-agent raise `INQUIRE CONFIRM 1` — "Please insert the card…" |
| `KEYINFO <keygrip>` | **Yes** | Same failure mode. This is how gpg-agent locates the key's card |
| `SETDATA <hex>` | **Yes** | Carries the payload to sign |
| `PKSIGN [--hash=algo] <keygrip>` | **Yes** | Returns the raw signature as `D` data |
| everything else | No | `LEARN`, `READKEY`, `GETATTR`, `RESTART`, `GETINFO`, `OPTION`, `RESET`, `NOP`, `LOCK`, `UNLOCK`, `DISCONNECT`, `KILLSCD`, `DEVINFO` were each denied individually with no effect on the signature |

Whitelist confirmation — with **only** `SERIALNO`, `KEYINFO`, `SETDATA`, `PKSIGN` answered,
`gpg --detach-sign` still produced a `Good signature`. It printed one cosmetic warning,
`gpg: error retrieving key fingerprint from card: Unknown IPC command` (from the denied
`GETATTR KEY-FPR`).

### To make gpg-agent create the `shadowed-private-key`

| Command | Required? |
|---|---|
| `LEARN` | **Yes** |
| `READKEY <keyid>` | **Yes** |
| `SERIALNO`, `GETATTR`, `KEYINFO`, `GETINFO`, `RESTART` | No |

### Practical minimum for a real implementation

`SERIALNO`, `LEARN`, `READKEY`, `KEYINFO`, `SETDATA`, `PKSIGN`, plus `GETINFO version` /
`GETINFO socket_name` and `OPTION`/`RESTART`/`RESET`/`BYE` as no-ops for a clean startup
handshake, plus `GETATTR` for `KEY-FPR`, `SERIALNO`, `$SIGNKEYID`, `$DISPSERIALNO` to silence
warnings and make `--card-status` look sane. Add `PKDECRYPT` for decryption (**untested**).

Notable: **`PKSIGN` and `KEYINFO` are addressed by keygrip**, not by the card's key-id string —
`PKSIGN --hash=sha256 0B5DFC29CC60F606432EDF5B6769B9794AEC3B02`. `READKEY`, however, is addressed
by the **key-id string** (`READKEY -- OPENPGP.1`). That asymmetry matters — see
[Gotchas](#gotchas-found-the-hard-way).

---

## The `shadowed-private-key` file

gpg-agent writes it; you should not have to. Produced automatically from `LEARN` + `READKEY`
(+ optional `GETATTR $DISPSERIALNO`), at
`$GNUPGHOME/private-keys-v1.d/<KEYGRIP>.key`:

```
Token: D2760001240103040006000000000000 0 OPENPGP.1 - 00000000
Key: (shadowed-private-key (rsa (n #00AAA7A97AEB…#)(e
  #010001#)(shadowed t1-v1 (#D276000124010304000600000000000000#
  OPENPGP.1))))
```

- Extended format: `Created:`/`Token:` headers, then `Key:` holding a *non-canonical* (spaces,
  hex-escaped MPIs, wrapped lines) S-expression. Contains **public parameters only**, plus the
  shadow reference `(shadowed t1-v1 (#<serial-hex># <keyid>))`.
- `Token:` fields are `<serial> <?> <keyid> <?> <dispserialno>`.
- Confirmed the stored `n` is byte-identical to the real key's `n`.
- After this file exists, `KEYINFO --list` at the agent level reports the key as
  `T <serial> <keyid>` (token-backed) instead of `D` (on disk).

Quirk: gpg-agent stored the serial as **17 bytes** (`D2760001…0000` **`00`**, 34 hex chars)
while the card reported 16 bytes (32 hex chars) via `S SERIALNO`. Signing worked anyway, so
gpg-agent evidently tolerates it, but a real implementation should check this rather than assume.

---

## Captured Assuan conversations

Captured with a tee wrapper installed as `scdaemon-program` that proxied to the real
`libexec/scdaemon` and logged both directions. `A->S` = gpg-agent to daemon.

### 1. Startup handshake (against the genuine scdaemon, no card present)

```
argv: ['scdaemon-program', '--multi-server', '--homedir', '/tmp/xx.XwvM']
fd0: FIFO   fd1: FIFO   (pipe pair, not a socket)

S->A   OK GNU Privacy Guard's Smartcard server ready, process 33590
A->S   GETINFO socket_name
S->A   D /tmp/xx.XwvM/S.scdaemon
S->A   OK
A->S   OPTION event-signal=31
S->A   OK
A->S   GETINFO version
S->A   D 2.5.21
S->A   OK
A->S   SERIALNO
S->A   ERR 100696144 Operation not supported by device <SCD>
A->S   RESTART
S->A   OK
```

After `GETINFO socket_name` succeeds, gpg-agent logs
`DBG: additional connections at '/tmp/xx.XwvM/S.scdaemon'` and uses that socket for concurrent
clients; the pipe remains connection #1.

### 2. `gpg --card-status`

```
GETINFO version → D 2.5.21 / OK
RESTART         → OK
GETINFO version → D 2.5.21 / OK
SERIALNO        → S SERIALNO D2760001240103040006000000000000 0 / OK
LEARN --force   → S SERIALNO …
                  S APPTYPE OpenPGP
                  S KEYPAIRINFO <grip> OPENPGP.1 sc <keytime> rsa2048
                  OK
GETATTR KEY-ATTR→ S KEY-ATTR 1 1 2048 0 65537 / OK
RESTART         → OK
```

`--card-status` fills in defaults for anything `LEARN` does not report; a real card emits
`DISP-NAME`, `KEY-FPR`, `MANUFACTURER` etc. as `LEARN` status lines.

### 3. Shadow-key creation (`gpg-connect-agent 'LEARN --sendinfo'`)

```
LEARN --force               → S SERIALNO <sn> 0
                              S APPTYPE OpenPGP
                              S KEYPAIRINFO <grip> OPENPGP.1 sc <keytime> rsa2048
                              OK
READKEY -- OPENPGP.1        → D (10:public-key(3:rsa(1:n257:<raw>)(1:e3:<raw>)))
                              OK
GETATTR $DISPSERIALNO <grip>→ S $DISPSERIALNO 00000000
                              OK
RESTART                     → OK
```

`READKEY` returns a **canonical S-expression as raw bytes** in `D` lines (`%`, CR, LF escaped as
`%25`, `%0D`, `%0A`). The `n` MPI carries a leading `00` because its high bit is set — hence
`1:n257:` for a 2048-bit modulus.

### 4. `gpg --detach-sign` (the money shot)

```
SERIALNO                     → S SERIALNO <sn> 0 / OK
SERIALNO                     → S SERIALNO <sn> 0 / OK
GETATTR KEY-FPR              → S KEY-FPR 1 E264505CF688DE50726CD04E3846CB4E87A0CD9A / OK
GETATTR SERIALNO             → S SERIALNO <sn> 0 / OK
GETATTR $SIGNKEYID           → S $SIGNKEYID OPENPGP.1 / OK
READKEY -- OPENPGP.1         → D (10:public-key(3:rsa(…)))  / OK
KEYINFO --list               → S KEYINFO <grip> T <sn> OPENPGP.1 - / OK
SERIALNO --all               → S SERIALNO <sn> 0 / OK
KEYINFO <grip>               → S KEYINFO <grip> T <sn> OPENPGP.1 - / OK
SETDATA 3031300D060960864801650304020105000420B078EFFE…D0424138
                             → OK
PKSIGN --hash=sha256 0B5DFC29CC60F606432EDF5B6769B9794AEC3B02
                             → D <256 raw signature bytes, %-escaped>
                               OK
RESTART                      → OK
```

**`SETDATA` carries the complete PKCS#1 DigestInfo, not a bare hash** — 51 bytes here:
`3031300D060960864801650304020105000420` (the SHA-256 AlgorithmIdentifier) followed by the
32-byte digest. The card does only the `00 01 FF…FF 00 ||` padding and the RSA private
operation, then returns the raw `k`-byte result. gpg-agent **verifies the signature it just
received** against the shadow key's public parameters (`DBG: rsa_verify … => Bad signature` on
mismatch), so a card cannot fake a signature past it.

---

## Gotchas found the hard way

These cost most of the spike's time and would cost an implementation the same.

1. **The downstream real scdaemon steals `$GNUPGHOME/S.scdaemon`.** If Trove's card advertises
   that path *and* spawns the real scdaemon with the same `--homedir`, the real daemon `unlink`s
   and rebinds the socket — after which gpg-agent's *additional* connections go straight to the
   real daemon, silently bypassing Trove. Symptom: the first sign works (pipe), concurrent ones
   fail. **Fix:** advertise a distinct socket path (e.g. `S.scd.trove`) and give the downstream
   daemon its own `--homedir`.

2. **Key-id strings are per-card and collide.** Every OpenPGP card calls its signing key
   `OPENPGP.1`. Because `READKEY` is addressed by key-id (not keygrip), two cards behind one
   daemon make `READKEY -- OPENPGP.1` ambiguous. In my first two-card run Trove's card answered
   with its *own* public key for the foreign key's `READKEY`; gpg-agent wrote a shadow file whose
   public parameters did not match the private key, and every signature came back
   `Bad signature`. **A proxying implementation must namespace/rewrite downstream key-ids and
   translate them back.**

3. **Presenting two cards via `SERIALNO --all` desynchronised gpg-agent.** With Trove reporting
   its own serial *and* relaying the downstream's, gpg-agent's responses on the scd channel went
   **one message out of step**: it consumed `SETDATA`'s `OK` as `PKSIGN`'s terminator, so the
   signature MPI arrived empty (`DBG: rsa_verify sig:+00 => Bad signature`). The card's own byte
   stream was verified strictly 1:1 request/response, and its signature verified correctly
   offline, so this is *not* a card-side framing bug — but I did not isolate the root cause.
   **Workaround that works:** present a **single virtual card** that owns every key, rewriting
   downstream `KEYINFO` serials to Trove's own and not merging `SERIALNO --all`. With that,
   local-key and proxied-key signing both returned `Good signature`. Treat multi-serial
   presentation as unsolved.

4. **gpg-agent starts scdaemon exactly once.** Config or binary changes need the daemon killed
   (`gpgconf --kill scdaemon`, or kill the process — gpg-agent respawns it on next use). In the
   isolated home `gpgconf --kill all` did not reliably reap gpg-agent; `pkill -f "homedir <dir>"`
   did.

5. **Environment artefact, not a GnuPG problem:** on this machine the *first* spawn of a new
   `scdaemon-program` by gpg-agent intermittently stalled ~110–120 s (a `sample` showed the child
   blocked in `dyld` at `blockOnSynchronousEvent`). Later spawns were instant, and running the
   same script directly from a shell was always instant. `ulimit -n` here is 1048576, which
   interacts badly with GnuPG's close-all-fds-before-exec; lowering it to 1024 helped but did not
   fully explain it. Budget long timeouts when iterating, and keep the agent alive between tests.

6. **Socket paths cap at ~104 bytes on macOS** — a long `GNUPGHOME` breaks gpg-agent with
   "File name too long". Used `mktemp -d /tmp/xx.XXXX` throughout.

---

## What I could not prove

Marked explicitly, because guessing here would be worse than admitting it.

- **No physical smartcard was available.** Every proxy result used either the real `scdaemon`
  binary *with no card* (which correctly returned `Card removed` / `Card not present`) or a
  second software card standing in for one. So: the Assuan plumbing for passthrough is proven;
  **passthrough to an actual Yubikey or PIV badge is unverified.** Untested in particular:
  card insertion/removal events (`OPTION event-signal=31` is accepted but its signal path was
  never exercised), PC/SC reader arbitration, `SWITCHCARD`/`SWITCHAPP` semantics, and whether a
  real card's `LEARN` output survives the merge intact.
- **ECC keys on the virtual card are untested.** The card served RSA-2048 only. Ed25519/NIST
  curves need a different `READKEY` S-expression, a different `KEY-ATTR`, and a `PKSIGN` that
  returns a raw signature rather than a padded RSA block. Trove's likely default is ed25519, so
  this needs its own spike. (An ordinary *on-disk* ed25519 key was generated and signed with
  successfully alongside the card, but that never touched the card.)
- **Decryption (`PKDECRYPT`) is untested.** Only signing was exercised.
- **`gpg --edit-card`, `keytocard`, `GENKEY`, `WRITEKEY`, `SETATTR`, `PASSWD`, `CHECKPIN`** were
  stubbed as unsupported or trivially OK'd; their real behaviour is unknown.
- **Root cause of gotcha 3 (multi-serial desync)** — worked around, not understood.
- **Linux/Windows behaviour** — not tested. GnuPG's spawn path, socket handling and
  `libexecdir` layout differ.
- **gpg 2.5.21 is a development series build.** All observations are from it. The
  keygrip-addressed `PKSIGN`/`KEYINFO` and key-id-addressed `READKEY` split, and the
  `SERIALNO --all` / `GETINFO card_list` multi-card verbs, are 2.3+ features; behaviour on 2.2
  is unverified.

---

## Verdict

**GO**, for a single-card, sign-only first implementation.

Reasons for:

- The core mechanism is confirmed end-to-end: gpg-agent launches the substituted daemon, hands
  it the digest, takes the signature back, and `gpg --verify` accepts it.
- It is genuinely non-displacing — keygen, `--edit-key`, and normal on-disk keys keep working.
  That is exactly what the two rejected approaches could not do.
- The required surface is small: four commands to sign, six to be respectable. Compare that with
  the full gpg-agent Assuan surface that approach #1 failed to cover.
- gpg-agent writes the `shadowed-private-key` itself, so Trove never fabricates key files.
- The pipe-only mode removes the need for a socket server in v1.
- `INQUIRE NEEDPIN` gives a supported route to a user prompt, which fits Trove's unlock model.

Conditions and residual risk:

- **The Yubikey coexistence story is "works in principle, unproven in practice."** Passthrough
  is real — the relay, including bidirectional `INQUIRE`, was demonstrated — but only against
  software stand-ins. Before shipping, this must be retested with actual hardware. Until then,
  treat "a user with a Yubikey keeps their Yubikey" as an **unverified claim**, and consider
  shipping the substitution as opt-in with a documented `gpgconf --kill scdaemon` escape hatch.
- The proxy must present **one virtual card**, namespace downstream key-ids, and give the
  downstream daemon its own homedir and socket path. All three of those were learned by breaking
  them.
- ECC needs its own spike before Trove can serve its likely default key type.

Recommended next step: a hardware-in-the-loop test of the passthrough path, and an ed25519
`READKEY`/`PKSIGN` spike. Neither blocks starting the implementation for RSA signing.
