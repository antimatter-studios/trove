# Windows — agent integration notes

Status: **notes, not implemented.** Native Windows builds work (named-pipe IPC,
control/ssh/gpg channels), but trove serves its agents on its *own* pipe names,
so no Windows client finds them without `SSH_AUTH_SOCK` pointing at a hashed
pipe name. This captures what makes Windows different and what to do about it.

## The core difference: Windows has a well-known agent pipe

On Unix, `ssh` finds its agent **only** through `$SSH_AUTH_SOCK`. There is no
path it probes, which is why reaching trove's agent needs either an env var, an
`IdentityAgent` line in `~/.ssh/config`, or pushing keys into whatever agent the
platform already runs (see [multi-vault.md](multi-vault.md) for the vault side
and `crates/troved/src/ssh_agent/forward.rs` for the forwarding mechanism).

Windows is the opposite, and closer to how gpg works: Win32-OpenSSH falls back
to the fixed pipe `\\.\pipe\openssh-ssh-agent` when `SSH_AUTH_SOCK` is unset.
That pipe is normally served by the **OpenSSH Authentication Agent** service —
which ships **disabled by default**. So on most machines the well-known name is
*free*.

That inverts the recommendation relative to macOS:

| | macOS / Linux | Windows |
|---|---|---|
| Well-known path exists? | no | **yes** |
| Preferred integration | `IdentityAgent`, else forward keys into the platform agent | **bind the well-known pipe ourselves** |
| Key material leaves troved? | yes, if forwarding | **no** |

Binding `\\.\pipe\openssh-ssh-agent` means every native Windows OpenSSH client
finds trove with zero configuration, keys stay in troved, and the lock guarantee
stays intact. It is the best integration story of any platform we support.

Owning the pipe is also what makes trove a *router* rather than just another
agent — see [agent-routing.md](agent-routing.md); Windows SSH is the first
place that design can actually land.

Only one process can own a pipe name, so the two modes are mutually exclusive
and the policy is simple:

- **pipe free** → bind it (preferred: no key material leaves troved)
- **pipe taken** (service enabled, or another agent) → forward into it, with the
  same tradeoffs as the macOS path

## What trove does today

`ipc::pipe_name` ([crates/troved/src/ipc.rs](../crates/troved/src/ipc.rs))
derives `\\.\pipe\trove-<fnv1a-hash>` from the socket path. Deterministic and
collision-free, but not a name anything else looks for. Nothing binds the
well-known agent pipe.

## Three client worlds, only one of which the pipe serves

A Windows box can have three ssh clients that do not agree on transport:

1. **Windows OpenSSH** (`C:\Windows\System32\OpenSSH\ssh.exe`) — native named
   pipes. Served by binding the well-known pipe.
2. **Git for Windows** — bundles an MSYS2/MinGW ssh using Cygwin-style
   Unix-socket *emulation*, not native pipes. Owning the OpenSSH pipe probably
   does **not** serve it unless git is pointed at the system ssh
   (`core.sshCommand`, or the installer's "use external OpenSSH" option).
3. **WSL2** — real Linux, real Unix sockets. Needs a relay such as
   [npiperelay](https://github.com/jstarks/npiperelay).

> **Verify before trusting:** [README.md](../README.md) currently says the
> native build "brokers for native-Windows clients (Git for Windows, Windows
> OpenSSH)". The Git for Windows half of that claim is doubtful for the reason
> above and has not been tested on a real machine. Either prove it or reword it.

## Security deltas on Windows

The threat model's [three barriers](threat-model.md) are not all present here.

- **No `SO_PEERCRED`.** Named pipes carry no peer credentials, so
  `crates/troved/src/main.rs` uses a `u32::MAX` sentinel for `peer_uid`. The
  "serve only the unlocking uid" barrier does not exist on Windows; extraction
  is gated by the session code and the pipe ACL alone.
- **Default pipe DACL.** `ipc.rs` notes this as known future hardening: the
  default DACL grants the creating user's logon session, and no explicit
  security descriptor is set. This matters more if we bind the well-known agent
  pipe, since every ssh client on the machine would then reach for it.
- **No `flock` singleton.** Windows relies on
  `ServerOptions::first_pipe_instance(true)` to reject a second binder instead
  of `crates/troved/src/singleton.rs`. Works, but means `trove daemons`
  (Unix-only) has no Windows equivalent for finding and reaping strays.

## Feature gaps

- `ssh_agent::forward` is `#[cfg(unix)]` — it connects a `UnixStream`. The
  Windows version needs the same protocol over a named pipe client, which
  `ipc.rs` already knows how to open.
- `trove daemons` / `daemons kill` are Unix-only.
- **gpg on Windows needs its own investigation.** Gpg4win's gpg-agent does not
  use a Unix socket; it uses libassuan's socket emulation — an `S.gpg-agent`
  *file* containing a loopback port plus a nonce, with clients connecting over
  TCP. trove's gpg agent has never been exercised against that. Confirm the
  mechanism before designing anything on top of it. Resolve the path with
  `gpgconf --list-dirs agent-socket`, never by hardcoding `$GNUPGHOME` — see
  [macos.md](macos.md#how-gpg-finds-its-agent--never-hardcode-the-path) for why
  one filename means three different things across platforms.
- **Pageant** (PuTTY) is a fourth agent implementation with its own IPC.
  Out of scope unless someone asks.

## Suggested order

1. Bind `\\.\pipe\openssh-ssh-agent` when free; fall back to forwarding when
   taken. Biggest win, no key material leaves troved.
2. Port `ssh_agent::forward` to named pipes so the fallback exists.
3. Settle the Git for Windows question and fix the README either way.
4. Explicit pipe security descriptor.
5. Investigate Gpg4win's assuan socket emulation before touching gpg on Windows.
