# CLI reference

Every `trove` subcommand, every `troved` env var, every control RPC. Verified against the code in [crates/trove-cli/src/main.rs](../crates/trove-cli/src/main.rs), [crates/troved/src/main.rs](../crates/troved/src/main.rs), and [crates/troved/src/protocol.rs](../crates/troved/src/protocol.rs). Run `trove <command> --help` for clap's auto-generated copy.

## Global flags (trove)

```
trove [OPTIONS] <COMMAND>
```

| Flag | Description |
| --- | --- |
| `--password-stdin` | Read the vault password from stdin (one line) instead of prompting. For `init`, the single line becomes the password without a confirm step. Global — works on every subcommand. |
| `-h`, `--help` | Print help. |
| `-V`, `--version` | Print version. |

Exit codes (from [`classify_exit`](../crates/trove-cli/src/main.rs)):

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | User-recoverable error (bad path, missing entry, I/O error) |
| 2 | Vault-level error (bad password, corrupt kdbx) |

## trove init

```
trove init <VAULT>
```

Create a new empty kdbx vault. Prompts twice for the master password (or once with `--password-stdin`). Errors if `<VAULT>` already exists.

Backed by [`Vault::create`](../crates/trove-core/src/lib.rs). The default kdbx config is KDBX 4 + AES-256 + GZip + ChaCha20 (inner stream) + Argon2d.

## trove list

```
trove list <VAULT>
```

Print one line per entry: `<uuid>  <title>  [attachments: ...]`. Recursively walks all groups.

## trove add

```
trove add <COMMAND>
```

Subcommands: `ssh`, `gpg`, `file`, `help`.

### trove add ssh

```
trove add ssh [OPTIONS] --key <KEY> <VAULT> <TITLE>
```

| Argument / flag | Description |
| --- | --- |
| `<VAULT>` | Path to the .kdbx vault. |
| `<TITLE>` | Entry title (e.g. `"github.com"`). |
| `--key <KEY>` | Path to the SSH private key file (e.g. `~/.ssh/id_ed25519`). Required. |
| `--user <USER>` | Optional `UserName` field. |
| `--password-stdin` | Global — see top. |

Stores the key bytes as a real KDBX `<Binary>` attachment named `id`. If an entry with the given title exists, its `id` attachment is replaced; otherwise a new entry is added at the root group.

### trove add gpg

```
trove add gpg [OPTIONS] --key <KEY> <VAULT> <TITLE>
```

| Argument / flag | Description |
| --- | --- |
| `<VAULT>` | Path to the .kdbx vault. |
| `<TITLE>` | Entry title (e.g. `"git-signing"`). |
| `--key <KEY>` | Path to the binary GPG secret-key export. Required. **Binary, not armored.** |
| `--password-stdin` | Global — see top. |

The export file is what `gpg --export-secret-keys --output <file> <KEYID>` produces (without `--armor`). Stored under the `gpg-priv` attachment. On vault unlock, troved parses each `gpg-priv` attachment and registers every ed25519 secret key it finds.

### trove add file

```
trove add file [OPTIONS] --src <SRC> --target <TARGET> <VAULT> <TITLE>
```

| Argument / flag | Description |
| --- | --- |
| `<VAULT>` | Path to the .kdbx vault. |
| `<TITLE>` | Entry title (e.g. `"kubeconfig-prod"`). |
| `--src <SRC>` | File to read bytes from. Required. |
| `--target <TARGET>` | Path to materialize the file to on unlock. Required. |
| `--name <NAME>` | Override attachment name. Default: basename of `--src`. |
| `--mode <MODE>` | File mode (octal, 3 or 4 digits). Default `0600`. |
| `--ttl <TTL>` | Materialization lifetime in seconds. Default: lifetime of the vault unlock. |
| `--allow-disk-backed` | Allow non-tmpfs target. Off by default. Sets `Materialize.AllowDiskBacked=true`. |
| `--password-stdin` | Global — see top. |

Stores file bytes as a real KDBX `<Binary>` attachment and sets the following entry custom fields (read by troved's [materialize](../crates/troved/src/materialize/mod.rs) module):

- `Materialize.Source` — the attachment name (`<NAME>` or `--src` basename).
- `Materialize.Target` — `<TARGET>` (literal string; the daemon expands `~`, `$HOME`, `$XDG_RUNTIME_DIR`).
- `Materialize.Mode` — `<MODE>`.
- `Materialize.TTL` — seconds, only set if `--ttl` is given.
- `Materialize.AllowDiskBacked` — `"true"` or `"false"`.

## trove get

```
trove get <COMMAND>
```

Subcommands: `ssh`, `gpg`, `file`, `help`. All three open the vault, find the entry by exact title match, read the relevant attachment, and write to `--out` (or stdout). On Unix, `--out` files are created `0600` via `O_CREAT|O_EXCL`.

### trove get ssh

```
trove get ssh [OPTIONS] <VAULT> <TITLE>
```

| Argument / flag | Description |
| --- | --- |
| `<VAULT>` | Path to the .kdbx vault. |
| `<TITLE>` | Entry title to look up. |
| `--out <OUT>` | Write the key to this path. Stdout if omitted. |
| `--password-stdin` | Global — see top. |

Reads the `id` attachment.

### trove get gpg

```
trove get gpg [OPTIONS] <VAULT> <TITLE>
```

Same shape as `get ssh`. Reads the `gpg-priv` attachment.

### trove get file

```
trove get file [OPTIONS] <VAULT> <TITLE>
```

| Argument / flag | Description |
| --- | --- |
| `<VAULT>` | Path to the .kdbx vault. |
| `<TITLE>` | Entry title to look up. |
| `--name <NAME>` | Attachment name to read. Default: `Materialize.Source` field, or `"blob"`. |
| `--out <OUT>` | Write to this path. Stdout if omitted. |
| `--password-stdin` | Global — see top. |

Reads any attachment by name. **Ignores** `Materialize.Target` / `Mode` / etc. — `--out` controls where the bytes land. One-shot equivalent of full materialization.

## trove ssh-agent

```
trove ssh-agent <COMMAND>
```

### trove ssh-agent socket

```
trove ssh-agent socket
```

Print the path to the troved SSH agent socket, then exit. Resolution order:

1. `TROVE_SSH_SOCK` env var (override).
2. `$XDG_RUNTIME_DIR/trove-ssh.sock`.
3. `${TMPDIR:-/tmp}/trove-ssh-$UID.sock`.

Typical use: `export SSH_AUTH_SOCK="$(trove ssh-agent socket)"`.

## trove gpg-agent

```
trove gpg-agent <COMMAND>
```

### trove gpg-agent socket

```
trove gpg-agent socket
```

Print the path to the troved GPG agent socket. Resolution order:

1. `TROVE_GPG_SOCK` env var (override).
2. `$XDG_RUNTIME_DIR/trove-gpg.sock`.
3. `${TMPDIR:-/tmp}/trove-gpg-$UID.sock`.

gpg(1) wants a fixed path under `$GNUPGHOME`. Typical use:

```sh
ln -sf "$(trove gpg-agent socket)" "${GNUPGHOME:-$HOME/.gnupg}/S.gpg-agent"
```

## trove materialize

```
trove materialize <VAULT>
```

Open the vault, run every entry's materialize plan **in-process** (not via the daemon), hold open until SIGINT / SIGTERM, then wipe everything and exit. Useful for testing and disconnected workflows. Does **not** touch the daemon's `MaterializedStore`; if `troved` is also running, drive it via the `unlock` RPC instead so SSH and GPG agents come up at the same time.

Per-entry materialize errors are logged but don't abort the others.

## trove completions

```
trove completions [SHELL] [--install | --check]
```

Manage shell completion for `trove`. `SHELL` is one of `bash`, `zsh`, `fish`,
`powershell`, `elvish`; it is optional with `--install`/`--check` (defaults to
`$SHELL`).

- **no flags** — print the completion script to stdout (pipe it where you want).
- **`--install`** — write the script to the standard location and wire it into
  your shell rc. Idempotent: it manages a single marked block, so re-running
  updates in place instead of appending. Targets: zsh → `$XDG_DATA_HOME/trove/completions/_trove`
  sourced from `~/.zshrc`; bash → `$XDG_DATA_HOME/bash-completion/completions/trove`
  sourced from `~/.bashrc`; fish → `$XDG_CONFIG_HOME/fish/completions/trove.fish`
  (auto-loaded, no rc edit).
- **`--check`** — read-only. Reports how your shell currently completes `trove`.

### The zsh `_openstack` clash

zsh ships a bundled `_openstack` completer whose `#compdef` line claims ~27
command names — including `trove`, because OpenStack's database-as-a-service
project is *also* called Trove. With no trove-specific completion installed,
typing `trove <TAB>` dispatches to `_openstack`, which errors with
`_values:compvalues: not enough arguments`. This happens even when nothing
OpenStack is installed — the completer ships with zsh itself.

`trove completions zsh --install` resolves it: the installed completion runs an
explicit `compdef _trove trove` that wins over `_openstack`. `--check` detects
and names the shadow:

```
$ trove completions zsh --check
shadowed: `trove` completes via `_openstack`.
...
fix it with: trove completions zsh --install
```

## troved — the daemon

```
troved
```

Long-running. Listens on three Unix sockets; serves clients until `shutdown` RPC, SIGINT, or SIGTERM. Removes its own socket files on exit.

Permission model: every socket is bound by the daemon, then `chmod 0600` so only the same UID can connect.

### troved environment variables

All env vars are read at process start.

| Env var | Default | Effect |
| --- | --- | --- |
| `TROVE_SOCK` | `$XDG_RUNTIME_DIR/trove.sock` or `${TMPDIR:-/tmp}/trove-$UID.sock` | Path of the control socket. |
| `TROVE_SSH_SOCK` | `$XDG_RUNTIME_DIR/trove-ssh.sock` or `${TMPDIR:-/tmp}/trove-ssh-$UID.sock` | Path of the SSH agent socket. |
| `TROVE_GPG_SOCK` | `$XDG_RUNTIME_DIR/trove-gpg.sock` or `${TMPDIR:-/tmp}/trove-gpg-$UID.sock` | Path of the GPG agent socket. |
| `TROVE_IDLE_TIMEOUT` | `900` | Idle-lock timeout in seconds. `0` disables auto-lock. Non-numeric values warn and fall back to default. |
| `XDG_RUNTIME_DIR` | (system) | Used in default socket-path resolution. |
| `TMPDIR` | `/tmp` | Used as fallback when `XDG_RUNTIME_DIR` is unset/empty. |
| `UID` | `0` | Used in the `$TMPDIR` fallback path only. (`UID` is rarely set by login shells; the fallback path is essentially "/tmp/trove-0.sock" in practice — set `TROVE_SOCK` explicitly if running multi-user on a shared machine.) |
| `HOME` | (system) | Used by the materialize path resolver to expand `~` / `$HOME` in `Materialize.Target`. |

The CLI's `ssh-agent socket` / `gpg-agent socket` subcommands resolve the same way as the daemon, so they always agree (no need to pass `TROVE_*` to both).

### Control protocol (line-JSON)

Connect to the control socket, write one JSON object per line, read one response per line. The protocol is defined in [crates/troved/src/protocol.rs](../crates/troved/src/protocol.rs).

Request envelope: `{"cmd": "<name>", ...}`. Response envelope: `{"status": "ok"|"err", ...}`.

| `cmd` | Request fields | Response on success | Notes |
| --- | --- | --- | --- |
| `ping` | none | `{"status":"ok","pong":true}` | Heartbeat. Does **not** reset the idle timer. |
| `unlock` | `path: string`, `password: string` | `{"status":"ok"}` | Loads vault, populates SSH+GPG stores, runs materialization. Synchronous: `ok` only after every materialized file is on disk. |
| `list` | none | `{"status":"ok","entries":[{"id","title","username","url","attachments"}, ...]}` | Errors if no vault is unlocked. |
| `lock` | none | `{"status":"ok"}` | Wipes materialized files, drops vault, clears SSH+GPG stores, cancels idle timer. Idempotent. |
| `shutdown` | none | `{"status":"ok"}` | Same as `lock`, then signals the daemon main loop to exit. |
| `materialize-status` | none | `{"status":"ok","materialized":[{"title","target_path","ttl_remaining_seconds","exists"}, ...]}` | Read-only; works even with vault locked (returns empty array). |
| `set-idle-timeout` | `seconds: u64` | `{"status":"ok"}` | `0` disables auto-lock. Takes effect immediately; if the new timeout has already elapsed, the timer fires on the next driver wake. |
| `get-idle-timeout` | none | `{"status":"ok","seconds": u64, "remaining": u64\|null}` | `seconds` is the configured timeout. `remaining` is seconds-until-fire if a vault is unlocked, else `null`. |

Error responses: `{"status":"err","error":"<message>"}`. Errors do not close the connection — you can pipeline more commands.

The `unlock` request payload contains the master password in cleartext. The connection is a Unix socket bound `0600`; treat it the way you'd treat any other same-UID IPC channel.

### SSH agent protocol

Standard OpenSSH agent protocol on a separate socket. We implement:

- `SSH_AGENTC_REQUEST_IDENTITIES` (11) → `SSH_AGENT_IDENTITIES_ANSWER` (12)
- `SSH_AGENTC_SIGN_REQUEST` (13) → `SSH_AGENT_SIGN_RESPONSE` (14)

Anything else returns `SSH_AGENT_FAILURE` (5). Supported algorithms: ed25519, RSA >= 2048 bits (signs with rsa-sha2-256 / rsa-sha2-512 per RFC 8332 flag selection), ECDSA P-256, ECDSA P-384.

`ssh-add` and friends will only see identities for entries whose `id` attachment parses as one of the supported algorithms. Encrypted, weak (RSA < 2048), or unsupported (DSA, P-521, Ed448) keys are skipped at unlock time with a one-line warning to stderr.

### GPG Assuan protocol

Standard Assuan ASCII protocol on a separate socket. The implemented commands are documented in [crates/troved/src/gpg_agent/](../crates/troved/src/gpg_agent/). The minimum required to make `git commit -S` work for an ed25519 OpenPGP key, plus PKDECRYPT for ed25519+cv25519. Unknown commands return `ERR <code> <message>` so clients fail cleanly rather than hang.

## Per-entry custom-field schema

The materialize feature is wholly expressed as kdbx custom string fields, so the vault stays openable and round-trippable in KeePassXC.

| Field | Required | Type | Effect |
| --- | --- | --- | --- |
| `Materialize.Source` | yes | string | Attachment name to read bytes from. Must exist on the entry. |
| `Materialize.Target` | yes | string | Path to materialize to. `~`, `$HOME`, `$XDG_RUNTIME_DIR` are expanded against the daemon's environment. |
| `Materialize.Mode` | no | octal string (3 or 4 digits) | File mode. Default `0600`. |
| `Materialize.TTL` | no | positive integer seconds | Wipe the file after N seconds even if vault stays unlocked. |
| `Materialize.AllowDiskBacked` | no | `"true"` / `"false"` (case-insensitive; `"yes"` / `"1"` also accepted) | Allow non-tmpfs target. Default `false`. |

Plus the implicit attachment slots used by SSH and GPG:

| Attachment slot | Used by | Format |
| --- | --- | --- |
| `id` | SSH agent | OpenSSH private key (PEM-armored or raw, unencrypted). |
| `gpg-priv` | GPG agent | OpenPGP secret-key packets (binary, NOT armored). |
