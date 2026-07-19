# CLI reference

Every `trove` subcommand, every `troved` env var, every control RPC. Verified against the code in [crates/trove-cli/src/main.rs](../crates/trove-cli/src/main.rs), [crates/troved/src/main.rs](../crates/troved/src/main.rs), and [crates/troved/src/protocol.rs](../crates/troved/src/protocol.rs). Run `trove <command> --help` for clap's auto-generated copy.

## Global flags (trove)

```
trove [OPTIONS] <COMMAND>
```

| Flag | Description |
| --- | --- |
| `--vault <PATH>` | Operate **offline** on this kdbx file, bypassing the daemon. Global — works before or after the subcommand. See "Operating modes" below. |
| `--password-stdin` | Read the vault password from stdin (one line) instead of prompting. For `init`, the single line becomes the password without a confirm step. Global — works on every subcommand. |
| `--key-file <PATH>` | Composite key: this keyfile PLUS the password, wherever a vault is opened — offline `--vault` commands, `init` (locks the new vault with the pair), and `unlock` (the daemon holds the bytes in memory so its re-saves keep the composite key). Any format KeePassXC accepts: XML v1/v2, raw 32-byte, hex-64, or an arbitrary file (SHA-256). A wrong/missing keyfile fails like a wrong password (exit 2). |
| `--yubikey <SLOT>[:SERIAL]` | *(builds with `--features yubikey`; Linux-only for now — upstream keepass pins a USB backend that doesn't compile on macOS.)* HMAC-SHA1 challenge-response composited with the password/keyfile, KeePassXC's scheme. Applies to offline `--vault` commands and `init`. The device must stay connected while writing: every save answers a fresh challenge. |
| `-h`, `--help` | Print help. |
| `-V`, `--version` | Print version. |

### Operating modes

`trove` has two modes, selected by the global `--vault` flag (both placements are equivalent: `trove --vault V list` == `trove list --vault V`):

- **Offline (`--vault <PATH>`)** — the command opens the kdbx file directly. The password comes from `--password-stdin` or a prompt (never the command line). No daemon, no `TROVE_SESSION`. This is the stateless path automation should use. `init` and `materialize` always operate this way; with `--vault`, so do `add ssh/gpg/file`, `generate ssh`, `get`, and `list`.
- **Daemon (no `--vault`)** — `add ssh/gpg/file`, `generate ssh`, `get`, and `list` act on the vault unlocked in the running `troved`, gated by the `TROVE_SESSION` code `trove unlock` minted. `init` and `materialize` have no daemon mode and error without `--vault`.

`unlock` is the exception: it is inherently daemon-directed, so it keeps its own positional `<VAULT>` and ignores `--vault`.

Entry-addressing commands accept a `group/sub/title` **entry path**; intermediate groups are created on write as needed.

Exit codes (from [`classify_exit`](../crates/trove-cli/src/main.rs)):

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | User-recoverable error (bad path, missing entry, I/O error) |
| 2 | Vault-level error (bad password, corrupt kdbx) |

## trove init

```
trove --vault <PATH> init
```

Create a new empty kdbx vault at `--vault <PATH>` (required). Prompts twice for the master password (or once with `--password-stdin`). Errors if the file already exists.

Backed by [`Vault::create`](../crates/trove-core/src/lib.rs). The default kdbx config is KDBX 4 + AES-256 + GZip + ChaCha20 (inner stream) + Argon2d.

## trove list

```
trove [--vault <PATH>] list
```

Print one line per entry: `<uuid>  <path>  [attachments: ...]`. Recursively walks all groups. With `--vault` it reads the file directly (offline); without it, it lists the daemon's currently unlocked vault.

## trove show

```
trove [--vault <PATH>] show [OPTIONS] <ENTRY_PATH>
```

Print an entry's details: path, title, username, URL, notes, custom-field
*names* and attachment names. The password is masked unless `--show-protected`.

| Flag | Description |
| --- | --- |
| `--attr <NAME>` | Print only this attribute's raw value (repeatable, order kept). Any standard or custom field name. Protected attributes (`Password`, `otp`) additionally require `--show-protected`. |
| `--show-protected` | Reveal protected values instead of masking/refusing. |
| `--totp` | Print the entry's CURRENT TOTP code (from its `otp` otpauth URI, KeePassXC's format). Stdout is exactly the code (pipes cleanly); a TTY gets the remaining validity on stderr. Daemon mode uses the code-gated `GetTotp` RPC — only the ephemeral code crosses the wire, never the shared secret. |

Daemon mode: the summary view uses the ungated `ShowEntry` RPC (which never
carries protected values); `--attr` values and the revealed password go
through the code-gated `GetField` RPC (`TROVE_SESSION`).

## trove search

```
trove [--vault <PATH>] search <TERM>
```

Case-insensitive substring match over title, username, URL, notes and group
path. Protected values are **never** searched. Output is `list`-shaped.

## trove edit

```
trove [--vault <PATH>] edit [OPTIONS] <ENTRY_PATH>
```

Field-level edits on an existing entry. At least one change flag is required.

| Flag | Description |
| --- | --- |
| `--title <T>` | Rename the entry (leaf title only; use `mv` to relocate). |
| `--username <U>` / `--url <U>` / `--notes <N>` | Set the standard fields. |
| `--password-prompt` | Prompt (hidden, confirmed) for a new password. |
| `--set NAME=VALUE` | Set a custom field (repeatable). |
| `--unset NAME` | Remove a custom field (repeatable). |

## trove rm

```
trove [--vault <PATH>] rm [--permanent] <ENTRY_PATH>
```

Remove an entry the KeePassXC way: move it to the recycle bin (created on
demand with the `Meta/RecycleBinUUID` convention, so KeePassXC sees the same
bin). An entry already inside the bin — or any entry with `--permanent` — is
destroyed outright. Reports which of the two happened.

## trove mv

```
trove [--vault <PATH>] mv <ENTRY_PATH> <GROUP_PATH>
```

Move an entry to an **existing** group (`Root` for the top level).
Destinations are never created implicitly — `trove mkdir` first.

## trove mkdir

```
trove [--vault <PATH>] mkdir <GROUP_PATH>
```

Create a group hierarchy (`mkdir -p` semantics for intermediate segments).
Errors if the leaf group already exists.

## trove rmdir

```
trove [--vault <PATH>] rmdir [--permanent [--recursive]] <GROUP_PATH>
```

Remove a group and everything in it — to the recycle bin by default.
`--permanent` destroys instead, and then a non-empty group additionally
requires `--recursive`.

## trove add

```
trove add <COMMAND>
```

Subcommands: `password`, `ssh`, `gpg`, `file`, `help`.

### trove add password

```
trove [--vault <PATH>] add password [OPTIONS] <ENTRY_PATH>
```

| Argument / flag | Description |
| --- | --- |
| `<ENTRY_PATH>` | Entry path, e.g. `"github.com"` or `"Work/github"`. Groups auto-created. |
| `--username <U>` / `--url <U>` / `--notes <N>` | Optional standard fields. |
| `--generate` | Mint the password (OS CSPRNG, letters+digits) and print it once to stdout — the only echo, so it pipes. |
| `--length <N>` | Length for `--generate` (default 20). |
| `--secret-stdin` | Read the password from stdin. With the global `--password-stdin`, the vault password is line 1 and this secret line 2. |
| `--vault <PATH>` | Global. Present → offline; absent → the unlocked daemon (`TROVE_SESSION`). |

Without `--generate`/`--secret-stdin` the secret is prompted for (hidden,
confirmed). Adding to an existing entry path is refused — use `trove edit`.

### trove add totp

```
trove [--vault <PATH>] add totp <ENTRY_PATH> (--uri <URI> | --secret <BASE32> [--digits N] [--period N] [--algorithm A])
```

Attach a TOTP (2FA) generator: stored as the `otp` string field carrying an
`otpauth://` URI — KeePassXC's native format, so codes render identically in
both tools. The field is Protected (never searchable, `--attr otp` needs
`--show-protected`). The entry is created if missing; an existing generator is
replaced. `--secret` takes the base32 "manual entry" code sites display
(whitespace tolerated), with `--digits` (default 6), `--period` (default 30s)
and `--algorithm` (SHA1 default, SHA256, SHA512). The URI is validated before
anything lands in the vault. Steam's 5-character variant is not supported.
Read codes with `trove show <entry> --totp`.

### trove add ssh

```
trove [--vault <PATH>] add ssh [OPTIONS] <ENTRY_PATH> <KEY_FILE> <COMMENT>
```

| Argument / flag | Description |
| --- | --- |
| `<ENTRY_PATH>` | Entry path, e.g. `"github.com"` or `"Work/SSH/github"`. Groups auto-created. |
| `<KEY_FILE>` | Path to the SSH private key file (e.g. `~/.ssh/id_ed25519`). Validated before storing. |
| `<COMMENT>` | Public-key comment, typically an email like `you@host`. Recorded in `id.pub` (and so in a server's authorized_keys). Required. |
| `--user <USER>` | Optional `UserName` field. |
| `--vault <PATH>` | Global. Present → offline; absent → the unlocked daemon (`TROVE_SESSION`). |
| `--password-stdin` | Global — see top (offline mode only). |

Stores the private key in the `id` attachment, the derived public key in `id.pub`, and `KeeAgent.settings`. An existing entry has its attachments replaced in place. See also `trove generate ssh` (mints a keypair in-tool).

### trove add gpg

```
trove [--vault <PATH>] add gpg [OPTIONS] --key <KEY> <TITLE>
```

| Argument / flag | Description |
| --- | --- |
| `<TITLE>` | Entry path or title (e.g. `"git-signing"`). |
| `--key <KEY>` | Path to the binary GPG secret-key export. Required. **Binary, not armored.** |
| `--vault <PATH>` | Global. Present → offline; absent → the unlocked daemon (`TROVE_SESSION`). |
| `--password-stdin` | Global — see top (offline mode only). |

The export file is what `gpg --export-secret-keys --output <file> <KEYID>` produces (without `--armor`). Stored under the `gpg-priv` attachment. On vault unlock, troved parses each `gpg-priv` attachment and registers every ed25519 secret key it finds.

### trove add file

```
trove [--vault <PATH>] add file [OPTIONS] --src <SRC> --target <TARGET> <TITLE>
```

| Argument / flag | Description |
| --- | --- |
| `<TITLE>` | Entry path or title (e.g. `"kubeconfig-prod"`). |
| `--src <SRC>` | File to read bytes from. Required. |
| `--target <TARGET>` | Path to materialize the file to on unlock. Required. |
| `--name <NAME>` | Override attachment name. Default: basename of `--src`. |
| `--mode <MODE>` | File mode (octal, 3 or 4 digits). Default `0600`. |
| `--ttl <TTL>` | Materialization lifetime in seconds. Default: lifetime of the vault unlock. |
| `--allow-disk-backed` | Allow non-tmpfs target. Off by default. Sets `Materialize.AllowDiskBacked=true`. |
| `--vault <PATH>` | Global. Present → offline; absent → the unlocked daemon (`TROVE_SESSION`). |
| `--password-stdin` | Global — see top (offline mode only). |

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

Subcommands: `password`, `ssh`, `gpg`, `file`, `help`. Each resolves the entry by path/title and writes to `--out` (or stdout). With `--vault` they read the file directly (offline); without it, they ask the daemon, gated by `TROVE_SESSION`. On Unix, private `--out` files are created `0600` via `O_CREAT|O_EXCL`.

### trove get password

```
trove [--vault <PATH>] get password <ENTRY_PATH>
```

Print the entry's password to stdout — the script primitive
(`trove get password api/stripe | …`). For a whole-entry view use `trove
show`. Daemon mode routes through the code-gated `GetField` RPC.

### trove get ssh

```
trove [--vault <PATH>] get ssh [OPTIONS] <ENTRY_PATH>
```

| Argument / flag | Description |
| --- | --- |
| `<ENTRY_PATH>` | Entry path to look up, e.g. `"github.com"` or `"Work/SSH/github"`. |
| `--public` | Emit the public key (authorized_keys line) instead of the private key. |
| `--out <OUT>` | Write to this path (private → 0600, plus `<OUT>.pub` → 0644). Stdout if omitted. |
| `--vault <PATH>` | Global. Present → offline; absent → the unlocked daemon (`TROVE_SESSION`). |
| `--password-stdin` | Global — see top (offline mode only). |

Reads the `id` (and `id.pub`) attachments; the public key falls back to being derived from the private key for legacy entries.

### trove get gpg

```
trove [--vault <PATH>] get gpg [OPTIONS] <TITLE>
```

Reads the `gpg-priv` attachment. `--vault` → offline; otherwise daemon (`TROVE_SESSION`). `--out` writes to a path (0600), else stdout.

### trove get file

```
trove [--vault <PATH>] get file [OPTIONS] <TITLE>
```

| Argument / flag | Description |
| --- | --- |
| `<TITLE>` | Entry path or title to look up. |
| `--name <NAME>` | Attachment name to read (e.g. `id.pub`). Default: `"blob"`. In daemon mode `Materialize.Source` is not resolved; pass `--name` for a non-`blob` slot. |
| `--out <OUT>` | Write to this path. Stdout if omitted. |
| `--vault <PATH>` | Global. Present → offline; absent → the unlocked daemon (`TROVE_SESSION`). |
| `--password-stdin` | Global — see top (offline mode only). |

Reads any attachment by name. **Ignores** `Materialize.Target` / `Mode` / etc. — `--out` controls where the bytes land. One-shot equivalent of full materialization.

## trove git-credential

```
git config credential.helper "trove --vault ~/v.kdbx git-credential"
```

A git credential helper. git appends the operation and speaks its
`key=value` protocol on stdin/stdout. `get` matches an entry by `URL` host
(scheme/port/path ignored; also filtered by username when git provides one)
and replies with that entry's `username`/`password`; no match yields an empty
reply so git falls back to its next helper or prompt. `store`/`erase` are
accepted and ignored — trove is a deliberate vault, not an autofilled cache.
Offline-only. With `--password-stdin`, the vault password is stdin line 1 and
git's request block follows.

## trove resolve

```
trove --vault <PATH> resolve trove://<entry-path>[/<field>]
```

Print one referenced secret to stdout. The field defaults to `Password`;
`trove://Infra/prod/postgres/UserName` names it explicitly (last `/`-segment
when the whole path isn't itself an entry). The scripting primitive for
config templating: `export PGPASSWORD=$(trove --vault v resolve
trove://Infra/prod/postgres)`. Offline-only.

## trove exec

```
trove --vault <PATH> exec <SCOPE> -- <cmd> [args…]
```

Run `<cmd>` with secrets injected for exactly its lifetime (the `op run` of
kdbx). `<SCOPE>` is an entry path or a group path (all entries at or under
it). String secrets become environment variables; file attachments
materialize into a private per-run directory (0700, files 0600) that is
wiped — overwritten, then removed — the moment the command exits, including
on Ctrl-C. The child's exit code becomes trove's.

Variable naming: an entry's `Exec.Env` custom field names the variable
exactly (`Exec.Env=KUBECONFIG` on an attachment entry → `KUBECONFIG=<temp
path>`; on a password entry → that variable carries the password). Without
`Exec.Env`: `TROVE_<TITLE>_PASSWORD` / `TROVE_<TITLE>_FILE` (title
uppercased, non-alphanumerics → `_`). Offline-only: requires `--vault`.

## trove merge

```
trove --vault <TARGET> merge <SOURCE> [--source-key-file <PATH>]
```

KDBX-standard merge of diverged copies of one vault (last-write-wins by
modification time, histories preserved — the same algorithm KeePassXC runs,
proven equivalent in the interop suite). The source is unchanged. Two secrets
arrive in order: target password (line 1 with `--password-stdin`), then source
password (line 2). The global `--key-file` applies to the target;
`--source-key-file` to the source. Unrelated vaults (different root UUID) are
refused with a clean error — merge reconciles copies, it doesn't import.
Offline-only.

## trove export

```
trove --vault <PATH> export [--format xml|csv]
```

**The output contains every secret in plaintext** on stdout. `xml` is
decrypted KeePass XML (re-importable by `keepassxc-cli import`, proven in the
interop suite); `csv` uses KeePassXC's exact column header. Offline-only.

## trove db-edit

```
trove --vault <PATH> db-edit [--set-password] [--set-key-file <PATH> | --unset-key-file] [--kdf-memory MIB] [--kdf-iterations N] [--kdf-parallelism N]
```

Rekey (new password prompted, or stdin line 2 after the current password) and
retune the Argon2 KDF. At least one change required. Offline-only.

## trove db-info

```
trove --vault <PATH> db-info
```

Non-secret facts: format version, cipher, compression, KDF parameters,
entry/group counts, recycle-bin presence. Offline-only.

## trove clip

```
trove [--vault <PATH>] clip <ENTRY_PATH> [--attr NAME | --totp] [--timeout SECS]
```

Copy the entry's password (default), another attribute, or its current TOTP
code to the system clipboard, then auto-clear after `--timeout` seconds
(default 10; `0` disables). The clear is guarded: a detached child re-reads
the clipboard and wipes it only if it still holds what trove put there —
something you copied in the meantime is left alone. The child receives a
SHA-256 of the value on argv, never the value. Offline with `--vault`;
daemon-routed (code-gated `GetField`/`GetTotp`) without. Requires a
clipboard: headless sessions get a clean error.

## trove generate password / diceware

```
trove generate password [--length N] [--special] [--no-lower] [--no-upper] [--no-numeric] [--exclude CHARS] [--count N]
trove generate diceware [--words N] [--count N]
```

Purely local (no vault, no daemon), OS CSPRNG, uniform selection. `password`
defaults to 20 chars over lower+upper+digits; `--special` adds printable
punctuation, `--exclude` drops ambiguous characters. `diceware` draws from the
vendored EFF large wordlist (7776 words ≈ 12.9 bits/word; default 7 words
≈ 90 bits), hyphen-separated.

## trove estimate

```
trove estimate [PASSWORD]
```

zxcvbn strength rating: length, entropy bits, 0–4 score, and the estimator's
warning/suggestions. Omit the argument to read one line from stdin — the
preferred form, since argv is visible in `ps` and shell history.

## trove analyze

```
trove --vault <PATH> analyze --hibp <FILE>
```

Offline Have-I-Been-Pwned audit: every vault password is SHA-1-hashed and
binary-searched in the sorted `pwned-passwords` dump at `<FILE>` (the multi-GB
file is seeked, never loaded; nothing is ever sent anywhere). Breached entries
print as `<path>  seen N times in breaches`. Exits 1 when anything is
breached — scriptable as a CI gate. Offline-only: requires `--vault`.

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

### Two accounts on one host

The agent serves every unlocked key, and `ssh` offers them to a host in turn
until one is accepted. When you hold two keys that are *both* valid for the same
host — a common case is a personal and a work account on `github.com` — `ssh`
may present the wrong one, landing you on the wrong account. This is a plain
SSH-agent concern (not specific to trove), and the standard fix is a
`~/.ssh/config` host alias that pins the identity:

```
# Personal account: the default github.com
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_personal.pub
    IdentitiesOnly yes

# Work account: reach it as `work-github`
Host work-github
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_work.pub
    IdentitiesOnly yes
```

`IdentitiesOnly yes` is the important line: it tells `ssh` to offer **only** the
listed `IdentityFile` for that alias instead of walking every key the agent
holds. The `IdentityFile` here is a `.pub` file — the public half is enough for
`ssh` to pick which agent key to use, and the private half never leaves the
daemon. `ssh` reads that file at connection time, so it **must exist on disk at
the referenced path**; if it's missing, `ssh` silently skips the key and you get
`Permission denied (publickey)`. Export the public keys to the exact paths named
in the config with `trove get ssh --public`:

```sh
trove get ssh personal/github.com --public --out ~/.ssh/id_personal.pub
trove get ssh work/github.com     --public --out ~/.ssh/id_work.pub
```

Then address each account by its `Host`:

```sh
git clone git@work-github:acme/backend.git       # offers id_work
git clone git@github.com:me/dotfiles.git         # offers id_personal
```

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
trove --vault <PATH> materialize
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
| `TROVE_SPAWN_TIMEOUT_SECS` | `5` | How long a client waits for an auto-spawned daemon's socket to become reachable before erroring. Raise on slow/loaded machines. |
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
| `unlock` | `path: string`, `password: string` | `{"status":"ok","code","daemon_version","materialize_warnings":[…]}` | Loads vault, populates SSH+GPG stores, runs materialization (creating any missing parent dirs of a target, mode 0700). Synchronous: `ok` only after every materialized file is on disk. A per-entry materialization failure does **not** fail the unlock (spec: one bad entry must not break the vault) but is reported in `materialize_warnings` (omitted when empty) so the CLI warns loudly — never a silent `ok` with a configured file missing. |
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
