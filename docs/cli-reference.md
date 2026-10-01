# CLI reference

Every `trove` subcommand, every `troved` env var, every control RPC. Verified against the code in [crates/trove-cli/src/main.rs](../crates/trove-cli/src/main.rs), [crates/troved/src/server.rs](../crates/troved/src/server.rs), and [crates/troved/src/protocol.rs](../crates/troved/src/protocol.rs). Run `trove <command> --help` for clap's auto-generated copy.

## Global flags (trove)

```
trove [OPTIONS] <COMMAND>
```

| Flag | Description |
| --- | --- |
| `--vault <PATH>` | Operate **offline** on this kdbx file, bypassing the daemon. Global — works before or after the subcommand. Defaults to `TROVE_VAULT` when set; an explicit flag wins. See "Operating modes" below. |
| `--password-stdin` | Read the vault password from stdin (one line) instead of prompting. For `init`, the single line becomes the password without a confirm step. Global — works on every subcommand. |
| `--key-file <PATH>` | Composite key: this keyfile PLUS the password, wherever a vault is opened — offline `--vault` commands, `init` (locks the new vault with the pair), and `unlock` (the daemon holds the bytes in memory so its re-saves keep the composite key). Any format KeePassXC accepts: XML v1/v2, raw 32-byte, hex-64, or an arbitrary file (SHA-256). A wrong/missing keyfile fails like a wrong password (exit 2). |
| `--yubikey <SLOT>[:SERIAL]` | *(builds with `--features yubikey`; Linux-only for now — upstream keepass pins a USB backend that doesn't compile on macOS.)* HMAC-SHA1 challenge-response composited with the password/keyfile, KeePassXC's scheme. Applies to offline `--vault` commands and `init`; daemon-backed commands, including `unlock`, reject it as unsupported. The device must stay connected while writing: every save answers a fresh challenge. |
| `-h`, `--help` | Print help. |
| `-V`, `--version` | Print version. |

### Operating modes

`trove` has two modes, selected by the global `--vault` flag or its `TROVE_VAULT` default (both flag placements are equivalent: `trove --vault V list` == `trove list --vault V`; the flag overrides the environment variable):

- **Offline (`--vault <PATH>`)** — the command opens the kdbx file directly. The password comes from `--password-stdin` or a prompt (never the command line). No daemon, no `TROVE_SESSION`. This is the stateless path automation should use. `init` and `materialize` always operate this way; with `--vault`, so do `add ssh/gpg/file`, `generate ssh`, `get`, and `list`.
- **Daemon (no vault path selected)** — `add ssh/gpg/file`, `generate ssh`, `get`, and `list` act on the vault unlocked in the running `troved`, gated by the `TROVE_SESSION` code `trove unlock` minted. `init` and `materialize` have no daemon mode and error without a path from `--vault` or `TROVE_VAULT`.

`unlock` is the exception: it is inherently daemon-directed, so it keeps its own positional `<VAULT>` and ignores `--vault`.

## Exit codes

From [`classify_exit`](../crates/trove-cli/src/main.rs), which walks the whole
error chain:

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | User-recoverable error: bad path, missing entry or group, entry/group/attachment already exists, non-empty group, missing or invalid TOTP, I/O error, no daemon or nothing unlocked, and anything not listed under 2 |
| 2 | Vault-level error: bad password or keyfile, corrupt or unreadable kdbx, or the file changed on disk in a way a save could not merge. From the daemon, only `unlock` reports 2, for an error mentioning a password, kdbx or decryption |

Outside `classify_exit`:

- A command-line usage error (unknown flag, missing argument) exits **2**,
  clap's code, the same as a vault error. `--help` and `--version` exit 0.
  `--env <PATH>` written without `=` exits 1 with a hint.
- `trove exec` exits with the child's exit code, or 1 when the child was
  killed by a signal.
- `trove unlock` that opens a session subshell (`--shell`, or a terminal
  without `--export`) exits with the shell's exit code: on Unix the shell
  replaces `trove`.
- `trove analyze` exits 1 when it finds a breached or empty password, with or
  without `--json`.
- `trove daemons kill` exits 1 if any target could not be stopped.

## trove unlock

```
trove unlock [--filter <TAG>] [--detach] <VAULT>
```

Unlocks a vault additively. `--filter` selects entries tagged `<TAG>` directly
or through a containing group (case-insensitive) for SSH/GPG agent exposure
and unlock-time materialization. The decrypted vault remains available to the
normal session-gated commands. `trove edit` manages entry tags; `trove group`
lists and edits group tags. Without `--filter`, every entry is exposed.
`--detach` unlocks without creating a session code or opening a subshell; the
agent keys and materialized files remain available.

Entry-addressing commands accept a `group/sub/title` **entry path**; intermediate groups are created on write as needed.

## trove init

```
trove --vault <PATH> init
```

Create a new empty kdbx vault at `--vault <PATH>` (required). Prompts twice for the master password (or once with `--password-stdin`). Errors if the file already exists.

Backed by [`Vault::create`](../crates/trove-core/src/lib.rs). The default kdbx config is KDBX 4 + AES-256 + GZip + ChaCha20 (inner stream) + Argon2d.

## trove list

```
trove [--vault <PATH>] list [--json] [--show-id]
```

Print one line per entry: its path and a summary of its attachments, with the
entry's UUID first when `--show-id` is given. Recursively walks all groups.
With `--vault` it reads the file directly (offline); without it, it lists the
daemon's currently unlocked vault. `--json` prints
[entry summaries](#trove-list---json-trove-search---json).

## trove show

```
trove [--vault <PATH>] show [OPTIONS] <ENTRY_PATH>
```

Print an entry's details: path, title, username, URL, notes, custom-field
*names* and attachment names. Protected fields (`Password`, `otp`) are hidden
from `--json` field names unless `--show-protected` is set; the flag also
reveals protected values where the selected mode returns them.

| Flag | Description |
| --- | --- |
| `--attr <NAME>` | Print only this attribute's raw value (repeatable, order kept). Any standard or custom field name. Protected attributes (`Password`, `otp`) additionally require `--show-protected`. |
| `--base64` | With exactly one `--attr`, print its value as standard base64 with no wrapping. A terminal gets a final newline; a pipe gets none. |
| `--show-protected` | Reveal protected values instead of masking/refusing. |
| `--totp` | Print the entry's CURRENT TOTP code (from its `otp` otpauth URI, KeePassXC's format). Stdout is exactly the code (pipes cleanly); a TTY gets the remaining validity on stderr. Daemon mode uses the code-gated `GetTotp` RPC — only the ephemeral code crosses the wire, never the shared secret. |
| `--json` | Print the entry as one [JSON object](#trove-show---json). Not with `--attr` or `--totp`. |

Daemon mode: the summary view uses the ungated `ShowEntry` RPC (which never
carries protected values); `--attr` values and the revealed password go
through the code-gated `GetField` RPC (`TROVE_SESSION`).

## trove describe

```
trove [--vault <PATH>] describe [--json] <ENTRY_OR_GROUP_PATH>
```

Print safe discovery metadata for an entry or every entry in a group. This
includes the path, username, URL, unprotected notes, whether a password is
present, attachment names and sizes, and unprotected custom fields whose names
start with `About.`. Protected values and attachment contents are never
returned. `About.*` is an optional naming convention, not a fixed schema:
Trove does not validate field names or interpret their meanings. Use
[`--json`](#trove-describe---json) for structured output suitable for agents.

The daemon view is read-only and does not require `TROVE_SESSION`; with multiple
vaults unlocked, Trove asks you to leave only one open to disambiguate group
paths.

## trove search

```
trove [--vault <PATH>] search [TERM] [--field NAME[=VALUE]] [--tag TAG] [--attachment GLOB] [--json]
```

Case-insensitive substring search across title, username, URL, notes, group
path, unprotected custom field names/values, attachment names and entry or
inherited group tags. Protected values are **never** searched. A term may be
combined with filters; each supplied filter category narrows results, while
repeated filters within a category are alternatives.

- `--field NAME` matches any unprotected field with that name (field names
  compare case-insensitively).
- `--field NAME=VALUE` requires an exact, case-sensitive value match.
- `--tag TAG` matches an entry tag or an inherited group tag, case-insensitively.
- `--attachment GLOB` matches attachment names with case-insensitive `*` and
  `?` wildcards, e.g. `--attachment '*.p8'`.

Without a term, at least one filter is required. Human output remains
list-shaped. `--json` returns [entry summaries](#trove-list---json-trove-search---json)
with a `matched` array naming the safe surfaces that caused each hit, such as
`field About.Purpose`, `tag signing`, or `attachment AuthKey_1234.p8`.
Protected names and values do not participate in substring or exact field
searches.

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
| `--tag TAG` / `--untag TAG` | Add or remove a KeePass-native entry tag (repeatable). |
| `--clear-tags` | Remove all KeePass-native entry tags before applying `--tag`. |
| `--expires <WHEN>` | Set when the entry expires: a date (`2030-06-15`, midnight UTC) or a UTC time (`2030-06-15T08:30:00Z`). |
| `--no-expiry` | Make the entry never expire. |

Expiry is KeePass's own `Expires`/`ExpiryTime`, so KeePassXC shows the same
date. It is advisory, as in KeePassXC: `show` marks an expired entry, nothing
stops it being used.

## trove group

```
trove [--vault <PATH>] group list [--json]
trove [--vault <PATH>] group edit <GROUP_PATH> [--tag TAG]... [--untag TAG]... [--clear-tags]
```

List groups (including empty groups and `Root`) with direct and inherited
KeePass tags, or edit tags directly on a group. Group edits are offline; pass
`--vault` and unlock the file through the CLI. Tags inherited from ancestors
are shown but not changed by editing a child group.

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
trove [--vault <PATH>] mv <ENTRY_PATH> <DEST>     # alias: move
```

Move an entry, renaming it when `<DEST>` names a new title — Unix `mv`
semantics, resolved against what already exists:

```sh
trove mv "a/key" "homelab"       # homelab is a group      -> homelab/key
trove mv "a/key" "homelab/ssh"   # ssh does not exist      -> homelab/ssh
trove mv "a/key" "typo/ssh"      # typo does not exist     -> error
trove mv -r "Apple.Backup" "Archive" # move a whole group tree
```

The destination's **parent** is never created implicitly, so a typo still
fails — `trove mkdir` first. A destination whose leaf is itself an existing
group means "move into it", which cannot be a typo because the group
demonstrably exists. `Root` is the top level.

Renaming in place is still `trove edit --title`; this is for when the entry
moves as well, which used to take two commands and left a window where the
entry sat in the right group under the wrong name.

`mv -r` moves a whole group tree, including empty subgroups, in one operation.
The destination follows the same existing-group or new-group-path rules.

## trove cp

```
trove [--vault <PATH>] cp <ENTRY_PATH> <DEST>     # alias: copy
```

Duplicate an entry, whole, at a new path — **key material and all**.

```sh
trove cp "antimatter-studios/gitea" "homelab/ssh"
trove cp -rv "Apple" "Apple.Backup"
trove cp -r "Apple" "Archive" --dry-run
```

The case this exists for: one SSH key reused across several machines ends up
filed under whichever service it was first created for, so the name lies — a
key called `gitea` grants shell access to a Raspberry Pi. Copying gives it a
second, accurate name without invalidating it or touching any
`authorized_keys`, and the two can then be rotated apart. Rotating "the gitea
key" today silently breaks the homelab.

Everything the entry holds comes with it: the private key, the derived
`id.pub`, `KeeAgent.settings`, custom fields, the password, every attachment.
A partial copy would look usable and not be — an SSH entry without its settings
blob is silently skipped by the agent, and one without `id.pub` is unreadable
by anything wanting the public half.

Without this the only route was `trove get` the private key to disk and
`trove add ssh` it back, which writes a key that had never existed outside the
vault onto a filesystem. `cp` keeps it inside the daemon, for the same reason
`trove generate ssh` exists so nobody has to run `ssh-keygen` themselves.

Same destination rules as `mv`, and an existing entry is **refused** rather
than overwritten.

**The copy is independent, and deliberately unmarked.** Nothing records that
two entries share key material. A recorded link invites tooling that treats
them as one thing — and then rotating the first key would take the second with
it before anyone had rotated that one, which is precisely the accident copying
exists to prevent. Two names for one key is the transitional state; rotating
them apart afterwards is the point.

`cp -r` copies a whole group tree, including empty subgroups, and refuses
destination conflicts before writing. It drops `Materialize.*` fields from
copies by default so originals and backups do not claim the same output paths.
`--keep-materialize` retains those fields and prints a warning about possible
target collisions. `--dry-run` prints the preflighted entry paths without
changing the vault; `-v` prints each source-to-destination path. `mv -r` moves
the corresponding group tree.

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
| `--secret-stdin` | Read the password from stdin. Offline only; with global `--password-stdin`, the vault password is line 1 and this secret line 2. |
| `--vault <PATH>` | Global. Present → offline; absent → the unlocked daemon (`TROVE_SESSION`). |

Without `--generate`/`--secret-stdin` the secret is prompted for (hidden,
confirmed). Adding to an existing entry path is refused — use `trove edit`.

### trove add totp

```
trove [--vault <PATH>] add totp <ENTRY_PATH> (--uri <URI> | --secret <BASE32> [--digits N] [--period N] [--algorithm A] | --secret <BASE32> --steam)
```

Attach a TOTP (2FA) generator: stored as the `otp` string field carrying an
`otpauth://` URI — KeePassXC's native format, so codes render identically in
both tools. The field is Protected (never searchable, `--attr otp` needs
`--show-protected`). The entry is created if missing; an existing generator is
replaced. `--secret` takes the base32 "manual entry" code sites display
(whitespace tolerated), with `--digits` (default 6), `--period` (default 30s)
and `--algorithm` (SHA1 default, SHA256, SHA512). The URI is validated before
anything lands in the vault. `--steam` stores a Steam Guard generator the way
KeePassXC does (`encoder=steam`: five characters from Steam's alphabet, 30s),
and a Steam URI from KeePassXC reads the same. HOTP (`otpauth://hotp`,
counter-based) is refused rather than misread as TOTP. Read codes with
`trove show <entry> --totp`.

### trove add ssh

```
trove [--vault <PATH>] add ssh [OPTIONS] <ENTRY_PATH> <KEY_FILE> <COMMENT>
```

| Argument / flag | Description |
| --- | --- |
| `<ENTRY_PATH>` | Entry path, e.g. `"github.com"` or `"Work/SSH/github"`. Groups auto-created. |
| `<KEY_FILE>` | Path to the SSH private key file (e.g. `~/.ssh/id_ed25519`), OpenSSH or PEM, or a PuTTY `.ppk` (v2 or v3, without a passphrase), which is stored converted to OpenSSH. Validated before storing. A passphrase-protected OpenSSH key prompts for its passphrase on the terminal and is stored decrypted, so no plaintext copy has to be written to disk. |
| `<COMMENT>` | Public-key comment, typically an email like `you@host`. Recorded in `id.pub` (and so in a server's authorized_keys). Required. |
| `--user <USER>` | Optional `UserName` field. |
| `--vault <PATH>` | Global. Present → offline; absent → the unlocked daemon (`TROVE_SESSION`). |
| `--password-stdin` | Global — see top (offline mode only). |

Stores the private key in the `id` attachment, the derived public key in `id.pub`, and `KeeAgent.settings`. An existing entry has its attachments replaced in place. See also `trove generate ssh` (mints a keypair in-tool).

### trove import-ssh

```
trove [--vault <PATH>] import-ssh [DIR] [--group <GROUP>] [--yes] [--dry-run]
```

| Argument / flag | Description |
| --- | --- |
| `[DIR]` | Directory to scan, not recursively. Default `~/.ssh`. |
| `--group <GROUP>` | Group for the new entries. Default `ssh`. |
| `--yes`, `-y` | Import every usable key without asking. |
| `--dry-run` | List what would be imported and what would be skipped; change nothing. |

Bootstraps a vault from existing keys without a `trove add ssh` per key. Every
regular file holding a PEM private key or a PuTTY key is offered, whatever its
name; `known_hosts`, `config`, `authorized_keys` and `*.pub` never are. Each
key becomes `<GROUP>/<file name>`, stored as `add ssh` stores it, with the
comment from the matching `.pub` (or the file name when there is none).

A passphrase-protected key is decrypted on the terminal, as `add ssh` does, and
stored without its passphrase; with no terminal it is skipped. A PuTTY `.ppk`
is stored converted to OpenSSH. Keys trove can't serve are listed on stderr with
the reason and left out: DSA, RSA under 2048 bits and a `.ppk` with a
passphrase. So is a key whose entry already exists; importing never overwrites. Without `--yes` it asks
about each key on the terminal, and refuses to run when there is none to ask on
(including with `--password-stdin`). The key files are never changed or removed.

Offline, the vault is opened once and saved once. Through the daemon, each key
is served by the agent as soon as it is stored.

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

The export file is what `gpg --export-secret-keys --output <file> <KEYID>` produces (without `--armor`). Stored under the `gpg-priv` attachment. On vault unlock, troved parses each `gpg-priv` attachment and registers every ed25519 and RSA secret key it finds.

A passphrase-protected export (gpg's default) is decrypted on the terminal: `add gpg` asks for the passphrase, three tries, and stores the key unprotected inside the vault, so no unprotected export has to touch the disk. With no terminal to ask on it refuses. Supported protection is what GnuPG writes by default: v4 keys, iterated and salted S2K over SHA-1 or SHA-2, AES-128/192/256. AEAD (OCB) protection and GnuPG stub keys are refused by name.

A protected export already in a vault (added by another tool) is decrypted at unlock with the entry's Password, as KeePassXC does for protected SSH keys. Without a Password it is skipped with a warning.

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

Each field is keyed by the attachment it describes, so one entry can materialize
several files — an SSH key and its `.pub`, a certificate and the key that
matches it:

- `Materialize.<attachment>.Target` — `<TARGET>` (literal string; the daemon expands `~`, `$HOME`, `$XDG_RUNTIME_DIR`).
- `Materialize.<attachment>.Mode` — `<MODE>`.
- `Materialize.<attachment>.TTL` — seconds, only set if `--ttl` is given.
- `Materialize.<attachment>.AllowDiskBacked` — `"true"` or `"false"`.

There is no `Source` field: the attachment name in the key is the source. An
attachment with no `Target` is simply not materialized.

## trove rename-attachment

```
trove rename-attachment <ENTRY_PATH> <OLD_NAME> <NEW_NAME> --vault <PATH>
```

Renames an attachment and everything that names it:

- the attachment itself
- `Materialize.<name>.*` — the settings are keyed by the name, so they follow it
- `KeeAgent.settings` — rewritten to name the new file, keeping the rest of the
  policy (lifetime, confirm, remove-at-close) and its original encoding

Offline only (`--vault`): it rewrites the file, while the daemon serves a vault
that is already open.

```
$ trove rename-attachment "Work/server" id_rsa id_ed25519 --vault v.kdbx --env
renamed attachment id_rsa → id_ed25519
  moved Materialize.id_ed25519.AllowDiskBacked
  moved Materialize.id_ed25519.Mode
  moved Materialize.id_ed25519.Target
  updated KeeAgent.settings to name the new file
```

Refused when the entry has no such attachment, or already has one under the new
name — silently replacing a different file would be worse than stopping.

The *values* are left alone: a target still points where it did, since where a
file lands is a separate question from what the attachment is called.


## trove get

```
trove get <COMMAND>
```

Subcommands: `password`, `ssh`, `gpg`, `file`, `help`. Each resolves the entry by path/title and writes to `--out` (or stdout). With `--vault` they read the file directly (offline); without it, they ask the daemon, gated by `TROVE_SESSION`. On Unix, private `--out` files are created `0600` via `O_CREAT|O_EXCL`.

### trove get password

```
trove [--vault <PATH>] get password <ENTRY_PATH> [--base64]
```

Print the entry's password to stdout — the script primitive
(`trove get password api/stripe | …`). `--base64` prints the standard
base64-encoded UTF-8 value without wrapping; a terminal gets a final newline,
while a pipe gets none. For a whole-entry view use `trove show`. Daemon mode
routes through the code-gated `GetField` RPC.

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
| `--name <NAME>` | Attachment name to read (e.g. `id.pub`). Default: `"blob"`. Pass it for any entry that does not use the conventional `blob` slot. |
| `--out <OUT>` | Write to this path. Stdout if omitted. |
| `--base64` | Write the standard base64 encoding instead of raw attachment bytes. No wrapping; a final newline is added only when writing to a terminal. Encoded files still use mode `0600`. |
| `--vault <PATH>` | Global. Present → offline; absent → the unlocked daemon (`TROVE_SESSION`). |
| `--password-stdin` | Global — see top (offline mode only). |

Reads any attachment by name. **Ignores** the `Materialize.*` fields — `--out` controls where the bytes land. One-shot equivalent of full materialization.

## trove git-credential

```
git config credential.helper "trove git-credential"
```

A git credential helper. git appends the operation and speaks its
`key=value` protocol on stdin/stdout. `get` matches an entry by `URL` host
(scheme/port/path ignored; also filtered by username when git provides one)
and replies with that entry's `username`/`password`; no match yields an empty
reply so git falls back to its next helper or prompt. `store`/`erase` are
accepted and ignored — trove is a deliberate vault, not an autofilled cache.
Without `--vault`, `get` uses the unlocked daemon and requires `TROVE_SESSION`;
this avoids re-opening the database for every HTTPS operation. Add `--vault`
to use offline mode instead. With `--vault --password-stdin`, the vault
password is stdin line 1 and git's request block follows.

### Which secret is sent: `git.token`, else `Password`

Forges increasingly refuse account passwords for git over HTTPS and want a
personal access token instead. The same entry is usually also the web login, so
writing the token into `Password` costs you the password for the site. Put it
in a `git.token` attribute and the helper prefers it:

```
antimatter-studios/git
  UserName:   chris.alex.thomas
  Password:   my-web-login       ← still logs into the web UI
  git.token:  a1b2c3…            ← what git gets
```

`git.token` is an ordinary KDBX custom string field — KeePassXC shows and edits
it under an entry's additional attributes like any other — and the name is
matched case-insensitively, so `Git.Token` works too. An empty value counts as
absent rather than as "send nothing", so a half-filled attribute can't silently
break an entry whose `Password` still works.

There is no cross-tool convention to adopt here. The name is meant to read as
"the token git uses" rather than as anything trove-specific, so it means the
same to someone who has never heard of trove.

A forge rejecting the wrong one of these says only `invalid username, password
or token`, which does not tell you which of the two it just refused — so if git
authentication fails against a host whose entry is also a web login, check
which secret is being sent before assuming the credential is stale.

## trove resolve

```
trove --vault <PATH> resolve [--base64] trove://<entry-path>[/<field>]
```

Print one referenced secret to stdout. `--base64` prints its standard base64
encoding without wrapping; a terminal gets a final newline, a pipe does not.
The field defaults to `Password`;
`trove://Infra/prod/postgres/UserName` names it explicitly (last `/`-segment
when the whole path isn't itself an entry). The scripting primitive for
config templating: `export PGPASSWORD=$(trove --vault v resolve
trove://Infra/prod/postgres)`. Offline-only.

## trove exec

```
trove [--vault <PATH>] exec <SCOPE> -- <cmd> [args…]
```

Run `<cmd>` with secrets injected for exactly its lifetime (the `op run` of
kdbx). `<SCOPE>` is an entry path or a group path (all entries at or under
it). String secrets become environment variables; file attachments
materialize into a private per-run directory (0700, files 0600) that is
wiped — overwritten, then removed — the moment the command exits, including
on Ctrl-C. The child's exit code becomes trove's.

On Linux the directory goes on tmpfs: `$XDG_RUNTIME_DIR` if it is
memory-backed, else `/dev/shm`. With neither, it falls back to the OS temp
dir and `exec` warns that the files can reach the disk. macOS and Windows have
no memory-backed filesystem to use, so there it is always the OS temp dir,
which is on disk; a SIGKILL or power loss leaves the files there until they
are deleted.

If a name matches both an entry and a group, `exec` reports the ambiguity.
Select the intended scope with `--entry PATH` or `--group PATH`, for example
`trove --vault v.kdbx exec --group Infra -- env`.

Variable naming: an entry's `Exec.Env` custom field names the variable
exactly (`Exec.Env=KUBECONFIG` on an attachment entry → `KUBECONFIG=<temp
path>`; on a password entry → that variable carries the password). Without
`Exec.Env`: `TROVE_<TITLE>_PASSWORD` / `TROVE_<TITLE>_FILE` (title
uppercased, non-alphanumerics → `_`).

With `--vault` it opens that file, asking for its password. Without it, it reads
the vaults unlocked in the daemon through the session-gated reads, so it needs
the `TROVE_SESSION` code from `trove unlock` and no password.

An entry that needs several variables maps each with an `Exec.<VAR>` field
naming its source: a field, standard or custom, or `@<attachment>` for the
path of that attachment in the run directory. A database entry might carry:

| field | value | exports |
| --- | --- | --- |
| `Exec.PGUSER` | `UserName` | `PGUSER=<UserName>` |
| `Exec.PGPASSWORD` | `Password` | `PGPASSWORD=<Password>` |
| `Exec.PGHOST` | `URL` | `PGHOST=<URL>` |
| `Exec.PGSSLROOTCERT` | `@ca.pem` | `PGSSLROOTCERT=<temp path>/…-ca.pem` |

An entry with mappings exports only those, plus `Exec.Env` if it has one; the
`TROVE_<TITLE>_*` fallback is off. A mapping that names a field or attachment
the entry doesn't have, or a variable name that isn't one, stops `exec` before
the command runs.

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

## trove sync

```
trove --vault <VAULT> sync <OTHER> [--other-key-file <PATH>]
```

Two-way sync with another copy of the same vault, such as one in a synced
folder, on a USB stick or on a network share. The other copy is merged into
`--vault` (the same merge as `trove merge`), then the result replaces the
other copy atomically, so both end equal. A missing copy is created from
`--vault` with the same password and key file; a copy that already has
everything is left untouched. `--vault` is authoritative for vault settings
such as the KDF, but what only the other copy has (custom data such as
KeePassXC-Browser keys, its recycle bin, deletions) is kept. For an existing
copy two secrets arrive in order: `--vault`'s password (line 1 with
`--password-stdin`), then the other copy's (line 2). The global `--key-file` applies to `--vault`;
`--other-key-file` to the other copy. Prints what was pulled and what was
pushed. Offline-only.

A sync service that could not merge two edits leaves a second file next to
the vault, such as Dropbox's `vault (… conflicted copy …).kdbx` or Syncthing's
`vault.sync-conflict-….kdbx`. Sync it into the vault with
`trove --vault vault.kdbx sync '<conflicted copy>'`, then delete the copy.

Writes to either file that land during the sync are merged in, not
overwritten. Every trove save does this: when the vault file changed since it
was opened, the other writer's changes are merged in before writing.

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
trove --vault <PATH> db-info [--json]
```

Non-secret facts: format version, cipher, compression, KDF parameters,
entry/group counts, recycle-bin presence. Offline-only.
[`--json`](#trove-db-info---json) prints them as one object.

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
trove estimate [PASSWORD] [--json]
```

zxcvbn strength rating: length, entropy bits, 0–4 score, and the estimator's
warning/suggestions. Omit the argument to read one line from stdin — the
preferred form, since argv is visible in `ps` and shell history.
[`--json`](#trove-estimate---json) prints the same facts as one object; the
password itself is never included.

## trove analyze

```
trove --vault <PATH> analyze [--hibp <FILE>] [--reuse] [--weak [--min-score N]] [--age DAYS] [--json]
```

Audit the vault's passwords; at least one check is required, and any finding
exits 1. Only entry paths are printed, never a password.

| Check | Reports |
| --- | --- |
| `--hibp <FILE>` | breached and empty passwords (below) |
| `--reuse` | groups of entries sharing a password, compared by SHA-256 in memory |
| `--weak` | entries whose zxcvbn score is below `--min-score` (0-4, default 3) |
| `--age DAYS` | entries unchanged for more than DAYS days, by the entry's last modification time (any edit counts, not just the password) |

Offline Have-I-Been-Pwned audit: every vault password is SHA-1-hashed and
binary-searched in the sorted `pwned-passwords` dump at `<FILE>` (the multi-GB
file is seeked, never loaded; nothing is ever sent anywhere). Breached entries
 print as `<path>  seen N times in breaches`. Exits 1 when anything is
 breached — scriptable as a CI gate. Offline-only: requires `--vault`.
Empty or missing passwords print as `<path>  empty password` in human mode,
fail the audit the same way, and are counted separately from passwords
checked against the dump. [`--json`](#trove-analyze---json) writes the counts
and findings as one object, including when a finding is present; the exit code
remains nonzero in that case.

## JSON output

Seventeen commands take `--json`: `list`, `search`, `show`, `describe`,
`group list`, `db-info`, `estimate`, `analyze`, `status`, `doctor`, `idle get`,
`materialize-status`, `ssh-agent list`, `ssh-agent sockets`, `gpg-agent list`,
`daemons list` and `keychain status`. Each prints one pretty-printed JSON
document on stdout; errors still go to stderr with the usual
[exit codes](#exit-codes).

These shapes are covered by the [stability promise](stability.md): a minor
version may add fields, but never renames, removes or retypes one. Parse by
name, ignore fields you don't know, and don't rely on key order (keys currently
come out sorted). The shapes are pinned by
[json_shapes_e2e.rs](../crates/trove-cli/tests/json_shapes_e2e.rs), so a change
fails CI until this section is updated with it.

Notation below: `string`, `integer` (a whole number), `number` (may have a
fraction), `bool`; `T | null` means the key is always there but may be null;
`"key"?` means the key may be missing; `[T]` is an array of `T`;
`{string: T}` is an object with arbitrary keys.

JSON output doesn't grant extra access: daemon-backed commands keep their
session and daemon requirements. For example,
`trove status --json | jq '.ssh_key_count'` prints the identity count without
parsing display text.

### `trove list --json`, `trove search --json`

An array of entry summaries, in vault order:

```
[
  {
    "id": string,               // entry UUID
    "title": string,
    "path"?: string,            // "Web/forge"; offline (--vault) only, see below
    "username": string | null,
    "url": string | null,
    "attachments": [string],    // attachment names
    "group_path": [string],     // containing groups, root first; [] at the top level
    "tags": [string],           // the entry's own tags
    "inherited_tags": [string], // tags of containing groups, root first
    "matched"?: [string]        // search only: what caused the hit
  }
]
```

Daemon mode leaves out `path`; join `group_path` and `title` with `/` to get
it. `matched` names each surface that matched: `title`, `username`, `url`,
`notes`, `group_path`, `field <NAME>`, `tag <TAG>` or `attachment <NAME>`.

```json
[
  {
    "attachments": ["recovery.txt"],
    "group_path": ["Web"],
    "id": "73d1336a-9fc5-41d7-83e3-b4c15e03387a",
    "inherited_tags": ["team"],
    "matched": ["title", "url"],
    "path": "Web/forge",
    "tags": ["web"],
    "title": "forge",
    "url": "https://forge.example",
    "username": "octo"
  }
]
```

### `trove show --json`

One object:

```
{
  "path": string,
  "title": string,
  "username": string | null,
  "url": string | null,
  "notes": string | null,
  "password"?: string,          // only with --show-protected
  "fields": {string: string | null},
  "attachments": [string],
  "tags": [string],
  "inherited_tags": [string],
  "expires": string | null      // RFC 3339 UTC; null if it never expires
}
```

`fields` holds the custom fields, keyed by name. Offline, the values are
strings. In daemon mode they are all `null`: the summary carries names only, and
each value is a separate code-gated read, so fetch the ones you want with
`--attr`. Protected fields (`otp`) are left out unless `--show-protected` is
given.

```json
{
  "attachments": ["recovery.txt"],
  "fields": {"About.Purpose": "code hosting"},
  "inherited_tags": ["team"],
  "notes": "work account",
  "path": "Web/forge",
  "tags": ["web"],
  "title": "forge",
  "url": "https://forge.example",
  "username": "octo",
  "expires": null
}
```

### `trove describe --json`

An array with one object per described entry (one for an entry path, every
entry at or under it for a group path). Same shape in both modes:

```
[
  {
    "path": string,
    "username": string | null,
    "url": string | null,
    "notes": string | null,
    "has_password": bool,
    "attributes": {string: string},   // unprotected About.* fields
    "attachments": [
      {"name": string, "size": integer}   // size in bytes
    ]
  }
]
```

```json
[
  {
    "attachments": [{"name": "recovery.txt", "size": 6}],
    "attributes": {"About.Purpose": "code hosting"},
    "has_password": true,
    "notes": "work account",
    "path": "Web/forge",
    "url": "https://forge.example",
    "username": "octo"
  }
]
```

### `trove group list --json`

An array with one object per group, `Root` and empty groups included:

```
[
  {
    "path": string,             // "Root", "Web", "Web/Team"
    "tags": [string],           // the group's own tags
    "inherited_tags": [string]  // tags of its ancestors
  }
]
```

```json
[
  {"inherited_tags": [], "path": "Root", "tags": []},
  {"inherited_tags": [], "path": "Web", "tags": ["team"]}
]
```

### `trove db-info --json`

```
{
  "path": string,        // the --vault path as given
  "version": string,     // "KDBX4.1"
  "cipher": string,      // "AES256"
  "compression": string, // "GZip"
  "kdf": string,         // free-form description of the KDF and its parameters
  "entries": integer,
  "groups": integer,     // not counting the root group
  "recycle_bin": bool
}
```

```json
{
  "cipher": "AES256",
  "compression": "GZip",
  "entries": 1,
  "groups": 1,
  "kdf": "Argon2 { iterations: 50, memory: 1048576, parallelism: 4, version: Version13 }",
  "path": "/home/me/vaults/work.kdbx",
  "recycle_bin": false,
  "version": "KDBX4.1"
}
```

### `trove estimate --json`

```
{
  "length": integer,        // characters
  "guesses": integer,       // zxcvbn's guess estimate
  "entropy_bits": number,   // log2(guesses)
  "score": integer,         // 0 (weakest) to 4
  "warning": string | null,
  "suggestions": [string]
}
```

```json
{
  "entropy_bits": 12.972441366563535,
  "guesses": 8037,
  "length": 7,
  "score": 1,
  "suggestions": ["Add another word or two. Uncommon words are better."],
  "warning": "This is a very common password."
}
```

### `trove analyze --json`

```
{
  "checked_passwords": integer,   // looked up in the dump
  "breached_passwords": integer,
  "empty_passwords": integer,     // empty or missing, not looked up
  "findings": [
    {"entry_path": string, "breach_count": integer}   // a breached password
    | {"entry_path": string, "finding": "empty_password"}
  ]
}
```

A breached finding has `breach_count` and no `finding`; an empty one has
`finding` and no `breach_count`. The command exits 1 whenever `findings` is
not empty.

These four keys appear only with `--hibp`. The other checks add their own, each
present only when its check ran, and each non-empty list also exits 1:

```
{
  "reused"?: [{"entry_paths": [string]}],             // --reuse, largest group first
  "weak"?: [{"entry_path": string, "score": integer}], // --weak, weakest first
  "stale"?: [{"entry_path": string, "age_days": integer}] // --age, oldest first
}
```

```json
{
  "breached_passwords": 1,
  "checked_passwords": 1,
  "empty_passwords": 1,
  "findings": [
    {"breach_count": 1337, "entry_path": "Web/forge"},
    {"entry_path": "bare", "finding": "empty_password"}
  ]
}
```

### `trove status --json`

```
{
  "daemon_running": bool,
  "vault_paths": [string],                  // every unlocked vault
  "idle_timeout_seconds": integer | null,   // 0 when auto-lock is off
  "idle_remaining_seconds": integer | null, // null when no countdown is running
  "ssh_key_count": integer,
  "gpg_key_count": integer,
  "materialized_file_count": integer,
  "skipped_keys": [                          // keys the agents couldn't load
    {
      "agent": string,                       // "ssh" or "gpg"
      "vault": string,
      "entry": string,                       // full path, e.g. "Work/SSH/github"
      "attachment": string,
      "reason": string
    }
  ]
}
```

With no daemon running it still succeeds: `daemon_running` is `false`,
`vault_paths` and `skipped_keys` are empty, the counts are 0 and both timers
are `null`.

`skipped_keys` lists every key in the unlocked vaults that troved found but
couldn't load: a passphrase-protected key its entry's Password doesn't
decrypt, an RSA key under 2048 bits, an unsupported algorithm, a KeeAgent entry
that points at an external key file instead of holding the key, an OpenPGP
export with no signing key. `unlock` warns
about the same keys on stderr. The human `trove status` output lists them under
"Skipped keys" when there are any.

`--verbose` (`-v`) adds what each unlocked vault is serving. With `--json` that
is two more keys:

```
{
  "vaults": [{
    "path": string,
    "ssh_keys": [string],                              // entry paths
    "materialized": [{"title": string, "target_path": string}],
    "skipped_keys": [string]                           // one line per key, with the reason
  }],
  "gpg_keys": [string]                                 // all vaults: the agent doesn't track which
}
```

```json
{
  "daemon_running": true,
  "gpg_key_count": 1,
  "idle_remaining_seconds": 597,
  "idle_timeout_seconds": 600,
  "materialized_file_count": 1,
  "skipped_keys": [],
  "ssh_key_count": 1,
  "vault_paths": ["/home/me/vaults/work.kdbx"]
}
```

### `trove doctor --json`

```
{
  "ok": bool,          // false when any check failed
  "checks": [{
    "name": string,    // daemon, version, keys, daemons, ssh-agent, gpg-agent, vault, env-file
    "status": string,  // ok, info, warn or fail
    "detail": string,
    "hint": string | null
  }]
}
```

Printed whether or not a check failed; a failure also makes the command exit 1.
Which checks appear depends on the machine: `version` and `keys` only with a
daemon running, `daemons` only on Unix, `env-file` once per `.env.trove` found.

### `trove idle get --json`

```
{
  "timeout_seconds": integer,           // 0 when auto-lock is off
  "remaining_seconds": integer | null   // null when no countdown is running
}
```

```json
{"remaining_seconds": 597, "timeout_seconds": 600}
```

### `trove materialize-status --json`

```
{
  "materialized": [
    {
      "title": string,                          // entry title
      "target_path": string,
      "vault"?: string,                         // the unlocked vault it came from
      "ttl_remaining_seconds": integer | null,  // null without a TTL
      "exists": bool,                           // whether the file is there now
      "memory_backed": bool                     // true only on a Linux tmpfs
    }
  ]
}
```

`materialized` is `[]` when nothing is materialized. `memory_backed` is `false`
on macOS and Windows even for `/tmp`: neither has tmpfs, so the bytes are on
disk and the wipe on lock is best effort.

```json
{
  "materialized": [
    {
      "exists": true,
      "memory_backed": true,
      "target_path": "/run/user/1000/kubeconfig",
      "title": "kube",
      "ttl_remaining_seconds": 3597,
      "vault": "/home/me/vaults/work.kdbx"
    }
  ]
}
```

### `trove ssh-agent list --json`

The keys the main agent serves; `[]` when no daemon is running.

```
[
  {
    "algo": string,      // "ssh-ed25519"
    "blob_b64": string,  // base64 public-key blob, as in authorized_keys
    "comment": string,
    "expires_in_secs": number  // only when the entry sets a lifetime
  }
]
```

An entry whose `KeeAgent.settings` sets a lifetime (KeePassXC's "Remove key
from agent after") is served for that long after unlock, or after
`ssh-agent add` for a private socket. After that the key is no longer listed
and signing with it is refused, though the vault stays unlocked. Unlocking
again restarts the lifetime.

```json
[{"algo": "ssh-ed25519", "blob_b64": "AAAAC3NzaC1lZDI1NTE5AAAA…", "comment": "Infra/s1"}]
```

### `trove ssh-agent sockets --json`

The private sockets from `ssh-agent empty`, in creation order, each with its
keys in the `ssh-agent list` shape; `[]` when no daemon is running.

```
[
  {
    "socket": string,
    "keys": [{"algo": string, "blob_b64": string, "comment": string}]
  }
]
```

```json
[
  {
    "keys": [{"algo": "ssh-ed25519", "blob_b64": "AAAAC3NzaC1lZDI1NTE5AAAA…", "comment": "Infra/s1"}],
    "socket": "/run/user/1000/trove-ssh-3f9c0a1b2d4e5f60.sock"
  }
]
```

### `trove gpg-agent list --json`

The GPG keys the agent serves; `[]` when no daemon is running.

```
[
  {
    "keygrip": string,   // lowercase hex, gpg-agent's key identifier
    "key_type": string,  // algorithm/role, e.g. "ed25519/sign"
    "comment": string
  }
]
```

```json
[{"comment": "git-signing", "key_type": "ed25519/sign", "keygrip": "237e7f46842208d3fbe82251a64a3b8bab609a27"}]
```

### `trove daemons list --json`

Unix only. One object per daemon found; `[]` when there are none.

```
[
  {
    "control_socket": string,
    "lock_path": string,
    "pid": integer | null,    // null when the lockfile carries no PID
    "alive": bool,            // false: leftover files of a dead daemon
    "socket_exists": bool
  }
]
```

```json
[
  {
    "alive": true,
    "control_socket": "/run/user/1000/trove.sock",
    "lock_path": "/run/user/1000/trove.lock",
    "pid": 48213,
    "socket_exists": true
  }
]
```

### `trove keychain status --json`

macOS only. Never includes the stored password.

```
{
  "stored": bool,
  "vault": string   // the keychain account: the vault's absolute path
}
```

```json
{"stored": true, "vault": "/Users/me/vaults/work.kdbx"}
```

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

On Windows it prints the named pipe the agent listens on
(`\\.\pipe\trove-<hash>`, derived from that path), which is what Windows
OpenSSH needs in `SSH_AUTH_SOCK`: `$env:SSH_AUTH_SOCK = trove ssh-agent socket`.
`ssh-agent empty` prints pipe names there too.

### trove ssh-agent empty

```
trove ssh-agent empty [--add <PATTERN>] [--tag <TAG>]
```

Print the path to a **new, private** agent socket that serves no keys.

`sshd`'s `MaxAuthTries` defaults to **6**, counted per connection, and every key
an agent lists is offered and counted against that — the publickey query phase
carries no signature, but it still costs an attempt. The socket above serves
every key in every unlocked vault, which is what you want at a terminal and not
what a deployment tool wants: hold more than six keys and a server refuses the
connection before reaching one that sits past the sixth, with
`Received disconnect: Too many authentication failures`. Worse, `sshd` logs a
failure from the fourth offer onward, which is what `fail2ban` counts.

An agent with nothing in it makes no offers at all, so it is the safe base to
fill deliberately:

```sh
sock=$(trove ssh-agent empty) || exit 1
export SSH_AUTH_SOCK="$sock"
trove ssh-agent add "Infra/s1"
trove ssh-agent add "Infra/homelab"
pulumi up
```

Assign first, export second. `export VAR=$(cmd)` returns the status of `export`,
not of the command, so `export SSH_AUTH_SOCK="$(trove ssh-agent empty)"` passes
even when `empty` fails — including under `set -e` — and leaves `SSH_AUTH_SOCK`
set to the empty string. `ssh` reads that as no agent at all, so the failure
resurfaces later as `Permission denied (publickey)` with nothing pointing at
trove. `empty` writes nothing to stdout when it fails, so the separated form
gives you the real status.

Every call returns a **separate** socket with its own keys, so callers that run
in parallel can't disturb each other's offers. The daemon owns the lifetime: the
sockets go on `trove lock`, on idle-lock and at shutdown. A caller that is
finished with its socket before then — anything that runs repeatedly while the
vault stays unlocked — should hand it back with
[`trove ssh-agent close`](#trove-ssh-agent-close). A key that leaves the vault — because its entry was edited, removed
or moved — is dropped from these sockets at the same moment it is dropped from
the main one. Key material never leaves troved: a scoped socket is served by the
same agent code as the main one.

One daemon holds at most **32** of these at once. A caller that loops on
`ssh-agent empty` without closing would otherwise consume file descriptors until
the daemon stopped accepting anything; past the limit `empty` is refused with a
message naming `trove ssh-agent close` and `trove lock`.

Requires a daemon that is already running — it does not autospawn one. A daemon
with no vault unlocked holds no keys, so a socket it handed out could never be
filled.

`--add <PATTERN>` and `--tag <TAG>` create the socket and fill it in one step,
with the same matching as [`trove ssh-agent add`](#trove-ssh-agent-add):

```sh
sock=$(trove ssh-agent empty --tag gitlab) || exit 1
export SSH_AUTH_SOCK="$sock"
```

If nothing matches, `empty` fails, prints nothing, and closes the socket it made.

### trove ssh-agent add

```
trove ssh-agent add <ENTRY>
trove ssh-agent add [<PATTERN>] [--tag <TAG>]
```

Add entries' SSH keys to the agent named by `$SSH_AUTH_SOCK`.

`<ENTRY>` is the entry path (`Infra/s1`), or `Infra/s1:deploy` when the entry
holds more than one key. A glob adds every key whose entry path matches: `*`
matches any run of characters, `/` included, and `?` exactly one, so `Infra/*`
takes everything under `Infra`. Quote it so the shell doesn't expand it.
`--tag <TAG>` adds every key whose entry carries the tag, directly or through its
group. With a pattern and a tag, a key must match both. Nothing matching is an
error. Naming the entry rather than a fingerprint is the
point: whoever created it already knew which server it was for, so there is no
discovery step — and there could not be one, because nothing in the SSH protocol
enumerates the keys a server will accept.

The socket must be one `trove ssh-agent empty` handed out; any other is refused,
since filling it would mean handing the key to an agent trove doesn't run.
Adding a key that is already there refreshes it instead of duplicating it, so
re-running a script doesn't double its own offer count. Past six keys on one
agent you get a warning — that is exactly where the original failure returns.

Confirmation and warnings go to stderr; stdout stays empty so the command
composes in a script.

For the design rationale and alternatives considered, see
[the scoped SSH-agent socket design note](ssh-agent-empty-add.md).

### trove ssh-agent close

```
trove ssh-agent close [SOCKET]
```

Close one private socket that `trove ssh-agent empty` handed out: stop serving
it, drop its keys and remove the socket file. The other private sockets, and the
main agent, are left alone. Without `SOCKET` it closes the one named by
`$SSH_AUTH_SOCK`.

A script that runs often while the vault stays unlocked should release what it
made, or every run holds a socket until the next lock and the 32-socket limit is
eventually reached:

```sh
sock=$(trove ssh-agent empty) || exit 1
trap 'trove ssh-agent close "$sock"' EXIT
export SSH_AUTH_SOCK="$sock"
trove ssh-agent add "Infra/s1"
```

Only sockets from `empty` can be closed. The main agent socket, a socket from
another agent, and a socket that is already closed are refused with an error.
Confirmation goes to stderr; stdout stays empty.

### trove ssh-agent sockets

```
trove ssh-agent sockets [--json]
```

List the private sockets the daemon serves, in creation order, with the keys on
each one as indented `ssh-add -L` lines. Use it to find sockets a caller forgot
to close. Prints nothing (or `[]` with [`--json`](#trove-ssh-agent-sockets---json))
when no daemon is running.

### Telling the agent which server a key is for

`sshd`'s `MaxAuthTries` defaults to **6**, counted per connection, and every key
an agent lists is offered and counted against it — the publickey query phase
carries no signature, but it still costs an attempt. The agent serves every key
in every unlocked vault, so past six keys a server refuses the connection before
reaching one that sits later in the order, with `Received disconnect: Too many
authentication failures`. It reads as the server rejecting you. And `sshd` logs
a failure once the count reaches half the limit, so from the fourth offer onward
it is writing the lines `fail2ban` counts.

An entry can say which servers its key is for, in an `SshAgent.HostKeys` field.
When a key claims the host `ssh` is connecting to, only the keys that claim it
are offered:

```sh
trove edit "Infra/s1" --set "SshAgent.HostKeys=$(ssh-keyscan example.com)"
```

Raw `ssh-keyscan` output goes in unedited, and that is the recommended way to
fill it: `ssh-keyscan` authenticates nothing, so collecting a host key can never
itself contribute to a lockout. `SHA256:` fingerprints and plain OpenSSH
public-key lines are accepted too, mixed freely, one per line; `#` lines are
comments. **Record every host key a server offers, not just one** — a server
presents one per algorithm and which one a client sees depends on
`HostKeyAlgorithms` negotiation, so pinning only the Ed25519 key stops matching
the day a client prefers the RSA one. `ssh-keyscan` returns them all. On a
reinstall, append rather than replace.

How the agent learns which server it is being consulted for: `ssh` sends the
server's host key in a `session-bind@openssh.com` message as the **first** thing
on the connection, before asking for identities, and separately on every hop of
a `ProxyJump`. See [ssh-agent-session-bind.md](ssh-agent-session-bind.md) for
the measurement.

When nothing claims the host, every key is offered — exactly as an agent that
had never heard of this feature would behave. That is deliberate: a declaration
that has gone stale (a reinstalled server, a rotated host key) must not break a
machine that worked yesterday. The cost is that a stale declaration quietly
stops helping, which is what `ssh-agent which` is for. If you need a guarantee
rather than an optimisation, use `ssh-agent empty` + `add`, which offers exactly
what you named.

### trove ssh-agent which

```
trove ssh-agent which <TARGET>
```

Show which keys would be offered to a server, without connecting to it.

`<TARGET>` is a host (`example.com`, `example.com:2222`), a `SHA256:`
fingerprint, or a file of public-key lines. A bare host is resolved with
`ssh-keyscan`.

```
$ trove ssh-agent which example.com
host key: SHA256:ldas6Axt6VLStrod1bjlqu5dCT18edL/zIFqGdQqJjM
1 of the agent's keys declare this host; only these are offered:
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… Infra/s1
```

Three answers are possible: keys claim this host and only those are offered;
nothing claims any host, so all are offered as always; or keys claim other hosts
but none claims this one, so all are offered and the declarations are doing
nothing here. The last is what a rotated host key looks like from this side, and
without this command it is visible only in the server's auth log.

The offered keys go to stdout in `ssh-add -L` format; the explanation goes to
stderr, so `trove ssh-agent which host | …` pipes just the keys.

### Forwarding into your own ssh-agent

`SSH_AUTH_SOCK` is inherited at fork, so exporting it in a shell never reaches an
already-running editor. For those, unlock also pushes each key into whatever
agent `$SSH_AUTH_SOCK` already names — the KeePassXC model — and lock asks that
agent to drop them again. Per-entry behaviour comes from `KeeAgent.settings` and
is editable from KeePassXC itself; see `docs/macos.md`. `TROVE_SSH_FORWARD=0`
turns it off, and it does nothing when `$SSH_AUTH_SOCK` is unset or already
points at trove.

Note what this costs: the private bytes leave troved, so trove's lock can only
*ask* for them back. `IdentityAgent /path/to/trove-ssh.sock` in `~/.ssh/config`
solves the same reachability problem with nothing leaving the daemon.

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
ln -sf "$(trove gpg-agent socket)" "$(gpgconf --list-dirs agent-socket)"
```

### trove gpg-agent import

```
trove [--vault <PATH>] gpg-agent import [--print]
```

Import the public half of every vault GPG key into gpg's keyring. gpg only asks
an agent to sign with a key it already knows, so a key that lives only in the
vault is invisible to `gpg` and `git commit -S` until its public key is in the
keyring.

Each entry's `gpg-priv` secret-key export is cut down to its public packets
(public key and subkeys, user IDs, signatures), the bytes `gpg --export` would
give, and fed to `gpg --batch --import`. No secret key material reaches gpg.
Entries the agent wouldn't serve are left out. Importing again changes nothing.
The keyring keeps the keys after `trove lock`; `gpg --delete-keys <ID>` removes
one.

It never runs on its own at unlock: the keyring outlives the lock, so changing
it is a deliberate step.

| Flag | Description |
| --- | --- |
| `--print` | Write the public keys (binary OpenPGP) to stdout instead of importing them. Refuses a terminal. |
| `--vault <PATH>` | Global. Present → read that vault file; absent → the vaults unlocked in the daemon. |

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

## CLI and daemon versions

The CLI and `troved` are released together and only promise to understand
each other at the same version. After an upgrade, a daemon started by the old
version keeps running until it is stopped. Commands still work while the old
daemon understands them, with a warning that the versions differ
(`TROVE_NO_VERSION_WARN=1` silences it). A command the old daemon can't decode
fails with an error that names both versions and says to restart it: stop it
with `trove daemons kill --all` (on Windows, end `troved.exe`), then re-run.
The next command starts the current daemon, and vaults need unlocking again.

## trove doctor

```
trove [--vault <PATH>] doctor [--json]
```

Check the setup around trove and say what to fix. Read-only, and it never starts
a daemon.

| check | looks at |
| --- | --- |
| `daemon` | whether troved is running on the control socket this CLI uses |
| `version` | the running daemon is the same build as the CLI |
| `keys` | keys in the unlocked vaults the agents couldn't load, and why |
| `daemons` | live daemons on other sockets, and files left by dead ones (Unix) |
| `ssh-agent` | `SSH_AUTH_SOCK`: unset, trove's agent, a private one from `ssh-agent empty`, another live agent, or nothing listening |
| `gpg-agent` | whether gpg's agent socket (`gpgconf --list-dirs agent-socket`) is a symlink to trove's |
| `vault` | the vault from `--vault` or `TROVE_VAULT` opens and is KDBX 4 (KDBX 3.1 is a warning) |
| `env-file` | each `.env.trove` a bare `--env` would find is readable only by its owner |

Each line is `ok`, `info`, `warn` or `FAIL`, with a suggested fix under it where
there is one. Exits 1 if any check fails. See
[`trove doctor --json`](#trove-doctor---json) for the JSON form.

## trove daemons *(Unix only)*

```
trove daemons [list [--json]]
trove daemons kill (<SOCKET> | --all)
```

Where `trove status` probes only the one control-socket path it resolves,
`daemons` scans the runtime dirs — `$XDG_RUNTIME_DIR`, `${TMPDIR:-/tmp}`, and the
directory of any `$TROVE_SOCK` — for trove control sockets and their lockfiles.
That surfaces **orphans the single-path probe misses**: a wedged daemon, or a
stray from an old build that resolved its socket to a different path (the
singleton lock is keyed per socket path, so such a daemon runs alongside the
current one and is otherwise invisible).

`list` (the default) prints one daemon per line — `STATE  PID  SOCKET` — where
`STATE` is `live` (a running process holds the lock) or `stale` (leftover
files from a crashed/killed daemon). Liveness is decided by a non-blocking probe
of the singleton `flock`, which the kernel releases the instant the holder dies,
so it needs no PID bookkeeping; the PID is read from the lockfile the live daemon
stamped. [`--json`](#trove-daemons-list---json) emits an array of daemon
records. Read-only — never spawns a daemon.

`kill` stops a straggler. Pass a `SOCKET` from `list`, or `--all` for every
daemon found. A **live** daemon is asked to shut down over its control socket
(the graceful path — it wipes keys, removes its own sockets, and exits);
if it is wedged and won't answer, `kill` signals the stamped PID (`SIGTERM`,
then `SIGKILL`). Only a PID that still holds the live lock is ever signalled, so
a dead or reused PID is never hit. A **stale** entry just has its leftover
socket/lock files removed. Exits non-zero if any target could not be stopped.

## troved — the daemon

```
troved [--resident]
```

Long-running. Listens on three Unix sockets; serves clients until `shutdown` RPC, SIGINT, or SIGTERM. Removes its own socket files on exit.

Without `--resident`, it also exits once the last vault is locked (by `trove lock` or the idle timer) and nothing materialized is left to clean up; the next `trove` command starts a fresh one. `--resident` keeps it running after that, with its agent sockets up and empty, for a service manager to own. The launchd agent and systemd user unit in [`packaging/`](../packaging/) and `brew services start trove` all run `troved --resident` and restart it if it dies, but not after a clean exit.

Permission model: every socket is bound by the daemon, then `chmod 0600` so only the same UID can connect.

## The `.env.trove` file

A dotenv `KEY=VALUE` file or YAML password map, loaded only when `--env` is
passed. Nothing is read without that flag: an exported password must never
silently open a vault for a command that didn't ask for one.

### Where it is found

| form | reads |
| --- | --- |
| `--env` | `./.env.trove`, then `<vault dir>/.env.trove` |
| `--env=<dir>` | `<dir>/.env.trove` |
| `--env=<file>` | exactly that file |

**A path must be attached with `=`.** `--env=<PATH>`, never `--env <PATH>`. An
option whose value is optional otherwise takes whatever follows it, and what
follows it is usually the subcommand — `trove --vault v --env git-credential
get` read `git-credential` as the path and then ran `trove get`. That is the
credential-helper invocation exactly, since git appends the operation to
whatever `credential.helper` holds, so the one command `--env` exists to serve
was the one command it broke. Writing the space-separated form now explains
itself rather than failing as an unknown subcommand.

Flags were never affected: `--env --keychain status` has always parsed, because
a `-`-prefixed token is not taken as an optional value.

Bare `--env` tries the working directory first, so a project checkout can override,
then the directory holding the vault being opened — which is where the file belongs
when a vault and its settings are kept together (`~/vaults/work.kdbx` beside
`~/vaults/.env.trove`). When neither exists, the error names both places it looked.

`--env=<file>` naming a file that does not exist is a **hard error**, never a silent
fallback: you named that path, so a typo must not be papered over by prompting or by
reading something else.

There is deliberately no user-wide config location. `~/.config` ends up committed to
dotfile repositories, and this file holds a vault password.

### Syntax

For one shared password, the dotenv format remains available:

```sh
# comments and blank lines are ignored
TROVE_VAULT_PASSWORD=correct horse battery staple
export TROVE_VAULT=/Users/me/vaults/work.kdbx   # an `export ` prefix is allowed
TROVE_IDLE_TIMEOUT="900"                        # quotes are optional
```

For several databases, dotenv profiles pair a `_FILE` value with a `_PASSWORD`
value. The file must match the exact vault filename, including `.kdbx`:

```dotenv
TROVE_VAULT_WORK_FILE=work.kdbx
TROVE_VAULT_WORK_PASSWORD="work vault password"
TROVE_VAULT_PERSONAL_FILE=personal.kdbx
TROVE_VAULT_PERSONAL_PASSWORD="personal vault password"
```

The profile name (`WORK` or `PERSONAL` here) links each pair of variables; it
does not need to resemble the filename. Dotenv profiles can share a file with
other settings such as `TROVE_IDLE_TIMEOUT`.

Alternatively, `.env.trove` can be a YAML mapping from the exact vault filename
to its password:

```yaml
work.kdbx: "work vault password"
personal.kdbx: "personal vault password"
```

With either format, `trove unlock work.kdbx --env` uses the work password, while
unlocking `personal.kdbx` uses the personal password. The YAML form is a
credentials map; dotenv settings such as `TROVE_IDLE_TIMEOUT` cannot be mixed
into that same file. `TROVE_VAULT_PASSWORD`, when set, takes precedence over a
matching profile or YAML entry.

In dotenv form there is no interpolation or multi-line values — this holds
configuration and a password, not a shell script. A variable **already set in the
environment wins**, so the file supplies defaults rather than overriding its caller.

Every trove variable can live in dotenv form, not just the password:
`TROVE_VAULT`, `TROVE_IDLE_TIMEOUT`, and the socket paths. `TROVE_VAULT` selects
the default offline vault for commands that accept `--vault`; `--vault <PATH>`
overrides it. For bare `--env`, trove searches the working directory first and
then beside an explicit `--vault` (or the positional vault for `unlock`). The
YAML form is for the per-vault password map.

### Permissions

The file holds a vault password, so trove warns when it is readable by more than its
owner:

```
trove: warning: .env.trove is mode 0644 — readable by more than its owner,
and it holds a vault password. Fix with: chmod 600 .env.trove
```

`TROVE_ENV_STRICT=1` turns that warning into a refusal, which is what `ssh` does with a
private key at 0644. It is not the default because an env file need not live where mode
bits mean anything: iCloud Drive does not guarantee POSIX modes survive a sync, so 0600
on one Mac can arrive 0644 on the next, and a volume mounted `noowners` ignores them
entirely. Refusing on that evidence would break unlocks for something the user did not
cause and cannot fix from that machine.

Keep it `0600`, and do not export the password into your shell — an exported variable is
inherited by every child process.

### Where the password comes from

More than one source can supply a vault password. They are tried in this order:

| order | source | can it block? |
| --- | --- | --- |
| 1 | `--env` file | no |
| 2 | `--password-stdin` | no |
| 3 | `--keychain` (macOS login keychain) | yes — needs a terminal |
| 4 | interactive prompt | yes — needs a terminal |

`--env` and `--password-stdin` are safe to give together: passing both is probably a
mistake, but the file simply wins and stdin is there if it yields nothing.

`--keychain` always loses to both, and refuses outright when there is no interactive
terminal. Reading the keychain can raise a system dialog — `brew upgrade` replaces the
binary, and an unfamiliar binary asking for an item prompts — and a dialog on a Mac you
are not sitting at is a command that never returns. When `--keychain` is combined with a
higher-priority source, trove says which one won rather than leaving it ambiguous.


### troved environment variables

All env vars are read at process start.

`--env` loads them from a file first — see [The `.env.trove` file](#the-envtrove-file).

| Env var | Default | Effect |
| --- | --- | --- |
| `TROVE_VAULT` | (unset) | Default path for offline commands that accept `--vault`. An explicit `--vault <PATH>` takes precedence. `unlock` uses its positional vault argument. |
| `TROVE_SOCK` | `$XDG_RUNTIME_DIR/trove.sock` or `${TMPDIR:-/tmp}/trove-$UID.sock` | Path of the control socket. |
| `TROVE_SSH_SOCK` | `$XDG_RUNTIME_DIR/trove-ssh.sock` or `${TMPDIR:-/tmp}/trove-ssh-$UID.sock` | Path of the SSH agent socket. |
| `TROVE_GPG_SOCK` | `$XDG_RUNTIME_DIR/trove-gpg.sock` or `${TMPDIR:-/tmp}/trove-gpg-$UID.sock` | Path of the GPG agent socket. |
| `TROVE_IDLE_TIMEOUT` | `900` | Idle-lock timeout in seconds. `0` disables auto-lock. Non-numeric values warn and fall back to default. Also the default lifetime constraint on forwarded SSH keys. |
| `TROVE_SSH_FORWARD` | (on) | Set to `0` / `false` / `no` / `off` to stop pushing unlocked SSH keys into the agent named by `$SSH_AUTH_SOCK`. Read on every unlock, not just at start. Forwarding is already inert when `$SSH_AUTH_SOCK` is unset or points at trove's own socket. |
| `TROVE_SSH_OPENSSH_PIPE` | (on) | Windows only. Set to `0` to stop troved also serving `\\.\pipe\openssh-ssh-agent`, the pipe Windows OpenSSH uses when `SSH_AUTH_SOCK` is unset. It is only taken when free. |
| `TROVE_SSH_STRICT_HOSTKEYS` | (off) | Set to `1` / `true` / `yes` to answer a server that no key's `SshAgent.HostKeys` declares with an empty identity list, instead of falling back to offering everything. Read once when the agent socket is bound. Turns a stale declaration from a missed optimisation into a refused connection — which is the point, and why it is off by default. |
| `TROVE_VAULT_PASSWORD` | (unset) | Vault password, used **only** with `--env` (see above). Prefer keeping it in a `0600` `.env.trove` that is never exported — an exported variable is inherited by every child process. |
| `TROVE_VAULT_<NAME>_FILE` / `TROVE_VAULT_<NAME>_PASSWORD` | (unset) | Named password profile, used **only** with `--env`. `_FILE` matches the exact vault filename; `_PASSWORD` supplies its password. |
| `TROVE_ENV_STRICT` | (off) | Set to `1` / `true` / `yes` / `on` to make `--env` **refuse** a file readable by more than its owner, instead of warning. macOS/Unix only. |
| `TROVE_SPAWN_TIMEOUT_SECS` | `5` | How long a client waits for an auto-spawned daemon's socket to become reachable before erroring. Raise on slow/loaded machines. |
| `XDG_RUNTIME_DIR` | (system) | Used in default socket-path resolution. |
| `TMPDIR` | `/tmp` | Used as fallback when `XDG_RUNTIME_DIR` is unset/empty. |
| `UID` | `0` | Used in the `$TMPDIR` fallback path only. (`UID` is rarely set by login shells; the fallback path is essentially "/tmp/trove-0.sock" in practice — set `TROVE_SOCK` explicitly if running multi-user on a shared machine.) |
| `HOME` | (system) | Used by the materialize path resolver to expand `~` / `$HOME` in a materialize target. |

The CLI's `ssh-agent socket` / `gpg-agent socket` subcommands resolve the same way as the daemon, so they always agree (no need to pass `TROVE_*` to both).

### Control protocol (line-JSON)

Connect to the control socket, write one JSON object per line, read one response per line. The protocol is defined in [crates/troved/src/protocol.rs](../crates/troved/src/protocol.rs).

Request envelope: `{"cmd": "<name>", ...}`. Response envelope: `{"status": "ok"|"err", ...}`.

| `cmd` | Request fields | Response on success | Notes |
| --- | --- | --- | --- |
| `ping` | none | `{"status":"ok","pong":true}` | Heartbeat. Does **not** reset the idle timer. |
| `unlock` | `path: string`, `password: string`, `filter?: string` | `{"status":"ok","code","daemon_version","materialize_warnings":[…],"ssh_forward_warnings":[…]}` | **Additive** — adds this vault to the unlocked set rather than replacing it, and the SSH/GPG stores are rebuilt from the union of every open vault (see [multi-vault.md](multi-vault.md)). Re-unlocking a vault already open replaces just that one. When `filter` is present, only entries carrying that KeePass-native tag are exposed through the agents and materialization. Otherwise runs materialization (creating any missing parent dirs of a target, mode 0700). Synchronous: `ok` only after every selected materialized file is on disk. A per-entry materialization failure does **not** fail the unlock (spec: one bad entry must not break the vault) but is reported in `materialize_warnings` (omitted when empty) so the CLI warns loudly — never a silent `ok` with a configured file missing. A target another unlocked vault already materialized is skipped and warned about, never overwritten. Also forwards the selected SSH keys into the agent named by `$SSH_AUTH_SOCK`, under the same contract: never fails the unlock, per-key failures land in `ssh_forward_warnings` (omitted when empty). |
| `list` | none | `{"status":"ok","entries":[{"id","title","username","url","attachments"}, ...]}` | The union across every unlocked vault, in unlock order. Errors if none is unlocked. |
| `lock` | `vault: string` *(optional)* | `{"status":"ok"}` | Without `vault`: wipes all materialized files, drops every vault, clears the SSH+GPG stores, cancels the idle timer. With `vault`: drops only that vault, wipes only **its** materialized files, rebuilds the key stores from what is still open, and keeps the idle timer armed; errors if no vault is unlocked at that path. Either way, keys that dropped out of the store are also removed from the agent named by `$SSH_AUTH_SOCK` (unless the entry set `RemoveAtDatabaseClose=false`); keys another still-unlocked vault provides stay. Idempotent. |
| `shutdown` | none | `{"status":"ok"}` | Same as `lock`, then signals the daemon main loop to exit. |
| `materialize-status` | none | `{"status":"ok","materialized":[{"title","target_path","vault","ttl_remaining_seconds","exists"}, ...]}` | Read-only; works even with every vault locked (returns empty array). `vault` names the unlocked vault the file came from. |
| `set-idle-timeout` | `seconds: u64` | `{"status":"ok"}` | `0` disables auto-lock. Takes effect immediately; if the new timeout has already elapsed, the timer fires on the next driver wake. |
| `get-idle-timeout` | none | `{"status":"ok","seconds": u64, "remaining": u64\|null}` | `seconds` is the configured timeout. `remaining` is seconds-until-fire if a vault is unlocked, else `null`. |

Error responses: `{"status":"err","error":"<message>"}`. Errors do not close the connection — you can pipeline more commands.

The `unlock` request payload contains the master password in cleartext. The connection is a Unix socket bound `0600`; treat it the way you'd treat any other same-UID IPC channel.

### SSH agent protocol

Standard OpenSSH agent protocol on a separate socket. We implement:

- `SSH_AGENTC_REQUEST_IDENTITIES` (11) → `SSH_AGENT_IDENTITIES_ANSWER` (12)
- `SSH_AGENTC_SIGN_REQUEST` (13) → `SSH_AGENT_SIGN_RESPONSE` (14)
- `SSH_AGENTC_REMOVE_IDENTITY` (18) and `SSH_AGENTC_REMOVE_ALL_IDENTITIES` (19) (`ssh-add -d` / `-D`)
- `SSH_AGENTC_LOCK` (22) and `SSH_AGENTC_UNLOCK` (23) (`ssh-add -x` / `-X`)
- `SSH_AGENTC_EXTENSION` (27) for `session-bind@openssh.com`

Anything else returns `SSH_AGENT_FAILURE` (5). Supported algorithms: ed25519, RSA >= 2048 bits (signs with rsa-sha2-256 / rsa-sha2-512 per RFC 8332 flag selection), ECDSA P-256, P-384 and P-521.

`ssh-add` and friends will only see identities for entries whose `id` attachment parses as one of the supported algorithms. Keys are read in OpenSSH, PEM (PKCS#1, PKCS#8) or PuTTY `.ppk` (v2 and v3) format; a `.ppk` attachment, which KeeAgent users on Windows often have, is served as it is. A passphrase-protected OpenSSH key is decrypted with its entry's Password, as KeePassXC does. Weak (RSA < 2048), unsupported (DSA, Ed448), passphrase-protected `.ppk`, or protected keys the Password doesn't decrypt are skipped at unlock time with a one-line warning to stderr.

### GPG Assuan protocol

Standard Assuan ASCII protocol on a separate socket. The implemented commands are documented in [crates/troved/src/gpg_agent/](../crates/troved/src/gpg_agent/). It covers `git commit -S` signing and `gpg --decrypt` with ed25519/cv25519 and RSA OpenPGP keys. Unknown commands return `ERR <code> <message>` so clients fail cleanly rather than hang.

## Per-entry custom-field schema

The materialize feature is wholly expressed as kdbx custom string fields, so the vault stays openable and round-trippable in KeePassXC.

| Field | Required | Type | Effect |
| --- | --- | --- | --- |
| `Materialize.<attachment>.Target` | yes | string | Path to materialize that attachment to. `~`, `$HOME`, `$XDG_RUNTIME_DIR` are expanded against the daemon's environment. The attachment must exist on the entry. |
| `Materialize.<attachment>.Mode` | no | octal string (3 or 4 digits) | File mode. Default `0600`. |
| `Materialize.<attachment>.TTL` | no | positive integer seconds | Wipe the file after N seconds even if the vault stays unlocked. |
| `Materialize.<attachment>.AllowDiskBacked` | no | `"true"` / `"false"` (case-insensitive; `"yes"` / `"1"` also accepted) | Allow a non-tmpfs target. Default `false`. |

`<attachment>` is the attachment's name, dots and all:
`Materialize.id_ed25519.pub.Target` describes the attachment `id_ed25519.pub`.

Renaming an attachment moves these with it — see `trove rename-attachment`.

Changes made through the daemon while the vault is unlocked take effect at
once: a new or changed plan is written, and the file behind a removed or
changed plan (entry deleted, target, mode, TTL or content changed) is wiped.
Plans a write doesn't change are left alone, so a live file isn't rewritten and
one its TTL already wiped doesn't come back. Changes KeePassXC makes to the file
on disk aren't seen until the next unlock. Problems go to the daemon's log
rather than the write's reply.

The entry-level `Materialize.Source` / `Materialize.Target` form was removed:
materialization describes a file, and an entry holds several. An entry still
carrying those fields is reported as an error on unlock rather than ignored,
naming what to rename them to.

Plus the implicit attachment slots used by SSH and GPG:

| Attachment slot | Used by | Format |
| --- | --- | --- |
| `id` | SSH agent | OpenSSH private key (PEM-armored or raw, unencrypted). |
| `gpg-priv` | GPG agent | OpenPGP secret-key packets (binary, NOT armored). |
