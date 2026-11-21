# Control-socket RPC

`troved` listens on a control socket. The `trove` CLI and the desktop app talk
to it, and so can scripts. This page is the contract: which requests are
stable, what they take and return, the error kinds, and how the protocol is
versioned. It is checked by `crates/troved/tests/rpc_contract.rs`.

Requests marked **stable** follow the rules in [Versioning](#versioning) and
the [stability promise](stability.md). Requests marked **internal** exist for
the CLI and the desktop app and may change in any release; from a script, run
the matching `trove` command with `--json` instead.

## Transport

**Socket path.** The first of these that applies:

1. `$TROVE_SOCK`
2. `$XDG_RUNTIME_DIR/trove.sock`, when `XDG_RUNTIME_DIR` is set and not empty
3. `$TMPDIR/trove-$UID.sock`, with `/tmp` when `TMPDIR` is unset

On Windows (experimental) the socket is a named pipe, `\\.\pipe\trove-<hash>`,
derived from the same path.

**Permissions.** The socket is created `0600`, so only the user who started the
daemon can connect. Code-gated requests also check the peer's uid against the
uid that unlocked. `unlock` carries the master password in clear text over this
socket; treat the connection like any other same-uid IPC channel.

**Framing.** One JSON object per line, UTF-8, `\n`-terminated, in each
direction. Each request gets exactly one response line, in order, so requests
can be pipelined on one connection. Blank lines are ignored. An error response
never closes the connection; `shutdown`, and a `lock` that leaves nothing
unlocked, end the daemon after the reply is written.

**Envelope.** A request is `{"cmd": "<name>", ...fields}`. A response is
`{"status": "ok", ...fields}` or `{"status": "err", "kind": "<kind>", "error":
"<message>"}`.

**Autospawn.** The daemon is not started for you. `trove unlock` starts it;
a script can do the same, or check with `ping` first.

Example:

```sh
printf '{"cmd":"get-version"}\n' | socat - UNIX-CONNECT:"$XDG_RUNTIME_DIR/trove.sock"
# {"status":"ok","daemon_version":"0.27.1","protocol_version":1}

# nc -U works too (on macOS, -w keeps it open long enough to read the reply)
printf '{"cmd":"ping"}\n{"cmd":"status"}\n' | nc -U -w 1 "$TROVE_SOCK"
```

## Errors

Every error response has a `kind`. Scripts branch on `kind`; the `error` text
is for people and may change in any release.

| `kind` | Meaning |
| --- | --- |
| `unknown-command` | The `cmd` names no request this daemon knows. `error` is `unknown command: <cmd>`. Usually the daemon is older than the client. |
| `invalid-request` | The line is not a JSON object, has no string `cmd`, or a field is missing or has the wrong type. `error` starts with `invalid request: `. |
| `locked` | Nothing is unlocked, or (for `lock` with `database`) not that database. |
| `session-refused` | A code-gated request was refused: the session code is missing or wrong, it came from another uid, or nothing is unlocked. These are one kind on purpose, so a caller can't tell them apart. |
| `failed` | Anything else: entry not found, a write that failed, and so on. |

New kinds may be added in a minor release; treat a kind you don't know as
`failed`. A daemon from before protocol version 1 sends no `kind` at all.

## Versioning

`get-version` reports `protocol_version`, currently `1`. A daemon that answers
`get-version` without it predates the versioned protocol.

- Adding a request, an optional request field or a response field does **not**
  change `protocol_version`. Clients must ignore response fields they don't
  know.
- Removing or renaming a stable request or field, changing a field's type, or
  changing what an existing field means **bumps** `protocol_version`.
- A stable request or field is deprecated for at least one minor release
  before it goes, as the [Deprecation](stability.md#deprecation) section of
  the stability promise describes.
- `daemon_version` is the build string. The CLI warns when it differs from its
  own; scripts should compare `protocol_version` instead.

## Session codes

`unlock` returns a session `code` (unless it was sent `"session": false`).
Code-gated requests carry it as `code`. The daemon accepts it only from the uid
that unlocked, and it lasts until nothing is left unlocked. The CLI passes it
around as `TROVE_SESSION`.

## Idle timer

Most requests count as activity and restart the idle-lock timer. The ones
marked "does not reset the idle timer" below are read-only probes, so a status
bar polling them doesn't keep the databases open forever.

## Stable requests

Field types: `string`, `integer` (unsigned), `bool`, `null`. A `?` marks a
field that is optional in a request, or may be absent from a response.

### `ping`

Request: no fields. Response: `{"status":"ok","pong":true}`. No session code.
Does not reset the idle timer.

### `get-version`

Request: no fields. Response: `{"status":"ok","daemon_version":string,
"protocol_version":integer}`. Works whether or not anything is unlocked. No
session code. Does not reset the idle timer.

### `status`

Request: no fields. Response:

```
{"status":"ok",
 "database_path": string|null,       // first unlocked database
 "database_paths"?: [string],        // every unlocked database, unlock order; absent when none
 "idle_timeout_secs": integer,       // 0 = auto-lock off
 "idle_remaining_secs": integer|null,
 "ssh_keys": integer, "gpg_keys": integer, "materialized": integer,
 "skipped_keys"?: [{"agent","database","entry","attachment","reason"}]}  // all strings
```

Works with nothing unlocked. No session code. Does not reset the idle timer.

### `unlock`

Request:

| Field | Type | |
| --- | --- | --- |
| `path` | string | Database file. |
| `password` | string | Master password. |
| `timeout` | integer? | Idle-lock timeout in seconds to set; `0` turns auto-lock off. Absent keeps the current setting. |
| `keyfile` | string? | Key file contents, base64, for a composite key. |
| `filter` | string? | KeePass tag; only entries carrying it are served by the agents and materialized. |
| `session` | bool? | `false` declines a session code. Absent or `true` mints one. |

Response:

```
{"status":"ok",
 "code"?: string,                    // absent when "session": false
 "daemon_version": string,
 "materialize_warnings"?: [string],
 "skipped_keys"?: [{"agent","database","entry","attachment","reason"}],
 "ssh_forward_warnings"?: [string],
 "ssh_forward_notes"?: [string],
 "ssh_forward_socket"?: string}
```

Adds the database to the unlocked set (unlocking one already open replaces
it), materializes files and forwards SSH keys as described in
[cli-reference.md](cli-reference.md#trove-unlock). A failure in one entry is a
warning, not an error. Errors: `failed` (wrong password, unreadable file).
No session code. Resets the idle timer.

### `lock`

Request: `database`: string? — the database file to lock. Absent locks every
database. Response: `{"status":"ok"}`.

Wipes the locked databases' materialized files and removes their keys from the
agents. When nothing is left unlocked (and no materialized file needs cleaning
up) the daemon exits after replying, unless it runs with `--resident`. Without
`database` it is idempotent. Errors: `locked` when `database` names one that
isn't unlocked. No session code.

### `list`

Request: no fields. Response: `{"status":"ok","entries":[entry]}` where entry
is:

```
{"id": string, "title": string, "username": string|null, "url": string|null,
 "attachments": [string], "group_path": [string], "tags": [string],
 "inherited_tags": [string]}
```

Every unlocked database, in unlock order. Errors: `locked`. No session code.
Resets the idle timer.

### `search`

Request:

| Field | Type | |
| --- | --- | --- |
| `term` | string? | Matched against unprotected fields. |
| `fields` | [string]? | `Name` (has the field) or `Name=value`. |
| `tags` | [string]? | Entry or inherited tags. |
| `attachments` | [string]? | Attachment names. |

At least one of them is required. Response: as `list`, with each entry also
carrying `matched`: [string] (which surfaces matched). Protected values never
match. Errors: `locked`, `failed` (no term or filter). No session code. Resets
the idle timer.

### `describe`

Request: `path`: string — an entry, or a group for every entry in it.
Response:

```
{"status":"ok","descriptions":[
  {"path": string, "username": string|null, "url": string|null,
   "notes": string|null, "has_password": bool,
   "attributes": {"<name>": string},
   "attachments": [{"name": string, "size": integer}]}]}
```

Needs exactly one unlocked database. Errors: `locked`, `failed`. No session
code. Does not reset the idle timer.

### `show-entry`

Request: `path`: string. Response: `{"status":"ok","entry":{...}}` with:

```
{"id": string, "title": string, "username": string|null, "url": string|null,
 "notes": string|null, "custom_fields": [string], "attachments": [string],
 "group_path": [string], "tags": [string], "inherited_tags": [string],
 "expires": string|null, "icon": integer|null}
```

`custom_fields` holds names only, never values. Errors: `locked`, `failed`
(not found, ambiguous). No session code. Resets the idle timer.

### `materialize-status`

Request: no fields. Response:

```
{"status":"ok","materialized":[
  {"title": string, "target_path": string, "database"?: string,
   "ttl_remaining_seconds": integer|null, "exists": bool,
   "memory_backed": bool}]}
```

Works with nothing unlocked (empty list). No session code. Does not reset the
idle timer.

### `get-idle-timeout`

Request: no fields. Response: `{"status":"ok","seconds":integer,
"remaining":integer|null}`. `remaining` is `null` when nothing is unlocked or
auto-lock is off. No session code. Does not reset the idle timer.

### `set-idle-timeout`

Request: `seconds`: integer, `0` turns auto-lock off. Response:
`{"status":"ok"}`. No session code. Resets the idle timer.

### `ssh-agent-list`

Request: no fields. Response: `{"status":"ok","ssh_keys":[{"algo": string,
"blob_b64": string, "comment": string, "expires_in_secs"?: integer}]}`. Empty
when nothing is unlocked. No session code. Does not reset the idle timer.

### `gpg-agent-list`

Request: no fields. Response: `{"status":"ok","gpg_keys":[{"keygrip": string,
"key_type": string, "comment": string}]}`. Empty when nothing is unlocked. No
session code. Does not reset the idle timer.

### `get-field`

Request: `path`: string, `field`: string, `code`: string. Response:
`{"status":"ok","value":string}`. This is how a password leaves the daemon.
Errors: `session-refused`, `failed` (not found, no such field). Session code
required. Resets the idle timer.

### `get-totp`

Request: `path`: string, `code`: string. Response: `{"status":"ok",
"totp_code": string, "valid_for_secs": integer, "period_secs": integer}`. The
shared secret never crosses the socket. Errors: `session-refused`, `failed`.
Session code required. Resets the idle timer.

## Internal requests

Internal, may change in any release. Use the matching `trove` command with
`--json` instead.

- `shutdown`
- `gpg-public-keys`
- `ssh-agent-empty`
- `ssh-agent-add`
- `ssh-agent-add-matching`
- `ssh-agent-close`
- `ssh-agent-sockets`
- `ssh-agent-which`
- `get`
- `add-ssh`
- `add-gpg`
- `add-file`
- `settings`
- `set-settings`
- `git-credential`
- `add-password`
- `edit-entry`
- `remove-entry`
- `move-entry`
- `copy-entry`
- `move-group`
- `copy-group`
- `mkdir`
- `rmdir`
- `add-totp`
- `set-expiry`
- `set-icon`
