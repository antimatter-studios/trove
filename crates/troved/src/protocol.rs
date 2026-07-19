//! Wire protocol for the troved Unix socket.
//!
//! Newline-delimited JSON. One request per line, one response per line.
//! Requests are tagged on `cmd`; responses on `status` (`"ok"` / `"err"`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
pub enum Request {
    Ping,
    Unlock {
        path: String,
        // NOTE: sensitive — never Debug-print a Request that may carry this.
        password: String,
        /// Optional idle-lock timeout (seconds) to set as part of this
        /// unlock. `Some(0)` disables auto-lock. `None` keeps whatever the
        /// daemon already has configured (env var default, or whatever a
        /// prior `set-idle-timeout` left behind). Wire-optional for back-compat.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout: Option<u64>,
        /// Optional keyfile bytes (base64) for a composite-key vault. The
        /// daemon holds the decoded bytes in Vault memory so its own
        /// re-saves derive the same composite key. Wire-optional for
        /// back-compat.
        // NOTE: sensitive — key material. Never Debug-print.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        keyfile: Option<String>,
    },
    List,
    Lock,
    Shutdown,
    /// Inspect what the daemon has currently materialized. Read-only; works
    /// even if the vault is locked (returns an empty list in that case).
    /// Added in v0.0.5.0.
    MaterializeStatus,
    /// v0.0.6.0: configure the idle-lock timeout (in seconds). 0 disables.
    SetIdleTimeout {
        seconds: u64,
    },
    /// v0.0.6.0: read the current idle-lock state.
    GetIdleTimeout,
    /// Return the daemon's build version so a connecting CLI can flag a
    /// CLI↔daemon drift (a stale sibling `troved` left behind by a CLI-only
    /// rebuild). Read-only; works whether or not a vault is unlocked.
    GetVersion,
    /// v0.0.9.0: snapshot of daemon state — vault path (if unlocked), idle
    /// timer state, and counts of in-memory secret stores. Read-only.
    Status,
    /// List the SSH keys the agent is currently serving (analogous to
    /// `ssh-add -L`). Read-only; returns an empty list when locked.
    SshAgentList,
    /// List the GPG keys the agent is currently serving. Read-only; returns an
    /// empty list when locked.
    GpgAgentList,
    /// Code-gated extraction over the unlocked daemon. Reads `attachment` (e.g.
    /// "id" for an SSH key) from the entry titled `title` and returns its bytes
    /// base64-encoded. Requires a vault unlocked by the same uid as the caller
    /// (SO_PEERCRED) and the session `code` minted by `Unlock`. Refused when
    /// locked or when the code is absent/wrong. See docs/provisioning-sessions.md.
    Get {
        title: String,
        attachment: String,
        // NOTE: sensitive — the session capability. Never Debug-print verbatim.
        code: String,
    },
    /// Code-gated write: store an SSH private key on the unlocked daemon's
    /// vault. `path` is the entry path (`group/.../title`, created mkdir-p if
    /// absent; an existing entry has its `id` attachment replaced). `key` is the
    /// private-key bytes, base64-encoded. Same session gate as `Get` (vault
    /// unlocked by the same uid + matching `code`). On success the daemon
    /// persists with `save()` and reloads the SSH agent key store so the new
    /// key is served immediately. See docs/provisioning-sessions.md.
    AddSsh {
        path: String,
        // NOTE: sensitive — base64 of the private key bytes. Never Debug-print.
        key: String,
        /// Public-key comment for the derived `id.pub` (usually an email).
        /// Absent → the daemon falls back to `path`, preserving old behaviour.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
        // NOTE: sensitive — the session capability. Never Debug-print verbatim.
        code: String,
    },
    /// Code-gated write: store a GPG secret-key export (binary OpenPGP packet
    /// stream) on the unlocked daemon's vault under the `gpg-priv` attachment of
    /// the entry titled `title` (created mkdir-p if absent). `key` is the export
    /// bytes, base64-encoded. Same session gate as `AddSsh` (vault unlocked by
    /// the same uid + matching `code`). On success the daemon persists with
    /// `save()` and reloads the GPG key store so any ed25519 secret keys are
    /// served by the agent without a re-unlock.
    AddGpg {
        title: String,
        // NOTE: sensitive — base64 of the GPG secret-key export. Never Debug-print.
        key: String,
        // NOTE: sensitive — the session capability. Never Debug-print verbatim.
        code: String,
    },
    /// Code-gated write: store an arbitrary file as a real `<Binary>` attachment
    /// named `name` on the entry titled `title` (created mkdir-p if absent),
    /// plus the `Materialize.*` custom fields describing where it should land on
    /// a future unlock. `src` is the file bytes, base64-encoded; the CLI
    /// resolves `name` (defaulting to the source basename) before sending. Same
    /// session gate as `AddSsh`. Persists with `save()` only — it does NOT
    /// materialize into the current session (the file lands on disk on the next
    /// unlock).
    AddFile {
        title: String,
        // NOTE: sensitive — base64 of the file bytes. Never Debug-print.
        src: String,
        name: String,
        target: String,
        mode: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl: Option<u64>,
        allow_disk_backed: bool,
        // NOTE: sensitive — the session capability. Never Debug-print verbatim.
        code: String,
    },
    /// Read one entry's non-secret surface: standard unprotected fields plus
    /// the NAMES of custom fields and attachments. Never returns Password or
    /// other protected values (use `GetField` for those — it is code-gated).
    /// Ungated beyond "a vault is unlocked", exactly like `List`.
    ShowEntry {
        path: String,
    },
    /// Case-insensitive substring search over unprotected fields and group
    /// paths. Returns `List`-shaped summaries; never matches secret values.
    /// Ungated beyond "a vault is unlocked", exactly like `List`.
    Search {
        term: String,
    },
    /// Code-gated single-field read (this is how Password values leave the
    /// daemon). Same session gate as `Get`.
    GetField {
        path: String,
        field: String,
        // NOTE: sensitive — the session capability. Never Debug-print verbatim.
        code: String,
    },
    /// Code-gated write: create a password entry at `path` (groups mkdir-p).
    AddPassword {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
        // NOTE: sensitive — the secret value itself. Never Debug-print.
        password: String,
        // NOTE: sensitive — the session capability. Never Debug-print verbatim.
        code: String,
    },
    /// Code-gated write: field-level edits on an existing entry. `sets` may
    /// carry ANY field including Password (values are sensitive); `unsets`
    /// removes custom fields; `title` renames.
    EditEntry {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        // NOTE: sensitive — may contain Password or other secrets. Never Debug-print values.
        #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        sets: std::collections::BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        unsets: Vec<String>,
        // NOTE: sensitive — the session capability. Never Debug-print verbatim.
        code: String,
    },
    /// Code-gated write: recycle (default) or permanently delete an entry.
    RemoveEntry {
        path: String,
        #[serde(default)]
        permanent: bool,
        // NOTE: sensitive — the session capability. Never Debug-print verbatim.
        code: String,
    },
    /// Code-gated write: move an entry to an EXISTING group.
    MoveEntry {
        path: String,
        group: String,
        // NOTE: sensitive — the session capability. Never Debug-print verbatim.
        code: String,
    },
    /// Code-gated write: create a group hierarchy (mkdir -p; errors if the
    /// leaf already exists).
    Mkdir {
        path: String,
        // NOTE: sensitive — the session capability. Never Debug-print verbatim.
        code: String,
    },
    /// Code-gated write: recycle (default) or permanently delete a group.
    /// `recursive` is only consulted for permanent deletion of a non-empty
    /// group, mirroring `trove-core`'s `remove_group`.
    Rmdir {
        path: String,
        #[serde(default)]
        permanent: bool,
        #[serde(default)]
        recursive: bool,
        // NOTE: sensitive — the session capability. Never Debug-print verbatim.
        code: String,
    },
    /// Code-gated read: the entry's CURRENT TOTP code. The daemon computes it
    /// from the protected `otp` field; only the ephemeral code (plus validity
    /// window) crosses the wire — never the shared secret.
    GetTotp {
        path: String,
        // NOTE: sensitive — the session capability. Never Debug-print verbatim.
        code: String,
    },
    /// Code-gated write: set an entry's `otp` field from an `otpauth://` URI
    /// (validated server-side; entry created mkdir-p if absent).
    AddTotp {
        path: String,
        // NOTE: sensitive — carries the TOTP shared secret. Never Debug-print.
        uri: String,
        // NOTE: sensitive — the session capability. Never Debug-print verbatim.
        code: String,
    },
}

// Custom Debug to make password leakage impossible by accident.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::Ping => f.write_str("Ping"),
            Request::Unlock { path, timeout, .. } => f
                .debug_struct("Unlock")
                .field("path", path)
                .field("password", &"<redacted>")
                .field("timeout", timeout)
                .field("keyfile", &"<redacted>")
                .finish(),
            Request::List => f.write_str("List"),
            Request::Lock => f.write_str("Lock"),
            Request::Shutdown => f.write_str("Shutdown"),
            Request::MaterializeStatus => f.write_str("MaterializeStatus"),
            Request::SetIdleTimeout { seconds } => f
                .debug_struct("SetIdleTimeout")
                .field("seconds", seconds)
                .finish(),
            Request::GetIdleTimeout => f.write_str("GetIdleTimeout"),
            Request::GetVersion => f.write_str("GetVersion"),
            Request::Status => f.write_str("Status"),
            Request::SshAgentList => f.write_str("SshAgentList"),
            Request::GpgAgentList => f.write_str("GpgAgentList"),
            Request::Get {
                title, attachment, ..
            } => f
                .debug_struct("Get")
                .field("title", title)
                .field("attachment", attachment)
                .field("code", &"<redacted>")
                .finish(),
            Request::AddSsh {
                path,
                comment,
                user,
                ..
            } => f
                .debug_struct("AddSsh")
                .field("path", path)
                .field("key", &"<redacted>")
                .field("comment", comment)
                .field("user", user)
                .field("code", &"<redacted>")
                .finish(),
            Request::AddGpg { title, .. } => f
                .debug_struct("AddGpg")
                .field("title", title)
                .field("key", &"<redacted>")
                .field("code", &"<redacted>")
                .finish(),
            Request::AddFile {
                title,
                name,
                target,
                mode,
                ttl,
                allow_disk_backed,
                ..
            } => f
                .debug_struct("AddFile")
                .field("title", title)
                .field("src", &"<redacted>")
                .field("name", name)
                .field("target", target)
                .field("mode", mode)
                .field("ttl", ttl)
                .field("allow_disk_backed", allow_disk_backed)
                .field("code", &"<redacted>")
                .finish(),
            Request::ShowEntry { path } => f.debug_struct("ShowEntry").field("path", path).finish(),
            Request::Search { term } => f.debug_struct("Search").field("term", term).finish(),
            Request::GetField { path, field, .. } => f
                .debug_struct("GetField")
                .field("path", path)
                .field("field", field)
                .field("code", &"<redacted>")
                .finish(),
            Request::AddPassword {
                path,
                username,
                url,
                ..
            } => f
                .debug_struct("AddPassword")
                .field("path", path)
                .field("username", username)
                .field("url", url)
                .field("password", &"<redacted>")
                .field("code", &"<redacted>")
                .finish(),
            Request::EditEntry {
                path,
                title,
                sets,
                unsets,
                ..
            } => f
                .debug_struct("EditEntry")
                .field("path", path)
                .field("title", title)
                // Field NAMES are safe to log; values may be secrets.
                .field("sets", &sets.keys().collect::<Vec<_>>())
                .field("unsets", unsets)
                .field("code", &"<redacted>")
                .finish(),
            Request::RemoveEntry {
                path, permanent, ..
            } => f
                .debug_struct("RemoveEntry")
                .field("path", path)
                .field("permanent", permanent)
                .field("code", &"<redacted>")
                .finish(),
            Request::MoveEntry { path, group, .. } => f
                .debug_struct("MoveEntry")
                .field("path", path)
                .field("group", group)
                .field("code", &"<redacted>")
                .finish(),
            Request::Mkdir { path, .. } => f
                .debug_struct("Mkdir")
                .field("path", path)
                .field("code", &"<redacted>")
                .finish(),
            Request::Rmdir {
                path,
                permanent,
                recursive,
                ..
            } => f
                .debug_struct("Rmdir")
                .field("path", path)
                .field("permanent", permanent)
                .field("recursive", recursive)
                .field("code", &"<redacted>")
                .finish(),
            Request::GetTotp { path, .. } => f
                .debug_struct("GetTotp")
                .field("path", path)
                .field("code", &"<redacted>")
                .finish(),
            Request::AddTotp { path, .. } => f
                .debug_struct("AddTotp")
                .field("path", path)
                .field("uri", &"<redacted>")
                .field("code", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct EntryDto {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub attachments: Vec<String>,
    /// Names of the groups containing this entry, root → leaf. Root group
    /// itself is excluded — an entry directly under root has an empty
    /// `group_path`. Older clients that ignore this field still get a
    /// usable `title`.
    #[serde(default)]
    pub group_path: Vec<String>,
}

/// Full non-secret view of one entry, for `ShowEntry`. Everything here is
/// safe to print without a session code: protected values (Password et al.)
/// are represented only by their *names* in `custom_fields`, never by value.
#[derive(Debug, Serialize)]
pub struct ShowDto {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    /// Names (not values) of custom string fields beyond the standard five.
    pub custom_fields: Vec<String>,
    pub attachments: Vec<String>,
    pub group_path: Vec<String>,
}

/// One SSH key served by the agent, for `ssh-agent list`. Rendered by the CLI
/// as the `ssh-add -L` line `<algo> <base64-blob> <comment>`.
#[derive(Debug, Serialize)]
pub struct SshKeyDto {
    pub algo: String,
    pub blob_b64: String,
    pub comment: String,
}

/// One GPG key served by the agent, for `gpg-agent list`.
#[derive(Debug, Serialize)]
pub struct GpgKeyDto {
    /// Lowercase hex of the libgcrypt keygrip (the gpg-agent key identifier).
    pub keygrip: String,
    /// Human-readable algorithm/role, e.g. "ed25519/sign" or "cv25519/encr".
    pub key_type: String,
    pub comment: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Response {
    Ok(OkBody),
    Err { error: String },
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum OkBody {
    Empty {},
    Pong {
        pong: bool,
    },
    List {
        entries: Vec<EntryDto>,
    },
    MaterializeStatus {
        materialized: Vec<crate::materialize::MaterializeStatus>,
    },
    /// v0.0.6.0: response body for `GetIdleTimeout`.
    /// `seconds` is the configured timeout (0 == disabled).
    /// `remaining` is the seconds-until-fire if a vault is unlocked, else null.
    IdleTimeout {
        seconds: u64,
        remaining: Option<u64>,
    },
    /// Response body for `GetVersion`: the daemon's build version, stamped by
    /// `build.rs`. Lets a connecting CLI warn on CLI↔daemon drift.
    Version {
        daemon_version: String,
    },
    /// v0.0.9.0: response body for `Status`. `vault_path` is `Some` only when
    /// a vault is unlocked. `idle_timeout_secs` is the configured timeout
    /// (0 == disabled). `idle_remaining_secs` is `Some` only when the timer
    /// is running. `ssh_keys` / `gpg_keys` / `materialized` count the entries
    /// in the corresponding in-memory stores.
    Status {
        vault_path: Option<PathBuf>,
        idle_timeout_secs: u64,
        idle_remaining_secs: Option<u64>,
        ssh_keys: usize,
        gpg_keys: usize,
        materialized: usize,
    },
    /// Response to `Unlock`: the one-time session code for this unlock. The CLI
    /// emits it as `export TROVE_SESSION=…`; subsequent `Get`s present it.
    Unlocked {
        code: String,
        /// The daemon's build version, stamped by `build.rs`. Surfaced by the
        /// CLI at unlock so a stale daemon (still running pre-rebuild code) is
        /// obvious without hunting through `ps`.
        daemon_version: String,
    },
    /// Response to `Get`: the requested secret's bytes, base64-encoded.
    Secret {
        data: String,
    },
    /// Response to `ShowEntry`.
    Show {
        entry: ShowDto,
    },
    /// Response to `GetField`: the field's string value (may be a secret —
    /// the request was code-gated).
    Value {
        value: String,
    },
    /// Response to `RemoveEntry` / `Rmdir`: whether the target was moved to
    /// the recycle bin (`true`) or destroyed (`false`).
    Recycled {
        recycled: bool,
    },
    /// Response to `GetTotp`: the ephemeral code and its validity window.
    Totp {
        totp_code: String,
        valid_for_secs: u64,
        period_secs: u64,
    },
    /// Response to `SshAgentList`: the public keys the agent serves.
    SshAgentList {
        ssh_keys: Vec<SshKeyDto>,
    },
    /// Response to `GpgAgentList`: the GPG keys the agent serves.
    GpgAgentList {
        gpg_keys: Vec<GpgKeyDto>,
    },
}

impl Response {
    pub fn ok_empty() -> Self {
        Response::Ok(OkBody::Empty {})
    }
    pub fn ok_pong() -> Self {
        Response::Ok(OkBody::Pong { pong: true })
    }
    pub fn ok_list(entries: Vec<EntryDto>) -> Self {
        Response::Ok(OkBody::List { entries })
    }
    pub fn ok_materialize_status(items: Vec<crate::materialize::MaterializeStatus>) -> Self {
        Response::Ok(OkBody::MaterializeStatus {
            materialized: items,
        })
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Response::Err { error: msg.into() }
    }
    pub fn ok_idle_timeout(seconds: u64, remaining: Option<u64>) -> Self {
        Response::Ok(OkBody::IdleTimeout { seconds, remaining })
    }
    pub fn ok_version() -> Self {
        Response::Ok(OkBody::Version {
            daemon_version: env!("TROVE_BUILD_VERSION").to_string(),
        })
    }
    pub fn ok_status(
        vault_path: Option<PathBuf>,
        idle_timeout_secs: u64,
        idle_remaining_secs: Option<u64>,
        ssh_keys: usize,
        gpg_keys: usize,
        materialized: usize,
    ) -> Self {
        Response::Ok(OkBody::Status {
            vault_path,
            idle_timeout_secs,
            idle_remaining_secs,
            ssh_keys,
            gpg_keys,
            materialized,
        })
    }
    pub fn ok_unlocked(code: String) -> Self {
        Response::Ok(OkBody::Unlocked {
            code,
            daemon_version: env!("TROVE_BUILD_VERSION").to_string(),
        })
    }
    pub fn ok_ssh_agent_list(ssh_keys: Vec<SshKeyDto>) -> Self {
        Response::Ok(OkBody::SshAgentList { ssh_keys })
    }
    pub fn ok_gpg_agent_list(gpg_keys: Vec<GpgKeyDto>) -> Self {
        Response::Ok(OkBody::GpgAgentList { gpg_keys })
    }
    pub fn ok_secret(data: String) -> Self {
        Response::Ok(OkBody::Secret { data })
    }
    pub fn ok_show(entry: ShowDto) -> Self {
        Response::Ok(OkBody::Show { entry })
    }
    pub fn ok_value(value: String) -> Self {
        Response::Ok(OkBody::Value { value })
    }
    pub fn ok_recycled(recycled: bool) -> Self {
        Response::Ok(OkBody::Recycled { recycled })
    }
    pub fn ok_totp(code: trove_core::TotpCode) -> Self {
        Response::Ok(OkBody::Totp {
            totp_code: code.code,
            valid_for_secs: code.valid_for_secs,
            period_secs: code.period_secs,
        })
    }
}
