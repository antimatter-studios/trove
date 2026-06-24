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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
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
            Request::AddSsh { path, user, .. } => f
                .debug_struct("AddSsh")
                .field("path", path)
                .field("key", &"<redacted>")
                .field("user", user)
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
}
