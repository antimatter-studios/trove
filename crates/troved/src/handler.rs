//! Request -> Response handler. Pure modulo what trove-core does.
//!
//! Concurrency: a single shared `Mutex<Option<Vault>>`. v0.0.1 holds at most
//! one vault. If `Unlock` is called while a vault is already held, the old
//! vault is dropped and replaced.
//!
//! v0.0.2.0: also owns the SSH agent key store. On `unlock`, every entry's
//! `id` attachment is parsed as an OpenSSH ed25519 private key; successful
//! parses populate the key store. On `lock` / `shutdown`, the store is
//! cleared (which zeroizes the in-memory keys via `SigningKey`'s
//! `ZeroizeOnDrop` impl).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use trove_core::{EntrySummary, Vault};

use crate::gpg_agent::{keys as gpg_keys, GpgKeyStore, LoadedGpgKey};
use crate::idle::{IdleState, IdleTracker};
use crate::materialize::{self, MaterializedFile, MaterializedStore};
use crate::protocol::{EntryDto, Request, Response};
use crate::ssh_agent::{keeagent, keys as ssh_keys, KeyStore, LoadedKey};

pub type SharedState = Arc<Mutex<Option<Vault>>>;

/// A provisioning session: the one-time code minted at `Unlock` plus the uid
/// that unlocked. Code-gated extraction (`Get`) requires presenting this code
/// from the same uid (SO_PEERCRED). Dropped on `Lock`/`Shutdown`/idle-lock.
pub struct Session {
    pub code: String,
    pub uid: u32,
}

pub type SessionStore = Arc<Mutex<Option<Session>>>;

/// Mint a fresh session code: 24 random bytes, URL-safe base64 (no padding, so
/// it's safe as an env-var value and on a command line).
fn mint_session_code() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut b = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Outcome control — let the connection loop know when to ask the daemon to exit.
pub struct Handled {
    pub response: Response,
    pub shutdown: bool,
}

#[allow(clippy::too_many_arguments)]
pub async fn handle(
    req: Request,
    state: &SharedState,
    key_store: &KeyStore,
    gpg_store: &GpgKeyStore,
    mat_store: &MaterializedStore,
    session: &SessionStore,
    idle: &Arc<IdleTracker>,
    peer_uid: u32,
) -> Handled {
    // Bump only on commands that represent real user activity. Read-only
    // inspection commands (Status, GetIdleTimeout, MaterializeStatus) and the
    // keepalive (Ping) deliberately don't bump — a `watch -n1 trove status`
    // or a polling materialize-status UI would otherwise indefinitely defeat
    // the auto-lock. unlock/lock/shutdown manage the timer state explicitly
    // below; bumping them here would be redundant but harmless. SSH and GPG
    // agent traffic bumps the timer from inside the agent listeners, not via
    // this path.
    match req {
        Request::Ping
        | Request::Status
        | Request::GetIdleTimeout
        | Request::GetVersion
        | Request::MaterializeStatus
        | Request::SshAgentList
        | Request::GpgAgentList => {}
        _ => idle.bump(),
    }
    match req {
        Request::Ping => Handled {
            response: Response::ok_pong(),
            shutdown: false,
        },

        Request::Unlock {
            path,
            password,
            timeout,
            keyfile,
        } => {
            let path_buf = PathBuf::from(path);
            // Decode composite-key material (if any) before the blocking open.
            let keyfile_bytes = match keyfile {
                Some(b64) => {
                    use base64::Engine;
                    match base64::engine::general_purpose::STANDARD.decode(&b64) {
                        Ok(bytes) => Some(bytes),
                        Err(e) => {
                            return Handled {
                                response: Response::err(format!("invalid keyfile encoding: {e}")),
                                shutdown: false,
                            }
                        }
                    }
                }
                None => None,
            };
            // trove-core's Vault::open is sync (and may do blocking file I/O +
            // KDF work). Wrap it in spawn_blocking to keep the runtime healthy.
            let result = tokio::task::spawn_blocking(move || {
                Vault::open_with_key(&path_buf, &password, keyfile_bytes.as_deref())
            })
            .await;
            match result {
                Ok(Ok(vault)) => {
                    // Pull SSH and GPG keys out of the vault before stashing
                    // it in shared state. We do this with the local handle so
                    // we never hold the state mutex across attachment reads.
                    let loaded_keys = load_ssh_keys_from_vault(&vault);
                    let loaded_gpg = load_gpg_keys_from_vault(&vault);

                    // Materialize opted-in entries while we still own the
                    // vault locally. We do this BEFORE handing off the vault
                    // to shared state so we never hold the state mutex across
                    // file I/O. Per-entry failures are logged; the unlock
                    // still succeeds. The unlock RESPONSE goes out only after
                    // every materialize completes — so by the time the user
                    // sees `ok`, the files are on disk.
                    let materialized = materialize_from_vault(&vault, mat_store).await;
                    {
                        let mut g = mat_store.write().await;
                        // Replace wholesale, same as ssh/gpg stores.
                        *g = materialized;
                    }

                    {
                        let mut guard = state.lock().await;
                        *guard = Some(vault);
                    }
                    {
                        let mut keys = key_store.write().await;
                        // Replace wholesale so a re-unlock doesn't accumulate
                        // stale keys from the previous vault.
                        *keys = loaded_keys;
                    }
                    {
                        let mut gkeys = gpg_store.write().await;
                        *gkeys = loaded_gpg;
                    }
                    // Arm the idle-lock timer. If the unlock request carried
                    // an explicit `timeout`, that value also becomes the new
                    // configured timeout going forward (start_or_reset writes
                    // both the timeout and last-activity). Otherwise we fall
                    // back to whatever the daemon already had configured.
                    // `0` disables auto-lock for either path.
                    let timeout_secs = timeout.unwrap_or_else(|| idle.current_timeout_secs());
                    idle.start_or_reset(Duration::from_secs(timeout_secs));

                    // Mint the session code, bound to the uid that unlocked.
                    // Extraction (`Get`) will demand both. Returned to the CLI,
                    // which emits it as `export TROVE_SESSION=…`.
                    let code = mint_session_code();
                    {
                        let mut sess = session.lock().await;
                        *sess = Some(Session {
                            code: code.clone(),
                            uid: peer_uid,
                        });
                    }
                    Handled {
                        response: Response::ok_unlocked(code),
                        shutdown: false,
                    }
                }
                Ok(Err(e)) => Handled {
                    response: Response::err(e.to_string()),
                    shutdown: false,
                },
                Err(join_err) => Handled {
                    response: Response::err(format!("internal error: {join_err}")),
                    shutdown: false,
                },
            }
        }

        Request::List => {
            let guard = state.lock().await;
            match guard.as_ref() {
                None => Handled {
                    response: Response::err("no vault unlocked"),
                    shutdown: false,
                },
                Some(vault) => {
                    let entries: Vec<EntryDto> = vault
                        .list_entries()
                        .into_iter()
                        .map(|s| EntryDto {
                            id: s.id.to_string(),
                            title: s.title,
                            username: s.username,
                            url: s.url,
                            attachments: s.attachment_names,
                            group_path: s.group_path,
                        })
                        .collect();
                    Handled {
                        response: Response::ok_list(entries),
                        shutdown: false,
                    }
                }
            }
        }

        Request::Lock => {
            // Cancel the idle timer FIRST so a near-deadline tick can't
            // race us into a double-wipe. The timer-fire path also serializes
            // through the same lock callback, but cancelling here is cheaper
            // and clearer.
            idle.cancel();

            // Wipe materialized files synchronously. The lock command should
            // not return ok until every file has at least been visited by
            // the wipe loop. Errors are logged inside wipe_all; we don't
            // surface them to the client (lock is best-effort by design).
            materialize::wipe_all(mat_store).await;

            {
                let mut guard = state.lock().await;
                *guard = None;
            }
            // Drop SSH and GPG keys too. SigningKey's ZeroizeOnDrop wipes the
            // private bytes when the Vec is cleared.
            {
                let mut keys = key_store.write().await;
                keys.clear();
            }
            {
                let mut gkeys = gpg_store.write().await;
                gkeys.clear();
            }
            {
                let mut sess = session.lock().await;
                *sess = None;
            }
            // The daemon exists only to hold unlocked vaults and to clean up
            // materialized files. The last vault is now locked and its files
            // wiped, so if nothing remains to serve the daemon has no reason to
            // live — signal shutdown (the connection loop acks first, then tears
            // down) so the next `unlock` autospawns a fresh process: always the
            // current binary, no lingering keyless daemon, no orphan pile-up.
            //
            // It stays alive iff a vault is still open OR materialized files
            // still need cleanup. Single-vault today, but the condition already
            // generalizes — locking one of several vaults won't exit; only the
            // last one (with nothing left to clean) does.
            let vault_open = state.lock().await.is_some();
            let has_materialized = !mat_store.read().await.is_empty();
            Handled {
                response: Response::ok_empty(),
                shutdown: !vault_open && !has_materialized,
            }
        }

        Request::Shutdown => {
            idle.cancel();

            // Same wipe-then-drop dance as Lock. We must wipe before
            // returning, otherwise troved exits and leaves materialized files
            // sitting on disk for an indefinite time.
            materialize::wipe_all(mat_store).await;

            // Drop vault and keys eagerly; main loop will also clean up.
            {
                let mut guard = state.lock().await;
                *guard = None;
            }
            {
                let mut keys = key_store.write().await;
                keys.clear();
            }
            {
                let mut gkeys = gpg_store.write().await;
                gkeys.clear();
            }
            {
                let mut sess = session.lock().await;
                *sess = None;
            }
            Handled {
                response: Response::ok_empty(),
                shutdown: true,
            }
        }

        Request::MaterializeStatus => {
            let snapshot = materialize::status_snapshot(mat_store).await;
            Handled {
                response: Response::ok_materialize_status(snapshot),
                shutdown: false,
            }
        }

        Request::SshAgentList => {
            use base64::Engine as _;
            let keys = key_store.read().await;
            let dtos = keys
                .iter()
                .map(|k| crate::protocol::SshKeyDto {
                    algo: k.algorithm_name().to_string(),
                    blob_b64: base64::engine::general_purpose::STANDARD.encode(&k.public_blob),
                    comment: k.comment.clone(),
                })
                .collect();
            Handled {
                response: Response::ok_ssh_agent_list(dtos),
                shutdown: false,
            }
        }

        Request::GpgAgentList => {
            use crate::gpg_agent::keys::LoadedGpgKey;
            let keys = gpg_store.read().await;
            let dtos = keys
                .iter()
                .map(|k| crate::protocol::GpgKeyDto {
                    keygrip: k.keygrip_hex(),
                    key_type: match k {
                        LoadedGpgKey::Ed25519(_) => "ed25519/sign",
                        LoadedGpgKey::Cv25519(_) => "cv25519/encr",
                    }
                    .to_string(),
                    comment: k.comment().to_string(),
                })
                .collect();
            Handled {
                response: Response::ok_gpg_agent_list(dtos),
                shutdown: false,
            }
        }

        Request::SetIdleTimeout { seconds } => {
            idle.set_timeout(Duration::from_secs(seconds));
            Handled {
                response: Response::ok_empty(),
                shutdown: false,
            }
        }

        Request::GetIdleTimeout => {
            let secs = idle.current_timeout_secs();
            let remaining = match idle.current_state() {
                IdleState::Running { remaining_secs } => Some(remaining_secs),
                IdleState::Disabled | IdleState::NotRunning => None,
            };
            Handled {
                response: Response::ok_idle_timeout(secs, remaining),
                shutdown: false,
            }
        }

        Request::GetVersion => Handled {
            response: Response::ok_version(),
            shutdown: false,
        },

        Request::Status => {
            // Capture vault path (if any) without holding the state lock
            // across other reads.
            let vault_path = {
                let guard = state.lock().await;
                guard.as_ref().map(|v| v.path().to_path_buf())
            };
            let idle_timeout_secs = idle.current_timeout_secs();
            let idle_remaining_secs = match idle.current_state() {
                IdleState::Running { remaining_secs } => Some(remaining_secs),
                IdleState::Disabled | IdleState::NotRunning => None,
            };
            let ssh_keys = key_store.read().await.len();
            let gpg_keys = gpg_store.read().await.len();
            let materialized = mat_store.read().await.len();
            Handled {
                response: Response::ok_status(
                    vault_path,
                    idle_timeout_secs,
                    idle_remaining_secs,
                    ssh_keys,
                    gpg_keys,
                    materialized,
                ),
                shutdown: false,
            }
        }

        Request::Get {
            title,
            attachment,
            code,
        } => get_secret(state, session, peer_uid, &title, &attachment, &code).await,

        Request::AddSsh {
            path,
            key,
            comment,
            user,
            code,
        } => {
            add_ssh(
                state,
                session,
                key_store,
                peer_uid,
                &path,
                &key,
                comment.as_deref(),
                user.as_deref(),
                &code,
            )
            .await
        }

        Request::AddGpg { title, key, code } => {
            add_gpg(state, session, gpg_store, peer_uid, &title, &key, &code).await
        }

        Request::AddFile {
            title,
            src,
            name,
            target,
            mode,
            ttl,
            allow_disk_backed,
            code,
        } => {
            add_file(
                state,
                session,
                peer_uid,
                &title,
                &src,
                &name,
                &target,
                &mode,
                ttl,
                allow_disk_backed,
                &code,
            )
            .await
        }

        Request::ShowEntry { path } => show_entry(state, &path).await,

        Request::Search { term } => search(state, &term).await,

        Request::GetField { path, field, code } => {
            get_field(state, session, peer_uid, &path, &field, &code).await
        }

        Request::AddPassword {
            path,
            username,
            url,
            notes,
            password,
            code,
        } => {
            add_password(
                state,
                session,
                peer_uid,
                &path,
                username.as_deref(),
                url.as_deref(),
                notes.as_deref(),
                &password,
                &code,
            )
            .await
        }

        Request::EditEntry {
            path,
            title,
            sets,
            unsets,
            code,
        } => {
            edit_entry(
                state,
                session,
                key_store,
                gpg_store,
                peer_uid,
                &path,
                title.as_deref(),
                &sets,
                &unsets,
                &code,
            )
            .await
        }

        Request::RemoveEntry {
            path,
            permanent,
            code,
        } => {
            remove_entry(
                state, session, key_store, gpg_store, peer_uid, &path, permanent, &code,
            )
            .await
        }

        Request::MoveEntry { path, group, code } => {
            move_entry(state, session, peer_uid, &path, &group, &code).await
        }

        Request::Mkdir { path, code } => mkdir(state, session, peer_uid, &path, &code).await,

        Request::Rmdir {
            path,
            permanent,
            recursive,
            code,
        } => {
            rmdir(
                state, session, key_store, gpg_store, peer_uid, &path, permanent, recursive, &code,
            )
            .await
        }

        Request::GetTotp { path, code } => get_totp(state, session, peer_uid, &path, &code).await,

        Request::AddTotp { path, uri, code } => {
            add_totp(state, session, peer_uid, &path, &uri, &code).await
        }
    }
}

/// Code-gated extraction. Validates the session (unlocked + code matches + same
/// uid as the unlocker), then reads `attachment` from the entry titled `title`
/// out of the held vault and returns it base64-encoded. The error is
/// deliberately generic on a session-validation failure so it isn't an oracle
/// for "is the vault unlocked?" vs "is the code wrong?".
async fn get_secret(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    title: &str,
    attachment: &str,
    code: &str,
) -> Handled {
    {
        let sess = session.lock().await;
        let ok = matches!(sess.as_ref(), Some(s) if s.code == code && s.uid == peer_uid);
        if !ok {
            return Handled {
                response: Response::err(
                    "refused: vault locked, or session code missing/invalid for this uid",
                ),
                shutdown: false,
            };
        }
    }
    let guard = state.lock().await;
    let vault = match guard.as_ref() {
        Some(v) => v,
        None => {
            return Handled {
                response: Response::err("no vault unlocked"),
                shutdown: false,
            }
        }
    };
    let id = match vault.find_by_title(title) {
        Some(id) => id,
        None => {
            return Handled {
                response: Response::err(format!("entry not found: {title}")),
                shutdown: false,
            }
        }
    };
    match vault.read_binary(&id, attachment) {
        Ok(Some(bytes)) => {
            use base64::Engine;
            let data = base64::engine::general_purpose::STANDARD.encode(&bytes);
            Handled {
                response: Response::ok_secret(data),
                shutdown: false,
            }
        }
        Ok(None) => Handled {
            response: Response::err(format!("entry '{title}' has no attachment '{attachment}'")),
            shutdown: false,
        },
        Err(e) => Handled {
            response: Response::err(format!("reading attachment: {e}")),
            shutdown: false,
        },
    }
}

/// Code-gated write. Validates the session (same gate as `get_secret`: vault
/// unlocked + code matches + same uid as the unlocker), decodes the base64 key
/// bytes, then stores them on the entry at `path` — creating the entry mkdir-p
/// if absent, or replacing the `id` attachment in place if it exists. Writes a
/// `KeeAgent.settings` blob so KeePassXC's agent loads it, sets `UserName` when
/// given, persists with `save()`, and finally reloads the SSH agent key store
/// from the updated vault so the new key is served without a re-unlock.
#[allow(clippy::too_many_arguments)]
async fn add_ssh(
    state: &SharedState,
    session: &SessionStore,
    key_store: &KeyStore,
    peer_uid: u32,
    path: &str,
    key_b64: &str,
    comment: Option<&str>,
    user: Option<&str>,
    code: &str,
) -> Handled {
    {
        let sess = session.lock().await;
        let ok = matches!(sess.as_ref(), Some(s) if s.code == code && s.uid == peer_uid);
        if !ok {
            return Handled {
                response: Response::err(
                    "refused: vault locked, or session code missing/invalid for this uid",
                ),
                shutdown: false,
            };
        }
    }

    let key_bytes = {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(key_b64) {
            Ok(b) => b,
            Err(e) => {
                return Handled {
                    response: Response::err(format!("decoding key bytes: {e}")),
                    shutdown: false,
                }
            }
        }
    };

    // Mutate the held vault and persist, then reload the agent key set off the
    // now-updated vault — all under the state lock, moving the reloaded Vec out
    // so we never hold the state lock across the key_store write below.
    let reloaded = {
        let mut guard = state.lock().await;
        let vault = match guard.as_mut() {
            Some(v) => v,
            None => {
                return Handled {
                    response: Response::err("no vault unlocked"),
                    shutdown: false,
                }
            }
        };
        let id = match vault.find_by_title(path) {
            Some(existing) => existing,
            None => match vault.add_entry(path) {
                Ok(id) => id,
                Err(e) => {
                    return Handled {
                        response: Response::err(format!("creating entry '{path}': {e}")),
                        shutdown: false,
                    }
                }
            },
        };
        if let Err(e) = vault.attach_binary(&id, "id", &key_bytes) {
            return Handled {
                response: Response::err(format!("attaching ssh key: {e}")),
                shutdown: false,
            };
        }
        // Persist the public key as a real `id.pub` attachment so any tool can
        // read the public half without deriving it from the private key. The
        // comment (usually an email) defaults to the entry path when absent.
        match ssh_keys::openssh_public_line(&key_bytes, comment.unwrap_or(path)) {
            Ok(pub_line) => {
                if let Err(e) = vault.attach_binary(&id, "id.pub", pub_line.as_bytes()) {
                    return Handled {
                        response: Response::err(format!("attaching public key: {e}")),
                        shutdown: false,
                    };
                }
            }
            Err(e) => {
                return Handled {
                    response: Response::err(format!("deriving public key: {e}")),
                    shutdown: false,
                };
            }
        }
        let settings = keeagent::settings_xml("id");
        if let Err(e) = vault.attach_binary(&id, keeagent::ATTACHMENT_NAME, &settings) {
            return Handled {
                response: Response::err(format!("attaching KeeAgent.settings: {e}")),
                shutdown: false,
            };
        }
        if let Some(user) = user {
            if let Err(e) = vault.set_field(&id, "UserName", user) {
                return Handled {
                    response: Response::err(format!("setting UserName: {e}")),
                    shutdown: false,
                };
            }
        }
        if let Err(e) = vault.save() {
            return Handled {
                response: Response::err(format!("saving vault: {e}")),
                shutdown: false,
            };
        }
        load_ssh_keys_from_vault(vault)
    };
    {
        let mut keys = key_store.write().await;
        *keys = reloaded;
    }
    Handled {
        response: Response::ok_empty(),
        shutdown: false,
    }
}

/// Code-gated write. Same session gate as `get_secret`/`add_ssh` (vault
/// unlocked + code matches + same uid as the unlocker), decodes the base64 key
/// bytes, then stores them on the entry at `title` as the `gpg-priv`
/// attachment — creating the entry mkdir-p if absent, or replacing in place if
/// it exists — and persists with `save()`. Finally reloads the GPG agent key
/// store from the updated vault so the new key is served without a re-unlock.
#[allow(clippy::too_many_arguments)]
async fn add_gpg(
    state: &SharedState,
    session: &SessionStore,
    gpg_store: &GpgKeyStore,
    peer_uid: u32,
    title: &str,
    key_b64: &str,
    code: &str,
) -> Handled {
    {
        let sess = session.lock().await;
        let ok = matches!(sess.as_ref(), Some(s) if s.code == code && s.uid == peer_uid);
        if !ok {
            return Handled {
                response: Response::err(
                    "refused: vault locked, or session code missing/invalid for this uid",
                ),
                shutdown: false,
            };
        }
    }

    let key_bytes = {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(key_b64) {
            Ok(b) => b,
            Err(e) => {
                return Handled {
                    response: Response::err(format!("decoding key bytes: {e}")),
                    shutdown: false,
                }
            }
        }
    };

    // Mutate the held vault and persist, then reload the agent key set off the
    // now-updated vault — all under the state lock, moving the reloaded Vec out
    // so we never hold the state lock across the gpg_store write below.
    let reloaded_gpg = {
        let mut guard = state.lock().await;
        let vault = match guard.as_mut() {
            Some(v) => v,
            None => {
                return Handled {
                    response: Response::err("no vault unlocked"),
                    shutdown: false,
                }
            }
        };
        let id = match vault.find_by_title(title) {
            Some(existing) => existing,
            None => match vault.add_entry(title) {
                Ok(id) => id,
                Err(e) => {
                    return Handled {
                        response: Response::err(format!("creating entry '{title}': {e}")),
                        shutdown: false,
                    }
                }
            },
        };
        if let Err(e) = vault.attach_binary(&id, "gpg-priv", &key_bytes) {
            return Handled {
                response: Response::err(format!("attaching gpg key: {e}")),
                shutdown: false,
            };
        }
        if let Err(e) = vault.save() {
            return Handled {
                response: Response::err(format!("saving vault: {e}")),
                shutdown: false,
            };
        }
        load_gpg_keys_from_vault(vault)
    };
    {
        let mut g = gpg_store.write().await;
        *g = reloaded_gpg;
    }
    Handled {
        response: Response::ok_empty(),
        shutdown: false,
    }
}

/// Code-gated write. Same session gate as `get_secret`/`add_ssh` (vault
/// unlocked + code matches + same uid as the unlocker), decodes the base64
/// source bytes, then stores them on the entry at `title` as the `name`
/// attachment — creating the entry mkdir-p if absent, or replacing in place if
/// it exists — sets the `Materialize.*` fields (Source/Target/Mode, optional
/// TTL, AllowDiskBacked) exactly as the offline `add file` CLI does, and
/// persists with `save()`. Unlike `add_gpg` this only persists: the file is
/// NOT materialized into the live session here — it materializes on the next
/// unlock.
#[allow(clippy::too_many_arguments)]
async fn add_file(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    title: &str,
    src_b64: &str,
    name: &str,
    target: &str,
    mode: &str,
    ttl: Option<u64>,
    allow_disk_backed: bool,
    code: &str,
) -> Handled {
    {
        let sess = session.lock().await;
        let ok = matches!(sess.as_ref(), Some(s) if s.code == code && s.uid == peer_uid);
        if !ok {
            return Handled {
                response: Response::err(
                    "refused: vault locked, or session code missing/invalid for this uid",
                ),
                shutdown: false,
            };
        }
    }

    let src_bytes = {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(src_b64) {
            Ok(b) => b,
            Err(e) => {
                return Handled {
                    response: Response::err(format!("decoding src bytes: {e}")),
                    shutdown: false,
                }
            }
        }
    };

    {
        let mut guard = state.lock().await;
        let vault = match guard.as_mut() {
            Some(v) => v,
            None => {
                return Handled {
                    response: Response::err("no vault unlocked"),
                    shutdown: false,
                }
            }
        };
        let id = match vault.find_by_title(title) {
            Some(existing) => existing,
            None => match vault.add_entry(title) {
                Ok(id) => id,
                Err(e) => {
                    return Handled {
                        response: Response::err(format!("creating entry '{title}': {e}")),
                        shutdown: false,
                    }
                }
            },
        };
        if let Err(e) = vault.attach_binary(&id, name, &src_bytes) {
            return Handled {
                response: Response::err(format!("attaching file bytes: {e}")),
                shutdown: false,
            };
        }
        if let Err(e) = vault.set_field(&id, "Materialize.Source", name) {
            return Handled {
                response: Response::err(format!("setting Materialize.Source: {e}")),
                shutdown: false,
            };
        }
        if let Err(e) = vault.set_field(&id, "Materialize.Target", target) {
            return Handled {
                response: Response::err(format!("setting Materialize.Target: {e}")),
                shutdown: false,
            };
        }
        if let Err(e) = vault.set_field(&id, "Materialize.Mode", mode) {
            return Handled {
                response: Response::err(format!("setting Materialize.Mode: {e}")),
                shutdown: false,
            };
        }
        if let Some(ttl) = ttl {
            if let Err(e) = vault.set_field(&id, "Materialize.TTL", &ttl.to_string()) {
                return Handled {
                    response: Response::err(format!("setting Materialize.TTL: {e}")),
                    shutdown: false,
                };
            }
        }
        if let Err(e) = vault.set_field(
            &id,
            "Materialize.AllowDiskBacked",
            if allow_disk_backed { "true" } else { "false" },
        ) {
            return Handled {
                response: Response::err(format!("setting Materialize.AllowDiskBacked: {e}")),
                shutdown: false,
            };
        }
        if let Err(e) = vault.save() {
            return Handled {
                response: Response::err(format!("saving vault: {e}")),
                shutdown: false,
            };
        }
    }
    Handled {
        response: Response::ok_empty(),
        shutdown: false,
    }
}

/// Build the materialization plan for `vault` and execute every plan,
/// returning the bookkeeping handles for the ones that succeeded. Per-entry
/// failures (validation OR I/O) are logged, never propagated.
async fn materialize_from_vault(vault: &Vault, store: &MaterializedStore) -> Vec<MaterializedFile> {
    let (plans, plan_errors) = materialize::build_plans(vault);
    for (title, e) in plan_errors {
        eprintln!("materialize: skipping entry '{title}': {e}");
    }
    let mut materialized = Vec::with_capacity(plans.len());
    for plan in plans {
        match materialize::materialize_one(vault, &plan, store.clone()) {
            Ok(m) => {
                eprintln!(
                    "materialize: '{}' -> {} (mode {:o}, ttl {:?})",
                    plan.entry_title,
                    plan.resolved_target.display(),
                    plan.mode,
                    plan.ttl,
                );
                materialized.push(m);
            }
            Err(e) => {
                eprintln!("materialize: failed for '{}': {}", plan.entry_title, e);
            }
        }
    }
    materialized
}

/// Validate the provisioning session for a code-gated request: vault unlocked
/// by this uid + matching code. Returns the standard deliberately-generic
/// refusal (`Some(Handled)`) on failure so callers can `return` it — the
/// message must not be an oracle for "locked" vs "wrong code".
async fn session_gate(session: &SessionStore, peer_uid: u32, code: &str) -> Option<Handled> {
    let sess = session.lock().await;
    let ok = matches!(sess.as_ref(), Some(s) if s.code == code && s.uid == peer_uid);
    if ok {
        None
    } else {
        Some(Handled {
            response: Response::err(
                "refused: vault locked, or session code missing/invalid for this uid",
            ),
            shutdown: false,
        })
    }
}

fn entry_dto(s: EntrySummary) -> EntryDto {
    EntryDto {
        id: s.id.to_string(),
        title: s.title,
        username: s.username,
        url: s.url,
        attachments: s.attachment_names,
        group_path: s.group_path,
    }
}

fn err_handled(msg: impl Into<String>) -> Handled {
    Handled {
        response: Response::err(msg),
        shutdown: false,
    }
}

fn ok_handled(response: Response) -> Handled {
    Handled {
        response,
        shutdown: false,
    }
}

/// Ungated (like `List`): one entry's non-secret surface. Field *names* only
/// for anything custom; values require the code-gated `GetField`.
async fn show_entry(state: &SharedState, path: &str) -> Handled {
    let guard = state.lock().await;
    let vault = match guard.as_ref() {
        Some(v) => v,
        None => return err_handled("no vault unlocked"),
    };
    let id = match vault.find_by_title(path) {
        Some(id) => id,
        None => return err_handled(format!("entry not found: {path}")),
    };
    let summary = vault.get_entry(&id).expect("entry just resolved");
    let notes = vault.get_field(&id, "Notes").ok().flatten();
    let custom_fields = vault.custom_field_names(&id).unwrap_or_default();
    ok_handled(Response::ok_show(crate::protocol::ShowDto {
        id: summary.id.to_string(),
        title: summary.title,
        username: summary.username,
        url: summary.url,
        notes,
        custom_fields,
        attachments: summary.attachment_names,
        group_path: summary.group_path,
    }))
}

/// Ungated (like `List`): substring search over non-secret surfaces.
async fn search(state: &SharedState, term: &str) -> Handled {
    let guard = state.lock().await;
    let vault = match guard.as_ref() {
        Some(v) => v,
        None => return err_handled("no vault unlocked"),
    };
    let entries: Vec<EntryDto> = vault
        .search_entries(term)
        .into_iter()
        .map(entry_dto)
        .collect();
    ok_handled(Response::ok_list(entries))
}

/// Code-gated single-field read — the only way a protected value (Password)
/// leaves the daemon.
async fn get_field(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    path: &str,
    field: &str,
    code: &str,
) -> Handled {
    if let Some(refused) = session_gate(session, peer_uid, code).await {
        return refused;
    }
    let guard = state.lock().await;
    let vault = match guard.as_ref() {
        Some(v) => v,
        None => return err_handled("no vault unlocked"),
    };
    let id = match vault.find_by_title(path) {
        Some(id) => id,
        None => return err_handled(format!("entry not found: {path}")),
    };
    match vault.get_field(&id, field) {
        Ok(Some(value)) => ok_handled(Response::ok_value(value)),
        Ok(None) => err_handled(format!("entry '{path}' has no field '{field}'")),
        Err(e) => err_handled(format!("reading field: {e}")),
    }
}

/// Code-gated write: create a password entry (groups mkdir-p) and persist.
#[allow(clippy::too_many_arguments)]
async fn add_password(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    path: &str,
    username: Option<&str>,
    url: Option<&str>,
    notes: Option<&str>,
    password: &str,
    code: &str,
) -> Handled {
    if let Some(refused) = session_gate(session, peer_uid, code).await {
        return refused;
    }
    let mut guard = state.lock().await;
    let vault = match guard.as_mut() {
        Some(v) => v,
        None => return err_handled("no vault unlocked"),
    };
    if vault.find_by_title(path).is_some() {
        return err_handled(format!(
            "entry already exists: {path} (use `trove edit` to change it)"
        ));
    }
    let id = match vault.add_entry(path) {
        Ok(id) => id,
        Err(e) => return err_handled(format!("creating entry '{path}': {e}")),
    };
    let fields = [
        ("Password", Some(password)),
        ("UserName", username),
        ("URL", url),
        ("Notes", notes),
    ];
    for (name, value) in fields {
        if let Some(value) = value {
            if let Err(e) = vault.set_field(&id, name, value) {
                return err_handled(format!("setting {name}: {e}"));
            }
        }
    }
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    ok_handled(Response::ok_empty())
}

/// After a structural write (edit/remove/move/rmdir) the affected entries may
/// have carried agent-served key material — reload both agent stores from the
/// saved vault so they never serve stale keys.
async fn reload_agent_stores(vault: &Vault, key_store: &KeyStore, gpg_store: &GpgKeyStore) {
    let ssh = load_ssh_keys_from_vault(vault);
    let gpg = load_gpg_keys_from_vault(vault);
    {
        let mut keys = key_store.write().await;
        *keys = ssh;
    }
    {
        let mut keys = gpg_store.write().await;
        *keys = gpg;
    }
}

/// Code-gated write: field-level edits (set/unset/rename) on one entry.
#[allow(clippy::too_many_arguments)]
async fn edit_entry(
    state: &SharedState,
    session: &SessionStore,
    key_store: &KeyStore,
    gpg_store: &GpgKeyStore,
    peer_uid: u32,
    path: &str,
    title: Option<&str>,
    sets: &std::collections::BTreeMap<String, String>,
    unsets: &[String],
    code: &str,
) -> Handled {
    if let Some(refused) = session_gate(session, peer_uid, code).await {
        return refused;
    }
    let mut guard = state.lock().await;
    let vault = match guard.as_mut() {
        Some(v) => v,
        None => return err_handled("no vault unlocked"),
    };
    let id = match vault.find_by_title(path) {
        Some(id) => id,
        None => return err_handled(format!("entry not found: {path}")),
    };
    for (field, value) in sets {
        if let Err(e) = vault.set_field(&id, field, value) {
            return err_handled(format!("setting {field}: {e}"));
        }
    }
    for field in unsets {
        if let Err(e) = vault.remove_field(&id, field) {
            return err_handled(format!("unsetting {field}: {e}"));
        }
    }
    if let Some(new_title) = title {
        if let Err(e) = vault.set_field(&id, "Title", new_title) {
            return err_handled(format!("renaming: {e}"));
        }
    }
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    reload_agent_stores(vault, key_store, gpg_store).await;
    ok_handled(Response::ok_empty())
}

/// Code-gated write: recycle (default) or destroy an entry.
#[allow(clippy::too_many_arguments)]
async fn remove_entry(
    state: &SharedState,
    session: &SessionStore,
    key_store: &KeyStore,
    gpg_store: &GpgKeyStore,
    peer_uid: u32,
    path: &str,
    permanent: bool,
    code: &str,
) -> Handled {
    if let Some(refused) = session_gate(session, peer_uid, code).await {
        return refused;
    }
    let mut guard = state.lock().await;
    let vault = match guard.as_mut() {
        Some(v) => v,
        None => return err_handled("no vault unlocked"),
    };
    let id = match vault.find_by_title(path) {
        Some(id) => id,
        None => return err_handled(format!("entry not found: {path}")),
    };
    let recycled = match vault.recycle_entry(&id, permanent) {
        Ok(r) => r,
        Err(e) => return err_handled(format!("removing entry: {e}")),
    };
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    reload_agent_stores(vault, key_store, gpg_store).await;
    ok_handled(Response::ok_recycled(recycled))
}

/// Code-gated write: move an entry to an existing group.
async fn move_entry(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    path: &str,
    group: &str,
    code: &str,
) -> Handled {
    if let Some(refused) = session_gate(session, peer_uid, code).await {
        return refused;
    }
    let mut guard = state.lock().await;
    let vault = match guard.as_mut() {
        Some(v) => v,
        None => return err_handled("no vault unlocked"),
    };
    let id = match vault.find_by_title(path) {
        Some(id) => id,
        None => return err_handled(format!("entry not found: {path}")),
    };
    if let Err(e) = vault.move_entry(&id, group) {
        return err_handled(format!("moving entry: {e}"));
    }
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    ok_handled(Response::ok_empty())
}

/// Code-gated write: create a group hierarchy.
async fn mkdir(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    path: &str,
    code: &str,
) -> Handled {
    if let Some(refused) = session_gate(session, peer_uid, code).await {
        return refused;
    }
    let mut guard = state.lock().await;
    let vault = match guard.as_mut() {
        Some(v) => v,
        None => return err_handled("no vault unlocked"),
    };
    if let Err(e) = vault.add_group(path) {
        return err_handled(format!("creating group: {e}"));
    }
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    ok_handled(Response::ok_empty())
}

/// Code-gated write: recycle (default) or destroy a group.
#[allow(clippy::too_many_arguments)]
async fn rmdir(
    state: &SharedState,
    session: &SessionStore,
    key_store: &KeyStore,
    gpg_store: &GpgKeyStore,
    peer_uid: u32,
    path: &str,
    permanent: bool,
    recursive: bool,
    code: &str,
) -> Handled {
    if let Some(refused) = session_gate(session, peer_uid, code).await {
        return refused;
    }
    let mut guard = state.lock().await;
    let vault = match guard.as_mut() {
        Some(v) => v,
        None => return err_handled("no vault unlocked"),
    };
    let recycled = match vault.remove_group(path, permanent, recursive) {
        Ok(r) => r,
        Err(e) => return err_handled(format!("removing group: {e}")),
    };
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    reload_agent_stores(vault, key_store, gpg_store).await;
    ok_handled(Response::ok_recycled(recycled))
}

/// Code-gated read: compute the entry's current TOTP code from its protected
/// `otp` field. Only the ephemeral code leaves the daemon, never the secret.
async fn get_totp(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    path: &str,
    code: &str,
) -> Handled {
    if let Some(refused) = session_gate(session, peer_uid, code).await {
        return refused;
    }
    let guard = state.lock().await;
    let vault = match guard.as_ref() {
        Some(v) => v,
        None => return err_handled("no vault unlocked"),
    };
    let id = match vault.find_by_title(path) {
        Some(id) => id,
        None => return err_handled(format!("entry not found: {path}")),
    };
    match vault.totp_now(&id) {
        Ok(totp) => ok_handled(Response::ok_totp(totp)),
        Err(e) => err_handled(format!("totp: {e}")),
    }
}

/// Code-gated write: set the `otp` field from an otpauth URI (validated in
/// trove-core before storing; entry created mkdir-p if absent).
async fn add_totp(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    path: &str,
    uri: &str,
    code: &str,
) -> Handled {
    if let Some(refused) = session_gate(session, peer_uid, code).await {
        return refused;
    }
    let mut guard = state.lock().await;
    let vault = match guard.as_mut() {
        Some(v) => v,
        None => return err_handled("no vault unlocked"),
    };
    let id = match vault.find_by_title(path) {
        Some(id) => id,
        None => match vault.add_entry(path) {
            Ok(id) => id,
            Err(e) => return err_handled(format!("creating entry '{path}': {e}")),
        },
    };
    if let Err(e) = vault.set_totp_uri(&id, uri) {
        return err_handled(format!("setting otp: {e}"));
    }
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    ok_handled(Response::ok_empty())
}

/// Walk every entry in `vault`, look for a `gpg-priv` attachment, and try to
/// parse it as an OpenPGP secret-key export. Returns one `LoadedGpgKey` per
/// ed25519 secret key found across all entries. Other algorithms and
/// encrypted exports are skipped with a one-line warning. Never panics.
pub fn load_gpg_keys_from_vault(vault: &Vault) -> Vec<LoadedGpgKey> {
    const ATTACHMENT_NAME: &str = "gpg-priv";
    let mut out = Vec::new();
    let entries: Vec<EntrySummary> = vault.list_entries();
    for entry in entries {
        if !entry.attachment_names.iter().any(|a| a == ATTACHMENT_NAME) {
            continue;
        }
        let bytes = match vault.read_binary(&entry.id, ATTACHMENT_NAME) {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(e) => {
                eprintln!(
                    "gpg-agent: failed to read 'gpg-priv' attachment on entry '{}': {}",
                    entry.title, e
                );
                continue;
            }
        };
        match gpg_keys::parse_gpg_export(&bytes, &entry.title) {
            Ok(loaded) => {
                for k in loaded {
                    out.push(k);
                }
            }
            Err(gpg_keys::ParseError::NoEd25519) => {
                eprintln!(
                    "gpg-agent: skipping entry '{}': no ed25519 keys in this export \
                     (v0.0.3.0 ed25519-only)",
                    entry.title
                );
            }
            Err(gpg_keys::ParseError::Encrypted) => {
                eprintln!(
                    "gpg-agent: skipping entry '{}': encrypted secret keys not supported \
                     in v0.0.3.0",
                    entry.title
                );
            }
            Err(e) => {
                eprintln!("gpg-agent: skipping entry '{}': {}", entry.title, e);
            }
        }
    }
    out
}

/// Walk every entry in `vault` and collect SSH private keys.
///
/// If an entry has a `KeeAgent.settings` attachment, we follow it: load only
/// the attachment it declares (if `AllowUseOfSshKey` + `AddAtDatabaseOpen`
/// are both true). Entries that explicitly opt out are skipped entirely.
///
/// If no `KeeAgent.settings` is present we fall back to content scanning:
/// every attachment is probed, and anything that parses as a private key is
/// loaded. This keeps plain KeePassXC vaults working without any settings blob.
///
/// The ssh-agent comment (`ssh-add -l`) is `<path>:<attachment>` (or just
/// `<path>` for the conventional `id` attachment name) where `<path>` is the
/// full group-prefixed title (`Work/SSH/github`).
pub fn load_ssh_keys_from_vault(vault: &Vault) -> Vec<LoadedKey> {
    let mut out = Vec::new();
    let entries: Vec<EntrySummary> = vault.list_entries();
    for entry in entries {
        if entry
            .attachment_names
            .iter()
            .any(|a| a == keeagent::ATTACHMENT_NAME)
        {
            // KeeAgent.settings present — let it decide which attachment to load.
            let settings_bytes = match vault.read_binary(&entry.id, keeagent::ATTACHMENT_NAME) {
                Ok(Some(b)) => b,
                Ok(None) => continue,
                Err(e) => {
                    eprintln!(
                        "keeagent: failed to read KeeAgent.settings on '{}': {}",
                        entry.title, e
                    );
                    continue;
                }
            };
            match keeagent::parse(&settings_bytes, &entry.title) {
                keeagent::Decision::Skip => {}
                keeagent::Decision::Load(att_name) => {
                    if let Some(k) = try_load_ssh_attachment(vault, &entry, &att_name) {
                        out.push(k);
                    }
                }
            }
        } else {
            // No KeeAgent.settings — content scan every attachment.
            for att_name in &entry.attachment_names {
                if let Some(k) = try_load_ssh_attachment(vault, &entry, att_name) {
                    out.push(k);
                }
            }
        }
    }
    out
}

/// Try to read and parse a single attachment as an SSH private key.
/// Silent on non-key content; warns on PEM-shaped blobs that fail to parse.
fn try_load_ssh_attachment(
    vault: &Vault,
    entry: &EntrySummary,
    attachment_name: &str,
) -> Option<LoadedKey> {
    let bytes = match vault.read_binary(&entry.id, attachment_name) {
        Ok(Some(b)) => b,
        Ok(None) => return None,
        Err(e) => {
            eprintln!(
                "ssh-agent: failed to read '{}' on '{}': {}",
                attachment_name, entry.title, e
            );
            return None;
        }
    };
    let display = entry.display_path();
    let comment = if attachment_name == "id" {
        display.clone()
    } else {
        format!("{display}:{attachment_name}")
    };
    match ssh_keys::parse_private_key(&bytes, &comment) {
        Ok(loaded) => Some(loaded),
        Err(ssh_keys::ParseError::NotOpenssh(detail)) => {
            if bytes.starts_with(b"-----BEGIN") {
                eprintln!(
                    "ssh-agent: skipping {}/{}: looks like a private key \
                     but failed to parse ({detail})",
                    display, attachment_name
                );
            }
            None
        }
        Err(ssh_keys::ParseError::UnsupportedAlgorithm(alg)) => {
            eprintln!(
                "ssh-agent: skipping {}/{}: unsupported key algorithm {} \
                 (supported: ed25519, rsa>=2048, ecdsa-nistp256, ecdsa-nistp384)",
                display, attachment_name, alg
            );
            None
        }
        Err(ssh_keys::ParseError::RsaTooSmall(bits)) => {
            eprintln!(
                "ssh-agent: skipping {}/{}: RSA key too short ({} bits, minimum 2048)",
                display, attachment_name, bits
            );
            None
        }
        Err(ssh_keys::ParseError::Encrypted) => {
            eprintln!(
                "ssh-agent: skipping {}/{}: encrypted private keys not supported",
                display, attachment_name
            );
            None
        }
        Err(e) => {
            eprintln!("ssh-agent: skipping {}/{}: {}", display, attachment_name, e);
            None
        }
    }
}
