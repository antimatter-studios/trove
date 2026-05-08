//! Request -> Response handler. Pure modulo what sdpm-core does.
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

use sdpm_core::{EntrySummary, Vault};

use crate::gpg_agent::{keys as gpg_keys, GpgKeyStore, LoadedGpgKey};
use crate::idle::{IdleState, IdleTracker};
use crate::materialize::{self, MaterializedFile, MaterializedStore};
use crate::protocol::{EntryDto, Request, Response};
use crate::ssh_agent::{keys as ssh_keys, KeyStore, LoadedKey};

pub type SharedState = Arc<Mutex<Option<Vault>>>;

/// Outcome control — let the connection loop know when to ask the daemon to exit.
pub struct Handled {
    pub response: Response,
    pub shutdown: bool,
}

pub async fn handle(
    req: Request,
    state: &SharedState,
    key_store: &KeyStore,
    gpg_store: &GpgKeyStore,
    mat_store: &MaterializedStore,
    idle: &Arc<IdleTracker>,
) -> Handled {
    // Bump on every command except ping. Ping is the keepalive heartbeat —
    // counting it would let a stuck client trivially defeat the auto-lock.
    // unlock/lock/shutdown handle the timer state explicitly below; bumping
    // them here is harmless because start_or_reset / cancel run after.
    if !matches!(req, Request::Ping) {
        idle.bump();
    }
    match req {
        Request::Ping => Handled {
            response: Response::ok_pong(),
            shutdown: false,
        },

        Request::Unlock { path, password } => {
            let path_buf = PathBuf::from(path);
            // sdpm-core's Vault::open is sync (and may do blocking file I/O +
            // KDF work). Wrap it in spawn_blocking to keep the runtime healthy.
            let result =
                tokio::task::spawn_blocking(move || Vault::open(&path_buf, &password)).await;
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
                    // Arm the idle-lock timer with the current configured
                    // timeout. If the timeout is 0 the tracker treats this as
                    // "disabled" and never fires.
                    let timeout_secs = idle.current_timeout_secs();
                    idle.start_or_reset(Duration::from_secs(timeout_secs));
                    Handled {
                        response: Response::ok_empty(),
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
            Handled {
                response: Response::ok_empty(),
                shutdown: false,
            }
        }

        Request::Shutdown => {
            idle.cancel();

            // Same wipe-then-drop dance as Lock. We must wipe before
            // returning, otherwise sdpmd exits and leaves materialized files
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

/// Walk every entry in `vault`, look for an `id` attachment, and try to parse
/// it as an OpenSSH private key (ed25519, RSA >= 2048, ECDSA P-256, or
/// ECDSA P-384). Skips (with a one-line warning) anything that doesn't
/// parse, is encrypted, is an unsupported algorithm (DSA, P-521), or is a
/// weak RSA key. Never panics.
pub fn load_ssh_keys_from_vault(vault: &Vault) -> Vec<LoadedKey> {
    const ATTACHMENT_NAME: &str = "id";
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
                    "ssh-agent: failed to read 'id' attachment on entry '{}': {}",
                    entry.title, e
                );
                continue;
            }
        };
        match ssh_keys::parse_private_key(&bytes, &entry.title) {
            Ok(loaded) => out.push(loaded),
            Err(ssh_keys::ParseError::UnsupportedAlgorithm(alg)) => {
                eprintln!(
                    "ssh-agent: skipping entry '{}': unsupported key algorithm {} \
                     (supported: ed25519, rsa>=2048, ecdsa-nistp256, ecdsa-nistp384)",
                    entry.title, alg
                );
            }
            Err(ssh_keys::ParseError::RsaTooSmall(bits)) => {
                eprintln!(
                    "ssh-agent: skipping entry '{}': RSA key too short ({} bits, \
                     minimum 2048)",
                    entry.title, bits
                );
            }
            Err(ssh_keys::ParseError::Encrypted) => {
                eprintln!(
                    "ssh-agent: skipping entry '{}': encrypted private keys not supported",
                    entry.title
                );
            }
            Err(e) => {
                eprintln!("ssh-agent: skipping entry '{}': {}", entry.title, e);
            }
        }
    }
    out
}
