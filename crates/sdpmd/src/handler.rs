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

use tokio::sync::Mutex;

use sdpm_core::{EntrySummary, Vault};

use crate::gpg_agent::{keys as gpg_keys, GpgKeyStore, LoadedGpgKey};
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
) -> Handled {
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
    }
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
                eprintln!(
                    "gpg-agent: skipping entry '{}': {}",
                    entry.title, e
                );
            }
        }
    }
    out
}

/// Walk every entry in `vault`, look for an `id` attachment, and try to parse
/// it as an OpenSSH ed25519 private key. Skips (with a one-line warning)
/// anything that doesn't parse, isn't ed25519, or is encrypted. Never panics.
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
        match ssh_keys::parse_openssh_ed25519(&bytes, &entry.title) {
            Ok(loaded) => out.push(loaded),
            Err(ssh_keys::ParseError::UnsupportedAlgorithm(alg)) => {
                eprintln!(
                    "ssh-agent: skipping entry '{}': unsupported key algorithm {} \
                     (v0.0.2.0 ed25519-only)",
                    entry.title, alg
                );
            }
            Err(ssh_keys::ParseError::Encrypted) => {
                eprintln!(
                    "ssh-agent: skipping entry '{}': encrypted private keys not supported \
                     in v0.0.2.0",
                    entry.title
                );
            }
            Err(e) => {
                eprintln!(
                    "ssh-agent: skipping entry '{}': {}",
                    entry.title, e
                );
            }
        }
    }
    out
}
