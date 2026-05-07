//! Request -> Response handler. Pure modulo what sdpm-core does.
//!
//! Concurrency: a single shared `Mutex<Option<Vault>>`. v0.0.1 holds at most
//! one vault. If `Unlock` is called while a vault is already held, the old
//! vault is dropped and replaced.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Mutex;

use sdpm_core::Vault;

use crate::protocol::{EntryDto, Request, Response};

pub type SharedState = Arc<Mutex<Option<Vault>>>;

/// Outcome control — let the connection loop know when to ask the daemon to exit.
pub struct Handled {
    pub response: Response,
    pub shutdown: bool,
}

pub async fn handle(req: Request, state: &SharedState) -> Handled {
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
                    let mut guard = state.lock().await;
                    *guard = Some(vault);
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
            let mut guard = state.lock().await;
            *guard = None;
            Handled {
                response: Response::ok_empty(),
                shutdown: false,
            }
        }

        Request::Shutdown => {
            // Drop vault eagerly here too; main loop will also clean up.
            let mut guard = state.lock().await;
            *guard = None;
            Handled {
                response: Response::ok_empty(),
                shutdown: true,
            }
        }
    }
}
