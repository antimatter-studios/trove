//! Tauri command surface bridging the UI to `trove-core`.
//!
//! The unlocked [`Vault`] lives in Tauri-managed state behind a `Mutex`. We
//! never hand the UI a `trove-core` type directly — those aren't `Serialize`,
//! and more importantly the entry list must stay free of secrets. Passwords and
//! other protected fields are read one at a time, on demand, via [`get_field`].

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;

use serde::Serialize;
use tauri::State;
use trove_core::{EntryId, Vault};

/// The currently-unlocked vault, if any. `None` means locked.
pub type VaultState = Mutex<Option<Vault>>;

/// Non-secret view of an entry, safe to render in a list.
#[derive(Serialize)]
pub struct EntryDto {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    /// Group segments from root to the entry's parent, as exact strings. Sent
    /// structured (not split from `display_path`) so names containing `/` stay
    /// intact in the UI's group tree and filters.
    pub group_path: Vec<String>,
    pub display_path: String,
    pub attachment_names: Vec<String>,
}

impl From<trove_core::EntrySummary> for EntryDto {
    fn from(e: trove_core::EntrySummary) -> Self {
        EntryDto {
            display_path: e.display_path(),
            group_path: e.group_path,
            id: e.id.as_str().to_string(),
            title: e.title,
            username: e.username,
            url: e.url,
            attachment_names: e.attachment_names,
        }
    }
}

fn summaries(vault: &Vault) -> Vec<EntryDto> {
    vault
        .list_entries()
        .into_iter()
        .map(EntryDto::from)
        .collect()
}

/// Borrow the open vault out of managed state, erroring if locked or poisoned.
fn with_vault<T>(
    state: &State<'_, VaultState>,
    f: impl FnOnce(&Vault) -> Result<T, String>,
) -> Result<T, String> {
    let guard = state
        .lock()
        .map_err(|_| "vault state was poisoned".to_string())?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| "no vault is open".to_string())?;
    f(vault)
}

/// Open `path` with `password`, store the vault in state, return its entries.
#[tauri::command]
pub fn open_vault(
    path: String,
    password: String,
    state: State<'_, VaultState>,
) -> Result<Vec<EntryDto>, String> {
    let vault = Vault::open(&PathBuf::from(path), &password).map_err(|e| e.to_string())?;
    let list = summaries(&vault);
    *state
        .lock()
        .map_err(|_| "vault state was poisoned".to_string())? = Some(vault);
    Ok(list)
}

/// Re-read the entry list from the open vault.
#[tauri::command]
pub fn list_entries(state: State<'_, VaultState>) -> Result<Vec<EntryDto>, String> {
    with_vault(&state, |v| Ok(summaries(v)))
}

/// Read a single field (e.g. `Password`) for one entry, on demand.
#[tauri::command]
pub fn get_field(
    id: String,
    field: String,
    state: State<'_, VaultState>,
) -> Result<Option<String>, String> {
    // EntryId's FromStr is infallible.
    let entry_id = EntryId::from_str(&id).unwrap();
    with_vault(&state, |v| {
        v.get_field(&entry_id, &field).map_err(|e| e.to_string())
    })
}

/// Drop the vault from memory.
#[tauri::command]
pub fn lock_vault(state: State<'_, VaultState>) -> Result<(), String> {
    *state
        .lock()
        .map_err(|_| "vault state was poisoned".to_string())? = None;
    Ok(())
}
