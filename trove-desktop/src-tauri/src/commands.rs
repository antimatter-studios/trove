//! Tauri command surface bridging the UI to `trove-core`.
//!
//! The app manages a *set* of registered vaults (the "Open vaults" switcher).
//! Each is either **locked** (path known, not decrypted) or **unlocked**
//! (a decrypted [`Vault`] held in memory). The whole set lives in Tauri-managed
//! state behind a single `Mutex<AppState>`, keyed by a stable vault id derived
//! from the file's canonical path. The registered `{path, name}` list is
//! persisted as JSON in the Tauri app config dir so it survives restarts.
//!
//! We never hand the UI a `trove-core` type directly — those aren't
//! `Serialize`, and the entry list must stay free of secrets. The list
//! [`EntryDto`] carries a server-computed strength score and a password length,
//! but never the password; secrets (password, notes, custom values) are read on
//! demand via [`get_field`] / [`get_entry_detail`] only when an entry is
//! selected.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};
use trove_core::{EntryId, Vault};
use zxcvbn::zxcvbn;

/// Basename of the JSON file (in the app config dir) that persists the
/// registered vault set as a list of `{path, name}`.
const RECENTS_FILE: &str = "vaults.json";

// --- state -----------------------------------------------------------------

/// A registered vault: its canonical path, display name, and — when unlocked —
/// the decrypted [`Vault`]. `vault: None` means locked.
pub struct RegisteredVault {
    pub path: PathBuf,
    pub name: String,
    pub vault: Option<Vault>,
}

/// The full multi-vault state: vault id → registered vault.
#[derive(Default)]
pub struct AppState {
    pub vaults: BTreeMap<String, RegisteredVault>,
}

/// Tauri-managed handle to [`AppState`].
pub type VaultState = Mutex<AppState>;

/// One persisted recent, mirrored to `vaults.json`.
#[derive(Serialize, Deserialize, Clone)]
struct RecentEntry {
    path: String,
    name: String,
}

// --- DTOs (serialized names are what the frontend sees) --------------------

/// A registered vault as the switcher sees it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDto {
    pub id: String,
    pub name: String,
    /// File basename including extension, e.g. `inpace.kdbx`.
    pub file: String,
    pub path: String,
    pub locked: bool,
}

/// Non-secret view of an entry, safe to render in a list. Carries a strength
/// score and a password length but never the password itself.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryDto {
    pub id: String,
    /// Display path `group/sub/Title`.
    pub path: String,
    pub title: String,
    /// Group segments root → leaf (empty for a root-level entry).
    pub group: Vec<String>,
    /// `group.join("/")`.
    pub group_path: String,
    pub username: String,
    pub url: String,
    /// `"login" | "ssh" | "cert" | "db"` — stored `_TroveType` else derived.
    pub entry_type: String,
    /// `0..=100`, computed server-side from the password.
    pub strength: u8,
    /// Password length in characters (so the UI shows "N chars" without the
    /// password).
    pub pw_len: u16,
    pub fav: bool,
    /// RFC3339 UTC, or `""` if unknown.
    pub created: String,
    /// RFC3339 UTC, or `""` if unknown.
    pub modified: String,
    pub attachment_names: Vec<String>,
}

/// One custom string field (`k` = name, `v` = value).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KvDto {
    pub k: String,
    pub v: String,
}

/// Non-list detail for a selected entry.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryDetailDto {
    pub notes: String,
    /// Custom fields only (standard Title/UserName/Password/URL/Notes and any
    /// reserved `_Trove*` key excluded).
    pub fields: Vec<KvDto>,
    pub password: String,
}

/// Input for [`save_entry`] — a create when `entry_id` is `None`, else update.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryInput {
    pub entry_id: Option<String>,
    /// `group/sub/name`: last segment is the Title, the rest the group path.
    pub path: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub entry_type: String,
}

/// Result of [`save_entry`]: the fresh list plus the saved entry's id (for
/// re-selection in the UI).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveResult {
    pub entries: Vec<EntryDto>,
    pub id: String,
}

// --- id / path helpers -----------------------------------------------------

/// Deterministic vault id: 16-char lowercase hex of an FNV-1a hash over the
/// canonical path string. FNV-1a is used (not `std`'s `DefaultHasher`, whose
/// output is not guaranteed stable across releases) so the *same file always
/// maps to the same id* across app restarts — the persisted recents depend on
/// it. Std-only, no extra dependency.
fn vault_id_for(canonical: &Path) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in canonical.to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

/// Canonicalize a path for id/storage. Falls back to an absolute (but
/// un-resolved) path when the file can't be canonicalized yet.
fn canonicalize(path: &str) -> PathBuf {
    let p = Path::new(path);
    std::fs::canonicalize(p).unwrap_or_else(|_| absolute(p))
}

/// Make `p` absolute without requiring it to exist (join the cwd if relative).
fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    }
}

/// Vault display name = file basename without extension (`inpace.kdbx` →
/// `inpace`).
fn vault_name(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// File basename including extension (`inpace.kdbx`).
fn vault_file(path: &Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn vault_dto(id: &str, rv: &RegisteredVault) -> VaultDto {
    VaultDto {
        id: id.to_string(),
        name: rv.name.clone(),
        file: vault_file(&rv.path),
        path: rv.path.to_string_lossy().into_owned(),
        locked: rv.vault.is_none(),
    }
}

fn poisoned<T>(_: T) -> String {
    "vault state was poisoned".to_string()
}

// --- persistence -----------------------------------------------------------

fn recents_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("resolving app config dir: {e}"))?;
    Ok(dir.join(RECENTS_FILE))
}

fn load_recents(app: &AppHandle) -> Vec<RecentEntry> {
    let Ok(path) = recents_path(app) else {
        return Vec::new();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return Vec::new();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn save_recents(app: &AppHandle, recents: &[RecentEntry]) -> Result<(), String> {
    let path = recents_path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("creating app config dir: {e}"))?;
    }
    let json = serde_json::to_vec_pretty(recents).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("writing recents: {e}"))
}

/// Add-or-update one recent by canonical path, then persist the whole list.
fn persist_recent(app: &AppHandle, canonical: &Path, name: &str) -> Result<(), String> {
    let cpath = canonical.to_string_lossy().into_owned();
    let mut recents = load_recents(app);
    if let Some(existing) = recents.iter_mut().find(|r| r.path == cpath) {
        existing.name = name.to_string();
    } else {
        recents.push(RecentEntry {
            path: cpath,
            name: name.to_string(),
        });
    }
    save_recents(app, &recents)
}

// --- open-vault access helpers ---------------------------------------------

fn with_open<T>(
    state: &State<'_, VaultState>,
    id: &str,
    f: impl FnOnce(&Vault) -> Result<T, String>,
) -> Result<T, String> {
    let guard = state.lock().map_err(poisoned)?;
    let rv = guard
        .vaults
        .get(id)
        .ok_or_else(|| "vault is not registered".to_string())?;
    let vault = rv
        .vault
        .as_ref()
        .ok_or_else(|| "vault is locked".to_string())?;
    f(vault)
}

fn with_open_mut<T>(
    state: &State<'_, VaultState>,
    id: &str,
    f: impl FnOnce(&mut Vault) -> Result<T, String>,
) -> Result<T, String> {
    let mut guard = state.lock().map_err(poisoned)?;
    let rv = guard
        .vaults
        .get_mut(id)
        .ok_or_else(|| "vault is not registered".to_string())?;
    let vault = rv
        .vault
        .as_mut()
        .ok_or_else(|| "vault is locked".to_string())?;
    f(vault)
}

// --- entry <-> DTO ----------------------------------------------------------

/// `0..=100` password strength from zxcvbn's `guesses_log10`, `0` for empty.
fn strength(password: &str) -> u8 {
    if password.is_empty() {
        return 0;
    }
    let log10 = zxcvbn(password, &[]).guesses_log10();
    (log10 * 5.0).round().clamp(0.0, 100.0) as u8
}

/// Derive an entry type from its URL scheme when `_TroveType` is absent.
fn derive_type(url: &str) -> String {
    let u = url.to_ascii_lowercase();
    if u.starts_with("ssh://") {
        "ssh".to_string()
    } else if u.starts_with("postgres://")
        || u.starts_with("postgresql://")
        || u.starts_with("mysql://")
        || u.starts_with("redis://")
        || u.starts_with("rediss://")
        || u.starts_with("mongodb://")
    {
        "db".to_string()
    } else if u.contains("mtls") {
        "cert".to_string()
    } else {
        // http/https and anything else default to a login.
        "login".to_string()
    }
}

fn build_entry_dtos(vault: &Vault) -> Vec<EntryDto> {
    vault
        .list_entries()
        .into_iter()
        .map(|s| entry_dto(vault, s))
        .collect()
}

fn entry_dto(vault: &Vault, s: trove_core::EntrySummary) -> EntryDto {
    // Read the reserved fields + password (for strength/length) per entry.
    // These are computed server-side; the password never leaves this function.
    let password = vault
        .get_field(&s.id, "Password")
        .ok()
        .flatten()
        .unwrap_or_default();
    let trove_type = vault.get_field(&s.id, "_TroveType").ok().flatten();
    let fav = vault
        .get_field(&s.id, "_TroveFav")
        .ok()
        .flatten()
        .as_deref()
        == Some("1");

    let id = s.id.as_str().to_string();
    let path = s.display_path();
    let group_path = s.group_path.join("/");
    let url = s.url.unwrap_or_default();
    let entry_type = match trove_type {
        Some(t) if !t.is_empty() => t,
        _ => derive_type(&url),
    };
    let pw_len = u16::try_from(password.chars().count()).unwrap_or(u16::MAX);
    let strength = strength(&password);

    EntryDto {
        id,
        path,
        title: s.title,
        group: s.group_path,
        group_path,
        username: s.username.unwrap_or_default(),
        url,
        entry_type,
        strength,
        pw_len,
        fav,
        created: s.created.unwrap_or_default(),
        modified: s.modified.unwrap_or_default(),
        attachment_names: s.attachment_names,
    }
}

// --- mutation helpers (shared by commands + tests) -------------------------

/// Set a standard field when `value` is non-empty, otherwise clear it —
/// "empty string clears/omits" per the contract.
fn set_or_clear(vault: &mut Vault, id: &EntryId, field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        vault.remove_field(id, field).map_err(|e| e.to_string())
    } else {
        vault.set_field(id, field, value).map_err(|e| e.to_string())
    }
}

/// Split `group/sub/name` into `(group_segments, leaf_title)`, mirroring
/// trove-core's parsing (leading case-insensitive `Root` dropped, empty
/// segments rejected). Kept in sync with core so the group-changed comparison
/// against `EntrySummary::group_path` is apples-to-apples.
fn split_entry_path(path: &str) -> Result<(Vec<String>, String), String> {
    if path.is_empty() {
        return Err("entry path must not be empty".to_string());
    }
    let mut segs: Vec<String> = path.split('/').map(str::to_string).collect();
    if segs.first().is_some_and(|s| s.eq_ignore_ascii_case("Root")) {
        segs.remove(0);
    }
    let leaf = segs.pop().unwrap_or_default();
    if leaf.is_empty() || segs.iter().any(String::is_empty) {
        return Err(format!("invalid entry path: {path}"));
    }
    Ok((segs, leaf))
}

/// Apply a possibly-changed path to an existing entry: move it to the new
/// group (creating the group with `mkdir -p` semantics) when the group path
/// changed, then set its title.
fn update_entry_path(vault: &mut Vault, id: &EntryId, path: &str) -> Result<(), String> {
    let (groups, leaf) = split_entry_path(path)?;
    let current = vault
        .get_entry(id)
        .ok_or_else(|| "entry not found".to_string())?;
    if current.group_path != groups {
        let group_path = groups.join("/");
        if !group_path.is_empty() {
            // move_entry requires the destination to exist; ensure it. A
            // pre-existing leaf group is fine (ignore GroupExists).
            match vault.add_group(&group_path) {
                Ok(()) | Err(trove_core::Error::GroupExists(_)) => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        vault
            .move_entry(id, &group_path)
            .map_err(|e| e.to_string())?;
    }
    vault
        .set_field(id, "Title", &leaf)
        .map_err(|e| e.to_string())
}

/// Create or update an entry from `input`, save the vault, return its id.
fn apply_save_entry(vault: &mut Vault, input: &EntryInput) -> Result<EntryId, String> {
    let entry_id = match &input.entry_id {
        None => vault.add_entry(&input.path).map_err(|e| e.to_string())?,
        Some(existing) => {
            // EntryId's FromStr is infallible.
            let eid = EntryId::from_str(existing).unwrap();
            update_entry_path(vault, &eid, &input.path)?;
            eid
        }
    };
    set_or_clear(vault, &entry_id, "UserName", &input.username)?;
    set_or_clear(vault, &entry_id, "Password", &input.password)?;
    set_or_clear(vault, &entry_id, "URL", &input.url)?;
    set_or_clear(vault, &entry_id, "Notes", &input.notes)?;
    set_or_clear(vault, &entry_id, "_TroveType", &input.entry_type)?;
    vault.save().map_err(|e| e.to_string())?;
    Ok(entry_id)
}

/// Non-secret + password detail for a selected entry.
fn entry_detail(vault: &Vault, eid: &EntryId) -> Result<EntryDetailDto, String> {
    let notes = vault
        .get_field(eid, "Notes")
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let password = vault
        .get_field(eid, "Password")
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let mut fields = Vec::new();
    for k in vault.custom_field_names(eid).map_err(|e| e.to_string())? {
        // custom_field_names already excludes the five standard fields; drop
        // the reserved _Trove* keys too — they are never user attributes.
        if k.starts_with("_Trove") {
            continue;
        }
        let v = vault
            .get_field(eid, &k)
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        fields.push(KvDto { k, v });
    }
    Ok(EntryDetailDto {
        notes,
        fields,
        password,
    })
}

/// Set/clear `_TroveFav` and save.
fn apply_set_favorite(vault: &mut Vault, eid: &EntryId, fav: bool) -> Result<(), String> {
    if fav {
        vault
            .set_field(eid, "_TroveFav", "1")
            .map_err(|e| e.to_string())?;
    } else {
        vault
            .remove_field(eid, "_TroveFav")
            .map_err(|e| e.to_string())?;
    }
    vault.save().map_err(|e| e.to_string())
}

/// Move an entry to the recycle bin and save.
fn apply_delete(vault: &mut Vault, eid: &EntryId) -> Result<(), String> {
    vault.recycle_entry(eid, false).map_err(|e| e.to_string())?;
    vault.save().map_err(|e| e.to_string())
}

// --- commands: vault lifecycle ---------------------------------------------

/// All registered vaults whose file still exists on disk. Syncs persisted
/// recents into state (as locked) first, so this is safe to call on startup.
#[tauri::command]
pub fn list_vaults(app: AppHandle, state: State<'_, VaultState>) -> Result<Vec<VaultDto>, String> {
    let recents = load_recents(&app);
    let mut guard = state.lock().map_err(poisoned)?;
    for r in &recents {
        let cpath = canonicalize(&r.path);
        if !cpath.exists() {
            continue;
        }
        let id = vault_id_for(&cpath);
        guard.vaults.entry(id).or_insert_with(|| RegisteredVault {
            path: cpath,
            name: r.name.clone(),
            vault: None,
        });
    }
    let mut out: Vec<VaultDto> = guard
        .vaults
        .iter()
        .filter(|(_, rv)| rv.path.exists())
        .map(|(id, rv)| vault_dto(id, rv))
        .collect();
    out.sort_by_key(|v| v.name.to_lowercase());
    Ok(out)
}

/// Register an existing `.kdbx` as **locked** (not decrypted) and persist.
/// Idempotent: returns the existing entry if already registered.
#[tauri::command]
pub fn register_vault(
    path: String,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<VaultDto, String> {
    let cpath = canonicalize(&path);
    if !cpath.exists() {
        return Err(format!("no such file: {}", cpath.display()));
    }
    let id = vault_id_for(&cpath);
    let name = vault_name(&cpath);
    {
        let mut guard = state.lock().map_err(poisoned)?;
        if let Some(rv) = guard.vaults.get(&id) {
            return Ok(vault_dto(&id, rv));
        }
        guard.vaults.insert(
            id.clone(),
            RegisteredVault {
                path: cpath.clone(),
                name: name.clone(),
                vault: None,
            },
        );
    }
    persist_recent(&app, &cpath, &name)?;
    let guard = state.lock().map_err(poisoned)?;
    let rv = guard
        .vaults
        .get(&id)
        .ok_or_else(|| "vault vanished after register".to_string())?;
    Ok(vault_dto(&id, rv))
}

/// Create a new `.kdbx` at `path`, register it **unlocked**, persist, return it.
#[tauri::command]
pub fn create_vault(
    path: String,
    password: String,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<VaultDto, String> {
    // The file doesn't exist yet, so resolve to an absolute (un-canonicalized)
    // path for Vault::create; canonicalize after it exists.
    let target = absolute(Path::new(&path));
    let vault = Vault::create(&target, &password).map_err(|e| e.to_string())?;
    let cpath = std::fs::canonicalize(&target).unwrap_or(target);
    let id = vault_id_for(&cpath);
    let name = vault_name(&cpath);
    {
        let mut guard = state.lock().map_err(poisoned)?;
        guard.vaults.insert(
            id.clone(),
            RegisteredVault {
                path: cpath.clone(),
                name: name.clone(),
                vault: Some(vault),
            },
        );
    }
    persist_recent(&app, &cpath, &name)?;
    let guard = state.lock().map_err(poisoned)?;
    let rv = guard
        .vaults
        .get(&id)
        .ok_or_else(|| "vault vanished after create".to_string())?;
    Ok(vault_dto(&id, rv))
}

/// Decrypt a registered vault, store the open `Vault`, return its entry list.
#[tauri::command]
pub fn unlock_vault(
    id: String,
    password: String,
    state: State<'_, VaultState>,
) -> Result<Vec<EntryDto>, String> {
    let mut guard = state.lock().map_err(poisoned)?;
    let rv = guard
        .vaults
        .get_mut(&id)
        .ok_or_else(|| "vault is not registered".to_string())?;
    let vault = Vault::open(&rv.path, &password).map_err(|e| e.to_string())?;
    let entries = build_entry_dtos(&vault);
    rv.vault = Some(vault);
    Ok(entries)
}

/// Drop the decrypted vault (keep it registered), marking it locked.
#[tauri::command]
pub fn lock_vault(id: String, state: State<'_, VaultState>) -> Result<(), String> {
    let mut guard = state.lock().map_err(poisoned)?;
    let rv = guard
        .vaults
        .get_mut(&id)
        .ok_or_else(|| "vault is not registered".to_string())?;
    rv.vault = None;
    Ok(())
}

/// Re-read the entry list for an unlocked vault.
#[tauri::command]
pub fn list_entries(id: String, state: State<'_, VaultState>) -> Result<Vec<EntryDto>, String> {
    with_open(&state, &id, |v| Ok(build_entry_dtos(v)))
}

// --- commands: reading one entry -------------------------------------------

/// Read a single field (e.g. `Password`) for one entry, on demand.
#[tauri::command]
pub fn get_field(
    id: String,
    entry_id: String,
    field: String,
    state: State<'_, VaultState>,
) -> Result<Option<String>, String> {
    let eid = EntryId::from_str(&entry_id).unwrap();
    with_open(&state, &id, |v| {
        v.get_field(&eid, &field).map_err(|e| e.to_string())
    })
}

/// Notes + custom fields + password for the selected entry.
#[tauri::command]
pub fn get_entry_detail(
    id: String,
    entry_id: String,
    state: State<'_, VaultState>,
) -> Result<EntryDetailDto, String> {
    let eid = EntryId::from_str(&entry_id).unwrap();
    with_open(&state, &id, |v| entry_detail(v, &eid))
}

// --- commands: mutations ----------------------------------------------------

/// Create or update an entry, save the vault, return the fresh list + saved id.
#[tauri::command]
pub fn save_entry(
    id: String,
    input: EntryInput,
    state: State<'_, VaultState>,
) -> Result<SaveResult, String> {
    with_open_mut(&state, &id, |vault| {
        let entry_id = apply_save_entry(vault, &input)?;
        Ok(SaveResult {
            entries: build_entry_dtos(vault),
            id: entry_id.as_str().to_string(),
        })
    })
}

/// Move an entry to the recycle bin, save, return the fresh list.
#[tauri::command]
pub fn delete_entry(
    id: String,
    entry_id: String,
    state: State<'_, VaultState>,
) -> Result<Vec<EntryDto>, String> {
    let eid = EntryId::from_str(&entry_id).unwrap();
    with_open_mut(&state, &id, |vault| {
        apply_delete(vault, &eid)?;
        Ok(build_entry_dtos(vault))
    })
}

/// Set/clear the favorite flag, save, return the fresh list.
#[tauri::command]
pub fn set_favorite(
    id: String,
    entry_id: String,
    fav: bool,
    state: State<'_, VaultState>,
) -> Result<Vec<EntryDto>, String> {
    let eid = EntryId::from_str(&entry_id).unwrap();
    with_open_mut(&state, &id, |vault| {
        apply_set_favorite(vault, &eid, fav)?;
        Ok(build_entry_dtos(vault))
    })
}

// --- tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a throwaway unlocked vault in a unique temp dir.
    fn temp_vault() -> (Vault, PathBuf) {
        // A process-wide counter guarantees a unique dir per test even when two
        // tests start within the same clock tick — otherwise concurrent saves to
        // a shared path race on the atomic write-then-rename (os error 2).
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "trove-desktop-test-{}-{}-{:?}",
            std::process::id(),
            seq,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.kdbx");
        let vault = Vault::create(&path, "correct horse").unwrap();
        (vault, path)
    }

    fn input(entry_id: Option<String>, path: &str) -> EntryInput {
        EntryInput {
            entry_id,
            path: path.to_string(),
            username: "deploy".to_string(),
            password: "Gx7$mQ2!vLpZ9wKt".to_string(),
            url: "ssh://build.example.io".to_string(),
            notes: "rotate quarterly".to_string(),
            entry_type: "ssh".to_string(),
        }
    }

    #[test]
    fn save_then_detail_round_trips_and_hides_secrets() {
        let (mut vault, _path) = temp_vault();
        let eid = apply_save_entry(&mut vault, &input(None, "Infra/SSH/build")).unwrap();

        // The list DTO carries no secret but does carry strength + length.
        let dtos = build_entry_dtos(&vault);
        assert_eq!(dtos.len(), 1);
        let dto = &dtos[0];
        assert_eq!(dto.title, "build");
        assert_eq!(dto.group, vec!["Infra".to_string(), "SSH".to_string()]);
        assert_eq!(dto.group_path, "Infra/SSH");
        assert_eq!(dto.path, "Infra/SSH/build");
        assert_eq!(dto.username, "deploy");
        assert_eq!(dto.entry_type, "ssh"); // stored _TroveType
        assert_eq!(dto.pw_len, "Gx7$mQ2!vLpZ9wKt".chars().count() as u16);
        assert!(dto.strength > 0 && dto.strength <= 100);
        assert!(!dto.fav);
        assert!(!dto.modified.is_empty()); // created/modified populated by core

        // Detail returns the password + notes; _TroveType is NOT a user field.
        let detail = entry_detail(&vault, &eid).unwrap();
        assert_eq!(detail.password, "Gx7$mQ2!vLpZ9wKt");
        assert_eq!(detail.notes, "rotate quarterly");
        assert!(!detail.fields.iter().any(|kv| kv.k.starts_with("_Trove")));
    }

    #[test]
    fn update_moves_group_renames_and_clears_empty_fields() {
        let (mut vault, _path) = temp_vault();
        let eid = apply_save_entry(&mut vault, &input(None, "Infra/SSH/build")).unwrap();

        // Rename + move to a different group, and clear the notes.
        let mut upd = input(Some(eid.as_str().to_string()), "Prod/DB/primary");
        upd.notes = String::new();
        upd.url = "postgres://db.example.io".to_string();
        upd.entry_type = String::new(); // clear _TroveType → derive from URL
        let saved = apply_save_entry(&mut vault, &upd).unwrap();
        assert_eq!(saved.as_str(), eid.as_str()); // same entry id preserved

        let dtos = build_entry_dtos(&vault);
        assert_eq!(dtos.len(), 1);
        let dto = &dtos[0];
        assert_eq!(dto.path, "Prod/DB/primary");
        assert_eq!(dto.group, vec!["Prod".to_string(), "DB".to_string()]);
        assert_eq!(dto.entry_type, "db"); // derived from postgres:// URL

        let detail = entry_detail(&vault, &eid).unwrap();
        assert_eq!(detail.notes, ""); // empty input cleared the field
    }

    #[test]
    fn favorite_toggles_and_delete_recycles() {
        let (mut vault, _path) = temp_vault();
        let eid = apply_save_entry(&mut vault, &input(None, "Infra/SSH/build")).unwrap();

        apply_set_favorite(&mut vault, &eid, true).unwrap();
        assert!(build_entry_dtos(&vault)[0].fav);
        apply_set_favorite(&mut vault, &eid, false).unwrap();
        assert!(!build_entry_dtos(&vault)[0].fav);

        // Delete recycles the entry: it leaves the live listing.
        apply_delete(&mut vault, &eid).unwrap();
        let live: Vec<_> = build_entry_dtos(&vault)
            .into_iter()
            .filter(|d| {
                !d.group
                    .iter()
                    .any(|g| g.as_str() == trove_core::RECYCLE_BIN_GROUP)
            })
            .collect();
        assert!(live.is_empty());
    }

    #[test]
    fn strength_follows_the_frozen_formula() {
        // The frozen formula is clamp(round(guesses_log10 * 5), 0, 100), with
        // 0 for empty. Absolute magnitudes are zxcvbn-version data (v3's
        // frequency list scores differ from the contract's illustrative
        // ~4/~12/100 figures), so we assert the formula's *identity* across a
        // spread of inputs rather than those version-specific numbers.
        assert_eq!(strength(""), 0); // empty → 0
        let reference = |p: &str| -> u8 {
            (zxcvbn(p, &[]).guesses_log10() * 5.0)
                .round()
                .clamp(0.0, 100.0) as u8
        };
        for p in [
            "a",
            "admin",
            "abc123",
            "correct-horse-battery-staple-42",
            "9f3Kx!2Lm@8Qp#7Rv&4Zt$1Wy^6Nb*0Jc7Hs%5Gd",
        ] {
            assert_eq!(strength(p), reference(p), "formula mismatch for {p}");
            assert!(strength(p) <= 100, "over cap for {p}");
        }
        // A long, high-entropy password lands near the top of the scale.
        assert!(strength("9f3Kx!2Lm@8Qp#7Rv&4Zt$1Wy^6Nb*0Jc7Hs%5Gd") >= 80);
    }

    #[test]
    fn type_derivation_from_url() {
        assert_eq!(derive_type("ssh://host"), "ssh");
        assert_eq!(derive_type("postgresql://db"), "db");
        assert_eq!(derive_type("mysql://db"), "db");
        assert_eq!(derive_type("https://api.example.io/mtls"), "cert");
        assert_eq!(derive_type("https://example.io"), "login");
        assert_eq!(derive_type(""), "login");
    }

    #[test]
    fn vault_id_is_deterministic_and_path_derived() {
        let a = vault_id_for(Path::new("/vaults/inpace.kdbx"));
        let b = vault_id_for(Path::new("/vaults/inpace.kdbx"));
        let c = vault_id_for(Path::new("/vaults/other.kdbx"));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 16);
    }
}
