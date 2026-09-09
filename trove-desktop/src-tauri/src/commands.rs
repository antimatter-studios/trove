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

use crate::biometric;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter as _, Manager, State};
use trove_core::{EntryId, Vault};
use troved::materialize::{self, MaterializedFile, MaterializedStore};
use troved::ssh_agent::{self, keeagent, ForwardedKey, LoadedKey};
use zxcvbn::zxcvbn;

/// Basename of the JSON file (in the app config dir) that persists the
/// registered vault set as a list of `{path, name}`.
const RECENTS_FILE: &str = "vaults.json";

/// Basename of the JSON file (in the app config dir) holding app settings.
const SETTINGS_FILE: &str = "settings.json";

// --- state -----------------------------------------------------------------

/// A registered vault: its canonical path, display name, and — when unlocked —
/// the decrypted [`Vault`]. `vault: None` means locked.
pub struct RegisteredVault {
    pub path: PathBuf,
    pub name: String,
    pub vault: Option<Vault>,
    /// The keys this vault pushed into the system agent, so locking removes
    /// exactly those and never another vault's (or another app's) identities.
    /// `ForwardedKey` carries the per-entry `RemoveAtDatabaseClose` wish.
    pub exported_keys: Vec<ForwardedKey>,
    /// Files this vault materialized, wiped on lock. Shares the daemon's
    /// store type so `materialize::wipe_all` does the removal.
    pub materialized: MaterializedStore,
    /// Unix seconds at which the first forwarded key expires, or `None` when
    /// nothing was forwarded or nothing expires. The agent keeps its own clock
    /// and never reports it, so this is trove's record of what it asked for.
    pub keys_expire_at: Option<u64>,
}

impl RegisteredVault {
    pub fn new(path: PathBuf, name: String) -> Self {
        Self {
            path,
            name,
            vault: None,
            exported_keys: Vec::new(),
            materialized: MaterializedStore::default(),
            keys_expire_at: None,
        }
    }
}

/// Persisted app settings. Mirrors the daemon's switches, but as real
/// settings rather than environment variables — a GUI has no shell.
#[derive(Serialize, Deserialize, Clone)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    /// Push the vault's SSH keys into the OS agent on unlock, remove on lock.
    /// This is what makes vault keys usable by other applications and by a
    /// terminal, neither of which can be handed troved's own socket.
    ///
    /// The daemon reads `TROVE_SSH_FORWARD` for the same decision; a windowed
    /// app has no shell, so it keeps the choice here.
    pub system_agent: bool,
    /// Fallback lifetime, in seconds, for a key whose entry doesn't state one:
    /// the agent drops it by itself after this long, which is the only part of
    /// the guarantee that survives the app quitting without locking.
    pub system_agent_lifetime: u32,
    /// Write `Materialize.*` entries to their target paths on unlock, and wipe
    /// them on lock.
    pub materialize: bool,
    /// Minutes of no interaction before the vault view locks itself. `0`
    /// disables it.
    ///
    /// This closes the window and drops the decrypted database; it does NOT
    /// retract keys from the OS agent, which have their own expiry. Locking a
    /// UI and revoking machine-wide credentials are different decisions.
    pub idle_lock_minutes: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            // On by default. The per-entry gate is the real control: only
            // entries whose KeeAgent.settings ask for agent loading are
            // exported, which is what `trove add ssh` writes and what
            // KeePassXC users already set. A vault of hand-attached,
            // unmarked keys exports nothing.
            system_agent: true,
            system_agent_lifetime: 900,
            materialize: false,
            idle_lock_minutes: 5,
        }
    }
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
pub struct BiometricDto {
    /// A fingerprint reader with an enrolled finger, usable right now.
    pub available: bool,
    /// This vault has a password stored for Touch ID to release.
    pub enrolled: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDto {
    pub id: String,
    pub name: String,
    /// File basename including extension, e.g. `inpace.kdbx`.
    pub file: String,
    pub path: String,
    pub locked: bool,
    /// How many of this vault's keys are currently sitting in the system
    /// agent. The whole point of forwarding is invisible otherwise — this is
    /// what makes "are my keys actually loaded?" answerable without a terminal.
    pub agent_keys: usize,
    /// When the soonest-expiring forwarded key drops out of the agent, in unix
    /// seconds. `null` when nothing expires — the UI shows a countdown from it.
    pub keys_expire_at: Option<u64>,
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
    /// Name of the attachment on this entry that holds an SSH private key,
    /// or `""` when there isn't one. The UI shows the agent toggle only for
    /// entries that have a key.
    pub ssh_key_attachment: String,
    /// Whether this entry is declared for agent loading — i.e. whether
    /// unlocking adds it to the system agent. Backed by `KeeAgent.settings`,
    /// the same bytes KeePassXC reads and writes.
    pub agent_key: bool,
    /// Per-entry expiry in seconds, or `null` to use the app's default. This is
    /// KeeAgent's `UseLifetimeConstraintWhenAdding` + `LifetimeConstraintDuration`
    /// folded into one value, the same way the loader reads it.
    pub agent_lifetime: Option<u32>,
    /// Ask the agent to confirm before every use of this key.
    pub agent_confirm: bool,
    /// Take this key back out of the agent when the vault is locked.
    pub agent_remove_on_close: bool,
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
        agent_keys: rv.exported_keys.len(),
        keys_expire_at: rv.keys_expire_at,
    }
}

fn poisoned<T>(_: T) -> String {
    "vault state was poisoned".to_string()
}

/// Guard against a vault-id hash collision. The id maps 1:1 to a registered
/// vault, so silently reusing it for a *different* file would clobber the first
/// registration (and later id-routed unlock/save/delete calls would hit the
/// wrong vault). Collisions are astronomically unlikely with a 64-bit FNV-1a id,
/// but we refuse rather than overwrite. Returns `Ok(true)` when `id` already
/// maps to this same path (caller treats it as an idempotent no-op), `Ok(false)`
/// when `id` is free.
fn ensure_no_id_collision(state: &AppState, id: &str, cpath: &Path) -> Result<bool, String> {
    match state.vaults.get(id) {
        Some(rv) if rv.path == cpath => Ok(true),
        Some(rv) => Err(format!(
            "vault id collision: {id} already maps to {}; refusing to register {}",
            rv.path.display(),
            cpath.display(),
        )),
        None => Ok(false),
    }
}

// --- persistence -----------------------------------------------------------

/// What the bundle identifier used to be, and therefore what the app's config
/// directory used to be called.
const LEGACY_BUNDLE_ID: &str = "com.trove.desktop";

/// Move settings and the vault list over from the old identifier's directory,
/// once.
///
/// macOS keys an app's data directory by bundle identifier, so renaming the
/// bundle orphans everything the app had written — for trove that is the list
/// of registered vaults and the agent settings, i.e. the app comes up looking
/// factory-new with the user's vaults apparently gone. Copying rather than
/// moving leaves the old directory intact, so an older build still works and
/// nothing is destroyed if this goes wrong.
///
/// Only runs when the new directory has no file of that name yet, so it can
/// never overwrite newer state, and it is safe to call on every start.
pub fn migrate_legacy_config(app: &AppHandle) {
    let Ok(new_dir) = app.path().app_config_dir() else {
        return;
    };
    let Some(old_dir) = new_dir.parent().map(|parent| parent.join(LEGACY_BUNDLE_ID)) else {
        return;
    };
    if !old_dir.is_dir() || old_dir == new_dir {
        return;
    }
    for name in [RECENTS_FILE, SETTINGS_FILE] {
        let (from, to) = (old_dir.join(name), new_dir.join(name));
        if !from.is_file() || to.exists() {
            continue;
        }
        if std::fs::create_dir_all(&new_dir).is_err() {
            return;
        }
        match std::fs::copy(&from, &to) {
            Ok(_) => eprintln!("trove: carried {name} over from {LEGACY_BUNDLE_ID}"),
            // Not fatal: the app still opens, the user re-adds their vaults.
            Err(e) => eprintln!("trove: could not carry {name} over: {e}"),
        }
    }
}

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

fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("resolving app config dir: {e}"))?;
    Ok(dir.join(SETTINGS_FILE))
}

/// Read settings, falling back to defaults for a missing or unreadable file —
/// a corrupt settings file must never stop the app from opening a vault.
pub fn load_settings(app: &AppHandle) -> Settings {
    let Ok(path) = settings_path(app) else {
        return Settings::default();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return Settings::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn save_settings(app: &AppHandle, settings: &Settings) -> Result<(), String> {
    let path = settings_path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("creating app config dir: {e}"))?;
    }
    let json = serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("writing settings: {e}"))
}

/// What build this is, for the title bar.
///
/// Two parts: the version, which every build has, and an optional mode. A
/// production build has an empty mode, so its version stands alone and nothing
/// has to be stripped back off for display; anything else carries the mode and
/// the commit, because "which build am I looking at" is otherwise guesswork
/// when a dev window and an installed one look identical.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildInfo {
    pub version: String,
    /// Empty in production; otherwise "dev", "rc", "nightly"… Set at compile
    /// time from `TROVE_BUILD_MODE`.
    pub mode: String,
    /// Short commit, or empty outside a git checkout. Only interesting
    /// alongside a mode — a release is identified by its version.
    pub commit: String,
}

#[tauri::command]
pub fn build_info() -> BuildInfo {
    BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        mode: env!("TROVE_BUILD_MODE").to_string(),
        commit: env!("TROVE_DESKTOP_GIT").to_string(),
    }
}

// --- unlock progress -------------------------------------------------------

/// One step of an unlock, reported to the UI as it happens.
///
/// Unlock is slow by construction — the KDF is deliberately expensive, and the
/// agent hand-off is a round trip per key — so a silent dialog reads as a
/// hang. The frontend renders these as a checklist and ticks them off.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UnlockStep {
    /// Stable id the UI matches on: `open`, `entries`, `agent`, `files`.
    pub step: &'static str,
    /// `pending` while running, `done` when finished, `skipped` when the
    /// setting is off, `failed` when it did not work (never fatal).
    pub state: &'static str,
    /// Human detail, e.g. "4 keys" — shown beside the step.
    pub detail: String,
}

const UNLOCK_PROGRESS_EVENT: &str = "unlock-progress";

fn step(app: &AppHandle, step: &'static str, state: &'static str, detail: impl Into<String>) {
    // Best-effort: a UI that isn't listening must never fail an unlock.
    let _ = app.emit(
        UNLOCK_PROGRESS_EVENT,
        UnlockStep {
            step,
            state,
            detail: detail.into(),
        },
    );
}

// --- unlock/lock side effects ----------------------------------------------

/// Push this vault's SSH keys into the system agent, returning what went in so
/// `lock` can take exactly those back out.
///
/// The heavy lifting is `troved`'s forwarding code, which honours each entry's
/// `KeeAgent.settings` — whether to load it at all, its lifetime, and whether
/// the agent should confirm each use. The app supplies only the yes/no and the
/// fallback window, because the daemon takes those from the environment and a
/// windowed app has no shell.
///
/// Best-effort by design: a vault still opens if the agent is unreachable.
async fn export_keys(vault: &Vault, settings: &Settings) -> (Vec<ForwardedKey>, Option<u64>) {
    if !settings.system_agent {
        return (Vec::new(), None);
    }
    let keys: Vec<LoadedKey> = troved::handler::load_ssh_keys_from_vault(vault);
    if keys.is_empty() {
        return (Vec::new(), None);
    }
    // Awaited, not `block_on`: this is socket I/O with a per-key timeout, and
    // blocking a thread on it is what made the window freeze.
    let forward =
        ssh_agent::forward_on_unlock_when(true, &keys, u64::from(settings.system_agent_lifetime))
            .await;
    for w in forward.warnings {
        eprintln!("trove: ssh-agent: warning: {w}");
    }
    // A healed `SSH_AUTH_SOCK` is worth saying once. The app cannot pass the
    // corrected socket on the way the CLI does — there is no shell to put it in
    // — but the keys did reach the live agent, which is what matters here.
    for n in forward.notes {
        eprintln!("trove: ssh-agent: {n}");
    }
    (
        ssh_agent::keys_to_unforward(&keys),
        soonest_expiry(&keys, settings.system_agent_lifetime),
    )
}

/// When the soonest of `keys` expires, given the app default for any key that
/// doesn't state its own. Mirrors the rule in `forward::on_unlock_when`: the
/// entry's lifetime wins, otherwise the default, and 0 anywhere means never.
fn soonest_expiry(keys: &[LoadedKey], default_secs: u32) -> Option<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    keys.iter()
        .map(|k| k.forward.lifetime_secs.unwrap_or(default_secs))
        .filter(|secs| *secs > 0)
        .min()
        .map(|secs| now + u64::from(secs))
}

/// Materialize every entry whose `Materialize.*` fields validate. Plan errors
/// are reported, never fatal — one bad entry must not block the unlock.
fn materialize_all(
    vault: &Vault,
    vault_path: &Path,
    store: &MaterializedStore,
    settings: &Settings,
) {
    if !settings.materialize {
        return;
    }
    // The daemon keys materialized files by vault so `lock --vault` wipes only
    // that vault's; the app has one store per registered vault but passes the
    // same key so the bookkeeping matches.
    let vault_key = troved::vaults::canonical_key(vault_path);
    let (plans, errors) = materialize::build_plans(vault);
    for (title, e) in errors {
        eprintln!("trove: skipping materialization for '{title}': {e}");
    }
    for plan in &plans {
        match materialize::materialize_one(vault, &vault_key, plan, store.clone()) {
            Ok(MaterializedFile { target, .. }) => {
                eprintln!("trove: materialized {}", target.display())
            }
            Err(e) => eprintln!("trove: materializing '{}' failed: {e}", plan.entry_title),
        }
    }
}

/// Undo both side effects, in the daemon's order: files off disk first, then
/// keys out of the agent.
async fn undo_side_effects(exported: Vec<ForwardedKey>, materialized: MaterializedStore) {
    materialize::wipe_all(&materialized).await;
    if !exported.is_empty() {
        ssh_agent::unforward_on_lock(&exported).await;
    }
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

/// Run `f` against an open vault, off the main thread.
///
/// EVERY command that touches a vault must go through this. A synchronous
/// `#[tauri::command]` runs on the MAIN thread, and these commands hold a
/// `std::sync::Mutex` over the whole app state while doing kdbx work — so a
/// sync command is a frozen window and a queue of everything behind it. The
/// lock is taken and released inside the blocking task, never across an await.
///
/// `AppHandle` is `Send`, which is what lets the state be reached from there;
/// `State` itself cannot cross the boundary.
async fn on_vault<T, F>(app: AppHandle, id: String, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&Vault) -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<VaultState>();
        with_open(&state, &id, f)
    })
    .await
    .map_err(|e| format!("vault task panicked: {e}"))?
}

/// [`on_vault`] for the mutating half.
async fn on_vault_mut<T, F>(app: AppHandle, id: String, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&mut Vault) -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<VaultState>();
        with_open_mut(&state, &id, f)
    })
    .await
    .map_err(|e| format!("vault task panicked: {e}"))?
}

/// Run any state-touching work off the main thread, for commands that need the
/// registry rather than an open vault.
async fn off_main<T, F>(app: AppHandle, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&AppHandle) -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || f(&app))
        .await
        .map_err(|e| format!("task panicked: {e}"))?
}

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
    let (ssh_key_attachment, agent_key, policy) =
        agent_key_state(vault, &s.id, &s.attachment_names);

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
        ssh_key_attachment,
        agent_key,
        agent_lifetime: policy.lifetime_secs,
        agent_confirm: policy.confirm,
        agent_remove_on_close: policy.remove_at_close,
    }
}

/// Which attachment on this entry is an SSH private key, and whether the entry
/// currently asks for it to be loaded into an agent.
///
/// `KeeAgent.settings` is authoritative when present — it names the attachment
/// and carries the opt-in. Without it we look for a parseable key so the UI can
/// still offer the toggle, and report it as not declared (which is exactly how
/// the export path treats it).
fn agent_key_state(
    vault: &Vault,
    id: &EntryId,
    attachment_names: &[String],
) -> (String, bool, keeagent::AgentPolicy) {
    if attachment_names
        .iter()
        .any(|a| a == keeagent::ATTACHMENT_NAME)
    {
        if let Ok(Some(bytes)) = vault.read_binary(id, keeagent::ATTACHMENT_NAME) {
            // A declared entry names its attachment and is opted in; an entry
            // that opted out still says which attachment it was about, so read
            // that out of the blob either way. The policy comes back for both,
            // so the editor shows what is stored rather than a default.
            let named = keeagent_attachment_name(&bytes);
            return match keeagent::parse(&bytes, "") {
                keeagent::Decision::Load {
                    attachment,
                    forward,
                } => (
                    attachment,
                    true,
                    keeagent::AgentPolicy {
                        allow: true,
                        lifetime_secs: forward.lifetime_secs,
                        confirm: forward.confirm,
                        remove_at_close: forward.remove_at_close,
                    },
                ),
                keeagent::Decision::Skip => (
                    named.unwrap_or_default(),
                    false,
                    stored_policy(&bytes).unwrap_or_default(),
                ),
            };
        }
    }
    // No settings at all: the key is found by content scan, so it is not
    // declared and carries the defaults an editor would start from.
    let found = attachment_names
        .iter()
        .find(|name| {
            vault
                .read_binary(id, name)
                .ok()
                .flatten()
                .is_some_and(|b| troved::ssh_agent::keys::parse_private_key(&b, "").is_ok())
        })
        .cloned()
        .unwrap_or_default();
    (found, false, keeagent::AgentPolicy::default())
}

/// Decode a settings blob to text, handling UTF-16 the way the loader does.
fn keeagent_text(bytes: &[u8]) -> Option<String> {
    troved::ssh_agent::keeagent::decode(bytes)
}

/// Read the stored policy out of a blob the loader decided to Skip, so an entry
/// that is switched off still shows the lifetime/confirm it had.
fn stored_policy(bytes: &[u8]) -> Option<keeagent::AgentPolicy> {
    let text = keeagent_text(bytes)?;
    let tag = |k: &str| -> Option<String> {
        let open = format!("<{k}>");
        let close = format!("</{k}>");
        let start = text.find(&open)? + open.len();
        let rest = &text[start..];
        Some(rest[..rest.find(&close)?].trim().to_string())
    };
    let flag = |k: &str| tag(k).is_some_and(|v| v.eq_ignore_ascii_case("true"));
    Some(keeagent::AgentPolicy {
        allow: false,
        lifetime_secs: (flag("UseLifetimeConstraintWhenAdding")
            || flag("UseLifetimeConstraintWhenSigning"))
        .then(|| tag("LifetimeConstraintDuration").and_then(|d| d.parse().ok()))
        .flatten(),
        confirm: flag("UseConfirmConstraintWhenAdding") || flag("UseConfirmConstraintWhenSigning"),
        remove_at_close: tag("RemoveAtDatabaseClose")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true),
    })
}

/// Pull `<AttachmentName>` out of a settings blob without judging the opt-in.
fn keeagent_attachment_name(bytes: &[u8]) -> Option<String> {
    // Through the shared decoder: KeePassXC writes UTF-16, and `from_utf8`
    // accepts those bytes while matching no tags.
    let xml = &keeagent_text(bytes)?;
    let start = xml.find("<AttachmentName>")? + "<AttachmentName>".len();
    let rest = &xml[start..];
    let end = rest.find("</AttachmentName>")?;
    Some(rest[..end].trim().to_string())
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
        // Route startup hydration through the same collision check as
        // register/create so the behaviour is consistent. On a genuine
        // (1-in-2^64) FNV id collision with a *different* path there is no id
        // that can key both vaults, so the newcomer is skipped — but loudly,
        // not silently: startup must stay resilient (one bad recent must never
        // blank the whole switcher), yet a dropped vault should be diagnosable.
        match ensure_no_id_collision(&guard, &id, &cpath) {
            Ok(true) => continue, // already registered under this same path
            Ok(false) => {
                guard
                    .vaults
                    .insert(id, RegisteredVault::new(cpath, r.name.clone()));
            }
            Err(e) => eprintln!("trove: skipping recent vault — {e}"),
        }
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
        if ensure_no_id_collision(&guard, &id, &cpath)? {
            // Already registered to this same path — idempotent.
            let rv = guard
                .vaults
                .get(&id)
                .expect("collision check saw it present");
            return Ok(vault_dto(&id, rv));
        }
        guard.vaults.insert(
            id.clone(),
            RegisteredVault::new(cpath.clone(), name.clone()),
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
        // Refuse to overwrite a *different* vault that hashes to the same id.
        // (Same path re-creating over itself is fine — it just re-registers.)
        ensure_no_id_collision(&guard, &id, &cpath)?;
        guard.vaults.insert(id.clone(), {
            let mut rv = RegisteredVault::new(cpath.clone(), name.clone());
            rv.vault = Some(vault);
            rv
        });
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
/// The registered vault's path, or an error naming the id that is not known.
///
/// The lock is taken and released here rather than held across the work that
/// follows: every command in this file learned that lesson when holding it
/// across an unlock froze the window.
fn vault_path(id: &str, state: &State<'_, VaultState>) -> Result<PathBuf, String> {
    let guard = state.lock().map_err(poisoned)?;
    guard
        .vaults
        .get(id)
        .map(|v| v.path.clone())
        .ok_or_else(|| format!("vault is not registered: {id}"))
}

/// Whether this Mac can do Touch ID at all, and whether THIS vault has a
/// password stored for it.
///
/// Both are asked at the moment the unlock screen draws, because both change
/// underneath you: biometry goes away when the lid is shut on a clamshell
/// setup or after too many failed attempts, and the entry can be removed from
/// Keychain Access or by the CLI at any time.
#[tauri::command]
pub async fn biometric_status(
    id: String,
    state: State<'_, VaultState>,
) -> Result<BiometricDto, String> {
    let path = vault_path(&id, &state)?;
    let enrolled = tauri::async_runtime::spawn_blocking(move || biometric::is_enrolled(&path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    Ok(BiometricDto {
        available: biometric::available(),
        enrolled,
    })
}

/// Unlock with a fingerprint instead of a typed password.
///
/// Returns `Ok(None)` when the prompt was cancelled or nothing is stored —
/// both are ordinary outcomes that leave the password field waiting, not
/// errors to put in front of someone.
#[tauri::command]
pub async fn biometric_unlock(
    app: AppHandle,
    id: String,
    state: State<'_, VaultState>,
) -> Result<Option<Vec<EntryDto>>, String> {
    let path = vault_path(&id, &state)?;
    let name = path
        .file_stem()
        .map(|s: &std::ffi::OsStr| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "your vault".to_string());
    let reason = format!("unlock {name}");

    // Off the main thread: the prompt blocks until the user answers it, and
    // that is exactly the freeze this app was fixed for.
    let password = {
        let path = path.clone();
        tauri::async_runtime::spawn_blocking(move || biometric::unlock(&path, &reason))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?
    };
    let Some(password) = password else {
        return Ok(None);
    };
    unlock_vault(app, id, password, state).await.map(Some)
}

/// Remember this vault's password for Touch ID.
///
/// The password is proved against the vault first: an entry that does not open
/// it is worse than none, because it fails later and somewhere else.
#[tauri::command]
pub async fn biometric_enroll(
    id: String,
    password: String,
    state: State<'_, VaultState>,
) -> Result<(), String> {
    let path = vault_path(&id, &state)?;
    tauri::async_runtime::spawn_blocking(move || {
        trove_core::Vault::open(&path, &password)
            .map_err(|e| format!("that password does not open this vault: {e}"))?;
        biometric::enroll(&path, &password).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Forget this vault's stored password.
#[tauri::command]
pub async fn biometric_forget(id: String, state: State<'_, VaultState>) -> Result<bool, String> {
    let path = vault_path(&id, &state)?;
    tauri::async_runtime::spawn_blocking(move || biometric::forget(&path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn unlock_vault(
    app: AppHandle,
    id: String,
    password: String,
    state: State<'_, VaultState>,
) -> Result<Vec<EntryDto>, String> {
    // ASYNC ON PURPOSE. A synchronous #[tauri::command] runs on the MAIN
    // thread, and unlock is the heaviest thing this app does: an Argon2 KDF by
    // design, then socket round-trips to the OS agent (one per key, each with
    // its own timeout) and file writes. Doing that on the main thread freezes
    // the window; doing it while holding the state mutex freezes every other
    // command behind it too. So: never hold the lock across an await, and keep
    // the CPU-bound open off the runtime's own threads.
    let path = {
        let guard = state.lock().map_err(poisoned)?;
        guard
            .vaults
            .get(&id)
            .ok_or_else(|| "vault is not registered".to_string())?
            .path
            .clone()
    };

    step(&app, "open", "pending", "decrypting");
    let open_path = path.clone();
    let vault = tauri::async_runtime::spawn_blocking(move || Vault::open(&open_path, &password))
        .await
        .map_err(|e| format!("unlock task panicked: {e}"))?
        .map_err(|e| {
            step(&app, "open", "failed", "wrong password");
            e.to_string()
        })?;
    step(&app, "open", "done", "");

    step(&app, "entries", "pending", "");
    let entries = build_entry_dtos(&vault);
    step(
        &app,
        "entries",
        "done",
        format!("{} entries", entries.len()),
    );

    // Unlocking here does what unlocking in the daemon does: keys into the
    // system agent (the only route to applications and terminals that can't be
    // pointed at our own socket) and materialized files onto disk. Both are
    // settings-gated and both are undone by `lock_vault`.
    let settings = load_settings(&app);

    if settings.system_agent {
        step(&app, "agent", "pending", "");
    } else {
        step(&app, "agent", "skipped", "turned off");
    }
    let (exported, keys_expire_at) = export_keys(&vault, &settings).await;
    if settings.system_agent {
        step(
            &app,
            "agent",
            "done",
            match exported.len() {
                0 => "no keys marked for the agent".to_string(),
                1 => "1 key".to_string(),
                n => format!("{n} keys"),
            },
        );
    }

    let materialized = MaterializedStore::default();
    if settings.materialize {
        step(&app, "files", "pending", "");
    } else {
        step(&app, "files", "skipped", "turned off");
    }
    materialize_all(&vault, &path, &materialized, &settings);
    if settings.materialize {
        let n = materialized.read().await.len();
        step(&app, "files", "done", format!("{n} written"));
    }

    {
        let mut guard = state.lock().map_err(poisoned)?;
        let rv = guard
            .vaults
            .get_mut(&id)
            .ok_or_else(|| "vault vanished while unlocking".to_string())?;
        rv.exported_keys = exported;
        rv.keys_expire_at = keys_expire_at;
        rv.materialized = materialized;
        rv.vault = Some(vault);
    }
    Ok(entries)
}

/// Drop the decrypted vault (keep it registered), marking it locked.
#[tauri::command]
/// `retract_keys` decides whether what trove handed the machine comes back:
/// keys out of the OS agent, materialized files off disk.
/// An EXPLICIT lock does (KeePassXC parity, honouring each entry's
/// `RemoveAtDatabaseClose`). The idle timer does NOT: it exists to blank a
/// window left untouched, and revoking machine-wide credentials because nobody
/// clicked the app for five minutes pulls keys out from under a running
/// `git push`. Absent ⇒ true, so an older caller keeps the safer behaviour.
pub async fn lock_vault(
    id: String,
    retract_keys: Option<bool>,
    state: State<'_, VaultState>,
) -> Result<(), String> {
    // Same reasoning as `unlock_vault`: retracting keys from the OS agent and
    // wiping files is I/O, and a sync command would do it on the main thread.
    // Take what has to be undone out under a short lock, drop the vault so it
    // reads as locked immediately, then do the undoing without the lock held.
    // One rule, both kinds of handover: an app lock HIDES (window locks, vault
    // forgotten, nothing outside the app is touched); an explicit lock PUTS
    // EVERYTHING BACK (keys retracted, files wiped). Wiping files on an idle
    // timer while leaving keys was the inconsistency — the timer says nobody
    // clicked the window, which says nothing about what the terminal is doing,
    // and a kubeconfig yanked mid-`kubectl` fails the same way a key does.
    // Both handovers have their own expiry for the "after a while" case.
    let put_back = retract_keys.unwrap_or(true);
    let (exported, materialized) = {
        let mut guard = state.lock().map_err(poisoned)?;
        let rv = guard
            .vaults
            .get_mut(&id)
            .ok_or_else(|| "vault is not registered".to_string())?;
        rv.vault = None;
        if put_back {
            rv.keys_expire_at = None;
            (
                std::mem::take(&mut rv.exported_keys),
                std::mem::take(&mut rv.materialized),
            )
        } else {
            (Vec::new(), MaterializedStore::default())
        }
    };
    undo_side_effects(exported, materialized).await;
    Ok(())
}

/// Current app settings, for the settings UI.
#[tauri::command]
pub async fn get_settings(app: AppHandle) -> Result<Settings, String> {
    off_main(app, |a| Ok(load_settings(a))).await
}

/// Persist app settings. Takes effect on the next unlock; already-exported
/// keys stay in the agent until the vault locks.
#[tauri::command]
pub async fn set_settings(app: AppHandle, settings: Settings) -> Result<(), String> {
    off_main(app, move |a| save_settings(a, &settings)).await
}

/// Has this vault's file been written by something else since we read it?
///
/// Polled by the window rather than pushed from a file watcher: it is one
/// `stat` on a path we already know, it only matters while somebody is looking
/// at the list, and there is no watcher to leak when a vault closes.
#[tauri::command]
pub async fn vault_changed_on_disk(app: AppHandle, id: String) -> Result<bool, String> {
    on_vault(app, id, |v| Ok(v.changed_on_disk())).await
}

/// Re-read a vault whose file was changed by something else, returning the
/// entry list as it now stands.
///
/// Safe to call unprompted because this app writes every change through
/// immediately — there is no unsaved state to lose, and a list that no longer
/// matches the file is worse than a list that jumps.
#[tauri::command]
pub async fn reload_vault(app: AppHandle, id: String) -> Result<Vec<EntryDto>, String> {
    on_vault_mut(app, id, |v| {
        v.reload().map_err(|e| e.to_string())?;
        Ok(build_entry_dtos(v))
    })
    .await
}

/// Re-read the entry list for an unlocked vault.
#[tauri::command]
pub async fn list_entries(app: AppHandle, id: String) -> Result<Vec<EntryDto>, String> {
    on_vault(app, id, |v| Ok(build_entry_dtos(v))).await
}

// --- commands: reading one entry -------------------------------------------

/// Read a single field (e.g. `Password`) for one entry, on demand.
#[tauri::command]
pub async fn get_field(
    app: AppHandle,
    id: String,
    entry_id: String,
    field: String,
) -> Result<Option<String>, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    on_vault(app, id, move |v| {
        v.get_field(&eid, &field).map_err(|e| e.to_string())
    })
    .await
}

/// Notes + custom fields + password for the selected entry.
#[tauri::command]
pub async fn get_entry_detail(
    app: AppHandle,
    id: String,
    entry_id: String,
) -> Result<EntryDetailDto, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    on_vault(app, id, move |v| entry_detail(v, &eid)).await
}

// --- commands: mutations ----------------------------------------------------

/// Create or update an entry, save the vault, return the fresh list + saved id.
#[tauri::command]
pub async fn save_entry(
    app: AppHandle,
    id: String,
    input: EntryInput,
) -> Result<SaveResult, String> {
    on_vault_mut(app, id, move |vault| {
        let entry_id = apply_save_entry(vault, &input)?;
        Ok(SaveResult {
            entries: build_entry_dtos(vault),
            id: entry_id.as_str().to_string(),
        })
    })
    .await
}

/// Move an entry to the recycle bin, save, return the fresh list.
#[tauri::command]
pub async fn delete_entry(
    app: AppHandle,
    id: String,
    entry_id: String,
) -> Result<Vec<EntryDto>, String> {
    // Not `unwrap`: a malformed id would panic the command, and a panic inside
    // the blocking task surfaces as an unhelpful "task panicked".
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    on_vault_mut(app, id, move |vault| {
        apply_delete(vault, &eid)?;
        Ok(build_entry_dtos(vault))
    })
    .await
}

/// Set/clear the favorite flag, save, return the fresh list.
#[tauri::command]
pub async fn set_favorite(
    app: AppHandle,
    id: String,
    entry_id: String,
    fav: bool,
) -> Result<Vec<EntryDto>, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    on_vault_mut(app, id, move |vault| {
        apply_set_favorite(vault, &eid, fav)?;
        Ok(build_entry_dtos(vault))
    })
    .await
}

/// Set this entry's SSH-agent policy: whether the key is added on unlock, how
/// long the agent should keep it, whether to confirm each use, and whether a
/// lock takes it back.
///
/// Writes the same `KeeAgent.settings` bytes KeePassXC reads, so the choice
/// travels with the vault file and both tools agree. Applies immediately as
/// well as on the next unlock.
///
/// `lifetime` is seconds, or `null` for "use the app default" — the same
/// meaning `UseLifetimeConstraintWhenAdding=false` has in the file.
#[tauri::command]
pub async fn set_agent_key(
    app: AppHandle,
    id: String,
    entry_id: String,
    enabled: bool,
    lifetime: Option<u32>,
    confirm: Option<bool>,
    remove_on_close: Option<bool>,
) -> Result<Vec<EntryDto>, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    let settings = load_settings(&app);
    let policy = keeagent::AgentPolicy {
        allow: enabled,
        lifetime_secs: lifetime.filter(|n| *n > 0),
        confirm: confirm.unwrap_or(false),
        remove_at_close: remove_on_close.unwrap_or(true),
    };

    // Phase 1 — vault write, under the lock, on a blocking thread. Returns the
    // key so the agent work can happen with the lock released.
    let write = {
        let app = app.clone();
        let id = id.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let state = app.state::<VaultState>();
            with_open_mut(&state, &id, move |vault| {
                let summary = vault
                    .list_entries()
                    .into_iter()
                    .find(|s| s.id == eid)
                    .ok_or_else(|| "entry not found".to_string())?;
                let (attachment, _, _) = agent_key_state(vault, &eid, &summary.attachment_names);
                if attachment.is_empty() {
                    return Err("this entry has no SSH private key attachment".to_string());
                }
                let key_bytes = vault
                    .read_binary(&eid, &attachment)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("attachment '{attachment}' is missing"))?;
                // Parsed up front to learn the public blob — how the agent
                // addresses this key — and to refuse early if it isn't usable.
                let probe = troved::ssh_agent::keys::parse_private_key(&key_bytes, &summary.title)
                    .map_err(|e| {
                        format!("attachment '{attachment}' is not a usable SSH key: {e}")
                    })?;
                vault
                    .attach_binary(
                        &eid,
                        keeagent::ATTACHMENT_NAME,
                        &keeagent::settings_xml_policy(
                            &attachment,
                            policy,
                            keeagent::Encoding::Utf8,
                        ),
                    )
                    .map_err(|e| e.to_string())?;
                vault.save().map_err(|e| e.to_string())?;
                // Re-read so the key carries the policy just written. On
                // disable the loader no longer returns it, so fall back to the
                // probe — the agent still has to be told to drop it.
                let key = troved::handler::load_ssh_keys_from_vault(vault)
                    .into_iter()
                    .find(|k| k.public_blob == probe.public_blob)
                    .unwrap_or(probe);
                Ok(key)
            })
        })
        .await
        .map_err(|e| format!("vault task panicked: {e}"))??
    };

    // Phase 2 — agent I/O with NO lock held. A round trip per key with its own
    // timeout; holding the state mutex across it would block every other
    // command, which is what the sync version did.
    if settings.system_agent {
        if enabled {
            let forward = ssh_agent::forward_on_unlock_when(
                true,
                std::slice::from_ref(&write),
                u64::from(settings.system_agent_lifetime),
            )
            .await;
            for w in forward.warnings {
                eprintln!("trove: ssh-agent: warning: {w}");
            }
            for n in forward.notes {
                eprintln!("trove: ssh-agent: {n}");
            }
        } else {
            // Not `keys_to_unforward`: that honours RemoveAtDatabaseClose, and
            // this is an explicit "take it out now" regardless.
            ssh_agent::unforward_on_lock(&[ForwardedKey::from(&write)]).await;
        }
    }

    // Phase 3 — bookkeeping + the fresh list, under the lock again.
    let blob = write.public_blob.clone();
    let forwarded = ssh_agent::keys_to_unforward(std::slice::from_ref(&write));
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<VaultState>();
        let mut guard = state.lock().map_err(poisoned)?;
        let rv = guard
            .vaults
            .get_mut(&id)
            .ok_or_else(|| "vault is not registered".to_string())?;
        if enabled {
            for f in forwarded {
                if !rv
                    .exported_keys
                    .iter()
                    .any(|k| k.public_blob == f.public_blob)
                {
                    rv.exported_keys.push(f);
                }
            }
        } else {
            rv.exported_keys.retain(|k| k.public_blob != blob);
        }
        let vault = rv
            .vault
            .as_ref()
            .ok_or_else(|| "vault is locked".to_string())?;
        Ok(build_entry_dtos(vault))
    })
    .await
    .map_err(|e| format!("vault task panicked: {e}"))?
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

    #[test]
    fn id_collision_with_a_different_path_is_rejected() {
        let mut state = AppState::default();
        let id = vault_id_for(Path::new("/vaults/a.kdbx"));
        state.vaults.insert(
            id.clone(),
            RegisteredVault::new(PathBuf::from("/vaults/a.kdbx"), "a".to_string()),
        );

        // Same id + same path → idempotent, no clobber.
        assert_eq!(
            ensure_no_id_collision(&state, &id, Path::new("/vaults/a.kdbx")),
            Ok(true)
        );
        // Same id + a *different* path → rejected rather than overwriting.
        assert!(ensure_no_id_collision(&state, &id, Path::new("/vaults/b.kdbx")).is_err());
        // A free id → Ok(false).
        let free = vault_id_for(Path::new("/vaults/c.kdbx"));
        assert_eq!(
            ensure_no_id_collision(&state, &free, Path::new("/vaults/c.kdbx")),
            Ok(false)
        );
    }
}
