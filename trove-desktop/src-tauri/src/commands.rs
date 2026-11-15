//! Tauri command surface bridging the UI to `trove-core`.
//!
//! The app manages a *set* of registered databases (the "Open databases" switcher).
//! Each is either **locked** (path known, not decrypted) or **unlocked**
//! (a decrypted [`Database`] held in memory). The whole set lives in Tauri-managed
//! state behind a single `Mutex<AppState>`, keyed by a stable database id derived
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
use std::time::Instant;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use crate::biometric;
use crate::daemon_host::{DaemonHost, DaemonStatus};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter as _, Manager, State};
use trove_core::settings::{self, Attributes, Capability, Document, Origin};
use trove_core::{Database, DatabaseMetadata, EntryId};
use troved::materialize::{self, MaterializedFile, MaterializedStore};
use troved::ssh_agent::{self, keeagent, ForwardedKey, LoadedKey};
use zxcvbn::zxcvbn;

mod lifecycle;
mod revisions;
pub use lifecycle::*;
pub use revisions::*;

/// Basename of the JSON file (in the app config dir) that persists the
/// registered database set as a list of `{path, name}`.
const RECENTS_FILE: &str = "databases.json";

/// Basename of the JSON file (in the app config dir) holding app settings.
const SETTINGS_FILE: &str = "settings.json";

const FAVORITE_TAG: &str = "Favorite";

// --- state -----------------------------------------------------------------

/// A registered database: its canonical path, display name, and — when unlocked —
/// the decrypted [`Database`]. `database: None` means locked.
pub struct RegisteredDatabase {
    pub path: PathBuf,
    pub name: String,
    pub trove_uuid: Option<String>,
    pub database: Option<Database>,
    /// The keys this database pushed into the system agent, so locking removes
    /// exactly those and never another database's (or another app's) identities.
    /// `ForwardedKey` carries the per-entry `RemoveAtDatabaseClose` wish.
    pub exported_keys: Vec<ForwardedKey>,
    /// Files this database materialized, wiped on lock. Shares the daemon's
    /// store type so `materialize::wipe_all` does the removal.
    pub materialized: MaterializedStore,
    /// Unix seconds at which the first forwarded key expires, or `None` when
    /// nothing was forwarded or nothing expires. The agent keeps its own clock
    /// and never reports it, so this is trove's record of what it asked for.
    pub keys_expire_at: Option<u64>,
    /// How long this database's last KDF-bearing operation took, in milliseconds:
    /// seeded by the unlock, replaced by each save. Writing a KDBX is not
    /// instant — a fresh master seed per save means a fresh Argon2 derivation
    /// — and the cost is a property of THIS database's KDF settings, so a
    /// measurement beats any constant we could pick. The UI sizes its progress
    /// bar with it.
    pub write_ms: Option<u64>,
}

impl RegisteredDatabase {
    pub fn new(path: PathBuf, name: String) -> Self {
        Self {
            path,
            name,
            trove_uuid: None,
            database: None,
            exported_keys: Vec::new(),
            materialized: MaterializedStore::default(),
            keys_expire_at: None,
            write_ms: None,
        }
    }
}

/// Persisted app settings. Mirrors the daemon's switches, but as real
/// settings rather than environment variables — a GUI has no shell.
#[derive(Serialize, Deserialize, Clone)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    /// Push the database's SSH keys into the OS agent on unlock, remove on lock.
    /// This is what makes database keys usable by other applications and by a
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
    /// Minutes of no interaction before the database view locks itself. `0`
    /// disables it.
    ///
    /// This closes the window and drops the decrypted database; it does NOT
    /// retract keys from the OS agent, which have their own expiry. Locking a
    /// UI and revoking machine-wide credentials are different decisions.
    pub idle_lock_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseMetadataDto {
    pub name: Option<String>,
    pub description: Option<String>,
    pub default_username: Option<String>,
    pub trove_uuid: Option<String>,
}

impl From<DatabaseMetadata> for DatabaseMetadataDto {
    fn from(metadata: DatabaseMetadata) -> Self {
        Self {
            name: metadata.name,
            description: metadata.description,
            default_username: metadata.default_username,
            trove_uuid: metadata.trove_uuid,
        }
    }
}

impl From<DatabaseMetadataDto> for DatabaseMetadata {
    fn from(metadata: DatabaseMetadataDto) -> Self {
        Self {
            name: metadata.name.filter(|value| !value.is_empty()),
            description: metadata.description.filter(|value| !value.is_empty()),
            default_username: metadata.default_username.filter(|value| !value.is_empty()),
            trove_uuid: metadata.trove_uuid.filter(|value| !value.is_empty()),
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            // On by default. The per-entry gate is the real control: only
            // entries whose KeeAgent.settings ask for agent loading are
            // exported, which is what `trove add ssh` writes and what
            // KeePassXC users already set. A database of hand-attached,
            // unmarked keys exports nothing.
            system_agent: true,
            system_agent_lifetime: 900,
            materialize: false,
            idle_lock_minutes: 5,
        }
    }
}

/// The full multi-database state: database id → registered database.
#[derive(Default)]
pub struct AppState {
    pub databases: BTreeMap<String, RegisteredDatabase>,
}

/// Tauri-managed handle to [`AppState`].
pub type DatabaseState = Mutex<AppState>;

/// One persisted recent, mirrored to `databases.json`.
#[derive(Serialize, Deserialize, Clone)]
struct RecentEntry {
    path: String,
    name: String,
    #[serde(default)]
    trove_uuid: Option<String>,
}

// --- DTOs (serialized names are what the frontend sees) --------------------

/// A registered database as the switcher sees it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BiometricDto {
    /// A fingerprint reader with an enrolled finger, usable right now.
    pub available: bool,
    /// This database has a password stored for Touch ID to release.
    pub enrolled: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseDto {
    pub id: String,
    pub name: String,
    /// File basename including extension, e.g. `inpace.kdbx`.
    pub file: String,
    pub path: String,
    pub trove_uuid: Option<String>,
    pub locked: bool,
    pub read_only: bool,
    /// How many of this database's keys are currently sitting in the system
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
    /// Tags assigned directly to this entry.
    pub tags: Vec<String>,
    /// Tags inherited from containing groups.
    pub inherited_tags: Vec<String>,
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
    /// Take this key back out of the agent when the database is locked.
    pub agent_remove_on_close: bool,
}

/// One custom string field (`k` = name, `v` = value). Travels both ways now:
/// out in an entry's detail, back in when the form saves.
#[derive(Serialize, Deserialize)]
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
    /// Direct KeePass-native entry tags. `None` preserves tags from older clients.
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// User-visible custom attributes, exactly the set [`entry_detail`]
    /// returns. Optional on the wire so an older frontend that does not send
    /// them leaves the entry's attributes alone rather than wiping them.
    #[serde(default)]
    pub fields: Option<Vec<KvDto>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupDto {
    pub path: Vec<String>,
    pub tags: Vec<String>,
    pub inherited_tags: Vec<String>,
    /// This group is the database's recycle bin (the UI pins it apart).
    pub recycle_bin: bool,
    /// Place among its siblings once someone has arranged them; `None` sorts
    /// alphabetically after the arranged ones.
    pub position: Option<u32>,
}

/// Result of [`save_entry`]: the fresh list plus the saved entry's id (for
/// re-selection in the UI).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveResult {
    pub entries: Vec<EntryDto>,
    pub groups: Vec<GroupDto>,
    pub id: String,
}

/// Result of [`delete_group`]: the fresh lists plus whether the folder went to
/// the recycle bin (`false` means it was destroyed outright).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteGroupResult {
    pub entries: Vec<EntryDto>,
    pub groups: Vec<GroupDto>,
    pub recycled: bool,
}

// --- id / path helpers -----------------------------------------------------

/// Deterministic database id: 16-char lowercase hex of an FNV-1a hash over the
/// canonical path string. FNV-1a is used (not `std`'s `DefaultHasher`, whose
/// output is not guaranteed stable across releases) so the *same file always
/// maps to the same id* across app restarts — the persisted recents depend on
/// it. Std-only, no extra dependency.
fn database_id_for(canonical: &Path) -> String {
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

/// Database display name = file basename without extension (`inpace.kdbx` →
/// `inpace`).
fn database_name(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// File basename including extension (`inpace.kdbx`).
fn database_file(path: &Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn database_dto(id: &str, rv: &RegisteredDatabase) -> DatabaseDto {
    DatabaseDto {
        id: id.to_string(),
        name: rv.name.clone(),
        file: database_file(&rv.path),
        path: rv.path.to_string_lossy().into_owned(),
        trove_uuid: rv.trove_uuid.clone(),
        locked: rv.database.is_none(),
        read_only: database_is_read_only(&rv.path),
        agent_keys: rv.exported_keys.len(),
        keys_expire_at: rv.keys_expire_at,
    }
}

fn database_is_read_only(path: &Path) -> bool {
    let file_read_only = std::fs::metadata(path)
        .map(|metadata| metadata.permissions().readonly())
        .unwrap_or(true);
    let parent_read_only = path
        .parent()
        .and_then(|parent| std::fs::metadata(parent).ok())
        .map(|metadata| metadata.permissions().readonly())
        .unwrap_or(true);
    file_read_only || parent_read_only
}

fn poisoned<T>(_: T) -> String {
    "database state was poisoned".to_string()
}

/// Guard against a database-id hash collision. The id maps 1:1 to a registered
/// database, so silently reusing it for a *different* file would clobber the first
/// registration (and later id-routed unlock/save/delete calls would hit the
/// wrong database). Collisions are astronomically unlikely with a 64-bit FNV-1a id,
/// but we refuse rather than overwrite. Returns `Ok(true)` when `id` already
/// maps to this same path (caller treats it as an idempotent no-op), `Ok(false)`
/// when `id` is free.
fn ensure_no_id_collision(state: &AppState, id: &str, cpath: &Path) -> Result<bool, String> {
    match state.databases.get(id) {
        Some(rv) if rv.path == cpath => Ok(true),
        Some(rv) => Err(format!(
            "database id collision: {id} already maps to {}; refusing to register {}",
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

/// Move settings and the database list over from the old identifier's directory,
/// once.
///
/// macOS keys an app's data directory by bundle identifier, so renaming the
/// bundle orphans everything the app had written — for trove that is the list
/// of registered databases and the agent settings, i.e. the app comes up looking
/// factory-new with the user's databases apparently gone. Copying rather than
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
            // Not fatal: the app still opens, the user re-adds their databases.
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
/// a corrupt settings file must never stop the app from opening a database.
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

/// Push this database's SSH keys into the system agent, returning what went in so
/// `lock` can take exactly those back out.
///
/// The heavy lifting is `troved`'s forwarding code, which honours each entry's
/// `KeeAgent.settings` — whether to load it at all, its lifetime, and whether
/// the agent should confirm each use. The app supplies only the yes/no and the
/// fallback window, because the daemon takes those from the environment and a
/// windowed app has no shell.
///
/// Best-effort by design: a database still opens if the agent is unreachable.
async fn export_keys(database: &Database, settings: &Settings) -> (Vec<ForwardedKey>, Option<u64>) {
    if !settings.system_agent {
        return (Vec::new(), None);
    }
    let keys: Vec<LoadedKey> = troved::handler::load_ssh_keys_from_database(database);
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
    database: &Database,
    database_path: &Path,
    store: &MaterializedStore,
    settings: &Settings,
) {
    if !settings.materialize {
        return;
    }
    // The daemon keys materialized files by database so `lock --database` wipes only
    // that database's; the app has one store per registered database but passes the
    // same key so the bookkeeping matches.
    let database_key = troved::databases::canonical_key(database_path);
    let (plans, errors) = materialize::build_plans(database);
    for (title, e) in errors {
        eprintln!("trove: skipping materialization for '{title}': {e}");
    }
    for plan in &plans {
        match materialize::materialize_one(database, &database_key, plan, store.clone()) {
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
fn persist_recent(
    app: &AppHandle,
    canonical: &Path,
    name: &str,
    trove_uuid: Option<Option<&str>>,
) -> Result<(), String> {
    let cpath = canonical.to_string_lossy().into_owned();
    let mut recents = load_recents(app);
    if let Some(existing) = recents.iter_mut().find(|r| r.path == cpath) {
        existing.name = name.to_string();
        if let Some(trove_uuid) = trove_uuid {
            existing.trove_uuid = trove_uuid.map(str::to_string);
        }
    } else {
        recents.push(RecentEntry {
            path: cpath,
            name: name.to_string(),
            trove_uuid: trove_uuid.flatten().map(str::to_string),
        });
    }
    save_recents(app, &recents)
}

fn cache_database_uuid(
    app: &AppHandle,
    id: &str,
    trove_uuid: Option<String>,
) -> Result<(), String> {
    let app_state = app.state::<DatabaseState>();
    let mut state = app_state.lock().map_err(poisoned)?;
    let database = state
        .databases
        .get_mut(id)
        .ok_or_else(|| "database is not registered".to_string())?;
    database.trove_uuid = trove_uuid.clone();
    persist_recent(
        app,
        &database.path,
        &database.name,
        Some(trove_uuid.as_deref()),
    )
}

// --- open-database access helpers ---------------------------------------------

/// Run `f` against an open database, off the main thread.
///
/// EVERY command that touches a database must go through this. A synchronous
/// `#[tauri::command]` runs on the MAIN thread, and these commands hold a
/// `std::sync::Mutex` over the whole app state while doing kdbx work — so a
/// sync command is a frozen window and a queue of everything behind it. The
/// lock is taken and released inside the blocking task, never across an await.
///
/// `AppHandle` is `Send`, which is what lets the state be reached from there;
/// `State` itself cannot cross the boundary.
async fn on_database<T, F>(app: AppHandle, id: String, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&Database) -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<DatabaseState>();
        with_open(&state, &id, f)
    })
    .await
    .map_err(|e| format!("database task panicked: {e}"))?
}

/// [`on_database`] for the mutating half. In-memory only — see
/// [`on_database_write`] for the mutations that have to reach the file.
async fn on_database_mut<T, F>(app: AppHandle, id: String, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&mut Database) -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<DatabaseState>();
        with_open_mut(&state, &id, f)
    })
    .await
    .map_err(|e| format!("database task panicked: {e}"))?
}

/// Progress for a database write, emitted to the whole window.
///
/// A KDBX save is NOT instant and cannot be made so: the format rotates the
/// master seed on every write, so every write re-derives the key with Argon2
/// — at KeePassXC's own defaults, seconds. (That rotation is the point: it
/// stops two versions of a database being encrypted under the same key.) Without
/// something on screen the window looks hung and people click again.
const DATABASE_WRITE_EVENT: &str = "database-write";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct WriteStep {
    /// `start`, `done` or `failed`.
    phase: &'static str,
    /// What the last write on this database actually cost, in milliseconds, so
    /// the bar is drawn against a measurement rather than a guess. `0` before
    /// anything has been measured — draw an indeterminate bar for that.
    estimate_ms: u64,
    detail: String,
}

fn write_step(app: &AppHandle, phase: &'static str, estimate_ms: u64, detail: impl Into<String>) {
    // Best-effort: a UI that isn't listening must never fail a save.
    let _ = app.emit(
        DATABASE_WRITE_EVENT,
        WriteStep {
            phase,
            estimate_ms,
            detail: detail.into(),
        },
    );
}

/// What the next write on this database is likely to cost, from the last one.
fn write_estimate_ms(app: &AppHandle, id: &str) -> u64 {
    let state = app.state::<DatabaseState>();
    state
        .lock()
        .ok()
        .and_then(|g| g.databases.get(id).and_then(|rv| rv.write_ms))
        .unwrap_or(0)
}

/// Mutate an open database AND persist it, reporting progress while it happens.
///
/// Every mutation that must survive a lock or a quit goes through here.
/// `on_database_mut` alone changes memory only — a database edited that way looks
/// saved and isn't.
async fn on_database_write<T, F>(app: AppHandle, id: String, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&mut Database) -> Result<T, String> + Send + 'static,
{
    let estimate = write_estimate_ms(&app, &id);
    write_step(&app, "start", estimate, "");

    let task_app = app.clone();
    let out = tauri::async_runtime::spawn_blocking(move || {
        let state = task_app.state::<DatabaseState>();
        let mut guard = state.lock().map_err(poisoned)?;
        let rv = guard
            .databases
            .get_mut(&id)
            .ok_or_else(|| "database is not registered".to_string())?;
        let database = rv
            .database
            .as_mut()
            .ok_or_else(|| "database is locked".to_string())?;
        let out = f(database)?;
        // Measure the save alone. The mutation before it is memory work and
        // costs nothing worth reporting; the KDF is the whole of the wait.
        let started = Instant::now();
        database.save().map_err(|e| e.to_string())?;
        rv.write_ms = Some(started.elapsed().as_millis() as u64);
        Ok::<T, String>(out)
    })
    .await
    .map_err(|e| format!("database task panicked: {e}"))?;

    match &out {
        Ok(_) => write_step(&app, "done", 0, ""),
        Err(e) => write_step(&app, "failed", 0, e.clone()),
    }
    out
}

/// Run any state-touching work off the main thread, for commands that need the
/// registry rather than an open database.
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
    state: &State<'_, DatabaseState>,
    id: &str,
    f: impl FnOnce(&Database) -> Result<T, String>,
) -> Result<T, String> {
    let guard = state.lock().map_err(poisoned)?;
    let rv = guard
        .databases
        .get(id)
        .ok_or_else(|| "database is not registered".to_string())?;
    let database = rv
        .database
        .as_ref()
        .ok_or_else(|| "database is locked".to_string())?;
    f(database)
}

fn with_open_mut<T>(
    state: &State<'_, DatabaseState>,
    id: &str,
    f: impl FnOnce(&mut Database) -> Result<T, String>,
) -> Result<T, String> {
    let mut guard = state.lock().map_err(poisoned)?;
    let rv = guard
        .databases
        .get_mut(id)
        .ok_or_else(|| "database is not registered".to_string())?;
    let database = rv
        .database
        .as_mut()
        .ok_or_else(|| "database is locked".to_string())?;
    f(database)
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

fn build_entry_dtos(database: &Database) -> Vec<EntryDto> {
    database
        .list_entries()
        .into_iter()
        .map(|s| entry_dto(database, s))
        .collect()
}

fn build_group_dtos(database: &Database) -> Vec<GroupDto> {
    let bin = database.recycle_bin_path();
    database
        .list_groups()
        .into_iter()
        .map(|group| GroupDto {
            recycle_bin: bin.as_ref() == Some(&group.path),
            path: group.path,
            tags: group.tags,
            inherited_tags: group.inherited_tags,
            position: group.position,
        })
        .collect()
}

fn entry_dto(database: &Database, s: trove_core::EntrySummary) -> EntryDto {
    // Read the reserved fields + password (for strength/length) per entry.
    // These are computed server-side; the password never leaves this function.
    let password = database
        .get_field(&s.id, "Password")
        .ok()
        .flatten()
        .unwrap_or_default();
    let trove_type = database.get_field(&s.id, "_TroveType").ok().flatten();
    let fav = database
        .get_entry_tags(&s.id)
        .is_ok_and(|tags| tags.iter().any(|tag| is_favorite_tag(tag)));

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
        agent_key_state(database, &s.id, &s.attachment_names);

    EntryDto {
        id,
        path,
        title: s.title,
        group: s.group_path,
        group_path,
        tags: s.tags,
        inherited_tags: s.inherited_tags,
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
    database: &Database,
    id: &EntryId,
    attachment_names: &[String],
) -> (String, bool, keeagent::AgentPolicy) {
    if attachment_names
        .iter()
        .any(|a| a == keeagent::ATTACHMENT_NAME)
    {
        if let Ok(Some(bytes)) = database.read_binary(id, keeagent::ATTACHMENT_NAME) {
            // A declared entry names its attachment and is opted in; an entry
            // that opted out still says which attachment it was about, so read
            // that out of the blob either way. The policy comes back for both,
            // so the editor shows what is stored rather than a default.
            let named = keeagent_attachment_name(&bytes);
            return match keeagent::parse(&bytes) {
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
                // Opted out, or opted in to a key trove can't load (an
                // external key file): either way it isn't served, so the
                // editor shows it off with the stored policy.
                keeagent::Decision::Skip | keeagent::Decision::Unusable(_) => (
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
            database
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
fn set_or_clear(
    database: &mut Database,
    id: &EntryId,
    field: &str,
    value: &str,
) -> Result<(), String> {
    if value.is_empty() {
        database.remove_field(id, field).map_err(|e| e.to_string())
    } else {
        database
            .set_field(id, field, value)
            .map_err(|e| e.to_string())
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
fn update_entry_path(database: &mut Database, id: &EntryId, path: &str) -> Result<(), String> {
    let (groups, leaf) = split_entry_path(path)?;
    let current = database
        .get_entry(id)
        .ok_or_else(|| "entry not found".to_string())?;
    if current.group_path != groups {
        let group_path = groups.join("/");
        if !group_path.is_empty() {
            // move_entry requires the destination to exist; ensure it. A
            // pre-existing leaf group is fine (ignore GroupExists).
            match database.add_group(&group_path) {
                Ok(()) | Err(trove_core::Error::GroupExists(_)) => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        database
            .move_entry(id, &group_path)
            .map_err(|e| e.to_string())?;
    }
    database
        .set_field(id, "Title", &leaf)
        .map_err(|e| e.to_string())
}

/// Create or update an entry from `input`, returning its id. The caller saves
/// — every command that mutates goes through [`on_database_write`], which is
/// where the save, its progress events and its timing live.
fn apply_save_entry(database: &mut Database, input: &EntryInput) -> Result<EntryId, String> {
    let entry_id = match &input.entry_id {
        None => database.add_entry(&input.path).map_err(|e| e.to_string())?,
        Some(existing) => {
            // EntryId's FromStr is infallible.
            let eid = EntryId::from_str(existing).unwrap();
            update_entry_path(database, &eid, &input.path)?;
            eid
        }
    };
    set_or_clear(database, &entry_id, "UserName", &input.username)?;
    set_or_clear(database, &entry_id, "Password", &input.password)?;
    set_or_clear(database, &entry_id, "URL", &input.url)?;
    set_or_clear(database, &entry_id, "Notes", &input.notes)?;
    set_or_clear(database, &entry_id, "_TroveType", &input.entry_type)?;
    if let Some(tags) = &input.tags {
        database
            .set_tags(&entry_id, tags)
            .map_err(|e| e.to_string())?;
    }
    if let Some(fields) = &input.fields {
        apply_attributes(database, &entry_id, fields)?;
    }
    Ok(entry_id)
}

/// Reconcile an entry's user attributes with what the form sent: set the ones
/// present, remove the ones that are gone.
///
/// Removal is by difference rather than by an explicit delete list, because the
/// form is the whole truth about the attributes it can see — a row the user
/// deleted simply is not there any more. Only keys passing
/// [`is_user_attribute`] are ever removed, so `_Trove*` and `Materialize.*`
/// survive a save they were never shown in.
///
/// A blank name is skipped rather than rejected: the form starts a new row
/// empty, and someone who adds a row and then thinks better of it should not
/// have to delete it before they can save.
///
/// Names are stored exactly as given. Trimming them here would silently rename
/// an existing attribute on an ordinary save — the form returns `" foo "` as it
/// found it, and a reconcile that wrote `foo` would create one key and delete
/// the other, breaking anything that looks the attribute up by name. Whitespace
/// only decides whether a row counts as blank.
fn apply_attributes(
    database: &mut Database,
    eid: &EntryId,
    fields: &[KvDto],
) -> Result<(), String> {
    let existing: Vec<String> = database
        .custom_field_names(eid)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|k| is_user_attribute(k))
        .collect();
    let mut kept: Vec<&str> = Vec::with_capacity(fields.len());
    for f in fields {
        let name = f.k.as_str();
        if name.trim().is_empty() || !is_user_attribute(name) || is_standard_field(name) {
            continue;
        }
        database
            .set_field(eid, name, &f.v)
            .map_err(|e| e.to_string())?;
        kept.push(name);
    }
    for old in existing {
        if !kept.iter().any(|k| *k == old) {
            database
                .remove_field(eid, &old)
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Whether a custom field is one the user owns and the UI shows.
///
/// `_Trove*` is our own bookkeeping. `Materialize.*` is not an attribute of the
/// entry at all — it describes an attachment, and the Attachments section
/// presents it as such; listed as an attribute it would be duplicate noise, and
/// editable there a typo would silently stop a file being written.
///
/// Read and write MUST agree on this, which is why it is one function rather
/// than two matching conditions. Saving reconciles the entry's attributes
/// against what the form sent, so anything excluded here is invisible to the
/// form and would be deleted on every save if the two ever drifted apart.
/// The five fields KDBX gives every entry, which the form already edits through
/// their own controls.
///
/// An attribute may not be named one of these. `apply_attributes` runs after
/// the standard fields are written, so a `Password` attribute would overwrite
/// the password the user just typed into the password control — and then vanish
/// from the attribute list, because these names are excluded from it. The
/// password would be gone with nothing on screen to show where it went.
fn is_standard_field(key: &str) -> bool {
    matches!(key, "Title" | "UserName" | "Password" | "URL" | "Notes")
}

fn is_user_attribute(key: &str) -> bool {
    !key.starts_with("_Trove") && !key.starts_with("Materialize.")
}

fn apply_custom_attribute(
    database: &mut Database,
    eid: &EntryId,
    old_name: Option<&str>,
    name: &str,
    value: &str,
) -> Result<(), String> {
    if name.trim().is_empty() || !is_user_attribute(name) || is_standard_field(name) {
        return Err("attribute name is empty or reserved".to_string());
    }
    let existing = database
        .custom_field_names(eid)
        .map_err(|e| e.to_string())?;
    if let Some(old) = old_name {
        if !existing
            .iter()
            .any(|field| field == old && is_user_attribute(field))
        {
            return Err(format!("custom attribute not found: {old}"));
        }
    }
    if old_name != Some(name) && existing.iter().any(|field| field == name) {
        return Err(format!("attribute already exists: {name}"));
    }
    database
        .set_field(eid, name, value)
        .map_err(|e| e.to_string())?;
    if let Some(old) = old_name.filter(|old| *old != name) {
        database.remove_field(eid, old).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn apply_remove_custom_attribute(
    database: &mut Database,
    eid: &EntryId,
    name: &str,
) -> Result<(), String> {
    let existing = database
        .custom_field_names(eid)
        .map_err(|e| e.to_string())?;
    if !existing
        .iter()
        .any(|field| field == name && is_user_attribute(field))
    {
        return Err(format!("custom attribute not found: {name}"));
    }
    database.remove_field(eid, name).map_err(|e| e.to_string())
}

/// Non-secret + password detail for a selected entry.
fn entry_detail(database: &Database, eid: &EntryId) -> Result<EntryDetailDto, String> {
    let notes = database
        .get_field(eid, "Notes")
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let password = database
        .get_field(eid, "Password")
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let mut fields = Vec::new();
    for k in database
        .custom_field_names(eid)
        .map_err(|e| e.to_string())?
    {
        // custom_field_names already excludes the five standard fields; drop
        // the reserved _Trove* keys too — they are never user attributes.
        //
        // `Materialize.*` is excluded for a different reason: it is not an
        // attribute of the entry, it describes an attachment, and the
        // Attachments section presents it as such. Listed here as well it is
        // duplicate noise, and worse, editable in a place where a typo would
        // silently stop a file being written.
        if !is_user_attribute(&k) {
            continue;
        }
        let v = database
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

fn is_favorite_tag(tag: &str) -> bool {
    tag.eq_ignore_ascii_case(FAVORITE_TAG)
}

/// Keep every unrelated tag in order and exactly one canonical Favorite tag.
fn set_favorite_tag(database: &mut Database, eid: &EntryId, fav: bool) -> Result<(), String> {
    let tags = database.get_entry_tags(eid).map_err(|e| e.to_string())?;
    let mut updated = Vec::with_capacity(tags.len() + usize::from(fav));
    let mut inserted = false;
    for tag in &tags {
        if is_favorite_tag(tag) {
            if fav && !inserted {
                updated.push(FAVORITE_TAG.to_string());
                inserted = true;
            }
        } else {
            updated.push(tag.clone());
        }
    }
    if fav && !inserted {
        updated.push(FAVORITE_TAG.to_string());
    }
    if updated != tags {
        database
            .set_entry_tags(eid, updated)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Set/clear the native Favorite tag. Saved by the caller.
fn apply_set_favorite(database: &mut Database, eid: &EntryId, fav: bool) -> Result<(), String> {
    set_favorite_tag(database, eid, fav)
}

/// Move an entry to the recycle bin. Saved by the caller.
fn apply_delete(database: &mut Database, eid: &EntryId) -> Result<(), String> {
    // `recycle_entry` reports whether it recycled or deleted outright; the
    // caller here does not branch on that.
    database
        .recycle_entry(eid, false)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// --- commands: database lifecycle ---------------------------------------------

/// All registered databases whose file still exists on disk. Syncs persisted
/// recents into state (as locked) first, so this is safe to call on startup.
#[tauri::command]
pub fn list_databases(
    app: AppHandle,
    state: State<'_, DatabaseState>,
) -> Result<Vec<DatabaseDto>, String> {
    let mut guard = state.lock().map_err(poisoned)?;
    let recents = load_recents(&app);
    for r in &recents {
        let cpath = canonicalize(&r.path);
        if !cpath.exists() {
            continue;
        }
        let id = database_id_for(&cpath);
        // Route startup hydration through the same collision check as
        // register/create so the behaviour is consistent. On a genuine
        // (1-in-2^64) FNV id collision with a *different* path there is no id
        // that can key both databases, so the newcomer is skipped — but loudly,
        // not silently: startup must stay resilient (one bad recent must never
        // blank the whole switcher), yet a dropped database should be diagnosable.
        match ensure_no_id_collision(&guard, &id, &cpath) {
            Ok(true) => {
                if let Some(trove_uuid) = &r.trove_uuid {
                    if let Some(database) = guard.databases.get_mut(&id) {
                        database.trove_uuid = Some(trove_uuid.clone());
                    }
                }
                continue;
            }
            Ok(false) => {
                guard.databases.insert(id, {
                    let mut database = RegisteredDatabase::new(cpath, r.name.clone());
                    database.trove_uuid = r.trove_uuid.clone();
                    database
                });
            }
            Err(e) => eprintln!("trove: skipping recent database — {e}"),
        }
    }
    let mut out: Vec<DatabaseDto> = guard
        .databases
        .iter()
        .filter(|(_, rv)| rv.path.exists())
        .map(|(id, rv)| database_dto(id, rv))
        .collect();
    out.sort_by_key(|v| v.name.to_lowercase());
    Ok(out)
}

/// Register an existing `.kdbx` as **locked** (not decrypted) and persist.
/// Idempotent: returns the existing entry if already registered.
#[tauri::command]
pub fn register_database(
    path: String,
    app: AppHandle,
    state: State<'_, DatabaseState>,
) -> Result<DatabaseDto, String> {
    let cpath = canonicalize(&path);
    if !cpath.exists() {
        return Err(format!("no such file: {}", cpath.display()));
    }
    let id = database_id_for(&cpath);
    let name = database_name(&cpath);
    {
        let mut guard = state.lock().map_err(poisoned)?;
        if ensure_no_id_collision(&guard, &id, &cpath)? {
            // Already registered to this same path — idempotent.
            let rv = guard
                .databases
                .get(&id)
                .expect("collision check saw it present");
            return Ok(database_dto(&id, rv));
        }
        guard.databases.insert(
            id.clone(),
            RegisteredDatabase::new(cpath.clone(), name.clone()),
        );
    }
    persist_recent(&app, &cpath, &name, None)?;
    let guard = state.lock().map_err(poisoned)?;
    let rv = guard
        .databases
        .get(&id)
        .ok_or_else(|| "database vanished after register".to_string())?;
    Ok(database_dto(&id, rv))
}

/// Create a new `.kdbx` at `path`, register it **unlocked**, persist, return it.
#[tauri::command]
pub fn create_database(
    path: String,
    password: String,
    app: AppHandle,
    state: State<'_, DatabaseState>,
) -> Result<DatabaseDto, String> {
    // The file doesn't exist yet, so resolve to an absolute (un-canonicalized)
    // path for Database::create; canonicalize after it exists.
    let target = absolute(Path::new(&path));
    let database = Database::create(&target, &password).map_err(|e| e.to_string())?;
    let cpath = std::fs::canonicalize(&target).unwrap_or(target);
    let id = database_id_for(&cpath);
    let name = database_name(&cpath);
    {
        let mut guard = state.lock().map_err(poisoned)?;
        // Refuse to overwrite a *different* database that hashes to the same id.
        // (Same path re-creating over itself is fine — it just re-registers.)
        ensure_no_id_collision(&guard, &id, &cpath)?;
        guard.databases.insert(id.clone(), {
            let mut rv = RegisteredDatabase::new(cpath.clone(), name.clone());
            rv.database = Some(database);
            rv
        });
    }
    persist_recent(&app, &cpath, &name, None)?;
    let guard = state.lock().map_err(poisoned)?;
    let rv = guard
        .databases
        .get(&id)
        .ok_or_else(|| "database vanished after create".to_string())?;
    Ok(database_dto(&id, rv))
}

/// Decrypt a registered database, store the open `Database`, return its entry list.
/// The registered database's path, or an error naming the id that is not known.
///
/// The lock is taken and released here rather than held across the work that
/// follows: every command in this file learned that lesson when holding it
/// across an unlock froze the window.
fn database_path(id: &str, state: &State<'_, DatabaseState>) -> Result<PathBuf, String> {
    let guard = state.lock().map_err(poisoned)?;
    guard
        .databases
        .get(id)
        .map(|v| v.path.clone())
        .ok_or_else(|| format!("database is not registered: {id}"))
}

/// Whether this Mac can do Touch ID at all, and whether THIS database has a
/// password stored for it.
///
/// Both are asked at the moment the unlock screen draws, because both change
/// underneath you: biometry goes away when the lid is shut on a clamshell
/// setup or after too many failed attempts, and the entry can be removed from
/// Keychain Access or by the CLI at any time.
#[tauri::command]
pub async fn biometric_status(
    id: String,
    state: State<'_, DatabaseState>,
) -> Result<BiometricDto, String> {
    let path = database_path(&id, &state)?;
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
    state: State<'_, DatabaseState>,
) -> Result<Option<Vec<EntryDto>>, String> {
    let path = database_path(&id, &state)?;
    let name = path
        .file_stem()
        .map(|s: &std::ffi::OsStr| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "your database".to_string());
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
    unlock_database(app, id, password, state).await.map(Some)
}

/// Remember this database's password for Touch ID.
///
/// The password is proved against the database first: an entry that does not open
/// it is worse than none, because it fails later and somewhere else.
#[tauri::command]
pub async fn biometric_enroll(
    id: String,
    password: String,
    state: State<'_, DatabaseState>,
) -> Result<(), String> {
    let path = database_path(&id, &state)?;
    tauri::async_runtime::spawn_blocking(move || {
        trove_core::Database::open(&path, &password)
            .map_err(|e| format!("that password does not open this database: {e}"))?;
        biometric::enroll(&path, &password).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Forget this database's stored password.
#[tauri::command]
pub async fn biometric_forget(id: String, state: State<'_, DatabaseState>) -> Result<bool, String> {
    let path = database_path(&id, &state)?;
    tauri::async_runtime::spawn_blocking(move || biometric::forget(&path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn unlock_database(
    app: AppHandle,
    id: String,
    password: String,
    state: State<'_, DatabaseState>,
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
            .databases
            .get(&id)
            .ok_or_else(|| "database is not registered".to_string())?
            .path
            .clone()
    };

    // A daemon this app was a client of may have exited since: host one
    // again. In the background, so the unlock never waits on it.
    let host_app = app.clone();
    tauri::async_runtime::spawn(async move {
        host_app.state::<DaemonHost>().ensure().await;
    });

    step(&app, "open", "pending", "decrypting");
    let open_path = path.clone();
    // Timed, because opening and saving pay the same Argon2 bill: the UI has
    // no other way to know that a save on THIS database takes two seconds rather
    // than fifty milliseconds, and a progress bar that guesses is a lie.
    let started = Instant::now();
    let database =
        tauri::async_runtime::spawn_blocking(move || Database::open(&open_path, &password))
            .await
            .map_err(|e| format!("unlock task panicked: {e}"))?
            .map_err(|e| {
                step(&app, "open", "failed", "wrong password");
                e.to_string()
            })?;
    let open_ms = started.elapsed().as_millis() as u64;
    step(&app, "open", "done", "");

    step(&app, "entries", "pending", "");
    let entries = build_entry_dtos(&database);
    step(
        &app,
        "entries",
        "done",
        format!("{} entries", entries.len()),
    );

    // Unlocking here does what unlocking in the daemon does: keys into the
    // system agent (the only route to applications and terminals that can't be
    // pointed at our own socket) and materialized files onto disk. Both are
    // settings-gated and both are undone by `lock_database`.
    let settings = load_settings(&app);

    if settings.system_agent {
        step(&app, "agent", "pending", "");
    } else {
        step(&app, "agent", "skipped", "turned off");
    }
    let (exported, keys_expire_at) = export_keys(&database, &settings).await;
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

    let trove_uuid = database.database_metadata().trove_uuid;
    let materialized = MaterializedStore::default();
    if settings.materialize {
        step(&app, "files", "pending", "");
    } else {
        step(&app, "files", "skipped", "turned off");
    }
    materialize_all(&database, &path, &materialized, &settings);
    if settings.materialize {
        let n = materialized.read().await.len();
        step(&app, "files", "done", format!("{n} written"));
    }

    {
        let mut guard = state.lock().map_err(poisoned)?;
        let rv = guard
            .databases
            .get_mut(&id)
            .ok_or_else(|| "database vanished while unlocking".to_string())?;
        rv.exported_keys = exported;
        rv.keys_expire_at = keys_expire_at;
        rv.materialized = materialized;
        rv.write_ms = Some(open_ms);
        rv.trove_uuid = trove_uuid.clone();
        rv.database = Some(database);
    }
    if let Err(error) = cache_database_uuid(&app, &id, trove_uuid) {
        eprintln!("trove: failed to cache database link UUID: {error}");
    }
    Ok(entries)
}

/// Drop the decrypted database (keep it registered), marking it locked.
#[tauri::command]
/// `retract_keys` decides whether what trove handed the machine comes back:
/// keys out of the OS agent, materialized files off disk.
/// An EXPLICIT lock does (KeePassXC parity, honouring each entry's
/// `RemoveAtDatabaseClose`). The idle timer does NOT: it exists to blank a
/// window left untouched, and revoking machine-wide credentials because nobody
/// clicked the app for five minutes pulls keys out from under a running
/// `git push`. Absent ⇒ true, so an older caller keeps the safer behaviour.
pub async fn lock_database(
    id: String,
    retract_keys: Option<bool>,
    state: State<'_, DatabaseState>,
) -> Result<(), String> {
    // Same reasoning as `unlock_database`: retracting keys from the OS agent and
    // wiping files is I/O, and a sync command would do it on the main thread.
    // Take what has to be undone out under a short lock, drop the database so it
    // reads as locked immediately, then do the undoing without the lock held.
    // One rule, both kinds of handover: an app lock HIDES (window locks, database
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
            .databases
            .get_mut(&id)
            .ok_or_else(|| "database is not registered".to_string())?;
        rv.database = None;
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

/// Who runs the trove daemon: this app, another process, or nobody.
#[tauri::command]
pub async fn daemon_status(host: State<'_, DaemonHost>) -> Result<DaemonStatus, String> {
    Ok(host.status().await)
}

/// Current app settings, for the settings UI.
#[tauri::command]
pub async fn get_settings(app: AppHandle) -> Result<Settings, String> {
    off_main(app, |a| Ok(load_settings(a))).await
}

/// Persist app settings. Takes effect on the next unlock; already-exported
/// keys stay in the agent until the database locks.
#[tauri::command]
pub async fn set_settings(app: AppHandle, settings: Settings) -> Result<(), String> {
    off_main(app, move |a| save_settings(a, &settings)).await
}

/// Has this database's file been written by something else since we read it?
///
/// Also true once after a save of ours merged in another writer's changes: the
/// file then holds entries the window's list does not.
///
/// Polled by the window rather than pushed from a file watcher: it is one
/// `stat` on a path we already know, it only matters while somebody is looking
/// at the list, and there is no watcher to leak when a database closes.
#[tauri::command]
pub async fn database_changed_on_disk(app: AppHandle, id: String) -> Result<bool, String> {
    on_database_mut(app, id, |v| {
        Ok(v.take_merged_on_save().is_some() || v.changed_on_disk())
    })
    .await
}

/// Re-read a database whose file was changed by something else, returning the
/// entry list as it now stands.
///
/// Safe to call unprompted because this app writes every change through
/// immediately — there is no unsaved state to lose, and a list that no longer
/// matches the file is worse than a list that jumps.
#[tauri::command]
pub async fn reload_database(app: AppHandle, id: String) -> Result<Vec<EntryDto>, String> {
    on_database_mut(app, id, |v| {
        v.reload().map_err(|e| e.to_string())?;
        Ok(build_entry_dtos(v))
    })
    .await
}

/// Re-read the entry list for an unlocked database.
#[tauri::command]
pub async fn list_entries(app: AppHandle, id: String) -> Result<Vec<EntryDto>, String> {
    on_database(app, id, |v| Ok(build_entry_dtos(v))).await
}

#[tauri::command]
pub async fn list_groups(app: AppHandle, id: String) -> Result<Vec<GroupDto>, String> {
    on_database(app, id, |v| Ok(build_group_dtos(v))).await
}

#[tauri::command]
pub async fn get_database_metadata(
    app: AppHandle,
    id: String,
) -> Result<DatabaseMetadataDto, String> {
    on_database(app, id, |database| Ok(database.database_metadata().into())).await
}

#[tauri::command]
pub async fn set_database_metadata(
    app: AppHandle,
    id: String,
    metadata: DatabaseMetadataDto,
) -> Result<DatabaseMetadataDto, String> {
    let result: DatabaseMetadataDto = on_database_write(app.clone(), id.clone(), move |database| {
        database
            .set_database_metadata(metadata.into())
            .map_err(|error| error.to_string())?;
        Ok(database.database_metadata().into())
    })
    .await?;
    if let Err(error) = cache_database_uuid(&app, &id, result.trove_uuid.clone()) {
        eprintln!("trove: failed to cache database link UUID: {error}");
    }
    Ok(result)
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
    on_database(app, id, move |v| {
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
    on_database(app, id, move |v| entry_detail(v, &eid)).await
}

/// One attachment, with where it lands on disk if it asked to.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentDto {
    pub name: String,
    pub size: usize,
    /// Whether the bytes look like text, and can therefore be shown in an
    /// editor rather than described. Decided by sniffing the content: an
    /// extension says what someone named the file, not what is in it.
    pub is_text: bool,
    /// Sniffed content type — `image/png`, `application/pdf` — or empty when
    /// the bytes match no magic number we know.
    pub mime: String,
    /// That type in words, for a panel that can only describe what it cannot
    /// show: "PNG image", "PDF document", falling back to "Text"/"Binary file".
    pub kind: String,
    /// Whether the UI can render these bytes as a picture rather than describe
    /// them. Decided by the magic number, never by the file name.
    pub is_image: bool,
    /// Where the attachment is written on unlock, after inheritance: its
    /// `<File>`'s own target, or its name inside an inherited `dir`. Empty when
    /// it is not written anywhere.
    pub target: String,
    pub mode: String,
    pub ttl: String,
    pub allow_disk_backed: bool,
    /// Whether the entry's Materialize.settings has a `<File>` for it.
    pub materialized: bool,
    /// Where `target` came from when it is not the item's own: `group <path>`
    /// or `database`. Empty when the item set it, or nothing did.
    pub target_from: String,
}

/// How a resolved value's origin reads in the UI: empty for the item's own.
fn origin_label(origin: &Origin) -> String {
    match origin {
        Origin::Item => String::new(),
        Origin::Entry => "entry defaults".to_string(),
        Origin::Group(g) => format!("group {g}"),
        Origin::Database => "database".to_string(),
    }
}

/// One attachment's resolved `<File>`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AttachmentPlan {
    target: String,
    target_from: String,
    mode: String,
    ttl: String,
    allow_disk_backed: bool,
}

/// What each attachment's `<File>` resolves to, by attachment name.
fn materialize_views(
    v: &Database,
    eid: &EntryId,
) -> Result<BTreeMap<String, AttachmentPlan>, String> {
    let mut out = BTreeMap::new();
    let Some(items) = v
        .effective_settings(eid, Capability::Materialize)
        .map_err(|e| e.to_string())?
    else {
        return Ok(out);
    };
    for item in items {
        let (target, target_from) =
            match (item.attributes.get("target"), item.attributes.get("dir")) {
                (Some(t), _) => (t.value.clone(), String::new()),
                (None, Some(d)) => (
                    format!("{}/{}", d.value.trim_end_matches('/'), item.key),
                    origin_label(&d.origin),
                ),
                (None, None) => (String::new(), String::new()),
            };
        out.insert(
            item.key.clone(),
            AttachmentPlan {
                target,
                target_from,
                mode: item.get("mode").unwrap_or_default().to_string(),
                ttl: item.get("ttl").unwrap_or_default().to_string(),
                allow_disk_backed: item.flag("allowDiskBacked"),
            },
        );
    }
    Ok(out)
}

/// Is this text a person can edit, or bytes we should not pretend to render?
///
/// NUL is the giveaway — no text format contains one, every binary does — and
/// invalid UTF-8 settles the rest. Sniffing beats trusting the extension: an
/// SSH private key has no suffix at all and is perfectly good text, while
/// `.settings` here is a UTF-16 XML blob KeePassXC wrote.
fn looks_like_text(bytes: &[u8]) -> bool {
    !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok()
}

/// A recognised content type: what it is, what to call it, and whether it can
/// be drawn.
struct Sniffed {
    mime: &'static str,
    kind: &'static str,
    is_image: bool,
}

const fn image(mime: &'static str, kind: &'static str) -> Option<Sniffed> {
    Some(Sniffed {
        mime,
        kind,
        is_image: true,
    })
}

const fn other(mime: &'static str, kind: &'static str) -> Option<Sniffed> {
    Some(Sniffed {
        mime,
        kind,
        is_image: false,
    })
}

/// Identify an attachment from its leading bytes.
///
/// KDBX stores a name and bytes — no content type — and the name is whatever
/// someone typed, so the magic number is the only honest source. An entry's
/// SSH key has no extension at all; a `.txt` may be a DER certificate.
fn sniff(bytes: &[u8]) -> Option<Sniffed> {
    let starts = |sig: &[u8]| bytes.starts_with(sig);
    // ISO base-media brand, shared by HEIC/AVIF/MP4: the 4-byte size comes
    // first, so the tag sits at offset 4 and the brand at 8.
    let brand = |b: &[u8]| bytes.len() >= 12 && &bytes[4..8] == b"ftyp" && &bytes[8..12] == b;

    if starts(b"\x89PNG\r\n\x1a\n") {
        return image("image/png", "PNG image");
    }
    if starts(b"\xff\xd8\xff") {
        return image("image/jpeg", "JPEG image");
    }
    if starts(b"GIF87a") || starts(b"GIF89a") {
        return image("image/gif", "GIF image");
    }
    if bytes.len() >= 12 && starts(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return image("image/webp", "WebP image");
    }
    if starts(b"BM") {
        return image("image/bmp", "Bitmap image");
    }
    if starts(b"II*\x00") || starts(b"MM\x00*") {
        return image("image/tiff", "TIFF image");
    }
    if starts(b"\x00\x00\x01\x00") {
        return image("image/x-icon", "Icon");
    }
    if brand(b"avif") {
        return image("image/avif", "AVIF image");
    }
    if brand(b"heic") || brand(b"heix") || brand(b"mif1") {
        return image("image/heic", "HEIC image");
    }
    // SVG is text, so it reaches the editor as well; it is flagged as an image
    // so the panel can offer the picture first. Rendered inside an <img>,
    // where a webview runs no script it may carry.
    if svg_looking(bytes) {
        return image("image/svg+xml", "SVG image");
    }
    if starts(b"%PDF-") {
        return other("application/pdf", "PDF document");
    }
    if starts(b"PK\x03\x04") {
        return other("application/zip", "Zip archive");
    }
    if starts(b"\x1f\x8b") {
        return other("application/gzip", "Gzip archive");
    }
    if starts(b"SQLite format 3\x00") {
        return other("application/vnd.sqlite3", "SQLite database");
    }
    if starts(b"\x7fELF") {
        return other("application/x-executable", "ELF executable");
    }
    if starts(b"\xcf\xfa\xed\xfe") || starts(b"\xca\xfe\xba\xbe") {
        return other("application/x-mach-binary", "Mach-O executable");
    }
    // A DER SEQUENCE with a long-form length: every X.509 certificate, PKCS#8
    // key and PKCS#12 bundle starts this way, and telling them apart needs a
    // real parse — so name the encoding and stop there rather than guess.
    if starts(b"\x30\x82") {
        return other(
            "application/octet-stream",
            "DER binary (certificate, key or PKCS#12)",
        );
    }
    None
}

/// Is this an SVG document? Only the first bytes are examined, past any
/// leading whitespace, XML declaration or doctype.
fn svg_looking(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(512)];
    let Ok(text) = std::str::from_utf8(head) else {
        // A truncated multi-byte character at the 512-byte cut is not a
        // reason to give up on a file that is otherwise plain text.
        return false;
    };
    let text = text.trim_start();
    (text.starts_with("<?xml") || text.starts_with("<!DOCTYPE svg") || text.starts_with("<svg"))
        && text.contains("<svg")
}

/// The type of an attachment as the UI should present it: the sniffed answer
/// when there is one, otherwise text or bytes.
fn describe(bytes: &[u8], is_text: bool) -> (String, String, bool) {
    match sniff(bytes) {
        Some(s) => (s.mime.to_string(), s.kind.to_string(), s.is_image),
        None if is_text => (String::new(), "Text".to_string(), false),
        None => (String::new(), "Binary file".to_string(), false),
    }
}

fn attachment_field(name: &str, setting: &str) -> String {
    format!("Materialize.{name}.{setting}")
}

/// Every attachment on an entry, with its materialize settings.
#[tauri::command]
pub async fn list_attachments(
    app: AppHandle,
    id: String,
    entry_id: String,
) -> Result<Vec<AttachmentDto>, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    on_database(app, id, move |v| {
        let summary = v
            .get_entry(&eid)
            .ok_or_else(|| "entry not found".to_string())?;
        let plans = materialize_views(v, &eid)?;
        let mut out = Vec::new();
        // Settings documents are edited in their own sections, not as files.
        for name in summary
            .attachment_names
            .iter()
            .filter(|n| !settings::is_settings_attachment(n))
        {
            let bytes = v
                .read_binary(&eid, name)
                .map_err(|e| e.to_string())?
                .unwrap_or_default();
            let plan = plans.get(name);
            let is_text = looks_like_text(&bytes);
            let (mime, kind, is_image) = describe(&bytes, is_text);
            out.push(AttachmentDto {
                name: name.clone(),
                size: bytes.len(),
                is_text,
                mime,
                kind,
                is_image,
                target: plan.map(|p| p.target.clone()).unwrap_or_default(),
                mode: plan.map(|p| p.mode.clone()).unwrap_or_default(),
                ttl: plan.map(|p| p.ttl.clone()).unwrap_or_default(),
                allow_disk_backed: plan.is_some_and(|p| p.allow_disk_backed),
                materialized: plan.is_some(),
                target_from: plan.map(|p| p.target_from.clone()).unwrap_or_default(),
            });
        }
        Ok(out)
    })
    .await
}

/// An attachment's bytes as text.
///
/// Refuses rather than returning mojibake: an editor showing replacement
/// characters would invite someone to save them back over a real key.
#[tauri::command]
pub async fn read_attachment(
    app: AppHandle,
    id: String,
    entry_id: String,
    name: String,
) -> Result<String, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    on_database(app, id, move |v| {
        let bytes = v
            .read_binary(&eid, &name)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("no attachment named {name:?}"))?;
        if !looks_like_text(&bytes) {
            return Err(format!(
                "{name} is binary ({} bytes) — editing it as text would corrupt it",
                bytes.len()
            ));
        }
        String::from_utf8(bytes).map_err(|_| "attachment is not valid UTF-8".to_string())
    })
    .await
}

/// An image attachment as a base64 payload the webview can put in an `<img>`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentImageDto {
    pub mime: String,
    pub base64: String,
}

/// The cap on what will be handed to the webview as a data URL. A picture in a
/// password database is a scan or a screenshot; anything past this is not
/// something a preview pane should be inflating into a string.
const MAX_PREVIEW_BYTES: usize = 16 * 1024 * 1024;

/// An attachment's bytes, base64'd, for showing as a picture.
///
/// Separate from `list_attachments` on purpose: that call is made every time an
/// entry is selected, and base64ing every attachment on it to fill a panel
/// nobody has opened would be wasteful.
#[tauri::command]
pub async fn read_attachment_image(
    app: AppHandle,
    id: String,
    entry_id: String,
    name: String,
) -> Result<AttachmentImageDto, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    on_database(app, id, move |v| {
        let bytes = v
            .read_binary(&eid, &name)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("no attachment named {name:?}"))?;
        let sniffed = sniff(&bytes).filter(|s| s.is_image).ok_or_else(|| {
            format!("{name} is not an image trove recognises, so it cannot be shown")
        })?;
        if bytes.len() > MAX_PREVIEW_BYTES {
            return Err(format!(
                "{name} is {} MB — too large to preview",
                bytes.len() / (1024 * 1024)
            ));
        }
        Ok(AttachmentImageDto {
            mime: sniffed.mime.to_string(),
            base64: BASE64.encode(&bytes),
        })
    })
    .await
}

/// Replace an attachment's content, or add a new one.
#[tauri::command]
pub async fn save_attachment(
    app: AppHandle,
    id: String,
    entry_id: String,
    name: String,
    content: String,
) -> Result<Vec<AttachmentDto>, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    let app2 = app.clone();
    let id2 = id.clone();
    on_database_write(app, id, move |v| {
        v.attach_binary(&eid, &name, content.as_bytes())
            .map_err(|e| e.to_string())?;
        Ok(())
    })
    .await?;
    list_attachments(app2, id2, entry_id).await
}

/// Attach a file picked from disk, keeping its bytes verbatim.
///
/// Separate from `save_attachment` because that one carries a `String`: a
/// re-encoded copy of a `.p12` or a DER certificate is a corrupt copy. This
/// reads the bytes and stores them unchanged.
///
/// The name defaults to the file's own basename, which is almost always what
/// someone means by "add this file".
#[tauri::command]
pub async fn attach_file(
    app: AppHandle,
    id: String,
    entry_id: String,
    path: String,
    name: Option<String>,
) -> Result<Vec<AttachmentDto>, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    let src = PathBuf::from(&path);
    let name = match name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty()) {
        Some(n) => n,
        None => src
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .ok_or_else(|| format!("{path} has no file name"))?,
    };
    let bytes = std::fs::read(&src).map_err(|e| format!("reading {path}: {e}"))?;

    let app2 = app.clone();
    let id2 = id.clone();
    on_database_write(app, id, move |v| {
        v.attach_binary(&eid, &name, &bytes)
            .map_err(|e| e.to_string())?;
        Ok(())
    })
    .await?;
    list_attachments(app2, id2, entry_id).await
}

/// Remove an attachment and the settings that describe it — leaving
/// `Materialize.<name>.*` or a settings item behind would ask the daemon to
/// write, or exec to export, a file that no longer exists.
#[tauri::command]
pub async fn delete_attachment(
    app: AppHandle,
    id: String,
    entry_id: String,
    name: String,
) -> Result<Vec<AttachmentDto>, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    let app2 = app.clone();
    let id2 = id.clone();
    on_database_write(app, id, move |v| {
        v.remove_binary(&eid, &name).map_err(|e| e.to_string())?;
        for setting in ["Target", "Mode", "TTL", "AllowDiskBacked"] {
            let _ = v.remove_field(&eid, &attachment_field(&name, setting));
        }
        v.forget_attachment_settings(&eid, &name)
            .map_err(|e| e.to_string())?;
        Ok(())
    })
    .await?;
    list_attachments(app2, id2, entry_id).await
}

/// Rename an attachment, taking its settings and the agent config with it.
#[tauri::command]
pub async fn rename_attachment(
    app: AppHandle,
    id: String,
    entry_id: String,
    old_name: String,
    new_name: String,
) -> Result<Vec<AttachmentDto>, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    let app2 = app.clone();
    let id2 = id.clone();
    on_database_write(app, id, move |v| {
        let renamed = v
            .rename_attachment(&eid, &old_name, &new_name)
            .map_err(|e| e.to_string())?;
        // The agent settings name their key inside XML trove-core does not
        // parse, so finish the job here where the format is understood.
        if renamed.has_keeagent_settings {
            if let Ok(Some(bytes)) = v.read_binary(&eid, "KeeAgent.settings") {
                if let Some(updated) =
                    troved::ssh_agent::keeagent::rewrite_key_attachment(&bytes, &new_name)
                {
                    v.attach_binary(&eid, "KeeAgent.settings", &updated)
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        Ok(())
    })
    .await?;
    list_attachments(app2, id2, entry_id).await
}

/// Where one attachment should land on disk, as the settings panel states it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterializeInput {
    pub target: String,
    pub mode: String,
    pub ttl: String,
    pub allow_disk_backed: bool,
    /// Write it on unlock into the directory a group (or the entry's defaults)
    /// gives, rather than to a target of its own.
    #[serde(default)]
    pub use_dir: bool,
}

/// Apply one attachment's materialize settings to its `<File>` in the entry's
/// Materialize.settings: written, or with no target and no inherited
/// directory, removed. The document goes when its last file does.
fn apply_materialize(
    v: &mut Database,
    eid: &EntryId,
    name: &str,
    input: &MaterializeInput,
) -> Result<(), String> {
    let target = input.target.trim();
    let mut doc = v
        .entry_settings(eid, Capability::Materialize)
        .map_err(|e| e.to_string())?
        .unwrap_or_else(|| Document::new(Capability::Materialize));
    if target.is_empty() && !input.use_dir {
        doc.remove_item(name);
    } else {
        let mut attrs: Attributes = vec![("attachment".to_string(), name.to_string())];
        if !target.is_empty() {
            attrs.push(("target".to_string(), target.to_string()));
        }
        if !input.mode.trim().is_empty() {
            attrs.push(("mode".to_string(), input.mode.trim().to_string()));
        }
        if !input.ttl.trim().is_empty() {
            attrs.push(("ttl".to_string(), input.ttl.trim().to_string()));
        }
        if input.allow_disk_backed {
            attrs.push(("allowDiskBacked".to_string(), "true".to_string()));
        }
        doc.upsert_item(attrs).map_err(|e| e.to_string())?;
    }
    let keep = !doc.items().is_empty() || !doc.defaults().is_empty();
    v.store_settings(eid, Capability::Materialize, keep.then_some(&doc))
        .map_err(|e| e.to_string())
}

/// Set (or clear) where an attachment materializes.
///
/// An empty target removes every setting for it: "write this nowhere" is the
/// absence of a target, not a target that is blank.
#[tauri::command]
pub async fn set_attachment_materialize(
    app: AppHandle,
    id: String,
    entry_id: String,
    name: String,
    settings: MaterializeInput,
) -> Result<Vec<AttachmentDto>, String> {
    let MaterializeInput {
        target,
        mode,
        ttl,
        allow_disk_backed,
        use_dir,
    } = settings;
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    let app2 = app.clone();
    let id2 = id.clone();
    let input = MaterializeInput {
        target,
        mode,
        ttl,
        allow_disk_backed,
        use_dir,
    };
    on_database_write(app, id, move |v| apply_materialize(v, &eid, &name, &input)).await?;
    list_attachments(app2, id2, entry_id).await
}

// --- capability settings -----------------------------------------------------

/// One resolved attribute of an item, and where it came from.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedAttr {
    pub value: String,
    /// Empty for the item's own value; else `entry defaults`, `group <path>`
    /// or `database` — what the panel shows greyed out beside an inherited one.
    pub from: String,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityItemDto {
    pub key: String,
    /// The attributes the item itself sets, which is what the panel edits.
    pub own: BTreeMap<String, String>,
    /// Every attribute after inheritance.
    pub effective: BTreeMap<String, ResolvedAttr>,
}

/// One capability's document on an entry.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDto {
    /// `env-agent`, `materialize` or `gpg-agent`.
    pub capability: String,
    /// Whether the entry has the document (or legacy fields standing in for
    /// it) — whether the capability is on.
    pub on: bool,
    /// The document is converted from legacy fields not yet written as one.
    pub legacy: bool,
    pub items: Vec<CapabilityItemDto>,
    /// What the panel can name as a source: the entry's fields (standard and
    /// custom) and its attachments, settings documents excluded.
    pub fields: Vec<String>,
    pub attachments: Vec<String>,
}

/// A group's (or the database's) defaults for one capability.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GroupCapabilityDto {
    pub capability: String,
    pub defaults: BTreeMap<String, String>,
    /// The attributes a group may set for this capability.
    pub allowed: Vec<String>,
}

fn capability(name: &str) -> Result<Capability, String> {
    Capability::from_name(name).ok_or_else(|| format!("unknown capability {name:?}"))
}

fn capability_dtos(v: &Database, eid: &EntryId) -> Result<Vec<CapabilityDto>, String> {
    let summary = v
        .get_entry(eid)
        .ok_or_else(|| "entry not found".to_string())?;
    let mut fields: Vec<String> = ["Password", "UserName", "URL", "Notes"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    fields.extend(v.custom_field_names(eid).map_err(|e| e.to_string())?);
    let attachments: Vec<String> = summary
        .attachment_names
        .iter()
        .filter(|n| !settings::is_settings_attachment(n))
        .cloned()
        .collect();
    let mut out = Vec::new();
    for cap in Capability::ALL {
        let stored = v.settings_document(eid, cap).map_err(|e| e.to_string())?;
        let legacy = stored.is_none();
        let doc = match stored {
            Some(d) => Some(d),
            None => v.legacy_settings(eid, cap).map_err(|e| e.to_string())?,
        };
        let effective = v
            .effective_settings(eid, cap)
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        let items = doc
            .as_ref()
            .map(|d| {
                d.items()
                    .iter()
                    .zip(effective.iter())
                    .map(|(own, eff)| CapabilityItemDto {
                        key: eff.key.clone(),
                        own: own.iter().cloned().collect(),
                        effective: eff
                            .attributes
                            .iter()
                            .map(|(k, r)| {
                                (
                                    k.clone(),
                                    ResolvedAttr {
                                        value: r.value.clone(),
                                        from: origin_label(&r.origin),
                                    },
                                )
                            })
                            .collect(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.push(CapabilityDto {
            capability: cap.cli_name().to_string(),
            on: doc.is_some(),
            legacy: legacy && doc.is_some(),
            items,
            fields: fields.clone(),
            attachments: attachments.clone(),
        });
    }
    Ok(out)
}

/// Add or replace one item. Empty values are dropped, so a cleared box
/// inherits rather than storing an empty string.
fn apply_capability_item(
    v: &mut Database,
    eid: &EntryId,
    cap: Capability,
    attrs: &BTreeMap<String, String>,
) -> Result<(), String> {
    let key_attr = cap.key_attribute();
    let mut ordered: Attributes = Vec::new();
    if let Some(k) = attrs.get(key_attr) {
        ordered.push((key_attr.to_string(), k.trim().to_string()));
    }
    for (k, val) in attrs {
        if k != key_attr && !val.trim().is_empty() {
            ordered.push((k.clone(), val.trim().to_string()));
        }
    }
    v.upsert_settings_item(eid, cap, ordered)
        .map_err(|e| e.to_string())
}

fn drop_capability_item(
    v: &mut Database,
    eid: &EntryId,
    cap: Capability,
    key: &str,
) -> Result<(), String> {
    let mut doc = v
        .entry_settings(eid, cap)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("the entry has no {}", cap.attachment_name()))?;
    if !doc.remove_item(key) {
        return Err(format!("{} has no item {key:?}", cap.attachment_name()));
    }
    v.store_settings(eid, cap, Some(&doc))
        .map_err(|e| e.to_string())
}

/// Turn a capability on (an empty document) or off (no document).
fn toggle_capability(
    v: &mut Database,
    eid: &EntryId,
    cap: Capability,
    on: bool,
) -> Result<(), String> {
    if on {
        if v.entry_settings(eid, cap)
            .map_err(|e| e.to_string())?
            .is_none()
        {
            v.store_settings(eid, cap, Some(&Document::new(cap)))
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    } else {
        v.store_settings(eid, cap, None).map_err(|e| e.to_string())
    }
}

fn group_capability_dtos(v: &Database, group: &str) -> Result<Vec<GroupCapabilityDto>, String> {
    let mut out = Vec::new();
    for cap in Capability::ALL {
        let doc = v.group_settings(group, cap).map_err(|e| e.to_string())?;
        out.push(GroupCapabilityDto {
            capability: cap.cli_name().to_string(),
            defaults: doc
                .map(|d| d.defaults().iter().cloned().collect())
                .unwrap_or_default(),
            allowed: cap
                .default_attributes()
                .into_iter()
                .map(str::to_string)
                .collect(),
        });
    }
    Ok(out)
}

/// Set (or with an empty value clear) one default on a group or, with an empty
/// path, the database. A document left with no defaults is removed.
fn apply_group_default(
    v: &mut Database,
    group: &str,
    cap: Capability,
    name: &str,
    value: &str,
) -> Result<(), String> {
    let mut doc = v
        .group_settings(group, cap)
        .map_err(|e| e.to_string())?
        .unwrap_or_else(|| Document::new(cap));
    let value = value.trim();
    doc.set_default(name, (!value.is_empty()).then_some(value))
        .map_err(|e| e.to_string())?;
    let keep = !doc.defaults().is_empty();
    v.set_group_settings(group, cap, keep.then_some(&doc))
        .map_err(|e| e.to_string())
}

/// Every capability document on an entry, for its settings sections.
#[tauri::command]
pub async fn entry_capabilities(
    app: AppHandle,
    id: String,
    entry_id: String,
) -> Result<Vec<CapabilityDto>, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    on_database(app, id, move |v| capability_dtos(v, &eid)).await
}

#[tauri::command]
pub async fn set_capability_item(
    app: AppHandle,
    id: String,
    entry_id: String,
    capability: String,
    attrs: BTreeMap<String, String>,
) -> Result<Vec<CapabilityDto>, String> {
    let cap = self::capability(&capability)?;
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    on_database_write(app, id, move |v| {
        apply_capability_item(v, &eid, cap, &attrs)?;
        capability_dtos(v, &eid)
    })
    .await
}

#[tauri::command]
pub async fn remove_capability_item(
    app: AppHandle,
    id: String,
    entry_id: String,
    capability: String,
    key: String,
) -> Result<Vec<CapabilityDto>, String> {
    let cap = self::capability(&capability)?;
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    on_database_write(app, id, move |v| {
        drop_capability_item(v, &eid, cap, &key)?;
        capability_dtos(v, &eid)
    })
    .await
}

#[tauri::command]
pub async fn set_capability_on(
    app: AppHandle,
    id: String,
    entry_id: String,
    capability: String,
    on: bool,
) -> Result<Vec<CapabilityDto>, String> {
    let cap = self::capability(&capability)?;
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    on_database_write(app, id, move |v| {
        toggle_capability(v, &eid, cap, on)?;
        capability_dtos(v, &eid)
    })
    .await
}

/// A group's (empty `group`: the database's) defaults, per capability.
#[tauri::command]
pub async fn group_capabilities(
    app: AppHandle,
    id: String,
    group: String,
) -> Result<Vec<GroupCapabilityDto>, String> {
    on_database(app, id, move |v| group_capability_dtos(v, &group)).await
}

#[tauri::command]
pub async fn set_group_default(
    app: AppHandle,
    id: String,
    group: String,
    capability: String,
    name: String,
    value: String,
) -> Result<Vec<GroupCapabilityDto>, String> {
    let cap = self::capability(&capability)?;
    on_database_write(app, id, move |v| {
        apply_group_default(v, &group, cap, &name, &value)?;
        group_capability_dtos(v, &group)
    })
    .await
}

// --- commands: mutations ----------------------------------------------------

/// Create or update an entry, save the database, return the fresh list + saved id.
#[tauri::command]
pub async fn save_entry(
    app: AppHandle,
    id: String,
    input: EntryInput,
) -> Result<SaveResult, String> {
    on_database_write(app, id, move |database| {
        let entry_id = apply_save_entry(database, &input)?;
        Ok(SaveResult {
            entries: build_entry_dtos(database),
            groups: build_group_dtos(database),
            id: entry_id.as_str().to_string(),
        })
    })
    .await
}

#[tauri::command]
pub async fn set_group_tags(
    app: AppHandle,
    id: String,
    path: String,
    tags: Vec<String>,
) -> Result<Vec<GroupDto>, String> {
    on_database_write(app, id, move |database| {
        database
            .set_group_tags(&path, &tags)
            .map_err(|e| e.to_string())?;
        Ok(build_group_dtos(database))
    })
    .await
}

/// Create an empty group, including any missing parent groups, and save it.
#[tauri::command]
pub async fn create_group(
    app: AppHandle,
    id: String,
    path: String,
) -> Result<Vec<GroupDto>, String> {
    on_database_write(app, id, move |database| {
        database.add_group(&path).map_err(|e| e.to_string())?;
        Ok(build_group_dtos(database))
    })
    .await
}

/// Set or rename one user-defined attribute, then save and return fresh detail.
#[tauri::command]
pub async fn set_custom_attribute(
    app: AppHandle,
    id: String,
    entry_id: String,
    old_name: Option<String>,
    name: String,
    value: String,
) -> Result<EntryDetailDto, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    on_database_write(app, id, move |database| {
        apply_custom_attribute(database, &eid, old_name.as_deref(), &name, &value)?;
        entry_detail(database, &eid)
    })
    .await
}

/// Remove one user-defined attribute and save.
#[tauri::command]
pub async fn remove_custom_attribute(
    app: AppHandle,
    id: String,
    entry_id: String,
    name: String,
) -> Result<EntryDetailDto, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    on_database_write(app, id, move |database| {
        apply_remove_custom_attribute(database, &eid, &name)?;
        entry_detail(database, &eid)
    })
    .await
}

/// Remove a folder and everything under it, save, return the fresh lists.
///
/// Recycled like a deleted entry; destroyed outright only when the folder is
/// already in the bin or the bin is disabled. The UI has already shown what is
/// inside, so the subtree goes whole (`recursive`).
#[tauri::command]
pub async fn delete_group(
    app: AppHandle,
    id: String,
    path: String,
) -> Result<DeleteGroupResult, String> {
    on_database_write(app, id, move |database| {
        let recycled = database
            .remove_group(&path, false, true)
            .map_err(|e| e.to_string())?;
        Ok(DeleteGroupResult {
            entries: build_entry_dtos(database),
            groups: build_group_dtos(database),
            recycled,
        })
    })
    .await
}

/// Drop an entry onto a folder in the sidebar: move it there, or copy it when
/// `copy` is set. The returned id is the copy's, so the UI can select it.
#[tauri::command]
pub async fn drop_entry(
    app: AppHandle,
    id: String,
    entry_id: String,
    group: String,
    copy: bool,
) -> Result<SaveResult, String> {
    let eid = EntryId::from_str(&entry_id).map_err(|e| format!("bad entry id: {e}"))?;
    on_database_write(app, id, move |database| {
        let landed = if copy {
            database
                .copy_entry(&eid, &group)
                .map_err(|e| e.to_string())?
        } else {
            database
                .move_entry_to_path(&eid, &group)
                .map_err(|e| e.to_string())?;
            eid
        };
        Ok(SaveResult {
            entries: build_entry_dtos(database),
            groups: build_group_dtos(database),
            id: landed.as_str().to_string(),
        })
    })
    .await
}

/// Drop a folder into `parent`, moving it (or copying it when `copy` is set),
/// then record `order` as the new order of `parent`'s children. A drop within
/// the same parent is a plain reorder. One command so the whole gesture costs
/// one database write.
#[tauri::command]
pub async fn drop_group(
    app: AppHandle,
    id: String,
    source: String,
    parent: String,
    copy: bool,
    order: Vec<String>,
) -> Result<SaveResult, String> {
    on_database_write(app, id, move |database| {
        if copy {
            database
                .copy_group(&source, &parent, false)
                .map_err(|e| e.to_string())?;
        } else {
            database
                .move_group_to_path(&source, &parent)
                .map_err(|e| e.to_string())?;
        }
        database
            .set_group_order(&parent, &order)
            .map_err(|e| e.to_string())?;
        Ok(SaveResult {
            entries: build_entry_dtos(database),
            groups: build_group_dtos(database),
            id: String::new(),
        })
    })
    .await
}

/// Compare two folder names the way the sidebar sorts unarranged folders:
/// case-insensitive, with runs of digits compared as numbers.
fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn chunks(s: &str) -> Vec<(bool, String)> {
        let mut out: Vec<(bool, String)> = Vec::new();
        for c in s.chars() {
            let digit = c.is_ascii_digit();
            match out.last_mut() {
                Some((d, run)) if *d == digit => run.push(c),
                _ => out.push((digit, c.to_string())),
            }
        }
        out
    }
    let (left, right) = (chunks(a), chunks(b));
    for ((ld, l), (rd, r)) in left.iter().zip(&right) {
        let order = if *ld && *rd {
            let (l, r) = (l.trim_start_matches('0'), r.trim_start_matches('0'));
            l.len().cmp(&r.len()).then_with(|| l.cmp(r))
        } else {
            l.to_lowercase().cmp(&r.to_lowercase())
        };
        if order.is_ne() {
            return order;
        }
    }
    left.len().cmp(&right.len())
}

/// The children of `parent` in sidebar order: arranged ones by position,
/// then the rest by name.
fn sibling_order(database: &Database, parent: &[String]) -> Vec<(String, Option<u32>)> {
    let mut siblings: Vec<(String, Option<u32>)> = database
        .list_groups()
        .into_iter()
        .filter(|g| g.path.len() == parent.len() + 1 && g.path[..parent.len()] == *parent)
        .map(|g| (g.path[parent.len()].clone(), g.position))
        .collect();
    siblings.sort_by(|(a, pa), (b, pb)| {
        let (pa, pb) = (pa.unwrap_or(u32::MAX), pb.unwrap_or(u32::MAX));
        pa.cmp(&pb).then_with(|| natural_cmp(a, b))
    });
    siblings
}

/// Rename the folder at `path` to `name`, keeping it under the same parent and
/// in the same place among its siblings. Returns the new path.
///
/// A plain `move_group_to_path` would move the folder INTO a sibling that
/// already has the name, like `mv -r A B` does, so that is refused here first.
/// Group lookups ignore ASCII case, so a sibling differing only in case
/// clashes too.
fn apply_rename_group(database: &mut Database, path: &str, name: &str) -> Result<String, String> {
    if name.trim().is_empty() {
        return Err("a folder name cannot be empty".into());
    }
    if name.contains('/') {
        return Err("a folder name cannot contain \"/\"".into());
    }
    let parts: Vec<String> = path.split('/').map(String::from).collect();
    if path.is_empty() || parts.iter().any(String::is_empty) {
        return Err("cannot rename the root folder".into());
    }
    let (old, parent) = parts.split_last().expect("path is not empty");
    if old == name {
        return Ok(path.to_string());
    }
    let parent_path = parent.join("/");
    let parent_label = if parent.is_empty() {
        "Root"
    } else {
        parent_path.as_str()
    };
    let before = sibling_order(database, parent);
    if !before.iter().any(|(n, _)| n == old) {
        return Err(format!("folder not found: {path}"));
    }
    let clash = before
        .iter()
        .any(|(n, _)| n != old && n.eq_ignore_ascii_case(name))
        || (parent.is_empty() && name.eq_ignore_ascii_case("Root"));
    if clash {
        return Err(format!(
            "a folder named \"{name}\" already exists in {parent_label}"
        ));
    }
    let join = |leaf: &str| {
        if parent.is_empty() {
            leaf.to_string()
        } else {
            format!("{parent_path}/{leaf}")
        }
    };
    let target = join(name);
    if old.eq_ignore_ascii_case(name) {
        // Only the case changes. The lookup would find the folder itself and
        // read it as "move into", so go through a name nothing else has.
        let mut step = format!("{name}.renaming");
        while before.iter().any(|(n, _)| n.eq_ignore_ascii_case(&step)) {
            step.push('_');
        }
        database
            .move_group_to_path(path, &join(&step))
            .map_err(|e| e.to_string())?;
        database
            .move_group_to_path(&join(&step), &target)
            .map_err(|e| e.to_string())?;
    } else {
        database
            .move_group_to_path(path, &target)
            .map_err(|e| e.to_string())?;
    }
    // An arranged folder keeps its position; an unarranged one would sort to
    // wherever its new name lands, so pin the order the sidebar showed.
    let order: Vec<String> = before
        .iter()
        .map(|(n, _)| {
            if n == old {
                name.to_string()
            } else {
                n.clone()
            }
        })
        .collect();
    let after: Vec<String> = sibling_order(database, parent)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    if after != order {
        database
            .set_group_order(&parent_path, &order)
            .map_err(|e| e.to_string())?;
    }
    Ok(target)
}

/// Rename a folder in place, save, return the fresh lists.
#[tauri::command]
pub async fn rename_group(
    app: AppHandle,
    id: String,
    path: String,
    name: String,
) -> Result<SaveResult, String> {
    on_database_write(app, id, move |database| {
        apply_rename_group(database, &path, &name)?;
        Ok(SaveResult {
            entries: build_entry_dtos(database),
            groups: build_group_dtos(database),
            id: String::new(),
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
    on_database_write(app, id, move |database| {
        apply_delete(database, &eid)?;
        Ok(build_entry_dtos(database))
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
    on_database_write(app, id, move |database| {
        apply_set_favorite(database, &eid, fav)?;
        Ok(build_entry_dtos(database))
    })
    .await
}

/// Set this entry's SSH-agent policy: whether the key is added on unlock, how
/// long the agent should keep it, whether to confirm each use, and whether a
/// lock takes it back.
///
/// Writes the same `KeeAgent.settings` bytes KeePassXC reads, so the choice
/// travels with the database file and both tools agree. Applies immediately as
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

    // Phase 1 — database write, under the lock, on a blocking thread. Returns the
    // key so the agent work can happen with the lock released.
    let write = {
        let app = app.clone();
        let id = id.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let state = app.state::<DatabaseState>();
            with_open_mut(&state, &id, move |database| {
                let summary = database
                    .list_entries()
                    .into_iter()
                    .find(|s| s.id == eid)
                    .ok_or_else(|| "entry not found".to_string())?;
                let (attachment, _, _) = agent_key_state(database, &eid, &summary.attachment_names);
                if attachment.is_empty() {
                    return Err("this entry has no SSH private key attachment".to_string());
                }
                let key_bytes = database
                    .read_binary(&eid, &attachment)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("attachment '{attachment}' is missing"))?;
                // Parsed up front to learn the public blob — how the agent
                // addresses this key — and to refuse early if it isn't usable.
                let probe = troved::ssh_agent::keys::parse_private_key(&key_bytes, &summary.title)
                    .map_err(|e| {
                        format!("attachment '{attachment}' is not a usable SSH key: {e}")
                    })?;
                database
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
                database.save().map_err(|e| e.to_string())?;
                // Re-read so the key carries the policy just written. On
                // disable the loader no longer returns it, so fall back to the
                // probe — the agent still has to be told to drop it.
                let key = troved::handler::load_ssh_keys_from_database(database)
                    .into_iter()
                    .find(|k| k.public_blob == probe.public_blob)
                    .unwrap_or(probe);
                Ok(key)
            })
        })
        .await
        .map_err(|e| format!("database task panicked: {e}"))??
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
        let state = app.state::<DatabaseState>();
        let mut guard = state.lock().map_err(poisoned)?;
        let rv = guard
            .databases
            .get_mut(&id)
            .ok_or_else(|| "database is not registered".to_string())?;
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
        let database = rv
            .database
            .as_ref()
            .ok_or_else(|| "database is locked".to_string())?;
        Ok(build_entry_dtos(database))
    })
    .await
    .map_err(|e| format!("database task panicked: {e}"))?
}

// --- tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_recent_entries_without_cached_database_uuid_still_load() {
        let recent: RecentEntry =
            serde_json::from_str(r#"{"path":"/tmp/database.kdbx","name":"database"}"#).unwrap();
        assert_eq!(recent.trove_uuid, None);
    }

    /// Create a throwaway unlocked database in a unique temp dir.
    fn temp_database() -> (Database, PathBuf) {
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
        let path = dir.join("database.kdbx");
        let database = Database::create(&path, "correct horse").unwrap();
        (database, path)
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
            tags: None,
            fields: None,
        }
    }

    /// `fields: None` means "the caller said nothing about attributes", which
    /// must leave them alone — an older frontend that does not send them should
    /// not wipe what is already on the entry.
    fn input_with_fields(entry_id: Option<String>, path: &str, kv: &[(&str, &str)]) -> EntryInput {
        EntryInput {
            fields: Some(
                kv.iter()
                    .map(|(k, v)| KvDto {
                        k: k.to_string(),
                        v: v.to_string(),
                    })
                    .collect(),
            ),
            ..input(entry_id, path)
        }
    }

    #[test]
    fn attributes_are_saved_and_come_back_in_the_detail() {
        let (mut database, _p) = temp_database();
        let eid = apply_save_entry(
            &mut database,
            &input_with_fields(None, "forge/gitea", &[("git.token", "tok_abc")]),
        )
        .unwrap();
        let d = entry_detail(&database, &eid).unwrap();
        let got: Vec<(String, String)> = d.fields.into_iter().map(|f| (f.k, f.v)).collect();
        assert_eq!(got, vec![("git.token".to_string(), "tok_abc".to_string())]);
    }

    #[test]
    fn custom_attributes_can_be_renamed_duplicated_and_deleted() {
        let (mut database, _p) = temp_database();
        let eid = apply_save_entry(
            &mut database,
            &input_with_fields(None, "forge/gitea", &[("Host", "db.prod")]),
        )
        .unwrap();
        apply_custom_attribute(&mut database, &eid, Some("Host"), "Server", "db.stage").unwrap();
        apply_custom_attribute(&mut database, &eid, None, "Server(2)", "db.stage").unwrap();
        apply_remove_custom_attribute(&mut database, &eid, "Server").unwrap();

        let fields: Vec<(String, String)> = entry_detail(&database, &eid)
            .unwrap()
            .fields
            .into_iter()
            .map(|field| (field.k, field.v))
            .collect();
        assert_eq!(
            fields,
            vec![("Server(2)".to_string(), "db.stage".to_string())]
        );
    }

    #[test]
    fn empty_nested_group_can_be_created_without_an_entry() {
        let (mut database, _p) = temp_database();
        database.add_group("empty/nested").unwrap();
        let paths: Vec<String> = build_group_dtos(&database)
            .into_iter()
            .map(|group| group.path.join("/"))
            .collect();
        assert!(paths.contains(&"empty".to_string()));
        assert!(paths.contains(&"empty/nested".to_string()));
        assert!(build_entry_dtos(&database).is_empty());
    }

    /// The UUID of the group at `path`, read back from the saved file.
    fn saved_group_uuid(path: &Path, group: &[&str]) -> String {
        let mut file = std::fs::File::open(path).unwrap();
        let key = keepass::DatabaseKey::new().with_password("correct horse");
        let db = keepass::Database::open(&mut file, key).unwrap();
        let uuid = db.root().group_by_path(group).unwrap().id().uuid();
        uuid.to_string()
    }

    fn group_paths(database: &Database) -> Vec<String> {
        database
            .list_groups()
            .into_iter()
            .map(|g| g.path.join("/"))
            .collect()
    }

    fn child_names(database: &Database, parent: &[&str]) -> Vec<String> {
        let parent: Vec<String> = parent.iter().map(|s| s.to_string()).collect();
        sibling_order(database, &parent)
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    }

    #[test]
    fn rename_group_keeps_uuids_tags_and_entries() {
        let (mut database, path) = temp_database();
        database.add_group("infra/web").unwrap();
        database.add_group("infra/zz").unwrap();
        database
            .set_group_tags("infra/web", &["prod".to_string()])
            .unwrap();
        let eid = apply_save_entry(&mut database, &input(None, "infra/web/deploy")).unwrap();
        database.set_tags(&eid, &["ssh".to_string()]).unwrap();
        database.save().unwrap();
        let uuid = saved_group_uuid(&path, &["infra", "web"]);

        let renamed = apply_rename_group(&mut database, "infra/web", "frontend").unwrap();
        database.save().unwrap();

        assert_eq!(renamed, "infra/frontend");
        assert_eq!(saved_group_uuid(&path, &["infra", "frontend"]), uuid);
        let group = database
            .list_groups()
            .into_iter()
            .find(|g| g.path.join("/") == "infra/frontend")
            .unwrap();
        assert_eq!(group.tags, vec!["prod".to_string()]);
        assert!(!group_paths(&database).contains(&"infra/web".to_string()));
        let entry = database.get_entry(&eid).expect("same entry UUID");
        assert_eq!(entry.display_path(), "infra/frontend/deploy");
        assert_eq!(entry.tags, vec!["ssh".to_string()]);
        // Unarranged siblings would re-sort by the new name; the order the
        // sidebar showed is kept instead.
        assert_eq!(child_names(&database, &["infra"]), vec!["frontend", "zz"]);
    }

    #[test]
    fn rename_group_keeps_its_place_among_arranged_and_unarranged_siblings() {
        let (mut database, _p) = temp_database();
        for g in ["a", "m", "z"] {
            database.add_group(g).unwrap();
        }
        apply_rename_group(&mut database, "a", "zzz").unwrap();
        assert_eq!(child_names(&database, &[]), vec!["zzz", "m", "z"]);

        database
            .set_group_order("", &["z".to_string(), "zzz".to_string(), "m".to_string()])
            .unwrap();
        apply_rename_group(&mut database, "zzz", "b").unwrap();
        assert_eq!(child_names(&database, &[]), vec!["z", "b", "m"]);
    }

    #[test]
    fn rename_group_changes_only_the_case() {
        let (mut database, _p) = temp_database();
        database.add_group("infra/web").unwrap();
        assert_eq!(
            apply_rename_group(&mut database, "infra", "Infra").unwrap(),
            "Infra"
        );
        assert_eq!(group_paths(&database), vec!["", "Infra", "Infra/web"]);
    }

    #[test]
    fn rename_group_keeps_materialize_and_agent_settings() {
        let (mut database, id) = settings_database();
        let agent = database.read_binary(&id, "KeeAgent.settings").unwrap();
        let input = MaterializeInput {
            target: "/tmp/cert.pem".to_string(),
            mode: "0640".to_string(),
            ttl: String::new(),
            allow_disk_backed: false,
            use_dir: false,
        };
        apply_materialize(&mut database, &id, "cert.pem", &input).unwrap();
        let document = database
            .settings_document(&id, Capability::Materialize)
            .unwrap();
        assert!(document.is_some());

        apply_rename_group(&mut database, "Apps", "Services").unwrap();

        assert_eq!(
            database.get_entry(&id).unwrap().display_path(),
            "Services/api"
        );
        assert_eq!(
            database.read_binary(&id, "KeeAgent.settings").unwrap(),
            agent
        );
        assert_eq!(
            database
                .settings_document(&id, Capability::Materialize)
                .unwrap(),
            document
        );
        assert_eq!(
            materialize_views(&database, &id).unwrap()["cert.pem"].target,
            "/tmp/cert.pem"
        );
    }

    #[test]
    fn rename_group_refuses_an_existing_sibling() {
        let (mut database, _p) = temp_database();
        database.add_group("infra/web").unwrap();
        database.add_group("infra/db").unwrap();
        let before = group_paths(&database);

        assert_eq!(
            apply_rename_group(&mut database, "infra/web", "db"),
            Err("a folder named \"db\" already exists in infra".to_string())
        );
        assert_eq!(
            apply_rename_group(&mut database, "infra/web", "DB"),
            Err("a folder named \"DB\" already exists in infra".to_string())
        );
        database.add_group("ops").unwrap();
        assert_eq!(
            apply_rename_group(&mut database, "ops", "infra"),
            Err("a folder named \"infra\" already exists in Root".to_string())
        );
        assert!(apply_rename_group(&mut database, "ops", "root").is_err());

        let mut expected = before;
        expected.push("ops".to_string());
        expected.sort_by_key(|p| p.to_lowercase());
        assert_eq!(group_paths(&database), expected, "nothing moved");
        assert!(!group_paths(&database).contains(&"infra/db/web".to_string()));
    }

    #[test]
    fn rename_group_refuses_empty_and_slash_names() {
        let (mut database, _p) = temp_database();
        database.add_group("infra/web").unwrap();
        let before = group_paths(&database);
        for name in ["", "   ", "a/b", "/"] {
            assert!(
                apply_rename_group(&mut database, "infra/web", name).is_err(),
                "{name:?} accepted"
            );
        }
        assert!(apply_rename_group(&mut database, "", "x").is_err());
        assert_eq!(group_paths(&database), before);
    }

    #[test]
    fn natural_order_matches_the_sidebar() {
        let mut names = vec!["b", "a10", "A2", "a1", "B1"];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(names, vec!["a1", "A2", "a10", "b", "B1"]);
    }

    #[test]
    fn an_attribute_removed_from_the_form_is_removed_from_the_entry() {
        let (mut database, _p) = temp_database();
        let eid = apply_save_entry(
            &mut database,
            &input_with_fields(None, "forge/gitea", &[("a", "1"), ("b", "2")]),
        )
        .unwrap();
        let id = eid.as_str().to_string();
        // Save again with `b` gone — the form is the whole truth about the
        // attributes it can see, so a row that is no longer there is a delete.
        apply_save_entry(
            &mut database,
            &input_with_fields(Some(id), "forge/gitea", &[("a", "1")]),
        )
        .unwrap();
        let names = database.custom_field_names(&eid).unwrap();
        assert!(names.iter().any(|k| k == "a"));
        assert!(!names.iter().any(|k| k == "b"), "got {names:?}");
    }

    /// The dangerous case: reserved keys are never shown in the form, so if the
    /// reconcile treated "absent from the form" as "delete" for them too, every
    /// save would silently destroy an entry's materialize config.
    #[test]
    fn reserved_keys_survive_a_save_that_never_mentioned_them() {
        let (mut database, _p) = temp_database();
        let eid = apply_save_entry(&mut database, &input(None, "forge/gitea")).unwrap();
        database
            .set_field(&eid, "Materialize.id.Target", "~/.ssh/id_ed25519")
            .unwrap();
        database.set_field(&eid, "_TroveObsolete", "1").unwrap();

        apply_save_entry(
            &mut database,
            &input_with_fields(
                Some(eid.as_str().to_string()),
                "forge/gitea",
                &[("git.token", "t")],
            ),
        )
        .unwrap();

        let names = database.custom_field_names(&eid).unwrap();
        assert!(
            names.iter().any(|k| k == "Materialize.id.Target"),
            "materialize config must survive: {names:?}"
        );
        assert!(names.iter().any(|k| k == "_TroveObsolete"), "got {names:?}");
        // And they are still hidden from the form.
        let d = entry_detail(&database, &eid).unwrap();
        assert_eq!(d.fields.len(), 1);
        assert_eq!(d.fields[0].k, "git.token");
    }

    #[test]
    fn omitting_fields_entirely_leaves_attributes_untouched() {
        let (mut database, _p) = temp_database();
        let eid = apply_save_entry(
            &mut database,
            &input_with_fields(None, "forge/gitea", &[("keep", "me")]),
        )
        .unwrap();
        // `fields: None` — an older frontend, or any caller that says nothing.
        apply_save_entry(
            &mut database,
            &input(Some(eid.as_str().to_string()), "forge/gitea"),
        )
        .unwrap();
        let names = database.custom_field_names(&eid).unwrap();
        assert!(names.iter().any(|k| k == "keep"), "got {names:?}");
    }

    /// An attribute named `Password` would be written after the password
    /// control and replace it — then vanish from the attribute list, because
    /// standard names are excluded there. The password would be gone with
    /// nothing on screen to show where it went.
    #[test]
    fn an_attribute_cannot_overwrite_a_standard_field() {
        let (mut database, _p) = temp_database();
        let eid = apply_save_entry(
            &mut database,
            &input_with_fields(
                None,
                "forge/gitea",
                &[
                    ("Password", "hijacked"),
                    ("UserName", "hijacked"),
                    ("git.token", "t"),
                ],
            ),
        )
        .unwrap();
        // The real password is the one the form's password control sent.
        assert_eq!(
            database.get_field(&eid, "Password").unwrap().as_deref(),
            Some("Gx7$mQ2!vLpZ9wKt")
        );
        assert_eq!(
            database.get_field(&eid, "UserName").unwrap().as_deref(),
            Some("deploy")
        );
        let d = entry_detail(&database, &eid).unwrap();
        assert_eq!(d.fields.len(), 1);
        assert_eq!(d.fields[0].k, "git.token");
    }

    /// The form returns an existing name exactly as it found it. Trimming on
    /// the way in would create the trimmed key and delete the original —
    /// renaming an attribute as a side effect of saving something else.
    #[test]
    fn saving_does_not_rename_an_attribute_with_surrounding_whitespace() {
        let (mut database, _p) = temp_database();
        let eid = apply_save_entry(&mut database, &input(None, "forge/gitea")).unwrap();
        database.set_field(&eid, " spaced ", "v").unwrap();

        // Round-trip: read what the form would show, save it back unchanged.
        let d = entry_detail(&database, &eid).unwrap();
        let same: Vec<(&str, &str)> = d
            .fields
            .iter()
            .map(|f| (f.k.as_str(), f.v.as_str()))
            .collect();
        apply_save_entry(
            &mut database,
            &input_with_fields(Some(eid.as_str().to_string()), "forge/gitea", &same),
        )
        .unwrap();

        let names = database.custom_field_names(&eid).unwrap();
        assert!(names.iter().any(|k| k == " spaced "), "got {names:?}");
        assert!(!names.iter().any(|k| k == "spaced"), "got {names:?}");
    }

    #[test]
    fn save_then_detail_round_trips_and_hides_secrets() {
        let (mut database, _path) = temp_database();
        let eid = apply_save_entry(&mut database, &input(None, "Infra/SSH/build")).unwrap();

        // The list DTO carries no secret but does carry strength + length.
        let dtos = build_entry_dtos(&database);
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
        let detail = entry_detail(&database, &eid).unwrap();
        assert_eq!(detail.password, "Gx7$mQ2!vLpZ9wKt");
        assert_eq!(detail.notes, "rotate quarterly");
        assert!(!detail.fields.iter().any(|kv| kv.k.starts_with("_Trove")));
    }

    #[test]
    fn update_moves_group_renames_and_clears_empty_fields() {
        let (mut database, _path) = temp_database();
        let eid = apply_save_entry(&mut database, &input(None, "Infra/SSH/build")).unwrap();

        // Rename + move to a different group, and clear the notes.
        let mut upd = input(Some(eid.as_str().to_string()), "Prod/DB/primary");
        upd.notes = String::new();
        upd.url = "postgres://db.example.io".to_string();
        upd.entry_type = String::new(); // clear _TroveType → derive from URL
        let saved = apply_save_entry(&mut database, &upd).unwrap();
        assert_eq!(saved.as_str(), eid.as_str()); // same entry id preserved

        let dtos = build_entry_dtos(&database);
        assert_eq!(dtos.len(), 1);
        let dto = &dtos[0];
        assert_eq!(dto.path, "Prod/DB/primary");
        assert_eq!(dto.group, vec!["Prod".to_string(), "DB".to_string()]);
        assert_eq!(dto.entry_type, "db"); // derived from postgres:// URL

        let detail = entry_detail(&database, &eid).unwrap();
        assert_eq!(detail.notes, ""); // empty input cleared the field
    }

    #[test]
    fn favorite_toggles_and_delete_recycles() {
        let (mut database, _path) = temp_database();
        let eid = apply_save_entry(&mut database, &input(None, "Infra/SSH/build")).unwrap();

        database
            .set_entry_tags(&eid, vec!["ssh".into(), "work".into()])
            .unwrap();

        apply_set_favorite(&mut database, &eid, true).unwrap();
        assert!(build_entry_dtos(&database)[0].fav);
        assert_eq!(
            database.get_entry_tags(&eid).unwrap(),
            ["ssh", "work", "Favorite"]
        );
        apply_set_favorite(&mut database, &eid, true).unwrap();
        assert_eq!(database.get_entry_tags(&eid).unwrap().len(), 3);
        apply_set_favorite(&mut database, &eid, false).unwrap();
        assert!(!build_entry_dtos(&database)[0].fav);
        assert_eq!(database.get_entry_tags(&eid).unwrap(), ["ssh", "work"]);
        // Delete recycles the entry: it leaves the live listing.
        apply_delete(&mut database, &eid).unwrap();
        let live: Vec<_> = build_entry_dtos(&database)
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
    fn native_favorite_tag_is_visible_and_star_removes_all_case_variants() {
        let (mut database, path) = temp_database();
        let eid = apply_save_entry(&mut database, &input(None, "forge/gitea")).unwrap();
        database
            .set_entry_tags(
                &eid,
                vec!["favorite".into(), "git".into(), "FAVORITE".into()],
            )
            .unwrap();
        database.save().unwrap();
        let mut reopened = Database::open(&path, "correct horse").unwrap();
        assert!(build_entry_dtos(&reopened)[0].fav);

        apply_set_favorite(&mut reopened, &eid, false).unwrap();
        reopened.save().unwrap();
        let cleared = Database::open(&path, "correct horse").unwrap();
        assert!(!build_entry_dtos(&cleared)[0].fav);
        assert_eq!(cleared.get_entry_tags(&eid).unwrap(), ["git"]);
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
    fn database_id_is_deterministic_and_path_derived() {
        let a = database_id_for(Path::new("/databases/inpace.kdbx"));
        let b = database_id_for(Path::new("/databases/inpace.kdbx"));
        let c = database_id_for(Path::new("/databases/other.kdbx"));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn id_collision_with_a_different_path_is_rejected() {
        let mut state = AppState::default();
        let id = database_id_for(Path::new("/databases/a.kdbx"));
        state.databases.insert(
            id.clone(),
            RegisteredDatabase::new(PathBuf::from("/databases/a.kdbx"), "a".to_string()),
        );

        // Same id + same path → idempotent, no clobber.
        assert_eq!(
            ensure_no_id_collision(&state, &id, Path::new("/databases/a.kdbx")),
            Ok(true)
        );
        // Same id + a *different* path → rejected rather than overwriting.
        assert!(ensure_no_id_collision(&state, &id, Path::new("/databases/b.kdbx")).is_err());
        // A free id → Ok(false).
        let free = database_id_for(Path::new("/databases/c.kdbx"));
        assert_eq!(
            ensure_no_id_collision(&state, &free, Path::new("/databases/c.kdbx")),
            Ok(false)
        );
    }

    fn settings_database() -> (Database, EntryId) {
        let (mut v, _path) = temp_database();
        v.add_group("Apps").unwrap();
        let id = v.add_entry("api").unwrap();
        v.move_entry(&id, "Apps").unwrap();
        v.set_field(&id, "token", "t").unwrap();
        v.attach_binary(&id, "cert.pem", b"PEM").unwrap();
        v.attach_binary(&id, "KeeAgent.settings", b"<x/>").unwrap();
        (v, id)
    }

    #[test]
    fn a_capability_item_round_trips_with_its_sources_and_origins() {
        let (mut v, id) = settings_database();
        let dtos = capability_dtos(&v, &id).unwrap();
        assert!(
            dtos.iter().all(|d| !d.on),
            "nothing is on until a document exists"
        );
        assert!(dtos[0].fields.contains(&"token".to_string()));
        assert_eq!(
            dtos[0].attachments,
            vec!["cert.pem"],
            "settings files are not sources"
        );

        let attrs: BTreeMap<String, String> = [
            ("name".to_string(), "API_TOKEN".to_string()),
            ("field".to_string(), "token".to_string()),
            ("lifetime".to_string(), "  ".to_string()),
        ]
        .into();
        apply_capability_item(&mut v, &id, Capability::EnvAgent, &attrs).unwrap();
        apply_group_default(&mut v, "Apps", Capability::EnvAgent, "lifetime", "600").unwrap();
        let env = &capability_dtos(&v, &id).unwrap()[0];
        assert!(env.on && !env.legacy);
        assert_eq!(env.items[0].key, "API_TOKEN");
        assert!(
            !env.items[0].own.contains_key("lifetime"),
            "a blank box is not stored"
        );
        assert_eq!(env.items[0].effective["lifetime"].value, "600");
        assert_eq!(env.items[0].effective["lifetime"].from, "group Apps");
        assert_eq!(env.items[0].effective["field"].from, "");

        drop_capability_item(&mut v, &id, Capability::EnvAgent, "API_TOKEN").unwrap();
        assert!(drop_capability_item(&mut v, &id, Capability::EnvAgent, "API_TOKEN").is_err());
        toggle_capability(&mut v, &id, Capability::EnvAgent, false).unwrap();
        assert!(!capability_dtos(&v, &id).unwrap()[0].on);
    }

    #[test]
    fn group_defaults_are_set_cleared_and_never_grant() {
        let (mut v, _id) = settings_database();
        apply_group_default(&mut v, "Apps", Capability::Materialize, "dir", "/tmp/apps").unwrap();
        let dtos = group_capability_dtos(&v, "Apps").unwrap();
        let mat = dtos.iter().find(|d| d.capability == "materialize").unwrap();
        assert_eq!(
            mat.defaults.get("dir").map(String::as_str),
            Some("/tmp/apps")
        );
        assert!(
            !mat.allowed.contains(&"attachment".to_string()),
            "a group sets no items"
        );
        assert!(
            apply_group_default(&mut v, "Apps", Capability::Materialize, "target", "/x").is_err()
        );
        apply_group_default(&mut v, "Apps", Capability::Materialize, "dir", "").unwrap();
        assert_eq!(
            v.group_settings("Apps", Capability::Materialize).unwrap(),
            None
        );
        apply_group_default(&mut v, "", Capability::GpgAgent, "uses", "sign").unwrap();
        assert!(v
            .group_settings("", Capability::GpgAgent)
            .unwrap()
            .is_some());
    }

    #[test]
    fn materialize_follows_the_document_and_inherits_a_directory() {
        let (mut v, id) = settings_database();
        let input = |target: &str, use_dir: bool| MaterializeInput {
            target: target.to_string(),
            mode: "0640".to_string(),
            ttl: String::new(),
            allow_disk_backed: false,
            use_dir,
        };
        apply_materialize(&mut v, &id, "cert.pem", &input("/tmp/cert.pem", false)).unwrap();
        let plans = materialize_views(&v, &id).unwrap();
        assert_eq!(plans["cert.pem"].target, "/tmp/cert.pem");
        assert_eq!(plans["cert.pem"].target_from, "");
        assert_eq!(plans["cert.pem"].mode, "0640");

        apply_group_default(&mut v, "Apps", Capability::Materialize, "dir", "/srv/apps").unwrap();
        apply_materialize(&mut v, &id, "cert.pem", &input("", true)).unwrap();
        let plans = materialize_views(&v, &id).unwrap();
        assert_eq!(plans["cert.pem"].target, "/srv/apps/cert.pem");
        assert_eq!(plans["cert.pem"].target_from, "group Apps");

        apply_materialize(&mut v, &id, "cert.pem", &input("", false)).unwrap();
        assert!(materialize_views(&v, &id).unwrap().is_empty());
        assert_eq!(
            v.settings_document(&id, Capability::Materialize).unwrap(),
            None,
            "the document goes with its last file"
        );
    }

    #[test]
    fn attachments_are_identified_by_their_bytes_not_their_names() {
        // A PNG called `notes.txt` is still a PNG: the name is whatever
        // someone typed, and KDBX stores no content type at all.
        let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let s = sniff(png).expect("PNG has a magic number");
        assert_eq!(s.mime, "image/png");
        assert!(s.is_image);

        let jpeg = sniff(b"\xff\xd8\xff\xe0\x00\x10JFIF").unwrap();
        assert_eq!(jpeg.mime, "image/jpeg");
        assert!(jpeg.is_image);

        // WebP and the ISO base-media brands need bytes past the first four.
        let mut webp = b"RIFF\x00\x00\x00\x00WEBPVP8 ".to_vec();
        webp.extend_from_slice(&[0; 8]);
        assert_eq!(sniff(&webp).unwrap().mime, "image/webp");
        let mut avif = vec![0, 0, 0, 0x18];
        avif.extend_from_slice(b"ftypavif");
        assert_eq!(sniff(&avif).unwrap().mime, "image/avif");
    }

    #[test]
    fn non_images_are_named_rather_than_drawn() {
        for (bytes, kind) in [
            (b"%PDF-1.7\n".as_slice(), "PDF document"),
            (b"PK\x03\x04\x14\x00".as_slice(), "Zip archive"),
            (
                b"\x30\x82\x04\xa3\x02\x01\x00".as_slice(),
                "DER binary (certificate, key or PKCS#12)",
            ),
        ] {
            let s = sniff(bytes).expect("known magic number");
            assert_eq!(s.kind, kind);
            assert!(!s.is_image, "{kind} must not be offered as a picture");
        }
    }

    #[test]
    fn svg_is_both_a_picture_and_text() {
        let svg = br#"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>"#;
        let s = sniff(svg).unwrap();
        assert_eq!(s.mime, "image/svg+xml");
        assert!(s.is_image);
        assert!(looks_like_text(svg), "the source must stay editable");

        // XML that is not SVG is not a picture.
        assert!(sniff(br#"<?xml version="1.0"?><KeePassFile/>"#).is_none());
    }

    #[test]
    fn unknown_bytes_fall_back_to_text_or_binary() {
        let key = b"-----BEGIN OPENSSH PRIVATE KEY-----\n";
        assert_eq!(
            describe(key, true),
            (String::new(), "Text".to_string(), false)
        );
        let junk = [0u8, 1, 2, 3, 4, 5, 6, 7];
        assert_eq!(
            describe(&junk, false),
            (String::new(), "Binary file".to_string(), false)
        );
    }
}
