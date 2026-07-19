//! File materialization — trove's headline feature.
//!
//! ## What this module does
//! On vault unlock, walk every entry, look for the `Materialize.*` custom
//! string fields, build a [`MaterializationPlan`], validate each entry's
//! plan, and write each opted-in attachment to disk under the user's
//! requested path with the user's requested permissions. On vault lock (and
//! on shutdown), wipe everything we materialized, in best-effort fashion.
//!
//! Optionally, an entry can specify a TTL (in seconds) after which the file
//! is wiped even if the vault stays unlocked — useful for short-lived
//! credentials. The TTL is implemented as a single `tokio::spawn`'d task per
//! materialization that races a `tokio::time::sleep` against a cancel
//! [`Notify`]. The `Notify` is fired on lock, ensuring the timer task is
//! cancelled before any wipe loop runs (so we don't double-wipe).
//!
//! ## Design choices
//! * **Materialization happens inside the unlock handler before the response
//!   goes out.** A user calling `unlock` should be able to assume that, by
//!   the time `ok` returns, every materialized file is on disk. Doing it
//!   asynchronously would race with the user's first `kubectl` invocation.
//! * **Per-entry failure doesn't fail the whole unlock, but is never
//!   silent.** The spec is explicit that a typo in `Materialize.Target` on one
//!   entry must not prevent the rest of the vault from working. But a failure
//!   is both logged AND returned to the caller (`materialize_warnings` in the
//!   unlock reply) so the CLI can warn loudly — `unlock` must never report `ok`
//!   with a configured materialized file missing (issue #56).
//! * **A missing parent directory is created, not rejected.** We `mkdir -p`
//!   the target's missing ancestors at write time (mode 0700, so a 0600 secret
//!   isn't dropped into a world-traversable dir), track exactly the dirs we
//!   created, and remove them on lock/wipe if empty — a pre-existing dir is
//!   never removed. Creating dirs does NOT bypass the tmpfs check: the
//!   `AllowDiskBacked=false` policy is enforced against the resolved target
//!   before any dir is created.
//! * **Wipe on lock is synchronous.** `lock` should return only after we've
//!   genuinely tried to wipe everything. If a wipe fails, we log it loudly
//!   and keep going — but we don't return ok until the loop finishes.
//! * **No logging of decrypted bytes.** The wipe / write paths log paths and
//!   error kinds only.
//!
//! ## What we do NOT do (yet)
//! * Cross-user permissions checks. Anyone who can read the user's home dir
//!   can read these files; that's the existing threat model and we don't fix
//!   it here.
//! * Re-materialization on `add` while unlocked. If you add a file entry to
//!   the vault while it's already open in the daemon, you have to lock and
//!   unlock to materialize it. Easy follow-up; not in v0.0.5.0 scope.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Notify, RwLock};

use trove_core::{EntryId, EntrySummary, Vault};

pub mod paths;
pub mod wipe;

/// Custom-field prefix that opts an entry in to materialization.
pub const MATERIALIZE_FIELD_PREFIX: &str = "Materialize.";
pub const FIELD_SOURCE: &str = "Materialize.Source";
pub const FIELD_TARGET: &str = "Materialize.Target";
pub const FIELD_MODE: &str = "Materialize.Mode";
pub const FIELD_TTL: &str = "Materialize.TTL";
pub const FIELD_ALLOW_DISK: &str = "Materialize.AllowDiskBacked";

/// Default file mode if `Materialize.Mode` is unset. 0600 = owner-RW only,
/// matching what `ssh-keygen` writes for private keys.
pub const DEFAULT_MODE: u32 = 0o600;

/// Why a single entry's materialization failed validation.
#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error(
        "entry has '{}' but no '{}' (or vice versa); both are required",
        FIELD_SOURCE,
        FIELD_TARGET
    )]
    PartialOptIn,

    #[error("attachment '{0}' not found on entry")]
    AttachmentMissing(String),

    #[error("invalid file mode {0:?}: must be 3 or 4 octal digits like \"600\" or \"0640\"")]
    InvalidMode(String),

    #[error("invalid TTL {0:?}: must be a positive integer number of seconds")]
    InvalidTtl(String),

    #[error("invalid AllowDiskBacked {0:?}: must be \"true\" or \"false\"")]
    InvalidAllowDiskBacked(String),

    #[error("path: {0}")]
    Path(#[from] paths::PathError),

    #[error(
        "target {0:?} is not on a memory-backed (tmpfs) filesystem; \
             set Materialize.AllowDiskBacked=true to override"
    )]
    NotTmpfs(PathBuf),

    #[error("vault: {0}")]
    Core(#[from] trove_core::Error),
}

/// One entry's parsed and validated materialization request.
#[derive(Debug, Clone)]
pub struct MaterializationPlan {
    pub entry_id: EntryId,
    pub entry_title: String,
    pub source_attachment: String,
    pub resolved_target: PathBuf,
    pub mode: u32,
    pub ttl: Option<Duration>,
    pub allow_disk_backed: bool,
}

/// One file we actually wrote on unlock. Tracked in shared state so we can
/// wipe it on lock / TTL expiry.
#[derive(Debug)]
pub struct MaterializedFile {
    pub entry_title: String,
    pub target: PathBuf,
    /// Parent directories trove itself created (mode 0700) to write `target`,
    /// innermost-last. Empty if the parent already existed. On wipe we remove
    /// these in reverse (innermost first) and only if empty, so a pre-existing
    /// directory is NEVER removed.
    pub created_dirs: Vec<PathBuf>,
    /// When this file should be wiped automatically, if ever.
    pub expires_at: Option<Instant>,
    /// Cancellation channel for the TTL timer task. Notify the cancel so the
    /// timer task wakes up and exits without touching the file (the lock
    /// handler is about to wipe it anyway).
    pub ttl_cancel: Arc<Notify>,
}

/// Shared store of currently-materialized files. Mirrors the SSH/GPG store
/// shape so the daemon's lifecycle is consistent.
pub type MaterializedStore = Arc<RwLock<Vec<MaterializedFile>>>;

/// Build a [`MaterializationPlan`] for one entry, given its summary. Returns
/// `Ok(None)` if the entry doesn't opt in (no `Materialize.*` fields at all);
/// returns `Err` if it opts in but the configuration is invalid.
pub fn plan_for_entry(
    vault: &Vault,
    entry: &EntrySummary,
) -> Result<Option<MaterializationPlan>, PlanError> {
    // Cheap pre-filter: any field at all under our prefix?
    let opted_fields = vault.fields_with_prefix(&entry.id, MATERIALIZE_FIELD_PREFIX)?;
    if opted_fields.is_empty() {
        return Ok(None);
    }

    let source = vault.get_field(&entry.id, FIELD_SOURCE)?;
    let target = vault.get_field(&entry.id, FIELD_TARGET)?;
    let (source, target) = match (source, target) {
        (Some(s), Some(t)) => (s, t),
        _ => return Err(PlanError::PartialOptIn),
    };

    // Source attachment must actually exist on the entry — fail early so we
    // don't validate paths for a misspelled source name.
    if !entry.attachment_names.iter().any(|n| n == &source) {
        return Err(PlanError::AttachmentMissing(source));
    }

    let mode = match vault.get_field(&entry.id, FIELD_MODE)? {
        Some(s) => parse_mode(&s)?,
        None => DEFAULT_MODE,
    };
    let ttl = match vault.get_field(&entry.id, FIELD_TTL)? {
        Some(s) => Some(parse_ttl(&s)?),
        None => None,
    };
    let allow_disk_backed = match vault.get_field(&entry.id, FIELD_ALLOW_DISK)? {
        Some(s) => parse_bool(&s)?,
        None => false,
    };

    let resolved = paths::resolve_and_validate_target(&target)?;

    if !allow_disk_backed {
        // Best-effort tmpfs check. macOS will always say "false" — and the
        // soft-allowlist `is_ephemeral_macos_path` is the most we can offer.
        if cfg!(target_os = "linux") {
            if !paths::is_tmpfs_backed(&resolved) {
                return Err(PlanError::NotTmpfs(resolved));
            }
        } else if cfg!(target_os = "macos") {
            // On macOS: accept paths the OS conventionally treats as
            // ephemeral. This is NOT a real tmpfs guarantee — see the
            // module-level comment in paths.rs. Without this, `AllowDiskBacked
            // =false` would refuse to materialize anywhere on macOS, which
            // makes the feature unusable.
            if !paths::is_ephemeral_macos_path(&resolved) {
                return Err(PlanError::NotTmpfs(resolved));
            }
        }
    }

    Ok(Some(MaterializationPlan {
        entry_id: entry.id.clone(),
        entry_title: entry.title.clone(),
        source_attachment: source,
        resolved_target: resolved,
        mode,
        ttl,
        allow_disk_backed,
    }))
}

/// Walk every entry and produce one plan per opted-in entry. Errors are
/// collected per-entry and returned alongside the successful plans, so the
/// caller can log per-entry failures without aborting unlock.
pub fn build_plans(vault: &Vault) -> (Vec<MaterializationPlan>, Vec<(String, PlanError)>) {
    let mut plans = Vec::new();
    let mut errors = Vec::new();
    for entry in vault.list_entries() {
        match plan_for_entry(vault, &entry) {
            Ok(Some(p)) => plans.push(p),
            Ok(None) => {}
            Err(e) => errors.push((entry.title, e)),
        }
    }
    (plans, errors)
}

/// Materialize a single plan: read the attachment bytes from `vault`, write
/// to `plan.resolved_target` with `plan.mode`, and (if `plan.ttl` is Some)
/// spawn a TTL timer task that wipes the file when it expires. Returns a
/// [`MaterializedFile`] bookkeeping handle that must be tracked by the
/// daemon so it can be wiped on lock.
///
/// Errors here mean we couldn't write the file. The daemon should log and
/// continue with other plans (already true at the call site).
pub fn materialize_one(
    vault: &Vault,
    plan: &MaterializationPlan,
    store: MaterializedStore,
) -> Result<MaterializedFile, MaterializeError> {
    let bytes = vault
        .read_binary(&plan.entry_id, &plan.source_attachment)
        .map_err(MaterializeError::Core)?
        .ok_or_else(|| MaterializeError::AttachmentMissing(plan.source_attachment.clone()))?;

    // Create any missing parent directories (mkdir -p, mode 0700) so a target
    // in a not-yet-existent dir materializes instead of silently vanishing.
    // 0700 keeps a 0600 secret out of a world-traversable directory. We track
    // exactly the dirs we created so wipe can remove them (and never a
    // pre-existing dir). A failure here surfaces as a MaterializeError — the
    // caller reflects it in the unlock result, never a silent success.
    let created_dirs = create_parent_dirs(&plan.resolved_target)
        .map_err(|e| MaterializeError::Mkdir(plan.resolved_target.clone(), e))?;

    if let Err(e) = write_file(&plan.resolved_target, plan.mode, &bytes) {
        // Roll back any dirs we just created so a failed write doesn't leave
        // empty trove-made dirs behind. Best-effort, innermost first.
        remove_created_dirs(&created_dirs);
        return Err(MaterializeError::Io(plan.resolved_target.clone(), e));
    }

    let cancel = Arc::new(Notify::new());
    let expires_at = plan.ttl.map(|d| Instant::now() + d);

    if let Some(ttl) = plan.ttl {
        spawn_ttl_task(
            plan.resolved_target.clone(),
            plan.entry_title.clone(),
            created_dirs.clone(),
            ttl,
            cancel.clone(),
            store,
        );
    }

    Ok(MaterializedFile {
        entry_title: plan.entry_title.clone(),
        target: plan.resolved_target.clone(),
        created_dirs,
        expires_at,
        ttl_cancel: cancel,
    })
}

/// Create every missing parent directory of `target`, top-down, each with mode
/// 0700 (user-only — a 0600 secret must not sit in a world-traversable dir).
/// Returns the dirs we actually created, innermost-last, so the caller can undo
/// them on wipe. A pre-existing parent yields an empty vec and no filesystem
/// changes.
///
/// If creating any dir fails we roll back the ones we made in this call and
/// return the error — we never leave a half-built, mis-permissioned chain.
fn create_parent_dirs(target: &std::path::Path) -> std::io::Result<Vec<PathBuf>> {
    let missing = paths::missing_ancestors(target); // outermost-first
    let mut created: Vec<PathBuf> = Vec::with_capacity(missing.len());
    for dir in missing {
        // Race guard: another process may have created it between the probe
        // and now. Treat AlreadyExists as "not ours" — don't track it, don't
        // fail.
        match create_dir_0700(&dir) {
            Ok(()) => created.push(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Someone (or something) created this dir between our probe and
                // now. It isn't ours, so don't track it for removal — but keep
                // going: deeper dirs in the pre-computed chain may still be
                // missing and are ours to create.
                continue;
            }
            Err(e) => {
                remove_created_dirs(&created);
                return Err(e);
            }
        }
    }
    Ok(created)
}

#[cfg(unix)]
fn create_dir_0700(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::PermissionsExt;
    std::fs::DirBuilder::new().mode(0o700).create(dir)?;
    // `mode` is masked by the process umask at creation time, so a hostile
    // umask could yield something other than 0700 (e.g. dropping the
    // user-execute bit, making the dir un-traversable). Force the exact mode
    // afterwards — same treatment `write_file` gives to files.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_dir_0700(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new().create(dir)
}

/// Remove directories trove created, innermost-first, and only while empty.
/// Best-effort: a dir that isn't empty (something else dropped a file in it) or
/// that we can't remove is left alone — we never force-remove. `dirs` is the
/// created list (innermost-last), so we iterate in reverse.
fn remove_created_dirs(dirs: &[PathBuf]) {
    for dir in dirs.iter().rev() {
        match std::fs::remove_dir(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                // Non-empty or permission problem: stop — outer dirs enclose
                // this one, so they can't be empty either.
                break;
            }
        }
    }
}

/// Errors specific to the actual write step (distinct from PlanError).
#[derive(Debug, thiserror::Error)]
pub enum MaterializeError {
    #[error("attachment '{0}' missing from entry at materialize time")]
    AttachmentMissing(String),

    #[error("create parent dir for {0:?}: {1}")]
    Mkdir(PathBuf, std::io::Error),

    #[error("write {0:?}: {1}")]
    Io(PathBuf, std::io::Error),

    #[error("vault: {0}")]
    Core(trove_core::Error),
}

#[cfg(unix)]
fn write_file(path: &std::path::Path, mode: u32, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // O_CREAT | O_EXCL — fail if it already exists (validation should have
    // caught this earlier, but TOCTOU). `mode` covers the creation perms.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;

    // On some umasks, `mode` may have been masked at open time. Force the
    // exact requested mode after creation.
    use std::os::unix::fs::PermissionsExt;
    let mut perms = f.metadata()?.permissions();
    perms.set_mode(mode & 0o7777);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file(path: &std::path::Path, _mode: u32, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Spawn a tokio task that races (sleep ttl) against (cancel notify). On
/// timeout, wipe the file and remove it from `store`. On cancel, exit
/// immediately — the lock handler is going to wipe it anyway.
fn spawn_ttl_task(
    target: PathBuf,
    entry_title: String,
    created_dirs: Vec<PathBuf>,
    ttl: Duration,
    cancel: Arc<Notify>,
    store: MaterializedStore,
) {
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(ttl) => {
                let report = wipe::wipe_file(&target);
                if !report.errors.is_empty() {
                    eprintln!(
                        "materialize: TTL wipe of '{}' ({}) had errors: {:?}",
                        entry_title,
                        target.display(),
                        report.errors,
                    );
                } else {
                    eprintln!(
                        "materialize: TTL wipe of '{}' ({}) ok",
                        entry_title,
                        target.display(),
                    );
                }
                // Remove any parent dirs trove created for this file (empty-only).
                remove_created_dirs(&created_dirs);
                // Remove from the shared store so subsequent lock doesn't
                // try to wipe a now-missing file (it's idempotent, but
                // we'd rather not log a false-positive error).
                let mut guard = store.write().await;
                guard.retain(|m| m.target != target);
            }
            _ = cancel.notified() => {
                // Lock-driven cancel; nothing to do. The lock handler will
                // wipe synchronously.
            }
        }
    });
}

/// Wipe every file in `store` synchronously. Used by lock and shutdown.
/// Errors per file are logged; the function only returns once every file has
/// been visited.
pub async fn wipe_all(store: &MaterializedStore) {
    let drained: Vec<MaterializedFile> = {
        let mut guard = store.write().await;
        std::mem::take(&mut *guard)
    };
    for m in drained {
        // Cancel the TTL task first so it doesn't race us. It's safe even if
        // the task already fired or never existed (Notify wakeup with no
        // waiter is a no-op).
        m.ttl_cancel.notify_waiters();
        let report = wipe::wipe_file(&m.target);
        if !report.errors.is_empty() {
            eprintln!(
                "materialize: wipe of '{}' ({}) had errors: {:?}",
                m.entry_title,
                m.target.display(),
                report.errors,
            );
        }
        // Remove parent dirs trove created for this file, innermost-first and
        // only while empty — a pre-existing dir is never in this list.
        remove_created_dirs(&m.created_dirs);
    }
}

/// Status struct returned by the `materialize-status` command.
#[derive(Debug, serde::Serialize)]
pub struct MaterializeStatus {
    pub title: String,
    pub target_path: String,
    /// Seconds remaining until TTL expiry, or `null` if no TTL.
    pub ttl_remaining_seconds: Option<u64>,
    /// `true` if the file currently exists on disk. (Best-effort: race
    /// window between this stat and the user reading the response.)
    pub exists: bool,
}

/// Snapshot the current materialized-file store as serialisable status.
pub async fn status_snapshot(store: &MaterializedStore) -> Vec<MaterializeStatus> {
    let now = Instant::now();
    let guard = store.read().await;
    guard
        .iter()
        .map(|m| MaterializeStatus {
            title: m.entry_title.clone(),
            target_path: m.target.display().to_string(),
            ttl_remaining_seconds: m.expires_at.map(
                |t| {
                    if t > now {
                        (t - now).as_secs()
                    } else {
                        0
                    }
                },
            ),
            exists: m.target.exists(),
        })
        .collect()
}

// --- helpers --------------------------------------------------------------

fn parse_mode(s: &str) -> Result<u32, PlanError> {
    let trimmed = s.trim();
    if trimmed.len() > 4 || trimmed.len() < 3 || !trimmed.chars().all(|c| ('0'..='7').contains(&c))
    {
        return Err(PlanError::InvalidMode(s.to_string()));
    }
    u32::from_str_radix(trimmed, 8).map_err(|_| PlanError::InvalidMode(s.to_string()))
}

fn parse_ttl(s: &str) -> Result<Duration, PlanError> {
    let n: u64 = s
        .trim()
        .parse()
        .map_err(|_| PlanError::InvalidTtl(s.to_string()))?;
    if n == 0 {
        return Err(PlanError::InvalidTtl(s.to_string()));
    }
    Ok(Duration::from_secs(n))
}

fn parse_bool(s: &str) -> Result<bool, PlanError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(PlanError::InvalidAllowDiskBacked(s.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_accepts_three_and_four_digits() {
        assert_eq!(parse_mode("600").unwrap(), 0o600);
        assert_eq!(parse_mode("0640").unwrap(), 0o640);
        assert_eq!(parse_mode("755").unwrap(), 0o755);
    }

    #[test]
    fn parse_mode_rejects_garbage() {
        assert!(parse_mode("abc").is_err());
        assert!(parse_mode("9999").is_err());
        assert!(parse_mode("12").is_err());
        assert!(parse_mode("12345").is_err());
        assert!(parse_mode("").is_err());
    }

    #[test]
    fn parse_ttl_rejects_zero_and_garbage() {
        assert_eq!(parse_ttl("60").unwrap(), Duration::from_secs(60));
        assert!(parse_ttl("0").is_err());
        assert!(parse_ttl("-1").is_err());
        assert!(parse_ttl("").is_err());
    }

    #[test]
    fn parse_bool_lenient() {
        assert!(parse_bool("true").unwrap());
        assert!(parse_bool("True").unwrap());
        assert!(parse_bool("yes").unwrap());
        assert!(!parse_bool("false").unwrap());
        assert!(!parse_bool("0").unwrap());
        assert!(parse_bool("maybe").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn create_parent_dirs_makes_missing_chain_0700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("x").join("y").join("secret");

        let created = create_parent_dirs(&target).expect("create dirs");
        // Two dirs created (x, x/y), innermost-last.
        assert_eq!(
            created,
            vec![tmp.path().join("x"), tmp.path().join("x").join("y")]
        );
        for d in &created {
            assert!(d.is_dir(), "{} should be a dir", d.display());
            let mode = std::fs::metadata(d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "created dir must be 0700");
        }
    }

    #[test]
    fn create_parent_dirs_noop_when_parent_exists() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("secret");
        assert!(
            create_parent_dirs(&target).expect("noop").is_empty(),
            "existing parent => nothing created"
        );
    }

    #[test]
    fn remove_created_dirs_removes_only_empty_innermost_first() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("p").join("q").join("secret");
        let created = create_parent_dirs(&target).expect("create");
        assert_eq!(created.len(), 2);
        remove_created_dirs(&created);
        assert!(!tmp.path().join("p").join("q").exists(), "q removed");
        assert!(!tmp.path().join("p").exists(), "p removed");
    }

    #[test]
    fn remove_created_dirs_keeps_nonempty_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("p").join("q").join("secret");
        let created = create_parent_dirs(&target).expect("create");
        // Drop a stray file into the innermost dir so it isn't empty.
        std::fs::write(tmp.path().join("p").join("q").join("stray"), b"x").unwrap();
        remove_created_dirs(&created);
        // Innermost not empty => nothing removed (outer encloses it).
        assert!(tmp.path().join("p").join("q").exists(), "non-empty q kept");
        assert!(tmp.path().join("p").exists(), "p kept (encloses q)");
    }
}
