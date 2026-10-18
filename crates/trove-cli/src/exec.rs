//! `trove exec` — run a command with secrets injected for exactly its
//! lifetime (à la `op run`): string secrets as environment variables, file
//! attachments materialized into a private per-run temp directory that is
//! wiped the moment the child exits. Nothing outlives the process tree.
//!
//! What an entry exports is its `EnvAgent.settings`: one `<Variable>` per
//! variable, naming a field (`field="gitea-token"`, `field="Password"`) or an
//! attachment, whose materialized PATH is exported
//! (`attachment="kubeconfig"` → `KUBECONFIG=/private/tmp/.../kubeconfig`).
//! An entry without the document exports nothing: to turn exec on for an
//! entry, create its document (`trove env-agent add`).
//!
//! During the transition, the fields the document replaces still count as
//! one: `Exec.<VAR>=<field>` or `Exec.<VAR>=@<attachment>` maps a variable,
//! and `Exec.Env=<VAR>` exports the entry's sole attachment or its Password.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use trove_core::settings::{Capability, EffectiveItem};
use trove_core::{EntryId, Vault};

/// One resolved injection: an env var carrying either a secret value or the
/// path of a materialized attachment.
pub struct Injection {
    pub name: String,
    pub value: String,
}

/// How to interpret an `exec` scope. `Auto` preserves the existing shorthand
/// when only one interpretation exists, while explicit selectors resolve a
/// name that exists as both an entry and a group.
pub enum Scope {
    Auto(String),
    Entry(String),
    Group(String),
}

/// One entry as `exec` sees it, from either source.
pub struct Entry {
    /// Stable id: names the entry's files in the run directory.
    pub id: String,
    pub title: String,
    pub group_path: Vec<String>,
    pub attachment_names: Vec<String>,
}

impl Entry {
    fn display_path(&self) -> String {
        if self.group_path.is_empty() {
            self.title.clone()
        } else {
            format!("{}/{}", self.group_path.join("/"), self.title)
        }
    }
}

/// Where `exec` reads entries from: a vault file opened here, or the vaults
/// unlocked in the daemon.
pub trait Source {
    fn entries(&self) -> Result<Vec<Entry>>;
    /// The id of the entry at `path` (a title alone finds the first match).
    fn find(&self, path: &str) -> Result<Option<String>>;
    fn field(&self, e: &Entry, name: &str) -> Result<Option<String>>;
    fn attachment(&self, e: &Entry, name: &str) -> Result<Option<Vec<u8>>>;
    /// The entry's `EnvAgent.settings` items, resolved through inheritance;
    /// `None` when exec is off for the entry.
    fn settings(&self, e: &Entry) -> Result<Option<Vec<EffectiveItem>>>;
    /// Whether this source asks for Touch ID itself before handing over a
    /// value whose item says `confirm="true"`. The daemon does; a vault file
    /// opened here has no one between it and the caller, so exec asks.
    fn approves_itself(&self) -> bool {
        false
    }
}

/// A vault file opened by `exec` itself.
pub struct VaultSource<'a> {
    vault: &'a Vault,
    ids: std::collections::HashMap<String, EntryId>,
}

impl<'a> VaultSource<'a> {
    pub fn new(vault: &'a Vault) -> Self {
        let ids = vault
            .list_entries()
            .into_iter()
            .map(|e| (e.id.to_string(), e.id))
            .collect();
        Self { vault, ids }
    }

    fn id(&self, e: &Entry) -> Result<&EntryId> {
        self.ids
            .get(&e.id)
            .ok_or_else(|| anyhow!("entry {} vanished", e.display_path()))
    }
}

impl Source for VaultSource<'_> {
    fn entries(&self) -> Result<Vec<Entry>> {
        Ok(self
            .vault
            .list_entries()
            .into_iter()
            .map(|e| Entry {
                id: e.id.to_string(),
                title: e.title,
                group_path: e.group_path,
                attachment_names: e.attachment_names,
            })
            .collect())
    }
    fn find(&self, path: &str) -> Result<Option<String>> {
        Ok(self.vault.find_by_title(path).map(|id| id.to_string()))
    }
    fn field(&self, e: &Entry, name: &str) -> Result<Option<String>> {
        Ok(self.vault.get_field(self.id(e)?, name)?)
    }
    fn attachment(&self, e: &Entry, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.vault.read_binary(self.id(e)?, name)?)
    }
    fn settings(&self, e: &Entry) -> Result<Option<Vec<EffectiveItem>>> {
        Ok(self
            .vault
            .effective_settings(self.id(e)?, Capability::EnvAgent)?)
    }
}

/// The vaults unlocked in the daemon, read through the session-gated RPCs
/// (`TROVE_SESSION`), so `exec` needn't reopen the vault or ask for its
/// password.
pub struct DaemonSource {
    code: String,
    entries: Vec<Entry>,
    /// Custom field names per entry id, fetched once each.
    custom: std::cell::RefCell<std::collections::HashMap<String, Vec<String>>>,
}

/// Fields every KeePass entry has, which `ShowEntry` doesn't list by name.
const STANDARD_FIELDS: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];

impl DaemonSource {
    pub fn connect() -> Result<Self> {
        Self::with_code(crate::require_session_code()?)
    }

    /// For `trove unlock`, which holds the code it was just handed before any
    /// environment does.
    pub fn with_code(code: String) -> Result<Self> {
        use serde_json::Value;
        let resp = crate::daemon_call(&crate::daemon::Request::List)?;
        let strings = |v: &Value, k: &str| -> Vec<String> {
            v.get(k)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        let entries = resp
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|e| Entry {
                id: e
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                title: e
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                group_path: strings(e, "group_path"),
                attachment_names: strings(e, "attachments"),
            })
            .collect();
        Ok(Self {
            code,
            entries,
            custom: Default::default(),
        })
    }

    fn custom_fields(&self, e: &Entry) -> Result<Vec<String>> {
        if let Some(names) = self.custom.borrow().get(&e.id) {
            return Ok(names.clone());
        }
        let resp = crate::daemon_call(&crate::daemon::Request::ShowEntry {
            path: e.display_path(),
        })?;
        let names: Vec<String> = resp
            .get("entry")
            .and_then(|en| en.get("custom_fields"))
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        self.custom.borrow_mut().insert(e.id.clone(), names.clone());
        Ok(names)
    }
}

impl Source for DaemonSource {
    fn entries(&self) -> Result<Vec<Entry>> {
        Ok(self
            .entries
            .iter()
            .map(|e| Entry {
                id: e.id.clone(),
                title: e.title.clone(),
                group_path: e.group_path.clone(),
                attachment_names: e.attachment_names.clone(),
            })
            .collect())
    }
    fn find(&self, path: &str) -> Result<Option<String>> {
        let hit = if path.contains('/') {
            self.entries.iter().find(|e| e.display_path() == path)
        } else {
            self.entries.iter().find(|e| e.title == path)
        };
        Ok(hit.map(|e| e.id.clone()))
    }
    fn field(&self, e: &Entry, name: &str) -> Result<Option<String>> {
        if !STANDARD_FIELDS.contains(&name) && !self.custom_fields(e)?.iter().any(|n| n == name) {
            return Ok(None);
        }
        let req = crate::daemon::Request::GetField {
            path: e.display_path(),
            field: name.to_string(),
            code: self.code.clone(),
        };
        match crate::daemon::send(&req) {
            Ok(resp) => match crate::daemon::response_error(&resp) {
                // A standard field that was never set.
                Some(msg) if msg.contains("has no field") => Ok(None),
                Some(msg) => Err(anyhow!("{msg}")),
                None => Ok(resp
                    .get("value")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)),
            },
            Err(e) => Err(e),
        }
    }
    fn attachment(&self, e: &Entry, name: &str) -> Result<Option<Vec<u8>>> {
        use base64::Engine as _;
        if !e.attachment_names.iter().any(|a| a == name) {
            return Ok(None);
        }
        let resp = crate::daemon_call(&crate::daemon::Request::Get {
            title: e.display_path(),
            attachment: name.to_string(),
            code: self.code.clone(),
        })?;
        let data = resp
            .get("data")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("malformed daemon response: missing 'data'"))?;
        Ok(Some(
            base64::engine::general_purpose::STANDARD.decode(data)?,
        ))
    }
    fn approves_itself(&self) -> bool {
        true
    }
    fn settings(&self, e: &Entry) -> Result<Option<Vec<EffectiveItem>>> {
        let resp = crate::daemon_call(&crate::daemon::Request::Settings {
            path: e.display_path(),
            capability: Capability::EnvAgent.cli_name().to_string(),
            group: false,
        })?;
        let dto: troved::protocol::SettingsDto = serde_json::from_value(
            resp.get("settings")
                .cloned()
                .ok_or_else(|| anyhow!("malformed daemon response: missing 'settings'"))?,
        )
        .context("reading the daemon's settings response")?;
        Ok(dto.effective_items())
    }
}

/// Env-var-safe rendering of an entry title: uppercase, non-alphanumerics
/// collapsed to single underscores.
pub fn env_name_from_title(title: &str) -> String {
    let mut out = String::with_capacity(title.len());
    let mut last_underscore = true; // suppress leading underscore
    for c in title.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_uppercase());
            last_underscore = false;
        } else if !last_underscore {
            out.push('_');
            last_underscore = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

/// Resolve the injections for `scope`: a single entry path, or a group whose
/// direct and nested entries all contribute. `tmp` receives materialized
/// attachment files (0600, inside a 0700 dir the caller owns).
pub fn resolve(v: &dyn Source, scope: Scope, tmp: &Path) -> Result<Vec<Injection>> {
    let all = v.entries()?;
    let (name, matches) = match scope {
        Scope::Auto(name) => {
            let entry = v.find(&name)?;
            let group = group_matches(&all, &name);
            match (entry, group.is_empty()) {
                (Some(_), false) => {
                    return Err(anyhow!(
                        "'{name}' matches both an entry and a group; choose --entry '{name}' or --group '{name}'"
                    ));
                }
                (Some(id), true) => (name, all.iter().filter(|e| e.id == id).collect()),
                (None, false) => (name, group),
                (None, true) => return Err(anyhow!("no entry or group matches '{name}'")),
            }
        }
        Scope::Entry(name) => {
            let id = v
                .find(&name)?
                .ok_or_else(|| anyhow!("no entry matches '{name}'"))?;
            (name, all.iter().filter(|e| e.id == id).collect())
        }
        Scope::Group(name) => {
            let group = group_matches(&all, &name);
            if group.is_empty() {
                return Err(anyhow!("no group matches '{name}'"));
            }
            (name, group)
        }
    };

    let mut out = Vec::new();
    let mut unconfigured: Vec<&Entry> = Vec::new();
    for e in matches {
        let Some(items) = v.settings(e)? else {
            unconfigured.push(e);
            continue;
        };
        out.extend(injections(v, e, &items, tmp)?);
    }
    if out.is_empty() {
        let hint = match unconfigured.first() {
            Some(e) => format!(
                "; turn exec on for an entry with `trove env-agent add '{}' TROVE_{}_PASSWORD \
                 --field Password`, naming the variable and field it should export",
                e.display_path(),
                env_name_from_title(&e.title)
            ),
            None => String::new(),
        };
        return Err(anyhow!(
            "'{name}' matched entries, but none has EnvAgent.settings saying what to export{hint}"
        ));
    }
    Ok(out)
}

/// The variables the open vaults ask to have exported into the shell at
/// `trove unlock --export`: every `<Variable>` whose `export` resolves to
/// `shell`. Read through the daemon like exec's, so a `confirm` item waits for
/// Touch ID here too. Problems are warnings, not failures: an unlock that
/// worked must not be reported as failed because one variable did not.
pub fn shell_exports(code: &str) -> Vec<Injection> {
    let source = match DaemonSource::with_code(code.to_string()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("trove: warning: shell exports skipped: {e:#}");
            return Vec::new();
        }
    };
    let mut out: Vec<Injection> = Vec::new();
    for e in &source.entries {
        let items = match source.settings(e) {
            Ok(Some(items)) => items,
            Ok(None) => continue,
            Err(err) => {
                eprintln!("trove: warning: {}: {err:#}", e.display_path());
                continue;
            }
        };
        for item in items.iter().filter(|i| i.get("export") == Some("shell")) {
            let path = e.display_path();
            let var = &item.key;
            let Some(field) = item.get("field") else {
                eprintln!(
                    "trove: warning: {path}: {var} names an attachment, which cannot be \
                     exported to a shell; use `trove exec`"
                );
                continue;
            };
            if out.iter().any(|i| &i.name == var) {
                eprintln!("trove: warning: {path}: {var} is already exported by another entry; kept the first");
                continue;
            }
            match source.field(e, field) {
                Ok(Some(value)) => out.push(Injection {
                    name: var.clone(),
                    value,
                }),
                Ok(None) => eprintln!(
                    "trove: warning: {path}: {var} names field '{field}', which the entry doesn't have"
                ),
                Err(err) => eprintln!("trove: warning: {path}: {var}: {err:#}"),
            }
        }
    }
    out
}

/// One entry's variables, from its effective `EnvAgent.settings` items. A
/// variable that names a field or attachment the entry doesn't have is an
/// error rather than a silently missing variable.
fn injections(
    v: &dyn Source,
    e: &Entry,
    items: &[EffectiveItem],
    tmp: &Path,
) -> Result<Vec<Injection>> {
    let path = e.display_path();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let var = &item.key;
        if item.flag("confirm") && !v.approves_itself() {
            let reason = format!("use {var} from {path}");
            match troved::approval::approve(&reason) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(anyhow!(
                        "{path}: {var} needs Touch ID approval, which was refused or timed out"
                    ))
                }
                Err(why) => return Err(anyhow!("{path}: {var}: {why}")),
            }
        }
        let value = if let Some(att) = item.get("attachment") {
            let bytes = v.attachment(e, att)?.ok_or_else(|| {
                anyhow!("{path}: {var} names attachment '{att}', which the entry doesn't have")
            })?;
            materialize(tmp, e, att, &bytes)?
                .to_string_lossy()
                .into_owned()
        } else if let Some(field) = item.get("field") {
            v.field(e, field)?.ok_or_else(|| {
                anyhow!("{path}: {var} names field '{field}', which the entry doesn't have")
            })?
        } else {
            return Err(anyhow!(
                "{path}: {var} names neither a field nor an attachment"
            ));
        };
        out.push(Injection {
            name: var.clone(),
            value,
        });
    }
    Ok(out)
}

/// Write one attachment into the run directory, once: two variables naming
/// the same attachment share the file. The directory is private to this run,
/// so a file already there is one this run wrote.
fn materialize(tmp: &Path, e: &Entry, att: &str, bytes: &[u8]) -> Result<PathBuf> {
    let file = tmp.join(format!("{}-{}", e.id, sanitize_filename(att)));
    if !file.exists() {
        write_private(&file, bytes)?;
    }
    Ok(file)
}

fn group_matches<'a>(all: &'a [Entry], scope: &str) -> Vec<&'a Entry> {
    all.iter()
        .filter(|e| {
            let group_path = e.group_path.join("/");
            group_path == scope || group_path.starts_with(&format!("{scope}/"))
        })
        .collect()
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("creating {}", path.display()))
}

/// Best-effort wipe: overwrite with zeros, then remove. Directory contents
/// only — the caller removes the dir.
pub fn wipe_dir(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if let Ok(meta) = entry.metadata() {
            if meta.is_file() {
                let len = meta.len() as usize;
                let _ = std::fs::write(&p, vec![0u8; len]);
            }
        }
        let _ = std::fs::remove_file(&p);
    }
    let _ = std::fs::remove_dir(dir);
}

/// Create the private per-run directory for materialized files. The name
/// carries CSPRNG bytes (not just the pid) so it is unpredictable: an
/// attacker cannot pre-create/symlink-squat the path to cause a fail-closed
/// DoS or redirect writes. `DirBuilder::create` (not `create_dir_all`) errors
/// if the path already exists, so even on a collision we never adopt an
/// attacker-owned directory.
pub fn private_tmp_dir() -> Result<PathBuf> {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let suffix =
        private_tmp_suffix(|bytes| rng.try_fill_bytes(bytes).map_err(anyhow::Error::from))?;
    let dir = base_dir().join(format!("trove-exec-{}-{suffix}", std::process::id()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// Where the per-run directory goes. On Linux, the first memory-backed choice
/// of `$XDG_RUNTIME_DIR` and `/dev/shm`, since `/tmp` is often on disk and
/// materialized files there can reach swap-free storage, backups and
/// snapshots. Elsewhere, and when neither is available, the OS temp dir.
fn base_dir() -> PathBuf {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from);
    pick_base_dir(
        runtime.as_deref(),
        std::env::temp_dir(),
        troved::materialize::paths::is_tmpfs_backed,
    )
}

fn pick_base_dir(
    runtime: Option<&Path>,
    temp: PathBuf,
    memory_backed: impl Fn(&Path) -> bool,
) -> PathBuf {
    if cfg!(target_os = "linux") {
        let candidates = runtime.into_iter().chain([Path::new("/dev/shm")]);
        for dir in candidates {
            if dir.is_dir() && memory_backed(dir) {
                return dir.to_path_buf();
            }
        }
    }
    temp
}

/// Whether files written under `dir` may land on disk, as far as trove can
/// tell. Only Linux can say no; macOS and Windows have no memory-backed
/// filesystem to check for.
pub fn is_disk_backed(dir: &Path) -> bool {
    !(cfg!(target_os = "linux") && troved::materialize::paths::is_tmpfs_backed(dir))
}

fn private_tmp_suffix(fill: impl FnOnce(&mut [u8]) -> Result<()>) -> Result<String> {
    let mut bytes = [0u8; 12];
    fill(&mut bytes).context("getting OS randomness for private exec directory")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn base_dir_prefers_a_memory_backed_runtime_dir_on_linux() {
        let runtime = TempDir::new().unwrap();
        let temp = PathBuf::from("/fallback-temp");
        let picked = pick_base_dir(Some(runtime.path()), temp.clone(), |d| d == runtime.path());
        if cfg!(target_os = "linux") {
            assert_eq!(picked, runtime.path());
        } else {
            assert_eq!(picked, temp, "only Linux looks past the OS temp dir");
        }
    }

    #[test]
    fn base_dir_falls_back_to_the_temp_dir_when_nothing_is_memory_backed() {
        let runtime = TempDir::new().unwrap();
        let temp = PathBuf::from("/fallback-temp");
        assert_eq!(
            pick_base_dir(Some(runtime.path()), temp.clone(), |_| false),
            temp
        );
        assert_eq!(pick_base_dir(None, temp.clone(), |_| false), temp);
    }

    #[test]
    fn env_names_are_sanitized() {
        assert_eq!(env_name_from_title("kubeconfig-prod"), "KUBECONFIG_PROD");
        assert_eq!(env_name_from_title("api.stripe (live)"), "API_STRIPE_LIVE");
        assert_eq!(env_name_from_title("__x__"), "X");
    }

    #[test]
    fn private_tmp_name_returns_os_randomness_errors_with_context() {
        let err = private_tmp_suffix(|_| Err(anyhow!("OS random source unavailable")))
            .expect_err("an RNG failure must be returned, not panic");
        assert!(
            err.to_string()
                .contains("getting OS randomness for private exec directory"),
            "missing context: {err}"
        );
        assert!(
            err.root_cause()
                .to_string()
                .contains("OS random source unavailable"),
            "missing RNG error: {err:#}"
        );
    }

    fn vault_for_exec(dir: &TempDir) -> Vault {
        let mut v = Vault::create(&dir.path().join("e.kdbx"), "pw").unwrap();
        // String secret with explicit env name.
        let id = v.add_entry("Infra/stripe").unwrap();
        v.set_field(&id, "Password", "sk_live_123").unwrap();
        v.set_field(&id, "Exec.Env", "STRIPE_KEY").unwrap();
        // No EnvAgent.settings and no Exec.* field: exec is off for it.
        let id = v.add_entry("Infra/db-main").unwrap();
        v.set_field(&id, "Password", "pg-pass").unwrap();
        // File attachment with explicit env name.
        let id = v.add_entry("Infra/kubeconfig-prod").unwrap();
        v.attach_binary(&id, "kubeconfig", b"apiVersion: v1\n")
            .unwrap();
        v.set_field(&id, "Exec.Env", "KUBECONFIG").unwrap();
        // Outside the scope.
        let id = v.add_entry("Personal/email").unwrap();
        v.set_field(&id, "Password", "not-injected").unwrap();
        v
    }

    #[test]
    fn group_scope_injects_env_and_files_and_wipes() {
        let dir = TempDir::new().unwrap();
        let v = vault_for_exec(&dir);
        let tmp = dir.path().join("run");
        std::fs::create_dir(&tmp).unwrap();

        let mut inj = resolve(&VaultSource::new(&v), Scope::Auto("Infra".into()), &tmp).unwrap();
        inj.sort_by(|a, b| a.name.cmp(&b.name));
        let names: Vec<&str> = inj.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["KUBECONFIG", "STRIPE_KEY"]);
        assert!(!inj.iter().any(|i| i.value == "not-injected"));
        assert!(
            !inj.iter().any(|i| i.value == "pg-pass"),
            "an entry without EnvAgent.settings exports nothing"
        );

        let kube = inj.iter().find(|i| i.name == "KUBECONFIG").unwrap();
        assert!(
            std::path::Path::new(&kube.value).starts_with(&tmp),
            "attachment injections point into the run dir"
        );
        assert_eq!(std::fs::read(&kube.value).unwrap(), b"apiVersion: v1\n");

        wipe_dir(&tmp);
        assert!(!std::path::Path::new(&kube.value).exists(), "wiped");
        assert!(!tmp.exists(), "run dir removed");
    }

    #[test]
    fn exec_mappings_export_several_fields_and_attachments() {
        let dir = TempDir::new().unwrap();
        let mut v = Vault::create(&dir.path().join("m.kdbx"), "pw").unwrap();
        let id = v.add_entry("Db/main").unwrap();
        v.set_field(&id, "UserName", "app").unwrap();
        v.set_field(&id, "Password", "pg-secret").unwrap();
        v.set_field(&id, "URL", "db.internal").unwrap();
        v.set_field(&id, "Port", "5433").unwrap();
        v.attach_binary(&id, "ca.pem", b"-----CA-----\n").unwrap();
        v.set_field(&id, "Exec.PGUSER", "UserName").unwrap();
        v.set_field(&id, "Exec.PGPASSWORD", "Password").unwrap();
        v.set_field(&id, "Exec.PGHOST", "URL").unwrap();
        v.set_field(&id, "Exec.PGPORT", "Port").unwrap();
        v.set_field(&id, "Exec.PGSSLROOTCERT", "@ca.pem").unwrap();
        let tmp = dir.path().join("run");
        std::fs::create_dir(&tmp).unwrap();

        let inj = resolve(&VaultSource::new(&v), Scope::Auto("Db/main".into()), &tmp).unwrap();
        let got: Vec<(&str, &str)> = inj
            .iter()
            .map(|i| (i.name.as_str(), i.value.as_str()))
            .collect();
        assert_eq!(
            &got[..4],
            &[
                ("PGHOST", "db.internal"),
                ("PGPASSWORD", "pg-secret"),
                ("PGPORT", "5433"),
                ("PGSSLROOTCERT", got[3].1),
            ]
        );
        assert_eq!(got[4], ("PGUSER", "app"));
        assert_eq!(
            got.len(),
            5,
            "no TROVE_ fallback once mappings exist: {got:?}"
        );
        assert_eq!(std::fs::read(got[3].1).unwrap(), b"-----CA-----\n");

        // Exec.Env still works alongside the mappings.
        v.set_field(&id, "Exec.Env", "DATABASE_PASSWORD").unwrap();
        let inj = resolve(&VaultSource::new(&v), Scope::Auto("Db/main".into()), &tmp).unwrap();
        assert!(inj.iter().any(|i| i.name == "DATABASE_PASSWORD"));
        wipe_dir(&tmp);
    }

    #[test]
    fn exec_mappings_fail_loudly_on_bad_config() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("run");
        std::fs::create_dir(&tmp).unwrap();
        for (field, source, wanted) in [
            ("Exec.PGHOST", "NoSuchField", "NoSuchField"),
            ("Exec.CERT", "@missing.pem", "missing.pem"),
            ("Exec.1BAD", "Password", "valid environment variable"),
            ("Exec.EMPTY", "", "empty"),
        ] {
            let mut v = Vault::create(&dir.path().join(format!("{wanted}.kdbx")), "pw").unwrap();
            let id = v.add_entry("e").unwrap();
            v.set_field(&id, "Password", "x").unwrap();
            v.set_field(&id, field, source).unwrap();
            let err = resolve(&VaultSource::new(&v), Scope::Auto("e".into()), &tmp)
                .err()
                .expect(field);
            assert!(err.to_string().contains(wanted), "{field}: {err}");
        }
    }

    fn doc_vault(dir: &TempDir, xml: &str) -> Vault {
        let mut v = Vault::create(&dir.path().join("d.kdbx"), "pw").unwrap();
        let id = v.add_entry("antimatter-studios/gitea").unwrap();
        v.set_field(&id, "UserName", "chris").unwrap();
        v.set_field(&id, "gitea-token", "tok-123").unwrap();
        v.attach_binary(&id, "gitea_ed25519", b"KEY").unwrap();
        v.attach_binary(&id, "EnvAgent.settings", xml.as_bytes())
            .unwrap();
        v
    }

    #[test]
    fn env_agent_settings_say_what_to_export() {
        let dir = TempDir::new().unwrap();
        let v = doc_vault(
            &dir,
            r#"<EnvAgentSettings version="1">
                 <Variable name="GITEA_TOKEN" field="gitea-token"/>
                 <Variable name="GITEA_USER" field="UserName"/>
               </EnvAgentSettings>"#,
        );
        let tmp = dir.path().join("run");
        std::fs::create_dir(&tmp).unwrap();
        let inj = resolve(
            &VaultSource::new(&v),
            Scope::Entry("antimatter-studios/gitea".into()),
            &tmp,
        )
        .unwrap();
        let got: Vec<(&str, &str)> = inj
            .iter()
            .map(|i| (i.name.as_str(), i.value.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![("GITEA_TOKEN", "tok-123"), ("GITEA_USER", "chris")]
        );
        assert!(
            std::fs::read_dir(&tmp).unwrap().next().is_none(),
            "an attachment the document doesn't name is never written"
        );
        wipe_dir(&tmp);
    }

    #[test]
    fn a_scope_with_nothing_configured_says_how_to_turn_exec_on() {
        let dir = TempDir::new().unwrap();
        let mut v = Vault::create(&dir.path().join("n.kdbx"), "pw").unwrap();
        let id = v.add_entry("Infra/db-main").unwrap();
        v.set_field(&id, "Password", "pg-pass").unwrap();
        let tmp = dir.path().join("run");
        std::fs::create_dir(&tmp).unwrap();
        let err = resolve(&VaultSource::new(&v), Scope::Auto("Infra".into()), &tmp)
            .err()
            .expect("nothing to export");
        let msg = err.to_string();
        assert!(msg.contains("EnvAgent.settings"), "{msg}");
        assert!(
            msg.contains("trove env-agent add 'Infra/db-main' TROVE_DB_MAIN_PASSWORD"),
            "{msg}"
        );
    }

    #[test]
    fn a_confirm_flagged_variable_is_refused_until_approval_exists() {
        // Debug builds read this instead of showing a real prompt; "none" is
        // the machine with no Touch ID, where the answer must be no.
        std::env::set_var("TROVE_TEST_APPROVER", "none");
        let dir = TempDir::new().unwrap();
        let v = doc_vault(
            &dir,
            r#"<EnvAgentSettings version="1">
                 <Variable name="GITEA_TOKEN" field="gitea-token" confirm="true"/>
               </EnvAgentSettings>"#,
        );
        let tmp = dir.path().join("run");
        std::fs::create_dir(&tmp).unwrap();
        let err = resolve(
            &VaultSource::new(&v),
            Scope::Entry("antimatter-studios/gitea".into()),
            &tmp,
        )
        .err()
        .expect("refused");
        assert!(err.to_string().contains("Touch ID"), "{err}");
    }

    #[test]
    fn a_variable_naming_a_missing_source_fails() {
        let dir = TempDir::new().unwrap();
        for (xml, wanted) in [
            (
                r#"<EnvAgentSettings version="1"><Variable name="A" field="nope"/></EnvAgentSettings>"#,
                "field 'nope'",
            ),
            (
                r#"<EnvAgentSettings version="1"><Variable name="A" attachment="nope.pem"/></EnvAgentSettings>"#,
                "attachment 'nope.pem'",
            ),
        ] {
            let sub = TempDir::new().unwrap();
            let v = doc_vault(&sub, xml);
            let tmp = dir.path().join(format!("run-{}", wanted.len()));
            std::fs::create_dir(&tmp).unwrap();
            let err = resolve(
                &VaultSource::new(&v),
                Scope::Entry("antimatter-studios/gitea".into()),
                &tmp,
            )
            .err()
            .expect(wanted);
            assert!(err.to_string().contains(wanted), "{err}");
        }
    }

    #[test]
    fn single_entry_scope_and_misses() {
        let dir = TempDir::new().unwrap();
        let v = vault_for_exec(&dir);
        let tmp = dir.path().join("run2");
        std::fs::create_dir(&tmp).unwrap();

        let inj = resolve(
            &VaultSource::new(&v),
            Scope::Auto("Infra/stripe".into()),
            &tmp,
        )
        .unwrap();
        assert_eq!(inj.len(), 1);
        assert_eq!(inj[0].name, "STRIPE_KEY");
        assert_eq!(inj[0].value, "sk_live_123");

        assert!(resolve(&VaultSource::new(&v), Scope::Auto("No/Such".into()), &tmp).is_err());
        wipe_dir(&tmp);
    }
}
