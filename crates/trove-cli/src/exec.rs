//! `trove exec` — run a command with secrets injected for exactly its
//! lifetime (à la `op run`): string secrets as environment variables, file
//! attachments materialized into a private per-run temp directory that is
//! wiped the moment the child exits. Nothing outlives the process tree.
//!
//! Naming: an entry with an `Exec.Env` custom field exports its Password
//! under exactly that name (`Exec.Env=STRIPE_KEY` → `STRIPE_KEY=...`). An
//! entry with an attachment and `Exec.Env` exports the attachment's
//! materialized PATH under that name (`Exec.Env=KUBECONFIG` →
//! `KUBECONFIG=/private/tmp/.../kubeconfig`). Without `Exec.Env` the
//! fallback is `TROVE_<TITLE>_PASSWORD` / `TROVE_<TITLE>_FILE`, title
//! uppercased with non-alphanumerics collapsed to `_`.
//!
//! An entry that needs more than one variable maps each explicitly with
//! `Exec.<VAR>` fields naming the source: another field
//! (`Exec.PGUSER=UserName`, `Exec.PGPASSWORD=Password`, `Exec.PGHOST=URL`,
//! or any custom field) or, with a leading `@`, an attachment whose
//! materialized path is exported (`Exec.PGSSLROOTCERT=@ca.pem`). Such an
//! entry exports only its mappings, plus `Exec.Env` if it also has one.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
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
    /// The names of the entry's fields starting with `prefix`.
    fn field_names(&self, e: &Entry, prefix: &str) -> Result<Vec<String>>;
    fn attachment(&self, e: &Entry, name: &str) -> Result<Option<Vec<u8>>>;
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
    fn field_names(&self, e: &Entry, prefix: &str) -> Result<Vec<String>> {
        Ok(self.vault.fields_with_prefix(self.id(e)?, prefix)?)
    }
    fn attachment(&self, e: &Entry, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.vault.read_binary(self.id(e)?, name)?)
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
        use serde_json::Value;
        let code = crate::require_session_code()?;
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
    fn field_names(&self, e: &Entry, prefix: &str) -> Result<Vec<String>> {
        Ok(self
            .custom_fields(e)?
            .into_iter()
            .filter(|n| n.starts_with(prefix))
            .collect())
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
    for e in matches {
        let exec_env = v.field(e, "Exec.Env")?;
        let fallback = env_name_from_title(&e.title);

        let mappings = mapped_injections(v, e, tmp)?;
        if !mappings.is_empty() {
            out.extend(mappings);
            if exec_env.is_none() {
                continue;
            }
        }

        // Attachment-bearing entries inject a FILE path. Prefer the
        // materialization source when declared, else a sole attachment.
        let att = match v.field(e, "Materialize.Source")? {
            Some(src) if e.attachment_names.contains(&src) => Some(src),
            _ if e.attachment_names.len() == 1 => Some(e.attachment_names[0].clone()),
            _ => None,
        };
        if let Some(att_name) = att {
            if let Some(bytes) = v.attachment(e, &att_name)? {
                let file = materialize(tmp, e, &att_name, &bytes)?;
                out.push(Injection {
                    name: exec_env
                        .clone()
                        .unwrap_or_else(|| format!("TROVE_{fallback}_FILE")),
                    value: file.to_string_lossy().into_owned(),
                });
                continue;
            }
        }

        // String secret: the Password field.
        if let Some(pw) = v.field(e, "Password")? {
            if !pw.is_empty() {
                out.push(Injection {
                    name: exec_env.unwrap_or_else(|| format!("TROVE_{fallback}_PASSWORD")),
                    value: pw,
                });
            }
        }
    }
    if out.is_empty() {
        return Err(anyhow!(
            "'{name}' matched entries but none carry a password or attachment to inject"
        ));
    }
    Ok(out)
}

/// The `Exec.<VAR>` mappings on one entry (every `Exec.*` field but
/// `Exec.Env`), resolved and sorted by variable name. A mapping that names a
/// field or attachment the entry doesn't have is an error rather than a
/// silently missing variable.
fn mapped_injections(v: &dyn Source, e: &Entry, tmp: &Path) -> Result<Vec<Injection>> {
    let mut names = v.field_names(e, "Exec.")?;
    names.retain(|n| n != "Exec.Env");
    names.sort();
    let path = e.display_path();
    let mut out = Vec::with_capacity(names.len());
    for field in names {
        let var = &field["Exec.".len()..];
        if !is_env_name(var) {
            return Err(anyhow!(
                "{path}: '{field}' doesn't name a valid environment variable \
                 (letters, digits and _, not starting with a digit)"
            ));
        }
        let source = v.field(e, &field)?.unwrap_or_default();
        let source = source.trim();
        let value = if let Some(att) = source.strip_prefix('@') {
            let bytes = v.attachment(e, att)?.ok_or_else(|| {
                anyhow!("{path}: {field} names attachment '{att}', which it doesn't have")
            })?;
            let file = materialize(tmp, e, att, &bytes)?;
            file.to_string_lossy().into_owned()
        } else {
            if source.is_empty() {
                return Err(anyhow!(
                    "{path}: {field} is empty; set it to a field name or @attachment"
                ));
            }
            v.field(e, source)?.ok_or_else(|| {
                anyhow!("{path}: {field} names field '{source}', which it doesn't have")
            })?
        };
        out.push(Injection {
            name: var.to_string(),
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

/// A POSIX-portable environment variable name.
fn is_env_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
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
        // String secret with fallback name.
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
        assert_eq!(
            names,
            vec!["KUBECONFIG", "STRIPE_KEY", "TROVE_DB_MAIN_PASSWORD"]
        );
        assert!(!inj.iter().any(|i| i.value == "not-injected"));

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
