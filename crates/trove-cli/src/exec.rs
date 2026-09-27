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

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use trove_core::{EntrySummary, Vault};

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
pub fn resolve(v: &Vault, scope: Scope, tmp: &Path) -> Result<Vec<Injection>> {
    let all = v.list_entries();
    let (name, matches) = match scope {
        Scope::Auto(name) => {
            let entry = v.find_by_title(&name);
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
                .find_by_title(&name)
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
        let exec_env = v.get_field(&e.id, "Exec.Env")?;
        let fallback = env_name_from_title(&e.title);

        // Attachment-bearing entries inject a FILE path. Prefer the
        // materialization source when declared, else a sole attachment.
        let att = match v.get_field(&e.id, "Materialize.Source")? {
            Some(src) if e.attachment_names.contains(&src) => Some(src),
            _ if e.attachment_names.len() == 1 => Some(e.attachment_names[0].clone()),
            _ => None,
        };
        if let Some(att_name) = att {
            if let Some(bytes) = v.read_binary(&e.id, &att_name)? {
                let file = tmp.join(format!("{}-{}", e.id, sanitize_filename(&att_name)));
                write_private(&file, &bytes)?;
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
        if let Some(pw) = v.get_field(&e.id, "Password")? {
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

fn group_matches<'a>(all: &'a [EntrySummary], scope: &str) -> Vec<&'a EntrySummary> {
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
    let dir = std::env::temp_dir().join(format!("trove-exec-{}-{suffix}", std::process::id()));
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

        let mut inj = resolve(&v, Scope::Auto("Infra".into()), &tmp).unwrap();
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
    fn single_entry_scope_and_misses() {
        let dir = TempDir::new().unwrap();
        let v = vault_for_exec(&dir);
        let tmp = dir.path().join("run2");
        std::fs::create_dir(&tmp).unwrap();

        let inj = resolve(&v, Scope::Auto("Infra/stripe".into()), &tmp).unwrap();
        assert_eq!(inj.len(), 1);
        assert_eq!(inj[0].name, "STRIPE_KEY");
        assert_eq!(inj[0].value, "sk_live_123");

        assert!(resolve(&v, Scope::Auto("No/Such".into()), &tmp).is_err());
        wipe_dir(&tmp);
    }
}
