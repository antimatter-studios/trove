//! `trove doctor` — pre-flight checks for the setup around trove: the daemon,
//! the agent sockets clients are pointed at, the vault file and the env file.
//!
//! Every check is read-only and never starts a daemon. A check that finds
//! something broken is a `fail` and makes the command exit non-zero; one that
//! finds something worth knowing but not broken is a `warn`; one that doesn't
//! apply here is `info`.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::daemon;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Info,
    Warn,
    Fail,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub status: Level,
    pub detail: String,
    pub hint: Option<String>,
}

impl Check {
    fn new(name: &'static str, status: Level, detail: impl Into<String>) -> Self {
        Check {
            name,
            status,
            detail: detail.into(),
            hint: None,
        }
    }

    fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn to_json(&self) -> Value {
        let status = match self.status {
            Level::Ok => "ok",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Fail => "fail",
        };
        serde_json::json!({
            "name": self.name,
            "status": status,
            "detail": self.detail,
            "hint": self.hint,
        })
    }
}

/// Run every check. `vault` is the vault the command line or `TROVE_VAULT`
/// names, if any.
pub fn run_checks(vault: Option<&Path>) -> Vec<Check> {
    let mut checks = Vec::new();
    let status = daemon::send(&daemon::Request::Status);
    let running = status.is_ok();
    checks.push(daemon_check(&status));
    if let Ok(resp) = &status {
        checks.push(version_check());
        checks.push(skipped_keys_check(resp));
        if let Some(c) = gpg_keyring_check() {
            checks.push(c);
        }
        if let Some(c) = materialized_check() {
            checks.push(c);
        }
    }
    #[cfg(unix)]
    checks.push(daemons_check());
    checks.push(ssh_check(running));
    checks.push(gpg_check());
    checks.push(vault_check(vault));
    checks.extend(env_file_checks(vault));
    checks
}

fn daemon_check(status: &anyhow::Result<Value>) -> Check {
    match status {
        Ok(resp) => {
            if let Some(msg) = daemon::response_error(resp) {
                return Check::new("daemon", Level::Fail, format!("troved answered: {msg}"));
            }
            let vaults = resp
                .get("vault_paths")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            let keys = resp.get("ssh_keys").and_then(Value::as_u64).unwrap_or(0);
            Check::new(
                "daemon",
                Level::Ok,
                format!(
                    "running on {}; {vaults} vault(s) unlocked, {keys} SSH key(s) served",
                    daemon::control_socket_path().display()
                ),
            )
        }
        Err(e) if daemon::is_daemon_not_running(e) => Check::new(
            "daemon",
            Level::Info,
            "not running, so nothing is unlocked; `trove unlock` starts it",
        ),
        Err(e) => Check::new(
            "daemon",
            Level::Fail,
            format!(
                "can't talk to troved on {}: {e:#}",
                daemon::control_socket_path().display()
            ),
        )
        .hint("`trove daemons list` shows every daemon and its socket"),
    }
}

/// Keys in the unlocked vaults that the agents couldn't load, and why.
fn skipped_keys_check(status: &Value) -> Check {
    let skipped: Vec<String> = status
        .get("skipped_keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|k| {
            let s = |f: &str| k.get(f).and_then(Value::as_str).unwrap_or("?");
            format!(
                "{} {}:{} ({})",
                s("agent"),
                s("entry"),
                s("attachment"),
                s("reason")
            )
        })
        .collect();
    if skipped.is_empty() {
        return Check::new("keys", Level::Ok, "every key in the unlocked vaults loaded");
    }
    Check::new(
        "keys",
        Level::Warn,
        format!(
            "{} key(s) not loaded: {}",
            skipped.len(),
            skipped.join("; ")
        ),
    )
    .hint("`trove status` lists them too")
}

/// Whether gpg's keyring has the public half of every GPG key the agent
/// serves: gpg won't ask an agent to sign with a key it doesn't know. `None`
/// when the agent serves no GPG keys or gpg isn't installed.
fn gpg_keyring_check() -> Option<Check> {
    let resp = daemon::send(&daemon::Request::GpgAgentList).ok()?;
    let served: Vec<(String, String)> = resp
        .get("gpg_keys")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|k| {
            Some((
                k.get("keygrip")?.as_str()?.to_ascii_lowercase(),
                k.get("comment")
                    .and_then(Value::as_str)
                    .unwrap_or("?")
                    .to_string(),
            ))
        })
        .collect();
    if served.is_empty() {
        return None;
    }
    let out = std::process::Command::new("gpg")
        .args(["--batch", "--with-colons", "--with-keygrip", "--list-keys"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let listing = String::from_utf8_lossy(&out.stdout);
    Some(classify_keyring(&served, &keyring_grips(&listing)))
}

/// Keygrips from `gpg --with-colons --with-keygrip` output (`grp` records).
fn keyring_grips(listing: &str) -> Vec<String> {
    listing
        .lines()
        .filter(|l| l.starts_with("grp:"))
        .filter_map(|l| l.split(':').nth(9))
        .map(str::to_ascii_lowercase)
        .collect()
}

fn classify_keyring(served: &[(String, String)], keyring: &[String]) -> Check {
    let mut missing: Vec<&str> = served
        .iter()
        .filter(|(grip, _)| !keyring.contains(grip))
        .map(|(_, comment)| comment.as_str())
        .collect();
    missing.sort_unstable();
    missing.dedup();
    if missing.is_empty() {
        return Check::new(
            "gpg-keyring",
            Level::Ok,
            "gpg's keyring has the public key of every vault GPG key",
        );
    }
    Check::new(
        "gpg-keyring",
        Level::Warn,
        format!(
            "gpg's keyring lacks the public key for {}, so gpg won't sign with it",
            missing.join(", ")
        ),
    )
    .hint("trove gpg-agent import")
}

/// Materialized files that sit on a disk-backed filesystem. `None` when
/// nothing is materialized.
fn materialized_check() -> Option<Check> {
    let resp = daemon::send(&daemon::Request::MaterializeStatus).ok()?;
    let files = resp.get("materialized").and_then(Value::as_array)?;
    if files.is_empty() {
        return None;
    }
    let on_disk: Vec<String> = files
        .iter()
        .filter(|f| {
            !f.get("memory_backed")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .filter_map(|f| {
            f.get("target_path")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect();
    Some(if on_disk.is_empty() {
        Check::new(
            "materialize",
            Level::Ok,
            format!("{} materialized file(s), all on tmpfs", files.len()),
        )
    } else {
        Check::new(
            "materialize",
            Level::Info,
            format!(
                "{} materialized file(s) on a disk-backed filesystem, so the wipe on lock is \
                 best effort: {}",
                on_disk.len(),
                on_disk.join(", ")
            ),
        )
    })
}

fn version_check() -> Check {
    let cli = daemon::cli_version();
    let resp = daemon::send(&daemon::Request::GetVersion).ok();
    match resp
        .as_ref()
        .and_then(|r| r.get("daemon_version"))
        .and_then(Value::as_str)
    {
        Some(v) if v == cli => {
            Check::new("version", Level::Ok, format!("cli and daemon are {cli}"))
        }
        Some(v) => Check::new(
            "version",
            Level::Warn,
            format!("cli is {cli} but the running daemon is {v}"),
        )
        .hint("restart it: `trove lock`, or `brew services restart trove` if it runs as a service"),
        None => Check::new(
            "version",
            Level::Warn,
            format!("the running daemon predates version reporting; cli is {cli}"),
        )
        .hint("restart it: `trove lock`, or `trove daemons kill --all`"),
    }
}

#[cfg(unix)]
fn daemons_check() -> Check {
    let all = troved::daemons::enumerate();
    let current = daemon::control_socket_path();
    let stray: Vec<String> = all
        .iter()
        .filter(|d| d.alive && d.control_sock != current)
        .map(|d| d.control_sock.display().to_string())
        .collect();
    let stale = all.iter().filter(|d| !d.alive).count();
    if !stray.is_empty() {
        return Check::new(
            "daemons",
            Level::Warn,
            format!(
                "{} other live daemon(s) on sockets this CLI doesn't use: {}",
                stray.len(),
                stray.join(", ")
            ),
        )
        .hint("stop one with `trove daemons kill <SOCKET>`");
    }
    if stale > 0 {
        return Check::new(
            "daemons",
            Level::Info,
            format!("{stale} stale lock or socket file(s) left by daemons that died"),
        )
        .hint("`trove daemons kill --all` clears them");
    }
    Check::new("daemons", Level::Ok, "no stray daemons")
}

fn ssh_check(daemon_running: bool) -> Check {
    let value = std::env::var("SSH_AUTH_SOCK").ok();
    let trove_main = troved::ssh_agent::resolve_ssh_socket_path();
    let scoped = if daemon_running {
        scoped_sockets()
    } else {
        Vec::new()
    };
    classify_ssh_auth_sock(value.as_deref(), &trove_main, &scoped, agent_reachable)
}

/// The private sockets the running daemon serves.
fn scoped_sockets() -> Vec<String> {
    daemon::send(&daemon::Request::SshAgentSockets)
        .ok()
        .and_then(|r| r.get("ssh_sockets").cloned())
        .and_then(|s| s.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.get("socket").and_then(Value::as_str).map(str::to_string))
        .collect()
}

#[cfg(unix)]
fn agent_reachable(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

#[cfg(windows)]
fn agent_reachable(path: &Path) -> bool {
    // A named pipe "exists" for as long as a server holds an instance open.
    // `metadata` on `\\.\pipe\name` doesn't connect, so it can't use up the
    // instance a real client is about to take.
    std::fs::metadata(path).is_ok()
}

/// What `SSH_AUTH_SOCK` means for trove. Pure, so the cases are unit-tested.
fn classify_ssh_auth_sock(
    value: Option<&str>,
    trove_main: &Path,
    scoped: &[String],
    reachable: impl Fn(&Path) -> bool,
) -> Check {
    let main_addr = troved::ipc::client_address(trove_main);
    let use_trove = format!("export SSH_AUTH_SOCK=\"$(trove ssh-agent socket)\" (now {main_addr})");
    let value = match value {
        Some(v) if !v.is_empty() => v,
        _ => {
            return Check::new(
                "ssh-agent",
                Level::Warn,
                "SSH_AUTH_SOCK is not set, so ssh uses no agent at all",
            )
            .hint(use_trove)
        }
    };
    let path = Path::new(value);
    if value == main_addr || path == trove_main {
        return if reachable(path) {
            Check::new(
                "ssh-agent",
                Level::Ok,
                format!("SSH_AUTH_SOCK is trove's agent ({value})"),
            )
        } else {
            Check::new(
                "ssh-agent",
                Level::Warn,
                format!("SSH_AUTH_SOCK is trove's agent ({value}), but troved isn't serving it"),
            )
            .hint("`trove unlock <VAULT>` starts it")
        };
    }
    if scoped.iter().any(|s| s == value) {
        return Check::new(
            "ssh-agent",
            Level::Ok,
            format!(
                "SSH_AUTH_SOCK is a private trove agent from `trove ssh-agent empty` ({value})"
            ),
        );
    }
    if reachable(path) {
        return Check::new(
            "ssh-agent",
            Level::Ok,
            format!(
                "SSH_AUTH_SOCK is another agent ({value}); unlock copies vault keys into it \
                 unless TROVE_SSH_FORWARD=0"
            ),
        );
    }
    Check::new(
        "ssh-agent",
        Level::Fail,
        format!("SSH_AUTH_SOCK is {value}, but nothing is listening there"),
    )
    .hint(use_trove)
}

fn gpg_check() -> Check {
    let trove_gpg = troved::gpg_agent::resolve_gpg_socket_path();
    let Some(agent_socket) = gpgconf_agent_socket() else {
        return Check::new(
            "gpg-agent",
            Level::Info,
            "gpgconf isn't on PATH, so gpg isn't set up here",
        );
    };
    let link = std::fs::read_link(&agent_socket).ok();
    classify_gpg(
        &agent_socket,
        link.as_deref(),
        &trove_gpg,
        trove_gpg.exists(),
    )
}

/// Where gpg looks for its agent, from `gpgconf --list-dirs agent-socket`.
fn gpgconf_agent_socket() -> Option<PathBuf> {
    let out = std::process::Command::new("gpgconf")
        .args(["--list-dirs", "agent-socket"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| PathBuf::from(s))
}

/// Whether gpg's agent socket is a symlink to trove's. Pure, so the cases are
/// unit-tested.
fn classify_gpg(
    agent_socket: &Path,
    link: Option<&Path>,
    trove_gpg: &Path,
    trove_gpg_exists: bool,
) -> Check {
    let link_cmd = format!(
        "ln -sf \"$(trove gpg-agent socket)\" {}",
        agent_socket.display()
    );
    match link {
        Some(target) if target == trove_gpg => {
            if trove_gpg_exists {
                Check::new(
                    "gpg-agent",
                    Level::Ok,
                    format!("{} points at trove", agent_socket.display()),
                )
            } else {
                Check::new(
                    "gpg-agent",
                    Level::Warn,
                    format!(
                        "{} points at trove, but troved isn't serving {}; gpg signing fails \
                         until a vault is unlocked",
                        agent_socket.display(),
                        trove_gpg.display()
                    ),
                )
            }
        }
        Some(target) => Check::new(
            "gpg-agent",
            Level::Warn,
            format!(
                "{} is a symlink to {}, not to trove's socket ({})",
                agent_socket.display(),
                target.display(),
                trove_gpg.display()
            ),
        )
        .hint(link_cmd),
        None => Check::new(
            "gpg-agent",
            Level::Info,
            format!(
                "gpg uses its own agent at {}; vault GPG keys aren't reachable from gpg",
                agent_socket.display()
            ),
        )
        .hint(format!("to sign with vault keys: {link_cmd}")),
    }
}

fn vault_check(vault: Option<&Path>) -> Check {
    let Some(path) = vault else {
        return Check::new(
            "vault",
            Level::Info,
            "no vault named (pass --vault or set TROVE_VAULT to check one)",
        );
    };
    match std::fs::File::open(path) {
        Ok(mut f) => {
            use std::io::Read as _;
            let mut head = [0u8; 12];
            let n = f.read(&mut head).unwrap_or(0);
            classify_vault_header(path, &head[..n])
        }
        Err(e) => Check::new(
            "vault",
            Level::Fail,
            format!("can't open {}: {e}", path.display()),
        ),
    }
}

/// Read the KDBX signature and version from a vault's first 12 bytes. Pure,
/// so the cases are unit-tested.
fn classify_vault_header(path: &Path, head: &[u8]) -> Check {
    const SIG1: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];
    const SIG2_KDBX: [u8; 4] = [0x67, 0xfb, 0x4b, 0xb5];
    const SIG2_KDB: [u8; 4] = [0x65, 0xfb, 0x4b, 0xb5];
    if head.len() < 12 || head[..4] != SIG1 {
        return Check::new(
            "vault",
            Level::Fail,
            format!("{} is not a KeePass database", path.display()),
        );
    }
    if head[4..8] == SIG2_KDB {
        return Check::new(
            "vault",
            Level::Fail,
            format!(
                "{} is a KeePass 1.x (.kdb) database, which trove can't open",
                path.display()
            ),
        )
        .hint("open it in KeePassXC and save it as KDBX 4");
    }
    if head[4..8] != SIG2_KDBX {
        return Check::new(
            "vault",
            Level::Fail,
            format!("{} is not a KDBX database", path.display()),
        );
    }
    let minor = u16::from_le_bytes([head[8], head[9]]);
    let major = u16::from_le_bytes([head[10], head[11]]);
    match major {
        4 => Check::new(
            "vault",
            Level::Ok,
            format!("{} is KDBX {major}.{minor}", path.display()),
        ),
        3 => Check::new(
            "vault",
            Level::Warn,
            format!(
                "{} is KDBX {major}.{minor}; trove reads it, and saving it writes KDBX 4",
                path.display()
            ),
        ),
        _ => Check::new(
            "vault",
            Level::Fail,
            format!(
                "{} is KDBX {major}.{minor}, which trove can't open",
                path.display()
            ),
        ),
    }
}

/// Every `.env.trove` a bare `--env` would find, checked for permissions.
fn env_file_checks(vault: Option<&Path>) -> Vec<Check> {
    crate::env_file_candidates(vault)
        .into_iter()
        .filter(|p| p.is_file())
        .map(|p| env_file_check(&p))
        .collect()
}

#[cfg(unix)]
fn env_file_check(path: &Path) -> Check {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 == 0 {
                Check::new(
                    "env-file",
                    Level::Ok,
                    format!("{} is mode {mode:04o}", path.display()),
                )
            } else {
                Check::new(
                    "env-file",
                    Level::Warn,
                    format!(
                        "{} is mode {mode:04o}, readable by more than its owner",
                        path.display()
                    ),
                )
                .hint(format!("chmod 600 {}", path.display()))
            }
        }
        Err(e) => Check::new(
            "env-file",
            Level::Fail,
            format!("can't read {}: {e}", path.display()),
        ),
    }
}

#[cfg(not(unix))]
fn env_file_check(path: &Path) -> Check {
    Check::new(
        "env-file",
        Level::Info,
        format!(
            "{} found; Windows has no mode bits to check",
            path.display()
        ),
    )
}

/// Print the checks, one per line, with any hint under its check.
pub fn print(checks: &[Check]) {
    let width = checks.iter().map(|c| c.name.len()).max().unwrap_or(0);
    for c in checks {
        println!(
            "{:<4}  {:<width$}  {}",
            c.status.label(),
            c.name,
            c.detail,
            width = width
        );
        if let Some(h) = &c.hint {
            println!("{:<4}  {:<width$}  -> {h}", "", "", width = width);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn never(_: &Path) -> bool {
        false
    }
    fn always(_: &Path) -> bool {
        true
    }

    #[test]
    fn ssh_auth_sock_unset_is_a_warning() {
        let c = classify_ssh_auth_sock(None, Path::new("/r/trove-ssh.sock"), &[], never);
        assert_eq!(c.status, Level::Warn);
        let c = classify_ssh_auth_sock(Some(""), Path::new("/r/trove-ssh.sock"), &[], never);
        assert_eq!(c.status, Level::Warn);
    }

    #[test]
    fn ssh_auth_sock_on_trove_is_ok_only_when_served() {
        let main = Path::new("/r/trove-ssh.sock");
        let c = classify_ssh_auth_sock(Some("/r/trove-ssh.sock"), main, &[], always);
        assert_eq!(c.status, Level::Ok);
        let c = classify_ssh_auth_sock(Some("/r/trove-ssh.sock"), main, &[], never);
        assert_eq!(c.status, Level::Warn);
    }

    #[test]
    fn ssh_auth_sock_on_a_scoped_socket_is_ok() {
        let scoped = vec!["/r/trove-ssh-abc.sock".to_string()];
        let c = classify_ssh_auth_sock(
            Some("/r/trove-ssh-abc.sock"),
            Path::new("/r/trove-ssh.sock"),
            &scoped,
            never,
        );
        assert_eq!(c.status, Level::Ok);
        assert!(c.detail.contains("private"), "{}", c.detail);
    }

    #[test]
    fn ssh_auth_sock_elsewhere_is_ok_when_live_and_a_failure_when_stale() {
        let main = Path::new("/r/trove-ssh.sock");
        let c = classify_ssh_auth_sock(Some("/tmp/other/agent"), main, &[], always);
        assert_eq!(c.status, Level::Ok);
        assert!(c.detail.contains("another agent"), "{}", c.detail);
        let c = classify_ssh_auth_sock(Some("/tmp/other/agent"), main, &[], never);
        assert_eq!(c.status, Level::Fail);
        assert!(c.hint.is_some());
    }

    #[test]
    fn skipped_keys_are_a_warning() {
        let clean = serde_json::json!({"status": "ok"});
        assert_eq!(skipped_keys_check(&clean).status, Level::Ok);
        let skipped = serde_json::json!({"skipped_keys": [{
            "agent": "ssh", "vault": "/v.kdbx", "entry": "Old/dsa",
            "attachment": "id", "reason": "DSA keys are not supported",
        }]});
        let c = skipped_keys_check(&skipped);
        assert_eq!(c.status, Level::Warn);
        assert!(
            c.detail.contains("Old/dsa:id") && c.detail.contains("DSA"),
            "{}",
            c.detail
        );
    }

    #[test]
    fn keyring_check_finds_missing_public_keys() {
        let listing = "pub:u:255:22:ABCD:1:::::::scSC:::::ed25519:::0:\n\
                       grp:::::::::AAAA1111:\n\
                       sub:u:255:18:EF01:1::::::e:::::cv25519::\n\
                       grp:::::::::BBBB2222:\n";
        let grips = keyring_grips(listing);
        assert_eq!(grips, ["aaaa1111", "bbbb2222"]);
        let served = vec![
            ("aaaa1111".to_string(), "Sign/work".to_string()),
            ("cccc3333".to_string(), "Sign/home".to_string()),
        ];
        let c = classify_keyring(&served, &grips);
        assert_eq!(c.status, Level::Warn);
        assert!(
            c.detail.contains("Sign/home") && !c.detail.contains("Sign/work"),
            "{}",
            c.detail
        );
        assert_eq!(classify_keyring(&served[..1], &grips).status, Level::Ok);
    }

    #[test]
    fn gpg_symlink_cases() {
        let agent = Path::new("/h/.gnupg/S.gpg-agent");
        let trove = Path::new("/r/trove-gpg.sock");
        assert_eq!(
            classify_gpg(agent, Some(trove), trove, true).status,
            Level::Ok
        );
        assert_eq!(
            classify_gpg(agent, Some(trove), trove, false).status,
            Level::Warn
        );
        let elsewhere = classify_gpg(agent, Some(Path::new("/old/trove-gpg.sock")), trove, true);
        assert_eq!(elsewhere.status, Level::Warn);
        assert!(elsewhere.hint.unwrap().contains("ln -sf"));
        assert_eq!(classify_gpg(agent, None, trove, true).status, Level::Info);
    }

    fn header(sig2: [u8; 4], minor: u16, major: u16) -> Vec<u8> {
        let mut h = vec![0x03, 0xd9, 0xa2, 0x9a];
        h.extend_from_slice(&sig2);
        h.extend_from_slice(&minor.to_le_bytes());
        h.extend_from_slice(&major.to_le_bytes());
        h
    }

    #[test]
    fn vault_header_cases() {
        let p = Path::new("v.kdbx");
        let kdbx = [0x67, 0xfb, 0x4b, 0xb5];
        assert_eq!(
            classify_vault_header(p, &header(kdbx, 1, 4)).status,
            Level::Ok
        );
        let v3 = classify_vault_header(p, &header(kdbx, 1, 3));
        assert_eq!(v3.status, Level::Warn);
        assert!(v3.detail.contains("KDBX 3.1"), "{}", v3.detail);
        assert_eq!(
            classify_vault_header(p, &header(kdbx, 0, 5)).status,
            Level::Fail
        );
        let kdb = classify_vault_header(p, &header([0x65, 0xfb, 0x4b, 0xb5], 0, 1));
        assert_eq!(kdb.status, Level::Fail);
        assert!(kdb.detail.contains("1.x"));
        assert_eq!(
            classify_vault_header(p, b"hello world!").status,
            Level::Fail
        );
        assert_eq!(classify_vault_header(p, b"").status, Level::Fail);
    }

    #[test]
    fn a_real_vault_passes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kdbx");
        trove_core::Vault::create(&path, "pw").unwrap();
        assert_eq!(vault_check(Some(&path)).status, Level::Ok);
        assert_eq!(
            vault_check(Some(&dir.path().join("missing.kdbx"))).status,
            Level::Fail
        );
    }
}
