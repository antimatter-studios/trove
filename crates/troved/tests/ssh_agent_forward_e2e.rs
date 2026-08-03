//! Forwarding unlocked keys into a real OpenSSH `ssh-agent`.
//!
//! Hand-rolled `ADD_IDENTITY` payloads are exactly the kind of code that
//! compiles, looks right, and is rejected on the wire — the per-algorithm
//! field order is easy to get wrong (RSA puts the modulus first here, the
//! opposite of the public-key blob). So these tests spawn the genuine
//! `ssh-agent(1)`, push keys into it, and confirm with `ssh-add -l` that it
//! accepted them and can list them back.
//!
//! Skipped with a printed note when `ssh-agent`/`ssh-add` aren't installed.

#![allow(missing_docs)]
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use troved::ssh_agent::forward;
use troved::ssh_agent::keys::{parse_private_key, LoadedKey};

/// ed25519, throwaway, passphrase-less. Not a credential for anything.
const ED25519: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCRn16z5GRM5oSgyqTKTUCE9pq380DCaHag2QpcZqw/0QAAAKBtJ5akbSeW
pAAAAAtzc2gtZWQyNTUxOQAAACCRn16z5GRM5oSgyqTKTUCE9pq380DCaHag2QpcZqw/0Q
AAAEBkyrrFCWovzvKMKPkHg1YnA3jxeD+EsAsngASytbJUCpGfXrPkZEzmhKDKpMpNQIT2
mrfzQMJodqDZClxmrD/RAAAAF211bHRpdmF1bHQtYkB0cm92ZS50ZXN0AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
";

fn have(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A real `ssh-agent` bound to a socket in a tempdir, killed on drop.
struct RealAgent {
    _dir: TempDir,
    sock: PathBuf,
    pid: Option<u32>,
}

impl RealAgent {
    fn start() -> Option<Self> {
        if !have("ssh-agent") || !have("ssh-add") {
            eprintln!("skipping: ssh-agent/ssh-add not installed");
            return None;
        }
        let dir = TempDir::new().expect("tempdir");
        let sock = dir.path().join("agent.sock");
        let out = Command::new("ssh-agent")
            .args(["-a", sock.to_str().expect("utf8")])
            .output()
            .expect("spawn ssh-agent");
        if !out.status.success() {
            eprintln!(
                "skipping: ssh-agent failed to start: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return None;
        }
        // `ssh-agent -a` daemonizes and prints `SSH_AGENT_PID=<pid>; export …`.
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let pid = stdout
            .split("SSH_AGENT_PID=")
            .nth(1)
            .and_then(|s| s.split(';').next())
            .and_then(|s| s.trim().parse::<u32>().ok());

        let deadline = Instant::now() + Duration::from_secs(5);
        while !sock.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if !sock.exists() {
            eprintln!("skipping: ssh-agent socket never appeared");
            return None;
        }
        Some(RealAgent {
            _dir: dir,
            sock,
            pid,
        })
    }

    /// `ssh-add -l` against this agent. Returns stdout; "no identities" is a
    /// success exit of 1, which we fold into an empty listing.
    fn list(&self) -> String {
        let out = Command::new("ssh-add")
            .arg("-l")
            .env("SSH_AUTH_SOCK", &self.sock)
            .output()
            .expect("run ssh-add -l");
        String::from_utf8_lossy(&out.stdout).to_string()
    }
}

impl Drop for RealAgent {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            let _ = Command::new("kill").arg(pid.to_string()).output();
        }
    }
}

fn load(pem: &[u8], comment: &str) -> LoadedKey {
    parse_private_key(pem, comment).expect("parse test key")
}

/// Generate a key with `ssh-keygen` so RSA/ECDSA coverage doesn't need a
/// multi-kilobyte literal in the source.
fn generate(dir: &Path, kind: &str, name: &str) -> Option<Vec<u8>> {
    if !have("ssh-keygen") {
        return None;
    }
    let path = dir.join(name);
    let mut cmd = Command::new("ssh-keygen");
    cmd.args(["-t", kind, "-N", "", "-C", "forward@trove.test", "-q", "-f"])
        .arg(&path);
    if kind == "rsa" {
        cmd.args(["-b", "2048"]);
    }
    let out = cmd.output().expect("run ssh-keygen");
    if !out.status.success() {
        return None;
    }
    std::fs::read(&path).ok()
}

#[tokio::test]
async fn a_real_ssh_agent_accepts_a_forwarded_ed25519_key() {
    let Some(agent) = RealAgent::start() else {
        return;
    };
    assert!(
        !agent.list().contains("forward-ed25519"),
        "agent should start empty"
    );

    let keys = vec![load(ED25519, "forward-ed25519")];
    // No lifetime constraint here: this asserts the plain ADD_IDENTITY path.
    let report = forward::add_all(&agent.sock, &keys, 0, false).await;
    assert_eq!(
        report.added, 1,
        "ssh-agent rejected the key: {:?}",
        report.warnings
    );

    let listed = agent.list();
    assert!(
        listed.contains("forward-ed25519"),
        "ssh-add -l should show the forwarded key, got: {listed}"
    );

    // …and lock must be able to take it back out again.
    let report = forward::remove_all(&agent.sock, &keys).await;
    assert_eq!(
        report.removed, 1,
        "ssh-agent refused the removal: {:?}",
        report.warnings
    );
    assert!(
        !agent.list().contains("forward-ed25519"),
        "key should be gone after remove_all"
    );
}

#[tokio::test]
async fn a_lifetime_constrained_add_is_accepted() {
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let keys = vec![load(ED25519, "forward-constrained")];
    // This is the path unlock actually uses: the constraint is the backstop
    // that expires the key even if troved dies before it can remove it.
    let report = forward::add_all(&agent.sock, &keys, 900, false).await;
    assert_eq!(
        report.added, 1,
        "ssh-agent rejected the constrained add: {:?}",
        report.warnings
    );
    assert!(agent.list().contains("forward-constrained"));
}

#[tokio::test]
async fn rsa_and_ecdsa_wire_formats_are_accepted_too() {
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let dir = TempDir::new().expect("tempdir");

    // Each algorithm has its own ADD_IDENTITY field layout, and RSA's differs
    // from the public-blob order — so each needs a real agent to vouch for it.
    let mut keys = Vec::new();
    if let Some(pem) = generate(dir.path(), "rsa", "id_rsa") {
        keys.push(load(&pem, "forward-rsa"));
    }
    if let Some(pem) = generate(dir.path(), "ecdsa", "id_ecdsa") {
        keys.push(load(&pem, "forward-ecdsa"));
    }
    if keys.is_empty() {
        eprintln!("skipping: ssh-keygen unavailable");
        return;
    }

    let expected = keys.len();
    let report = forward::add_all(&agent.sock, &keys, 0, false).await;
    assert_eq!(
        report.added, expected,
        "ssh-agent rejected a key: {:?}",
        report.warnings
    );

    let listed = agent.list();
    for key in &keys {
        assert!(
            listed.contains(&key.comment),
            "ssh-add -l missing '{}', got: {listed}",
            key.comment
        );
    }
}

#[tokio::test]
async fn forwarding_to_a_dead_agent_warns_instead_of_failing() {
    let dir = TempDir::new().expect("tempdir");
    let nowhere = dir.path().join("not-an-agent.sock");
    let keys = vec![load(ED25519, "forward-nowhere")];

    // An unreachable agent must never fail an unlock that otherwise worked —
    // but it must not be silent either.
    let report = forward::add_all(&nowhere, &keys, 0, false).await;
    assert_eq!(report.added, 0);
    assert_eq!(report.warnings.len(), 1, "the failure must be reported");
    assert!(
        report.warnings[0].contains("forward-nowhere"),
        "warning should name the key: {}",
        report.warnings[0]
    );
}
