//! trove's ssh-agent answering the *management* half of the protocol, driven
//! by the real `ssh-add(1)`.
//!
//! Until now trove answered only `REQUEST_IDENTITIES` and `SIGN_REQUEST`, so
//! `ssh-add -d`, `-D`, `-x` and `-X` all failed against it. That matters on its
//! own, and doubly so for the Windows plan in `docs/windows.md`, where trove
//! would bind the well-known agent pipe and every client on the machine would
//! reach for it.
//!
//! Driving the genuine `ssh-add` rather than hand-rolled bytes is the point:
//! these are the exact messages a real client sends.

#![allow(missing_docs)]
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::RwLock;
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::ssh_agent::{self, KeyStore};

/// Throwaway, passphrase-less ed25519 key. Not a credential for anything.
const KEY: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCRn16z5GRM5oSgyqTKTUCE9pq380DCaHag2QpcZqw/0QAAAKBtJ5akbSeW
pAAAAAtzc2gtZWQyNTUxOQAAACCRn16z5GRM5oSgyqTKTUCE9pq380DCaHag2QpcZqw/0Q
AAAEBkyrrFCWovzvKMKPkHg1YnA3jxeD+EsAsngASytbJUCpGfXrPkZEzmhKDKpMpNQIT2
mrfzQMJodqDZClxmrD/RAAAAF211bHRpdmF1bHQtYkB0cm92ZS50ZXN0AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
";

fn noop_idle() -> Arc<IdleTracker> {
    let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
    IdleTracker::new(Duration::from_secs(0), cb)
}

fn have(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run `ssh-add <args>` against our agent. Returns (success, stdout+stderr).
fn ssh_add(sock: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new("ssh-add")
        .args(args)
        .env("SSH_AUTH_SOCK", sock)
        // `-x`/`-X` want a passphrase; feed it without a tty.
        .env("SSH_ASKPASS_REQUIRE", "never")
        .output()
        .expect("run ssh-add");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// Stand up trove's agent on a temp socket with one key loaded.
async fn start_agent(tmp: &TempDir) -> (PathBuf, KeyStore) {
    let sock = tmp.path().join("a.sock");
    let key = troved::ssh_agent::keys::parse_private_key(KEY, "lifecycle@trove").expect("parse");
    let store: KeyStore = Arc::new(RwLock::new(vec![key]));

    let s = store.clone();
    let p = sock.clone();
    tokio::spawn(async move {
        let _ = ssh_agent::run(p, s, noop_idle()).await;
    });
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sock.exists(), "agent socket never appeared");
    (sock, store)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_add_can_remove_one_identity() {
    if !have("ssh-add") {
        eprintln!("skipping: ssh-add not installed");
        return;
    }
    let tmp = TempDir::new().expect("tempdir");
    let (sock, store) = start_agent(&tmp).await;

    let (ok, out) = ssh_add(&sock, &["-l"]);
    assert!(
        ok && out.contains("lifecycle@trove"),
        "listing failed: {out}"
    );

    assert_eq!(store.read().await.len(), 1, "one key loaded to start with");
    // `ssh-add -d` needs the public key on disk to know what to remove.
    let publine = troved::ssh_agent::keys::openssh_public_line(KEY, "lifecycle@trove")
        .expect("derive public line");
    let pubpath = tmp.path().join("id.pub");
    std::fs::write(&pubpath, &publine).expect("write pub");

    let (ok, out) = ssh_add(&sock, &["-d", pubpath.to_str().unwrap()]);
    assert!(ok, "ssh-add -d should succeed: {out}");
    assert!(
        store.read().await.is_empty(),
        "the key should be gone from the store"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_add_dash_capital_d_clears_the_agent() {
    if !have("ssh-add") {
        eprintln!("skipping: ssh-add not installed");
        return;
    }
    let tmp = TempDir::new().expect("tempdir");
    let (sock, store) = start_agent(&tmp).await;
    assert_eq!(store.read().await.len(), 1);

    let (ok, out) = ssh_add(&sock, &["-D"]);
    assert!(ok, "ssh-add -D should succeed: {out}");
    assert!(
        store.read().await.is_empty(),
        "-D must clear every key from the agent"
    );

    let (_, out) = ssh_add(&sock, &["-l"]);
    assert!(
        out.contains("no identities"),
        "agent should report empty after -D: {out}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locking_the_agent_hides_keys_until_unlocked() {
    if !have("ssh-add") || !have("expect") {
        eprintln!("skipping: ssh-add/expect not installed");
        return;
    }
    let tmp = TempDir::new().expect("tempdir");
    let (sock, store) = start_agent(&tmp).await;

    // `ssh-add -x` prompts on the tty, so drive it through `expect`.
    let lock_script = "spawn ssh-add -x\n\
         expect \"passphrase:\"\n send \"secret\\r\"\n\
         expect \"passphrase:\"\n send \"secret\\r\"\n\
         expect eof\n";
    let script_path = tmp.path().join("lock.exp");
    std::fs::write(&script_path, lock_script).expect("write script");
    let out = Command::new("expect")
        .arg(&script_path)
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .expect("run expect");
    let combined = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        combined.contains("Agent locked"),
        "ssh-add -x should lock our agent: {combined}"
    );

    // Locked: the listing must be empty even though the key is still held.
    let (_, out) = ssh_add(&sock, &["-l"]);
    assert!(
        out.contains("no identities"),
        "a locked agent must not list identities: {out}"
    );
    assert_eq!(
        store.read().await.len(),
        1,
        "locking hides keys; it does not discard them"
    );

    // Wrong passphrase must not unlock.
    let bad = tmp.path().join("bad.exp");
    std::fs::write(
        &bad,
        "spawn ssh-add -X\nexpect \"passphrase:\"\n send \"wrong\\r\"\nexpect eof\n",
    )
    .expect("write");
    let out = Command::new("expect")
        .arg(&bad)
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .expect("run expect");
    let combined = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        !combined.contains("Agent unlocked"),
        "the wrong passphrase must not unlock the agent: {combined}"
    );

    // Right passphrase does.
    let good = tmp.path().join("good.exp");
    std::fs::write(
        &good,
        "spawn ssh-add -X\nexpect \"passphrase:\"\n send \"secret\\r\"\nexpect eof\n",
    )
    .expect("write");
    let out = Command::new("expect")
        .arg(&good)
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .expect("run expect");
    let combined = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        combined.contains("Agent unlocked"),
        "the right passphrase should unlock: {combined}"
    );

    let (ok, out) = ssh_add(&sock, &["-l"]);
    assert!(
        ok && out.contains("lifecycle@trove"),
        "keys should be visible again after unlock: {out}"
    );
}
