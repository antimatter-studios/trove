//! End-to-end test: drive a real `git commit -S` against our gpg agent
//! socket and confirm `gpg --verify` accepts the resulting signature.
//!
//! Skips automatically when `gpg`, `git`, or `gpgconf` aren't on `$PATH` —
//! this test is meaningful only on a system that ships GnuPG.
//!
//! What it does:
//!   1. Spin up an isolated `GNUPGHOME`.
//!   2. Generate a real ed25519 GPG signing key (`--quick-generate-key`).
//!   3. Export the secret as a binary blob.
//!   4. Stash it in a real .kdbx vault under attachment `gpg-priv`.
//!   5. Open the vault, populate the in-memory GPG key store.
//!   6. Spawn our GPG agent listener on a temp socket; symlink it as
//!      `$GNUPGHOME/S.gpg-agent` so gpg connects to *our* agent.
//!   7. Run `git commit -S --allow-empty` and assert the commit was made.
//!   8. Run `git log --show-signature` and assert "Good signature" appears.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use sdpm_core::Vault;
use sdpmd::gpg_agent::{self, GpgKeyStore};
use sdpmd::handler::load_gpg_keys_from_vault;
use tempfile::TempDir;
use tokio::sync::RwLock;

fn have_tool(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_commit_dash_capital_s_against_our_agent() {
    if !have_tool("gpg") || !have_tool("git") || !have_tool("gpgconf") {
        eprintln!("SKIP: gpg/git/gpgconf not on $PATH");
        return;
    }

    let tmp = TempDir::new().expect("tempdir");
    let gnupghome = tmp.path().join("gnupghome");
    std::fs::create_dir(&gnupghome).expect("mkdir gnupghome");
    {
        // chmod 700 — gpg refuses to use a world-readable homedir.
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&gnupghome).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&gnupghome, perms).unwrap();
    }
    let secret_path = tmp.path().join("secret.gpg");
    let vault_path = tmp.path().join("vault.kdbx");
    let sock_path = tmp.path().join("gpg.sock");
    let repo_path = tmp.path().join("repo");

    // 1. Generate an ed25519 GPG signing key.
    let kg = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args([
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            "sdpm-itest <itest@sdpm>",
            "ed25519",
            "sign",
        ])
        .output()
        .expect("spawn gpg --quick-generate-key");
    if !kg.status.success() {
        let stderr = String::from_utf8_lossy(&kg.stderr);
        eprintln!("SKIP: gpg --quick-generate-key failed (often happens on minimal CI envs without enough entropy):\n{stderr}");
        return;
    }

    // 2. Discover the fingerprint.
    let lk = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args(["--with-colons", "--list-secret-keys"])
        .output()
        .expect("spawn gpg --list-secret-keys");
    assert!(lk.status.success());
    let stdout = String::from_utf8_lossy(&lk.stdout);
    let fpr = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("fpr:::::::::"))
        .filter_map(|s| s.split(':').next())
        .next()
        .expect("find fingerprint")
        .to_string();
    assert_eq!(fpr.len(), 40, "fpr should be 40 hex chars: {fpr:?}");

    // 3. Export the secret key.
    let ex = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args([
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--export-secret-keys",
            "--output",
        ])
        .arg(&secret_path)
        .arg(&fpr)
        .output()
        .expect("spawn gpg --export-secret-keys");
    assert!(
        ex.status.success(),
        "gpg --export-secret-keys failed: {}",
        String::from_utf8_lossy(&ex.stderr)
    );
    let secret_bytes = std::fs::read(&secret_path).expect("read exported key");
    assert!(!secret_bytes.is_empty());

    // 4. Stash in a vault.
    let password = "itest-pw";
    {
        let mut vault = Vault::create(&vault_path, password).expect("create vault");
        let id = vault.add_entry("gpg-itest").expect("add entry");
        vault
            .attach_binary(&id, "gpg-priv", &secret_bytes)
            .expect("attach gpg-priv");
        vault.save().expect("save vault");
    }

    // 5. Populate the GPG key store from the vault.
    let vault = Vault::open(&vault_path, password).expect("reopen");
    let keys = load_gpg_keys_from_vault(&vault);
    assert!(
        !keys.is_empty(),
        "vault should yield at least one ed25519 GPG key"
    );
    let store: GpgKeyStore = Arc::new(RwLock::new(keys));

    // 6. Start our agent on a temp socket and symlink it as gnupghome/S.gpg-agent.
    let store_for_task = store.clone();
    let sock_for_task = sock_path.clone();
    let agent_handle = tokio::spawn(async move {
        let _ = gpg_agent::run(sock_for_task, store_for_task).await;
    });
    for _ in 0..100 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sock_path.exists(), "agent socket never appeared");

    // gpg looks for $GNUPGHOME/S.gpg-agent (a Unix-domain socket). Symlink ours.
    let agent_symlink = gnupghome.join("S.gpg-agent");
    let _ = std::fs::remove_file(&agent_symlink);
    std::os::unix::fs::symlink(&sock_path, &agent_symlink).expect("symlink");

    // Make sure no real gpg-agent is squatting (defensive — kill any process
    // that might have been started by the earlier `gpg --quick-generate-key`).
    let _ = Command::new("gpgconf")
        .env("GNUPGHOME", &gnupghome)
        .args(["--kill", "gpg-agent"])
        .output();
    // Re-symlink in case `gpgconf --kill` removed the file.
    let _ = std::fs::remove_file(&agent_symlink);
    std::os::unix::fs::symlink(&sock_path, &agent_symlink).expect("symlink");

    // 7. `git init` + `git commit -S`.
    std::fs::create_dir(&repo_path).expect("mkdir repo");
    let _ = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo_path)
        .output()
        .expect("git init");
    for (k, v) in [
        ("user.email", "itest@sdpm"),
        ("user.name", "sdpm-itest"),
        ("commit.gpgsign", "true"),
    ] {
        let _ = Command::new("git")
            .args(["config", k, v])
            .current_dir(&repo_path)
            .output()
            .expect("git config");
    }
    let _ = Command::new("git")
        .args(["config", "user.signingkey", &fpr])
        .current_dir(&repo_path)
        .output()
        .expect("git config user.signingkey");

    let commit = Command::new("git")
        .args(["commit", "-S", "--allow-empty", "-m", "sdpm itest commit"])
        .env("GNUPGHOME", &gnupghome)
        .current_dir(&repo_path)
        .output()
        .expect("git commit");
    eprintln!("git commit stdout: {}", String::from_utf8_lossy(&commit.stdout));
    eprintln!("git commit stderr: {}", String::from_utf8_lossy(&commit.stderr));
    assert!(
        commit.status.success(),
        "git commit -S should succeed against our gpg agent"
    );

    // 8. Verify the signature.
    let log = Command::new("git")
        .args(["log", "--show-signature"])
        .env("GNUPGHOME", &gnupghome)
        .current_dir(&repo_path)
        .output()
        .expect("git log");
    let log_out = format!(
        "{}{}",
        String::from_utf8_lossy(&log.stdout),
        String::from_utf8_lossy(&log.stderr)
    );
    eprintln!("git log --show-signature output:\n{log_out}");
    assert!(
        log_out.contains("Good signature"),
        "expected `Good signature` in `git log --show-signature` output, got:\n{log_out}"
    );

    agent_handle.abort();
    // best-effort: kill any gpg-agent that may have spawned from the test
    let _ = Command::new("gpgconf")
        .env("GNUPGHOME", &gnupghome)
        .args(["--kill", "all"])
        .output();
}

// Suppress dead-code warnings for the `PathBuf` import on platforms where
// the test is skipped via #[cfg(...)] (currently always compiled, but kept
// for parity with the SSH e2e test).
#[allow(dead_code)]
fn _force_use(_: PathBuf) {}
