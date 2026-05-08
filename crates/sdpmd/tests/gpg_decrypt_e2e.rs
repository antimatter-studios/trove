//! End-to-end test: drive a real `gpg --decrypt` against our gpg agent
//! socket and confirm the recovered plaintext matches what we encrypted.
//!
//! Skips automatically when `gpg` or `gpgconf` aren't on `$PATH`.
//!
//! What it does:
//!   1. Spin up an isolated `GNUPGHOME`.
//!   2. Generate a real ed25519+cv25519 GPG key (`--quick-generate-key default
//!      default`) — that gives us a signing primary plus an encryption subkey.
//!   3. Export the secret key bundle as a binary blob.
//!   4. Stash it in a real .kdbx vault under attachment `gpg-priv`.
//!   5. Open the vault, populate the in-memory GPG key store. Both keygrips
//!      (signing + encryption) should appear.
//!   6. Encrypt a message with `gpg --encrypt` (uses real gpg-agent for the
//!      encryption side — encryption needs no secret).
//!   7. Spawn our GPG agent listener on a temp socket; symlink it as
//!      `$GNUPGHOME/S.gpg-agent` so gpg connects to *our* agent.
//!   8. Run `gpg --decrypt` and assert the plaintext matches.
//!   9. Run `gpg --list-keys` and assert it succeeds (uses READKEY).

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use sdpm_core::Vault;
use sdpmd::gpg_agent::{self, GpgKeyStore};
use sdpmd::handler::load_gpg_keys_from_vault;
use sdpmd::idle::{IdleTracker, LockCallback, LockFuture};
use tempfile::TempDir;
use tokio::sync::RwLock;

fn noop_idle() -> Arc<IdleTracker> {
    let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
    IdleTracker::new(Duration::from_secs(0), cb)
}

fn have_tool(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gpg_decrypt_against_our_agent_recovers_plaintext() {
    if !have_tool("gpg") || !have_tool("gpgconf") {
        eprintln!("SKIP: gpg/gpgconf not on $PATH");
        return;
    }

    let tmp = TempDir::new().expect("tempdir");
    let gnupghome = tmp.path().join("gnupghome");
    std::fs::create_dir(&gnupghome).expect("mkdir gnupghome");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&gnupghome).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&gnupghome, perms).unwrap();
    }
    let secret_path = tmp.path().join("secret.gpg");
    let vault_path = tmp.path().join("vault.kdbx");
    let sock_path = tmp.path().join("gpg.sock");
    let plaintext_path = tmp.path().join("plain.txt");
    let cipher_path = tmp.path().join("plain.gpg");
    let recovered_path = tmp.path().join("recovered.txt");

    // 1. Generate a default key — gives ed25519 primary + cv25519 subkey on
    // modern gpg.
    let kg = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args([
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            "sdpm-decrypt-itest <decrypt@sdpm>",
            "default",
            "default",
        ])
        .output()
        .expect("spawn gpg --quick-generate-key");
    if !kg.status.success() {
        let stderr = String::from_utf8_lossy(&kg.stderr);
        eprintln!("SKIP: gpg --quick-generate-key failed:\n{stderr}");
        return;
    }

    // 2. Discover the primary fingerprint.
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

    // 3. Export the secret key bundle (primary + subkey).
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
    let password = "decrypt-itest-pw";
    {
        let mut vault = Vault::create(&vault_path, password).expect("create vault");
        let id = vault.add_entry("gpg-decrypt-itest").expect("add entry");
        vault
            .attach_binary(&id, "gpg-priv", &secret_bytes)
            .expect("attach gpg-priv");
        vault.save().expect("save vault");
    }

    // 5. Populate the GPG key store from the vault.
    let vault = Vault::open(&vault_path, password).expect("reopen");
    let keys = load_gpg_keys_from_vault(&vault);
    // Should contain both the ed25519 primary and the cv25519 subkey.
    assert!(
        keys.len() >= 2,
        "vault should yield both signing and encryption GPG keys, got {}",
        keys.len()
    );
    let mut have_ed25519 = false;
    let mut have_cv25519 = false;
    for k in &keys {
        match k {
            sdpmd::gpg_agent::keys::LoadedGpgKey::Ed25519(_) => have_ed25519 = true,
            sdpmd::gpg_agent::keys::LoadedGpgKey::Cv25519(_) => have_cv25519 = true,
        }
    }
    assert!(have_ed25519, "expected an ed25519 signing key in the bundle");
    assert!(have_cv25519, "expected a cv25519 encryption subkey in the bundle");
    let store: GpgKeyStore = Arc::new(RwLock::new(keys));

    // 6. Encrypt a message using *real* gpg-agent (encryption needs only the
    // recipient's public key — it doesn't need our agent yet).
    let original_plain = b"sdpm-test plaintext: hello, ECDH world! 1234567890 the quick brown fox";
    std::fs::write(&plaintext_path, original_plain).expect("write plaintext");
    let enc = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args([
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--recipient",
            &fpr,
            "--encrypt",
            "--output",
        ])
        .arg(&cipher_path)
        .arg(&plaintext_path)
        .output()
        .expect("spawn gpg --encrypt");
    assert!(
        enc.status.success(),
        "gpg --encrypt failed: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    // 7. Now redirect gpg-agent to ours. Kill any existing real one so the
    // symlink is the only path.
    let _ = Command::new("gpgconf")
        .env("GNUPGHOME", &gnupghome)
        .args(["--kill", "gpg-agent"])
        .output();

    let store_for_task = store.clone();
    let sock_for_task = sock_path.clone();
    let idle_for_task = noop_idle();
    let agent_handle = tokio::spawn(async move {
        let _ = gpg_agent::run(sock_for_task, store_for_task, idle_for_task).await;
    });
    for _ in 0..100 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sock_path.exists(), "agent socket never appeared");

    let agent_symlink = gnupghome.join("S.gpg-agent");
    let _ = std::fs::remove_file(&agent_symlink);
    std::os::unix::fs::symlink(&sock_path, &agent_symlink).expect("symlink");

    // 8. Decrypt against our agent.
    let dec = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args(["--batch", "--yes", "--decrypt", "--output"])
        .arg(&recovered_path)
        .arg(&cipher_path)
        .output()
        .expect("spawn gpg --decrypt");
    let dec_stderr = String::from_utf8_lossy(&dec.stderr).into_owned();
    eprintln!("gpg --decrypt stdout: {}", String::from_utf8_lossy(&dec.stdout));
    eprintln!("gpg --decrypt stderr: {dec_stderr}");
    if !dec.status.success() {
        agent_handle.abort();
        let _ = Command::new("gpgconf")
            .env("GNUPGHOME", &gnupghome)
            .args(["--kill", "all"])
            .output();
        panic!(
            "gpg --decrypt against our agent failed.\nstderr:\n{dec_stderr}"
        );
    }
    let recovered = std::fs::read(&recovered_path).expect("read recovered");
    assert_eq!(
        recovered, original_plain,
        "decrypted plaintext must match the original"
    );

    // 9. Run gpg --list-keys to exercise READKEY.
    let lk2 = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args(["--list-keys"])
        .output()
        .expect("spawn gpg --list-keys");
    eprintln!("gpg --list-keys stdout: {}", String::from_utf8_lossy(&lk2.stdout));
    eprintln!("gpg --list-keys stderr: {}", String::from_utf8_lossy(&lk2.stderr));
    // We assert *success* — list-keys reads pubkeys from the keyring, but it
    // does call into the agent for state queries. If READKEY misbehaves, the
    // command may print warnings; we accept warnings, not failures.
    assert!(
        lk2.status.success(),
        "gpg --list-keys should succeed even when our agent is in front: {}",
        String::from_utf8_lossy(&lk2.stderr)
    );

    agent_handle.abort();
    let _ = Command::new("gpgconf")
        .env("GNUPGHOME", &gnupghome)
        .args(["--kill", "all"])
        .output();
}

#[allow(dead_code)]
fn _force_use(_: PathBuf) {}
