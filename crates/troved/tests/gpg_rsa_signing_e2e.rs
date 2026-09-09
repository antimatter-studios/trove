//! End-to-end: `git commit -S` with an **RSA** OpenPGP key served by our agent.
//!
//! The ed25519 sibling of this test lives in `gpg_git_signing_e2e.rs`. This one
//! exists because RSA is the algorithm most existing PGP keys actually use —
//! `gpg --gen-key` defaulted to it until GnuPG 2.3 — so ed25519-only support
//! left most users unable to sign at all.
//!
//! It also acts as a differential probe. If the ed25519 test fails on a given
//! gpg build (a known symptom on development 2.5.x releases) but this one
//! passes, the fault is algorithm-specific rather than socket plumbing.
//!
//! Skips automatically when `gpg`/`git`/`gpgconf` aren't installed.

#![allow(missing_docs)]
#![cfg(unix)]

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::RwLock;
use trove_core::Vault;
use troved::gpg_agent::{self, GpgKeyStore};
use troved::handler::load_gpg_keys_from_vault;
use troved::idle::{IdleTracker, LockCallback, LockFuture};

fn noop_idle() -> Arc<IdleTracker> {
    let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
    IdleTracker::new(Duration::from_secs(0), cb)
}

/// A `git` command isolated from the developer's own global/system config.
///
/// Without this the user's `~/.gitconfig` leaks into the test. A `gpg.program`
/// wrapper there — a common trove setup, and exactly what one developer had —
/// re-exports its own `GNUPGHOME`, discarding the isolated one this test sets.
/// gpg then looks in the wrong keyring, finds no key, and reports
/// `skipped "<FPR>": No secret key`. That failure looks convincingly like a gpg
/// protocol bug and was misdiagnosed as one for a long time; it is not.
fn git_isolated(repo: &std::path::Path, no_config: &std::path::Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", no_config)
        .env("GIT_CONFIG_SYSTEM", no_config)
        .env("GIT_CONFIG_NOSYSTEM", "1");
    c
}

fn have_tool(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_commit_dash_capital_s_with_an_rsa_key() {
    if !have_tool("gpg") || !have_tool("git") || !have_tool("gpgconf") {
        eprintln!("SKIP: gpg/git/gpgconf not on $PATH");
        return;
    }

    let tmp = TempDir::new().expect("tempdir");
    let gnupghome = tmp.path().join("gh");
    std::fs::create_dir(&gnupghome).expect("mkdir gnupghome");
    {
        // gpg refuses a world-readable homedir.
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&gnupghome).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&gnupghome, perms).unwrap();
    }
    let secret_path = tmp.path().join("secret.gpg");
    let vault_path = tmp.path().join("vault.kdbx");
    let sock_path = tmp.path().join("g.sock");
    let repo_path = tmp.path().join("repo");

    // 1. A real RSA-2048 signing key.
    let kg = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args([
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            "trove-rsa-itest <rsa@trove>",
            "rsa2048",
            "sign",
        ])
        .output()
        .expect("spawn gpg --quick-generate-key");
    if !kg.status.success() {
        eprintln!(
            "SKIP: gpg --quick-generate-key failed:\n{}",
            String::from_utf8_lossy(&kg.stderr)
        );
        return;
    }

    // 2. Fingerprint + the keygrip gpg itself computed. Comparing the latter
    //    against ours is the single most useful assertion here: if they differ,
    //    gpg will never route a signature request to us at all.
    let lk = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args(["--with-colons", "--with-keygrip", "--list-secret-keys"])
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
    let gpg_keygrip = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("grp:::::::::"))
        .filter_map(|s| s.split(':').next())
        .next()
        .expect("find keygrip")
        .to_ascii_lowercase();

    // 3. Export and stash in a vault, as a user would.
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
        "export failed: {}",
        String::from_utf8_lossy(&ex.stderr)
    );
    let secret_bytes = std::fs::read(&secret_path).expect("read export");

    let password = "rsa-itest-pw";
    {
        let mut vault = Vault::create(&vault_path, password).expect("create vault");
        let id = vault.add_entry("gpg-rsa").expect("add entry");
        vault
            .attach_binary(&id, "gpg-priv", &secret_bytes)
            .expect("attach");
        vault.save().expect("save");
    }

    // 4. Load it the way the daemon does on unlock.
    let vault = Vault::open(&vault_path, password).expect("reopen");
    let keys = load_gpg_keys_from_vault(&vault);
    assert!(
        !keys.is_empty(),
        "an RSA export must yield a usable key — an empty store here means the \
         packet parser skipped algorithm 1 again"
    );
    assert_eq!(
        keys[0].keygrip_hex(),
        gpg_keygrip,
        "our keygrip must match gpg's, or gpg never asks us to sign"
    );
    let store: GpgKeyStore = Arc::new(RwLock::new(keys));

    // 5. Serve it, and point gpg at our socket.
    let store_for_task = store.clone();
    let sock_for_task = sock_path.clone();
    let idle_for_task = noop_idle();
    let _agent = tokio::spawn(async move {
        let _ = gpg_agent::run(sock_for_task, store_for_task, idle_for_task).await;
    });
    // Wait until the socket ACCEPTS, not until the path exists: a Unix socket
    // appears on disk at `bind()`, before `listen()`, and a connect in that gap
    // is refused. Passes either way on a fast machine; fails on a loaded runner.
    for _ in 0..200 {
        if std::os::unix::net::UnixStream::connect(&sock_path).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sock_path.exists(), "agent socket never appeared");

    let agent_link = gnupghome.join("S.gpg-agent");
    let _ = Command::new("gpgconf")
        .env("GNUPGHOME", &gnupghome)
        .args(["--kill", "gpg-agent"])
        .output();
    let _ = std::fs::remove_file(&agent_link);
    std::os::unix::fs::symlink(&sock_path, &agent_link).expect("symlink");

    // Our agent must answer the two questions gpg asks before signing.
    // These are environment-independent, unlike the `git commit -S` step below.
    for (cmd, what) in [
        (format!("HAVEKEY {}", gpg_keygrip.to_uppercase()), "HAVEKEY"),
        (
            format!("KEYINFO --data {}", gpg_keygrip.to_uppercase()),
            "KEYINFO",
        ),
    ] {
        let probe = Command::new("gpg-connect-agent")
            .env("GNUPGHOME", &gnupghome)
            .arg(&cmd)
            .arg("/bye")
            .output()
            .expect("gpg-connect-agent");
        let out = String::from_utf8_lossy(&probe.stdout);
        assert!(
            out.contains("OK") && !out.contains("ERR"),
            "our agent should answer {what} for an RSA keygrip, got: {out}"
        );
        if what == "KEYINFO" {
            // Field 6 is protection status; `C` (clear) is what a real
            // gpg-agent reports for an unprotected key, and what we now send.
            assert!(
                out.contains(" D - - - C - - -"),
                "KEYINFO should report the key as unprotected, got: {out}"
            );
        }
    }

    // 6. Sign a commit for real.
    // A path that does not exist: git treats it as an empty config file.
    let no_git_config = tmp.path().join("no-such-gitconfig");
    std::fs::create_dir(&repo_path).expect("mkdir repo");
    let _ = git_isolated(&repo_path, &no_git_config)
        .args(["init", "-q"])
        .output()
        .expect("git init");
    for (k, v) in [
        ("user.email", "rsa@trove"),
        ("user.name", "trove-rsa-itest"),
        ("commit.gpgsign", "true"),
        // Repo config outranks global, so this survives even if the
        // GIT_CONFIG_* isolation above is ever removed.
        ("gpg.program", "gpg"),
        ("user.signingkey", &fpr),
    ] {
        let _ = git_isolated(&repo_path, &no_git_config)
            .args(["config", k, v])
            .output()
            .expect("git config");
    }

    let commit = git_isolated(&repo_path, &no_git_config)
        .args(["commit", "-S", "--allow-empty", "-m", "trove rsa itest"])
        .env("GNUPGHOME", &gnupghome)
        .output()
        .expect("git commit");
    eprintln!(
        "git commit stderr: {}",
        String::from_utf8_lossy(&commit.stderr)
    );
    assert!(
        commit.status.success(),
        "git commit -S should succeed against our agent with an RSA key: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    // 7. And the signature must actually verify.
    let log = git_isolated(&repo_path, &no_git_config)
        .args(["log", "--show-signature", "-1"])
        .env("GNUPGHOME", &gnupghome)
        .output()
        .expect("git log");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&log.stdout),
        String::from_utf8_lossy(&log.stderr)
    );
    assert!(
        combined.contains("Good signature"),
        "expected a good signature, got:\n{combined}"
    );
}
