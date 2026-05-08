//! End-to-end SSH agent tests using the real `ssh-keygen` and `ssh-add`
//! binaries shipped with macOS / OpenSSH.
//!
//! For each supported algorithm (ed25519, RSA-3072, ECDSA-P256, ECDSA-P384)
//! we:
//!   1. Generate a fresh keypair via `ssh-keygen -t … -N ''`.
//!   2. Compute the expected SHA256 fingerprint via `ssh-keygen -lf <pub>`.
//!   3. Stash the private key in a real .kdbx vault under attachment "id".
//!   4. Open the vault, populate the in-memory key store, and start the
//!      SSH agent listener on a temp socket.
//!   5. Run `SSH_AUTH_SOCK=<socket> ssh-add -l` and assert the fingerprint
//!      and comment line up.
//!   6. Run `SSH_AUTH_SOCK=<socket> ssh-add -L` and assert the public-key
//!      blob byte-matches `algo + base64` from the on-disk pubkey.
//!
//! If `ssh-keygen` or `ssh-add` aren't on $PATH, we print a skip message and
//! pass.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use sdpm_core::Vault;
use sdpmd::handler::load_ssh_keys_from_vault;
use sdpmd::ssh_agent::{self, KeyStore};
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
async fn ssh_add_lists_and_dumps_vault_ed25519_key() {
    if !have_tool("ssh-keygen") || !have_tool("ssh-add") {
        eprintln!("SKIP: ssh-keygen/ssh-add not on $PATH");
        return;
    }
    run_e2e_for(
        &["-t", "ed25519"],
        "ssh-ed25519",
        "(ED25519)",
        "test@sdpm-ed25519",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_add_lists_and_dumps_vault_rsa_3072_key() {
    if !have_tool("ssh-keygen") || !have_tool("ssh-add") {
        eprintln!("SKIP: ssh-keygen/ssh-add not on $PATH");
        return;
    }
    run_e2e_for(
        &["-t", "rsa", "-b", "3072"],
        "ssh-rsa",
        "(RSA)",
        "test@sdpm-rsa",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_add_lists_and_dumps_vault_ecdsa_p256_key() {
    if !have_tool("ssh-keygen") || !have_tool("ssh-add") {
        eprintln!("SKIP: ssh-keygen/ssh-add not on $PATH");
        return;
    }
    run_e2e_for(
        &["-t", "ecdsa", "-b", "256"],
        "ecdsa-sha2-nistp256",
        "(ECDSA)",
        "test@sdpm-p256",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_add_lists_and_dumps_vault_ecdsa_p384_key() {
    if !have_tool("ssh-keygen") || !have_tool("ssh-add") {
        eprintln!("SKIP: ssh-keygen/ssh-add not on $PATH");
        return;
    }
    run_e2e_for(
        &["-t", "ecdsa", "-b", "384"],
        "ecdsa-sha2-nistp384",
        "(ECDSA)",
        "test@sdpm-p384",
    )
    .await;
}

/// Drive the full vault → agent → ssh-add round-trip for a single key type.
///
/// `keygen_args` is the prefix passed to `ssh-keygen` (e.g. `["-t","rsa","-b","3072"]`);
/// `expected_pubkey_prefix` is the algorithm token we expect at the start of
/// `ssh-add -L` (e.g. `ssh-rsa`, `ecdsa-sha2-nistp256`); `expected_kind_token`
/// is the parenthetical algorithm marker `ssh-add -l` prints in the trailer
/// (e.g. `(RSA)`, `(ECDSA)`); `comment` is the comment we attach to the key
/// and expect to see echoed.
async fn run_e2e_for(
    keygen_args: &[&str],
    expected_pubkey_prefix: &str,
    expected_kind_token: &str,
    comment: &str,
) {
    let tmp = TempDir::new().expect("tempdir");
    let key_path = tmp.path().join("k");
    let pub_path = tmp.path().join("k.pub");
    let vault_path = tmp.path().join("vault.kdbx");
    let sock_path = tmp.path().join("agent.sock");

    // 1. Generate a real keypair on disk.
    let mut keygen = Command::new("ssh-keygen");
    keygen.args(keygen_args).args(["-N", "", "-C", comment, "-f"]).arg(&key_path);
    let kg = keygen.output().expect("spawn ssh-keygen");
    assert!(
        kg.status.success(),
        "ssh-keygen {:?} failed: {}",
        keygen_args,
        String::from_utf8_lossy(&kg.stderr)
    );

    // 2. Capture the expected fingerprint line.
    let fp_out = Command::new("ssh-keygen")
        .args(["-lf"])
        .arg(&pub_path)
        .output()
        .expect("spawn ssh-keygen -lf");
    assert!(fp_out.status.success(), "ssh-keygen -lf failed");
    let expected_line = String::from_utf8_lossy(&fp_out.stdout).trim().to_string();
    let expected_sha = expected_line
        .split_whitespace()
        .find(|tok| tok.starts_with("SHA256:"))
        .expect("SHA256 token in fingerprint output")
        .to_string();
    eprintln!("expected fingerprint line ({comment}): {expected_line}");

    let pubkey_text = std::fs::read_to_string(&pub_path).expect("read pub");

    // 3. Stash the private key into a real vault under attachment "id".
    let key_bytes = std::fs::read(&key_path).expect("read priv");
    let password = "test-password";
    {
        let mut vault = Vault::create(&vault_path, password).expect("create vault");
        let id = vault.add_entry(comment).expect("add entry");
        vault
            .attach_binary(&id, "id", &key_bytes)
            .expect("attach id");
        vault.save().expect("save vault");
    }

    // 4a. Reopen vault, pull keys out, populate the key store.
    let vault = Vault::open(&vault_path, password).expect("reopen vault");
    let keys = load_ssh_keys_from_vault(&vault);
    assert_eq!(keys.len(), 1, "exactly one key should load for {comment}");
    let store: KeyStore = Arc::new(RwLock::new(keys));

    // 4b. Start the SSH agent listener on a temp socket.
    let sock_for_task = sock_path.clone();
    let store_for_task = store.clone();
    let listener_handle = tokio::spawn(async move {
        let _ = ssh_agent::run(sock_for_task, store_for_task).await;
    });

    for _ in 0..100 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sock_path.exists(), "agent socket never appeared");

    // 5. ssh-add -l → fingerprint listing.
    let list = ssh_add(&sock_path, &["-l"]);
    eprintln!("ssh-add -l stdout ({comment}):\n{}", list.stdout);
    eprintln!("ssh-add -l stderr ({comment}):\n{}", list.stderr);
    assert!(
        list.success,
        "ssh-add -l should succeed against our agent for {comment}"
    );
    assert!(
        list.stdout.contains(&expected_sha),
        "ssh-add -l output should contain expected fingerprint {expected_sha}\nactual:\n{}",
        list.stdout
    );
    assert!(
        list.stdout.contains(comment),
        "ssh-add -l output should contain the comment '{comment}'\nactual:\n{}",
        list.stdout
    );
    assert!(
        list.stdout.contains(expected_kind_token),
        "ssh-add -l output should contain the kind token '{expected_kind_token}'\nactual:\n{}",
        list.stdout
    );

    // 6. ssh-add -L → public-key lines.
    let dump = ssh_add(&sock_path, &["-L"]);
    eprintln!("ssh-add -L stdout ({comment}):\n{}", dump.stdout);
    eprintln!("ssh-add -L stderr ({comment}):\n{}", dump.stderr);
    assert!(
        dump.success,
        "ssh-add -L should succeed against our agent for {comment}"
    );
    let dump_first = dump.stdout.lines().next().unwrap_or("");
    assert!(
        dump_first.starts_with(&format!("{expected_pubkey_prefix} AAAA")),
        "ssh-add -L first line should start with '{expected_pubkey_prefix} AAAA…': got {dump_first:?}"
    );
    let our_blob = dump_first
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let disk_blob = pubkey_text
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(
        our_blob, disk_blob,
        "public key returned by agent must match the one ssh-keygen produced for {comment}"
    );

    listener_handle.abort();
}

struct CmdResult {
    success: bool,
    stdout: String,
    stderr: String,
}

fn ssh_add(sock: &Path, args: &[&str]) -> CmdResult {
    let out = Command::new("ssh-add")
        .args(args)
        .env("SSH_AUTH_SOCK", PathBuf::from(sock))
        // Defensive: clear any inherited agent state that could confuse things.
        .env_remove("SSH_AGENT_PID")
        .output()
        .expect("spawn ssh-add");
    CmdResult {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}
