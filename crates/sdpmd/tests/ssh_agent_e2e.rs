//! End-to-end SSH agent test using the real `ssh-keygen` and `ssh-add`
//! binaries shipped with macOS / OpenSSH.
//!
//! What we do:
//!   1. Generate a fresh ed25519 keypair via `ssh-keygen -t ed25519 -N ''`.
//!   2. Compute the expected SHA256 fingerprint via `ssh-keygen -lf <pub>`.
//!   3. Stash the private key in a real .kdbx vault under attachment "id".
//!   4. Open the vault, populate the in-memory key store, and start the
//!      SSH agent listener on a temp socket.
//!   5. Run `SSH_AUTH_SOCK=<socket> ssh-add -l` and assert the fingerprint
//!      and comment line up.
//!   6. Run `SSH_AUTH_SOCK=<socket> ssh-add -L` and assert the public-key
//!      line starts with `ssh-ed25519 AAAA…`.
//!
//! If `ssh-keygen` or `ssh-add` aren't on $PATH, we print a skip message and
//! pass — per the v0.0.2.0 spec.

use std::path::PathBuf;
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

    let tmp = TempDir::new().expect("tempdir");
    let key_path = tmp.path().join("k");
    let pub_path = tmp.path().join("k.pub");
    let vault_path = tmp.path().join("vault.kdbx");
    let sock_path = tmp.path().join("agent.sock");

    // 1. Generate a real ed25519 keypair on disk.
    let kg = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "test@sdpm",
            "-f",
        ])
        .arg(&key_path)
        .output()
        .expect("spawn ssh-keygen");
    assert!(
        kg.status.success(),
        "ssh-keygen failed: {}",
        String::from_utf8_lossy(&kg.stderr)
    );

    // 2. Capture the expected fingerprint line, e.g.
    //    `256 SHA256:abc... test@sdpm (ED25519)`
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
    eprintln!("expected fingerprint line: {expected_line}");

    // Read pubkey content for later comparison with ssh-add -L.
    let pubkey_text = std::fs::read_to_string(&pub_path).expect("read pub");

    // 3. Stash the private key into a real vault under attachment "id".
    let key_bytes = std::fs::read(&key_path).expect("read priv");
    let password = "test-password";
    {
        let mut vault = Vault::create(&vault_path, password).expect("create vault");
        let id = vault.add_entry("test@sdpm").expect("add entry");
        vault
            .attach_binary(&id, "id", &key_bytes)
            .expect("attach id");
        vault.save().expect("save vault");
    }

    // 4a. Reopen vault, pull keys out, populate the key store.
    let vault = Vault::open(&vault_path, password).expect("reopen vault");
    let keys = load_ssh_keys_from_vault(&vault);
    assert_eq!(keys.len(), 1, "exactly one ed25519 key should load");
    let store: KeyStore = Arc::new(RwLock::new(keys));

    // 4b. Start the SSH agent listener on a temp socket.
    let sock_for_task = sock_path.clone();
    let store_for_task = store.clone();
    let listener_handle = tokio::spawn(async move {
        let _ = ssh_agent::run(sock_for_task, store_for_task).await;
    });

    // Wait briefly for the socket to appear.
    for _ in 0..100 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sock_path.exists(), "agent socket never appeared");

    // 5. ssh-add -l → fingerprint listing.
    let list = ssh_add(&sock_path, &["-l"]);
    eprintln!("ssh-add -l stdout:\n{}", list.stdout);
    eprintln!("ssh-add -l stderr:\n{}", list.stderr);
    assert!(
        list.success,
        "ssh-add -l should succeed against our agent"
    );
    assert!(
        list.stdout.contains(&expected_sha),
        "ssh-add -l output should contain expected fingerprint {expected_sha}\nactual:\n{}",
        list.stdout
    );
    assert!(
        list.stdout.contains("test@sdpm"),
        "ssh-add -l output should contain the comment 'test@sdpm'\nactual:\n{}",
        list.stdout
    );
    assert!(
        list.stdout.contains("(ED25519)"),
        "ssh-add -l output should mark the key as ED25519\nactual:\n{}",
        list.stdout
    );

    // 6. ssh-add -L → public-key lines.
    let dump = ssh_add(&sock_path, &["-L"]);
    eprintln!("ssh-add -L stdout:\n{}", dump.stdout);
    eprintln!("ssh-add -L stderr:\n{}", dump.stderr);
    assert!(dump.success, "ssh-add -L should succeed against our agent");
    let dump_first = dump.stdout.lines().next().unwrap_or("");
    assert!(
        dump_first.starts_with("ssh-ed25519 AAAA"),
        "ssh-add -L first line should start with 'ssh-ed25519 AAAA…': got {dump_first:?}"
    );
    // The public-key field (algo + base64 blob) should match what ssh-keygen
    // wrote to disk — comments may differ.
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
        "public key returned by agent must match the one ssh-keygen produced"
    );

    listener_handle.abort();
}

struct CmdResult {
    success: bool,
    stdout: String,
    stderr: String,
}

fn ssh_add(sock: &PathBuf, args: &[&str]) -> CmdResult {
    let out = Command::new("ssh-add")
        .args(args)
        .env("SSH_AUTH_SOCK", sock)
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
