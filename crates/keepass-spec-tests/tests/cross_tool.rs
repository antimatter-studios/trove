//! Cross-tool reference test: if `keepassxc-cli` is on `PATH`, write a vault
//! and assert it can list entries. Skip-if-missing — this is the only
//! "external tool sees our output" test we have until KeePassXC is
//! installable in CI.

#![forbid(unsafe_code)]

mod common;

use std::io::Write as _;
use std::process::{Command, Stdio};

use common::{config_and_key_for, rich_database, round_trip_combos};

fn keepassxc_cli_present() -> bool {
    Command::new("keepassxc-cli")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn keepassxc_cli_lists_our_vault() {
    if !keepassxc_cli_present() {
        eprintln!("keepassxc-cli not on PATH — skipping");
        return;
    }

    let combos = round_trip_combos();
    let combo = combos
        .iter()
        .find(|c| c.label == "aes256+gz+inner-chacha20+argon2d")
        .expect("baseline combo");
    let (cfg, key) = config_and_key_for(combo);
    let db = rich_database(cfg);
    let bytes = common::save_to_vec(&db, key);

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("fixture.kdbx");
    std::fs::write(&path, &bytes).expect("write vault");

    let mut child = Command::new("keepassxc-cli")
        .arg("ls")
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keepassxc-cli");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"correct horse battery staple\n")
        .expect("write password");
    let out = child.wait_with_output().expect("wait keepassxc-cli");
    if !out.status.success() {
        panic!(
            "keepassxc-cli ls failed: {} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("entry-"),
        "keepassxc-cli output didn't list our entries: {:?}",
        stdout
    );
}
