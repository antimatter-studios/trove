//! End-to-end checks for user-defined metadata search.

#![allow(missing_docs)]

use std::io::Write;
use std::process::{Command, Stdio};

use tempfile::TempDir;
use trove_core::Vault;

const VAULT_PASSWORD: &str = "search-metadata-test-password";

fn run(vault: &str, tail: &[&str]) -> std::process::Output {
    let mut args = vec![
        "--vault".to_string(),
        vault.to_string(),
        "--password-stdin".to_string(),
    ];
    args.extend(tail.iter().map(|s| (*s).to_string()));
    let mut child = Command::new(env!("CARGO_BIN_EXE_trove"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trove");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{VAULT_PASSWORD}\n").as_bytes())
        .unwrap();
    child.wait_with_output().expect("wait for trove")
}

#[test]
fn search_filters_are_generic_combinable_and_report_match_reasons() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.kdbx");
    let mut vault = Vault::create(&path, VAULT_PASSWORD).unwrap();
    vault.add_group("Build").unwrap();
    vault.set_group_tags("Build", &["release".into()]).unwrap();
    let id = vault.add_entry("Build/signing").unwrap();
    vault.set_field(&id, "Password", "entry-secret").unwrap();
    vault
        .set_field(&id, "Automation.Target", "MACOS_CERTIFICATE")
        .unwrap();
    vault
        .attach_binary(&id, "developer_id.p12", &[0, 1, 2, 250, 255])
        .unwrap();
    vault.save().unwrap();
    let path = path.display().to_string();

    let output = run(
        &path,
        &[
            "search",
            "--field",
            "Automation.Target=MACOS_CERTIFICATE",
            "--tag",
            "RELEASE",
            "--attachment",
            "*.p12",
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let hits = json.as_array().unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["path"], "Build/signing");
    let matched = hits[0]["matched"].as_array().unwrap();
    assert!(matched.iter().any(|v| v == "field Automation.Target"));
    assert!(matched.iter().any(|v| v == "tag release"));
    assert!(matched.iter().any(|v| v == "attachment developer_id.p12"));

    let output = run(&path, &["search", "MACOS_CERTIFICATE", "--json"]);
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 1);

    let output = run(&path, &["search", "entry-secret", "--json"]);
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        json.as_array().unwrap().is_empty(),
        "protected value was searchable"
    );
}
