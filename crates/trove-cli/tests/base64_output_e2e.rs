//! End-to-end checks for base64 output of stored values.

#![allow(missing_docs)]

use std::io::Write;
use std::process::{Command, Stdio};

use tempfile::TempDir;
use trove_core::Vault;

const VAULT_PASSWORD: &str = "base64-output-test-password";

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
fn base64_encodes_password_file_attribute_and_resolved_values_without_pipe_newlines() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.kdbx");
    let mut vault = Vault::create(&path, VAULT_PASSWORD).unwrap();
    let id = vault.add_entry("Build/signing").unwrap();
    vault.set_field(&id, "Password", "entry-secret").unwrap();
    vault
        .set_field(&id, "Automation.Target", "MACOS_CERTIFICATE")
        .unwrap();
    vault.set_field(&id, "UserName", "notary-key-id").unwrap();
    vault
        .attach_binary(&id, "developer_id.p12", &[0, 1, 2, 250, 255])
        .unwrap();
    vault.save().unwrap();
    let vault = path.display().to_string();

    for (args, expected) in [
        (
            vec!["get", "password", "Build/signing", "--base64"],
            b"ZW50cnktc2VjcmV0".to_vec(),
        ),
        (
            vec![
                "get",
                "file",
                "Build/signing",
                "--name",
                "developer_id.p12",
                "--base64",
            ],
            b"AAEC+v8=".to_vec(),
        ),
        (
            vec![
                "show",
                "Build/signing",
                "--attr",
                "Automation.Target",
                "--base64",
            ],
            b"TUFDT1NfQ0VSVElGSUNBVEU=".to_vec(),
        ),
        (
            vec!["resolve", "trove://Build/signing/UserName", "--base64"],
            b"bm90YXJ5LWtleS1pZA==".to_vec(),
        ),
    ] {
        let output = run(&vault, &args);
        assert!(
            output.status.success(),
            "args={args:?}, stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, expected, "args={args:?}");
    }

    let out_path = dir.path().join("encoded-file");
    let out_path_string = out_path.display().to_string();
    let output = run(
        &vault,
        &[
            "get",
            "file",
            "Build/signing",
            "--name",
            "developer_id.p12",
            "--base64",
            "--out",
            &out_path_string,
        ],
    );
    assert!(output.status.success());
    assert_eq!(std::fs::read(&out_path).unwrap(), b"AAEC+v8=");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
