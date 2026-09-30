//! `trove gpg-agent import`, offline: a vault holding a real GPG secret-key
//! export, and an empty `GNUPGHOME`. After the import that keyring must hold
//! the key's public half (same fingerprints) and no secret key; `--print`
//! writes the same public keys to stdout.
//!
//! Skips when the `trove` binary or `gpg` is missing. Unix-only.

#![allow(missing_docs)]
#![cfg(unix)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use trove_core::Vault;

const PASSWORD: &str = "gpg-import-test-pw";

fn find_trove() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_trove")?);
    p.exists().then_some(p)
}

fn have_gpg() -> bool {
    Command::new("gpg")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn gpg(home: &Path, args: &[&str]) -> Output {
    let out = Command::new("gpg")
        .env("GNUPGHOME", home)
        .args(["--batch", "--no-tty"])
        .args(args)
        .output()
        .expect("spawn gpg");
    assert!(
        out.status.success(),
        "gpg {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn fingerprints(home: &Path) -> Vec<String> {
    let out = gpg(home, &["--with-colons", "--list-keys"]);
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with("fpr:"))
        .map(|l| l.split(':').nth(9).unwrap_or("").to_string())
        .collect()
}

fn trove(bin: &Path, home: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(bin)
        .env("GNUPGHOME", home)
        .env_remove("TROVE_SESSION")
        .env_remove("TROVE_VAULT")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trove");
    let _ = child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{PASSWORD}\n").as_bytes());
    child.wait_with_output().expect("wait trove")
}

fn gnupg_home() -> tempfile::TempDir {
    // Short path: gpg-agent's socket must fit in sun_path.
    let d = tempfile::Builder::new()
        .prefix("tg")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::set_permissions(
        d.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    d
}

fn kill_agent(home: &Path) {
    let _ = Command::new("gpgconf")
        .env("GNUPGHOME", home)
        .args(["--kill", "gpg-agent"])
        .status();
}

#[test]
fn gpg_agent_import_puts_only_public_keys_in_the_keyring() {
    let Some(bin) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    if !have_gpg() {
        eprintln!("skipping: gpg not on PATH");
        return;
    }
    let source = gnupg_home();
    let target = gnupg_home();
    gpg(
        source.path(),
        &[
            "--passphrase",
            "",
            "--quick-generate-key",
            "Trove Import <import@example.invalid>",
            "ed25519",
            "sign",
            "never",
        ],
    );
    let secret = gpg(
        source.path(),
        &[
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--export-secret-keys",
        ],
    )
    .stdout;
    let expected = fingerprints(source.path());

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("v.kdbx");
    let mut v = Vault::create(&vault, PASSWORD).unwrap();
    let id = v.add_entry("Signing/work").unwrap();
    v.attach_binary(&id, "gpg-priv", &secret).unwrap();
    v.save().unwrap();
    let vault = vault.to_str().unwrap();

    let out = trove(
        &bin,
        target.path(),
        &["--vault", vault, "--password-stdin", "gpg-agent", "import"],
    );
    assert!(
        out.status.success(),
        "import: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("Signing/work"));
    assert_eq!(fingerprints(target.path()), expected);
    let secrets = gpg(target.path(), &["--with-colons", "--list-secret-keys"]);
    assert!(secrets.stdout.is_empty(), "no secret key may be imported");

    // Again: nothing changes, and it still succeeds.
    let out = trove(
        &bin,
        target.path(),
        &["--vault", vault, "--password-stdin", "gpg-agent", "import"],
    );
    assert!(out.status.success());
    assert_eq!(fingerprints(target.path()), expected);

    let out = trove(
        &bin,
        target.path(),
        &[
            "--vault",
            vault,
            "--password-stdin",
            "gpg-agent",
            "import",
            "--print",
        ],
    );
    assert!(out.status.success());
    assert_eq!(
        out.stdout.first().map(|b| b & 0x3F),
        Some(6),
        "a public-key packet first"
    );

    kill_agent(source.path());
    kill_agent(target.path());
}
