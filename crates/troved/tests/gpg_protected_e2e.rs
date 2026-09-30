//! Passphrase-protected `gpg --export-secret-keys` output against real gpg:
//! the same key exported with and without a passphrase must load as the same
//! keys (keygrips) once the protected one is decrypted, a wrong passphrase
//! must be caught, and the decrypted export must still be one gpg imports.
//!
//! Skips when `gpg` is not on PATH. Unix-only.

#![allow(missing_docs)]
#![cfg(unix)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use troved::gpg_agent::keys::{parse_gpg_export, ParseError};
use troved::gpg_agent::protect::{decrypt_export, is_protected};

const PASSPHRASE: &str = "correct horse";

fn have_gpg() -> bool {
    Command::new("gpg")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn gpg(home: &Path, args: &[&str], stdin: Option<&[u8]>) -> Vec<u8> {
    let mut child = Command::new("gpg")
        .env("GNUPGHOME", home)
        .args(["--batch", "--no-tty", "--pinentry-mode", "loopback"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gpg");
    let mut pipe = child.stdin.take().unwrap();
    if let Some(b) = stdin {
        pipe.write_all(b).unwrap();
    }
    drop(pipe);
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "gpg {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn home() -> tempfile::TempDir {
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

fn keygrips(export: &[u8]) -> Vec<String> {
    let mut g: Vec<String> = parse_gpg_export(export, "k")
        .unwrap()
        .iter()
        .map(|k| k.keygrip_hex())
        .collect();
    g.sort();
    g
}

fn check(algo: &str, subkey: Option<&str>) {
    let h = home();
    gpg(
        h.path(),
        &[
            "--passphrase",
            PASSPHRASE,
            "--quick-generate-key",
            "P <p@example.invalid>",
            algo,
            "sign",
            "never",
        ],
        None,
    );
    if let Some(sub) = subkey {
        let listing =
            String::from_utf8(gpg(h.path(), &["--with-colons", "--list-keys"], None)).unwrap();
        let fpr = listing
            .lines()
            .find(|l| l.starts_with("fpr:"))
            .and_then(|l| l.split(':').nth(9))
            .unwrap()
            .to_string();
        gpg(
            h.path(),
            &[
                "--passphrase",
                PASSPHRASE,
                "--quick-add-key",
                &fpr,
                sub,
                "encr",
                "never",
            ],
            None,
        );
    }
    let protected = gpg(
        h.path(),
        &["--passphrase", PASSPHRASE, "--export-secret-keys"],
        None,
    );
    assert!(
        is_protected(&protected),
        "{algo}: gpg exported it protected"
    );
    assert!(matches!(
        parse_gpg_export(&protected, "k"),
        Err(ParseError::Encrypted)
    ));

    let decrypted =
        decrypt_export(&protected, PASSPHRASE.as_bytes()).unwrap_or_else(|e| panic!("{algo}: {e}"));
    assert!(!is_protected(&decrypted));
    let got = keygrips(&decrypted);
    assert!(!got.is_empty(), "{algo}: keys load after decryption");

    assert!(matches!(
        decrypt_export(&protected, b"wrong"),
        Err(ParseError::WrongPassphrase)
    ));

    // Stored as-is in a vault (as KeePassXC users keep it), the entry's
    // Password decrypts it at load; without one it is skipped.
    let dir = tempfile::tempdir().unwrap();
    let mut v = trove_core::Vault::create(&dir.path().join("v.kdbx"), "pw").unwrap();
    let with = v.add_entry("with-password").unwrap();
    v.attach_binary(&with, "gpg-priv", &protected).unwrap();
    v.set_field(&with, "Password", PASSPHRASE).unwrap();
    let without = v.add_entry("without-password").unwrap();
    v.attach_binary(&without, "gpg-priv", &protected).unwrap();
    let loaded = troved::handler::load_gpg_keys_from_vault_filtered(&v, None);
    let mut grips: Vec<String> = loaded.iter().map(|k| k.keygrip_hex()).collect();
    grips.sort();
    assert_eq!(grips, got, "{algo}: only the entry with a Password loads");

    // gpg accepts the decrypted export as a secret key with no passphrase.
    let other = home();
    gpg(other.path(), &["--import"], Some(&decrypted));
    let secrets = String::from_utf8(gpg(
        other.path(),
        &["--with-colons", "--list-secret-keys"],
        None,
    ))
    .unwrap();
    assert!(
        secrets.contains("sec:"),
        "{algo}: gpg imports it: {secrets}"
    );

    for d in [h.path(), other.path()] {
        let _ = Command::new("gpgconf")
            .env("GNUPGHOME", d)
            .args(["--kill", "gpg-agent"])
            .status();
    }
}

#[test]
fn protected_ed25519_with_cv25519_subkey() {
    if !have_gpg() {
        eprintln!("SKIP: gpg not on PATH");
        return;
    }
    check("ed25519", Some("cv25519"));
}

#[test]
fn protected_rsa() {
    if !have_gpg() {
        eprintln!("SKIP: gpg not on PATH");
        return;
    }
    check("rsa2048", None);
}
