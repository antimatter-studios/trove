//! `public_key_export` against real gpg: a key generated in one isolated
//! `GNUPGHOME`, exported as a secret key, cut down to its public part, and
//! imported into a second, empty `GNUPGHOME` must show up there as a public
//! key only, with the same fingerprint and user ID. That is what lets gpg ask
//! trove's agent to sign with a key that lives only in the vault.
//!
//! Skips when `gpg` is not on PATH. Unix-only (gpg-agent sockets in a temp
//! GNUPGHOME).

#![allow(missing_docs)]
#![cfg(unix)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use troved::gpg_agent::keys::public_key_export;

fn have_gpg() -> bool {
    Command::new("gpg")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn gpg(home: &Path, args: &[&str], stdin: Option<&[u8]>) -> std::process::Output {
    let mut child = Command::new("gpg")
        .env("GNUPGHOME", home)
        .args(["--batch", "--no-tty"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gpg");
    let mut pipe = child.stdin.take().expect("stdin");
    if let Some(bytes) = stdin {
        pipe.write_all(bytes).expect("write gpg stdin");
    }
    drop(pipe);
    let out = child.wait_with_output().expect("wait gpg");
    assert!(
        out.status.success(),
        "gpg {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// `fpr` and `uid` records from `--with-colons` output.
fn fingerprints_and_uids(listing: &[u8]) -> (Vec<String>, Vec<String>) {
    let text = String::from_utf8_lossy(listing);
    let field = |kind: &str, n: usize| {
        text.lines()
            .filter(|l| l.starts_with(kind))
            .map(|l| l.split(':').nth(n).unwrap_or("").to_string())
            .collect::<Vec<_>>()
    };
    (field("fpr:", 9), field("uid:", 9))
}

fn kill_agent(home: &Path) {
    let _ = Command::new("gpgconf")
        .env("GNUPGHOME", home)
        .args(["--kill", "gpg-agent"])
        .status();
}

#[test]
fn derived_public_export_imports_into_a_fresh_keyring() {
    if !have_gpg() {
        eprintln!("SKIP: gpg not on PATH");
        return;
    }
    // Short paths: gpg-agent's socket path must fit in sun_path.
    let a = tempfile::Builder::new()
        .prefix("tg")
        .tempdir_in("/tmp")
        .unwrap();
    let b = tempfile::Builder::new()
        .prefix("tg")
        .tempdir_in("/tmp")
        .unwrap();
    for d in [a.path(), b.path()] {
        std::fs::set_permissions(d, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    }

    gpg(
        a.path(),
        &[
            "--passphrase",
            "",
            "--quick-generate-key",
            "Trove Test <trove@example.invalid>",
            "ed25519",
            "sign",
            "never",
        ],
        None,
    );
    let listing = gpg(a.path(), &["--with-colons", "--list-keys"], None);
    let fpr = fingerprints_and_uids(&listing.stdout).0[0].clone();
    gpg(
        a.path(),
        &[
            "--passphrase",
            "",
            "--quick-add-key",
            &fpr,
            "cv25519",
            "encr",
            "never",
        ],
        None,
    );
    let secret = gpg(
        a.path(),
        &[
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--export-secret-keys",
        ],
        None,
    )
    .stdout;
    let expected =
        fingerprints_and_uids(&gpg(a.path(), &["--with-colons", "--list-keys"], None).stdout);

    let public = public_key_export(&secret).expect("derive public export");
    gpg(b.path(), &["--import"], Some(&public));

    let got = fingerprints_and_uids(&gpg(b.path(), &["--with-colons", "--list-keys"], None).stdout);
    assert_eq!(got, expected, "same primary, subkey and user ID");
    assert_eq!(expected.0.len(), 2, "primary and subkey: {expected:?}");
    let secrets = gpg(b.path(), &["--with-colons", "--list-secret-keys"], None);
    assert!(
        secrets.stdout.is_empty(),
        "no secret key may reach the keyring: {}",
        String::from_utf8_lossy(&secrets.stdout)
    );

    kill_agent(a.path());
    kill_agent(b.path());
}
