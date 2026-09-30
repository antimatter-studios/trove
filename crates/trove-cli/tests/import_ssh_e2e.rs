//! `trove import-ssh` against a throwaway `.ssh`-like directory of real keys,
//! offline (`--vault`, `--password-stdin`, `--yes`). Proves the usable keys
//! land as entries with their `.pub` comment, the unusable ones are reported
//! and left out, a second run doesn't overwrite, `--dry-run` changes nothing,
//! and the key files are left as they were.
//!
//! Skips gracefully when the `trove` binary or `ssh-keygen` is missing.

#![allow(missing_docs)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use trove_core::Vault;

const PASSWORD: &str = "import-ssh-test-pw";

fn find_trove() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_trove")?);
    p.exists().then_some(p)
}

fn have_ssh_keygen() -> bool {
    Command::new("ssh-keygen")
        .arg("-?")
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .is_ok()
}

fn run_trove(trove: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(trove)
        .args(args)
        .env_remove("TROVE_SESSION")
        .env_remove("TROVE_VAULT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trove");
    let _ = child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(stdin.as_bytes());
    child.wait_with_output().expect("wait trove")
}

fn keygen(dir: &Path, name: &str, args: &[&str]) {
    let out = Command::new("ssh-keygen")
        .args(["-q", "-f"])
        .arg(dir.join(name))
        .args(args)
        .output()
        .expect("spawn ssh-keygen");
    assert!(
        out.status.success(),
        "ssh-keygen {name}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn text(out: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn import_ssh_stores_usable_keys_and_reports_the_rest() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    if !have_ssh_keygen() {
        eprintln!("skipping: ssh-keygen not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let keys = tmp.path().join("dot-ssh");
    std::fs::create_dir(&keys).unwrap();
    keygen(
        &keys,
        "id_ed25519",
        &["-t", "ed25519", "-N", "", "-C", "me@laptop"],
    );
    keygen(
        &keys,
        "locked",
        &["-t", "ed25519", "-N", "secret", "-C", "locked"],
    );
    keygen(
        &keys,
        "weak",
        &["-t", "rsa", "-b", "1024", "-N", "", "-C", "weak"],
    );
    std::fs::write(keys.join("known_hosts"), "github.com ssh-ed25519 AAAA\n").unwrap();
    let before = std::fs::read(keys.join("id_ed25519")).unwrap();

    let vault = tmp.path().join("v.kdbx");
    Vault::create(&vault, PASSWORD).expect("create vault");
    let v = vault.to_str().unwrap();
    let k = keys.to_str().unwrap();
    let stdin = format!("{PASSWORD}\n");

    // A dry run lists and changes nothing.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            v,
            "--password-stdin",
            "import-ssh",
            k,
            "--dry-run",
        ],
        &stdin,
    );
    assert!(out.status.success(), "{}", text(&out));
    let listing = text(&out);
    assert!(
        listing.contains("would import") && listing.contains("ssh/id_ed25519"),
        "{listing}"
    );
    assert!(
        listing.contains("locked") && listing.contains("passphrase"),
        "{listing}"
    );
    assert!(
        listing.contains("weak") && listing.contains("2048"),
        "{listing}"
    );
    assert!(!listing.contains("known_hosts"), "{listing}");
    let opened = Vault::open(&vault, PASSWORD).unwrap();
    assert!(
        opened.list_entries().is_empty(),
        "dry run wrote to the vault"
    );

    // Without --yes and no terminal, it refuses rather than guessing.
    let out = run_trove(
        &trove,
        &["--vault", v, "--password-stdin", "import-ssh", k],
        &stdin,
    );
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("--yes"), "{}", text(&out));

    let out = run_trove(
        &trove,
        &["--vault", v, "--password-stdin", "import-ssh", k, "--yes"],
        &stdin,
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("imported"), "{}", text(&out));

    let opened = Vault::open(&vault, PASSWORD).unwrap();
    let paths: Vec<String> = opened
        .list_entries()
        .iter()
        .map(|e| e.display_path())
        .collect();
    assert_eq!(paths, ["ssh/id_ed25519"]);
    let id = opened.find_by_title("ssh/id_ed25519").unwrap();
    let pub_line = opened.read_binary(&id, "id.pub").unwrap().unwrap();
    assert!(
        String::from_utf8_lossy(&pub_line)
            .trim_end()
            .ends_with("me@laptop"),
        "comment comes from the .pub: {}",
        String::from_utf8_lossy(&pub_line)
    );
    assert_eq!(opened.read_binary(&id, "id").unwrap().unwrap(), before);

    // A second run leaves the existing entry alone.
    let out = run_trove(
        &trove,
        &["--vault", v, "--password-stdin", "import-ssh", k, "--yes"],
        &stdin,
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("already exists"), "{}", text(&out));

    // The originals are untouched.
    assert_eq!(std::fs::read(keys.join("id_ed25519")).unwrap(), before);
    assert!(keys.join("locked").exists() && keys.join("weak").exists());
}
