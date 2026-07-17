#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! Vault-ops interop against the `keepassxc-cli` oracle:
//!   1. Merge equivalence — trove and keepassxc merge the SAME diverged pair;
//!      both results contain the same entry set.
//!   2. `db-edit` rekey — keepassxc opens the vault with the new credentials
//!      (and refuses the old ones).
//!   3. `export --format xml` — keepassxc IMPORTS trove's XML and reads the
//!      secrets back.
//!   4. CSV header parity with `keepassxc-cli export -f csv`.

mod matrix;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use matrix::{keepassxc_party, trove_party};

const PW: &str = "interop-vault-ops-pw";

fn run(bin: &Path, args: &[&str], stdin_lines: &str) -> (bool, String, String) {
    let mut child = Command::new(bin)
        .args(args)
        .env_remove("TROVE_SESSION")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", bin.display()));
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin_lines.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn run_ok(bin: &Path, args: &[&str], stdin_lines: &str) -> String {
    let (ok, stdout, stderr) = run(bin, args, stdin_lines);
    assert!(
        ok,
        "{} {:?} failed\nstdout: {stdout}\nstderr: {stderr}",
        bin.display(),
        args
    );
    stdout
}

fn trove_bin() -> std::path::PathBuf {
    trove_party::locate()
        .expect("trove binary not built (never skip interop)")
        .path
}

fn oracles() -> Vec<keepassxc_party::Oracle> {
    let oracles = keepassxc_party::discover();
    assert!(
        !oracles.is_empty(),
        "no keepassxc-cli found — must not skip."
    );
    oracles
}

fn seed(trove: &Path, vault: &str, entry: &str, secret: &str) {
    run_ok(
        trove,
        &["--vault", vault, "--password-stdin", "init"],
        &format!("{PW}\n"),
    );
    run_ok(
        trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "add",
            "password",
            entry,
            "--secret-stdin",
        ],
        &format!("{PW}\n{secret}\n"),
    );
}

fn add(trove: &Path, vault: &str, entry: &str, secret: &str) {
    run_ok(
        trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "add",
            "password",
            entry,
            "--secret-stdin",
        ],
        &format!("{PW}\n{secret}\n"),
    );
}

/// Both tools merge the same diverged pair; entry sets must match.
#[test]
fn merge_matches_keepassxc() {
    let trove = trove_bin();
    for oracle in oracles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("base.kdbx");
        let bases = base.to_str().unwrap();
        let fork = dir.path().join("fork.kdbx");
        let forks = fork.to_str().unwrap();

        seed(&trove, bases, "shared", "orig");
        std::fs::copy(&base, &fork).unwrap();
        add(&trove, bases, "only-base", "a");
        add(&trove, forks, "only-fork", "b");

        // trove merges fork→copy1; keepassxc merges fork→copy2.
        let trove_merged = dir.path().join("trove-merged.kdbx");
        std::fs::copy(&base, &trove_merged).unwrap();
        let tms = trove_merged.to_str().unwrap();
        run_ok(
            &trove,
            &["--vault", tms, "--password-stdin", "merge", forks],
            &format!("{PW}\n{PW}\n"),
        );

        let kpxc_merged = dir.path().join("kpxc-merged.kdbx");
        std::fs::copy(&base, &kpxc_merged).unwrap();
        let kms = kpxc_merged.to_str().unwrap();
        // `merge -s`: same credentials for both databases; password on stdin.
        run_ok(
            &oracle.path,
            &["merge", "-q", "-s", kms, forks],
            &format!("{PW}\n"),
        );

        // Same entry titles visible to keepassxc in both results.
        let titles = |db: &str| -> Vec<String> {
            let mut t: Vec<String> = run_ok(
                &oracle.path,
                &["ls", "-q", "-R", "-f", db],
                &format!("{PW}\n"),
            )
            .lines()
            .map(|l| l.trim().trim_end_matches('/').to_string())
            .filter(|l| !l.is_empty() && !l.ends_with(':') && *l != "[empty]")
            .collect();
            t.sort();
            t.dedup();
            t
        };
        assert_eq!(
            titles(tms),
            titles(kms),
            "trove-merged and keepassxc-merged vaults must agree"
        );
    }
}

/// trove rekeys; keepassxc opens with the new pair and refuses the old.
#[test]
fn rekey_recognized_by_keepassxc() {
    let trove = trove_bin();
    let dir = tempfile::tempdir().expect("tempdir");
    let v = dir.path().join("rk.kdbx");
    let vs = v.to_str().unwrap();
    seed(&trove, vs, "survivor", "sekrit");

    let kf = dir.path().join("new-key.bin");
    std::fs::write(&kf, (10u8..42).collect::<Vec<u8>>()).unwrap();
    let kfs = kf.to_str().unwrap();

    run_ok(
        &trove,
        &[
            "--vault",
            vs,
            "--password-stdin",
            "db-edit",
            "--set-password",
            "--set-key-file",
            kfs,
        ],
        &format!("{PW}\nbrand-new-pw\n"),
    );

    for oracle in oracles() {
        // New composite pair works…
        let out = run_ok(
            &oracle.path,
            &[
                "show", "-q", "-s", "-k", kfs, vs, "survivor", "-a", "Password",
            ],
            "brand-new-pw\n",
        );
        assert_eq!(out.trim_end(), "sekrit");
        // …old password alone is refused.
        let (ok, _, _) = run(&oracle.path, &["ls", "-q", vs], &format!("{PW}\n"));
        assert!(!ok, "old credentials must be dead");
    }
}

/// keepassxc imports trove's exported XML and reads the secret back.
#[test]
fn exported_xml_reimports_in_keepassxc() {
    let trove = trove_bin();
    let dir = tempfile::tempdir().expect("tempdir");
    let v = dir.path().join("x.kdbx");
    let vs = v.to_str().unwrap();
    seed(&trove, vs, "roundtrip", "xml-secret");

    let xml = run_ok(
        &trove,
        &["--vault", vs, "--password-stdin", "export"],
        &format!("{PW}\n"),
    );
    let xml_path = dir.path().join("export.xml");
    std::fs::write(&xml_path, xml.as_bytes()).unwrap();

    for oracle in oracles() {
        let imported = dir.path().join("imported.kdbx");
        // `import -p`: password prompted twice for the NEW database.
        run_ok(
            &oracle.path,
            &[
                "import",
                "-q",
                "-p",
                xml_path.to_str().unwrap(),
                imported.to_str().unwrap(),
            ],
            &format!("{PW}\n{PW}\n"),
        );
        let out = run_ok(
            &oracle.path,
            &[
                "show",
                "-q",
                "-s",
                imported.to_str().unwrap(),
                "roundtrip",
                "-a",
                "Password",
            ],
            &format!("{PW}\n"),
        );
        assert_eq!(out.trim_end(), "xml-secret");
        let _ = std::fs::remove_file(&imported);
    }
}

/// trove's CSV header matches keepassxc's own `export -f csv`.
#[test]
fn csv_header_matches_keepassxc() {
    let trove = trove_bin();
    let dir = tempfile::tempdir().expect("tempdir");
    let v = dir.path().join("c.kdbx");
    let vs = v.to_str().unwrap();
    seed(&trove, vs, "csv-entry", "csv-secret");

    let ours = run_ok(
        &trove,
        &[
            "--vault",
            vs,
            "--password-stdin",
            "export",
            "--format",
            "csv",
        ],
        &format!("{PW}\n"),
    );
    for oracle in oracles() {
        let theirs = run_ok(
            &oracle.path,
            &["export", "-q", "-f", "csv", vs],
            &format!("{PW}\n"),
        );
        assert_eq!(
            ours.lines().next().unwrap(),
            theirs.lines().next().unwrap(),
            "CSV headers must be identical"
        );
    }
}
