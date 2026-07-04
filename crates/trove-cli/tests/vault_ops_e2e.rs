//! End-to-end tests for the vault-ops commands: merge (two-secret stdin
//! order), export xml/csv, db-edit (rekey + KDF), db-info.

#![allow(missing_docs)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const PW: &str = "vault-ops-e2e-pw";

fn find_trove() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_trove")?);
    p.exists().then_some(p)
}

fn run_trove(trove: &std::path::Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(trove)
        .args(args)
        .env_remove("TROVE_SESSION")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trove");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait trove")
}

fn ok(out: &Output, what: &str) -> String {
    assert!(
        out.status.success(),
        "{what} should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Build a vault with one password entry via the CLI.
fn seed(trove: &std::path::Path, vault: &str, entry: &str, secret: &str) {
    ok(
        &run_trove(
            trove,
            &["--vault", vault, "--password-stdin", "init"],
            &format!("{PW}\n"),
        ),
        "init",
    );
    ok(
        &run_trove(
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
        ),
        "seed add",
    );
}

#[test]
fn merge_flows_and_errors() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let a = dir.path().join("a.kdbx");
    let a = a.to_str().unwrap();
    let b = dir.path().join("b.kdbx");
    let b = b.to_str().unwrap();

    // Diverged copies of ONE vault — the case KDBX merge exists for.
    seed(&trove, a, "shared", "orig");
    std::fs::copy(a, b).unwrap();
    ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                a,
                "--password-stdin",
                "add",
                "password",
                "in-a",
                "--secret-stdin",
            ],
            &format!("{PW}\nsecret-a\n"),
        ),
        "diverge a",
    );
    ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                b,
                "--password-stdin",
                "add",
                "password",
                "in-b",
                "--secret-stdin",
            ],
            &format!("{PW}\nsecret-b\n"),
        ),
        "diverge b",
    );

    // Merge b into a: target pw line 1, source pw line 2.
    let out = ok(
        &run_trove(
            &trove,
            &["--vault", a, "--password-stdin", "merge", b],
            &format!("{PW}\n{PW}\n"),
        ),
        "merge",
    );
    assert!(out.contains("created"), "{out}");
    let out = ok(
        &run_trove(
            &trove,
            &["--vault", a, "--password-stdin", "list"],
            &format!("{PW}\n"),
        ),
        "list after merge",
    );
    assert!(
        out.contains("in-a") && out.contains("in-b") && out.contains("shared"),
        "{out}"
    );

    // Wrong source password → vault-error exit (2), target untouched.
    let out = run_trove(
        &trove,
        &["--vault", a, "--password-stdin", "merge", b],
        &format!("{PW}\nwrong-source-pw\n"),
    );
    assert_eq!(out.status.code(), Some(2), "bad source creds");

    // Unrelated vaults refuse cleanly (no panic): different root UUIDs.
    let c = dir.path().join("c.kdbx");
    let c = c.to_str().unwrap();
    seed(&trove, c, "unrelated", "x");
    let out = run_trove(
        &trove,
        &["--vault", a, "--password-stdin", "merge", c],
        &format!("{PW}\n{PW}\n"),
    );
    assert!(!out.status.success(), "unrelated vaults must refuse");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("different root UUID"),
        "clean unrelated-vault error"
    );
}

#[test]
fn export_xml_and_csv_shapes() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let v = dir.path().join("x.kdbx");
    let v = v.to_str().unwrap();
    seed(&trove, v, "Web/exported", "xml-csv-secret");

    let xml = ok(
        &run_trove(
            &trove,
            &["--vault", v, "--password-stdin", "export"],
            &format!("{PW}\n"),
        ),
        "export xml",
    );
    assert!(xml.contains("KeePassFile"), "XML root present");
    assert!(xml.contains("exported"), "entry title in XML");

    let csv = ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                v,
                "--password-stdin",
                "export",
                "--format",
                "csv",
            ],
            &format!("{PW}\n"),
        ),
        "export csv",
    );
    let mut lines = csv.lines();
    assert_eq!(
        lines.next().unwrap(),
        "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"",
        "KeePassXC CSV header"
    );
    let row = lines.next().expect("one data row");
    assert!(
        row.contains("\"Root/Web\"") && row.contains("\"exported\""),
        "{row}"
    );
    assert!(row.contains("xml-csv-secret"), "{row}");
}

#[test]
fn db_edit_rekey_kdf_and_db_info() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let v = dir.path().join("e.kdbx");
    let v = v.to_str().unwrap();
    seed(&trove, v, "survivor", "sekrit");

    // Nothing-to-change is a clean error.
    let out = run_trove(
        &trove,
        &["--vault", v, "--password-stdin", "db-edit"],
        &format!("{PW}\n"),
    );
    assert!(!out.status.success());

    // Rekey: current pw line 1, new pw line 2.
    ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                v,
                "--password-stdin",
                "db-edit",
                "--set-password",
            ],
            &format!("{PW}\nnew-master-pw\n"),
        ),
        "db-edit --set-password",
    );
    // Old password now fails (exit 2); new one lists the surviving entry.
    let out = run_trove(
        &trove,
        &["--vault", v, "--password-stdin", "list"],
        &format!("{PW}\n"),
    );
    assert_eq!(out.status.code(), Some(2));
    let out = ok(
        &run_trove(
            &trove,
            &["--vault", v, "--password-stdin", "list"],
            "new-master-pw\n",
        ),
        "list with new pw",
    );
    assert!(out.contains("survivor"));

    // KDF retune persists and shows up in db-info.
    ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                v,
                "--password-stdin",
                "db-edit",
                "--kdf-memory",
                "128",
                "--kdf-iterations",
                "3",
            ],
            "new-master-pw\n",
        ),
        "db-edit kdf",
    );
    let info = ok(
        &run_trove(
            &trove,
            &["--vault", v, "--password-stdin", "db-info"],
            "new-master-pw\n",
        ),
        "db-info",
    );
    assert!(info.contains("Entries:     1"), "{info}");
    assert!(info.contains("Argon2"), "{info}");
    assert!(info.contains("131072"), "128 MiB in KiB: {info}");
    assert!(!info.contains("sekrit"), "db-info must not leak secrets");
}
