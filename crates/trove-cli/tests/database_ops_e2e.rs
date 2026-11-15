//! End-to-end tests for the database-ops commands: merge (two-secret stdin
//! order), export xml/csv, db-edit (rekey + KDF), db-info.

#![allow(missing_docs)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const PW: &str = "database-ops-e2e-pw";

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

/// Build a database with one password entry via the CLI.
fn seed(trove: &std::path::Path, database: &str, entry: &str, secret: &str) {
    ok(
        &run_trove(
            trove,
            &["--database", database, "--password-stdin", "init"],
            &format!("{PW}\n"),
        ),
        "init",
    );
    ok(
        &run_trove(
            trove,
            &[
                "--database",
                database,
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

    // Diverged copies of ONE database — the case KDBX merge exists for.
    seed(&trove, a, "shared", "orig");
    std::fs::copy(a, b).unwrap();
    ok(
        &run_trove(
            &trove,
            &[
                "--database",
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
                "--database",
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
            &["--database", a, "--password-stdin", "merge", b],
            &format!("{PW}\n{PW}\n"),
        ),
        "merge",
    );
    assert!(out.contains("created"), "{out}");
    let out = ok(
        &run_trove(
            &trove,
            &["--database", a, "--password-stdin", "list"],
            &format!("{PW}\n"),
        ),
        "list after merge",
    );
    assert!(
        out.contains("in-a") && out.contains("in-b") && out.contains("shared"),
        "{out}"
    );

    // Wrong source password → database-error exit (2), target untouched.
    let out = run_trove(
        &trove,
        &["--database", a, "--password-stdin", "merge", b],
        &format!("{PW}\nwrong-source-pw\n"),
    );
    assert_eq!(out.status.code(), Some(2), "bad source creds");

    // Unrelated databases refuse cleanly (no panic): different root UUIDs.
    let c = dir.path().join("c.kdbx");
    let c = c.to_str().unwrap();
    seed(&trove, c, "unrelated", "x");
    let out = run_trove(
        &trove,
        &["--database", a, "--password-stdin", "merge", c],
        &format!("{PW}\n{PW}\n"),
    );
    assert!(!out.status.success(), "unrelated databases must refuse");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("different root UUID"),
        "clean unrelated-database error"
    );
}

#[test]
fn sync_flows_and_errors() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let a = dir.path().join("a.kdbx");
    let a = a.to_str().unwrap();
    let b = dir.path().join("b.kdbx");
    let b = b.to_str().unwrap();
    let list = |database: &str| {
        ok(
            &run_trove(
                &trove,
                &["--database", database, "--password-stdin", "list"],
                &format!("{PW}\n"),
            ),
            "list",
        )
    };

    // A missing copy is created.
    seed(&trove, a, "shared", "orig");
    let out = ok(
        &run_trove(
            &trove,
            &["--database", a, "--password-stdin", "sync", b],
            &format!("{PW}\n"),
        ),
        "sync creates",
    );
    assert!(out.contains("created"), "{out}");
    assert!(list(b).contains("shared"));

    // Each side's change reaches the other.
    for (database, entry) in [(a, "in-a"), (b, "in-b")] {
        ok(
            &run_trove(
                &trove,
                &[
                    "--database",
                    database,
                    "--password-stdin",
                    "add",
                    "password",
                    entry,
                    "--secret-stdin",
                ],
                &format!("{PW}\nsecret\n"),
            ),
            "diverge",
        );
    }
    let out = ok(
        &run_trove(
            &trove,
            &["--database", a, "--password-stdin", "sync", b],
            &format!("{PW}\n{PW}\n"),
        ),
        "sync",
    );
    assert!(out.contains("pulled 1 created"), "{out}");
    assert!(out.contains("pushed 1 created"), "{out}");
    for database in [a, b] {
        let out = list(database);
        assert!(out.contains("in-a") && out.contains("in-b"), "{out}");
    }

    // Wrong password for the other copy → database-error exit (2).
    let out = run_trove(
        &trove,
        &["--database", a, "--password-stdin", "sync", b],
        &format!("{PW}\nwrong\n"),
    );
    assert_eq!(out.status.code(), Some(2), "bad other creds");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("b.kdbx"), "names the other copy: {stderr}");

    // Nothing new on either side: the other copy is left alone.
    let before = std::fs::read(b).unwrap();
    let out = ok(
        &run_trove(
            &trove,
            &["--database", a, "--password-stdin", "sync", b],
            &format!("{PW}\n{PW}\n"),
        ),
        "sync again",
    );
    assert!(out.contains("already had everything"), "{out}");
    assert_eq!(std::fs::read(b).unwrap(), before);
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
            &["--database", v, "--password-stdin", "export"],
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
                "--database",
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
        &["--database", v, "--password-stdin", "db-edit"],
        &format!("{PW}\n"),
    );
    assert!(!out.status.success());

    // Rekey: current pw line 1, new pw line 2.
    ok(
        &run_trove(
            &trove,
            &[
                "--database",
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
        &["--database", v, "--password-stdin", "list"],
        &format!("{PW}\n"),
    );
    assert_eq!(out.status.code(), Some(2));
    let out = ok(
        &run_trove(
            &trove,
            &["--database", v, "--password-stdin", "list"],
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
                "--database",
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
            &["--database", v, "--password-stdin", "db-info"],
            "new-master-pw\n",
        ),
        "db-info",
    );
    assert!(info.contains("Entries:     1"), "{info}");
    assert!(info.contains("Argon2"), "{info}");
    // db-info reports KDBX's stored byte count (128 MiB), not the CLI's
    // --kdf-memory input unit (MiB) or the setter's API unit (KiB).
    assert!(info.contains("134217728"), "128 MiB in bytes: {info}");
    assert!(!info.contains("sekrit"), "db-info must not leak secrets");
}

#[test]
fn database_metadata_can_be_shown_set_and_linked() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let database = dir.path().join("metadata.kdbx");
    let database = database.to_str().unwrap();
    seed(&trove, database, "metadata-test", "secret");

    let shown = ok(
        &run_trove(
            &trove,
            &[
                "--database",
                database,
                "--password-stdin",
                "database",
                "metadata",
                "show",
                "--json",
            ],
            &format!("{PW}\n"),
        ),
        "show database metadata",
    );
    let metadata: serde_json::Value = serde_json::from_str(&shown).expect("metadata JSON");
    assert!(metadata.get("name").is_some());
    assert_eq!(metadata["trove_uuid"], serde_json::Value::Null);

    let uuid = "3c7e4e44-5fca-4e2f-bb19-0912ebf2ab09";
    ok(
        &run_trove(
            &trove,
            &[
                "--database",
                database,
                "--password-stdin",
                "database",
                "metadata",
                "set",
                "--name",
                "Shared copy",
                "--description",
                "linked test database",
                "--default-username",
                "chris",
                "--trove-uuid",
                uuid,
            ],
            &format!("{PW}\n"),
        ),
        "set database metadata",
    );
    let shown = ok(
        &run_trove(
            &trove,
            &[
                "--database",
                database,
                "--password-stdin",
                "database",
                "metadata",
                "show",
                "--json",
            ],
            &format!("{PW}\n"),
        ),
        "show updated database metadata",
    );
    let metadata: serde_json::Value = serde_json::from_str(&shown).expect("updated metadata JSON");
    assert_eq!(metadata["name"], "Shared copy");
    assert_eq!(metadata["description"], "linked test database");
    assert_eq!(metadata["default_username"], "chris");
    assert_eq!(metadata["trove_uuid"], uuid);

    ok(
        &run_trove(
            &trove,
            &[
                "--database",
                database,
                "--password-stdin",
                "database",
                "metadata",
                "set",
                "--generate-trove-uuid",
            ],
            &format!("{PW}\n"),
        ),
        "generate database UUID",
    );
    let shown = ok(
        &run_trove(
            &trove,
            &[
                "--database",
                database,
                "--password-stdin",
                "database",
                "metadata",
                "show",
                "--json",
            ],
            &format!("{PW}\n"),
        ),
        "show generated database UUID",
    );
    let metadata: serde_json::Value =
        serde_json::from_str(&shown).expect("generated metadata JSON");
    let generated_uuid = metadata["trove_uuid"].as_str().unwrap();
    assert_eq!(generated_uuid.len(), 36);
    assert_eq!(generated_uuid.matches('-').count(), 4);
}
