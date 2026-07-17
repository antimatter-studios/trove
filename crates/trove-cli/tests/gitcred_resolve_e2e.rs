//! End-to-end tests for `trove git-credential` and `trove resolve`. Both are
//! offline-only and read one secret; git-credential additionally consumes
//! git's protocol block from stdin AFTER the --password-stdin line.

#![allow(missing_docs)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const PW: &str = "gitcred-e2e-pw";

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

fn seed(trove: &std::path::Path, dir: &tempfile::TempDir) -> String {
    let vault = dir.path().join("g.kdbx");
    let vs = vault.to_str().unwrap().to_string();
    ok(
        &run_trove(
            trove,
            &["--vault", &vs, "--password-stdin", "init"],
            &format!("{PW}\n"),
        ),
        "init",
    );
    ok(
        &run_trove(
            trove,
            &[
                "--vault",
                &vs,
                "--password-stdin",
                "add",
                "password",
                "Git/github",
                "--username",
                "octocat",
                "--url",
                "https://github.com",
                "--secret-stdin",
            ],
            &format!("{PW}\nghp_token_e2e\n"),
        ),
        "add github",
    );
    vs
}

#[test]
fn git_credential_get_fills_from_matching_entry() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let vs = seed(&trove, &dir);

    // stdin: vault password (line 1), then git's request block.
    let stdin = format!("{PW}\nprotocol=https\nhost=github.com\n\n");
    let out = ok(
        &run_trove(
            &trove,
            &["--vault", &vs, "--password-stdin", "git-credential", "get"],
            &stdin,
        ),
        "git-credential get",
    );
    assert!(out.contains("username=octocat"), "{out}");
    assert!(out.contains("password=ghp_token_e2e"), "{out}");

    // No matching host → empty reply, still exit 0 (git falls back).
    let stdin = format!("{PW}\nprotocol=https\nhost=example.com\n\n");
    let out = run_trove(
        &trove,
        &["--vault", &vs, "--password-stdin", "git-credential", "get"],
        &stdin,
    );
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");

    // store is a no-op that still exits 0.
    let stdin = format!("{PW}\nhost=github.com\npassword=x\n\n");
    let out = run_trove(
        &trove,
        &[
            "--vault",
            &vs,
            "--password-stdin",
            "git-credential",
            "store",
        ],
        &stdin,
    );
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
}

#[test]
fn resolve_prints_referenced_value() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let vs = seed(&trove, &dir);
    let pw = format!("{PW}\n");

    // Default field (Password).
    let out = ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                &vs,
                "--password-stdin",
                "resolve",
                "trove://Git/github",
            ],
            &pw,
        ),
        "resolve default",
    );
    assert_eq!(out.trim_end(), "ghp_token_e2e");

    // Named field.
    let out = ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                &vs,
                "--password-stdin",
                "resolve",
                "trove://Git/github/UserName",
            ],
            &pw,
        ),
        "resolve UserName",
    );
    assert_eq!(out.trim_end(), "octocat");

    // Missing entry → error exit.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            &vs,
            "--password-stdin",
            "resolve",
            "trove://No/Such",
        ],
        &pw,
    );
    assert!(!out.status.success());
}
