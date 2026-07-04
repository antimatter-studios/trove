//! End-to-end tests for `trove exec` (scoped injection, wipe-on-exit, exit
//! code passthrough) and the `--json` output of list/search/db-info.

#![allow(missing_docs)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const PW: &str = "exec-json-e2e-pw";

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

/// Vault with a string secret (custom env name), a fallback-named secret and
/// a file attachment entry, built through the CLI + trove-core.
fn seed(trove: &std::path::Path, dir: &tempfile::TempDir) -> String {
    let vault = dir.path().join("x.kdbx");
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
                "Infra/stripe",
                "--secret-stdin",
            ],
            &format!("{PW}\nsk_live_e2e\n"),
        ),
        "add stripe",
    );
    ok(
        &run_trove(
            trove,
            &[
                "--vault",
                &vs,
                "--password-stdin",
                "edit",
                "Infra/stripe",
                "--set",
                "Exec.Env=STRIPE_KEY",
            ],
            &format!("{PW}\n"),
        ),
        "set Exec.Env",
    );
    // File entry via add file (also sets Materialize.Source).
    let kube = dir.path().join("kubeconfig");
    std::fs::write(&kube, "apiVersion: v1\nkind: Config\n").unwrap();
    ok(
        &run_trove(
            trove,
            &[
                "--vault",
                &vs,
                "--password-stdin",
                "add",
                "file",
                "Infra/kubeconfig-prod",
                "--src",
                kube.to_str().unwrap(),
                "--target",
                "/tmp/unused-here",
            ],
            &format!("{PW}\n"),
        ),
        "add file",
    );
    ok(
        &run_trove(
            trove,
            &[
                "--vault",
                &vs,
                "--password-stdin",
                "edit",
                "Infra/kubeconfig-prod",
                "--set",
                "Exec.Env=KUBECONFIG",
            ],
            &format!("{PW}\n"),
        ),
        "set kube Exec.Env",
    );
    vs
}

#[test]
fn exec_injects_wipes_and_propagates_exit_codes() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let vs = seed(&trove, &dir);
    let pw = format!("{PW}\n");

    // Group scope: env var carries the secret; KUBECONFIG points at a real
    // temp file with the attachment bytes. Print both from inside the child.
    let out = ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                &vs,
                "--password-stdin",
                "exec",
                "Infra",
                "--",
                "sh",
                "-c",
                "printf '%s|' \"$STRIPE_KEY\"; cat \"$KUBECONFIG\"; printf '|%s' \"$KUBECONFIG\"",
            ],
            &pw,
        ),
        "exec group scope",
    );
    let mut parts = out.split('|');
    assert_eq!(parts.next().unwrap(), "sk_live_e2e");
    assert_eq!(parts.next().unwrap(), "apiVersion: v1\nkind: Config\n");
    let kube_path = parts.next().unwrap().trim().to_string();
    assert!(
        !std::path::Path::new(&kube_path).exists(),
        "materialized file must be wiped after exec: {kube_path}"
    );

    // Child exit code propagates.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            &vs,
            "--password-stdin",
            "exec",
            "Infra/stripe",
            "--",
            "sh",
            "-c",
            "exit 7",
        ],
        &pw,
    );
    assert_eq!(out.status.code(), Some(7), "child exit code passthrough");

    // Unknown scope is a clean error.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            &vs,
            "--password-stdin",
            "exec",
            "No/Scope",
            "--",
            "true",
        ],
        &pw,
    );
    assert!(!out.status.success());
}

#[test]
fn json_outputs_parse_with_expected_fields() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let vs = seed(&trove, &dir);
    let pw = format!("{PW}\n");

    let list: serde_json::Value = serde_json::from_str(&ok(
        &run_trove(
            &trove,
            &["--vault", &vs, "--password-stdin", "list", "--json"],
            &pw,
        ),
        "list --json",
    ))
    .expect("valid JSON");
    let arr = list.as_array().expect("array");
    assert_eq!(arr.len(), 2);
    assert!(arr.iter().any(|e| e["path"] == "Infra/stripe"));
    assert!(
        arr.iter().all(|e| e.get("password").is_none()),
        "summaries must never carry secrets"
    );

    let hits: serde_json::Value = serde_json::from_str(&ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                &vs,
                "--password-stdin",
                "search",
                "stripe",
                "--json",
            ],
            &pw,
        ),
        "search --json",
    ))
    .expect("valid JSON");
    assert_eq!(hits.as_array().unwrap().len(), 1);
    assert_eq!(hits[0]["title"], "stripe");

    let info: serde_json::Value = serde_json::from_str(&ok(
        &run_trove(
            &trove,
            &["--vault", &vs, "--password-stdin", "db-info", "--json"],
            &pw,
        ),
        "db-info --json",
    ))
    .expect("valid JSON");
    assert_eq!(info["entries"], 2);
    assert!(info["kdf"].as_str().unwrap().contains("Argon2"));
}
