//! End-to-end test for offline mode: the global `--vault <PATH>` selector lets
//! every vault command operate directly on a kdbx file, with no daemon and no
//! `TROVE_SESSION`. This is the path automation drives — each invocation is a
//! fresh process that addresses entries by `group/sub/title` and reads the
//! password from stdin (`--password-stdin`), never the command line.
//!
//! Critically, `--vault` is a GLOBAL option: it works both BEFORE and AFTER the
//! subcommand. The round trip below alternates placement on purpose.
//!
//! Also asserts the daemon-mode contract (no `--vault`) still gates on
//! `TROVE_SESSION`, and that commands with no daemon mode error without
//! `--vault`.
//!
//! Skips gracefully when the `trove` binary is missing.

#![allow(missing_docs)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const PASSWORD: &str = "correct horse battery staple";

/// The compiled `trove` binary cargo built for this test, if present.
fn find_trove() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_trove")?);
    p.exists().then_some(p)
}

/// Run `trove <args>` with `password\n` on stdin and a clean env (no inherited
/// `TROVE_SESSION` from the developer's shell). Returns the captured output.
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

fn assert_ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn offline_round_trip_no_daemon() {
    let Some(trove) = find_trove() else {
        eprintln!("trove binary not found; skipping offline e2e");
        return;
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let vault = tmp.path().join("v.kdbx");
    let vault_s = vault.to_str().unwrap();

    // init — global flags BEFORE the subcommand.
    let out = run_trove(
        &trove,
        &["--vault", vault_s, "--password-stdin", "init"],
        PASSWORD,
    );
    assert_ok(&out, "init");
    assert!(vault.exists(), "init should create the vault file");

    // generate ssh — global flags AFTER the subcommand (global-arg behavior).
    // Mints a real keypair in-tool, stored offline at the entry path.
    let out = run_trove(
        &trove,
        &[
            "generate",
            "ssh",
            "work/github",
            "--vault",
            vault_s,
            "--password-stdin",
        ],
        PASSWORD,
    );
    assert_ok(&out, "generate ssh");

    // get ssh --public (offline) → an authorized_keys line.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault_s,
            "--password-stdin",
            "get",
            "ssh",
            "work/github",
            "--public",
        ],
        PASSWORD,
    );
    assert_ok(&out, "get ssh --public");
    let pub_line = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(
        pub_line.starts_with("ssh-ed25519 "),
        "expected an ed25519 public line, got: {pub_line:?}"
    );

    // get file --name id.pub (offline) must return the SAME bytes as the public
    // key — proving the persisted `id.pub` attachment is what's served.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault_s,
            "--password-stdin",
            "get",
            "file",
            "work/github",
            "--name",
            "id.pub",
        ],
        PASSWORD,
    );
    assert_ok(&out, "get file id.pub");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        pub_line,
        "get file --name id.pub should equal get ssh --public"
    );

    // get ssh --out (offline): private key to <out> (0600), public to <out>.pub.
    let key_out = tmp.path().join("id");
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault_s,
            "--password-stdin",
            "get",
            "ssh",
            "work/github",
            "--out",
            key_out.to_str().unwrap(),
        ],
        PASSWORD,
    );
    assert_ok(&out, "get ssh --out");
    let priv_bytes = std::fs::read(&key_out).expect("read private key out");
    assert!(
        priv_bytes.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----"),
        "expected an OpenSSH private key on disk"
    );
    let pub_on_disk =
        std::fs::read_to_string(key_out.with_extension("pub")).expect("read .pub out");
    assert_eq!(pub_on_disk.trim(), pub_line, "<out>.pub should match");

    // list (offline) → shows the entry at its full path.
    let out = run_trove(
        &trove,
        &["--vault", vault_s, "--password-stdin", "list"],
        PASSWORD,
    );
    assert_ok(&out, "list");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("work/github"),
        "list should show the entry path 'work/github'\nstdout: {stdout}"
    );
}

#[test]
fn get_without_vault_or_session_fails() {
    let Some(trove) = find_trove() else {
        eprintln!("trove binary not found; skipping offline e2e");
        return;
    };
    // No --vault and no TROVE_SESSION → daemon mode rejects up front with the
    // session-code requirement, never opening any vault.
    let out = run_trove(&trove, &["get", "ssh", "whatever"], "");
    assert!(
        !out.status.success(),
        "get ssh with neither --vault nor TROVE_SESSION must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("session code required"),
        "expected the session-code hint\nstderr: {stderr}"
    );
}

#[test]
fn vault_required_commands_error_without_vault() {
    let Some(trove) = find_trove() else {
        eprintln!("trove binary not found; skipping offline e2e");
        return;
    };
    // `init` has no daemon mode; without --vault it must explain it needs one.
    let out = run_trove(&trove, &["--password-stdin", "init"], PASSWORD);
    assert!(!out.status.success(), "init without --vault must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--vault"),
        "expected an error naming --vault\nstderr: {stderr}"
    );
}
