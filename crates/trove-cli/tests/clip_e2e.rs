//! End-to-end tests for `trove clip`. Clipboard CONTENT correctness lives in
//! the clip module's unit tests (guarded clear, hash mismatch); these cover
//! the command surface: value resolution errors, gating, the report line,
//! and the hidden clearer staying hidden. Skips the copy paths cleanly where
//! no clipboard exists (headless CI).

#![allow(missing_docs)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const PASSWORD: &str = "clip-e2e-pw";

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

fn has_clipboard() -> bool {
    arboard::Clipboard::new().is_ok()
}

#[test]
fn clip_resolves_values_and_reports() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("c.kdbx");
    let vault = vault.to_str().unwrap();
    let pw = format!("{PASSWORD}\n");
    let two = format!("{PASSWORD}\nclip-secret-value\n");

    let out = run_trove(&trove, &["--vault", vault, "--password-stdin", "init"], &pw);
    assert!(out.status.success());
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "add",
            "password",
            "svc",
            "--username",
            "alice",
            "--secret-stdin",
        ],
        &two,
    );
    assert!(out.status.success());

    // Missing entry / missing attr fail cleanly regardless of clipboard.
    let out = run_trove(
        &trove,
        &["--vault", vault, "--password-stdin", "clip", "nope"],
        &pw,
    );
    assert!(!out.status.success(), "missing entry must fail");
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "clip",
            "svc",
            "--attr",
            "NoSuch",
        ],
        &pw,
    );
    assert!(!out.status.success(), "missing attr must fail");

    // TOTP on an entry without otp is the precise no-otp error.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "clip",
            "svc",
            "--totp",
        ],
        &pw,
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no otp field"));

    if !has_clipboard() {
        eprintln!("skipping copy paths: no clipboard in this environment");
        return;
    }

    // Successful copy reports the countdown; --timeout 0 reports disabled.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "clip",
            "svc",
            "--timeout",
            "0",
        ],
        &pw,
    );
    assert!(out.status.success(), "{out:?}");
    let msg = String::from_utf8_lossy(&out.stdout);
    assert!(msg.contains("auto-clear disabled"), "{msg}");
    assert!(
        !msg.contains("clip-secret-value"),
        "the secret must never be echoed"
    );

    // --attr copies a non-secret field and says so.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "clip",
            "svc",
            "--attr",
            "UserName",
            "--timeout",
            "0",
        ],
        &pw,
    );
    assert!(out.status.success(), "{out:?}");
}

/// The detached clearer, end to end: `clip --timeout 1` copies and spawns
/// the child; within a generous margin the clipboard no longer holds the
/// secret. Serialized with the other clipboard test by file ordering only —
/// uses its own unique value so cross-talk can't false-positive.
#[test]
fn detached_clearer_wipes_after_timeout() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    if !has_clipboard() {
        eprintln!("skipping: no clipboard in this environment");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("t.kdbx");
    let vault = vault.to_str().unwrap();
    let pw = format!("{PASSWORD}\n");
    let unique = format!("clearer-e2e-{}", std::process::id());
    let two = format!("{PASSWORD}\n{unique}\n");

    let out = run_trove(&trove, &["--vault", vault, "--password-stdin", "init"], &pw);
    assert!(out.status.success());
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "add",
            "password",
            "wipe-me",
            "--secret-stdin",
        ],
        &two,
    );
    assert!(out.status.success());

    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "clip",
            "wipe-me",
            "--timeout",
            "1",
        ],
        &pw,
    );
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("clears in 1s"));

    // Immediately after: the secret is on the clipboard.
    let mut cb = arboard::Clipboard::new().unwrap();
    assert_eq!(cb.get_text().unwrap_or_default(), unique);

    // Within the margin the detached child must have wiped it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
    loop {
        let now = cb.get_text().unwrap_or_default();
        if now != unique {
            return; // wiped (or replaced by another process — either way, gone)
        }
        assert!(
            std::time::Instant::now() < deadline,
            "clipboard still holds the secret after the timeout"
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

#[test]
fn clearer_is_hidden_from_help() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let out = run_trove(&trove, &["--help"], "");
    assert!(out.status.success());
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("__clear-clipboard"),
        "internal clearer must not appear in help"
    );
}
