//! End-to-end tests for TOTP in offline mode: `add totp` (secret and URI
//! forms), `show --totp`, protected-attr gating on `otp`, and failure modes.

#![allow(missing_docs)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const PASSWORD: &str = "totp-e2e-pw";
/// RFC 6238 test secret, base32.
const SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

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

#[test]
fn totp_offline_lifecycle() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("t.kdbx");
    let vault = vault.to_str().unwrap();
    let pw = format!("{PASSWORD}\n");

    ok(
        &run_trove(&trove, &["--vault", vault, "--password-stdin", "init"], &pw),
        "init",
    );

    // add totp --secret creates the entry and stores the otpauth URI.
    // Sites show secrets with spaces; trove normalizes them away.
    let spaced = format!("{} {}", &SECRET_B32[..16], &SECRET_B32[16..]);
    ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "add",
                "totp",
                "Web/github",
                "--secret",
                &spaced,
            ],
            &pw,
        ),
        "add totp --secret",
    );

    // show --totp prints a 6-digit code.
    let out = ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "show",
                "Web/github",
                "--totp",
            ],
            &pw,
        ),
        "show --totp",
    );
    let code = out.trim_end();
    assert_eq!(code.len(), 6, "default is 6 digits, got '{code}'");
    assert!(code.chars().all(|c| c.is_ascii_digit()));

    // The otp attribute is protected: refused without --show-protected…
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "show",
            "Web/github",
            "--attr",
            "otp",
        ],
        &pw,
    );
    assert!(
        !out.status.success(),
        "otp attr must require --show-protected"
    );
    // …and revealed with it (the full otpauth URI).
    let out = ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "show",
                "Web/github",
                "--attr",
                "otp",
                "--show-protected",
            ],
            &pw,
        ),
        "show --attr otp --show-protected",
    );
    assert!(
        out.contains(SECRET_B32),
        "URI should carry the normalized secret"
    );

    // add totp --uri on an existing entry replaces the generator (8 digits).
    let uri = format!("otpauth://totp/gh?secret={SECRET_B32}&period=30&digits=8&algorithm=SHA1");
    ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "add",
                "totp",
                "Web/github",
                "--uri",
                &uri,
            ],
            &pw,
        ),
        "add totp --uri",
    );
    let out = ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "show",
                "Web/github",
                "--totp",
            ],
            &pw,
        ),
        "show --totp after uri replace",
    );
    assert_eq!(out.trim_end().len(), 8, "digits=8 honored");

    // Garbage URI is rejected.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "add",
            "totp",
            "bad",
            "--uri",
            "not-a-uri",
        ],
        &pw,
    );
    assert!(!out.status.success(), "invalid URI must be rejected");

    // show --totp on an entry with no otp field is a clean user error.
    let two = format!("{PASSWORD}\nsome-pass\n");
    ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "add",
                "password",
                "plain",
                "--secret-stdin",
            ],
            &two,
        ),
        "add plain entry",
    );
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "show",
            "plain",
            "--totp",
        ],
        &pw,
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no otp field"),
        "precise no-otp error expected"
    );
}
