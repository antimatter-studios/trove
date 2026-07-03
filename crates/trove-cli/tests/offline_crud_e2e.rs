//! End-to-end tests for the generic entry-CRUD commands in offline mode
//! (`--vault <PATH>`, `--password-stdin`): add password / get password /
//! show / edit / search / mkdir / mv / rm / rmdir. Each command is a fresh
//! process, exactly how scripts drive trove.
//!
//! Recycle-bin semantics are asserted end-to-end: `rm` relocates to the
//! "Recycle Bin" group (KeePassXC convention), a second `rm` destroys, and
//! `--permanent` skips the bin outright.
//!
//! Skips gracefully when the `trove` binary is missing.

#![allow(missing_docs)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const PASSWORD: &str = "correct horse battery staple";
const SECRET: &str = "hunter2-but-longer";

fn find_trove() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_trove")?);
    p.exists().then_some(p)
}

/// Run `trove <args>` with `stdin` piped in and a clean env. Returns output.
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

fn assert_fails(out: &Output, what: &str) {
    assert!(
        !out.status.success(),
        "{what} should FAIL\nstdout: {}",
        String::from_utf8_lossy(&out.stdout),
    );
}

fn stdout_str(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// The whole CRUD lifecycle against one vault file, one process per step.
#[test]
fn offline_crud_lifecycle() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("crud.kdbx");
    let vault = vault.to_str().expect("utf8 path");
    let pw_line = format!("{PASSWORD}\n");

    // init
    assert_ok(
        &run_trove(
            &trove,
            &["--vault", vault, "--password-stdin", "init"],
            &pw_line,
        ),
        "init",
    );

    // add password with username/url; secret arrives as stdin line 2.
    let two_lines = format!("{PASSWORD}\n{SECRET}\n");
    assert_ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "add",
                "password",
                "Web/github",
                "--username",
                "alice",
                "--url",
                "https://github.com",
                "--secret-stdin",
            ],
            &two_lines,
        ),
        "add password",
    );

    // Duplicate add is refused (edit is the way to change).
    assert_fails(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "add",
                "password",
                "Web/github",
                "--secret-stdin",
            ],
            &two_lines,
        ),
        "duplicate add password",
    );

    // get password prints exactly the secret.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "get",
            "password",
            "Web/github",
        ],
        &pw_line,
    );
    assert_ok(&out, "get password");
    assert_eq!(stdout_str(&out).trim_end(), SECRET);

    // show masks the password by default…
    let out = run_trove(
        &trove,
        &["--vault", vault, "--password-stdin", "show", "Web/github"],
        &pw_line,
    );
    assert_ok(&out, "show");
    let shown = stdout_str(&out);
    assert!(shown.contains("UserName: alice"), "show output: {shown}");
    assert!(shown.contains("URL: https://github.com"));
    assert!(shown.contains("Path: Web/github"));
    assert!(
        !shown.contains(SECRET),
        "password must be masked by default"
    );

    // …and refuses a protected --attr without --show-protected…
    assert_fails(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "show",
                "Web/github",
                "--attr",
                "Password",
            ],
            &pw_line,
        ),
        "protected attr without --show-protected",
    );

    // …but reveals it with the flag.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "show",
            "Web/github",
            "--attr",
            "Password",
            "--show-protected",
        ],
        &pw_line,
    );
    assert_ok(&out, "show --attr Password --show-protected");
    assert_eq!(stdout_str(&out).trim_end(), SECRET);

    // edit: standard field + custom field; then verify both.
    assert_ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "edit",
                "Web/github",
                "--username",
                "bob",
                "--set",
                "Env=prod",
            ],
            &pw_line,
        ),
        "edit",
    );
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "show",
            "Web/github",
            "--attr",
            "UserName",
            "--attr",
            "Env",
        ],
        &pw_line,
    );
    assert_ok(&out, "show edited attrs");
    assert_eq!(stdout_str(&out), "bob\nprod\n");

    // edit with nothing to change is a user error.
    assert_fails(
        &run_trove(
            &trove,
            &["--vault", vault, "--password-stdin", "edit", "Web/github"],
            &pw_line,
        ),
        "edit with no changes",
    );

    // search: title hit, username hit, secret never matches.
    let out = run_trove(
        &trove,
        &["--vault", vault, "--password-stdin", "search", "github"],
        &pw_line,
    );
    assert_ok(&out, "search title");
    assert!(stdout_str(&out).contains("Web/github"));
    let out = run_trove(
        &trove,
        &["--vault", vault, "--password-stdin", "search", SECRET],
        &pw_line,
    );
    assert_ok(&out, "search secret");
    assert_eq!(
        stdout_str(&out),
        "",
        "protected values must not be searchable"
    );

    // mkdir + mv; a second identical mkdir fails; mv to a missing group fails.
    assert_ok(
        &run_trove(
            &trove,
            &["--vault", vault, "--password-stdin", "mkdir", "Work/Infra"],
            &pw_line,
        ),
        "mkdir",
    );
    assert_fails(
        &run_trove(
            &trove,
            &["--vault", vault, "--password-stdin", "mkdir", "Work/Infra"],
            &pw_line,
        ),
        "duplicate mkdir",
    );
    assert_fails(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "mv",
                "Web/github",
                "No/Such",
            ],
            &pw_line,
        ),
        "mv to missing group",
    );
    assert_ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "mv",
                "Web/github",
                "Work/Infra",
            ],
            &pw_line,
        ),
        "mv",
    );
    let out = run_trove(
        &trove,
        &["--vault", vault, "--password-stdin", "list"],
        &pw_line,
    );
    assert_ok(&out, "list after mv");
    assert!(stdout_str(&out).contains("Work/Infra/github"));

    // rm: first recycles (entry survives under "Recycle Bin"), second destroys.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "rm",
            "Work/Infra/github",
        ],
        &pw_line,
    );
    assert_ok(&out, "rm (recycle)");
    assert!(stdout_str(&out).contains("recycle bin"));
    let out = run_trove(
        &trove,
        &["--vault", vault, "--password-stdin", "list"],
        &pw_line,
    );
    assert!(stdout_str(&out).contains("Recycle Bin/github"));
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "rm",
            "Recycle Bin/github",
        ],
        &pw_line,
    );
    assert_ok(&out, "rm inside bin (destroy)");
    assert!(stdout_str(&out).contains("permanently deleted"));
    let out = run_trove(
        &trove,
        &["--vault", vault, "--password-stdin", "list"],
        &pw_line,
    );
    assert!(
        !stdout_str(&out).contains("github"),
        "entry must be fully gone"
    );

    // rmdir: recycles a group tree by default; --permanent needs --recursive
    // when non-empty.
    let two_lines2 = format!("{PASSWORD}\n{SECRET}2\n");
    assert_ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "add",
                "password",
                "Old/Project/token",
                "--secret-stdin",
            ],
            &two_lines2,
        ),
        "add for rmdir",
    );
    assert_fails(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "rmdir",
                "Old",
                "--permanent",
            ],
            &pw_line,
        ),
        "rmdir --permanent non-empty without --recursive",
    );
    let out = run_trove(
        &trove,
        &["--vault", vault, "--password-stdin", "rmdir", "Old"],
        &pw_line,
    );
    assert_ok(&out, "rmdir (recycle)");
    let out = run_trove(
        &trove,
        &["--vault", vault, "--password-stdin", "list"],
        &pw_line,
    );
    assert!(stdout_str(&out).contains("Recycle Bin/Old/Project/token"));

    // add password --generate prints the minted secret and stores it.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "add",
            "password",
            "minted",
            "--generate",
            "--length",
            "32",
        ],
        &pw_line,
    );
    assert_ok(&out, "add password --generate");
    let minted = stdout_str(&out).trim_end().to_string();
    assert_eq!(minted.len(), 32);
    assert!(minted.chars().all(|c| c.is_ascii_alphanumeric()));
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "get",
            "password",
            "minted",
        ],
        &pw_line,
    );
    assert_ok(&out, "get minted password");
    assert_eq!(stdout_str(&out).trim_end(), minted);
}

/// Daemon-mode contract: without `--vault`, the write/read CRUD commands are
/// gated on `TROVE_SESSION` and refuse cleanly when it is absent.
#[test]
fn daemon_mode_requires_session_code() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    for args in [
        vec!["add", "password", "x", "--secret-stdin"],
        vec!["get", "password", "x"],
        vec!["edit", "x", "--username", "u"],
        vec!["rm", "x"],
        vec!["mv", "x", "y"],
        vec!["mkdir", "y"],
        vec!["rmdir", "y"],
        vec!["show", "x", "--attr", "Password", "--show-protected"],
    ] {
        let out = run_trove(&trove, &args, "sekrit\n");
        assert!(
            !out.status.success(),
            "daemon-mode `trove {}` without TROVE_SESSION should fail",
            args.join(" "),
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("session code required") || err.contains("TROVE_SESSION"),
            "unexpected error for `trove {}`: {err}",
            args.join(" "),
        );
    }
}
