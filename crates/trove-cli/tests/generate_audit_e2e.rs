//! End-to-end tests for the generation + audit commands: `generate password`,
//! `generate diceware`, `estimate`, and `analyze --hibp` (offline breach
//! check with meaningful exit codes).

#![allow(missing_docs)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const PASSWORD: &str = "gen-audit-e2e-pw";

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

/// Uppercase-hex SHA-1, mirroring hibp::sha1_hex_upper for fixture building.
fn sha1_hex(pw: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(pw.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02X}")).collect()
}

#[test]
fn generate_password_and_diceware_shapes() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };

    // Defaults: one 20-char alphanumeric password.
    let out = ok(
        &run_trove(&trove, &["generate", "password"], ""),
        "generate",
    );
    let pw = out.trim_end();
    assert_eq!(pw.len(), 20);
    assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));

    // Zero is a useful value for computed batch counts: do not emit an
    // unrequested secret.
    let out = ok(
        &run_trove(&trove, &["generate", "password", "--count", "0"], ""),
        "generate zero passwords",
    );
    assert!(out.is_empty(), "count zero should print nothing: {out:?}");

    // Policy flags + count.
    let out = ok(
        &run_trove(
            &trove,
            &[
                "generate",
                "password",
                "--length",
                "32",
                "--no-lower",
                "--no-upper",
                "--exclude",
                "01",
                "--count",
                "3",
            ],
            "",
        ),
        "generate with policy",
    );
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3);
    for l in &lines {
        assert_eq!(l.len(), 32);
        assert!(l.chars().all(|c| "23456789".contains(c)), "{l}");
    }

    // An empty pool is a clean error.
    let out = run_trove(
        &trove,
        &[
            "generate",
            "password",
            "--no-lower",
            "--no-upper",
            "--no-numeric",
        ],
        "",
    );
    assert!(!out.status.success(), "empty pool must error");

    // Diceware: 7 hyphen-separated lowercase words by default. A few EFF words
    // contain '-' (e.g. "t-shirt"), so the token count is >= 7, not exactly 7 —
    // asserting equality here flakes ~0.3% of runs. Check the lower bound and
    // that every token is a nonempty lowercase word.
    let out = ok(
        &run_trove(&trove, &["generate", "diceware"], ""),
        "diceware",
    );
    let words: Vec<&str> = out.trim_end().split('-').collect();
    assert!(words.len() >= 7, "{out}");
    assert!(
        words
            .iter()
            .all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase())),
        "{out}"
    );

    let out = ok(
        &run_trove(&trove, &["generate", "diceware", "--count", "0"], ""),
        "generate zero passphrases",
    );
    assert!(out.is_empty(), "count zero should print nothing: {out:?}");
}

#[test]
fn estimate_rates_weak_below_strong() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let score = |pw: &str| -> u8 {
        // Password via stdin — the preferred, history-safe path.
        let out = ok(
            &run_trove(&trove, &["estimate"], &format!("{pw}\n")),
            "estimate",
        );
        out.lines()
            .find_map(|l| l.strip_prefix("Score:"))
            .and_then(|s| s.trim().strip_suffix("/4"))
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or_else(|| panic!("no score in output:\n{out}"))
    };
    let weak = score("password");
    let strong = score("vXk9$mQz2!pLr7@wN4hT");
    assert!(weak <= 1, "'password' must rate 0-1, got {weak}");
    assert_eq!(strong, 4, "random 20-char must rate 4");

    let out = ok(
        &run_trove(&trove, &["estimate", "--json"], "password\n"),
        "JSON estimate",
    );
    let value: serde_json::Value = serde_json::from_str(&out).expect("estimate JSON");
    assert_eq!(value["length"], 8);
    assert!(value["score"].as_u64().is_some());
    assert!(value["entropy_bits"].as_f64().is_some());
    assert!(value["suggestions"].is_array());
    assert!(
        value.get("password").is_none(),
        "JSON must not echo secrets"
    );
}

#[test]
fn analyze_flags_breached_and_gates_exit_code() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("v.kdbx");
    let vault = vault.to_str().unwrap();
    let pw = format!("{PASSWORD}\n");

    ok(
        &run_trove(&trove, &["--vault", vault, "--password-stdin", "init"], &pw),
        "init",
    );
    for (entry, secret) in [
        ("breached-one", "hunter2"),
        ("clean-one", "uncompromised-xK92!m"),
    ] {
        ok(
            &run_trove(
                &trove,
                &[
                    "--vault",
                    vault,
                    "--password-stdin",
                    "add",
                    "password",
                    entry,
                    "--secret-stdin",
                ],
                &format!("{PASSWORD}\n{secret}\n"),
            ),
            entry,
        );
    }

    // Synthetic sorted dump: contains hunter2 (and padding hashes), not the
    // clean password.
    let mut lines = [
        format!("{}:1337", sha1_hex("hunter2")),
        format!("{}:42", sha1_hex("password")),
        format!("{}:7", sha1_hex("letmein")),
    ];
    lines.sort();
    let hibp = dir.path().join("pwned.txt");
    std::fs::write(&hibp, format!("{}\n", lines.join("\n"))).unwrap();
    let hibps = hibp.to_str().unwrap();

    // Breach found → exit 1, entry named with its count.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "analyze",
            "--hibp",
            hibps,
            "--json",
        ],
        &pw,
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "breaches must gate the exit code"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("breached-one"), "{stdout}");
    assert!(stdout.contains("1337"), "{stdout}");
    assert!(!stdout.contains("clean-one"), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("analyze JSON");
    assert_eq!(value["checked_passwords"], 2);
    assert_eq!(value["breached_passwords"], 1);
    assert_eq!(value["findings"][0]["entry_path"], "breached-one");
    assert_eq!(value["findings"][0]["breach_count"], 1337);

    // Clean vault → exit 0.
    ok(
        &run_trove(
            &trove,
            &[
                "--vault",
                vault,
                "--password-stdin",
                "rm",
                "breached-one",
                "--permanent",
            ],
            &pw,
        ),
        "rm breached",
    );
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "analyze",
            "--hibp",
            hibps,
            "--json",
        ],
        &pw,
    );
    assert_eq!(out.status.code(), Some(0), "clean vault must exit 0");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("clean analyze JSON");
    assert_eq!(value["checked_passwords"], 1);
    assert_eq!(value["breached_passwords"], 0);
    assert_eq!(value["findings"], serde_json::json!([]));

    // Empty and absent Password fields must be visible and fail the audit,
    // without being counted as HIBP lookups.
    for (entry, edit_arg) in [("blank-one", "Password="), ("missing-one", "")] {
        ok(
            &run_trove(
                &trove,
                &[
                    "--vault",
                    vault,
                    "--password-stdin",
                    "add",
                    "password",
                    entry,
                    "--secret-stdin",
                ],
                &format!("{PASSWORD}\ntemporary-secret\n"),
            ),
            entry,
        );
        let edit_args = if edit_arg.is_empty() {
            vec![
                "--vault",
                vault,
                "--password-stdin",
                "edit",
                entry,
                "--unset",
                "Password",
            ]
        } else {
            vec![
                "--vault",
                vault,
                "--password-stdin",
                "edit",
                entry,
                "--set",
                edit_arg,
            ]
        };
        ok(&run_trove(&trove, &edit_args, &pw), "clear password");
    }
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "analyze",
            "--hibp",
            hibps,
        ],
        &pw,
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "empty passwords must fail audit"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("blank-one  empty password"), "{stdout}");
    assert!(stdout.contains("missing-one  empty password"), "{stdout}");
    assert!(!stdout.contains("no breached passwords"), "{stdout}");
    assert!(
        stderr.contains("checked 1 passwords, 0 breached, 2 empty"),
        "{stderr}"
    );

    // Missing dump file is a clean error.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "analyze",
            "--hibp",
            "/no/such/file",
        ],
        &pw,
    );
    assert!(!out.status.success());
}

#[test]
fn analyze_reports_reuse_weakness_and_age_without_secrets() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("v.kdbx");
    let vault = vault.to_str().unwrap();
    let pw = format!("{PASSWORD}\n");
    ok(
        &run_trove(&trove, &["--vault", vault, "--password-stdin", "init"], &pw),
        "init",
    );
    let shared = "Shared-secret-9f!Kq2#zz";
    for (entry, secret) in [
        ("Web/a", shared),
        ("Web/b", shared),
        ("Web/weak", "password1"),
        ("Web/solo", "Unique-and-long-7$Qx!pL0"),
    ] {
        ok(
            &run_trove(
                &trove,
                &[
                    "--vault",
                    vault,
                    "--password-stdin",
                    "add",
                    "password",
                    entry,
                    "--secret-stdin",
                ],
                &format!("{PASSWORD}\n{secret}\n"),
            ),
            entry,
        );
    }

    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "analyze",
            "--reuse",
            "--weak",
            "--json",
        ],
        &pw,
    );
    assert_eq!(out.status.code(), Some(1), "findings gate the exit code");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains(shared) && !stdout.contains("password1"),
        "{stdout}"
    );
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("analyze JSON");
    assert_eq!(
        value["reused"][0]["entry_paths"],
        serde_json::json!(["Web/a", "Web/b"])
    );
    assert_eq!(value["reused"].as_array().unwrap().len(), 1);
    assert_eq!(value["weak"][0]["entry_path"], "Web/weak");
    assert!(
        value.get("checked_passwords").is_none(),
        "no HIBP keys without --hibp"
    );

    // Everything was written just now, so nothing is older than a year.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "analyze",
            "--age",
            "365",
            "--json",
        ],
        &pw,
    );
    assert!(out.status.success(), "{out:?}");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["stale"], serde_json::json!([]));

    // At least one check is required.
    let out = run_trove(
        &trove,
        &["--vault", vault, "--password-stdin", "analyze"],
        &pw,
    );
    assert!(!out.status.success());
}
