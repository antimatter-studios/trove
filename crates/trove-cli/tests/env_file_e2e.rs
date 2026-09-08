//! End-to-end tests for `--env`: load a dotenv-style file before running, so a
//! vault opens without a prompt, a pipeline, or a password on the command line.
//!
//! Three forms, all exercised below: bare `--env` (`./.env.trove` in the
//! current directory), `--env <dir>` (that directory's `.env.trove`), and
//! `--env <file>`.
//!
//! Two properties matter beyond "it works":
//!   * A variable already set in the environment WINS over the file, so the
//!     file supplies defaults and never overrides an explicit caller.
//!   * The password is taken from the environment ONLY when `--env` was passed.
//!     An exported `TROVE_DB_PASSWORD` must never silently unlock a vault for a
//!     command that didn't ask for it.
//!
//! Skips gracefully when the `trove` binary is missing.

#![allow(missing_docs)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const PASSWORD: &str = "env-file-test-pw";

fn find_trove() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_trove")?);
    p.exists().then_some(p)
}

/// Run `trove` in `cwd` with a clean environment plus `extra_env`.
fn run_in(
    trove: &Path,
    cwd: &Path,
    args: &[&str],
    stdin: &str,
    extra_env: &[(&str, &str)],
) -> Output {
    let mut cmd = Command::new(trove);
    cmd.args(args)
        .current_dir(cwd)
        .env_remove("TROVE_SESSION")
        .env_remove("TROVE_DB_PASSWORD")
        .env_remove("TROVE_VAULT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn trove");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait for trove")
}

/// A vault with one entry, plus a `.env.trove` in `dir` naming its password.
fn fixture(trove: &Path, dir: &Path) -> PathBuf {
    let vault = dir.join("v.kdbx");
    let out = run_in(
        trove,
        dir,
        &[
            "init",
            "--vault",
            vault.to_str().unwrap(),
            "--password-stdin",
        ],
        &format!("{PASSWORD}\n"),
        &[],
    );
    assert!(out.status.success(), "init should succeed");
    std::fs::write(
        dir.join(".env.trove"),
        format!("# vault credentials\nTROVE_DB_PASSWORD={PASSWORD}\n"),
    )
    .expect("write .env.trove");
    vault
}

#[test]
fn bare_env_reads_dot_env_trove_from_the_current_directory() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());

    let out = run_in(
        &trove,
        tmp.path(),
        &["list", "--vault", vault.to_str().unwrap(), "--env"],
        "",
        &[],
    );
    assert!(
        out.status.success(),
        "bare --env should unlock: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn env_accepts_a_directory_and_appends_the_default_filename() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    let elsewhere = TempDir::new().expect("second tempdir");

    // Run from a directory with no .env.trove of its own, pointing at the one
    // that has it.
    let out = run_in(
        &trove,
        elsewhere.path(),
        &[
            "list",
            "--vault",
            vault.to_str().unwrap(),
            "--env",
            tmp.path().to_str().unwrap(),
        ],
        "",
        &[],
    );
    assert!(
        out.status.success(),
        "--env <dir> should find <dir>/.env.trove: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn env_accepts_an_explicit_file_path() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    let renamed = tmp.path().join("credentials.env");
    std::fs::rename(tmp.path().join(".env.trove"), &renamed).expect("rename");

    let out = run_in(
        &trove,
        tmp.path(),
        &[
            "list",
            "--vault",
            vault.to_str().unwrap(),
            "--env",
            renamed.to_str().unwrap(),
        ],
        "",
        &[],
    );
    assert!(
        out.status.success(),
        "--env <file> should read that file: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_environment_wins_over_the_file() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());

    // The file holds the right password; the environment holds a wrong one.
    // The environment must win, so this must FAIL — proving the file supplies
    // defaults rather than overriding the caller.
    let out = run_in(
        &trove,
        tmp.path(),
        &["list", "--vault", vault.to_str().unwrap(), "--env"],
        "",
        &[("TROVE_DB_PASSWORD", "not-the-password")],
    );
    assert!(
        !out.status.success(),
        "an explicit environment variable must override the file"
    );
}

#[test]
fn the_password_is_only_used_when_env_was_asked_for() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());

    // Correct password in the environment, but no --env: trove must not use it.
    // Stdin is closed, so a prompt fails rather than hanging.
    let out = run_in(
        &trove,
        tmp.path(),
        &["list", "--vault", vault.to_str().unwrap()],
        "",
        &[("TROVE_DB_PASSWORD", PASSWORD)],
    );
    assert!(
        !out.status.success(),
        "TROVE_DB_PASSWORD must not unlock a vault unless --env opted in"
    );
}

#[test]
fn a_missing_env_file_is_an_error_not_a_silent_prompt() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    std::fs::remove_file(tmp.path().join(".env.trove")).expect("remove");

    let out = run_in(
        &trove,
        tmp.path(),
        &["list", "--vault", vault.to_str().unwrap(), "--env"],
        "",
        &[],
    );
    assert!(!out.status.success(), "a missing --env file must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(".env.trove"),
        "the error should name the file it looked for, got: {err}"
    );
}

#[test]
fn other_trove_variables_load_from_the_file_too() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    // `--env` is a general loader, not a password mechanism: anything in the
    // file lands in the environment. TROVE_VAULT is the useful one — it makes
    // the path argument unnecessary for other tooling.
    std::fs::write(
        tmp.path().join(".env.trove"),
        format!("export TROVE_DB_PASSWORD=\"{PASSWORD}\"\nTROVE_NO_VERSION_WARN=1\n"),
    )
    .expect("write");

    let out = run_in(
        &trove,
        tmp.path(),
        &["list", "--vault", vault.to_str().unwrap(), "--env"],
        "",
        &[],
    );
    assert!(
        out.status.success(),
        "quoted values and `export ` prefixes should parse: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Bare `--env` falls back to the vault's own directory.
///
/// Keeping `work.kdbx` and `.env.trove` together is the natural layout, and
/// `trove unlock ~/vaults/work.kdbx` run from anywhere else must still find it —
/// otherwise the flag only works when you happen to be standing in the right
/// directory.
#[test]
fn bare_env_falls_back_to_the_directory_holding_the_vault() {
    let Some(trove) = find_trove() else { return };
    let vault_dir = TempDir::new().expect("tempdir");
    let elsewhere = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, vault_dir.path());
    assert!(
        !elsewhere.path().join(".env.trove").exists(),
        "the working directory must NOT have one, or this proves nothing"
    );

    let out = run_in(
        &trove,
        elsewhere.path(),
        &["list", "--vault", vault.to_str().unwrap(), "--env"],
        "",
        &[],
    );
    assert!(
        out.status.success(),
        "should find the vault's own .env.trove: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("loaded 1 variable"),
        "and say which file it used: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The working directory wins, so a checkout can override the vault's own file.
#[test]
fn the_working_directory_beats_the_vaults_directory() {
    let Some(trove) = find_trove() else { return };
    let vault_dir = TempDir::new().expect("tempdir");
    let cwd = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, vault_dir.path());

    // A local file that names the WRONG password: if it is the one used, the
    // unlock fails, which is what proves precedence rather than a lucky pass.
    std::fs::write(
        cwd.path().join(".env.trove"),
        "TROVE_DB_PASSWORD=not-the-vault-password\n",
    )
    .expect("write local .env.trove");

    let out = run_in(
        &trove,
        cwd.path(),
        &["list", "--vault", vault.to_str().unwrap(), "--env"],
        "",
        &[],
    );
    assert!(
        !out.status.success(),
        "the working directory's file must be preferred, wrong password and all"
    );
}

/// With no file anywhere, the error names every place that was tried — a bare
/// "No such file or directory" about a path the user never typed is a riddle.
#[test]
fn a_missing_env_file_reports_where_it_looked() {
    let Some(trove) = find_trove() else { return };
    let vault_dir = TempDir::new().expect("tempdir");
    let cwd = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, vault_dir.path());
    std::fs::remove_file(vault_dir.path().join(".env.trove")).expect("remove fixture env file");

    let out = run_in(
        &trove,
        cwd.path(),
        &["list", "--vault", vault.to_str().unwrap(), "--env"],
        "",
        &[],
    );
    assert!(!out.status.success(), "no file anywhere should fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("looked in"),
        "the error should say where it looked: {err}"
    );
    assert!(
        err.contains(vault_dir.path().to_str().expect("utf8")),
        "including the vault's directory: {err}"
    );
}

/// An env file holds a vault password, so a group/world-readable one is worth
/// saying out loud — but only saying, by default. See `check_env_file_perms`:
/// the file may live in a synced folder or on a `noowners` volume, where the
/// mode bits are not the user's doing and not theirs to fix.
#[cfg(unix)]
#[test]
fn a_world_readable_env_file_warns_but_still_works() {
    use std::os::unix::fs::PermissionsExt;
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    std::fs::set_permissions(
        tmp.path().join(".env.trove"),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("chmod 644");

    let out = run_in(
        &trove,
        tmp.path(),
        &["list", "--vault", vault.to_str().unwrap(), "--env"],
        "",
        &[],
    );
    assert!(
        out.status.success(),
        "a warning must not fail the unlock: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("0644"), "names the mode: {err}");
    assert!(err.contains("chmod 600"), "and the fix: {err}");
}

/// `TROVE_ENV_STRICT=1` opts into ssh's behaviour — refuse rather than warn.
#[cfg(unix)]
#[test]
fn strict_mode_refuses_a_world_readable_env_file() {
    use std::os::unix::fs::PermissionsExt;
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    std::fs::set_permissions(
        tmp.path().join(".env.trove"),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("chmod 644");

    let out = run_in(
        &trove,
        tmp.path(),
        &["list", "--vault", vault.to_str().unwrap(), "--env"],
        "",
        &[("TROVE_ENV_STRICT", "1")],
    );
    assert!(!out.status.success(), "strict mode must refuse");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("TROVE_ENV_STRICT"),
        "and say why it refused: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 0600 is accepted in strict mode, so the gate is the mode and nothing else.
    std::fs::set_permissions(
        tmp.path().join(".env.trove"),
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("chmod 600");
    let out = run_in(
        &trove,
        tmp.path(),
        &["list", "--vault", vault.to_str().unwrap(), "--env"],
        "",
        &[("TROVE_ENV_STRICT", "1")],
    );
    assert!(
        out.status.success(),
        "0600 passes strict mode: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
