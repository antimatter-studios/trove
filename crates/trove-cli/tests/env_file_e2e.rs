//! End-to-end tests for `--env`: load a `.env.trove.yaml` before running, so a
//! vault opens without a prompt, a pipeline, or a password on the command line.
//!
//! Three forms, all exercised below: bare `--env` (`./.env.trove.yaml` in the
//! current directory), `--env <dir>` (that directory's `.env.trove.yaml`), and
//! `--env <file>`. The retired dotenv `.env.trove` is refused with directions.
//!
//! Two properties matter beyond "it works":
//!   * A variable already set in the environment WINS over the file, so the
//!     file supplies defaults and never overrides an explicit caller.
//!   * The password is taken from the environment ONLY when `--env` was passed.
//!     An exported `TROVE_VAULT_PASSWORD` must never silently unlock a vault for a
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
        .env_remove("TROVE_VAULT_PASSWORD")
        .env_remove("TROVE_VAULT")
        .env_remove("TROVE_ENV_STRICT")
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

const ENV_FILE: &str = ".env.trove.yaml";

/// A vault with one entry, plus a `.env.trove.yaml` in `dir` naming its password.
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
        dir.join(ENV_FILE),
        format!("# vault credentials\ndatabases:\n  v.kdbx: \"{PASSWORD}\"\n"),
    )
    .expect("write .env.trove.yaml");
    vault
}

fn write_suffix_credentials(path: &Path, entries: &[(&str, &str)]) {
    let databases: std::collections::BTreeMap<_, _> = entries.iter().copied().collect();
    let text = serde_yaml::to_string(&serde_json::json!({"databases": databases}))
        .expect("serialize credentials");
    std::fs::write(path, text).expect("write credentials");
}

#[test]
fn yaml_path_suffixes_disambiguate_same_named_vaults() {
    let trove = find_trove().expect("cargo-built trove");
    let tmp = TempDir::new().expect("tempdir");
    let credentials = tmp.path().join(".env.trove.yaml");
    write_suffix_credentials(
        &credentials,
        &[
            ("v.kdbx", "fallback-password"),
            ("docs/v.kdbx", "wrong-generic-password"),
            ("lab/docs/v.kdbx", "wrong-partial-directory-password"),
            ("homelab/docs/v.kdbx", "homelab-password"),
            ("icloud/docs/v.kdbx", "icloud-password"),
        ],
    );
    let env_arg = format!("--env={}", credentials.display());

    for (directory, password) in [
        ("homelab/docs", "homelab-password"),
        ("icloud/docs", "icloud-password"),
        ("archive", "fallback-password"),
    ] {
        let dir = tmp.path().join(directory);
        std::fs::create_dir_all(&dir).expect("create vault directory");
        let vault = dir.join("v.kdbx");
        let init = run_in(
            &trove,
            &dir,
            &["init", "--vault", "v.kdbx", "--password-stdin"],
            &format!("{password}\n"),
            &[],
        );
        assert!(
            init.status.success(),
            "init: {}",
            String::from_utf8_lossy(&init.stderr)
        );

        // A bare filename must still match its parent directories from cwd.
        for path in ["v.kdbx", vault.to_str().unwrap()] {
            let out = run_in(&trove, &dir, &["list", "--vault", path, &env_arg], "", &[]);
            assert!(
                out.status.success(),
                "{directory} ({path}): {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

#[test]
fn yaml_path_suffixes_do_not_match_partial_components() {
    let trove = find_trove().expect("cargo-built trove");
    let tmp = TempDir::new().expect("tempdir");
    let dir = tmp.path().join("homelab");
    std::fs::create_dir_all(&dir).expect("create vault directory");
    let vault = fixture(&trove, &dir);
    let credentials = tmp.path().join(".env.trove.yaml");
    write_suffix_credentials(
        &credentials,
        &[("lab/v.kdbx", PASSWORD), ("kdbx", PASSWORD)],
    );
    let out = run_in(
        &trove,
        &dir,
        &[
            "list",
            "--vault",
            vault.to_str().unwrap(),
            &format!("--env={}", credentials.display()),
        ],
        "",
        &[],
    );
    assert!(
        !out.status.success(),
        "partial components must not supply a password"
    );
}

#[cfg(unix)]
#[test]
fn unlock_preserves_alias_suffixes_and_legacy_canonical_filenames() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::{fs::symlink, net::UnixListener};
    use std::time::Duration;

    let trove = find_trove().expect("cargo-built trove");
    // Keep the socket below macOS's Unix-domain socket path length limit.
    let tmp = tempfile::Builder::new()
        .prefix("trove-suffix-")
        .tempdir_in("/tmp")
        .expect("tempdir");
    let storage = tmp.path().join("storage");
    std::fs::create_dir(&storage).expect("create storage");
    let vault = fixture(&trove, &storage);
    let alias = tmp.path().join("homelab");
    symlink(&storage, &alias).expect("create alias");
    symlink(&vault, tmp.path().join("renamed.kdbx")).expect("create renamed file alias");
    let credentials = tmp.path().join(".env.trove.yaml");
    write_suffix_credentials(
        &credentials,
        &[
            ("v.kdbx", "legacy-password"),
            ("homelab/v.kdbx", "alias-password"),
        ],
    );
    let socket = tmp.path().join("control.sock");
    let listener = UnixListener::bind(&socket).expect("bind isolated mock daemon");
    let server = std::thread::spawn(move || {
        let mut requests = Vec::new();
        // Each unlock is followed by a list request for shell exports.
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().expect("accept unlock");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout");
            let mut line = String::new();
            BufReader::new(stream.try_clone().expect("clone stream"))
                .read_line(&mut line)
                .expect("read unlock");
            let request: serde_json::Value = serde_json::from_str(&line).expect("unlock JSON");
            match request["cmd"].as_str() {
                Some("unlock") => {
                    stream
                        .write_all(b"{\"status\":\"ok\",\"code\":\"test-session\"}\n")
                        .expect("unlock reply");
                    requests.push(request);
                }
                Some("list") => {
                    stream
                        .write_all(b"{\"status\":\"ok\",\"entries\":[]}\n")
                        .expect("list reply");
                }
                cmd => panic!("unexpected mock command: {cmd:?}"),
            }
        }
        requests
    });
    for path in ["homelab/v.kdbx", "renamed.kdbx"] {
        let out = run_in(
            &trove,
            tmp.path(),
            &[
                "unlock",
                path,
                &format!("--env={}", credentials.display()),
                "--export",
            ],
            "",
            &[
                ("TROVE_SOCK", socket.to_str().unwrap()),
                ("TROVE_NO_AUTOSPAWN", "1"),
                ("TROVE_NO_VERSION_WARN", "1"),
            ],
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let requests = server.join().expect("mock daemon");
    assert_eq!(
        requests[0]["password"], "alias-password",
        "alias-specific credentials must win"
    );
    assert_eq!(requests[1]["password"], "legacy-password");
    for request in requests {
        assert_eq!(
            request["path"],
            std::fs::canonicalize(&vault).unwrap().to_str().unwrap()
        );
    }
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

    // Run from a directory with no .env.trove.yaml of its own, pointing at the one
    // that has it.
    let out = run_in(
        &trove,
        elsewhere.path(),
        &[
            "list",
            "--vault",
            vault.to_str().unwrap(),
            &format!("--env={}", tmp.path().display()),
        ],
        "",
        &[],
    );
    assert!(
        out.status.success(),
        "--env=<dir> should find <dir>/.env.trove.yaml: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn env_accepts_an_explicit_file_path() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    let renamed = tmp.path().join("credentials.yaml");
    std::fs::rename(tmp.path().join(ENV_FILE), &renamed).expect("rename");

    let out = run_in(
        &trove,
        tmp.path(),
        &[
            "list",
            "--vault",
            vault.to_str().unwrap(),
            &format!("--env={}", renamed.display()),
        ],
        "",
        &[],
    );
    assert!(
        out.status.success(),
        "--env=<file> should read that file: {}",
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
        &[("TROVE_VAULT_PASSWORD", "not-the-password")],
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
        &[("TROVE_VAULT_PASSWORD", PASSWORD)],
    );
    assert!(
        !out.status.success(),
        "TROVE_VAULT_PASSWORD must not unlock a vault unless --env opted in"
    );
}

#[test]
fn a_missing_env_file_is_an_error_not_a_silent_prompt() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    std::fs::remove_file(tmp.path().join(ENV_FILE)).expect("remove");

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
        err.contains(ENV_FILE),
        "the error should name the file it looked for, got: {err}"
    );
}

#[test]
fn other_trove_variables_load_from_the_file_too() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    // `--env` is a general loader, not only a password mechanism: anything
    // under `environment:` lands in the environment. A bare YAML number is
    // taken as its text, so `1` needs no quotes.
    std::fs::write(
        tmp.path().join(ENV_FILE),
        format!("databases:\n  v.kdbx: \"{PASSWORD}\"\nenvironment:\n  TROVE_NO_VERSION_WARN: 1\n"),
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
        "an `environment:` section should load: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("and 1 variable(s)"),
        "and count the variable it set: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Bare `--env` falls back to the vault's own directory.
///
/// Keeping `work.kdbx` and `.env.trove.yaml` together is the natural layout, and
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
        !elsewhere.path().join(ENV_FILE).exists(),
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
        "should find the vault's own .env.trove.yaml: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("loaded 1 database password"),
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
        cwd.path().join(ENV_FILE),
        "databases:\n  v.kdbx: \"not-the-vault-password\"\n",
    )
    .expect("write local .env.trove.yaml");

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
    std::fs::remove_file(vault_dir.path().join(ENV_FILE)).expect("remove fixture env file");

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
        tmp.path().join(ENV_FILE),
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

/// Strict mode checks and reads one opened file, and the Unix open refuses a
/// symlink that could redirect the credential path.
#[cfg(unix)]
#[test]
fn env_file_does_not_follow_symlinks() {
    use std::os::unix::fs::symlink;
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    std::fs::rename(
        tmp.path().join(ENV_FILE),
        tmp.path().join("credentials.yaml"),
    )
    .expect("rename env file");
    symlink(
        tmp.path().join("credentials.yaml"),
        tmp.path().join(ENV_FILE),
    )
    .expect("symlink env file");

    let out = run_in(
        &trove,
        tmp.path(),
        &["list", "--vault", vault.to_str().unwrap(), "--env"],
        "",
        &[],
    );
    assert!(!out.status.success(), "env file symlinks must be rejected");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("opening env file"),
        "expected an open error: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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
        tmp.path().join(ENV_FILE),
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
        tmp.path().join(ENV_FILE),
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

/// `--keychain` can raise a system dialog, and a dialog in a shell with no
/// terminal is a hang that costs someone their remote session. So it refuses
/// there, and it loses to every source that cannot hang.
#[cfg(target_os = "macos")]
#[test]
fn keychain_refuses_without_a_terminal_and_never_outranks_the_others() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());

    // `run_in` gives the child pipes, not a tty — exactly the agent case.
    let out = run_in(
        &trove,
        tmp.path(),
        &["list", "--vault", vault.to_str().unwrap(), "--keychain"],
        "",
        &[],
    );
    assert!(!out.status.success(), "must refuse without a terminal");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("interactive terminal"),
        "explaining why: {err}"
    );
    assert!(
        err.contains("--env") && err.contains("--password-stdin"),
        "and what to use instead: {err}"
    );

    // With --env alongside it, the file wins and the run succeeds — the
    // keychain is not consulted at all, so its terminal requirement is moot.
    let out = run_in(
        &trove,
        tmp.path(),
        &[
            "list",
            "--vault",
            vault.to_str().unwrap(),
            "--env",
            "--keychain",
        ],
        "",
        &[],
    );
    assert!(
        out.status.success(),
        "--env outranks --keychain: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--keychain ignored"),
        "and says which source won"
    );
}

/// The bug `require_equals` exists to fix, at the level it actually bit.
///
/// `git config credential.helper "trove --vault v --env git-credential"` has
/// git append the operation, so trove sees `--env git-credential get`. With an
/// optional value and no `=`, `--env` took `git-credential` as its path and
/// `get` became the subcommand — so the one command `--env` was written to
/// serve was the one command it broke, and silently, by running a different
/// one.
#[test]
fn a_bare_env_does_not_swallow_the_subcommand() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());

    let out = run_in(
        &trove,
        tmp.path(),
        &[
            "--vault",
            vault.to_str().unwrap(),
            "--env",
            "git-credential",
            "get",
        ],
        "protocol=https\nhost=example.com\n\n",
        &[],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Usage: trove get"),
        "--env must not eat the subcommand and leave `get` running: {stderr}"
    );
    assert!(
        out.status.success(),
        "the credential helper should run: {stderr}"
    );
}

/// The cost of requiring `=`: the space-separated form now fails. It must fail
/// by naming the fix, not as `unrecognized subcommand '/some/path'`, which
/// describes the symptom and hides the cause.
#[test]
fn the_space_separated_form_says_what_to_type_instead() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    let env_path = tmp.path().join(ENV_FILE);

    let out = run_in(
        &trove,
        tmp.path(),
        &[
            "list",
            "--vault",
            vault.to_str().unwrap(),
            "--env",
            env_path.to_str().unwrap(),
        ],
        "",
        &[],
    );
    assert!(!out.status.success(), "the space form should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!("--env={}", env_path.display())),
        "the error should show the exact fix: {stderr}"
    );
}

#[test]
fn environment_trove_vault_selects_the_default_offline_vault() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    std::fs::write(
        tmp.path().join(ENV_FILE),
        format!(
            "databases:\n  v.kdbx: \"{PASSWORD}\"\nenvironment:\n  TROVE_VAULT: \"{}\"\n",
            vault.display()
        ),
    )
    .expect("write .env.trove.yaml");

    let out = run_in(&trove, tmp.path(), &["db-info", "--json", "--env"], "", &[]);
    assert!(
        out.status.success(),
        "TROVE_VAULT should select the offline vault: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let info: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON db-info");
    assert_eq!(info["path"], vault.to_string_lossy().as_ref());
}

#[test]
fn explicit_vault_flag_overrides_trove_vault_from_env_file() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    std::fs::write(
        tmp.path().join(ENV_FILE),
        format!(
            "databases:\n  v.kdbx: \"{PASSWORD}\"\nenvironment:\n  TROVE_VAULT: /does/not/exist.kdbx\n"
        ),
    )
    .expect("write .env.trove.yaml");

    let out = run_in(
        &trove,
        tmp.path(),
        &[
            "db-info",
            "--json",
            "--vault",
            vault.to_str().unwrap(),
            "--env",
        ],
        "",
        &[],
    );
    assert!(
        out.status.success(),
        "--vault must win over TROVE_VAULT: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let info: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON db-info");
    assert_eq!(info["path"], vault.to_string_lossy().as_ref());
}

#[test]
fn exported_trove_vault_selects_offline_mode_without_env_file() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());

    let out = run_in(
        &trove,
        tmp.path(),
        &["db-info", "--json", "--password-stdin"],
        &format!("{PASSWORD}\n"),
        &[("TROVE_VAULT", vault.to_str().unwrap())],
    );
    assert!(
        out.status.success(),
        "exported TROVE_VAULT should select the offline vault: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let info: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON db-info");
    assert_eq!(info["path"], vault.to_string_lossy().as_ref());
}

/// Run `trove list --env` in `cwd` and return its stderr, asserting it failed.
fn env_list_fails(trove: &Path, cwd: &Path, vault: &Path) -> String {
    let out = run_in(
        trove,
        cwd,
        &["list", "--vault", vault.to_str().unwrap(), "--env"],
        "",
        &[],
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!out.status.success(), "should fail: {stderr}");
    stderr
}

/// The retired `.env.trove` is never read. Finding one where the new file
/// belongs fails and says how to convert it, instead of falling back to a
/// prompt that leaves the user guessing why their password stopped working.
#[test]
fn a_retired_env_trove_is_refused_with_directions() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    std::fs::rename(tmp.path().join(ENV_FILE), tmp.path().join(".env.trove"))
        .expect("rename to the retired name");

    let err = env_list_fails(&trove, tmp.path(), &vault);
    assert!(err.contains(".env.trove "), "names the old file: {err}");
    assert!(err.contains(ENV_FILE), "names the new file: {err}");
    assert!(err.contains("databases:"), "shows the new layout: {err}");
}

/// A retired file in the working directory stops the search there: carrying on
/// to the vault's directory would hide it behind whatever is found next.
#[test]
fn a_retired_env_trove_stops_the_search_even_when_a_new_file_exists_further_on() {
    let Some(trove) = find_trove() else { return };
    let vault_dir = TempDir::new().expect("tempdir");
    let cwd = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, vault_dir.path());
    std::fs::write(
        cwd.path().join(".env.trove"),
        format!("TROVE_VAULT_PASSWORD={PASSWORD}\n"),
    )
    .expect("write retired file");

    let err = env_list_fails(&trove, cwd.path(), &vault);
    assert!(err.contains("databases:"), "says how to convert: {err}");
}

/// `--env=<dir>` naming a directory that only holds the retired file says so,
/// rather than reporting a missing file.
#[test]
fn env_dir_with_only_a_retired_file_says_how_to_convert_it() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    std::fs::rename(tmp.path().join(ENV_FILE), tmp.path().join(".env.trove"))
        .expect("rename to the retired name");
    let elsewhere = TempDir::new().expect("tempdir");

    let out = run_in(
        &trove,
        elsewhere.path(),
        &[
            "list",
            "--vault",
            vault.to_str().unwrap(),
            &format!("--env={}", tmp.path().display()),
        ],
        "",
        &[],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "should fail: {err}");
    assert!(err.contains("databases:"), "says how to convert: {err}");
}

/// Dotenv lines are refused even under the new name: the format is retired,
/// not just the filename.
#[test]
fn dotenv_lines_in_the_new_file_are_refused() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    std::fs::write(
        tmp.path().join(ENV_FILE),
        format!("TROVE_VAULT_PASSWORD={PASSWORD}\n"),
    )
    .expect("write dotenv lines");

    let err = env_list_fails(&trove, tmp.path(), &vault);
    assert!(err.contains("databases:"), "says how to convert: {err}");
}

/// The old bare `filename: password` map is refused too: passwords now live
/// under `databases:`.
#[test]
fn a_bare_filename_to_password_map_is_refused() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    std::fs::write(
        tmp.path().join(ENV_FILE),
        format!("v.kdbx: \"{PASSWORD}\"\n"),
    )
    .expect("write bare map");

    let err = env_list_fails(&trove, tmp.path(), &vault);
    assert!(err.contains("databases:"), "says how to convert: {err}");
}

/// A password smuggled in through `environment:` is refused, so there is one
/// place a password can be and one thing to audit.
#[test]
fn environment_cannot_carry_a_vault_password() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let vault = fixture(&trove, tmp.path());
    std::fs::write(
        tmp.path().join(ENV_FILE),
        format!("environment:\n  TROVE_VAULT_PASSWORD: \"{PASSWORD}\"\n"),
    )
    .expect("write");

    let err = env_list_fails(&trove, tmp.path(), &vault);
    assert!(
        err.contains("TROVE_VAULT_PASSWORD") && err.contains("databases:"),
        "names the variable and where passwords go: {err}"
    );
}

/// One file holds several vaults' passwords, each matched by filename.
#[test]
fn each_vault_gets_the_password_named_by_its_filename() {
    let Some(trove) = find_trove() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let mut vaults = Vec::new();
    for (name, password) in [("a.kdbx", "alpha-pw"), ("b.kdbx", "beta-pw")] {
        let vault = tmp.path().join(name);
        let out = run_in(
            &trove,
            tmp.path(),
            &[
                "init",
                "--vault",
                vault.to_str().unwrap(),
                "--password-stdin",
            ],
            &format!("{password}\n"),
            &[],
        );
        assert!(out.status.success(), "init {name}");
        vaults.push(vault);
    }
    std::fs::write(
        tmp.path().join(ENV_FILE),
        "databases:\n  a.kdbx: \"alpha-pw\"\n  b.kdbx: \"beta-pw\"\n",
    )
    .expect("write");

    for vault in &vaults {
        let out = run_in(
            &trove,
            tmp.path(),
            &["list", "--vault", vault.to_str().unwrap(), "--env"],
            "",
            &[],
        );
        assert!(
            out.status.success(),
            "{} should open with its own password: {}",
            vault.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
