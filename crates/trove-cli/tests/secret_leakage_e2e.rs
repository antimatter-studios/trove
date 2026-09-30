//! Secrets must not leak into places nobody meant them to go: error messages,
//! other processes' command lines, or the daemon's log. Each test seeds a
//! vault with recognisable canary values, drives a surface, and checks every
//! output channel for them.
//!
//! The daemon half runs the real `troved` with every socket isolated in a
//! tempdir and its stderr captured; it skips when `troved` isn't built next to
//! `trove` (`cargo test --workspace` and CI build it). Clipboard auto-clear is
//! covered by clip_e2e.rs and the clip module's unit tests.

#![allow(missing_docs)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const MASTER: &str = "leak-canary-master-4e1b";
const WRONG_MASTER: &str = "leak-canary-wrong-3b9e";
const SECRET: &str = "leak-canary-secret-8c2f";
const FILE_BYTES: &str = "leak-canary-file-5a7d";
const WRONG_CODE: &str = "leak-canary-code-6f0a";

fn find_trove() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_trove")?);
    p.exists().then_some(p)
}

fn run(trove: &Path, env: &[(&str, &str)], args: &[&str], stdin: &str) -> Output {
    let mut cmd = Command::new(trove);
    cmd.args(args)
        .env_remove("TROVE_SESSION")
        .env_remove("TROVE_VAULT")
        .env_remove("SSH_AUTH_SOCK")
        .env("TROVE_NO_AUTOSPAWN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn trove");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait trove")
}

fn ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Fail if any canary appears in `text`.
fn assert_clean(what: &str, text: &str, canaries: &[&str]) {
    for c in canaries {
        assert!(!text.contains(c), "{what} leaked the canary {c:?}:\n{text}");
    }
}

/// Neither stdout nor stderr may carry a canary.
fn assert_output_clean(what: &str, out: &Output, canaries: &[&str]) {
    assert_clean(
        &format!("{what} (stdout)"),
        &String::from_utf8_lossy(&out.stdout),
        canaries,
    );
    assert_clean(
        &format!("{what} (stderr)"),
        &String::from_utf8_lossy(&out.stderr),
        canaries,
    );
}

/// A vault holding the canaries: a password entry exec can inject, and a file
/// attachment.
fn seed(trove: &Path, dir: &Path) -> String {
    let vault = dir.join("leak.kdbx");
    let vs = vault.to_str().unwrap().to_string();
    let pw = format!("{MASTER}\n");
    let offline = |args: &[&str], stdin: &str, what: &str| {
        let mut full = vec!["--vault", vs.as_str(), "--password-stdin"];
        full.extend_from_slice(args);
        ok(&run(trove, &[], &full, stdin), what);
    };
    offline(&["init"], &pw, "init");
    offline(
        &["add", "password", "Infra/svc", "--secret-stdin"],
        &format!("{MASTER}\n{SECRET}\n"),
        "add password",
    );
    offline(
        &["edit", "Infra/svc", "--set", "Exec.Env=SVC_KEY"],
        &pw,
        "set Exec.Env",
    );
    let src = dir.join("cfg");
    std::fs::write(&src, FILE_BYTES).unwrap();
    offline(
        &[
            "add",
            "file",
            "Infra/cfg",
            "--src",
            src.to_str().unwrap(),
            "--target",
            dir.join("unused").to_str().unwrap(),
        ],
        &pw,
        "add file",
    );
    std::fs::remove_file(&src).unwrap();
    vs
}

#[test]
fn offline_errors_and_reads_do_not_leak() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let vs = seed(&trove, tmp.path());
    let all = [MASTER, WRONG_MASTER, SECRET, FILE_BYTES];
    let offline = |args: &[&str], stdin: &str| {
        let mut full = vec!["--vault", vs.as_str(), "--password-stdin"];
        full.extend_from_slice(args);
        run(&trove, &[], &full, stdin)
    };
    let pw = format!("{MASTER}\n");

    // A wrong master password is refused without echoing either password.
    let out = offline(&["show", "Infra/svc"], &format!("{WRONG_MASTER}\n"));
    assert!(!out.status.success(), "wrong master password must fail");
    assert_output_clean("show with the wrong password", &out, &all);

    // Reads that don't ask for protected values don't print them.
    for args in [
        &["show", "Infra/svc"][..],
        &["show", "Infra/svc", "--json"],
        &["describe", "Infra", "--json"],
        &["list", "--json"],
        &["search", "svc"],
    ] {
        let out = offline(args, &pw);
        ok(&out, &args.join(" "));
        assert_output_clean(&args.join(" "), &out, &all);
    }

    // Error paths that touch the secret's entry.
    for args in [
        &["show", "Infra/svc", "--attr", "Nope"][..],
        &["clip", "Infra/svc", "--attr", "Nope"],
        &["exec", "Infra/svc", "--", "/nonexistent/leak-probe"],
    ] {
        let out = offline(args, &pw);
        assert!(!out.status.success(), "{} should fail", args.join(" "));
        assert_output_clean(&args.join(" "), &out, &all);
    }
}

/// `exec` hands the secret over in the environment and a private file, never
/// on a command line: while the child runs, no process on the machine shows a
/// canary in its argv.
#[cfg(unix)]
#[test]
fn exec_keeps_secrets_off_every_command_line() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let vs = seed(&trove, tmp.path());
    let dump = tmp.path().join("ps.txt");
    let script = format!(
        "test -n \"$SVC_KEY\" && ps -A -o args= > '{}'",
        dump.display()
    );
    let out = run(
        &trove,
        &[],
        &[
            "--vault",
            &vs,
            "--password-stdin",
            "exec",
            "Infra",
            "--",
            "sh",
            "-c",
            &script,
        ],
        &format!("{MASTER}\n"),
    );
    ok(&out, "exec");
    assert_output_clean("exec", &out, &[MASTER, SECRET, FILE_BYTES]);
    let ps = std::fs::read_to_string(&dump).expect("ps dump");
    assert!(ps.contains("ps -A"), "ps dump looks empty:\n{ps}");
    assert_clean(
        "argv of running processes",
        &ps,
        &[MASTER, SECRET, FILE_BYTES],
    );
}

#[cfg(unix)]
mod daemon {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::process::Child;
    use std::time::{Duration, Instant};

    /// Kills the daemon (by its own PID) however the test ends.
    struct Troved(Child);

    impl Drop for Troved {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn wait_connectable(path: &Path) -> bool {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if UnixStream::connect(path).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }

    #[test]
    fn daemon_errors_and_log_do_not_leak() {
        let Some(trove) = find_trove() else {
            eprintln!("skipping: trove binary not built");
            return;
        };
        let troved = trove.with_file_name("troved");
        if !troved.is_file() {
            eprintln!("skipping: troved binary not built next to trove");
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path();
        let vs = seed(&trove, dir);

        let sock = dir.join("trove.sock");
        let sock_s = sock.to_str().unwrap();
        let log_path = dir.join("troved.log");
        let log = std::fs::File::create(&log_path).expect("create log");
        let child = Command::new(&troved)
            .env("TROVE_SOCK", &sock)
            .env("TROVE_SSH_SOCK", dir.join("trove-ssh.sock"))
            .env("TROVE_GPG_SOCK", dir.join("trove-gpg.sock"))
            .env("TROVE_IDLE_TIMEOUT", "600")
            .env("TROVE_SSH_FORWARD", "0")
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn troved");
        let mut troved = Troved(child);
        assert!(wait_connectable(&sock), "troved never came up");

        let env = [("TROVE_SOCK", sock_s)];
        let unlock = ["unlock", vs.as_str(), "--password-stdin", "--export"];

        // A wrong password first: refused, and not echoed.
        let out = run(&trove, &env, &unlock, &format!("{WRONG_MASTER}\n"));
        assert!(!out.status.success(), "unlock with the wrong password");
        assert_output_clean("unlock with the wrong password", &out, &[WRONG_MASTER]);

        let out = run(&trove, &env, &unlock, &format!("{MASTER}\n"));
        ok(&out, "unlock");
        assert_clean(
            "unlock (stderr)",
            &String::from_utf8_lossy(&out.stderr),
            &[MASTER, SECRET, FILE_BYTES],
        );
        let code = String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("export TROVE_SESSION="))
            .map(|c| c.trim().trim_matches('\'').to_string())
            .expect("session code on stdout");
        let session = [("TROVE_SOCK", sock_s), ("TROVE_SESSION", code.as_str())];
        let all = [MASTER, WRONG_MASTER, SECRET, FILE_BYTES, code.as_str()];

        let out = run(&trove, &session, &["show", "Infra/svc", "--json"], "");
        ok(&out, "show (daemon)");
        assert_output_clean("show (daemon)", &out, &all);

        // Reading the secret on purpose works, so the log check below sees a
        // daemon that has actually served it.
        let out = run(
            &trove,
            &session,
            &["show", "Infra/svc", "--show-protected", "--json"],
            "",
        );
        ok(&out, "show --show-protected (daemon)");
        assert!(String::from_utf8_lossy(&out.stdout).contains(SECRET));

        // A forged session code is refused without echoing it.
        let forged = [("TROVE_SOCK", sock_s), ("TROVE_SESSION", WRONG_CODE)];
        let out = run(
            &trove,
            &forged,
            &["show", "Infra/svc", "--show-protected"],
            "",
        );
        assert!(!out.status.success(), "forged session code must be refused");
        assert_output_clean(
            "forged session code",
            &out,
            &[&all[..], &[WRONG_CODE]].concat(),
        );

        let out = run(&trove, &session, &["show", "Infra/nope"], "");
        assert!(!out.status.success(), "missing entry must fail");
        assert_output_clean("missing entry (daemon)", &out, &all);

        ok(&run(&trove, &session, &["lock"], ""), "lock");
        let _ = troved.0.kill();
        let _ = troved.0.wait();

        let log = std::fs::read_to_string(&log_path).expect("read troved log");
        assert!(log.contains("troved"), "troved log looks empty:\n{log}");
        assert_clean("troved log", &log, &[&all[..], &[WRONG_CODE]].concat());
    }
}
