//! Passkeys stored the KeePassXC way, as the `trove` binary shows them:
//! `show`, `show --json`, `describe --json`, `list --json` and `search --json`,
//! offline and through the daemon. The private key never reaches stdout
//! unless asked for with `--attr KPEX_PASSKEY_PRIVATE_KEY_PEM --show-protected`.

#![allow(missing_docs)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use trove_core::Database;

const PW: &str = "passkey-e2e-pw";
const PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----";
const KEY_MARKER: &str = "MIGHAgEAMBMGByqGSM49";

/// The attributes KeePassXC 2.8.0 writes for a passkey, with its Protected
/// flags.
const PASSKEY: [(&str, &str, bool); 7] = [
    ("KPEX_PASSKEY_USERNAME", "alice", false),
    ("KPEX_PASSKEY_CREDENTIAL_ID", "q7UwRd2kTcGg9w", true),
    ("KPEX_PASSKEY_PRIVATE_KEY_PEM", PEM, true),
    ("KPEX_PASSKEY_RELYING_PARTY", "webauthn.io", false),
    ("KPEX_PASSKEY_USER_HANDLE", "dXNlci1oYW5kbGU", true),
    ("KPEX_PASSKEY_FLAG_BE", "1", false),
    ("KPEX_PASSKEY_FLAG_BS", "1", false),
];

fn find_trove() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_trove")?);
    p.exists().then_some(p)
}

fn run(trove: &Path, env: &[(&str, &str)], args: &[&str], stdin: &str) -> Output {
    let mut cmd = Command::new(trove);
    cmd.args(args)
        .env_remove("TROVE_SESSION")
        .env_remove("TROVE_DATABASE")
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

fn stdout_ok(out: &Output, what: &str) -> String {
    assert!(
        out.status.success(),
        "{what} should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        !stdout.contains(KEY_MARKER),
        "{what}: the private key reached stdout:\n{stdout}"
    );
    stdout
}

fn json_ok(out: &Output, what: &str) -> Value {
    let stdout = stdout_ok(out, what);
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{what}: not JSON ({e}):\n{stdout}"))
}

/// A database with `Web/site` holding a KeePassXC-shaped passkey and
/// `Web/plain` holding none.
fn seed(dir: &Path) -> PathBuf {
    let path = dir.join("p.kdbx");
    let mut database = Database::create(&path, PW).unwrap();
    database.add_entry("Web/site").unwrap();
    database.add_entry("Web/plain").unwrap();
    database.save().unwrap();
    drop(database);

    let key = || keepass::DatabaseKey::new().with_password(PW);
    let mut db = keepass::Database::open(&mut std::fs::File::open(&path).unwrap(), key()).unwrap();
    let entry_id = db
        .iter_all_entries()
        .find(|e| e.get_title() == Some("site"))
        .unwrap()
        .id();
    {
        let mut entry = db.entry_mut(entry_id).unwrap();
        for (k, v, protected) in PASSKEY {
            if protected {
                entry.set_protected(k, v);
            } else {
                entry.set_unprotected(k, v);
            }
        }
    }
    db.save(&mut std::fs::File::create(&path).unwrap(), key())
        .unwrap();
    path
}

fn by_title<'a>(items: &'a Value, title: &str) -> &'a Value {
    items
        .as_array()
        .expect("array")
        .iter()
        .find(|v| v["title"] == title)
        .unwrap_or_else(|| panic!("no {title} in {items}"))
}

fn expected_passkey() -> Value {
    serde_json::json!({
        "relying_party": "webauthn.io",
        "username": "alice",
        "credential_id": "q7UwRd2kTcGg9w",
        "user_handle": "dXNlci1oYW5kbGU",
    })
}

/// The checks both modes share. `call` runs trove with the right database
/// selection for its mode.
fn check_outputs(call: &dyn Fn(&[&str]) -> Output) {
    let show = stdout_ok(&call(&["show", "Web/site"]), "show");
    assert!(
        show.lines().any(|l| l == "Passkey: webauthn.io (alice)"),
        "show:\n{show}"
    );
    let plain = stdout_ok(&call(&["show", "Web/plain"]), "show plain");
    assert!(!plain.contains("Passkey:"), "show plain:\n{plain}");

    let json = json_ok(&call(&["show", "Web/site", "--json"]), "show --json");
    assert_eq!(json["passkey"], expected_passkey());
    assert!(
        json["fields"].get("KPEX_PASSKEY_PRIVATE_KEY_PEM").is_none(),
        "protected field listed without --show-protected: {json}"
    );
    let json = json_ok(&call(&["show", "Web/plain", "--json"]), "show plain --json");
    assert_eq!(json["passkey"], Value::Null);

    let described = json_ok(&call(&["describe", "Web", "--json"]), "describe --json");
    assert_eq!(by_title_path(&described, "Web/site")["has_passkey"], true);
    assert_eq!(by_title_path(&described, "Web/plain")["has_passkey"], false);

    let list = json_ok(&call(&["list", "--json"]), "list --json");
    assert_eq!(by_title(&list, "site")["passkey"], true);
    assert_eq!(by_title(&list, "plain")["passkey"], false);

    let hits = json_ok(&call(&["search", "Web", "--json"]), "search --json");
    assert_eq!(by_title(&hits, "site")["passkey"], true);
    assert_eq!(by_title(&hits, "plain")["passkey"], false);

    let refused = call(&["show", "Web/site", "--attr", "KPEX_PASSKEY_PRIVATE_KEY_PEM"]);
    assert!(!refused.status.success(), "the key needs --show-protected");
    assert!(!String::from_utf8_lossy(&refused.stdout).contains(KEY_MARKER));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--show-protected"),
        "stderr: {}",
        String::from_utf8_lossy(&refused.stderr)
    );

    let key = call(&[
        "show",
        "Web/site",
        "--attr",
        "KPEX_PASSKEY_PRIVATE_KEY_PEM",
        "--show-protected",
    ]);
    assert!(key.status.success());
    assert_eq!(String::from_utf8_lossy(&key.stdout).trim_end(), PEM);
}

fn by_title_path<'a>(items: &'a Value, path: &str) -> &'a Value {
    items
        .as_array()
        .expect("array")
        .iter()
        .find(|v| v["path"] == path)
        .unwrap_or_else(|| panic!("no {path} in {items}"))
}

#[test]
fn passkey_outputs_offline() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let database = seed(dir.path());
    let database = database.to_str().unwrap();
    let pw = format!("{PW}\n");
    check_outputs(&|args: &[&str]| {
        let mut full = vec!["--database", database, "--password-stdin"];
        full.extend_from_slice(args);
        run(&trove, &[], &full, &pw)
    });
}

#[cfg(unix)]
mod daemon_mode {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::process::Child;
    use std::time::{Duration, Instant};

    /// Kills the daemon this test started, by its own handle.
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
    fn passkey_outputs_through_the_daemon() {
        let Some(trove) = find_trove() else {
            eprintln!("skipping: trove binary not built");
            return;
        };
        let Some(troved) = trove
            .parent()
            .map(|p| p.join("troved"))
            .filter(|p| p.is_file())
        else {
            eprintln!("skipping: troved binary not built next to trove");
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let database = seed(dir);
        let sock = dir.join("trove.sock");
        let sock_s = sock.to_str().unwrap();
        let child = Command::new(&troved)
            .env("TROVE_SOCK", &sock)
            .env("TROVE_SSH_SOCK", dir.join("trove-ssh.sock"))
            .env("TROVE_GPG_SOCK", dir.join("trove-gpg.sock"))
            .env("TROVE_IDLE_TIMEOUT", "600")
            .env("TROVE_SSH_FORWARD", "0")
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn troved");
        let _troved = Troved(child);
        assert!(wait_connectable(&sock), "troved never came up");

        let out = run(
            &trove,
            &[("TROVE_SOCK", sock_s)],
            &[
                "unlock",
                database.to_str().unwrap(),
                "--password-stdin",
                "--export",
            ],
            &format!("{PW}\n"),
        );
        assert!(
            out.status.success(),
            "unlock: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let code = String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("export TROVE_SESSION="))
            .map(|c| c.trim().trim_matches('\'').to_string())
            .expect("session code on stdout");
        let env = [("TROVE_SOCK", sock_s), ("TROVE_SESSION", code.as_str())];
        check_outputs(&|args: &[&str]| run(&trove, &env, args, ""));
    }
}
