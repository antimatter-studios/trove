//! Pins the shape of every `--json` output: key names, value types and
//! nesting, never the values. docs/stability.md lets a minor release add a
//! field but not rename, remove or retype one, so an accidental change must
//! fail here. A deliberate change updates the spec below and the "JSON output"
//! section of docs/cli-reference.md together.
//!
//! Offline commands run against a seeded vault file. Daemon-backed commands run
//! against the real `troved` binary with every socket isolated in a tempdir;
//! that part skips when `troved` isn't built next to `trove` (`cargo test -p
//! trove-cli` alone doesn't build it; `cargo test --workspace` and CI do).
//! `keychain status --json` needs a terminal and a keychain, so its shape is
//! pinned by a unit test in main.rs instead.

#![allow(missing_docs)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};
use trove_core::Vault;

const PW: &str = "json-shapes-e2e-pw";

fn find_trove() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_trove")?);
    p.exists().then_some(p)
}

/// Run `trove` with `env` set, `SSH_AUTH_SOCK`/`TROVE_SESSION` cleared unless
/// `env` sets them, and never autospawning a daemon.
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

/// Parse stdout as JSON. `expect_ok` is false only for `analyze`, which exits
/// 1 when it has findings and still prints its JSON.
fn json_out(out: &Output, what: &str, expect_ok: bool) -> Value {
    assert!(
        out.status.success() == expect_ok,
        "{what}: unexpected exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{what}: stdout is not JSON ({e}):\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "number",
        Value::Number(_) => "integer",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Compare `actual` against a shape spec:
///
/// - a string names the JSON type: `string`, `integer`, `number` (any
///   number), `bool` or `null`, with alternatives joined by `|`;
/// - an object lists every key, no more and no fewer, unless its only key is
///   `*`, which means "any keys, each value shaped like this";
/// - `[]` means the array must be empty; `[a]` means every item matches `a`;
///   `[a, b]` means every item matches `a` or `b`.
fn check(at: &str, actual: &Value, spec: &Value, errs: &mut Vec<String>) {
    match spec {
        Value::String(types) => {
            let got = type_name(actual);
            let ok = types
                .split('|')
                .any(|t| t == got || (t == "number" && got == "integer"));
            if !ok {
                errs.push(format!("{at}: expected {types}, got {got}"));
            }
        }
        Value::Array(items_spec) => {
            let Some(items) = actual.as_array() else {
                errs.push(format!("{at}: expected array, got {}", type_name(actual)));
                return;
            };
            if items_spec.is_empty() && !items.is_empty() {
                errs.push(format!("{at}: expected an empty array"));
            }
            for (i, item) in items.iter().enumerate() {
                let at = format!("{at}[{i}]");
                if let [only] = items_spec.as_slice() {
                    check(&at, item, only, errs);
                } else if !items_spec.iter().any(|s| {
                    let mut e = Vec::new();
                    check(&at, item, s, &mut e);
                    e.is_empty()
                }) {
                    errs.push(format!("{at}: matches none of the item shapes"));
                }
            }
        }
        Value::Object(fields) => {
            let Some(obj) = actual.as_object() else {
                errs.push(format!("{at}: expected object, got {}", type_name(actual)));
                return;
            };
            if let Some(each) = fields.get("*") {
                for (k, v) in obj {
                    check(&format!("{at}.{k}"), v, each, errs);
                }
                return;
            }
            for (k, s) in fields {
                match obj.get(k) {
                    Some(v) => check(&format!("{at}.{k}"), v, s, errs),
                    None => errs.push(format!("{at}.{k}: missing")),
                }
            }
            for k in obj.keys().filter(|k| !fields.contains_key(*k)) {
                errs.push(format!("{at}.{k}: not in the documented shape"));
            }
        }
        _ => panic!("bad shape spec at {at}: {spec}"),
    }
}

fn assert_shape(what: &str, actual: &Value, spec: &Value) {
    let mut errs = Vec::new();
    check("$", actual, spec, &mut errs);
    assert!(
        errs.is_empty(),
        "`{what}` --json shape changed (update docs/cli-reference.md if deliberate):\n  {}\n\noutput:\n{}",
        errs.join("\n  "),
        serde_json::to_string_pretty(actual).unwrap()
    );
}

/// Guards against a vacuous pass: an empty array matches any item spec.
fn assert_has(what: &str, arr: &Value, key: &str, want: &str) {
    let items = arr.as_array().expect("array");
    assert!(
        items.iter().any(|v| v[key] == want),
        "{what}: expected an item with {key} = {want:?} in {arr}"
    );
}

fn entry_summary_offline() -> Value {
    json!({
        "id": "string",
        "title": "string",
        "path": "string",
        "username": "string|null",
        "url": "string|null",
        "attachments": ["string"],
        "group_path": ["string"],
        "tags": ["string"],
        "inherited_tags": ["string"],
    })
}

/// Daemon-mode `list`/`search` summaries have no `path` (see the docs).
fn entry_summary_daemon() -> Value {
    json!({
        "id": "string",
        "title": "string",
        "username": "string|null",
        "url": "string|null",
        "attachments": ["string"],
        "group_path": ["string"],
        "tags": ["string"],
        "inherited_tags": ["string"],
    })
}

fn with(mut base: Value, key: &str, spec: Value) -> Value {
    base.as_object_mut()
        .expect("object spec")
        .insert(key.into(), spec);
    base
}

fn show_spec(field_values: &str) -> Value {
    json!({
        "path": "string",
        "title": "string",
        "username": "string|null",
        "url": "string|null",
        "notes": "string|null",
        "fields": {"*": field_values},
        "attachments": ["string"],
        "tags": ["string"],
        "inherited_tags": ["string"],
        "expires": "string|null",
    })
}

fn describe_spec() -> Value {
    json!([{
        "path": "string",
        "username": "string|null",
        "url": "string|null",
        "notes": "string|null",
        "has_password": "bool",
        "attributes": {"*": "string"},
        "attachments": [{"name": "string", "size": "integer"}],
    }])
}

fn ssh_key_spec() -> Value {
    json!({"algo": "string", "blob_b64": "string", "comment": "string"})
}

fn status_spec() -> Value {
    json!({
        "daemon_running": "bool",
        "vault_paths": ["string"],
        "idle_timeout_seconds": "integer|null",
        "idle_remaining_seconds": "integer|null",
        "ssh_key_count": "integer",
        "gpg_key_count": "integer",
        "materialized_file_count": "integer",
        "skipped_keys": [{
            "agent": "string",
            "vault": "string",
            "entry": "string",
            "attachment": "string",
            "reason": "string",
        }],
    })
}

fn sha1_hex(s: &str) -> String {
    use sha1::{Digest, Sha1};
    Sha1::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// A vault exercising every field the JSON outputs can carry: an entry with
/// everything set, one with nothing set, a materialized file, an SSH key and a
/// GPG key. `out_dir` is where the file entry materializes.
fn seed(trove: &Path, dir: &Path, out_dir: &Path) -> PathBuf {
    let path = dir.join("v.kdbx");
    let mut v = Vault::create(&path, PW).expect("create vault");

    let gh = v.add_entry("Web/github").expect("add github");
    v.set_field(&gh, "UserName", "octo").unwrap();
    v.set_field(&gh, "URL", "https://github.com").unwrap();
    v.set_field(&gh, "Notes", "work account").unwrap();
    v.set_field(&gh, "Password", "hunter2").unwrap();
    v.set_field(&gh, "About.Purpose", "code hosting").unwrap();
    v.set_tags(&gh, &["web".to_string()]).unwrap();
    v.attach_binary(&gh, "recovery.txt", b"codes").unwrap();
    v.set_group_tags("Web", &["team".to_string()]).unwrap();

    v.add_entry("bare").expect("add bare");

    let kube = v.add_entry("Infra/kube").expect("add kube");
    v.set_field(&kube, "Password", "not in the dump").unwrap();
    v.attach_binary(&kube, "blob", b"apiVersion: v1\n").unwrap();
    let target = out_dir.join("kubeconfig");
    v.set_field(&kube, "Materialize.blob.Target", target.to_str().unwrap())
        .unwrap();
    v.set_field(&kube, "Materialize.blob.Mode", "0600").unwrap();
    v.set_field(&kube, "Materialize.blob.TTL", "3600").unwrap();
    v.set_field(&kube, "Materialize.blob.AllowDiskBacked", "true")
        .unwrap();

    // Looks like a key but isn't one, so status lists it under skipped_keys.
    let broken = v.add_entry("Infra/broken").expect("add broken key");
    v.attach_binary(
        &broken,
        "id",
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nnot a key\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();

    let gpg = v.add_entry("Infra/signing").expect("add gpg");
    v.attach_binary(
        &gpg,
        "gpg-priv",
        include_bytes!("../../troved/tests/fixtures/rsa2048-secret.gpg"),
    )
    .unwrap();
    v.save().expect("save vault");
    drop(v);

    let vs = path.to_str().unwrap();
    let out = run(
        trove,
        &[],
        &[
            "--vault",
            vs,
            "--password-stdin",
            "generate",
            "ssh",
            "Infra/s1",
        ],
        &format!("{PW}\n"),
    );
    assert!(
        out.status.success(),
        "generate ssh: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    path
}

#[test]
fn offline_json_shapes() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let vault = seed(&trove, tmp.path(), tmp.path());
    let vs = vault.to_str().unwrap();
    let pw = format!("{PW}\n");
    let offline = |args: &[&str]| {
        let mut full = vec!["--vault", vs, "--password-stdin"];
        full.extend_from_slice(args);
        run(&trove, &[], &full, &pw)
    };

    let list = json_out(&offline(&["list", "--json"]), "list", true);
    assert_has("list", &list, "path", "Web/github");
    assert_shape("list", &list, &json!([entry_summary_offline()]));

    let hits = json_out(&offline(&["search", "github", "--json"]), "search", true);
    assert_has("search", &hits, "path", "Web/github");
    let hit = with(entry_summary_offline(), "matched", json!(["string"]));
    assert_shape("search", &hits, &json!([hit]));

    let show = json_out(&offline(&["show", "Web/github", "--json"]), "show", true);
    assert_shape("show", &show, &show_spec("string"));
    let bare = json_out(&offline(&["show", "bare", "--json"]), "show bare", true);
    assert_shape("show", &bare, &show_spec("string"));
    let revealed = json_out(
        &offline(&["show", "Web/github", "--json", "--show-protected"]),
        "show --show-protected",
        true,
    );
    let spec = with(show_spec("string"), "password", json!("string"));
    assert_shape("show --show-protected", &revealed, &spec);

    for path in ["Web/github", "Infra"] {
        let d = json_out(&offline(&["describe", path, "--json"]), "describe", true);
        assert_shape("describe", &d, &describe_spec());
    }

    let groups = json_out(&offline(&["group", "list", "--json"]), "group list", true);
    assert_has("group list", &groups, "path", "Web");
    let spec = json!([{"path": "string", "tags": ["string"], "inherited_tags": ["string"]}]);
    assert_shape("group list", &groups, &spec);

    let info = json_out(&offline(&["db-info", "--json"]), "db-info", true);
    let spec = json!({
        "path": "string",
        "version": "string",
        "cipher": "string",
        "compression": "string",
        "kdf": "string",
        "entries": "integer",
        "groups": "integer",
        "recycle_bin": "bool",
    });
    assert_shape("db-info", &info, &spec);

    let dump = tmp.path().join("pwned.txt");
    std::fs::write(&dump, format!("{}:1337\n", sha1_hex("hunter2"))).unwrap();
    let analyze = json_out(
        &offline(&["analyze", "--hibp", dump.to_str().unwrap(), "--json"]),
        "analyze",
        false,
    );
    assert_has("analyze", &analyze["findings"], "entry_path", "Web/github");
    assert_has("analyze", &analyze["findings"], "finding", "empty_password");
    let spec = json!({
        "checked_passwords": "integer",
        "breached_passwords": "integer",
        "empty_passwords": "integer",
        "findings": [
            {"entry_path": "string", "breach_count": "integer"},
            {"entry_path": "string", "finding": "string"},
        ],
    });
    assert_shape("analyze", &analyze, &spec);

    for pw in ["password\n", "correct horse battery staple\n"] {
        let est = json_out(
            &run(&trove, &[], &["estimate", "--json"], pw),
            "estimate",
            true,
        );
        let spec = json!({
            "length": "integer",
            "guesses": "integer",
            "entropy_bits": "number",
            "score": "integer",
            "warning": "string|null",
            "suggestions": ["string"],
        });
        assert_shape("estimate", &est, &spec);
    }
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

    fn sibling_troved(trove: &Path) -> Option<PathBuf> {
        let p = trove.parent()?.join("troved");
        p.is_file().then_some(p)
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
    fn daemon_json_shapes() {
        let Some(trove) = find_trove() else {
            eprintln!("skipping: trove binary not built");
            return;
        };
        let Some(troved) = sibling_troved(&trove) else {
            eprintln!("skipping: troved binary not built next to trove");
            return;
        };
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path();
        let out_dir = dir.join("out");
        let vault = seed(&trove, dir, &out_dir);
        let vs = vault.to_str().unwrap();

        let sock = dir.join("trove.sock");
        let sock_s = sock.to_str().unwrap();
        let dir_s = dir.to_str().unwrap();
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

        let env = [("TROVE_SOCK", sock_s)];
        let out = run(
            &trove,
            &env,
            &["unlock", vs, "--password-stdin", "--export"],
            &format!("{PW}\n"),
        );
        assert!(
            out.status.success(),
            "unlock: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("ssh key Infra/broken (id) not loaded"),
            "unlock should warn about the skipped key:\n{stderr}"
        );
        let code = String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("export TROVE_SESSION="))
            .map(|c| c.trim().trim_matches('\'').to_string())
            .expect("session code on stdout");
        let session = [("TROVE_SOCK", sock_s), ("TROVE_SESSION", code.as_str())];
        let daemon = |args: &[&str]| run(&trove, &session, args, "");

        let list = json_out(&daemon(&["list", "--json"]), "list (daemon)", true);
        assert_has("list (daemon)", &list, "title", "github");
        assert_shape("list (daemon)", &list, &json!([entry_summary_daemon()]));

        let hits = json_out(
            &daemon(&["search", "github", "--json"]),
            "search (daemon)",
            true,
        );
        assert_has("search (daemon)", &hits, "title", "github");
        let hit = with(entry_summary_daemon(), "matched", json!(["string"]));
        assert_shape("search (daemon)", &hits, &json!([hit]));

        let show = json_out(
            &daemon(&["show", "Web/github", "--json"]),
            "show (daemon)",
            true,
        );
        assert_shape("show (daemon)", &show, &show_spec("null"));
        let revealed = json_out(
            &daemon(&["show", "Web/github", "--json", "--show-protected"]),
            "show --show-protected (daemon)",
            true,
        );
        let spec = with(show_spec("null"), "password", json!("string"));
        assert_shape("show --show-protected (daemon)", &revealed, &spec);

        let d = json_out(
            &daemon(&["describe", "Infra", "--json"]),
            "describe (daemon)",
            true,
        );
        assert_shape("describe (daemon)", &d, &describe_spec());

        let status = json_out(&daemon(&["status", "--json"]), "status", true);
        assert_eq!(status["daemon_running"], true);
        assert_has("status", &status["skipped_keys"], "entry", "Infra/broken");
        assert_shape("status", &status, &status_spec());

        // --verbose groups what is served per vault.
        let verbose = json_out(
            &daemon(&["status", "--verbose", "--json"]),
            "status --verbose",
            true,
        );
        let mut spec = status_spec();
        spec["vaults"] = json!([{
            "path": "string",
            "ssh_keys": ["string"],
            "materialized": [{"title": "string", "target_path": "string"}],
            "skipped_keys": ["string"],
        }]);
        spec["gpg_keys"] = json!(["string"]);
        assert_shape("status --verbose", &verbose, &spec);
        let v0 = &verbose["vaults"][0];
        assert!(
            v0["ssh_keys"]
                .as_array()
                .unwrap()
                .iter()
                .any(|k| k == "Infra/s1"),
            "{verbose}"
        );
        assert_eq!(v0["materialized"][0]["title"], "kube", "{verbose}");
        assert!(
            v0["skipped_keys"]
                .as_array()
                .unwrap()
                .iter()
                .any(|k| k.as_str().unwrap().contains("Infra/broken")),
            "{verbose}"
        );

        let idle = json_out(&daemon(&["idle", "get", "--json"]), "idle get", true);
        let spec = json!({"timeout_seconds": "integer", "remaining_seconds": "integer|null"});
        assert_shape("idle get", &idle, &spec);

        let mat = json_out(
            &daemon(&["materialize-status", "--json"]),
            "materialize-status",
            true,
        );
        assert_has("materialize-status", &mat["materialized"], "title", "kube");
        let spec = json!({"materialized": [{
            "title": "string",
            "target_path": "string",
            "vault": "string",
            "ttl_remaining_seconds": "integer|null",
            "exists": "bool",
            "memory_backed": "bool",
        }]});
        assert_shape("materialize-status", &mat, &spec);

        let keys = json_out(
            &daemon(&["ssh-agent", "list", "--json"]),
            "ssh-agent list",
            true,
        );
        assert_eq!(keys.as_array().map(Vec::len), Some(1), "{keys}");
        assert_shape("ssh-agent list", &keys, &json!([ssh_key_spec()]));

        let out = daemon(&["ssh-agent", "empty"]);
        assert!(out.status.success(), "ssh-agent empty: {out:?}");
        let scoped = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let with_agent = [
            ("TROVE_SOCK", sock_s),
            ("TROVE_SESSION", code.as_str()),
            ("SSH_AUTH_SOCK", scoped.as_str()),
        ];
        let out = run(&trove, &with_agent, &["ssh-agent", "add", "Infra/s1"], "");
        assert!(out.status.success(), "ssh-agent add: {out:?}");
        let sockets = json_out(
            &daemon(&["ssh-agent", "sockets", "--json"]),
            "ssh-agent sockets",
            true,
        );
        assert_has("ssh-agent sockets", &sockets, "socket", &scoped);
        let spec = json!([{"socket": "string", "keys": [ssh_key_spec()]}]);
        assert_shape("ssh-agent sockets", &sockets, &spec);

        // A glob adds every match; `empty --add` creates and fills in one step,
        // and a fill that matches nothing prints no socket and hands it back.
        let out = run(&trove, &with_agent, &["ssh-agent", "add", "Infra/*"], "");
        assert!(out.status.success(), "ssh-agent add <glob>: {out:?}");
        let out = daemon(&["ssh-agent", "empty", "--add", "Infra/*"]);
        assert!(out.status.success(), "ssh-agent empty --add: {out:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("added Infra/s1"),
            "{out:?}"
        );
        let filled = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let out = daemon(&["ssh-agent", "empty", "--tag", "no-such-tag"]);
        assert!(!out.status.success(), "{out:?}");
        assert!(out.stdout.is_empty(), "{out:?}");
        let sockets = json_out(
            &daemon(&["ssh-agent", "sockets", "--json"]),
            "ssh-agent sockets",
            true,
        );
        assert_eq!(sockets.as_array().map(Vec::len), Some(2), "{sockets}");
        let out = daemon(&["ssh-agent", "close", &filled]);
        assert!(out.status.success(), "ssh-agent close: {out:?}");

        // `exec` reads the unlocked vault through the daemon: no --vault, no
        // password, the session code is enough.
        let out = daemon(&[
            "edit",
            "Web/github",
            "--set",
            "Exec.GH_USER=UserName",
            "--set",
            "Exec.GH_TOKEN=Password",
            "--set",
            "Exec.GH_CODES=@recovery.txt",
        ]);
        assert!(out.status.success(), "edit: {out:?}");
        let out = daemon(&[
            "exec",
            "--entry",
            "Web/github",
            "--",
            "sh",
            "-c",
            "printf '%s %s ' \"$GH_USER\" \"$GH_TOKEN\"; cat \"$GH_CODES\"",
        ]);
        assert!(out.status.success(), "exec via daemon: {out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "octo hunter2 codes");

        let gpg = json_out(
            &daemon(&["gpg-agent", "list", "--json"]),
            "gpg-agent list",
            true,
        );
        assert_eq!(gpg.as_array().map(Vec::len), Some(1), "{gpg}");
        let spec = json!([{"keygrip": "string", "key_type": "string", "comment": "string"}]);
        assert_shape("gpg-agent list", &gpg, &spec);

        // Scan only this test's tempdir, never a real daemon on the machine.
        let scan = [
            ("TROVE_SOCK", sock_s),
            ("TMPDIR", dir_s),
            ("XDG_RUNTIME_DIR", dir_s),
        ];
        let daemons = json_out(
            &run(&trove, &scan, &["daemons", "list", "--json"], ""),
            "daemons list",
            true,
        );
        assert_has("daemons list", &daemons, "control_socket", sock_s);
        let spec = json!([{
            "control_socket": "string",
            "lock_path": "string",
            "pid": "integer|null",
            "alive": "bool",
            "socket_exists": "bool",
        }]);
        assert_shape("daemons list", &daemons, &spec);

        let out = daemon(&["lock"]);
        assert!(out.status.success(), "lock: {out:?}");
    }

    /// With no daemon, the read commands still print JSON: the locked
    /// defaults, and empty arrays.
    #[test]
    fn no_daemon_json_shapes() {
        let Some(trove) = find_trove() else {
            eprintln!("skipping: trove binary not built");
            return;
        };
        let tmp = tempfile::tempdir().expect("tempdir");
        let sock = tmp.path().join("nope.sock");
        let env = [("TROVE_SOCK", sock.to_str().unwrap())];

        let status = json_out(
            &run(&trove, &env, &["status", "--json"], ""),
            "status (no daemon)",
            true,
        );
        assert_eq!(status["daemon_running"], false);
        assert_shape("status (no daemon)", &status, &status_spec());

        for args in [
            ["ssh-agent", "list", "--json"],
            ["ssh-agent", "sockets", "--json"],
            ["gpg-agent", "list", "--json"],
        ] {
            let what = args.join(" ");
            let v = json_out(&run(&trove, &env, &args, ""), &what, true);
            assert_shape(&what, &v, &json!([]));
        }

        // `doctor` still prints its JSON when a check fails, and exits 1: here
        // SSH_AUTH_SOCK names a socket nobody listens on.
        let stale = tmp.path().join("stale-agent.sock");
        let doctor_env = [
            ("TROVE_SOCK", sock.to_str().unwrap()),
            ("SSH_AUTH_SOCK", stale.to_str().unwrap()),
        ];
        let out = run(&trove, &doctor_env, &["doctor", "--json"], "");
        assert_eq!(out.status.code(), Some(1), "doctor: {out:?}");
        let doctor = json_out(&out, "doctor", false);
        assert_eq!(doctor["ok"], false);
        let spec = json!({"ok": "bool", "checks": [{
            "name": "string",
            "status": "string",
            "detail": "string",
            "hint": "string|null",
        }]});
        assert_shape("doctor", &doctor, &spec);
        let ssh = doctor["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "ssh-agent")
            .expect("an ssh-agent check");
        assert_eq!(ssh["status"], "fail", "{ssh}");
    }
}
