//! End-to-end tests for the commands that write capability settings
//! documents: `trove env-agent`, `trove materialize add|remove|disable|
//! defaults`, `trove gpg-agent enable|disable`, `trove ssh-agent
//! enable|disable` and `trove settings show|edit|validate|migrate`.
//!
//! Each runs the real `trove` binary against a vault file, and the last runs
//! it through a real `troved`, so the offline and daemon paths are both
//! covered. A missing binary fails the test rather than skipping it.

#![allow(missing_docs)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use trove_core::settings::Capability;
use trove_core::Vault;

const PW: &str = "settings-e2e-pw";

fn trove() -> PathBuf {
    let p = PathBuf::from(env!("CARGO_BIN_EXE_trove"));
    assert!(p.exists(), "trove binary not built at {}", p.display());
    p
}

fn run(env: &[(&str, &str)], args: &[&str], stdin: &str) -> Output {
    let mut cmd = Command::new(trove());
    cmd.args(args)
        .env_remove("TROVE_SESSION")
        .env_remove("TROVE_VAULT")
        .env_remove("SSH_AUTH_SOCK")
        .env("TROVE_NO_AUTOSPAWN", "1")
        .env("TROVE_NO_VERSION_WARN", "1")
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
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait trove")
}

/// `trove --vault <v> --password-stdin <args>`, which must succeed.
fn ok(vault: &Path, args: &[&str]) -> String {
    let out = offline(vault, args);
    assert!(
        out.status.success(),
        "trove {args:?} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn offline(vault: &Path, args: &[&str]) -> Output {
    let mut full = vec!["--vault", vault.to_str().unwrap(), "--password-stdin"];
    full.extend_from_slice(args);
    run(&[], &full, &format!("{PW}\n"))
}

fn fails(vault: &Path, args: &[&str]) -> String {
    let out = offline(vault, args);
    assert!(!out.status.success(), "trove {args:?} should fail");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A vault with the gitea entry from the motivating case.
fn gitea_vault(dir: &Path) -> PathBuf {
    let path = dir.join("v.kdbx");
    let mut v = Vault::create(&path, PW).unwrap();
    v.add_group("antimatter-studios").unwrap();
    let id = v.add_entry("gitea").unwrap();
    v.move_entry(&id, "antimatter-studios").unwrap();
    v.set_field(&id, "UserName", "chris").unwrap();
    v.set_field(&id, "gitea-token", "tok-e2e-123").unwrap();
    v.attach_binary(&id, "gitea_ed25519", b"not a real key")
        .unwrap();
    v.save().unwrap();
    path
}

fn reopen(path: &Path) -> Vault {
    Vault::open(path, PW).unwrap()
}

#[test]
fn env_agent_add_turns_exec_on_and_disable_turns_it_off() {
    let tmp = tempfile::tempdir().unwrap();
    let v = gitea_vault(tmp.path());
    let entry = "antimatter-studios/gitea";

    let err = fails(&v, &["exec", "--entry", entry, "--", "true"]);
    assert!(err.contains("trove env-agent add"), "{err}");

    ok(
        &v,
        &[
            "env-agent",
            "add",
            entry,
            "GITEA_TOKEN",
            "--field",
            "gitea-token",
        ],
    );
    let out = ok(
        &v,
        &[
            "exec",
            "--entry",
            entry,
            "--",
            "sh",
            "-c",
            "printf %s \"$GITEA_TOKEN\"",
        ],
    );
    assert_eq!(out, "tok-e2e-123");

    let vault = reopen(&v);
    let id = vault.find_by_title(entry).unwrap();
    let doc = vault
        .settings_document(&id, Capability::EnvAgent)
        .unwrap()
        .expect("the document exists");
    assert!(doc.item("GITEA_TOKEN").is_some());

    ok(&v, &["env-agent", "remove", entry, "GITEA_TOKEN"]);
    let err = fails(&v, &["env-agent", "remove", entry, "GITEA_TOKEN"]);
    assert!(err.contains("does not export"), "{err}");

    ok(
        &v,
        &[
            "env-agent",
            "add",
            entry,
            "GITEA_TOKEN",
            "--field",
            "gitea-token",
        ],
    );
    ok(&v, &["env-agent", "disable", entry]);
    let vault = reopen(&v);
    let id = vault.find_by_title(entry).unwrap();
    assert_eq!(
        vault.settings_document(&id, Capability::EnvAgent).unwrap(),
        None
    );
    fails(&v, &["exec", "--entry", entry, "--", "true"]);
}

#[test]
fn env_agent_refuses_bad_names_and_sources() {
    let tmp = tempfile::tempdir().unwrap();
    let v = gitea_vault(tmp.path());
    let err = fails(
        &v,
        &[
            "env-agent",
            "add",
            "antimatter-studios/gitea",
            "1BAD",
            "--field",
            "x",
        ],
    );
    assert!(err.contains("valid environment variable"), "{err}");
    fails(&v, &["env-agent", "add", "antimatter-studios/gitea", "A"]);
    fails(
        &v,
        &["env-agent", "add", "no/such/entry", "A", "--field", "x"],
    );
}

#[test]
fn adding_to_an_entry_with_legacy_fields_keeps_and_replaces_them() {
    let tmp = tempfile::tempdir().unwrap();
    let v = gitea_vault(tmp.path());
    let entry = "antimatter-studios/gitea";
    ok(&v, &["edit", entry, "--set", "Exec.GITEA_USER=UserName"]);
    ok(
        &v,
        &[
            "env-agent",
            "add",
            entry,
            "GITEA_TOKEN",
            "--field",
            "gitea-token",
        ],
    );
    let vault = reopen(&v);
    let id = vault.find_by_title(entry).unwrap();
    let doc = vault
        .settings_document(&id, Capability::EnvAgent)
        .unwrap()
        .unwrap();
    assert!(
        doc.item("GITEA_USER").is_some(),
        "the legacy mapping carried over"
    );
    assert!(
        vault
            .legacy_settings_fields(&id, Capability::EnvAgent)
            .unwrap()
            .is_empty(),
        "and its field is gone"
    );
}

#[test]
fn materialize_add_and_group_defaults_resolve_together() {
    let tmp = tempfile::tempdir().unwrap();
    let v = gitea_vault(tmp.path());
    let entry = "antimatter-studios/gitea";
    let dir = tmp.path().join("secrets");
    ok(
        &v,
        &[
            "materialize",
            "add",
            entry,
            "gitea_ed25519",
            "--mode",
            "0640",
        ],
    );
    ok(
        &v,
        &[
            "materialize",
            "defaults",
            "antimatter-studios",
            "--dir",
            dir.to_str().unwrap(),
            "--allow-disk-backed",
        ],
    );
    let out = ok(&v, &["settings", "show", entry, "materialize", "--json"]);
    let shown: Value = serde_json::from_str(&out).unwrap();
    let attrs = &shown[0]["effective"][0]["attributes"];
    assert_eq!(attrs["dir"]["value"], dir.to_str().unwrap());
    assert_eq!(attrs["dir"]["origin"], "group");
    assert_eq!(attrs["dir"]["group"], "antimatter-studios");
    assert_eq!(attrs["mode"]["value"], "0640");
    assert_eq!(attrs["mode"]["origin"], "item");

    let text = ok(
        &v,
        &["settings", "show", entry, "materialize", "--effective"],
    );
    assert!(text.contains("(group antimatter-studios)"), "{text}");

    let groups = ok(
        &v,
        &[
            "settings",
            "show",
            "antimatter-studios",
            "--group",
            "--json",
        ],
    );
    let groups: Value = serde_json::from_str(&groups).unwrap();
    assert!(groups
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["capability"] == "materialize" && d["document"].is_string()));

    ok(
        &v,
        &[
            "materialize",
            "defaults",
            "antimatter-studios",
            "--clear",
            "dir",
            "--clear",
            "allowDiskBacked",
        ],
    );
    let vault = reopen(&v);
    assert_eq!(
        vault
            .group_settings("antimatter-studios", Capability::Materialize)
            .unwrap(),
        None,
        "a defaults document left empty is removed"
    );
    ok(&v, &["materialize", "remove", entry, "gitea_ed25519"]);
    ok(&v, &["materialize", "disable", entry]);
}

#[test]
fn database_defaults_need_no_group() {
    let tmp = tempfile::tempdir().unwrap();
    let v = gitea_vault(tmp.path());
    ok(&v, &["env-agent", "defaults", "--database", "--confirm"]);
    ok(
        &v,
        &[
            "env-agent",
            "add",
            "antimatter-studios/gitea",
            "GITEA_TOKEN",
            "--field",
            "gitea-token",
            "--no-confirm",
        ],
    );
    let err = fails(
        &v,
        &["exec", "--entry", "antimatter-studios/gitea", "--", "true"],
    );
    assert!(
        err.contains("Touch ID"),
        "the database's confirm cannot be loosened below it: {err}"
    );
}

#[test]
fn a_group_can_never_hold_an_item() {
    let tmp = tempfile::tempdir().unwrap();
    let v = gitea_vault(tmp.path());
    let editor = tmp.path().join("editor.sh");
    std::fs::write(
        &editor,
        "#!/bin/sh\ncat > \"$1\" <<'XML'\n<EnvAgentSettings version=\"1\">\n  \
         <Variable name=\"A\" field=\"Password\"/>\n</EnvAgentSettings>\nXML\n",
    )
    .unwrap();
    make_executable(&editor);
    let out = run(
        &[("EDITOR", editor.to_str().unwrap())],
        &[
            "--vault",
            v.to_str().unwrap(),
            "--password-stdin",
            "settings",
            "edit",
            "env-agent",
            "antimatter-studios",
            "--group",
        ],
        &format!("{PW}\n"),
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("never grants"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn settings_edit_validates_before_saving() {
    let tmp = tempfile::tempdir().unwrap();
    let v = gitea_vault(tmp.path());
    let entry = "antimatter-studios/gitea";
    let bad = tmp.path().join("bad.sh");
    std::fs::write(&bad, "#!/bin/sh\nprintf '<EnvAgentSettings>' > \"$1\"\n").unwrap();
    make_executable(&bad);
    let out = run(
        &[("EDITOR", bad.to_str().unwrap())],
        &[
            "--vault",
            v.to_str().unwrap(),
            "--password-stdin",
            "settings",
            "edit",
            "env-agent",
            entry,
        ],
        &format!("{PW}\n"),
    );
    assert!(!out.status.success(), "an invalid edit is not saved");
    let vault = reopen(&v);
    let id = vault.find_by_title(entry).unwrap();
    assert_eq!(
        vault.settings_document(&id, Capability::EnvAgent).unwrap(),
        None
    );

    let good = tmp.path().join("good.sh");
    std::fs::write(
        &good,
        "#!/bin/sh\ncat > \"$1\" <<'XML'\n<EnvAgentSettings version=\"1\">\n  \
         <Variable name=\"GITEA_USER\" field=\"UserName\"/>\n</EnvAgentSettings>\nXML\n",
    )
    .unwrap();
    make_executable(&good);
    let out = run(
        &[("EDITOR", good.to_str().unwrap())],
        &[
            "--vault",
            v.to_str().unwrap(),
            "--password-stdin",
            "settings",
            "edit",
            "env-agent",
            entry,
        ],
        &format!("{PW}\n"),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let shown = ok(
        &v,
        &[
            "exec",
            "--entry",
            entry,
            "--",
            "sh",
            "-c",
            "printf %s \"$GITEA_USER\"",
        ],
    );
    assert_eq!(shown, "chris");
}

#[test]
fn validate_finds_a_broken_document_and_migrate_converts_legacy_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let v = gitea_vault(tmp.path());
    ok(&v, &["settings", "validate"]);
    ok(
        &v,
        &[
            "edit",
            "antimatter-studios/gitea",
            "--set",
            "Exec.GITEA_USER=UserName",
        ],
    );
    let dry = ok(&v, &["settings", "migrate", "--dry-run"]);
    assert!(dry.contains("would convert 1"), "{dry}");
    ok(&v, &["settings", "migrate"]);
    let vault = reopen(&v);
    let id = vault.find_by_title("antimatter-studios/gitea").unwrap();
    assert!(vault
        .settings_document(&id, Capability::EnvAgent)
        .unwrap()
        .is_some());
    assert!(vault
        .legacy_settings_fields(&id, Capability::EnvAgent)
        .unwrap()
        .is_empty());
    drop(vault);

    let mut vault = reopen(&v);
    vault
        .attach_binary(&id, "Materialize.settings", b"<MaterializeSettings")
        .unwrap();
    vault.save().unwrap();
    drop(vault);
    let err = fails(&v, &["settings", "validate"]);
    assert!(err.contains("Materialize.settings"), "{err}");
}

#[test]
fn gpg_agent_disable_keeps_a_legacy_key_off() {
    let tmp = tempfile::tempdir().unwrap();
    let v = gitea_vault(tmp.path());
    let mut vault = reopen(&v);
    let id = vault.add_entry("signing").unwrap();
    vault.attach_binary(&id, "gpg-priv", b"x").unwrap();
    vault.save().unwrap();
    drop(vault);
    ok(&v, &["gpg-agent", "disable", "signing"]);
    let vault = reopen(&v);
    let id = vault.find_by_title("signing").unwrap();
    let doc = vault
        .entry_settings(&id, Capability::GpgAgent)
        .unwrap()
        .unwrap();
    assert!(
        doc.items().is_empty(),
        "an empty document keeps gpg-priv unserved"
    );
    drop(vault);
    ok(&v, &["gpg-agent", "enable", "signing", "--uses", "sign"]);
    let vault = reopen(&v);
    let doc = vault
        .settings_document(&id, Capability::GpgAgent)
        .unwrap()
        .unwrap();
    assert_eq!(doc.attachments(), vec!["gpg-priv"]);
}

#[test]
fn ssh_agent_disable_writes_a_document_that_says_no() {
    let tmp = tempfile::tempdir().unwrap();
    let v = gitea_vault(tmp.path());
    let entry = "antimatter-studios/gitea";
    let err = fails(&v, &["ssh-agent", "enable", entry]);
    assert!(err.contains("--key"), "{err}");
    ok(
        &v,
        &[
            "ssh-agent",
            "enable",
            entry,
            "--key",
            "gitea_ed25519",
            "--confirm",
        ],
    );
    let shown = ok(&v, &["settings", "show", entry, "ssh-agent"]);
    assert!(
        shown.contains("<AllowUseOfSshKey>true</AllowUseOfSshKey>"),
        "{shown}"
    );
    assert!(shown.contains("gitea_ed25519"), "{shown}");
    ok(&v, &["ssh-agent", "disable", entry]);
    let shown = ok(&v, &["settings", "show", entry, "ssh-agent"]);
    assert!(
        shown.contains("<AllowUseOfSshKey>false</AllowUseOfSshKey>"),
        "{shown}"
    );
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

/// The motivating case through a real daemon: the agent's shell has only
/// `TROVE_SESSION`, never the vault password.
#[cfg(unix)]
#[test]
fn env_agent_add_and_exec_through_the_daemon() {
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    struct Troved(std::process::Child);
    impl Drop for Troved {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let v = gitea_vault(dir);
    let troved = trove().parent().unwrap().join("troved");
    assert!(
        troved.is_file(),
        "troved not built next to trove at {}",
        troved.display()
    );
    let sock = dir.join("trove.sock");
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
    let deadline = Instant::now() + Duration::from_secs(30);
    while UnixStream::connect(&sock).is_err() {
        assert!(Instant::now() < deadline, "troved never came up");
        std::thread::sleep(Duration::from_millis(25));
    }
    let sock_s = sock.to_str().unwrap();
    let out = run(
        &[("TROVE_SOCK", sock_s)],
        &[
            "unlock",
            v.to_str().unwrap(),
            "--password-stdin",
            "--export",
        ],
        &format!("{PW}\n"),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let code = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("export TROVE_SESSION="))
        .map(|c| c.trim().trim_matches('\'').to_string())
        .expect("session code");
    let env = [("TROVE_SOCK", sock_s), ("TROVE_SESSION", code.as_str())];
    let entry = "antimatter-studios/gitea";

    let out = run(
        &env,
        &[
            "env-agent",
            "add",
            entry,
            "GITEA_TOKEN",
            "--field",
            "gitea-token",
        ],
        "",
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run(
        &env,
        &[
            "exec",
            "--entry",
            entry,
            "--",
            "sh",
            "-c",
            "printf %s \"$GITEA_TOKEN\"",
        ],
        "",
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "tok-e2e-123");

    // Writing needs the session code; reading does not.
    let out = run(
        &[("TROVE_SOCK", sock_s)],
        &["env-agent", "add", entry, "X", "--field", "UserName"],
        "",
    );
    assert!(
        !out.status.success(),
        "a write without the session code is refused"
    );
    let out = run(
        &[("TROVE_SOCK", sock_s)],
        &["settings", "show", entry, "env-agent", "--json"],
        "",
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let shown: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(shown[0]["effective"][0]["key"], "GITEA_TOKEN");
}
