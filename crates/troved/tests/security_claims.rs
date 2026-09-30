//! Security claims from docs/threat-model.md, checked against the real
//! `troved` binary. Each test names the claim it backs.

#![allow(missing_docs)]
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn troved_bin() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_troved")?);
    p.exists().then_some(p)
}

/// "Crash-dumped daemon memory": troved marks itself non-dumpable, so a crash
/// writes no core file and same-uid processes can't ptrace it.
#[test]
fn troved_is_not_dumpable() {
    let Some(bin) = troved_bin() else {
        eprintln!("SKIP: troved binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("trove.sock");
    let mut child = Command::new(bin)
        .env("TROVE_SOCK", &sock)
        .env("TROVE_SSH_SOCK", dir.path().join("trove-ssh.sock"))
        .env("TROVE_GPG_SOCK", dir.path().join("trove-gpg.sock"))
        .env("TROVE_IDLE_TIMEOUT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn troved");

    // The control socket appears after the prctl call, so once it exists the
    // flag is set.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    // Same uid as troved, so this read only fails because troved is not
    // dumpable: the kernel then refuses `/proc/<pid>/environ` (and `mem`) to
    // anyone without CAP_SYS_PTRACE.
    let environ = std::fs::read(format!("/proc/{}/environ", child.id()));
    let _ = child.kill();
    let _ = child.wait();

    assert!(sock.exists(), "troved never bound its control socket");
    let err = environ.expect_err("read troved's environ, so it is still dumpable");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
}
