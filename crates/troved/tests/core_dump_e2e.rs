//! `hardening::disable_core_dumps` must leave the process unable to write a
//! core file on every Unix: `RLIMIT_CORE` is 0, soft and hard.
//!
//! The limit is per process and lowering the hard limit cannot be undone, so
//! the call runs in a child: this test binary re-runs itself with an
//! environment variable set, and the child does the check.
#![allow(missing_docs)]
#![cfg(unix)]

use std::process::Command;

const CHILD_ENV: &str = "TROVE_CORE_DUMP_TEST_CHILD";
const TEST_NAME: &str = "disable_core_dumps_zeroes_rlimit_core";

#[test]
fn disable_core_dumps_zeroes_rlimit_core() {
    if std::env::var_os(CHILD_ENV).is_some() {
        troved::hardening::disable_core_dumps().expect("disable_core_dumps");
        let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
        assert_eq!(
            (limit.current, limit.maximum),
            (Some(0), Some(0)),
            "RLIMIT_CORE must be 0 (soft and hard)"
        );
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let out = Command::new(exe)
        .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .output()
        .expect("run child");
    assert!(
        out.status.success(),
        "child failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // The filter must have matched, or the child ran nothing and passed.
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("1 passed"),
        "child did not run the test: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
