//! Stamps the build version into the binary.
//!
//! Release builds (with `TROVE_RELEASE` set in the environment) report the plain
//! package version, e.g. `0.2.0`. Every other build is a dev build and gets a
//! build timestamp appended — `0.2.0-dev-YYYYMMDDHHMMSS` — so you can tell at a
//! glance which dev build you're running and when it was compiled.
use std::env;

fn main() {
    // Recompute on every build so a dev build's timestamp is always current.
    // A path that never exists is always treated as "changed", forcing a re-run;
    // cargo then only relinks the crate if the stamped version actually changed
    // (i.e. at most once per second between dev builds).
    println!("cargo:rerun-if-changed=.trove-build-version-always-rerun");
    println!("cargo:rerun-if-env-changed=TROVE_RELEASE");

    let pkg = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let version = if env::var_os("TROVE_RELEASE").is_some() {
        pkg
    } else {
        let stamp = chrono::Local::now().format("%Y%m%d%H%M%S");
        format!("{pkg}-dev-{stamp}")
    };
    println!("cargo:rustc-env=TROVE_BUILD_VERSION={version}");
}
