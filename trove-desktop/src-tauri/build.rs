use std::process::Command;

fn main() {
    // Build identity, in two parts.
    //
    // MODE is the optional half: empty for a production build, so the version
    // stands alone and nothing has to be trimmed off it later. Anything else —
    // "dev", "rc", "nightly" — is carried through verbatim and concatenated by
    // the consumer. Override with TROVE_BUILD_MODE; otherwise a debug build
    // says "dev" and a release build says nothing.
    let mode = std::env::var("TROVE_BUILD_MODE").unwrap_or_else(|_| {
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            String::new()
        } else {
            "dev".to_string()
        }
    });
    println!("cargo:rustc-env=TROVE_BUILD_MODE={mode}");
    println!("cargo:rerun-if-env-changed=TROVE_BUILD_MODE");

    // COMMIT identifies which build it is, and is only meaningful alongside a
    // mode — a released version is identified by its version number. Empty
    // outside a git checkout, so a source tarball still builds.
    let commit = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    println!("cargo:rustc-env=TROVE_DESKTOP_GIT={commit}");

    // Without this the stamp sticks at whatever it was on the first build.
    for p in ["../../.git/HEAD", "../../.git/refs/heads"] {
        if std::path::Path::new(p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }

    tauri_build::build()
}
