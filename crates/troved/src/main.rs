//! troved — the trove headless daemon.
//!
//! Serves newline-delimited JSON requests over a local IPC endpoint: a Unix
//! domain socket on macOS/Linux, a named pipe on Windows (see `ipc`). The
//! daemon itself lives in [`troved::server`]; this is its command line.

#![forbid(unsafe_code)]

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
compile_error!("troved currently supports macOS, Linux and Windows only");

use anyhow::Result;
use troved::server::{serve, ServeOptions};

#[tokio::main]
async fn main() -> Result<()> {
    // `troved --version` / `-V` prints the build version and exits, without
    // starting the daemon. Stamped by build.rs (see trove-cli for the format).
    if std::env::args()
        .skip(1)
        .any(|a| a == "--version" || a == "-V")
    {
        println!("troved {}", env!("TROVE_BUILD_VERSION"));
        return Ok(());
    }
    let resident = std::env::args().skip(1).any(|a| a == "--resident");
    // A second daemon exits 0 without binding: the first one serves.
    serve(ServeOptions {
        resident,
        ..ServeOptions::default()
    })
    .await?;
    Ok(())
}
