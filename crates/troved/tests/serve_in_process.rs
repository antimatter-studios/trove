//! `troved::server::serve` run in-process, as a host like the desktop app
//! would: it serves, a second `serve` against the same sockets reports
//! `AlreadyRunning` without binding anything, and notifying the shutdown
//! handle stops the first and removes its sockets.

#![allow(missing_docs)]
#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Notify;
use troved::server::{serve, ServeOptions, Served};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_stops_on_its_handle_and_a_second_one_defers() {
    let dir = tempfile::tempdir().unwrap();
    let ctrl = dir.path().join("trove.sock");
    // This test binary is its own process, so the env is ours to set.
    std::env::set_var("TROVE_SOCK", &ctrl);
    std::env::set_var("TROVE_SSH_SOCK", dir.path().join("ssh.sock"));
    std::env::set_var("TROVE_GPG_SOCK", dir.path().join("gpg.sock"));
    std::env::set_var("TROVE_IDLE_TIMEOUT", "0");

    let shutdown = Arc::new(Notify::new());
    let first = tokio::spawn(serve(ServeOptions {
        handle_signals: false,
        shutdown: shutdown.clone(),
        ..ServeOptions::default()
    }));

    let mut stream = None;
    for _ in 0..200 {
        if let Ok(s) = tokio::net::UnixStream::connect(&ctrl).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let stream = stream.expect("serve never bound the control socket");
    let (r, mut w) = tokio::io::split(stream);
    w.write_all(b"{\"cmd\":\"ping\"}\n").await.unwrap();
    let line = BufReader::new(r)
        .lines()
        .next_line()
        .await
        .unwrap()
        .unwrap();
    assert!(line.contains("\"pong\":true"), "{line}");

    let second = serve(ServeOptions {
        handle_signals: false,
        ..ServeOptions::default()
    })
    .await
    .unwrap();
    assert_eq!(second, Served::AlreadyRunning);
    assert!(
        ctrl.exists(),
        "the second serve must not touch the first's socket"
    );

    shutdown.notify_one();
    let ended = tokio::time::timeout(Duration::from_secs(10), first)
        .await
        .expect("serve stops when notified")
        .unwrap()
        .unwrap();
    assert_eq!(ended, Served::Stopped);
    assert!(!ctrl.exists(), "serve removes its socket on the way out");
}
