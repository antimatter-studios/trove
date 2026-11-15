//! `troved::server::serve` run in-process, as a host like the desktop app
//! would: it serves, a second `serve` against the same sockets reports
//! `AlreadyRunning` without binding anything, and notifying the shutdown
//! handle stops the first and removes its sockets. A stopped `serve` leaves
//! no task running behind it, so a host can serve again in the same process.

#![allow(missing_docs)]
#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Notify;
use troved::server::{serve, ServeOptions, Served};

// The tests share the process environment (`TROVE_SOCK` and friends), so they
// take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Point every daemon socket into `dir`.
fn sockets_in(dir: &std::path::Path) -> std::path::PathBuf {
    let ctrl = dir.join("trove.sock");
    // This test binary is its own process, so the env is ours to set.
    std::env::set_var("TROVE_SOCK", &ctrl);
    std::env::set_var("TROVE_SSH_SOCK", dir.join("ssh.sock"));
    std::env::set_var("TROVE_GPG_SOCK", dir.join("gpg.sock"));
    std::env::set_var("TROVE_IDLE_TIMEOUT", "0");
    ctrl
}

async fn ping(ctrl: &std::path::Path) -> String {
    let mut stream = None;
    for _ in 0..200 {
        if let Ok(s) = tokio::net::UnixStream::connect(ctrl).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let stream = stream.expect("serve never bound the control socket");
    let (r, mut w) = tokio::io::split(stream);
    w.write_all(b"{\"cmd\":\"ping\"}\n").await.unwrap();
    BufReader::new(r)
        .lines()
        .next_line()
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_stops_on_its_handle_and_a_second_one_defers() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let ctrl = sockets_in(dir.path());

    let shutdown = Arc::new(Notify::new());
    let first = tokio::spawn(serve(ServeOptions {
        handle_signals: false,
        shutdown: shutdown.clone(),
        ..ServeOptions::default()
    }));

    let line = ping(&ctrl).await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stopped_serve_leaves_no_task_running() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let ctrl = sockets_in(dir.path());
    let metrics = tokio::runtime::Handle::current().metrics();
    let before = metrics.num_alive_tasks();

    let shutdown = Arc::new(Notify::new());
    let served = tokio::spawn(serve(ServeOptions {
        resident: true,
        handle_signals: false,
        shutdown: shutdown.clone(),
    }));
    let line = ping(&ctrl).await;
    assert!(line.contains("\"pong\":true"), "{line}");
    shutdown.notify_one();
    let ended = tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("serve stops when notified")
        .unwrap()
        .unwrap();
    assert_eq!(ended, Served::Stopped);

    // The SSH and GPG listeners and the idle timer are serve's own tasks. A
    // host that serves again (the desktop app taking over from a troved that
    // exited) would otherwise gather one more set each time.
    for _ in 0..100 {
        if metrics.num_alive_tasks() <= before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        metrics.num_alive_tasks(),
        before,
        "tasks still running after serve returned"
    );
}
