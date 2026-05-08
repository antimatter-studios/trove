//! End-to-end GPG agent tests.
//!
//! These exercise the Assuan protocol over a real Unix socket without
//! requiring `gpg` itself — every test is hermetic. A separate integration
//! test (`gpg_agent_with_real_gpg_test`, marked `#[ignore]`) attempts the
//! full `git commit -S` flow against our agent and is **not** wired into
//! CI; it documents the manual reproduction recipe.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::RwLock;
use troved::gpg_agent::{self, keys::LoadedGpgKey, GpgKeyStore};
use troved::idle::{IdleTracker, LockCallback, LockFuture};

fn noop_idle() -> Arc<IdleTracker> {
    let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
    IdleTracker::new(Duration::from_secs(0), cb)
}

/// Build a synthetic ed25519 OpenPGP secret-key packet and parse it. Used by
/// the e2e tests below to load keys without depending on `gpg` being on PATH.
fn synthetic_ed25519_packet(seed: [u8; 32]) -> Vec<u8> {
    use ed25519_dalek::SigningKey;

    const ED25519_OID: [u8; 9] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];

    let sk = SigningKey::from_bytes(&seed);
    let q: [u8; 32] = sk.verifying_key().to_bytes();

    let mut body = Vec::new();
    body.push(4);
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.push(22);
    body.push(9);
    body.extend_from_slice(&ED25519_OID);
    body.extend_from_slice(&263u16.to_be_bytes());
    body.push(0x40);
    body.extend_from_slice(&q);
    body.push(0);
    body.extend_from_slice(&256u16.to_be_bytes());
    body.extend_from_slice(&seed);
    let cksum: u16 = seed.iter().map(|b| *b as u16).sum::<u16>();
    body.extend_from_slice(&cksum.to_be_bytes());

    let mut packet = Vec::new();
    packet.push(0x80 | 0x40 | 5);
    packet.push(255);
    packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}

async fn spawn_agent_with_keys(
    sock_path: &Path,
    keys: Vec<LoadedGpgKey>,
) -> tokio::task::JoinHandle<()> {
    let store: GpgKeyStore = Arc::new(RwLock::new(keys));
    let sock = sock_path.to_path_buf();
    let idle = noop_idle();
    let handle = tokio::spawn(async move {
        let _ = gpg_agent::run(sock, store, idle).await;
    });
    for _ in 0..100 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        sock_path.exists(),
        "gpg agent socket never appeared at {}",
        sock_path.display()
    );
    handle
}

/// Read the greeting (single OK line). Panics if the agent doesn't speak
/// proper Assuan.
async fn expect_greeting(
    reader: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
) {
    let line = reader
        .next_line()
        .await
        .expect("read greeting")
        .expect("eof during greeting");
    assert!(
        line.starts_with("OK Pleased to meet you"),
        "unexpected greeting: {line:?}"
    );
}

/// Read response lines until we see an `OK` or `ERR`. Returns all collected
/// lines, including the terminator.
async fn read_until_terminator(
    reader: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
) -> Vec<String> {
    let mut out = Vec::new();
    loop {
        let line = reader
            .next_line()
            .await
            .expect("read response")
            .expect("eof in response");
        let starts = line.starts_with("OK") || line.starts_with("ERR");
        out.push(line);
        if starts {
            return out;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn assuan_basic_handshake() {
    let tmp = TempDir::new().expect("tempdir");
    let sock = tmp.path().join("gpg.sock");

    let key =
        troved::gpg_agent::keys::parse_gpg_export(&synthetic_ed25519_packet([0x11; 32]), "alice")
            .expect("parse synthetic key")
            .pop()
            .expect("at least one key");
    let _agent = spawn_agent_with_keys(&sock, vec![key]).await;

    let stream = UnixStream::connect(&sock).await.expect("connect");
    let (rh, mut wh) = stream.into_split();
    let mut reader = BufReader::new(rh).lines();

    expect_greeting(&mut reader).await;

    // RESET → OK
    wh.write_all(b"RESET\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert_eq!(lines, vec!["OK"]);

    // OPTION ttyname=... → OK
    wh.write_all(b"OPTION ttyname=/dev/pts/9\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert_eq!(lines, vec!["OK"]);

    // GETINFO version → D 2.4.5\nOK
    wh.write_all(b"GETINFO version\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "D 2.4.5");
    assert_eq!(lines[1], "OK");

    // GETINFO socket_name → D <path>\nOK
    wh.write_all(b"GETINFO socket_name\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("D "));
    assert_eq!(lines[1], "OK");

    // BYE → OK closing connection
    wh.write_all(b"BYE\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert!(lines[0].starts_with("OK"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keyinfo_and_havekey() {
    let tmp = TempDir::new().expect("tempdir");
    let sock = tmp.path().join("gpg.sock");

    let key =
        troved::gpg_agent::keys::parse_gpg_export(&synthetic_ed25519_packet([0x22; 32]), "bob")
            .expect("parse synthetic key")
            .pop()
            .expect("at least one key");
    let grip = key.keygrip_hex();
    let _agent = spawn_agent_with_keys(&sock, vec![key]).await;

    let stream = UnixStream::connect(&sock).await.expect("connect");
    let (rh, mut wh) = stream.into_split();
    let mut reader = BufReader::new(rh).lines();
    expect_greeting(&mut reader).await;

    // KEYINFO --list → at least one S KEYINFO line then OK
    wh.write_all(b"KEYINFO --list\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    let s_lines: Vec<&String> = lines
        .iter()
        .filter(|l| l.starts_with("S KEYINFO "))
        .collect();
    assert_eq!(s_lines.len(), 1);
    assert!(
        s_lines[0].to_lowercase().contains(&grip),
        "expected grip {grip} in {}",
        s_lines[0]
    );
    assert_eq!(lines.last().unwrap(), "OK");

    // HAVEKEY <our-grip> → OK
    let have_cmd = format!("HAVEKEY {grip}\n");
    wh.write_all(have_cmd.as_bytes()).await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert_eq!(lines, vec!["OK"]);

    // HAVEKEY <bogus-grip> → ERR ... No_Secret_Key
    wh.write_all(b"HAVEKEY 0000000000000000000000000000000000000000\n")
        .await
        .unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert!(lines[0].starts_with("ERR "));
    assert!(lines[0].contains("No_Secret_Key"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pksign_full_round_trip_signs_and_verifies() {
    let tmp = TempDir::new().expect("tempdir");
    let sock = tmp.path().join("gpg.sock");

    let seed = [0x33u8; 32];
    let key = troved::gpg_agent::keys::parse_gpg_export(&synthetic_ed25519_packet(seed), "carol")
        .expect("parse synthetic key")
        .pop()
        .expect("at least one key");
    let grip = key.keygrip_hex();
    let public_q = *key.public_q();
    let _agent = spawn_agent_with_keys(&sock, vec![key]).await;

    let stream = UnixStream::connect(&sock).await.expect("connect");
    let (rh, mut wh) = stream.into_split();
    let mut reader = BufReader::new(rh).lines();
    expect_greeting(&mut reader).await;

    // RESET / OPTION dance, like a real client.
    for cmd in &["RESET", "OPTION agent-awareness=2.4.5"] {
        wh.write_all(format!("{cmd}\n").as_bytes()).await.unwrap();
        let lines = read_until_terminator(&mut reader).await;
        assert_eq!(lines, vec!["OK"], "{cmd} should OK");
    }

    // SIGKEY <grip> → OK
    wh.write_all(format!("SIGKEY {grip}\n").as_bytes())
        .await
        .unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert_eq!(lines, vec!["OK"]);

    // SETKEYDESC ... → OK
    wh.write_all(b"SETKEYDESC trove-test\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert_eq!(lines, vec!["OK"]);

    // SETHASH 8 <hex of "hello-trove" sha-256-stand-in> → OK
    // We just need a 32-byte payload; ed25519 can sign anything.
    let payload: [u8; 32] = [0xAB; 32];
    let hex = payload
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let cmd = format!("SETHASH 8 {hex}\n");
    wh.write_all(cmd.as_bytes()).await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert_eq!(lines, vec!["OK"]);

    // PKSIGN → D <encoded sigval>\nOK
    wh.write_all(b"PKSIGN\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    let d_line = lines.iter().find(|l| l.starts_with("D ")).expect("D line");
    assert_eq!(lines.last().unwrap(), "OK");

    // Decode the %-encoded payload and pull out the 32-byte r and s components.
    let encoded = d_line.strip_prefix("D ").unwrap();
    let raw = troved::gpg_agent::assuan::percent_decode(encoded).expect("percent decode");
    // Format: (7:sig-val(5:eddsa(1:r32:<32 bytes>)(1:s32:<32 bytes>)))
    let r_marker = b"(1:r32:";
    let r_pos = raw
        .windows(r_marker.len())
        .position(|w| w == r_marker)
        .expect("find r marker");
    let r_start = r_pos + r_marker.len();
    let r = &raw[r_start..r_start + 32];
    let s_marker = b")(1:s32:";
    let s_pos = raw
        .windows(s_marker.len())
        .position(|w| w == s_marker)
        .expect("find s marker");
    let s_start = s_pos + s_marker.len();
    let s = &raw[s_start..s_start + 32];

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(r);
    sig[32..].copy_from_slice(s);

    // Verify with ed25519-dalek directly. The signed payload was the bytes
    // we passed to SETHASH (PureEdDSA — no internal pre-hash).
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&public_q).unwrap();
    let signature = ed25519_dalek::Signature::from_bytes(&sig);
    assert!(
        vk.verify_strict(&payload, &signature).is_ok(),
        "the signature returned by PKSIGN should verify against the public key"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_command_returns_err() {
    let tmp = TempDir::new().expect("tempdir");
    let sock = tmp.path().join("gpg.sock");
    let _agent = spawn_agent_with_keys(&sock, vec![]).await;

    let stream = UnixStream::connect(&sock).await.expect("connect");
    let (rh, mut wh) = stream.into_split();
    let mut reader = BufReader::new(rh).lines();
    expect_greeting(&mut reader).await;

    wh.write_all(b"NONSENSE arg1 arg2\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert!(lines[0].starts_with("ERR "));
    assert!(
        lines[0].contains("Unknown_IPC_Command"),
        "got: {}",
        lines[0]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scd_returns_no_smartcard_daemon() {
    let tmp = TempDir::new().expect("tempdir");
    let sock = tmp.path().join("gpg.sock");
    let _agent = spawn_agent_with_keys(&sock, vec![]).await;

    let stream = UnixStream::connect(&sock).await.expect("connect");
    let (rh, mut wh) = stream.into_split();
    let mut reader = BufReader::new(rh).lines();
    expect_greeting(&mut reader).await;

    wh.write_all(b"SCD SERIALNO\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert!(lines[0].starts_with("ERR "));
    assert!(lines[0].contains("No_SmartCard_Daemon"));
}
