//! GPG agent socket: speaks the Assuan protocol against an in-memory
//! ed25519 key store loaded from vault attachments named `gpg-priv`.
//!
//! ## Scope (v0.0.3.0)
//!
//! Signing-only. The bare minimum to make `git commit -S` work for an
//! ed25519 OpenPGP key. We do NOT implement:
//!   * PKDECRYPT (no decryption — useful for symmetric & email);
//!   * GENKEY / IMPORT_KEY (key generation/import);
//!   * PASSWD (passphrase change);
//!   * pinentry interaction (we never prompt — keys are unlocked when the
//!     vault is unlocked, and that's it);
//!   * smartcard daemon proxying.
//!
//! Anything else returns a clear `ERR` so the client surfaces a meaningful
//! error rather than hanging.
//!
//! ## Lifecycle
//!
//! Mirrors the SSH agent: socket bound at troved startup, key store empty
//! until vault unlock populates it, cleared on lock or shutdown.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::RwLock;

use crate::ipc;

pub mod assuan;
pub mod keys;
pub mod pkdecrypt;

pub use keys::LoadedGpgKey;

use crate::gpg_agent::assuan::{
    percent_encode, write_data, write_err, write_ok, write_ok_with, write_status, AssuanWriter,
    Line, ERR_INV_VALUE, ERR_NO_SCDAEMON, ERR_NO_SECRET_KEY, ERR_UNKNOWN_COMMAND,
};
use crate::gpg_agent::pkdecrypt::ecdh_decrypt;
use crate::idle::IdleTracker;

/// Shared key store. Same shape as the SSH agent's KeyStore but holds
/// `LoadedGpgKey`. We use a separate type alias so the two stores don't get
/// accidentally swapped at a call site.
pub type GpgKeyStore = Arc<RwLock<Vec<LoadedGpgKey>>>;

/// Decide where the GPG agent socket should live. Order:
///   1. `TROVE_GPG_SOCK` env var.
///   2. `$XDG_RUNTIME_DIR/trove-gpg.sock`.
///   3. `${TMPDIR:-/tmp}/trove-gpg-$UID.sock`.
pub fn resolve_gpg_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("TROVE_GPG_SOCK") {
        return PathBuf::from(p);
    }
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            return PathBuf::from(rt).join("trove-gpg.sock");
        }
    }
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let uid = std::env::var("UID").unwrap_or_else(|_| "0".to_string());
    PathBuf::from(tmp).join(format!("trove-gpg-{uid}.sock"))
}

/// Bind the GPG agent socket and serve forever. Mirrors the SSH agent's
/// `run` exactly — including stale-socket cleanup and 0600 perms — because
/// the lifecycle invariants are identical.
pub async fn run(
    socket_path: PathBuf,
    store: GpgKeyStore,
    idle: Arc<IdleTracker>,
) -> std::io::Result<()> {
    let mut listener = ipc::bind(&socket_path).await?;
    eprintln!("gpg-agent listening on {}", socket_path.display());

    loop {
        match listener.accept().await {
            Ok(stream) => {
                let store = store.clone();
                let idle = idle.clone();
                idle.bump();
                tokio::spawn(async move {
                    let _ = serve_connection(stream, store, idle).await;
                });
            }
            Err(_) => {
                tokio::task::yield_now().await;
            }
        }
    }
}

/// Per-connection mutable state. This is recreated on every `RESET` and on
/// every new connection. Keeping it on the stack of `serve_connection` (not
/// shared) avoids any cross-client confusion.
#[derive(Default)]
struct Session {
    /// Keygrip selected by `SIGKEY` (lowercase hex). Cleared on `RESET` and
    /// after a successful `PKSIGN`.
    sigkey: Option<String>,
    /// Hash payload set by `SETHASH`. Cleared after `PKSIGN`.
    hash: Option<Vec<u8>>,
    /// Hash algorithm name set by `SETHASH`. Currently informational; we
    /// always sign the raw bytes regardless because EdDSA is "PureEdDSA"
    /// (no internal pre-hash) and the client passes the already-computed
    /// digest as the payload.
    #[allow(dead_code)]
    hash_algo: Option<String>,
}

async fn serve_connection(
    stream: ipc::Stream,
    store: GpgKeyStore,
    idle: Arc<IdleTracker>,
) -> std::io::Result<()> {
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    // Greeting: gpg-agent prints `OK Pleased to meet you, process %d` on
    // accept. The PID is purely informational; we use ours.
    let pid = std::process::id();
    let greeting = format!("OK Pleased to meet you, process {pid}\n");
    if write_half.write_all(greeting.as_bytes()).await.is_err() {
        return Ok(());
    }

    let mut session = Session::default();

    loop {
        let line = match assuan::read_line(&mut reader).await {
            Ok(Some(l)) => l,
            Ok(None) => return Ok(()),
            Err(_) => return Ok(()),
        };
        // Bump on every Assuan line — including malformed ones. The user is
        // talking to us; auto-lock should defer.
        idle.bump();
        let parsed = match Line::parse(&line) {
            Ok(p) => p,
            Err(_) => continue, // empty line — ignore
        };

        if std::env::var("TROVE_GPG_TRACE").is_ok() {
            eprintln!("gpg-agent <- {} {}", parsed.verb, parsed.rest);
        }
        let outcome =
            handle_command(&parsed, &mut session, &store, &mut reader, &mut write_half).await;
        match outcome {
            CommandOutcome::Continue => {}
            CommandOutcome::Disconnect => return Ok(()),
        }
    }
}

enum CommandOutcome {
    Continue,
    Disconnect,
}

async fn handle_command(
    cmd: &Line,
    session: &mut Session,
    store: &GpgKeyStore,
    reader: &mut assuan::AssuanReader,
    w: &mut AssuanWriter,
) -> CommandOutcome {
    macro_rules! send {
        ($expr:expr) => {
            if $expr.await.is_err() {
                return CommandOutcome::Disconnect;
            }
        };
    }

    match cmd.verb.as_str() {
        "BYE" => {
            let _ = write_ok_with(w, "closing connection").await;
            return CommandOutcome::Disconnect;
        }

        "RESET" => {
            *session = Session::default();
            send!(write_ok(w));
        }

        // OPTION sets a key=value or just a flag. We accept everything —
        // the agent doesn't drive a UI, so options like `ttyname`,
        // `display`, `lc-ctype`, `pinentry-mode` are no-ops for us.
        "OPTION" => {
            send!(write_ok(w));
        }

        // `agent-awareness` and other no-arg flag-like commands.
        "NOP" => {
            send!(write_ok(w));
        }

        // GETINFO returns one piece of agent metadata.
        "GETINFO" => {
            let what = cmd.rest.trim();
            match what {
                "version" => {
                    send!(write_data(w, b"2.4.5"));
                    send!(write_ok(w));
                }
                "pid" => {
                    let pid = std::process::id().to_string();
                    send!(write_data(w, pid.as_bytes()));
                    send!(write_ok(w));
                }
                "socket_name" => {
                    let p = resolve_gpg_socket_path();
                    let s = p.display().to_string();
                    send!(write_data(w, s.as_bytes()));
                    send!(write_ok(w));
                }
                "ssh_socket_name" => {
                    // We have a separate SSH socket — gpg-agent normally
                    // serves SSH on the same socket via `--enable-ssh-support`.
                    // Return the path to ours for parity.
                    let p = crate::ssh_agent::resolve_ssh_socket_path();
                    let s = p.display().to_string();
                    send!(write_data(w, s.as_bytes()));
                    send!(write_ok(w));
                }
                "scd_running" => {
                    // We never run a smartcard daemon.
                    send!(write_data(w, b"0"));
                    send!(write_ok(w));
                }
                "std_session_env" | "std_startup_env" => {
                    // Empty — we don't carry session env.
                    send!(write_ok(w));
                }
                "cmd_has_option" => {
                    // Format: `GETINFO cmd_has_option <CMD> <OPT>`. Conservatively
                    // claim no extra options.
                    send!(write_err(w, ERR_INV_VALUE, "no extra options"));
                }
                _ => {
                    send!(write_err(w, ERR_INV_VALUE, "unknown GETINFO key"));
                }
            }
        }

        // KEYINFO — list info about loaded keys. The format gpg-agent uses
        // is `S KEYINFO <grip> <type> <serialno> <idstr> <cached> <protection> <fpr> <ttl> <flags>`;
        // values we don't track are `-`. With `--list` we emit one S line per
        // loaded key followed by OK. With a specific grip we emit just that
        // one (or ERR if missing).
        "KEYINFO" => {
            let arg = cmd.rest.trim();
            let keys = store.read().await;
            if arg == "--list" || arg.is_empty() {
                for k in keys.iter() {
                    let grip = k.keygrip_hex();
                    let line = format!("{} D - - - P - - -", grip.to_uppercase());
                    send!(write_status(w, "KEYINFO", &line));
                }
                send!(write_ok(w));
            } else {
                // Could be a flag like "--data" followed by a grip; strip flags.
                let grip_arg = arg
                    .split_whitespace()
                    .find(|t| !t.starts_with("--"))
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if let Some(k) = keys.iter().find(|k| k.keygrip_hex() == grip_arg) {
                    let grip = k.keygrip_hex().to_uppercase();
                    let line = format!("{grip} D - - - P - - -");
                    send!(write_status(w, "KEYINFO", &line));
                    send!(write_ok(w));
                } else {
                    send!(write_err(w, ERR_NO_SECRET_KEY, "No_Secret_Key"));
                }
            }
        }

        // HAVEKEY <grip>... — succeeds if any of the listed grips is loaded.
        // `git commit -S` calls this to find out which key gpg-agent thinks
        // exists for the given fingerprint.
        "HAVEKEY" => {
            let arg = cmd.rest.trim();
            // Some clients invoke `HAVEKEY --list` or `HAVEKEY --info <grip>`.
            // We treat both as a structured query.
            if arg.starts_with("--list") {
                // Return a `D <binary keygrips>` block. gpg-agent emits the
                // 20-byte raw grips concatenated. Minimal: emit each one and
                // close with OK.
                let keys = store.read().await;
                let mut blob = Vec::with_capacity(keys.len() * 20);
                for k in keys.iter() {
                    blob.extend_from_slice(k.keygrip());
                }
                if !blob.is_empty() {
                    send!(write_data(w, &blob));
                }
                send!(write_ok(w));
            } else {
                let asked: Vec<String> = arg
                    .split_whitespace()
                    .filter(|t| !t.starts_with("--"))
                    .map(|s| s.to_ascii_lowercase())
                    .collect();
                let keys = store.read().await;
                let any_match = asked
                    .iter()
                    .any(|g| keys.iter().any(|k| &k.keygrip_hex() == g));
                if asked.is_empty() {
                    send!(write_err(w, ERR_INV_VALUE, "missing keygrip"));
                } else if any_match {
                    send!(write_ok(w));
                } else {
                    send!(write_err(w, ERR_NO_SECRET_KEY, "No_Secret_Key"));
                }
            }
        }

        // SIGKEY <grip> — record the key for the next PKSIGN.
        "SIGKEY" | "SETKEY" => {
            let grip = cmd.rest.trim().to_ascii_lowercase();
            if grip.is_empty() {
                send!(write_err(w, ERR_INV_VALUE, "missing keygrip"));
            } else {
                let keys = store.read().await;
                if keys.iter().any(|k| k.keygrip_hex() == grip) {
                    session.sigkey = Some(grip);
                    send!(write_ok(w));
                } else {
                    send!(write_err(w, ERR_NO_SECRET_KEY, "No_Secret_Key"));
                }
            }
        }

        // SETKEYDESC: text shown in the pinentry prompt. We don't have a
        // pinentry, so we just acknowledge.
        "SETKEYDESC" => {
            send!(write_ok(w));
        }

        // SETHASH [--hash=<algo>] <hex-hash>
        // Or:   SETHASH <algo-num> <hex-hash>
        // Stores the bytes to be signed.
        "SETHASH" => {
            // Accept `--hash=NAME` or numeric algo first arg.
            let mut algo: Option<String> = None;
            let mut hex_hash: Option<&str> = None;
            for tok in cmd.rest.split_whitespace() {
                if let Some(name) = tok.strip_prefix("--hash=") {
                    algo = Some(name.to_string());
                } else if tok.starts_with("--") {
                    // ignore unknown flags
                } else if hex_hash.is_none() {
                    // First non-flag positional could be `--hash=`-equivalent
                    // numeric algo (8=SHA256, 10=SHA512, 11=SHA224, 12=SHA384).
                    // If it's all digits, treat as algo and continue; else as
                    // the hex digest.
                    if tok.chars().all(|c| c.is_ascii_digit()) && tok.len() <= 3 && algo.is_none() {
                        algo = Some(format!("algo{tok}"));
                    } else {
                        hex_hash = Some(tok);
                    }
                } else {
                    // Trailing junk — ignore.
                }
            }
            let hex_hash = match hex_hash {
                Some(h) => h,
                None => {
                    send!(write_err(w, ERR_INV_VALUE, "missing hash"));
                    return CommandOutcome::Continue;
                }
            };
            match decode_hex(hex_hash) {
                Some(bytes) => {
                    session.hash = Some(bytes);
                    session.hash_algo = algo;
                    send!(write_ok(w));
                }
                None => {
                    send!(write_err(w, ERR_INV_VALUE, "hash not hex"));
                }
            }
        }

        // PKSIGN — produce an EdDSA signature over the recorded hash with the
        // recorded SIGKEY. Output: `D (7:sig-val(5:eddsa(1:r 32:<r>)(1:s 32:<s>)))`.
        "PKSIGN" => {
            let grip = match &session.sigkey {
                Some(g) => g.clone(),
                None => {
                    send!(write_err(w, ERR_INV_VALUE, "no SIGKEY"));
                    return CommandOutcome::Continue;
                }
            };
            let hash = match &session.hash {
                Some(h) => h.clone(),
                None => {
                    send!(write_err(w, ERR_INV_VALUE, "no SETHASH"));
                    return CommandOutcome::Continue;
                }
            };
            let sig_bytes_opt: Option<[u8; 64]> = {
                let keys = store.read().await;
                keys.iter()
                    .find(|k| k.keygrip_hex() == grip)
                    .and_then(|k| k.sign_raw(&hash))
            };
            match sig_bytes_opt {
                Some(sig) => {
                    let sexp = encode_eddsa_sigval(&sig);
                    // Reset session sign state on success.
                    session.hash = None;
                    session.sigkey = None;
                    send!(write_data(w, &sexp));
                    send!(write_ok(w));
                }
                None => {
                    send!(write_err(w, ERR_NO_SECRET_KEY, "No_Secret_Key"));
                }
            }
        }

        // PKDECRYPT — Curve25519 ECDH decrypt of the wrapped session key.
        //
        // Wire flow per gpg-agent docs:
        //   1. Client has previously sent `SETKEY <grip>` (handled above —
        //      stored in `session.sigkey` regardless of which command alias
        //      was used).
        //   2. Client sends `PKDECRYPT`.
        //   3. We respond with `INQUIRE CIPHERTEXT`.
        //   4. Client sends one or more `D <pct-encoded>` lines, terminated
        //      by `END\n`.
        //   5. We decode the canonical S-expression, do the ECDH + AES-KW
        //      unwrap, and return the result as `D (5:value%lenN:%body)\nOK`.
        //
        // Errors at any step return a single `ERR ...\n` and reset the
        // command state so the client can retry cleanly.
        "PKDECRYPT" => {
            let grip = match &session.sigkey {
                Some(g) => g.clone(),
                None => {
                    send!(write_err(w, ERR_INV_VALUE, "no SETKEY"));
                    return CommandOutcome::Continue;
                }
            };

            // INQUIRE — collect ciphertext from the client.
            if std::env::var("TROVE_GPG_TRACE").is_ok() {
                eprintln!("gpg-agent -> INQUIRE CIPHERTEXT");
            }
            if w.write_all(b"INQUIRE CIPHERTEXT\n").await.is_err() {
                return CommandOutcome::Disconnect;
            }
            let ciphertext_bytes = match read_inquired_data(reader).await {
                Ok(b) => b,
                Err(e) => {
                    if std::env::var("TROVE_GPG_TRACE").is_ok() {
                        eprintln!("gpg-agent: INQUIRE read failed: {e}");
                    }
                    send!(write_err(w, ERR_INV_VALUE, "ciphertext_read_error"));
                    return CommandOutcome::Continue;
                }
            };
            if std::env::var("TROVE_GPG_TRACE").is_ok() {
                eprintln!("gpg-agent: got ciphertext {} bytes", ciphertext_bytes.len());
            }

            // Pull out the key. We hold the lock for as little as possible —
            // copy what we need into local stack vars, drop the guard.
            #[allow(clippy::type_complexity)]
            let key_data: Option<([u8; 32], [u8; 32], [u8; 20], u8, u8)> = {
                let keys = store.read().await;
                keys.iter()
                    .find(|k| k.keygrip_hex() == grip)
                    .and_then(|k| match k {
                        keys::LoadedGpgKey::Cv25519(c) => Some((
                            c.secret_scalar_le(),
                            c.public_q,
                            c.fingerprint,
                            c.kdf_hash_algo,
                            c.kdf_sym_algo,
                        )),
                        _ => None,
                    })
            };

            let (secret_le, public_q, fingerprint, kdf_hash, kdf_sym) = match key_data {
                Some(t) => t,
                None => {
                    send!(write_err(
                        w,
                        ERR_NO_SECRET_KEY,
                        "No_Secret_Key_or_wrong_type"
                    ));
                    session.sigkey = None;
                    return CommandOutcome::Continue;
                }
            };

            match ecdh_decrypt(
                &ciphertext_bytes,
                &secret_le,
                &public_q,
                &fingerprint,
                kdf_hash,
                kdf_sym,
            ) {
                Ok(session_key_blob) => {
                    let sexp = encode_value_sexp(&session_key_blob);
                    session.sigkey = None;
                    send!(write_data(w, &sexp));
                    send!(write_ok(w));
                }
                Err(e) => {
                    // We don't echo `e` (it may include length info that
                    // could leak about the input shape). Map to a stable
                    // category. Logging at info-level is fine.
                    eprintln!("gpg-agent: PKDECRYPT failed for grip {grip}: {e}");
                    session.sigkey = None;
                    send!(write_err(w, ERR_INV_VALUE, "decrypt_failed"));
                }
            }
        }

        // READKEY <grip> — return the public key as a libgcrypt S-expression.
        //
        // For ed25519 EdDSA:
        //   `(public-key(ecc(curve Ed25519)(flags eddsa)(q ...)))`
        // For Curve25519 ECDH:
        //   `(public-key(ecc(curve Curve25519)(flags djb-tweak)(q ...)))`
        //
        // Used by `gpg --list-keys` (and similar inspection commands) to
        // recover the public key when the keyring only has a stub.
        "READKEY" => {
            let arg = cmd.rest.trim();
            // Skip option flags like `--no-data`.
            let grip = arg
                .split_whitespace()
                .find(|t| !t.starts_with("--"))
                .unwrap_or("")
                .to_ascii_lowercase();
            if grip.is_empty() {
                send!(write_err(w, ERR_INV_VALUE, "missing keygrip"));
                return CommandOutcome::Continue;
            }
            let blob_opt: Option<Vec<u8>> = {
                let keys = store.read().await;
                keys.iter()
                    .find(|k| k.keygrip_hex() == grip)
                    .map(encode_public_key_sexp)
            };
            match blob_opt {
                Some(blob) => {
                    send!(write_data(w, &blob));
                    send!(write_ok(w));
                }
                None => {
                    send!(write_err(w, ERR_NO_SECRET_KEY, "No_Secret_Key"));
                }
            }
        }

        // SCD <subcmd> — smartcard daemon. We don't run one.
        "SCD" => {
            send!(write_err(w, ERR_NO_SCDAEMON, "No_SmartCard_Daemon"));
        }

        // Pinentry-related — never invoked because we never prompt.
        "PRESET_PASSPHRASE" | "CLEAR_PASSPHRASE" | "GET_PASSPHRASE" | "GET_CONFIRMATION" => {
            send!(write_ok(w));
        }

        // KEYWRAP_KEY, EXPORT_KEY etc. — not implemented.
        // Return a structured error so the client doesn't silently retry.
        _ => {
            let msg = format!("Unknown_IPC_Command: {}", cmd.verb);
            // Suppress the verb itself from the encoded message so a malformed
            // verb can't inject control bytes; percent-escape just to be safe.
            let _ = msg; // kept for potential debug logging
            send!(write_err(
                w,
                ERR_UNKNOWN_COMMAND,
                &format!(
                    "Unknown_IPC_Command_{}",
                    percent_encode(cmd.verb.as_bytes())
                )
            ));
        }
    }
    CommandOutcome::Continue
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    // Hex strings must have an even number of nibbles. Bitmask form keeps
    // both clippy and MSRV (`is_multiple_of` is 1.87+) happy.
    #[allow(clippy::manual_is_multiple_of)]
    if s.len() & 1 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_value(bytes[i])?;
        let lo = hex_value(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Read inquired data from the client until we see a bare `END` line. Each
/// line is read bytewise (not as UTF-8) because modern gpg ships `D` payloads
/// with raw 0x80..0xFF bytes — only `%`, CR, LF are %-escaped. We strip the
/// leading `D[ ]?` prefix, %-decode, and concatenate.
async fn read_inquired_data(reader: &mut assuan::AssuanReader) -> std::io::Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(256);
    loop {
        let raw = match assuan::read_line_bytes(reader).await? {
            Some(l) => l,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF in INQUIRE data",
                ))
            }
        };
        // Strip trailing CR/LF.
        let mut end = raw.len();
        while end > 0 && (raw[end - 1] == b'\n' || raw[end - 1] == b'\r') {
            end -= 1;
        }
        let trimmed = &raw[..end];
        if trimmed == b"END" {
            return Ok(out);
        }
        if trimmed == b"CAN" {
            return Err(std::io::Error::other("INQUIRE cancelled by client"));
        }
        if trimmed.is_empty() {
            continue;
        }
        let payload: &[u8] = if trimmed.starts_with(b"D ") {
            &trimmed[2..]
        } else if trimmed.starts_with(b"D") {
            &trimmed[1..]
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected verb during INQUIRE",
            ));
        };
        let mut i = 0;
        while i < payload.len() {
            if payload[i] == b'%' {
                if i + 2 >= payload.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "bad %-encoding in INQUIRE",
                    ));
                }
                let hi = hex_value(payload[i + 1]).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "bad %-encoding in INQUIRE",
                    )
                })?;
                let lo = hex_value(payload[i + 2]).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "bad %-encoding in INQUIRE",
                    )
                })?;
                out.push((hi << 4) | lo);
                i += 3;
            } else {
                out.push(payload[i]);
                i += 1;
            }
        }
    }
}

/// Wrap a raw byte payload in the libgcrypt `(5:value ...)` outer S-expression
/// expected by PKDECRYPT clients. The caller passes the already-formed inner
/// payload (e.g. `algo || session_key || checksum`). The returned bytes are
/// suitable for sending in a `D` line.
pub fn encode_value_sexp(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 16);
    out.extend_from_slice(b"(5:value");
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(payload);
    out.push(b')');
    out
}

/// Build the libgcrypt public-key S-expression for a `LoadedGpgKey`. Used
/// by READKEY responses.
///
/// EdDSA: `(public-key(ecc(curve Ed25519)(flags eddsa)(q <33B 0x40||point>)))`.
/// ECDH:  `(public-key(ecc(curve Curve25519)(flags djb-tweak)(q <33B 0x40||point>)))`.
///
/// The `q` field is the same 33-byte form `gpg --export` writes: `0x40` prefix
/// followed by the 32-byte raw point. Libgcrypt is permissive about the
/// prefix and we keep it for parity with what gpg's own `READKEY` returns.
pub fn encode_public_key_sexp(key: &keys::LoadedGpgKey) -> Vec<u8> {
    let (curve_name, flags, q): (&[u8], &[u8], [u8; 33]) = match key {
        keys::LoadedGpgKey::Ed25519(k) => {
            let mut q = [0u8; 33];
            q[0] = 0x40;
            q[1..].copy_from_slice(&k.public_q);
            (b"Ed25519", b"eddsa", q)
        }
        keys::LoadedGpgKey::Cv25519(k) => {
            let mut q = [0u8; 33];
            q[0] = 0x40;
            q[1..].copy_from_slice(&k.public_q);
            (b"Curve25519", b"djb-tweak", q)
        }
    };
    let mut out: Vec<u8> = Vec::with_capacity(96);
    out.extend_from_slice(b"(10:public-key(3:ecc(5:curve");
    out.extend_from_slice(curve_name.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(curve_name);
    out.extend_from_slice(b")(5:flags");
    out.extend_from_slice(flags.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(flags);
    out.extend_from_slice(b")(1:q33:");
    out.extend_from_slice(&q);
    out.extend_from_slice(b")))");
    out
}

/// Build the PKSIGN data payload for an ed25519 signature: a canonical
/// S-expression `(7:sig-val(5:eddsa(1:r32:<R>)(1:s32:<S>)))`. The libgcrypt
/// format puts each component in its own parameter.
pub fn encode_eddsa_sigval(sig: &[u8; 64]) -> Vec<u8> {
    let r = &sig[..32];
    let s = &sig[32..];
    let mut out = Vec::with_capacity(64 + 40);
    out.extend_from_slice(b"(7:sig-val(5:eddsa(1:r32:");
    out.extend_from_slice(r);
    out.extend_from_slice(b")(1:s32:");
    out.extend_from_slice(s);
    out.extend_from_slice(b")))");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_gpg_socket_honours_explicit_override() {
        let prev = std::env::var("TROVE_GPG_SOCK").ok();
        std::env::set_var("TROVE_GPG_SOCK", "/tmp/explicit-trove-gpg.sock");
        let p = resolve_gpg_socket_path();
        assert_eq!(p, PathBuf::from("/tmp/explicit-trove-gpg.sock"));
        match prev {
            Some(v) => std::env::set_var("TROVE_GPG_SOCK", v),
            None => std::env::remove_var("TROVE_GPG_SOCK"),
        }
    }

    #[test]
    fn encode_eddsa_sigval_layout() {
        let sig = [0x42u8; 64];
        let blob = encode_eddsa_sigval(&sig);
        assert!(blob.starts_with(b"(7:sig-val(5:eddsa(1:r32:"));
        assert!(blob.ends_with(b")))"));
        // Find the r-value and confirm 32 bytes follow.
        let r_marker = b"(1:r32:";
        let r_pos = blob
            .windows(r_marker.len())
            .position(|w| w == r_marker)
            .unwrap();
        let r_start = r_pos + r_marker.len();
        assert_eq!(&blob[r_start..r_start + 32], &sig[..32]);
    }

    #[test]
    fn decode_hex_round_trip() {
        assert_eq!(decode_hex("00ff42").unwrap(), vec![0x00, 0xFF, 0x42]);
        assert_eq!(
            decode_hex("DEADBEEF").unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert!(decode_hex("xyz").is_none());
        assert!(decode_hex("abc").is_none()); // odd length
    }
}
