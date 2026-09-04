//! End-to-end test: drive a real `gpg --decrypt` of an **RSA**-encrypted
//! message against our gpg agent socket, and confirm the recovered plaintext
//! matches what we encrypted. Also exercises RSA `PKSIGN` on the same bundle.
//!
//! This is the majority case in the wild: most PGP keys still in circulation
//! are RSA, and `pass`, `sops`, `git-crypt` and encrypted mail all hammer the
//! decrypt path.
//!
//! Skips automatically when `gpg` or `gpgconf` aren't on `$PATH`.
//!
//! What it does:
//!   1. Spin up an isolated `GNUPGHOME`.
//!   2. Generate a real RSA key with an RSA *encryption subkey*. This needs a
//!      `--batch --gen-key` parameter file: `--quick-generate-key ... rsa2048`
//!      produces a sign-only primary and no subkey at all, which would leave
//!      nothing to decrypt with.
//!   3. Export the secret key bundle as a binary blob.
//!   4. Stash it in a real .kdbx vault under attachment `gpg-priv`.
//!   5. Open the vault, populate the in-memory GPG key store. Both keygrips
//!      (signing primary + encryption subkey) should appear as RSA keys.
//!   6. Encrypt a message with `gpg --encrypt` (encryption needs no secret).
//!   7. Spawn our GPG agent listener on a temp socket; symlink it as
//!      `$GNUPGHOME/S.gpg-agent` so gpg connects to *our* agent.
//!   8. Run `gpg --decrypt` and assert the plaintext matches.
//!   9. Run `gpg --sign` + `gpg --verify` to prove RSA PKSIGN too.

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::RwLock;
use trove_core::Vault;
use troved::gpg_agent::{self, GpgKeyStore};
use troved::handler::load_gpg_keys_from_vault;
use troved::idle::{IdleTracker, LockCallback, LockFuture};

fn noop_idle() -> Arc<IdleTracker> {
    let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
    IdleTracker::new(Duration::from_secs(0), cb)
}

fn have_tool(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gpg_rsa_decrypt_against_our_agent_recovers_plaintext() {
    if !have_tool("gpg") || !have_tool("gpgconf") {
        eprintln!("SKIP: gpg/gpgconf not on $PATH");
        return;
    }

    let tmp = TempDir::new().expect("tempdir");
    let gnupghome = tmp.path().join("gnupghome");
    std::fs::create_dir(&gnupghome).expect("mkdir gnupghome");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&gnupghome).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&gnupghome, perms).unwrap();
    }
    let params_path = tmp.path().join("keyparams");
    let secret_path = tmp.path().join("secret.gpg");
    let vault_path = tmp.path().join("vault.kdbx");
    let sock_path = tmp.path().join("gpg.sock");
    let plaintext_path = tmp.path().join("plain.txt");
    let cipher_path = tmp.path().join("plain.gpg");
    let recovered_path = tmp.path().join("recovered.txt");
    let signed_path = tmp.path().join("signed.gpg");

    // 1. Generate an RSA primary *plus* an RSA encryption subkey. 2048 bits
    // keeps generation fast; the code path is bit-length agnostic.
    std::fs::write(
        &params_path,
        b"Key-Type: RSA\n\
          Key-Length: 2048\n\
          Key-Usage: sign\n\
          Subkey-Type: RSA\n\
          Subkey-Length: 2048\n\
          Subkey-Usage: encrypt\n\
          Name-Real: trove rsa itest\n\
          Name-Email: rsa@trove\n\
          Expire-Date: 0\n\
          %no-protection\n\
          %commit\n",
    )
    .expect("write key params");
    let kg = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args(["--batch", "--gen-key"])
        .arg(&params_path)
        .output()
        .expect("spawn gpg --gen-key");
    if !kg.status.success() {
        let stderr = String::from_utf8_lossy(&kg.stderr);
        eprintln!("SKIP: gpg --batch --gen-key failed:\n{stderr}");
        return;
    }

    // 2. Discover the primary fingerprint.
    let lk = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args(["--with-colons", "--list-secret-keys"])
        .output()
        .expect("spawn gpg --list-secret-keys");
    assert!(lk.status.success());
    let stdout = String::from_utf8_lossy(&lk.stdout);
    let fpr = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("fpr:::::::::"))
        .filter_map(|s| s.split(':').next())
        .next()
        .expect("find fingerprint")
        .to_string();
    assert_eq!(fpr.len(), 40, "fpr should be 40 hex chars: {fpr:?}");

    // Collect the keygrips gpg itself computed. Ours must match exactly or
    // gpg will never route a PKDECRYPT to us.
    let mut gpg_keygrips: Vec<String> = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("grp:::::::::"))
        .filter_map(|s| s.split(':').next())
        .map(|s| s.to_ascii_lowercase())
        .collect();
    gpg_keygrips.sort();
    assert_eq!(
        gpg_keygrips.len(),
        2,
        "expected a primary + encryption subkey keygrip, got {gpg_keygrips:?}"
    );

    // 3. Export the secret key bundle (primary + subkey).
    let ex = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args([
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--export-secret-keys",
            "--output",
        ])
        .arg(&secret_path)
        .arg(&fpr)
        .output()
        .expect("spawn gpg --export-secret-keys");
    assert!(
        ex.status.success(),
        "gpg --export-secret-keys failed: {}",
        String::from_utf8_lossy(&ex.stderr)
    );
    let secret_bytes = std::fs::read(&secret_path).expect("read exported key");
    assert!(!secret_bytes.is_empty());

    // 4. Stash in a vault.
    let password = "rsa-decrypt-itest-pw";
    {
        let mut vault = Vault::create(&vault_path, password).expect("create vault");
        let id = vault.add_entry("gpg-rsa-decrypt-itest").expect("add entry");
        vault
            .attach_binary(&id, "gpg-priv", &secret_bytes)
            .expect("attach gpg-priv");
        vault.save().expect("save vault");
    }

    // 5. Populate the GPG key store from the vault.
    let vault = Vault::open(&vault_path, password).expect("reopen");
    let keys = load_gpg_keys_from_vault(&vault);
    assert_eq!(
        keys.len(),
        2,
        "vault should yield the RSA primary and the RSA encryption subkey, got {}",
        keys.len()
    );
    for k in &keys {
        assert!(
            matches!(k, troved::gpg_agent::keys::LoadedGpgKey::Rsa(_)),
            "expected every key in an RSA bundle to parse as RSA, got {k:?}"
        );
    }
    let mut our_keygrips: Vec<String> = keys.iter().map(|k| k.keygrip_hex()).collect();
    our_keygrips.sort();
    assert_eq!(
        our_keygrips, gpg_keygrips,
        "our RSA keygrips must match the ones gpg computed"
    );
    let store: GpgKeyStore = Arc::new(RwLock::new(keys));

    // 6. Encrypt a message using *real* gpg-agent (encryption needs only the
    // recipient's public key — it doesn't need our agent yet).
    let original_plain = b"trove-test plaintext: hello, RSA world! 1234567890 the quick brown fox";
    std::fs::write(&plaintext_path, original_plain).expect("write plaintext");
    let enc = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args([
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--recipient",
            &fpr,
            "--encrypt",
            "--output",
        ])
        .arg(&cipher_path)
        .arg(&plaintext_path)
        .output()
        .expect("spawn gpg --encrypt");
    assert!(
        enc.status.success(),
        "gpg --encrypt failed: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    // 7. Now redirect gpg-agent to ours. Kill any existing real one so the
    // symlink is the only path.
    let _ = Command::new("gpgconf")
        .env("GNUPGHOME", &gnupghome)
        .args(["--kill", "gpg-agent"])
        .output();

    let store_for_task = store.clone();
    let sock_for_task = sock_path.clone();
    let idle_for_task = noop_idle();
    let agent_handle = tokio::spawn(async move {
        let _ = gpg_agent::run(sock_for_task, store_for_task, idle_for_task).await;
    });
    for _ in 0..100 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sock_path.exists(), "agent socket never appeared");

    let agent_symlink = gnupghome.join("S.gpg-agent");
    let _ = std::fs::remove_file(&agent_symlink);
    std::os::unix::fs::symlink(&sock_path, &agent_symlink).expect("symlink");

    // Anything that fails from here on has to tear the agent down before it
    // panics, or the test binary hangs on the still-running listener.
    let cleanup = |handle: tokio::task::JoinHandle<()>| {
        handle.abort();
        let _ = Command::new("gpgconf")
            .env("GNUPGHOME", &gnupghome)
            .args(["--kill", "all"])
            .output();
    };

    // 8. Decrypt against our agent.
    let dec = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args(["--batch", "--yes", "--decrypt", "--output"])
        .arg(&recovered_path)
        .arg(&cipher_path)
        .output()
        .expect("spawn gpg --decrypt");
    let dec_stderr = String::from_utf8_lossy(&dec.stderr).into_owned();
    eprintln!("gpg --decrypt stderr: {dec_stderr}");
    if !dec.status.success() {
        cleanup(agent_handle);
        panic!("gpg --decrypt against our agent failed.\nstderr:\n{dec_stderr}");
    }
    let recovered = std::fs::read(&recovered_path).expect("read recovered");
    if recovered != original_plain {
        cleanup(agent_handle);
        panic!("decrypted plaintext must match the original");
    }

    // 9. READKEY: our RSA public-key S-expression has to match the shape a
    // real agent returns, or `gpg --list-keys` against a keyring stub breaks.
    // A real gpg 2.5.21 replies `D (10:public-key(3:rsa(1:n257:…)(1:e3:…)))`
    // for rsa2048 — note the 257, i.e. the modulus carries libgcrypt's sign
    // byte.
    let rk = Command::new("gpg-connect-agent")
        .env("GNUPGHOME", &gnupghome)
        .arg(format!("READKEY {}", our_keygrips[0].to_uppercase()))
        .arg("/bye")
        .output()
        .expect("spawn gpg-connect-agent READKEY");
    let rk_stdout = String::from_utf8_lossy(&rk.stdout).into_owned();
    if !rk_stdout.starts_with("D (10:public-key(3:rsa(1:n257:") {
        cleanup(agent_handle);
        panic!("READKEY returned an unexpected shape:\n{rk_stdout}");
    }

    let lk2 = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args(["--list-keys"])
        .output()
        .expect("spawn gpg --list-keys");
    if !lk2.status.success() {
        cleanup(agent_handle);
        panic!(
            "gpg --list-keys should succeed with our agent in front: {}",
            String::from_utf8_lossy(&lk2.stderr)
        );
    }

    // 10. RSA PKSIGN: sign with our agent, verify with gpg's own crypto.
    let sg = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args(["--batch", "--yes", "--sign", "--output"])
        .arg(&signed_path)
        .arg(&plaintext_path)
        .output()
        .expect("spawn gpg --sign");
    let sg_stderr = String::from_utf8_lossy(&sg.stderr).into_owned();
    if !sg.status.success() {
        cleanup(agent_handle);
        panic!("gpg --sign against our agent failed.\nstderr:\n{sg_stderr}");
    }
    let vf = Command::new("gpg")
        .env("GNUPGHOME", &gnupghome)
        .args(["--batch", "--verify"])
        .arg(&signed_path)
        .output()
        .expect("spawn gpg --verify");
    let vf_stderr = String::from_utf8_lossy(&vf.stderr).into_owned();
    let vf_ok = vf.status.success();

    cleanup(agent_handle);
    assert!(
        vf_ok,
        "gpg --verify rejected the RSA signature our agent produced.\nstderr:\n{vf_stderr}"
    );
}
