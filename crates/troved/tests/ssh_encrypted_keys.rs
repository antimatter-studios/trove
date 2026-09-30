//! Passphrase-protected SSH keys in a vault load the way KeePassXC loads
//! them: decrypted with the entry's Password.

#![allow(missing_docs)]

use tempfile::TempDir;
use trove_core::Vault;
use troved::handler::load_ssh_keys_from_vault;

fn encrypted_key(passphrase: &str) -> Vec<u8> {
    let pk = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
        .expect("random key")
        .encrypt(&mut rand_core::OsRng, passphrase)
        .expect("encrypt");
    pk.to_openssh(ssh_key::LineEnding::LF)
        .expect("encode")
        .as_bytes()
        .to_vec()
}

fn vault_with(dir: &TempDir, entries: &[(&str, &[u8], Option<&str>)]) -> Vault {
    let path = dir.path().join("v.kdbx");
    let mut v = Vault::create(&path, "vault-pw").expect("create");
    for (title, key, password) in entries {
        let id = v.add_entry(title).expect("add entry");
        v.attach_binary(&id, "id", key).expect("attach key");
        if let Some(pw) = password {
            v.set_field(&id, "Password", pw).expect("set password");
        }
    }
    v.save().expect("save");
    Vault::open(&path, "vault-pw").expect("reopen")
}

#[test]
fn the_entry_password_decrypts_a_protected_key() {
    let dir = TempDir::new().unwrap();
    let key = encrypted_key("key-pass");
    let v = vault_with(&dir, &[("protected", &key, Some("key-pass"))]);
    let keys = load_ssh_keys_from_vault(&v);
    assert_eq!(keys.len(), 1, "the key loads with the entry's Password");
    assert_eq!(keys[0].comment, "protected");
}

#[test]
fn a_protected_key_without_the_right_password_is_skipped() {
    let dir = TempDir::new().unwrap();
    let key = encrypted_key("key-pass");
    let v = vault_with(
        &dir,
        &[
            ("no-password", &key, None),
            ("wrong-password", &key, Some("something else")),
        ],
    );
    assert!(load_ssh_keys_from_vault(&v).is_empty());
}
