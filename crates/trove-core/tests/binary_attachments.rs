use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::fs::File;
use std::path::Path;
use tempfile::TempDir;
use trove_core::Vault;

fn non_utf8_blob() -> Vec<u8> {
    let mut buf: Vec<u8> = (0u16..=255).map(|n| n as u8).collect();
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_F00D_BAAD);
    let mut tail = vec![0u8; 4096];
    rng.fill_bytes(&mut tail);
    buf.extend_from_slice(&tail);
    assert!(std::str::from_utf8(&buf[..256]).is_err());
    buf
}

#[test]
fn non_utf8_binary_round_trips_across_save_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let password = "pw";
    let blob = non_utf8_blob();

    let id = {
        let mut vault = Vault::create(&path, password).expect("create");
        let id = vault.add_entry("blob-host").expect("add");
        vault.attach_binary(&id, "raw", &blob).expect("attach");
        vault.save().expect("save");
        id
    };

    let vault = Vault::open(&path, password).expect("reopen");
    let read = vault.read_binary(&id, "raw").expect("ok").expect("present");
    assert_eq!(read.len(), blob.len(), "length must match");
    assert_eq!(read, blob, "bytes must match exactly");

    let xml = decrypt_to_xml(&path, password);
    assert!(
        xml.contains("<Binary>") && xml.contains("Ref="),
        "expected real <Binary> reference in entry XML, got:\n{xml}"
    );
}

#[test]
fn multiple_attachments_with_mixed_names_and_sizes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let password = "pw";

    let tiny = vec![0xFFu8];
    let ascii: Vec<u8> = b"hello, world\n".to_vec();
    let mid: Vec<u8> = (0..2048).map(|i| (i & 0xFF) as u8).collect();

    let id = {
        let mut vault = Vault::create(&path, password).expect("create");
        let id = vault.add_entry("multi").expect("add");
        vault
            .attach_binary(&id, "tiny.bin", &tiny)
            .expect("attach tiny");
        vault
            .attach_binary(&id, "note.txt", &ascii)
            .expect("attach ascii");
        vault
            .attach_binary(&id, "data.bin", &mid)
            .expect("attach mid");
        vault.save().expect("save");
        id
    };

    let vault = Vault::open(&path, password).expect("reopen");
    let summary = vault.get_entry(&id).expect("entry survives");
    let mut names = summary.attachment_names.clone();
    names.sort();
    assert_eq!(
        names,
        vec![
            "data.bin".to_string(),
            "note.txt".to_string(),
            "tiny.bin".to_string()
        ]
    );

    assert_eq!(vault.read_binary(&id, "tiny.bin").unwrap().unwrap(), tiny);
    assert_eq!(vault.read_binary(&id, "note.txt").unwrap().unwrap(), ascii);
    assert_eq!(vault.read_binary(&id, "data.bin").unwrap().unwrap(), mid);
}

fn decrypt_to_xml(path: &Path, password: &str) -> String {
    let mut f = File::open(path).expect("open vault");
    let key = keepass::DatabaseKey::new().with_password(password);
    let xml = keepass::Database::get_xml(&mut f, key).expect("decrypt xml");
    String::from_utf8_lossy(&xml).into_owned()
}

/// Removing one entry's attachment must not change what other entries'
/// attachments read back as. keepass-rs wrote attachment ids into the file
/// while storing the bytes by position, so after a removal every later
/// attachment read back as the next one's data (sseemayer/keepass-rs#374,
/// fixed on the fork trove pins).
#[test]
fn removing_one_attachment_leaves_the_others_intact() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    {
        let mut vault = Vault::create(&path, "pw").unwrap();
        for (title, bytes) in [
            ("a", b"AAAA"),
            ("b", b"BBBB"),
            ("c", b"CCCC"),
            ("d", b"DDDD"),
        ] {
            let id = vault.add_entry(title).unwrap();
            vault.attach_binary(&id, "f", bytes).unwrap();
        }
        vault.save().unwrap();
    }
    {
        let mut vault = Vault::open(&path, "pw").unwrap();
        let b = vault.find_by_title("b").unwrap();
        vault.remove_binary(&b, "f").unwrap();
        vault.save().unwrap();
    }
    let vault = Vault::open(&path, "pw").unwrap();
    let read = |title: &str| {
        let id = vault.find_by_title(title).unwrap();
        vault.read_binary(&id, "f").unwrap()
    };
    assert_eq!(read("a").as_deref(), Some(&b"AAAA"[..]));
    assert_eq!(read("b"), None);
    assert_eq!(read("c").as_deref(), Some(&b"CCCC"[..]));
    assert_eq!(read("d").as_deref(), Some(&b"DDDD"[..]));
}
