#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! Manual interop with clients CI can't drive (KeePassDX, KeePass2). Both
//! tests are `#[ignore]`d; `docs/interop-checklist.md` has the steps.
//!
//! 1. `write_fixture` writes a trove vault to `$TROVE_INTEROP_OUT`.
//! 2. A human opens it in the other client, edits the notes of the entry
//!    titled `unrelated`, saves, and copies the file back.
//! 3. `verify_returned_file` checks `$TROVE_INTEROP_FILE`: trove opens it, and
//!    the SSH and file entries carry the same attachments, byte for byte, as a
//!    freshly written fixture.

mod matrix;

use std::path::PathBuf;

use matrix::trove_party::{self, Trove, TroveAdd, TEST_ED25519_KEY};
use matrix::{crate_party, pykeepass_party, DatabaseRepr, DatabaseSpec};

/// The fixture's password. Typed by hand on a phone, so short.
const PW: &str = "demopass";

/// Entries trove writes and the other client must leave alone.
const KEPT: [&str; 2] = ["github.com", "kubeconfig-prod"];

/// The entry the human edits.
const UNRELATED: &str = "unrelated";

fn spec() -> DatabaseSpec {
    DatabaseSpec {
        name: "interop-manual".to_string(),
        password: PW,
        key: matrix::KeyMaterial::Password,
        config: matrix::Config::default(),
        entries: Vec::new(),
    }
}

fn require_trove() -> Trove {
    trove_party::locate().unwrap_or_else(|| {
        panic!("trove binary not found: build it (cargo build -p trove-cli) or set $TROVE_BIN")
    })
}

fn adds() -> Vec<TroveAdd> {
    vec![
        TroveAdd::Ssh {
            title: KEPT[0].to_string(),
            user: "git".to_string(),
            key: TEST_ED25519_KEY.as_bytes().to_vec(),
        },
        TroveAdd::File {
            title: KEPT[1].to_string(),
            src_name: "kubeconfig".to_string(),
            bytes: b"apiVersion: v1\n".to_vec(),
            target: "/tmp/kubeconfig".to_string(),
            mode: "0600".to_string(),
        },
        TroveAdd::File {
            title: UNRELATED.to_string(),
            src_name: "notes.txt".to_string(),
            bytes: b"edit my notes\n".to_vec(),
            target: "/tmp/trove-interop-notes.txt".to_string(),
            mode: "0600".to_string(),
        },
    ]
}

/// Read every entry with the keepass crate, or with pykeepass when the crate
/// can't parse the file (Bug F in docs/keepass-bugs.md).
fn read(bytes: &[u8]) -> DatabaseRepr {
    match crate_party::kp017::consume(bytes, &spec()) {
        Ok(repr) => repr,
        Err(crate_err) => {
            let py = pykeepass_party::discover()
                .unwrap_or_else(|| panic!("keepass crate can't read the file: {crate_err}"));
            pykeepass_party::consume(&py, bytes, &spec()).unwrap_or_else(|e| {
                panic!("neither the keepass crate ({crate_err}) nor pykeepass ({e}) reads it")
            })
        }
    }
}

fn env_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("set ${name}"))
}

#[test]
#[ignore = "manual: writes the fixture for docs/interop-checklist.md"]
fn write_fixture() {
    let out = env_path("TROVE_INTEROP_OUT");
    assert!(!out.exists(), "{} exists; pick a new path", out.display());
    let bytes = trove_party::produce(&require_trove(), PW, &adds()).expect("trove writes");
    std::fs::write(&out, bytes).expect("write fixture");
    eprintln!("wrote {} (password: {PW})", out.display());
}

#[test]
#[ignore = "manual: checks a file returned by another client"]
fn verify_returned_file() {
    let trove = require_trove();
    let returned = std::fs::read(env_path("TROVE_INTEROP_FILE")).expect("read returned file");

    let listed = trove_party::consume(&trove, &returned, PW).expect("trove opens the file");
    for title in KEPT.iter().chain([&UNRELATED]) {
        assert!(listed.contains_key(*title), "trove doesn't list {title}");
    }

    let reference = read(&trove_party::produce(&trove, PW, &adds()).expect("trove writes"));
    let got = read(&returned);
    for title in KEPT {
        assert_eq!(
            got[title].username, reference[title].username,
            "{title}: UserName"
        );
        assert_eq!(
            got[title].attachments, reference[title].attachments,
            "{title}: attachments (KeeAgent.settings / Materialize.settings / data) changed"
        );
    }
    assert_ne!(
        got[UNRELATED].notes, "",
        "the {UNRELATED} entry's notes weren't edited; was the file saved?"
    );
}
