#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! trove ↔ pykeepass round trip, driven by the real `trove` binary.
//!
//! trove writes an SSH entry (`id` + `KeeAgent.settings` attachments) and a
//! materialize-file entry (the file + `Materialize.settings`). pykeepass must
//! read all of it exactly as the keepass crate does. pykeepass then edits an
//! unrelated entry and saves, and trove must reopen the file, save it again,
//! and leave its own entries untouched.
//!
//! Skips when pykeepass is missing, unless `TROVE_REQUIRE_PYKEEPASS=1` (CI).

mod matrix;

use matrix::trove_party::{self, Trove, TroveAdd, TEST_ED25519_KEY};
use matrix::{crate_party, pykeepass_party, DatabaseRepr, DatabaseSpec};

const PW: &str = "demopass";

fn pw_spec() -> DatabaseSpec {
    DatabaseSpec {
        name: "trove-output".to_string(),
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

fn trove_adds() -> Vec<TroveAdd> {
    vec![
        TroveAdd::Ssh {
            title: "github.com".to_string(),
            user: "git".to_string(),
            key: TEST_ED25519_KEY.as_bytes().to_vec(),
        },
        TroveAdd::File {
            title: "kubeconfig-prod".to_string(),
            src_name: "kubeconfig".to_string(),
            bytes: b"apiVersion: v1\n".to_vec(),
            target: "/tmp/kubeconfig".to_string(),
            mode: "0600".to_string(),
        },
    ]
}

/// The keepass crate's view of `bytes`, which trove itself uses.
fn crate_view(bytes: &[u8]) -> DatabaseRepr {
    crate_party::kp017::consume(bytes, &pw_spec()).expect("keepass crate opens the database")
}

#[test]
fn pykeepass_reads_trove_output_and_trove_reopens_pykeepass_save() {
    let Some(py) = pykeepass_party::discover() else {
        eprintln!("pykeepass not found: skipping (set TROVE_REQUIRE_PYKEEPASS=1 to fail)");
        return;
    };
    let trove = require_trove();

    let bytes = trove_party::produce(&trove, PW, &trove_adds()).expect("trove produces a database");
    let trove_entries = crate_view(&bytes);
    let ssh = &trove_entries["github.com"];
    let file = &trove_entries["kubeconfig-prod"];
    for name in ["id", "KeeAgent.settings"] {
        assert!(ssh.attachments.contains_key(name), "ssh entry lacks {name}");
    }
    for name in ["kubeconfig", "Materialize.settings"] {
        assert!(
            file.attachments.contains_key(name),
            "file entry lacks {name}"
        );
    }

    // pykeepass reads every field, custom field, tag and attachment byte the
    // same way the keepass crate does.
    let read = pykeepass_party::consume_with(&py, &bytes, PW, None)
        .expect("pykeepass opens trove's database");
    assert_eq!(
        read, trove_entries,
        "pykeepass@{} read trove's database differently",
        py.version
    );

    // pykeepass edits an unrelated entry and saves. It appends the new Notes
    // field after <Times>, which released keepass-rs can't read (matrix
    // finding #8), so pykeepass itself is the reference reader here.
    let edited = pykeepass_party::edit_notes(&py, &bytes, PW, "unrelated", "edited by pykeepass")
        .expect("pykeepass edits and saves");
    let after_py = pykeepass_party::consume_with(&py, &edited, PW, None)
        .expect("pykeepass reopens its own save");
    assert_eq!(after_py["unrelated"].notes, "edited by pykeepass");
    for title in ["github.com", "kubeconfig-prod"] {
        assert_eq!(
            after_py[title], trove_entries[title],
            "pykeepass@{} changed trove's entry {title} on save",
            py.version
        );
    }

    // trove opens pykeepass's file, lists it, and saves it again.
    let listed = trove_party::consume(&trove, &edited, PW).expect("trove opens pykeepass's save");
    let mut titles: Vec<&str> = listed.keys().map(String::as_str).collect();
    titles.sort_unstable();
    assert_eq!(titles, ["github.com", "kubeconfig-prod", "unrelated"]);

    let resaved = trove_party::resave_with_added_ssh(
        &trove,
        &edited,
        PW,
        "second-key",
        TEST_ED25519_KEY.as_bytes(),
    )
    .expect("trove saves pykeepass's file");
    let after_trove = crate_view(&resaved);
    for title in ["github.com", "kubeconfig-prod", "unrelated"] {
        assert_eq!(
            after_trove[title], after_py[title],
            "trove changed entry {title} when re-saving pykeepass's file"
        );
    }
    assert!(after_trove.contains_key("second-key"));

    // And pykeepass still reads trove's re-save.
    let reread = pykeepass_party::consume_with(&py, &resaved, PW, None)
        .expect("pykeepass opens trove's re-save");
    assert_eq!(reread, after_trove);
}
