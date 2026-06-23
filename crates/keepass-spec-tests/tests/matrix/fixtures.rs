//! Vault fixtures for the cross-tool spec matrix.
//!
//! Two families:
//!   - CONTENT fixtures use each producer's native config and vary
//!     structure/field fidelity (empty, flat fields incl. unicode/multiline,
//!     nested groups, attachments).
//!   - CONFIG fixtures hold a trivial entry and sweep the FULL crypto/format
//!     cartesian product (KDF × outer cipher × compression × KDBX4 minor) so we
//!     exhaustively cover every combination a producer might emit.
#![allow(missing_docs)]

use crate::matrix::{Compression, Config, EntrySpec, Kdf, KeyMaterial, OuterCipher, VaultSpec};

/// Common demo password used by every fixture.
const PW: &str = "demopass";

/// Build an [`EntrySpec`] with sensible empty defaults; override fields after.
fn entry(group_path: Vec<&'static str>, title: &'static str) -> EntrySpec {
    EntrySpec {
        group_path,
        title,
        username: "",
        password: "",
        url: "",
        notes: "",
        custom_fields: Vec::new(),
        tags: Vec::new(),
        attachments: Vec::new(),
    }
}

/// All vault fixtures exercised by the cross-tool matrix: the content set plus
/// the full crypto/format cartesian product.
pub fn all() -> Vec<VaultSpec> {
    let mut v = vec![
        empty(),
        flat_fields(),
        nested_groups(),
        attachments(),
        custom_materialize(),
        custom_keeagent(),
        custom_protected(),
        custom_many(),
        tags_basic(),
        tags_and_custom(),
        scale_many_entries(),
        scale_deep_nesting(),
        scale_large_attachment(),
        scale_zero_and_many_attachments(),
        edge_field_values(),
        entry_references(),
        dup_titles_different_groups(),
        keyfile_hashed_composite(),
        keyfile_raw32_composite(),
    ];
    v.extend(config_cartesian());
    v
}

// ---------------------------------------------------------------------------
// CONTENT fixtures (native config, vary content)
// ---------------------------------------------------------------------------

fn empty() -> VaultSpec {
    VaultSpec {
        name: "empty".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: Vec::new(),
    }
}

fn flat_fields() -> VaultSpec {
    let full = EntrySpec {
        username: "git",
        password: "s3cret-pw",
        url: "https://github.com",
        notes: "single line note",
        ..entry(vec![], "github.com")
    };
    let unicode = EntrySpec {
        username: "naïve",
        password: "pä$$wörd",
        url: "https://例え.テスト",
        notes: "日本語 + emoji 🚀",
        ..entry(vec![], "café-☕")
    };
    let multiline = EntrySpec {
        username: "u",
        password: "p",
        notes: "line1\nline2\nline3",
        ..entry(vec![], "multiline")
    };
    VaultSpec {
        name: "flat-fields".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![full, unicode, multiline],
    }
}

fn nested_groups() -> VaultSpec {
    let root_entry = EntrySpec {
        username: "r",
        ..entry(vec![], "root-entry")
    };
    let work_entry = EntrySpec {
        username: "w",
        password: "wp",
        ..entry(vec!["work"], "work-entry")
    };
    let prod_db = EntrySpec {
        username: "admin",
        password: "hunter2",
        url: "db://prod",
        ..entry(vec!["work", "prod"], "prod-db")
    };
    let stage_db = EntrySpec {
        username: "stg",
        ..entry(vec!["work", "staging"], "stage-db")
    };
    VaultSpec {
        name: "nested-groups".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![root_entry, work_entry, prod_db, stage_db],
    }
}

fn attachments() -> VaultSpec {
    let one_blob = EntrySpec {
        attachments: vec![(
            "blob.bin",
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0xFF, 0x7F],
        )],
        ..entry(vec![], "one-blob")
    };
    let two_blobs = EntrySpec {
        attachments: vec![
            ("a.txt", b"hello\nworld".to_vec()),
            ("b.dat", (0u8..=255).collect::<Vec<u8>>()),
        ],
        ..entry(vec![], "two-blobs")
    };
    let mixed = EntrySpec {
        username: "u",
        password: "p",
        attachments: vec![("k.pem", b"-----BEGIN-----\nabc\n-----END-----\n".to_vec())],
        ..entry(vec![], "entry-and-fields-and-attachment")
    };
    VaultSpec {
        name: "attachments".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![one_blob, two_blobs, mixed],
    }
}

// ---------------------------------------------------------------------------
// CONTENT fixtures: custom fields + tags (trove's extension model)
//
// trove writes `Materialize.*` instructions and KeeAgent.settings-style docs
// as arbitrary custom string fields that keepassxc must treat as
// opaque-but-preserved. These fixtures prove that round-trip fidelity.
// ---------------------------------------------------------------------------

/// A trove file-entry: `Materialize.*` instructions plus the source attachment.
fn custom_materialize() -> VaultSpec {
    let kubeconfig = EntrySpec {
        custom_fields: vec![
            ("Materialize.Source", "kubeconfig", false),
            ("Materialize.Target", "/tmp/kubeconfig", false),
            ("Materialize.Mode", "0600", false),
            ("Materialize.TTL", "300", false),
            ("Materialize.AllowDiskBacked", "false", false),
        ],
        attachments: vec![(
            "kubeconfig",
            b"apiVersion: v1\nkind: Config\nclusters: []\n".to_vec(),
        )],
        ..entry(vec![], "kubeconfig-prod")
    };
    VaultSpec {
        name: "custom-materialize".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![kubeconfig],
    }
}

/// A KeeAgent-style entry: an SSH private key attachment plus a settings doc
/// carried as an arbitrary custom STRING field (single line for CLI safety).
fn custom_keeagent() -> VaultSpec {
    let github = EntrySpec {
        username: "git",
        custom_fields: vec![(
            "KeeAgent.settings.note",
            "<?xml version=\"1.0\"?><configuration><AllowUseOfSshKey>true</AllowUseOfSshKey></configuration>",
            false,
        )],
        attachments: vec![(
            "id",
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYDATA\n-----END OPENSSH PRIVATE KEY-----\n"
                .to_vec(),
        )],
        ..entry(vec![], "github.com")
    };
    VaultSpec {
        name: "custom-keeagent".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![github],
    }
}

/// A protected custom field alongside an unprotected one.
fn custom_protected() -> VaultSpec {
    let secret = EntrySpec {
        custom_fields: vec![
            ("X-Api-Token", "tok_live_abc123", true),
            ("X-Env", "prod", false),
        ],
        ..entry(vec![], "secret-config")
    };
    VaultSpec {
        name: "custom-protected".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![secret],
    }
}

/// Several custom fields at once.
fn custom_many() -> VaultSpec {
    let many = EntrySpec {
        custom_fields: vec![
            ("F1", "v1", false),
            ("F2", "v2", false),
            ("F3", "v3", false),
            ("F4", "v4", false),
            ("F5", "v5", false),
            ("F6", "v6", false),
        ],
        ..entry(vec![], "many-fields")
    };
    VaultSpec {
        name: "custom-many".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![many],
    }
}

/// Tags only.
fn tags_basic() -> VaultSpec {
    let tagged = EntrySpec {
        username: "u",
        tags: vec!["work", "ssh", "prod"],
        ..entry(vec![], "tagged")
    };
    VaultSpec {
        name: "tags-basic".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![tagged],
    }
}

/// Tags and custom fields together.
fn tags_and_custom() -> VaultSpec {
    let combo = EntrySpec {
        username: "u",
        tags: vec!["a", "b"],
        custom_fields: vec![
            ("Materialize.Target", "/tmp/x", false),
            ("Note.kind", "combo", false),
        ],
        ..entry(vec![], "combo")
    };
    VaultSpec {
        name: "tags-and-custom".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![combo],
    }
}

// ---------------------------------------------------------------------------
// CONTENT fixtures: scale (volume / depth / size stress)
//
// These push entry count, group nesting depth, and attachment size/count to
// shake out producers that buffer, truncate, or mis-index at the edges.
// The &str fields stay literal; only the Vec<EntrySpec> / Vec<u8> payloads are
// built at runtime, which is allowed.
// ---------------------------------------------------------------------------

/// 25 flat root entries, titles `e00`..`e24`, usernames `u00`..`u24`.
fn scale_many_entries() -> VaultSpec {
    // Titles/usernames must be `&'static str`, so map a fixed lookup table
    // rather than formatting at runtime.
    const TITLES: [&str; 25] = [
        "e00", "e01", "e02", "e03", "e04", "e05", "e06", "e07", "e08", "e09", "e10", "e11", "e12",
        "e13", "e14", "e15", "e16", "e17", "e18", "e19", "e20", "e21", "e22", "e23", "e24",
    ];
    const USERS: [&str; 25] = [
        "u00", "u01", "u02", "u03", "u04", "u05", "u06", "u07", "u08", "u09", "u10", "u11", "u12",
        "u13", "u14", "u15", "u16", "u17", "u18", "u19", "u20", "u21", "u22", "u23", "u24",
    ];
    let entries: Vec<EntrySpec> = TITLES
        .iter()
        .zip(USERS.iter())
        .map(|(&title, &username)| EntrySpec {
            username,
            ..entry(vec![], title)
        })
        .collect();
    VaultSpec {
        name: "scale-many-entries".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries,
    }
}

/// A single entry six group levels deep, plus one at the first level to prove
/// the intermediate groups are real and traversable.
fn scale_deep_nesting() -> VaultSpec {
    let deep = EntrySpec {
        username: "deep",
        ..entry(vec!["g1", "g2", "g3", "g4", "g5", "g6"], "deep-entry")
    };
    let mid = EntrySpec {
        username: "mid",
        ..entry(vec!["g1"], "mid-entry")
    };
    VaultSpec {
        name: "scale-deep-nesting".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![deep, mid],
    }
}

/// One root entry carrying a ~256 KiB attachment built programmatically.
fn scale_large_attachment() -> VaultSpec {
    let big_bytes: Vec<u8> = (0..256 * 1024).map(|i| (i % 256) as u8).collect();
    let big = EntrySpec {
        attachments: vec![("big.bin", big_bytes)],
        ..entry(vec![], "big")
    };
    VaultSpec {
        name: "scale-large-attachment".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![big],
    }
}

/// One root entry with a zero-byte attachment plus several tiny distinct ones.
fn scale_zero_and_many_attachments() -> VaultSpec {
    let att_edge = EntrySpec {
        attachments: vec![
            ("empty.bin", Vec::new()),
            ("a1", vec![0x01]),
            ("a2", vec![0x02, 0x02]),
            ("a3", vec![0x03, 0x03, 0x03]),
            ("a4", vec![0x04, 0x04, 0x04, 0x04]),
            ("a5", vec![0x05, 0x05, 0x05, 0x05, 0x05]),
        ],
        ..entry(vec![], "att-edge")
    };
    VaultSpec {
        name: "scale-zero-and-many-attachments".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![att_edge],
    }
}

// ---------------------------------------------------------------------------
// CONTENT fixtures: edge characters in field VALUES
//
// XML forbids NUL; everything else (quotes, separators, multiline, tabs,
// non-ASCII) is legal and must survive round-trip. We keep these in values,
// not titles/group names, so path parsing stays unambiguous.
// ---------------------------------------------------------------------------

/// One root entry whose fields stress separator/quote/whitespace/unicode/length
/// handling. The long value is a compile-time literal (no runtime `.repeat`).
fn edge_field_values() -> VaultSpec {
    // ~500 'A's as a literal so the value stays `&'static str`.
    const LONG: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let edgy = EntrySpec {
        username: "has spaces and \"quotes\"",
        password: "semi;colon,comma=equals|pipe",
        url: "https://x/y?a=1&b=2",
        notes: "trailing-space-line \n  leading-space-line\ttab",
        custom_fields: vec![
            ("X.Long", LONG, false),
            ("X.Unicode", "Zürich café ☕ — naïve", false),
        ],
        ..entry(vec![], "edgy")
    };
    VaultSpec {
        name: "edge-field-values".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![edgy],
    }
}

// ---------------------------------------------------------------------------
// CONTENT fixtures: entry-reference / placeholder literals
//
// `{REF:...}` placeholders are resolved by KeePass clients at display time. We
// only assert the LITERAL string survives round-trip; resolution is not tested.
// ---------------------------------------------------------------------------

/// A target entry plus a referrer whose fields hold literal `{REF:...}` strings.
fn entry_references() -> VaultSpec {
    let target = EntrySpec {
        username: "real-user",
        password: "real-pass",
        ..entry(vec![], "target")
    };
    let referrer = EntrySpec {
        username: "{REF:U@T:target}",
        notes: "see {REF:P@T:target}",
        custom_fields: vec![("Note.ref", "{REF:A@I:0123456789ABCDEF}", false)],
        ..entry(vec![], "referrer")
    };
    VaultSpec {
        name: "entry-references".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![target, referrer],
    }
}

// ---------------------------------------------------------------------------
// CONTENT fixtures: duplicate titles
//
// The same title in two different groups yields two distinct keys (path-based),
// so both must survive independently.
// ---------------------------------------------------------------------------

/// Title `dup` at root and again under `other`, distinguished by username.
fn dup_titles_different_groups() -> VaultSpec {
    let root_dup = EntrySpec {
        username: "root-dup",
        ..entry(vec![], "dup")
    };
    let other_dup = EntrySpec {
        username: "other-dup",
        ..entry(vec!["other"], "dup")
    };
    VaultSpec {
        name: "dup-titles-different-groups".to_string(),
        password: PW,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![root_dup, other_dup],
    }
}

// ---------------------------------------------------------------------------
// CONTENT fixtures: composite key (password + keyfile)
//
// A composite key is password AND keyfile. KDBX derives the keyfile component
// two ways depending on the file's bytes:
//   - non-32-byte, non-hex, non-XML content => SHA-256 of the whole file
//     (the "hash any file" path), and
//   - exactly 32 raw bytes => used directly as the key (the "raw 32-byte" path).
// We cover both so producers/consumers agree on keyfile handling.
// ---------------------------------------------------------------------------

/// Composite key whose keyfile is hashed (content is neither 32 bytes nor
/// hex/XML, so KDBX takes its SHA-256).
fn keyfile_hashed_composite() -> VaultSpec {
    let kf = EntrySpec {
        username: "k",
        ..entry(vec![], "kf")
    };
    VaultSpec {
        name: "keyfile-hashed-composite".to_string(),
        password: PW,
        key: KeyMaterial::PasswordAndKeyfile(
            b"trove conformance keyfile - hashed via sha256\n".to_vec(),
        ),
        config: Config::default(),
        entries: vec![kf],
    }
}

/// Composite key whose keyfile is exactly 32 bytes, used directly as the raw
/// key (the "raw 32-byte" derivation path).
fn keyfile_raw32_composite() -> VaultSpec {
    let kf = EntrySpec {
        username: "k",
        ..entry(vec![], "kf")
    };
    VaultSpec {
        name: "keyfile-raw32-composite".to_string(),
        password: PW,
        key: KeyMaterial::PasswordAndKeyfile((0u8..32).collect::<Vec<u8>>()),
        config: Config::default(),
        entries: vec![kf],
    }
}

// ---------------------------------------------------------------------------
// CONFIG fixtures (full crypto/format cartesian product)
// ---------------------------------------------------------------------------

/// A trivial single-entry payload so the focus stays on the crypto/format
/// configuration rather than content.
fn cfg_entries() -> Vec<EntrySpec> {
    vec![EntrySpec {
        username: "c",
        ..entry(vec![], "cfg")
    }]
}

/// Every (KDF × outer cipher × compression × KDBX4 minor) combination:
/// 3 × 3 × 2 × 3 = 54 fixtures. `minor` is `native` (producer default),
/// `v40` (forced 4.0), or `v41` (forced 4.1).
fn config_cartesian() -> Vec<VaultSpec> {
    let kdfs = [
        (Kdf::Argon2d, "argon2d"),
        (Kdf::Argon2id, "argon2id"),
        (Kdf::Aes, "aeskdf"),
    ];
    let outers = [
        (OuterCipher::Aes256, "aes256"),
        (OuterCipher::ChaCha20, "chacha20"),
        (OuterCipher::Twofish, "twofish"),
    ];
    let comps = [(Compression::GZip, "gzip"), (Compression::None, "none")];
    let minors: [(Option<u32>, &str); 3] = [(None, "native"), (Some(0), "v40"), (Some(1), "v41")];

    let mut out = Vec::new();
    for (kdf, kn) in kdfs {
        for (outer, on) in outers {
            for (compression, cn) in comps {
                for (minor, mn) in minors {
                    out.push(VaultSpec {
                        name: format!("cfg-{kn}-{on}-{cn}-{mn}"),
                        password: PW,
                        key: KeyMaterial::Password,
                        config: Config {
                            kdbx4_minor: minor,
                            kdf,
                            outer,
                            compression,
                        },
                        entries: cfg_entries(),
                    });
                }
            }
        }
    }
    out
}
