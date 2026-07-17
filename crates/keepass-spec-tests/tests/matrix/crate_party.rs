//! Producer + consumer for each linked `keepass` crate version.
//!
//! Two `keepass` crates are linked under distinct names in `Cargo.toml`:
//!   - `keepass`     = 0.12.5  -> module `kp012`
//!   - `keepass_013` = 0.13.13 -> module `kp013`
//!
//! Their public APIs are identical for everything we touch, so a single
//! `macro_rules!` generates the per-version module; we invoke it twice. Each
//! module exposes:
//!   - `produce(spec: &VaultSpec) -> Vec<u8>`  — mint a `.kdbx` from a logical spec.
//!   - `consume(bytes: &[u8], spec: &VaultSpec) -> Result<VaultRepr, String>` — open
//!     a `.kdbx` (using `spec`'s credentials) and recover its content into the
//!     normalized comparison repr.
#![allow(missing_docs)]

/// Generate a `produce`/`consume` module for one linked `keepass` crate.
///
/// `$mod` is the module name (`kp012` / `kp013`); `$kp` is the crate's linked
/// ident (`keepass` / `keepass_013`). Every `keepass` path inside is written as
/// `$kp::...` so the macro binds to the correct crate version.
macro_rules! crate_impl {
    ($mod:ident, $kp:ident) => {
        pub mod $mod {
            use crate::matrix::{
                Compression, Config, EntryRepr, Kdf, OuterCipher, VaultRepr, VaultSpec,
            };

            use $kp::{
                config::{
                    CompressionConfig, DatabaseConfig, DatabaseVersion, InnerCipherConfig,
                    KdfConfig, OuterCipherConfig,
                },
                db::{fields, Database, GroupId, GroupRef, Value},
                DatabaseKey,
            };

            // Deliberately cheap KDF parameters so minting stays fast. `memory`
            // is in KiB (matching `common/mod.rs`); we shrink it further here.
            fn kdf_config(kdf: Kdf) -> KdfConfig {
                match kdf {
                    Kdf::Argon2d => KdfConfig::Argon2 {
                        iterations: 1,
                        memory: 16 * 1024,
                        parallelism: 1,
                        version: argon2::Version::Version13,
                    },
                    Kdf::Argon2id => KdfConfig::Argon2id {
                        iterations: 1,
                        memory: 16 * 1024,
                        parallelism: 1,
                        version: argon2::Version::Version13,
                    },
                    Kdf::Aes => KdfConfig::Aes { rounds: 16 },
                }
            }

            fn database_config(config: &Config) -> DatabaseConfig {
                let mut cfg = DatabaseConfig::default();
                // Only force the KDBX4 minor when the fixture asks for a specific
                // one; otherwise keep this crate version's native default (0.12.5
                // → 4.0, 0.13.13 → 4.1) since 0.13.13 can only *save* 4.1.
                if let Some(minor) = config.kdbx4_minor {
                    cfg.version = DatabaseVersion::KDB4(minor as u16);
                }
                cfg.outer_cipher_config = match config.outer {
                    OuterCipher::Aes256 => OuterCipherConfig::AES256,
                    OuterCipher::ChaCha20 => OuterCipherConfig::ChaCha20,
                    OuterCipher::Twofish => OuterCipherConfig::Twofish,
                };
                cfg.compression_config = match config.compression {
                    Compression::GZip => CompressionConfig::GZip,
                    Compression::None => CompressionConfig::None,
                };
                cfg.inner_cipher_config = InnerCipherConfig::ChaCha20;
                cfg.kdf_config = kdf_config(config.kdf);
                cfg.public_custom_data = None;
                cfg
            }

            /// Find-or-create the group at `path` (ancestor names below root),
            /// returning its id. Each `db` borrow is scoped tightly so the
            /// immutable lookup and the mutable `add_group` never overlap.
            fn ensure_group(db: &mut Database, path: &[&str]) -> GroupId {
                let mut cur = db.root().id();
                for name in path {
                    let existing = {
                        let g = db.group(cur).unwrap();
                        let mut found = None;
                        for c in g.groups() {
                            if c.name == **name {
                                found = Some(c.id());
                                break;
                            }
                        }
                        found
                    };
                    cur = existing.unwrap_or_else(|| {
                        let mut gm = db.group_mut(cur).unwrap();
                        let mut ng = gm.add_group();
                        ng.name = (*name).to_string();
                        ng.id()
                    });
                }
                cur
            }

            /// Build the `DatabaseKey` for `spec`: always password-based, plus a
            /// keyfile when the credential axis is composite. Shared by `produce`
            /// and `consume` so mint and open use identical key material.
            fn db_key(spec: &VaultSpec) -> Result<DatabaseKey, String> {
                let mut k = DatabaseKey::new().with_password(spec.password);
                if let Some(kf) = spec.key.keyfile() {
                    k = k
                        .with_keyfile(&mut std::io::Cursor::new(kf))
                        .map_err(|e| e.to_string())?;
                }
                Ok(k)
            }

            pub fn produce(spec: &VaultSpec) -> Result<Vec<u8>, String> {
                let mut db = Database::with_config(database_config(&spec.config));

                for e in &spec.entries {
                    let gid = ensure_group(&mut db, &e.group_path);
                    {
                        let mut gm = db.group_mut(gid).unwrap();
                        let mut entry = gm.add_entry();
                        entry.set_unprotected(fields::TITLE, e.title);
                        if !e.username.is_empty() {
                            entry.set_unprotected(fields::USERNAME, e.username);
                        }
                        if !e.password.is_empty() {
                            entry.set_protected(fields::PASSWORD, e.password);
                        }
                        if !e.url.is_empty() {
                            entry.set_unprotected(fields::URL, e.url);
                        }
                        if !e.notes.is_empty() {
                            entry.set_unprotected(fields::NOTES, e.notes);
                        }
                        for (key, value, protected) in &e.custom_fields {
                            if *protected {
                                entry.set_protected(*key, *value);
                            } else {
                                entry.set_unprotected(*key, *value);
                            }
                        }
                        for tag in &e.tags {
                            entry.tags.push((*tag).to_string());
                        }
                        for (name, bytes) in &e.attachments {
                            entry.add_attachment(*name, Value::unprotected(bytes.clone()));
                        }
                    }
                }

                let key = db_key(spec)?;
                let mut buf = Vec::new();
                db.save(&mut buf, key).map_err(|e| e.to_string())?;
                Ok(buf)
            }

            pub fn consume(bytes: &[u8], spec: &VaultSpec) -> Result<VaultRepr, String> {
                let key = db_key(spec)?;
                let mut cursor = std::io::Cursor::new(bytes);
                let db = Database::open(&mut cursor, key).map_err(|e| e.to_string())?;

                let mut out = VaultRepr::new();
                walk(&db.root(), &mut Vec::new(), &mut out);
                Ok(out)
            }

            /// Recursively collect entries. `prefix` holds the ancestor group
            /// names EXCLUDING root; an entry's path is
            /// `prefix.join("/") + "/" + title` (no leading slash; a root entry
            /// => bare title).
            fn walk(group: &GroupRef<'_>, prefix: &mut Vec<String>, out: &mut VaultRepr) {
                for e in group.entries() {
                    let title = e.get(fields::TITLE).unwrap_or("");
                    let mut path = prefix.join("/");
                    if !path.is_empty() {
                        path.push('/');
                    }
                    path.push_str(title);

                    // Standard string fields are surfaced as their own EntryRepr
                    // members; everything else on the entry is a custom field.
                    const STANDARD_KEYS: [&str; 5] = [
                        fields::TITLE,
                        fields::USERNAME,
                        fields::PASSWORD,
                        fields::URL,
                        fields::NOTES,
                    ];

                    let mut custom_fields = std::collections::BTreeMap::new();
                    for (k, v) in &e.fields {
                        if !STANDARD_KEYS.contains(&k.as_str()) {
                            custom_fields.insert(k.clone(), v.get().clone());
                        }
                    }

                    let mut tags: Vec<String> = e.tags.clone();
                    tags.sort();

                    let repr = EntryRepr {
                        username: e.get(fields::USERNAME).unwrap_or("").to_string(),
                        password: e.get(fields::PASSWORD).unwrap_or("").to_string(),
                        url: e.get(fields::URL).unwrap_or("").to_string(),
                        notes: e.get(fields::NOTES).unwrap_or("").to_string(),
                        attachments: e
                            .attachments_named()
                            .map(|(n, a)| (n.to_string(), hex::encode(a.data.get())))
                            .collect(),
                        custom_fields,
                        tags,
                    };
                    out.insert(path, repr);
                }

                for cg in group.groups() {
                    prefix.push(cg.name.clone());
                    walk(&cg, prefix, out);
                    prefix.pop();
                }
            }
        }
    };
}

crate_impl!(kp012, keepass);
crate_impl!(kp013, keepass_013);
