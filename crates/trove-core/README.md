# trove-core

kdbx-compatible vault primitives: opening, saving, and editing KeePass `.kdbx`
databases, with format compatibility with KeePassXC as a hard requirement.

The crate exposes a small, synchronous API over an open vault:

```rust
use trove_core::Vault;

let mut vault = Vault::open("vault.kdbx".as_ref(), "correct horse")?;
for entry in vault.list_entries() {
    println!("{}", entry.display_path());
}
# Ok::<(), trove_core::Error>(())
```

- `Vault::open` / `Vault::create` / `save`
- `list_entries` / `get_entry` / `find_by_title` — non-secret summaries
- `get_field` / `set_field` — read or write a single field on demand
- `add_entry` / `delete_entry`
- `attach_binary` / `read_binary` / `remove_binary`

Scope today is KDBX 4 with a password master key. The crate forbids `unsafe`
and delegates protected-value handling to the underlying `keepass` crate.

## Stability

From 1.0 the public API follows semantic versioning; see
[docs/stability.md](https://github.com/antimatter-studios/trove/blob/main/docs/stability.md).
Structs and enums that may grow, including `Error`, are `#[non_exhaustive]`:
match `Error` with a wildcard arm, and build a `SearchQuery` from
`SearchQuery::default()` with its `with_*` methods.

## License

Licensed under either of Apache-2.0 or MIT at your option.
