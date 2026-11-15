# Manual interop checklist

CI checks trove against KeePassXC and pykeepass on every PR (see
`crates/keepass-spec-tests`). KeePassDX runs only on Android, and KeePass2's
headless KPScript has not been tried in CI, so both are checked by hand with
this list.

The check: trove writes a vault, the other client edits one unrelated entry
and saves, and trove's own entries must come back unchanged. That covers the
SSH key entry (`id` and `KeeAgent.settings` attachments) and the file entry
(the file plus `Materialize.settings`).

## Steps

Run from the repo root.

1. Build trove and write the fixture to a path that doesn't exist yet:

   ```sh
   cargo build -p trove-cli
   TROVE_BIN=$PWD/target/debug/trove TROVE_INTEROP_OUT=/tmp/trove-interop.kdbx \
     cargo test --manifest-path crates/keepass-spec-tests/Cargo.toml \
     --test interop_manual -- --ignored write_fixture
   ```

   The password is `demopass`. The vault holds three entries: `github.com`
   (SSH key), `kubeconfig-prod` (file) and `unrelated` (file).

2. Copy `/tmp/trove-interop.kdbx` to the device or machine running the client.
3. Open it with the client. Edit the **Notes** of the `unrelated` entry. Don't
   touch the other two entries. Save.
4. Copy the saved file back, e.g. to `/tmp/trove-interop-returned.kdbx`.
5. Verify:

   ```sh
   TROVE_BIN=$PWD/target/debug/trove TROVE_INTEROP_FILE=/tmp/trove-interop-returned.kdbx \
     cargo test --manifest-path crates/keepass-spec-tests/Cargo.toml \
     --test interop_manual -- --ignored verify_returned_file
   ```

   It passes when trove opens the file, the `unrelated` notes are set, and
   `github.com` and `kubeconfig-prod` have the same user name and attachment
   bytes as a freshly written fixture.

6. Record the result below.

## Results

| Client | Version | Platform | Date | Result |
| --- | --- | --- | --- | --- |
| KeePassDX | not run yet | Android | | |
| KeePass2 | not run yet | | | |
