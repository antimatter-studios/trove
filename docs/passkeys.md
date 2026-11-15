# Passkeys

trove reads passkeys the way KeePassXC's browser integration stores them, keeps
them unchanged through its own edits, and shows where each one signs in. It
does not create passkeys or sign in with them: create them in KeePassXC.
Signing with a stored passkey needs the browser native-messaging host (#448).

## Stored format

A passkey is a set of ordinary string attributes on an entry. KeePassXC also
adds the tag `Passkey`. Checked against KeePassXC 2.8.0 (tag `2.8.0`, commit
`fef511f45c191745b3822e2585de8e050daeada2`): `BrowserService::addPasskeyToEntry`
writes the attributes, `EntryAttributes` defines their names.

| Attribute | Value | Protected |
| --- | --- | --- |
| `KPEX_PASSKEY_USERNAME` | The account name on the site, as text | no |
| `KPEX_PASSKEY_CREDENTIAL_ID` | Credential id, base64url without padding | yes |
| `KPEX_PASSKEY_PRIVATE_KEY_PEM` | PKCS#8 private key, PEM (`-----BEGIN PRIVATE KEY-----`) | yes |
| `KPEX_PASSKEY_RELYING_PARTY` | Relying party id, e.g. `webauthn.io` | no |
| `KPEX_PASSKEY_USER_HANDLE` | User handle, base64url without padding | yes |
| `KPEX_PASSKEY_FLAG_BE` | Backup Eligible flag, `1` (KeePassXC also reads `true`) | no |
| `KPEX_PASSKEY_FLAG_BS` | Backup State flag, `1` (KeePassXC also reads `true`) | no |

KeePassXC 2.7.7 to 2.7.10 write the first five; the two flags are new in 2.8.0.
For StrongBox compatibility KeePassXC also reads `KPEX_PASSKEY_GENERATED_USER_ID`
in place of the credential id and `KPXC_PASSKEY_USERNAME` in place of the
username when they exist, and trove does the same.

## What trove does

- An entry holds a passkey when it has both `KPEX_PASSKEY_PRIVATE_KEY_PEM` and
  `KPEX_PASSKEY_RELYING_PARTY`.
- `trove show` prints `Passkey: <relying party> (<username>)`. `show --json`
  has a `passkey` object (relying party, username, credential id, user handle);
  `describe --json` has `has_passkey`; `list --json` and `search --json` have
  `passkey`. None of them contain the private key. It is printed only by
  `trove show <ENTRY> --attr KPEX_PASSKEY_PRIVATE_KEY_PEM --show-protected`.
- Saving, `trove edit`, `mv`, `cp`, `merge`, `sync` and history restore keep
  every `KPEX_PASSKEY_*` value and its Protected flag.
- The desktop app shows a Passkey section (relying party and username) and
  marks passkey entries in the list. Its edit form does not show or touch the
  `KPEX_PASSKEY_*` attributes.
