# Changelog

All notable changes, per released version. trove is pre-1.0, so minor versions
may carry behavior changes. The most recent releases are also summarized in the
README; the full history and the pre-1.0 development milestones live here.

## v0.17.4 — 2026-09-20

**Entry paths in the desktop app are relative to the folder you are in.** The
path field was absolute and saving reset the folder to All Entries, so every
save lost your place in the tree. Typing `ssh` inside `Infra` now creates
`Infra/ssh`; a leading `/` escapes to the root, so `/Personal/thing` goes where
it says regardless of where you are standing. The field previews where a path
will land. Editing shows the path relative to the current folder, because
showing the full path would re-prefix it on save.

**Saving stays where you are** unless the entry has left the view, and only
then follows it. Editing an entry in a subfolder while browsing its parent no
longer navigates deeper for no reason.

**A folder lists what is filed directly in it**, the way a file browser does —
subfolders are things you click into, not contents that spill into the list.
Its badge counts that rather than the whole subtree, with the recursive total
moved to a tooltip.

Two bugs found by using the app rather than testing it. Pressing **New entry**
while the edit form was open kept the previous entry's values on screen and
would have saved them as a duplicate of that entry — the form was never keyed,
so React reused it and its state initialiser did not re-run. And a new entry no
longer arrives with a **generated password**: most new entries record a
credential that already exists, and in a password manager a value nobody asked
for is alarming before it is convenient, because nothing on screen says whether
it was generated, leaked in from another entry, or a bug. The generate button
beside the field covers the other case in one click.

## v0.17.3 — 2026-09-18

**Attributes are editable in the desktop app, not just copyable.** The detail
pane showed an entry's attributes and let you copy them, and that was all —
adding or changing one meant leaving the app for KeePassXC or the CLI. That is
not a rare corner: a `git.token` attribute is how the credential helper is told
to send a personal access token rather than the web login, and there was no way
to create one from the app that stores it.

The edit form now has an Attributes section with name/value rows, add and
remove. Saving reconciles: what is present is set, what was removed is deleted.

Three things it deliberately refuses to do, each of which would lose data
quietly. `_Trove*` and `Materialize.*` are hidden from the form and survive a
save that never mentioned them, so editing an entry's username cannot destroy
its materialize config. An attribute may not be named `Title`, `UserName`,
`Password`, `URL` or `Notes` — attributes are written after the standard
fields, so a `Password` attribute would replace the password just typed and
then vanish from the attribute list, leaving nothing on screen to show where it
went. And names are stored exactly as given, because trimming them would rename
an existing attribute as a side effect of saving something else.

## v0.17.2 — 2026-09-18

**The git credential helper sends a `git.token` attribute when the entry has
one.** Forges increasingly refuse account passwords for git over HTTPS and want
a personal access token instead, but the entry for a self-hosted forge is
usually also the web login — so `Password`, the only field the helper read, was
already holding the site password. Putting the token there cost you the web
login; keeping the web login there meant git could not authenticate.

```
antimatter-studios/git
  Password:   my-web-login       # still logs into the web UI
  git.token:  a1b2c3…            # what git gets
```

`git.token` is an ordinary KDBX custom string field, so KeePassXC shows and
edits it under an entry's additional attributes like any other. The name is
matched case-insensitively, and an empty value counts as absent rather than as
"send nothing", so a half-filled attribute cannot break an entry whose
`Password` still works.

## v0.17.1 — 2026-09-18

**`--env` needs its path attached, and stops eating the subcommand.** `--env`
takes an optional value, and an option whose value is optional consumes
whatever follows it — which is usually the subcommand. So
`trove --vault v --env git-credential get` read `git-credential` as the path
and then ran `trove get`. That is the git credential helper's exact
invocation, since `credential.helper` holds everything up to the subcommand
and git appends the operation, so the one command `--env` exists to serve was
the one command it broke, silently, by running a different one.

Bare `--env` still searches for `.env.trove`. **Naming a file is now
`--env=<PATH>`** — the space-separated form no longer works, and says so,
naming the replacement rather than failing as `unrecognized subcommand`.
A `credential.helper` line needs no change: it uses bare `--env`.

Flags were never affected — `--env --keychain status` always parsed, because a
`-`-prefixed token is not taken as an optional value. Only bare words were
swallowed.

## v0.17.0 — 2026-09-16

**`trove cp` duplicates an entry, key material and all.** One SSH key reused
across several machines ends up filed under whichever service it was first
created for, and then the name lies — a key called `antimatter-studios/gitea`
is also what grants shell access to a Raspberry Pi. Giving it a second, accurate
name previously meant `trove get`ting the private key to disk and
`trove add ssh`ing it back, writing a key that had never existed outside the
vault onto a filesystem:

```sh
trove cp "antimatter-studios/gitea" "homelab/ssh"
```

Everything the entry holds comes with it — private key, derived `id.pub`,
`KeeAgent.settings`, custom fields, password, every attachment — because a
partial copy looks usable and is not: an SSH entry without its settings blob is
silently skipped by the agent. The copy is **independent and deliberately
unmarked**: nothing records that two entries share key material, because such a
link invites tooling that treats them as one thing, and then rotating the first
key takes the second with it before anyone has rotated that one. Two names for
one key is the transitional state; rotating them apart is the point.

**`trove mv` renames while it moves.** It took a group and nothing else, so
relocating and renaming were separate commands and doing both left a window
where the entry sat in the right group under the wrong name. It now resolves a
destination the way Unix does, and the rule that made it strict survives — the
destination's parent must already exist, so a typo still fails:

```sh
trove mv "a/key" "homelab"       # homelab is a group  -> homelab/key
trove mv "a/key" "homelab/ssh"   # ssh does not exist  -> homelab/ssh
trove mv "a/key" "typo/ssh"      # typo does not exist -> error
```

Both verbs resolve their destination through one function, refuse a path
another entry already occupies, and carry an alias so the pair stays symmetric:
`cp`/`copy`, `mv`/`move`. A move now rebuilds the agent stores as a copy does —
an SSH key's agent comment is its display path, so without that the agent goes
on announcing a path that no longer exists.

## v0.16.0 — 2026-09-16

**An agent with more than six keys can lock you out of a server.** `sshd`'s
`MaxAuthTries` defaults to 6, counted per connection, and every key an agent
lists is offered and counted against it — the publickey query phase carries no
signature, but it still costs an attempt. trove's agent serves every key in
every unlocked vault, so a key sitting past the sixth is never reached and the
connection dies with `Received disconnect: Too many authentication failures`,
which reads as the server rejecting you. The agent's order is not stable across
unlocks, so an unchanged setup works at 15:00 and fails at 17:00, and `sshd`
logs a failure from the fourth offer onward, which is what `fail2ban` counts.

**Choose exactly what gets offered.** `trove ssh-agent empty` prints the path to
a new, private agent socket serving nothing, and `trove ssh-agent add <entry>`
puts one named entry's key on it:

```sh
sock=$(trove ssh-agent empty) || exit 1
export SSH_AUTH_SOCK="$sock"
trove ssh-agent add "Infra/s1"
```

Assign first and export second — `export VAR=$(cmd)` returns export's own status,
so a failure passes even under `set -e` and leaves `SSH_AUTH_SOCK` empty, which
`ssh` reads as no agent at all. Every `empty` is a separate socket with its own
keys, so callers running in parallel cannot disturb each other's offers. Key
material never leaves the daemon — a private socket is served by the same agent
code as the main one — and the daemon owns the lifetime, so the sockets go on
`lock`, on idle-lock and at shutdown, and a key that leaves the vault leaves
them at the same moment.

**Or let the agent choose, from the server's host key.** An entry can name the
servers its key is for in an `SshAgent.HostKeys` field, and the agent then offers
only the keys that claim the host `ssh` is connecting to:

```sh
trove edit "Infra/s1" --set "SshAgent.HostKeys=$(ssh-keyscan example.com)"
```

Raw `ssh-keyscan` output goes in unedited, which matters because `ssh-keyscan`
authenticates nothing — collecting a host key cannot itself contribute to a
lockout. The agent learns the host from `session-bind@openssh.com`, which `ssh`
sends before asking for identities and separately on every hop of a `ProxyJump`;
that ordering was measured rather than assumed, and the measurement is in
`docs/ssh-agent-session-bind.md`. When nothing claims the host, everything is
offered exactly as before, so switching this on cannot take a working setup
away. `trove ssh-agent which <host>` shows what would be offered without
connecting, and `TROVE_SSH_STRICT_HOSTKEYS=1` makes a miss offer nothing for
callers who would rather find out immediately.

## v0.15.0 — 2026-09-10

**Desktop attachments reach the file.** Adding, replacing, renaming or deleting
an attachment in the app changed the vault in memory and stopped there, so the
work survived exactly as long as the window stayed open. Every mutating command
now goes through one path that mutates and then saves — entry save, delete and
favourite included.

**A save says how long it is going to take.** KDBX rotates the master seed on
every write, so every write re-derives the key with Argon2; at KeePassXC's own
defaults that is seconds, and it cannot be cached without encrypting two
versions of a vault under one key. The app now measures its own unlock, re-times
each save, and draws the progress bar against that measurement rather than an
invented duration. A picked file appears in the list immediately, marked
*saving*, instead of the list sitting empty and looking broken.

**Attachments are identified by their bytes, not their names.** KDBX stores a
name and a blob and no content type, and the name is whatever someone typed.
PNG, JPEG, GIF, WebP, BMP, TIFF, ICO, AVIF, HEIC and SVG are recognised and
shown as pictures — over a checkerboard, so a transparent image reads as
transparent — and PDF, Zip, gzip, SQLite, ELF, Mach-O and DER are at least named
rather than reported as an opaque blob. SVG offers the picture and the source.

**Adding a file is one action.** "Add file…" and "New" were two matching buttons
for what read as the same thing. One button picks a file that exists; a quiet
link beside it starts a blank one to type into.

Also here: the attachment file picker itself (bytes stored verbatim, so a
`.p12` or a DER certificate survives the round trip), Credentials moved to the
top of an entry, section headings and minor labels lifted from 2.5:1 to 6.4:1
and 4.6:1 contrast, `Materialize.*` no longer duplicated in Attributes, and the
debug-build KDF override corrected to `rust-argon2` — the misnamed override was
silently ignored, which is what made a debug save take ten seconds.

## v0.14.0 — 2026-09-09

**Saving no longer overwrites another writer's changes.** `Vault::save()` wrote
memory over disk unconditionally — no comparison of any kind — so with the
desktop app open and the CLI editing the same file, whichever saved last threw
the other's work away silently. That is one file with several writers: the CLI,
the app, KeePassXC, and the same vault synced onto a second Mac.

`save()` now records what the file looked like when it was read and refuses to
write over a file that changed since. The desktop app checks every three
seconds while a vault is open and the window visible, and again on regaining
focus, then reloads and says so — a list that stopped being true is worse than
one that jumps, and the selection survives when its entry still exists.

**Materialization describes an attachment, not an entry.** An entry holds
several — an SSH key and its `.pub`, a certificate and the key that matches it
— but there was one `Materialize.Target` per entry, with `Materialize.Source`
naming which single attachment it applied to. The settings are now keyed by the
attachment:

    Materialize.<attachment>.Target
    Materialize.<attachment>.Mode
    Materialize.<attachment>.TTL
    Materialize.<attachment>.AllowDiskBacked

One entry writes as many files as ask, each with its own mode — which matters
immediately, since a private key wants `0600` and its public half does not.
`Source` is gone: the name in the key is the attachment. The entry-level form
is removed rather than kept alongside, and an entry still carrying it is
reported as an error naming what to rename — an entry that asked for a file and
silently got none is the worst outcome available.

**`trove rename-attachment`** renames an attachment and everything that names
it: the `Materialize.<name>.*` settings follow, and `KeeAgent.settings` is
rewritten to point at the new file while keeping the lifetime, confirm and
remove-at-close it already said.

**Touch ID unlocks the desktop app.** The unlock screen offers a fingerprint
when the vault has a password stored for it, and "Remember with Touch ID"
enrols after a password the vault has just accepted — never from what someone
typed into a box. Cancelling returns to the password field rather than showing
an error, because cancelling is a decision.

Worth being plain about what this is: the fingerprint is a gate in the
application's own code, not a cryptographic binding, so anything that can
already read your login keychain can reach the password without a prompt. The
stronger form needs an entitlement that only a bundle carrying a provisioning
profile may claim — measured, not assumed — and will replace only the storage
layer when it lands.

**The app's bundle identifier is `com.antimatterstudios.trove`**, matching the
other applications in this account. macOS keys an app's config directory by
that identifier, so the registered-vault list and settings are copied across on
first run rather than being orphaned.

## v0.13.0 — 2026-09-09

**Breaking: `TROVE_DB_PASSWORD` is now `TROVE_VAULT_PASSWORD`.** Rename it in
your `.env.trove`. There is no fallback and no deprecation period — a secret
that answers to two names is exactly the thing that rots quietly. Nothing else
in trove says "DB": the vault is a vault everywhere else, `TROVE_VAULT` is its
path, and this is that vault's password.

**`--keychain` takes the password from the macOS login keychain**, managed with
`trove keychain save|forget|status`. `save` proves the password opens the vault
before storing it, because an entry that does not work is worse than no entry —
it fails later and somewhere else.

It is opt-in, and it is the lowest-priority source. `--env` and
`--password-stdin` both outrank it, and it refuses outright when there is no
interactive terminal. That is not caution for its own sake: a keychain read can
raise a system dialog — the ACL trusts a particular binary, and `brew upgrade`
replaces that binary, so the "unfamiliar binary" prompt recurs — and a dialog on
a Mac nobody is sitting at is a command that never returns. On a remote session
that costs the work in flight. So the sources that cannot block always win,
giving both `--env` and `--password-stdin` is harmless (the file wins, stdin
remains if it yields nothing), and when a higher-priority source is present
trove says which one won rather than leaving it ambiguous.

There is no biometry here, and it is worth recording why. Touch ID needs
`kSecAttrAccessControl` on the data-protection keychain, which needs a
team-prefixed `keychain-access-groups` entitlement, which under Developer ID
needs a provisioning profile, which only an `.app` bundle can carry. A bare
executable claiming that entitlement is killed at exec — measured, not assumed.
Touch ID therefore belongs to `Trove.app`, and `--touchid` will be served by a
helper inside that bundle rather than by this binary.

**docs/cli-reference.md documents the `.env.trove` file properly** — where bare
`--env` looks and why, the syntax, why there is deliberately no `~/.config`
location (dotfile repositories get committed, and this file holds a vault
password), the permission warning and `TROVE_ENV_STRICT`, and the
password-source order with the reason each source sits where it does.

## v0.12.0 — 2026-09-08

**One listing shape.** 0.11.0 grouped `list` by folder; in use that is not worth
it. A header per folder saves horizontal repetition and costs the property that
matters more — every line being a complete path you can grep for and paste
straight into `trove show` — and it left `list` and `search` printing the same
data two different ways. Both now print one entry per line as
`group/sub/title`, sorted by full path, with the same column saying what each
entry carries. `list` keeps a trailing count; `search` does not, since a hit
count belongs to a query rather than to a vault.

**An env file anyone can read now says so.** `--env` loads a vault password from
a file, and a real one was sitting at mode 0644 with nothing said about it. ssh
refuses a private key at 0644 outright and this file is worse — it opens the
whole vault, not one key.

trove warns rather than refuses, because the two files do not live in the same
world. `~/.ssh` is local, owned, on a real filesystem. An env file may sit in a
synced folder — iCloud Drive does not guarantee POSIX modes survive a sync, so
0600 on one Mac can arrive 0644 on the next — or on a volume mounted
`noowners`, where the bits mean nothing at all. Refusing on that evidence would
break unlocks for a reason the user did not cause and cannot fix from there.
`TROVE_ENV_STRICT=1` opts into ssh's behaviour where the bits can be trusted.
Unix only: Windows has no comparable modes.

## v0.11.0 — 2026-09-08

**`trove list` is readable.** It led with 36 characters nobody reads, in
insertion order, with every line repeating its folder and the one attachment
name worth seeing buried under its `.pub` half and KeePassXC's settings blob:

    d45b1785-cc74-43c9-adfc-7523e4a1a0d9  Semdatex/ssh christhomas@100.101.102.187  [attachments: semdatex.id_ed25519.pub, KeeAgent.settings, semdatex.id_ed25519]

Entries are now grouped by folder and sorted naturally and case-insensitively,
with one short column saying what each carries: an SSH entry is named by its
private key, a single attachment by its name, several by a count.
`KeeAgent.settings` is never shown or counted — it is KeePassXC's per-entry
agent policy, not something anyone attached.

An SSH entry is recognised from its contents rather than a naming convention: a
private key is an attachment whose name plus `.pub` is also attached, or — when
KeePassXC left its settings blob — whichever attachment is not a public half.
That catches `00000.inpace.build.id_ed25519` and `id_ed25519.sandbox.staging`,
which no pattern would have.

The UUID moved behind `--show-id`. Nothing takes one — every command resolves
entries by title or path — so it was noise pushing the readable part rightward.
`--json` still carries it. `search` gained the same contents column but stays
flat: its results cross folders, so grouping would bury the path that says where
each hit lives.

The conformance harness was itself parsing that display format, UUID and
`[attachments: …]` marker and all. It reads `list --json` now, which is the
interface — and cannot break again the next time the human output improves.

## v0.10.0 — 2026-09-07

**`trove show --json`.** `list` and `search` already had it; `show` did not, so
anything reading one entry was parsing a display format — slicing the label off
an `Attachments:` line and splitting on commas, which breaks on the first
attachment whose name contains one. `--json` prints an object instead:
attachments as an array, custom fields as an object of values rather than a list
of names, and absent scalars as `null` so "empty" and "unset" are
distinguishable. Protected values keep the rule the human output already has —
a password is an *absent key* unless `--show-protected`, never an empty string,
so a caller can tell "you did not ask" from "there is none".

In daemon mode custom fields come back as names mapped to `null`: the summary
RPC carries names only and each value is a separate code-gated round trip, so
populating them would mean `--json` quietly pulling every secret in an entry
across the wire. `--attr` remains the way to read one deliberately.

**Bare `--env` looks beside the vault.** It meant one hardcoded relative path,
so `trove unlock ~/vaults/work.kdbx --env` failed with `No such file or
directory` while `.env.trove` sat next to the vault that command named — and the
error quoted a path the user never typed. It now looks in the working directory
first, so a checkout can override, then in the directory holding the vault,
which is where the file belongs when a vault and its settings are kept together.
With neither present the error lists every place tried. Deliberately not a
user-wide config directory: `~/.config` gets committed to dotfile repositories,
and this file holds a vault password.

## v0.9.1 — 2026-09-06

**The app is called Trove.** The Dock read "TroveDesktop" — the name of the
repository that builds it, not something a person calls an application. The Dock
and Finder label an app by its bundle filename, so the display keys in
`Info.plist` could not fix this on their own: LaunchServices already held a
friendlier name while the Dock showed otherwise. `productName` is what names the
bundle, so the app is now `Trove.app`, with `CFBundleName` and the window title
agreeing with it.

The identifier stays `com.trove.desktop`, so macOS treats this as the same
application — preferences and granted permissions carry over rather than
resetting. The Homebrew cask token stays `trove-desktop`, which is what keeps it
a separate package from the `trove-cli` formula, and the CLI is still `trove`.
The macOS release asset is now `Trove_<version>_universal.dmg`.

## v0.9.0 — 2026-09-06

**Unlocking in the desktop app no longer freezes the window.** Every
`#[tauri::command]` was synchronous, so it ran on the main thread and blocked
the event loop for the whole Argon2 derivation — on a vault tuned to 50 rounds
and 64 MB that is seconds of a dead window and a spinning cursor. All sixteen
commands now run off the main thread, and the unlock reports each step as it
happens rather than going dark and finishing all at once.

**Locking is two ideas now, because one button was doing both.** *App lock*
hides the window and takes nothing back from the machine; it is what the idle
timer fires. *Data lock* removes that vault's keys from the system agent and
dematerializes its files. Data lock applies to one database, so with several
open you land on the next open vault rather than at a login screen — you have
finished with that vault, not with the app. The old single "lock" left people
guessing which of those it meant.

**Every SSH entry carries its own agent policy.** Whether to load it at all, how
long it lives, whether the agent confirms each signature, and whether a data
lock takes it back — written to `KeeAgent.settings` in the encoding KeePassXC
reads, so the two applications agree about the same vault.

**`SSH_AUTH_SOCK` is a snapshot, and trove now copes when it goes stale.** macOS
restarts its launchd ssh-agent on a fresh socket directory, and from that moment
every shell, daemon and GUI app started earlier still exports the old path.
Forwarding failed with `Connection refused` once per key, which reads as trove
being broken and left the user diagnosing a variable they never set. Trove now
probes the socket by asking for the identity list and requiring a real
`SSH_AGENT_IDENTITIES_ANSWER` — a socket file with nothing behind it proves
nothing — and if that fails it asks launchd where the agent is listening now.
Every candidate is verified the same way before a key is sent to it, so a wrong
guess costs a connection attempt rather than a leaked key.

Forwarding into the live agent is only half of it: `ssh`, `git` and `ssh-add`
read the variable for themselves, so a caller still holding the stale one cannot
reach the keys that were just forwarded. The daemon returns the socket it used
and `unlock` puts it in the session shell, or prints it beside
`export TROVE_SESSION=…` — but only when it had to correct it, so a working
environment is left exactly as it was. `TROVE_SSH_HEAL=0` switches this off for
anyone who pinned an agent deliberately and would rather see it fail than have
keys go elsewhere; `TROVE_SSH_AGENT_SOCK` names one outright.

**`--no-shell`** is an alias for `--export`: automation wants to say what it is
avoiding, and a subshell is the thing a harness has no way to exit.

The window title bar carries the vault name, the forwarded-key count and their
expiry, and the build stamp. The toolbar row is gone — search sits above the
list it filters, lock state on the vault chip it describes, the app controls at
the top of the detail column, and Data lock above New entry in the sidebar.

## v0.8.0 — 2026-09-05

**Unlocking in the desktop app now does what unlocking in the daemon does.** The
app held its own vault and talked to nothing, so opening one gave you an entry
list and no more: no agent keys, no materialized files, nothing another
application or a terminal could see. It now forwards the vault's SSH keys into
the system agent and writes `Materialize.*` entries to their targets, and
locking undoes both — files first, then keys. Per-vault bookkeeping means
locking one vault never retracts another's keys. Both are settings-gated, with a
settings panel and a per-entry "add this key to the system agent" toggle that
writes the same `KeeAgent.settings` KeePassXC reads. A GUI has no shell, so this
is the only route from a desktop unlock to the rest of the machine.

**KeePassXC's `KeeAgent.settings` are finally read correctly.** On a real
KeePassXC vault trove served 2 SSH keys where KeePassXC served 5, and the two
that worked got in through the content-scan fallback — every key the user had
explicitly marked was skipped, silently. Three causes: the file is UTF-16 and
`str::from_utf8` *accepts* those bytes (NUL is valid UTF-8), so every tag lookup
missed; `SelectedType` is written lowercase; and the constraint tags are spelled
`...WhenAdding`, not `...WhenSigning`, so lifetime and confirm constraints never
applied. Reading now handles UTF-8 and UTF-16 (either byte order, BOM optional),
matches case-insensitively, and accepts both tag spellings. Since we read both
encodings we write both — `settings_xml_encoded` takes an `Encoding`, and the
declared `encoding=` always matches the bytes. Proven against the real
`keepassxc-cli` in both directions.

**`--env` opens a vault without a prompt.** `trove unlock <vault> --env` reads
`./.env.trove`; `--env <dir>` reads that directory's; `--env <file>` reads that
file. It is a general loader, not a password mechanism: every `KEY=VALUE` lands
in the environment, so `TROVE_VAULT`, `TROVE_IDLE_TIMEOUT` and the socket paths
can live in one file, and `TROVE_DB_PASSWORD` is simply the one the unlock path
also consults. A variable already set wins, so the file supplies defaults; and
the password is used only when `--env` was passed, so an exported
`TROVE_DB_PASSWORD` can never silently unlock a vault for a command that didn't
ask for one.

**macOS binaries are signed with the hardened runtime.** Not for Gatekeeper —
Homebrew tarballs aren't quarantined — but because `troved` holds the decrypted
vault and your SSH keys in memory, and an ad-hoc signed binary can be attached
to by any process running as the same user. Apple's own `ssh-agent` is
SIP-protected and refuses; a Developer ID signature with the hardened runtime
and no `get-task-allow` puts `troved` in that class. Release builds sign when
the `APPLE_*` secrets are present; `scripts/sign-macos.sh` does it locally.

**Several vaults unlocked at once.** `unlock` is now additive rather than
replacing whatever was open: a personal vault and a work vault can serve keys
simultaneously, and the SSH and GPG agents serve the union. Agents identify a key
by public blob or keygrip, so different keys simply coexist. `trove lock --vault
<PATH>` drops one vault and leaves the rest serving; a bare `trove lock` still
drops everything. `list`, `search` and `status` span the whole open set, and
`status` reports every unlocked vault.

A title held by two open vaults is refused with both vault paths named rather
than resolved by guessing — returning the wrong vault's secret would be worse
than an error. Materialized files are first-wins across vaults: a target another
open vault already owns is skipped with a warning instead of being overwritten,
since overwriting would replace data a live process is using.

**RSA OpenPGP keys work.** trove previously parsed only ed25519 and cv25519 and
silently skipped everything else — and `gpg --gen-key` defaulted to RSA until
GnuPG 2.3, so most existing PGP keys could not be used at all. RSA (OpenPGP
algorithms 1, 2 and 3) is now supported for both signing and decryption, which
covers git commit signing, artifact and distro package signing, and the
decryption path `pass`, `sops` and `git-crypt` depend on.

**The ssh-agent answers management commands.** `ssh-add -d`, `-D`, `-x` and `-X`
previously failed against trove's agent, which only answered identity listings
and signature requests. `REMOVE_IDENTITY`, `REMOVE_ALL_IDENTITIES`, `LOCK` and
`UNLOCK` are now implemented, with OpenSSH's locked semantics: a locked agent
returns an empty identity list rather than an error, refuses to sign, and keeps
its keys in memory until unlocked.

**SSH keys reach processes that never inherited the socket** *(on by default —
existing installs will start forwarding after upgrading; set `TROVE_SSH_FORWARD=0`
to keep the previous behaviour)*: unlock now also pushes
each key into whatever agent `$SSH_AUTH_SOCK` already names — the KeePassXC model —
and lock, idle-lock and shutdown ask that agent to drop them again. `SSH_AUTH_SOCK`
is inherited at fork, so exporting it in a shell never reaches an already-running
editor; this does. Per-key behaviour comes from each entry's `KeeAgent.settings`, so
it's configurable from KeePassXC itself: `RemoveAtDatabaseClose`,
`UseLifetimeConstraintWhenSigning` + `LifetimeConstraintDuration`, and
`UseConfirmConstraintWhenSigning` are all honoured. Keys with no stated lifetime
inherit trove's own auto-lock window, so a forwarded copy expires roughly when the
vault would have locked anyway.

Forwarding never fails an unlock: per-key failures come back as
`ssh_forward_warnings` and `trove unlock` prints them on stderr. `TROVE_SSH_FORWARD=0`
turns it off, and it does nothing when `$SSH_AUTH_SOCK` is unset or already points at
trove. `RemoveAtDatabaseClose=false` applies only to the forwarded copy — trove's own
agent still drops every key on lock.

## v0.7.1 — 2026-07-29

**Sorted sidebar:** the desktop app's group tree now lists folders alphabetically at
every level (natural, case-insensitive) instead of in entry-insertion order.

## v0.7.0 — 2026-07-29

**Desktop app, now backed by real vaults:** the Trove desktop app graduates from a
design prototype to a working KeePass manager. It opens, creates, unlocks, and locks
real `.kdbx` files; browses the group/entry tree; adds, edits, moves, and deletes
entries; and reveals and copies secrets on demand behind an auto-clearing clipboard,
locking itself after five minutes idle. Recently-opened vaults are remembered, and
opening one uses the native file picker. Passwords never sit in the entry list —
strength is scored server-side and each secret is fetched only when its entry is
selected.

**App icon + system tray:** ships the Trove icon as the application and menu-bar /
tray icon, with a Show Trove / Quit Trove menu, plus a web favicon.

**Resizable three-pane layout:** drag the dividers between the sidebar, entry list,
and detail pane to resize them; double-click a divider to reset it; the widths
persist across restarts.

**Unlock-screen polish:** the locked-vault chip no longer wraps its path or lets it
collide with the Change control on a long path — the directory truncates with an
ellipsis while the filename stays visible (full path on hover), and Change is now a
proper button.

**Library:** `trove-core`'s `EntrySummary` now carries `created` / `modified`
timestamps. The `trove` and `troved` CLIs are unchanged from v0.6.0.

## v0.6.0 — 2026-07-19

**Daemon visibility + reap (`trove daemons`, Unix):** a new command that scans
every runtime dir — not just the one expected control socket — and lists all
trove daemons, live or the stale remains of a crashed one, with pid/socket/
liveness. `trove daemons kill (<SOCKET> | --all)` stops a straggler: gracefully
over its control socket, escalating to a signal (`SIGTERM`→`SIGKILL`) for a
wedged daemon, and clearing stale files. This surfaces and clears orphans the
single-path `status` probe misses — a wedged daemon, or a stray from an old
build whose socket path differed and so ran alongside the current one. The
singleton daemon now stamps its pid into the lockfile so a reaper can name and
signal it (liveness still comes from the `flock`, not the pid).

**CLI↔daemon version drift warning:** the CLI now learns the running (or freshly
spawned) daemon's build version and warns on stderr when it differs from the
CLI's — so a stale sibling `troved` (e.g. left by a CLI-only `cargo build`) no
longer drives a subtly different protocol in silence. Warning-only, suppressible
with `TROVE_NO_VERSION_WARN=1`. Release builds report a plain version and match,
so it never fires on a release.

**Materialize creates missing parent directories — and never silently fails:** a
`Materialize.Target` whose parent directory doesn't exist now has that directory
created (`0700`) instead of the entry being silently dropped, and any
materialization that still can't be written surfaces a loud unlock warning
rather than a false `ok`. Directories trove created are removed again on
lock/TTL (only if empty; a pre-existing directory is never touched). The tmpfs /
`AllowDiskBacked` guarantee is unchanged.

**Docs — two accounts on one host:** guidance for the work-plus-personal case
(e.g. two GitHub accounts): a `~/.ssh/config` host alias with `IdentitiesOnly
yes` pointed at trove's agent, so only the intended key is offered per alias.

## v0.5.0 — 2026-07-04

Full `keepassxc-cli` command parity (the seven gaps in
`docs/parity-plan.md`, all proven against the real `keepassxc-cli` binary in
CI), plus beyond-parity features `keepassxc-cli` has no equivalent for. The
individual entries below are grouped by theme.

**Generic entry management (parity G1):** `add password`, `get password`,
`show` (`--attr`, `--show-protected`), `edit` (`--set`/`--unset`/
`--password-prompt`), `search`, `mkdir`, `mv`, `rm`, `rmdir` — offline and
daemon-routed, with KeePassXC recycle-bin semantics.

**Composite keys (parity G2, G7):** global `--key-file` (every KeePassXC
keyfile format) and `--yubikey <SLOT>[:SERIAL]` HMAC-SHA1 challenge-response
(behind `--features yubikey`, Linux-only for now).

**TOTP (parity G3):** `add totp` + `show --totp`, stored as KeePassXC's
`otpauth://` `otp` field; codes match keepassxc-cli in both directions.

**Generation + audit (parity G4):** `generate password`/`diceware`,
`estimate` (zxcvbn), `analyze --hibp` (offline breach check, exits 1 to gate
CI).

**Clipboard (parity G5):** `clip` with a hash-guarded detached auto-clear.

**Vault ops (parity G6):** `merge` (proven equivalent to keepassxc-cli's
merge), `export xml|csv` (re-importable), `db-edit` (rekey + Argon2 retune),
`db-info`. Fixed a latent bug: entry mutations now stamp
`LastModificationTime`/`LocationChanged`, so trove edits no longer silently
lose KDBX merges in any tool.

**Beyond parity:** `exec <scope> -- cmd` (secrets scoped to one process tree,
wiped on exit — the `op run` of kdbx); `--json` on `list`/`search`/`db-info`;
`git-credential` helper; `resolve trove://…` secret references.

**Also:** `TROVE_SPAWN_TIMEOUT_SECS` knob for the daemon auto-spawn wait;
`docs/security-review-2026-07-04.md`; unpredictable `exec` temp-dir names.

**Desktop app (new):** a Tauri 2 GUI (`trove-desktop/`) that links `trove-core`
directly — a three-pane vault browser that opens a `.kdbx` and reveals fields on
demand (secrets stay in the backend, never in the entry list). Brought into this
monorepo and shipped in the same release as macOS (universal), Linux
(`.deb`/AppImage) and Windows (NSIS) bundles.

### Detailed entries

- `trove git-credential <get|store|erase>` (beyond parity): a git credential
  helper backed by the vault. `git config credential.helper "trove --vault
  ~/v.kdbx git-credential"` — `git push` authenticates against an entry
  matched by URL host (and username when git sends one), with no plaintext
  `~/.git-credentials`. store/erase are accepted and ignored.
- `trove resolve trove://<entry>[/<field>]` (beyond parity): print one
  referenced secret (field defaults to Password), à la 1Password's `op://` —
  the primitive for config templating (`export DB=$(trove resolve …)`).
- `trove exec <SCOPE> -- cmd…` (beyond parity): run any command with secrets
  injected for exactly its lifetime — string secrets as env vars, file
  attachments materialized into a private 0700 per-run dir, everything wiped
  when the child exits, child exit code propagated. An entry's `Exec.Env`
  custom field names the variable (`Exec.Env=KUBECONFIG` on a kubeconfig
  attachment → `trove exec Infra -- bash` gives that shell a scoped,
  self-destructing kubeconfig); fallback `TROVE_<TITLE>_PASSWORD`/`_FILE`.
- `--json` on `list`, `search` and `db-info`: stable machine-readable output
  (summaries never carry secrets), making trove scriptable without text
  scraping — something keepassxc-cli has no equivalent for.
- YubiKey challenge-response unlock (keepassxc-cli parity G7), behind
  `--features yubikey`: global `--yubikey <SLOT>[:SERIAL]` composites an
  HMAC-SHA1 challenge-response with the password (and optional keyfile) —
  KeePassXC's scheme, same vault unlocks there with the same device. The
  device answers a fresh challenge on every save. Validated in CI (Linux)
  through the keepass crate's software `LocalChallenge` provider — the
  identical derivation minus USB; the hardware test ships `#[ignore]`d for
  manual runs. Linux-only for now: upstream keepass pins the nusb USB
  backend, which doesn't compile on macOS.
- Vault ops (keepassxc-cli parity G6), all offline-only: `trove merge`
  (KDBX-standard reconciliation of diverged copies — proven equivalent to
  keepassxc-cli's merge on the same pair; unrelated vaults refuse cleanly),
  `trove export --format xml|csv` (decrypted KeePass XML that keepassxc
  imports back, CSV with KeePassXC's exact header), `trove db-edit`
  (rekey password/keyfile, Argon2 retuning), `trove db-info`. XML *import*
  stays out of scope (no public parser in the keepass crate).
- Compatibility fix surfaced by the merge work: trove edits now stamp
  `LastModificationTime` (and moves stamp `LocationChanged`) like KeePassXC
  does. Previously trove-side changes could silently lose KDBX merges in
  any tool because their timestamps never advanced.
- Clipboard (keepassxc-cli parity G5): `trove clip <entry>` copies the
  password (or `--attr NAME`, or `--totp` for the current code) and
  auto-clears after `--timeout` seconds (default 10, 0 disables) via a
  detached clearer that wipes ONLY if the clipboard still holds our value —
  the comparison travels as a SHA-256 on argv, never the secret. Works
  offline and daemon-routed; macOS/Windows/X11/Wayland via arboard.
- Generation + audit (keepassxc-cli parity G4), all purely local:
  `trove generate password` (charset policy flags, `--exclude`, `--count`),
  `trove generate diceware` (EFF large wordlist, vendored, CC BY 3.0),
  `trove estimate` (zxcvbn; reads stdin so secrets stay out of history), and
  `trove analyze --hibp <FILE>` — offline breach check that binary-searches
  the sorted pwned-passwords dump on disk (never loaded, never on the wire)
  and exits 1 when breaches are found so CI can gate on it.
- TOTP (keepassxc-cli parity G3): `trove add totp` stores an `otpauth://` URI
  in the Protected `otp` field (KeePassXC's own format — validated before
  storing, whitespace-tolerant base32 `--secret` form included);
  `trove show <entry> --totp` prints the current code (RFC 6238,
  SHA1/256/512, 6–8 digits, custom period). Daemon mode adds code-gated
  `GetTotp`/`AddTotp` RPCs — only the ephemeral code ever crosses the wire.
  Interop proven against keepassxc-cli: identical codes both directions.
  (Steam's non-standard 5-char variant is out of scope.)
- Keyfile unlock (keepassxc-cli parity G2): global `--key-file <PATH>`
  composites the keyfile with the password wherever a vault is opened —
  offline commands, `init` (new vault locked with the pair), and `unlock`
  (the daemon holds the bytes so its re-saves keep the composite key; the
  wire `Unlock` RPC grew an optional base64 `keyfile` field). Every format
  KeePassXC accepts. Interop proven both directions against keepassxc-cli.
- Generic entry CRUD, closing the first keepassxc-cli parity gap
  (docs/parity-plan.md): `add password` (prompt / `--secret-stdin` /
  `--generate`), `get password`, `show` (`--attr`, `--show-protected`),
  `edit` (`--set`/`--unset`/`--password-prompt`), `search`, `mkdir`, `mv`,
  `rm`, `rmdir`. All work offline (`--vault`) and daemon-routed (new
  `ShowEntry`/`Search`/`GetField`/`AddPassword`/`EditEntry`/`RemoveEntry`/
  `MoveEntry`/`Mkdir`/`Rmdir` RPCs, session-gated like `add ssh`).
- `rm`/`rmdir` follow KeePassXC recycle-bin semantics: entries and groups move
  to a shared "Recycle Bin" (created on demand, `Meta/RecycleBinUUID`
  convention); a repeat remove — or `--permanent` — destroys.
- CRUD interop is proven against real `keepassxc-cli` in the conformance
  suite: trove-authored vaults read back field-for-field, keepassxc-authored
  vaults round-trip through every trove command, and trove-recycled entries
  appear in keepassxc's own Recycle Bin view.

## v0.4.0 — 2026-07-01

- `add file` / `add gpg` now target the vault unlocked in the running daemon by
  default (gated by `TROVE_SESSION`), consistent with `add ssh`. Pass
  `--vault <PATH>` to operate on a kdbx file directly (offline).
- `troved` takes a singleton `flock`, making orphaned/stale SSH- and GPG-agent
  sockets impossible.

## v0.3.0 — 2026-06-24

- `--vault <PATH>` is now a global offline selector (works before or after the
  subcommand); positional vault arguments dropped.
- `add ssh` requires a `<comment>` argument, recorded in `id.pub`.
- The vault's top-level group is named `Root` and treated as the default group.
- KDBX 4.0 → 4.1 heal on save, daemon lifecycle management, and `ssh`/`gpg` CLI
  wrappers.
- Upgraded to `keepass 0.13.10` (KeePassXC-readable vaults) with a cross-tool
  conformance suite and session-code provisioning.
- Windows support (named-pipe IPC) and the cross-platform release pipeline.
- Installed the github-guard git hooks.

## v0.2.0 — 2026-06-22

- `KeeAgent.settings` export, nested group support, daemon auto-spawn, RSA PEM
  import, and an idle-lock fix.
- Added the Install section (Homebrew + cargo) to the README.

## v0.1.0 — 2026-05-08

Initial tagged release: kdbx-compatible vault (`trove-core`), the `trove` CLI
and `troved` headless daemon with a line-JSON control socket, in-memory SSH and
GPG agents, real KDBX `<Binary>` attachments, file materialization (the founding
feature), idle-lock, and the daemon-aware CLI. The granular history is below.

## Pre-1.0 development milestones

Fine-grained feature log from before the tagged-release cadence (oldest first):

- **v0.0.1** — kdbx vault read/write ([crates/trove-core/src/lib.rs](crates/trove-core/src/lib.rs)), `trove` CLI scaffold (`init`, `list`, `add ssh`, `get ssh`), `troved` headless daemon with the line-JSON control socket, end-to-end SSH-key roundtrip.
- **v0.0.2** — SSH agent listener serving ed25519 keys over `SSH_AUTH_SOCK`. Keys live only in daemon memory; cleared on lock.
- **v0.0.3** — SSH agent algorithm coverage extended: RSA (>= 2048 bits, signs with rsa-sha2-256 / rsa-sha2-512 per RFC 8332), ECDSA P-256, ECDSA P-384.
- **v0.0.4** — GPG agent listener speaking the Assuan protocol; ed25519 OpenPGP signing works against `git commit -S`. Hand-rolled OpenPGP packet parser ([crates/troved/src/gpg_agent/keys.rs](crates/troved/src/gpg_agent/keys.rs)) avoids pulling in `rpgp`.
- **v0.0.5** — GPG `PKDECRYPT` for ECDH-on-Curve25519: AES-128/192/256 KW unwrap of the wrapped session key against gpg 2.5.x. RSA / NIST-curve / Ed448 still out of scope.
- **v0.0.6** — Real KDBX `<Binary>` attachments via a vendored fork of `keepass` 0.7.33 (since retired in v0.0.14); legacy `_SDPM_BIN_*` string-field fallback kept for read-compat with v0.0.1–v0.0.5 vaults (also retired in v0.0.14).
- **v0.0.7** — File materialization (the founding feature): `trove add file`, `Materialize.{Source,Target,Mode,TTL,AllowDiskBacked}` custom-field schema, in-process `trove materialize`, daemon-driven materialize-on-unlock + wipe-on-lock with optional TTL. Linux: refuses non-tmpfs targets unless `AllowDiskBacked=true`. macOS: soft allowlist (`/tmp`, `/private/tmp`, `$XDG_RUNTIME_DIR`) — APFS provides no real tmpfs, so this is a hint, not a guarantee.
- **v0.0.8** — Idle-lock. `IdleTracker` with a tokio driver task ([crates/troved/src/idle.rs](crates/troved/src/idle.rs)); auto-locks after configurable inactivity (default 900s). Activity = any control RPC except `ping`, any SSH agent message, any GPG Assuan command. New `set-idle-timeout` / `get-idle-timeout` RPCs and `TROVE_IDLE_TIMEOUT` env var.
- **v0.0.9** — GitHub Actions CI (`.github/workflows/ci.yml`): test matrix on Linux + macOS, clippy with `-D warnings`, fmt check, cargo-audit, MSRV check at Rust 1.75. Repo run through `cargo fmt --all`.
- **v0.0.10** — Documentation: README quickstart + [docs/architecture.md](docs/architecture.md) + [docs/threat-model.md](docs/threat-model.md) + [docs/cli-reference.md](docs/cli-reference.md).
- **v0.0.11** — Fuzz harnesses for the SSH agent wire decoder and Assuan line parser ([crates/troved/fuzz/](crates/troved/fuzz/), nightly-only) plus proptest property tests on stable. ~4.3M libfuzzer iterations on this machine, 0 crashes.
- **v0.0.12** — Clean-room kdbx spec test suite: round-trip matrix, malformed-input rejection, keyfile formats, binary pool, cross-tool (`keepassxc-cli`) interop. Programmatically generated fixtures from a seeded RNG; no GPL imports. Originally lived under `vendor/keepass/tests/`; relocated to [crates/keepass-spec-tests](crates/keepass-spec-tests/) in v0.0.14.
- **v0.0.13** — Daemon-aware CLI: `trove unlock`, `trove lock`, `trove status`, `trove idle set/get`, `trove materialize-status`. Replaces the `printf '{...}' | nc -U` incantations from v0.0.8 with proper subcommands.
- **v0.0.14** — Migrated off the vendored `keepass` 0.7.33 fork to the published `keepass = "0.12.5"`. Upstream's PR #294 already restructured attachments as first-class Database-owned objects with `EntryMut::add_attachment(name, Value::Unprotected(bytes))`, which is what our 3 patches were trying to enable. Local fork retired; legacy `_SDPM_BIN_*` migration code retired (no production v0.0.1–v0.0.5 vaults exist).
