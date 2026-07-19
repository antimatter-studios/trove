//! `trove` — command-line client for trove.
//!
//! v0.0.1 surface: `init`, `list`, `add ssh`, `get ssh`. Master key only;
//! no keyfiles, no env-var passwords.

#![forbid(unsafe_code)]

mod clip;
mod daemon;
mod exec;
mod gitcred;
mod hibp;
mod ipc;
mod pwgen;
mod xml_export;

use std::fs::OpenOptions;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use trove_core::{Error as CoreError, Vault};

/// Exit code for user-recoverable errors (bad path, missing entry, etc.).
const EXIT_USER_ERROR: u8 = 1;
/// Exit code for vault-level errors (bad password, corrupt kdbx).
const EXIT_VAULT_ERROR: u8 = 2;

/// Attachment slot used for SSH private keys. Kept short and conventional.
const SSH_KEY_ATTACHMENT: &str = "id";

/// Attachment slot for the derived OpenSSH public key, stored alongside the
/// private key so any tool can read the public half without re-deriving it.
/// Mirrors the `id` / `id.pub` filename pair ssh-keygen produces.
const SSH_PUBKEY_ATTACHMENT: &str = "id.pub";

/// Attachment slot used for GPG secret-key exports. Matches what
/// `troved::handler::load_gpg_keys_from_vault` looks for.
const GPG_KEY_ATTACHMENT: &str = "gpg-priv";

#[derive(Debug, Parser)]
#[command(
    name = "trove",
    // Stamped by build.rs: `0.2.0` for release builds, `0.2.0-dev-YYYYMMDDHHMMSS`
    // for dev builds so the running binary is easy to identify.
    version = env!("TROVE_BUILD_VERSION"),
    about = "trove — KeePassXC-compatible CLI",
    propagate_version = true
)]
struct Cli {
    /// Read the vault password from stdin (one line) instead of prompting.
    /// For `init`, the single line is used as the password without a confirm step.
    /// Intended for scripts and CI; do not use in shells where stdin may be logged.
    #[arg(long = "password-stdin", global = true)]
    password_stdin: bool,

    /// Operate directly on this .kdbx file (offline mode), bypassing the daemon.
    ///
    /// trove has two modes, selected by the presence of this flag:
    ///
    /// * `--vault <PATH>` present — offline. The command opens the file at PATH
    ///   directly; the password comes from `--password-stdin` or a prompt (never
    ///   the command line). No daemon, no `TROVE_SESSION` needed. `init` and
    ///   `materialize` always work this way; with this flag `add`, `generate`,
    ///   `get`, and `list` do too.
    /// * `--vault` absent — daemon. `add` (ssh/gpg/file), `generate ssh`, `get`,
    ///   and `list` act on the vault unlocked in the running `troved`, gated by
    ///   the `TROVE_SESSION` code `trove unlock` minted. `init` and `materialize`
    ///   have no daemon mode and error without `--vault`.
    ///
    /// `unlock` is the exception: it is inherently daemon-directed, so it takes
    /// its target as a positional `<VAULT>` and ignores this flag.
    ///
    /// Works before or after the subcommand: `trove --vault V list` and
    /// `trove list --vault V` are equivalent.
    #[arg(long = "vault", global = true, value_name = "PATH")]
    vault: Option<PathBuf>,

    /// Unlock with a composite key: this keyfile PLUS the password. Applies
    /// wherever a vault is opened — offline `--vault` commands, `init`
    /// (locks the new vault with the composite key), and `unlock` (the
    /// daemon holds the keyfile bytes in memory for re-saves). Accepts any
    /// format KeePassXC does: XML v1/v2, raw 32-byte, hex-64, or an
    /// arbitrary file (hashed with SHA-256).
    #[arg(long = "key-file", global = true, value_name = "PATH")]
    key_file: Option<PathBuf>,

    /// Unlock with a YubiKey HMAC-SHA1 challenge-response (KeePassXC's
    /// scheme): `--yubikey <SLOT>[:SERIAL]`, e.g. `--yubikey 2`. Applies to
    /// offline `--vault` commands and `init`. The device must stay connected
    /// while writing — every save answers a fresh challenge.
    #[cfg(feature = "yubikey")]
    #[arg(long = "yubikey", global = true, value_name = "SLOT[:SERIAL]")]
    yubikey: Option<String>,

    /// Internal (tests): software challenge-response secret, hex — the same
    /// HMAC-SHA1 derivation a YubiKey performs, without hardware.
    #[cfg(feature = "yubikey")]
    #[arg(
        long = "cr-secret-hex",
        global = true,
        hide = true,
        conflicts_with = "yubikey"
    )]
    cr_secret_hex: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new empty vault at `--vault <PATH>` (required; must not exist).
    Init,

    /// List entries, one per line.
    ///
    /// With `--vault <PATH>`: open that file directly (offline). Without it:
    /// list the vault currently unlocked in the running daemon (auto-spawning
    /// if needed) — no password prompt.
    List {
        /// Machine-readable output: a JSON array of entry summaries.
        #[arg(long)]
        json: bool,
    },

    /// Add a resource (SSH key, password, ...) to a vault.
    Add {
        #[command(subcommand)]
        resource: AddResource,
    },

    /// Generate a new key in-tool and store it (no ssh-keygen needed).
    Generate {
        #[command(subcommand)]
        resource: GenerateResource,
    },

    /// Retrieve a resource from a vault.
    Get {
        #[command(subcommand)]
        resource: GetResource,
    },

    /// SSH agent helper subcommands.
    SshAgent {
        #[command(subcommand)]
        op: SshAgentOp,
    },

    /// GPG agent helper subcommands.
    GpgAgent {
        #[command(subcommand)]
        op: GpgAgentOp,
    },

    /// Materialize all opted-in entries in the vault to disk in-process,
    /// without going through the daemon. Useful for testing and for
    /// disconnected workflows. Wipes everything on Ctrl-C / SIGINT.
    Materialize,

    /// Unlock a vault and start a session. The keys + materialize plan land in
    /// daemon memory; the SSH and GPG agents serve them.
    ///
    /// `unlock` is inherently daemon-directed, so it takes its target as a
    /// positional `<VAULT>` and ignores the global `--vault` selector (which
    /// means "operate offline" everywhere else).
    ///
    /// Prompts for the master password unless `--password-stdin` is set; the
    /// password never lands on the command line.
    ///
    /// On an interactive terminal this drops you into a session subshell with
    /// `$TROVE_SESSION` already set, so `add`/`get` work immediately — `exit`
    /// ends the session. When stdout is piped (e.g. `eval "$(trove unlock …)"`)
    /// it instead prints `export TROVE_SESSION=…` for the calling shell.
    /// `--export` / `--shell` force a mode.
    Unlock {
        /// Path to the .kdbx vault to unlock.
        vault: PathBuf,
        /// Idle-lock timeout in seconds. Resets on every daemon request
        /// (control RPC, ssh-agent op, gpg-agent op). `0` disables auto-lock.
        /// When omitted, keeps the daemon's currently configured timeout
        /// (the env-var default or whatever a prior `idle set` left).
        #[arg(long = "timeout")]
        timeout: Option<u64>,
        /// Print `export TROVE_SESSION=…` for `eval "$(…)"` instead of opening a
        /// session subshell. Implied when stdout is not a terminal.
        #[arg(long = "export")]
        export: bool,
        /// Open a session subshell even when stdout is not a terminal.
        #[arg(long = "shell", conflicts_with = "export")]
        shell: bool,
    },

    /// Tell the running `troved` to lock the vault: wipe materialized files,
    /// drop SSH+GPG keys, drop the vault. Idempotent.
    Lock,

    /// Print a human-readable summary of the running `troved`'s state:
    /// vault path (if unlocked), idle-lock state, and counts of SSH keys,
    /// GPG keys, and materialized files in memory.
    Status,

    /// Configure or read the daemon's idle-lock timeout.
    Idle {
        #[command(subcommand)]
        op: IdleOp,
    },

    /// One line per active materialization: title, target path, TTL
    /// remaining, and whether the file is still on disk.
    MaterializeStatus,

    /// Print an entry's details: title, username, URL, notes, custom-field
    /// names and attachment names. The password (and any other protected
    /// value) is shown only with `--show-protected`.
    ///
    /// With `--vault <PATH>`: read the file directly (offline). Without it:
    /// served by the running daemon; the summary view needs no session code,
    /// but protected values (`--attr Password --show-protected`) present the
    /// `TROVE_SESSION` code from `trove unlock`.
    Show {
        /// Entry path, e.g. "github.com" or "Work/github".
        entry_path: String,
        /// Print only this attribute's raw value (repeatable, order kept).
        /// Standard names: Title, UserName, Password, URL, Notes — plus any
        /// custom field. Protected attributes (Password, otp) additionally
        /// require --show-protected.
        #[arg(long = "attr", value_name = "NAME")]
        attrs: Vec<String>,
        /// Reveal protected values (Password, otp) instead of refusing.
        #[arg(long = "show-protected")]
        show_protected: bool,
        /// Print the entry's CURRENT TOTP code (computed from its `otp`
        /// otpauth URI, KeePassXC-compatible). In daemon mode only the
        /// ephemeral code crosses the wire — never the shared secret.
        #[arg(long, conflicts_with = "attrs")]
        totp: bool,
    },

    /// Search entries: case-insensitive substring match over title, username,
    /// URL, notes and group path. Protected values are never searched. Output
    /// is `list`-shaped (id, path, attachments), one hit per line.
    Search {
        /// The term to look for.
        term: String,
        /// Machine-readable output: a JSON array of entry summaries.
        #[arg(long)]
        json: bool,
    },

    /// Edit an existing entry: standard fields via flags, custom fields via
    /// `--set NAME=VALUE` / `--unset NAME`, rename via `--title`. To change
    /// the password interactively pass `--password-prompt`.
    Edit {
        /// Entry path, e.g. "github.com" or "Work/github".
        entry_path: String,
        /// Rename the entry (its leaf title; the group stays — use `mv` to
        /// relocate).
        #[arg(long)]
        title: Option<String>,
        /// Set the UserName field.
        #[arg(long)]
        username: Option<String>,
        /// Set the URL field.
        #[arg(long)]
        url: Option<String>,
        /// Set the Notes field.
        #[arg(long)]
        notes: Option<String>,
        /// Prompt (hidden, with confirmation) for a new password.
        #[arg(long = "password-prompt")]
        password_prompt: bool,
        /// Set a custom field (repeatable): --set API-Token=abc123
        #[arg(long = "set", value_name = "NAME=VALUE")]
        sets: Vec<String>,
        /// Remove a custom field (repeatable).
        #[arg(long = "unset", value_name = "NAME")]
        unsets: Vec<String>,
    },

    /// Remove an entry. Default is the KeePassXC behavior: move it to the
    /// recycle bin (created on demand, shared with KeePassXC); an entry
    /// already in the bin is destroyed. `--permanent` destroys immediately.
    Rm {
        /// Entry path, e.g. "github.com" or "Work/github".
        entry_path: String,
        /// Destroy outright instead of recycling.
        #[arg(long)]
        permanent: bool,
    },

    /// Move an entry to an EXISTING group. Destinations are never created
    /// implicitly (a typo should fail) — create one first with `trove mkdir`.
    Mv {
        /// Entry path to move, e.g. "github.com" or "Old/github".
        entry_path: String,
        /// Destination group path, e.g. "Work/SSH" (or "Root" for top level).
        group_path: String,
    },

    /// Create a group hierarchy. Intermediate groups are created as needed
    /// (`mkdir -p`); errors if the leaf group already exists.
    Mkdir {
        /// Group path, e.g. "Work/SSH".
        group_path: String,
    },

    /// Remove a group and everything in it. Default: move it to the recycle
    /// bin (KeePassXC behavior). `--permanent` destroys instead, and then a
    /// non-empty group additionally requires `--recursive`.
    Rmdir {
        /// Group path, e.g. "Old/Project".
        group_path: String,
        /// Destroy outright instead of recycling.
        #[arg(long)]
        permanent: bool,
        /// With --permanent: allow destroying a non-empty group.
        #[arg(long)]
        recursive: bool,
    },

    /// Copy an entry's password (default), another attribute, or its current
    /// TOTP code to the clipboard, then auto-clear after `--timeout` seconds
    /// — but only if the clipboard still holds what we put there (someone
    /// copying something else meanwhile is left alone).
    Clip {
        /// Entry path, e.g. "github.com" or "Work/github".
        entry_path: String,
        /// Copy this attribute instead of Password.
        #[arg(long = "attr", value_name = "NAME", conflicts_with = "totp")]
        attr: Option<String>,
        /// Copy the entry's current TOTP code.
        #[arg(long)]
        totp: bool,
        /// Seconds until the guarded auto-clear. 0 disables clearing.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },

    /// Internal: the detached clipboard clearer (spawned by `clip`).
    #[command(hide = true, name = "__clear-clipboard")]
    ClearClipboard {
        secs: u64,
        /// SHA-256 of the copied value — clears only on a match.
        hash: String,
    },

    /// Estimate a password's strength with zxcvbn (the estimator KeePassXC's
    /// `estimate` is modeled on). Purely local — nothing leaves the machine.
    /// Reads the password from stdin when the argument is omitted (preferred:
    /// keeps secrets out of shell history).
    Estimate {
        /// The password to rate. PREFER stdin (omit this) — argv is visible
        /// in `ps` and shell history.
        password: Option<String>,
    },

    /// Check every password in the vault against an OFFLINE Have-I-Been-Pwned
    /// dump (the sorted `pwned-passwords` file: `SHA1:count` per line).
    /// Nothing is sent anywhere; the multi-GB file is binary-searched on
    /// disk, never loaded. Offline-only: requires `--vault`.
    Analyze {
        /// Path to the sorted pwned-passwords dump.
        #[arg(long, value_name = "FILE", required = true)]
        hibp: PathBuf,
    },

    /// Act as a git credential helper (`git config credential.helper "trove
    /// --vault ~/v.kdbx git-credential"`). git appends the operation
    /// (get/store/erase) and speaks its key=value protocol on stdin/stdout.
    /// `get` matches an entry by URL host (and username if git sends one) and
    /// replies with its username/password; store/erase are accepted and
    /// ignored. Offline-only.
    GitCredential {
        /// The git operation: get, store, or erase.
        operation: String,
    },

    /// Resolve a `trove://<entry-path>[/<field>]` secret reference and print
    /// the value to stdout (the field defaults to Password). The primitive
    /// behind config templating — `export DB=$(trove --vault v resolve
    /// trove://Infra/prod/postgres)`. Offline-only.
    Resolve {
        /// The trove:// reference to resolve.
        reference: String,
    },

    /// Run a command with secrets injected for exactly its lifetime — no
    /// on-disk residue, nothing outlives the process tree. `<SCOPE>` is an
    /// entry or a group: string secrets become env vars, file attachments
    /// materialize into a private per-run directory (0700) whose contents
    /// are wiped when the command exits.
    ///
    /// Naming: an entry's `Exec.Env` custom field names the variable
    /// (`Exec.Env=KUBECONFIG` on a kubeconfig attachment →
    /// `KUBECONFIG=/tmp/.../kubeconfig` in the child). Without it:
    /// `TROVE_<TITLE>_PASSWORD` / `TROVE_<TITLE>_FILE`. The child's exit
    /// code becomes trove's. Offline-only: requires `--vault`.
    ///
    /// Example: `trove --vault v.kdbx exec Infra/kubeconfig-prod -- bash`
    Exec {
        /// Entry path or group path whose secrets to inject.
        scope: String,
        /// The command to run (everything after `--`).
        #[arg(last = true, required = true)]
        command: Vec<std::ffi::OsString>,
    },

    /// Merge another kdbx vault into `--vault` (KDBX-standard semantics:
    /// last-write-wins by modification time, histories preserved — the same
    /// algorithm KeePassXC uses, so either tool can merge the same pair).
    /// Offline-only. The SOURCE vault's password is prompted separately
    /// (with `--password-stdin` it is stdin line 2; target password line 1).
    Merge {
        /// Path to the source .kdbx to merge from (left unchanged).
        source: PathBuf,
        /// Keyfile for the SOURCE vault, when it uses a composite key.
        /// (The global --key-file applies to the TARGET vault.)
        #[arg(long = "source-key-file", value_name = "PATH")]
        source_key_file: Option<PathBuf>,
    },

    /// Export the vault: `xml` (the decrypted KeePass XML, importable by any
    /// KeePass tool) or `csv` (KeePassXC's column convention). Offline-only,
    /// stdout. THE OUTPUT CONTAINS EVERY SECRET IN PLAINTEXT.
    Export {
        /// Output format.
        #[arg(long, value_enum, default_value_t = ExportFormat::Xml)]
        format: ExportFormat,
    },

    /// Change database-level settings: credentials and Argon2 KDF cost.
    /// Offline-only. With `--set-password`, the new password is prompted
    /// (with `--password-stdin`: current password line 1, new password
    /// line 2).
    DbEdit {
        /// Set a new master password (prompted / stdin line 2).
        #[arg(long = "set-password")]
        set_password: bool,
        /// Lock with a (new) keyfile in addition to the password.
        #[arg(long = "set-key-file", value_name = "PATH")]
        set_key_file: Option<PathBuf>,
        /// Remove the keyfile requirement (password-only afterwards).
        #[arg(long = "unset-key-file", conflicts_with = "set_key_file")]
        unset_key_file: bool,
        /// Argon2 memory in MiB.
        #[arg(long = "kdf-memory", value_name = "MIB")]
        kdf_memory: Option<u64>,
        /// Argon2 iterations.
        #[arg(long = "kdf-iterations")]
        kdf_iterations: Option<u64>,
        /// Argon2 parallelism (lanes).
        #[arg(long = "kdf-parallelism")]
        kdf_parallelism: Option<u32>,
    },

    /// Print non-secret database facts: format version, cipher, compression,
    /// KDF parameters, entry/group counts, recycle-bin presence. Offline-only.
    DbInfo {
        /// Machine-readable output: a JSON object.
        #[arg(long)]
        json: bool,
    },

    /// Print, install, or check a shell completion script.
    ///
    /// With no flags, prints the script to stdout for SHELL. Without an
    /// installed completion, your shell falls back to filename completion for
    /// `trove` — or, on zsh, to whatever unrelated completion happens to claim
    /// the name `trove` (zsh ships an `_openstack` completer that claims it,
    /// since OpenStack's database service is also called Trove).
    ///
    /// `--install` writes the script to the standard location and wires it into
    /// your shell rc (idempotent; safe to re-run). `--check` reports how your
    /// shell currently completes `trove`, flagging the `_openstack` shadow.
    /// SHELL is optional with `--install`/`--check` (defaults to `$SHELL`).
    Completions {
        /// Shell dialect: bash, zsh, fish, powershell, or elvish.
        shell: Option<clap_complete::Shell>,
        /// Install the completion for SHELL and wire it into your shell rc.
        #[arg(long)]
        install: bool,
        /// Report how SHELL currently completes `trove`, then exit (read-only).
        #[arg(long, conflicts_with = "install")]
        check: bool,
    },
}

/// Output format for `trove export`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ExportFormat {
    /// Decrypted KeePass XML (importable by keepassxc-cli and KeePass2).
    Xml,
    /// KeePassXC's CSV column convention.
    Csv,
}

#[derive(Debug, Subcommand)]
enum IdleOp {
    /// Set the idle-lock timeout in seconds. `0` disables auto-lock entirely.
    /// Takes effect immediately; if the new value is shorter than the time
    /// since last activity, the daemon locks on the next driver wake.
    Set {
        /// Timeout in seconds. `0` disables auto-lock.
        seconds: u64,
    },

    /// Print the current idle-lock state. `disabled` if timeout is 0,
    /// otherwise `<N>s (remaining: <M>s)` while the timer is running, or
    /// `<N>s (vault locked)` while it isn't.
    Get,
}

#[derive(Debug, Subcommand)]
enum GpgAgentOp {
    /// Print the path to the troved GPG agent socket.
    ///
    /// Resolution order matches `troved`:
    /// 1. `TROVE_GPG_SOCK` env var (override).
    /// 2. `$XDG_RUNTIME_DIR/trove-gpg.sock`.
    /// 3. `${TMPDIR:-/tmp}/trove-gpg-$UID.sock`.
    ///
    /// Typical usage (gpg 2.x speaks Assuan over a fixed path; bind-mount or
    /// symlink the standard location at `~/.gnupg/S.gpg-agent` to ours):
    ///   `ln -sf "$(trove gpg-agent socket)" ~/.gnupg/S.gpg-agent`.
    Socket,

    /// List the GPG keys the running agent is serving (keygrip, type, comment).
    ///
    /// Reads the running daemon; if it isn't running (nothing unlocked) it
    /// prints nothing and exits 0. One key per line, tab-separated.
    List,
}

#[derive(Debug, Subcommand)]
enum SshAgentOp {
    /// Print the path to the troved SSH agent socket.
    ///
    /// Resolution order matches `troved`:
    /// 1. `TROVE_SSH_SOCK` env var (override).
    /// 2. `$XDG_RUNTIME_DIR/trove-ssh.sock`.
    /// 3. `${TMPDIR:-/tmp}/trove-ssh-$UID.sock`.
    ///
    /// Typical usage: `export SSH_AUTH_SOCK="$(trove ssh-agent socket)"`.
    Socket,

    /// List the SSH public keys the running agent is serving — the consistent
    /// equivalent of `ssh-add -L` (`<algo> <base64-key> <comment>`, one per
    /// line). Reads the running daemon; prints nothing and exits 0 if it isn't
    /// running (nothing unlocked).
    List,
}

/// SSH key algorithm for `trove generate ssh`.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum SshKeyType {
    /// Ed25519 — modern, fast, recommended (default).
    Ed25519,
    /// RSA 4096-bit (slower to generate; broadest compatibility).
    Rsa,
    /// ECDSA NIST P-256.
    #[value(name = "ecdsa-p256")]
    EcdsaP256,
    /// ECDSA NIST P-384.
    #[value(name = "ecdsa-p384")]
    EcdsaP384,
}

#[derive(Debug, Subcommand)]
enum GenerateResource {
    /// Generate a random password and print it to stdout. Purely local: no
    /// vault, no daemon. Default pool is lower+upper+digits; add `--special`
    /// or subtract classes with `--no-lower/--no-upper/--no-numeric`.
    Password {
        /// Password length.
        #[arg(long, default_value_t = 20)]
        length: usize,
        /// Include special characters (printable ASCII punctuation).
        #[arg(long)]
        special: bool,
        /// Exclude lowercase letters.
        #[arg(long = "no-lower")]
        no_lower: bool,
        /// Exclude uppercase letters.
        #[arg(long = "no-upper")]
        no_upper: bool,
        /// Exclude digits.
        #[arg(long = "no-numeric")]
        no_numeric: bool,
        /// Drop these characters from the pool (e.g. ambiguous "l1O0").
        #[arg(long, default_value = "")]
        exclude: String,
        /// How many passwords to print (one per line).
        #[arg(long, default_value_t = 1)]
        count: usize,
    },

    /// Generate a diceware passphrase from the EFF large wordlist
    /// (7776 words ≈ 12.9 bits/word), hyphen-separated. Purely local.
    Diceware {
        /// Number of words (default 7 ≈ 90 bits).
        #[arg(long, default_value_t = 7)]
        words: usize,
        /// How many passphrases to print (one per line).
        #[arg(long, default_value_t = 1)]
        count: usize,
    },

    /// Generate a new SSH keypair and store it on the vault, addressed by entry
    /// path — no need to run `ssh-keygen` yourself. Stores the private key, the
    /// derived `id.pub`, and `KeeAgent.settings`, exactly like `add ssh`.
    ///
    /// Like `add ssh`, this targets the vault unlocked in the running daemon by
    /// default (using `TROVE_SESSION` from `trove unlock`); pass the global
    /// `--vault <path>` to write a kdbx file directly (offline).
    Ssh {
        /// Entry path, e.g. "github.com" or "Work/SSH/github".
        entry_path: String,
        /// Key comment (e.g. an email like you@host). Defaults to the entry path.
        comment: Option<String>,
        /// Key algorithm. Defaults to ed25519.
        #[arg(long = "type", value_enum, default_value_t = SshKeyType::Ed25519)]
        key_type: SshKeyType,
        /// Optional UserName field to record on the entry (e.g. git user).
        #[arg(long = "user")]
        user: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum AddResource {
    /// Store a username/password entry, addressed by entry path
    /// (`group/sub/title`; groups auto-created). The password is prompted for
    /// (hidden, confirmed) unless `--generate` mints one or `--secret-stdin`
    /// reads it from stdin.
    ///
    /// By default targets the vault unlocked in the running daemon (using the
    /// `TROVE_SESSION` code from `trove unlock`); pass the global
    /// `--vault <path>` to write a kdbx file directly (offline).
    Password {
        /// Entry path, e.g. "github.com" or "Work/github".
        entry_path: String,
        /// UserName field.
        #[arg(long)]
        username: Option<String>,
        /// URL field.
        #[arg(long)]
        url: Option<String>,
        /// Notes field.
        #[arg(long)]
        notes: Option<String>,
        /// Generate the password (OS CSPRNG, letters+digits) and print it
        /// once to stdout instead of prompting.
        #[arg(long, conflicts_with = "secret_stdin")]
        generate: bool,
        /// Length of the generated password (with --generate; default 20).
        #[arg(long, requires = "generate")]
        length: Option<usize>,
        /// Read the password from stdin instead of prompting. When the global
        /// `--password-stdin` is also set, the VAULT password is line 1 and
        /// this secret is line 2.
        #[arg(long = "secret-stdin")]
        secret_stdin: bool,
    },

    /// Attach a TOTP (2FA) generator to an entry, stored as the `otp` field
    /// in KeePassXC's otpauth-URI format — codes render identically in both
    /// tools. The entry is created if missing (groups mkdir -p). Read codes
    /// with `trove show <entry> --totp`.
    ///
    /// Provide either a full `--uri otpauth://totp/...` (from the site's QR
    /// code) or a bare `--secret` (the base32 "manual entry" code) plus
    /// optional `--digits/--period/--algorithm`.
    Totp {
        /// Entry path, e.g. "github.com" or "Work/github".
        entry_path: String,
        /// Full otpauth:// URI.
        #[arg(long, conflicts_with_all = ["secret", "digits", "period", "algorithm"], required_unless_present = "secret")]
        uri: Option<String>,
        /// Base32 shared secret (as sites display it for manual entry).
        #[arg(long)]
        secret: Option<String>,
        /// Code length (default 6).
        #[arg(long, default_value_t = 6)]
        digits: u32,
        /// Code period in seconds (default 30).
        #[arg(long, default_value_t = 30)]
        period: u32,
        /// HMAC algorithm: SHA1 (default, near-universal), SHA256 or SHA512.
        #[arg(long, default_value = "SHA1")]
        algorithm: String,
    },

    /// Store an SSH private key on the unlocked vault, addressed by entry path.
    ///
    /// `<ENTRY_PATH>` is a `/`-separated path (`group/sub/title`); groups are
    /// created as needed and an existing entry has its `id` key replaced in
    /// place. `<KEY_FILE>` is the private key on disk — it is validated before
    /// being stored, so a public key, an encrypted key, or an unsupported/weak
    /// algorithm is rejected with a precise error. `<COMMENT>` is the public-key
    /// comment (usually an email) recorded in the derived `id.pub`.
    ///
    /// By default the key is added to the vault currently unlocked in the
    /// running daemon — no vault path needed — using the `TROVE_SESSION` code
    /// from `trove unlock`. Pass the global `--vault <path>` to operate on a
    /// kdbx file directly (offline), prompting for the master password.
    Ssh {
        /// Entry path, e.g. "github.com" or "Work/SSH/github".
        entry_path: String,
        /// Path to the SSH private key file (e.g. ~/.ssh/id_ed25519).
        #[arg(value_name = "KEY_FILE")]
        key: PathBuf,
        /// Key comment for the public-key line — typically an email like
        /// `you@host`. This is what lands in `id.pub` and so in a server's
        /// authorized_keys, identifying the key to humans.
        comment: String,
        /// Optional UserName field to record on the entry (e.g. git user).
        #[arg(long = "user")]
        user: Option<String>,
    },

    /// Store a GPG secret key (binary export) in the vault under the
    /// `gpg-priv` attachment slot. Produced by:
    ///
    ///   `gpg --batch --pinentry-mode loopback --passphrase '' \
    ///        --export-secret-keys --output secret.gpg <KEYID>`
    ///
    /// The blob must be the binary OpenPGP packet stream (NOT armored). On
    /// vault unlock, troved parses each `gpg-priv` attachment and registers
    /// every ed25519 secret key it finds with the GPG agent listener.
    ///
    /// By default the key is added to the vault currently unlocked in the
    /// running daemon — no vault path needed — using the `TROVE_SESSION` code
    /// from `trove unlock`. Pass the global `--vault <path>` to operate on a
    /// kdbx file directly (offline), prompting for the master password.
    Gpg {
        /// Entry path or title (e.g. "git-signing").
        title: String,
        /// Path to the binary GPG secret-key export.
        #[arg(long = "key")]
        key: PathBuf,
    },

    /// Store an arbitrary file (kubeconfig, .env, TLS cert, ...) in the vault
    /// and configure it to materialize to disk on unlock. The file's bytes
    /// land in a real KDBX `<Binary>` attachment; the `Materialize.*` custom
    /// fields tell troved where to write it on unlock.
    ///
    /// By default the file is added to the vault currently unlocked in the
    /// running daemon — no vault path needed — using the `TROVE_SESSION` code
    /// from `trove unlock`. Pass the global `--vault <path>` to operate on a
    /// kdbx file directly (offline), prompting for the master password.
    File {
        /// Entry path or title (e.g. "kubeconfig-prod").
        title: String,
        /// Path to the file to read bytes from.
        #[arg(long = "src")]
        src: PathBuf,
        /// Path to materialize the file to on unlock.
        #[arg(long = "target")]
        target: PathBuf,
        /// Optional override for the attachment name. Defaults to the
        /// basename of `--src`.
        #[arg(long = "name")]
        name: Option<String>,
        /// File mode (octal) to set on the materialized file. 3 or 4 digits.
        #[arg(long = "mode", default_value = "0600")]
        mode: String,
        /// Materialization lifetime in seconds. Default: lifetime of the
        /// vault unlock state.
        #[arg(long = "ttl")]
        ttl: Option<u64>,
        /// Allow materializing to a non-tmpfs path. Off by default; setting
        /// this is a deliberate "I accept disk-backed exposure" choice.
        #[arg(long = "allow-disk-backed", default_value_t = false)]
        allow_disk_backed: bool,
    },
}

#[derive(Debug, Subcommand)]
enum GetResource {
    /// Print an entry's password to stdout — the script-friendly primitive
    /// (`trove get password api/stripe | …`). For a human-readable view of
    /// the whole entry use `trove show`.
    ///
    /// With the global `--vault <PATH>`: read the file directly (offline).
    /// Without it: served by the running daemon, gated by the `TROVE_SESSION`
    /// code from `trove unlock`.
    Password {
        /// Entry path to look up, e.g. "github.com" or "Work/github".
        entry_path: String,
    },

    /// Retrieve a stored SSH key by entry path.
    ///
    /// With the global `--vault <PATH>`: read it from the file directly
    /// (offline). Without it: served by the running daemon, gated by the
    /// `TROVE_SESSION` code from `trove unlock`. By default the PRIVATE key is
    /// written to stdout. `--public` emits the public key (an authorized_keys
    /// line) instead. `--out <path>` writes the private key to <path> (0600)
    /// and the public key to <path>.pub (0644); with `--public` it writes only
    /// the public key to <path> (0644).
    Ssh {
        /// Entry path to look up, e.g. "github.com" or "Work/SSH/github".
        entry_path: String,
        /// Emit the public key (authorized_keys line) instead of the private key.
        #[arg(long = "public")]
        public: bool,
        /// Write to this path instead of stdout (see the command help).
        #[arg(long = "out")]
        out: Option<PathBuf>,
    },

    /// Retrieve a stored GPG secret-key export (the `gpg-priv` attachment).
    ///
    /// With the global `--vault <PATH>`: read it from the file (offline).
    /// Without it: read from the daemon's unlocked vault (`TROVE_SESSION`).
    Gpg {
        /// Entry path or title to look up.
        title: String,
        /// Write the export to this path (chmod 0600 on Unix). Stdout if omitted.
        #[arg(long = "out")]
        out: Option<PathBuf>,
    },

    /// Read a named attachment to disk WITHOUT going through materialization.
    /// The materialization config (Materialize.Target, Mode, ...) is ignored —
    /// `--out` controls where the bytes land.
    ///
    /// With the global `--vault <PATH>`: read it from the file (offline).
    /// Without it: read from the daemon's unlocked vault (`TROVE_SESSION`).
    File {
        /// Entry path or title to look up.
        title: String,
        /// Attachment name to read (e.g. `id.pub`). Defaults to "blob". Pass
        /// `--name` for entries that don't use the conventional `blob` slot;
        /// in daemon mode the vault is not opened to resolve `Materialize.Source`.
        #[arg(long = "name")]
        name: Option<String>,
        /// Write the bytes to this path (chmod 0600 on Unix). Stdout if omitted.
        #[arg(long = "out")]
        out: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(classify_exit(&err))
        }
    }
}

/// Unwrap the global `--vault` for commands that cannot run without a vault
/// path (no daemon mode): `init`, `materialize`.
fn require_vault(vault: Option<&Path>) -> Result<&Path> {
    vault.ok_or_else(|| {
        anyhow!("this command needs a vault file; pass --vault <PATH> (the password comes from --password-stdin or a prompt)")
    })
}

/// The `--key-file` bytes, read once in `run()` before any command executes.
/// A read-only global mirroring the flag's global scope (same trust model as
/// the `TROVE_SOCK` env override) — every vault-opening path consults it via
/// [`global_keyfile`] without threading a parameter through each command.
static KEY_FILE: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();

fn global_keyfile() -> Option<&'static [u8]> {
    KEY_FILE.get().and_then(|o| o.as_deref())
}

/// The `--yubikey`/`--cr-secret-hex` challenge-response provider, resolved
/// once in `run()` (device lookup happens there, so a missing YubiKey fails
/// fast before any password prompt). Same read-once model as [`KEY_FILE`].
#[cfg(feature = "yubikey")]
static CHALLENGE_RESPONSE: std::sync::OnceLock<Option<trove_core::ChallengeResponseKey>> =
    std::sync::OnceLock::new();

#[cfg(feature = "yubikey")]
fn global_challenge_response() -> Option<&'static trove_core::ChallengeResponseKey> {
    CHALLENGE_RESPONSE.get().and_then(|o| o.as_ref())
}

/// Resolve `--yubikey SLOT[:SERIAL]` to a device-backed provider.
#[cfg(feature = "yubikey")]
fn resolve_yubikey(spec: &str) -> Result<trove_core::ChallengeResponseKey> {
    use trove_core::ChallengeResponseKey;
    let (slot, serial) = match spec.split_once(':') {
        Some((s, ser)) => (
            s,
            Some(ser.parse::<u32>().context("parsing yubikey serial")?),
        ),
        None => (spec, None),
    };
    if !["1", "2"].contains(&slot) {
        return Err(anyhow!("--yubikey slot must be 1 or 2, got '{slot}'"));
    }
    let yubikey = ChallengeResponseKey::get_yubikey(serial)
        .map_err(|e| anyhow!("locating YubiKey: {e:?}"))?;
    Ok(ChallengeResponseKey::YubikeyChallenge(
        yubikey,
        slot.to_string(),
    ))
}

fn run(cli: Cli) -> Result<()> {
    let pw_stdin = cli.password_stdin;
    // Fail fast on an unreadable keyfile, before any password prompt.
    let keyfile_bytes = match cli.key_file.as_deref() {
        Some(p) => {
            Some(std::fs::read(p).with_context(|| format!("reading key file {}", p.display()))?)
        }
        None => None,
    };
    KEY_FILE.set(keyfile_bytes).expect("run() is called once");
    #[cfg(feature = "yubikey")]
    {
        // Fail fast: a missing/ambiguous device or bad hex should surface
        // before any password prompt.
        let cr = match (&cli.yubikey, &cli.cr_secret_hex) {
            (Some(spec), _) => Some(resolve_yubikey(spec)?),
            (None, Some(hex)) => Some(trove_core::ChallengeResponseKey::LocalChallenge(
                hex.clone(),
            )),
            (None, None) => None,
        };
        CHALLENGE_RESPONSE.set(cr).expect("run() is called once");
    }
    // The global offline selector. `Some` → operate on this file directly;
    // `None` → use the daemon (for commands that have a daemon mode). Commands
    // with no daemon mode (init/materialize) require it via `require_vault`.
    // `unlock` ignores it and uses its own positional.
    let vault = cli.vault.as_deref();
    match cli.command {
        Command::Init => cmd_init(require_vault(vault)?, pw_stdin),
        Command::List { json } => cmd_list(vault, pw_stdin, json),
        Command::Add {
            resource:
                AddResource::Ssh {
                    entry_path,
                    key,
                    comment,
                    user,
                },
        } => cmd_add_ssh(
            &entry_path,
            &key,
            &comment,
            vault,
            user.as_deref(),
            pw_stdin,
        ),
        Command::Add {
            resource: AddResource::Gpg { title, key },
        } => cmd_add_gpg(vault, &title, &key, pw_stdin),
        Command::Add {
            resource:
                AddResource::File {
                    title,
                    src,
                    target,
                    name,
                    mode,
                    ttl,
                    allow_disk_backed,
                },
        } => cmd_add_file(
            vault,
            &title,
            &src,
            &target,
            name.as_deref(),
            &mode,
            ttl,
            allow_disk_backed,
            pw_stdin,
        ),
        Command::Generate {
            resource:
                GenerateResource::Ssh {
                    entry_path,
                    comment,
                    key_type,
                    user,
                },
        } => cmd_generate_ssh(
            &entry_path,
            comment.as_deref(),
            key_type,
            vault,
            user.as_deref(),
            pw_stdin,
        ),
        Command::Get {
            resource:
                GetResource::Ssh {
                    entry_path,
                    public,
                    out,
                },
        } => cmd_get_ssh(&entry_path, public, out.as_deref(), vault, pw_stdin),
        Command::Get {
            resource: GetResource::Gpg { title, out },
        } => cmd_get_gpg(vault, &title, out.as_deref(), pw_stdin),
        Command::Get {
            resource: GetResource::File { title, name, out },
        } => cmd_get_file(vault, &title, name.as_deref(), out.as_deref(), pw_stdin),
        Command::SshAgent {
            op: SshAgentOp::Socket,
        } => cmd_ssh_agent_socket(),
        Command::SshAgent {
            op: SshAgentOp::List,
        } => cmd_ssh_agent_list(),
        Command::GpgAgent {
            op: GpgAgentOp::Socket,
        } => cmd_gpg_agent_socket(),
        Command::GpgAgent {
            op: GpgAgentOp::List,
        } => cmd_gpg_agent_list(),
        Command::Materialize => cmd_materialize(require_vault(vault)?, pw_stdin),
        // `unlock` is daemon-directed: it uses its own positional vault and
        // deliberately ignores the global `--vault` offline selector.
        Command::Unlock {
            vault,
            timeout,
            export,
            shell,
        } => cmd_unlock(&vault, timeout, export, shell, pw_stdin),
        Command::Lock => cmd_lock(),
        Command::Status => cmd_status(),
        Command::Idle {
            op: IdleOp::Set { seconds },
        } => cmd_idle_set(seconds),
        Command::Idle { op: IdleOp::Get } => cmd_idle_get(),
        Command::MaterializeStatus => cmd_materialize_status(),
        Command::Clip {
            entry_path,
            attr,
            totp,
            timeout,
        } => cmd_clip(vault, &entry_path, attr.as_deref(), totp, timeout, pw_stdin),
        Command::ClearClipboard { secs, hash } => {
            clip::run_clearer(secs, &hash)?;
            Ok(())
        }
        Command::Estimate { password } => cmd_estimate(password.as_deref()),
        Command::Analyze { hibp } => cmd_analyze(require_vault(vault)?, &hibp, pw_stdin),
        Command::Exec { scope, command } => {
            cmd_exec(require_vault(vault)?, &scope, &command, pw_stdin)
        }
        Command::GitCredential { operation } => {
            cmd_git_credential(require_vault(vault)?, &operation, pw_stdin)
        }
        Command::Resolve { reference } => cmd_resolve(require_vault(vault)?, &reference, pw_stdin),
        Command::Merge {
            source,
            source_key_file,
        } => cmd_merge(
            require_vault(vault)?,
            &source,
            source_key_file.as_deref(),
            pw_stdin,
        ),
        Command::Export { format } => cmd_export(require_vault(vault)?, format, pw_stdin),
        Command::DbEdit {
            set_password,
            set_key_file,
            unset_key_file,
            kdf_memory,
            kdf_iterations,
            kdf_parallelism,
        } => cmd_db_edit(
            require_vault(vault)?,
            set_password,
            set_key_file.as_deref(),
            unset_key_file,
            kdf_memory,
            kdf_iterations,
            kdf_parallelism,
            pw_stdin,
        ),
        Command::DbInfo { json } => cmd_db_info(require_vault(vault)?, pw_stdin, json),
        Command::Generate {
            resource:
                GenerateResource::Password {
                    length,
                    special,
                    no_lower,
                    no_upper,
                    no_numeric,
                    exclude,
                    count,
                },
        } => {
            let opts = pwgen::GenerateOpts {
                length,
                lower: !no_lower,
                upper: !no_upper,
                numeric: !no_numeric,
                special,
                exclude,
            };
            for _ in 0..count.max(1) {
                println!("{}", pwgen::generate(&opts)?);
            }
            Ok(())
        }
        Command::Generate {
            resource: GenerateResource::Diceware { words, count },
        } => {
            for _ in 0..count.max(1) {
                println!("{}", pwgen::diceware(words)?);
            }
            Ok(())
        }
        Command::Show {
            entry_path,
            attrs,
            show_protected,
            totp,
        } => {
            if totp {
                cmd_show_totp(vault, &entry_path, pw_stdin)
            } else {
                cmd_show(vault, &entry_path, &attrs, show_protected, pw_stdin)
            }
        }
        Command::Search { term, json } => cmd_search(vault, &term, pw_stdin, json),
        Command::Edit {
            entry_path,
            title,
            username,
            url,
            notes,
            password_prompt,
            sets,
            unsets,
        } => cmd_edit(
            vault,
            &entry_path,
            title.as_deref(),
            username.as_deref(),
            url.as_deref(),
            notes.as_deref(),
            password_prompt,
            &sets,
            &unsets,
            pw_stdin,
        ),
        Command::Rm {
            entry_path,
            permanent,
        } => cmd_rm(vault, &entry_path, permanent, pw_stdin),
        Command::Mv {
            entry_path,
            group_path,
        } => cmd_mv(vault, &entry_path, &group_path, pw_stdin),
        Command::Mkdir { group_path } => cmd_mkdir(vault, &group_path, pw_stdin),
        Command::Rmdir {
            group_path,
            permanent,
            recursive,
        } => cmd_rmdir(vault, &group_path, permanent, recursive, pw_stdin),
        Command::Add {
            resource:
                AddResource::Totp {
                    entry_path,
                    uri,
                    secret,
                    digits,
                    period,
                    algorithm,
                },
        } => cmd_add_totp(
            vault,
            &entry_path,
            uri.as_deref(),
            secret.as_deref(),
            digits,
            period,
            &algorithm,
            pw_stdin,
        ),
        Command::Add {
            resource:
                AddResource::Password {
                    entry_path,
                    username,
                    url,
                    notes,
                    generate,
                    length,
                    secret_stdin,
                },
        } => cmd_add_password(
            vault,
            &entry_path,
            username.as_deref(),
            url.as_deref(),
            notes.as_deref(),
            generate,
            length,
            secret_stdin,
            pw_stdin,
        ),
        Command::Get {
            resource: GetResource::Password { entry_path },
        } => cmd_get_password(vault, &entry_path, pw_stdin),
        Command::Completions {
            shell,
            install,
            check,
        } => cmd_completions(shell, install, check),
    }
}

/// Markers delimiting the block `--install` manages in a shell rc file. Kept
/// stable so re-running replaces the block in place instead of appending.
const RC_BEGIN: &str =
    "# >>> trove shell completions (managed by `trove completions --install`) >>>";
const RC_END: &str = "# <<< trove shell completions (managed by `trove completions --install`) <<<";

/// `trove completions [SHELL] [--install|--check]`. Pure local operation: no
/// vault, no daemon, no password.
///
/// - no flags: print the completion script for SHELL to stdout.
/// - `--install`: write the script to the standard location and wire it into
///   the shell rc (idempotent).
/// - `--check`: report how the shell currently completes `trove`.
fn cmd_completions(shell: Option<clap_complete::Shell>, install: bool, check: bool) -> Result<()> {
    if check {
        return completions_check(shell.or_else(detect_shell));
    }
    if install {
        let shell = shell
            .or_else(detect_shell)
            .context("could not detect shell from $SHELL; pass one explicitly, e.g. `trove completions zsh --install`")?;
        return completions_install(shell);
    }
    let shell = shell
        .context("specify a shell, e.g. `trove completions zsh` (or use --install / --check)")?;
    print!("{}", render_completion(shell));
    Ok(())
}

/// Generate the completion script for `shell` from the clap command tree.
fn render_completion(shell: clap_complete::Shell) -> String {
    let mut cmd = <Cli as clap::CommandFactory>::command();
    let bin = cmd.get_name().to_string();
    let mut buf = Vec::new();
    clap_complete::generate(shell, &mut cmd, bin, &mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Best-effort shell detection from `$SHELL`. Returns `None` for shells we
/// can't install for (the caller turns that into a helpful error).
fn detect_shell() -> Option<clap_complete::Shell> {
    use clap_complete::Shell;
    let shell = std::env::var("SHELL").ok()?;
    match Path::new(&shell).file_name()?.to_str()? {
        "zsh" => Some(Shell::Zsh),
        "bash" => Some(Shell::Bash),
        "fish" => Some(Shell::Fish),
        _ => None,
    }
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .context("$HOME is not set")
}

/// `$XDG_DATA_HOME` or `~/.local/share`.
fn data_home() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("XDG_DATA_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(d));
    }
    Ok(home_dir()?.join(".local/share"))
}

/// `$XDG_CONFIG_HOME` or `~/.config`.
fn config_home() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(d));
    }
    Ok(home_dir()?.join(".config"))
}

fn write_completion_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Ensure `rc` contains exactly the managed block (between `RC_BEGIN`/`RC_END`).
/// Replaces an existing block in place, otherwise appends one. Returns whether
/// the file was changed.
fn upsert_rc_block(rc: &Path, body: &str) -> Result<bool> {
    let block = format!("{RC_BEGIN}\n{body}\n{RC_END}");
    let existing = match std::fs::read_to_string(rc) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", rc.display())),
    };

    let updated = match (existing.find(RC_BEGIN), existing.find(RC_END)) {
        (Some(start), Some(end_marker)) if end_marker >= start => {
            let end = end_marker + RC_END.len();
            let mut s = String::with_capacity(existing.len());
            s.push_str(&existing[..start]);
            s.push_str(&block);
            s.push_str(&existing[end..]);
            s
        }
        _ => {
            let mut s = existing.clone();
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(&block);
            s.push('\n');
            s
        }
    };

    if updated == existing {
        return Ok(false);
    }
    if let Some(parent) = rc.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(rc, updated).with_context(|| format!("writing {}", rc.display()))?;
    Ok(true)
}

fn completions_install(shell: clap_complete::Shell) -> Result<()> {
    use clap_complete::Shell;
    let script = render_completion(shell);
    match shell {
        Shell::Zsh => {
            // Source the generated function file from the rc and let its
            // self-registering footer run `compdef _trove trove`. The explicit
            // compdef wins over zsh's bundled `_openstack`, which claims the
            // `trove` name. The guard initializes compinit if the rc hasn't.
            let file = data_home()?.join("trove/completions/_trove");
            write_completion_file(&file, &script)?;
            let rc = home_dir()?.join(".zshrc");
            let body = format!(
                "(( $+functions[compdef] )) || {{ autoload -Uz compinit && compinit }}\nsource {:?}",
                file.display().to_string()
            );
            let changed = upsert_rc_block(&rc, &body)?;
            println!("wrote {}", file.display());
            println!(
                "{} {}",
                if changed {
                    "updated"
                } else {
                    "already current:"
                },
                rc.display()
            );
            println!("restart your shell or run: exec zsh");
        }
        Shell::Bash => {
            let file = data_home()?.join("bash-completion/completions/trove");
            write_completion_file(&file, &script)?;
            let rc = home_dir()?.join(".bashrc");
            let body = format!("[[ -f {0:?} ]] && source {0:?}", file.display().to_string());
            let changed = upsert_rc_block(&rc, &body)?;
            println!("wrote {}", file.display());
            println!(
                "{} {}",
                if changed {
                    "updated"
                } else {
                    "already current:"
                },
                rc.display()
            );
            println!("restart your shell or run: exec bash");
        }
        Shell::Fish => {
            // Fish auto-loads files in this directory; no rc edit needed.
            let file = config_home()?.join("fish/completions/trove.fish");
            write_completion_file(&file, &script)?;
            println!("wrote {}", file.display());
            println!("fish auto-loads it; start a new shell to use it");
        }
        other => {
            anyhow::bail!(
                "--install supports bash, zsh, and fish; for {other} run \
                 `trove completions {other} > <path>` and source it per your shell's docs",
            );
        }
    }
    Ok(())
}

/// Report how the shell currently completes `trove`. For zsh this runs a
/// throwaway interactive shell to read the live completion binding, so it
/// reflects the user's real config (fpath, rc, frameworks).
fn completions_check(shell: Option<clap_complete::Shell>) -> Result<()> {
    use clap_complete::Shell;
    match shell {
        Some(Shell::Zsh) | None => {
            // `None` falls through here: the shadowing problem is zsh-specific,
            // and zsh is the only shell we can introspect this way.
            let binding =
                zsh_completion_binding().context("could not query zsh; is `zsh` on PATH?")?;
            match binding.as_str() {
                "_trove" => {
                    println!("ok: `trove` completes via its own `_trove` function.");
                }
                "" | "<none>" => {
                    println!("no dedicated completion: `trove` falls back to filename completion.");
                    println!("install it with: trove completions zsh --install");
                }
                b if b.contains("openstack") => {
                    println!("shadowed: `trove` completes via `{b}`.");
                    println!(
                        "This is zsh's bundled OpenStack completer (OpenStack's database\n\
                         service is also called Trove); it errors with `_values:compvalues`."
                    );
                    println!("fix it with: trove completions zsh --install");
                }
                b => {
                    println!("`trove` completes via `{b}` (not trove's own `_trove`).");
                    println!("install trove's own with: trove completions zsh --install");
                }
            }
            Ok(())
        }
        Some(other) => {
            println!("--check introspects zsh only (the `_openstack` name clash is zsh-specific).");
            println!("for {other}, install with: trove completions {other} --install");
            Ok(())
        }
    }
}

/// Spawn a throwaway interactive zsh and read which completion function is
/// bound to `trove`. The value is wrapped in a marker so it can be picked out
/// of any noise the user's rc prints. `<none>` means unbound.
fn zsh_completion_binding() -> Result<String> {
    use std::process::{Command, Stdio};
    let out = Command::new("zsh")
        .args([
            "-ic",
            "print -r -- \"TROVE_COMP_BINDING=${_comps[trove]:-<none>}\"",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("running zsh")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value = stdout
        .lines()
        .rev()
        .find_map(|l| l.strip_prefix("TROVE_COMP_BINDING="))
        .context("zsh did not report a completion binding")?;
    Ok(value.trim().to_string())
}

fn cmd_gpg_agent_socket() -> Result<()> {
    // Mirrors `troved::gpg_agent::resolve_gpg_socket_path`.
    let path = if let Ok(p) = std::env::var("TROVE_GPG_SOCK") {
        PathBuf::from(p)
    } else if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            PathBuf::from(rt).join("trove-gpg.sock")
        } else {
            gpg_socket_tmp_fallback()
        }
    } else {
        gpg_socket_tmp_fallback()
    };
    println!("{}", path.display());
    Ok(())
}

fn gpg_socket_tmp_fallback() -> PathBuf {
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let uid = std::env::var("UID").unwrap_or_else(|_| "0".to_string());
    PathBuf::from(tmp).join(format!("trove-gpg-{uid}.sock"))
}

fn cmd_ssh_agent_socket() -> Result<()> {
    // Resolution must mirror `troved::ssh_agent::resolve_ssh_socket_path`.
    // Kept inline here to avoid pulling troved as a dependency of the CLI.
    let path = if let Ok(p) = std::env::var("TROVE_SSH_SOCK") {
        PathBuf::from(p)
    } else if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            PathBuf::from(rt).join("trove-ssh.sock")
        } else {
            ssh_socket_tmp_fallback()
        }
    } else {
        ssh_socket_tmp_fallback()
    };
    println!("{}", path.display());
    Ok(())
}

fn ssh_socket_tmp_fallback() -> PathBuf {
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let uid = std::env::var("UID").unwrap_or_else(|_| "0".to_string());
    PathBuf::from(tmp).join(format!("trove-ssh-{uid}.sock"))
}

/// `trove ssh-agent list` — the consistent equivalent of `ssh-add -L`: one
/// `<algo> <base64-key> <comment>` line per served key. Reads the running
/// daemon without autospawning; if it isn't running (nothing unlocked), there
/// are no served keys, so we print nothing and exit 0.
fn cmd_ssh_agent_list() -> Result<()> {
    match daemon::send(&daemon::Request::SshAgentList) {
        Ok(resp) => {
            if let Some(msg) = daemon::response_error(&resp) {
                return Err(DaemonClassified {
                    message: msg,
                    exit: EXIT_USER_ERROR,
                }
                .into());
            }
            if let Some(keys) = resp.get("ssh_keys").and_then(Value::as_array) {
                for k in keys {
                    let algo = k.get("algo").and_then(Value::as_str).unwrap_or("");
                    let blob = k.get("blob_b64").and_then(Value::as_str).unwrap_or("");
                    let comment = k.get("comment").and_then(Value::as_str).unwrap_or("");
                    println!("{algo} {blob} {comment}");
                }
            }
            Ok(())
        }
        // No daemon ⇒ nothing unlocked ⇒ nothing served. Like `status`, don't
        // autospawn and don't error — just print nothing.
        Err(e) if daemon::is_daemon_not_running(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

/// `trove gpg-agent list` — list the GPG keys the running agent serves, one per
/// line: `<keygrip>\t<type>\t<comment>`. Same daemon-or-nothing semantics as
/// `ssh-agent list`.
fn cmd_gpg_agent_list() -> Result<()> {
    match daemon::send(&daemon::Request::GpgAgentList) {
        Ok(resp) => {
            if let Some(msg) = daemon::response_error(&resp) {
                return Err(DaemonClassified {
                    message: msg,
                    exit: EXIT_USER_ERROR,
                }
                .into());
            }
            if let Some(keys) = resp.get("gpg_keys").and_then(Value::as_array) {
                for k in keys {
                    let keygrip = k.get("keygrip").and_then(Value::as_str).unwrap_or("");
                    let key_type = k.get("key_type").and_then(Value::as_str).unwrap_or("");
                    let comment = k.get("comment").and_then(Value::as_str).unwrap_or("");
                    println!("{keygrip}\t{key_type}\t{comment}");
                }
            }
            Ok(())
        }
        Err(e) if daemon::is_daemon_not_running(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

fn cmd_init(vault_path: &Path, pw_stdin: bool) -> Result<()> {
    if vault_path.exists() {
        return Err(anyhow!(
            "vault file already exists: {}",
            vault_path.display()
        ));
    }
    let password = if pw_stdin {
        read_password_from_stdin().context("reading new vault password from stdin")?
    } else {
        prompt_new_password().context("reading new vault password")?
    };
    #[cfg(feature = "yubikey")]
    if let Some(cr) = global_challenge_response() {
        let _vault = Vault::create_with_challenge_response(
            vault_path,
            &password,
            global_keyfile(),
            cr.clone(),
        )
        .context("creating vault")?;
        println!(
            "created vault at {} (composite key incl. challenge-response)",
            vault_path.display()
        );
        return Ok(());
    }
    let _vault = Vault::create_with_key(vault_path, &password, global_keyfile())
        .context("creating vault")?;
    match global_keyfile() {
        Some(_) => println!(
            "created vault at {} (composite key: password + key file)",
            vault_path.display()
        ),
        None => println!("created vault at {}", vault_path.display()),
    }
    Ok(())
}

/// One entry summary as the stable JSON shape shared by `list --json` and
/// `search --json` (and matching the daemon's wire summaries).
fn entry_summary_json(e: &trove_core::EntrySummary) -> Value {
    serde_json::json!({
        "id": e.id.to_string(),
        "title": e.title,
        "path": e.display_path(),
        "username": e.username,
        "url": e.url,
        "attachments": e.attachment_names,
        "group_path": e.group_path,
    })
}

fn cmd_list(vault_path: Option<&Path>, pw_stdin: bool, json: bool) -> Result<()> {
    match vault_path {
        Some(path) => {
            let vault = open_vault(path, pw_stdin)?;
            if json {
                let arr: Vec<Value> = vault
                    .list_entries()
                    .iter()
                    .map(entry_summary_json)
                    .collect();
                println!("{}", serde_json::to_string_pretty(&arr)?);
                return Ok(());
            }
            for entry in vault.list_entries() {
                print_list_row(
                    &entry.id.to_string(),
                    &entry.display_path(),
                    &entry.attachment_names,
                );
            }
            Ok(())
        }
        None => cmd_list_via_daemon(json),
    }
}

/// Daemon-backed list. The vault must already be unlocked in the daemon;
/// otherwise the daemon returns "no vault unlocked" and we surface that as
/// a user error (exit 1). Auto-spawn semantics are inherited from
/// `daemon::send_autospawn` — if no daemon is running we spawn one, but it
/// will come up with no vault unlocked, so the user gets the same friendly
/// "no vault unlocked" message and a hint to run `trove unlock`.
fn cmd_list_via_daemon(json: bool) -> Result<()> {
    let resp = match daemon::send_autospawn(&daemon::Request::List) {
        Ok(v) => v,
        Err(e) if daemon::is_daemon_not_running(&e) => {
            return Err(DaemonClassified {
                message: e.to_string(),
                exit: EXIT_USER_ERROR,
            }
            .into());
        }
        Err(e) => return Err(e),
    };
    if let Some(msg) = daemon::response_error(&resp) {
        let hint = if msg.contains("no vault") {
            "; pass a vault path or run `trove unlock <vault>` first"
        } else {
            ""
        };
        return Err(DaemonClassified {
            message: format!("{msg}{hint}"),
            exit: EXIT_USER_ERROR,
        }
        .into());
    }
    let entries = resp
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }
    print_entry_rows_from_json(&entries);
    Ok(())
}

/// Render daemon `List`/`Search`-shaped entry summaries with
/// [`print_list_row`], reconstructing each `Group/Sub/Title` display path.
fn print_entry_rows_from_json(entries: &[Value]) {
    for entry in entries {
        let id = entry.get("id").and_then(Value::as_str).unwrap_or("?");
        let title = entry.get("title").and_then(Value::as_str).unwrap_or("?");
        let group_path: Vec<&str> = entry
            .get("group_path")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let display = if group_path.is_empty() {
            title.to_string()
        } else {
            format!("{}/{title}", group_path.join("/"))
        };
        let attachments: Vec<String> = entry
            .get("attachments")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        print_list_row(id, &display, &attachments);
    }
}

fn print_list_row(id: &str, title: &str, attachments: &[String]) {
    if attachments.is_empty() {
        println!("{id}  {title}");
    } else {
        println!("{id}  {title}  [attachments: {}]", attachments.join(", "));
    }
}

fn cmd_add_ssh(
    entry_path: &str,
    key_path: &Path,
    comment: &str,
    vault: Option<&Path>,
    user: Option<&str>,
    pw_stdin: bool,
) -> Result<()> {
    let key_bytes = std::fs::read(key_path)
        .with_context(|| format!("reading ssh key from {}", key_path.display()))?;

    // Validate before storing: reject a public key, an encrypted key, or an
    // unsupported/weak algorithm with a precise, user-facing message.
    validate_ssh_private_key(&key_bytes, comment)?;

    store_ssh_key(
        "stored", entry_path, &key_bytes, comment, vault, user, pw_stdin,
    )
}

/// `trove generate ssh`: mint a fresh keypair in-tool and store it exactly like
/// `add ssh` (private key + derived `id.pub` + `KeeAgent.settings`), so users
/// never have to drive `ssh-keygen` themselves. Defaults to ed25519.
fn cmd_generate_ssh(
    entry_path: &str,
    comment: Option<&str>,
    key_type: SshKeyType,
    vault: Option<&Path>,
    user: Option<&str>,
    pw_stdin: bool,
) -> Result<()> {
    use troved::ssh_agent::keys::KeyType;
    // A key comment is purely cosmetic in the .pub line; default it to the entry
    // path so a generated key is still identifiable without the user supplying one.
    let comment = comment.unwrap_or(entry_path);
    let kt = match key_type {
        SshKeyType::Ed25519 => KeyType::Ed25519,
        SshKeyType::Rsa => KeyType::Rsa,
        SshKeyType::EcdsaP256 => KeyType::EcdsaP256,
        SshKeyType::EcdsaP384 => KeyType::EcdsaP384,
    };
    let key_bytes = troved::ssh_agent::keys::generate_private_key(kt, comment)
        .map_err(|e| anyhow!("generating ssh key: {e}"))?;
    store_ssh_key(
        "generated",
        entry_path,
        &key_bytes,
        comment,
        vault,
        user,
        pw_stdin,
    )
}

/// Store SSH private-key bytes on an entry, the single path shared by `add ssh`
/// (imported key) and `generate ssh` (freshly minted): the private key, the
/// derived `id.pub`, and `KeeAgent.settings`. `verb` ("stored"/"generated")
/// only flavours the success line.
///
/// `Some(vault)` opens the kdbx file directly (offline); the default routes
/// through the unlocked daemon, which derives id.pub + KeeAgent itself and
/// reloads the agent key store so a new key is served immediately.
fn store_ssh_key(
    verb: &str,
    entry_path: &str,
    key_bytes: &[u8],
    comment: &str,
    vault: Option<&Path>,
    user: Option<&str>,
    pw_stdin: bool,
) -> Result<()> {
    match vault {
        // Offline: open the kdbx file directly and write to it.
        Some(vault_path) => {
            let mut vault = open_vault(vault_path, pw_stdin)?;
            let id = match vault.find_by_title(entry_path) {
                Some(existing) => existing,
                None => vault
                    .add_entry(entry_path)
                    .with_context(|| format!("creating entry '{entry_path}'"))?,
            };
            vault
                .attach_binary(&id, SSH_KEY_ATTACHMENT, key_bytes)
                .context("attaching ssh key")?;
            // KeeAgent.settings so KeePassXC's SSH agent picks this entry up.
            let settings = troved::ssh_agent::keeagent::settings_xml(SSH_KEY_ATTACHMENT);
            vault
                .attach_binary(&id, troved::ssh_agent::keeagent::ATTACHMENT_NAME, &settings)
                .context("attaching KeeAgent.settings")?;
            // Persist the public key as real data so any tool can read it
            // without deriving it from the private key (a trove-only ability).
            let pub_line = ssh_public_line(key_bytes, comment)?;
            vault
                .attach_binary(&id, SSH_PUBKEY_ATTACHMENT, pub_line.as_bytes())
                .context("attaching public key")?;
            if let Some(user) = user {
                vault
                    .set_field(&id, "UserName", user)
                    .context("setting UserName")?;
            }
            vault.save().context("saving vault")?;
            println!("{verb} ssh key on entry {id} ({entry_path})");
            Ok(())
        }
        // Default: store into the daemon's currently unlocked vault. The daemon
        // mutates the held vault, persists it, and reloads the agent key store
        // so the new key is served immediately.
        None => {
            let code = require_session_code()?;
            use base64::Engine;
            let key = base64::engine::general_purpose::STANDARD.encode(key_bytes);
            let req = daemon::Request::AddSsh {
                path: entry_path.to_string(),
                key,
                comment: Some(comment.to_string()),
                user: user.map(str::to_string),
                code,
            };
            let resp = match daemon::send_autospawn(&req) {
                Ok(v) => v,
                Err(e) if daemon::is_daemon_not_running(&e) => {
                    return Err(DaemonClassified {
                        message: e.to_string(),
                        exit: EXIT_USER_ERROR,
                    }
                    .into());
                }
                Err(e) => return Err(e),
            };
            if let Some(msg) = daemon::response_error(&resp) {
                return Err(DaemonClassified {
                    message: msg,
                    exit: EXIT_USER_ERROR,
                }
                .into());
            }
            println!("{verb} ssh key for {entry_path}");
            Ok(())
        }
    }
}

fn cmd_add_gpg(vault: Option<&Path>, title: &str, key_path: &Path, pw_stdin: bool) -> Result<()> {
    let key_bytes = std::fs::read(key_path)
        .with_context(|| format!("reading gpg secret-key export from {}", key_path.display()))?;

    match vault {
        // Offline: open the kdbx file directly and write to it.
        Some(vault_path) => {
            let mut vault = open_vault(vault_path, pw_stdin)?;

            let id = match vault.find_by_title(title) {
                Some(existing) => existing,
                None => vault
                    .add_entry(title)
                    .with_context(|| format!("creating entry '{title}'"))?,
            };

            vault
                .attach_binary(&id, GPG_KEY_ATTACHMENT, &key_bytes)
                .context("attaching gpg secret key")?;

            vault.save().context("saving vault")?;
            println!("stored gpg secret key on entry {id} ({title})");
            Ok(())
        }
        // Default: store into the daemon's currently unlocked vault.
        None => {
            let code = require_session_code()?;
            use base64::Engine;
            let key = base64::engine::general_purpose::STANDARD.encode(&key_bytes);
            let req = daemon::Request::AddGpg {
                title: title.to_string(),
                key,
                code,
            };
            let resp = match daemon::send_autospawn(&req) {
                Ok(v) => v,
                Err(e) if daemon::is_daemon_not_running(&e) => {
                    return Err(DaemonClassified {
                        message: e.to_string(),
                        exit: EXIT_USER_ERROR,
                    }
                    .into());
                }
                Err(e) => return Err(e),
            };
            if let Some(msg) = daemon::response_error(&resp) {
                return Err(DaemonClassified {
                    message: msg,
                    exit: EXIT_USER_ERROR,
                }
                .into());
            }
            println!("stored gpg secret key for {title}");
            Ok(())
        }
    }
}

/// Pull an attachment out of the *unlocked daemon*, gated by the session code.
///
/// Extraction (`get`) no longer opens the vault one-shot — that would let any
/// password holder bypass the session-code gate. Instead we read `TROVE_SESSION`
/// (the one-time code `trove unlock` minted) and ask the daemon, which serves
/// the bytes only if: the vault is unlocked, the code matches, and we are the
/// uid that unlocked (SO_PEERCRED). The daemon returns the bytes base64-encoded
/// on the JSON wire; we decode them here. See docs/provisioning-sessions.md.
fn daemon_get_attachment(title: &str, attachment: &str) -> Result<Vec<u8>> {
    let code = require_session_code()?;

    let req = daemon::Request::Get {
        title: title.to_string(),
        attachment: attachment.to_string(),
        code,
    };
    let resp = match daemon::send_autospawn(&req) {
        Ok(v) => v,
        Err(e) if daemon::is_daemon_not_running(&e) => {
            return Err(DaemonClassified {
                message: e.to_string(),
                exit: EXIT_USER_ERROR,
            }
            .into());
        }
        Err(e) => return Err(e),
    };
    if let Some(msg) = daemon::response_error(&resp) {
        return Err(DaemonClassified {
            message: msg,
            exit: EXIT_USER_ERROR,
        }
        .into());
    }

    let b64 = resp
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("daemon returned ok but no secret data"))?;
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("decoding base64 secret from daemon")
}

/// Write secret bytes to `out` (chmod 0600 on Unix) or stdout. `what` names the
/// payload for error context.
fn write_secret_out(out: Option<&Path>, bytes: &[u8], what: &str) -> Result<()> {
    match out {
        Some(path) => write_private_file(path, bytes)
            .with_context(|| format!("writing {what} to {}", path.display())),
        None => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle
                .write_all(bytes)
                .with_context(|| format!("writing {what} to stdout"))
        }
    }
}

/// Read an attachment by entry path directly from a kdbx file (offline mode).
/// Opens the vault (password via `--password-stdin` or prompt), resolves the
/// entry path, and returns the named attachment's bytes.
fn offline_get_attachment(
    vault_path: &Path,
    entry_path: &str,
    attachment: &str,
    pw_stdin: bool,
) -> Result<Vec<u8>> {
    let vault = open_vault(vault_path, pw_stdin)?;
    let id = vault
        .find_by_title(entry_path)
        .ok_or_else(|| anyhow!("no entry at '{entry_path}' in {}", vault_path.display()))?;
    vault
        .read_binary(&id, attachment)
        .with_context(|| format!("reading attachment '{attachment}' from '{entry_path}'"))?
        .ok_or_else(|| anyhow!("entry '{entry_path}' has no attachment '{attachment}'"))
}

fn cmd_get_gpg(
    vault: Option<&Path>,
    title: &str,
    out: Option<&Path>,
    pw_stdin: bool,
) -> Result<()> {
    let bytes = match vault {
        Some(path) => offline_get_attachment(path, title, GPG_KEY_ATTACHMENT, pw_stdin)?,
        None => daemon_get_attachment(title, GPG_KEY_ATTACHMENT)?,
    };
    write_secret_out(out, &bytes, "gpg secret key")
}

/// Fetch an entry's SSH public key: prefer the persisted `id.pub` attachment
/// (the whole point of storing it — no derivation, works for any tool), and
/// fall back to deriving it from the private key only for legacy entries that
/// predate id.pub. A public-key request thus never pulls the private key when
/// the public half is already stored.
fn fetch_ssh_public(entry_path: &str) -> Result<Vec<u8>> {
    if let Ok(b) = daemon_get_attachment(entry_path, SSH_PUBKEY_ATTACHMENT) {
        return Ok(b);
    }
    let priv_bytes = daemon_get_attachment(entry_path, SSH_KEY_ATTACHMENT)?;
    Ok(ssh_public_line(&priv_bytes, entry_path)?.into_bytes())
}

fn cmd_get_ssh(
    entry_path: &str,
    public: bool,
    out: Option<&Path>,
    vault: Option<&Path>,
    pw_stdin: bool,
) -> Result<()> {
    match vault {
        Some(vault_path) => cmd_get_ssh_offline(vault_path, entry_path, public, out, pw_stdin),
        None => cmd_get_ssh_daemon(entry_path, public, out),
    }
}

/// Daemon path for `get ssh`: served by the running `troved`, gated by
/// `TROVE_SESSION`.
fn cmd_get_ssh_daemon(entry_path: &str, public: bool, out: Option<&Path>) -> Result<()> {
    // Public-key request: hand back the persisted id.pub (deriving only as a
    // fallback for legacy entries).
    if public {
        let pub_bytes = fetch_ssh_public(entry_path)?;
        return match out {
            None => {
                print!("{}", String::from_utf8_lossy(&pub_bytes));
                Ok(())
            }
            Some(p) => write_public_file(p, &pub_bytes)
                .with_context(|| format!("writing public key to {}", p.display())),
        };
    }

    // Private-key request.
    let priv_bytes = daemon_get_attachment(entry_path, SSH_KEY_ATTACHMENT)?;
    match out {
        // Private key straight to stdout.
        None => write_secret_out(None, &priv_bytes, "ssh key"),
        // Reconstruct the pair: private to <out> (0600), public to <out>.pub (0644).
        Some(p) => {
            write_private_file(p, &priv_bytes)
                .with_context(|| format!("writing ssh key to {}", p.display()))?;
            let pub_bytes = fetch_ssh_public(entry_path)?;
            let pub_path = {
                let mut s = p.as_os_str().to_os_string();
                s.push(".pub");
                PathBuf::from(s)
            };
            write_public_file(&pub_path, &pub_bytes)
                .with_context(|| format!("writing public key to {}", pub_path.display()))
        }
    }
}

/// Offline path for `get ssh`: open the kdbx file directly and read the `id` /
/// `id.pub` attachments. The vault is opened once (one password prompt) and the
/// public key falls back to deriving it from the private key for legacy entries
/// that predate the persisted `id.pub`.
fn cmd_get_ssh_offline(
    vault_path: &Path,
    entry_path: &str,
    public: bool,
    out: Option<&Path>,
    pw_stdin: bool,
) -> Result<()> {
    let vault = open_vault(vault_path, pw_stdin)?;
    let id = vault
        .find_by_title(entry_path)
        .ok_or_else(|| anyhow!("no entry at '{entry_path}' in {}", vault_path.display()))?;

    let read = |name: &str| -> Result<Option<Vec<u8>>> {
        vault
            .read_binary(&id, name)
            .with_context(|| format!("reading attachment '{name}' from '{entry_path}'"))
    };
    let read_priv = || -> Result<Vec<u8>> {
        read(SSH_KEY_ATTACHMENT)?.ok_or_else(|| {
            anyhow!(
                "entry '{entry_path}' has no '{}' attachment",
                SSH_KEY_ATTACHMENT
            )
        })
    };

    if public {
        let pub_bytes = match read(SSH_PUBKEY_ATTACHMENT)? {
            Some(b) => b,
            None => ssh_public_line(&read_priv()?, entry_path)?.into_bytes(),
        };
        return match out {
            None => {
                print!("{}", String::from_utf8_lossy(&pub_bytes));
                Ok(())
            }
            Some(p) => write_public_file(p, &pub_bytes)
                .with_context(|| format!("writing public key to {}", p.display())),
        };
    }

    let priv_bytes = read_priv()?;
    match out {
        None => write_secret_out(None, &priv_bytes, "ssh key"),
        Some(p) => {
            write_private_file(p, &priv_bytes)
                .with_context(|| format!("writing ssh key to {}", p.display()))?;
            let pub_bytes = match read(SSH_PUBKEY_ATTACHMENT)? {
                Some(b) => b,
                None => ssh_public_line(&priv_bytes, entry_path)?.into_bytes(),
            };
            let pub_path = {
                let mut s = p.as_os_str().to_os_string();
                s.push(".pub");
                PathBuf::from(s)
            };
            write_public_file(&pub_path, &pub_bytes)
                .with_context(|| format!("writing public key to {}", pub_path.display()))
        }
    }
}

/// Read the one-time session code minted by `trove unlock` from `TROVE_SESSION`.
/// Daemon-gated reads (`get`) and the daemon-routed `add ssh` both present it.
fn require_session_code() -> Result<String> {
    std::env::var("TROVE_SESSION")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            DaemonClassified {
                message: "session code required: run `eval \"$(trove unlock <vault>)\"` first, \
                          then retry in the same shell"
                    .to_string(),
                exit: EXIT_USER_ERROR,
            }
            .into()
        })
}

/// Parse `bytes` as an SSH private key purely to validate it, mapping each
/// failure to a precise, user-facing message. `Ok(())` means it is storable.
fn validate_ssh_private_key(bytes: &[u8], comment: &str) -> Result<()> {
    use troved::ssh_agent::keys::{parse_private_key, ParseError};
    let user_err = |message: String| -> anyhow::Error {
        DaemonClassified {
            message,
            exit: EXIT_USER_ERROR,
        }
        .into()
    };
    match parse_private_key(bytes, comment) {
        Ok(_) => Ok(()),
        Err(ParseError::Encrypted) => Err(user_err(
            "the key is passphrase-encrypted; decrypt a copy first \
             (`ssh-keygen -p -f <file>`) and add that"
                .to_string(),
        )),
        Err(ParseError::RsaTooSmall(bits)) => Err(user_err(format!(
            "RSA key too small: {bits} bits (minimum 2048)"
        ))),
        Err(ParseError::UnsupportedAlgorithm(alg)) => Err(user_err(format!(
            "unsupported key algorithm: {alg} \
             (supported: ed25519, rsa>=2048, ecdsa-nistp256, ecdsa-nistp384)"
        ))),
        Err(ParseError::NotOpenssh(detail)) => {
            if looks_like_public_key(bytes) {
                Err(user_err(
                    "that looks like a public key; pass the PRIVATE key file \
                     (e.g. ~/.ssh/id_ed25519, not id_ed25519.pub)"
                        .to_string(),
                ))
            } else {
                Err(user_err(format!(
                    "couldn't parse as an SSH private key: {detail}"
                )))
            }
        }
        Err(ParseError::PublicBlob(e)) => Err(anyhow!("internal: encoding public key: {e}")),
    }
}

/// Heuristic: does `bytes` look like an OpenSSH *public* key line
/// (`ssh-ed25519 AAAA…`, `ssh-rsa AAAA…`, `ecdsa-sha2-… AAAA…`, `sk-…`)? Used
/// only to turn a parse failure into a clearer "you passed the .pub" message.
fn looks_like_public_key(bytes: &[u8]) -> bool {
    let head = match std::str::from_utf8(bytes) {
        Ok(s) => s.trim_start(),
        Err(_) => return false,
    };
    const PREFIXES: [&str; 5] = [
        "ssh-ed25519 ",
        "ssh-rsa ",
        "ecdsa-sha2-",
        "sk-ssh-",
        "ssh-dss ",
    ];
    PREFIXES.iter().any(|p| head.starts_with(p))
}

/// Derive the OpenSSH public-key line (`<algo> <base64-blob> <comment>`) from
/// raw private-key bytes, via `troved`'s shared helper so the encoding matches
/// exactly what the agent serves and what `add ssh` persists as `id.pub`.
fn ssh_public_line(priv_bytes: &[u8], comment: &str) -> Result<String> {
    troved::ssh_agent::keys::openssh_public_line(priv_bytes, comment)
        .map_err(|e| anyhow!("deriving public key: {e}"))
}

/// Write a non-secret file (public key) at mode 0644, truncating any existing
/// content. The private-key counterpart is [`write_private_file`] (0600,
/// create-new).
#[cfg(unix)]
fn write_public_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_public_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

fn open_vault(path: &Path, pw_stdin: bool) -> Result<Vault> {
    if !path.exists() {
        return Err(CoreError::NotFound(path.to_path_buf()).into());
    }
    let password = if pw_stdin {
        read_password_from_stdin().context("reading vault password from stdin")?
    } else {
        rpassword::prompt_password("Vault password: ").context("reading vault password")?
    };
    #[cfg(feature = "yubikey")]
    if let Some(cr) = global_challenge_response() {
        return Vault::open_with_challenge_response(path, &password, global_keyfile(), cr.clone())
            .with_context(|| format!("opening vault {}", path.display()));
    }
    Vault::open_with_key(path, &password, global_keyfile())
        .with_context(|| format!("opening vault {}", path.display()))
}

fn prompt_new_password() -> Result<String> {
    let first = rpassword::prompt_password("New vault password: ")?;
    let second = rpassword::prompt_password("Confirm password: ")?;
    if first != second {
        return Err(anyhow!("passwords do not match"));
    }
    if first.is_empty() {
        return Err(anyhow!("password must not be empty"));
    }
    Ok(first)
}

fn read_password_from_stdin() -> Result<String> {
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
    if trimmed.is_empty() {
        return Err(anyhow!("password from stdin must not be empty"));
    }
    Ok(trimmed)
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

/// `trove add file`. Stores file bytes as a real KDBX `<Binary>` attachment
/// and writes the `Materialize.*` custom fields. The basename of `--src` is
/// the default attachment name; `--name` overrides.
#[allow(clippy::too_many_arguments)]
fn cmd_add_file(
    vault: Option<&Path>,
    title: &str,
    src: &Path,
    target: &Path,
    name: Option<&str>,
    mode: &str,
    ttl: Option<u64>,
    allow_disk_backed: bool,
    pw_stdin: bool,
) -> Result<()> {
    // Read file bytes BEFORE prompting for password — fail fast on a typo.
    let bytes =
        std::fs::read(src).with_context(|| format!("reading source file {}", src.display()))?;

    let attachment_name: String = match name {
        Some(n) => n.to_string(),
        None => src
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                anyhow!("could not derive attachment name from --src; pass --name explicitly")
            })?,
    };

    match vault {
        // Offline: open the kdbx file directly and write to it.
        Some(vault_path) => {
            let mut vault = open_vault(vault_path, pw_stdin)?;
            let id = match vault.find_by_title(title) {
                Some(existing) => existing,
                None => vault
                    .add_entry(title)
                    .with_context(|| format!("creating entry '{title}'"))?,
            };

            vault
                .attach_binary(&id, &attachment_name, &bytes)
                .context("attaching file bytes")?;
            vault
                .set_field(&id, "Materialize.Source", &attachment_name)
                .context("setting Materialize.Source")?;
            let target_str = target
                .to_str()
                .ok_or_else(|| anyhow!("target path is not valid utf8"))?;
            vault
                .set_field(&id, "Materialize.Target", target_str)
                .context("setting Materialize.Target")?;
            vault
                .set_field(&id, "Materialize.Mode", mode)
                .context("setting Materialize.Mode")?;
            if let Some(ttl) = ttl {
                vault
                    .set_field(&id, "Materialize.TTL", &ttl.to_string())
                    .context("setting Materialize.TTL")?;
            }
            vault
                .set_field(
                    &id,
                    "Materialize.AllowDiskBacked",
                    if allow_disk_backed { "true" } else { "false" },
                )
                .context("setting Materialize.AllowDiskBacked")?;

            vault.save().context("saving vault")?;
            println!(
                "stored '{}' as attachment '{attachment_name}' on entry {id} ({title}); \
                 materializes to {} on unlock",
                src.display(),
                target.display()
            );
            if !allow_disk_backed {
                eprintln!(
                    "note: AllowDiskBacked=false. The daemon will refuse to materialize \
                     unless the target is on a tmpfs/memory-backed filesystem (Linux). \
                     On macOS this maps to a soft allowlist (/tmp, /private/tmp, \
                     $XDG_RUNTIME_DIR) — APFS does not provide a real tmpfs."
                );
            }
            Ok(())
        }
        // Default: store into the daemon's currently unlocked vault. The file
        // lands on disk on the next unlock, not in the current session.
        None => {
            let target_str = target
                .to_str()
                .ok_or_else(|| anyhow!("target path is not valid utf8"))?;
            let code = require_session_code()?;
            use base64::Engine;
            let src_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            let req = daemon::Request::AddFile {
                title: title.to_string(),
                src: src_b64,
                name: attachment_name.clone(),
                target: target_str.to_string(),
                mode: mode.to_string(),
                ttl,
                allow_disk_backed,
                code,
            };
            let resp = match daemon::send_autospawn(&req) {
                Ok(v) => v,
                Err(e) if daemon::is_daemon_not_running(&e) => {
                    return Err(DaemonClassified {
                        message: e.to_string(),
                        exit: EXIT_USER_ERROR,
                    }
                    .into());
                }
                Err(e) => return Err(e),
            };
            if let Some(msg) = daemon::response_error(&resp) {
                return Err(DaemonClassified {
                    message: msg,
                    exit: EXIT_USER_ERROR,
                }
                .into());
            }
            println!(
                "stored '{}' as attachment '{attachment_name}' for entry {title}",
                src.display()
            );
            Ok(())
        }
    }
}

/// `trove get file` — read a named attachment to disk WITHOUT engaging
/// materialization. Offline with `--vault`, otherwise daemon-routed and
/// session-code-gated like `trove get ssh`.
///
/// The attachment name comes from `--name`, defaulting to `"blob"`. (In daemon
/// mode we cannot resolve a default from the entry's `Materialize.Source` field
/// without opening the vault, which would defeat the session-code gate — so
/// pass `--name` for entries that don't use the conventional `blob` slot.)
fn cmd_get_file(
    vault: Option<&Path>,
    title: &str,
    name: Option<&str>,
    out: Option<&Path>,
    pw_stdin: bool,
) -> Result<()> {
    let attachment = name.unwrap_or("blob");
    let bytes = match vault {
        Some(path) => offline_get_attachment(path, title, attachment, pw_stdin)?,
        None => daemon_get_attachment(title, attachment)?,
    };
    write_secret_out(out, &bytes, "file")
}

// --- generic entry CRUD (G1) -------------------------------------------------

/// One daemon round-trip with the standard error plumbing shared by the CRUD
/// commands: autospawn, map "daemon not running" and protocol-level errors to
/// user errors (exit 1), append the unlock hint when no vault is open.
fn daemon_call(req: &daemon::Request) -> Result<Value> {
    let resp = match daemon::send_autospawn(req) {
        Ok(v) => v,
        Err(e) if daemon::is_daemon_not_running(&e) => {
            return Err(DaemonClassified {
                message: e.to_string(),
                exit: EXIT_USER_ERROR,
            }
            .into());
        }
        Err(e) => return Err(e),
    };
    if let Some(msg) = daemon::response_error(&resp) {
        let hint = if msg.contains("no vault") {
            "; pass a vault path or run `trove unlock <vault>` first"
        } else {
            ""
        };
        return Err(DaemonClassified {
            message: format!("{msg}{hint}"),
            exit: EXIT_USER_ERROR,
        }
        .into());
    }
    Ok(resp)
}

/// The fields trove-core stores with the kdbx Protected flag (see
/// `Vault::set_field`): `Password` and `otp` — the same pair KeePassXC
/// memory-protects by default.
fn is_protected_field(name: &str) -> bool {
    name.eq_ignore_ascii_case("password") || name.eq_ignore_ascii_case("otp")
}

/// Prompt (hidden) for an entry password, twice, requiring a non-empty match.
fn prompt_entry_password() -> Result<String> {
    let first = rpassword::prompt_password("Entry password: ")?;
    let second = rpassword::prompt_password("Confirm password: ")?;
    if first != second {
        return Err(anyhow!("passwords do not match"));
    }
    if first.is_empty() {
        return Err(anyhow!("password must not be empty"));
    }
    Ok(first)
}

/// Mint an entry password with `add password --generate` defaults
/// (alphanumeric pool — see [`pwgen::GenerateOpts`] for the full policy
/// surface exposed by `trove generate password`).
fn generate_entry_password(len: usize) -> String {
    pwgen::generate(&pwgen::GenerateOpts {
        length: len,
        ..pwgen::GenerateOpts::default()
    })
    .expect("default charset pool is never empty")
}

/// Parse a `--set NAME=VALUE` argument.
fn parse_set_kv(s: &str) -> Result<(String, String)> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| anyhow!("--set expects NAME=VALUE, got '{s}'"))?;
    if k.is_empty() {
        return Err(anyhow!("--set expects a non-empty NAME, got '{s}'"));
    }
    Ok((k.to_string(), v.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn cmd_add_password(
    vault: Option<&Path>,
    entry_path: &str,
    username: Option<&str>,
    url: Option<&str>,
    notes: Option<&str>,
    generate: bool,
    length: Option<usize>,
    secret_stdin: bool,
    pw_stdin: bool,
) -> Result<()> {
    // Offline mode opens the vault FIRST so that with `--password-stdin
    // --secret-stdin` the vault password is line 1 and the secret line 2.
    let mut offline_vault = match vault {
        Some(path) => Some(open_vault(path, pw_stdin)?),
        None => None,
    };
    let password = if generate {
        generate_entry_password(length.unwrap_or(20))
    } else if secret_stdin {
        read_password_from_stdin().context("reading entry password from stdin")?
    } else {
        prompt_entry_password().context("reading entry password")?
    };

    match offline_vault.as_mut() {
        Some(v) => {
            if v.find_by_title(entry_path).is_some() {
                return Err(anyhow!(
                    "entry already exists: {entry_path} (use `trove edit` to change it)"
                ));
            }
            let id = v.add_entry(entry_path).context("creating entry")?;
            v.set_field(&id, "Password", &password)
                .context("setting Password")?;
            for (name, value) in [("UserName", username), ("URL", url), ("Notes", notes)] {
                if let Some(value) = value {
                    v.set_field(&id, name, value)
                        .with_context(|| format!("setting {name}"))?;
                }
            }
            v.save().context("saving vault")?;
        }
        None => {
            let code = require_session_code()?;
            daemon_call(&daemon::Request::AddPassword {
                path: entry_path.to_string(),
                username: username.map(str::to_string),
                url: url.map(str::to_string),
                notes: notes.map(str::to_string),
                password: password.clone(),
                code,
            })?;
        }
    }
    if generate {
        // The only time the secret is echoed: the user asked us to mint it
        // and has no other way to learn it. Stdout, so it pipes.
        println!("{password}");
    } else {
        println!("stored password entry at '{entry_path}'");
    }
    Ok(())
}

fn cmd_get_password(vault: Option<&Path>, entry_path: &str, pw_stdin: bool) -> Result<()> {
    match vault {
        Some(path) => {
            let v = open_vault(path, pw_stdin)?;
            let id = v
                .find_by_title(entry_path)
                .ok_or_else(|| anyhow!("entry not found: {entry_path}"))?;
            let pw = v
                .get_field(&id, "Password")
                .context("reading Password")?
                .ok_or_else(|| anyhow!("entry '{entry_path}' has no password"))?;
            println!("{pw}");
        }
        None => {
            let code = require_session_code()?;
            let resp = daemon_call(&daemon::Request::GetField {
                path: entry_path.to_string(),
                field: "Password".to_string(),
                code,
            })?;
            let pw = resp
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("malformed daemon response: missing 'value'"))?;
            println!("{pw}");
        }
    }
    Ok(())
}

/// Shared renderer for `show`'s summary view. `password` is `Some` only when
/// `--show-protected` resolved it; `None` prints the masked placeholder.
#[allow(clippy::too_many_arguments)]
fn print_show_summary(
    display_path: &str,
    title: &str,
    username: Option<&str>,
    url: Option<&str>,
    notes: Option<&str>,
    password: Option<&str>,
    custom_fields: &[String],
    attachments: &[String],
) {
    println!("Path: {display_path}");
    println!("Title: {title}");
    println!("UserName: {}", username.unwrap_or(""));
    match password {
        Some(pw) => println!("Password: {pw}"),
        None => println!("Password: [PROTECTED — pass --show-protected to reveal]"),
    }
    println!("URL: {}", url.unwrap_or(""));
    println!("Notes: {}", notes.unwrap_or(""));
    if !custom_fields.is_empty() {
        println!("Custom fields: {}", custom_fields.join(", "));
    }
    if !attachments.is_empty() {
        println!("Attachments: {}", attachments.join(", "));
    }
}

fn cmd_show(
    vault: Option<&Path>,
    entry_path: &str,
    attrs: &[String],
    show_protected: bool,
    pw_stdin: bool,
) -> Result<()> {
    // Refuse protected --attr without --show-protected up front, in both modes.
    if let Some(p) = attrs.iter().find(|a| is_protected_field(a)) {
        if !show_protected {
            return Err(anyhow!(
                "attribute '{p}' is protected; pass --show-protected to print it"
            ));
        }
    }
    match vault {
        Some(path) => {
            let v = open_vault(path, pw_stdin)?;
            let id = v
                .find_by_title(entry_path)
                .ok_or_else(|| anyhow!("entry not found: {entry_path}"))?;
            if !attrs.is_empty() {
                for attr in attrs {
                    let value = v
                        .get_field(&id, attr)
                        .context("reading field")?
                        .ok_or_else(|| anyhow!("entry '{entry_path}' has no field '{attr}'"))?;
                    println!("{value}");
                }
                return Ok(());
            }
            let summary = v.get_entry(&id).expect("entry just resolved");
            let notes = v.get_field(&id, "Notes").ok().flatten();
            let password = if show_protected {
                v.get_field(&id, "Password").ok().flatten()
            } else {
                None
            };
            let custom = v.custom_field_names(&id).unwrap_or_default();
            print_show_summary(
                &summary.display_path(),
                &summary.title,
                summary.username.as_deref(),
                summary.url.as_deref(),
                notes.as_deref(),
                password.as_deref(),
                &custom,
                &summary.attachment_names,
            );
        }
        None => {
            if !attrs.is_empty() {
                // Raw values (possibly protected) — always code-gated.
                let code = require_session_code()?;
                for attr in attrs {
                    let resp = daemon_call(&daemon::Request::GetField {
                        path: entry_path.to_string(),
                        field: attr.clone(),
                        code: code.clone(),
                    })?;
                    let value = resp
                        .get("value")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow!("malformed daemon response: missing 'value'"))?;
                    println!("{value}");
                }
                return Ok(());
            }
            let resp = daemon_call(&daemon::Request::ShowEntry {
                path: entry_path.to_string(),
            })?;
            let entry = resp
                .get("entry")
                .ok_or_else(|| anyhow!("malformed daemon response: missing 'entry'"))?;
            let s = |k: &str| entry.get(k).and_then(Value::as_str).map(str::to_string);
            let list = |k: &str| -> Vec<String> {
                entry
                    .get(k)
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let title = s("title").unwrap_or_default();
            let group_path = list("group_path");
            let display = if group_path.is_empty() {
                title.clone()
            } else {
                format!("{}/{title}", group_path.join("/"))
            };
            // The summary RPC never carries protected values; fetch Password
            // separately (code-gated) only when asked to reveal it.
            let password = if show_protected {
                let code = require_session_code()?;
                let resp = daemon_call(&daemon::Request::GetField {
                    path: entry_path.to_string(),
                    field: "Password".to_string(),
                    code,
                })?;
                resp.get("value")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            } else {
                None
            };
            print_show_summary(
                &display,
                &title,
                s("username").as_deref(),
                s("url").as_deref(),
                s("notes").as_deref(),
                password.as_deref(),
                &list("custom_fields"),
                &list("attachments"),
            );
        }
    }
    Ok(())
}

fn cmd_search(vault: Option<&Path>, term: &str, pw_stdin: bool, json: bool) -> Result<()> {
    match vault {
        Some(path) => {
            let v = open_vault(path, pw_stdin)?;
            if json {
                let arr: Vec<Value> = v
                    .search_entries(term)
                    .iter()
                    .map(entry_summary_json)
                    .collect();
                println!("{}", serde_json::to_string_pretty(&arr)?);
                return Ok(());
            }
            for entry in v.search_entries(term) {
                print_list_row(
                    &entry.id.to_string(),
                    &entry.display_path(),
                    &entry.attachment_names,
                );
            }
        }
        None => {
            let resp = daemon_call(&daemon::Request::Search {
                term: term.to_string(),
            })?;
            let entries = resp
                .get("entries")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
                return Ok(());
            }
            print_entry_rows_from_json(&entries);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_edit(
    vault: Option<&Path>,
    entry_path: &str,
    title: Option<&str>,
    username: Option<&str>,
    url: Option<&str>,
    notes: Option<&str>,
    password_prompt: bool,
    set_args: &[String],
    unsets: &[String],
    pw_stdin: bool,
) -> Result<()> {
    let mut sets = std::collections::BTreeMap::new();
    for (flag, field) in [(username, "UserName"), (url, "URL"), (notes, "Notes")] {
        if let Some(value) = flag {
            sets.insert(field.to_string(), value.to_string());
        }
    }
    for kv in set_args {
        let (k, v) = parse_set_kv(kv)?;
        sets.insert(k, v);
    }
    if password_prompt {
        sets.insert(
            "Password".to_string(),
            prompt_entry_password().context("reading new password")?,
        );
    }
    if sets.is_empty() && unsets.is_empty() && title.is_none() {
        return Err(anyhow!(
            "nothing to change: pass --title/--username/--url/--notes, \
             --password-prompt, --set or --unset"
        ));
    }
    match vault {
        Some(path) => {
            let mut v = open_vault(path, pw_stdin)?;
            let id = v
                .find_by_title(entry_path)
                .ok_or_else(|| anyhow!("entry not found: {entry_path}"))?;
            for (field, value) in &sets {
                v.set_field(&id, field, value)
                    .with_context(|| format!("setting {field}"))?;
            }
            for field in unsets {
                v.remove_field(&id, field)
                    .with_context(|| format!("unsetting {field}"))?;
            }
            if let Some(new_title) = title {
                v.set_field(&id, "Title", new_title).context("renaming")?;
            }
            v.save().context("saving vault")?;
        }
        None => {
            let code = require_session_code()?;
            daemon_call(&daemon::Request::EditEntry {
                path: entry_path.to_string(),
                title: title.map(str::to_string),
                sets,
                unsets: unsets.to_vec(),
                code,
            })?;
        }
    }
    println!("updated '{entry_path}'");
    Ok(())
}

fn report_removal(what: &str, recycled: bool) {
    if recycled {
        println!("moved '{what}' to the recycle bin");
    } else {
        println!("permanently deleted '{what}'");
    }
}

fn cmd_rm(vault: Option<&Path>, entry_path: &str, permanent: bool, pw_stdin: bool) -> Result<()> {
    let recycled = match vault {
        Some(path) => {
            let mut v = open_vault(path, pw_stdin)?;
            let id = v
                .find_by_title(entry_path)
                .ok_or_else(|| anyhow!("entry not found: {entry_path}"))?;
            let recycled = v.recycle_entry(&id, permanent).context("removing entry")?;
            v.save().context("saving vault")?;
            recycled
        }
        None => {
            let code = require_session_code()?;
            let resp = daemon_call(&daemon::Request::RemoveEntry {
                path: entry_path.to_string(),
                permanent,
                code,
            })?;
            resp.get("recycled")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        }
    };
    report_removal(entry_path, recycled);
    Ok(())
}

fn cmd_mv(vault: Option<&Path>, entry_path: &str, group_path: &str, pw_stdin: bool) -> Result<()> {
    match vault {
        Some(path) => {
            let mut v = open_vault(path, pw_stdin)?;
            let id = v
                .find_by_title(entry_path)
                .ok_or_else(|| anyhow!("entry not found: {entry_path}"))?;
            v.move_entry(&id, group_path).context("moving entry")?;
            v.save().context("saving vault")?;
        }
        None => {
            let code = require_session_code()?;
            daemon_call(&daemon::Request::MoveEntry {
                path: entry_path.to_string(),
                group: group_path.to_string(),
                code,
            })?;
        }
    }
    println!("moved '{entry_path}' to '{group_path}'");
    Ok(())
}

fn cmd_mkdir(vault: Option<&Path>, group_path: &str, pw_stdin: bool) -> Result<()> {
    match vault {
        Some(path) => {
            let mut v = open_vault(path, pw_stdin)?;
            v.add_group(group_path).context("creating group")?;
            v.save().context("saving vault")?;
        }
        None => {
            let code = require_session_code()?;
            daemon_call(&daemon::Request::Mkdir {
                path: group_path.to_string(),
                code,
            })?;
        }
    }
    println!("created group '{group_path}'");
    Ok(())
}

fn cmd_rmdir(
    vault: Option<&Path>,
    group_path: &str,
    permanent: bool,
    recursive: bool,
    pw_stdin: bool,
) -> Result<()> {
    let recycled = match vault {
        Some(path) => {
            let mut v = open_vault(path, pw_stdin)?;
            let recycled = v
                .remove_group(group_path, permanent, recursive)
                .context("removing group")?;
            v.save().context("saving vault")?;
            recycled
        }
        None => {
            let code = require_session_code()?;
            let resp = daemon_call(&daemon::Request::Rmdir {
                path: group_path.to_string(),
                permanent,
                recursive,
                code,
            })?;
            resp.get("recycled")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        }
    };
    report_removal(group_path, recycled);
    Ok(())
}

/// `trove show <entry> --totp`: print the current code. Offline computes
/// in-process; daemon mode uses the code-gated `GetTotp` RPC, which returns
/// only the ephemeral code — the shared secret stays in the daemon.
fn cmd_show_totp(vault: Option<&Path>, entry_path: &str, pw_stdin: bool) -> Result<()> {
    match vault {
        Some(path) => {
            let v = open_vault(path, pw_stdin)?;
            let id = v
                .find_by_title(entry_path)
                .ok_or_else(|| anyhow!("entry not found: {entry_path}"))?;
            let totp = v.totp_now(&id).context("computing totp")?;
            println!("{}", totp.code);
            report_totp_window(totp.valid_for_secs);
        }
        None => {
            let code = require_session_code()?;
            let resp = daemon_call(&daemon::Request::GetTotp {
                path: entry_path.to_string(),
                code,
            })?;
            let totp_code = resp
                .get("totp_code")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("malformed daemon response: missing 'totp_code'"))?;
            println!("{totp_code}");
            if let Some(secs) = resp.get("valid_for_secs").and_then(Value::as_u64) {
                report_totp_window(secs);
            }
        }
    }
    Ok(())
}

/// On a TTY, note the remaining validity on stderr (stdout stays exactly the
/// code, so `trove show x --totp | pbcopy` works).
fn report_totp_window(valid_for_secs: u64) {
    use std::io::IsTerminal;
    if std::io::stderr().is_terminal() {
        eprintln!("(valid for {valid_for_secs}s)");
    }
}

/// `trove add totp`: build/validate the otpauth URI and store it.
#[allow(clippy::too_many_arguments)]
fn cmd_add_totp(
    vault: Option<&Path>,
    entry_path: &str,
    uri: Option<&str>,
    secret: Option<&str>,
    digits: u32,
    period: u32,
    algorithm: &str,
    pw_stdin: bool,
) -> Result<()> {
    let uri = match (uri, secret) {
        (Some(u), _) => u.to_string(),
        (None, Some(s)) => {
            let algo = algorithm.to_uppercase();
            if !["SHA1", "SHA256", "SHA512"].contains(&algo.as_str()) {
                return Err(anyhow!(
                    "unsupported --algorithm '{algorithm}' (SHA1, SHA256 or SHA512)"
                ));
            }
            // Base32 secrets are [A-Z2-7=]; strip the spaces sites add for
            // readability and normalize case before building the URI.
            let s: String = s
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_uppercase();
            let label = entry_path.rsplit('/').next().unwrap_or(entry_path);
            format!(
                "otpauth://totp/{label}?secret={s}&period={period}&digits={digits}&algorithm={algo}"
            )
        }
        (None, None) => unreachable!("clap requires --uri or --secret"),
    };
    match vault {
        Some(path) => {
            let mut v = open_vault(path, pw_stdin)?;
            let id = match v.find_by_title(entry_path) {
                Some(id) => id,
                None => v.add_entry(entry_path).context("creating entry")?,
            };
            v.set_totp_uri(&id, &uri).context("setting otp")?;
            v.save().context("saving vault")?;
        }
        None => {
            let code = require_session_code()?;
            daemon_call(&daemon::Request::AddTotp {
                path: entry_path.to_string(),
                uri,
                code,
            })?;
        }
    }
    println!("stored TOTP on '{entry_path}' — read codes with `trove show {entry_path} --totp`");
    Ok(())
}

/// `trove clip` — resolve the value (Password by default, `--attr`, or the
/// current TOTP code), copy it, and hand the guarded auto-clear to a
/// detached child so this process can exit immediately.
fn cmd_clip(
    vault: Option<&Path>,
    entry_path: &str,
    attr: Option<&str>,
    totp: bool,
    timeout: u64,
    pw_stdin: bool,
) -> Result<()> {
    let (value, label) = match vault {
        Some(path) => {
            let v = open_vault(path, pw_stdin)?;
            let id = v
                .find_by_title(entry_path)
                .ok_or_else(|| anyhow!("entry not found: {entry_path}"))?;
            if totp {
                (v.totp_now(&id).context("computing totp")?.code, "TOTP code")
            } else {
                let name = attr.unwrap_or("Password");
                let value = v
                    .get_field(&id, name)
                    .context("reading field")?
                    .ok_or_else(|| anyhow!("entry '{entry_path}' has no field '{name}'"))?;
                (
                    value,
                    if attr.is_none() {
                        "password"
                    } else {
                        "attribute"
                    },
                )
            }
        }
        None => {
            let code = require_session_code()?;
            if totp {
                let resp = daemon_call(&daemon::Request::GetTotp {
                    path: entry_path.to_string(),
                    code,
                })?;
                let c = resp
                    .get("totp_code")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("malformed daemon response: missing 'totp_code'"))?;
                (c.to_string(), "TOTP code")
            } else {
                let name = attr.unwrap_or("Password");
                let resp = daemon_call(&daemon::Request::GetField {
                    path: entry_path.to_string(),
                    field: name.to_string(),
                    code,
                })?;
                let v = resp
                    .get("value")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("malformed daemon response: missing 'value'"))?;
                (
                    v.to_string(),
                    if attr.is_none() {
                        "password"
                    } else {
                        "attribute"
                    },
                )
            }
        }
    };

    clip::copy(&value)?;
    if timeout > 0 {
        clip::spawn_clearer(timeout, &clip::value_hash(&value))?;
        println!("copied {label} from '{entry_path}' — clipboard clears in {timeout}s");
    } else {
        println!("copied {label} from '{entry_path}' (auto-clear disabled)");
    }
    Ok(())
}

/// `trove git-credential <op>` — a git credential helper over stdin/stdout.
fn cmd_git_credential(vault_path: &Path, operation: &str, pw_stdin: bool) -> Result<()> {
    let v = open_vault(vault_path, pw_stdin)?;
    // git's request block arrives AFTER the vault password when
    // --password-stdin is used; read_password_from_stdin already consumed
    // exactly one line, so the rest of stdin is git's protocol.
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    gitcred::run(&v, operation, &mut reader, &mut writer)
}

/// `trove resolve trove://…` — print one referenced secret to stdout.
fn cmd_resolve(vault_path: &Path, reference: &str, pw_stdin: bool) -> Result<()> {
    let v = open_vault(vault_path, pw_stdin)?;
    let value = v.resolve_ref(reference).context("resolving reference")?;
    println!("{value}");
    Ok(())
}

/// `trove exec <SCOPE> -- cmd…` — inject, run, wipe. The child's exit code
/// becomes ours (after cleanup), so pipelines and CI see the real result.
fn cmd_exec(
    vault_path: &Path,
    scope: &str,
    command: &[std::ffi::OsString],
    pw_stdin: bool,
) -> Result<()> {
    let v = open_vault(vault_path, pw_stdin)?;
    let tmp = exec::private_tmp_dir()?;
    // Resolve + run inside a closure so EVERY exit path below funnels
    // through the wipe. (SIGKILL can't be caught; SIGINT is handled by the
    // tokio ctrl_c guard which keeps us alive until the child dies.)
    let result = (|| -> Result<i32> {
        let injections = exec::resolve(&v, scope, &tmp)?;
        drop(v); // decrypted vault not needed while the child runs

        let (program, args) = command.split_first().expect("clap requires the command");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building tokio runtime")?;
        rt.block_on(async {
            let mut cmd = tokio::process::Command::new(program);
            cmd.args(args);
            for inj in &injections {
                cmd.env(&inj.name, &inj.value);
            }
            let mut child = cmd
                .spawn()
                .with_context(|| format!("spawning {}", std::path::Path::new(program).display()))?;
            loop {
                tokio::select! {
                    status = child.wait() => {
                        let status = status.context("waiting for child")?;
                        return Ok(status.code().unwrap_or(1));
                    }
                    // Ctrl-C reaches the child via the foreground process
                    // group; we just keep living until it exits so the wipe
                    // below still runs.
                    _ = tokio::signal::ctrl_c() => continue,
                }
            }
        })
    })();
    exec::wipe_dir(&tmp);
    let code = result?;
    if code != 0 {
        // Propagate the child's exit code faithfully (cleanup already done).
        std::process::exit(code);
    }
    Ok(())
}

/// `trove merge <SOURCE>` — KDBX-standard merge into `--vault`. Two secrets
/// arrive in order: target vault password, then source vault password.
fn cmd_merge(
    vault_path: &Path,
    source: &Path,
    source_key_file: Option<&Path>,
    pw_stdin: bool,
) -> Result<()> {
    let mut v = open_vault(vault_path, pw_stdin)?;
    let source_password = if pw_stdin {
        read_password_from_stdin().context("reading SOURCE vault password from stdin (line 2)")?
    } else {
        rpassword::prompt_password("Source vault password: ")
            .context("reading source vault password")?
    };
    let source_keyfile = match source_key_file {
        Some(p) => Some(
            std::fs::read(p).with_context(|| format!("reading source key file {}", p.display()))?,
        ),
        None => None,
    };
    let s = v
        .merge_from(source, &source_password, source_keyfile.as_deref())
        .context("merging")?;
    println!(
        "merged {}: {} created, {} updated, {} relocated, {} deleted",
        source.display(),
        s.created,
        s.updated,
        s.relocated,
        s.deleted
    );
    Ok(())
}

/// `trove export` — decrypted XML or KeePassXC-convention CSV on stdout.
fn cmd_export(vault_path: &Path, format: ExportFormat, pw_stdin: bool) -> Result<()> {
    let v = open_vault(vault_path, pw_stdin)?;
    match format {
        ExportFormat::Xml => {
            let xml = xml_export::export_xml(&v).context("exporting xml")?;
            print!("{xml}");
        }
        ExportFormat::Csv => {
            // KeePassXC's `export -f csv` column set, quoted the same way.
            println!(
                "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\""
            );
            let q = |s: &str| s.replace('"', "\"\"");
            for e in v.list_entries() {
                let field =
                    |name: &str| v.get_field(&e.id, name).ok().flatten().unwrap_or_default();
                // KeePassXC prefixes the root group name; ours is "Root".
                let group = if e.group_path.is_empty() {
                    "Root".to_string()
                } else {
                    format!("Root/{}", e.group_path.join("/"))
                };
                // Icon, Last Modified and Created are constant columns here
                // (trove doesn't map icons; timestamps stay internal).
                println!(
                    "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"0\",\"\",\"\"",
                    q(&group),
                    q(&e.title),
                    q(&field("UserName")),
                    q(&field("Password")),
                    q(&field("URL")),
                    q(&field("Notes")),
                    q(&field("otp")),
                );
            }
        }
    }
    Ok(())
}

/// `trove db-edit` — rekey and/or retune the KDF. At least one change is
/// required. Password changes read the NEW password as stdin line 2 (or a
/// confirmed prompt).
#[allow(clippy::too_many_arguments)]
fn cmd_db_edit(
    vault_path: &Path,
    set_password: bool,
    set_key_file: Option<&Path>,
    unset_key_file: bool,
    kdf_memory: Option<u64>,
    kdf_iterations: Option<u64>,
    kdf_parallelism: Option<u32>,
    pw_stdin: bool,
) -> Result<()> {
    let any_kdf = kdf_memory.is_some() || kdf_iterations.is_some() || kdf_parallelism.is_some();
    let any_key = set_password || set_key_file.is_some() || unset_key_file;
    if !any_kdf && !any_key {
        return Err(anyhow!(
            "nothing to change: pass --set-password, --set-key-file, --unset-key-file, \
             or a --kdf-* option"
        ));
    }
    let mut v = open_vault(vault_path, pw_stdin)?;

    if any_key {
        let new_password = if set_password {
            if pw_stdin {
                read_password_from_stdin().context("reading NEW password from stdin (line 2)")?
            } else {
                prompt_new_password().context("reading new password")?
            }
        } else {
            // Keeping the password: reuse the one that just opened the vault.
            // rekey() needs it verbatim; prompting again would be hostile.
            v.current_password().to_string()
        };
        let new_keyfile = if unset_key_file {
            None
        } else if let Some(p) = set_key_file {
            Some(std::fs::read(p).with_context(|| format!("reading key file {}", p.display()))?)
        } else {
            v.current_keyfile().map(<[u8]>::to_vec)
        };
        v.rekey(&new_password, new_keyfile.as_deref())
            .context("rekeying")?;
        println!("credentials updated");
    }

    if any_kdf {
        v.set_argon2_params(
            kdf_memory.map(|m| m * 1024),
            kdf_iterations,
            kdf_parallelism,
        )
        .context("retuning KDF")?;
        println!("KDF updated");
    }
    Ok(())
}

/// `trove db-info` — non-secret database facts.
fn cmd_db_info(vault_path: &Path, pw_stdin: bool, json: bool) -> Result<()> {
    let v = open_vault(vault_path, pw_stdin)?;
    let i = v.db_info();
    if json {
        let obj = serde_json::json!({
            "path": vault_path.display().to_string(),
            "version": i.version,
            "cipher": i.cipher,
            "compression": i.compression,
            "kdf": i.kdf,
            "entries": i.entries,
            "groups": i.groups,
            "recycle_bin": i.recycle_bin,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
        return Ok(());
    }
    println!("Path:        {}", vault_path.display());
    println!("Version:     {}", i.version);
    println!("Cipher:      {}", i.cipher);
    println!("Compression: {}", i.compression);
    println!("KDF:         {}", i.kdf);
    println!("Entries:     {}", i.entries);
    println!("Groups:      {}", i.groups);
    println!("Recycle bin: {}", if i.recycle_bin { "yes" } else { "no" });
    Ok(())
}

/// `trove estimate` — zxcvbn strength rating. Stdin (one line) when no
/// argument; the report goes to stdout, never echoing the password back.
fn cmd_estimate(password: Option<&str>) -> Result<()> {
    let owned;
    let password = match password {
        Some(p) => p,
        None => {
            owned = read_password_from_stdin().context("reading password from stdin")?;
            &owned
        }
    };
    let e = zxcvbn::zxcvbn(password, &[]);
    let guesses = e.guesses();
    println!("Length:      {}", password.chars().count());
    println!("Entropy:     {:.1} bits", (guesses as f64).log2());
    println!("Score:       {}/4", u8::from(e.score()));
    if let Some(fb) = e.feedback() {
        if let Some(w) = fb.warning() {
            println!("Warning:     {w}");
        }
        for s in fb.suggestions() {
            println!("Suggestion:  {s}");
        }
    }
    Ok(())
}

/// `trove analyze --hibp <FILE>` — offline breach check of every password in
/// the vault. Prints one line per breached entry (path + count); exits 0 with
/// "no breached passwords" when clean. Exit 1 when breaches were found, so
/// scripts and CI can gate on it.
fn cmd_analyze(vault_path: &Path, hibp_file: &Path, pw_stdin: bool) -> Result<()> {
    if !hibp_file.exists() {
        return Err(anyhow!("HIBP file not found: {}", hibp_file.display()));
    }
    let v = open_vault(vault_path, pw_stdin)?;
    let mut breached = 0usize;
    let mut checked = 0usize;
    for entry in v.list_entries() {
        let Some(pw) = v.get_field(&entry.id, "Password").ok().flatten() else {
            continue;
        };
        if pw.is_empty() {
            continue;
        }
        checked += 1;
        let hash = hibp::sha1_hex_upper(&pw);
        if let Some(count) = hibp::lookup(hibp_file, &hash)? {
            breached += 1;
            println!("{}  seen {count} times in breaches", entry.display_path());
        }
    }
    eprintln!("checked {checked} passwords, {breached} breached");
    if breached > 0 {
        // Same DaemonClassified channel the daemon paths use: user-level
        // failure, exit 1 — CI can gate on `trove analyze`.
        return Err(DaemonClassified {
            message: format!("{breached} breached password(s) found"),
            exit: EXIT_USER_ERROR,
        }
        .into());
    }
    println!("no breached passwords");
    Ok(())
}

/// `trove materialize` — open vault, run the materialize plan in-process,
/// hold open until SIGINT, then wipe.
///
/// We deliberately do NOT touch the daemon's MaterializedStore here; this is
/// a standalone command meant for testing and disconnected use. If you have
/// the daemon running, use `troved unlock` instead so SSH/GPG agents work too.
fn cmd_materialize(vault_path: &Path, pw_stdin: bool) -> Result<()> {
    let vault = open_vault(vault_path, pw_stdin)?;
    let (plans, errors) = troved::materialize::build_plans(&vault);
    for (title, e) in &errors {
        eprintln!("skip '{title}': {e}");
    }
    if plans.is_empty() {
        println!("no entries opted in to materialization");
        return Ok(());
    }

    // Spin up a tokio runtime for the TTL tasks and the SIGINT handler.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    rt.block_on(async {
        // Local store, not shared with any daemon.
        let store: troved::materialize::MaterializedStore =
            std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new()));
        let mut materialised_count = 0usize;
        for plan in &plans {
            match troved::materialize::materialize_one(&vault, plan, store.clone()) {
                Ok(m) => {
                    println!(
                        "materialized '{}' -> {} (mode {:o}{}{})",
                        plan.entry_title,
                        plan.resolved_target.display(),
                        plan.mode,
                        if let Some(t) = plan.ttl {
                            format!(", ttl {}s", t.as_secs())
                        } else {
                            String::new()
                        },
                        if !plan.allow_disk_backed {
                            ""
                        } else {
                            ", disk-backed allowed"
                        },
                    );
                    let mut g = store.write().await;
                    g.push(m);
                    materialised_count += 1;
                }
                Err(e) => {
                    eprintln!("failed '{}': {}", plan.entry_title, e);
                }
            }
        }
        if materialised_count == 0 {
            return Ok::<(), anyhow::Error>(());
        }
        println!("{materialised_count} file(s) materialized. Press Ctrl-C to wipe and exit.");

        // Wait for SIGINT (or SIGTERM). The wipe runs synchronously before
        // we return so the user sees "wiped" before the shell prompt comes
        // back. If the user sends SIGKILL, the OS will reap us and the files
        // will linger — that's the irreducible price of `kill -9` and we
        // can't help it.
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigint = signal(SignalKind::interrupt())
                .map_err(|e| anyhow!("install SIGINT handler: {e}"))?;
            let mut sigterm = signal(SignalKind::terminate())
                .map_err(|e| anyhow!("install SIGTERM handler: {e}"))?;
            tokio::select! {
                _ = sigint.recv() => {}
                _ = sigterm.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            // Windows: Ctrl-C is the portable wipe trigger tokio exposes.
            tokio::signal::ctrl_c()
                .await
                .map_err(|e| anyhow!("install Ctrl-C handler: {e}"))?;
        }
        println!("\nwiping materialized files...");
        troved::materialize::wipe_all(&store).await;
        println!("done.");
        Ok(())
    })
}

/// Sentinel error returned by the daemon-aware commands. Carries an
/// already-classified exit code so `classify_exit` can short-circuit the
/// usual `CoreError` walk. We use this for cases where the error originated
/// from the daemon (a string we can only parse heuristically) rather than
/// from trove-core (where rich types are available).
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
struct DaemonClassified {
    message: String,
    exit: u8,
}

/// `trove unlock <vault>` — send `unlock` to the daemon. Prompts for password
/// (or reads stdin) before calling out, so we fail fast on a typo.
fn cmd_unlock(
    vault: &Path,
    timeout: Option<u64>,
    export: bool,
    shell: bool,
    pw_stdin: bool,
) -> Result<()> {
    if !vault.exists() {
        return Err(DaemonClassified {
            message: format!("vault file not found: {}", vault.display()),
            exit: EXIT_USER_ERROR,
        }
        .into());
    }
    // The daemon runs in its own working directory, so a relative path would be
    // resolved against *its* cwd, not the user's — and fail to open. Resolve to
    // an absolute path here, against the user's cwd (the existence check above
    // guarantees canonicalize succeeds), so the daemon opens the file the user
    // actually named.
    let vault_abs = std::fs::canonicalize(vault)
        .with_context(|| format!("resolving vault path: {}", vault.display()))?;
    let vault_str = vault_abs
        .to_str()
        .ok_or_else(|| anyhow!("vault path is not valid utf-8"))?
        .to_string();
    let password = if pw_stdin {
        read_password_from_stdin().context("reading vault password from stdin")?
    } else {
        rpassword::prompt_password("Vault password: ").context("reading vault password")?
    };

    let req = daemon::Request::Unlock {
        path: vault_str,
        password,
        timeout,
        keyfile: global_keyfile().map(|bytes| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(bytes)
        }),
    };
    let (resp, autospawned) = match daemon::send_autospawn_reporting(&req) {
        Ok(v) => v,
        Err(e) if daemon::is_daemon_not_running(&e) => {
            return Err(DaemonClassified {
                message: e.to_string(),
                exit: EXIT_USER_ERROR,
            }
            .into());
        }
        Err(e) => return Err(e),
    };

    if let Some(msg) = daemon::response_error(&resp) {
        // Heuristic: anything that mentions "password" or "kdbx" is a vault
        // error (exit 2); everything else is a user error (exit 1). This
        // matches the existing `classify_exit` mapping for trove-core errors.
        let exit = if looks_like_vault_error(&msg) {
            EXIT_VAULT_ERROR
        } else {
            EXIT_USER_ERROR
        };
        return Err(DaemonClassified { message: msg, exit }.into());
    }

    // The daemon minted a one-time session code for this unlock. Code-gated
    // `add`/`get` read it back from $TROVE_SESSION. See docs/provisioning-sessions.md.
    let code = resp
        .get("code")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("daemon unlocked but returned no session code"))?;

    // Diagnostic banner on stderr (never the `export …` stdout that
    // `eval "$(…)"` consumes): the CLI + daemon build versions and how the
    // daemon came to be. Rarely needed, but decisive when a stale binary is in
    // play — e.g. a daemon still running pre-rebuild code after a `cargo build`.
    let spawn_state = if autospawned {
        "spawned now"
    } else {
        "already running"
    };
    let cli_version = daemon::cli_version();
    match resp.get("daemon_version").and_then(Value::as_str) {
        Some(daemon_version) => {
            eprintln!("trove: cli {cli_version} · daemon {daemon_version} ({spawn_state})");
            // Beyond the informational banner, flag a genuine drift explicitly:
            // the daemon we're now driving is a different build than this CLI
            // (e.g. a stale sibling troved left by a CLI-only rebuild).
            daemon::warn_on_version_mismatch(daemon_version);
        }
        // No version field ⇒ the daemon was built before version reporting, so
        // it's older than this CLI and running stale code. That's exactly the
        // case worth flagging — spell it out and say how to fix it, rather than
        // the ambiguous bare "unknown".
        None => {
            eprintln!(
                "trove: cli {cli_version} · daemon ({spawn_state}) is an older build that \
                 predates version reporting — it's running stale code. Restart it to load the \
                 current binary: kill troved, then re-unlock."
            );
        }
    }

    // Two delivery modes, so the operator never has to type `eval`:
    //   * subshell — set $TROVE_SESSION and exec the operator's own $SHELL, so
    //     they land in a session shell where `add`/`get` work immediately. The
    //     code is passed only through the child's environment — never written
    //     to disk — so barrier #3 (docs/provisioning-sessions.md) is preserved:
    //     it lives in process env, just the subshell's.
    //   * export — print `export TROVE_SESSION=…` on stdout for `eval "$(…)"`.
    // Pick by context: an interactive terminal → subshell; piped stdout (an
    // `eval "$(…)"` or a script) → export, so those keep working unchanged.
    // `--shell` / `--export` force a mode.
    let spawn_shell = shell || (!export && std::io::stdout().is_terminal());
    if spawn_shell {
        eprintln!(
            "trove: unlocked {} · session active in this shell — run add/get here, `exit` to end",
            vault.display()
        );
        return exec_session_shell(code);
    }
    println!("export TROVE_SESSION={code}");
    eprintln!(
        "trove: unlocked {} · session code exported to $TROVE_SESSION",
        vault.display()
    );
    Ok(())
}

/// Launch the operator's own shell with `TROVE_SESSION` set, so they land in a
/// subshell where the session code is live and `add`/`get` work with no `eval`.
/// On Unix we `exec` (replace this process) so no stray `trove` lingers; on
/// other platforms we spawn and wait, forwarding the shell's exit status. The
/// code is passed only via the child's environment — never written to disk.
fn exec_session_shell(code: &str) -> Result<()> {
    // The user's login shell (zsh, bash, fish, …); fall back to /bin/sh.
    let shell = std::env::var_os("SHELL").unwrap_or_else(|| std::ffi::OsString::from("/bin/sh"));
    let mut cmd = std::process::Command::new(&shell);
    cmd.env("TROVE_SESSION", code);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // `exec` returns only if it failed to replace this process.
        let err = cmd.exec();
        Err(anyhow!(
            "starting session shell {}: {err}",
            shell.to_string_lossy()
        ))
    }
    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .with_context(|| format!("starting session shell {}", shell.to_string_lossy()))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Heuristic mapping from a daemon-reported error string to vault-error
/// status. Anything mentioning "password" or "kdbx" is treated as a vault
/// error; anything else is a user error.
fn looks_like_vault_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("password") || lower.contains("kdbx") || lower.contains("decrypt")
}

/// `trove lock` — send `lock` to the daemon. Idempotent on the daemon side;
/// we treat its response as the source of truth.
fn cmd_lock() -> Result<()> {
    let resp = match daemon::send_autospawn(&daemon::Request::Lock) {
        Ok(v) => v,
        Err(e) if daemon::is_daemon_not_running(&e) => {
            return Err(DaemonClassified {
                message: e.to_string(),
                exit: EXIT_USER_ERROR,
            }
            .into());
        }
        Err(e) => return Err(e),
    };
    if let Some(msg) = daemon::response_error(&resp) {
        return Err(DaemonClassified {
            message: msg,
            exit: EXIT_USER_ERROR,
        }
        .into());
    }
    println!("vault locked");
    Ok(())
}

/// `trove status` — pretty-print the daemon's `Status` response.
fn cmd_status() -> Result<()> {
    // `status` never autospawns. The daemon runs only while a vault is unlocked
    // (or materialized files still need cleanup), so "no daemon" is itself the
    // answer: nothing is unlocked. A live daemon gives the real state; otherwise
    // we print the empty/locked default rather than starting one just to say so.
    match daemon::send(&daemon::Request::Status) {
        Ok(resp) => {
            if let Some(msg) = daemon::response_error(&resp) {
                return Err(DaemonClassified {
                    message: msg,
                    exit: EXIT_USER_ERROR,
                }
                .into());
            }
            println!("Daemon:          running");
            print_status(&resp);
            // Diagnostic command — a natural place to surface CLI↔daemon drift
            // (a stale sibling troved speaking a slightly different protocol).
            daemon::check_running_daemon_version();
        }
        Err(e) if daemon::is_daemon_not_running(&e) => {
            println!("Daemon:          not running (nothing unlocked)");
            println!("Vault:           no vault unlocked");
            println!("SSH keys:        0 loaded");
            println!("GPG keys:        0 loaded");
            println!("Materialized:    0 files");
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

fn print_status(resp: &Value) {
    // Vault path. `null` -> "no vault unlocked".
    let vault_line = match resp.get("vault_path") {
        Some(v) if v.is_null() => "no vault unlocked".to_string(),
        Some(v) => v.as_str().unwrap_or("(unparseable vault_path)").to_string(),
        None => "no vault unlocked".to_string(),
    };
    println!("Vault:           {vault_line}");

    let idle_secs = resp.get("idle_timeout_secs").and_then(Value::as_u64);
    let idle_line = match idle_secs {
        Some(0) => "disabled".to_string(),
        Some(n) => format_seconds(n),
        None => "(unknown)".to_string(),
    };
    println!("Idle timeout:    {idle_line}");

    if let Some(remaining) = resp.get("idle_remaining_secs").and_then(Value::as_u64) {
        println!("Idle remaining:  {}", format_seconds(remaining));
    }

    let ssh = resp.get("ssh_keys").and_then(Value::as_u64).unwrap_or(0);
    let gpg = resp.get("gpg_keys").and_then(Value::as_u64).unwrap_or(0);
    let mat = resp
        .get("materialized")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    println!("SSH keys:        {ssh} loaded");
    println!("GPG keys:        {gpg} loaded");
    println!("Materialized:    {mat} files");
}

/// Render a second count as `<n>s` with a humanized suffix in brackets for
/// anything ≥ 1 minute: `65s (1m 05s)`, `3725s (1h 02m 05s)`. Sub-minute
/// values get just the raw seconds — the bracket would be redundant.
fn format_seconds(secs: u64) -> String {
    match humanize_seconds(secs) {
        Some(h) => format!("{secs}s ({h})"),
        None => format!("{secs}s"),
    }
}

fn humanize_seconds(secs: u64) -> Option<String> {
    if secs < 60 {
        return None;
    }
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    Some(if h > 0 {
        format!("{h}h {m:02}m {s:02}s")
    } else {
        format!("{m}m {s:02}s")
    })
}

/// `trove idle set <seconds>`.
fn cmd_idle_set(seconds: u64) -> Result<()> {
    let resp = match daemon::send_autospawn(&daemon::Request::SetIdleTimeout { seconds }) {
        Ok(v) => v,
        Err(e) if daemon::is_daemon_not_running(&e) => {
            return Err(DaemonClassified {
                message: e.to_string(),
                exit: EXIT_USER_ERROR,
            }
            .into());
        }
        Err(e) => return Err(e),
    };
    if let Some(msg) = daemon::response_error(&resp) {
        return Err(DaemonClassified {
            message: msg,
            exit: EXIT_USER_ERROR,
        }
        .into());
    }
    if seconds == 0 {
        println!("idle timeout: disabled");
    } else {
        println!("idle timeout: {seconds}s");
    }
    Ok(())
}

/// `trove idle get`. Pretty-prints the current state.
fn cmd_idle_get() -> Result<()> {
    let resp = match daemon::send_autospawn(&daemon::Request::GetIdleTimeout) {
        Ok(v) => v,
        Err(e) if daemon::is_daemon_not_running(&e) => {
            return Err(DaemonClassified {
                message: e.to_string(),
                exit: EXIT_USER_ERROR,
            }
            .into());
        }
        Err(e) => return Err(e),
    };
    if let Some(msg) = daemon::response_error(&resp) {
        return Err(DaemonClassified {
            message: msg,
            exit: EXIT_USER_ERROR,
        }
        .into());
    }
    let secs = resp.get("seconds").and_then(Value::as_u64).unwrap_or(0);
    let remaining = resp.get("remaining").and_then(Value::as_u64);
    if secs == 0 {
        println!("disabled");
    } else if let Some(r) = remaining {
        println!("{secs}s (remaining: {r}s)");
    } else {
        println!("{secs}s (vault locked)");
    }
    Ok(())
}

/// `trove materialize-status` — list of active materializations, one per line.
fn cmd_materialize_status() -> Result<()> {
    let resp = match daemon::send_autospawn(&daemon::Request::MaterializeStatus) {
        Ok(v) => v,
        Err(e) if daemon::is_daemon_not_running(&e) => {
            return Err(DaemonClassified {
                message: e.to_string(),
                exit: EXIT_USER_ERROR,
            }
            .into());
        }
        Err(e) => return Err(e),
    };
    if let Some(msg) = daemon::response_error(&resp) {
        return Err(DaemonClassified {
            message: msg,
            exit: EXIT_USER_ERROR,
        }
        .into());
    }
    let arr = resp
        .get("materialized")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if arr.is_empty() {
        println!("(no active materializations)");
        return Ok(());
    }
    for entry in arr {
        let title = entry.get("title").and_then(Value::as_str).unwrap_or("?");
        let target = entry
            .get("target_path")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let exists = entry
            .get("exists")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let ttl_str = match entry.get("ttl_remaining_seconds") {
            Some(v) if v.is_null() => "none".to_string(),
            Some(v) => v
                .as_u64()
                .map(|n| format!("{n}s"))
                .unwrap_or_else(|| "?".to_string()),
            None => "none".to_string(),
        };
        println!("{title}  {target}  ttl={ttl_str}  exists={exists}");
    }
    Ok(())
}

/// Map an error chain to one of our documented exit codes.
fn classify_exit(err: &anyhow::Error) -> u8 {
    for cause in err.chain() {
        if let Some(d) = cause.downcast_ref::<DaemonClassified>() {
            return d.exit;
        }
        if let Some(core) = cause.downcast_ref::<CoreError>() {
            return match core {
                CoreError::BadPassword | CoreError::Kdbx(_) => EXIT_VAULT_ERROR,
                CoreError::AlreadyExists(_)
                | CoreError::NotFound(_)
                | CoreError::EntryNotFound(_)
                | CoreError::InvalidPath(_)
                | CoreError::GroupNotFound(_)
                | CoreError::GroupExists(_)
                | CoreError::GroupNotEmpty(_)
                | CoreError::NoTotp(_)
                | CoreError::Totp(_)
                | CoreError::Io(_) => EXIT_USER_ERROR,
            };
        }
    }
    EXIT_USER_ERROR
}

#[cfg(test)]
mod format_tests {
    use super::*;

    #[test]
    fn format_seconds_renders_durations() {
        assert_eq!(format_seconds(0), "0s");
        assert_eq!(format_seconds(5), "5s");
        assert_eq!(format_seconds(59), "59s");
        assert_eq!(format_seconds(60), "60s (1m 00s)");
        assert_eq!(format_seconds(65), "65s (1m 05s)");
        assert_eq!(format_seconds(3600), "3600s (1h 00m 00s)");
        assert_eq!(format_seconds(3725), "3725s (1h 02m 05s)");
        assert_eq!(format_seconds(46566), "46566s (12h 56m 06s)");
    }
}

#[cfg(test)]
mod completions_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Unique temp path per call; no `tempfile` dep, no clock/RNG.
    fn temp_rc() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "trove-rc-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn upsert_appends_then_replaces_in_place() {
        let rc = temp_rc();
        std::fs::write(&rc, "# existing config\nalias x=y\n").unwrap();

        // First upsert appends a single managed block, preserving prior config.
        assert!(upsert_rc_block(&rc, "source \"/a/_trove\"").unwrap());
        let first = std::fs::read_to_string(&rc).unwrap();
        assert!(first.contains("# existing config"));
        assert_eq!(first.matches(RC_BEGIN).count(), 1);
        assert_eq!(first.matches(RC_END).count(), 1);
        assert!(first.contains("source \"/a/_trove\""));

        // Identical re-run is a no-op (idempotent).
        assert!(!upsert_rc_block(&rc, "source \"/a/_trove\"").unwrap());
        assert_eq!(std::fs::read_to_string(&rc).unwrap(), first);

        // A changed body replaces the block in place — no duplicate markers,
        // old contents gone, surrounding config untouched.
        assert!(upsert_rc_block(&rc, "source \"/b/_trove\"").unwrap());
        let second = std::fs::read_to_string(&rc).unwrap();
        assert_eq!(second.matches(RC_BEGIN).count(), 1);
        assert!(second.contains("source \"/b/_trove\""));
        assert!(!second.contains("/a/_trove"));
        assert!(second.contains("# existing config"));

        let _ = std::fs::remove_file(&rc);
    }

    #[test]
    fn upsert_creates_file_when_missing() {
        let rc = temp_rc();
        assert!(upsert_rc_block(&rc, "source \"/x\"").unwrap());
        let s = std::fs::read_to_string(&rc).unwrap();
        assert!(s.starts_with(RC_BEGIN));
        assert!(s.contains("source \"/x\""));
        let _ = std::fs::remove_file(&rc);
    }
}

#[cfg(test)]
mod classify_tests {
    use super::*;

    /// The heuristic that decides whether a daemon-reported error string maps
    /// to exit 2 (vault error) vs exit 1 (user error). Must be case-insensitive
    /// and key only off the password/kdbx/decrypt vocabulary.
    #[test]
    fn looks_like_vault_error_matches_vault_vocabulary() {
        assert!(looks_like_vault_error(
            "invalid password or corrupted vault"
        ));
        assert!(looks_like_vault_error("kdbx error: bad header id"));
        assert!(looks_like_vault_error("failed to decrypt inner stream"));
        // Case-insensitive.
        assert!(looks_like_vault_error("PASSWORD incorrect"));
        assert!(looks_like_vault_error("KDBX corrupt"));

        // Non-vault daemon errors stay user-level.
        assert!(!looks_like_vault_error("no vault unlocked"));
        assert!(!looks_like_vault_error("vault file not found: /x"));
        assert!(!looks_like_vault_error(""));
    }

    #[test]
    fn classify_exit_maps_daemon_classified_verbatim() {
        let vault: anyhow::Error = DaemonClassified {
            message: "bad password".into(),
            exit: EXIT_VAULT_ERROR,
        }
        .into();
        assert_eq!(classify_exit(&vault), EXIT_VAULT_ERROR);

        let user: anyhow::Error = DaemonClassified {
            message: "no vault unlocked".into(),
            exit: EXIT_USER_ERROR,
        }
        .into();
        assert_eq!(classify_exit(&user), EXIT_USER_ERROR);
    }

    #[test]
    fn classify_exit_maps_core_errors() {
        // Vault-level (exit 2).
        assert_eq!(
            classify_exit(&CoreError::BadPassword.into()),
            EXIT_VAULT_ERROR
        );
        assert_eq!(
            classify_exit(&CoreError::Kdbx("bad block".into()).into()),
            EXIT_VAULT_ERROR
        );

        // User-level (exit 1).
        assert_eq!(
            classify_exit(&CoreError::NotFound(PathBuf::from("/x.kdbx")).into()),
            EXIT_USER_ERROR
        );
        assert_eq!(
            classify_exit(&CoreError::EntryNotFound("github".into()).into()),
            EXIT_USER_ERROR
        );
        assert_eq!(
            classify_exit(&CoreError::AlreadyExists(PathBuf::from("/x")).into()),
            EXIT_USER_ERROR
        );
        assert_eq!(
            classify_exit(&CoreError::InvalidPath("a//b".into()).into()),
            EXIT_USER_ERROR
        );
        let io: anyhow::Error = CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "x",
        ))
        .into();
        assert_eq!(classify_exit(&io), EXIT_USER_ERROR);
    }

    /// `classify_exit` walks the whole error chain, so a `CoreError` buried
    /// under `.context(...)` still maps correctly (the real code path: every
    /// command wraps core errors in context strings).
    #[test]
    fn classify_exit_walks_context_chain() {
        let wrapped = anyhow::Error::new(CoreError::BadPassword)
            .context("opening vault /home/x.kdbx")
            .context("running unlock");
        assert_eq!(classify_exit(&wrapped), EXIT_VAULT_ERROR);
    }

    /// Anything we don't recognise defaults to the user-error exit code.
    #[test]
    fn classify_exit_defaults_to_user_error() {
        assert_eq!(classify_exit(&anyhow!("totally unknown")), EXIT_USER_ERROR);
    }
}
