//! `sdpm` — command-line client for SuperDuperPasswordManager.
//!
//! v0.0.1 surface: `init`, `list`, `add ssh`, `get ssh`. Master key only;
//! no keyfiles, no env-var passwords.

#![forbid(unsafe_code)]

mod daemon;

use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use sdpm_core::{EntryId, Error as CoreError, Vault};
use serde_json::Value;

/// Exit code for user-recoverable errors (bad path, missing entry, etc.).
const EXIT_USER_ERROR: u8 = 1;
/// Exit code for vault-level errors (bad password, corrupt kdbx).
const EXIT_VAULT_ERROR: u8 = 2;

/// Attachment slot used for SSH private keys. Kept short and conventional.
const SSH_KEY_ATTACHMENT: &str = "id";

/// Attachment slot used for GPG secret-key exports. Matches what
/// `sdpmd::handler::load_gpg_keys_from_vault` looks for.
const GPG_KEY_ATTACHMENT: &str = "gpg-priv";

#[derive(Debug, Parser)]
#[command(
    name = "sdpm",
    version,
    about = "SuperDuperPasswordManager — KeePassXC-compatible CLI",
    propagate_version = true
)]
struct Cli {
    /// Read the vault password from stdin (one line) instead of prompting.
    /// For `init`, the single line is used as the password without a confirm step.
    /// Intended for scripts and CI; do not use in shells where stdin may be logged.
    #[arg(long = "password-stdin", global = true)]
    password_stdin: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new empty vault.
    Init {
        /// Path to the new .kdbx file. Must not exist.
        vault: PathBuf,
    },

    /// List entries in a vault, one per line.
    List {
        /// Path to an existing .kdbx file.
        vault: PathBuf,
    },

    /// Add a resource (SSH key, password, ...) to a vault.
    Add {
        #[command(subcommand)]
        resource: AddResource,
    },

    /// Retrieve a resource from a vault.
    Get {
        #[command(subcommand)]
        resource: GetResource,
    },

    /// SSH agent helper subcommands.
    Agent {
        #[command(subcommand)]
        op: AgentOp,
    },

    /// GPG agent helper subcommands (v0.0.3.0).
    GpgAgent {
        #[command(subcommand)]
        op: GpgAgentOp,
    },

    /// Materialize all opted-in entries in the vault to disk in-process,
    /// without going through the daemon. Useful for testing and for
    /// disconnected workflows. Wipes everything on Ctrl-C / SIGINT.
    Materialize {
        /// Path to the .kdbx vault.
        vault: PathBuf,
    },

    /// Tell the running `sdpmd` to unlock a vault. The keys + materialize
    /// plan land in daemon memory; SSH and GPG agents serve them.
    ///
    /// Prompts for the master password unless `--password-stdin` is set.
    /// The password never lands on the command line.
    Unlock {
        /// Path to the .kdbx vault.
        vault: PathBuf,
    },

    /// Tell the running `sdpmd` to lock the vault: wipe materialized files,
    /// drop SSH+GPG keys, drop the vault. Idempotent.
    Lock,

    /// Print a human-readable summary of the running `sdpmd`'s state:
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
    /// Print the path to the sdpmd GPG agent socket.
    ///
    /// Resolution order matches `sdpmd`:
    /// 1. `SDPM_GPG_SOCK` env var (override).
    /// 2. `$XDG_RUNTIME_DIR/sdpm-gpg.sock`.
    /// 3. `${TMPDIR:-/tmp}/sdpm-gpg-$UID.sock`.
    ///
    /// Typical usage (gpg 2.x speaks Assuan over a fixed path; bind-mount or
    /// symlink the standard location at `~/.gnupg/S.gpg-agent` to ours):
    ///   `ln -sf "$(sdpm gpg-agent socket)" ~/.gnupg/S.gpg-agent`.
    Socket,
}

#[derive(Debug, Subcommand)]
enum AgentOp {
    /// Print the path to the sdpmd SSH agent socket.
    ///
    /// Resolution order matches `sdpmd`:
    /// 1. `SDPM_SSH_SOCK` env var (override).
    /// 2. `$XDG_RUNTIME_DIR/sdpm-ssh.sock`.
    /// 3. `${TMPDIR:-/tmp}/sdpm-ssh-$UID.sock`.
    ///
    /// Typical usage: `export SSH_AUTH_SOCK="$(sdpm agent socket)"`.
    Socket,
}

#[derive(Debug, Subcommand)]
enum AddResource {
    /// Store an SSH private key in the vault.
    ///
    /// If an entry with the given title already exists, its `id` attachment is
    /// replaced in place. Otherwise a fresh entry is created at the root group.
    Ssh {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Entry title (e.g. "github.com").
        title: String,
        /// Path to the SSH private key file (e.g. ~/.ssh/id_ed25519).
        #[arg(long = "key")]
        key: PathBuf,
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
    /// vault unlock, sdpmd parses each `gpg-priv` attachment and registers
    /// every ed25519 secret key it finds with the GPG agent listener.
    Gpg {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Entry title (e.g. "git-signing").
        title: String,
        /// Path to the binary GPG secret-key export.
        #[arg(long = "key")]
        key: PathBuf,
    },

    /// Store an arbitrary file (kubeconfig, .env, TLS cert, ...) in the vault
    /// and configure it to materialize to disk on unlock. The file's bytes
    /// land in a real KDBX `<Binary>` attachment; the `Materialize.*` custom
    /// fields tell sdpmd where to write it on unlock.
    File {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Entry title (e.g. "kubeconfig-prod").
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
    /// Retrieve a previously stored SSH private key by entry title.
    Ssh {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Entry title to look up.
        title: String,
        /// Write the key to this path (chmod 0600 on Unix). Stdout if omitted.
        #[arg(long = "out")]
        out: Option<PathBuf>,
    },

    /// Retrieve a previously stored GPG secret-key export by entry title.
    Gpg {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Entry title to look up.
        title: String,
        /// Write the export to this path (chmod 0600 on Unix). Stdout if omitted.
        #[arg(long = "out")]
        out: Option<PathBuf>,
    },

    /// Read a file attachment to disk WITHOUT going through materialization.
    /// One-shot equivalent of `sdpm get ssh`. The materialization config
    /// (Materialize.Target, Mode, ...) is ignored — `--out` controls where
    /// the bytes land.
    File {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Entry title to look up.
        title: String,
        /// Attachment name to read. Defaults to the entry's
        /// `Materialize.Source` field, or "blob" if neither is set.
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

fn run(cli: Cli) -> Result<()> {
    let pw_stdin = cli.password_stdin;
    match cli.command {
        Command::Init { vault } => cmd_init(&vault, pw_stdin),
        Command::List { vault } => cmd_list(&vault, pw_stdin),
        Command::Add {
            resource:
                AddResource::Ssh {
                    vault,
                    title,
                    key,
                    user,
                },
        } => cmd_add_ssh(&vault, &title, &key, user.as_deref(), pw_stdin),
        Command::Add {
            resource: AddResource::Gpg { vault, title, key },
        } => cmd_add_gpg(&vault, &title, &key, pw_stdin),
        Command::Add {
            resource:
                AddResource::File {
                    vault,
                    title,
                    src,
                    target,
                    name,
                    mode,
                    ttl,
                    allow_disk_backed,
                },
        } => cmd_add_file(
            &vault,
            &title,
            &src,
            &target,
            name.as_deref(),
            &mode,
            ttl,
            allow_disk_backed,
            pw_stdin,
        ),
        Command::Get {
            resource: GetResource::Ssh { vault, title, out },
        } => cmd_get_ssh(&vault, &title, out.as_deref(), pw_stdin),
        Command::Get {
            resource: GetResource::Gpg { vault, title, out },
        } => cmd_get_gpg(&vault, &title, out.as_deref(), pw_stdin),
        Command::Get {
            resource:
                GetResource::File {
                    vault,
                    title,
                    name,
                    out,
                },
        } => cmd_get_file(&vault, &title, name.as_deref(), out.as_deref(), pw_stdin),
        Command::Agent {
            op: AgentOp::Socket,
        } => cmd_agent_socket(),
        Command::GpgAgent {
            op: GpgAgentOp::Socket,
        } => cmd_gpg_agent_socket(),
        Command::Materialize { vault } => cmd_materialize(&vault, pw_stdin),
        Command::Unlock { vault } => cmd_unlock(&vault, pw_stdin),
        Command::Lock => cmd_lock(),
        Command::Status => cmd_status(),
        Command::Idle {
            op: IdleOp::Set { seconds },
        } => cmd_idle_set(seconds),
        Command::Idle { op: IdleOp::Get } => cmd_idle_get(),
        Command::MaterializeStatus => cmd_materialize_status(),
    }
}

fn cmd_gpg_agent_socket() -> Result<()> {
    // Mirrors `sdpmd::gpg_agent::resolve_gpg_socket_path`.
    let path = if let Ok(p) = std::env::var("SDPM_GPG_SOCK") {
        PathBuf::from(p)
    } else if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            PathBuf::from(rt).join("sdpm-gpg.sock")
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
    PathBuf::from(tmp).join(format!("sdpm-gpg-{uid}.sock"))
}

fn cmd_agent_socket() -> Result<()> {
    // Resolution must mirror `sdpmd::ssh_agent::resolve_ssh_socket_path`.
    // Kept inline here to avoid pulling sdpmd as a dependency of the CLI.
    let path = if let Ok(p) = std::env::var("SDPM_SSH_SOCK") {
        PathBuf::from(p)
    } else if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            PathBuf::from(rt).join("sdpm-ssh.sock")
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
    PathBuf::from(tmp).join(format!("sdpm-ssh-{uid}.sock"))
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
    let _vault = Vault::create(vault_path, &password).context("creating vault")?;
    println!("created vault at {}", vault_path.display());
    Ok(())
}

fn cmd_list(vault_path: &Path, pw_stdin: bool) -> Result<()> {
    let vault = open_vault(vault_path, pw_stdin)?;
    for entry in vault.list_entries() {
        if entry.attachment_names.is_empty() {
            println!("{}  {}", entry.id, entry.title);
        } else {
            println!(
                "{}  {}  [attachments: {}]",
                entry.id,
                entry.title,
                entry.attachment_names.join(", ")
            );
        }
    }
    Ok(())
}

fn cmd_add_ssh(
    vault_path: &Path,
    title: &str,
    key_path: &Path,
    user: Option<&str>,
    pw_stdin: bool,
) -> Result<()> {
    let key_bytes = std::fs::read(key_path)
        .with_context(|| format!("reading ssh key from {}", key_path.display()))?;

    let mut vault = open_vault(vault_path, pw_stdin)?;

    // Reuse existing entry if title matches; otherwise create a new one.
    let id = match vault.find_by_title(title) {
        Some(existing) => existing,
        None => vault
            .add_entry(title)
            .with_context(|| format!("creating entry '{title}'"))?,
    };

    vault
        .attach_binary(&id, SSH_KEY_ATTACHMENT, &key_bytes)
        .context("attaching ssh key")?;

    if let Some(user) = user {
        vault
            .set_field(&id, "UserName", user)
            .context("setting UserName")?;
    }

    vault.save().context("saving vault")?;
    println!("stored ssh key on entry {id} ({title})");
    Ok(())
}

fn cmd_add_gpg(vault_path: &Path, title: &str, key_path: &Path, pw_stdin: bool) -> Result<()> {
    let key_bytes = std::fs::read(key_path)
        .with_context(|| format!("reading gpg secret-key export from {}", key_path.display()))?;

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

fn cmd_get_gpg(vault_path: &Path, title: &str, out: Option<&Path>, pw_stdin: bool) -> Result<()> {
    let vault = open_vault(vault_path, pw_stdin)?;
    let id: EntryId = vault
        .find_by_title(title)
        .ok_or_else(|| CoreError::EntryNotFound(title.to_string()))
        .context("looking up entry by title")?;

    let bytes = vault
        .read_binary(&id, GPG_KEY_ATTACHMENT)
        .context("reading gpg secret-key attachment")?
        .ok_or_else(|| anyhow!("entry '{title}' has no '{GPG_KEY_ATTACHMENT}' attachment"))?;

    match out {
        Some(path) => write_private_file(path, &bytes)
            .with_context(|| format!("writing key to {}", path.display()))?,
        None => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle
                .write_all(&bytes)
                .context("writing gpg secret key to stdout")?;
        }
    }
    Ok(())
}

fn cmd_get_ssh(vault_path: &Path, title: &str, out: Option<&Path>, pw_stdin: bool) -> Result<()> {
    let vault = open_vault(vault_path, pw_stdin)?;
    let id: EntryId = vault
        .find_by_title(title)
        .ok_or_else(|| CoreError::EntryNotFound(title.to_string()))
        .context("looking up entry by title")?;

    let bytes = vault
        .read_binary(&id, SSH_KEY_ATTACHMENT)
        .context("reading ssh key attachment")?
        .ok_or_else(|| anyhow!("entry '{title}' has no '{SSH_KEY_ATTACHMENT}' attachment"))?;

    match out {
        Some(path) => write_private_file(path, &bytes)
            .with_context(|| format!("writing key to {}", path.display()))?,
        None => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle
                .write_all(&bytes)
                .context("writing ssh key to stdout")?;
        }
    }
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
    Vault::open(path, &password).with_context(|| format!("opening vault {}", path.display()))
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

/// `sdpm add file`. Stores file bytes as a real KDBX `<Binary>` attachment
/// and writes the `Materialize.*` custom fields. The basename of `--src` is
/// the default attachment name; `--name` overrides.
#[allow(clippy::too_many_arguments)]
fn cmd_add_file(
    vault_path: &Path,
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

/// `sdpm get file` — read an attachment to disk WITHOUT engaging
/// materialization. One-shot, like `sdpm get ssh`.
fn cmd_get_file(
    vault_path: &Path,
    title: &str,
    name: Option<&str>,
    out: Option<&Path>,
    pw_stdin: bool,
) -> Result<()> {
    let vault = open_vault(vault_path, pw_stdin)?;
    let id: EntryId = vault
        .find_by_title(title)
        .ok_or_else(|| CoreError::EntryNotFound(title.to_string()))
        .context("looking up entry by title")?;

    // Resolve the attachment name. Priority:
    //   1. --name flag (explicit)
    //   2. Materialize.Source on the entry
    //   3. literal "blob"
    let resolved_name: String = match name {
        Some(n) => n.to_string(),
        None => match vault.get_field(&id, "Materialize.Source")? {
            Some(s) => s,
            None => "blob".to_string(),
        },
    };

    let bytes = vault
        .read_binary(&id, &resolved_name)
        .context("reading file attachment")?
        .ok_or_else(|| anyhow!("entry '{title}' has no attachment named '{resolved_name}'"))?;

    match out {
        Some(path) => write_private_file(path, &bytes)
            .with_context(|| format!("writing file to {}", path.display()))?,
        None => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle.write_all(&bytes).context("writing file to stdout")?;
        }
    }
    Ok(())
}

/// `sdpm materialize` — open vault, run the materialize plan in-process,
/// hold open until SIGINT, then wipe.
///
/// We deliberately do NOT touch the daemon's MaterializedStore here; this is
/// a standalone command meant for testing and disconnected use. If you have
/// the daemon running, use `sdpmd unlock` instead so SSH/GPG agents work too.
fn cmd_materialize(vault_path: &Path, pw_stdin: bool) -> Result<()> {
    let vault = open_vault(vault_path, pw_stdin)?;
    let (plans, errors) = sdpmd::materialize::build_plans(&vault);
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
        let store: sdpmd::materialize::MaterializedStore =
            std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new()));
        let mut materialised_count = 0usize;
        for plan in &plans {
            match sdpmd::materialize::materialize_one(&vault, plan, store.clone()) {
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
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint =
            signal(SignalKind::interrupt()).map_err(|e| anyhow!("install SIGINT handler: {e}"))?;
        let mut sigterm =
            signal(SignalKind::terminate()).map_err(|e| anyhow!("install SIGTERM handler: {e}"))?;
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
        println!("\nwiping materialized files...");
        sdpmd::materialize::wipe_all(&store).await;
        println!("done.");
        Ok(())
    })
}

/// Sentinel error returned by the daemon-aware commands. Carries an
/// already-classified exit code so `classify_exit` can short-circuit the
/// usual `CoreError` walk. We use this for cases where the error originated
/// from the daemon (a string we can only parse heuristically) rather than
/// from sdpm-core (where rich types are available).
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
struct DaemonClassified {
    message: String,
    exit: u8,
}

/// `sdpm unlock <vault>` — send `unlock` to the daemon. Prompts for password
/// (or reads stdin) before calling out, so we fail fast on a typo.
fn cmd_unlock(vault: &Path, pw_stdin: bool) -> Result<()> {
    if !vault.exists() {
        return Err(DaemonClassified {
            message: format!("vault file not found: {}", vault.display()),
            exit: EXIT_USER_ERROR,
        }
        .into());
    }
    let vault_str = vault
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
    };
    let resp = match daemon::send(&req) {
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
        // matches the existing `classify_exit` mapping for sdpm-core errors.
        let exit = if looks_like_vault_error(&msg) {
            EXIT_VAULT_ERROR
        } else {
            EXIT_USER_ERROR
        };
        return Err(DaemonClassified { message: msg, exit }.into());
    }

    println!("vault unlocked: {}", vault.display());
    Ok(())
}

/// Heuristic mapping from a daemon-reported error string to vault-error
/// status. Anything mentioning "password" or "kdbx" is treated as a vault
/// error; anything else is a user error.
fn looks_like_vault_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("password") || lower.contains("kdbx") || lower.contains("decrypt")
}

/// `sdpm lock` — send `lock` to the daemon. Idempotent on the daemon side;
/// we treat its response as the source of truth.
fn cmd_lock() -> Result<()> {
    let resp = match daemon::send(&daemon::Request::Lock) {
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

/// `sdpm status` — pretty-print the daemon's `Status` response.
fn cmd_status() -> Result<()> {
    let resp = match daemon::send(&daemon::Request::Status) {
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
    print_status(&resp);
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
        Some(n) => format!("{n}s"),
        None => "(unknown)".to_string(),
    };
    println!("Idle timeout:    {idle_line}");

    if let Some(remaining) = resp.get("idle_remaining_secs").and_then(Value::as_u64) {
        println!("Idle remaining:  {remaining}s");
    }

    let ssh = resp.get("ssh_keys").and_then(Value::as_u64).unwrap_or(0);
    let gpg = resp.get("gpg_keys").and_then(Value::as_u64).unwrap_or(0);
    let mat = resp.get("materialized").and_then(Value::as_u64).unwrap_or(0);
    println!("SSH keys:        {ssh} loaded");
    println!("GPG keys:        {gpg} loaded");
    println!("Materialized:    {mat} files");
}

/// `sdpm idle set <seconds>`.
fn cmd_idle_set(seconds: u64) -> Result<()> {
    let resp = match daemon::send(&daemon::Request::SetIdleTimeout { seconds }) {
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

/// `sdpm idle get`. Pretty-prints the current state.
fn cmd_idle_get() -> Result<()> {
    let resp = match daemon::send(&daemon::Request::GetIdleTimeout) {
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

/// `sdpm materialize-status` — list of active materializations, one per line.
fn cmd_materialize_status() -> Result<()> {
    let resp = match daemon::send(&daemon::Request::MaterializeStatus) {
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
        let exists = entry.get("exists").and_then(Value::as_bool).unwrap_or(false);
        let ttl_str = match entry.get("ttl_remaining_seconds") {
            Some(v) if v.is_null() => "none".to_string(),
            Some(v) => v.as_u64().map(|n| format!("{n}s")).unwrap_or_else(|| "?".to_string()),
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
                | CoreError::Io(_) => EXIT_USER_ERROR,
            };
        }
    }
    EXIT_USER_ERROR
}
