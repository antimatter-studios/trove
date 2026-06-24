//! `trove` — command-line client for trove.
//!
//! v0.0.1 surface: `init`, `list`, `add ssh`, `get ssh`. Master key only;
//! no keyfiles, no env-var passwords.

#![forbid(unsafe_code)]

mod daemon;
mod ipc;

use std::fs::OpenOptions;
use std::io::{BufRead, Write};
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
    ///
    /// If `<VAULT>` is omitted, list the entries of the vault currently
    /// unlocked in the running daemon (auto-spawning if needed) — no
    /// password prompt. Passing a path always reopens the file directly.
    List {
        /// Path to an existing .kdbx file. Optional: omit to list from the
        /// daemon's currently unlocked vault.
        vault: Option<PathBuf>,
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
    Materialize {
        /// Path to the .kdbx vault.
        vault: PathBuf,
    },

    /// Tell the running `troved` to unlock a vault. The keys + materialize
    /// plan land in daemon memory; SSH and GPG agents serve them.
    ///
    /// Prompts for the master password unless `--password-stdin` is set.
    /// The password never lands on the command line.
    Unlock {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Idle-lock timeout in seconds. Resets on every daemon request
        /// (control RPC, ssh-agent op, gpg-agent op). `0` disables auto-lock.
        /// When omitted, keeps the daemon's currently configured timeout
        /// (the env-var default or whatever a prior `idle set` left).
        #[arg(long = "timeout")]
        timeout: Option<u64>,
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
    /// vault unlock, troved parses each `gpg-priv` attachment and registers
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
    /// fields tell troved where to write it on unlock.
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
    /// One-shot equivalent of `trove get ssh`. The materialization config
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
        Command::List { vault } => cmd_list(vault.as_deref(), pw_stdin),
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
        Command::SshAgent {
            op: SshAgentOp::Socket,
        } => cmd_ssh_agent_socket(),
        Command::GpgAgent {
            op: GpgAgentOp::Socket,
        } => cmd_gpg_agent_socket(),
        Command::Materialize { vault } => cmd_materialize(&vault, pw_stdin),
        Command::Unlock { vault, timeout } => cmd_unlock(&vault, timeout, pw_stdin),
        Command::Lock => cmd_lock(),
        Command::Status => cmd_status(),
        Command::Idle {
            op: IdleOp::Set { seconds },
        } => cmd_idle_set(seconds),
        Command::Idle { op: IdleOp::Get } => cmd_idle_get(),
        Command::MaterializeStatus => cmd_materialize_status(),
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

fn cmd_list(vault_path: Option<&Path>, pw_stdin: bool) -> Result<()> {
    match vault_path {
        Some(path) => {
            let vault = open_vault(path, pw_stdin)?;
            for entry in vault.list_entries() {
                print_list_row(
                    &entry.id.to_string(),
                    &entry.display_path(),
                    &entry.attachment_names,
                );
            }
            Ok(())
        }
        None => cmd_list_via_daemon(),
    }
}

/// Daemon-backed list. The vault must already be unlocked in the daemon;
/// otherwise the daemon returns "no vault unlocked" and we surface that as
/// a user error (exit 1). Auto-spawn semantics are inherited from
/// `daemon::send_autospawn` — if no daemon is running we spawn one, but it
/// will come up with no vault unlocked, so the user gets the same friendly
/// "no vault unlocked" message and a hint to run `trove unlock`.
fn cmd_list_via_daemon() -> Result<()> {
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
    Ok(())
}

fn print_list_row(id: &str, title: &str, attachments: &[String]) {
    if attachments.is_empty() {
        println!("{id}  {title}");
    } else {
        println!("{id}  {title}  [attachments: {}]", attachments.join(", "));
    }
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

    // Write KeeAgent.settings so KeePassXC's SSH agent picks this entry up.
    let settings = troved::ssh_agent::keeagent::settings_xml(SSH_KEY_ATTACHMENT);
    vault
        .attach_binary(&id, troved::ssh_agent::keeagent::ATTACHMENT_NAME, &settings)
        .context("attaching KeeAgent.settings")?;

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

/// Pull an attachment out of the *unlocked daemon*, gated by the session code.
///
/// Extraction (`get`) no longer opens the vault one-shot — that would let any
/// password holder bypass the session-code gate. Instead we read `TROVE_SESSION`
/// (the one-time code `trove unlock` minted) and ask the daemon, which serves
/// the bytes only if: the vault is unlocked, the code matches, and we are the
/// uid that unlocked (SO_PEERCRED). The daemon returns the bytes base64-encoded
/// on the JSON wire; we decode them here. See docs/provisioning-sessions.md.
fn daemon_get_attachment(title: &str, attachment: &str) -> Result<Vec<u8>> {
    let code = std::env::var("TROVE_SESSION")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DaemonClassified {
            message: "session code required: run `eval \"$(trove unlock <vault>)\"` first, \
                      then retry in the same shell"
                .to_string(),
            exit: EXIT_USER_ERROR,
        })?;

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

fn cmd_get_gpg(_vault_path: &Path, title: &str, out: Option<&Path>, _pw_stdin: bool) -> Result<()> {
    let bytes = daemon_get_attachment(title, GPG_KEY_ATTACHMENT)?;
    write_secret_out(out, &bytes, "gpg secret key")
}

fn cmd_get_ssh(_vault_path: &Path, title: &str, out: Option<&Path>, _pw_stdin: bool) -> Result<()> {
    let bytes = daemon_get_attachment(title, SSH_KEY_ATTACHMENT)?;
    write_secret_out(out, &bytes, "ssh key")
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

/// `trove add file`. Stores file bytes as a real KDBX `<Binary>` attachment
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

/// `trove get file` — read an attachment to disk WITHOUT engaging
/// materialization. Daemon-routed and session-code-gated, like `trove get ssh`.
///
/// The attachment name comes from `--name`, defaulting to `"blob"`. (The old
/// one-shot path resolved an absent `--name` from the entry's
/// `Materialize.Source` field, but reading that field would mean opening the
/// vault here — which defeats the session-code gate. Pass `--name` for
/// entries that don't use the conventional `blob` attachment slot.)
fn cmd_get_file(
    _vault_path: &Path,
    title: &str,
    name: Option<&str>,
    out: Option<&Path>,
    _pw_stdin: bool,
) -> Result<()> {
    let attachment = name.unwrap_or("blob");
    let bytes = daemon_get_attachment(title, attachment)?;
    write_secret_out(out, &bytes, "file")
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
fn cmd_unlock(vault: &Path, timeout: Option<u64>, pw_stdin: bool) -> Result<()> {
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

    // The daemon minted a one-time session code for this unlock. We emit it as
    // a shell-eval'able export on STDOUT so `eval "$(trove unlock …)"` lands it
    // in the operator's environment — never printed to a terminal, never in
    // `ps`. The human-readable notice goes to STDERR. Code-gated `get` reads
    // it back from $TROVE_SESSION. See docs/provisioning-sessions.md.
    let code = resp
        .get("code")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("daemon unlocked but returned no session code"))?;
    println!("export TROVE_SESSION={code}");
    eprintln!(
        "trove: unlocked {} · session code exported to $TROVE_SESSION",
        vault.display()
    );
    Ok(())
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
    let resp = match daemon::send_autospawn(&daemon::Request::Status) {
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
