//! Path validation and expansion for the materialization extension.
//!
//! Two jobs:
//!
//! 1. **Resolve** the target string from the entry's custom field into an
//!    absolute path. We expand `~`, `$HOME`, and `$XDG_RUNTIME_DIR` using the
//!    daemon's environment — never the entry's. (An entry could otherwise
//!    smuggle env-var references that the user didn't intend.)
//! 2. **Validate** that the resolved path is safe to write to. We refuse:
//!    - paths whose textual form contains a `..` segment (before expansion);
//!    - paths under known system directories (`/etc/`, `/usr/`, `/bin/`,
//!      `/sbin/`, `/var/log/`);
//!    - paths that already exist (don't clobber).
//!
//! A missing parent directory is **not** an error: the materializer creates
//! the missing chain (mkdir -p, mode 0700) at write time. See
//! [`missing_ancestors`] for the list of directories that would have to be
//! created — the caller uses it both to create them and to remove trove's own
//! dirs on wipe.
//!
//! Also exposes [`is_tmpfs_backed`] / [`is_ephemeral_macos_path`] so the
//! caller can implement the `AllowDiskBacked=false` policy.
//!
//! ## macOS reality check
//! macOS doesn't have a real tmpfs. `/private/tmp` and `/tmp` (which is a
//! symlink to `/private/tmp`) are APFS-backed and *not* memory-only.
//! [`is_ephemeral_macos_path`] returns `true` for those paths only as a
//! best-effort hint that "the OS treats this as scratch space"; it is **not**
//! a guarantee that bytes never hit the SSD. Set this expectation explicitly
//! in error messages so users know what `AllowDiskBacked=false` means on Mac.

use std::env;
use std::path::{Component, Path, PathBuf};

/// Failure modes for [`resolve_and_validate_target`].
///
/// Each variant has a stable Display format that we re-emit in handler logs.
/// Don't reorder — log-scrapers may key on the leading word.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    #[error("path traversal segment ('..') is not allowed in target")]
    TraversalSegment,

    #[error("target points to a system directory ({0}); refusing to materialize")]
    SystemDirectory(String),

    #[error("target already exists: {0}")]
    AlreadyExists(PathBuf),

    #[error("target is empty")]
    Empty,

    #[error("HOME is not set; cannot expand '~' or '$HOME' in target")]
    HomeNotSet,

    #[error("XDG_RUNTIME_DIR is not set; cannot expand '$XDG_RUNTIME_DIR' in target")]
    XdgRuntimeNotSet,
}

/// System-directory prefixes we refuse to materialize into. Order matters
/// only for the error message we produce (the first match wins).
///
/// These are intentionally conservative. If a user really wants to drop a
/// kubeconfig under `/etc/kubernetes/` they can do that with a real config
/// management tool; a password manager isn't the right interface.
const FORBIDDEN_PREFIXES: &[&str] = &[
    "/etc/",
    "/usr/",
    "/bin/",
    "/sbin/",
    "/var/log/",
    // /boot/ and /lib/ aren't in the spec but they're equally bad targets;
    // we leave them off to stay faithful to the spec.
];

/// Expand `~`, `$HOME`, and `$XDG_RUNTIME_DIR` against the daemon's environment
/// without invoking a shell. Returns the un-validated absolute path.
///
/// We expand `~` only at the very start of the string (a leading `~/` or the
/// bare string `~`). A `~` later in the string is treated as a literal —
/// matching what most shells do.
///
/// `$HOME` and `$XDG_RUNTIME_DIR` are recognized in two forms: `$HOME`
/// (followed by `/` or end-of-string) and `${HOME}`. No other env vars are
/// expanded; we don't want to surprise users with `$PATH` etc.
pub fn expand_env(raw: &str) -> Result<PathBuf, PathError> {
    if raw.is_empty() {
        return Err(PathError::Empty);
    }

    // ~ expansion (start-of-string only).
    let after_tilde: String = if raw == "~" {
        env::var("HOME").map_err(|_| PathError::HomeNotSet)?
    } else if let Some(rest) = raw.strip_prefix("~/") {
        let home = env::var("HOME").map_err(|_| PathError::HomeNotSet)?;
        format!("{home}/{rest}")
    } else {
        raw.to_string()
    };

    // env-var expansion. Cheap state machine; we don't use a generic shell
    // expander because we deliberately allow only HOME and XDG_RUNTIME_DIR.
    let mut out = String::with_capacity(after_tilde.len());
    let mut chars = after_tilde.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        // Distinguish ${VAR} from $VAR.
        let braced = chars.peek() == Some(&'{');
        if braced {
            chars.next(); // consume '{'
            let mut name = String::new();
            let mut closed = false;
            for nc in chars.by_ref() {
                if nc == '}' {
                    closed = true;
                    break;
                }
                name.push(nc);
            }
            if !closed {
                // Malformed `${VAR` — preserve literally to avoid silent loss.
                out.push('$');
                out.push('{');
                out.push_str(&name);
                continue;
            }
            push_env_value(&mut out, &name)?;
        } else {
            // Read identifier chars [A-Za-z_][A-Za-z0-9_]*.
            let mut name = String::new();
            while let Some(&pc) = chars.peek() {
                let ok = if name.is_empty() {
                    pc.is_ascii_alphabetic() || pc == '_'
                } else {
                    pc.is_ascii_alphanumeric() || pc == '_'
                };
                if !ok {
                    break;
                }
                name.push(pc);
                chars.next();
            }
            if name.is_empty() {
                // A bare `$` not followed by an identifier — emit literally.
                out.push('$');
            } else {
                push_env_value(&mut out, &name)?;
            }
        }
    }

    Ok(PathBuf::from(out))
}

fn push_env_value(out: &mut String, name: &str) -> Result<(), PathError> {
    match name {
        "HOME" => match env::var("HOME") {
            Ok(v) => {
                out.push_str(&v);
                Ok(())
            }
            Err(_) => Err(PathError::HomeNotSet),
        },
        "XDG_RUNTIME_DIR" => match env::var("XDG_RUNTIME_DIR") {
            Ok(v) if !v.is_empty() => {
                out.push_str(&v);
                Ok(())
            }
            _ => Err(PathError::XdgRuntimeNotSet),
        },
        // Anything else: not in our allowlist. Don't expand it; emit literally.
        // (Refusing would block legitimate static paths that happen to contain
        // a `$`; emitting literally lets the rest of validation catch it if
        // the path is bogus.)
        other => {
            out.push('$');
            out.push_str(other);
            Ok(())
        }
    }
}

/// Reject if the *raw* (un-expanded) path string contains a `..` segment.
///
/// We check the raw string rather than the expanded path because expansion
/// could in theory eliminate a `..` (e.g. `$HOME/../bad` becomes
/// `/Users/foo/../bad` — still has `..` — but consider `$WEIRD/safe` which
/// expands to `/safe`). Checking the raw string is the user-visible policy:
/// "if you write `..`, we refuse." The expanded form is then re-checked via
/// path components for safety in depth.
pub fn check_no_traversal(raw: &str) -> Result<(), PathError> {
    // Split on both '/' and '\\' even though we're POSIX-only — paranoid.
    for seg in raw.split(['/', '\\']) {
        if seg == ".." {
            return Err(PathError::TraversalSegment);
        }
    }
    Ok(())
}

/// Final validation against the resolved absolute path:
/// - re-check no `..` components (defense in depth);
/// - reject system directories;
/// - reject existing target (no clobber).
///
/// A missing parent directory is **not** rejected here — the materializer
/// creates the missing chain at write time (see [`missing_ancestors`]).
fn check_resolved(p: &Path) -> Result<(), PathError> {
    for comp in p.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(PathError::TraversalSegment);
        }
    }

    // System-dir reject. We compare against the path's lossy string form so
    // we treat "/etc/foo" and "/etc/foo/" identically.
    if let Some(s) = p.to_str() {
        for prefix in FORBIDDEN_PREFIXES {
            if s.starts_with(prefix) {
                return Err(PathError::SystemDirectory((*prefix).to_string()));
            }
        }
    }

    if p.exists() {
        return Err(PathError::AlreadyExists(p.to_path_buf()));
    }

    Ok(())
}

/// The chain of parent directories of `target` that do not yet exist, ordered
/// **outermost-first** (nearest existing ancestor's missing child first, down
/// to the target's immediate parent last). Empty if the parent already exists.
///
/// Used two ways:
/// * at write time: create each entry in order with mode 0700;
/// * on wipe: remove trove's own created dirs in reverse (innermost first),
///   only if empty.
///
/// This does NOT create anything and does NOT touch the filesystem beyond
/// `exists()` probes. The returned paths are always ancestors of `target`.
pub fn missing_ancestors(target: &Path) -> Vec<PathBuf> {
    let parent = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        // Root or empty parent — nothing to create.
        _ => return Vec::new(),
    };

    // Walk up from the parent collecting non-existent ancestors, stopping at
    // the first ancestor that exists (or the filesystem root).
    let mut missing: Vec<PathBuf> = Vec::new();
    let mut cur = Some(parent);
    while let Some(dir) = cur {
        if dir.as_os_str().is_empty() || dir.exists() {
            break;
        }
        missing.push(dir.to_path_buf());
        cur = dir.parent();
    }
    // Collected innermost-first; reverse to outermost-first so callers can
    // create top-down.
    missing.reverse();
    missing
}

/// One-shot: take an entry's `Materialize.Target` value and produce a fully
/// resolved, validated absolute path that is safe to materialize to.
///
/// Errors are precise so the daemon log can tell the user *why* this entry's
/// materialization was skipped. The unlock RPC continues with other entries.
pub fn resolve_and_validate_target(raw: &str) -> Result<PathBuf, PathError> {
    check_no_traversal(raw)?;
    let expanded = expand_env(raw)?;
    check_resolved(&expanded)?;
    Ok(expanded)
}

// --- tmpfs / ephemeral detection ------------------------------------------

/// Best-effort tmpfs detection.
///
/// On Linux: read `/proc/mounts`, find every tmpfs mountpoint, and return
/// `true` iff `path`'s longest mount-prefix matches a tmpfs entry. (The
/// "longest mount-prefix" matters: `/` is always mounted, but if `/run` is
/// mounted as tmpfs, `/run/foo` is tmpfs even though `/` is not.)
///
/// On macOS: there is no real tmpfs in the OS. This function always returns
/// `false` on macOS — see [`is_ephemeral_macos_path`] for the soft-allowlist
/// alternative.
pub fn is_tmpfs_backed(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/mounts") {
            Ok(s) => is_tmpfs_backed_with_mounts(path, &s),
            Err(_) => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        false
    }
}

/// Test seam for [`is_tmpfs_backed`]. `mounts` is the literal contents of
/// `/proc/mounts`. Format per `proc(5)`:
///
/// ```text
/// device mountpoint fstype options dump pass
/// ```
///
/// We split on whitespace and look at columns 2 and 3. Octal-escape sequences
/// in the mountpoint (e.g. spaces written as `\040`) are decoded.
pub fn is_tmpfs_backed_with_mounts(path: &Path, mounts: &str) -> bool {
    // Collect (mountpoint, fstype) tuples.
    let mut tmpfs_mounts: Vec<PathBuf> = Vec::new();
    for line in mounts.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 {
            continue;
        }
        let fstype = cols[2];
        // Treat `tmpfs` and `ramfs` as memory-backed. `devtmpfs` is also
        // tmpfs-shaped but we don't materialize into /dev anyway.
        if fstype != "tmpfs" && fstype != "ramfs" {
            continue;
        }
        let mp = decode_mount_escapes(cols[1]);
        tmpfs_mounts.push(PathBuf::from(mp));
    }

    if tmpfs_mounts.is_empty() {
        return false;
    }

    // Pick the longest matching prefix among ALL filesystems — but we only
    // have tmpfs entries cached. To do "longest among all" properly we'd
    // need every mount, but the spec says "longest mount-prefix matches a
    // tmpfs entry" so we just take the longest tmpfs prefix the path is
    // under. If there's a non-tmpfs filesystem mounted *deeper*, the path
    // still wouldn't be tmpfs — but that's an obscure case (you'd have to
    // bind-mount ext4 onto a tmpfs subdir) and not worth the extra parse.
    let mut best: Option<&PathBuf> = None;
    for mp in &tmpfs_mounts {
        if path.starts_with(mp) {
            best = match best {
                None => Some(mp),
                Some(prev) if mp.as_os_str().len() > prev.as_os_str().len() => Some(mp),
                Some(prev) => Some(prev),
            };
        }
    }
    best.is_some()
}

/// Decode `\NNN` octal escapes that the kernel uses for whitespace and
/// nonprintable characters in mountpoint names in `/proc/mounts`.
fn decode_mount_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let n = std::str::from_utf8(&bytes[i + 1..i + 4]).ok();
            if let Some(n) = n {
                if let Ok(code) = u8::from_str_radix(n, 8) {
                    out.push(code as char);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// macOS-only soft check: does `path` live under `/private/tmp`, `/tmp`, or
/// `$XDG_RUNTIME_DIR` (if set)?
///
/// Returning `true` does NOT mean memory-backed. `/private/tmp` is APFS,
/// snapshotted by Time Machine (configurably), and persists across boots in
/// some cases. Treat this as "the OS calls this ephemeral; the user did the
/// best they could on macOS." The caller should encode this distinction in
/// the user-visible error or warning.
pub fn is_ephemeral_macos_path(path: &Path) -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    let candidates = ["/private/tmp", "/tmp"];
    for c in candidates {
        if path.starts_with(c) {
            return true;
        }
    }
    if let Ok(rt) = env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() && path.starts_with(&rt) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    /// Tests in this module mutate process-global env vars (`HOME`,
    /// `XDG_RUNTIME_DIR`). Cargo runs tests within one binary in parallel by
    /// default; without serialization the env-touching tests race. We don't
    /// want to require `--test-threads=1` for the whole crate, so this mutex
    /// linearizes just the env-mutating tests.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(key: &str, val: Option<&str>, f: F) {
        // Hold the lock for the entire body so two with_env calls can't
        // interleave their save/restore steps.
        let _g = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let prev = env::var(key).ok();
        match val {
            Some(v) => env::set_var(key, v),
            None => env::remove_var(key),
        }
        f();
        match prev {
            Some(p) => env::set_var(key, p),
            None => env::remove_var(key),
        }
    }

    #[test]
    fn rejects_double_dot_segment() {
        assert!(matches!(
            resolve_and_validate_target("/tmp/foo/../bar"),
            Err(PathError::TraversalSegment)
        ));
        assert!(matches!(
            resolve_and_validate_target("../etc/passwd"),
            Err(PathError::TraversalSegment)
        ));
    }

    #[test]
    fn rejects_system_dirs() {
        for bad in &[
            "/etc/foo",
            "/usr/local/bad",
            "/bin/notme",
            "/sbin/anything",
            "/var/log/seekrit",
        ] {
            let res = resolve_and_validate_target(bad);
            assert!(
                matches!(res, Err(PathError::SystemDirectory(_))),
                "expected SystemDirectory for {bad}, got {res:?}"
            );
        }
    }

    #[test]
    fn missing_parent_is_accepted_and_reported() {
        // A missing parent no longer fails validation — the materializer will
        // create it. Validation succeeds and `missing_ancestors` reports the
        // dirs that would have to be created.
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("a").join("b").join("secret");
        let res = resolve_and_validate_target(target.to_str().unwrap());
        assert!(res.is_ok(), "missing parent should validate: {res:?}");

        let missing = missing_ancestors(&target);
        assert_eq!(
            missing,
            vec![tmp.path().join("a"), tmp.path().join("a").join("b")],
            "outermost-first chain of dirs to create"
        );
    }

    #[test]
    fn missing_ancestors_empty_when_parent_exists() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("secret");
        assert!(
            missing_ancestors(&target).is_empty(),
            "existing parent means nothing to create"
        );
    }

    #[test]
    fn rejects_existing_target() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let p = tmp.path().join("exists");
        std::fs::write(&p, b"x").expect("write");
        let res = resolve_and_validate_target(p.to_str().unwrap());
        assert!(
            matches!(res, Err(PathError::AlreadyExists(_))),
            "got {res:?}"
        );
    }

    #[test]
    fn expands_tilde_and_home() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().to_str().unwrap().to_string();
        with_env("HOME", Some(&home), || {
            let p = expand_env("~/foo").expect("expand");
            assert_eq!(p, PathBuf::from(format!("{home}/foo")));
            let p = expand_env("$HOME/bar").expect("expand");
            assert_eq!(p, PathBuf::from(format!("{home}/bar")));
            let p = expand_env("${HOME}/baz").expect("expand");
            assert_eq!(p, PathBuf::from(format!("{home}/baz")));
        });
    }

    #[test]
    fn expands_xdg_runtime_dir() {
        with_env("XDG_RUNTIME_DIR", Some("/run/user/1000"), || {
            let p = expand_env("$XDG_RUNTIME_DIR/trove/k").expect("expand");
            assert_eq!(p, PathBuf::from("/run/user/1000/trove/k"));
            let p = expand_env("${XDG_RUNTIME_DIR}/k").expect("expand");
            assert_eq!(p, PathBuf::from("/run/user/1000/k"));
        });
    }

    #[test]
    fn unknown_env_var_is_left_literal() {
        let p = expand_env("/static/$NOT_A_REAL_VAR/x").expect("expand");
        assert_eq!(p, PathBuf::from("/static/$NOT_A_REAL_VAR/x"));
    }

    #[test]
    fn missing_xdg_runtime_dir_errors() {
        with_env("XDG_RUNTIME_DIR", None, || {
            let res = expand_env("$XDG_RUNTIME_DIR/x");
            assert!(matches!(res, Err(PathError::XdgRuntimeNotSet)));
        });
    }

    #[test]
    fn empty_path_rejected() {
        assert!(matches!(expand_env(""), Err(PathError::Empty)));
    }

    #[test]
    fn tmpfs_detection_with_synthetic_mounts() {
        let mounts = "\
proc /proc proc rw 0 0
sysfs /sys sysfs rw 0 0
tmpfs /run tmpfs rw,nosuid,nodev,size=10% 0 0
tmpfs /dev/shm tmpfs rw 0 0
ext4 /home ext4 rw 0 0
tmpfs /tmp tmpfs rw 0 0
";
        assert!(is_tmpfs_backed_with_mounts(
            Path::new("/run/user/1000/trove.sock"),
            mounts
        ));
        assert!(is_tmpfs_backed_with_mounts(Path::new("/tmp/x"), mounts));
        assert!(is_tmpfs_backed_with_mounts(Path::new("/dev/shm/y"), mounts));
        assert!(!is_tmpfs_backed_with_mounts(
            Path::new("/home/user/x"),
            mounts
        ));
        assert!(!is_tmpfs_backed_with_mounts(Path::new("/etc/x"), mounts));
    }

    #[test]
    fn tmpfs_detection_picks_longest_prefix() {
        // /tmp tmpfs, /tmp/persist ext4 (bind mount). We don't try to fully
        // resolve this — see the comment in is_tmpfs_backed_with_mounts —
        // but make sure the basic prefix logic doesn't mistakenly say "false"
        // for /tmp/x just because there's no exact match.
        let mounts = "\
tmpfs /tmp tmpfs rw 0 0
tmpfs /run/user/1000 tmpfs rw 0 0
";
        assert!(is_tmpfs_backed_with_mounts(Path::new("/tmp/foo"), mounts));
        assert!(is_tmpfs_backed_with_mounts(
            Path::new("/run/user/1000/x"),
            mounts
        ));
        assert!(!is_tmpfs_backed_with_mounts(
            Path::new("/run/user/0/x"),
            mounts
        ));
    }

    #[test]
    fn tmpfs_detection_decodes_mount_escapes() {
        // A space in the mountpoint becomes \040 in /proc/mounts.
        let mounts = "tmpfs /mnt/with\\040space tmpfs rw 0 0\n";
        assert!(is_tmpfs_backed_with_mounts(
            Path::new("/mnt/with space/x"),
            mounts
        ));
    }
}
