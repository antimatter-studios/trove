//! Process-level hardening applied once at daemon startup.

/// Mark the daemon non-dumpable on Linux (`prctl(PR_SET_DUMPABLE, 0)`).
///
/// troved holds decrypted vault material, so a crash must not write it to a
/// core file. Being non-dumpable also stops other processes running as the
/// same user from `ptrace`-attaching to troved or reading `/proc/<pid>/mem`.
/// macOS gets the equivalent from the hardened runtime on the signed release
/// binaries; other platforms have nothing to set, so this is a no-op there.
pub fn disable_core_dumps() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{set_dumpable_behavior, DumpableBehavior};
        set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    }
    Ok(())
}
