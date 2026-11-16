//! Process-level hardening applied once at daemon startup.

/// Keep troved's memory out of crash dumps.
///
/// troved holds decrypted database material, so a crash must not write it to
/// disk.
///
/// * Every Unix: `RLIMIT_CORE` is set to 0, soft and hard, so the kernel
///   writes no core file and nothing in the process can raise the limit again.
/// * Linux also marks the process non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`).
///   That stops other processes running as the same user from
///   `ptrace`-attaching to troved or reading `/proc/<pid>/mem`.
/// * Windows: no "program has stopped working" dialog
///   (`SEM_NOGPFAULTERRORBOX`), and troved's executable is excluded from
///   Windows Error Reporting for the current user, so a crash leaves no WER
///   report or dump.
pub fn disable_core_dumps() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{set_dumpable_behavior, DumpableBehavior};
        set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    }
    #[cfg(unix)]
    {
        use rustix::process::{setrlimit, Resource, Rlimit};
        setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )?;
    }
    #[cfg(windows)]
    windows::disable_error_reporting()?;
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::System::Diagnostics::Debug::{
        GetErrorMode, SetErrorMode, SEM_NOGPFAULTERRORBOX,
    };
    use windows_sys::Win32::System::ErrorReporting::WerAddExcludedApplication;

    pub(super) fn disable_error_reporting() -> std::io::Result<()> {
        // SAFETY: both calls take and return plain integers.
        unsafe {
            SetErrorMode(GetErrorMode() | SEM_NOGPFAULTERRORBOX);
        }

        let exe = std::env::current_exe()?;
        let wide: Vec<u16> = exe.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
        // call. `0` (FALSE) limits the exclusion to the current user, which
        // needs no admin rights.
        let hr = unsafe { WerAddExcludedApplication(wide.as_ptr(), 0) };
        if hr < 0 {
            return Err(std::io::Error::other(format!(
                "WerAddExcludedApplication failed: HRESULT {hr:#010x}"
            )));
        }
        Ok(())
    }
}
