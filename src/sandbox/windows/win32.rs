//! Thin win32 adapters. Real implementations on windows targets; stubs
//! elsewhere so decision logic unit-tests on any host. Keep this the ONLY
//! module with raw win32 FFI.
//!
//! v1 scope note: shell/tool readability probing is a PATH-PREFIX heuristic
//! (see `shell.rs`), not a DACL walk — machine-root prefixes are readable
//! by the sandbox account via BUILTIN\Users, per-user prefixes are not,
//! and anything else is "unknown" (the runtime error is the backstop).
//! A full DACL walk is a v2 refinement if the heuristic proves noisy.

/// Query a drive root (`"C:\"`) for a mapped/remote (network) drive type.
#[cfg(windows)]
pub fn drive_is_remote(root: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;
    let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
    // GetDriveTypeW returns the drive type; 4 == DRIVE_REMOTE (a
    // network-mapped letter). UNC paths are rejected lexically before this
    // is consulted.
    const DRIVE_REMOTE: u32 = 4;
    unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) == DRIVE_REMOTE }
}

#[cfg(not(windows))]
pub fn drive_is_remote(_root: &str) -> bool {
    false
}
