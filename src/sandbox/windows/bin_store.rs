//! Machine-store location, resolution and extraction of the `srt-win.exe`
//! helper binary.
//!
//! Layout: `%ProgramData%\sandbox-runtime\bin\srt-win-<sha256>.exe`.
//!
//! - The parent `%ProgramData%\sandbox-runtime` is provisioned by
//!   `srt-win install` with a sandbox-group DENY DACL (the CA key must not
//!   be readable from inside the sandbox). The `bin` subdir therefore
//!   carries its own PROTECTED DACL (`/inheritance:r`) granting the sandbox
//!   group read+execute only — the runner hop (`CreateProcessWithLogonW`)
//!   needs FILE_READ_DATA|FILE_EXECUTE on the image, and nothing more.
//! - The filename embeds the SHA-256 of the bytes this broker was built
//!   with: resolution accepts ONLY the exact-hash copy, so a stale
//!   extraction after a picrab update surfaces as version drift
//!   (`InstallRequired`), never as a silent contract mismatch.
//! - Extraction runs inside the elevated `windows-install` flow (the dir is
//!   created by the elevated caller, so no ownership takeover is needed;
//!   hardening mirrors `srt-win install::provision_machine_store`).

use std::path::{Path, PathBuf};

use crate::error::SandboxError;

/// Resolved srt-win spawn descriptor — mirrors upstream's `SrtWinSpawn`:
/// the executable plus the leading `--srt-win` dispatch sentinel (the
/// standalone binary strips it harmlessly; multicall embedders route on it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtWinSpawn {
    pub exe: PathBuf,
    pub prepend_args: Vec<&'static str>,
}

pub const SRT_WIN_DISPATCH_ARG1: &str = "--srt-win";

/// Resolve the srt-win spawn descriptor, in priority order:
/// 1. explicit `windows.srtWinPath` from config (used verbatim),
/// 2. machine-store copy whose SHA-256 matches this build's embedded exe,
/// 3. dev builds without an embedded exe: this binary's own `--srt-win`
///    multicall sentinel (only works when the dev binary sits somewhere the
///    sandbox account can read/execute).
///
/// Errors:
/// - configured path set but missing → `ExecutionFailed` (config bug, not
///   an install problem),
/// - embedded exe present but machine-store copy absent/mismatched →
///   `InstallRequired` (version drift or never installed).
pub fn resolve_srt_win_spawn(configured: Option<&Path>) -> Result<SrtWinSpawn, SandboxError> {
    if let Some(cfg) = configured {
        if !cfg.is_file() {
            return Err(SandboxError::ExecutionFailed(format!(
                "windows.srtWinPath is set to {} but the file does not exist",
                cfg.display()
            )));
        }
        return Ok(SrtWinSpawn {
            exe: cfg.to_path_buf(),
            prepend_args: vec![SRT_WIN_DISPATCH_ARG1],
        });
    }

    if let Some(hash) = crate::sandbox::windows::embed::embedded_srt_win_sha256() {
        let path = exe_path_for_hash(&hash)?;
        if path.is_file() {
            return Ok(SrtWinSpawn {
                exe: path,
                prepend_args: vec![SRT_WIN_DISPATCH_ARG1],
            });
        }
        return Err(SandboxError::InstallRequired(
            "srt-win helper is not installed for this build (or was extracted by a \
             different version). Run the one-time elevated install: `srt windows-install` \
             (one UAC prompt; no logout needed)."
                .to_string(),
        ));
    }

    let exe = std::env::current_exe()?;
    Ok(SrtWinSpawn {
        exe,
        prepend_args: vec![SRT_WIN_DISPATCH_ARG1],
    })
}

/// `%ProgramData%\sandbox-runtime` — must stay in sync with srt-win's
/// `state_db::machine_store_dir()` (same env var, same absolute-path rule).
pub fn machine_store_dir() -> Result<PathBuf, SandboxError> {
    let base = std::env::var_os("ProgramData").ok_or_else(|| {
        SandboxError::ExecutionFailed("%ProgramData% is not set".to_string())
    })?;
    let base = PathBuf::from(base);
    if !base.is_absolute() {
        return Err(SandboxError::ExecutionFailed(format!(
            "%ProgramData% must be absolute, got {}",
            base.display()
        )));
    }
    Ok(base.join("sandbox-runtime"))
}

/// `%ProgramData%\sandbox-runtime\bin`.
pub fn bin_dir() -> Result<PathBuf, SandboxError> {
    Ok(bin_dir_in(&machine_store_dir()?))
}

/// Pure helper: bin dir under a given store base (unit-testable off-Windows).
fn bin_dir_in(store_base: &Path) -> PathBuf {
    store_base.join("sandbox-runtime").join("bin")
}

/// Exact-hash filename for the given hex sha256.
pub fn exe_path_for_hash(hash: &str) -> Result<PathBuf, SandboxError> {
    Ok(exe_in(&bin_dir()?, hash))
}

/// Pure helper: exact-hash exe filename under a given bin dir.
fn exe_in(bin: &Path, hash: &str) -> PathBuf {
    bin.join(format!("srt-win-{hash}.exe"))
}

/// Elevated install step: write the embedded exe into the machine bin dir
/// and grant the sandbox group read+execute via `icacls`.
///
/// Idempotent: an exact-hash copy that already exists at full size is left
/// untouched, so re-installs and update-repairs are cheap and never
/// truncate a running helper. The ACL is re-asserted on every call — a
/// previous run may have died between the write and the icacls step.
///
/// Returns the installed path, or `None` when the build has no embedded exe.
pub fn extract_embedded(group_sid: &str) -> Result<Option<PathBuf>, SandboxError> {
    use std::io::Write;

    let Some(bytes) = crate::sandbox::windows::embed::embedded_srt_win_exe() else {
        return Ok(None);
    };
    let hash = crate::sandbox::windows::embed::embedded_srt_win_sha256()
        .expect("embedded exe implies hash");
    let dir = bin_dir()?;
    std::fs::create_dir_all(&dir)?;
    let target = dir.join(format!("srt-win-{hash}.exe"));

    let already_there = target.is_file()
        && std::fs::metadata(&target).map(|m| m.len()).unwrap_or(0) == bytes.len() as u64;
    if !already_there {
        // Atomic-ish: write sibling temp, then rename over. A crashed run
        // can only leave a `.tmp<pid>` behind, never a half-written
        // exact-hash exe.
        let tmp = dir.join(format!(".tmp{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &target)?;
    }

    // Protected DACL on the bin dir: drop inherited ACEs (the parent tree
    // DENIES the sandbox group), then grant SYSTEM/Admins full and the
    // sandbox group inherited read+execute. Files created afterwards
    // inherit — including ones written before this call.
    grant_sandbox_read_execute(&dir, group_sid)?;

    Ok(Some(target))
}

/// `icacls`-based ACL hardening of the bin dir (protected DACL).
fn grant_sandbox_read_execute(dir: &Path, group_sid: &str) -> Result<(), SandboxError> {
    // icacls SID syntax: *<SID>. RX = read+execute; (OI)(CI) inherits to
    // files/subdirs. /inheritance:r strips the parent's sandbox-DENY before
    // the grants land. SYSTEM = S-1-5-18, Administrators = S-1-5-32-544.
    let grants = [
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
        &format!("*{group_sid}:(OI)(CI)RX"),
    ];
    let mut cmd = std::process::Command::new("icacls");
    cmd.arg(dir).arg("/inheritance:r");
    for grant in grants {
        cmd.arg("/grant").arg(grant);
    }
    let out = cmd
        .output()
        .map_err(|e| SandboxError::ExecutionFailed(format!("failed to run icacls: {e}")))?;
    if !out.status.success() {
        return Err(SandboxError::ExecutionFailed(format!(
            "icacls failed to harden {} (sandbox group {group_sid}): {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_store_rejects_missing_programdata() {
        // Runs on every host; %ProgramData% only exists on Windows.
        if std::env::var_os("ProgramData").is_some() {
            return;
        }
        assert!(machine_store_dir().is_err());
    }

    #[test]
    fn exe_filename_carries_hash() {
        let bin = bin_dir_in(Path::new("P"));
        let p = exe_in(&bin, "abcd");
        assert_eq!(
            p,
            Path::new("P").join("sandbox-runtime").join("bin").join("srt-win-abcd.exe")
        );
    }

    #[test]
    fn resolve_without_embed_falls_back_to_sentinel() {
        // On hosts without an embedded exe (unix CI, dev builds without
        // SRT_WIN_EXE) and no configured path, resolution must use the
        // multicall sentinel — never error.
        if crate::sandbox::windows::embed::embedded_srt_win_sha256().is_some() {
            return;
        }
        let spawn = resolve_srt_win_spawn(None).expect("dev fallback resolves");
        assert_eq!(spawn.prepend_args, vec![SRT_WIN_DISPATCH_ARG1]);
        assert!(spawn.exe.is_absolute());
    }

    #[test]
    fn resolve_configured_missing_path_errors() {
        let err = resolve_srt_win_spawn(Some(Path::new("Z:/definitely/not/here.exe")));
        if cfg!(windows) {
            assert!(err.is_err());
        } else {
            // Same behavior everywhere: an explicit path is used verbatim
            // and only validated as a file. On unix this path won't exist.
            assert!(err.is_err());
        }
    }
}
