//! Inner-shell resolution and sandbox-readiness probing (B6).
//!
//! Port of TS `parseWindowsBinShell` (the sole normalizer — no silent
//! fallback) plus the fork's readability heuristic. All pure logic.

use std::path::{Path, PathBuf};

use crate::error::SandboxError;

/// Inner shell to run the user's command under, inside the sandbox.
/// `exe` must come from trusted host configuration — never workspace
/// content (same rule as upstream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellProbe {
    pub exe: PathBuf,
    pub args: Vec<&'static str>,
}

const PWSH_FLAGS: [&str; 2] = ["-NoProfile", "-Command"];

/// Sole normalizer from the config surface (`cmd` | `powershell` | `pwsh`
/// | absolute path to bash.exe/sh.exe) to a spawnable `{exe, args}` pair.
/// Bare `bash` is rejected as ambiguous (WSL vs Git Bash) — pass the
/// resolved install path. Throws on anything else; no silent cmd.exe
/// fallback.
pub fn parse_bin_shell(raw: Option<&str>) -> Result<ShellProbe, SandboxError> {
    let system_root =
        std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("C:\\Windows"));
    let cmd_default = || ShellProbe {
        exe: system_root.join("System32").join("cmd.exe"),
        args: vec!["/d", "/s", "/c"],
    };
    let Some(raw) = raw else {
        return Ok(cmd_default());
    };

    let p = Path::new(raw);
    let is_abs = is_windows_absolute(p);
    let base = win_file_name(raw);
    if is_abs {
        return match base.as_str() {
            "bash.exe" | "sh.exe" | "bash" | "sh" => Ok(ShellProbe {
                exe: p.to_path_buf(),
                args: vec!["-c"],
            }),
            "pwsh.exe" | "pwsh" => Ok(ShellProbe {
                exe: p.to_path_buf(),
                args: PWSH_FLAGS.to_vec(),
            }),
            "powershell.exe" | "powershell" => Ok(ShellProbe {
                exe: p.to_path_buf(),
                args: PWSH_FLAGS.to_vec(),
            }),
            "cmd.exe" | "cmd" => Ok(cmd_default()),
            other => Err(bin_shell_invalid(format!(
                "unrecognised absolute shell path {other:?}: expected \
                 bash.exe/sh.exe/pwsh.exe/powershell.exe/cmd.exe"
            ))),
        };
    }

    // Bare tokens only (a relative path with a directory component is
    // neither — never silently degrade).
    if raw != base {
        return Err(bin_shell_invalid(format!(
            "binShell string must be a bare token or an absolute path (got {raw:?})"
        )));
    }
    match base.as_str() {
        "cmd" | "cmd.exe" => Ok(cmd_default()),
        "powershell" | "powershell.exe" => Ok(ShellProbe {
            exe: system_root
                .join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe"),
            args: PWSH_FLAGS.to_vec(),
        }),
        "pwsh" | "pwsh.exe" => Ok(ShellProbe {
            exe: PathBuf::from("pwsh.exe"),
            args: PWSH_FLAGS.to_vec(),
        }),
        "bash" | "sh" | "bash.exe" | "sh.exe" => Err(bin_shell_invalid(
            "binShell bash path must be absolute (bare 'bash' is ambiguous: \
             WSL vs Git Bash); pass the resolved Git Bash install path"
                .to_string(),
        )),
        other => Err(bin_shell_invalid(format!(
            "unrecognised binShell {other:?}: expected 'cmd' | 'powershell' | 'pwsh' \
             or an absolute path to bash.exe/sh.exe/pwsh.exe/powershell.exe"
        ))),
    }
}

fn bin_shell_invalid(detail: String) -> SandboxError {
    SandboxError::Config(crate::error::ConfigError::ValidationError(format!(
        "binShell: {detail}"
    )))
}

/// Windows-aware absolute-path test (`Path::is_absolute` on a unix host
/// doesn't recognize `C:\…` or `\\server\…`) — kept host-portable so the
/// normalizer unit-tests anywhere.
fn is_windows_absolute(p: &Path) -> bool {
    if p.is_absolute() {
        return true;
    }
    let text = p.to_string_lossy();
    let bytes = text.as_bytes();
    (bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic())
        || text.starts_with("\\\\")
        || text.starts_with("//")
}

/// Last path component, splitting on BOTH separators (a unix host's
/// `Path::file_name` doesn't split backslash paths — the shell strings are
/// Windows paths even when this code runs on a mac).
fn win_file_name(raw: &str) -> String {
    raw.replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or(raw)
        .to_lowercase()
}

/// Reject WSL-resident shells up front: a sandboxed WSL launch would land
/// in the sandbox account's empty WSL environment, not the user's distro.
fn check_not_wsl(exe: &Path) -> Result<(), SandboxError> {
    let text = exe.to_string_lossy().to_lowercase();
    let base = exe
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let is_wsl = text.contains("\\\\wsl$")
        || text.contains("\\\\wsl.localhost")
        || base == "wsl.exe" || base == "wsl";
    if is_wsl {
        return Err(SandboxError::ShellNotReadable {
            path: exe.display().to_string(),
            hint: "WSL-resident shells are not supported under the Windows sandbox; \
                   point the shell at a native Git Bash install"
                .to_string(),
        });
    }
    Ok(())
}

/// Readiness heuristic for the shell (and by extension the tool tree):
/// - paths under well-known MACHINE roots (Program Files, SystemRoot,
///   ProgramData) are readable by the sandbox account via BUILTIN\Users;
/// - paths under the user profile are NOT (cross-account model inverts the
///   unix default: nothing under the user profile is readable unless
///   granted) → typed error with the machine-install instruction;
/// - anything else → unknown, accept (the runtime error is the backstop).
///
/// This is a heuristic by design (see win32.rs scope note); `srt-win`'s
/// typed exec errors remain the enforcement truth.
pub fn probe_shell(exe: &Path) -> Result<(), SandboxError> {
    check_not_wsl(exe)?;
    if !exe.is_file() {
        return Err(SandboxError::ShellNotReadable {
            path: exe.display().to_string(),
            hint: "shell executable not found; configure sandbox.binShell with the \
                   resolved Git Bash path (e.g. C:\\Program Files\\Git\\bin\\bash.exe)"
                .to_string(),
        });
    }

    let exe_text = exe.to_string_lossy().replace('/', "\\");
    let lowered = exe_text.to_lowercase();

    for var in ["ProgramFiles", "SystemRoot", "ProgramData"] {
        if let Some(root) = std::env::var_os(var) {
            let root_text = PathBuf::from(&root).to_string_lossy().replace('/', "\\").to_lowercase();
            if lowered.starts_with(&root_text) {
                return Ok(());
            }
        }
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        let profile_text = PathBuf::from(&profile).to_string_lossy().replace('/', "\\").to_lowercase();
        if lowered.starts_with(&profile_text) {
            return Err(SandboxError::ShellNotReadable {
                path: exe.display().to_string(),
                hint: "per-user installs are not readable by the sandbox account. \
                       Install the shell (and toolchain) machine-wide — e.g. \
                       `choco install git` (lands in C:\\Program Files\\Git) — or point \
                       sandbox.binShell at a machine-wide bash.exe"
                    .to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_bash_is_rejected_as_ambiguous() {
        let err = parse_bin_shell(Some("bash")).unwrap_err();
        assert!(err.to_string().contains("ambiguous"));
    }

    #[test]
    fn relative_path_with_dir_component_is_rejected() {
        assert!(parse_bin_shell(Some("bin\\bash.exe")).is_err());
    }

    #[test]
    fn absolute_bash_gets_dash_c() {
        let sh = parse_bin_shell(Some("C:\\Program Files\\Git\\bin\\bash.exe")).unwrap();
        assert_eq!(sh.args, vec!["-c"]);
        assert!(sh.exe.to_string_lossy().ends_with("bash.exe"));
    }

    #[test]
    fn cmd_bare_token_resolves_to_system32() {
        let sh = parse_bin_shell(Some("cmd")).unwrap();
        assert_eq!(sh.args, vec!["/d", "/s", "/c"]);
        assert!(sh.exe.ends_with("cmd.exe"));
    }

    #[test]
    fn unknown_bare_token_rejected() {
        assert!(parse_bin_shell(Some("fish")).is_err());
    }

    #[test]
    fn wsl_path_rejected() {
        let err = probe_shell(Path::new("\\\\wsl$\\Ubuntu\\usr\\bin\\bash"));
        assert!(matches!(err, Err(SandboxError::ShellNotReadable { ref hint, .. }) if hint.contains("WSL")));
    }

    #[test]
    fn user_profile_shell_rejected_with_machine_hint() {
        if std::env::var_os("USERPROFILE").is_none() {
            return;
        }
        let profile = PathBuf::from(std::env::var_os("USERPROFILE").unwrap());
        let exe = profile.join("AppData").join("Local").join("Programs").join("Git").join("bin").join("bash.exe");
        let err = probe_shell(&exe);
        assert!(matches!(err, Err(SandboxError::ShellNotReadable { ref hint, .. }) if hint.contains("machine-wide")));
    }

    #[test]
    fn missing_file_rejected() {
        let err = probe_shell(Path::new(if cfg!(windows) { "C:\\no\\such\\bash.exe" } else { "/no/such/bash.exe" }));
        assert!(matches!(err, Err(SandboxError::ShellNotReadable { ref hint, .. }) if hint.contains("not found")));
    }
}
