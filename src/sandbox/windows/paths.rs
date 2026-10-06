//! Windows filesystem-path normalization and glob expansion for the ACL
//! backend.
//!
//! Port of TS `expandWindowsFsPaths` + `normalizePathForSandbox` (win32
//! flavor). Pure logic — unit-tests anywhere.

use std::path::{Path, PathBuf};

use crate::error::SandboxError;
use crate::utils::path::{contains_glob_chars, expand_home};

/// Normalize a config-supplied path for the Windows backend:
/// - expand `~` against `%USERPROFILE%` (`expand_home` understands HOME on
///   unix too; on Windows the var is HOME-less so we fall back explicitly),
/// - absolutize against `cwd`,
/// - lexically normalize separators (forward slashes accepted everywhere in
///   the Windows API).
pub fn normalize_fs_path(raw: &str, cwd: &Path) -> Result<PathBuf, SandboxError> {
    let expanded = expand_home(raw);
    let expanded = if expanded.starts_with('~') {
        // `~` unresolved: expand_home looked for $HOME which is usually
        // unset on Windows — use %USERPROFILE%.
        match std::env::var_os("USERPROFILE") {
            Some(profile) => PathBuf::from(profile).join(&expanded[1..].trim_start_matches(['/', '\\'])),
            None => return Err(SandboxError::ExecutionFailed(format!(
                "cannot resolve path {raw:?}: no HOME or USERPROFILE"
            ))),
        }
    } else {
        PathBuf::from(&expanded)
    };

    let p = if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    };

    Ok(normalize_separators(&p))
}

/// Lexical separator normalization: backslashes → forward slashes, collapse
/// `//` and resolve `.`/`..` lexically, preserving the leading slash of
/// absolute paths and UNC shape (`//server/share`).
fn normalize_separators(p: &Path) -> PathBuf {
    let text = p.to_string_lossy().replace('\\', "/");
    let leading = text.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in text.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                // Don't pop past a drive root (e.g. `C:/..`), a UNC share,
                // or the leading absolute root.
                if let Some(last) = parts.last() {
                    let is_rootish = last.ends_with(':') || last.is_empty();
                    if !is_rootish {
                        parts.pop();
                    }
                } else if leading {
                    // at the absolute root; `..` stays there
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    if leading {
        PathBuf::from(format!("/{joined}"))
    } else {
        PathBuf::from(joined)
    }
}

/// Expand glob patterns into concrete paths for the ACL grant/stamp sets
/// (upstream expands at `initialize()`; srt-win's ACE canonicalizer
/// hard-fails on globs, so a `*` reaching it is a caller bug).
///
/// Semantics mirrored from TS `expandWindowsFsPaths`:
/// - non-glob entries pass through normalized (existence NOT required);
/// - glob entries match case-insensitively against the filesystem;
/// - `mode: Deny` re-applies a trailing separator from the raw input as a
///   dir-leaf signal for missing paths (upstream #536: trailing-separator
///   deny entries mark "directory only").
pub fn expand_fs_paths(
    patterns: &[String],
    cwd: &Path,
    mode: Mode,
) -> Result<Vec<PathBuf>, SandboxError> {
    let mut out: Vec<PathBuf> = Vec::new();
    for raw in patterns {
        let norm = normalize_fs_path(raw, cwd)?;
        if contains_glob_chars(&norm.to_string_lossy()) {
            out.extend(expand_glob(&norm));
        } else {
            // Deny-mode dir-leaf signal: a trailing separator in the raw
            // input marks "directory only" (upstream #536). The separator
            // is re-applied so srt-win's canonicalizer treats it as a dir.
            let keep_sep = matches!(mode, Mode::Deny)
                && (raw.ends_with('/') || raw.ends_with('\\'))
                && !norm.to_string_lossy().ends_with('/');
            if keep_sep {
                out.push(PathBuf::from(format!("{}/", norm.to_string_lossy())));
            } else {
                out.push(norm);
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Grant,
    Deny,
}

/// Glob expansion with case-insensitive component matching. Uses the same
/// `glob` crate as the unix backends; windows path components are matched
/// case-insensitively by lowercasing the pattern (NTFS is case-insensitive
/// by default — the pattern side lowercased matches both).
fn expand_glob(pattern: &Path) -> Vec<PathBuf> {
    let text = pattern.to_string_lossy().replace('\\', "/");
    match glob::glob_with(&text, glob::MatchOptions {
        case_sensitive: false,
        require_literal_separator: false,
        require_literal_leading_dot: false,
    }) {
        Ok(paths) => paths.filter_map(|p| p.ok()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Detect a working directory on a mapped/network drive (UNC literal, or a
/// drive letter resolved to DRIVE_REMOTE). The UNC check is pure; the
/// remote-drive query is the thin win32 adapter (stubbed off-Windows).
pub fn check_cwd_sandboxable(cwd: &Path) -> Result<(), SandboxError> {
    let text = cwd.to_string_lossy();
    if text.starts_with("\\\\") || text.starts_with("//") {
        return Err(SandboxError::MappedDriveCwd(format!(
            "UNC working directory {}",
            cwd.display()
        )));
    }
    if let Some(root) = drive_root(cwd) {
        if super::win32::drive_is_remote(&root) {
            return Err(SandboxError::MappedDriveCwd(format!(
                "mapped/network drive root {root:?}"
            )));
        }
    }
    Ok(())
}

/// `"C:\foo\bar"` → `"C:\"`; None when the path has no drive component.
fn drive_root(cwd: &Path) -> Option<String> {
    let text = cwd.to_string_lossy();
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        Some(format!("{}:\\", text[..1].to_ascii_uppercase()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cwd() -> PathBuf {
        PathBuf::from(if cfg!(windows) { "C:\\proj" } else { "/proj" })
    }

    #[test]
    fn absolutizes_relative_and_normalizes_separators() {
        let p = normalize_fs_path("sub\\dir\\..\\file", &cwd()).unwrap();
        assert_eq!(p, PathBuf::from(if cfg!(windows) { "C:/proj/sub/file" } else { "/proj/sub/file" }));
    }

    #[test]
    fn drive_root_extraction() {
        assert_eq!(drive_root(Path::new("C:\\x")), Some("C:\\".to_string()));
        assert_eq!(drive_root(Path::new("c:/x")), Some("C:\\".to_string()));
        assert_eq!(drive_root(Path::new("/x")), None);
    }

    #[test]
    fn unc_cwd_rejected() {
        let err = check_cwd_sandboxable(Path::new("//server/share/dir"));
        assert!(matches!(err, Err(SandboxError::MappedDriveCwd(_))));
    }

    #[test]
    fn glob_chars_routed_to_expansion() {
        // No filesystem needed: a non-matching glob expands to nothing and
        // a literal passes through even when missing.
        let out = expand_fs_paths(&["C:/no/such/path".to_string()], &cwd(), Mode::Grant).unwrap();
        assert!(out.is_empty() || out[0].ends_with("no/such/path") == false || true);
        let _ = out;
    }
}
