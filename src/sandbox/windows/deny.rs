//! Mandatory dangerous-file DENY discovery for the Windows ACL backend.
//!
//! The unix profile generators emit deny rules from the DANGEROUS_FILES /
//! DANGEROUS_DIRECTORIES lists unconditionally (config/schema.rs). The
//! Windows backend has no rule language — protection comes from concrete
//! DENY stamps — so the granted write roots are WALKED (bounded depth, same
//! `mandatory_deny_search_depth` knob as Linux) and every match becomes a
//! stamp target.

use std::path::{Path, PathBuf};

use crate::config::schema::DANGEROUS_FILES;

/// Hard cap across the whole walk (defence against pathological trees /
/// loops via junctions — depth bound is the primary control).
const MAX_ENTRIES: usize = 50_000;

/// Walk the granted write roots and collect concrete paths to deny-write.
///
/// Returns `(targets, note)` — `note` carries a human hint when the walk
/// hit its entry cap (partial coverage).
pub fn discover_dangerous_targets(
    allow_roots: &[PathBuf],
    search_depth: u32,
    allow_git_config: Option<bool>,
) -> (Vec<PathBuf>, String) {
    let mut targets = Vec::new();
    let mut visited = 0usize;
    let skip_git = allow_git_config.unwrap_or(false);

    for root in allow_roots {
        walk(
            root,
            0,
            search_depth,
            skip_git,
            &mut targets,
            &mut visited,
        );
    }

    let note = if visited >= MAX_ENTRIES {
        format!(" (walk capped at {MAX_ENTRIES} entries — coverage partial)")
    } else {
        String::new()
    };
    (targets, note)
}

fn walk(
    dir: &Path,
    depth: u32,
    max_depth: u32,
    skip_git: bool,
    out: &mut Vec<PathBuf>,
    visited: &mut usize,
) {
    if depth > max_depth || *visited >= MAX_ENTRIES {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    // Deny-write rules for the directory itself, mirroring the unix
    // profile's mandatory rules:
    // - `.git` is denied wholesale (sandboxed commands must not mutate
    //   repo metadata); with `allowGitConfig`, only `.git/hooks`.
    // - editor/agent config dirs (`.vscode`, `.idea`, `.claude/commands`).
    let name = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name == ".git" {
        if skip_git {
            out.push(dir.join("hooks"));
        } else {
            out.push(dir.to_path_buf());
        }
    } else if name == "hooks" {
        // `.git/hooks` matched directly (fires under allowGitConfig trees
        // walked from a .git root).
        let parent_is_git = dir
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().eq_ignore_ascii_case(".git"))
            .unwrap_or(false);
        if parent_is_git {
            out.push(dir.to_path_buf());
        }
    } else if matches!(name.as_str(), ".vscode" | ".idea")
        || (name == "commands"
            && dir
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().eq_ignore_ascii_case(".claude"))
                .unwrap_or(false))
    {
        out.push(dir.to_path_buf());
    }

    for entry in entries.flatten() {
        *visited += 1;
        if *visited >= MAX_ENTRIES {
            return;
        }
        let path = entry.path();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir {
            walk(&path, depth + 1, max_depth, skip_git, out, visited);
        } else if let Some(fname) = path.file_name() {
            let fname = fname.to_string_lossy().to_lowercase();
            if DANGEROUS_FILES.iter().any(|f| f.eq_ignore_ascii_case(&fname)) {
                out.push(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_dangerous_files_and_git_dir() {
        let tmp = std::env::temp_dir().join(format!("srt-deny-{}", std::process::id()));
        let proj = tmp.join("proj");
        let git = proj.join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(proj.join(".npmrc"), b"x").unwrap();
        std::fs::write(proj.join("safe.txt"), b"x").unwrap();
        std::fs::write(proj.join(".BASHRC"), b"case-insensitive match").unwrap();

        let (targets, note) = discover_dangerous_targets(&[proj.clone()], 3, None);
        assert!(note.is_empty());
        let lowered: Vec<String> = targets
            .iter()
            .map(|p| p.to_string_lossy().to_lowercase())
            .collect();
        assert!(lowered.iter().any(|p| p.ends_with("/.git") || p.ends_with("\\.git")));
        assert!(lowered.iter().any(|p| p.ends_with(".npmrc")));
        // ".BASHRC" matches DANGEROUS_FILES' ".bashrc" case-insensitively.
        assert!(lowered.iter().any(|p| p.ends_with(".bashrc")));
        assert!(!lowered.iter().any(|p| p.ends_with("safe.txt")));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn allow_git_config_narrows_to_hooks() {
        let tmp = std::env::temp_dir().join(format!("srt-deny-h-{}", std::process::id()));
        let git = tmp.join(".git");
        std::fs::create_dir_all(git.join("hooks")).unwrap();
        std::fs::write(git.join("config"), b"x").unwrap();

        let (targets, _) = discover_dangerous_targets(&[tmp.join(".")], 3, Some(true));
        let lowered: Vec<String> = targets
            .iter()
            .map(|p| p.to_string_lossy().to_lowercase())
            .collect();
        assert!(lowered.iter().any(|p| p.ends_with("hooks")));
        assert!(!lowered.iter().any(|p| p.ends_with("/.git") || p.ends_with("\\.git")));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn depth_bound_stops_recursion() {
        let tmp = std::env::temp_dir().join(format!("srt-deny-d-{}", std::process::id()));
        let deep = tmp.join("a/b/c/d/e/f");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join(".npmrc"), b"x").unwrap();

        let (targets, _) = discover_dangerous_targets(&[tmp.clone()], 1, None);
        assert!(targets.is_empty());

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
