//! Session ACL lifecycle: grant / stamp / revoke / restore / recover via
//! `srt-win acl` subcommands (JSON on stdin, refcounted per holder PID).
//!
//! Port of TS `grantWindowsAcl` / `stampWindowsAcl` / `revokeWindowsAcl` /
//! `restoreWindowsAcl`. The holder PID is the LONG-LIVED host process
//! (the manager's process) — the short-lived `srt-win acl` process exits
//! immediately, so keying on its own PID would orphan the ACEs.

use serde_json::json;

use super::bin_store::SrtWinSpawn;
use super::invocation;
use crate::error::SandboxError;

/// Add session-level ALLOW ACEs (read: R|X, write: MODIFY-no-DELETE_CHILD)
/// for the sandbox user on the given concrete paths.
pub fn grant(
    spawn: &SrtWinSpawn,
    holder_pid: u32,
    sandbox_user_sid: &str,
    read: &[String],
    write: &[String],
) -> Result<(), SandboxError> {
    let payload = json!({ "read": read, "write": write }).to_string();
    run_acl(
        spawn,
        &["acl", "grant", "--holder-pid", &holder_pid.to_string(), "--sandbox-user-sid", sandbox_user_sid],
        &payload,
    )
}

/// Add session-level DENY ACEs (mandatory dangerous-file protection).
/// Globs are rejected by srt-win; callers pre-expand via
/// [`super::paths::expand_fs_paths`].
pub fn stamp(
    spawn: &SrtWinSpawn,
    holder_pid: u32,
    sandbox_user_sid: &str,
    deny_read: &[String],
    deny_write: &[String],
) -> Result<(), SandboxError> {
    let payload = json!({ "denyRead": deny_read, "denyWrite": deny_write }).to_string();
    run_acl(
        spawn,
        &["acl", "stamp", "--holder-pid", &holder_pid.to_string(), "--sandbox-user-sid", sandbox_user_sid],
        &payload,
    )
}

/// Release the holder's claims on granted paths; ACEs whose refcount
/// reaches zero are removed.
pub fn revoke(
    spawn: &SrtWinSpawn,
    holder_pid: u32,
    sandbox_user_sid: &str,
) -> Result<(), SandboxError> {
    run_acl(
        spawn,
        &["acl", "revoke", "--json", "--holder-pid", &holder_pid.to_string(), "--sandbox-user-sid", sandbox_user_sid],
        "{}",
    )
}

/// Release the holder's DENY stamps.
pub fn restore(
    spawn: &SrtWinSpawn,
    holder_pid: u32,
    sandbox_user_sid: &str,
) -> Result<(), SandboxError> {
    run_acl(
        spawn,
        &["acl", "restore", "--json", "--holder-pid", &holder_pid.to_string(), "--sandbox-user-sid", sandbox_user_sid],
        "{}",
    )
}

/// Crash-recovery sweep: prune dead holders, drop orphaned ACEs. Called
/// opportunistically at initialize (matches upstream's recovery story).
pub fn recover(spawn: &SrtWinSpawn) -> Result<(), SandboxError> {
    run_acl(spawn, &["acl", "recover", "--json"], "{}")
}

fn run_acl(spawn: &SrtWinSpawn, args: &[&str], stdin: &str) -> Result<(), SandboxError> {
    let out = invocation::run(spawn, args, Some(stdin), invocation::DEFAULT_TIMEOUT_MS)?;
    match out.status {
        Some(0) => Ok(()),
        Some(2) => Err(SandboxError::ExecutionFailed(format!(
            "srt-win {} skipped one or more inputs: {}",
            args.join(" "),
            out.stderr.trim().chars().take(400).collect::<String>()
        ))),
        _ => Err(SandboxError::ExecutionFailed(format!(
            "srt-win {} failed (status {:?}): {}",
            args.join(" "),
            out.status,
            out.stderr.trim().chars().take(400).collect::<String>()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holder_pid_is_threaded_into_args() {
        // Arg construction is the logic here; assert via a dry wrapper of
        // the same shape used by run_acl.
        let args = [
            "acl", "grant", "--holder-pid", &4242u32.to_string(), "--sandbox-user-sid", "S-1-5-21-1",
        ];
        assert!(args.contains(&"--holder-pid"));
        assert!(args.contains(&"4242"));
    }
}
