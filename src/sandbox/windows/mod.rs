//! Windows sandbox backend orchestration.
//!
//! Port of the upstream TypeScript `windows-sandbox-utils.ts` (vendored at
//! `srt_legacy_ts/`, baseline 40804af). The enforcement primitives live in
//! the vendored `srt-win` crate (`vendor/srt-win/`); this module is the
//! broker-side orchestration that spawns `srt-win.exe` as a subprocess and
//! speaks its JSON CLI.
//!
//! Hard constraint (fork decision): win32 calls stay behind thin adapters
//! in this module tree so decision logic and pure helpers unit-test on any
//! host; CI is the only place the real integration runs.
//!
//! Platform gaps vs macOS/Linux are tracked in UPSTREAM_BASE.md.

pub mod bin_store;
pub mod deny;
pub mod embed;
pub mod install;
pub mod invocation;
pub mod paths;
pub mod session;
pub mod shell;
pub mod status;
pub mod win32;
pub mod wrap;

pub use bin_store::{resolve_srt_win_spawn, SrtWinSpawn};

use crate::config::SandboxRuntimeConfig;
use crate::error::SandboxError;

/// Per-manager Windows session state: the resolved helper, the sandbox
/// account's SID (ACE trustee), and the holder PID that owns the session's
/// refcounted ACEs (this process — the short-lived `srt-win acl` helper
/// exits immediately, so keying on ITS pid would orphan the ACEs).
#[derive(Debug, Clone)]
pub struct WindowsSession {
    pub spawn: SrtWinSpawn,
    pub sandbox_user_sid: String,
    pub holder_pid: u32,
}

/// Windows initialize ACL phase (called by `SandboxManager::initialize`
/// after the dependency check, before proxies): crash-recovery sweep, then
/// session grants (explicit `allow_read` + `allow_write` roots) and the
/// mandatory dangerous-file DENY stamps.
///
/// Proxy startup + the behavioral `wfp verify` remain the manager's job
/// (async / fence ordering).
pub fn initialize_session(config: &SandboxRuntimeConfig) -> Result<WindowsSession, SandboxError> {
    let win_cfg = config.windows.clone().unwrap_or_default();
    let spawn = resolve_srt_win_spawn(win_cfg.srt_win_path.as_deref())?;
    let status = status::RawStatus::fetch(&spawn, win_cfg.sublayer_guid.as_deref())?;
    let sid = status
        .sandbox_user_sid()
        .ok_or_else(|| {
            SandboxError::InstallRequired(status::install_instructions(
                win_cfg.sublayer_guid.as_deref(),
            ))
        })?
        .to_string();

    // Crash-recovery sweep: prune dead holders before claiming ours.
    let _ = session::recover(&spawn);

    let cwd = std::env::current_dir()?;
    let depth = config.mandatory_deny_search_depth.unwrap_or(3);

    let read_grants = paths::expand_fs_paths(&config.filesystem.allow_read, &cwd, paths::Mode::Grant)?;
    let write_grants =
        paths::expand_fs_paths(&config.filesystem.allow_write, &cwd, paths::Mode::Grant)?;

    // Mandatory dangerous-file discovery walks the granted roots (bounded —
    // same knob as the Linux backend).
    let (mut deny_writes, deny_roots_note) =
        deny::discover_dangerous_targets(&write_grants, depth, config.filesystem.allow_git_config);
    tracing::debug!(
        "[Sandbox Windows] mandatory deny discovery: {} write targets{}",
        deny_writes.len(),
        deny_roots_note
    );
    deny_writes.extend(paths::expand_fs_paths(
        &config.filesystem.deny_write,
        &cwd,
        paths::Mode::Deny,
    )?);
    let deny_reads = paths::expand_fs_paths(&config.filesystem.deny_read, &cwd, paths::Mode::Deny)?;

    session::grant(
        &spawn,
        std::process::id(),
        &sid,
        &to_strings(&read_grants),
        &to_strings(&write_grants),
    )?;
    session::stamp(
        &spawn,
        std::process::id(),
        &sid,
        &to_strings(&deny_reads),
        &to_strings(&deny_writes),
    )?;

    Ok(WindowsSession {
        spawn,
        sandbox_user_sid: sid,
        holder_pid: std::process::id(),
    })
}

/// Release this manager's session claims (grants + deny stamps). Called by
/// `reset()`; best-effort — a failure is logged, not fatal (the crash-
/// recovery sweep at the next initialize prunes dead holders anyway).
pub fn release_session(sess: &WindowsSession) {
    if let Err(e) = session::revoke(&sess.spawn, sess.holder_pid, &sess.sandbox_user_sid) {
        tracing::warn!("[Sandbox Windows] acl revoke failed: {e}");
    }
    if let Err(e) = session::restore(&sess.spawn, sess.holder_pid, &sess.sandbox_user_sid) {
        tracing::warn!("[Sandbox Windows] acl restore failed: {e}");
    }
}

fn to_strings(paths: &[std::path::PathBuf]) -> Vec<String> {
    paths.iter().map(|p| p.to_string_lossy().to_string()).collect()
}
