//! `windows-install` / `windows-uninstall` orchestration (fork CLI flavor).
//!
//! Division of labor:
//! - account/group/WFP/registry provisioning is `srt-win install`'s job —
//!   it self-elevates via UAC internally and relays its exit code, so the
//!   fork never touches elevation APIs;
//! - the fork then extracts its OWN embedded helper into the machine bin
//!   dir (unelevated is sufficient: the creating user owns the dir and only
//!   grants the sandbox group read+execute; see bin_store.rs for the trust
//!   note). Same-build hash ⇒ idempotent no-op.
//!
//! Exit codes (mirrors srt-win's contract):
//! 0 installed · 10 UAC cancelled · 12 WFP failed · 13 port-range/user
//! conflict (`--force` to replace) · 14 user provisioning failed · 1 other.

use std::process::Command;

use crate::config::schema::{WindowsConfig, DEFAULT_WINDOWS_PROXY_PORT_RANGE};
use crate::error::SandboxError;

use super::bin_store;
use super::status;

/// std::io errors become `Other` install failures.
impl From<std::io::Error> for InstallError {
    fn from(e: std::io::Error) -> Self {
        InstallError::Other(SandboxError::Io(e))
    }
}

pub const EXIT_OK: i32 = 0;
pub const EXIT_UAC_CANCELLED: i32 = 10;
pub const EXIT_WFP_FAILED: i32 = 12;
pub const EXIT_CONFLICT: i32 = 13;
pub const EXIT_USER_FAILED: i32 = 14;

pub struct InstallOutcome {
    pub code: i32,
    pub message: String,
}

/// Run the full install: provision (elevated via srt-win) + extract our
/// embedded helper + verify. `opts` come from the CLI flags / config.
pub fn run_install(opts: &InstallOptions) -> InstallOutcome {
    match run_install_inner(opts) {
        Ok(msg) => InstallOutcome {
            code: EXIT_OK,
            message: msg,
        },
        Err(InstallError::SrtWin(code, msg)) => InstallOutcome { code, message: msg },
        Err(InstallError::Other(e)) => InstallOutcome {
            code: 1,
            message: e.to_string(),
        },
    }
}

pub struct InstallOptions {
    pub sublayer_guid: Option<String>,
    /// `None` → srt-win's default range.
    pub proxy_port_range: Option<(u16, u16)>,
    pub sandbox_user: Option<String>,
    pub force: bool,
}

enum InstallError {
    SrtWin(i32, String),
    Other(SandboxError),
}

impl From<SandboxError> for InstallError {
    fn from(e: SandboxError) -> Self {
        InstallError::Other(e)
    }
}

fn run_install_inner(opts: &InstallOptions) -> Result<String, InstallError> {
    // 1. Provision through srt-win (it self-elevates; we relay the code).
    let self_exe = std::env::current_exe()?;
    let mut cmd = Command::new(&self_exe);
    cmd.arg(super::bin_store::SRT_WIN_DISPATCH_ARG1).arg("install");
    if let Some(guid) = &opts.sublayer_guid {
        cmd.arg("--sublayer-guid").arg(guid);
    }
    if let Some((low, high)) = opts.proxy_port_range {
        cmd.arg("--proxy-port-range").arg(format!("{low}-{high}"));
    }
    if let Some(user) = &opts.sandbox_user {
        cmd.arg("--sandbox-user").arg(user);
    }
    if opts.force {
        cmd.arg("--force");
    }
    let out = cmd.output().map_err(|e| {
        InstallError::Other(SandboxError::ExecutionFailed(format!(
            "failed to launch srt-win install: {e}"
        )))
    })?;
    let code = out.status.code().unwrap_or(1);
    if code != EXIT_OK {
        let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(InstallError::SrtWin(code, explain_install_exit(code, &detail)));
    }

    // 2. Extract this build's helper into the machine bin dir (idempotent).
    let spawned = bin_store::SrtWinSpawn {
        exe: self_exe,
        prepend_args: vec![bin_store::SRT_WIN_DISPATCH_ARG1],
    };
    let status = status::RawStatus::fetch(&spawned, opts.sublayer_guid.as_deref())?;
    let Some(sid) = status.sandbox_user_sid().map(str::to_string) else {
        return Err(InstallError::SrtWin(
            EXIT_USER_FAILED,
            "install reported success but the sandbox account has no SID".to_string(),
        ));
    };
    let extracted = bin_store::extract_embedded(&sid)?;
    let wfp_note = match status.wfp.state.as_str() {
        "installed" => format!(
            ", WFP filters active ({}, range {:?})",
            status.wfp.filters,
            status.wfp.port_range.map(|(l, h)| (l as u16, h as u16)).unwrap_or(DEFAULT_WINDOWS_PROXY_PORT_RANGE)
        ),
        "cannot-read" => ", WFP state unreadable from this (non-elevated) context — verified at first use"
            .to_string(),
        _ => ", WARNING: WFP filters not visible — sandbox networking will fail closed"
            .to_string(),
    };

    Ok(match extracted {
        Some(path) => format!(
            "installed (sandbox account SID {sid}); helper extracted to {}{wfp_note}",
            path.display()
        ),
        None => format!(
            "installed (sandbox account SID {sid}); no embedded helper in this build — \
             the `--srt-win` multicall sentinel will be used{wfp_note}"
        ),
    })
}

/// Uninstall: drop the WFP filters + account via srt-win (elevated), then
/// best-effort remove our bin-store copies.
pub fn run_uninstall(sublayer_guid: Option<&str>, keep_user: bool) -> InstallOutcome {
    let self_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            return InstallOutcome {
                code: 1,
                message: e.to_string(),
            }
        }
    };
    let mut cmd = Command::new(&self_exe);
    cmd.arg(super::bin_store::SRT_WIN_DISPATCH_ARG1)
        .arg("uninstall");
    if let Some(guid) = sublayer_guid {
        cmd.arg("--sublayer-guid").arg(guid);
    }
    if keep_user {
        cmd.arg("--keep-user");
    }
    let out = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            return InstallOutcome {
                code: 1,
                message: format!("failed to launch srt-win uninstall: {e}"),
            }
        }
    };
    let code = out.status.code().unwrap_or(1);
    if code != EXIT_OK {
        return InstallOutcome {
            code,
            message: explain_install_exit(code, String::from_utf8_lossy(&out.stderr).trim()),
        };
    }
    // Best-effort: remove every extracted helper copy.
    if let Ok(dir) = bin_store::bin_dir() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let _ = std::fs::remove_file(e.path());
            }
        }
        let _ = std::fs::remove_dir(&dir);
    }
    InstallOutcome {
        code: EXIT_OK,
        message: "uninstalled (WFP filters removed; helper copies deleted)".to_string(),
    }
}

fn explain_install_exit(code: i32, detail: &str) -> String {
    let base = match code {
        EXIT_UAC_CANCELLED => "UAC prompt cancelled — install aborted",
        EXIT_WFP_FAILED => "WFP filter installation failed",
        EXIT_CONFLICT => {
            "already installed with a DIFFERENT port range or sandbox-user name; \
             pass --force to replace"
        }
        EXIT_USER_FAILED => "sandbox account provisioning failed",
        _ => "install failed",
    };
    if detail.is_empty() {
        format!("{base} (exit {code})")
    } else {
        format!("{base} (exit {code}): {detail}")
    }
}

impl From<&WindowsConfig> for InstallOptions {
    fn from(cfg: &WindowsConfig) -> Self {
        InstallOptions {
            sublayer_guid: cfg.sublayer_guid.clone(),
            proxy_port_range: cfg.proxy_port_range,
            sandbox_user: cfg.sandbox_user.clone(),
            force: false,
        }
    }
}
