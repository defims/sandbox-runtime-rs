//! Readiness probes: single-spawn `srt-win status`, dependency
//! interpretation, WFP egress verification, install instructions.
//!
//! Port of TS `checkWindowsSandboxStatus` / `interpretDependencyProbes` /
//! `verifyWindowsWfpEgress` / `windowsInstallInstructions`.

use serde::Deserialize;

use super::invocation;
use super::bin_store::SrtWinSpawn;
use crate::error::SandboxError;
use crate::sandbox::SandboxDependencyCheck;

/// Raw `srt-win user status` stdout (snake_case; see srt-win cli.rs).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RawUserStatus {
    #[serde(default)]
    pub user: RawUserAccount,
    #[serde(default = "bool_true")]
    pub cred_present: bool,
    #[serde(default)]
    pub marker_version: Option<u32>,
    #[serde(default)]
    pub real_user_sid: Option<String>,
    #[serde(default)]
    pub ca_cert_thumb: Option<String>,
    #[serde(default)]
    pub ca_cert_pem: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RawUserAccount {
    #[serde(default)]
    pub exists: bool,
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub group_exists: bool,
    #[serde(default)]
    pub group_sid: Option<String>,
    #[serde(default)]
    pub in_builtin_users: bool,
    #[serde(default)]
    pub in_sandbox_group: bool,
    #[serde(default)]
    pub hidden_from_logon: bool,
}

fn bool_true() -> bool {
    true
}

/// Raw `srt-win wfp status` stdout.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RawWfpStatus {
    /// `absent` | `installed` | `cannot-read` (BFE enum is admin-gated).
    pub state: String,
    #[serde(default)]
    pub filters: u32,
    #[serde(default)]
    pub port_range: Option<(u32, u32)>,
    #[serde(default)]
    pub user_sid: Option<String>,
    #[serde(default)]
    pub hint: Option<String>,
}

/// Combined single-spawn `srt-win status` output.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RawStatus {
    #[serde(default)]
    pub user: RawUserStatus,
    #[serde(default)]
    pub wfp: RawWfpStatus,
}

impl RawStatus {
    pub fn fetch(
        spawn: &SrtWinSpawn,
        sublayer_guid: Option<&str>,
    ) -> Result<RawStatus, SandboxError> {
        let mut args = vec!["status"];
        if let Some(guid) = sublayer_guid {
            args.push("--sublayer-guid");
            args.push(guid);
        }
        invocation::run_json(spawn, &args, None, invocation::DEFAULT_TIMEOUT_MS)
    }

    /// The dedicated sandbox user's SID (`srt-sandbox`), when provisioned.
    pub fn sandbox_user_sid(&self) -> Option<&str> {
        self.user.user.sid.as_deref()
    }
}

impl RawUserStatus {
    pub fn provisioned(&self) -> bool {
        self.user.exists && self.cred_present
    }
}

/// Install instructions surfaced verbatim in error messages.
/// (Upstream names `npx sandbox-runtime windows-install`; the fork ships
/// the `srt windows-install` CLI instead.)
pub fn install_instructions(sublayer_guid: Option<&str>) -> String {
    let sl = sublayer_guid
        .map(|g| format!(" --sublayer-guid {g}"))
        .unwrap_or_default();
    format!(
        "Windows sandbox needs a one-time install (one UAC prompt):\n  \
         `srt windows-install`\n  \
         — or run `srt-win.exe install{sl}` directly.\n\
         No logout is needed: the WFP filter keys on the dedicated \
         `srt-sandbox` user's SID, so your network is unaffected."
    )
}

/// Interpret the combined status into a `SandboxDependencyCheck`.
/// Port of TS `interpretDependencyProbes`; error strings intentionally
/// mirror the upstream wording.
pub fn interpret_status(status: &RawStatus, sublayer_guid: Option<&str>) -> SandboxDependencyCheck {
    let mut result = SandboxDependencyCheck::default();

    if !status.user.provisioned() {
        result.errors.push(format!(
            "Sandbox user is not provisioned (user={}, cred={}). {}",
            status.user.user.exists,
            status.user.cred_present,
            install_instructions(sublayer_guid)
        ));
    }

    match status.wfp.state.as_str() {
        "cannot-read" => {
            // BFE enumeration is admin-gated; informational only. The
            // behavioral check (`wfp verify`) runs at initialize().
            tracing::debug!(
                "[Sandbox Windows] wfp status cannot-read (non-elevated): {}",
                status.wfp.hint.as_deref().unwrap_or("")
            );
        }
        "installed" => {
            if let Some((low, high)) = status.wfp.port_range {
                tracing::debug!(
                    "[Sandbox Windows] WFP installed: {} filters, proxy port range {low}-{high}",
                    status.wfp.filters
                );
            }
        }
        _ => {
            // 'absent' — only repeat the install instruction when the user
            // error above didn't already give it.
            if status.user.provisioned() {
                result.errors.push(format!(
                    "WFP filters not installed under sublayer {}. {}",
                    sublayer_guid.unwrap_or("(default)"),
                    install_instructions(sublayer_guid)
                ));
            }
        }
    }

    result
}

/// Full dependency probe: one `srt-win status` spawn, interpreted.
pub fn check_dependencies(
    spawn: &SrtWinSpawn,
    sublayer_guid: Option<&str>,
) -> SandboxDependencyCheck {
    match RawStatus::fetch(spawn, sublayer_guid) {
        Ok(status) => interpret_status(&status, sublayer_guid),
        Err(e) => SandboxDependencyCheck {
            errors: vec![format!("srt-win status failed: {e}")],
            warnings: Vec::new(),
        },
    }
}

/// Behavioral WFP fence check (non-elevated): `srt-win wfp verify` spawns
/// a probe as the sandbox user and expects the connect to be BLOCKED.
/// Ok on exit 0 (`blocked`); any other outcome is an error — tri-state is
/// unobservable on the return path, same as upstream.
pub fn verify_wfp_egress(
    spawn: &SrtWinSpawn,
    sublayer_guid: Option<&str>,
    target: &str,
) -> Result<(), SandboxError> {
    let mut args = vec!["wfp", "verify", "--target", target];
    if let Some(guid) = sublayer_guid {
        args.push("--sublayer-guid");
        args.push(guid);
    }
    let out = invocation::run(spawn, &args, None, invocation::DEFAULT_TIMEOUT_MS)?;
    match out.status {
        Some(0) => Ok(()),
        _ => Err(SandboxError::ExecutionFailed(format!(
            "WFP egress verify failed (status {:?}): {}",
            out.status,
            out.stderr.trim().chars().take(300).collect::<String>()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpret_not_provisioned_gives_install_instructions() {
        let raw: RawStatus = serde_json::from_str(
            r#"{"user":{"user":{"exists":false},"cred_present":false},
                "wfp":{"state":"absent","filters":0}}"#,
        )
        .unwrap();
        let check = interpret_status(&raw, None);
        assert_eq!(check.errors.len(), 1);
        assert!(check.errors[0].contains("srt windows-install"));
        assert!(check.errors[0].contains("user=false"));
    }

    #[test]
    fn interpret_absent_wfp_only_repeats_when_user_ok() {
        let raw: RawStatus = serde_json::from_str(
            r#"{"user":{"user":{"exists":true},"cred_present":true},
                "wfp":{"state":"absent","filters":0}}"#,
        )
        .unwrap();
        let check = interpret_status(&raw, None);
        assert_eq!(check.errors.len(), 1);
        assert!(check.errors[0].contains("WFP filters not installed"));
    }

    #[test]
    fn interpret_cannot_read_is_not_an_error() {
        let raw: RawStatus = serde_json::from_str(
            r#"{"user":{"user":{"exists":true,"sid":"S-1-5-21-1"},"cred_present":true},
                "wfp":{"state":"cannot-read","filters":0,"hint":"admin gated"}}"#,
        )
        .unwrap();
        let check = interpret_status(&raw, None);
        assert!(check.errors.is_empty());
        assert!(raw.sandbox_user_sid().is_some());
    }

    #[test]
    fn interpret_installed_is_clean() {
        let raw: RawStatus = serde_json::from_str(
            r#"{"user":{"user":{"exists":true,"sid":"S-1-5-21-1"},"cred_present":true},
                "wfp":{"state":"installed","filters":4,"port_range":[60080,60089]}}"#,
        )
        .unwrap();
        let check = interpret_status(&raw, None);
        assert!(check.errors.is_empty());
        assert!(check.warnings.is_empty());
    }
}
