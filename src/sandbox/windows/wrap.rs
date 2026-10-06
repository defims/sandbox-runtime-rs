//! Build the native spawn spec for a sandboxed command.
//!
//! Port of TS `wrapCommandWithSandboxWindows`,产出原生 spawn 规格而非
//! shell 字符串(fork 决策 N3):picrab 直接 spawn srt-win,不经外层 bash,
//!(规避双层引号 + MSYS 路径改写)。语义对齐上游:--env overlay 顺序、
//! NO_PROXY/TMPDIR 删除、git safe.directory、30k 命令行上限。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::bin_store::SrtWinSpawn;
use super::paths::check_cwd_sandboxable;
use super::shell::ShellProbe;
use crate::error::SandboxError;

/// CreateProcessW's lpCommandLine cap is 32767 WCHARs; upstream budgets
/// ~30000 to leave quoting headroom.
const CMDLINE_BUDGET: usize = 30_000;

/// Everything needed to wrap one command.
pub struct WrapParams<'a> {
    pub spawn: &'a SrtWinSpawn,
    pub command: &'a str,
    pub shell: &'a ShellProbe,
    /// Broker-relayed host env (picrab passes its FILTERED env — the plan's
    /// N4 decision: relay so API tokens survive, cap on total size).
    pub relay_env: &'a [(String, String)],
    pub http_proxy_port: Option<u16>,
    pub socks_proxy_port: Option<u16>,
    pub deny_read: &'a [String],
    pub deny_write: &'a [String],
    pub cwd: &'a Path,
    /// Session-granted write roots — each becomes a git `safe.directory`.
    pub allow_write: &'a [String],
}

/// Native spawn spec: picrab does `Command::new(program).args(args)` and
/// applies `env` (KEY=VALUE pairs) + `env_removals` on top of its own env.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapOutput {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Env vars to strip from the broker spawn env (defensive: relay sets
    /// never contain these, but a stale caller env might).
    pub env_removals: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// Generate the proxy env overlay for the sandboxed child (localhost TCP).
fn generate_proxy_env(http_port: Option<u16>, socks_port: Option<u16>) -> Vec<(String, String)> {
    let mut env = Vec::new();
    if let Some(port) = http_port {
        let url = format!("http://localhost:{port}");
        for k in ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"] {
            env.push((k.to_string(), url.clone()));
        }
    }
    if let Some(port) = socks_port {
        let url = format!("socks5://localhost:{port}");
        for k in ["ALL_PROXY", "all_proxy"] {
            env.push((k.to_string(), url.clone()));
        }
        // Git over SSH: route through the SOCKS proxy. Git Bash ships no
        // `nc`; use connect.exe from Git for Windows (always present where
        // git is) — proxied by PATH resolution inside the sandbox.
        env.push((
            "GIT_SSH_COMMAND".to_string(),
            format!("ssh -o ProxyCommand=\"connect -S localhost:{port} %h %p\""),
        ));
    }
    env
}

/// git dubious-ownership: the sandbox account doesn't own the working
/// tree, so git refuses it. Upstream threads `safe.directory` entries via
/// GIT_CONFIG_*; compose against the relay set (relay first, gitCfg wins).
fn build_git_config_env(
    base: &mut BTreeMap<String, String>,
    safe_dirs: &[String],
) {
    let mut count = base
        .get("GIT_CONFIG_COUNT")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    for dir in safe_dirs {
        base.insert(format!("GIT_CONFIG_KEY_{count}"), "safe.directory".to_string());
        base.insert(format!("GIT_CONFIG_VALUE_{count}"), dir.clone());
        count += 1;
    }
    base.insert("GIT_CONFIG_COUNT".to_string(), count.to_string());
}

pub fn wrap(p: &WrapParams) -> Result<WrapOutput, SandboxError> {
    check_cwd_sandboxable(p.cwd)?;

    // ── overlay (insertion order = precedence: relay < generated < git) ──
    let mut overlay: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in p.relay_env {
        // Defensive strip: same rationale as upstream — a NO_PROXY match
        // would make clients bypass the proxy and hit the WFP fence; a
        // POSIX TMPDIR breaks msys2 tools.
        if k.eq_ignore_ascii_case("NO_PROXY") || k.eq_ignore_ascii_case("no_proxy") || k == "TMPDIR" {
            continue;
        }
        overlay.insert(k.clone(), v.clone());
    }
    for (k, v) in generate_proxy_env(p.http_proxy_port, p.socks_proxy_port) {
        overlay.insert(k, v);
    }
    let mut safe_dirs: Vec<String> = vec![p.cwd.to_string_lossy().to_string()];
    safe_dirs.extend(p.allow_write.iter().cloned());
    build_git_config_env(&mut overlay, &safe_dirs);

    // ── argv ──
    let mut args: Vec<String> = p.spawn.prepend_args.iter().map(|s| s.to_string()).collect();
    args.push("exec".into());
    args.push("--quiet".into());
    for d in p.deny_read {
        args.push("--deny-read".into());
        args.push(d.clone());
    }
    for d in p.deny_write {
        args.push("--deny-write".into());
        args.push(d.clone());
    }
    for (k, v) in &overlay {
        args.push("--env".into());
        args.push(format!("{k}={v}"));
    }
    args.push("--".into());
    args.push(p.shell.exe.to_string_lossy().to_string());
    for a in &p.shell.args {
        args.push(a.to_string());
    }
    // The command lands as ONE argv element; srt-win's build_cmdline
    // MSVCRT-quotes it so the inner shell receives it intact.
    args.push(p.command.to_string());

    let cmdline_estimate: usize = args.iter().map(|a| a.len() + 3).sum();
    if cmdline_estimate > CMDLINE_BUDGET {
        return Err(SandboxError::CommandLineTooLong {
            len: cmdline_estimate,
        });
    }

    Ok(WrapOutput {
        program: p.spawn.exe.clone(),
        args,
        env_removals: vec![
            "NO_PROXY".into(),
            "no_proxy".into(),
            "TMPDIR".into(),
        ],
        env: overlay.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell() -> ShellProbe {
        ShellProbe {
            exe: PathBuf::from("C:\\Program Files\\Git\\bin\\bash.exe"),
            args: vec!["-c"],
        }
    }

    fn spawn() -> SrtWinSpawn {
        SrtWinSpawn {
            exe: PathBuf::from("C:\\ProgramData\\sandbox-runtime\\bin\\srt-win-x.exe"),
            prepend_args: vec!["--srt-win"],
        }
    }

    #[test]
    fn argv_shape_matches_upstream() {
        let relay = vec![("PATH".to_string(), "C:\\tools".to_string())];
        let out = wrap(&WrapParams {
            spawn: &spawn(),
            command: "echo hi",
            shell: &shell(),
            relay_env: &relay,
            http_proxy_port: Some(60080),
            socks_proxy_port: Some(60081),
            deny_read: &["C:\\proj\\.env".to_string()],
            deny_write: &[],
            cwd: Path::new("C:\\proj"),
            allow_write: &["C:\\proj".to_string()],
        })
        .unwrap();

        let a = &out.args;
        assert_eq!(a[0], "--srt-win");
        assert_eq!(a[1], "exec");
        assert_eq!(a[2], "--quiet");
        assert_eq!(&a[3..5], &["--deny-read".to_string(), "C:\\proj\\.env".to_string()]);
        let dd = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(a[dd + 1], "C:\\Program Files\\Git\\bin\\bash.exe");
        assert_eq!(a[dd + 2], "-c");
        assert_eq!(a[dd + 3], "echo hi");
        assert_eq!(out.program, spawn().exe);
    }

    #[test]
    fn env_overlay_precedence_and_strips() {
        let relay = vec![
            ("PATH".to_string(), "C:\\tools;C:\\Windows".to_string()),
            ("GH_TOKEN".to_string(), "secret".to_string()),
            ("NO_PROXY".to_string(), "localhost".to_string()),
            ("TMPDIR".to_string(), "/tmp".to_string()),
        ];
        let out = wrap(&WrapParams {
            spawn: &spawn(),
            command: "true",
            shell: &shell(),
            relay_env: &relay,
            http_proxy_port: Some(60080),
            socks_proxy_port: Some(60081),
            deny_read: &[],
            deny_write: &[],
            cwd: Path::new("C:\\proj"),
            allow_write: &[],
        })
        .unwrap();

        let env = |k: &str| {
            out.env
                .iter()
                .find(|(ek, _)| ek == k)
                .map(|(_, v)| v.clone())
        };
        // relay survives…
        assert_eq!(env("GH_TOKEN").as_deref(), Some("secret"));
        // …proxy overrides any relay proxy, NO_PROXY/TMPDIR stripped…
        assert_eq!(env("NO_PROXY"), None);
        assert_eq!(env("TMPDIR"), None);
        assert_eq!(env("HTTPS_PROXY").as_deref(), Some("http://localhost:60080"));
        assert_eq!(env("ALL_PROXY").as_deref(), Some("socks5://localhost:60081"));
        // …git safe.directory: cwd first, composed on top.
        let count: u32 = env("GIT_CONFIG_COUNT").unwrap().parse().unwrap();
        assert!(count >= 1);
        assert_eq!(env("GIT_CONFIG_KEY_0").as_deref(), Some("safe.directory"));
        assert_eq!(env("GIT_CONFIG_VALUE_0").as_deref(), Some("C:\\proj"));
        // removals requested for the broker spawn env
        assert!(out.env_removals.contains(&"NO_PROXY".to_string()));
    }

    #[test]
    fn oversized_command_line_rejected() {
        let big = "x".repeat(35_000);
        let err = wrap(&WrapParams {
            spawn: &spawn(),
            command: &big,
            shell: &shell(),
            relay_env: &[],
            http_proxy_port: None,
            socks_proxy_port: None,
            deny_read: &[],
            deny_write: &[],
            cwd: Path::new("C:\\proj"),
            allow_write: &[],
        })
        .unwrap_err();
        assert!(matches!(err, SandboxError::CommandLineTooLong { len: _ }));
    }

    #[test]
    fn unc_cwd_rejected_before_spawn() {
        let err = wrap(&WrapParams {
            spawn: &spawn(),
            command: "true",
            shell: &shell(),
            relay_env: &[],
            http_proxy_port: None,
            socks_proxy_port: None,
            deny_read: &[],
            deny_write: &[],
            cwd: Path::new("//server/share"),
            allow_write: &[],
        })
        .unwrap_err();
        assert!(matches!(err, SandboxError::MappedDriveCwd(_)));
    }
}
