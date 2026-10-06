//! CLI parsing and execution.

use std::path::PathBuf;

use clap::Parser;

/// Sandbox Runtime - OS-level sandboxing tool
#[derive(Parser, Debug)]
#[command(name = "srt")]
#[command(about = "Sandbox Runtime - enforce filesystem and network restrictions on processes")]
#[command(version)]
pub struct Cli {
    /// Enable debug logging
    #[arg(short = 'd', long = "debug")]
    pub debug: bool,

    /// Path to settings file (default: ~/.srt-settings.json)
    #[arg(short = 's', long = "settings")]
    pub settings: Option<PathBuf>,

    /// Run command string directly (sh -c mode)
    #[arg(short = 'c')]
    pub command: Option<String>,

    /// Read config updates from file descriptor (JSON lines protocol)
    #[arg(long = "control-fd")]
    pub control_fd: Option<i32>,

    /// One-time elevated Windows install: provisions the sandbox account +
    /// WFP fence (UAC prompt handled by srt-win), then extracts this
    /// build's embedded helper into the machine store. Windows only.
    #[arg(long = "windows-install")]
    pub windows_install: bool,

    /// Remove the WFP filters and (unless --keep-user) the sandbox
    /// account. Windows only.
    #[arg(long = "windows-uninstall")]
    pub windows_uninstall: bool,

    /// Keep the sandbox account on --windows-uninstall.
    #[arg(long = "keep-user")]
    pub keep_user: bool,

    /// Replace an existing install whose port range or sandbox-user name
    /// differs (otherwise the install exits with a conflict).
    #[arg(long)]
    pub force: bool,

    /// Loopback PERMIT range for --windows-install, LOW-HIGH
    /// (default 60080-60089). Must match windows.proxyPortRange in the
    /// config used at run time.
    #[arg(long = "proxy-port-range")]
    pub proxy_port_range: Option<String>,

    /// WFP sublayer GUID override (advanced).
    #[arg(long = "sublayer-guid")]
    pub sublayer_guid: Option<String>,

    /// Sandbox account name override (advanced; must match the config's
    /// windows.sandboxUser at run time).
    #[arg(long = "sandbox-user")]
    pub sandbox_user: Option<String>,

    /// Command and arguments to run
    #[arg(trailing_var_arg = true)]
    pub args: Vec<String>,
}

/// Parse the `LOW-HIGH` proxy port range flag.
pub fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
    let (low, high) = s
        .split_once('-')
        .ok_or_else(|| format!("--proxy-port-range must be LOW-HIGH, got {s:?}"))?;
    let low: u16 = low
        .parse()
        .map_err(|_| format!("--proxy-port-range LOW invalid: {low:?}"))?;
    let high: u16 = high
        .parse()
        .map_err(|_| format!("--proxy-port-range HIGH invalid: {high:?}"))?;
    if low == 0 || low >= high {
        return Err(format!(
            "--proxy-port-range must be LOW<HIGH within 1-65535, got {low}-{high}"
        ));
    }
    Ok((low, high))
}

impl Cli {
    /// Parse CLI arguments.
    pub fn parse_args() -> Self {
        Cli::parse()
    }

    /// Get the command to execute.
    /// Returns (command_string, shell_mode)
    /// - shell_mode = true when using -c flag
    /// - shell_mode = false when using positional args
    pub fn get_command(&self) -> Option<(String, bool)> {
        if let Some(ref cmd) = self.command {
            Some((cmd.clone(), true))
        } else if !self.args.is_empty() {
            // Join args with proper quoting
            let cmd = crate::utils::join_args(&self.args);
            Some((cmd, false))
        } else {
            None
        }
    }

    /// Get the settings file path.
    pub fn get_settings_path(&self) -> Option<PathBuf> {
        self.settings.clone().or_else(crate::config::default_settings_path)
    }
}
