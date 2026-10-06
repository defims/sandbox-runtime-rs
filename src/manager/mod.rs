//! Sandbox manager - main orchestration module.

pub mod filesystem;
pub mod network;
pub mod state;

use std::sync::Arc;

use parking_lot::RwLock;

use crate::config::SandboxRuntimeConfig;
use crate::error::SandboxError;
use crate::utils::{current_platform, check_ripgrep, Platform};
use crate::violation::SandboxViolationStore;

use self::state::ManagerState;

pub use filesystem::{FsReadRestrictionConfig, FsWriteRestrictionConfig};

/// Result of wrapping a command — platform-shaped (fork decision: Windows
/// returns a NATIVE spawn spec instead of a shell string, so picrab spawns
/// srt-win directly and skips the outer bash entirely; that avoids double
/// quoting and MSYS path rewriting).
#[derive(Debug, Clone)]
pub enum WrappedCommand {
    /// macOS/Linux: command line for the caller's `sh -c` (unix shape).
    Shell(String),
    /// Windows: spawn srt-win directly (program + args + env overlay).
    WindowsSpawn(crate::sandbox::windows::wrap::WrapOutput),
}

impl WrappedCommand {
    /// The shell command line, when this is the unix shape.
    pub fn as_shell(&self) -> Option<&str> {
        match self {
            WrappedCommand::Shell(s) => Some(s),
            WrappedCommand::WindowsSpawn(_) => None,
        }
    }
}

/// The sandbox manager - main entry point for sandbox operations.
pub struct SandboxManager {
    state: Arc<RwLock<ManagerState>>,
}

impl Default for SandboxManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxManager {
    /// Create a new sandbox manager.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(ManagerState::new())),
        }
    }

    /// Check if the current platform is supported.
    pub fn is_supported_platform() -> bool {
        current_platform().is_some()
    }

    /// Check if all required dependencies are available.
    pub fn check_dependencies(&self, config: Option<&SandboxRuntimeConfig>) -> Result<(), SandboxError> {
        let platform = current_platform()
            .ok_or_else(|| SandboxError::UnsupportedPlatform("Unsupported platform".to_string()))?;

        // Check platform-specific dependencies
        crate::sandbox::check_dependencies(platform)?;

        // Check ripgrep (optional on macOS, recommended on Linux)
        if platform == Platform::Linux {
            let rg_config = config.and_then(|c| c.ripgrep.as_ref());
            if !check_ripgrep(rg_config) {
                tracing::warn!("ripgrep not found - dangerous file detection will be limited");
            }
        }

        Ok(())
    }

    /// Initialize the sandbox manager with the given configuration.
    pub async fn initialize(&self, config: SandboxRuntimeConfig) -> Result<(), SandboxError> {
        // Validate configuration
        config.validate()?;

        // Check dependencies
        self.check_dependencies(Some(&config))?;

        let platform = current_platform()
            .ok_or_else(|| SandboxError::UnsupportedPlatform("Unsupported platform".to_string()))?;

        // Initialize platform-specific infrastructure.
        //
        // Windows: session ACL grants + mandatory deny stamps happen BEFORE
        // the proxies start (fail fast on install/drift errors); the
        // behavioral WFP fence check runs AFTER them. Proxy ports MUST sit
        // inside the WFP PERMIT range on Windows — an ephemeral port is
        // unreachable from inside the fence.
        let is_windows = platform == Platform::Windows;
        let windows_session = if is_windows {
            Some(crate::sandbox::windows::initialize_session(&config)?)
        } else {
            None
        };

        let port_range = if is_windows {
            Some(
                config
                    .windows
                    .as_ref()
                    .and_then(|w| w.proxy_port_range)
                    .unwrap_or(crate::config::schema::DEFAULT_WINDOWS_PROXY_PORT_RANGE),
            )
        } else {
            None
        };

        // Initialize proxies
        let (http_proxy, socks_proxy) =
            network::initialize_proxies(&config.network, port_range).await?;

        let http_port = http_proxy.port();
        let socks_port = socks_proxy.port();

        // Update state
        let mut state = self.state.write();
        state.http_proxy = Some(http_proxy);
        state.socks_proxy = Some(socks_proxy);
        state.http_proxy_port = Some(http_port);
        state.socks_proxy_port = Some(socks_port);
        state.windows_session = windows_session;

        // Linux: Unix socket bridges for the proxies.
        #[cfg(target_os = "linux")]
        {
            use crate::sandbox::linux::{generate_socket_path, SocatBridge};

            let http_socket_path = generate_socket_path("srt-http");
            let socks_socket_path = generate_socket_path("srt-socks");

            let http_bridge =
                SocatBridge::unix_to_tcp(http_socket_path.clone(), "localhost", http_port).await?;
            let socks_bridge =
                SocatBridge::unix_to_tcp(socks_socket_path.clone(), "localhost", socks_port)
                    .await?;

            state.http_socket_path = Some(http_socket_path.display().to_string());
            state.socks_socket_path = Some(socks_socket_path.display().to_string());
            state.bridges.push(http_bridge);
            state.bridges.push(socks_bridge);
        }

        state.config = Some(config);
        state.initialized = true;
        state.network_ready = true;

        // Windows: behavioral fence verification with the proxies up —
        // a sandbox-account egress probe must come back BLOCKED.
        if is_windows {
            if let Some(sess) = state.windows_session.as_ref() {
                let sublayer = state
                    .config
                    .as_ref()
                    .and_then(|c| c.windows.as_ref())
                    .and_then(|w| w.sublayer_guid.clone());
                crate::sandbox::windows::status::verify_wfp_egress(
                    &sess.spawn,
                    sublayer.as_deref(),
                    // Literal IP: no DNS dependency in the probe itself.
                    "1.1.1.1:443",
                )?;
            }
        }

        tracing::info!(
            "Sandbox manager initialized for {} (HTTP proxy: {}, SOCKS proxy: {})",
            platform.name(),
            http_port,
            socks_port
        );

        Ok(())
    }

    /// Check if the manager is initialized.
    pub fn is_initialized(&self) -> bool {
        self.state.read().initialized
    }

    /// Get the current configuration.
    pub fn get_config(&self) -> Option<SandboxRuntimeConfig> {
        self.state.read().config.clone()
    }

    /// Update the configuration.
    pub fn update_config(&self, config: SandboxRuntimeConfig) -> Result<(), SandboxError> {
        config.validate()?;
        self.state.write().config = Some(config);
        Ok(())
    }

    /// Get the HTTP proxy port.
    pub fn get_proxy_port(&self) -> Option<u16> {
        self.state.read().http_proxy_port
    }

    /// Get the SOCKS proxy port.
    pub fn get_socks_proxy_port(&self) -> Option<u16> {
        self.state.read().socks_proxy_port
    }

    /// Get the HTTP socket path (Linux only).
    #[cfg(target_os = "linux")]
    pub fn get_http_socket_path(&self) -> Option<String> {
        self.state.read().http_socket_path.clone()
    }

    /// Get the SOCKS socket path (Linux only).
    #[cfg(target_os = "linux")]
    pub fn get_socks_socket_path(&self) -> Option<String> {
        self.state.read().socks_socket_path.clone()
    }

    /// Check if network is ready.
    pub fn is_network_ready(&self) -> bool {
        self.state.read().network_ready
    }

    /// Wait for network initialization.
    pub async fn wait_for_network_initialization(&self) -> bool {
        // Already ready in this implementation since we initialize synchronously
        self.is_network_ready()
    }

    /// Get filesystem read restriction config.
    pub fn get_fs_read_config(&self) -> FsReadRestrictionConfig {
        let state = self.state.read();
        if let Some(ref config) = state.config {
            filesystem::process_fs_config(&config.filesystem).0
        } else {
            FsReadRestrictionConfig::default()
        }
    }

    /// Get filesystem write restriction config.
    pub fn get_fs_write_config(&self) -> FsWriteRestrictionConfig {
        let state = self.state.read();
        if let Some(ref config) = state.config {
            filesystem::process_fs_config(&config.filesystem).1
        } else {
            FsWriteRestrictionConfig::default()
        }
    }

    /// Get glob pattern warnings for Linux.
    pub fn get_linux_glob_pattern_warnings(&self) -> Vec<String> {
        #[cfg(target_os = "linux")]
        {
            let state = self.state.read();
            if let Some(ref config) = state.config {
                let mut warnings = Vec::new();
                for path in &config.filesystem.allow_write {
                    if crate::utils::contains_glob_chars(path) {
                        warnings.push(format!(
                            "Glob pattern '{}' is not supported on Linux",
                            path
                        ));
                    }
                }
                for path in &config.filesystem.deny_write {
                    if crate::utils::contains_glob_chars(path) {
                        warnings.push(format!(
                            "Glob pattern '{}' is not supported on Linux",
                            path
                        ));
                    }
                }
                return warnings;
            }
        }
        Vec::new()
    }

    /// Get the violation store.
    pub fn get_violation_store(&self) -> Arc<SandboxViolationStore> {
        self.state.read().violation_store.clone()
    }

    /// Wrap a command with sandbox restrictions.
    ///
    /// `relay_env`: host environment to relay INTO the sandboxed child
    /// (Windows only — the two-hop runner starts from a FRESH profile env,
    /// so callers pass their filtered env here or API tokens etc. vanish).
    /// Ignored on macOS/Linux (children inherit the caller's env there).
    pub async fn wrap_with_sandbox(
        &self,
        command: &str,
        shell: Option<&str>,
        custom_config: Option<SandboxRuntimeConfig>,
        relay_env: &[(String, String)],
    ) -> Result<WrappedCommand, SandboxError> {
        // Extract needed values from state while holding the lock
        let (config, custom_for_windows, http_port, socks_port) = {
            let state = self.state.read();

            if !state.initialized {
                return Err(SandboxError::ExecutionFailed(
                    "Sandbox manager not initialized".to_string(),
                ));
            }

            let merged = custom_config
                .clone()
                .or_else(|| state.config.clone())
                .ok_or_else(|| SandboxError::ExecutionFailed("No configuration available".to_string()))?;

            (merged, custom_config, state.http_proxy_port, state.socks_proxy_port)
        };

        let platform = current_platform()
            .ok_or_else(|| SandboxError::UnsupportedPlatform("Unsupported platform".to_string()))?;

        // Windows: spawn-spec shape. Custom configs may only TIGHTEN
        // (deny lists) — allow grants are session-level (initialize-time
        // ACLs), matching upstream's Windows contract.
        if platform == Platform::Windows {
            let session = {
                let state = self.state.read();
                state
                    .windows_session
                    .clone()
                    .ok_or_else(|| SandboxError::ExecutionFailed(
                        "Windows session not initialized".to_string(),
                    ))?
            };

            let shell_probe = crate::sandbox::windows::shell::parse_bin_shell(shell)?;
            crate::sandbox::windows::shell::probe_shell(&shell_probe.exe)?;

            let (deny_read, deny_write) = match &custom_for_windows {
                None => (Vec::new(), Vec::new()),
                Some(c) => {
                    if !c.filesystem.allow_write.is_empty() || !c.filesystem.allow_read.is_empty()
                    {
                        return Err(SandboxError::ExecutionFailed(
                            "per-exec allow overrides are not supported on Windows; \
                             grants are session-level — put them in the manager config"
                                .to_string(),
                        ));
                    }
                    let cwd = std::env::current_dir()?;
                    (
                        crate::sandbox::windows::paths::expand_fs_paths(
                            &c.filesystem.deny_read,
                            &cwd,
                            crate::sandbox::windows::paths::Mode::Deny,
                        )?,
                        crate::sandbox::windows::paths::expand_fs_paths(
                            &c.filesystem.deny_write,
                            &cwd,
                            crate::sandbox::windows::paths::Mode::Deny,
                        )?,
                    )
                }
            };
            let to_str = |v: Vec<std::path::PathBuf>| {
                v.into_iter().map(|p| p.to_string_lossy().to_string()).collect::<Vec<_>>()
            };
            let deny_read_s = to_str(deny_read);
            let deny_write_s = to_str(deny_write);
            let session_cfg = self.get_config();
            let session_cfg = session_cfg.unwrap_or(config.clone());
            let allow_write_s: Vec<String> =
                session_cfg.filesystem.allow_write.iter().cloned().collect();
            let cwd = std::env::current_dir()?;
            let params = crate::sandbox::windows::wrap::WrapParams {
                spawn: &session.spawn,
                command,
                shell: &shell_probe,
                relay_env,
                http_proxy_port: http_port,
                socks_proxy_port: socks_port,
                deny_read: &deny_read_s,
                deny_write: &deny_write_s,
                cwd: &cwd,
                allow_write: &allow_write_s,
            };
            let out = crate::sandbox::windows::wrap::wrap(&params)?;
            return Ok(WrappedCommand::WindowsSpawn(out));
        }

        // Call platform-specific wrapper
        #[cfg(target_os = "macos")]
        {
            let (wrapped, _log_tag) = crate::sandbox::macos::wrap_command(
                command,
                &config,
                http_port,
                socks_port,
                shell,
                true, // enable log monitor
            )?;
            Ok(WrappedCommand::Shell(wrapped))
        }

        #[cfg(target_os = "linux")]
        {
            let (http_socket, socks_socket) = {
                let state = self.state.read();
                (state.http_socket_path.clone(), state.socks_socket_path.clone())
            };

            let cwd = std::env::current_dir()?;
            let (wrapped, warnings) = crate::sandbox::linux::generate_bwrap_command(
                command,
                &config,
                &cwd,
                http_socket.as_deref(),
                socks_socket.as_deref(),
                http_port.unwrap_or(3128),
                socks_port.unwrap_or(1080),
                shell,
            )?;

            for warning in warnings {
                tracing::warn!("{}", warning);
            }

            Ok(WrappedCommand::Shell(wrapped))
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Err(SandboxError::UnsupportedPlatform(
                "Platform not supported".to_string(),
            ))
        }
    }

    /// Annotate stderr with sandbox failure information.
    pub fn annotate_stderr_with_sandbox_failures(&self, command: &str, stderr: &str) -> String {
        let store = self.get_violation_store();
        let violations = store.get_violations_for_command(command);

        if violations.is_empty() {
            return stderr.to_string();
        }

        let mut annotated = stderr.to_string();
        annotated.push_str("\n\n--- Sandbox Violations ---\n");
        for violation in violations {
            annotated.push_str(&format!("  {}\n", violation.line));
        }

        annotated
    }

    /// Reset the sandbox manager, cleaning up all resources.
    pub async fn reset(&self) {
        // Clean up temp files on macOS
        #[cfg(target_os = "macos")]
        {
            crate::sandbox::macos::cleanup_temp_profiles();
        }

        // Windows: release the session's refcounted ACL claims BEFORE the
        // proxies stop (order irrelevant to correctness, but revoking while
        // the fence is still up matches "session ending" semantics).
        let windows_session = self.state.read().windows_session.clone();
        if let Some(sess) = &windows_session {
            crate::sandbox::windows::release_session(sess);
        }

        let mut state = self.state.write();
        // We need to release the lock before calling async reset
        // So we'll just do the cleanup inline

        // Stop proxies
        if let Some(ref mut proxy) = state.http_proxy {
            proxy.stop();
        }
        if let Some(ref mut proxy) = state.socks_proxy {
            proxy.stop();
        }

        // Stop bridges (Linux)
        #[cfg(target_os = "linux")]
        {
            // Note: We can't call async stop here, so we rely on Drop
            state.bridges.clear();
            state.http_socket_path = None;
            state.socks_socket_path = None;
        }

        // Clear state
        state.http_proxy = None;
        state.socks_proxy = None;
        state.http_proxy_port = None;
        state.socks_proxy_port = None;
        state.config = None;
        state.initialized = false;
        state.network_ready = false;

        tracing::info!("Sandbox manager reset");
    }
}

impl Drop for SandboxManager {
    fn drop(&mut self) {
        // Cleanup is handled by reset() or individual component Drop implementations
    }
}
