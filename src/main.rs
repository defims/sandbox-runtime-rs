//! CLI entry point for the sandbox runtime (srt).

#[cfg(unix)]
use std::os::unix::io::FromRawFd;
use std::process::ExitCode;
use std::sync::Arc;

#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, BufReader};
#[cfg(unix)]
use tokio::sync::oneshot;

use sandbox_runtime::cli::Cli;
use sandbox_runtime::config::{load_config, load_config_from_string, load_default_config};
use sandbox_runtime::manager::SandboxManager;
use sandbox_runtime::utils::init_debug_logging;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse_args();

    // Initialize logging
    init_debug_logging(cli.debug);

    // Load configuration
    let config = match cli.get_settings_path() {
        Some(path) if path.exists() => match load_config(&path) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Error loading config from {:?}: {}", path, e);
                return ExitCode::from(1);
            }
        },
        _ => match load_default_config() {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Error loading default config: {}", e);
                return ExitCode::from(1);
            }
        },
    };

    // Get command to execute
    let (command, _shell_mode) = match cli.get_command() {
        Some(cmd) => cmd,
        None => {
            eprintln!("No command specified. Use -c <command> or provide command as arguments.");
            return ExitCode::from(1);
        }
    };

    // Initialize sandbox manager
    let manager = Arc::new(SandboxManager::new());
    if let Err(e) = manager.initialize(config).await {
        eprintln!("Failed to initialize sandbox: {}", e);
        return ExitCode::from(1);
    }

    // Set up control fd for dynamic config updates if specified.
    // Control fds are a Unix parent-child IPC pattern; other platforms
    // ignore the flag with a warning.
    // Shutdown channel for graceful termination of the control fd reader task
    #[cfg(unix)]
    let control_fd_shutdown: Option<oneshot::Sender<()>> = if let Some(fd) = cli.control_fd {
        // Validate fd is non-negative (negative fds are invalid and could cause UB)
        if fd < 0 {
            eprintln!("Invalid control fd: {} (must be non-negative)", fd);
            return ExitCode::from(1);
        }

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let manager_clone = Arc::clone(&manager);
        tokio::spawn(async move {
            // Safety: The control fd is provided by the parent process (typically Claude Code).
            // We trust the parent to pass a valid, open file descriptor. The parent is
            // responsible for ensuring the fd is readable and appropriate for our use.
            // This is a standard Unix pattern for parent-child IPC (similar to stdin/stdout).
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let async_file = tokio::fs::File::from_std(file);
            let reader = BufReader::new(async_file);
            let mut lines = reader.lines();

            tracing::debug!("Listening for config updates on fd {}", fd);

            loop {
                tokio::select! {
                    // Check for shutdown signal first (biased)
                    biased;
                    _ = &mut shutdown_rx => {
                        tracing::debug!("Control fd reader shutting down");
                        break;
                    }
                    result = lines.next_line() => {
                        match result {
                            Ok(Some(line)) => {
                                if let Some(new_config) = load_config_from_string(&line) {
                                    tracing::debug!("Config updated from control fd: {:?}", new_config);
                                    if let Err(e) = manager_clone.update_config(new_config) {
                                        tracing::warn!("Failed to apply config update: {}", e);
                                    }
                                } else if !line.trim().is_empty() {
                                    // Only log non-empty lines that failed to parse
                                    tracing::debug!("Invalid config on control fd (ignored): {}", line);
                                }
                            }
                            Ok(None) => {
                                // EOF reached
                                tracing::debug!("Control fd closed (EOF)");
                                break;
                            }
                            Err(e) => {
                                tracing::debug!("Error reading from control fd: {}", e);
                                break;
                            }
                        }
                    }
                }
            }
        });
        Some(shutdown_tx)
    } else {
        None
    };

    #[cfg(not(unix))]
    let control_fd_shutdown = {
        if cli.control_fd.is_some() {
            eprintln!("Warning: --control-fd is not supported on this platform; ignoring.");
        }
    };

    // Wrap and execute the command
    let wrapped_command = match manager.wrap_with_sandbox(&command, None, None).await {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("Failed to wrap command: {}", e);
            manager.reset().await;
            return ExitCode::from(1);
        }
    };

    tracing::debug!("Wrapped command: {}", wrapped_command);

    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg("-c").arg(&wrapped_command);

    // Inject proxy env vars when the network is restricted, so proxy-aware
    // tools (curl, git, pip...) reach the allowlist filter. With no domain
    // lists configured the profile allows direct egress and no proxy is used.
    // (macOS only here: the srt demo binary wraps through the Seatbelt path;
    // platform-parity wrapping is the manager's job, not this binary's.)
    #[cfg(target_os = "macos")]
    {
        let network_restricted = manager
            .get_config()
            .map(|c| {
                !c.network.allowed_domains.is_empty() || !c.network.denied_domains.is_empty()
            })
            .unwrap_or(false);
        if network_restricted {
            for (k, v) in sandbox_runtime::sandbox::macos::generate_proxy_env(
                manager.get_proxy_port().unwrap_or(0),
                manager.get_socks_proxy_port().unwrap_or(0),
            ) {
                cmd.env(k, v);
            }
        }
    }

    // Execute the wrapped command
    let status = cmd.status().await;

    // Cleanup: signal control fd reader to stop and reset sandbox manager
    #[cfg(unix)]
    if let Some(shutdown_tx) = control_fd_shutdown {
        // Send shutdown signal (ignore error if receiver already dropped)
        let _ = shutdown_tx.send(());
    }
    #[cfg(not(unix))]
    let _ = control_fd_shutdown;
    manager.reset().await;

    match status {
        Ok(status) => {
            if let Some(code) = status.code() {
                ExitCode::from(code as u8)
            } else {
                // Terminated by signal
                ExitCode::from(128)
            }
        }
        Err(e) => {
            eprintln!("Failed to execute command: {}", e);
            ExitCode::from(1)
        }
    }
}
