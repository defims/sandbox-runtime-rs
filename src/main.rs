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
use sandbox_runtime::config::{load_config, load_default_config};
#[cfg(unix)]
use sandbox_runtime::config::load_config_from_string;
use sandbox_runtime::manager::SandboxManager;
use sandbox_runtime::utils::init_debug_logging;

#[tokio::main]
async fn main() -> ExitCode {
    // Multicall dispatch: `argv[1] == --srt-win` routes into the vendored
    // srt-win CLI. Must run before clap sees argv. run_from_args takes the
    // FULL argv and strips the sentinel itself; the sentinel also survives
    // srt-win's internal re-spawns (runner hop, UAC hop), which key on
    // current_exe() — so this dispatcher routes those back too.
    #[cfg(windows)]
    {
        let mut it = std::env::args_os();
        let _argv0 = it.next();
        if it.next().as_deref() == Some(std::ffi::OsStr::new(srt_win::SRT_WIN_DISPATCH_ARG1)) {
            std::process::exit(srt_win::run_from_args(std::env::args_os()));
        }
    }

    let cli = Cli::parse_args();

    // Initialize logging
    init_debug_logging(cli.debug);

    // Windows install/uninstall: provisioning orchestration, no manager.
    // On non-Windows targets these flags are a hard error (fail closed —
    // silently ignoring an install request would mislead automation).
    if cli.windows_install || cli.windows_uninstall {
        #[cfg(not(windows))]
        {
            let _ = (&cli.keep_user, &cli.force);
            eprintln!("--windows-install/--windows-uninstall are Windows-only");
            return ExitCode::from(1);
        }
        #[cfg(windows)]
        {
            let outcome = if cli.windows_install {
                let range = match cli.proxy_port_range.as_deref() {
                    Some(s) => match sandbox_runtime::cli::parse_port_range(s) {
                        Ok(r) => Some(r),
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(1);
                        }
                    },
                    None => None,
                };
                sandbox_runtime::sandbox::windows::install::run_install(
                    &sandbox_runtime::sandbox::windows::install::InstallOptions {
                        sublayer_guid: cli.sublayer_guid.clone(),
                        proxy_port_range: range,
                        sandbox_user: cli.sandbox_user.clone(),
                        force: cli.force,
                    },
                )
            } else {
                sandbox_runtime::sandbox::windows::install::run_uninstall(
                    cli.sublayer_guid.as_deref(),
                    cli.keep_user,
                )
            };
            println!("{}", outcome.message);
            return ExitCode::from(outcome.code as u8);
        }
    }

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
    let wrapped = match manager.wrap_with_sandbox(&command, None, None, &[]).await {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("Failed to wrap command: {}", e);
            manager.reset().await;
            return ExitCode::from(1);
        }
    };

    tracing::debug!("Wrapped command: {:?}", wrapped);

    // Execute, platform-shaped: Windows spawns srt-win natively (the wrap
    // carries its own env overlay); unix runs the shell command line with
    // proxy env injected by the caller.
    #[cfg(windows)]
    let status = match &wrapped {
        sandbox_runtime::manager::WrappedCommand::WindowsSpawn(spec) => {
            let mut c = tokio::process::Command::new(&spec.program);
            c.args(&spec.args);
            c.envs(spec.env.iter().cloned());
            for k in &spec.env_removals {
                c.env_remove(k);
            }
            c.status().await
        }
        sandbox_runtime::manager::WrappedCommand::Shell(s) => {
            let mut c = tokio::process::Command::new("sh");
            c.arg("-c").arg(s);
            c.status().await
        }
    };

    #[cfg(not(windows))]
    let status = {
        let sh = wrapped
            .as_shell()
            .expect("unix wraps are shell-shaped");
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c").arg(sh);

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

        cmd.status().await
    };

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
