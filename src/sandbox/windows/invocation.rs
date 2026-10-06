//! Spawn `srt-win.exe` and parse its JSON CLI results.
//!
//! Port of the TS `runSrtWin*` helpers. All spawns go through here so the
//! sentinel prepend, timeouts, and typed-error parsing stay in one place.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;

use super::bin_store::SrtWinSpawn;
use crate::error::SandboxError;

/// Default per-invocation timeout (TS: 15s; Defender cold-scan can add
/// seconds to the first spawn).
pub const DEFAULT_TIMEOUT_MS: u64 = 15_000;

/// Exit code `srt-win exec` uses for a mapped/network-drive working
/// directory (typed JSON line on stderr — see `parse_typed_error`).
pub const EXIT_MAPPED_DRIVE_CWD: i32 = 16;

pub struct RunResult {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Spawn `srt-win` with `args`, feed `stdin`, wait up to `timeout_ms`.
pub fn run(
    spawn: &SrtWinSpawn,
    args: &[&str],
    stdin: Option<&str>,
    timeout_ms: u64,
) -> Result<RunResult, SandboxError> {
    let mut child = Command::new(&spawn.exe)
        .args(&spawn.prepend_args)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            SandboxError::ExecutionFailed(format!(
                "failed to spawn srt-win at {}: {e}",
                spawn.exe.display()
            ))
        })?;

    if let Some(input) = stdin {
        if let Some(mut pipe) = child.stdin.take() {
            let _ = pipe.write_all(input.as_bytes());
            // Dropping the pipe closes stdin so the child's read sees EOF.
        }
    }

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Reap piped output. Order: take stdout/stderr first.
                use std::io::Read;
                let mut stdout = String::new();
                let mut stderr = String::new();
                if let Some(mut p) = child.stdout.take() {
                    let _ = p.read_to_string(&mut stdout);
                }
                if let Some(mut p) = child.stderr.take() {
                    let _ = p.read_to_string(&mut stderr);
                }
                return Ok(RunResult {
                    status: status.code(),
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SandboxError::ExecutionFailed(format!(
                        "srt-win {:?} timed out after {timeout_ms}ms",
                        args.first().unwrap_or(&"")
                    )));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                return Err(SandboxError::from(e));
            }
        }
    }
}

/// Run + parse a JSON stdout payload; non-zero exit or bad JSON is an error.
pub fn run_json<T: DeserializeOwned>(
    spawn: &SrtWinSpawn,
    args: &[&str],
    stdin: Option<&str>,
    timeout_ms: u64,
) -> Result<T, SandboxError> {
    let out = run(spawn, args, stdin, timeout_ms)?;
    let status = out.status.unwrap_or(-1);
    if status != 0 {
        return Err(SandboxError::ExecutionFailed(format!(
            "srt-win {} exited {status}: {}",
            args.first().unwrap_or(&""),
            summarize(&out.stderr)
        )));
    }
    serde_json::from_str::<T>(out.stdout.trim()).map_err(|e| SandboxError::SrtWinBadJson {
        args: args.join(" "),
        detail: e.to_string(),
    })
}

/// Parse a typed `srt-win exec` failure from its stderr (single JSON line
/// `{"code":…,"message":…}`), mirroring TS `parseWindowsSandboxError`.
/// Call only after gating on a non-zero srt-win exit — the sandboxed
/// child's own stderr is pumped through unchanged.
pub fn parse_typed_error(out: &RunResult) -> Option<SandboxError> {
    for line in out.stderr.lines() {
        let t = line.trim();
        if !t.starts_with('{') || !t.contains("\"code\"") {
            continue;
        }
        if let Ok(j) = serde_json::from_str::<serde_json::Value>(t) {
            if j.get("code").and_then(|c| c.as_str()) == Some("mapped_drive_cwd") {
                let drive = j
                    .get("drive")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                let message = j
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("mapped/network-drive working directory");
                return Some(SandboxError::MappedDriveCwd(if drive.is_empty() {
                    message.to_string()
                } else {
                    format!("{message} ({drive})")
                }));
            }
        }
    }
    None
}

fn summarize(stderr: &str) -> String {
    let t = stderr.trim();
    let mut last = t.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("");
    if last.starts_with("srt-win: error: ") {
        last = &last["srt-win: error: ".len()..];
    }
    last.chars().take(400).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_error_parses_mapped_drive_line() {
        let out = RunResult {
            status: Some(EXIT_MAPPED_DRIVE_CWD),
            stdout: String::new(),
            stderr: "progress line\n{\"code\":\"mapped_drive_cwd\",\"message\":\"mapped/network-drive working directory\",\"drive\":\"Z:\"}\n"
                .to_string(),
        };
        let err = parse_typed_error(&out).expect("typed error");
        assert!(matches!(err, SandboxError::MappedDriveCwd(ref m) if m.contains("Z:")));
    }

    #[test]
    fn typed_error_ignores_child_noise() {
        let out = RunResult {
            status: Some(1),
            stdout: String::new(),
            stderr: "some error {\"code\":\"other\"}\n".to_string(),
        };
        assert!(parse_typed_error(&out).is_none());
    }
}
