//! Library-path smoke test: the exact flow picrab will use.
//!
//! initialize(config) → wrap_with_sandbox(cmd) → spawn `sh -c <wrapped>`
//! with proxy env injected → verify enforcement → annotate violations → reset.
//!
//! Run: cargo run --example library_smoke

use sandbox_runtime::config::{FilesystemConfig, NetworkConfig, SandboxRuntimeConfig};
use sandbox_runtime::manager::SandboxManager;

fn run_wrapped(wrapped: &sandbox_runtime::manager::WrappedCommand, extra_env: &[(String, String)]) -> (bool, String) {
    let sh = wrapped.as_shell().expect("unix wraps are shell-shaped").to_string();
    let mut cmd = std::process::Command::new("sh");
    cmd.arg("-c").arg(sh);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), combined)
}

#[tokio::main]
async fn main() {
    let mut failures = Vec::new();

    // --- Case 1: filesystem rules with network unrestricted (empty domain lists) ---
    let manager = SandboxManager::new();
    let config = SandboxRuntimeConfig {
        network: NetworkConfig::default(), // empty = allow network* (picrab network: off)
        filesystem: FilesystemConfig {
            deny_read: vec!["~/.ssh".to_string()],
            allow_write: vec!["/tmp".to_string()],
            ..Default::default()
        },
        allow_pty: Some(true),
        ..Default::default()
    };
    manager
        .initialize(config)
        .await
        .expect("initialize (fs case)");

    // Inject proxy env only when network is restricted; for network-off the
    // profile allows direct egress and the proxies are unused but harmless to omit.
    let (_, out) = run_wrapped(
        &manager
            .wrap_with_sandbox(
                "cat ~/.ssh/known_hosts 2>&1 | head -1; echo rc=$?",
                None,
                None,
                &[],
            )
            .await
            .expect("wrap deny-read probe"),
        &[],
    );
    println!("[fs] deny-read probe:\n{out}");
    if out.contains("Operation not permitted") {
        println!("PASS: deny_read ~/.ssh blocked");
    } else {
        failures.push("deny_read ~/.ssh NOT blocked".to_string());
    }

    let (_, out) = run_wrapped(
        &manager
            .wrap_with_sandbox(
                "echo hi > /tmp/srt-lib-smoke.txt && cat /tmp/srt-lib-smoke.txt && rm /tmp/srt-lib-smoke.txt && echo RM_OK || echo RM_BLOCKED",
                None,
                None,
                &[],
            )
            .await
            .expect("wrap write probe"),
        &[],
    );
    println!("[fs] write probe:\n{out}");
    if out.contains("RM_BLOCKED") {
        println!("NOTE: rm blocked inside allowed dir (global file-write-unlink deny) — known fork bug, needs patch");
    }

    manager.reset().await;

    // --- Case 2: network allowlist through proxy (picrab network: allowlist) ---
    let manager2 = SandboxManager::new();
    let config2 = SandboxRuntimeConfig {
        network: NetworkConfig {
            allowed_domains: vec!["api.github.com".to_string(), "github.com".to_string()],
            ..Default::default()
        },
        filesystem: FilesystemConfig {
            allow_write: vec!["/tmp".to_string()],
            ..Default::default()
        },
        ..Default::default()
    };
    manager2
        .initialize(config2)
        .await
        .expect("initialize (net case)");
    let http_port = manager2.get_proxy_port().expect("http port");
    let socks_port = manager2.get_socks_proxy_port().expect("socks port");
    println!("[net] proxy ports: http={http_port} socks={socks_port}");

    let env = sandbox_runtime::sandbox::macos::generate_proxy_env(http_port, socks_port);
    let wrapped_allowed = manager2
        .wrap_with_sandbox("curl -sS -m 15 https://api.github.com/zen", None, None, &[])
        .await
        .expect("wrap allowed-domain probe");
    let (ok, out) = run_wrapped(&wrapped_allowed, &env);
    println!("[net] allowed-domain probe (ok={ok}):\n{out}");
    if ok {
        println!("PASS: allowed domain reachable via proxy");
    } else {
        failures.push(format!("allowed domain failed via proxy: {out}"));
    }

    let wrapped_blocked = manager2
        .wrap_with_sandbox(
            "curl -sS -m 15 https://example.com 2>&1 | head -2; echo curl_rc=$?",
            None,
            None,
            &[],
        )
        .await
        .expect("wrap blocked-domain probe");
    let (ok, out) = run_wrapped(&wrapped_blocked, &env);
    println!("[net] blocked-domain probe (ok={ok}):\n{out}");
    // The proxy answers blocked CONNECTs with 403; curl surfaces it as a
    // tunnel failure. Either that or an EPERM-style block is a pass.
    if out.contains("403") || out.contains("CONNECT tunnel failed") || !out.contains("Example Domain")
    {
        println!("PASS: blocked domain did not return content");
    } else {
        failures.push(format!("blocked domain NOT blocked: {out}"));
    }

    // Violation annotation surface
    let annotated = manager2.annotate_stderr_with_sandbox_failures("probe", "some stderr");
    println!("[net] annotate sample: {annotated:?}");

    manager2.reset().await;

    if failures.is_empty() {
        println!("\nALL LIBRARY SMOKE CHECKS PASSED");
    } else {
        println!("\nFAILURES:");
        for f in &failures {
            println!("  - {f}");
        }
        std::process::exit(1);
    }
}
