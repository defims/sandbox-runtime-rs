//! Configuration schema types matching the TypeScript Zod schemas.

use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, SandboxError};

/// MITM proxy configuration for routing specific domains through a man-in-the-middle proxy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MitmProxyConfig {
    /// Unix socket path for the MITM proxy.
    pub socket_path: String,
    /// Domains to route through the MITM proxy.
    pub domains: Vec<String>,
}

/// Network restriction configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConfig {
    /// Domains allowed for network access (e.g., "github.com", "*.npmjs.org").
    #[serde(default)]
    pub allowed_domains: Vec<String>,

    /// Domains explicitly denied for network access.
    #[serde(default)]
    pub denied_domains: Vec<String>,

    /// macOS only: Unix socket paths to allow.
    /// Ignored on Linux (seccomp cannot filter by path).
    #[serde(default)]
    pub allow_unix_sockets: Option<Vec<String>>,

    /// If true, allow all Unix sockets (disables blocking on both platforms).
    /// On macOS: allows all socket paths.
    /// On Linux: disables seccomp blocking (sockets are blocked by default).
    #[serde(default)]
    pub allow_all_unix_sockets: Option<bool>,

    /// Allow binding to localhost.
    #[serde(default)]
    pub allow_local_binding: Option<bool>,

    /// External HTTP proxy port.
    #[serde(default)]
    pub http_proxy_port: Option<u16>,

    /// External SOCKS proxy port.
    #[serde(default)]
    pub socks_proxy_port: Option<u16>,

    /// MITM proxy configuration.
    #[serde(default)]
    pub mitm_proxy: Option<MitmProxyConfig>,
}

/// Filesystem restriction configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemConfig {
    /// Paths/patterns denied for reading.
    #[serde(default)]
    pub deny_read: Vec<String>,

    /// Paths allowed for writing.
    #[serde(default)]
    pub allow_write: Vec<String>,

    /// Paths denied for writing (overrides allow_write).
    #[serde(default)]
    pub deny_write: Vec<String>,

    /// Allow writes to .git/config.
    #[serde(default)]
    pub allow_git_config: Option<bool>,

    /// Windows only: paths explicitly granted read+execute for the sandbox
    /// account. The cross-account model has no implicit read (unlike
    /// macOS/Linux same-user sandboxing), so user-profile resources
    /// (`~/.gitconfig`, tool caches, …) need explicit entries here.
    /// Ignored on other platforms.
    #[serde(default)]
    pub allow_read: Vec<String>,
}

/// Windows backend configuration (ignored on other platforms).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WindowsConfig {
    /// WFP sublayer GUID — must match the one the elevated install used,
    /// otherwise the readiness probe reads the wrong filter set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sublayer_guid: Option<String>,

    /// Loopback PERMIT range the WFP filters were installed with, as
    /// `[LOW, HIGH]` (default 60080–60089). The in-process proxies bind
    /// inside this range; a mismatch means fenced clients can't reach the
    /// proxy at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_port_range: Option<(u16, u16)>,

    /// Explicit path to a `srt-win.exe` helper. Overrides the machine-store
    /// copy (which is the exact-hash extraction of this build's embedded
    /// helper).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srt_win_path: Option<std::path::PathBuf>,

    /// Sandbox account name — must match the elevated install (`srt-win`
    /// only manages an account it provisioned). Default `srt-sandbox`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_user: Option<String>,
}

/// Default loopback PERMIT range — must stay in sync with srt-win's
/// install default (`LOW-HIGH` = 60080-60089).
pub const DEFAULT_WINDOWS_PROXY_PORT_RANGE: (u16, u16) = (60080, 60089);

/// Ripgrep configuration for dangerous file discovery on Linux.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RipgrepConfig {
    /// Path to the ripgrep command.
    pub command: String,
    /// Additional arguments.
    #[serde(default)]
    pub args: Option<Vec<String>>,
}

impl Default for RipgrepConfig {
    fn default() -> Self {
        Self {
            command: "rg".to_string(),
            args: None,
        }
    }
}

/// Custom seccomp filter configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SeccompConfig {
    /// Path to custom BPF filter.
    pub bpf_path: Option<String>,
    /// Path to custom apply-seccomp binary.
    pub apply_path: Option<String>,
}

/// Main sandbox runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SandboxRuntimeConfig {
    /// Network restriction configuration.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Filesystem restriction configuration.
    #[serde(default)]
    pub filesystem: FilesystemConfig,

    /// Violation filtering by command pattern.
    #[serde(default)]
    pub ignore_violations: Option<std::collections::HashMap<String, Vec<String>>>,

    /// Enable weaker nested sandbox mode.
    #[serde(default)]
    pub enable_weaker_nested_sandbox: Option<bool>,

    /// Ripgrep configuration.
    #[serde(default)]
    pub ripgrep: Option<RipgrepConfig>,

    /// Search depth for mandatory deny discovery (Linux, default: 3).
    #[serde(default)]
    pub mandatory_deny_search_depth: Option<u32>,

    /// Allow pseudo-terminal (macOS only).
    #[serde(default)]
    pub allow_pty: Option<bool>,

    /// Custom seccomp configuration.
    #[serde(default)]
    pub seccomp: Option<SeccompConfig>,

    /// Windows backend configuration (ignored on other platforms).
    #[serde(default)]
    pub windows: Option<WindowsConfig>,
}

/// Dangerous files that should never be writable.
pub const DANGEROUS_FILES: &[&str] = &[
    ".gitconfig",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".mcp.json",
    ".mcp-settings.json",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
];

/// Dangerous directories that should never be writable.
pub const DANGEROUS_DIRECTORIES: &[&str] = &[
    ".git/hooks",
    ".git",
    ".vscode",
    ".idea",
    ".claude/commands",
];

impl SandboxRuntimeConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), SandboxError> {
        // Validate allowed domains
        for domain in &self.network.allowed_domains {
            validate_domain_pattern(domain)?;
        }

        // Validate denied domains
        for domain in &self.network.denied_domains {
            validate_domain_pattern(domain)?;
        }

        // Validate MITM proxy domains
        if let Some(ref mitm) = self.network.mitm_proxy {
            for domain in &mitm.domains {
                validate_domain_pattern(domain)?;
            }
        }

        // Windows: the proxy bind range must be sane — a mismatch with the
        // WFP install means fenced clients can never reach the proxy.
        if let Some(windows) = &self.windows {
            if let Some((low, high)) = windows.proxy_port_range {
                if low == 0 || low >= high {
                    return Err(ConfigError::ValidationError(format!(
                        "windows.proxyPortRange must be LOW<HIGH within 1-65535, got {low}-{high}"
                    ))
                    .into());
                }
            }
        }

        Ok(())
    }
}

/// Validate a domain pattern.
fn validate_domain_pattern(pattern: &str) -> Result<(), SandboxError> {
    // Check for empty pattern
    if pattern.is_empty() {
        return Err(ConfigError::InvalidDomainPattern {
            pattern: pattern.to_string(),
            reason: "domain pattern cannot be empty".to_string(),
        }
        .into());
    }

    // Bare "*" is valid: upstream sandbox-runtime semantics (allow/deny everything).
    if pattern == "*" {
        return Ok(());
    }

    // Check for too broad patterns like *.com
    if pattern.starts_with("*.") {
        let suffix = pattern.strip_prefix("*").unwrap_or(pattern);
        // Check if suffix is a TLD or too short
        if !suffix.contains('.') && suffix.len() <= 4 {
            return Err(ConfigError::InvalidDomainPattern {
                pattern: pattern.to_string(),
                reason: "pattern is too broad (matches entire TLD)".to_string(),
            }
            .into());
        }
    }

    // Check for port numbers
    if pattern.contains(':') {
        return Err(ConfigError::InvalidDomainPattern {
            pattern: pattern.to_string(),
            reason: "domain patterns cannot include port numbers".to_string(),
        }
        .into());
    }

    // Check for invalid characters
    let check_part = pattern.strip_prefix("*.").unwrap_or(pattern);

    for ch in check_part.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-' && ch != '_' {
            return Err(ConfigError::InvalidDomainPattern {
                pattern: pattern.to_string(),
                reason: format!("invalid character '{}' in domain pattern", ch),
            }
            .into());
        }
    }

    Ok(())
}

/// Check if a hostname matches a domain pattern.
pub fn matches_domain_pattern(hostname: &str, pattern: &str) -> bool {
    // Bare "*" matches everything (upstream sandbox-runtime semantics).
    if pattern == "*" {
        return true;
    }

    let hostname_lower = hostname.to_lowercase();
    let pattern_lower = pattern.to_lowercase();

    if pattern_lower.starts_with("*.") {
        // Wildcard pattern: *.example.com matches api.example.com but NOT example.com
        let base_domain = pattern_lower.strip_prefix("*").unwrap_or(&pattern_lower);
        hostname_lower.ends_with(&format!(".{}", base_domain))
    } else {
        // Exact match
        hostname_lower == pattern_lower
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_pattern_matching() {
        // Exact match
        assert!(matches_domain_pattern("example.com", "example.com"));
        assert!(matches_domain_pattern("EXAMPLE.COM", "example.com"));
        assert!(!matches_domain_pattern("api.example.com", "example.com"));

        // Wildcard match
        assert!(matches_domain_pattern("api.example.com", "*.example.com"));
        assert!(matches_domain_pattern("deep.api.example.com", "*.example.com"));
        assert!(!matches_domain_pattern("example.com", "*.example.com"));

        // Case insensitivity
        assert!(matches_domain_pattern("API.EXAMPLE.COM", "*.example.com"));
    }

    #[test]
    fn test_domain_pattern_validation() {
        // Valid patterns
        assert!(validate_domain_pattern("example.com").is_ok());
        assert!(validate_domain_pattern("*.example.com").is_ok());
        assert!(validate_domain_pattern("localhost").is_ok());
        assert!(validate_domain_pattern("api.github.com").is_ok());
        assert!(validate_domain_pattern("*").is_ok());

        // Invalid patterns
        assert!(validate_domain_pattern("").is_err());
        assert!(validate_domain_pattern("*.com").is_err());
        assert!(validate_domain_pattern("example.com:8080").is_err());
    }

    #[test]
    fn test_bare_wildcard_matching() {
        assert!(matches_domain_pattern("anything.example.com", "*"));
        assert!(matches_domain_pattern("example.com", "*"));
    }
}
