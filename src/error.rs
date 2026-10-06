//! Error types for the sandbox runtime.

use thiserror::Error;

/// Main error type for the sandbox runtime.
#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),

    #[error("Missing dependency: {0}")]
    MissingDependency(String),

    #[error("Sandbox execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Proxy error: {0}")]
    Proxy(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Command failed: {0}")]
    CommandFailed(String),

    #[error("Profile generation error: {0}")]
    ProfileGeneration(String),

    #[error("Seccomp error: {0}")]
    Seccomp(String),

    // ── Windows backend ────────────────────────────────────────────────
    #[error("srt-win returned malformed JSON for `{args}`: {detail}")]
    SrtWinBadJson { args: String, detail: String },

    /// One-time elevated install is missing, or the extracted srt-win no
    /// longer matches this build (version drift after an update). The
    /// message carries actionable install instructions.
    #[error("{0}")]
    InstallRequired(String),

    #[error("working directory on a mapped drive is not supported for sandboxing: {0}")]
    MappedDriveCwd(String),

    #[error("sandbox command line too long: ~{len} chars (CreateProcessW limit is 32767)")]
    CommandLineTooLong { len: usize },

    #[error(
        "sandbox env overlay too long: ~{len} chars (CreateProcessW limit is 32767); \
         shorten PATH or drop sandbox.environment entries"
    )]
    EnvTooLarge { len: usize },

    #[error(
        "shell is not readable by the sandbox account: {path}. {hint}"
    )]
    ShellNotReadable { path: String, hint: String },
}

/// Configuration-specific errors.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid domain pattern '{pattern}': {reason}")]
    InvalidDomainPattern { pattern: String, reason: String },

    #[error("Invalid path pattern '{pattern}': {reason}")]
    InvalidPathPattern { pattern: String, reason: String },

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),
}

pub type Result<T> = std::result::Result<T, SandboxError>;
