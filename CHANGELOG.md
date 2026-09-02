# Changelog

## [0.2.0-defims.1] - 2026-09-03

### Changed (fork takeover)
- Forked from wangyedev/sandbox-runtime-rs v0.1.1 (fa51f05) by defims for
  integration with the picrab coding agent. Relicensed MIT -> Apache-2.0 to
  comply with the upstream Anthropic sandbox-runtime license chain (the
  implementation is a derivative of Apache-2.0 upstream; see NOTICE).
- Vendored the upstream TypeScript snapshot (srt_legacy_ts/, v0.0.75,
  commit 40804af) as the line-level porting reference.
- Added UPSTREAM_BASE.md (alignment baseline + deviation ledger) and
  upstream watch workflow.

### Fixed
- macOS profile: removed the global `(deny file-write-unlink)` rule which
  made deletion impossible inside allowed write directories (rm, git clean,
  temp cleanup). Upstream has no such global rule; mandatory `file-write*`
  denies already cover dangerous paths.
- Domain patterns: bare `*` is now accepted (upstream semantics:
  allow/deny everything); previously rejected by validation.
- macOS: profile temp files now use a unique per-wrap name (pid + seq) so
  concurrent wrap calls cannot overwrite each other's profile.
- CLI: proxy environment variables are now injected on macOS when domain
  lists are non-empty (previously only the Linux bwrap path had them), so
  proxy-aware tools (curl, git, pip...) can actually reach the allowlist.


All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-01-24

### Fixed

- **Control-FD Safety**: Added validation to reject negative file descriptor values with a clear error message
- **WSL Detection**: Fixed case sensitivity bug in WSL version parsing that could cause incorrect byte position indexing
- **Mutex Poisoning**: Cache lookups now recover gracefully if another thread panicked while holding the lock

### Changed

- **Control-FD Handling**: Refactored to use `tokio::select!` with a shutdown channel for graceful task termination
- **Platform Code**: Improved unused variable suppression to only apply on non-Linux platforms using `cfg_attr`
- **Error Logging**: `load_config_from_string()` now logs parsing failures at debug level for better debugging

### Added

- Unit tests for `load_config_from_string()` covering valid JSON, empty strings, invalid JSON, and whitespace handling
- Unit tests for WSL version parsing covering WSL1, WSL2, native Linux, and forward compatibility with future versions
- Documentation for WSL detection explaining the logic and WSL1/WSL2 differences

## [0.1.0] - 2026-01-23

### Added

- Initial release
- OS-level sandboxing for macOS (Seatbelt) and Linux (bubblewrap + seccomp)
- HTTP and SOCKS5 proxy-based network filtering
- Domain allowlist/denylist with wildcard pattern support
- MITM proxy routing for specific domains
- Filesystem read/write restrictions with glob pattern support
- Dynamic configuration updates via control file descriptor
- Mandatory deny paths for security-sensitive files
