# Upstream alignment baseline

This crate is maintained as a line-level Rust port of
[anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime).

## Current baseline

| Field | Value |
|---|---|
| Upstream version | v0.0.75 |
| Upstream commit | 40804af269e1616092e9971de12a1f358f58eba9 |
| Baseline date | 2026-09-03 |
| Vendored snapshot | `srt_legacy_ts/` |

## Alignment policy

- Upstream is the single behavioral authority for semantics covered by the
  port (filesystem rules, domain allow/deny, proxy behavior, mandatory
  denies, platform handling).
- `upstream-watch.yml` checks for new upstream releases daily; security
  fixes are flagged immediately. In-scope behavior changes are batched into
  a monthly alignment pass; out-of-scope changes are recorded below.
  A full review happens quarterly.
- Every alignment run: update the snapshot → evaluate the TS diff → port
  changes → run golden/behavioral regression → update this file → tag
  `aligned-srt-vX.Y.Z`.

## Known deviations (intentional or pending)

| Item | Status | Notes |
|---|---|---|
| Global `(deny file-write-unlink)` in macOS profile | **Removed (fixed)** | Broke `rm`/cleanup inside allowed write dirs; upstream has no such global rule. Mandatory `file-write*` denies already protect dangerous paths. |
| Bare `*` domain pattern rejected | **Fixed** | Upstream allows `*` (allow/deny everything); validator + matcher now accept it. |
| Concurrent profile temp-file overwrite (per-PID name) | **Fixed** | Unique per-wrap filename (pid + seq); cleanup scans by prefix. |
| CLI did not inject proxy env on macOS | **Fixed** | Proxy env injected when domain lists are non-empty. |
| DNS: direct outbound `*:53`/`*:853` allowed in profile | Pending | Upstream resolves DNS proxy-side / via mDNSResponder specifics; direct-DNS is an exfiltration channel. Align during macOS profile depth pass. |
| Blanket `(allow mach-lookup)` | Pending | Broader than upstream's targeted lookups; tighten during macOS profile depth pass. |
| Local DNS resolution fails under restricted network | Pending | Missing mDNSResponder-specific seatbelt rules; proxy-aware tools unaffected (remote resolution). Fail-closed, documented. |
| control-FD dynamic config updates | Deferred | picrab passes per-session static config; no runtime update need. |
| TLS-terminate MITM / parent proxy / credential masking / JVM agent | Deferred | Enterprise features; tracked in gap ledger. |

## Windows backend (implemented 2026-10, baseline v0.0.75)

The Windows orchestration is a behavioral port of upstream
`src/sandbox/windows-sandbox-utils.ts` (blob-verified against 40804af);
enforcement primitives are the vendored `srt-win` crate
(`vendor/srt-win/`, see its PROVENANCE.md). Alignment follows the same
upstream-watch / monthly-diff process, moving `srt_legacy_ts/` and
`vendor/srt-win/` to the same upstream tree each pass.

**Semantic inheritance statement:** the Windows backend inherits this
fork's v0.0.75 semantics WHOLESALE — including the pending deviations
above and the post-baseline upstream fixes (#522 private-range hostname
resolution, #614 write-by-destination, #533 deny precedence). It is not
staler than the macOS/Linux backends; cross-platform fixes flow through
the normal monthly alignment pass and are NOT pre-carried into Windows
only.

### Windows-specific deviations from upstream

| Item | Status | Notes |
|---|---|---|
| Helper distribution: embedded + machine-store extraction | **Deviation (intentional)** | Upstream ships `vendor/srt-win/<arch>/srt-win.exe` inside the npm package; the fork embeds the helper at build time (`SRT_WIN_EXE`) and extracts to `%ProgramData%\sandbox-runtime\bin\srt-win-<sha256>.exe` on install (single-artifact distribution). Exact-hash resolution → version drift surfaces as `InstallRequired`, never a silent contract mismatch. |
| `wrap_with_sandbox` returns `WrappedCommand` (Shell \| WindowsSpawn) | **Deviation (intentional)** | Upstream returns `{argv, env}`; the fork's unix shape stays a command string, Windows returns a native spawn spec (picrab spawns srt-win directly — no outer shell, no double quoting, no MSYS rewriting). |
| Env relay via `relay_env` parameter | **Extension** | Upstream relays only PATH/PATHEXT + mask sentinels + proxy; the fork threads the caller's FILTERED env so user tokens survive the fresh-profile env. Still subject to the 32 767-char command-line cap (`EnvTooLarge`). |
| TLS-terminate (MITM) on Windows | Deferred | `proxy/mitm` path is `#[cfg(unix)]`; a Mitm filter decision returns HTTP 501 on Windows. schannel `user trust-ca` plumbing exists in the vendored helper but is unused until MITM lands. |
| Per-exec `allowRead`/`allowWrite` overrides | Unsupported (parity) | Upstream also rejects them; custom configs may only tighten (deny lists). Session grants come from `initialize()`. |
| Violation store / log monitoring | Inert on Windows | No Seatbelt-log equivalent; `annotate_stderr` surface remains for callers. |
| Shell readability probe | Heuristic (fork) | Path-prefix heuristic (machine roots vs user profile) instead of a DACL walk; WSL shells rejected; typed `ShellNotReadable` errors carry machine-install hints. Runtime `Access denied` remains the enforcement truth. |
| Mandatory deny discovery | Bounded walk (fork) | Concrete DENY stamps require concrete paths: granted roots are walked (depth = `mandatory_deny_search_depth`, 50k-entry cap) matching DANGEROUS_FILES/DIRECTORIES. |
| Broker-side `acl` holder PID | fork manager process | Same contract as upstream (long-lived host owns the refcount). |
