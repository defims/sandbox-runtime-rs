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
| Windows sandboxing | Deferred | Upstream ships alpha `srt-win`; out of scope until needed. |
| TLS-terminate MITM / parent proxy / credential masking / JVM agent | Deferred | Enterprise features; tracked in gap ledger. |
