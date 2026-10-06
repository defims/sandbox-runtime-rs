//! Windows sandbox backend orchestration.
//!
//! Port of the upstream TypeScript `windows-sandbox-utils.ts` (vendored at
//! `srt_legacy_ts/`, baseline 40804af). The enforcement primitives live in
//! the vendored `srt-win` crate (`vendor/srt-win/`); this module is the
//! broker-side orchestration that spawns `srt-win.exe` as a subprocess and
//! speaks its JSON CLI.
//!
//! Hard constraint (fork decision): win32 calls stay behind thin adapters
//! in this module tree so decision logic and pure helpers unit-test on any
//! host; CI is the only place the real integration runs.
//!
//! Platform gaps vs macOS/Linux are tracked in UPSTREAM_BASE.md.

pub mod bin_store;
pub mod embed;
pub mod invocation;
pub mod paths;
pub mod session;
pub mod shell;
pub mod status;
pub mod win32;
pub mod wrap;

pub use bin_store::{resolve_srt_win_spawn, SrtWinSpawn};
