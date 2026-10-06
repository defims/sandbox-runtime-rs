//! Embed a prebuilt `srt-win.exe` into the crate when the release pipeline
//! provides one, so `windows-install` can extract it to the machine store
//! without shipping a sidecar binary (single-artifact distribution).
//!
//! Pipeline contract: set `SRT_WIN_EXE` to the path of a prebuilt
//! srt-win.exe **for the current target architecture** before building for
//! `*-pc-windows-*` (x64 builds embed the x64 exe, arm64 builds the arm64
//! exe — one arch per binary, matched to the host triple). The env var is
//! visible to dependency build scripts too, but only this crate consumes
//! it. Dev/CI builds without the env get `embedded_srt_win_exe() -> None`
//! and fall back to the `--srt-win` multicall sentinel.

fn main() {
    println!("cargo:rerun-if-env-changed=SRT_WIN_EXE");
    println!("cargo:rustc-check-cfg=cfg(has_embedded_srt_win)");

    // CARGO_CFG_WINDOWS is set by cargo for windows targets regardless of
    // host — the embed must follow the target, not the build host.
    let windows_target = std::env::var("CARGO_CFG_WINDOWS").is_ok();
    if windows_target {
        if let Ok(path) = std::env::var("SRT_WIN_EXE") {
            if !path.is_empty() {
                println!("cargo:rustc-env=SRT_WIN_EMBED={}", path);
                println!("cargo:rustc-cfg=has_embedded_srt_win");
            }
        }
    }
}
