//! Embedded `srt-win.exe` (single-artifact distribution).
//!
//! Release pipelines set `SRT_WIN_EXE` (path to a prebuilt exe matching the
//! current target arch) when building for `*-pc-windows-*`; `build.rs` turns
//! that into the `has_embedded_srt_win` cfg + `SRT_WIN_EMBED` env, which
//! this module turns into bytes. Dev builds without the env get `None` and
//! the `--srt-win` multicall sentinel is the fallback srt-win source.

/// The embedded srt-win.exe, when the release pipeline provided one.
pub fn embedded_srt_win_exe() -> Option<&'static [u8]> {
    #[cfg(has_embedded_srt_win)]
    {
        Some(include_bytes!(env!("SRT_WIN_EMBED")) as &[u8])
    }
    #[cfg(not(has_embedded_srt_win))]
    {
        None
    }
}

/// SHA-256 of the embedded exe (hex, lowercase), used as the machine-store
/// filename discriminator: `srt-win-<sha256>.exe`. Same build ⇒ same hash,
/// so an installed copy matches this broker exactly or is treated as
/// version drift.
pub fn embedded_srt_win_sha256() -> Option<String> {
    embedded_srt_win_exe().map(|bytes| {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(bytes);
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            hex.push(HEX[(byte >> 4) as usize] as char);
            hex.push(HEX[(byte & 0xf) as usize] as char);
        }
        hex
    })
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_stable_hex() {
        // Not embedding anything on unix/dev hosts; the hash helper is only
        // reachable with an embed. Exercise the hex formatting via a
        // deterministic digest instead.
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(b"srt-win");
        let mut hex = String::new();
        for byte in digest {
            hex.push(HEX[(byte >> 4) as usize] as char);
            hex.push(HEX[(byte & 0xf) as usize] as char);
        }
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(hex.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[cfg(has_embedded_srt_win)]
    #[test]
    fn embedded_bytes_expose_hash() {
        assert!(embedded_srt_win_exe().is_some());
        assert_eq!(embedded_srt_win_sha256().unwrap().len(), 64);
    }
}
