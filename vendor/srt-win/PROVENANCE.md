# srt-win provenance

Vendored verbatim from `anthropics/sandbox-runtime`, pinned baseline tree:

- upstream repo: https://github.com/anthropics/sandbox-runtime
- commit: `40804af269e1616092e9971de12a1f358f58eba9` (v0.0.75, 2026-09-03)
- path: `vendor/srt-win-src` → vendored here as `vendor/srt-win/`
- includes upstream `Cargo.lock` verbatim (do not regenerate casually; bump
  only through an upstream alignment pass so dependency drift stays reviewable)
- `ci/*.ps1` smoke scripts are kept for the fork's Windows CI to reuse
- license: Apache-2.0 (same project license; see repo NOTICE)

Alignment policy: upstream-watch tracks upstream releases; `vendor/srt-win/`
follows the same monthly alignment diff as `srt_legacy_ts/`, always moving
both to the same upstream tree so the TS orchestration reference and the
helper-crate source never diverge across trees.
