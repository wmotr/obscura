# Local dependency security patch

Source: crates.io `wreq-util` version `3.0.0-rc.12`.
Archive SHA-256: `baa5d2ab72139256916ca352a3d05c53d74e1dd360052eb5ba7691033c417c65`.

The only functional change to the published crate is the normalized
`Cargo.toml` requirement for `zstd`, upgraded from `0.13.3` to `0.14.3`.
`Cargo.toml.orig` preserves the original upstream manifest. Registry bookkeeping
files and upstream-only `.github` automation are omitted.

This resolves RUSTSEC-2026-0391 and allows the patched `zstd-safe` and
`zstd-sys` releases required by RUSTSEC-2026-0398, RUSTSEC-2026-0403 and
RUSTSEC-2026-0410. Keep the existing browser-emulation API and features;
no security advisory is ignored. All upstream Rust source files are unchanged.

Remove this patch when an API-compatible upstream release supports patched
zstd versions. The newer published wreq-util releases still require zstd 0.13
at the time this patch was added.
