# Testing, benchmarks, and CI

## Test layout

| Location | What |
|---|---|
| `src/crypto/read/test.rs`, `src/crypto/write/test.rs` | crypto stream unit tests |
| `src/encryptedfs/test.rs` | filesystem unit tests |
| `src/keyring.rs` (inline `mod tests`) | keyring tests — need a real OS keyring/secret service |
| `src/test_common.rs` | shared test utilities (crate-private) |
| `tests/rencfs_linux_itest.rs` | Linux integration tests (mount, create/write/read, metadata); setup helpers in `tests/linux_mount_setup/mod.rs` (`TestGuard`, `DATA_PATH`, `MOUNT_PATH`) |
| `tests/cli_passwd_itest.rs` | spawns the binary (`CARGO_BIN_EXE_rencfs`) to check `passwd` subcommand dispatch; uses `setsid` so rpassword's `/dev/tty` prompt fails fast instead of hanging |
| `tests/python/` | pytest scripts exercising real file operations against a mounted fs (copy/move/rename/delete, image/video/PDF integrity) |

Things to know:

- `BLOCK_SIZE` is **100 bytes under `#[cfg(test)]`** (256 KB otherwise) so small files span multiple blocks; `stream_util::BUF_SIZE` also shrinks in tests. Don't write tests that assume the production sizes.
- Benches use nightly `#![feature(test)]` in-tree (`src/crypto/write/bench.rs`, `src/encryptedfs/bench.rs`) plus a criterion bench in `benches/crypto_read.rs` (`harness = false`).
- Integration tests are `#![cfg(target_os = "linux")]` and need FUSE (`/dev/fuse`); in containers add `--device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined`.
- Environment setup for VSCode/Codespaces/containers: `docs/readme/Testing.md`.

## Commands

```bash
cargo test --release --all --all-features
cargo bench --workspace --all-targets --all-features -j 14
```

## Pre-push check script

`scripts/check-before-push.sh` (zsh; `.bat` variant for Windows, `-act.sh` runs GitHub workflows locally via `act`). It runs, for the root crate **and again inside `java-bridge/`**: `cargo fmt`, debug+release builds (`--all-targets --all-features`), `clippy --fix` then strict clippy (with a handful of `-A` allowances), `fmt --check`, `check`, tests, benches, and `cargo doc`. The root pass additionally runs `cargo aur` and `cargo generate-rpm`, so those cargo plugins must be installed for the script to complete.

## CI

`.github/workflows/`: `build_and_tests.yaml` (+ `_reusable`), `package_reusable.yaml`, `release.yaml`, `version_reusable.yaml`, `jekyll-gh-pages.yaml`.
