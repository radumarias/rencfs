# CLAUDE.md — java-bridge

JNI bindings exposing rencfs mount functionality to Kotlin/Java (used by the [rencfs-kotlin](https://github.com/radumarias/rencfs-kotlin) example app).

This is a **separate crate** (own `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` — also nightly), not a workspace member of the root crate. It depends on rencfs via `rencfs = { path = "../" }`, so changes to the root crate's public API can break this crate — build both before pushing (`scripts/check-before-push.sh` at the repo root does this).

## Layout

- `src/lib.rs` — all the JNI code. `crate-type = ["cdylib"]`, lib name `java_bridge`.
- Exported JNI functions (Java class `RustLibrary`): `Java_RustLibrary_hello`, `Java_RustLibrary_mount`, `Java_RustLibrary_umount`, `Java_RustLibrary_umountAll`, `Java_RustLibrary_state`.

## Commands

Run from this directory:

```bash
cargo build --release                                  # current target
cargo build --release --target aarch64-linux-android   # Android
cargo test --release --all --all-features
cargo clippy --all-targets --release
```

Same quality bar as the root crate: release profile has `panic = "abort"`, LTO, and treats warnings as errors (`rustflags = ["-Dwarnings"]`).

See `README.md` in this directory for how the resulting `.so` is loaded from Java (`-Djava.library.path=...`).
