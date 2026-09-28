//! Emits the WinFsp delay-load link flags when building for Windows with the
//! `windows-mount` feature.
//!
//! WinFsp only supports delay-loading of its library, so the final binary must
//! be linked with the corresponding `/DELAYLOAD` flag. This mirrors
//! [`winfsp::build::winfsp_link_delayload`](https://docs.rs/winfsp) — it is
//! reimplemented here (without taking `winfsp` as a build dependency) because
//! an optional build-dependency cannot be referenced conditionally from a
//! build script, and because this also works when cross-compiling. The flags
//! emitted by `winfsp-sys` cover the library itself; these apply to every
//! binary target of this crate.

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_abi = std::env::var("CARGO_CFG_TARGET_ABI").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if target_os != "windows" || std::env::var_os("CARGO_FEATURE_WINDOWS_MOUNT").is_none() {
        return;
    }

    let dll = match target_arch.as_str() {
        "x86_64" => "winfsp-x64.dll",
        "x86" => "winfsp-x86.dll",
        "aarch64" => "winfsp-a64.dll",
        other => panic!("unsupported architecture for WinFsp: {other}"),
    };

    match (target_env.as_str(), target_abi.as_str()) {
        ("msvc", _) => {
            println!("cargo:rustc-link-lib=dylib=delayimp");
            println!("cargo:rustc-link-arg=/DELAYLOAD:{dll}");
        }
        // LLVM-MinGW: lld provides the delay-load helper itself
        ("gnu", "llvm") => {
            println!("cargo:rustc-link-arg=-Wl,--delayload={dll}");
        }
        (env, abi) => panic!("unsupported target for WinFsp: env={env} abi={abi}"),
    }
}
