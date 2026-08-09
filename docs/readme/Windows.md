# Windows support

Native Windows mounting is **not implemented yet**. This document records the
research and the implementation plan, and it is intentionally honest about what
works today:

- The project already builds on `windows-latest` (CI matrix includes it).
- `src/mount/windows.rs` is a compile-only adapter: the CLI on Windows reaches
  the mount path and `mount()` fails with a controlled, explicit
  "not implemented" error pointing here.
- A real WinFsp-backed filesystem is the next milestone; nothing here claims it
  works today.

## Recommendation: WinFsp

Use [WinFsp](https://winfsp.dev/) as the native Windows mount backend.

Reasons:

- WinFsp is the maintained Windows equivalent of FUSE: a user-mode filesystem
  host backed by a Windows kernel driver, supporting both drive letters and
  directory mount points.
- The Rust [`winfsp`](https://crates.io/crates/winfsp) crate (winfsp-rs,
  maintained at <https://github.com/SnowflakePowered/winfsp-rs>) provides safe
  bindings and examples. Check crates.io for the current version
  (e.g. `0.13.0+winfsp-2.1`).
- rencfs keeps its existing `EncryptedFs` storage/crypto layer; WinFsp is only
  the mount transport, similar to how `fuse3` is used on Linux.

Alternatives considered and why they are less attractive:

- **Dokan**: viable, but rencfs already has a FUSE-like design that maps more
  directly to WinFsp.
- **WebDAV**: changes filesystem semantics and adds a network server surface.
- **WSL only**: useful for development, but it is not native Windows support.
- **ProjFS**: read-heavy/sparse scenarios; harder to adapt for a fully writable
  encrypted filesystem.

## Licensing checkpoint

WinFsp is **GPLv3 with a FLOSS exception**, and commercial licenses are
available. Because rencfs is `MIT OR Apache-2.0`, this is an explicit maintainer
decision before shipping binaries.

- If rencfs links to or redistributes WinFsp under the FLOSS exception, the
  required attribution must be included in user-facing docs/UI:

  > WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos
  > https://github.com/winfsp/winfsp

- The first implementation milestone can avoid redistribution entirely by
  requiring users (and CI smoke tests) to install WinFsp separately, so the
  dependency is a runtime prerequisite rather than something rencfs bundles.
  This keeps the licensing impact to a documented decision.

## Dependency shape (planned, not yet added)

Add the dependency only for Windows targets. The `winfsp` crate exposes
features for both linking against an installed SDK (`system`) and delay-loading
(`delayload`); delay-loading is friendlier for CI/contributors because the
executable can print a clear runtime error when WinFsp is missing instead of
failing at link time.

```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = { version = "0.13", default-features = false, features = ["delayload"] }

[target.'cfg(target_os = "windows")'.build-dependencies]
winfsp = { version = "0.13", default-features = false, features = ["build"] }
```

The exact feature names must be confirmed against the current `winfsp` crate
docs before adding the dependency. `build.rs` would emit the WinFsp delay-load
link flags via the crate's build helper.

## Module layout

Keep the existing platform split:

```text
src/mount.rs       # backend selection (cfg)
src/mount/linux.rs # fuse3 backend
src/mount/windows.rs # WinFsp backend (currently compile-only stub)
src/mount/dummy.rs # unsupported non-Linux/non-Windows targets
```

`src/mount.rs` selects backends like this:

```rust
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod dummy;
```

Do not add a separate Windows CLI parser. The Linux path already goes through
`run::run()`, Clap, and `create_mount_point()`; reusing it avoids option drift.

## Runtime architecture (planned)

The Windows backend should be a thin adapter around `EncryptedFs`, mirroring
`EncryptedFsFuse3`:

1. `MountPointImpl::new(...)` stores mount options.
2. `MountPointImpl::mount()` creates `EncryptedFs::new(...)` with the supplied
   password provider, cipher, and read-only flag.
3. A WinFsp context owns `Arc<EncryptedFs>` plus a Tokio runtime or runtime
   handle.
4. WinFsp callbacks synchronously bridge into rencfs async methods with one
   controlled runtime boundary.
5. `MountHandleInnerImpl` owns the WinFsp host/service handle and unmounts it in
   `unmount()`.

Pitfalls to avoid:

- Do not create a Tokio runtime per filesystem callback.
- Do not spawn a thread on every `Future::poll`; that leaks threads and can hang.
- Do not return success for unimplemented callbacks. Return explicit Windows
  errors for unsupported operations.
- Do not parse a second ad-hoc Windows CLI; keep Clap as the single interface.

## Operation mapping (planned)

The first useful milestone should support regular files and directories only,
matching the current `FileType` enum.

| WinFsp callback | rencfs `EncryptedFs` method |
|---|---|
| `GetSecurityByName` / `GetFileInfo` | `lookup()` / `get_attr()` |
| `Open` | `open()` (read/write flags from requested access) |
| `Create` | `create()` |
| `Read` | `read()` |
| `Write` | `write()` |
| `Overwrite` / `SetFileSize` | `set_attr()` / `set_len()` |
| `ReadDirectory` | `read_dir_plus()` / `read_dir()` |
| `Rename` | `rename()` |
| `Cleanup` / `Close` | `release()` |
| `Unlink` / `RemoveDirectory` | `remove()` |

Unsupported initially (return explicit unsupported-operation errors):

- reparse points and symlinks;
- alternate data streams;
- extended attributes;
- hard links;
- Windows ACL preservation beyond a simple default descriptor;
- case-insensitive lookup compatibility while encrypted names stay
  case-sensitive.

## Windows metadata decisions (planned)

rencfs stores Unix-style uid/gid/permission bits in `FileAttr`; Windows needs a
small compatibility layer rather than a lossy one-off conversion in each
callback.

Recommended first pass:

- directories -> `FILE_ATTRIBUTE_DIRECTORY`;
- files with no write bit -> `FILE_ATTRIBUTE_READONLY`;
- use `FileAttr::{atime,mtime,ctime,crtime}` for Win32 file times;
- default security descriptor for the mounted volume (owner = current process
  SID; world-readable) instead of round-tripping arbitrary ACLs;
- document that ACL preservation is not part of the first milestone.

## Build and CI plan

The GitHub Actions matrix already runs `cargo build --all-targets
--all-features`, `cargo check --all`, and clippy on `windows-latest`.

1. Keep the Windows build green with the stub (this is the current state).
2. After the real backend lands, add a Windows-only check that the binary
   prints a useful error when WinFsp is not installed.
3. Add a manual smoke-test job/checklist on a runner with WinFsp installed;
   GitHub-hosted Windows runners must not be assumed to have the WinFsp driver.

A local macOS/Linux cross-compile is only an early syntax check: native Windows
dependencies such as `ring` and WinFsp linking need MSVC/Windows SDK behavior.

## Manual smoke test (for the implementation milestone)

On a Windows machine with Rust and WinFsp installed:

```powershell
cargo build --release
mkdir data
$env:RENCFS_PASSWORD = "test-password"
cargo run --release -- mount --mount-point X: --data-dir .\data
```

In another PowerShell session:

```powershell
Set-Content X:\hello.txt "hello"
Get-Content X:\hello.txt
New-Item -ItemType Directory X:\dir
Set-Content X:\dir\nested.txt "nested"
Get-ChildItem X:\ -Recurse
Remove-Item X:\hello.txt
Remove-Item X:\dir\nested.txt
Remove-Item X:\dir
```

Then unmount, mount again with the same password, and verify persisted files
are readable and that `data` contains no plaintext filenames or contents.

## Milestones

1. **Compile-only adapter (done in this PR):** Windows cfg wiring, `windows.rs`
   that reaches the mount path and returns a controlled "not implemented" error,
   CI green on `windows-latest`. No new dependencies.
2. **WinFsp dependency + host skeleton:** add the crate, build flags, and a
   host that starts far enough to fail cleanly per callback.
3. **Read-only filesystem:** lookup, getattr, open, read, directory listing.
4. **Writable regular files:** create, write, truncate, rename, delete, release.
5. **Windows semantics hardening:** file times, read-only attribute, case
   behavior, error-code mapping, cleanup/close behavior, unsupported paths.
6. **Packaging:** installer notes, WinFsp attribution, release validation.

## PR acceptance criteria (for the implementation milestone)

A first implementation PR should be considered ready only when it can
truthfully check these boxes:

- builds on `windows-latest` with the Windows backend enabled;
- does not add a separate Windows CLI surface unless justified;
- unsupported operations return explicit errors, not success placeholders;
- the smoke test above ran on a Windows host with WinFsp installed;
- the PR documents whether WinFsp was linked, delay-loaded, or required at
  runtime;
- AI assistance, if used, is disclosed in the PR body.
