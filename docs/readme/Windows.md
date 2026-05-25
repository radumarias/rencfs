# Windows support research

This document captures a practical first path for bringing `rencfs` to native
Windows hosts. It is intentionally written as implementation research, not as a
claim that Windows mounting already works today.

## Recommendation

Use [WinFsp](https://winfsp.dev/) as the first native Windows backend.

Why WinFsp is the best first milestone:

- it is the most mature FUSE-like option on Windows;
- it has an actively maintained Rust crate (`winfsp`);
- it supports drive-letter mounts and directory mount points;
- it maps well to the callback-driven interface that `rencfs` already uses on
  Linux through the `mount` abstraction.

Alternatives considered:

- `Dokan`: viable, but the Rust ecosystem and maintenance story around WinFsp
  looks stronger for a first delivery;
- `Win32` projected file systems (`ProjFS`): useful for virtualization
  scenarios, but not a direct fit for a writable encrypted filesystem;
- `WSL` + Linux FUSE: useful for development, but does not provide a native
  Windows mount experience.

## Licensing checkpoint

Before shipping a Windows backend, confirm the redistribution story around the
WinFsp runtime and installer.

- `rencfs` is dual licensed as `MIT OR Apache-2.0`;
- the Rust crate can be consumed as a Windows-only dependency;
- packaging the WinFsp driver or bundling its installer may introduce
  additional attribution or distribution requirements that should be documented
  in release notes and installer packaging.

The safest first milestone is:

1. require WinFsp to be installed separately on the Windows machine;
2. document the supported WinFsp version;
3. keep the Rust dependency gated behind `cfg(target_os = "windows")`.

## Proposed crate layout

The current `src/mount.rs` split already points to the right shape.

Suggested layout:

- `src/mount/linux.rs`: existing FUSE implementation;
- `src/mount/windows.rs`: native Windows mount bridge;
- `src/mount/dummy.rs`: fallback for unsupported targets;
- `src/mount.rs`: selects the target backend and exposes a stable public API.

The Windows module should wrap the existing `EncryptedFs` layer instead of
re-implementing filesystem logic. That keeps encryption, path handling, file
chunking, and password flow shared across platforms.

## Architecture for `src/mount/windows.rs`

The Windows backend should own:

- a WinFsp filesystem context object;
- a shared `EncryptedFs` instance;
- path conversion helpers between Windows paths and the internal relative path
  model;
- metadata translation helpers between `std::fs::Metadata` and WinFsp file
  info.

High-level shape:

1. initialize WinFsp and validate that the runtime is installed;
2. create a filesystem context holding `Arc<EncryptedFs>`;
3. mount using a drive letter or directory mount point supplied by the CLI;
4. translate WinFsp callbacks into calls on `EncryptedFs`;
5. unmount cleanly and drop the context.

## Callback mapping

The first implementation can target the minimum operations needed for normal
file browsing and small-file editing.

Suggested mapping:

- `create/open`: map to existing open/create flows in `EncryptedFs`;
- `read`: read encrypted chunks, decrypt, and copy into the caller buffer;
- `write`: encrypt and write through the current chunked write path;
- `flush/fsync`: commit buffered state and sync the backing store;
- `get_file_info`: derive file size, timestamps, and kind from stored metadata;
- `read_directory`: list decrypted directory entries and synthesize `.` / `..`
  where required by WinFsp;
- `set_basic_info`: support timestamps and readonly flag if feasible;
- `rename`: use existing rename/move logic on decrypted paths;
- `cleanup/delete`: translate Windows delete-on-close semantics carefully to the
  internal remove operations.

Operations that can be deferred from milestone one:

- alternate data streams;
- file locking beyond what WinFsp requires for correctness;
- reparse points, symlinks, junctions, and hard links;
- named pipes, device files, and other non-regular Unix concepts.

## Windows metadata decisions

The first version should prefer correctness and clarity over perfect NTFS
feature parity.

Recommended decisions:

- support regular files and directories only;
- preserve file size and modification timestamps;
- expose conservative file attributes (`FILE_ATTRIBUTE_DIRECTORY`,
  `FILE_ATTRIBUTE_NORMAL`, readonly when applicable);
- do not claim support for ACL translation in the first milestone;
- document that DOS attributes, EAs, short names, and ADS are unsupported;
- reject unsupported operations with explicit Windows error codes instead of
  silently approximating them.

## Dependency and build shape

Keep all Windows-only code behind target-specific dependencies.

`Cargo.toml` shape:

```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = "..."
windows-sys = "..."
```

Build guidance:

- keep Linux unchanged;
- compile-check Windows code with the `x86_64-pc-windows-msvc` target in CI;
- avoid pulling Windows-specific dependencies on non-Windows hosts;
- prefer runtime loading or documented installation of WinFsp instead of
  hard-coding system paths.

If WinFsp dynamic libraries must be discovered at runtime, document that in the
CLI error shown when the dependency is missing.

## CLI and UX considerations

The native Windows flow should mirror the Linux CLI where possible:

- `rencfs mount --data-dir ... --mount-point X:`;
- accept either a drive root (`X:`) or directory mount point;
- fail early with a friendly message if WinFsp is not installed;
- print an unmount hint in help output and mount success logs.

Un-mount support will likely need a Windows-specific implementation in
`src/mount.rs` rather than calling Unix `umount`.

## CI plan

Suggested phased validation:

1. `cargo check --target x86_64-pc-windows-msvc`;
2. Windows unit tests for path translation and metadata conversion helpers;
3. a GitHub Actions Windows job that installs Rust and WinFsp, then runs smoke
   tests;
4. manual end-to-end validation on a Windows host before claiming production
   support.

## Manual smoke test

Minimum smoke test for a first PR:

1. install WinFsp on Windows 11;
2. build `rencfs` with the MSVC target;
3. initialize an encrypted data directory;
4. mount to a free drive letter;
5. create, read, rename, and delete files from Explorer and PowerShell;
6. copy a nested directory tree in and out of the mount;
7. unmount and remount, then verify files still decrypt correctly.

## Acceptance criteria for a truthful first implementation PR

A first Windows implementation PR should only claim support if it can:

- build on `x86_64-pc-windows-msvc`;
- mount on a native Windows machine with WinFsp installed;
- browse directories from Explorer;
- create, read, overwrite, rename, and delete regular files;
- survive unmount/remount without data corruption;
- clearly document unsupported NTFS features and known limitations.

Anything less should still be valuable, but should be presented as groundwork or
experimental support rather than complete Windows support.
