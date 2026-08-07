# Windows support research

Native Windows mounting is **not implemented**. Today:

- Non-Linux targets compile the library through `src/mount/dummy.rs`
  (`MountPointImpl::mount()` returns `FsError::Other("Dummy implementation")`).
- The binary exits early in `src/main.rs` on Windows/macOS with
  `"not yet ready for this platform"`.
- Linux is the only real mount backend (`src/mount/linux.rs` + `fuse3`).

This note is an implementation research contract for a truthful first Windows
milestone. It does **not** claim that rencfs mounts on Windows today.

## Recommendation

Use [WinFsp](https://winfsp.dev/) as the native Windows mount backend, via the
Rust [`winfsp`](https://crates.io/crates/winfsp) crate (`winfsp-rs`).

Reasons:

- WinFsp is the maintained Windows analogue of FUSE: a kernel driver plus a
  user-mode filesystem host.
- rencfs already separates storage/crypto (`EncryptedFs`) from the mount
  adapter (`src/mount/{linux,dummy}.rs`). WinFsp fits that split.
- Drive-letter and directory mounts match Windows user expectations.
- `winfsp` exposes `FileSystemContext` and, with the `async-io` feature,
  `AsyncFileSystemContext`, which can dispatch work onto Tokio.

Alternatives considered and rejected for the first milestone:

| Approach | Why not first |
| --- | --- |
| WSL only | Useful for development; not native Windows support |
| Dokan / dokan-rust | Viable, but WinFsp is closer to the existing FUSE-shaped design and has clearer Rust bindings |
| WebDAV / SMB server | Changes semantics and adds a network attack surface |
| ProjFS | Aimed at virtualization/projection scenarios, not a general encrypted mount |
| `std::fs` / `windows-rs` without a FS driver | Cannot present a real mount point to Explorer and other apps |

## Licensing checkpoint

rencfs is licensed `MIT OR Apache-2.0`.

WinFsp is GPLv3 with a [FLOSS exception](https://github.com/winfsp/winfsp/blob/master/License.txt).
Commercial licenses are also available.

Under the FLOSS exception, linking against the platform WinFsp DLL and/or
redistributing the unmodified WinFsp installer is allowed for FLOSS projects
that:

1. ship under a license that satisfies the Free Software or Open Source
   Definition (MIT and Apache-2.0 qualify);
2. include this attribution in the UI and user-facing docs:

   > WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos  
   > https://github.com/winfsp/winfsp

3. are not linked or distributed with proprietary (non-FLOSS) components.

The Rust `winfsp` crate itself is GPLv3. Treat dependency licensing as an
**explicit maintainer decision** before packaging Windows binaries.

Practical first-milestone stance:

- Require users/CI to install WinFsp separately (no redistribution yet).
- Prefer delay-load so a missing WinFsp install becomes a clear runtime error.
- Add the attribution text to README / Windows docs before any release that
  links WinFsp.
- Revisit redistribution and commercial licensing only at packaging time.

## Proposed dependency shape

Mirror the existing Linux-only `fuse3` dependency pattern in `Cargo.toml`:

```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = { version = "0.13", default-features = false, features = ["delayload", "async-io"] }

[target.'cfg(target_os = "windows")'.build-dependencies]
winfsp = { version = "0.13", default-features = false, features = ["build"] }
```

Add a Windows-aware `build.rs` that calls
`winfsp::build::winfsp_link_delayload()`. The `winfsp` docs state delay-load
link flags are required.

Notes:

- Pin the exact crate/`+winfsp-*` version in the first implementation PR after
  verifying against the installed WinFsp SDK on a Windows host.
- Enable `async-io` so read/write/readdir can use `AsyncFileSystemContext` with
  Tokio (`spawn_task` → `tokio::spawn` / runtime handle).
- Prefer delay-load over the `system` feature for contributor ergonomics: the
  binary can explain that WinFsp is missing instead of failing at link time.
- Keep `fuse3` Linux-only; never pull WinFsp into Linux/macOS builds.

## Module layout

```text
src/mount.rs             # platform-independent MountPoint / MountHandle API
src/mount/linux.rs       # existing fuse3 backend
src/mount/windows.rs     # new WinFsp backend (to add)
src/mount/dummy.rs       # unsupported non-Linux/non-Windows targets
```

`src/mount.rs` selection shape:

```rust
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::{MountHandleInnerImpl, MountPointImpl};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::{MountHandleInnerImpl, MountPointImpl};

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod dummy;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
use dummy::{MountHandleInnerImpl, MountPointImpl};
```

Also open the binary platform gate in `src/main.rs` so Windows reaches
`run::run()` (today `run` is `#[cfg(target_os = "linux")]` only). Reuse the
existing Clap CLI; do not invent a second Windows parser. Mount-point values on
Windows may be drive letters (`X:`) or empty directories — document that in Usage
when the backend lands.

## Runtime architecture

Keep `EncryptedFs` as the single source of truth for inode storage, encryption,
and metadata. The Windows module should be a thin adapter, parallel to
`EncryptedFsFuse3` in `linux.rs`.

Suggested flow:

1. `MountPointImpl::new(...)` stores mount options
   (`mountpoint`, `data_dir`, `password_provider`, `cipher`, flags).
2. `MountPointImpl::mount()` builds `EncryptedFs::new(...)`.
3. A `WindowsEncryptedFs` context owns `Arc<EncryptedFs>` plus a Tokio runtime
   handle and a small path→inode cache.
4. Implement `winfsp::filesystem::FileSystemContext` (and
   `AsyncFileSystemContext` for hot paths).
5. Start a `FileSystemHost` (optionally via `FileSystemServiceBuilder`) and
   mount at the requested point.
6. `MountHandleInnerImpl` owns the host/service and unmounts in `unmount()`.
   `Future` completion should track host teardown the way Linux tracks the
   fuse3 `MountHandle`.

### Path model (important)

WinFsp callbacks are **path-based** (`\foo\bar.txt` as `U16CStr`).
`EncryptedFs` is **inode-based** (`parent` + `SecretString` name), like FUSE.

The Windows adapter must therefore:

1. Normalize Win32 paths (`\` → component walk, reject `..` escape, handle `\`).
2. Resolve components with `EncryptedFs::find_by_name` from `ROOT_INODE` (1).
3. Cache resolved inodes per open `FileContext` so read/write/close do not
   re-walk the path every time.
4. Convert UTF-16 WinFsp names to UTF-8 `SecretString` for rencfs APIs.

### Async bridge

Avoid creating a Tokio runtime per callback and avoid spawning unmanaged
threads on every `poll`. Preferred options, in order:

1. **`AsyncFileSystemContext` + existing Tokio runtime** for read/write/readdir.
2. **One shared multi-thread runtime** with `Handle::block_on` /
   `tokio::task::block_in_place` only where the WinFsp trait is synchronous.
3. Never return success for unimplemented optional callbacks; leave them
   unimplemented so `winfsp` returns `STATUS_INVALID_DEVICE_REQUEST`, or map to
   an explicit Windows status.

## Operation mapping

First milestone: regular files and directories only — matching
`encryptedfs::FileType::{Directory, RegularFile}`.

| WinFsp (`FileSystemContext`) | rencfs (`EncryptedFs`) | Notes |
| --- | --- | --- |
| `get_security_by_name` | `find_by_name` + `get_attr` | Path walk; return default SD + attributes |
| `get_file_info` | `get_attr` | From open `FileContext` inode |
| `open` | `find_by_name` walk + `open` | Derive read/write from `granted_access` |
| `create` | `create` + `CreateFileAttr` | Distinguishes file vs directory via create options |
| `read` / `read_async` | `read` | Offset/length unchanged (256 KiB encrypted blocks help seek) |
| `write` / `write_async` | `write` | Honor `write_to_eof` by using current size |
| `overwrite` | `set_len(0)` / `set_attr` | Then continue writing |
| `set_file_size` | `set_len` | Allocation-size-only requests can no-op or approximate |
| `read_directory` / `read_async` dir | `read_dir_plus` | Fill WinFsp `DirBuffer` / `DirInfo` |
| `rename` | `rename` | Map `replace_if_exists` carefully |
| `set_delete` + `cleanup` | `remove_file` / `remove_dir` | Delete on cleanup when delete-on-close is set — do not delete inside `set_delete` |
| `close` / `cleanup` | `release` / `flush` | Flush writable handles before release |
| `flush` | `flush` | Volume flush (`context = None`) can be a no-op initially |
| `set_basic_info` | `set_attr` | Map times / read-only bit |
| `get_volume_info` | static / stub | Reasonable totals; exact free-space later |

Unsupported in milestone 1 (explicit error or default
`STATUS_INVALID_DEVICE_REQUEST`):

- reparse points / symlinks (not in `FileType` yet);
- alternate data streams (`get_stream_info`);
- extended attributes;
- hard links;
- arbitrary Windows ACL round-tripping (`set_security`);
- case-insensitive lookup if encrypted names remain case-sensitive;
- short 8.3 names;
- opportunistic locks / byte-range locks beyond what WinFsp handles by default.

## Windows metadata decisions

`FileAttr` stores Unix-oriented fields (`uid`, `gid`, `perm`, `nlink`, …).
Windows needs a small compatibility layer, not a lossy conversion scattered
across callbacks.

Recommended first pass:

- Directories → `FILE_ATTRIBUTE_DIRECTORY`.
- Regular files without owner write bit → `FILE_ATTRIBUTE_READONLY`.
- Map `crtime` → creation, `atime` → last access, `mtime` → last write,
  `ctime` → change time.
- Serve a single default security descriptor for the volume; do not claim ACL
  preservation.
- Case sensitivity: document actual behavior. Prefer preserving rencfs
  case-sensitive names and returning not-found on case mismatches rather than
  silently folding case.
- Root inode creation currently uses `libc::getuid()` / `getgid()` only on
  Linux/macOS (`EncryptedFs` init). On Windows, keep the existing `0`/`0`
  defaults (or a documented constant) unless/until a SID mapping exists.
- `allow_root` / `allow_other` are FUSE concepts; on Windows, document them as
  ignored or map later to security-descriptor policy.

## Build and CI plan

`.github/workflows/build_and_tests_reusable.yaml` already runs on
`windows-latest`, but several steps are skipped there. For a Windows
implementation branch:

1. Keep compiling the workspace on `windows-latest`.
2. Once `windows.rs` exists, ensure `cargo build --release` exercises the
   WinFsp-enabled backend (delay-load so runners without WinFsp still link).
3. Add a check that the binary prints a useful error when WinFsp is missing
   (instead of the current unconditional "not yet ready" gate).
4. Do **not** assume GitHub-hosted runners have the WinFsp kernel driver.
   Runtime mount tests stay manual or on a self-hosted/image with WinFsp.
5. Cross-compiling from macOS/Linux is only an early syntax check; MSVC +
   Windows SDK behavior for `ring` and WinFsp is the release evidence.

## Manual smoke test

On a Windows host with Rust nightly (see `rust-toolchain.toml`) and WinFsp
installed (developer files for build if not delay-loading everything):

```powershell
rustup show
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

Then:

1. Unmount cleanly.
2. Mount again with the same password and confirm files persist.
3. Inspect `.\data` and confirm filenames/contents are not plaintext.
4. Repeat a subset with `--read-only` and confirm writes fail clearly.
5. Run without WinFsp installed (or with the driver stopped) and confirm a
   clear runtime error.

## Milestones

1. **Compile-only adapter** — Windows `cfg` wiring, dependency + `build.rs`,
   `windows.rs` implementing `MountPoint`/`MountHandleInner`, WinFsp init that
   fails with a controlled error until callbacks are ready. CI green on
   `windows-latest`.
2. **Read-only filesystem** — path resolve, `get_security_by_name`,
   `get_file_info`, `open`, `read`, `read_directory` against an existing data
   dir.
3. **Writable regular files/dirs** — `create`, `write`, `set_file_size`,
   `rename`, `set_delete`/`cleanup`, `flush`, `close`/`release`.
4. **Windows semantics hardening** — times, read-only attribute, error-code
   map from `FsError` to NTSTATUS, case behavior docs, cleanup correctness.
5. **Packaging** — installer notes, WinFsp attribution, optional redistribution
   review, release validation.

## PR acceptance criteria

A first *implementation* PR (code, not this research note) is ready only when
it can truthfully claim:

- [ ] Builds on `windows-latest` with the Windows backend enabled (delay-load
      acceptable).
- [ ] Reuses `create_mount_point` / Clap; no parallel Windows CLI unless
      justified.
- [ ] Unsupported operations return explicit errors (or WinFsp's default
      invalid-request status), not success placeholders.
- [ ] Path resolution and inode/`FileContext` lifetime are documented in code
      comments or this file.
- [ ] The smoke test above was run on a Windows host with WinFsp installed, and
      results are summarized in the PR.
- [ ] The PR states whether WinFsp is delay-loaded, system-linked, and/or
      redistributed.
- [ ] Licensing/attribution checkpoint is addressed or explicitly deferred with
      maintainer acknowledgement.
- [ ] AI assistance, if used, is disclosed in the PR body.

This research document alone does not satisfy an implementation bounty; it
defines the contract for that work.
