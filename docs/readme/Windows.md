# Windows support research

This note is implementation research for native Windows support. It is not a
claim that rencfs can mount on Windows today.

Current state:

- `src/main.rs` exits early on Windows.
- `src/mount.rs` routes every non-Linux target to `src/mount/dummy.rs`.
- `fuse3` is declared only under `target_os = "linux"` in `Cargo.toml`.
- The reusable `EncryptedFs` layer already owns the encrypted namespace, file
  handles, metadata, reads, writes, truncation, directory iteration, rename, and
  removal operations that a Windows backend should call.

## Recommended backend

Use WinFsp through the Rust `winfsp` crate for the first native implementation.

Reasons:

- WinFsp is the established userspace file system bridge for Windows. Its
  project describes the stack as a kernel mode file system driver plus a user
  mode DLL, so rencfs can stay in user mode rather than shipping a kernel driver.
- WinFsp exposes a native Windows API and FUSE compatibility APIs. The native API
  is the better fit for a new Windows backend because it models Windows file
  system semantics directly, including UTF-16 names, Windows deletion behavior,
  security descriptors, reparse points, alternate data streams, and volume info.
- The Rust `winfsp` crate provides a `FileSystemContext` trait and
  `FileSystemHost` lifecycle instead of requiring rencfs to maintain raw FFI for
  `FSP_FILE_SYSTEM_INTERFACE`.
- The crate documents the required delay-load link step via
  `winfsp::build::winfsp_link_delayload()`, which fits a Windows-only dependency
  and build shape.

Alternatives considered:

- WinFsp FUSE compatibility layer: useful for porting a FUSE implementation, but
  it hides Windows-specific semantics behind a POSIX-shaped API. rencfs already
  has a clean internal filesystem layer, so a native adapter is preferable.
- Dokany: another userspace filesystem option, but it would add a different API
  surface and does not have the same direct path from current Rust `winfsp`
  bindings to Windows filesystem operations.
- Network redirector / SMB loopback: would avoid a local filesystem driver
  dependency, but it changes behavior and deployment enough that it should not be
  the first native mount path.
- Kernel driver: out of scope. rencfs should keep crypto and filesystem logic in
  a user-mode process.

References:

- WinFsp overview: https://github.com/winfsp/winfsp
- Native API versus FUSE: https://winfsp.dev/doc/Native-API-vs-FUSE/
- Rust `winfsp` crate: https://docs.rs/winfsp/latest/winfsp/
- `FileSystemContext` callbacks: https://docs.rs/winfsp/latest/winfsp/filesystem/trait.FileSystemContext.html

## Licensing checkpoint

rencfs is licensed as `MIT OR Apache-2.0`. WinFsp itself is GPLv3 with a special
exception for Free/Libre and Open Source Software, and the project also offers a
commercial license. The Rust `winfsp` crate is listed as GPL-3.0 on docs.rs.

Before merging a Windows backend, confirm and document:

- whether depending on the `winfsp` crate is acceptable for a project published
  as `MIT OR Apache-2.0`;
- whether the WinFsp FOSS exception covers the intended rencfs distribution
  model, including binary releases;
- what attribution, installer notice, and third-party license files are needed;
- whether a commercial WinFsp license is needed for any official binary release
  path.

Until that review is complete, prefer a feature-gated experimental branch or a
source-only proof of concept over claiming supported Windows releases.

## Dependency and build shape

Add Windows-only dependencies so non-Windows builds remain unchanged:

```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = "0.13"
windows = { version = "...", features = ["Win32_Foundation", "Win32_Storage_FileSystem"] }
```

The exact `windows` crate version should match the version selected by `winfsp`
or be avoided if the backend can use `winfsp` re-exports.

Add a `build.rs` only when the Windows backend is introduced:

```rust
fn main() {
    #[cfg(target_os = "windows")]
    winfsp::build::winfsp_link_delayload();
}
```

Expected module routing:

```rust
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod dummy;
```

The Windows `MountPointImpl` should implement the existing `MountPoint` trait so
callers still use `create_mount_point`. The backend should own a WinFsp host and
return a `MountHandle` that stops the host during `unmount`.

## Proposed architecture

Create `src/mount/windows.rs` with these pieces:

- `MountPointImpl`: stores mountpoint, data directory, password provider, cipher,
  and read-only flag. `allow_root` and `allow_other` are Linux/FUSE concepts and
  should be accepted for CLI compatibility but ignored or rejected with a clear
  warning on Windows.
- `EncryptedFsWinFsp`: wraps `Arc<EncryptedFs>` and implements
  `winfsp::filesystem::FileSystemContext`.
- `WinFileContext`: per-open handle state containing inode, rencfs handle id,
  granted read/write permissions, directory state if needed, and delete-on-close
  state.
- path conversion helpers: convert WinFsp UTF-16 paths into rencfs path segments,
  then resolve through repeated `find_by_name` calls. Keep this separate from
  crypto and from WinFsp callback code.
- metadata conversion helpers: convert between `FileAttr` and WinFsp file info,
  including Windows FILETIME values.
- error conversion helpers: map `FsError` and `io::ErrorKind` to NTSTATUS values.

The Linux backend uses inode-based FUSE callbacks. WinFsp callbacks are
path-oriented at open/create time and handle-oriented afterward. The Windows
adapter should resolve names to rencfs inodes at open/create, then store the
inode and rencfs file handle in `WinFileContext`.

The first implementation should preserve rencfs invariants:

- all plaintext names passed into `EncryptedFs` remain `SecretString` values;
- all file data goes through `EncryptedFs::read`, `write`, `flush`, and
  `release`;
- no backend writes plaintext or decrypted metadata outside the mounted view;
- read-only mode is enforced in the Windows backend before calling mutating
  `EncryptedFs` methods.

## Operation mapping

Initial callback mapping:

| WinFsp operation | rencfs call path |
| --- | --- |
| `get_security_by_name` | Resolve path with `find_by_name`; return basic file attributes and a minimal security descriptor. |
| `open` | Resolve path; call `EncryptedFs::open(ino, read, write)` for files; create a directory context for directories. |
| `create` | Resolve parent path; call `EncryptedFs::create(parent, name, attr, read, write)`. |
| `close` | Call `EncryptedFs::release(handle)` for file handles. |
| `cleanup` / delete-on-close | If delete is requested, call `remove_file` or `remove_dir` after the handle lifecycle rules allow it. |
| `flush` | Call `EncryptedFs::flush(handle)` for file handles; no-op for volume flush until a backing store flush API exists. |
| `get_file_info` | Call `EncryptedFs::get_attr(ino)` and convert to WinFsp file info. |
| `read` | Call `EncryptedFs::read(ino, offset, len, handle)`. |
| `write` | Call `EncryptedFs::write(ino, offset, buffer, handle)`; reject writes in read-only mode. |
| `set_file_size` | Call `EncryptedFs::set_len(ino, new_size)` unless this is allocation-size-only metadata. |
| `set_basic_info` | Convert Windows times and attributes into `SetFileAttr`; ignore unsupported allocation-only changes. |
| `read_directory` | Call `EncryptedFs::read_dir_plus(ino)` and fill the WinFsp directory buffer, including `.` and `..` if WinFsp expects them. |
| `get_dir_info_by_name` | Resolve child with `find_by_name`; return converted metadata. |
| `rename` | Resolve old and new parent/name pairs; call `EncryptedFs::rename`. |
| `overwrite` | Truncate or update attributes via `set_len` and `set_attr` according to requested disposition. |
| `get_volume_info` | Return static or configured volume values similar to Linux `STATFS`, with an honest capacity story. |

Unsupported in the first milestone:

- alternate data streams;
- reparse points, symbolic links, junctions, and hard links;
- Windows ACL persistence beyond a minimal descriptor required by WinFsp;
- extended attributes;
- named pipes, device nodes, sockets, and other non-regular-file types;
- case-insensitive duplicate prevention beyond whatever the first path resolver
  explicitly implements.

Unsupported operations should return an explicit Windows error such as
`STATUS_INVALID_DEVICE_REQUEST`, `STATUS_NOT_SUPPORTED`, or
`STATUS_ACCESS_DENIED`, depending on the request.

## Windows metadata decisions

Recommended first milestone behavior:

- File names: treat rencfs names as Unicode strings; convert WinFsp UTF-16 paths
  to Rust strings, reject invalid input, and define whether lookup is
  case-sensitive or case-insensitive. Windows users expect case-insensitive
  lookup, but preserving case while preventing case-fold collisions requires
  deliberate directory lookup logic.
- Permissions: map rencfs POSIX-like `perm`, `uid`, and `gid` to a minimal
  Windows security descriptor. Do not claim NTFS ACL persistence until
  descriptors are stored in encrypted metadata.
- Times: map `atime`, `mtime`, `ctime`, and `crtime` to Windows file times.
  Preserve creation time using `crtime` where possible.
- Attributes: support directory, regular file, read-only, archive, and hidden
  only if represented in encrypted metadata. Otherwise return stable defaults.
- File ids: use rencfs inode numbers as stable file indexes.
- Volume label: expose `rencfs` or a configurable label; reject label mutation
  until metadata storage exists.
- Capacity: return conservative static values until rencfs has a cross-platform
  storage capacity abstraction.

## Build and CI plan

First CI milestone:

- `cargo check --target x86_64-pc-windows-msvc` with the Windows backend feature
  disabled or with compile-only stubs.
- `cargo check --target x86_64-pc-windows-msvc --features windows-winfsp` once the
  dependency and build script are ready.
- Linux build and test jobs must continue to run unchanged.

Native Windows CI can compile the backend, but it should not run mount tests
unless the runner installs WinFsp and has permission to mount a test filesystem.
The first implementation PR should include a manual smoke test instead of
pretending CI proves runtime mount support.

Manual smoke test on a Windows host with WinFsp installed:

```powershell
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc --features windows-winfsp
mkdir C:\rencfs-data
mkdir C:\rencfs-mount
$env:RENCFS_PASSWORD = "test-password"
.\target\x86_64-pc-windows-msvc\release\rencfs.exe mount --mount-point C:\rencfs-mount --data-dir C:\rencfs-data
```

In another PowerShell window:

```powershell
Set-Content C:\rencfs-mount\hello.txt "hello from Windows"
Get-Content C:\rencfs-mount\hello.txt
mkdir C:\rencfs-mount\dir
Move-Item C:\rencfs-mount\hello.txt C:\rencfs-mount\dir\renamed.txt
Get-ChildItem C:\rencfs-mount\dir
Remove-Item C:\rencfs-mount\dir\renamed.txt
Remove-Item C:\rencfs-mount\dir
```

Then unmount using the rencfs process shutdown path or the future Windows
`umount` equivalent, and verify the process exits cleanly.

## Acceptance criteria for the first implementation PR

A truthful first Windows implementation PR should satisfy all of these:

- README and CLI text clearly say Windows support requires WinFsp and remains
  experimental if that is still true.
- Windows builds no longer exit from `main.rs` before CLI dispatch when the
  backend is enabled.
- `src/mount/windows.rs` implements the existing `MountPoint` contract.
- `Cargo.toml` keeps WinFsp dependencies under `cfg(target_os = "windows")` or a
  Windows-only feature.
- `build.rs` performs WinFsp delay-load linking only on Windows.
- The implementation passes Linux tests and at least Windows `cargo check`.
- Manual smoke test evidence covers create, read, write, list, rename, truncate,
  delete, and clean unmount on a real Windows host with WinFsp installed.
- Unsupported Windows features are documented and return explicit errors.
- The licensing checkpoint is resolved before publishing official binaries.
