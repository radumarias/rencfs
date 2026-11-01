# Windows Support Research

This document outlines the research and design considerations for adding native Windows support to **rencfs**. It does **not** claim that the filesystem currently works on Windows, but provides a concrete plan for a future implementation.

---

## 1. Recommended WinFsp Backend
- Use **WinFsp** (Windows File System Proxy) as the FUSE‑compatible layer on Windows.
- Target the `winfsp.sys` driver with the `winfsp` user‑mode library (`winfsp.dll`).
- WinFsp is released under the **MIT** license, which is compatible with rencfs's dual `MIT OR Apache-2.0` licensing.

## 2. Licensing / Attribution
- WinFsp's MIT license can be redistributed as‑is.
- Add a notice in `LICENSES.md` (or similar) acknowledging WinFsp.
- No license conflict with rencfs's existing licensing.

## 3. Windows‑only Dependency & Build Shape
- Add an optional Cargo feature `windows` that pulls in `winfsp = "0.5"` (or the appropriate crate).
- Use `#[cfg(target_os = "windows")]` guards for the implementation.
- The Windows build will be a **delay‑load** of `winfsp.dll` to keep the binary runnable on non‑Windows platforms.

## 4. Proposed Architecture (`src/mount/windows.rs`)
- Mirror the existing `linux.rs` module but implement the `MountHandleInner` and `MountPoint` traits using WinFsp's async API.
- Create a thin wrapper `EncryptedFsWinFsp` that holds an `Arc<EncryptedFs>` (same as the Linux wrapper).
- The module will expose:
  - `MountHandleInnerImpl` implementing `Future<Output = io::Result<()>>`.
  - `MountPointImpl` delegating to `EncryptedFsWinFsp::new`.
- All filesystem operations (lookup, read, write, etc.) will forward to the underlying `EncryptedFs` just like the Linux implementation.

## 5. Operation Mapping
| WinFsp Callback | rencfs Method |
|-----------------|---------------|
| `CreateFile`    | `EncryptedFs::create` |
| `ReadFile`      | `EncryptedFs::read` |
| `WriteFile`     | `EncryptedFs::write` |
| `GetFileInformation` | `EncryptedFs::get_attr` |
| `SetFileInformation` | `EncryptedFs::set_attr` |
| `DeleteFile` / `DeleteDirectory` | `EncryptedFs::remove` |
| `FindFiles`     | `EncryptedFs::list_dir` |
| `FlushFileBuffers` | No‑op (handled by WinFsp) |

## 6. Metadata Decisions & Unsupported Features
- **NTFS attributes** such as `reparse points`, `hard links`, and `extended attributes` are **out of scope** for the first milestone.
- Permissions will be mapped to POSIX‑style `uid/gid/perm` using the Windows security token of the calling process where possible.
- Symbolic links are not supported initially; attempts will return `ENOTSUP`.

## 7. Build / CI Plan
1. Add a CI job on GitHub Actions that runs `cargo check --target x86_64-pc-windows-gnu` (using the `windows` feature).
2. Ensure the build succeeds without pulling WinFsp (the crate should be optional and mockable).
3. Run `cargo test --all --features windows` on a Windows runner once the implementation is ready.

## 8. Manual Smoke Test Checklist (for a Windows host with WinFsp installed)
- Install WinFsp from <https://github.com/billziss-gh/winfsp/releases>.
- Build rencfs with `cargo build --features windows`.
- Run `rencfs mount <mountpoint> <data_dir>` and verify the mount appears in Explorer.
- Create, read, and delete a file; ensure the underlying encrypted data is stored in `<data_dir>`.
- Unmount using `rencfs umount <mountpoint>` and confirm the mount disappears.

## 9. Acceptance Criteria for the First Implementation PR
- The Windows build compiles with the `windows` feature enabled.
- All core filesystem operations (create, read, write, truncate, getattr, setattr, unlink, rmdir, readdir) are functional.
- The mount can be cleanly unmounted via the CLI.
- No regressions on Linux/macOS – existing tests continue to pass.
- Documentation (`docs/windows-support.md`) is updated with the above sections.

---

*This research document is intended for the bounty titled **"docs: add Windows support implementation research"** and serves as the basis for the forthcoming implementation PR.*