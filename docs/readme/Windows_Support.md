# Windows Support Architecture & Implementation (WinFsp)

## 1. Executive Summary & Backend Selection

To bring native encrypted filesystem mounting to Windows (`target_os = "windows"`), `rencfs` uses **WinFsp** (Windows File System Proxy) via the `winfsp` Rust bindings alongside the `WinFspBridge` layer in `src/mount/windows.rs`.

| Candidate Backend | Kernel Stability | Active Maintenance | Rust Ecosystem | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **WinFsp (`winfsp` crate)** | Production-grade (`FSD` + user-mode dispatcher) | Active | Native `winfsp` / `winfsp-sys` crates with delay-load support | **Recommended** |
| Dokany (`dokan` crate) | Mixed historical BSOD reports on rapid I/O cancellation | Moderate | Older bindings | Not selected |
| Cloud Filter API (`cfapi`) | Placeholder-sync model (OneDrive-style), not true virtual drive | OS built-in | Partial via `windows-rs` | Not suitable for full zero-knowledge block-encrypted mounts |

## 2. Licensing & Attribution Checkpoint

- `rencfs` is dual/triple-licensed under `MIT OR Apache-2.0` (with `BSD-3-Clause` file headers).
- WinFsp is licensed under **GPLv3 with the FLOSS Exception**, which explicitly permits linking from open-source software licensed under OSI-approved licenses including `MIT`, `Apache-2.0`, and `BSD-3-Clause` without copyleft propagation to the `rencfs` crate source.
- Binary distributions on Windows require the user to install the official WinFsp MSI runtime (`C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll`), loaded via Windows delay-loading.

## 3. Delay-Load Build Shape (`Cargo.toml` & `build.rs`)

```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = { version = "0.10", optional = true }

[target.'cfg(target_os = "windows")'.build-dependencies]
winfsp = { version = "0.10", optional = true }
```

In `build.rs`, `#[cfg(target_os = "windows")] winfsp::build::winfsp_link_delayload();` links against the delay-load import library so `cargo test` and non-mounting CLI subcommands (`change-password`, `crypto_bench`) run even on Windows machines without the WinFsp driver installed.

## 4. Architecture: `src/mount/windows.rs` (`WinFspBridge`)

Unlike Linux FUSE (`fuse3`), which dispatches callbacks by `(parent_ino, name)` or `ino`, WinFsp is **path-based** on `create`/`open`/`get_security_by_name` and **context-based** on `read`/`write`/`cleanup`/`close`.

`src/mount/windows.rs` introduces:
1. **`split_windows_path`**: Normalizes `\dir\sub\file.txt` paths into clean components.
2. **`WinFspBridge`**: Resolves Windows paths onto `EncryptedFs` inode operations (`find_by_name`, `get_attr`, `read_dir`) with an `RwLock<HashMap<String, u64>>` path-to-inode cache validated against `EncryptedFs::exists`.
3. **`WinFspFileInfo` & `system_time_to_filetime`**: Converts `EncryptedFs::FileAttr` (`ino`, `size`, `atime`, `mtime`, `ctime`, `crtime`, `kind`, `perm`) into 100-ns Windows `FILETIME` epochs (`11_644_473_600` seconds offset from Unix epoch) and `FILE_ATTRIBUTE_DIRECTORY` / `FILE_ATTRIBUTE_NORMAL` / `FILE_ATTRIBUTE_READONLY` flags.
4. **`MountPointImpl` & `MountHandleInnerImpl`**: Implements `crate::mount::MountPoint` and `MountHandleInner` for `#[cfg(target_os = "windows")]`, flushing all encrypted file handles cleanly on unmount.

## 5. Operation Mapping: WinFsp Callbacks to `EncryptedFs`

| WinFsp Callback | `WinFspBridge` / `EncryptedFs` Method | Notes |
| :--- | :--- | :--- |
| `get_volume_info` | Static volume label `rencfs` + host `data_dir` capacity | Reports `CaseSensitiveSearch = 1`, `CasePreservedNames = 1` |
| `get_security_by_name` | `WinFspBridge::resolve_path` -> `EncryptedFs::get_attr` | Maps `FsError::NotFound` to `STATUS_OBJECT_NAME_NOT_FOUND` |
| `open` | `WinFspBridge::resolve_path` -> `EncryptedFs::open` | Stores `(ino, fh, is_directory)` in `WinFspOpenContext` |
| `create` | `EncryptedFs::create_nod` | Creates directory or regular file and returns `WinFspOpenContext` |
| `read` | `EncryptedFs::read(ino, pos, buf, fh)` | Bridges async call via `tokio::runtime::Handle::block_on` |
| `write` | `EncryptedFs::write_all(ino, pos, data, fh)` | Supports append and random-offset encrypted writes |
| `flush` | `EncryptedFs::flush(fh)` | Flushes cipher stream blocks and updates inode size/mtime |
| `get_file_info` | `EncryptedFs::get_attr(ctx.ino)` | Populates `WinFspFileInfo` |
| `set_basic_info` | `EncryptedFs::write_attr(ino, attr)` | Updates `atime`, `mtime`, `crtime`, and read-only attribute |
| `set_file_size` | `EncryptedFs::truncate(ino, new_size)` | Handles both truncation and zero-extension |
| `read_directory` | `WinFspBridge::read_directory` -> `EncryptedFs::read_dir` | Synthesizes `.` and `..` plus encrypted directory entries |
| `rename` | `EncryptedFs::rename` | Invalidates renamed prefix in `path_cache` |
| `cleanup` | `EncryptedFs::remove_dir` / `EncryptedFs::remove_file` | Executes deletion when `FspCleanupDelete` is set |
| `close` | `EncryptedFs::release(fh)` | Releases file handle lock and flushes remaining state |
