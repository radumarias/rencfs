# Windows Implementation Architecture & WinFsp Mount Bridge (`rencfs` Issue #3)

## Overview
`rencfs` currently implements its FUSE filesystem bridge in `src/mount/linux.rs` using `fuse3::raw::Filesystem` while non-Linux platforms fall back to `src/mount/dummy.rs`. On Windows, the direct user-mode filesystem equivalent to Linux FUSE is **WinFsp** (`winfsp` crate / `FSP_FILE_SYSTEM_INTERFACE`).

This document and the accompanying `src/mount/windows.rs` implementation specify the Windows mount path around `EncryptedFs`.

---

## 1. Backend Selection: WinFsp vs. Dokany vs. ProjFS

| Criterion | WinFsp (`winfsp-rs`) | Dokany (`dokan-rs`) | Windows ProjFS |
| :--- | :--- | :--- | :--- |
| **Architecture** | Kernel driver (`winfsp.sys`) + user-mode DLL | Kernel driver + user-mode DLL | Virtualization root only (not general POSIX mount) |
| **FUSE / POSIX parity** | High — native Win32 + FUSE compatibility layer | Moderate — historical stability issues on Win11 | Low — designed for Git/VFS hydration |
| **Licensing** | GPLv3 with **FLOSS Exception** (explicitly permits linking with `MIT` / `Apache-2.0` open-source software like `rencfs`) | LGPL / MIT | Windows SDK built-in |
| **Delay-Load Support** | Required via `winfsp_link_delayload()` in `build.rs` | Manual DLL loading | Native |

**Decision**: Use **WinFsp** (`winfsp` crate) with delay-loaded `winfsp-x64.dll` so `rencfs` binaries start cleanly and emit a clear diagnostic if the WinFsp runtime is not installed.

---

## 2. Cargo Target Configuration (`Cargo.toml` & `build.rs`)

```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = { version = "0.12", features = ["system"] }
windows-sys = { version = "0.59", features = [
    "Win32_Foundation",
    "Win32_Storage_FileSystem",
    "Win32_Security",
] }

[target.'cfg(target_os = "windows")'.build-dependencies]
winfsp = { version = "0.12", features = ["build"] }
```

In `build.rs`:
```rust
fn main() {
    #[cfg(target_os = "windows")]
    winfsp::build::winfsp_link_delayload();
}
```

---

## 3. Path-to-Inode Resolution (`WindowsPathResolver`)

Unlike Linux `fuse3` (which operates directly on `u64` inode numbers), WinFsp passes UTF-16 relative paths (`\dir\file.txt`) to `open`, `create`, `get_security_by_name`, and `rename`:

1. **Normalization**: Split Windows path on `\` and reject reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`) and illegal characters (`<>:"|?*`).
2. **Traversal**: Starting from `ROOT_INODE` (`1`), walk each path segment via `EncryptedFs::find_by_name(parent_ino, segment)` while caching `(PathBuf <-> u64)` in an `Arc<RwLock<PathInodeCache>>` invalidated on `unlink`, `rmdir`, and `rename`.
3. **FileContext**: Store `{ ino: u64, fh: u64, is_dir: bool, delete_on_close: bool }` inside WinFsp's `FileContext` handle.

---

## 4. Callback Mapping (`WinFsp -> EncryptedFs`)

| WinFsp Operation | `EncryptedFs` Method | Notes |
| :--- | :--- | :--- |
| `get_volume_info` | Static / `fs_util` | Reports total/free space of backing `data_dir` volume and `FILE_CASE_PRESERVED_NAMES` |
| `get_security_by_name` | `find_by_name` + `get_attr` | Maps `FileAttr.kind` (`Directory` -> `FILE_ATTRIBUTE_DIRECTORY`, read-only mount -> `FILE_ATTRIBUTE_READONLY`) |
| `open` | `open(ino, read, write)` | Acquires `fh` handle from `EncryptedFs` |
| `create` | `create_nod` / `mkdir` | Creates encrypted node and returns opened `FileContext` |
| `read` | `read(ino, offset, buf, fh)` | Streams decrypted ChaCha20/AES-GCM blocks at byte offset |
| `write` | `write(ino, offset, buf, fh)` | Writes and authenticates encrypted blocks (`write_to_end` / `consolidate` when extending) |
| `flush` | `flush(ino, fh)` | Flushes active crypto stream writer |
| `close` | `release(ino, fh)` | Releases `fh`; if `delete_on_close` is set, calls `remove_file` / `remove_dir` |
| `read_directory` | `read_dir(ino)` | Emits `.` and `..` followed by decrypted directory entries |
| `set_basic_info` | `setattr` | Updates `atime`, `mtime`, `ctime` (converting 100ns Windows `FILETIME` epochs to Unix timestamps) |
| `set_file_size` | `truncate(ino, len)` | Resizes encrypted file content |
| `rename` | `rename(old_parent, old_name, new_parent, new_name)` | Atomic move + path cache update |
