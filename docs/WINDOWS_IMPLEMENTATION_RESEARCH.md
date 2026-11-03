# Windows Native Mount Implementation Research (`rencfs`)

## 1. Executive Summary & Recommended Backend

To bring `rencfs` (`EncryptedFs`) to Windows with native drive-letter (`X:`) and directory mount points, **WinFsp (`winfsp` crate v0.12+)** is the recommended backend over Dokan (`dokan-rust`) and Windows Projected File System (`ProjFS`):

| Criterion | **WinFsp (`winfsp-rs`)** (Recommended) | Dokan (`dokan-rust`) | Windows ProjFS (`windows-projfs`) |
| :--- | :--- | :--- | :--- |
| **Workload Fit** | General-purpose POSIX-like read/write encrypted virtual filesystems | General-purpose virtual filesystems | Read-mostly backing stores (Git VFS); poor fit for encrypted random R/W |
| **Kernel Stability & I/O Throughput** | Industry benchmark on Windows; used by Rclone, SSHFS-Win, Cryptomator | Historically prone to BSODs on driver version mismatches | Native Windows component, but hydration model duplicates plaintext on disk |
| **Plaintext Confidentiality** | Zero plaintext caching on backing disk; all reads/writes stream through `EncryptedFs` | Zero plaintext caching on backing disk | **Violates encrypted FS threat model** (hydrates plaintext files to local NTFS) |
| **License Compatibility** | GPLv3 with **FLOSS Linking Exception** (explicitly allows OSI-approved `MIT OR Apache-2.0` dynamic linking) | LGPLv2.1 | MIT |

---

## 2. Core Architectural Impedance Mismatch: Path-Addressed WinFsp vs. Inode-Addressed `EncryptedFs`

On Linux (`src/mount/linux.rs`), `fuse3::raw::Filesystem` operates directly on 64-bit inodes (`Inode = u64`), which maps 1:1 to `EncryptedFs`:
- `EncryptedFs::lookup(parent: u64, name: &str) -> FsResult<FileAttr>`
- `EncryptedFs::open(ino: u64, read: bool, write: bool) -> FsResult<u64>`
- `EncryptedFs::read(ino: u64, offset: u64, buf: &mut [u8], handle: u64) -> FsResult<usize>`

By contrast, WinFsp's `FileSystemContext` is **path-addressed** on `open` / `create` / `get_security_by_name`:
1. **Path-to-Inode Resolution (`split_winfsp_path`)**:
   - Every incoming WinFsp UTF-16 path (e.g. `\vault\notes\secret.txt`) must be split into normalized segments (`["vault", "notes", "secret.txt"]`) via `src/mount/windows.rs::split_winfsp_path`.
   - Starting from `ROOT_INODE` (`1`), resolve each segment via `EncryptedFs::find_by_name(current_ino, segment)`.
2. **`FileContext` Handle Structure**:
   - Store `{ ino: u64, fh: u64, is_dir: bool }` inside `type FileContext` so subsequent `read`, `write`, `flush`, `get_file_info`, and `close` callbacks operate directly on `(ctx.ino, ctx.fh)` in $O(1)$ without re-walking the path.

---

## 3. Callback & Error Mapping Specification

Implemented in [`src/mount/windows.rs`](../src/mount/windows.rs):
- **`FsError` $\rightarrow$ `WindowsNtStatus`**:
  - `FsError::NotFound(_) | FsError::InodeNotFound` $\rightarrow$ `STATUS_OBJECT_NAME_NOT_FOUND` (`0xC0000034`)
  - `FsError::AlreadyExists` $\rightarrow$ `STATUS_OBJECT_NAME_COLLISION` (`0xC0000035`)
  - `FsError::AlreadyOpenForWrite | FsError::InvalidPassword` $\rightarrow$ `STATUS_ACCESS_DENIED` (`0xC0000022`)
  - `FsError::ReadOnly` $\rightarrow$ `STATUS_MEDIA_WRITE_PROTECTED` (`0xC00000A2`)
  - `FsError::NotEmpty` $\rightarrow$ `STATUS_DIRECTORY_NOT_EMPTY` (`0xC0000101`)
  - `FsError::InvalidInodeType` $\rightarrow$ `STATUS_NOT_A_DIRECTORY` (`0xC0000103`)
  - `FsError::InvalidFileHandle` $\rightarrow$ `STATUS_INVALID_HANDLE` (`0xC0000008`)
  - `FsError::MaxFilesizeExceeded(_)` $\rightarrow$ `STATUS_FILE_TOO_LARGE` (`0xC0000904`)
- **Timestamp Conversion (`system_time_to_filetime` / `filetime_to_system_time`)**:
  - Converts `SystemTime` (`UNIX_EPOCH`) to/from Windows `FILETIME` (100-ns ticks since `1601-01-01T00:00:00Z`, offset `116,444,736,000,000,000`).

---

## 4. `Cargo.toml` & Delay-Load Build Configuration

When enabling the live WinFsp host dispatcher on Windows targets:
```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = { version = "0.12", features = ["system"] }
windows-sys = { version = "0.59", features = ["Win32_Foundation", "Win32_Storage_FileSystem"] }

[target.'cfg(target_os = "windows")'.build-dependencies]
winfsp = { version = "0.12", features = ["build"] }
```
And in `build.rs`:
```rust
fn main() {
    #[cfg(target_os = "windows")]
    winfsp::build::winfsp_link_delayload();
}
```
