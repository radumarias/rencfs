# Windows Support Implementation Research (`rencfs`)

## 1. Scope & Current Codebase Baseline

`rencfs` (`v0.13.78`, licensed `MIT OR Apache-2.0`) already cleanly separates its encrypted storage engine (`src/encryptedfs.rs`) from its OS mount transport (`src/mount.rs`):

- **Storage & Crypto Layer (Platform-Agnostic Ready):** `EncryptedFs` stores metadata and ciphertext blocks in host directories (`INODES_DIR`, `CONTENTS_DIR`, `SECURITY_DIR`, `LS_DIR`) using `ring`, `argon2`, `okaywal`, `bincode`, and `keyring` (`v2.3.2`). Notably, `src/fs_util.rs` already gates `atomic_write_file::unix::OpenOptionsExt` behind `#[cfg(unix)]`.
- **Mount Dispatch (`src/mount.rs`):** Defines the `MountPoint` and `MountHandleInner` traits, dispatching `#[cfg(target_os = "linux")] mod linux;` (`fuse3` `0.8.1`) and falling back to `src/mount/dummy.rs` on non-Linux targets.

---

## 2. Backend Comparison for Windows

| Candidate | Rust Ecosystem | Architecture Fit for `EncryptedFs` | License & Redistribution | Verdict |
|---|---|---|---|---|
| **WinFsp (`winfsp` crate)** | Mature (`winfsp` `0.12+` safe wrapper + `winfsp-sys`) | **Best fit:** NT kernel driver (`FSD`) with full POSIX-like rename, byte-range read/write, and handle lifecycle matching `EncryptedFs` | GPLv3 **with FLOSS Exception** (explicitly permits linking from `MIT OR Apache-2.0` binaries when WinFsp is installed separately as a system component via MSI/winget) | **Recommended** |
| **Dokan (`dokan` crate)** | Older bindings, less active maintenance | Works for drive-letter mounts, historically higher edge-case churn around concurrentlocks/oplocks | LGPLv2.1 / MIT user-mode lib | Viable fallback |
| **Windows ProjectedFS (`ProjFS`)** | Windows API (`windows` crate) | Hydrates plain files onto disk cache — **unsuitable** for zero-plaintext-at-rest encrypted vaults | Built into Windows 10/11 | Reject (breaks threat model) |
| **WebDAV / SMB Loopback** | Pure Rust (`dav-server` / TCP) | High latency, Explorer 50 MB WebClient size limits, weak file-locking semantics | MIT/Apache-2.0 | Secondary CLI fallback only |

---

## 3. Licensing & Build Shape (`Cargo.toml` + Delay-Load)

1. **License Compliance (`MIT OR Apache-2.0`):** Under the WinFsp FLOSS Exception, `rencfs` keeps its `MIT OR Apache-2.0` license untouched provided it dynamically delay-loads `winfsp-x64.dll` from `%ProgramFiles(x86)%\WinFsp\bin` rather than bundling proprietary/copyleft installers.
2. **Conditional Dependencies in `Cargo.toml`:**
   ```toml
   [target.'cfg(target_os = "windows")'.dependencies]
   winfsp = { version = "0.12", features = ["delayload"] }
   windows-sys = { version = "0.59", features = ["Win32_Foundation", "Win32_Storage_FileSystem", "Win32_Security"] }

   [target.'cfg(target_os = "windows")'.build-dependencies]
   winfsp = { version = "0.12", features = ["build"] }
   ```
   In `build.rs`, invoke `#[cfg(target_os = "windows")] winfsp::build::winfsp_link_delayload();` so `rencfs --help` and library callers run cleanly even before WinFsp is installed, returning a clear actionable error only when `MountPoint::mount()` is called.
3. **Credential Manager (`src/keyring.rs`):** Enable the `windows-native` feature on `keyring` (`v2.3.2`) on Windows targets so vault passwords integrate natively with Windows Credential Manager.

---

## 4. Proposed `src/mount/windows.rs` Architecture

Unlike Linux FUSE (`fuse3::raw::Filesystem`), which addresses entries by `u64` inode, **WinFsp callbacks are UTF-16 NT-path based** (`\dir\sub\file.txt`) while `EncryptedFs` is inode-indexed (`ROOT_INODE = 1`).

### 4.1 Path-to-Inode Bridge & Async Runtime
- **`WinFspContext`:** Holds `Arc<EncryptedFs>`, `tokio::runtime::Handle`, `read_only: bool`, and an `RwLock<PathInodeCache>` mapping normalized relative paths (`\foo\bar`) to `u64` inodes (invalidated on `rename` / `unlink` / `rmdir`).
- **Async-to-Sync Bridging:** WinFsp dispatches worker threads in native C; each `FileSystemContext` callback calls `self.rt_handle.block_on(async { ... })` against `EncryptedFs` async methods without starving Tokio I/O drivers.
- **`FileContext` Handle:** Stores `{ inode: u64, fh: u64, is_dir: bool, delete_on_close: AtomicBool }`.

### 4.2 WinFsp Callback -> `EncryptedFs` Mapping

| WinFsp `FileSystemContext` Method | `EncryptedFs` Operation | Key Windows Details |
|---|---|---|
| `get_volume_info` | Stat constants / vault info | Expose volume label `rencfs`, `FILE_CASE_PRESERVED_NAMES \| FILE_UNICODE_ON_DISK` |
| `get_security_by_name` | Walk path -> `find_by_name` + `get_attr` | Return `STATUS_OBJECT_NAME_NOT_FOUND` on `FsError::NotFound`; synthesize owner SDDL |
| `open` | Path resolve -> `EncryptedFs::open` | Enforce `read_only` -> `STATUS_MEDIA_WRITE_PROTECTED` on write access masks |
| `create` | Parent resolve -> `create_nod` / `mkdir` | Map `FILE_DIRECTORY_FILE` to `FileType::Directory`, else `FileType::RegularFile` |
| `read` | `EncryptedFs::read(ino, offset, buf, fh)` | Return `(bytes_read)` directly; EOF -> `STATUS_END_OF_FILE` (`0` bytes) |
| `write` | `EncryptedFs::write_all` / `write` | Support `write_to_end_of_file` (`u64::MAX` offset -> current `attr.size`) |
| `flush` | `EncryptedFs::flush(fh)` / `fsync` | Flush `CryptoWrite` stream when `context` is `Some` |
| `get_file_info` | `EncryptedFs::get_attr(ino)` | Convert `SystemTime` -> Windows `FILETIME` (100ns ticks since `1601-01-01`) |
| `set_basic_info` | `EncryptedFs::set_attr(ino, SetFileAttr)` | Update `atime`/`mtime`/`ctime`; map `FILE_ATTRIBUTE_READONLY` |
| `set_file_size` | `EncryptedFs::truncate(ino, new_size)` | Zero-extend or shrink ciphertext stream when `set_allocation_size == false` |
| `read_directory` | `EncryptedFs::read_dir(ino)` | Inject `.` and `..` entries, sort/resume past `marker` cursor |
| `rename` | `EncryptedFs::rename(...)` | Honour `replace_if_exists` -> `STATUS_OBJECT_NAME_COLLISION` when false |
| `set_delete` + `cleanup` | `remove_file` / `remove_dir` | Windows deletes happen in two phases: mark `delete_on_close` in `set_delete`, unlink in `cleanup` (`FspCleanupDelete`) before `close` |
| `close` | `EncryptedFs::release(fh)` | Release open cryptographic reader/writer handle |

---

## 5. Windows-Specific Filesystem Edge Cases (Milestone 1)

- **Case Sensitivity:** Default Milestone 1 to case-sensitive lookup (`CaseSensitiveSearch = 1` in `FSP_FSCTL_VOLUME_PARAMS`) or optional case-folding cache to match existing Linux vault portability.
- **Reserved Characters & Streams:** Reject NTFS Alternate Data Streams (`file.txt:stream` -> `STATUS_INVALID_PARAMETER`) and reserved device names (`CON`, `NUL`, `AUX`) at mount boundary.
- **Mount Targets:** Support both unused drive letters (`R:`) and non-existent directory mountpoints (`C:\Users\<user>\Vault`) via `FileSystemHost::mount()`.
- **`MountHandle` Integration:** Spawn `FileSystemHost::start()` inside `MountPointImpl::mount()`, wire `ctrlc` / `MountHandle::umount()` to `host.stop()`, and resolve the `MountHandleInner` `Future` cleanly on stop.

---

## 6. CI & Manual Smoke-Test Plan

1. **GitHub Actions (`windows-latest`):**
   - Install WinFsp MSI silently: `choco install winfsp -y --version=2.0.23075`
   - Run `cargo check --all-targets` and `cargo test --lib` (validating `EncryptedFs` on NTFS paths + `fs_util::open_atomic_write`).
2. **End-to-End Mount Smoke Test:**
   - Mount temporary vault on `R:`, create/write/seek-read a multi-chunk file (>64 KiB cipher blocks), rename across subdirectories, delete, unmount, remount with same password, and verify SHA-256 digest equality.
