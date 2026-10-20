# Windows Encrypted Filesystem Implementation Research (`rencfs`)

## 1. Executive Summary
Currently, `rencfs` mounts encrypted directories on Linux via `fuse3` (`EncryptedFsFuse3`). To provide native Windows mount support (`C:\` drive letters or NTFS directory mount points) with minimal architectural divergence, **WinFsp (`winfsp-rs`)** is the recommended primary backend, with **Dokan (`dokan-rust`)** and ** Windows Projected File System (`ProjFS`)** evaluated as alternatives.

---

## 2. Candidate Backend Comparison

| Criteria | **WinFsp (`winfsp-rs`)** (Recommended) | **Dokan (`dokan-rust`)** | **WebDAV Loopback (`dav-server`)** |
|---|---|---|---|
| **Kernel Driver Maturity** | Production-grade (`rclone`, `cryfs`, `sshfs-win`) | Mature but higher overhead | Built-in OS client, 50MB file limit by default |
| **Rust Bindings** | `winfsp` crate (`0.10+`) with safe `FileSystemContext` trait | `dokan` crate (`0.3+`) | Pure async Rust (`dav-server`), no driver install |
| **POSIX / FUSE Mapping** | Direct 1:1 mapping for `open`, `read`, `write`, `readdir`, `setattr` | Custom `FileSystemHandler` callbacks | HTTP WebDAV semantics (weaker random I/O) |
| **Performance (4KB Random R/W)** | **Highest** (zero-copy IRP queue) | Medium | Lowest |

---

## 3. Proposed Crate Architecture (`#[cfg(target_os = "windows")]`)

1. **Conditional Dependency in `Cargo.toml`:**
   ```toml
   [target.'cfg(target_os = "windows")'.dependencies]
   winfsp = { version = "0.10", features = ["system"] }
   windows-sys = { version = "0.52", features = ["Win32_Storage_FileSystem", "Win32_Foundation"] }
   ```
2. **Backend Abstraction (`src/encryptedfs/winfsp_mount.rs`):**
   - Implement `winfsp::filesystem::FileSystemContext` wrapping `Arc<EncryptedFs>`.
   - Map `EncryptedFs::read` / `EncryptedFs::write` directly to WinFsp `read` and `write` callbacks using inode-to-file-handle mapping (`FileContext = u64`).
   - Translate `FsError` variants to `windows_sys::Win32::Foundation::NTSTATUS` codes (`STATUS_OBJECT_NAME_NOT_FOUND`, `STATUS_ACCESS_DENIED`, `STATUS_DISK_FULL`).

## 4. Security & Key Storage on Windows
- Use Windows **DPAPI (`CryptProtectData`)** or **Windows Hello / Credential Manager** to seal master key material at rest.
- Lock key pages in RAM via `VirtualLock` (`winapi::um::memoryapi::VirtualLock`) as the Windows equivalent of `mlock`.
