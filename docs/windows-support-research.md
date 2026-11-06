# Windows Support Implementation Research for rencfs

## 1. Executive Summary & Objective

`rencfs` currently provides a secure, high-performance encrypted filesystem using FUSE on Linux and macOS. The objective of this research is to define the technical architecture, framework selection, licensing considerations, and operation mappings required to bring native Windows mounting support to `rencfs`.

This document serves as the architectural foundation for resolving [Issue #3](https://github.com/radumarias/rencfs/issues/3) and claiming the Opire bounty (`research implementation for Windows`).

---

## 2. Windows User-Mode Filesystem Framework Evaluation

To mount a user-mode encrypted filesystem on Windows, three primary technologies were evaluated:

| Criteria | WinFsp (Windows File System Proxy) | Dokan (DokanY) | Windows Projected File System (ProjFS) |
| :--- | :--- | :--- | :--- |
| **Maturity & Stability** | High (Industry standard, used by rclone, SSHFS-Win, Git LFS) | Moderate | Moderate (Windows 10+ native, but read-heavy) |
| **Rust Ecosystem** | Excellent (`winfsp` and `winfsp-sys` crates maintained) | Legacy (`dokan` crate has minimal active maintenance) | Limited (Designed primarily for virtualized file trees like VFS for Git) |
| **FUSE Compatibility** | Direct POSIX/FUSE translation layer available | FUSE wrapper exists, but higher overhead | No FUSE layer (strict NT kernel callback structure) |
| **Performance** | Kernel caching, high throughput zero-copy I/O | Standard user/kernel context switches | Optimized for on-demand hydration, poor for arbitrary write streams |
| **Recommendation** | **Recommended (Primary Choice)** | Alternative fallback | Not suitable for general encrypted storage |

**Conclusion:** **WinFsp** is the recommended framework due to its battle-tested stability, modern Rust bindings (`winfsp-rs`), full support for non-admin user mounts, and close alignment with existing FUSE semantics.

---

## 3. Licensing & Attribution Compatibility

`rencfs` is dual-licensed under `MIT OR Apache-2.0`.
- **WinFsp Licensing**: WinFsp kernel driver and runtime are licensed under GPLv3 with a **special FLOSS Exception**.
- The FLOSS Exception explicitly permits linking with software licensed under OSI-approved permissive licenses, including **MIT** and **Apache-2.0**.
- **Distribution Model**:
  - The `rencfs` binary will dynamically link to `winfsp-x64.dll` (delay-loaded) at runtime.
  - Users install the WinFsp runtime package independently (or via `winget install WinFsp.WinFsp`).
  - No GPL code is compiled directly into the static `rencfs` artifact.

---

## 4. Architecture & Mount Pipeline

### Proposed Module Structure

```
src/
├── mount/
│   ├── mod.rs          # Cross-platform mount dispatcher
│   ├── fuse.rs         # Existing Linux/macOS FUSE adapter
│   └── windows.rs      # Windows WinFsp adapter (conditional cfg(windows))
```

### Flow of Execution on Windows

```
[Windows File Explorer / App]
           │ (Win32 I/O: CreateFileW, ReadFile, WriteFile)
           ▼
    [WinFsp Kernel Driver]
           │ (IPC / Fast I/O)
           ▼
[WinFsp DLL / winfsp-rs runtime]
           │ (Safe Rust Callbacks: FileSystemContext, FileContext)
           ▼
[src/mount/windows.rs]
           │ (Translates Windows NT paths & attributes)
           ▼
[rencfs::EncryptedFs Core Engine]
           │ (Authenticated Encryption: ChaCha20-Poly1305 / AES-GCM)
           ▼
[Underlying Encrypted Storage on Windows Disk / NTFS / ReFS]
```

---

## 5. Operation Mapping Matrix

WinFsp exposes an object-oriented file system interface implementing `FileSystemContext`. The mapping from WinFsp callbacks to `rencfs` core functions is defined below:

| WinFsp Callback | rencfs Core Target | Purpose & Handling |
| :--- | :--- | :--- |
| `mount` / `start` | `EncryptedFs::init` | Initializes mount point (drive letter `Z:` or directory junction) |
| `get_file_info` | `EncryptedFs::getattr` | Returns file size, timestamps, attributes (`FILE_ATTRIBUTE_DIRECTORY`, etc.) |
| `open` / `create` | `EncryptedFs::create` / `lookup` | Allocates a `FileContext` storing decryptor state, handle ID, and access flags |
| `read` | `EncryptedFs::read` | Decrypts ciphertext chunks; handles partial block alignment |
| `write` | `EncryptedFs::write` | Encrypts plaintext chunks; updates authenticated tags and header length |
| `flush` | `EncryptedFs::flush` | Commits pending encrypted blocks to underlying Windows backing store |
| `cleanup` | `EncryptedFs::release` | Called when last user-mode handle closes; updates metadata |
| `close` | `EncryptedFs::destroy` | Deallocates `FileContext` memory |
| `read_directory` | `EncryptedFs::readdir` | Returns decrypted file entries (`FileInfo`) to populate directory listing |
| `set_file_info` | `EncryptedFs::setattr` | Handles truncation, renaming, and timestamp updates |

---

## 6. Windows-Specific Semantics & Considerations

1. **Path Normalization**:
   - Windows uses backslashes (`\`) and drive letters (e.g., `Z:\folder\file.txt`).
   - `src/mount/windows.rs` normalizes paths to forward slashes (`/`) internally before dispatching to `EncryptedFs`.
2. **Case Sensitivity**:
   - By default, Windows applications expect case-preserving but case-insensitive matching (`FILE_FLAG_POSIX_SEMANTICS` can enable case-sensitivity, but may break Explorer).
   - In Milestone 1, paths will be preserved as written and looked up case-sensitively or normalized via internal cache.
3. **File Attributes & Permissions**:
   - POSIX mode `0644` translates to `FILE_ATTRIBUTE_NORMAL`.
   - POSIX directories translate to `FILE_ATTRIBUTE_DIRECTORY`.
   - Read-only files translate to `FILE_ATTRIBUTE_READONLY`.
4. **Unsupported Features in Milestone 1**:
   - Named Streams (Alternate Data Streams / Zone.Identifier) are rejected with `STATUS_NOT_SUPPORTED`.
   - Windows Extended Security Descriptors (DACL/SACL) return default inherited permissions.

---

## 7. Cargo Configuration & Build Plan

In `Cargo.toml`, Windows dependencies are conditionally isolated:

```toml
[target.'cfg(windows)'.dependencies]
winfsp = "0.1"
windows-sys = { version = "0.52", features = [
    "Win32_Foundation",
    "Win32_Storage_FileSystem",
    "Win32_Security"
] }
```

Building on Windows requires:
```powershell
# Install WinFsp via winget or chocolatey
winget install WinFsp.WinFsp

# Compile rencfs with Windows target
cargo build --release --target x86_64-pc-windows-msvc
```

---

## 8. CI/CD Integration & Smoke Test Checklist

### GitHub Actions Workflow Addition (`.github/workflows/windows_build.yaml`):
```yaml
name: Windows Build Check

on: [push, pull_request]

jobs:
  check-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Install WinFsp Developer Tools
        run: choco install winfsp -y
      - name: Cargo Check
        run: cargo check --target x86_64-pc-windows-msvc
```

### Manual Smoke-Test Verification:
- [ ] Mount encrypted volume to drive letter `X:`: `rencfs.exe mount C:\vault X:`
- [ ] Create text file via PowerShell: `"Secret Data" | Out-File X:\test.txt`
- [ ] Read file: `Get-Content X:\test.txt` matches `"Secret Data"`
- [ ] Inspect `C:\vault`: Encrypted chunk files created; plaintext is not exposed.
- [ ] Unmount cleanly: `rencfs.exe unmount X:`

---

## 9. Conclusion & Next Steps

This design provides a clear, compliant, and performant roadmap for Windows support using WinFsp. Contributors can proceed to implement `src/mount/windows.rs` following the operation mapping defined in Section 5.
