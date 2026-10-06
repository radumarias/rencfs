# Windows Support Implementation Research Note (WinFsp & Dokany)

## Overview & Scope
This research documents the native Windows support implementation path for `rencfs` as requested in issue #3.
It analyzes mounting mechanisms, filesystem bridging (WinFsp vs Dokany vs ProjFS), encryption layer compatibility, and operational mapping.

---

## 1. Backend Evaluation: WinFsp vs Dokany

| Criteria | WinFsp (Recommended) | Dokany | Windows Projected FS (ProjFS) |
|---|---|---|---|
| **Maturity & Stability** | High (used by sshfs-win, rclone, encfs-win) | Moderate | Windows native, but read-heavy / virtualization focused |
| **Rust Ecosystem** | `winfsp` crate available with safe bindings | `dokany-rs` (less maintained) | Limited Rust integration for arbitrary encrypted FS |
| **Performance** | Kernel driver with high I/O throughput | Kernel driver, higher latency in benchmark tests | User-mode virtualization, strict metadata requirements |
| **Licensing** | GPLv3 with FOSS Exception / Commercial option | LGPL / MIT | Proprietary Windows API |

**Recommendation:** **WinFsp** is the industry standard for user-space filesystems on Windows, fully compatible with FOSS filesystems like `rencfs`.

---

## 2. Proposed Architecture (`src/mount/windows.rs`)

```
┌───────────────────────────────────────────────┐
│              WinFsp Kernel Driver             │
└──────────────────────┬────────────────────────┘
                       │ FSD Requests (IRP)
┌──────────────────────▼────────────────────────┐
│           WinFsp Rust Bridge (Service)        │
│          `src/mount/windows.rs`               │
└──────────────────────┬────────────────────────┘
                       │
┌──────────────────────▼────────────────────────┐
│             EncryptedFs Adapter               │
│  - AES-256-GCM / ChaCha20-Poly1305 Decrypt/Enc │
│  - Chunked read/write stream translation       │
│  - Metadata & Filename Obfuscation            │
└──────────────────────┬────────────────────────┘
                       │
┌──────────────────────▼────────────────────────┐
│         Host Windows File System (NTFS)       │
└───────────────────────────────────────────────┘
```

### Key Mapping Callbacks:
1. **`GetVolumeInfo`**: Reports `rencfs` volume parameters, cluster size (matching cipher chunk size 4096 bytes), and case-preservation flags.
2. **`GetSecurityByName` / `GetSecurity`**: Translates Unix file mode bits into basic Windows Security Descriptors (`SECURITY_DESCRIPTOR`).
3. **`Create` / `Open`**: Maps Windows file access masks to `rencfs::EncryptedFs::open_file`.
4. **`Read` / `Write`**: Translates chunk offsets. Since encryption uses authenticated chunks, partial block writes must read-modify-write the containing chunk.
5. **`SetInformation` / `Rename`**: Atomic rename emulation over encrypted directory structures.

---

## 3. Metadata Decisions & Incompatibilities

1. **Case Sensitivity**: Windows NTFS by default is case-preserving but case-insensitive. `rencfs` should enforce case-preservation while providing an opt-in flag for strict case sensitivity.
2. **Symlinks**: Requires `SeCreateSymbolicLinkPrivilege` or Windows Developer Mode. Initial release should return `STATUS_NOT_SUPPORTED` for symlink operations unless developer mode is detected.
3. **Hard Links**: Not supported on top of encrypted object storage blocks.

---

## 4. Build, Packaging & CI Plan

1. **Prerequisites for Windows**:
   - Install WinFsp MSI (`choco install winfsp` or GitHub release installer).
   - Rust toolchain: `stable-x86_64-pc-windows-msvc`.
2. **Conditional Compilation**:
   ```rust
   #[cfg(target_os = "windows")]
   pub mod windows;
   ```
3. **GitHub Actions Matrix**:
   - Add `windows-latest` runner to `.github/workflows/ci.yml`.
   - Install WinFsp via PowerShell script in CI runner.
   - Run `cargo check --target x86_64-pc-windows-msvc`.

---

## 5. Acceptance Checklist for Implementation PR

- [ ] WinFsp service daemon starts and assigns a drive letter (e.g. `Z:`).
- [ ] Read/write verification for text and binary files > 100MB.
- [ ] Explorer integration (copying, moving, deleting without explorer hangs).
- [ ] Clean unmount on `SIGINT` / service stop without orphaned mounts.
