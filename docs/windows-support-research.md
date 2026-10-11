# Windows Support Implementation Research

> **Status**: Research & Design — not yet implemented.  
> This document outlines the recommended path for adding native Windows support to `rencfs`. It is intentionally framed as research, not a claim that rencfs currently mounts on Windows.

---

## 1. Backend Recommendation: WinFsp

**WinFsp** (Windows File System Proxy) is the recommended FUSE-like backend for Windows.

### Why WinFsp?
- Mature, production-grade FUSE replacement for Windows.
- Actively maintained (Spencer-Fuse/WinFsp).
- Well-documented API with clear callback lifecycle.
- Supports both user-mode and kernel-mode filesystems (we target user-mode).
- LGPL-2.1 license, which is compatible with an MIT/Apache-2.0 project when used as a dynamic dependency (delay-loaded).

### Alternatives Considered
| Alternative | Verdict | Reason |
|---|---|---|
| [SSHFS-Win](https://github.com/winfsp/sshfs-win) | ❌ Rejected | Built on top of WinFsp; adds SSH layer we don't need. |
| [ Dokany ](https://github.com/dokan-dev/dokany) | ⚠️ Considered | Permissive license (MPL-2.0), but less mature and smaller community. |
| [Win32 Native File System Driver](https://docs.microsoft.com/en-us/windows/win32/fileio/file-system-minifilter-drivers) | ❌ Rejected | Kernel-mode; far too complex for initial implementation. |
| [9P / Plan9 filesystem](https://github.com/honori/plan9port) | ❌ Rejected | Unnecessary abstraction layer. |

**Decision**: Proceed with **WinFsp** as the primary backend. Dokany retained as a fallback for future evaluation.

---

## 2. WinFsp Licensing / Attribution Checkpoint

`rencfs` is licensed under **MIT OR Apache-2.0**. WinFsp is licensed under **LGPL-2.1-or-later**.

### Compatibility Analysis
- Linking against WinFsp **dynamically** (delay-load DLL) does **not** create a derivative work of WinFsp under LGPL.
- The LGPL permits use of the library in proprietary software as long as:
  1. The library is used as an unmodified dynamic link library.
  2. Users are informed of the LGPL terms and given the ability to relink against a modified version.
- WinFsp's own FAQ confirms this interpretation for user-mode DLL linking.

### Required Attribution
- Include a `NOTICES-WINDOWS.txt` file at the repository root referencing WinFsp and its license.
- Add a Windows-specific `LICENSE-THIRD-PARTY` acknowledgment in the README's "Licenses" section.
- Include WinFsp's license text in `third-party/WinFsp-LICENSE.txt`.

**No new project-wide license change is required.** The existing MIT/Apache-2.0 dual license remains intact.

---

## 3. Windows-Only Dependency & Delay-Load Build Shape

### Dependency Declaration
In `rencfs/Cargo.toml`, add a Windows-conditional dependency:

```toml
[target.'cfg(windows)'.dependencies]
winsp = { version = "0.2", optional = true }

[features]
windows-backend = ["dep:winsp"]
default = []
```

*(Note: the exact crate name will be finalized once the WinFsp Rust bindings are selected or a thin FFI wrapper is written.)*

### Delay-Load Strategy
- WinFsp's `winfsp.dll` and `winfsp-x64.dll` are **delay-loaded** at runtime.
- This means:
  - The binary can run on non-Windows systems without WinFsp present.
  - The mount point initialization fails gracefully with a clear error if WinFsp is not installed.
- Configure via linker flag: `/DELAYLOAD:winfsp.dll` (Rust: `link_args` in `.cargo/config.toml` for `x86_64-pc-windows-msvc`).

### Conditional Compilation
```rust
#[cfg(windows)]
mod mount; // src/mount/windows.rs

#[cfg(unix)]
mod mount; // existing unix mount logic
```

This keeps the Unix codepath untouched and isolated.

---

## 4. Proposed Architecture: `src/mount/windows.rs`

```
src/
├── mount/
│   ├── mod.rs          # trait / abstraction for mount backends
│   ├── unix.rs         # existing Unix/FUSE implementation
│   └── windows.rs      # NEW: WinFsp-backed implementation
├── fs/
│   └── encrypted.rs    # EncryptedFs (shared across platforms)
└── lib.rs
```

### `mount/mod.rs` — Backend Trait
```rust
pub trait MountBackend: Send + Sync {
    type Error: std::error::Error + Send + Sync;
    
    fn mount(&self, spec: &MountSpec) -> Result<(), Self::Error>;
    fn unmount(&self, spec: &MountSpec) -> Result<(), Self::Error>;
}

#[cfg(unix)]
pub use unix::UnixMount as DefaultMount;
#[cfg(windows)]
pub use windows::WinFspMount as DefaultMount;
```

### `mount/windows.rs` — Key Components
```rust
use winsp::*; // placeholder for WinFsp FFI bindings

pub struct WinFspMount {
    encryption: EncryptedFs,
    /// WinFsp filesystem context handle
    _ctx: Option<FsContext>,
}

impl MountBackend for WinFspMount {
    type Error = WinFspError;
    
    fn mount(&self, spec: &MountSpec) -> Result<(), Self::Error> {
        // 1. Validate drive letter / mount point
        // 2. Initialize WinFsp filesystem
        // 3. Register callbacks (see §5)
        // 4. Call winfsp_mount()
        todo!()
    }
}
```

### Relationship to `EncryptedFs`
The `EncryptedFs` layer (already cross-platform) remains **unchanged**. `WinFspMount` wraps it and translates WinFsp callbacks into `EncryptedFs` method calls. No encryption logic is duplicated.

---

## 5. Operation Mapping: WinFsp Callbacks → rencfs Methods

| WinFsp Callback | rencfs Equivalent | Notes |
|---|---|---|
| `GetFileInfo` | `EncryptedFs::get_metadata()` | Returns file size, timestamps, attributes |
| `GetDirectoryInformation` | `EncryptedFs::read_dir()` | Directory enumeration |
| `CreateFile` (open) | `EncryptedFs::open()` | With create/disposition handling |
| `Cleanup` / `CloseFile` | `EncryptedFs::close()` | Flush cached writes if dirty |
| `ReadFile` | `EncryptedFs::read_at()` | Offset-based read, decryption on the fly |
| `WriteFile` | `EncryptedFs::write_at()` | Offset-based write, encryption on the fly |
| `SetFileInfo` | `EncryptedFs::set_metadata()` | chmod, utimes |
| `DeleteFile` / `DeleteDir` | `EncryptedFs::remove()` | Delete with trash/secure-delete option |
| `Rename` | `EncryptedFs::rename()` | Cross-directory rename |
| `FlushFileBuffers` | `EncryptedFs::sync()` | Force metadata + data flush |
| `SetEA` / `GetEA` | *(deferred)* | Extended attributes — see §7 |

### Security Attribute Mapping
Windows security attributes (`SECURITY_ATTRIBUTES`) are **not mapped** to the encrypted filesystem. rencfs manages its own permission model. WinFsp's default DACL behavior applies to the mount point directory, not individual files.

---

## 6. Windows Metadata Decisions

### First Milestone: Limited Metadata Support
| Feature | Supported? | Rationale |
|---|---|---|
| Basic permissions (owner read/write) | ✅ | Mapped to Unix mode bits |
| `FILE_ATTRIBUTE_ARCHIVE`, `HIDDEN`, `SYSTEM` | ✅ | Read-only exposure; write ignored |
| NTFS ADS (Alternate Data Streams) | ❌ | Not applicable to rencfs encryption model |
| NTFS Compression | ❌ | Redundant with encryption layer |
| NTFS Encryption (EFS) | ❌ | Conflict with rencfs encryption |
| POSIX rename semantics | ✅ | Basic rename supported |
| Long path names (>260 chars) | ✅ | WinFsp handles `\\?\` prefix |
| Hard links | ❌ | Not supported in first milestone |
| Sparse files | ❌ | Out of scope |

### File Attribute Behavior
- All files appear with `FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ENCRYPTED`.
- The `ENCRYPTED` flag signals to Windows that the file is encrypted (consistent with user expectation, even though rencfs manages encryption internally).

---

## 7. Build & CI Plan

### Local Build (Windows host)
```powershell
# Prerequisites
# 1. Install WinFsp: https://github.com/winfsp/winfsp/releases
# 2. Ensure winfsp.dll is on PATH or in system32

cargo build --features windows-backend --target x86_64-pc-windows-msvc
```

### CI Integration
- Add a Windows runner job in `.github/workflows/ci.yml`:
  ```yaml
  windows-test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install WinFsp
        run: choco install winfsp --no-progress
      - name: Build (Windows)
        run: cargo build --features windows-backend
      - name: Smoke test
        run: cargo run --features windows-backend -- mount --help
  ```

### Conditional CI Gate
- The `windows-backend` feature is **opt-in**; default CI (macOS/Linux) is unaffected.

---

## 8. Manual Smoke Test Checklist

A human tester on a Windows host should verify the following once a PR lands:

- [ ] `cargo build --features windows-backend` compiles without errors on `x86_64-pc-windows-msvc`.
- [ ] Running `rencfs mount` without WinFsp installed produces a clear error message (not a panic).
- [ ] After installing WinFsp, `rencfs mount <keyfile> <source> <drive>:` attaches successfully.
- [ ] `dir <drive>:` lists files correctly (decrypted names visible).
- [ ] Reading and writing a file through the mount point round-trips correctly.
- [ ] `rencfs umount <drive>:` unmounts cleanly with no leaked handles.
- [ ] The process exits without memory leaks (checked via basic task manager observation).

---

## 9. Acceptance Criteria for First Implementation PR

A PR claiming initial Windows support must satisfy **all** of the following:

1. **Builds on Windows**: `cargo build --features windows-backend` succeeds on `x86_64-pc-windows-msvc`.
2. **No regression on Unix**: All existing tests pass on macOS and Linux.
3. **Mount / Umount cycle**: A live mount and unmount of a test filesystem works end-to-end on Windows with WinFsp installed.
4. **Read / Write round-trip**: Writing a file and reading it back yields identical plaintext.
5. **List directory**: `dir` shows decrypted filenames correctly.
6. **Graceful error on missing WinFsp**: Clear diagnostic when WinFsp is not installed.
7. **Attribution files present**: `NOTICES-WINDOWS.txt` and `third-party/WinFsp-LICENSE.txt` exist.
8. **No new Rust dependencies on non-Windows targets**: `cargo tree` on macOS shows zero added deps.
9. **CI green**: All GitHub Actions workflows pass, including any new Windows job.

---

## 10. Open Questions

- **Which Rust crate wraps WinFsp?** Evaluation in progress between `winsp`, a custom FFI thin layer, and direct `bindgen` from WinFsp's C headers.
- **How to handle Windows path separators?** WinFsp normalizes to forward slashes internally; mapping to backslashes for display is a minor concern.
- **Should we support Windows Subsystem for Linux (WSL)?** Out of scope for the first milestone; WSL2 can use the existing Unix FUSE backend.

---

*Last updated: research phase. References this document for tracking implementation progress.*
