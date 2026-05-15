# Windows Support Implementation Research

> **Status:** Research / Design Document
> **Target:** Native Windows support via WinFsp (Win32 FUSE)
> **Repository:** radumarias/rencfs
> **Issue:** #3 — `research implementation for Windows`

---

## 1. WinFsp Backend Selection

### Recommended: WinFsp (Win32 FUSE)

**WinFsp** (Win32 File System Proxy) is the recommended backend for Windows support. It exposes a FUSE-compatible API on Windows, allowing Linux FUSE filesystem code to be ported with minimal architectural changes.

**Alternatives Considered:**

- **Dokany** — Less maintained, smaller community, GPL-licensed (problematic for MIT/Apache-2.0 project). WinFsp is more performant.
- **NFS/SMB loopback** — Requires network stack, adds latency and complexity.
- **Direct kernel driver (WDK)** — Extreme complexity, signed-driver requirements, not feasible.
- **minifilter** — Designed for filtering, not providing filesystems from userspace.
- **cbindgen + C FFI to own driver** — Not feasible for a single-crate project.

### WinFsp Licensing Check

- **WinFsp license:** GPLv3 with linking exception
- **rencfs license:** MIT OR Apache-2.0
- **Verdict:** Compatible. The GPLv3 linking exception permits distribution of WinFsp binaries alongside MIT/Apache-2.0 Rust code. Attribution must be included.

**Required:** Include a THIRD_PARTY_LICENSES.md entry:
```
WinFsp - Windows File System Proxy
Copyright (c) Bill Zissimopoulos
License: GPLv3 with linking exception
https://github.com/billziss-gh/winfsp
```

---

## 2. Build Architecture

### Current Structure

```
src/
  mount.rs              # Platform-dispatch: cfg(linux) -> linux, else -> dummy
  mount/linux.rs        # fuse3-based FUSE implementation
  mount/dummy.rs        # Fallback (returns error)
  encryptedfs.rs        # Core EncryptedFs — platform-agnostic
```

### Proposed Addition: src/mount/windows.rs

### Cargo.toml Changes

```toml
[target.'cfg(target_os = "linux")'.dependencies]
fuse3 = { version = "0.8.1", features = ["tokio-runtime", "unprivileged"] }

[target.'cfg(target_os = "windows")'.dependencies]
winfsp-sys = { version = "0.1", features = ["winfsp"] }

[target.'cfg(target_os = "windows")'.dependencies.windows]
version = "0.58"
features = [
    "Win32_Foundation",
    "Win32_Storage_FileSystem",
    "Win32_Security",
    "Win32_System_IO",
]
```

### Conditional Compilation in mount.rs

```rust
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::MountHandleInnerImpl;
#[cfg(target_os = "windows")]
use windows::MountPointImpl;

// Change dummy fallback to:
// #[cfg(not(any(target_os = "linux", target_os = "windows")))]
```

---

## 3. Architecture: src/mount/windows.rs

The Windows module mirrors mount/linux.rs but uses WinFsp FUSE operations instead of the fuse3 trait.

### Structural Differences from Linux

- **Dispatch:** C function pointer table (FUSE_OPERATIONS) vs Rust trait
- **Runtime:** WinFsp worker threads vs Tokio
- **Callback model:** Primarily sync (use block_in_place) vs fully async
- **Mount/unmount:** FuseMount/FuseUnmount vs Session::mount_with_unprivileged

---

## 4. Operation Mapping

| WinFsp Callback | EncryptedFs Method | Notes |
|---|---|---|
| GetVolumeInfo | (static metadata) | Volume label, serial number |
| Open | open(inode, read, write) | CRUD setup |
| Create | create(parent, name, attr, read, write) | Create with FSD attributes |
| Read | read(inode, offset, buf, fh) | Buffered reads |
| Write | write(inode, offset, data, fh) | Buffered writes |
| Close / Cleanup | flush(fh), release(fh) | Close + flush |
| GetFileInfo | get_attr(inode) | File attributes |
| SetBasicInfo | set_attr(inode, SetFileAttr) | Set times/attributes |
| SetFileSize | set_len(inode, size) | Truncate |
| FindFiles | read_dir(inode) | Directory listing |
| Rename | rename(parent, name, new_parent, new_name) | Rename/Move |
| Delete | remove_file() / remove_dir() | Unlink/Rmdir |
| GetSecurity | (stub — return default SD) | Deferred to M2 |
| SetSecurity | (stub — accept + discard) | Deferred to M2 |

### WinFsp FUSE Flags for M1

```rust
const WINFSP_FLAGS: u32 = FUSE_FLAG_CASE_INSENSITIVE
    | FUSE_DISABLE_STREAMINFO
    | FUSE_FILE_INFO_TIMEOUT;
```

---

## 5. Windows Metadata Decisions (M1 Scope)

| Feature | Decision | Rationale |
|---|---|---|
| Case sensitivity | Case-insensitive lookups | Windows/NTFS default |
| Symlinks | Unsupported | Not on Linux side either |
| Hard links | Unsupported | nlink tracked but no WinFsp equivalent |
| Named streams (ADS) | Unsupported | Disabled via FUSE_DISABLE_STREAMINFO |
| Reparse points | Unsupported | Deferred |
| Security descriptors | Stub | Full ACL requires POSIX-to-ACE mapping |
| UNICODE paths | Supported natively | Rust stdlib handles UTF-16 |
| File times | SystemTime <-> FILETIME | Native conversion |
| Sparse files | Unsupported | Not meaningful for encrypted blocks |
| Compression | Unsupported | Encryption after compression is misordered |

---

## 6. Build and CI Plan

### Local Build (Windows host)

Prerequisites: WinFsp installed, Rust stable-x86_64-pc-windows-msvc, VS Build Tools

```powershell
choco install winfsp
cargo build --target x86_64-pc-windows-msvc
```

### CI Plan

```yaml
# .github/workflows/windows.yml
name: Windows Build
on: [push, pull_request]
jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          target: x86_64-pc-windows-msvc
      - name: Install WinFsp
        run: choco install winfsp --no-progress
      - name: Build
        run: cargo build --target x86_64-pc-windows-msvc
      - name: Unit tests (non-mount)
        run: cargo test --target x86_64-pc-windows-msvc --lib
```

### Manual Smoke Test

```powershell
mkdir C:	mpencfs_data, C:	mpencfs_mount
rencfs.exe --mountpoint C:	mpencfs_mount --data-dir C:	mpencfs_data
echo hello > C:	mpencfs_mount	est.txt
dir C:	mpencfs_mount# Verify encrypted data:
dir C:	mpencfs_data\contents# Remount and verify:
rencfs.exe --mountpoint C:	mpencfs_mount --data-dir C:	mpencfs_data
type C:	mpencfs_mount	est.txt
# Unmount:
rencfs.exe --unmount C:	mpencfs_mount
```

---

## 7. Security Considerations

| Concern | Mitigation |
|---|---|
| Password input | rpassword crate (already a dep, works via ReadConsoleW) |
| Keyring | keyring crate supports Windows Credential Manager (already a dep) |
| Data dir permissions | User must secure manually (same as Linux) |
| WinFsp driver trust | WinFsp is signed; installed via official MSI |
| Handle leaks | Rust Drop for MountHandle ensures FuseUnmount |

### NTSTATUS Error Mapping

| POSIX errno | NTSTATUS | rencfs FsError |
|---|---|---|
| ENOENT | STATUS_OBJECT_NAME_NOT_FOUND | FsError::NotFound |
| EACCES | STATUS_ACCESS_DENIED | FsError::AccessDenied |
| EEXIST | STATUS_OBJECT_NAME_COLLISION | FsError::AlreadyExists |
| ENOTEMPTY | STATUS_DIRECTORY_NOT_EMPTY | FsError::NotEmpty |
| EIO | STATUS_UNSUCCESSFUL | FsError::Io |
| EFBIG | STATUS_FILE_TOO_LARGE | FsError::MaxFilesizeExceeded |
| ENOSPC | STATUS_DISK_FULL | FsError::NoSpace |
| ENOSYS | STATUS_NOT_IMPLEMENTED | stub operations |

---

## 8. Acceptance Criteria

First implementation PR must include:

- [ ] src/mount/windows.rs — WinFsp backend
- [ ] Cargo.toml — conditional Windows dependencies
- [ ] src/mount.rs — updated dispatch (cfg windows)
- [ ] THIRD_PARTY_LICENSES.md — WinFsp attribution
- [ ] .github/workflows/windows.yml — Windows CI
- [ ] WINDOWS_SMOKE_TEST.md — manual test checklist
- [ ] README.md — experimental Windows support note
- [ ] cargo check --target x86_64-pc-windows-msvc passes
- [ ] All non-mount unit tests pass on Windows
- [ ] No cfg(linux) leaks into shared code

### Non-goals for M1

- Mount integration tests in CI
- Security descriptor pass-through
- Named streams / ADS
- Hard links, symbolic links, sparse files

---

## 9. Implementation Roadmap

- **M1** — First PR: src/mount/windows.rs, CI build, smoke test
- **M2** — Hardening: integration tests, security descriptors, perf
- **M3** — Feature parity: symlinks, long paths, Unicode normalization

---

## References

- WinFsp: https://winfsp.dev
- WinFsp API: https://github.com/billziss-gh/winfsp/wiki
- WinFsp License: https://github.com/billziss-gh/winfsp/blob/master/License.md
- fuser crate: https://crates.io/crates/fuser
- rencfs mount/linux.rs: src/mount/linux.rs
- rencfs encryptedfs.rs: src/encryptedfs.rs
