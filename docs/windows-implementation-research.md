# Windows Implementation Research for rencfs

> **Status:** Research document — milestone 0.  
> This document describes a concrete, actionable implementation path for native Windows support in rencfs.  
> It is intentionally scoped to *what must be true* before the first working prototype PR, not a finished implementation.

---

## 1. Problem Statement

rencfs currently compiles on Windows but mounts nothing — the `#[cfg(not(target_os = "linux"))]` branch falls through to `src/mount/dummy.rs`, which returns `FsError::Other("Dummy implementation")` on every `mount()` call. Windows users cannot use rencfs as a virtual filesystem today.

The goal of this research is to identify the lowest-friction path from the current dummy implementation to a Mount Point that:

1. Exposes the existing `EncryptedFs` layer as a real filesystem visible in Windows Explorer.
2. Compiles cleanly on a Windows host with the chosen backend.
3. Does not break existing Linux CI.
4. Passes a manual smoke-test (write file → reopen after remount → contents correct).

---

## 2. Backend Candidates

### 2.1 WinFsp (Recommended)

[WinFsp](https://github.com/winfsp/winfsp) is the de-facto standard FUSE-equivalent for Windows, used by Dokan successors, SSHFS-win, rclone mount, and many others.

| Property | Detail |
|---|---|
| License | GPLv3 + commercial exception for OSS projects |
| Rust binding | [`winfsp-rs`](https://github.com/SnowflakePowered/winfsp-rs) (MIT) |
| Runtime requirement | WinFsp installer must be present on target machine |
| Tested OS | Windows 10 21H2+, Windows 11, Windows Server 2019+ |
| FUSE compatibility | WinFsp ships a FUSE3 compatibility layer (`winfsp/inc/fuse3`) |

**Licensing checkpoint:**  
WinFsp is GPLv3 with a **FLOSS exception** — any OSS project under an approved FLOSS license (Apache-2.0 ✅, MIT ✅) may use WinFsp without the copyleft restriction applying. rencfs is `MIT OR Apache-2.0`, so distribution of WinFsp-linked binaries is permissible under the FLOSS exception without additional action beyond attribution.

Required attribution in `README.md`:

```
Windows filesystem support provided by [WinFsp](https://github.com/winfsp/winfsp) (GPLv3 + FLOSS exception).
```

### 2.2 Dokan (Not Recommended)

Dokan2 Rust binding (`dokan-rust`) is actively maintained but the driver install is more invasive and less widely deployed than WinFsp. WinFsp ships a Dokan compatibility shim anyway, so there is no scenario where Dokan2 is strictly better.

### 2.3 ProjFS (Rejected for Milestone 1)

Windows Projected Filesystem is suited for virtual read-only views (like Git VFS). It does not support full read-write mutable file semantics without significant extra plumbing. Not appropriate for rencfs's use case.

### 2.4 FUSE-compatible user-mode approach via `winfsp-rs`

`winfsp-rs` exposes a safe Rust API that maps closely to the FUSE3 `Filesystem` trait already implemented in `src/mount/linux.rs`. This is the lowest-effort path: implement `winfsp_rs::filesystem::FileSystemContext` for a new struct that delegates to the existing `EncryptedFs`.

---

## 3. Proposed Module Architecture

### 3.1 File layout

```
src/mount/
├── dummy.rs          # unchanged (non-Linux, non-Windows fallback)
├── linux.rs          # unchanged
├── windows.rs        # NEW — WinFsp-backed implementation
└── mod.rs            # add #[cfg(target_os = "windows")] mod windows;
```

### 3.2 Cargo.toml changes

```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp-rs = { version = "0.3", features = ["notify"] }
windows = { version = "0.58", features = [
    "Win32_Foundation",
    "Win32_Storage_FileSystem",
    "Win32_Security",
    "Win32_System_IO",
] }

[target.'cfg(target_os = "windows")'.build-dependencies]
winfsp-build = "0.3"
```

The `winfsp-build` crate handles link-library discovery at build time and emits the correct `cargo:rustc-link-lib` directives. It requires WinFsp to be installed at build time (standard location `C:\Program Files (x86)\WinFsp`).

### 3.3 `mount.rs` conditional compilation additions

```rust
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::MountHandleInnerImpl;
#[cfg(target_os = "windows")]
use windows::MountPointImpl;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod dummy;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
use dummy::MountHandleInnerImpl;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
use dummy::MountPointImpl;
```

### 3.4 `src/mount/windows.rs` — skeleton

```rust
//! Windows FUSE mount backend using WinFsp via winfsp-rs.

use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;

use async_trait::async_trait;
use shush_rs::SecretString;
use tokio::sync::oneshot;
use winfsp_rs::filesystem::{FileContextKind, FileSystemContext, FileSystemHost, MountOptions as WinFspMountOptions};
use winfsp_rs::U16CString;

use crate::crypto::Cipher;
use crate::encryptedfs::{EncryptedFs, FsResult, PasswordProvider};
use crate::mount::{MountHandleInner, MountPoint};

pub struct MountPointImpl {
    mountpoint: PathBuf,
    data_dir: PathBuf,
    password_provider: Box<dyn PasswordProvider>,
    cipher: Cipher,
    allow_root: bool,
    allow_other: bool,
    read_only: bool,
}

#[async_trait]
impl MountPoint for MountPointImpl {
    fn new(
        mountpoint: PathBuf,
        data_dir: PathBuf,
        password_provider: Box<dyn PasswordProvider>,
        cipher: Cipher,
        allow_root: bool,
        allow_other: bool,
        read_only: bool,
    ) -> Self {
        Self {
            mountpoint,
            data_dir,
            password_provider,
            cipher,
            allow_root,
            allow_other,
            read_only,
        }
    }

    async fn mount(self) -> FsResult<crate::mount::MountHandle> {
        // 1. Initialise EncryptedFs (same as linux.rs)
        let fs = Arc::new(
            EncryptedFs::new(
                self.data_dir.clone(),
                self.password_provider,
                self.cipher,
            )
            .await?,
        );

        // 2. Build WinFsp host
        let mountpoint_str = U16CString::from_os_str(
            self.mountpoint.as_os_str(),
        )
        .map_err(|_| crate::encryptedfs::FsError::Other("invalid mountpoint path"))?;

        let opts = WinFspMountOptions::default()
            .read_only(self.read_only)
            .case_sensitive_search(false);   // NTFS convention

        let ctx = WinFspContext { fs: fs.clone() };

        let (stop_tx, stop_rx) = oneshot::channel::<()>();

        // 3. Spawn blocking WinFsp host thread (WinFsp expects a Windows thread)
        tokio::task::spawn_blocking(move || {
            let mut host = FileSystemHost::new(ctx, &mountpoint_str, opts)
                .expect("WinFsp: failed to create FileSystemHost");
            host.start().expect("WinFsp: failed to start");
            // Block until unmount signal
            let _ = tokio::runtime::Handle::current()
                .block_on(stop_rx);
            host.stop();
        });

        Ok(crate::mount::MountHandle {
            inner: MountHandleInnerImpl { _stop: stop_tx },
        })
    }
}

/// WinFsp filesystem context — bridges WinFsp callbacks to EncryptedFs.
struct WinFspContext {
    fs: Arc<EncryptedFs>,
}

/// Implement FileSystemContext for WinFspContext.
/// Each method maps a WinFsp callback to the appropriate EncryptedFs FsResult call.
/// Full implementation is out of scope for milestone 0 (left as `unimplemented!` stubs).
impl FileSystemContext for WinFspContext {
    type FileContext = u64; // inode number used as file handle
    const KIND: FileContextKind = FileContextKind::Descriptor;

    // Required stubs — each will be filled in the follow-up implementation PR.
    fn get_volume_info(&self, _out: &mut winfsp_rs::filesystem::VolumeInfo) -> winfsp_rs::Result<()> {
        unimplemented!("milestone 1")
    }
    // ... (open, close, read, write, create, cleanup, read_directory, get_file_info, set_basic_info, etc.)
}

pub(in crate::mount) struct MountHandleInnerImpl {
    _stop: oneshot::Sender<()>,
}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Will be ready when the WinFsp thread drops (on unmount)
        Poll::Pending
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(self) -> io::Result<()> {
        // Dropping _stop signals the WinFsp thread to call host.stop()
        drop(self._stop);
        Ok(())
    }
}
```

---

## 4. Operation Mapping

The table below maps each WinFsp `FileSystemContext` callback to the corresponding `EncryptedFs` method. This drives the implementation checklist for the first real PR.

| WinFsp callback | `EncryptedFs` method | Notes |
|---|---|---|
| `get_volume_info` | — | Return fixed FsInfo (1 TB virtual) |
| `create` | `create_node` | Map `FileAttributes` → `CreateFileAttr` |
| `open` | `get_inode` / `open` | Returns inode as `FileContext` |
| `close` | `release` | Flush dirty pages |
| `read` | `read` | Translates offset+length into `EncryptedFs::read` |
| `write` | `write` | `constrained_io` flag maps to append-only check |
| `flush` | `flush` | |
| `get_file_info` | `get_attr` | Converts `FileAttr` → `FileInfo` |
| `set_basic_info` | `set_attr` | Maps `SetBasicInfo` fields → `SetFileAttr` |
| `rename` | `rename` | Check move-across-dirs |
| `read_directory` | `read_dir` | Iterate `DirectoryEntryIterator` |
| `cleanup` | — | Trigger delete-on-close if flagged |
| `overwrite` | `truncate` | |
| `get_security` | — | Return minimal DACL (owner: current user, full control) |
| `set_security` | — | No-op in milestone 1 (NTFS security is advisory) |

### Metadata decisions for milestone 1

- **File times:** `EncryptedFs` stores `atime`, `mtime`, `ctime` as `SystemTime`. These map directly to WinFsp's `FILETIME` (via `windows::Win32::Foundation::FILETIME`).
- **Allocation size:** Report `ceil(size / 4096) * 4096` (4 KB cluster size) — matches NTFS convention.
- **Inode as file handle:** WinFsp's `FileContext` is an opaque pointer; storing the inode as a `u64` cast to pointer is safe because rencfs inodes are stable for the lifetime of the mount.
- **Case sensitivity:** WinFsp mounts are case-insensitive by default. `EncryptedFs` stores filenames case-sensitively; the mapping layer must call `get_attr_by_name_ci` (case-insensitive lookup, to be added) for open/lookup calls.
- **Unsupported NTFS features (milestone 1):** alternate data streams, reparse points, object IDs, hardlinks (rencfs inode model is 1:1 path to inode). These return `STATUS_NOT_SUPPORTED`.

---

## 5. Build & CI Plan

### 5.1 Local build (developer)

Prerequisites on Windows host:
1. Install [WinFsp 2.0+](https://winfsp.dev/rel/) (standard installer).
2. Rust stable `x86_64-pc-windows-msvc` toolchain.
3. `cargo build --target x86_64-pc-windows-msvc`

The `winfsp-build` crate detects WinFsp's MSVC library at `C:\Program Files (x86)\WinFsp\lib\winfsp-x64.lib` and emits `cargo:rustc-link-lib=winfsp-x64`.

### 5.2 CI addition (GitHub Actions)

Add to `.github/workflows/`:

```yaml
name: Windows CI
on: [push, pull_request]
jobs:
  windows:
    runs-on: windows-2022
    steps:
      - uses: actions/checkout@v4
      - name: Install WinFsp
        run: |
          $url = "https://github.com/winfsp/winfsp/releases/download/v2.0/winfsp-2.0.23075.msi"
          Invoke-WebRequest $url -OutFile winfsp.msi
          Start-Process msiexec.exe -ArgumentList '/i winfsp.msi /quiet' -Wait
        shell: pwsh
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: x86_64-pc-windows-msvc
      - name: Build (no test — requires WinFsp kernel driver loaded)
        run: cargo build --target x86_64-pc-windows-msvc
      - name: Unit tests (no mount)
        run: cargo test --target x86_64-pc-windows-msvc -- --skip integration
```

Note: Integration tests that actually mount a virtual drive require the WinFsp *kernel driver* to be loaded, which is unavailable on standard GitHub-hosted runners. Mount tests must be run on a self-hosted Windows runner or validated manually.

### 5.3 Manual smoke test

On a Windows machine with WinFsp installed:

```powershell
# Build
cargo build --release --target x86_64-pc-windows-msvc

# Mount
.\target\release\rencfs.exe mount --data-dir C:\rencfs-data --mount W: --cipher AES256GCM

# Verify
echo "hello rencfs" > W:\test.txt
cat W:\test.txt   # should print "hello rencfs"

# Unmount
.\target\release\rencfs.exe umount W:

# Re-mount and verify persistence
.\target\release\rencfs.exe mount --data-dir C:\rencfs-data --mount W: --cipher AES256GCM
cat W:\test.txt   # should still print "hello rencfs"
```

---

## 6. Acceptance Criteria for Milestone 1 (Implementation PR)

A follow-up PR implementing the actual Windows mount will be considered complete when:

- [ ] `cargo build --target x86_64-pc-windows-msvc` succeeds with no warnings on a machine with WinFsp installed.
- [ ] `cargo test --target x86_64-pc-windows-msvc -- --skip integration` passes (unit tests for `EncryptedFs`, crypto layer, etc.).
- [ ] Manual smoke test: write file → unmount → remount → file readable with correct contents.
- [ ] `cargo clippy --target x86_64-pc-windows-msvc` produces no new errors.
- [ ] Linux CI (`cargo test --target x86_64-unknown-linux-gnu`) still passes (no regression).
- [ ] WinFsp attribution added to `README.md`.
- [ ] `WINDOWS_SUPPORT.md` updated to reflect tested WinFsp version.

---

## 7. Open Questions for Maintainer

1. **`MountHandle` field visibility:** `MountHandle.inner` is currently private; the Windows `MountPointImpl::mount()` needs to construct it. Suggest making `inner` `pub(crate)` or adding a `pub(crate) fn new_with_inner(inner: MountHandleInnerImpl) -> MountHandle` constructor.
2. **Case-insensitive lookup:** `EncryptedFs` does not expose a case-insensitive `lookup`. Should this be added to the `EncryptedFs` API, or handled in the Windows layer via a directory scan + Unicode fold?
3. **Security descriptors:** Is a static "owner: current process SID, full control" DACL acceptable for milestone 1, or is there a preference for inheriting parent or a configurable ACL?
4. **WinFsp version pin:** Should `winfsp-rs` be pinned to a specific WinFsp runtime version or track the latest?

---

## 8. References

- [WinFsp FOSS exception](https://github.com/winfsp/winfsp/blob/master/License.txt)
- [`winfsp-rs` crate](https://github.com/SnowflakePowered/winfsp-rs)
- [WinFsp FileSystemContext trait](https://winfsp.dev/doc/WinFsp-API-FUSE/)
- [rencfs `EncryptedFs` trait](./src/encryptedfs.rs)
- [rencfs Linux FUSE implementation](./src/mount/linux.rs)
- [GitHub Actions WinFsp install example](https://github.com/nicowillis/winfsp-actions)
