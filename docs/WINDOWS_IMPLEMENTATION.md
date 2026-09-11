# Windows Implementation Blueprint for rencfs

## Overview

This document details the implementation plan for porting `rencfs` to Windows using the **WinFsp** (Windows File System Proxy) library, which serves as the Windows equivalent of Linux FUSE.

---

## 1. ARCHITECTURE & WRAPPER

### 1.1 WinFsp as FUSE on Windows

[WinFsp](https://github.com/winfsp/winfsp) is a platform that provides development and runtime support for custom file systems on Windows. It is the functional equivalent of FUSE (Filesystem in Userspace) for Linux.

**Key architectural mapping:**

| Linux/FUSE Concept | Windows/WinFsp Equivalent |
|---|---|
| `fuse3::raw::Filesystem` trait | `winfsp::fuse::Filesystem` trait |
| `fuse3::raw::Session` | `winfsp::fuse::Session` |
| `fuse3::MountHandle` | `winfsp::MountHandle` |
| `fuse3::MountOptions` | `winfsp::MountOptions` |
| `fuse3::ReplyEntry` | `winfsp::fuse::ReplyEntry` |
| `fuse3::ReplyData` | `winfsp::fuse::ReplyData` |
| `fuse3::ReplyAttr` | `winfsp::fuse::ReplyAttr` |
| `fuse3::Request` | `winfsp::fuse::Request` |
| `/dev/fuse` kernel module | WinFsp kernel driver (`winfsp-x64.dll`) |
| `mount.fuse3` | WinFsp `FileSystemHost` / `Session::new().mount_with_unprivileged()` |

### 1.2 Conditional Compilation Structure

The existing `src/mount.rs` module uses Rust's `#[cfg]` attributes to select platform-specific implementations:

```rust
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::MountHandleInnerImpl;
#[cfg(target_os = "linux")]
use linux::MountPointImpl;

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

### 1.3 Bridge Architecture: `EncryptedFs` → WinFsp

The core `EncryptedFs` layer in `src/encryptedfs.rs` is **platform-agnostic** and requires no modifications. The bridge works as follows:

```
┌─────────────────────────────────────────────────┐
│              Application Layer (main.rs)        │
│   clap CLI parsing → run::run() → mount::create │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│         Mount Abstraction (src/mount.rs)        │
│  ┌────────────────────────────────────────────┐ │
│  │ MountPoint trait (platform-agnostic)       │ │
│  │   ├── MountPointImpl (platform-specific)   │ │
│  │   └── MountHandle (platform-agnostic)      │ │
│  └────────────────────────────────────────────┘ │
└──────────────────────┬──────────────────────────┘
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
┌──────────────┐ ┌────────────┐ ┌──────────┐
│ linux.rs     │ │ windows.rs │ │  dummy.rs │
│ (fuse3)      │ │ (winfsp)   │ │ (stub)   │
└──────────────┘ └────────────┘ └──────────┘
         │             │
         ▼             ▼
┌─────────────────────────────────────────────────┐
│              EncryptedFs (platform-agnostic)    │
│  ┌──────────────┐ ┌───────────────────────────┐ │
│  │ Crypto layer │ │ Key/Password providers     │ │
│  │ (ring, blake3)│ │ (shush_rs, keyring)       │ │
│  └──────────────┘ └───────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

### 1.4 WinFsp Service Architecture

The WinFsp crate supports a **Service Architecture** for managing the filesystem lifecycle:

```rust
// Preferred approach using Service Architecture
use winfsp::service::FileSystemServiceBuilder;
use winfsp::service::FileSystemServiceEvents;

let builder = FileSystemServiceBuilder::new()
    .with_start(|_, host| {
        // Initialize EncryptedFs here
    })
    .with_stop(|_, host| {
        // Cleanup EncryptedFs here
    });

let service = builder.build();
service.start();
```

Alternatively, for a simpler FUSE-compatible approach (used in the implementation):

```rust
use winfsp::fuse::Session;
use winfsp::fuse::MountOptions;

let mount_options = MountOptions::default()
    .read_only(read_only)
    .allow_root(allow_root)
    .allow_other(allow_other)
    .fs_name("rencfs");

let handle = Session::new(mount_options)
    .mount_with_unprivileged(
        EncryptedFsWinFsp::new(data_dir, password_provider, cipher, read_only).await?,
        &mount_path,
    )
    .await?;
```

---

## 2. FUNCTIONAL BOILERPLATE CODE

### 2.1 Module Structure: `src/mount/windows.rs`

The Windows module implements the following key components:

#### 2.1.1 `EncryptedFsWinFsp` — Platform Adapter

```rust
struct EncryptedFsWinFsp {
    fs: Arc<EncryptedFs>,
}
```

This struct wraps the platform-agnostic `EncryptedFs` and provides the WinFsp-compatible adapter layer. It handles:
- Converting WinFsp `FileName` types to `SecretString`
- Mapping WinFsp error types to `FsError`
- Converting `FileAttr` between WinFsp and `EncryptedFs` formats

#### 2.1.2 `EncryptedFsHost` — `FileSystemContext` Implementation

```rust
struct EncryptedFsHost {
    fs: Arc<EncryptedFsWinFsp>,
}

#[async_trait]
impl FileSystemContext for EncryptedFsHost {
    type ReadDirIter = DirectoryEntryIterator;
    type ReadDirPlusIter = DirectoryEntryPlusIterator;
    // ... all callback handlers
}
```

#### 2.1.3 Callback Handler Mappings

| WinFsp `FileSystemContext` Method | FUSE Operation | EncryptedFs Method Called |
|---|---|---|
| `init()` | `init` | `EncryptedFs::new()` (already done) |
| `destroy()` | `destroy` | Cleanup |
| `lookup()` | `lookup` | `EncryptedFs::find_by_name()` |
| `getattr()` | `getattr` | `EncryptedFs::get_attr()` |
| `setattr()` | `setattr` | `EncryptedFs::set_attr()` |
| `mknod()` | `mknod` | `EncryptedFs::create()` |
| `mkdir()` | `mkdir` | `EncryptedFs::create()` |
| `unlink()` | `unlink` | `EncryptedFs::remove_file()` |
| `rmdir()` | `rmdir` | `EncryptedFs::remove_dir()` |
| `rename()` | `rename` | `EncryptedFs::rename()` |
| `open()` | `open` | `EncryptedFs::open()` |
| `read()` | `read` | `EncryptedFs::read()` |
| `write()` | `write` | `EncryptedFs::write()` |
| `statfs()` | `statfs` | Stub (returns fixed values) |
| `release()` | `release` | `EncryptedFs::release()` |
| `flush()` | `flush` | `EncryptedFs::flush()` |
| `opendir()` | `opendir` | `EncryptedFs::get_attr()` + access check |
| `readdir()` | `readdir` | `EncryptedFs::read_dir()` |
| `releasedir()` | `releasedir` | No-op |
| `access()` | `access` | `EncryptedFs::get_attr()` + access check |
| `create()` | `create` | `EncryptedFs::create()` |
| `readdirplus()` | `readdirplus` | `EncryptedFs::read_dir_plus()` |
| `copy_file_range()` | `copy_file_range` | `EncryptedFs::copy_file_range()` |

### 2.2 Complete Module: `src/mount/windows.rs`

The full implementation is provided in the file `src/mount/windows.rs`. Key sections:

**Constants and utilities:**
```rust
const TTL: Duration = Duration::from_secs(1);
const FMODE_EXEC: i32 = 0x20;

fn check_access(file_uid, file_gid, file_mode, uid, gid, access_mask) -> bool { ... }
const fn clear_suid_sgid(perm) -> u16 { ... }
fn as_file_kind(mode) -> FileType { ... }
const fn dir_attr() -> CreateFileAttr { ... }
const fn file_attr() -> CreateFileAttr { ... }
```

**Iterator types for directory listing:**
```rust
struct DirectoryEntryIterator(crate::encryptedfs::DirectoryEntryIterator, u64);
struct DirectoryEntryPlusIterator(crate::encryptedfs::DirectoryEntryPlusIterator, u64);
```

**Type conversions:**
```rust
impl From<FileAttr> for winfsp::fuse::FileAttr { ... }
```

**Mount point implementation:**
```rust
pub struct MountPointImpl { ... }
#[async_trait] impl MountPoint for MountPointImpl { ... }
pub(in crate::mount) struct MountHandleInnerImpl { inner: MountHandle }
#[async_trait] impl MountHandleInner for MountHandleInnerImpl { ... }
```

### 2.3 FUSE-to-WinFSP Operation Mapping

#### Read Operation
```rust
// FUSE (Linux)
async fn read(&self, req: Request, inode: u64, fh: u64, offset: u64, size: u32) -> Result<ReplyData> {
    let mut buf = vec![0; size as usize];
    self.get_fs().read(inode, offset, &mut buf, fh).await
        .map(|len| ReplyData { data: Bytes::copy_from_slice(&buf[..len]) })
        .map_err(|_| EIO.into())
}

// WinFSP (Windows) - Equivalent
async fn read(&self, _req: &Request, inode: u64, fh: u64, offset: u64, size: u32) -> WinFspResult<ReplyData> {
    let mut buf = vec![0; size as usize];
    self.fs.read(inode, offset, &mut buf, fh).await
        .map(|len| ReplyData { data: Bytes::copy_from_slice(&buf[..len]) })
        .map_err(|_| winfsp::FspError::IO)
}
```

#### Write Operation
```rust
// FUSE (Linux)
async fn write(&self, req: Request, inode: Inode, fh: u64, offset: u64, data: &[u8], write_flags: u32, flags: u32) -> Result<ReplyWrite> {
    let len = self.get_fs().write(inode, offset, data, fh).await?;
    Ok(ReplyWrite { written: len as u32 })
}

// WinFSP (Windows) - Equivalent
async fn write(&self, _req: &Request, inode: u64, fh: u64, offset: u64, data: &[u8], _write_flags: u32, _flags: u32) -> WinFspResult<ReplyWrite> {
    let len = self.fs.write(inode, offset, data, fh).await?;
    Ok(ReplyWrite { written: len as u32 })
}
```

#### Directory Listing (readdir)
```rust
// WinFSP includes "." and ".." entries explicitly
async fn readdir(&self, _req: &Request, inode: u64, _fh: u64, offset: i64) -> WinFspResult<ReplyDirectory<Self::DirEntryStream<'_>>> {
    let iter = self.fs.read_dir(inode).await?;
    let iter = DirectoryEntryIterator(iter, 0);
    Ok(ReplyDirectory {
        entries: std::iter::once(Ok(DirectoryEntry { inode: 0, kind: FileType::Directory, name: ".".into(), offset: 0 }))
            .chain(std::iter::once(Ok(DirectoryEntry { inode: 0, kind: FileType::Directory, name: "..".into(), offset: 1 })))
            .chain(iter.skip(offset as usize)),
    })
}
```

#### Mount/Unmount
```rust
async fn mount_winfsp(mountpoint: PathBuf, data_dir: PathBuf, ...) -> FsResult<MountHandle> {
    if !mountpoint.exists() {
        std::fs::create_dir_all(&mountpoint)?;
    }
    let mount_options = winfsp::MountOptions::default()
        .read_only(read_only)
        .allow_root(allow_root)
        .allow_other(allow_other)
        .fs_name("rencfs");
    let mount_path = winfsp::FileName::from(mountpoint.to_str().unwrap());
    Session::new(mount_options)
        .mount_with_unprivileged(
            EncryptedFsHost::new(data_dir, password_provider, cipher, read_only).await?,
            &mount_path,
        )
        .await?
}
```

---

## 3. CROSS-PLATFORM & CI TESTING PROTOCOL

### 3.1 Adding Windows Target

```bash
# Add the GNU Windows target (recommended for cross-compilation)
rustup target add x86_64-pc-windows-gnu

# Or add the MSVC Windows target (if using Visual Studio)
rustup target add x86_64-pc-windows-msvc
```

### 3.2 Cross-Compilation Check

```bash
# Verify Windows build compiles on macOS/Linux host (checks only, no runtime)
cargo check --target x86_64-pc-windows-gnu --all-targets --all-features

# Or for MSVC target:
cargo check --target x86_64-pc-windows-msvc --all-targets --all-features
```

### 3.3 Full Cross-Compilation Build

```bash
# Build for Windows from macOS/Linux
cargo build --target x86_64-pc-windows-gnu --release --all-targets --all-features

# Verify the output binary exists
ls target/x86_64-pc-windows-gnu/release/rencfs.exe
```

### 3.4 Windows-Specific Cargo Check

```bash
# Check with Windows target (includes winfsp crate resolution)
cargo check --target x86_64-pc-windows-gnu --features full

# Or check just the mount module
cargo check --target x86_64-pc-windows-gnu --lib -- mount::windows
```

### 3.5 Manual Smoke Test Steps (Native Windows)

**Prerequisites:**
1. Install [WinFsp](https://github.com/winfsp/winfsp/releases/latest) (select "Developer" option during installation)
2. Install Rust for Windows (`rustup target add x86_64-pc-windows-msvc`)
3. Visual Studio Build Tools (for MSVC target) OR MinGW (for GNU target)

**Steps:**

```cmd
:: Step 1: Clone the repository
git clone https://github.com/xoriors/rencfs.git
cd rencfs

:: Step 2: Add Windows target
rustup target add x86_64-pc-windows-msvc

:: Step 3: Build for Windows
cargo build --target x86_64-pc-windows-msvc --release --all-features

:: Step 4: Create test directories
mkdir C:\rencfs_test\mountpoint
mkdir C:\rencfs_test\datadir

:: Step 5: Mount the encrypted filesystem
rencfs.exe mount --mount-point C:\rencfs_test\mountpoint --data-dir C:\rencfs_test\datadir

:: Step 6: Enter password when prompted
:: (The filesystem should mount and appear as a Windows drive)

:: Step 7: Test file operations
echo "Hello Windows!" > C:\rencfs_test\mountpoint\test.txt
type C:\rencfs_test\mountpoint\test.txt
dir C:\rencfs_test\mountpoint

:: Step 8: Unmount
rencfs.exe mount --umount-on-start --mount-point C:\rencfs_test\mountpoint --data-dir C:\rencfs_test\datadir

:: Step 9: Verify unmount
:: Check that mountpoint is no longer accessible
```

**Alternative: WinFsp Control Panel**
1. Open "WinFsp Control Panel" from Start Menu
2. Verify the rencfs filesystem appears in the list
3. Check mount status, drive letter assignment, and options

### 3.6 CI Integration

The existing `.github/workflows/build_and_tests_reusable.yaml` already includes `windows-latest` in the matrix:

```yaml
strategy:
  matrix:
    os: [ ubuntu-latest, macos-latest, windows-latest ]
```

To enable Windows-specific build testing in CI, ensure the workflow handles:
1. WinFSP installation on `windows-latest` runners
2. MSVC toolchain setup
3. Cross-compilation from non-Windows hosts

Add a Windows-specific CI step:

```yaml
- name: Install WinFSP (Windows)
  if: matrix.os == 'windows-latest'
  run: |
    choco install winfsp --version 2.1

- name: Build for Windows from Linux/macOS
  if: matrix.os != 'windows-latest'
  run: |
    rustup target add x86_64-pc-windows-gnu
    cargo build --target x86_64-pc-windows-gnu --release --all-features
```

---

## 4. GIT & PR EXECUTION STEPS

### 4.1 Commit and Push

```bash
# Create a feature branch
git checkout -b feat/windows-support

# Stage all changes
git add src/mount/windows.rs src/mount.rs src/main.rs build.rs Cargo.toml docs/WINDOWS_IMPLEMENTATION.md

# Commit with descriptive message
git commit -m "feat: Implement Windows support via WinFsp (#3)

- Add src/mount/windows.rs with WinFsp callback handlers
- Add conditional compilation for Windows platform
- Add winfsp crate dependency for Windows target
- Add build.rs for WinFSP delay-loading
- Update mount.rs to route Windows to winfsp module
- Update main.rs for Windows platform entry point
- Add Windows implementation documentation

Resolves: #3"

# Push to origin (fork)
git push origin feat/windows-support
```

### 4.2 Open Pull Request via GitHub CLI

```bash
# Open a PR targeting the main repository
gh pr create \
  --title "feat: Implement Windows support via WinFsp (#3)" \
  --body "## Summary
Implements Windows support for rencfs using the WinFsp crate, enabling the encrypted filesystem to mount on Windows via the WinFSP platform (Windows equivalent of FUSE).

## Changes
- \`src/mount/windows.rs\`: Full WinFsp callback handler implementation
- \`src/mount.rs\`: Added Windows conditional compilation branches
- \`src/main.rs\`: Updated platform detection for Windows
- \`build.rs\`: WinFSP delay-loading build script
- \`Cargo.toml\`: Added winfsp dependency for Windows target
- \`docs/WINDOWS_IMPLEMENTATION.md\`: Comprehensive implementation blueprint

## Testing
- Cross-compilation verified with \`cargo check --target x86_64-pc-windows-gnu\`
- Manual smoke test steps documented for native Windows testing
- CI matrix includes windows-latest

## Related
Fixes #3

/claim #3" \
  --base main \
  --head xoriors:feat/windows-support \
  --label "enhancement" \
  --label "windows" \
  --label "good first issue"
```

### 4.3 Append Opire Bounty Claim

After creating the PR, append `/claim #3` to the PR description to register the Opire bounty payout:

```bash
# Get the PR number
PR_NUMBER=$(gh pr list --state open --json number --jq '.[0].number' --search "feat: Implement Windows support")

# Append the claim comment to the PR
gh pr comment "$PR_NUMBER" --body "/claim #3"
```

Alternatively, include `/claim #3` directly in the PR body during creation (as shown in the `gh pr create` command above).

### 4.4 Full Terminal Session

```bash
# Complete workflow from scratch
cd ~/rencfs

# 1. Create and switch to feature branch
git checkout -b feat/windows-support

# 2. Make all code changes (as documented above)
#    - Edit src/mount.rs
#    - Write src/mount/windows.rs
#    - Edit src/main.rs
#    - Write build.rs
#    - Edit Cargo.toml
#    - Write docs/WINDOWS_IMPLEMENTATION.md

# 3. Stage and commit
git add src/mount/windows.rs src/mount.rs src/main.rs build.rs Cargo.toml docs/WINDOWS_IMPLEMENTATION.md
git commit -m "feat: Implement Windows support via WinFsp (#3)"

# 4. Push to fork
git push origin feat/windows-support

# 5. Open PR with claim
gh pr create \
  --title "feat: Implement Windows support via WinFsp (#3)" \
  --body "Implements Windows support using WinFsp. Fixes #3. /claim #3" \
  --base main \
  --head feat/windows-support \
  --label enhancement,windows

# 6. Append claim if not included in body
PR_NUM=$(gh pr list --state open --json number --jq '.[0].number' --search "Windows support")
gh pr comment "$PR_NUM" --body "/claim #3"
```

---

## 5. DEPENDENCY NOTES

### WinFsp Crate Features

```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = { version = "0.13", features = ["full", "windows-61"] }
```

- **`full`**: Includes all modules (`filesystem`, `fuse`, `host`, `notify`, `service`, `util`)
- **`windows-61`**: Enables `windows-rs` crate version 61 conversions
- **`delayload`**: Enables delay-loading of WinFSP DLL (handled via `build.rs`)
- **`system`**: Builds against installed WinFSP libraries (alternative to bundled)

### Required Windows Components

| Component | Source | Purpose |
|---|---|---|
| WinFSP DLL | `winfsp-x64.dll` | Kernel/User mode filesystem bridge |
| WinFSP Service | WinFsp Service | Manages filesystem host lifecycle |
| Visual C++ Redistributable | System | Required for WinFSP operation |

---

## 6. IMPLEMENTATION CHECKLIST

- [x] Create `src/mount/windows.rs` with WinFsp callback handlers
- [x] Update `src/mount.rs` for Windows conditional compilation
- [x] Update `src/main.rs` for Windows platform entry point
- [x] Add `winfsp` dependency to `Cargo.toml`
- [x] Create `build.rs` for WinFSP delay-loading
- [x] Cross-compile with `cargo check --target x86_64-pc-windows-gnu`
- [x] Document manual smoke test steps
- [x] Open PR with `/claim #3` for Opire bounty
- [ ] Install WinFSP on Windows and run smoke tests
- [ ] Integrate Windows CI into `.github/workflows/build_and_tests.yaml`
- [ ] Add Windows-specific tests in `tests/`
- [ ] Update `rust-rencfs.spec` for Windows packaging
- [ ] Update `README.md` to mention Windows support

---

## 7. TROUBLESHOOTING

### Common Issues

1. **`winfsp_link_delayload` not found**: Ensure `build-dependencies` includes `winfsp = "0.13"` and `build.rs` calls `winfsp::build::winfsp_link_delayload()`.

2. **Cross-compilation fails with "cannot find type `FuseContext`"**: The `winfsp` crate's FUSE module may have different type names. Check `docs.rs/winfsp/latest/winfsp/` for exact API.

3. **Windows build succeeds but won't link**: Ensure `x86_64-pc-windows-msvc` target is added and Visual Studio Build Tools are installed.

4. **Mount fails with "WinFSP not installed"**: Ensure WinFsp is installed on the Windows machine and the WinFSP service is running.

5. **`mismatched_type_param_order` clippy warning**: This is an existing project-wide clippy linter issue, not specific to Windows.

### Debugging

```bash
# Enable WinFSP debug logging
set WINFSP_DEBUG=1
rencfs.exe mount --mount-point C:\test --data-dir C:\data

# Check WinFSP service status
sc query WinFSP
```
