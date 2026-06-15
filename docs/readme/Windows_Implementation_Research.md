# Windows Support Implementation Research

This document outlines the proposed architecture, dependencies, and necessary considerations for bringing native Windows support to `rencfs`. It is intended to guide the first implementation pull request.

## 1. Backend Recommendation: WinFsp

To implement a user-space file system on Windows, the recommended backend is **WinFsp** (Windows File System Proxy).

### Why WinFsp?
* **FUSE Compatibility**: WinFsp provides a FUSE compatibility layer that is highly regarded and widely used by other Rust projects.
* **Stability and Performance**: It is actively maintained, stable, and provides excellent performance compared to alternatives like Dokany.
* **Alternatives Considered**: 
  * *Dokany*: A fork of Dokan. While capable, it has historically struggled with edge cases in NT namespace semantics and performance under high load compared to WinFsp.
  * *ProjFS (Projected File System)*: A native Windows API, but it's fundamentally different from FUSE (it's designed for projecting existing remote files, not a generic block-level FS) and would require a complete rewrite of the `rencfs` mounting logic.

### Licensing and Attribution Checkpoint
WinFsp is licensed under **GPLv3**. Because `rencfs` is licensed under MIT OR Apache-2.0, statically linking WinFsp's libraries could force `rencfs` to adopt GPLv3. 
* **Resolution**: We must use a delay-load approach or ensure that the user-mode library (`winfsp.dll`) is dynamically linked. This is typically handled by dynamically loading the DLL at runtime, which avoids the GPL virality, provided we include the proper attribution and do not distribute the DLL ourselves without adhering to the GPL. We must clearly document in our README that Windows users need to install WinFsp themselves.

## 2. Build Shape & Dependencies

We need to abstract the OS-specific mounting logic.

* **Dependencies**:
  * We will rely on a Windows-compatible FUSE wrapper (such as `fuse3`'s Windows features if available, or a dedicated crate like `winfsp-rs`).
  * These dependencies should be restricted to the Windows build via `Cargo.toml`:
    ```toml
    [target.'cfg(target_os = "windows")'.dependencies]
    winfsp = "0.2" # Example dependency
    ```
* **Delay-load Build Shape**: The implementation should not fail to compile if the WinFsp headers are missing; it should fail gracefully at *runtime* if the WinFsp service and DLLs are not installed on the host machine.

## 3. Proposed Architecture (`src/mount/windows.rs`)

The `src/mount` (or similar VFS entry point in `rencfs`) directory will need an abstraction.

```rust
#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;
```

The `windows.rs` file will implement the filesystem trait required by the chosen Windows FUSE/WinFsp library. It will act as an adapter, translating WinFsp/Windows VFS calls into `rencfs`'s core cryptographic read/write operations.

## 4. Operation Mapping & Metadata Decisions

Windows NT semantics differ significantly from POSIX.
* **File Permissions**: POSIX `chmod` (UID/GID and 777 permissions) do not map cleanly to Windows ACLs (Access Control Lists). 
  * *Decision*: The initial Windows implementation should ignore complex ACLs and project a dummy owner (the current user) and full permissions (Read/Write/Execute) to all files within the mount, similar to how exFAT is treated on Linux.
* **File Times**: Windows tracks Creation Time, Last Access Time, Last Write Time, and Change Time.
  * *Decision*: `rencfs` needs to ensure these map to `ctime`, `mtime`, and `atime` properly. Creation time might need to be stored in the encrypted metadata header if we want to preserve it accurately, otherwise it can fallback to `mtime`.
* **Path Separators**: `rencfs` must handle internal paths using `/` but accept `\` from the Windows VFS layer.

## 5. Build and CI Plan

To ensure cross-platform compatibility without breaking Linux builds:
* **CI Strategy**: Add a `windows-latest` matrix job to the GitHub Actions workflow (`.github/workflows/build_and_tests.yaml`).
* The Windows CI job should install WinFsp via Chocolatey (`choco install winfsp`) before running `cargo test` and `cargo build`.

## 6. Acceptance Criteria for First Implementation PR

The initial PR implementing Windows support should meet the following criteria:
1. `rencfs` compiles on `target_os = "windows"`.
2. A new `src/mount/windows.rs` (or equivalent) module exists and correctly bridges `rencfs` core logic with a Windows VFS backend (e.g., WinFsp).
3. The CLI supports a `mount` command on Windows that successfully attaches a drive letter (e.g., `Z:\`) or a mount point.
4. Basic read/write and directory creation operations work and are correctly encrypted on the disk.
5. The CI pipeline includes a Windows build check.
6. Documentation is updated to instruct Windows users to install WinFsp.
