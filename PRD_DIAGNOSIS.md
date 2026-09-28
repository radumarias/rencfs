# PRD: #3: research implementation for Windows

## 1. Executive Summary & Problem Statement
`rencfs` is an encrypted filesystem implemented in Rust that currently mounts exclusively on Linux via FUSE (`fuse3::Filesystem`). Issue #3 calls for researching and planning a Windows implementation. Unlike Linux, Windows does not provide native in-kernel FUSE support. Furthermore, `rencfs` historically contained hardcoded POSIX assumptions including unconditional `libc` dependencies, UID/GID handling, Unix `umount` execution, and early process termination in `src/main.rs` on non-Linux platforms.

This initiative defines the Windows architecture, documents an Architecture Decision Record (ADR), establishes the POSIX-to-Windows filesystem semantic translation specifications, and provides a proof-of-concept mount backend using WinFsp.

## 2. Technology Evaluation & Decision Record (ADR)

### 2.1 Evaluated Technologies
1. **WinFsp (Windows File System Proxy)**: Mature user-mode filesystem stack with a kernel driver signed by Microsoft. Offers a FUSE-compatible callback model and first-class Rust bindings (`winfsp` / `winfsp-rs`). Used at scale by `rclone` and `sshfs-win`. Supports delayed DLL loading.
2. **Dokany**: User-mode filesystem library; however, its Rust bindings are less actively maintained, and driver lifecycle management is less robust.
3. **Windows ProjFS (Projected File System)**: Microsoft's virtualization provider (used for Git VFS / OneDrive). Designed for read-heavy projections with local virtualization, unsuitable for a general read/write encrypted block vault.
4. **NFS/SMB Loopback**: Emulating an in-process network server introduces substantial network overhead, firewall friction, and security risks on localhost.
5. **WSL2**: Running a Linux VM fails to deliver a native Windows drive/directory mount experience.

### 2.2 Decision
**Adopt WinFsp** via the `winfsp` crate behind a new `windows-mount` feature flag. The core encryption engine (`encryptedfs`) remains completely platform-agnostic, with all Windows-specific VFS adaptations isolated within `src/mount/windows/`.

## 3. POSIX to Windows Semantic Mapping Specification

### 3.1 Ownership and Identity
- Unix `uid` and `gid` have no direct equivalent in Windows user-mode filesystem contexts. Crate-level `UID` and `GID` resolve to `0` on Windows.
- Security descriptors are synthesized (owner = current user SID, `Everyone:Full` DACL). File mode permissions map only to the `FILE_ATTRIBUTE_READONLY` flag when write bits are absent.

### 3.2 Error Code Mapping (`FsError` -> `NTSTATUS`)
- `NotFound` -> `STATUS_OBJECT_NAME_NOT_FOUND`
- `AlreadyExists` -> `STATUS_OBJECT_NAME_COLLISION`
- `InvalidInput` -> `STATUS_INVALID_PARAMETER`
- `PermissionDenied` -> `STATUS_ACCESS_DENIED`
- `IsDirectory` -> `STATUS_FILE_IS_A_DIRECTORY`
- `NotADirectory` -> `STATUS_NOT_A_DIRECTORY`
- `NotEmpty` -> `STATUS_DIRECTORY_NOT_EMPTY`
- `Other(_)` -> `STATUS_UNEXPECTED_IO_ERROR`

### 3.3 Path & Filename Rules
- Reject filenames containing invalid characters: `< > : " / \ | ? *` and ASCII control characters (0-31).
- Reject DOS reserved device names: `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9` (including filenames with extensions like `CON.txt`).
- Enforce component length limits of 255 UTF-16 code units.
- Support case-insensitive lookups while preserving casing on disk.

### 3.4 Timestamps & Delete Semantics
- Bi-directional conversion between `std::time::SystemTime` (1970 UNIX epoch) and Windows `FILETIME` (100-nanosecond intervals since Jan 1, 1601).
- Implement Windows delete-pending semantics (`CanDelete`/`cleanup`): files unlinked while open remain physically in storage until the last handle closes.

## 4. Architectural Modifications & File Scope
- `docs/windows_support_research.md`: Research paper, comparison matrix, ADR, semantic specification, and risk register.
- `Cargo.toml`: Move `libc` to `[target.'cfg(unix)'.dependencies]`; add `winfsp = { version = "0.13", optional = true }` under Windows target; declare `windows-mount` feature.
- `build.rs`: Emit MSVC linker flags (`/DELAYLOAD:winfsp-x64.dll`) when compiling on Windows with `windows-mount`.
- `src/lib.rs` & `src/encryptedfs.rs`: Gate `libc` imports under `cfg(unix)` and fallback to `0` for `UID`/`GID` on Windows.
- `src/mount.rs`: Route `MountPoint` and `MountHandle` to `windows` module when targeting Windows with `windows-mount`; gate `umount` shell-out to Unix.
- `src/mount/windows_semantics.rs`: Pure, platform-independent translation utilities with extensive unit tests.
- `src/mount/windows/mod.rs`: WinFsp `FileSystemContext` implementation bridging WinFsp callbacks to `EncryptedFs`.
- `src/main.rs` & `src/run.rs`: Enable CLI commands on Windows when `windows-mount` feature is present.
- `.github/workflows/build_and_tests_reusable.yaml`: Add unit tests and clippy verification on `windows-latest`.

## 5. Implementation Roadmap & Milestones
- **Milestone 1 (Research & Decoupling)**: Document ADR, isolate POSIX libc dependencies, and build platform-independent semantics module.
- **Milestone 2 (WinFsp PoC Adapter)**: Implement WinFsp callback adapter and delay-load build scripts for Windows mounts.
- **Milestone 3 (Verification & CI)**: Validate with cross-platform unit tests and GitHub Actions Windows runners.