# Windows Support Implementation Research

## Overview

This document researches the feasibility and architecture for porting rencfs to Microsoft Windows. Currently rencfs supports Linux exclusively via FUSE (src/mount/linux.rs), with non-Linux platforms falling back to a dummy stub (src/mount/dummy.rs). The goal is to replace the dummy stub with a production-ready Windows implementation using WinFsp.

## 1. Recommended Backend: WinFsp

WinFsp (Windows File System Proxy) is the de facto FUSE-compatible layer for Windows. It provides a kernel-mode FUSE driver, a user-mode DLL implementing FUSE 2.8/3.1 protocol, and an .msi installer.

Alternatives rejected:
- Dokan: LGPL license risk for MIT/Apache-2.0 project
- CBFS Connect: Commercial license
- ProjFS: Windows 10 1809+ only, designed for cloud sync
- Raw IFS kernel driver: Requires EV signing cert, high maintenance

### Licensing Check

WinFsp is LGPLv3-licensed. Dynamic linking (LoadLibrary/delay-load of winfsp-x64.dll) does not impose copyleft on the calling MIT/Apache-2.0 application. Do NOT statically link or bundle WinFsp source. Attribute WinFsp in NOTICE/documentation.

## 2. Architecture: src/mount/windows.rs

Replace the current two-branch cfg in src/mount.rs:

#[cfg(target_os = "linux")]
use linux::MountPointImpl;
#[cfg(target_os = "windows")]
use windows::MountPointImpl;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
use dummy::MountPointImpl;

### Dependency

[target.'cfg(target_os = "windows")'.dependencies]
winfsp-sys = "0.2"

## 3. WinFsp Callback -> rencfs Mapping

| WinFsp Callback    | rencfs Method         |
|--------------------|-----------------------|
| GetVolumeInfo      | Static metadata       |
| Create/Open        | create_file/open_file |
| Read               | read()                |
| Write              | write()               |
| Flush              | flush()               |
| GetFileInfo        | getattr()             |
| SetBasicInfo       | setattr()             |
| SetFileSize        | truncate()            |
| Rename             | rename()              |
| ReadDirectory      | readdir()             |
| Delete             | delete_file/delete_dir|
| Cleanup/Close      | close_file()          |

## 4. Mount/Unmount Lifecycle

Mount flow:
1. Detect WinFsp installation via registry (HKLM\SOFTWARE\WinFsp)
2. Initialize EncryptedFs with data_dir + password + cipher
3. Create WinFsp filesystem session
4. Mount to drive letter (e.g. "R:") or directory path
5. Return MountHandle wrapping session

Unmount: Call WinFsp unmount API.

## 5. Windows Metadata Decisions

- UID/GID: Always 0 (Windows uses SIDs, not POSIX IDs)
- Permissions: 0o755 dirs, 0o644 files (FUSE compat)
- Timestamps: NTFS 100ns -> truncate to seconds
- Hard links, symlinks, ADS, EAs: Not supported (same as Linux)

## 6. Build & CI

cargo build requires WinFsp SDK installed. GitHub Actions workflow:
- Use windows-latest runner
- Install WinFsp via msi
- cargo build + cargo test (skip mount tests on CI)

## 7. Manual Smoke Test

1. cargo build --release succeeds
2. R: drive appears in Explorer after mount
3. Create/read/delete file on R: works
4. File encrypted on disk in data_dir
5. Data persists across remount
6. Unmount works via CLI and Explorer eject
7. Crash does not leave stale mount (WinFsp auto-cleanup)

## 8. Acceptance Criteria

- Replace dummy with real windows.rs on cfg(target_os = "windows")
- Keep dummy for unknown platforms
- cargo check passes on Windows target
- No Linux regression
- Document WinFsp prerequisite in README
