# Windows Support Implementation Research

This document outlines the research and architectural plan for bringing native Windows support to `rencfs`. It is framed as an initial research milestone and does not claim that `rencfs` currently mounts on Windows.

## 1. Recommended Backend and Alternatives

**Recommended:** `WinFsp` (Windows File System Proxy)
WinFsp is the de facto standard for building user-mode file systems on Windows. It boasts high performance, excellent compatibility with NTFS semantics, and a robust architecture (kernel-mode FSD + user-mode DLL).

**Alternatives Considered:**
- **Dokan/DokanY:** Popular in the past but has suffered from performance bottlenecks, maintenance periods of inactivity, and compatibility issues with newer Windows 10/11 features compared to WinFsp.
- **CBFS (Callback File System):** Excellent commercial alternative with great support, but it requires paid licensing which is incompatible with an open-source project like `rencfs`.
- **ProjectProjfs (Windows Projected File System):** Good for specialized read-heavy or partial-hydration scenarios (like Git VFS), but lacks full POSIX/general-purpose filesystem capabilities required by `rencfs`.

## 2. WinFsp Licensing and Attribution

`rencfs` is distributed under a dual `MIT OR Apache-2.0` license.
WinFsp is licensed under the **GPLv3**, with a special exception: the **WinFsp API Exception**.

This exception allows any application (regardless of its license) to dynamically link to the user-mode `winfsp-x64.dll` without adopting the GPLv3 license for the application itself. Because of this exception, integrating WinFsp into `rencfs` does **not** violate the MIT/Apache-2.0 licensing, provided we dynamically link the library and do not statically compile WinFsp GPL code into our binaries.

## 3. Windows-only Dependency and Delay-Load Build Shape

To keep Linux/macOS builds clean, the WinFsp integration will use conditional compilation and delay-loading.

**Cargo configuration:**
We will use the `winfsp` Rust crate (or similar FFI bindings) as a target-specific dependency:
```toml
[target.'cfg(windows)'.dependencies]
winfsp = "0.2" # Example crate version
```

**Delay Loading:**
To allow the CLI to run on Windows without crashing if WinFsp is not installed (e.g., to just show help or run non-mount commands), we must dynamically load the WinFsp DLL at runtime rather than linking it at load time. We will verify WinFsp presence via Registry (`HKLM\SOFTWARE\WinFsp\InstallDir`) and output a helpful error message guiding the user to install WinFsp if it's missing.

## 4. Proposed `src/mount/windows.rs` Architecture

We will create a `src/mount/windows.rs` module that acts as the WinFsp service bridge to the existing `EncryptedFs` layer.

**Architecture:**
- `mount()` function detects OS, calls `mount::windows::mount()` on Windows.
- A `RencfsWinFspFileSystem` struct implements the `winfsp::FileSystemContext` trait (or raw FFI callbacks).
- This struct wraps an `Arc<EncryptedFs>`.
- The mount thread registers the filesystem with the WinFsp service and blocks until unmounted.

## 5. Operation Mapping (WinFsp Callbacks to Rencfs)

| WinFsp Callback | `rencfs` Method (`EncryptedFs`) | Notes |
| :--- | :--- | :--- |
| `GetVolumeInfo` | `statfs` equivalent | Returns volume size and free space. |
| `Open` / `Create` | `open` / `create` | Resolves path, checks permissions, returns context/handle. |
| `Read` | `read` | Maps byte ranges, triggers `rencfs` decryption stream. |
| `Write` | `write` | Triggers `rencfs` encryption stream, updates file size. |
| `GetFileInfo` | `getattr` | Maps POSIX mode/times to Windows `FILE_BASIC_INFO` / `FILE_STANDARD_INFO`. |
| `SetBasicInfo` | `setattr` | Maps Windows time/attribute updates back to `rencfs` metadata. |
| `ReadDirectory` | `readdir` | Iterates directory entries, encrypting/decrypting filenames as needed. |
| `Rename` | `rename` | Handles atomic renames. |
| `Unlink` | `unlink` / `rmdir` | Deletes files/directories. |

## 6. Metadata Decisions and Unsupported NTFS Features

For the first milestone, we will prioritize functional file access over full NTFS feature parity.

**Decisions:**
- **File Attributes:** We will map standard POSIX permissions (read/write/execute) to basic Windows Read-Only and Hidden attributes.
- **Timestamps:** Windows uses 100-nanosecond intervals since 1601. We will convert `rencfs` UNIX timestamps during `GetFileInfo` and `ReadDirectory`.

**Unsupported in Milestone 1:**
- Alternate Data Streams (ADS)
- Windows Access Control Lists (ACLs) - basic Everyone Read/Write will be used.
- Reparse points / Symlinks (unless trivially mapped to POSIX symlinks already supported by `rencfs`).
- Extended Attributes (EA) beyond what is required for basic operation.

## 7. Build/CI Plan and Manual Smoke Test

**CI Plan:**
- Add a `windows-latest` runner to GitHub Actions.
- In the CI workflow, install WinFsp via Chocolatey (`choco install winfsp -y`).
- Build the project using `cargo build --target x86_64-pc-windows-msvc`.
- Run unit tests and a brief integration test that mounts to a local drive letter (e.g., `Z:`), writes a file, reads it back, and unmounts.

**Manual Smoke Test:**
1. Install WinFsp locally.
2. Build `rencfs`.
3. Initialize an encrypted directory: `rencfs init ./cipher_dir`
4. Mount to a drive letter: `rencfs mount ./cipher_dir Z:`
5. Open Windows Explorer, navigate to `Z:`.
6. Create a text file, write data, save, and close.
7. Verify the file exists in `Z:` and its encrypted counterpart exists in `./cipher_dir`.
8. Unmount gracefully (Ctrl+C or unmount command).

## 8. Acceptance Criteria for First Implementation PR

To consider the native Windows implementation complete for the first PR, the following must be met:
- [ ] `src/mount/windows.rs` implements WinFsp callbacks mapped to `EncryptedFs`.
- [ ] Conditional compilation ensures Linux/macOS builds are unaffected.
- [ ] Missing WinFsp installation is handled gracefully at runtime.
- [ ] Manual smoke test passes (mount, read, write, unmount via Windows Explorer).
- [ ] GitHub Actions CI builds the Windows target successfully.
- [ ] No GPL code is statically linked or committed to the repository.
