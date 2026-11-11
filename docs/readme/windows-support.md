# Windows Support Implementation Research

## 1. Overview & Objective

This document outlines the architectural research, dependency strategy, operation mappings, and testing roadmap for adding native **Windows** mount support to `rencfs`.

Currently, `rencfs` mounts encrypted filesystems on Linux using `fuse3` (`src/mount/linux.rs`). Non-Linux platforms route through a placeholder stub (`src/mount/dummy.rs`). This research specifies the path to implement native mounting on Windows using **WinFsp** (Windows File System Proxy) as the filesystem driver backend while reusing the existing async `EncryptedFs` engine.

---

## 2. Windows Filesystem Driver Evaluation

To provide user-mode filesystem mounting on Windows, four primary approaches were evaluated:

| Backend / API | Kernel Driver Required | FUSE Compatibility | Performance | License Compatibility | Production Stability | Recommendation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **WinFsp** | Yes (installed via signed MSI) | Native Win32 API + FUSE wrapper | High (fast I/O request packet dispatch, kernel caching) | GPLv2 with FOSS Exception (Compatible with MIT / Apache 2.0) | High (industry standard: Rclone, SSHFS-Win, Git for Windows) | **Recommended** |
| **Dokan** | Yes | FUSE translation layer | Medium (higher context switch overhead) | LGPL / MIT | Medium (historical driver stability regressions across Windows updates) | Not Recommended |
| **ProjFS** (Windows Projected Filesystem) | Built into Windows (optional feature) | No (custom COM/C API) | High | Native Microsoft OS API | Restricted to virtualization/placeholder scenarios; no raw encrypted block write model | Unsuitable |
| **Cloud Filter API (CfApi)** | Built into Windows | No (placeholder sync model) | High | Native Microsoft OS API | Sync engine for cloud hydration (OneDrive/Dropbox style); requires full local file replicas | Unsuitable |

### Conclusion
**WinFsp** is the recommended backend. It provides:
1. Native Windows NT kernel driver with signed WHQL certification.
2. Complete Win32 filesystem semantics (drive letters, directory mount points, file locking, case-preservation).
3. First-class Rust ecosystem bindings (`winfsp` and `winfsp-sys` crates).

---

## 3. Licensing & Attribution Checkpoint

`rencfs` is dual-licensed under **MIT** and **Apache-2.0**.

- **WinFsp License**: WinFsp is licensed under GPLv2 with a formal **FOSS Exception** (Free and Open Source Software Exception).
- **Compliance Analysis**: The WinFsp FOSS Exception explicitly grants permission to link the WinFsp user-mode library (`winfsp-x64.dll`) and header files with software licensed under recognized OSI licenses, including **Apache License 2.0** and the **MIT License**, without subjecting the derived or parent codebase to copyleft requirements.
- **Distribution Model**:
  - `rencfs` binary distributions will not bundle the kernel driver directly into the repository.
  - End users install the official signed WinFsp runtime package (MSI) on Windows.
  - Delay-loading ensures `rencfs` executables do not fail to start on machines where WinFsp is absent.

---

## 4. Build Shape & Delay-Loading Architecture

### 4.1. Cargo Configuration

Windows-specific dependencies are segregated using platform target specifications in `Cargo.toml`:

```toml
[target.'cfg(target_os = "windows")'.dependencies]
# Native WinFsp bindings
winfsp = { version = "0.2", optional = true }
windows-sys = { version = "0.52", features = [
    "Win32_Foundation",
    "Win32_Storage_FileSystem",
    "Win32_Security",
    "Win32_System_IO",
    "Win32_System_LibraryLoader",
] }
```

### 4.2. Delay-Load / Dynamic DLL Resolution

To guarantee that non-mounting CLI commands (e.g. `rencfs --help`, key derivation, password changes, inspection) run on Windows systems without WinFsp installed:
1. **Dynamic DLL Loading**: The WinFsp user-mode DLL (`winfsp-x64.dll` or `winfsp-a64.dll`) is resolved dynamically at runtime using `LoadLibraryW` when `create_mount_point` is invoked.
2. **Registry Lookup**: WinFsp registers its installation directory in `HKLM\Software\WinFsp\InstallDir`. The launcher probes this key to locate and load the runtime DLL dynamically.
3. **Graceful Error Handling**: If WinFsp is missing when `mount` is executed, `rencfs` reports a descriptive error:
   ```text
   Error: WinFsp installation not detected. Please install WinFsp from https://winfsp.dev/ to mount filesystems on Windows.
   ```

---

## 5. Proposed `src/mount/windows.rs` Architecture

### 5.1. Component Architecture

```
+-------------------------------------------------------------+
|                     Windows User Space                      |
|                                                             |
|   Windows Explorer / Applications (Win32 / POSIX APIs)      |
|                              |                              |
|                              v                              |
|                   WinFsp DLL (winfsp-x64.dll)               |
|                              |                              |
|                              v                              |
|                src/mount/windows.rs (MountPointImpl)        |
|                - Wide-char Path to Inode resolution         |
|                - FileContext handle tracking                |
|                - Win32 NTSTATUS error code mapping          |
|                              |                              |
|                              v                              |
|                  tokio Runtime Bridge                       |
|                              |                              |
|                              v                              |
|               src/encryptedfs.rs (EncryptedFs)              |
|               - Parallel Chunk Encryption / Decryption      |
|               - AAD & Inode Verification                    |
|               - Memory-locked keys via shush-rs             |
+-------------------------------------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                     Underlying Storage                      |
|                  data_dir (Encrypted blocks)                |
+-------------------------------------------------------------+
```

### 5.2. File Context & Inode Mapping

Unlike Linux FUSE which provides inode numbers directly in operations, Windows APIs operate on normalized UTF-16 path strings (`PCWSTR`). 

`src/mount/windows.rs` maintains:
1. **`FileContext`**: Allocated per open file handle:
   ```rust
   pub struct WindowsFileContext {
       pub inode: u64,
       pub path: PathBuf,
       pub is_dir: bool,
       pub read_only: bool,
       pub delete_on_close: bool,
   }
   ```
2. **Path-to-Inode Cache**: A concurrent bidirectional map (`Arc<RwLock<PathInodeMap>>`) resolving canonical paths (e.g., `\folder\file.txt`) to 64-bit inodes recognized by `EncryptedFs`.

---

## 6. Filesystem Operation Mappings

| Windows / WinFsp Operation | Semantics | `EncryptedFs` Mapping | NTSTATUS Return Mapping |
| :--- | :--- | :--- | :--- |
| **`GetVolumeInfo`** | Reports filesystem parameters (label, sector size, maximum component length). | Static metadata: volume label `"rencfs"`, max path component 255, `CasePreservedNames: 1`. | `STATUS_SUCCESS` |
| **`GetSecurity` / `SetSecurity`** | Reads/writes Windows Security Descriptors (DACL/SACL). | Synthesizes a permissive DACL granting current user `GENERIC_ALL` or maps POSIX file modes. | `STATUS_SUCCESS` |
| **`Create` / `Open`** | Handles `CreateFileW` with flags (`FILE_OPEN`, `FILE_CREATE`, `FILE_OVERWRITE_IF`). | Resolves path, verifies permissions, initializes inode via `EncryptedFs::create_file` or `EncryptedFs::open_file`. Attaches `WindowsFileContext`. | `STATUS_SUCCESS`, `STATUS_OBJECT_NAME_NOT_FOUND`, `STATUS_ACCESS_DENIED` |
| **`Read`** | Reads `Length` bytes at `Offset`. | Dispatches to `EncryptedFs::read(inode, offset, length)`. Handles decrypted chunk assembly across block boundaries. | `STATUS_SUCCESS`, `STATUS_END_OF_FILE` |
| **`Write`** | Writes `Length` bytes at `Offset`, expanding EOF if required. | Dispatches to `EncryptedFs::write(inode, offset, data)`. Re-encrypts affected cipher blocks and recalculates HMACs. | `STATUS_SUCCESS`, `STATUS_DISK_FULL` |
| **`GetFileInfo`** | Returns `BY_HANDLE_FILE_INFORMATION` (size, attributes, timestamps). | Queries `EncryptedFs::getattr(inode)` and translates POSIX times into Windows 100-ns intervals since 1601 (`FILETIME`). | `STATUS_SUCCESS` |
| **`SetBasicInfo`** | Updates file attributes or timestamps (`touch`). | Calls `EncryptedFs::setattr(inode, attrs)`. | `STATUS_SUCCESS` |
| **`SetFileSize`** | Truncates or extends file allocation. | Calls `EncryptedFs::truncate(inode, new_size)`. | `STATUS_SUCCESS` |
| **`Rename`** | Moves or renames a file/directory (`ReplaceIfExists`). | Calls `EncryptedFs::rename(old_path, new_path)`. Updates in-memory path resolution cache. | `STATUS_SUCCESS`, `STATUS_OBJECT_NAME_COLLISION` |
| **`ReadDirectory`** | Enumerates directory entries (fill pattern matching Win32 `ZwQueryDirectoryFile`). | Calls `EncryptedFs::readdir(inode)`. Converts filenames to UTF-16 wide strings and fills `FSP_FSCTL_DIR_INFO`. | `STATUS_SUCCESS`, `STATUS_NO_MORE_FILES` |
| **`Flush`** | Commits dirty write buffers to disk. | Calls `EncryptedFs::flush(inode)`. | `STATUS_SUCCESS` |
| **`Cleanup` / `Close`** | Finalizes file handle; handles `DeleteOnClose` flag. | If `delete_on_close` is set, unlinks via `EncryptedFs::unlink`. Deallocates `WindowsFileContext`. | `STATUS_SUCCESS` |

---

## 7. Platform Specifics & Edge Cases

1. **Path Normalization**:
   - Windows uses backslash (`\`) separators, while `EncryptedFs` expects forward slashes (`/`). All incoming paths are normalized before indexing.
2. **Case Sensitivity**:
   - Windows user applications expect case-preserving, case-insensitive lookups by default. WinFsp handles case-insensitive lookup automatically when initialized with `CaseSensitiveSearch = 0`.
3. **8.3 Short Names**:
   - Legacy short 8.3 names are disabled (`PassQueryDirectoryWithPattern = 0`), preventing filename collision complexities in the encrypted store.
4. **Alternate Data Streams (ADS)**:
   - NTFS ADS (`filename.ext:streamname`) is not supported by standard POSIX encrypted layouts. Incoming requests targeting streams return `STATUS_OBJECT_NAME_NOT_FOUND` or `STATUS_NOT_SUPPORTED`.

---

## 8. Conformance & Validation Testing Roadmap

1. **Unit Testing**:
   - Path normalization tests (converting Windows `\` to canonical POSIX `/`).
   - Filetime conversion tests (POSIX epoch `<->` Windows 100ns `FILETIME`).
   - NTSTATUS code mapping validation.
2. **Integration & Conformance Battery**:
   - **WinFsp Test Suite (`winfsp-tests-x64.exe`)**: Standard compliance suite verifying NTFS compatibility, directory enumeration, locking, and multi-threaded file creation.
   - **fsx-windows**: File system exerciser testing random overlapping reads, writes, and truncations under concurrent load.
3. **Continuous Integration**:
   - Add a `windows-latest` runner in `.github/workflows/build_and_tests.yaml` running `cargo check --target x86_64-pc-windows-msvc` and unit tests.
