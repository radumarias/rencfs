# Windows support — implementation research

Native Windows mounting is not yet functional. The current code compiles on
Windows via `src/mount/windows.rs` (a typed stub) and exits with a clear error
message. This document records the recommended implementation path so it can be
reviewed and refined before code is written.

---

## Recommendation: WinFsp

Use [WinFsp](https://winfsp.dev/) as the native Windows mount backend via the
[`winfsp`](https://crates.io/crates/winfsp) Rust crate (`winfsp-rs`).

**Why WinFsp over the alternatives:**

| Option | Assessment |
|--------|-----------|
| **WinFsp** | Maintained Windows FUSE equivalent; user-mode driver; supports drive letters and directory mount points; MIT-licensed kernel driver + LGPL user-mode DLL |
| Dokan | Viable but smaller community; less idiomatic for a FUSE-style design |
| WebDAV | Changes filesystem semantics; adds a local HTTP server surface |
| WSL-only | Useful for development but does not give a native Windows experience |
| ProjFS | Microsoft Virtual File System — good for read-heavy/sparse scenarios; harder to adapt for a fully writable encrypted FS |

---

## Licensing checkpoint

WinFsp ships under two licenses:

- **Kernel driver** (`winfsp.sys`): GPLv3 — distributed separately; users
  install WinFsp independently. rencfs does **not** need to bundle or
  statically link the driver.
- **User-mode DLL** (`winfsp-x64.dll`): LGPL v3 — can be dynamically linked
  without triggering copyleft for rencfs itself.
- The Rust `winfsp` crate is MIT.

**Conclusion:** rencfs (MIT OR Apache-2.0) can link WinFsp dynamically without
a license conflict. The WinFsp installer must be noted as a runtime prerequisite
in the README and Windows release notes.

---

## Cargo.toml changes

```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = { version = "0.3", features = ["system"] }
```

The `system` feature locates the installed WinFsp SDK at build time.

---

## Architecture: `src/mount/windows.rs`

The stub in `src/mount/windows.rs` already follows the existing
`MountPoint` / `MountHandleInner` trait structure. The real implementation
adds a `RencfsHost` struct that wraps `EncryptedFs` and implements
`winfsp::FileSystemContext`.

```
┌──────────────────────────────────────────┐
│  WinFsp kernel driver  (winfsp.sys)      │
│  ↕  IOCTL channel                        │
│  WinFsp user-mode DLL (winfsp-x64.dll)  │
│  ↕  winfsp Rust crate                   │
│  RencfsHost  (src/mount/windows.rs)     │
│   ├─ open / read / write / close        │
│   ├─ create / rename / unlink           │
│   └─ read_directory / get_file_info     │
│        ↓                                │
│  EncryptedFs  (src/encryptedfs.rs)      │  ← unchanged
│   └─ crypto layer (src/crypto/)         │  ← unchanged
└──────────────────────────────────────────┘
```

---

## Operation mapping

| WinFsp callback | rencfs `EncryptedFs` method | Notes |
|---|---|---|
| `get_volume_info` | `statfs()` | Map total/free blocks |
| `get_security_by_name` | `getattr()` + synthesise SECURITY_DESCRIPTOR | See §Metadata below |
| `open` | `open_file()` / `lookup()` | Return file handle |
| `close` | `release()` | Flush before close |
| `read` | `read()` | Decrypt on the fly |
| `write` | `write()` | Encrypt on write |
| `flush` | `flush()` | |
| `get_file_info` | `getattr()` | Return `FILE_INFO` |
| `set_basic_info` | `setattr()` | Timestamps + attributes |
| `set_file_size` | `truncate()` | |
| `rename` | `rename()` | |
| `create` | `create_file()` or `mkdir()` | |
| `overwrite` / `overwrite_ex` | `create_file()` with O_TRUNC | |
| `cleanup` (delete-on-close) | `unlink()` / `rmdir()` | |
| `read_directory` | `read_dir()` | Stream directory entries |
| `get_dir_info_by_name` | `lookup()` within parent | |
| `get_extended_attributes` | — | Not supported (milestone 1) |
| `set_extended_attributes` | — | Not supported (milestone 1) |

---

## Windows metadata (milestone 1)

Keep it simple for the first working implementation:

- **File attributes:** `FILE_ATTRIBUTE_NORMAL` for files;
  `FILE_ATTRIBUTE_DIRECTORY` for directories.
- **Timestamps:** map rencfs `atime` / `mtime` / `ctime` ↔ FILETIME.
- **Owner SID:** derive from the current process token
  (`GetTokenInformation(TokenUser)`).
- **SECURITY_DESCRIPTOR:** world-readable for milestone 1
  (`DACL` granting `GENERIC_ALL` to the owner, `GENERIC_READ | GENERIC_EXECUTE`
  to `Everyone`). Full per-file ACL support is a follow-up milestone.

**NTFS features deferred to later milestones:**

- Alternate data streams (ADS)
- Hard links
- Reparse points / junctions / symbolic links
- Object identifiers
- NTFS encryption / compression flags (rencfs handles its own crypto at
  the storage layer; NTFS-level attributes should remain unset)

---

## Windows-only dependency shape

```toml
# Cargo.toml — add below the existing [target.'cfg(target_os = "linux")'] block

[target.'cfg(target_os = "windows")'.dependencies]
winfsp = { version = "0.3", features = ["system"] }
```

No change to Linux or macOS builds.

---

## Build and CI plan

1. **Cross-compile check** (CI — no Windows runner needed initially):
   ```
   cargo check --target x86_64-pc-windows-gnu
   ```
   Ensures `src/mount/windows.rs` and `src/mount.rs` compile. The `winfsp`
   crate can be omitted from the cross-check by gating it behind
   `#[cfg(not(target_arch = "x86_64_pc_windows_gnu"))]` until the linking
   story is resolved, or by adding a `windows-stub` feature flag.

2. **Full Windows CI** (later): add a `windows-latest` GitHub Actions runner,
   install WinFsp via `choco install winfsp`, then run `cargo test`.

3. **Smoke test** (manual, once functional — see below).

---

## Manual smoke test checklist

Prerequisites: Windows 10/11 host, WinFsp ≥ 2.0 installed (from
[winfsp.dev/rel](https://winfsp.dev/rel/)), rencfs built with
`cargo build --target x86_64-pc-windows-msvc`.

```
# 1. Create an encrypted directory
rencfs.exe encrypt --data-dir C:\rencfs-data --mount-point Z: --cipher AES256GCM

# 2. Write a file
echo hello > Z:\hello.txt

# 3. Verify the file reads back correctly
type Z:\hello.txt

# 4. Unmount
rencfs.exe umount Z:

# 5. Verify the raw data is unreadable without the key
type C:\rencfs-data\<any file>   # should look like encrypted binary
```

Acceptance criteria for a "passing" smoke test:
- [ ] Mount succeeds without crashing
- [ ] Files written through the mount point are readable back through the mount point
- [ ] Raw files in `data_dir` are not plaintext
- [ ] Unmount succeeds cleanly
- [ ] No panics or unhandled errors in the rencfs log

---

## Acceptance criteria for the first real implementation PR

A follow-up PR that moves from this skeleton to a working implementation should:

1. Replace `MountPointImpl::mount()` in `src/mount/windows.rs` with a real
   WinFsp `FileSystemHost` startup.
2. Implement `RencfsHost: winfsp::FileSystemContext` covering all operations in
   the mapping table above.
3. Pass the manual smoke test on a Windows host.
4. CI: `cargo check --target x86_64-pc-windows-gnu` (or equivalent) passes.
5. No regressions on Linux (`cargo test` on Linux still green).
