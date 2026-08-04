# Windows support — implementation research

This document records the recommended implementation path for native Windows
support in rencfs. Native Windows mounting is **not yet functional**; the code
compiles on Windows via `src/mount/windows.rs` (a typed stub, verified with
`cargo check --target x86_64-pc-windows-msvc`) and fails with a descriptive
error that points here. Everything below is written so a follow-up PR can move
from the stub to a working implementation with minimal rework.

---

## Recommendation: WinFsp

Use [WinFsp](https://winfsp.dev/) as the native Windows mount backend through
the [`winfsp`](https://crates.io/crates/winfsp) Rust crate (`winfsp-rs`,
current version `0.13.0+winfsp-2.1`).

**Why WinFsp over the alternatives:**

| Option | Assessment |
|--------|-----------|
| **WinFsp** | Maintained, FUSE-equivalent Windows filesystem proxy; user-mode; supports drive letters and directory mount points; mature Rust bindings; purpose-built for exposing a POSIX-style FS on Windows |
| Dokan | Viable, but a smaller community and a less FUSE-idiomatic API surface |
| WebDAV | Changes filesystem semantics and adds a local HTTP server attack surface |
| WSL-only | Useful for development, but does not give a native Windows experience |
| ProjFS | Microsoft Virtual File System — optimized for read-heavy/sparse scenarios; poorly suited to a fully writable encrypted FS |
| Kernel-mode FS | Unnecessary complexity; WinFsp already lets user-mode programs implement file systems without kernel programming |

---

## Licensing checkpoint (authoritative)

WinFsp is **GPLv3** with a special **FLOSS exception**. It is *not* LGPL.

From the official [`License.txt`](https://github.com/winfsp/winfsp/blob/master/License.txt):

> The WinFsp project is Copyright (C) Bill Zissimopoulos. It is licensed under
> the terms of the GPLv3.
>
> As a special exception to GPLv3, Bill Zissimopoulos grants additional
> permissions to Free/Libre and Open Source Software ("FLOSS") without
> requiring that such software is covered by the GPLv3.
>
> 1. Permission to link with a platform specific version of the WinFsp DLL
>    (one of: winfsp-a64.dll, winfsp-x64.dll, winfsp-x86.dll, winfsp-msil.dll).
> 2. Permission to distribute unmodified binary releases of the WinFsp
>    installer (as released by the WinFsp project).
>
> These permissions (and no other) are granted provided that the software:
>
> 1. Is distributed under a license that satisfies the Free Software
>    Definition ... or the Open Source Definition ...
> 2. Includes the copyright notice "WinFsp - Windows File System Proxy,
>    Copyright (C) Bill Zissimopoulos" and a link to the WinFsp repository
>    in its user-interface and any user-facing documentation.
> 3. Is not linked or distributed with proprietary (non-FLOSS) software.

**Conclusion for rencfs (MIT OR Apache-2.0):**

- rencfs is FLOSS, so the exception applies — it may **link against the
  WinFsp DLL** and **distribute the unmodified WinFsp installer** without
  rencfs becoming GPLv3.
- **Obligations to satisfy**:
  1. Add the required copyright notice
     ("WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos")
     and a link to the WinFsp repository in rencfs' user-facing documentation
     (the Windows section of `README.md` and the CLI `--help`/version output
     satisfy this naturally).
  2. Do **not** ship WinFsp with any proprietary code path.
- The Rust `winfsp` crate itself is MIT-licensed; `winfsp-sys` builds against
  the WinFsp SDK import library.

> ⚠️ Earlier drafts of this research described the WinFsp user-mode DLL as
> "LGPL v3". That is incorrect — the whole project is GPLv3 with the FLOSS
> exception above. Use this document as the source of truth.

---

## Cargo.toml changes

Add a Windows-only dependency (no change to Linux or macOS builds):

```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = { version = "0.13", features = ["system"] }
```

Notes:

- `version = "0.13"` resolves to `0.13.0+winfsp-2.1`.
- The `system` feature builds against the WinFsp SDK located via the Registry
  (installed by the WinFsp installer). The default feature set builds against
  an included import library.
- To **delay-load** the WinFsp DLL (so rencfs still starts when WinFsp is not
  installed, failing only at mount time), add a build script:

  ```toml
  [build-dependencies]
  winfsp = { version = "0.13", features = ["delayload"] }
  ```

  ```rust
  // build.rs (windows only)
  fn main() {
      #[cfg(target_os = "windows")]
      winfsp::build::winfsp_link_delayload();
  }
  ```

---

## Architecture: `src/mount/windows.rs`

The stub in `src/mount/windows.rs` already mirrors the `MountPoint` /
`MountHandleInner` trait structure used by `linux.rs`, so the CLI and
`create_mount_point` are platform-agnostic. The real implementation adds a
`RencfsHost` that wraps [`EncryptedFs`](crate::encryptedfs::EncryptedFs) and
implements `winfsp::filesystem::FileSystemContext`.

```
┌──────────────────────────────────────────┐
│  WinFsp kernel driver  (winfsp.sys)      │
│  ↕  IOCTL channel                        │
│  WinFsp user-mode DLL (winfsp-x64.dll)  │
│  ↕  winfsp Rust crate (0.13)            │
│  RencfsHost  (src/mount/windows.rs)     │
│   ├─ open / read / write / close        │
│   ├─ create / rename / set_delete       │
│   ├─ read_directory / get_file_info     │
│   └─ get_volume_info / get_security     │
│        ↓                                │
│  EncryptedFs  (src/encryptedfs.rs)      │  ← unchanged
│   └─ crypto layer (src/crypto/)         │  ← unchanged
└──────────────────────────────────────────┘
```

Because `FileSystemContext` methods take `&self` (the driver can call any
method on any thread), the `FileContext` type must use **interior mutability**
for any mutable per-handle state (e.g. write flags), following the crate's own
`DirBuffer` guidance.

---

## Operation mapping (WinFsp → EncryptedFs)

WinFsp's `FileSystemContext` trait in `winfsp` 0.13:

| WinFsp callback | rencfs `EncryptedFs` method | Notes |
|---|---|---|
| `get_volume_info` | `statfs()` | Map total/free blocks into `VolumeInfo` |
| `get_security_by_name` | `get_attr()` + synthesise `FileSecurity` | Owner SID from process token; world-readable DACL for milestone 1 |
| `open` | `open()` (read/write flags) | Return `FileContext` handle |
| `close` | `release()` | Flush before close |
| `read` | `read()` | Decrypt on the fly |
| `write` | `write()` | Encrypt on write |
| `flush` | `flush()` | |
| `get_file_info` | `get_attr()` | Map to `FileInfo` |
| `set_basic_info` | `set_attr()` | Timestamps + attributes |
| `set_file_size` | `set_len()` | Truncate |
| `rename` | `rename()` | `replace_if_exists` → overwrite semantics |
| `create` | `create()` (file) / `create()` (dir) | Distinguish `FILE_DIRECTORY_FILE` |
| `overwrite` | `create()` with truncate | |
| `set_delete` | `remove_file()` / `remove_dir()` | Handles delete-on-close |
| `read_directory` | `read_dir()` | Stream entries into `DirBuffer` |
| `get_dir_info_by_name` | `find_by_name()` | |
| `get_security` / `set_security` | — | Milestone 1: read-only, synthesized default |
| `get_stream_info` | — | NTFS ADS deferred |
| `get_reparse_point*` / `set_reparse_point*` | — | Symlinks/reparse points deferred |
| `get_extended_attributes` / `set_extended_attributes` | — | Not supported (milestone 1) |
| `control` | — | Pass-through `DeviceIoControl`; not needed |
| `dispatcher_stopped` | — | Log and exit cleanly |

---

## Windows metadata (milestone 1)

Keep the first working implementation minimal:

- **File attributes:** `FILE_ATTRIBUTE_NORMAL` for files;
  `FILE_ATTRIBUTE_DIRECTORY` for directories.
- **Timestamps:** map rencfs `atime` / `mtime` / `ctime` (UNIX epoch) ↔
  Windows `FILETIME` (1601 epoch, 100 ns units).
- **Owner SID:** derive from the current process token
  (`GetTokenInformation(TokenUser)`).
- **SECURITY_DESCRIPTOR:** world-readable for milestone 1 — a DACL granting
  `GENERIC_ALL` to the owner and `GENERIC_READ | GENERIC_EXECUTE` to
  `Everyone`. Full per-file ACL support is a follow-up milestone.

**NTFS features deferred to later milestones:**

- Alternate data streams (ADS) — `get_stream_info` / `set_stream_size`
- Hard links
- Reparse points / junctions / symbolic links
- Object identifiers
- NTFS encryption / compression flags (rencfs owns its own crypto at the
  storage layer; NTFS-level attributes should remain unset)

---

## Build and CI plan

The stub has been verified to compile on a real Windows host with:

```text
cargo check --target x86_64-pc-windows-msvc
```

1. **Cross-compile check** (CI, no Windows runner needed to start):
   ```text
   cargo check --target x86_64-pc-windows-msvc
   ```
   This validates `src/mount/windows.rs` and `src/mount.rs` gate correctly.
   The `winfsp` crate is only a `cfg(target_os = "windows")` dependency, so
   Linux/macOS builds are unaffected.

2. **Full Windows CI** (once the implementation lands): add a `windows-latest`
   GitHub Actions job, install WinFsp (`choco install winfsp -y`), then run
   `cargo test`.

3. **Smoke test** (manual, on a Windows host with WinFsp installed — see below).

---

## Manual smoke test checklist

Prerequisites: Windows 10/11 host, WinFsp ≥ 2.0 installed (from
[winfsp.dev/rel](https://winfsp.dev/rel/)), rencfs built with
`cargo build --target x86_64-pc-windows-msvc`.

```text
# 1. Create an encrypted directory (assume the CLI accepts a drive letter)
rencfs.exe encrypt --data-dir C:\rencfs-data --mount-point Z: --cipher AES256GCM

# 2. Write a file
echo hello > Z:\hello.txt

# 3. Verify the file reads back correctly
type Z:\hello.txt

# 4. Unmount
rencfs.exe umount Z:

# 5. Verify the raw data is unreadable without the key
type C:\rencfs-data\any-file
```

Acceptance criteria for a "passing" smoke test:

- [ ] Mount succeeds without crashing
- [ ] Files written through the mount point are readable back through the mount point
- [ ] Raw files in `data_dir` are not plaintext
- [ ] Unmount succeeds cleanly
- [ ] No panics or unhandled errors in the rencfs log

---

## Acceptance criteria for the first real implementation PR

A follow-up PR that moves from the stub to a working implementation should:

1. Replace `MountPointImpl::mount()` in `src/mount/windows.rs` with a real
   WinFsp `FileSystemHost` startup (`winfsp_init`, build `VolumeParams`,
   create `FileSystemHost::new`, `host.mount(drive_letter)`, `host.start()`).
2. Implement `RencfsHost: winfsp::filesystem::FileSystemContext` covering all
   operations in the mapping table above, using interior mutability in the
   `FileContext` where needed.
3. Honor the FLOSS license obligations (copyright notice + repo link) in
   user-facing docs and CLI output.
4. Pass the manual smoke test on a Windows host.
5. CI: `cargo check --target x86_64-pc-windows-msvc` passes and Linux
   `cargo test` stays green.
