# Windows support — implementation research

> Status: research note, not a claim that `rencfs` mounts on Windows today.
> The current native path is a typed stub in `src/mount/windows.rs` that
> compiles on `x86_64-pc-windows-msvc` and exits with a clear error directing
> users to this document. This note records the recommended implementation path
> so a follow-up PR can land a truthful WinFsp integration without guesswork.

---

## 1. Recommendation: WinFsp

Use [WinFsp (Windows File System Proxy)](https://winfsp.dev/) as the native
Windows mount backend via the [`winfsp`](https://crates.io/crates/winfsp)
Rust crate (`winfsp-rs`).

**Why WinFsp over the alternatives:**

| Option | Assessment |
|--------|-----------|
| **WinFsp (recommended)** | Maintained user-mode filesystem framework for Windows; kernel driver + user-mode DLL; supports drive letters and directory mount points; exposes a FUSE-compatible layer (`winfsp-x64.dll` / FUSE API); closest mapping to the existing `linux.rs` + `fuse3` design |
| `winfsp` (Rust Native C API, `winfsp-sys`) | Lower-level bindings to the same WinFsp runtime; more surface to wrap manually — prefer the higher-level `winfsp` crate unless a callback is missing |
| Dokany / `dokan-rs` | Viable but smaller community, less actively maintained than WinFsp; driver edge cases; not the de-facto choice for FUSE-style Rust ports |
| WebDAV | Changes filesystem semantics (HTTP layer), adds a local server surface; not a drop-in for the current `Filesystem` trait |
| WSL-only | Useful for development but does not give a native Windows Explorer experience |
| ProjFS (Windows Projected File System) | Optimised for read-heavy / sparse / cloud-backed scenarios; harder to adapt for a fully writable encrypted FS like rencfs |

---

## 2. Licensing / attribution checkpoint

`rencfs` is `MIT OR Apache-2.0`. WinFsp ships under two licenses:

- **Kernel driver** (`winfsp.sys`, `winfsp-launcher`): **GPLv3** — distributed
  separately; users install WinFsp independently. `rencfs` does **not** need
  to bundle or statically link the driver.
- **User-mode DLL** (`winfsp-x64.dll` and friends): **LGPLv3** — can be
  dynamically linked without triggering copyleft for `rencfs` itself as long
  as the DLL is not statically linked / vendored.
- The Rust `winfsp` crate is **MIT**-licensed.

**Conclusion:** `rencfs` can link WinFsp dynamically without a license
conflict. The WinFsp installer must be noted as a runtime prerequisite in the
README and Windows release notes. Keep the NOTICE / attribution for WinFsp in
packaging docs. Do not vendor `winfsp.sys` or `winfsp-x64.dll` into the
repository.

---

## 3. Windows-only dependency & delay-load build shape

Add `winfsp` only on Windows so Linux/macOS builds are unchanged:

```toml
# Cargo.toml — add below the existing [target.'cfg(target_os = "linux")'] block

[target.'cfg(target_os = "windows")'.dependencies]
winfsp = { version = "0.3", features = ["system"] }
```

Notes:

- The `system` feature locates the installed WinFsp SDK at build time
  (requires WinFsp installed on the Windows build host / CI runner).
- No change to Linux or macOS dependency graphs.
- Until the linking story is resolved for cross-compilation, the `winfsp`
  import in `src/mount/windows.rs` can be kept behind a narrow `cfg` or a
  `windows-stub` feature flag so `cargo check --target x86_64-pc-windows-gnu`
  stays green on non-Windows CI.

Recommended `src/mount.rs` gating (matching the existing Linux / dummy split):

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

---

## 4. Proposed `src/mount/windows.rs` architecture

The stub in `src/mount/windows.rs` already follows the existing
`MountPoint` / `MountHandleInner` trait structure so the real implementation
can be dropped in without touching `src/mount.rs` again. The real
implementation adds a `RencfsHost` struct that wraps the existing
`EncryptedFs` layer and implements `winfsp::FileSystemContext`.

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

Key properties:

- The **storage + crypto layer** (`EncryptedFs`, `src/crypto`) stays unchanged;
  Windows only replaces the mount / filesystem shim (today `fuse3` on Linux).
- Sensitive paths / secrets continue to use `shush-rs` + `zeroize` as on Linux.
- Mount-point lifecycle (async `MountPoint::mount()` → `MountHandle` future →
  `umount()`) is preserved; the Windows handle wraps `winfsp::FileSystemHost`.

---

## 5. Operation mapping: WinFsp callbacks → rencfs methods

| WinFsp callback | rencfs `EncryptedFs` method | Notes |
|---|---|---|
| `get_volume_info` | `statfs()` | Map total / free blocks for Explorer |
| `get_security_by_name` | `get_attr()` + synthesise `SECURITY_DESCRIPTOR` | See §6 |
| `open` | `open()` / `find_by_name()` | Return file handle |
| `close` | `release()` | Flush before close |
| `read` | `read()` | Decrypt on the fly |
| `write` | `write()` | Encrypt on write |
| `flush` | `flush()` | |
| `get_file_info` | `get_attr()` | Return `FILE_INFO` / `FileAttr` |
| `set_basic_info` | `set_attr()` | Timestamps + attributes |
| `set_file_size` | `set_len()` / `truncate` via `set_attr()` | |
| `rename` | `rename()` | |
| `create` | `create()` (file or directory) | |
| `overwrite` / `overwrite_ex` | `create()` with `O_TRUNC` semantics | |
| `cleanup` (delete-on-close) | `remove_file()` / `remove_dir()` | |
| `read_directory` | `read_dir()` / `read_dir_plus()` | Stream directory entries |
| `get_dir_info_by_name` | `find_by_name()` within parent | |
| `get_extended_attributes` | — | Not supported (milestone 1) |
| `set_extended_attributes` | — | Not supported (milestone 1) |
| `copy_file_range` (if exposed) | `copy_file_range()` | |

POSIX-only FUSE concepts (`allow_root`, `allow_other`, `uid`/`gid` permission
checks via `fuse3::Request`) have no direct WinFsp equivalent and should be
mapped to Windows access semantics (§6) rather than forwarded literally.

---

## 6. Windows metadata decisions (milestone 1)

Keep it simple for the first working implementation; defer NTFS extras.

- **File attributes:** `FILE_ATTRIBUTE_NORMAL` for regular files;
  `FILE_ATTRIBUTE_DIRECTORY` for directories. No other flags in milestone 1.
- **Timestamps:** map rencfs `atime` / `mtime` / `ctime` ↔ WinFsp `FILETIME`
  (`SystemTime` ↔ `FILETIME` via `UNIX_EPOCH`).
- **Owner SID / SECURITY_DESCRIPTOR:** derive the owner SID from the current
  process token (`GetTokenInformation(TokenUser)`). For milestone 1 use a
  world-readable DACL (e.g. `GENERIC_ALL` for the owner, `GENERIC_READ |
  GENERIC_EXECUTE` for `Everyone`); full per-file ACL support is a follow-up
  milestone. Document that `allow_root` / `allow_other` are Linux-only flags.
- **Case sensitivity:** Windows is case-insensitive by default; rencfs internal
  names are case-sensitive. Normalise lookup paths consistently and document
  the behaviour.
- **Path prefix:** WinFsp mount points accept drive letters (`Z:`) or directory
  junctions (`C:\mount\rencfs`); validate the mountpoint path early.

**NTFS features explicitly deferred to later milestones:**

- Alternate data streams (ADS)
- Hard links
- Reparse points / junctions / symbolic links (inside the mounted FS)
- Object identifiers
- NTFS encryption / compression flags (rencfs handles its own crypto at the
  storage layer; leave NTFS-level attributes unset)
- Extended attributes / `get/set_extended_attributes`

---

## 7. Build / CI plan

1. **Cross-compile check** (CI — no Windows runner needed initially):
   ```
   cargo check --target x86_64-pc-windows-gnu
   cargo check --all
   ```
   Ensures `src/mount/windows.rs` and `src/mount.rs` cfg gating compile on
   both hosts. The `winfsp` crate can be kept behind a narrow cfg or a
   `windows-stub` feature flag until the linking story is resolved.

2. **Full Windows CI** (later): add a `windows-latest` GitHub Actions runner,
   install WinFsp, then run the usual build + test steps. Example step:
   ```yaml
   - name: install WinFsp
     if: matrix.os == 'windows-latest'
     run: choco install winfsp -y
   - run: cargo test --release --all --all-features -- --skip keyring
   ```
   Until a functional WinFsp host exists, keep Windows tests gated or skipped
   (the existing workflow already skips `cargo test` / `cargo bench` on
   `windows-latest` — extend that until milestone 1 passes).

3. **Smoke test** (manual, once functional — see §8).

---

## 8. Manual smoke test (Windows host with WinFsp installed)

Prerequisites: Windows 10/11 host, WinFsp ≥ 2.0 installed (from
[winfsp.dev/rel](https://winfsp.dev/rel/)), `rencfs` built with
`cargo build --target x86_64-pc-windows-msvc`.

```powershell
# 1. Create an encrypted directory and mount it (example — adapt flags to CLI)
rencfs.exe encrypt --data-dir C:\rencfs-data --mount-point Z: --cipher AES256GCM

# 2. Write a file through the mount
echo hello > Z:\hello.txt

# 3. Verify the file reads back correctly
type Z:\hello.txt

# 4. Unmount
rencfs.exe umount Z:

# 5. Verify the raw data is not plaintext
type C:\rencfs-data\<any file>   # should look like encrypted binary
```

Acceptance checklist for a passing smoke test:

- [ ] Mount succeeds without crashing (drive letter or directory mount point appears).
- [ ] Files written through the mount point are readable back through the mount point.
- [ ] Raw files in `data_dir` are not plaintext.
- [ ] Unmount succeeds cleanly; remount works.
- [ ] No panics or unhandled errors in the rencfs log (`tracing` output).

---

## 9. Acceptance criteria for a truthful first implementation PR

A follow-up PR that moves from this skeleton to a working implementation should:

1. Replace `MountPointImpl::mount()` in `src/mount/windows.rs` with a real
   WinFsp `FileSystemHost` startup (e.g. `RencfsHost: winfsp::FileSystemContext`
   backed by `Arc<EncryptedFs>`).
2. Implement `RencfsHost` covering all operations in the mapping table (§5).
3. Document any deviations from §6 (metadata / SID / DACL choices).
4. Pass the manual smoke test on a Windows host (§8) — state the host and
   WinFsp version in the PR description; do not claim Windows runtime validation
   without it.
5. CI: `cargo check --target x86_64-pc-windows-gnu` (or `cargo check --all`) and
   `cargo fmt` / `cargo clippy` pass; no regressions on Linux (`cargo test` on
   Linux still green).
6. Update `README.md` / release notes to list WinFsp as a Windows runtime
   prerequisite.

---

## References

- WinFsp: https://winfsp.dev/ and https://github.com/winfsp/winfsp
- `winfsp` Rust crate: https://crates.io/crates/winfsp
- `fuse3` (Linux backend used by rencfs today): https://crates.io/crates/fuse3
- rencfs repo: https://github.com/radumarias/rencfs / https://github.com/xoriors/rencfs
