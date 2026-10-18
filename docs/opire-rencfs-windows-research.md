# Research: Implementing rencfs on Windows

**Bounty:** Opire — "research implementation for Windows" ($42), project `radumarias/rencfs`
**Date:** 2026-10-18
**Type:** Research document (no code). This is technical research + writing, not a claim of Rust/filesystem expertise.

> Convention in this document: **(verified)** = checked against a real source cited in §6. **(analysis)** = my engineering judgment, clearly marked as such. Anything I could not verify is marked **unknown**.

---

## 1. How rencfs works on Linux today (verified from repo inspection)

**Repository:** https://github.com/radumarias/rencfs — "An encrypted file system written in Rust that is mounted with FUSE on Linux." License: Apache-2.0 / MIT / BSD-3-Clause (tri-licensed). README explicitly lists as a next step: *"The plan is to implement it also on macOS and Windows."* (verified)

### 1.1 Layered architecture

The codebase is already cleanly split into a **platform-independent core** and a **platform-specific mount layer**:

| Layer | File(s) | Role |
|---|---|---|
| Crypto core | `src/crypto/` (`read.rs`, `write.rs`, `buf_mut.rs`) | AEAD encryption via `ring` 0.17.8 (AES-256-GCM / ChaCha20-Poly1305), parallel writes, fast seek |
| Filesystem core | `src/encryptedfs.rs` (~2,668 lines) | `EncryptedFs` struct: inode-based (`ino: u64`) async API over an encrypted data dir; metadata, dir entries, attrs, WAL via `okaywal`, attr/name caches |
| Mount abstraction | `src/mount.rs` | `MountPoint` / `MountHandle` traits + `create_mount_point()` factory |
| Linux adapter | `src/mount/linux.rs` (~1,460 lines) | Implements FUSE ops via the `fuse3` crate 0.8.1 (`tokio-runtime`, `unprivileged` features) |
| Non-Linux stub | `src/mount/dummy.rs` | Placeholder used when `target_os != "linux"` |

The mount module is cfg-gated (verified):

```rust
#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(target_os = "linux"))]
mod dummy;
```

**Key architectural finding (verified):** adding Windows support means writing a new `src/mount/windows.rs` implementing the existing `MountPoint` trait — the `EncryptedFs` core needs no redesign. The core is async (tokio) and inode-addressed, which maps well to any adapter.

### 1.2 `EncryptedFs` public API (verified from source)

Async methods the adapter calls: `new`, `create`, `open(ino, read, write)`, `read`, `write`, `flush`, `release`, `get_attr`, `set_attr`, `read_dir` / `read_dir_plus`, `remove_file`, `remove_dir`, `rename`, `set_len`, `copy_file_range`, `exists` / `exists_by_name` / `find_by_name`, `is_dir`, `is_file`, `len`, `passwd`.

### 1.3 FUSE ops implemented on Linux (verified from source)

`init`, `lookup`, `getattr`, `setattr`, `mknod`/`create_nod`, `mkdir`, `unlink`, `rmdir`, `rename`, `open`, `read`, `write`, `statfs` (hardcoded constants), `release`, `flush`, `opendir`, `readdir`/`readdirplus`, `releasedir`, `access`, `create`, `copy_file_range`.

### 1.4 Mount flow on Linux (verified)

`create_mount_point(mountpoint, data_dir, password_provider, cipher, allow_root, allow_other, read_only)` → `MountPointImpl::new(...)` → `.mount()` → `fuse3::raw::Session::new(mount_options).mount_with_unprivileged(...)` → the session future drives FUSE requests into the `Filesystem` impl, which delegates to `EncryptedFs`. Unmount shells out to `umount` (Linux-only — a Windows adapter needs its own unmount path).

### 1.5 Notable dependencies (verified from Cargo.toml)

`tokio` (full), `fuse3` 0.8.1 (**Linux-only** — gated under `[target.'cfg(target_os = "linux")'.dependencies]`), `ring` 0.17.8, `argon2`, `keyring` 2.3.2, `okaywal`, `shush-rs` (secret memory), `bincode`/`serde`. MSRV 1.75.

---

## 2. Windows filesystem options for Rust — comparison

Three realistic options: **WinFSP**, **Dokany (Dokan)**, **Windows Projected File System (ProjFS)**.

| Criterion | WinFSP (+ `winfsp` crate) | Dokany (+ `dokan`/`dokan-sys` crates) | ProjFS |
|---|---|---|---|
| Model | Full user-mode FS (kernel driver + user-mode API), FUSE-like | Full user-mode FS (kernel driver + user-mode DLL) | **Projection/virtualization only** — hydrates files from a backing store on demand; not a general read/write FS |
| Maturity | Very mature: "in use in millions of installations", trusted by large software/cloud/financial companies per winfsp.dev (verified) | Mature (Dokan 2.x line), widely used, but secondary sources report more stability/performance caveats vs WinFSP | Built into Windows 10 1809+; but designed for VFS scenarios (e.g. Git), wrong abstraction for an encrypted FS |
| Rust support | **`winfsp` crate** v0.13.1+winfsp-2.1, ~9.8K downloads (verified via lib.rs). `FileSystemContext` trait (+ `AsyncFileSystemContext` with `async-io` feature, executor-agnostic via `spawn_task` — verified via docs.rs) | **`dokan` crate** v0.3.1+dokan206 (+`dokan-sys` raw bindings), ~2.6K downloads, MIT, actively maintained by dokan-dev org, upgrading to Dokan 2.3.0 (verified) | No meaningful Rust story; provider API is native C |
| APIs | Native, **FUSE2, FUSE3, .NET** (verified). Note: the FUSE-compat layer is the **C** libfuse API — not directly usable from rencfs's Rust `fuse3` crate (analysis) | FUSE wrapper exists (dokanfuse); native Dokan C API | Provider API only |
| Performance | Claims parity with NTFS in many scenarios; "outperforms its competition often by an order of magnitude" (project's claim — verified as their marketing, not independently tested) | User-mode overhead; generally regarded slower/less stable than WinFSP (secondary sources) | N/A for this use case |
| Windows versions / arch | Windows 7 → 11; x86, x64, ARM64 (verified) | Windows 7+ (verified) | Windows 10 1809+ only |
| Licensing | **GPLv3 with special FLOSS exception**; commercial license $6,000/3yr (org) or $2,400/3yr (individual) (verified). rencfs is open-source → the FLOSS exception plausibly applies (analysis — confirm with the maintainer) | dokan-rust crates MIT (verified); Dokan library/driver reported as LGPL, tools MIT (secondary source — verify before distributing) | Built into Windows (no extra license) |
| Deployment | End users must install the WinFsp runtime (MSI ships a signed driver) | End users must install the Dokan driver package | Feature must be enabled (`Client-ProjFS`) |
| Suitability for rencfs | **Best fit** — full FS semantics, maintained Rust bindings with async support, FUSE-like model matches rencfs's architecture | Viable fallback — but weaker Rust ecosystem, smaller community, more stability caveats | **Not suitable** — wrong abstraction (projection, not a real FS) |

**Also noted (verified):** the `confuse` crate is "a fuser-compatible filesystem API facade using Dokan on Windows and fuser elsewhere" — interesting but it targets the `fuser` API (not `fuse3`) and is still Dokan-based on Windows, so it doesn't change the recommendation.

**Eliminated:** ProjFS is out (wrong model). The choice is WinFSP first, Dokany as fallback.

---

## 3. Recommended approach: WinFSP + `winfsp` crate, new `src/mount/windows.rs`

### 3.1 Why WinFSP (analysis, grounded in §2)

1. **Architectural fit:** rencfs already separates core (`EncryptedFs`) from mount adapter; WinFSP's callback model (open/read/write/create/cleanup/...) maps 1:1 onto the adapter layer, same as the existing FUSE adapter.
2. **Async fit:** `EncryptedFs` is async/tokio; `winfsp`'s `AsyncFileSystemContext` is executor-agnostic with `spawn_task`, so tokio can be wired in without fighting the crate.
3. **Maturity + Rust bindings:** most mature option with the most-used Rust crate (9.8K vs 2.6K downloads).
4. **License fit:** open-source project → GPLv3 FLOSS exception; no commercial license needed (to be confirmed by maintainer).

### 3.2 Implementation plan (analysis — concrete steps)

**Phase 0 — Scaffolding**
1. Add `#[cfg(target_os = "windows")] mod windows;` to `src/mount.rs`; add `winfsp` crate under `[target.'cfg(target_os = "windows")'.dependencies]` (mirroring how `fuse3` is Linux-gated today).
2. Implement `MountPoint`/`MountHandleInner` for Windows: mount as a drive letter or directory mount point via `FileSystemHost`; unmount via the host's stop API (replacing the Linux `umount` shell-out).

**Phase 1 — Callback adapter** (new `RencFsWinFsp` struct holding `Arc<EncryptedFs>`, implementing `FileSystemContext`):

| WinFSP callback | Maps to | Notes |
|---|---|---|
| `get_security_by_name` (**required**) | `find_by_name` + synthesized security descriptor | Must return a valid descriptor; see §3.3 |
| `open` / `create` | `open` / `create` | Carry the rencfs `ino` in the `FileContext` |
| `close` / `cleanup` | `release` / `flush` + delete-disposition handling | Deletion happens on cleanup with delete flag (Windows delete-on-close semantics differ from POSIX `unlink`) |
| `read` / `write` (+`_async` variants) | `read` / `write` | Use `AsyncFileSystemContext` + `spawn_task` → `tokio::spawn` |
| `read_directory` | `read_dir` / `read_dir_plus` | Fill `DirBuffer` |
| `get_file_info` | `get_attr` | Translate `FileAttr` → `FileInfo` (sizes, times, attributes) |
| `set_basic_info` / `set_file_size` / `set_security` | `set_attr` / `set_len` | Partial mapping; see §3.3 |
| `rename` | `rename` | |
| `get_volume_info` | hardcoded, like Linux `STATFS` | |
| `overwrite` | `open` (truncate) + `set_len(0)` | |

**Phase 2 — Async bridging.** WinFSP dispatches callbacks on its own threads. Recommended: implement `AsyncFileSystemContext`, route `spawn_task` to `tokio::spawn` on the existing runtime handle; for the sync callbacks, bridge with `Handle::block_on` from non-tokio threads (avoid calling from within the runtime to prevent deadlocks). Validate with a stress test.

**Phase 3 — Windows-ization of the CLI.** `keyring` needs checking on Windows (its docs report Windows Credential Manager support — **verify**); `shush-rs` `mlock`/`mprotect` equivalents on Windows (**verify** — if unsupported, credentials lose hardening on Windows); replace `umount` shell-out; handle `ctrlc` (already cross-platform).

**Phase 4 — Testing.** Mount round-trip tests on Windows 10/11 (create/read/write/rename/delete, unicode names, long paths, concurrent I/O), plus the existing `EncryptedFs` unit tests (platform-independent, should pass unchanged).

### 3.3 Key challenges (analysis)

1. **Inode-based core vs name-based callbacks.** WinFSP identifies files by path (`U16CStr`); `EncryptedFs` is addressed by `ino: u64`. The adapter must resolve name→inode on every `open`/`get_security_by_name` (`find_by_name`/`exists_by_name` exist — good), and cache the mapping in the `FileContext`. Handle churn cost.
2. **Case-insensitivity.** Windows is normally case-insensitive; rencfs's encrypted namespace is case-sensitive. Two names differing only by case would collide. Mitigation: case-insensitive lookup in the adapter (normalize before `find_by_name`); document the residual collision risk.
3. **Permissions: Unix modes → ACLs.** `get_security_by_name` is mandatory in `winfsp-rs`. rencfs stores Unix-style attrs. The adapter must synthesize a Windows security descriptor (e.g., map owner rwx to an ACL, or start with a permissive-but-sane default and document it). Full ACL fidelity is out of scope for v1.
4. **Encrypted filename constraints.** Encrypted names are ASCII-safe (base64-family), which sidesteps most UTF-16 issues, but verify: max path length (opt into long-path support), reserved names (`CON`, `PRN`, trailing dots/spaces), which Windows forbids.
5. **Delete semantics.** POSIX `unlink` (Linux adapter) vs Windows delete-on-close in `cleanup`. Must be emulated carefully or files "deleted" while open will misbehave.
6. **Driver distribution.** Users must install the WinFsp MSI; the rencfs installer/docs must bundle or reference it. Dokany fallback has the same issue.
7. **Performance.** User-mode FS + per-block AEAD crypto: fine for the project's experimental stage, but set expectations (the Linux README already warns the crate is unaudited/experimental).

---

## 4. Risks and open questions

**Risks**
- **License confirmation needed:** GPLv3 + FLOSS exception should cover an Apache-2.0/MIT open-source project, but the maintainer should confirm this reading before depending on WinFSP (analysis).
- **winfsp crate maintenance risk:** single-ecosystem crate (~9.8K downloads); if it lags behind WinFSP releases, the adapter may need pinning to a WinFSP version (analysis).
- **Security posture:** rencfs README warns it is unaudited and "do not use with sensitive data" — a Windows port must not imply production-readiness (verified from README).
- **No Windows CI currently:** the repo's build matrix is Linux-focused; Windows CI (GitHub Actions `windows-latest`) must be added (verified: no windows target config seen in repo).

**Open questions for the maintainer**
1. Research-only deliverable, or is a prototype adapter expected next? (This bounty says "research".)
2. Drive-letter mount vs directory mount point — which is wanted?
3. Is the FLOSS-exception reading of WinFSP's license acceptable for rencfs?
4. Should macOS (macFUSE) be designed in the same pass, or Windows only?
5. Minimum Windows version to support (WinFSP supports 7→11; ProjFS would need 10 1809+ — another reason WinFSP wins).

---

## 5. Effort sketch (analysis)

| Phase | Content | Rough size |
|---|---|---|
| 0 | Scaffolding, cfg-gating, `winfsp` dep | Small |
| 1 | Sync callback adapter (`FileSystemContext`) | Medium — the bulk of the work (~1,000+ lines, comparable to `mount/linux.rs`) |
| 2 | Async bridging via `AsyncFileSystemContext` + tokio | Medium; deadlock-testing heavy |
| 3 | CLI Windows-ization (keyring, mlock, unmount) | Small–medium |
| 4 | Windows tests + CI | Medium |

---

## 6. Sources

- rencfs repo + README (architecture, deps, "implement it also on macOS and Windows", license, unaudited warning): https://github.com/radumarias/rencfs
- rencfs `src/mount.rs` / `src/mount/linux.rs` / `src/encryptedfs.rs` / `Cargo.toml`: inspected from a local clone of the repo (commit `11d87ca`, main branch, Oct 2026)
- WinFSP project (maturity, performance claims, APIs incl. FUSE2/FUSE3/.NET, Win 7–11, x86/x64/ARM64): https://winfsp.dev/
- WinFSP licensing (GPLv3 + FLOSS exception; commercial $6,000 org / $2,400 individual per 3 years): https://winfsp.dev/com/
- `winfsp` Rust crate — `FileSystemContext` trait: https://docs.rs/winfsp/0.12.4+winfsp-2.1/winfsp/filesystem/trait.FileSystemContext.html
- `winfsp` Rust crate — `AsyncFileSystemContext` (async-io, executor-agnostic `spawn_task`): https://docs.rs/winfsp/0.12.4+winfsp-2.1/winfsp/filesystem/trait.AsyncFileSystemContext.html
- `winfsp` crate listing (v0.13.1+winfsp-2.1, ~9.8K downloads, "Rust bindings to WinFSP"): https://lib.rs/filesystem
- `winfsp` crate docs index: https://docs.rs/winfsp/latest/winfsp/filesystem/index.html
- WinFsp implements the libfuse2/libfuse3 C APIs (Wikipedia): https://en.wikipedia.org/wiki/FUSE_(Linux)
- dokan-rust (`dokan` + `dokan-sys`, MIT, v0.3.1+dokan206, ~2.6K downloads, Dokan 2.3.0 upgrade in progress): https://docs.rs/crate/dokan/0.2.0+dokan150 and repo info via https://deepwiki.com/dokan-dev/dokan-rust/8-project-information (repo: https://github.com/dokan-dev/dokan-rust)
- `confuse` crate (fuser-compatible facade, Dokan on Windows): https://lib.rs/keywords/fuse
- ProjFS model (projection/hydration, Win 10 1809+, optional feature `Client-ProjFS`): http://scorpiosoftware.net/2024/02/20/projected-file-system/ and https://www.ctfiot.com/163351.html
- Dokan library/driver licensing (LGPL per secondary source — verify): https://topic.alibabacloud.com/a/dokan-the-file-system-in-user-mode-the-network-disk-can-be-developed-into-virtual-disk-cloud-storage-similar-to-jinshan-fast_3_77_10247163.html
