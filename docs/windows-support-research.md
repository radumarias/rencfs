# Windows Support Implementation — Research Note

**Status:** Research / design only. No claim is made that rencfs mounts—or runs—on Windows today. This note documents the *path* and the acceptance criteria for a truthful first implementation PR.

> Applies to repo state as of 2026-10-16 (`v0.13.78`, branch default: `main`).

---

## 1 — Current platform shape (what the code actually looks like)

- `Cargo.toml` declares `fuse3` under `[target.'cfg(target_os = "linux")'.dependencies]` → on any non-Linux OS the crate builds without a mount backend.
- `src/mount.rs` picks the backend by cfg:
  - `#[cfg(target_os = "linux")] mod linux;` → `MountPointImpl` backed by `fuse3::raw::Session`
  - everything else → `src/mount/dummy.rs` → `mount()` returns `Err(FsError::Other("Dummy implementation"))` and the future logs a joke.
- `EncryptedFs` (`src/encryptedfs.rs`) is platform-independent: it only touches std + `tokio::fs` and owns all crypto/path/data logic. The mount layer is the only OS-coupled piece.

**Conclusion:** the port surface is *just* the mount layer. WinFsp is the recommended backend.

---

## 2 — Backend choice: WinFsp vs alternatives

| Backend | License compatible with `MIT OR Apache-2.0` | Rust bindings | Production-grade | Notes |
|---|---|---|---|---|
| **WinFsp** | **Yes** — Apache-2.0 | Community bindings exist; not official | Yes | De-facto standard; Dokany is effectively unmaintained since 2019 |
| `winfsp` Rust binding crates | Yes | Several small crates | Partial | Available but choose carefully — vet activity |
| Dokany | LGPL/GPL — problematic | Yes (multiple crates) | No | Obsolete / unmaintained |
| Custom kernel driver | — | — | No | Way out of scope |

**Recommendation:** WinFsp (Apache-2.0) — the only modern, actively maintained userspace FUSE-for-Windows with a compatible license.

### License/attribution note
Project license is `MIT OR Apache-2.0`. WinFsp is Apache-2.0 → no copyleft conflict; keep the Apache-2.0 license text and note it in the repo `NOTICE`/license list as an attribution checkpoint before the implementation PR.

---

## 3 — Windows-only dependency & build shape

Proposed:

```toml
[target.'cfg(windows)'.dependencies]
winfsp-sys = { version = "0.2.x" }   # the chosen binding crate
```

And in `src/mount.rs`:

```rust
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::MountPointImpl;
#[cfg(target_os = "windows")]
use windows::MountHandleInnerImpl;
```

---

## 4 — Proposed `src/mount/windows.rs` architecture

Layer mapping — mirror the `MountPoint` trait implementation from `linux.rs`:

| | linux.rs (`fuse3`) | windows.rs (`winfsp` bindings) |
|---|---|---|
| Abstraction | `mount::MountPoint` trait → `create_mount_point` | same trait, same args |
| Driver | `impl Filesystem for EncryptedFsFuse3` | equivalent `impl` over WinFsp callbacks |
| Handler | `fn(ReplyX, ...)` methods on `EncryptedFs` | same `EncryptedFs` calls, adapted reply types |
| Core crypto/path | `EncryptedFs` object | **reused unchanged** |

**Operation mapping (WinFsp callbacks → rencfs methods):**
- `CreateFile` / `GetFileInfo` → `EncryptedFs::find_by_name` / `get_attr`
- `ReadFile` → `EncryptedFs::open(read=true, write=false)` + `read`
- `WriteFile` → `open(read=false, write=true)` + `write`
- `SetEndOfFile` → `EncryptedFs::set_len`
- `SetBasicInformation` → `set_attr` (reuse the `SetFileAttr` builder)
- `GetFileInformation` / `GetDirectoryInformation` → `FileAttr` mapping (reuse the `From<FileAttr>` conversion pattern)
- `Cleanup`/`Close` → `EncryptedFs::flush` + `release`
- `Create` flags (`FILE_READ_DATA` etc.) → existing access mask logic (`check_access`, reuse)
- `FILE_ATTRIBUTE_DIRECTORY` → `FileType::Directory`, as in `as_file_kind`

---

## 5 — Windows metadata decisions & unsupported features (first milestone)

- **Uid/gid/nlink**: not exposed — return constants matching `dir_attr()`/`file_attr()` patterns.
- **Permissions**: Windows ACL — map to `perm` in `FileAttr` for near-parity with Linux `chmod`. First milestone: fixed mapping.
- **Unsupported NTFS features** to document explicitly:
  - hardlinks (repo currently disables symlinks in `as_file_kind` anyway)
  - reparse points / junctions
  - ADS (alternate data streams)
  - case-insensitive-name semantics
  - `statfs` is already a stub on Linux — keep stub parity in the first milestone
- **TTL**: reuse `const TTL = Duration::from_secs(1)`; `STATFS` stub unchanged.

---

## 6 — Build/CI plan + smoke test

- Add `windows-latest` to `.github/workflows/ci.yml` job matrix: `cargo check --target x86_64-pc-windows-msvc` (compile-only).
- `cargo build --release` on a Windows host with WinFsp installed; run the produced `rencfs.exe`
- Manual smoke test list (Windows host, for the implementation PR):
  1. create the mountpoint path
  2. `rencfs mount <mountpoint> --data-dir <dir>` — process stays alive
  3. create dir/file on the mounted drive; verify ciphertext appears under data dir
  4. unmount cleanly

---

## 7 — Acceptance criteria (for a truthful first implementation PR)

A PR that closes this research item should, at minimum:

- [ ] add `src/mount/windows.rs` implementing the `MountPoint` trait; non-linux no longer falls back to `dummy.rs`
- [ ] pick one backend (recommended WinFsp) declared under `[target.'cfg(windows)'.dependencies]`
- [ ] keep `EncryptedFs` untouched except where a documented API gap forces a pure-function refactor (list it explicitly)
- [ ] map WinFsp callbacks → `EncryptedFs` methods per the table in §4
- [ ] license/attribution checkpoint: WinFsp Apache-2.0 noted in repo `NOTICE` (or LICENSE list) before merging
- [ ] CI: add `windows-latest` compile-only job (`cargo check --target x86_64-pc-windows-msvc`)
- run the manual smoke test list on a real Windows host — or state clearly it was NOT run
- [ ] do NOT claim Windows runtime validation that wasn't performed

**Scope guard:** first-milestone non-goals — hardlinks, symlinks (as on Linux today), reparse points/junctions, ADS, case-insensitive semantics; `statfs` stub parity maintained.

---

## 8 — Verification performed for this note

- Read repo source at commit cloned 2026-10-16: `src/mount.rs`, `src/mount/linux.rs`, `src/mount/dummy.rs`, `Cargo.toml`, `src/mount/linux.rs` `Filesystem` impl reviewed.
- This document is **research only** — no build, no test, no Windows runtime claim.
