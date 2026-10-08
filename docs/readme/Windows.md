# Windows Support — Implementation Research

> **Framing:** This is a *research* note, not a claim that rencfs mounts on Windows
> today. It maps the existing platform-independent crypto layer onto a concrete
> Windows backend, with the exact operation mapping, build shape, and acceptance
> criteria a future implementation PR must satisfy. Every code reference below was
> verified against the current `main` source.

## 1. Current state of the codebase (verified)

The platform boundary is a single `#[cfg]` split in `src/mount.rs`:

```rust
#[cfg(target_os = "linux")]
mod linux;          // real implementation, uses the `fuse3` crate (v0.8.1)

#[cfg(not(target_os = "linux"))]
mod dummy;          // stub: mount() -> Err(FsError::Other("Dummy implementation"))
```

Three facts that shape everything in this document:

1. **The Linux mount is *low-level raw* FUSE, not a safe FUSE wrapper.**
   `src/mount/linux.rs` implements `fuse3::raw::Filesystem` (the raw FUSE
   protocol) over a tokio runtime, replying with `fuse3::raw::prelude::*` types.
   It is not using a high-level "implement these callbacks" abstraction. The
   Windows equivalent must therefore also be a *low-level* backend, which points
   to **WinFSP** (see §3).

2. **The platform-independent contract is the `EncryptedFs` type in
   `src/encryptedfs.rs`, exposed through a set of `async` methods.** The mount
   layer is *only* responsible for translating kernel callbacks into calls on
   this type and back. The methods that matter for a mount backend are:

   | `EncryptedFs` method (async) | Signature (abridged) |
   |---|---|
   | `get_attr` | `async fn get_attr(&self, ino: u64) -> FsResult<FileAttr>` |
   | `set_attr` | `async fn set_attr(&self, ino: u64, set_attr: SetFileAttr) -> FsResult<()>` |
   | `read` | `async fn read(&self, ino: u64, offset: u64, size: u32, handle: u64) -> FsResult<Bytes>` |
   | `write` | `async fn write(&self, ino: u64, offset: u64, buf: &[u8], handle: u64) -> FsResult<usize>` |
   | `open` | `async fn open(&self, ino: u64, read: bool, write: bool) -> FsResult<u64>` (returns an fh) |
   | `release` | `async fn release(&self, handle: u64) -> FsResult<()>` |
   | `flush` | `async fn flush(&self, handle: u64) -> FsResult<()>` |
   | `copy_file_range` | `async fn copy_file_range(...) -> FsResult<u64>` |
   | `create` | `async fn create(&self, parent: u64, name: &SecretString, attr: CreateFileAttr) -> FsResult<(u64, bool)>` |
   | `remove_file` | `async fn remove_file(&self, parent: u64, name: &SecretString) -> FsResult<()>` |
   | `remove_dir` | `async fn remove_dir(&self, parent: u64, name: &SecretString) -> FsResult<()>` |
   | `read_dir` | `async fn read_dir(&self, ino: u64) -> FsResult<DirectoryEntryIterator>` |
   | `read_dir_plus` | `async fn read_dir_plus(&self, ino: u64) -> FsResult<DirectoryEntryPlusIterator>` |
   | `exists_by_name` | `pub fn exists_by_name(&self, parent: u64, name: &SecretString) -> FsResult<bool>` |

   `FileAttr` (`src/encryptedfs.rs`) carries: `ino, size, blocks, atime, mtime,
   ctime, crtime, kind, perm, nlink, uid, gid, rdev`. Root is `ROOT_INODE: u64 = 1`.

3. **rencfs stores its own metadata.** The encrypted data and *all* filesystem
   metadata live under `data_dir` (`contents/`, `security/`, `ls/`, `hash/` —
   see the `*_DIR` constants in `src/encryptedfs.rs`). The OS-level filesystem
   that backs the mount is therefore just an opaque store of encrypted blobs.
   This has a major consequence documented in §6: **NTFS metadata capabilities
   (ACLs, ownership, hard links, reparse points) are largely irrelevant to the
   encrypted view**, because `perm`/`uid`/`gid`/times are presented by rencfs
   from its own records, not read from the host OS.

## 2. The `MountPoint` / `MountHandle` contract to satisfy

A Windows implementation must provide, mirroring `src/mount/linux.rs`:

- `MountPoint::new(mountpoint, data_dir, password_provider, cipher,
  allow_root, allow_other, read_only) -> Self`
- `async fn mount(self) -> FsResult<MountHandle>`
- `MountHandle: Future<Output = io::Result<()>>` + `async fn umount(self)`

where `MountHandleInner` is the platform trait (`src/mount.rs`) that the
existing `dummy` and `linux` modules both implement. A `src/mount/windows.rs`
would be a third implementor, selected with:

```rust
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::MountHandleInnerImpl;
#[cfg(target_os = "windows")]
use windows::MountPointImpl;
```

The `allow_root` / `allow_other` arguments are Linux/FUSE concepts. On Windows
there is no equivalent per-mount ACL gate at this layer; they should be accepted
(for signature compatibility) and documented as no-ops in the first milestone
(see §6).

## 3. Backend selection

| Backend | What it is | Status / notes | Verdict |
|---|---|---|---|
| **WinFSP** (winfsp-rs) | Microsoft's user-mode filesystem framework; a kernel driver (`winfsp-x64.sys`) proxies the NTFS-compatible I/O manager to a user-mode DLL. The Rust crate `winfsp` (winfsp-rs) is *safe* FFI with a `system` feature and a delay-load build helper. | Actively maintained; listed on the official `winfsp/winfsp` "Known File Systems" wiki as the Rust binding. The `ntptfs-winfsp-rs` port passes all upstream `ntptfs` tests. | **Recommended.** |
| Dokan (dokan-rust) | Older user-mode filesystem framework; C API + a Rust binding. | Maintenance is sporadic compared to WinFSP; the WinFSP project is the de-facto standard on Windows now. | Not recommended for new code. |
| `std::fs` + manual re-parsing (no FUSE-equivalent) | A few prior threads floated "just use `std::fs`". | **Not a mount backend.** It cannot present a *new* filesystem object to Explorer/Win32; it can only read/write the backing `data_dir` directly. It would not satisfy the issue's goal ("rencfs mounts on Windows"). | Rejected. |

**Recommendation: WinFSP via the `winfsp` crate.**

## 4. Licensing analysis (important for a `MIT OR Apache-2.0` project)

- WinFSP is **GPLv3 with a FLOSS exception** (Bill Zissimopoulos). The exception
  grants permission to *link* against `winfsp-x64.dll` without the combined work
  becoming GPLv3, **provided the linking software is itself FLOSS** (satisfies the
  Free Software Definition 1.141 / Open Source Definition 1.9).
- rencfs is `MIT OR Apache-2.0` — i.e. FLOSS. Therefore **linking rencfs against
  WinFSP is permitted under the FLOSS exception** and does *not* force rencfs
  (or its users) into GPLv3.
- Two obligations come with the exception and must be honored in the
  implementation:
  1. Include the copyright notice
     `"WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos"`
     plus a link to the WinFsp repository in user-facing documentation.
  2. WinFSP must not be bundled with proprietary (non-FLOSS) software.
- The **user must install WinFSP** to use the Windows mount (it ships a kernel
  driver). This must be stated in `docs/readme/Windows.md` (this file) and in the
  top-level `README.md` "Installation" section, and the build must not require
  WinFSP at *compile* time (delay-load, §5).

**Conclusion:** no license blocker. Add an attribution line + a "requires WinFSP
install" note.

## 5. Build & dependency shape

Goal: the crate still compiles and tests on Linux/macOS *without* WinFSP
installed, and a Windows build delay-loads `winfsp-x64.dll` so the process can
start and print a helpful error if WinFSP is missing.

```toml
# Windows-only, so it is never fetched/linked for other targets
[target.'cfg(windows)'.dependencies]
winfsp = { version = "0.13", features = ["system"] }

[target.'cfg(windows)'.build-dependencies]
winfsp = { version = "0.13" }
```

and in `build.rs` (Windows branch only):

```rust
#[cfg(windows)]
fn main() {
    winfsp::build::winfsp_link_delayload();
}
```

Notes:
- `features = ["system"]` links against the *installed* WinFSP (found via the
  registry) rather than a vendored import library — correct for a delay-load,
  user-installs-WinFSP model.
- All WinFSP-specific code stays behind `#[cfg(target_os = "windows")]`, so the
  existing `linux` and `dummy` modules are untouched.
- CI must **not** require a Windows runner for the default (Linux) matrix; the
  Windows job is additive (see §9).

## 6. Architecture of `src/mount/windows.rs`

Mirror the shape of `src/mount/linux.rs`:

```
MountPointImpl  -- (mount()) -->  MountHandleInnerImpl
   │                              │
   │  owns:  EncryptedFs          │  owns:  WinFSP session handle
   │          PasswordProvider    │
   └──────────┬───────────────────┘
              │  calls into (async)
        crate::encryptedfs::EncryptedFs
```

- `MountPointImpl::new` constructs the `EncryptedFs` exactly the way the Linux
  `MountPointImpl` does (same `data_dir`/`cipher`/`password_provider` wiring),
  so the crypto path is shared verbatim.
- `mount()` calls `FspFsRegistration` / `FspFileSystem` to start the WinFSP
  session, then returns a `MountHandleInnerImpl` that drives the callback loop.
- The WinFSP **callbacks are synchronous** and run on WinFSP-managed worker
  threads, while every `EncryptedFs` method is `async` (tokio). This is the single
  hardest design point and is handled in §7.

### What is *not* stored in NTFS
Because rencfs keeps its own metadata (§1.3):
- `perm`, `uid`, `gid`, `nlink`, timestamps, and `kind` are presented from
  rencfs's own `FileAttr` — **not** from the host NTFS file.
- The Windows ACL / ownership / hard-link / reparse-point of the *backing*
  `contents/` files is irrelevant to the encrypted view.
- Consequently, a first milestone can:
  - report `perm` from `FileAttr`, mapping it to a coarse Windows DACL, and
    document the mapping;
  - return `EACCES`/`EPERM` (→ Windows access-denied) when the requested op
    violates `read_only`;
  - **ignore** `FspSetSecurity` / `FspGetSecurity` with a documented
    "not supported" error, rather than trying to map full Windows ACLs onto
    rencfs's POSIX-style `perm`.

## 7. The sync ↔ async bridge (the core technical problem)

WinFSP callbacks are synchronous; `EncryptedFs` is async. The Linux side solves
the analogous problem by running a tokio runtime and blocking FUSE worker
threads on futures. The Windows side should do the same:

1. On `mount()`, create a **dedicated multi-thread tokio runtime** for the mount
   (do *not* reuse the module-level `DIR_ENTRIES_RT` / `NOD_RT` statics in
   `src/encryptedfs.rs`, which are owned by the crypto layer).
2. Each WinFSP callback wraps the corresponding `EncryptedFs` call in
   `runtime.block_on(...)`.
3. A **blocking-capable** `EncryptedFs` handle must be `Send` across the WinFSP
   worker threads — verify `EncryptedFs` (or an `Arc<Mutex<..>>`/channel front to
   it) is `Send + 'static`. If it is not currently `Send`, introduce a thin
   `Send`-safe façade that owns the runtime + the `EncryptedFs` behind an
   `Arc`. This is the most likely place a naive implementation silently breaks,
   and it is worth a unit test that asserts `fn assert_send<T: Send>() { assert_send::<WindowsMountState>(); }`.

**Do not** call `.now_or_never()` / drop futures on timeout: a WinFSP callback
that returns an error the kernel treats as fatal can wedge the mount. A callback
must return a *defined* result; on internal failure return a Windows error code
(e.g. `EIO`) and log, matching how `linux.rs` maps `FsError` → `Errno`.

## 8. Operation mapping (WinFSP callback → `EncryptedFs`)

Root inode mapping: WinFSP's `FspFileInfo.InoNumber` is set by the app on
create/read-dir replies; use it to carry rencfs `ino` (`ROOT_INODE = 1` for the
root). A small `ino` registry (like the one `linux.rs` implicitly relies on via
FUSE inodes) maps WinFSP `InoNumber` ↔ rencfs `ino` for the lifetime of the
mount.

| WinFSP callback | `EncryptedFs` call(s) | Notes |
|---|---|---|
| `FspInitialize` | (validate args) | set `MaxComponentLength`, `FileAttributes`, `Capabilities`; reject unsupported ops |
| `FspDestroy` | `EncryptedFs` shutdown | cancel runtime, unmount |
| `FspFileSystem` (query info) | `get_attr(ROOT_INODE)` | return volume label, block size, etc. |
| `FspGetAttributes` | `get_attr(ino)` | map `FileAttr` → `WIN32_FILE_ATTRIBUTE_DATA` |
| `FspReadDirectory` / `FspFindFiles` | `read_dir(ino)` (+ `read_dir_plus`) | set `InoNumber` per entry |
| `FspRead` | `read(ino, offset, size, fh)` | `fh` is the rencfs handle from `open` |
| `FspWrite` | `write(ino, offset, buf, fh)` | |
| `FspCreate` | `open` (for open) / `create` (for new) | return fh; for new, return `Created` disposition + `InoNumber` |
| `FspClose` / `FspCleanup` | `release(fh)` | |
| `FspFlush` | `flush(fh)` | |
| `FspDelete` | `remove_file` / `remove_dir` | branch on entry kind |
| `FspSetAttributes` | `set_attr(ino, ...)` | map `FILE_BASIC_INFO`/`FILE_STANDARD_INFO`/`FILE_END_OF_FILE_INFO` |
| `FspRename` | `create` + `copy_file_range` + `remove_file`, **or** a dedicated atomic rename if added to `EncryptedFs` | see risk in §11 |
| `FspStatistics` | `get_attr(ino)` | |
| `FspCopyFileEx` | `copy_file_range` | |
| `FspSetSecurity` / `FspGetSecurity` | (not supported) | documented error (§6) |
| `FspReadDirectoryChanges` | (not supported in v1) | documented error; no inotify/ReadDirectoryChangesW emulation |

**`FspRename` is the biggest functional gap.** rencfs's `EncryptedFs` has no
single atomic rename primitive; the Linux FUSE side implements `rename` by
composing existing calls (or is limited). The implementation PR must either
(a) implement rename as a *non-atomic* `create` + `copy_file_range` +
`remove_file` sequence inside the same runtime task with a clear "not crash-safe
under power loss" caveat, or (b) add an atomic `rename(parent, old, new_parent,
new)` method to `EncryptedFs` and thread it through `linux.rs` too. Option (b) is
preferred for correctness; if out of scope for v1, ship (a) and document it.

## 9. CI plan

Add a **Windows job** to `.github/workflows/build_and_tests_reusable.yaml` (the
reusable workflow already referenced by `build_and_tests.yaml`):

- Runner: `windows-latest` (no admin needed for *build*; the `system` feature
  only needs WinFSP present at *runtime*, which the CI smoke job provides).
- Steps:
  1. `cargo build --target x86_64-pc-windows-msvc` (proves the crate compiles on
     Windows with the `winfsp` dep).
  2. *Optional smoke* (separate job, needs admin + WinFSP MSI installed):
     install WinFSP, `cargo run -- mount <mp> <data> --password <p>`, then a
     PowerShell `dir` / copy / `del` round-trip, then umount.
- The Linux/macOS jobs are unchanged. The Windows smoke job is **optional /
  nightly** at first to keep the fast matrix green while the backend is new.

## 10. Manual smoke test (run on a real Windows machine with WinFSP)

1. Install WinFSP from the official site.
2. `cargo build --release`.
3. `rencfs mount C:\enc\mp C:\enc\data --password secret` (expected: a drive /
   folder appears).
4. `echo hello > C:\enc\mp\hello.txt` → then `type C:\enc\mp\hello.txt` (read
   back must equal `hello`).
5. `mkdir C:\enc\mp\sub` → `dir C:\enc\mp` (must show `hello.txt` and `sub`).
6. `del C:\enc\mp\hello.txt` → `dir` (must be gone).
7. `umount` (the `umount` helper path must be adapted for Windows — the Linux
   `src/mount.rs::umount` shells out to the `umount` binary; Windows uses
   `FspUnmount` / closing the session, **not** a shell command).
8. Unplug scenario (skip): verify a hard stop doesn't corrupt `data_dir`.

## 11. Risks & open questions (honest list)

1. **`Send` across WinFSP threads** — the `EncryptedFs` handle must be `Send`.
   If it is not today, a thin façade is required (§7). *Verify first thing.*
2. **Rename atomicity** — no atomic rename primitive exists; see §8.
3. **Inode/handle registry** — WinFSP `InoNumber` ↔ rencfs `ino` mapping across
   the lifetime of the mount (esp. after deletes).
4. **`umount` helper** — the shared `src/mount.rs::umount` shells out to the
   Unix `umount` binary; Windows needs a WinFSP-specific unmount path, so
   `umount` must become `cfg`-split too.
5. **`allow_root` / `allow_other`** — no Windows equivalent; no-op in v1.
6. **Read-only enforcement** — map to WinFSP capabilities + reject writes.
7. **Keyring / password provider** — the `keyring` crate supports the Windows
   Credential Manager; needs a runtime test (the research cannot assert this
   without a Windows host).
8. **No Windows runtime validation has been performed in this research.** The
   smoke test in §10 is the gate before claiming the implementation works.

## 12. Acceptance criteria for the implementation PR

A PR is "done" for the bounty only when **all** of the following are true:

1. `cargo build` succeeds on a Windows target **without** WinFSP installed
   (delay-load), and `cargo build` + `cargo test` still pass on Linux (no
   regression to the existing `linux` module).
2. On a Windows host with WinFSP installed, the §10 smoke test passes end to
   end: create / read / list / delete / umount.
3. `FileAttr` values (size, kind, timestamps) round-trip correctly (read back
   equals what was written).
4. `umount` is a clean WinFSP unmount (no lingering session / file locks).
5. A unit test asserts the mount state is `Send`.
6. README + this doc note "Windows requires WinFSP installed" and include the
   WinFSP attribution (§4).
7. No `panic!` on the hot read/write path; errors map to defined Windows codes.
