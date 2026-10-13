# Windows Support: Implementation Research

> **Status: research note — not a claim that rencfs mounts on Windows today.**
>
> This document studies *how* native Windows support could be implemented on top of
> the existing `EncryptedFs` layer. It does not ship a working Windows mount, it does
> not claim runtime validation on Windows, and it does not add a partial backend that
> silently pretends to work.

Tracking issue: [#3 — docs: add Windows support implementation research](https://github.com/radumarias/rencfs/issues/3)

---

## 1. Executive summary

rencfs is an encrypted filesystem whose cryptographic core (`EncryptedFs`) is already
platform-independent; only the **mount front-end** is Linux-specific (`fuse3`). On any
non-Linux target rencfs currently compiles against a **no-op dummy** mount backend, so
the project builds but cannot mount.

This note:

- confirms from the checked-in source that the correct integration seam already exists
  (the `MountPoint` / `MountHandleInner` traits in `src/mount.rs`, and the
  platform-neutral `EncryptedFs` API);
- recommends **WinFsp** (via the `winfsp` Rust crate) as the Windows kernel↔user
  bridge, and compares it against Dokany, ProjFS and CallbackFS;
- flags one **licensing checkpoint** that should be confirmed with the maintainer
  before any Windows dependency is added to a `MIT OR Apache-2.0` crate;
- proposes a concrete `src/mount/windows.rs` architecture and a full
  **WinFsp callback → `EncryptedFs` method mapping table**;
- lists the Windows metadata decisions and the NTFS features deliberately left out of
  milestone 1;
- gives a build/CI plan, a manual smoke-test checklist, and **acceptance criteria for a
  truthful first implementation PR**.

---

## 2. Current state of rencfs (evidence from source)

Facts below come from the repository at `main` (commit `11d87caa`, 2024-12-21).

### 2.1 Only Linux has a real mount backend

`Cargo.toml` declares the FUSE dependency under a target gate:

```toml
[target.'cfg(target_os = "linux")'.dependencies]
fuse3 = { version = "0.8.1", features = ["tokio-runtime", "unprivileged"] }
```

So `fuse3` is *not* pulled in on Windows — nothing breaks, but nothing mounts either.

### 2.2 The platform seam already exists

`src/mount.rs` defines **platform-neutral traits**, and selects an implementation by
target OS:

```rust
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::MountHandleInnerImpl;
#[cfg(target_os = "linux")]
use linux::MountPointImpl;

#[cfg(not(target_os = "linux"))]
mod dummy;
#[cfg(not(target_os = "linux"))]
use dummy::MountHandleInnerImpl;
#[cfg(not(target_os = "linux"))]
use dummy::MountPointImpl;
```

The public entry point is already OS-agnostic:

```rust
pub fn create_mount_point(
    mountpoint: &Path,
    data_dir: &Path,
    password_provider: Box<dyn PasswordProvider>,
    cipher: Cipher,
    allow_root: bool,
    allow_other: bool,
    read_only: bool,
) -> impl MountPoint { /* -> MountPointImpl::new(...) */ }
```

| File | Lines | Role |
|------|------:|------|
| `src/mount.rs` | ~150 | `MountPoint`, `MountHandle`, `MountHandleInner` traits + `create_mount_point()` + `umount()` |
| `src/mount/linux.rs` | 1460 | Real backend: `fuse3::raw::Filesystem` impl mapping FUSE ops → `EncryptedFs` |
| `src/mount/dummy.rs` | 69 | No-op stub compiled on macOS/Windows/BSD today |
| `src/encryptedfs.rs` | 2668 | Platform-agnostic encrypted FS core |

**Conclusion:** Windows support is a matter of adding `src/mount/windows.rs` that
implements the *same* two traits and wiring it into the `cfg(target_os = "windows")`
arm — **no changes to `EncryptedFs` are required.**

### 2.3 `EncryptedFs` is already FUSE-agnostic

`EncryptedFs` returns **its own** attribute/error types, not `fuse3` types — which is
exactly what makes a second front-end feasible:

```rust
pub struct FileAttr { ino: u64, size: u64, blocks: u64, atime, mtime, ctime,
                      crtime: SystemTime, kind: FileType, perm: u16, nlink: u32,
                      uid: u32, gid: u32, rdev: u32, blksize: u32, flags: u32 }

pub enum FileType { Directory, RegularFile }   // Symlink/Socket/NamedPipe commented out
```

Key public methods available to any front-end (`src/encryptedfs.rs`):

```
new, exists, is_dir, is_file, create, find_by_name, len, remove_dir, remove_file,
exists_by_name, read_dir, read_dir_plus, get_attr, set_attr, read, release,
is_read_handle, is_write_handle, write, flush, copy_file_range, open, set_len,
rename, create_write, create_write_seek, create_read, create_read_seek, passwd
```

Note `FileAttr.crtime` is documented *"macOS only"* today — on Windows a real creation
time **is** available, so this field becomes usable for the first time.

### 2.4 Build environment

| Property | Value |
|----------|-------|
| Edition | 2021 |
| Version | 0.13.78 |
| License | `MIT OR Apache-2.0` |
| Toolchain | `rust-toolchain.toml` → `channel = "nightly"` (+ rustfmt, rustc-dev, clippy) |
| Tests | `tests/rencfs_linux_itest.rs` (Linux-only integration test) |

The nightly pin matters: any Windows CI job must install the same nightly channel.

---

## 3. Backend selection

A Windows filesystem needs a user-mode↔kernel bridge. Candidates:

| Option | Rust crate | Latest | Downloads | License | Verdict |
|--------|-----------|--------|----------:|---------|---------|
| **WinFsp** (native API) | `winfsp` / `winfsp-sys` | 0.13.1+winfsp-2.1 | 86k / 59k | GPLv3 **+ FLOSS exception** / commercial | **Recommended** |
| WinFsp (FUSE-compat API) | (via WinFsp DLL) | — | — | same | Fallback; less control |
| Dokany | `dokan` / `dokan-sys` | 0.3.1+dokan206 | 22k / 30k | LGPL (incl. kernel driver) | Not recommended (see §4) |
| Projected FS | `windows-projfs` / `projfs` | 0.1.8 / 0.1.2 | 12k / 4k | MIT (crate) | Wrong model — projection, not a real FS |
| CallbackFS | none (C/.NET only) | — | — | Commercial | Rejected (proprietary, no Rust) |

### 3.1 Why WinFsp

1. **Mature and widely deployed** — the de-facto "FUSE for Windows"; used by
   many OSS and commercial products, and validated by the WinFsp test-suite.
2. **Native Rust bindings exist** — [`winfsp`](https://github.com/SnowflakePowered/winfsp-rs)
   (`winfsp` 0.13.1+winfsp-2.1, `winfsp-sys` 0.12.1). The crate exposes
   `winfsp::host::FileSystemHost<T: FileSystemContext>` with `new` / `new_async`,
   `mount`, `start_with_threads`, `unmount`, `stop`, plus a `FileSystemContext` trait
   that maps cleanly onto rencfs' inode/handle design. It builds on **stable Rust
   ≥ 1.87** (rencfs' own nightly pin is independent).
3. **Offers both** a native API *and* a FUSE-compatibility layer — we start with the
   native API for control, and keep the FUSE layer as a documented fallback.
4. Delay-loading is a **first-class feature** of the crate
   (`winfsp::build::winfsp_link_delayload()`), which keeps the Windows-only surface
   isolated behind a target-`cfg`.

### 3.2 Why not Dokany

Dokany is a reasonable library, but its **kernel driver is LGPL**. Static/free use of an
LGPL kernel-mode driver from an MIT/Apache-2.0 project raises unresolved
derivative-work questions that rencfs should not take on without a lawyer.
WinFsp's *explicit* FLOSS exception is a designed-for-this-use-case alternative.

### 3.3 Why not ProjFS

Projected Filesystem is a *projection* mechanism (placeholder files materialised on
demand), not a full filesystem driver. It cannot express rencfs' semantics (create,
rename, arbitrary writes) faithfully.

---

## 4. Licensing checkpoint — **confirm before adding any dependency** ⚠️

This is the single item that should be settled *before* code lands.

WinFsp is licensed **GPLv3 with a special exception for Free/Libre and Open Source
Software (FLOSS)**, or under a commercial license otherwise. The FLOSS exception
grants additional permissions beyond GPLv3 — specifically for software that meets the
FLOSS definition — to link with WinFsp DLLs.

rencfs is `MIT OR Apache-2.0`, which **is** FLOSS (both are OSI-approved). So the
exception *should* apply, subject to:

- [ ] the linking being to the **unmodified WinFsp DLL** (delay-load), not vendoring
      WinFsp source into rencfs;
- [ ] shipping the required **copyright / license notices** for WinFsp;
- [ ] **not redistributing the WinFsp installer** without checking the exception's
      redistribution terms (document an install prerequisite instead).

> **Action item for the maintainer:** confirm the FLOSS-exception text covers rencfs'
> intended distribution model (a MIT/Apache-2.0 crate + binary). Everything below
> assumes *yes*; if the answer is *no*, the whole Windows path needs a different
> backend and this document should be superseded.

Sources: <https://winfsp.dev/com/> · <https://github.com/winfsp/winfsp/blob/master/License.txt>

---

## 5. Windows-only dependency & build shape

### 5.1 Cargo wiring (no effect on Linux/macOS builds)

```toml
[target.'cfg(windows)'.dependencies]
winfsp = { version = "0.13", features = ["system", "windows-62"] }
windows = { version = "0.62", features = ["Win32_Foundation", "Win32_Storage_FileSystem"] }

[target.'cfg(windows)'.build-dependencies]
winfsp = "0.13"          # for winfsp::build::winfsp_link_delayload()
```

- The `system` feature builds against the **installed** WinFsp libraries (path resolved
  via the Registry) instead of the bundled import library — appropriate for CI where
  WinFsp is installed by the runner setup step.
- The `windows-62` feature opts into conversions between `windows` crate error types
  and `FspError` for `windows` 0.62 (the current release line). Supported values are
  `windows-56`, `windows-60`, `windows-61`, `windows-62`.

`fuse3` stays gated to `cfg(target_os = "linux")` exactly as today.

### 5.2 Delay-load / dynamic linking

The `winfsp` crate requires a build script to emit the delay-load directive:

```rust
// build.rs  (Windows target only)
fn main() {
    #[cfg(windows)]
    winfsp::build::winfsp_link_delayload();
}
```

Linking against `winfsp-x64.dll` (or `winfsp-a64.dll` on ARM64) **dynamically** means:

- the binary still *starts* on a machine without WinFsp and can emit a clear
  "WinFsp not installed" error instead of failing to load at process start;
- the GPL/FLOSS boundary is a clean dynamic-link boundary.

`WINFSP_DLL_OUTPUT_PATH` can be set to have the build script copy the DLL next to the
output for local testing.

### 5.3 Toolchain

- **Host build:** MSVC (`stable-x86_64-pc-windows-msvc`). The `winfsp` crate expects a
  MSVC-compatible ABI; do **not** target `*-gnu` (MinGW) — `winfsp`'s import library
  and delay-load machinery assume MSVC.
- **Cross-compile from Linux (dev convenience):** `cargo-xwin` is the pragmatic route,
  but it needs the WinFsp headers/import lib available to the cross build; treat
  cross-compilation as a *check-only* convenience, not a substitute for a real Windows
  CI job.
- **Nightly pin preserved:** Windows CI must install the channel from
  `rust-toolchain.toml`.

---

## 6. Proposed `src/mount/windows.rs` architecture

Mirror the structure of `linux.rs` so the trait contract stays identical.

```
src/mount.rs                 (unchanged traits + new cfg arm)
src/mount/linux.rs           (unchanged)
src/mount/dummy.rs           (unchanged — still used on macOS/BSD)
src/mount/windows.rs         (NEW)
```

Wire-up in `src/mount.rs`:

```rust
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::{MountHandleInnerImpl, MountPointImpl};
```

Sketch of `windows.rs`:

```rust
pub struct MountPointImpl {
    mountpoint: PathBuf,          // drive letter ("R:") or directory
    data_dir: PathBuf,
    password_provider: Box<dyn PasswordProvider>,
    cipher: Cipher,
    read_only: bool,              // allow_root/allow_other: no direct WinFsp equiv, see §8
}

pub struct MountHandleImpl { host: winfsp::host::FileSystemHost<RencFsContext> }

#[async_trait]
impl MountPoint for MountPointImpl {
    fn new(/* same 7 args as linux.rs */) -> Self { /* ... */ }
    async fn mount(self) -> FsResult<MountHandle> {
        // 1. EncryptedFs::new(...)  — identical to linux.rs
        // 2. build RencFsContext { fs: Arc<EncryptedFs>, handles: ... }
        //    implementing winfsp::filesystem::FileSystemContext
        // 3. FileSystemHost::new_async(volume_params, ctx)?  (EncryptedFs is async/tokio)
        //    host.mount(mountpoint)?; host.start_with_threads(n)?
        // 4. return MountHandle{ inner: MountHandleImpl { host } }
    }
}

#[async_trait]
impl MountHandleInner for MountHandleImpl {
    async fn unmount(self) -> io::Result<()> {
        // host.stop(); host.unmount();
    }
}
```

Verified `winfsp` 0.13.x surface used above (from the crate source, `winfsp/src/host/fshost.rs`
and `winfsp/src/filesystem/context.rs`):

| Symbol | Path | Purpose |
|--------|------|---------|
| `FileSystemHost<T: FileSystemContext, S = FineGuard>` | `winfsp::host` | hosts a filesystem; `new` / `new_async` / `new_with_options`, `mount`, `start_with_threads`, `unmount`, `stop` |
| `FileSystemContext` (trait) | `winfsp::filesystem` | implement the WinFsp callbacks on your context type; `AsyncFileSystemContext` variant exists |
| `VolumeParams` / `FileSystemParams` | `winfsp::host` | volume + host configuration |
| `MountPoint` | `winfsp::host` | mount target (drive letter or directory) |
| `winfsp::build::winfsp_link_delayload()` | `winfsp::build` | build-script delay-load directive |
| `winfsp::init::{winfsp_init, winfsp_init_or_die}` | `winfsp::init` | library initialisation |

The FS context wraps `Arc<EncryptedFs>` plus a **file-context registry**: WinFsp hands
opaque per-file context objects back to callbacks, and rencfs must carry the `ino` and
the open `EncryptedFs` handle across calls (see §7).

---

## 7. Operation mapping: WinFsp callbacks → `EncryptedFs`

Grounding: `linux.rs` already performs the analogous FUSE→`EncryptedFs` translation, so
each Windows callback has a Linux precedent.

| WinFsp callback | Linux/FUSE analogue in `linux.rs` | `EncryptedFs` call(s) |
|-----------------|-----------------------------------|-----------------------|
| `GetVolumeInfo` | `statfs` | return the existing `STATFS` block constants |
| `GetSecurityByName` | `lookup` | `find_by_name(parent, name)` → `get_attr(ino)` |
| `Create` | `create` | `create(parent, name, CreateFileAttr{...})` |
| `Open` | `open` | `open(ino, read, write)` → handle |
| `Overwrite` | `setattr` (truncate) | `set_len(ino, 0)` |
| `Read` | `read` | `read(ino, offset, size, handle)` |
| `Write` | `write` | `write(ino, offset, buf, handle)` |
| `Flush` | `flush` | `flush(handle)` |
| `Close` / `Cleanup` | `release` | `release(handle)` |
| `GetFileInfo` | `getattr` | `get_attr(ino)` |
| `SetBasicInfo` | `setattr` | `set_attr(ino, SetFileAttr{ atime, mtime, ctime, ... })` |
| `SetFileSize` | `setattr` | `set_len(ino, size)` |
| `Rename` | `rename` | `rename(parent, name, new_parent, new_name)` |
| `ReadDirectory` | `readdir` | `read_dir(ino)` / `read_dir_plus(ino)` iterator |
| `GetDirInfoByName` | `lookup` (dir) | `find_by_name` → `get_attr` |
| `Close` (dir) | `releasedir` | `release(handle)` |

Notes:

- **Handle identity.** `EncryptedFs::open()` returns a `u64` handle; store it in the
  per-file context object together with the `ino` so `Read`/`Write`/`Close` resolve
  correctly.
- **Directory enumeration.** WinFsp expects the callback to fill a `DirBuffer`; iterate
  `read_dir(ino)` and push entries, exactly as `linux.rs`'s `DirectoryEntryIterator`
  adapts `encryptedfs::DirectoryEntry` into `fuse3::DirectoryEntry`.
- **`copy_file_range`** has a `linux.rs` precedent; WinFsp exposes it via
  `SetFileInfo`/FSCTL paths — treat as milestone-2 (fall back to read/write copy).

---

## 8. Windows metadata decisions

| Concern | Decision for milestone 1 |
|---------|--------------------------|
| **Inode (`ino`)** | Reuse the native `EncryptedFs` `u64` ino; carry it in the WinFsp `FileContext`. No separate inode table needed. |
| **`uid`/`gid`** | No POSIX identity on Windows. Report synthetic `0/0` (or map the process SID) and **document** it. Real ACL mapping is milestone 2. |
| **Timestamps** | Convert `FILETIME` (100-ns ticks since 1601-01-01 UTC) ↔ `std::time::SystemTime`. Provide `filetime_to_systemtime()` / inverse helpers. |
| **Creation time** | Windows reports it natively → populate `FileAttr.crtime` (previously "macOS only"). |
| **`perm` bits** | Windows has no Unix permission bits; map read-only ↔ `0o444`/`0o666` for display only. |
| **Case sensitivity** | NTFS is case-**in**sensitive by default; `EncryptedFs` name lookup is case-sensitive. Milestone 1 should **document** the behaviour rather than silently uppercase/lowercase (silent case-folding weakens the encrypted-name design). Confirm desired behaviour with the maintainer. |
| **Long paths** | Support `\\?\`-style long paths; WinFsp handles the kernel side but the mount root path must be well-formed. |
| **Drive letter vs directory** | Support both `R:` and a directory mount point (`FileSystemHost::mount` accepts either). |

---

## 9. Deliberately unsupported in milestone 1

These are **out of scope** and must be stated plainly in the PR (not silently faked):

- **Symbolic links** — `FileType` only has `Directory` and `RegularFile` (the others are
  commented out in `encryptedfs.rs`).
- **Hard links / `nlink` > 1** — `nlink` is synthetic today.
- **Alternate Data Streams (ADS)** and any xattr interface.
- **Reparse points / junctions.**
- **Security descriptors / Windows ACLs** — no mapping exists yet.
- **Byte-range / opportunistic locks**, oplocks.
- **Sparse files**, **EFS** integration, **compression** attributes.
- **`copy_file_range` fast path** (milestone 2).

---

## 10. Build & CI plan

### 10.1 GitHub Actions

Add a Windows job alongside the Linux one:

```yaml
windows:
  runs-on: windows-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@nightly   # honour rust-toolchain.toml
    - name: Install WinFsp
      run: choco install winfsp -y
    - run: cargo check --all-targets
    - run: cargo clippy
    - run: cargo test --lib
```

### 10.2 Test gating

- `tests/rencfs_linux_itest.rs` is **Linux-only** — it must be `cfg`-gated so the
  Windows job skips it rather than failing to compile.
- The `encryptedfs` unit tests are platform-independent and *should* run on Windows —
  that is the cheapest proof the core is healthy on the target.
- An **end-to-end mount test cannot run in CI** without WinFsp's kernel driver being
  loadable on the runner; treat the real mount as a *manual* smoke test (§11).

---

## 11. Manual smoke test — Windows host with WinFsp installed

Run on a real Windows 10/11 machine after `choco install winfsp`:

1. `rencfs create R:\secret` (or the project's equivalent) → data dir created.
2. `rencfs mount R:\secret R:` → mount succeeds; drive appears in Explorer.
3. `echo hello > R:\hello.txt && type R:\hello.txt` → round-trips.
4. Unmount → remount → `hello.txt` still readable (**persistence**).
5. `mkdir`, `ren`, `del`, `copy` via Explorer and via `cmd` → all reflected.
6. Copy a 100 MB file in and out; compare hashes.
7. Verify the **on-disk data dir contains only ciphertext** (grep for the plaintext
   filename/content should find nothing).
8. Confirm no leftover process/drive after unmount.

Record the exact Windows build number and WinFsp version in the PR.

---

## 12. Acceptance criteria for a truthful first implementation PR

A first Windows PR is acceptable **only if** all of these hold:

- [ ] `src/mount/windows.rs` implements `MountPoint` + `MountHandleInner` (no stub
      returning `Ok(())`).
- [ ] `cargo check --all-targets` and `cargo clippy` pass on **Windows/MSVC** with the
      same nightly toolchain as Linux.
- [ ] The core `encryptedfs` unit tests pass on Windows.
- [ ] Every callback in the §7 table is either implemented or explicitly returns
      `STATUS_NOT_SUPPORTED` — **no silent no-ops**.
- [ ] §9 unsupported list is reproduced in the PR description.
- [ ] §4 licensing checkpoint is confirmed (or the PR states it is pending).
- [ ] CI job added and green; Linux build behaviour unchanged.
- [ ] PR contains **no** claim of Windows runtime validation that was not actually
      performed.
- [ ] The manual smoke-test results (§11), with Windows build + WinFsp version, are
      attached **if** a Windows host was available.

---

## 13. Risks & open questions

1. **Licensing (§4)** — the only potentially blocking item. Must be confirmed first.
2. **Async model mismatch.** `EncryptedFs` is async/`tokio`; WinFsp callbacks are
   synchronous. Plan: run a `tokio` runtime on the mount thread and
   `block_on` inside callbacks (matching how `linux.rs` uses a `tokio` runtime).
3. **Case sensitivity (§8)** — a product decision, not just an implementation detail.
4. **Identity/ACL (§8)** — anything beyond synthetic `0/0` is significantly more work.
5. **`FileType` too narrow** — if symlinks are ever wanted, `encryptedfs.rs` must grow
   first; out of scope here.
6. **Nightly pin** — Windows contributors must use the pinned nightly, or CI will
   diverge.
7. **Cross-compilation** is a convenience only; correctness must be proven on real
   Windows/CI.

---

## 14. Sources

Repository (checked out at `main`, `11d87caa`, 2024-12-21):

- `src/mount.rs`, `src/mount/linux.rs`, `src/mount/dummy.rs`
- `src/encryptedfs.rs`
- `Cargo.toml`, `rust-toolchain.toml`, `tests/rencfs_linux_itest.rs`

External:

- WinFsp — <https://github.com/winfsp/winfsp> · licensing: <https://winfsp.dev/com/>
- WinFsp license text: <https://github.com/winfsp/winfsp/blob/master/License.txt>
- WinFsp native API vs FUSE: <https://winfsp.dev/doc/Native-API-vs-FUSE/>
- Rust bindings `winfsp-rs`: <https://github.com/SnowflakePowered/winfsp-rs> · docs: <https://docs.rs/winfsp>
- Dokany: <https://github.com/dokan-dev/dokany>
- crates.io (versions observed 2026-10-13): `winfsp` 0.13.1+winfsp-2.1 ·
  `winfsp-sys` 0.12.1+winfsp-2.1 · `dokan` 0.3.1+dokan206 · `windows` 0.62.2 ·
  `windows-projfs` 0.1.8 ·

---

*Related: #3 — "docs: add Windows support implementation research".*
