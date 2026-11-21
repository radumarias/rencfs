# Windows support — implementation research

> Status: **research only**. Nothing in this document claims that rencfs mounts on
> Windows today. It maps the current codebase onto the Windows filesystem stack
> and proposes a concrete, staged path to a truthful first implementation PR.

## 1. Where the codebase stands today

The mount layer is already abstracted behind a small trait surface, which is the
single most important fact for a Windows port:

- `src/mount.rs` defines `MountPoint::new(...)` and `MountPoint::mount()` and
  cfg-gates two implementations:
  - `linux` → real FUSE3 backend (`src/mount/linux.rs`, `fuse3` crate,
    `tokio-runtime` feature).
  - everything else → `dummy.rs`, which accepts the arguments and returns
    `FsError::Other("Dummy implementation")` from `mount()`.
- All platform-specific dependency is already isolated:
  `fuse3` lives under `[target.'cfg(target_os = "linux")'.dependencies]` in
  `Cargo.toml`, so a Windows build of the crate compiles today (it just cannot
  mount).
- `EncryptedFs` (`src/encryptedfs.rs`) is the platform-neutral core. Its public
  API — `new`, `create`, `find_by_name`, `exists_by_name`, `read_dir`,
  `read_dir_plus`, `get_attr`, `set_attr`, `read`, `write`, `open`, `release`,
  `flush`, `set_len`, `rename`, `remove_file`, `remove_dir`, `copy_file_range`,
  `passwd` — uses only `std::path`, `std::time::SystemTime`, and tokio
  synchronization primitives. No FUSE types leak into it.
- `src/keyring.rs` already uses the `keyring` crate, which supports the Windows
  Credential Manager on `x86_64-pc-windows-msvc`. Password storage is **not** a
  porting blocker.
- `tokio = { version = "1.36", features = ["full"] }` is already a dependency,
  so the async runtime needed to drive `EncryptedFs` from synchronous Windows
  callbacks is available without new crates.

Conclusion: the port is "one new backend module + build/packaging work", not an
architecture rewrite.

## 2. Backend options on Windows

| Option | Maturity | Fit for rencfs | Notes |
|---|---|---|---|
| **WinFsp** (`winfsp` crate family) | Mature, actively maintained, FUSE-like callback model | **Recommended.** Closest semantic match to `src/mount/linux.rs`; per-user or global mounts; widely used by SSHFS-Win, rclone mount, etc. | LGPL-3.0 — see §3. Requires the WinFsp runtime installed (or shipped). |
| **Dokany** | Mature; bindings exist but Rust crate maintenance is weaker | Viable fallback | Also LGPL-family licensing; callback model similar to WinFsp. Evaluate only if WinFsp bindings prove unmaintained. |
| **ProjFS / Cloud Filter API** | Microsoft-native, but designed for *cloud placeholder* files with hydration | Poor fit | Files appear as online-only placeholders; sync/async hydration model does not match a fully-local encrypted FS. Revisit only if "files-on-demand" becomes a goal. |
| **NFS/SMB server + Windows client** | Works but heavy | Poor fit | Requires a server component, UNC paths, and gives up drive-letter UX. Not recommended. |
| **WinFsp "memfs"/passthrough experiments** | N/A | Not applicable | We need a real encrypted backend, not a demo FS. |

Recommendation: **WinFsp**, behind the existing `MountPoint` trait, exactly the
way `fuse3` sits behind it on Linux.

## 3. Licensing checkpoint (must resolve before shipping)

- rencfs is `MIT OR Apache-2.0`. WinFsp is **LGPL-3.0** (verify the exact version
  of the `winfsp`/`winfsp-sys` crates and the bundled launcher at implementation
  time — licenses in this space move).
- LGPL is compatible with MIT/Apache-2.0 **if WinFsp is used as a separate
  work**: dynamic linking against `winfsp-x64.dll`, no static linking, no
  modification of WinFsp sources, and license notices preserved. The Rust
  `winfsp-sys` bindings are thin FFI and do not create a derivative work of
  rencfs, but the *packaging* story must be explicit:
  - Option A (preferred): require the user to install WinFsp (winget/MSI) and
    document it; rencfs ships no WinFsp binaries.
  - Option B: bundle the WinFsp installer/launcher DLLs with rencfs releases and
    provide the required LGPL notices + a written offer for WinFsp sources.
- Action item for the implementation PR: add a `LICENSE` note or `THIRD_PARTY`
  file entry naming WinFsp, its license, and how it is linked. Do not claim
  "MIT only" packaging if WinFsp binaries are redistributed.

## 4. Proposed architecture

```
Cargo.toml
  [target.'cfg(target_os = "windows")'.dependencies]
  winfsp = ...        # FFI bindings (exact crate/version TBD at impl time)

src/mount.rs
  #[cfg(target_os = "windows")] mod windows;
  #[cfg(target_os = "windows")] use windows::MountHandleInnerImpl;
  #[cfg(target_os = "windows")] use windows::MountPointImpl;
  // cfg(not(any(linux, windows))) keeps dummy.rs for macOS etc.

src/mount/windows.rs   # new: WinFsp filesystem impl, mirrors mount/linux.rs role
```

`MountPointImpl::new` keeps the same signature. `mount()`:

1. `EncryptedFs::new(data_dir, password_provider, cipher, read_only)` — already
   cross-platform.
2. Build a `winfsp::Volume` + `FileSystem` implementation whose callbacks call
   into `Arc<EncryptedFs>`.
3. Return a `MountHandle` whose `Future`/`unmount` mirrors `mount/linux.rs`:
   the handle resolves when the filesystem is unmounted (WinFsp dispatch loop
   ends), and `unmount()` stops the dispatcher.

### 4.1 Sync-callback ↔ async-core bridge

WinFsp invokes filesystem callbacks on its own worker threads — they are
**synchronous**. `EncryptedFs` methods are `async` and use `tokio::sync` locks
plus `tokio::fs`. Two viable bridges:

- **Per-thread runtime (recommended for M1):** each WinFsp worker thread lazily
  creates a `tokio::runtime::Builder::new_current_thread().enable_all()` and
  `block_on`s the `EncryptedFs` call. Simple, no deadlocks, no
  `block_in_place` requirements. Slight overhead per callback; acceptable for a
  first milestone.
- **Shared multi-thread runtime + `block_in_place`:** one
  `Runtime::new()` owned by the mount, callbacks do
  `tokio::task::block_in_place(|| Handle::current().block_on(fut))`. Faster but
  requires the callback thread to *be* a runtime worker thread — WinFsp threads
  are not, so this only works via `runtime.spawn` + a `std::sync::mpsc`/oneshot
  round-trip. More machinery; defer to M2 if profiling demands it.

Important: `EncryptedFs` uses `std::sync::RwLock` in a few iterator paths
(`DirectoryEntryIterator`) *because* they run in sync code — the Windows backend
must preserve that property and not hold a tokio guard across a WinFsp callback
boundary.

### 4.2 WinFsp volume flags

Set on the `Volume`/`FileSystem`:

- `CaseSensitive = false` is **not** a WinFsp option — WinFsp filesystems are
  case-preserving but lookups are performed by the OS; see §5.1 for the case
  sensitivity decision.
- `CaseInsensitive` lookup behavior: WinFsp passes the name the caller used;
  matching against rencfs's exact `SecretString` names must be decided
  explicitly (see §5.1).
- `FileInfo`/open flags: disable memory-mapped I/O (`FILE_FLAG_…`/WinFsp
  `VolumeParams`/`FileSystemHost` options) for M1 — rencfs's read path is not
  exercised under mmap today, and mmap on FUSE is also typically off.
- `ReadOnly` mount: WinFsp supports a read-only filesystem flag; also keep
  passing `read_only` into `EncryptedFs::new` so the *data layer* refuses writes
  even if the FS flag is bypassed (defense in depth, same as Linux).

## 5. Semantic gaps that need explicit decisions

These are the places where "it compiles" ≠ "it works correctly". Each must be
decided and documented in the implementation PR, not silently inherited.

### 5.1 Case sensitivity and Unicode normalization

NTFS is case-insensitive and applies Unicode normalization; rencfs stores
names as exact `SecretString`s and `find_by_name`/`exists_by_name` do exact
matching. On Windows, `Readme.txt` vs `README.TXT` will reach the same callback.
Options:

- **A (recommended M1):** document that rencfs-on-Windows presents a
  case-*sensitive* namespace and normalize lookups by storing names in a
  canonical form (e.g. NFC + a documented case rule). Requires a small change in
  how `EncryptedFs` resolves names or a lookup-fallback in the Windows layer.
- **B:** keep exact-match and accept that some Windows apps will fail to open
  files they created under a different case. Cheapest, worst UX.
- Whatever is chosen must be written into `docs/readme/` — silent divergence
  from NTFS semantics is the #1 source of "it almost works" bug reports.

### 5.2 Timestamps

`FileAttr` uses `std::time::SystemTime` with `atime/mtime/ctime/crtime`.
Windows reports `FILETIME` (100 ns since 1601) and distinguishes
`CreationTime/LastAccessTime/LastWriteTime/ChangeTime`. Map:

- `crtime` → `CreationTime`, `mtime` → `LastWriteTime`, `atime` →
  `LastAccessTime`. `ctime` (metadata-change) has no direct Windows peer;
  either map it to `ChangeTime` (NTFS has one) or fold it into `mtime` and
  document the loss.
- WinFsp `SetFileInformationByName`/`SetFileInfo` must route through
  `EncryptedFs::set_attr` — verify `SetFileAttr` covers every field Windows
  sends (it does: size, times, perm, uid/gid, rdev, flags — see
  `src/encryptedfs.rs:116-200`).

### 5.3 Permissions and ownership

`FileAttr`/`CreateFileAttr` carry `perm: u16`, `uid`, `gid` — Unix-shaped.
Windows security is ACL/DACL-based:

- M1: return a static, permissive security descriptor from
  `GetSecurityByName`/`GetFileSecurity` and ignore `SetSecurityByName` (log at
  debug). Do **not** try to translate `perm` to DACLs.
- `allow_root`/`allow_other` have no Windows equivalent — Windows mounts are
  per-user-session (or global with the `-o global`/service mode). Decide:
  accept-and-ignore with a CLI warning, or reject the flags on Windows.
  Document the choice in `run.rs`/CLI help.

### 5.4 File identity and hard links

`EncryptedFs` identifies files by `ino: u64`. WinFsp has `FileIndex`
(64-bit) — map `ino` directly. WinFsp also supports hard links via
`GetHardLinkInfo`/`CreateHardLink`; rencfs has no link concept — return
"not supported"/empty for M1.

### 5.5 Delete/cleanup semantics

FUSE splits `flush`/`release`; WinFsp splits `Close`/`Cleanup`. Map:

- `Cleanup` ≈ last-handle-close bookkeeping → `EncryptedFs::release`/`flush`
  equivalents. `Close` fires after `Cleanup`; treat it as a no-op ack.
- WinFsp delete-pending semantics differ from POSIX `unlink`-while-open.
  `remove_file`/`remove_dir` must tolerate the file still being open — check
  `opened_files_for_read/write` handling in `EncryptedFs` before assuming the
  Linux ordering holds.

### 5.6 Read/write path details

- `EncryptedFs::read/write` take `offset: u64` and `handle: u64` — WinFsp
  provides byte offsets and a `FileHandle` you allocate; keep a
  `handle → fh` map in the Windows layer (the Linux layer does the same via
  fuse file handles).
- `copy_file_range` has no Windows peer; WinFsp `CopyFileRange` can be
  implemented as read+write through `EncryptedFs` (it already exists) or
  declined — check what `FSCTL`/`CopyFileEx` callers actually require.
- Directory enumeration: `read_dir`/`read_dir_plus` return iterators;
  WinFsp `ReadDirectory`/`ReadDirectoryEntry`(+`Ex`) need restartable
  iteration — buffer entries per open directory handle or re-create the
  iterator on each callback (measure; entries are `SecretString` names, cheap
  to rebuild but not free).

## 6. Build, CI, packaging

- `rust-toolchain.toml` already pins a toolchain; add
  `x86_64-pc-windows-msvc` (and optionally `-gnu`) to CI matrix.
- `winfsp-sys` typically needs WinFsp headers/libs at build time — either
  document "install WinFsp first" for source builds, or vendor the FFI and
  load `winfsp-x64.dll` dynamically at runtime (preferred: keeps builds
  hermetic and matches the Option-A licensing story in §3).
- `cargo test` on Windows: `src/keyring.rs` tests already exercise the
  Credential Manager path — run them on a Windows runner to confirm.
- Releases: Windows artifact should be a `.msi`/`.zip` plus a README note
  "requires WinFsp runtime" (winget id to be pinned at release time).

## 7. Milestones and acceptance criteria

- **M0 — this document.** Research only; no code claims.
- **M1 — read-only mount.** `src/mount/windows.rs` implements
  `MountPoint`/`MountHandleInner` over WinFsp; `mount()` works with
  `read_only=true`; directory listing, attribute reads, and file reads pass a
  manual smoke test on a real Windows host with WinFsp installed. Writes
  return `EROFS`-equivalent.
- **M2 — read-write mount.** Create/write/rename/delete/set_attr paths wired;
  delete-pending and cleanup semantics verified (§5.5); case-sensitivity
  decision implemented and documented (§5.1).
- **M3 — polish.** Packaging, docs (`Usage.md`, `Testing.md` Windows
  checklist), CI on `windows-latest`, license/notice file for WinFsp.

### Smoke test checklist (must run on Windows + WinFsp, not WSL)

- [ ] `rencfs --help` shows Windows mount path; `rencfs <mountpoint> <datadir>` mounts a drive letter or `\\?\Volume{GUID}` path.
- [ ] Create a file with Explorer, write >4 KiB (multi-block), close, reopen, contents identical.
- [ ] `dir` listing shows correct names/sizes; `type file.txt` reads decrypted content.
- [ ] Rename and delete work; delete-while-open behaves sanely (no hung handles).
- [ ] Unmount via `rencfs` exit / `net use`-equivalent; remount requires password again.
- [ ] Read-only mount rejects writes at both FS and data layer.
- [ ] Reboot persistence: mount does not auto-restore (document expected behavior).

## 8. Risks

1. **WinFsp Rust binding maturity** — if `winfsp`/`winfsp-sys` is unmaintained
   or lacks needed callbacks (e.g. `CopyFileRange`, directory-plus), the
   fallback is raw `winfsp-x64.dll` FFI or Dokany. Verify crate freshness
   before committing to M1.
2. **Callback threading** — a mistaken `Handle::block_on` on a runtime worker
   deadlocks the FS; the per-thread-runtime bridge in §4.1 avoids this.
3. **Case/Unicode divergence** — silent NTFS-semantics mismatch is the most
   likely "works in demo, breaks in apps" failure; decide §5.1 explicitly.
4. **Licensing** — shipping WinFsp binaries without LGPL compliance would
   contaminate the `MIT OR Apache-2.0` promise; Option A (user-installed
   runtime) is the safe default.
5. **Scope creep** — ProjFS/cloud-files features, NTFS ADS, EFS
   interactions are explicitly out of scope for M1–M3.

## 9. References to verify at implementation time

- WinFsp: https://winfsp.dev — callback API (`FileSystem` trait surface),
  `Volume` flags, security-descriptor callbacks, current license text.
- Rust bindings: crates.io `winfsp`, `winfsp-sys` — check last release date,
  MSRV vs `rust-toolchain.toml`, feature coverage vs the callback list above.
- Dokany (fallback): https://dokan-dev.github.io — license and binding state.
- Microsoft Docs: "Projected File System (ProjFS)", "Cloud Filter API",
  `FILETIME`, `CreateFile` disposition flags — for §5 mapping details.
