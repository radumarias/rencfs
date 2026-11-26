# Windows support: implementation research

> Research note, not a claim that rencfs mounts on Windows today. This document scopes the work,
> records the licensing checkpoint, and proposes a concrete architecture so the change can be reviewed
> before any code lands.

## 1. Scope and non-goals

**Goal.** Let `rencfs` expose the same `EncryptedFs` layer as a real drive letter (`Z:`) or a directory
mount point on Windows, using a user-mode filesystem backend, with the same on-disk format that Linux
already writes.

**Non-goals (first iteration).**

- No change to the crypto or on-disk layout. A directory written by Linux must open on Windows and
  vice versa; that is the acceptance test.
- No kernel driver of our own.
- No attempt to reproduce NTFS-specific semantics (alternate data streams, reparse points, oplocks).
  Unsupported operations return `STATUS_NOT_SUPPORTED` explicitly; silence would be worse.

## 2. Backend selection

| Backend | Model | License | Verdict |
|---|---|---|---|
| **WinFsp** | user-mode FS service + kernel driver (`winfsp-x64.dll`, `winfsp.sys`) | GPLv3 **with FOSS Exception** | **Recommended** |
| Dokan | user-mode FS library + driver | LGPL (user library), driver separately distributed | Viable fallback; smaller community, semantics further from FUSE |
| Projected File System (ProjFS) | virtualization callbacks, files are *projected* on access | Windows SDK | Rejected: designed for read-mostly virtual trees, awkward for real create/write workloads |
| CBFS Connect | commercial | paid | Rejected on cost |
| WSL + existing Linux FUSE | runs the Linux build inside WSL | n/a | Rejected: that is not Windows support; the drive is not visible to native Win32 apps |

WinFsp is chosen because it is the closest analogue to libfuse: a callback interface with
per-file contexts, native path semantics, and it is the backend every mature Windows FUSE port uses.

## 3. Licensing checkpoint (blocking, needs maintainer sign-off)

`Cargo.toml` declares `license = "MIT OR Apache-2.0"`, and the repository ships `LICENSE-MIT`,
`LICENSE-Apache-2.0` and `LICENSE-BSD-3-Clause`.

- WinFsp itself is **GPLv3 with a FOSS Exception**. The exception exists precisely so that
  OSI-approved FOSS projects can use WinFsp without their own code becoming GPL. `MIT OR Apache-2.0`
  is OSI-approved, so the intended path is available.
- The exception has conditions (attribution/notice requirements and restrictions on relicensing the
  WinFsp binaries themselves). **This note does not give legal advice**; before merging, the
  maintainer should confirm the exact wording of the exception as shipped with the WinFsp version we
  target, and record the conclusion in this document.
- Practical consequence for packaging: we must **not** vendor WinFsp binaries into our release
  artifacts under our own license. We depend on it at runtime, detect it, and instruct the user to
  install it (or install it as a separate, clearly-labelled component).

Open question to resolve in review: does shipping a Windows build that *requires* a user-installed
WinFsp change how the project advertises its license? (Proposed answer: no, provided we do not
redistribute WinFsp and we keep the notice.)

## 4. Dependency and build shape

```
[target.'cfg(windows)'.dependencies]
winfsp = { version = "0.11", optional = true }   # binds winfsp-x64.dll
windows-sys = { version = "0.59", features = ["Win32_Foundation", "Win32_Storage_FileSystem"] }
```

- Gate everything behind `#[cfg(windows)]` plus a `windows-mount` cargo feature, so a plain
  `cargo build` on Linux is byte-identical to today.
- The DLL is resolved at load time by the bindings. To keep `rencfs.exe` startable on machines without
  WinFsp (so `--help` and the CLI still work), prefer **delay-load** of `winfsp-x64.dll`; if the
  bindings do not expose that, load the library explicitly on first mount and return a clear
  diagnostic (`STATUS_DRIVER_NOT_INSTALLED`) when it is missing.
- CI: add a `windows-latest` job that only runs `cargo check --target x86_64-pc-windows-msvc
  --features windows-mount` (no mounting in CI; mounting needs the driver and an interactive session).

## 5. Proposed module layout

`src/mount.rs` currently selects `linux` or `dummy` by `cfg`. Windows gets a third arm, mirroring the
Linux shape so the rest of the crate stays untouched:

```
src/mount.rs            // #[cfg(windows)] mod windows;  -> MountPointImpl / MountHandleInnerImpl
src/mount/windows.rs    // EncryptedFsWinFsp: the callback adapter + MountPoint/MountHandleInner impls
```

`EncryptedFsWinFsp` holds `Arc<EncryptedFs>` exactly like `EncryptedFsFuse3` does today, plus the
WinFsp file-system handle and a per-file context table.

### 5.1 Async bridging (the part most likely to bite)

WinFsp callbacks are **synchronous**; `EncryptedFs` is async. Options:

1. `Handle::block_on` on a **dedicated multi-thread runtime** owned by the mount (not the caller's
   runtime). Simple; each callback occupies one runtime worker.
2. `runtime.spawn(...)` + `block_on(oneshot::Receiver)` — keeps the callback thread free but adds a
   hop per operation.

Recommendation: option 1 for the first iteration, with the runtime kept in `MountHandleInnerImpl`
so it outlives the mount, and an explicit comment that calling `block_on` from inside a runtime
worker **must not** happen (it panics/deadlocks). If profiling shows throughput problems, switch the
hot paths (`Read`/`Write`) to option 2.

## 6. Operation mapping

WinFsp `FSP_FILE_SYSTEM_INTERFACE` callbacks versus the existing FUSE3 handlers in
`src/mount/linux.rs`. Only rows where semantics differ are called out.

| FUSE3 handler (linux.rs) | WinFsp callback | Notes |
|---|---|---|
| `init` | `FspFileSystemCreate` + `SetVolumeParams` | set sector size, `SectorSize=512`, max component length 255 |
| (mount) | — | mount point is a drive letter or an empty directory; there is no `umount(8)`, use `FspFileSystemRemoveMountPoint` |
| `lookup` | `GetSecurityByName` (probe) / `Create` (open-or-create) | WinFsp splits "does it exist" from "open it" |
| `getattr` | `GetFileInfo` | `FileAttr` → `FSP_FSCTL_FILE_INFO`; `AllocationSize` must be sector-aligned (`FileSize` need not be) |
| `setattr` | `SetBasicInfo` / `SetFileSize` / `SetFileAttributes` | three separate callbacks; map fields individually, reject attribute bits we do not model |
| `open` / `create` | `Create` (+ `Overwrite`) | must honour `FILE_OVERWRITE_IF` vs `FILE_CREATE` vs `FILE_OPEN` |
| `read` / `write` | `Read` / `Write` | offsets are `u64`; short reads at EOF must be reported, not padded |
| `release` | `Cleanup` then `Close` | **Cleanup may be called with `FspCleanupDelete`** — that is where deletion is performed; `Close` only drops the context |
| `unlink` / `rmdir` | `Cleanup` with delete flag | no separate unlink; check empty-directory rule for dirs |
| `rename` | `Rename` | WinFsp may pass `ReplaceIfExists`; also a `RenameInformation` with no target = move; return `STATUS_OBJECT_NAME_COLLISION` when refusing to replace |
| `readdir` / `readdirplus` | `ReadDirectory` | must emit `.`/`..`-free list and use `FspFileSystemAddDirInfo`; set `NextOffset` for resumption |
| `statfs` | `GetVolumeInfo` | total/free bytes: rencfs has no quota, report volume free space of the backing disk |
| `access` | `GetSecurity` / `SetSecurity` | return a default security descriptor (owner = caller) or `STATUS_NOT_IMPLEMENTED` if `--allow-other` semantics are requested |
| `flush` | `Flush` | close of the encrypted write buffer |
| `copy_file_range` | — | not exposed by WinFsp; fine to omit |

### 6.1 Path handling

WinFsp hands us `\dir\file` with a leading backslash. Required normalisation before touching
`EncryptedFs`:

- map `\` → `/`, strip the leading separator;
- reject Win32-reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`, with or without
  extension);
- reject trailing spaces/dots in components, and the characters `< > : " | ? *`;
- enforce the 255-UTF-16-unit component limit and reject names that would normalise to nothing.

These checks belong in a small pure function with unit tests, independent of WinFsp, so they can be
tested on Linux CI too.

### 6.2 Metadata decisions

| Field | Decision |
|---|---|
| `FileAttributes` | directories `FILE_ATTRIBUTE_DIRECTORY`; hidden/system bits never set by us |
| `FileSize` / `AllocationSize` | plaintext length; allocation rounded up to 4096 |
| timestamps | creation time = first write, last-write = mtime, last-access = mtime (no atime tracking) |
| `IndexNumber` | reuse the FUSE inode counter — stable per open |
| `ReparseTag` | always 0 (no reparse points) |
| `HardLinkCount` | 1 |
| `EaSize` | 0 (extended attributes unsupported; `GetEa`/`SetEa` return `STATUS_NOT_SUPPORTED`) |
| security descriptor | fixed default; `SetSecurity` accepted and ignored, documented as such |

### 6.3 Explicitly unsupported NTFS features

Alternate data streams, reparse points/symlinks/junctions, oplocks and byte-range locks, sparse
files, compression, quotas, USN journal, extended attributes, case-insensitive lookup.
Each returns a specific NTFS status (`STATUS_NOT_SUPPORTED` / `STATUS_NOT_IMPLEMENTED`) and is listed
in the user documentation rather than silently mis-behaving.

Case sensitivity deserves its own note: `EncryptedFs` is case-sensitive, NTFS is not by default.
Proposal: keep rencfs case-sensitive and document it, because silently folding case would break the
on-disk format contract with Linux. Revisit if user feedback demands otherwise.

## 7. Testing plan

1. **Cross-platform round-trip** (the acceptance test): create a directory tree with Linux build →
   mount it with the Windows build → verify file contents, names (including Unicode and long paths),
   sizes, and that a file written on Windows reads back identically on Linux.
2. **Path normalisation unit tests** run on all platforms (pure functions, no WinFsp needed).
3. **Callback-level tests** with a fake file-system interface: assert that `Cleanup` with delete is what
   actually removes a file, that `Read` at EOF reports a short read, and that `Rename` refuses to
   replace when asked to.
4. **Manual smoke script** (`scripts/winfsp-smoke.ps1`): mount, run `dir`, copy a 100 MB file, unmount,
   remount, compare hashes.
5. CI: `cargo check --features windows-mount` on `windows-latest`; the smoke script stays manual.

## 8. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| FOSS Exception wording differs from expectation | blocks the whole approach | resolve in review before writing code; fallback is Dokan |
| `block_on` inside a runtime worker deadlocks | hangs the mount | dedicated runtime + a guard that panics loudly in debug |
| WinFsp expects NTFS-ish error codes; FUSE errno mapping is not 1:1 | apps see wrong errors | central `io::Error -> NTSTATUS` mapping table with tests |
| Large sequential writes perform poorly through the callback boundary | unusable for big files | measure early with the smoke script; consider `Read`/`Write` offload |
| Users install mismatched WinFsp version | cryptic load failure | detect version at mount, print actionable message |

## 9. Phased plan

1. **P0** — this document + maintainer sign-off on licensing and on "case-sensitive, no ADS" decisions.
2. **P1** — `src/mount/windows.rs` skeleton behind a feature flag: `Create`/`GetFileInfo`/`ReadDirectory`
   only, read-only mount of an existing directory.
3. **P2** — write path: `Write`/`SetFileSize`/`Cleanup(delete)`/`Rename`, plus the path-normalisation
   test suite.
4. **P3** — `GetVolumeInfo`, error mapping table, smoke script, docs.
5. **P4** — optional: security descriptor support, performance work.

Each phase is independently mergeable and independently reviewable; nothing in P1–P4 changes the
Linux behaviour.
