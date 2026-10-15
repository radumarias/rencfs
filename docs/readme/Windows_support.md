# Windows support

> Status: **research note only**. Nothing here works yet: rencfs mounts only on Linux (fuse3) today, and every other
> platform falls back to the `dummy` mount that returns "not supported". This document is the researched plan for a
> first Windows implementation, so that the future implementation PR can be judged against criteria that were written
> before any code existed.

Related to [rencfs issue #3](https://github.com/radumarias/rencfs/issues/3).

## Current architecture (Linux today)

- [`src/mount.rs`](../src/mount.rs) defines the OS-independent `MountPoint` trait: every backend has to implement
  `new(mountpoint, data_dir, password_provider, cipher, allow_root, allow_other, read_only)` and `mount()`, returning a
  `MountHandle`.
- [`src/mount/linux.rs`](../src/mount/linux.rs) implements that trait on top of `fuse3` (async FUSE) and forwards each
  FUSE callback into the storage layer, `EncryptedFs` ([`src/encryptedfs.rs`](../src/encryptedfs.rs)).
- [`src/mount/dummy.rs`](../src/mount/dummy.rs) is the placeholder for all non-Linux targets; today Windows also compiles
  it.
- Everything below `MountPoint` is already portable: tokio, crypto, inode storage. Only the OS boundary is Linux-specific.

The Windows port therefore touches exactly one seam: add a backend module that speaks the Windows filesystem callback
API and translate those callbacks to the **same** `EncryptedFs` methods that `linux.rs` already calls.

## Backend choice

### Recommended: WinFsp

[WinFsp](https://winfsp.dev/) (Windows File System Proxy) is the de-facto userspace filesystem framework on Windows:

- same shape as FUSE: a driver in the kernel + a userspace library, filesystem logic lives in userspace
- documented, stable op vector (a fixed set of callbacks very close to FUSE's mental model)
- supports both the C API and .NET; usable from Rust via `winfsp-sys` / `winfsp` crates that wrap the C header
- mounting is a userspace action with the driver installed by an installer (no WDKM build, no test signing certificate)

### Alternatives considered (and why they are worse here)

| Option | Why not |
|---|---|
| **cbkdrive / dokany** | dokan is capable but the Rust bindings are thin and the callback shape drifts from FUSE; smaller community |
| **write a WDM/minifilter ourselves** | needs the WDK, test-signing dance, kernel-mode debugging for every bug: too heavy for this project |
| **iSCSI / target-based** | not a filesystem at the Windows layer: no Explorer integration, no per-file encryption semantics |
| **ProjFS** | needs a special provider model and is tied to virtualization scenarios; poor fit for a general encrypted disk |

## Licensing check (blocking, before any code)

rencfs is licensed `MIT OR Apache-2.0`. WinFsp is **BSD-3-Clause** (with an additional GPL option only relevant if we
wanted to build a driver of our own). Implications:

- BSD-3-Clause is compatible with both MIT and Apache-2.0, so the project does not need relicensing.
- The repository already carries [`LICENSE-BSD-3-Clause`](../LICENSE-BSD-3-Clause), which is what the attribution clause
  requires; the implementation PR must keep a pointer to it from the Windows backend module and mention WinFsp in the
  docs.
- WinFsp installer/DLL redistribution at install time is a packaging decision, not a build-time dependency; nothing
  BSD-3-clause ships inside our source tree.

Verdict: **no blocker**, but the PR must not vendor WinFsp sources without carrying the BSD-3 notice.

## Dependency and build shape

```toml
# Cargo.toml
[target.'cfg(windows)'.dependencies]
winfsp-sys = "0.x"          # raw bindings to the WinFsp C API
windows = "0.x"             # if/when needed for volume metadata
```

Guidance for the implementation:

- Windows-only crates stay behind `cfg(windows)`; Linux and the dummy fallback must keep building unchanged
- WinFsp can be **delay-loaded** (`/DELAYLOAD:winfsp-2.dll` + a `.def` import lib) so that a binary built on Windows
  still fails with a clear message instead of a loader dialog when WinFsp is not installed. This matters because our
  release builds are not per-OS artifacts yet
- `winfsp-sys` needs the WinFsp headers at build time only on the Windows target; no Fedora/Debian package step is
  affected

## Proposed `src/mount/windows.rs`

Mirror `linux.rs` one-to-one so the diff stays reviewable:

```text
src/mount/windows.rs
├── MountPointImpl                 // implements the existing MountPoint trait
├── WindowsFs                       // holds Arc<EncryptedFs> + per-mount state
└── op-dispatch fns                 // the WinFsp callback vector, one fn per callback
```

- construction: `MountPoint::new(...)` stores what it stores today and registers nothing with the system until
  `mount()` runs
- `mount()`: start the WinFsp file system host on the requested `mountpoint` path (drive letter or directory); resolve
  WinFsp DLL absence into a readable `FsError`
- thread model: WinFsp is callback-driven, but our callbacks have to run a tokio runtime (that is how `EncryptedFs`
  already works on Linux). Same shape as fuse3's: a dedicated runtime plus block-on/`Handle::enter()` around each
  callback, or a single-threaded executor for filesystem ops with `spawn_blocking` where needed
- `MountHandle`: Wrap the WinFsp host handle; `umount()` stops the host; `poll` reports the session done
- paths: WinFsp gives NT-ish path buffers; convert to the `OsString`/`String` forms `EncryptedFs` already expects,
  keeping the same normalization rules as the Linux backend (no case folding, no separator translation)

## Callback → `EncryptedFs` mapping

WinFsp's op vector (`FSP_FILE_SYSTEM_INTERFACE`) versus the methods our storage layer already exposes:

| WinFsp callback | rencfs call in `EncryptedFs` | Notes |
|---|---|---|
| `Open` / `Create` | `create`, `get_attr`, `set_attr` | same as FUSE lookup/create split |
| `Overwrite` / `Cleanup` | `release`, `flush` | cleanup fires on last close |
| `Close` | `release` | |
| `Read` | `read` | offset/length → chunked read, unchanged |
| `Write` | `write` | |
| `Flush` | `flush` | |
| `GetSecurity` | `get_attr` (+ canonical 0o777/0o600 mapping) | see metadata below |
| `SetSecurity` | `set_attr` | milestone 1: accept and ignore ACLs we cannot store |
| `QueryDirectory` | `read_dir`, `read_dir_plus` | the plus variants keep the dirent cache warm |
| `GetFileInfo` | `get_attr` | |
| `SetFileInfo` (`BasicInfo`, `AllocationInfo`, `EndOfFileInfo`) | `set_attr` | size changes ride `set_attr` like FUSE's `setattr` |
| `GetVolumeInfo` | new small helper (name, serial, size caps) | not a storage concern; serve from mount constants |
| `GetSecurityByName` | `find_by_name` + `get_attr` | FUSE's lookup equivalent |
| `SetDelete` / `Rename` as supported | `remove_file`, `remove_dir` | renames = create new entry + remove old, milestone 1 |
| unsupported/optional (`ReparsePoint*`, `GetDirInfoByName`, `Control`, `Transact*`) | — | milestone 1: return `STATUS_NOT_IMPLEMENTED` |

Everything not listed above is answered with `STATUS_NOT_IMPLEMENTED` / `STATUS_NOT_SUPPORTED` in milestone 1.

## Metadata decisions for milestone 1

- permissions: WinFsp's world has ACLs, POSIX has mode bits. Serve a fixed owner:full mapping (no ACL storage yet),
  document it, do not attempt to persist ACLs
- timestamps: our `FileAttr` already stores the usual timestamps; fill WinFsp's `FileTime` fields from them (FILETIME
  is 100ns ticks since 1601; convert at the boundary only)
- hard links, reparse points, NTFS alternate data streams, extended attributes: **explicitly out of scope** for the first
  milestone, returned as unsupported
- case sensitivity: mount is case-sensitive (matching the encrypted name model); `FILE_CASE_SENSITIVE_SEARCH` set once
  per volume
- sparse files: not in milestone 1; treat as regular writes

## CI and smoke test plan

CI (`.github/workflows/build_and_tests_reusable.yaml`), Windows runner only:

1. install WinFsp from the official installer (silent install), pin the version, add it to the job's setup cache
2. `cargo build --target x86_64-pc-windows-msvc` (toolchain already pinned in `rust-toolchain.toml`)
3. `cargo test --target x86_64-pc-windows-msvc` (unit tests; no mounting in tests)
4. clippy/fmt gates identical to the Linux job

Manual smoke test (cannot run in CI because mounting needs an interactive session):

1. install WinFsp on a Windows host
2. `rencfs mount X: C:\tmp\rencfs-data` on a scratch data dir
3. create a file, write, read back, unmount, remount, verify content
4. verify the failure path: same commands with WinFsp uninstalled produce the documented error message, not a loader
   crash

## Acceptance criteria for the first implementation PR

A PR claiming Windows support counts as done when **all** of these are true, and no earlier:

1. `src/mount/windows.rs` implements `MountPoint` on WinFsp and is the only `cfg(windows)` mount backend; the dummy
   fallback is gone for Windows
2. create/write/read/unmount/remount round-trip works for a file and a directory via WinFsp on a real Windows host
3. unchanged behavior on Linux: no diff in `linux.rs`, all existing tests and CI stay green
4. license attribution present: WinFsp/BSD-3 reference kept in the module and docs; no vendored WinFsp sources
5. the "WinFsp not installed" path returns the documented error (delay-load trick above verified by hand)
6. docs updated: this note moves from *research* to *supported/unsupported tables* that match reality, e.g. an entry in
   `docs/readme/Stack.md` and `docs/readme/Usage.md` describing Windows prerequisites
