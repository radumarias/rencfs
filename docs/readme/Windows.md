# Windows support research (verified against main)

Native Windows mounting is not implemented yet. This note records an
implementation path that was checked line by line against the actual code on
`main` (`11d87caa345f`, 2024-12-21, rencfs 0.13.78), so that an implementation
PR can start from method names, file paths, and Cargo features that really
exist. It intentionally does **not** claim that rencfs mounts on Windows
today, and it does not claim any Windows runtime validation: there was no
Windows host and no WinFsp install available while writing it. Section 14
lists exactly what was and was not validated.

## 0. What exists today (verified)

- `src/mount.rs` (lines 12-23) selects the backend by target OS:
  `#[cfg(target_os = "linux")] mod linux;`, everything else compiles
  `mod dummy;`. On Windows today, `MountPointImpl::mount()` in
  `src/mount/dummy.rs:49` returns `Err(FsError::Other("Dummy implementation"))`.
- The dummy is not the only gate. `src/main.rs:8-13` exits before any mount
  code runs on Windows and macOS: it prints "he he, not yet ready for this
  platform, but soon my friend, soon :)" and returns `Ok(())`. And `mod run`
  in `main.rs` is `#[cfg(target_os = "linux")]` only. A Windows
  implementation must change `main.rs` and enable `run.rs` for Windows, not
  just add a mount module.
- `Cargo.toml` has **no `[features]` section at all**. The only
  platform-gated dependency is
  `[target.'cfg(target_os = "linux")'.dependencies] fuse3 = "0.8.1"`.
  There are no Windows dependencies today. License is `MIT OR Apache-2.0`.
- `rust-toolchain.toml` pins the nightly toolchain, so the smoke test below
  uses nightly, matching the repo.
- CI (`.github/workflows/build_and_tests_reusable.yaml`) builds on
  `ubuntu-latest`, `macos-latest`, and `windows-latest` with the nightly
  toolchain, but `cargo test` and `cargo bench` are skipped on
  `windows-latest` (`if: matrix.os != 'windows-latest'`). A Windows
  implementation must keep `cargo build --all-targets --all-features`
  green on `windows-latest`; tests there are a separate decision (section 11).

## 1. Corrections to PR #3

PR #3 ("docs: add Windows support implementation research", open since
2026-05-12) is a serious research note and several of its sections are kept
below (licensing structure, FILETIME math, case policy, reserved names).
But its operation mapping names methods that do not exist in `EncryptedFs`,
and it misses two code gates. An implementation that followed it literally
would not compile. The corrections, each checked against `main`:

| PR #3 says | What the code actually has | File:line |
| --- | --- | --- |
| `EncryptedFs::lookup()` | No such method. Path lookup is `find_by_name(parent: u64, name: &SecretString) -> FsResult<Option<FileAttr>>` | `src/encryptedfs.rs:835` |
| `EncryptedFs::remove()` | No such method. There are two: `remove_dir(parent, name)` and `remove_file(parent, name)` | `src/encryptedfs.rs:886`, `:963` |
| `Overwrite` / `SetFileSize` -> `set_attr()` with `SetFileAttr::with_size(...)` | Wrong for shrinking. `set_attr()` merges through `merge_attr()` with `overwrite_size = false`, which does `attr.size = attr.size.max(size)`: it can only grow the recorded size, never shrink it. Truncation must call `set_len(ino, size)` | `src/encryptedfs.rs:1313`, `:1858`, `merge_attr` at `:2604` |
| `GetVolumeInfo` -> `EncryptedFs::get_volume_info()` | No such method, and no volume-info concept exists anywhere in `EncryptedFs`. Volume info is new work, or a stub (see section 8). | (absent; grep-verified) |
| `GetSecurity` / `SetSecurity` -> `set_security()` / `get_security()` | No such methods, and no security-descriptor storage exists. ACL round-tripping is new storage work, not a mapping. | (absent; grep-verified) |
| `GetFileInfo` -> `get_file_info()` | No such method. File info comes from `get_attr(ino)`, after resolving the path with `find_by_name`. | `src/encryptedfs.rs:1278` |
| `SetInformation` -> `set_information()` | No such method. Attribute changes go through `set_attr(ino, SetFileAttr)` with the clamping behavior in section 8. | `src/encryptedfs.rs:1313` |
| Mount module only | Also misses the `main.rs` early-exit gate and the Linux-only `mod run` gate (section 0). | `src/main.rs:8-13` |
| `winfsp` 0.12 line as the proposed version | Superseded. Latest is `0.13.2+winfsp-2.1` (2026-10-20); `winfsp-sys` latest is `0.12.1+winfsp-2.1` (2025-10-09). Both still `GPL-3.0` on crates.io (checked 2026-11-21). | crates.io API |

What PR #3 got right and is kept: the two-checkpoint licensing structure
(WinFsp driver/library vs. Rust bindings), the FILETIME epoch and formulas,
the case-sensitive volume policy, the reserved-name rules, the smoke-test
shape, and the "no separate Windows CLI surface" rule. Where this note
reuses those sections it says so; where it changes them it says why.

## 2. Findings in `main` discovered while verifying

Two defects were found in `main` during verification. They are not Windows
bugs, but the Windows adapter would trip over the first one, so the
implementation PR must account for it.

1. **`SetFileAttr::with_flags` writes to the wrong field**
   (`src/encryptedfs.rs:195-196`):
   ```rust
   pub const fn with_flags(mut self, flags: u32) -> Self {
       self.rdev = Some(flags); // BUG: should be self.flags
       self
   }
   ```
   Any caller using `with_flags` silently overwrites `rdev` instead of
   `flags`. The Windows metadata mapping (section 9) must not use
   `with_flags` until this is fixed, and the fix belongs in the
   implementation PR or a separate small PR first.
2. **The `passwd` subcommand can never run** (`src/run.rs:183` vs `:209`).
   The CLI defines the subcommand as `"passwd"`, but `async_main` matches
   `Some(("change-password", ...))`, so `rencfs passwd ...` falls through
   to the "Invalid subcommand" error. Unrelated to Windows; recorded here
   because it was found while verifying the CLI surface the Windows path
   would reuse.

## 3. Recommendation

Investigate [WinFsp](https://winfsp.dev/) as the preferred native Windows
mount backend, conditional on resolving both licensing checkpoints in
section 4. Reasons, checked against the current code and registry:

- WinFsp is the maintained Windows equivalent of FUSE: a user-mode
  filesystem host backed by a Windows kernel driver.
- The Rust [`winfsp`](https://crates.io/crates/winfsp) crate provides safe
  Rust bindings. Latest is `0.13.2+winfsp-2.1` (2026-10-20), `GPL-3.0`,
  edition 2024, with features `default = ["full", "handle-util"]`,
  `delayload`, `build`, `async-io`, `notify`, `system`, and
  `windows-56`/`windows-60`/`windows-61`/`windows-62`.
- WinFsp supports the drive-letter/directory-mount workflow Windows users
  expect, while rencfs keeps its existing encrypted storage layer: the
  storage/crypto core (`data`, `crypto`, `encryptedfs`) is already
  platform-independent, and only the mount/drive layer is
  platform-specific (`src/mount/linux.rs` vs `src/mount/dummy.rs` today).

Alternatives, kept from PR #3 with the same conclusion: Dokan is viable
but needs a different callback adapter and its own Rust-binding assessment
(this note has not measured the relative Rust ecosystems); ProjFS is a
projected directory with on-demand hydration, not a mounted filesystem,
and hydrated files introduce plaintext-at-rest concerns unlike the
encrypted backing-store contract; Cloud Files API is a sync-provider
design, not a drop-in volume adapter; WSL passthrough reuses the Linux
FUSE backend but is not a native Windows mount; WebDAV adds an HTTP
service and network-filesystem semantics. None of these is ruled out as
incapable; WinFsp is first because it is the closest structural match to
the existing `fuse3` backend.

## 4. Licensing checkpoint

There are two independent checkpoints, not one. Neither is cleared by this
note.

1. **WinFsp driver/library.** The
   [WinFsp license](https://github.com/winfsp/winfsp/blob/master/License.txt)
   is GPLv3 with a FLOSS exception; commercial terms are also available.
   Review the exact exception and distribution terms for the chosen WinFsp
   release.
2. **Rust bindings.** The `winfsp` crate and `winfsp-sys` are separate
   dependencies, and both report `license: "GPL-3.0"` on crates.io
   (`winfsp` 0.13.2+winfsp-2.1; `winfsp-sys` 0.12.1+winfsp-2.1; checked
   2026-11-21). The `winfsp` repository
   [`LICENSE.md`](https://github.com/SnowflakePowered/winfsp-rs/blob/0cdd86a6f1ecd38c89da6ccf3fe2fc3312e11d8f/LICENSE.md)
   contains the GPLv3 text without a WinFsp-style FLOSS linking exception.
   Missing registry metadata would not establish permission either; read
   the selected release's actual sources and license, including
   `winfsp-sys`.

Because rencfs is `MIT OR Apache-2.0`, the bindings' GPL terms remain an
**implementation blocker** for the proposed dependency shape until
maintainers choose a supported licensing/distribution approach or another
binding/backend. A commercial license or FLOSS exception for the WinFsp
library does not grant an exception for separately authored Rust bindings.
Do not add or ship the dependency on the assumption that attribution is
enough.

If the selected WinFsp FLOSS exception applies, user-facing docs and any UI
must also carry its required attribution (preserved here):

> WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos
> https://github.com/winfsp/winfsp

Requiring users and CI to install WinFsp separately avoids bundling that
driver; it does not settle the license of Rust binding code linked into
rencfs. Maintainers must resolve both checkpoints before
implementation/distribution.

## 5. Proposed dependency shape (conditional on licensing clearance)

The following is an API/build sketch, **not an approved dependency
addition**. If the licensing gate is resolved, add the bindings only for
Windows targets. Version updated from PR #3's 0.12 line to the current
0.13 line:

```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = { version = "0.13", default-features = false, features = ["delayload", "windows-61"] }

[target.'cfg(target_os = "windows")'.build-dependencies]
winfsp = { version = "0.13", default-features = false, features = ["build"] }
```

Add `build.rs` or a Windows-only build script path that emits WinFsp
delay-load link flags via `winfsp::build::winfsp_link_delayload()`. The
crate documentation states this is required for `winfsp-rs`.

Use the `system` feature only if the project wants to link against an
installed WinFsp library during build. For CI and contributor ergonomics,
delay-loading is usually friendlier because the executable can produce a
clear runtime error when WinFsp is missing instead of failing at link
time. Note `winfsp` 0.13 uses edition 2024; rencfs is edition 2021 on a
nightly toolchain, which accepts edition-2024 dependencies.

## 6. Module layout and the gates PR #3 missed

Keep the current platform split, extended:

```text
src/mount.rs
src/mount/linux.rs       # existing fuse3 backend
src/mount/windows.rs     # new WinFsp backend
src/mount/dummy.rs       # unsupported non-Linux/non-Windows targets
```

`src/mount.rs` should select backends like this:

```rust
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod dummy;
```

That alone is not enough. Three more gates must change before any Windows
mount can run:

1. **`src/main.rs:8-13`** — remove the Windows early exit, and change
   `#[cfg(target_os = "linux")] mod run;` so `run.rs` compiles on
   Windows. Until this changes, `rencfs mount` on Windows prints "not
   yet ready" and exits, no matter what `src/mount/windows.rs` contains.
2. **`src/mount.rs` `umount()`** — today it shells out to `umount`,
   `umount -f`, `umount -l`. Those commands do not exist on Windows.
   `run.rs` calls `mount::umount()` in three error paths (lines 66, 76,
   87), in the `--umount-on-start` path (line 317), and as a fallback in
   the Ctrl-C handler. The Windows implementation needs a `#[cfg]`
   branch: for a drive-letter mount, the equivalent cleanup is releasing
   the WinFsp host (the real unmount) and, if a drive letter was
   assigned, removing it; the Unix shell-out must not run on Windows.
3. **CLI reuse, no new surface.** Do not add a separate Windows CLI
   parser. The Linux path already goes through `run::run()`, Clap, and
   `create_mount_point()`. Reusing that path avoids option drift. The
   existing flags are already Windows-shaped: `mount --mount-point X:
   --data-dir .\data` uses `--mount-point`/`-m` and `--data-dir`/`-d`
   (`src/run.rs`), and the password comes from `RENCFS_PASSWORD` or an
   interactive prompt. `--allow-root`/`-s` and `--allow-other`/`-o` are
   FUSE concepts with no Windows meaning; document them as accepted but
   ignored on Windows, or gate them out of the Windows help text.
   `run.rs`'s direct dependencies (`ctrlc` 3.1.9, `rpassword` 7.3.1,
   `keyring` 2.3.2) are cross-platform crates; the Windows blockers in
   `run.rs` are the `umount` shell-outs, not the dependency set.

## 7. Runtime architecture

The Windows backend should be a thin adapter around `EncryptedFs`, shaped
like the existing `EncryptedFsFuse3` (`src/mount/linux.rs:131`):

1. `MountPointImpl::new(...)` stores mount options.
2. `MountPointImpl::mount()` creates `EncryptedFs::new(data_dir,
   password_provider, cipher, read_only).await` — the exact constructor
   signature (`src/encryptedfs.rs:582`) — and returns `Arc<EncryptedFs>`.
3. A `WindowsEncryptedFs` context owns `Arc<EncryptedFs>` plus one Tokio
   runtime handle. WinFsp callbacks are synchronous; every rencfs call is
   `async`. There must be exactly one controlled runtime boundary: the
   mount owns a single Tokio runtime (built once in `mount()`), and each
   callback enters it with `handle.block_on(...)`. PR #3's "one controlled
   runtime boundary" is kept; the concrete shape is specified here because
   the failure modes are specific: a runtime per callback leaks runtimes,
   and spawning a thread per `Future::poll` leaks threads and can hang.
4. `MountHandleInnerImpl` owns the WinFsp host/service handle and
   unmounts it in `unmount()` — the real unmount. `run.rs`'s
   `mount::umount()` shell-out fallback must not run on Windows
   (section 6).

Avoid these pitfalls:

- Do not create a Tokio runtime per filesystem callback.
- Do not spawn a thread on every `Future::poll`; that leaks threads and
  can hang.
- Do not return success for unimplemented callbacks. Return explicit
  Windows errors for unsupported operations.
- Do not parse a second ad-hoc Windows CLI; keep Clap as the single
  interface.
- Do not call `release()` twice for one handle. WinFsp calls `Cleanup`
  then `Close`; `EncryptedFs::release()` errors with
  `FsError::InvalidFileHandle` on an unknown handle
  (`src/encryptedfs.rs:1477`, and the `!valid_fh` arm at the end of
  `release`), and a write-handle release finishes the writer and syncs
  (`release` body). Call `release()` exactly once, on `Cleanup`, and
  treat `Close` as a context drop. A handle value of `0` means "no
  handle" in `EncryptedFs` (directories, or files created without being
  opened) and `release(0)` is a no-op `Ok(())`.

## 8. Operation mapping (verified against `EncryptedFs`)

The first useful milestone supports regular files and directories only.
That matches the current `FileType` enum (`src/encryptedfs.rs:98`),
which has exactly two variants — `Directory` and `RegularFile`. Symlink,
pipe, device, and socket variants are commented out in the source. Any
WinFsp feature that needs another type is new `EncryptedFs` work, not a
mapping.

Path resolution comes first: WinFsp addresses entries by path, rencfs by
inode (`u64`). Every path-based callback must resolve
`(parent_ino, name)` with `find_by_name(parent, name)` (returns
`Option<FileAttr>`, errors `InodeNotFound` if the parent is missing and
`InvalidInodeType` if the parent is not a directory), then call
`get_attr(ino)` for metadata. The root inode is `ROOT_INODE = 1`
(`src/encryptedfs.rs:48`). PR #3's mapping skipped this step; it is
required for every entry below.

| WinFsp operation | `EncryptedFs` call (verified) | Status |
| --- | --- | --- |
| `GetVolumeInfo` | None exists. No volume-info method or concept in `EncryptedFs`. | New work, or stub parity: the Linux `statfs` is itself a stub (`src/mount/linux.rs:983-986`, logs "implementation is a stub" and returns a constant). A Windows stub returning fixed volume values is honest parity, not a regression. |
| `GetSecurityByName` / `GetFileInfo` | `find_by_name(parent, name)` then `get_attr(ino)` | Exists. Note `get_attr` merges open-handle state (in-progress write size and times) into the returned `FileAttr`, so a file being written reports its current size. |
| `Open` | `open(ino, read, write) -> FsResult<u64>` (handle) | Exists. Errors if both flags are false, and if `write` is set on a read-only mount. Handles start at 1; the adapter keeps the `u64` handle as the WinFsp file context. |
| `Create` | `create(parent, name, CreateFileAttr, read, write) -> FsResult<(u64, FileAttr)>` | Exists. Returns the opened handle and the attr together. For directories the handle is `0` (no handle is created for directories; see `create` body). `CreateFileAttr` needs `kind`, `perm`, `uid`, `gid`, `rdev`, `flags` — on Windows `uid`/`gid` must be synthesized (section 9); there is no uid/gid in a WinFsp request, unlike the FUSE `Request` used by `linux.rs`. |
| `Overwrite` | `set_len(ino, 0)` then open for write, or `open` + `set_len` | Exists. Truncation is `set_len`, not `set_attr` (section 1). |
| `SetFileSize` | `set_len(ino, size)` | Exists. This corrects PR #3. |
| `Read` | `read(ino, offset, buf, handle) -> FsResult<usize>` | Exists. Requires a valid read handle; errors `InvalidFileHandle` otherwise. |
| `Write` | `write(ino, offset, buf, handle) -> FsResult<usize>` | Exists. Requires a valid write handle. Data is finalized on `release()` (writer finish + `sync_all`), not on `write()`. |
| `SetBasicInfo` (times/attrs) | `set_attr(ino, SetFileAttr)` | Exists, with clamping: `merge_attr` takes the **max** of old and new for `size`, `atime`, `mtime`, `ctime`, `crtime` (`src/encryptedfs.rs:2604`). Setting an *older* mtime (e.g. restoring a file's original timestamp) silently keeps the newer time. The adapter must document this and, if exact timestamps matter, fix `merge_attr` first. Also: do not use `SetFileAttr::with_flags` until the section-2 bug is fixed. |
| `ReadDirectory` | `read_dir(ino)` / `read_dir_plus(ino)` | Exists, but the iterators are synchronous, `VecDeque`-backed, and have **no pattern filter and no resume index**. WinFsp passes a file-name pattern (e.g. `*.txt`) and calls repeatedly with a marker. The adapter must filter by pattern itself and hold enumeration state (drain the iterator into a `Vec` once, serve by index). `len(ino)` counts children excluding `.` and `..`. |
| `Rename` | `rename(parent, name, new_parent, new_name)` | Exists. |
| `Cleanup` | `release(handle)` exactly once | Exists (see section 7). This is where write data is flushed. |
| `Close` | Context drop only; do not call `release()` again | By design (section 7). |
| `Delete` / `RemoveDirectory` | `remove_file(parent, name)` / `remove_dir(parent, name)` | Exists. This corrects PR #3's invented `remove()`. |
| `Flush` | `flush(handle)` | Exists. |
| `GetSecurity` / `SetSecurity` | None exists; no security-descriptor storage | New `EncryptedFs` work. First milestone: return a fixed default security descriptor and document that ACL preservation is out of scope. Do not pretend to round-trip ACLs. |
| `ResolveReparsePoints` / `GetReparsePoint` / `SetReparsePoint` | Nothing to map to: no symlink/reparse type in `FileType` | Unsupported; return explicit errors. New storage work to support later. |
| `GetStreamInfo` (alternate data streams) | Nothing to map to | Unsupported; return explicit errors. Note `validate_filename` already rejects `:` inside a component only if the adapter passes it through — the Windows validator (section 10) must reject `:` first. |
| Hard links | No link creation API; `FileAttr.nlink` is only a stored field | Unsupported; return explicit errors. |
| Extended attributes | No xattr API at all | Unsupported; return explicit errors. |
| `CopyFileRange` | `copy_file_range(...)` exists in `EncryptedFs` (`src/encryptedfs.rs:1746`) and is used by the Linux `copy_file_range` op, but WinFsp has no equivalent operation | Not applicable to the adapter. |

Unsupported initially (all must return clear unsupported-operation errors,
never success placeholders): reparse points and symlinks; alternate data
streams; extended attributes; hard links; Windows ACL preservation beyond
a simple default descriptor; case-insensitive alias lookup or automatic
case folding.

### Case-sensitive volume policy

The encrypted store distinguishes `Foo` and `foo`. Preserve that
identity rather than merging entries or changing the on-disk name format.
Configure `FSP_FSCTL_VOLUME_PARAMS.CaseSensitiveSearch = TRUE`
(`VolumeParams::case_sensitive_search(true)` in the `winfsp` Rust host
API) and `CasePreservedNames = TRUE` before starting the host. Do not
advertise case-insensitive lookup, lowercase incoming names, or build a
case-folded index that silently aliases distinct encrypted entries.

This is a proposed adapter contract, not a claim of full Windows
compatibility. Some Windows clients do not request case-sensitive opens;
Explorer, installers, and applications that assume case-insensitive
paths need testing and may fail or be unable to distinguish both names.
Flag that limitation in the README instead of promising NTFS-like
case-insensitive behavior. Before accepting an adapter, test exact-case
lookup, create, enumerate, and rename of both `Foo` and `foo`, remount
persistence, and representative Win32 clients on an actual Windows host.

### Reserved and unrepresentable names

Apply a single component validator to create and rename destinations and
to lookups that reach the adapter. Follow the
[Windows naming rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).
This matters because `EncryptedFs::validate_filename`
(`src/encryptedfs.rs:660`) rejects only `/` and `\` — everything below
must be enforced by the adapter, not the storage layer:

- Reject `< > : " / \ | ? *`, NUL and control characters U+0001..U+001F.
  Separators delimit paths; they are never part of a filename component. A
  colon must not accidentally enable an unsupported alternate data stream.
- Reject the case-insensitive device names `CON`, `PRN`, `AUX`, `NUL`,
  `COM1`..`COM9`, `LPT1`..`LPT9`, including extensions such as `NUL.txt`
  and the documented superscript-digit device forms. Treat `.` and `..`
  as path syntax, never new entry names.
- Reject trailing dots or spaces; do not trim them into a different
  stored name.
- Preserve representable Unicode without lossy UTF-8/UTF-16 conversion.
  Document and reject any name the selected API/storage conversion cannot
  represent.

Return `STATUS_OBJECT_NAME_INVALID` for invalid names that reach
callbacks, not a misleading not-found response
(`STATUS_OBJECT_NAME_NOT_FOUND`). Valid but absent names still get the
appropriate not-found error. Win32 may normalize or reject paths before
invoking the filesystem; the adapter cannot promise that all client
requests will reach this validator.

Linux-created encrypted data can already contain incompatible names. The
first Windows implementation should preflight the decrypted namespace and
refuse the mount with an actionable incompatibility report if those names
cannot be exposed faithfully. Keep any decrypted-name diagnostic local,
opt-in, and outside routine logs. Do not silently rename, trim, delete,
hide, or rewrite backing entries. A lossless escaping/alias scheme would
be a separate on-disk/API design decision, not an implicit workaround in
lookup. Until then, rename incompatible entries through the Linux mount
before using that data on Windows.

Required future adapter tests: each forbidden-character class,
trailing-dot and trailing-space names, mixed-case device names with and
without extensions, create/rename/lookup error mapping, unchanged backing
entries after rejection, and an existing Linux-created incompatible
namespace. These are proposed tests, not evidence of current Windows
runtime support.

## 9. Windows metadata decisions

rencfs stores Unix-style uid/gid/permission bits in `FileAttr`
(`src/encryptedfs.rs:63`). Windows needs a small compatibility layer
rather than a lossy one-off conversion in each callback.

- **uid/gid synthesis (new in this note).** The Linux backend takes
  `uid`/`gid` from the FUSE request (`linux.rs` `create_nod`, and
  `mount_fuse` sets the mount uid/gid from `libc::getuid()`/
  `libc::getgid()` at `src/mount/linux.rs:1442`). WinFsp requests carry
  no uid/gid. The adapter must pick one documented policy: either a
  fixed pair (e.g. `0`/`0`, matching a single-user volume) or the
  current Windows user's SID mapped to a stable `u32`. Whichever is
  chosen, record it in the adapter docs and keep it stable across
  remounts, because `FileAttr.uid`/`gid` are persisted in the encrypted
  metadata.
- Treat directories as `FILE_ATTRIBUTE_DIRECTORY`.
- Treat files with no write bit as `FILE_ATTRIBUTE_READONLY`.
- Use `FileAttr::{atime, mtime, ctime, crtime}` for Win32 file times,
  with the `set_attr` clamping caveat in section 8.
- Set a default security descriptor for the mounted volume instead of
  trying to round-trip arbitrary ACLs. ACL preservation is not part of
  the first milestone (section 8).
- Do not use `SetFileAttr::with_flags` until the section-2 bug is fixed;
  it writes to `rdev`.

### FILETIME conversion contract

WinFsp file-info timestamps use Windows
[`FILETIME`](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times):
unsigned 64-bit **100-nanosecond** ticks since **1601-01-01 00:00:00 UTC**,
not nanoseconds or seconds since 1970. The epoch offset is exactly
`11644473600` seconds. Map `crtime` to creation, `atime` to last access,
`mtime` to last write, and `ctime` to metadata change time.

Centralize both directions in one checked conversion layer. With signed,
normalized Unix seconds and `0 <= unix_nanos < 1_000_000_000`:

```text
filetime_ticks = (unix_secs + 11644473600) * 10_000_000 + unix_nanos / 100
unix_secs      = filetime_ticks / 10_000_000 - 11644473600
unix_nanos     = (filetime_ticks % 10_000_000) * 100
```

Use a wide signed intermediate and checked arithmetic before narrowing.
Normalize pre-1970 `SystemTime` values correctly instead of unwrapping
`duration_since` or using an absolute duration. Reject dates before 1601
and overflow/unrepresentable values with an explicit invalid-parameter
error, not wrapping or clamping. The forward conversion truncates to
100 ns precision; a reverse/forward round-trip must preserve every
representable tick. Honor callback-specific timestamp setter sentinels
separately from ordinary timestamps.

Required future adapter tests (not implemented or claimed by this research
PR): 1601 epoch -> 0; Unix epoch -> 116444736000000000; a pre-1970 date;
leap day; subsecond values on both sides of a second boundary; a
representable modern-date round-trip; and underflow/overflow of both the
tick and rencfs time types. Prove that any precision loss is less than
100 ns, and separately test setter sentinels.

## 10. Build and CI plan

Verified CI state (section 0): the matrix already includes
`windows-latest` with the nightly toolchain; builds, fmt, check, clippy,
and docs run there; tests and benches are skipped there. For the Windows
implementation branch:

1. Keep `cargo build --all-targets --all-features` on `windows-latest`
   green. The Windows backend is a new `cfg(target_os = "windows")`
   module, so the existing Windows CI job is the first gate for it.
2. Add a Windows-only check that verifies the binary prints a useful
   error when WinFsp is not installed (delay-load path, section 5).
3. Decide explicitly whether to enable `cargo test` on
   `windows-latest` for the adapter's unit tests (FILETIME conversion,
   name validation, operation mapping). Today tests are skipped there;
   enabling them only for the adapter's platform-independent unit tests
   is a smaller step than enabling the whole suite.
4. Add a manual smoke-test job or checklist for a runner with WinFsp
   installed. GitHub-hosted Windows runners should not be assumed to
   have the WinFsp driver.

A local macOS/Linux cross-compile is not enough for this project because
native Windows dependencies such as `ring` and WinFsp linking need
MSVC/Windows SDK behavior. Use it only as an early syntax check, not as
release evidence.

## 11. Manual smoke test

On a Windows machine with Rust and WinFsp developer files installed.
Note the first step: the `main.rs` early-exit gate (section 0, section 6)
must be removed first, or the command below exits immediately with "not
yet ready".

```powershell
rustup default nightly
cargo build --release
mkdir data
$env:RENCFS_PASSWORD = "test-password"
cargo run --release -- mount --mount-point X: --data-dir .\data
```

Flags verified against `src/run.rs`: `mount --mount-point`/`-m` and
`--data-dir`/`-d` are required; `RENCFS_PASSWORD` is read from the
environment; the toolchain is nightly per `rust-toolchain.toml`.

In another PowerShell session:

```powershell
Set-Content X:\hello.txt "hello"
Get-Content X:\hello.txt
New-Item -ItemType Directory X:\dir
Set-Content X:\dir\nested.txt "nested"
Get-ChildItem X:\ -Recurse
Remove-Item X:\hello.txt
Remove-Item X:\dir\nested.txt
Remove-Item X:\dir
```

Then unmount (Ctrl-C in the mount session, which exercises the
`unmount()` path — verify the drive letter is released and no WinFsp
host is left running), mount again with the same password, and verify
that persisted files are readable and that `data` does not contain
plaintext filenames or contents. Also verify the failure mode: run the
binary on a machine without WinFsp installed and confirm a clear runtime
error, not a load failure.

## 12. Milestones

0. **Gates and licensing:** resolve both licensing checkpoints
   (section 4); remove the `main.rs` early exit; enable `run.rs` for
   Windows; add the Windows branch for `umount()` cleanup paths.
1. **Compile-only adapter:** add Windows cfg wiring, WinFsp dependency,
   build script, and a `windows.rs` that mounts only far enough to return
   a controlled "not implemented" error from each callback. CI must pass
   on `windows-latest`.
2. **Read-only filesystem:** implement path resolution, `GetFileInfo`,
   `Open`, `Read`, and directory listing against an existing encrypted
   data directory.
3. **Writable regular files:** implement `Create`, `Write`, `SetFileSize`
   via `set_len`, `Rename`, `Delete`, and `Cleanup`/`release()`.
4. **Windows semantics hardening:** file times (with the `set_attr`
   clamping caveat), read-only attribute, case behavior, reserved-name
   validation, error-code mapping, cleanup/close behavior, uid/gid
   synthesis, and explicit unsupported paths.
5. **Packaging:** installer notes, WinFsp attribution, and release
   validation.

## 13. PR acceptance criteria

A first implementation PR should be considered ready only when it can
truthfully check these boxes:

- Maintainers have resolved the WinFsp and Rust-binding licensing
  checkpoints; installing WinFsp separately is not treated as blanket
  clearance.
- The `main.rs` gate and `run.rs` Windows enablement are included; the
  binary no longer exits early on Windows.
- `umount()` cleanup paths do not shell out to Unix `umount` on Windows.
- FILETIME epoch/precision/bounds tests and case-sensitive-name
  round-trips pass.
- Invalid-name create/rename/lookup tests pass without mutating backing
  entries; incompatible Linux-created namespaces get the documented
  preflight failure.
- Truncation uses `set_len`, not `set_attr` with size; a shrink test
  proves it.
- `release()` is called exactly once per handle (on `Cleanup`); a
  double-release test proves `Close` does not error.
- The README explains case-sensitive Windows client limitations.
- The project builds on `windows-latest` with the Windows backend
  enabled.
- The PR does not add a separate Windows CLI surface unless justified.
- Unsupported operations return explicit errors, not success
  placeholders.
- The smoke test above has been run on a Windows host with WinFsp
  installed.
- The PR documents whether WinFsp was linked, delay-loaded, or required
  at runtime.
- The `with_flags` bug (section 2) is fixed or the PR does not use
  `with_flags`.
- AI assistance, if used, is disclosed in the PR body.

## 14. What was NOT validated

- No Windows host was available. No WinFsp driver or developer files
  were installed. Nothing in this note was compiled for a Windows
  target, and no Windows runtime behavior was observed.
- The `winfsp` crate's Rust API surface (trait method names, `VolumeParams`
  shape) was not compiled against; callback names here use the WinFsp C
  API operation names, which the Rust bindings mirror. Verify exact Rust
  method names against `winfsp` 0.13.2 docs when writing the adapter.
- `Dokany`, `ProjFS`, and the Cloud Files API were compared from their
  documented designs, not from built prototypes.
- The `passwd` subcommand mismatch (section 2) was found by reading
  `src/run.rs`; it was not executed.

What *was* validated, and how: every `EncryptedFs` method named in
section 8 was read in `src/encryptedfs.rs` on `main` (`11d87caa345f`)
with its signature checked; every non-existence claim (no `lookup`,
`remove`, `get_volume_info`, `set_security`, `get_security`,
`set_information`, `get_file_info`, `set_file_size`, no xattr/symlink
APIs) was checked by searching the file; `merge_attr`'s max-clamping was
read, not assumed; `release()`'s double-release error was read; the
`main.rs` gate, the `mod run` gate, the `umount` shell-outs, the CLI
flags, the CI matrix, and the `with_flags` bug were all read in the
files cited; `winfsp` 0.13.2+winfsp-2.1 and `winfsp-sys`
0.12.1+winfsp-2.1 license and features were read from the crates.io API
on 2026-11-21.

## Appendix: `EncryptedFs` method inventory used by this note

All from `src/encryptedfs.rs` on `main` (`11d87caa345f`). Signatures are
abbreviated; read the file for full generics and docs.

| Method | Line | Signature (abbreviated) |
| --- | --- | --- |
| `new` | 582 | `new(data_dir, password_provider, cipher, read_only) -> FsResult<Arc<Self>>` |
| `exists` | 643 | `exists(&self, ino: u64) -> bool` |
| `is_dir` / `is_file` | 647 / 651 | `is_dir(&self, ino: u64) -> bool` |
| `create` | 675 | `create(&self, parent, name, CreateFileAttr, read, write) -> FsResult<(u64, FileAttr)>` |
| `find_by_name` | 835 | `find_by_name(&self, parent, name) -> FsResult<Option<FileAttr>>` |
| `len` | 868 | `len(&self, ino: u64) -> FsResult<usize>` |
| `remove_dir` | 886 | `remove_dir(&self, parent, name) -> FsResult<()>` |
| `remove_file` | 963 | `remove_file(&self, parent, name) -> FsResult<()>` |
| `exists_by_name` | 1035 | `exists_by_name(&self, parent, name) -> FsResult<bool>` |
| `read_dir` | 1048 | `read_dir(&self, ino) -> FsResult<DirectoryEntryIterator>` |
| `read_dir_plus` | 1064 | `read_dir_plus(&self, ino) -> FsResult<DirectoryEntryPlusIterator>` |
| `get_attr` | 1278 | `get_attr(&self, ino) -> FsResult<FileAttr>` |
| `set_attr` | 1313 | `set_attr(&self, ino, SetFileAttr) -> FsResult<()>` |
| `read` | 1370 | `read(&self, ino, offset, buf, handle) -> FsResult<usize>` |
| `release` | 1477 | `release(&self, handle) -> FsResult<()>` |
| `is_read_handle` / `is_write_handle` | 1588 / 1593 | `is_read_handle(&self, fh) -> bool` |
| `write` | 1603 | `write(&self, ino, offset, buf, handle) -> FsResult<usize>` |
| `flush` | 1711 | `flush(&self, handle) -> FsResult<()>` |
| `copy_file_range` | 1746 | `copy_file_range(&self, ...) -> FsResult<...>` |
| `open` | 1791 | `open(&self, ino, read, write) -> FsResult<u64>` |
| `set_len` | 1858 | `set_len(&self, ino, size) -> FsResult<()>` |
| `rename` | 1992 | `rename(&self, parent, name, new_parent, new_name) -> FsResult<()>` |
| `passwd` | 2133 | `passwd(data_dir, password, new_password, cipher) -> FsResult<()>` |
| `validate_filename` | 660 | private; rejects only `/` and `\` |
| `merge_attr` | 2604 | private; max-clamps size and times when `overwrite_size` is false |
| `ROOT_INODE` | 48 | `pub(crate) const ROOT_INODE: u64 = 1` |

Related types: `FileAttr` (line 63, fields `ino, size, blocks, atime,
mtime, ctime, crtime, kind, perm, nlink, uid, gid, rdev, blksize,
flags`); `FileType` (line 98, only `Directory` and `RegularFile`);
`SetFileAttr` (line 116, all-`Option` fields); `CreateFileAttr` (line
202); `FsError` (line 245); `DirectoryEntry` / `DirectoryEntryPlus`
(lines 408, 424).
