# Windows support research

Native Windows mounting is not implemented yet. The current code keeps Windows
buildable through `src/mount/dummy.rs`; the CLI exits early from `main.rs` with
a "not yet ready" message.

This note records an implementation path that can be reviewed before code is
added. It intentionally does **not** claim that rencfs mounts on Windows today.

## Recommendation

Investigate [WinFsp](https://winfsp.dev/) as the preferred native Windows mount
backend, conditional on resolving both licensing checkpoints below.

Reasons:

- WinFsp is the maintained Windows equivalent of FUSE: it exposes a user-mode
  filesystem host backed by a Windows kernel driver.
- The Rust [`winfsp`](https://crates.io/crates/winfsp) crate provides safe Rust
  bindings and examples through `winfsp-rs`.
- WinFsp supports the drive-letter/directory-mount workflow expected by Windows
  users, while letting rencfs keep its existing encrypted storage layer.

WinFsp is the preferred native backend **only if the licensing gates below can
be resolved**. Alternatives remain viable and should be compared by their real
constraints rather than ruled out as incapable:

| Route | Why it is not the first choice here | Licensing / decision checkpoint |
| --- | --- | --- |
| [WinFsp](https://winfsp.dev/) | Familiar FUSE-like host with Rust bindings and drive/directory mounts. | Driver/library GPLv3 + FLOSS exception or commercial terms; Rust bindings require a separate review. |
| [Dokany](https://github.com/dokan-dev/dokany#license) | Viable native driver-backed filesystem; requires a different callback adapter and separate Rust-binding assessment. This note has not measured the relative Rust ecosystems. | User-mode library LGPL with a static-linking exception; driver MIT. Verify the selected Rust wrapper separately. |
| [ProjFS](https://learn.microsoft.com/en-us/windows/win32/projfs/projected-file-system) | A projected directory with on-demand hydration and local full-file state, rather than the same custom mounted-filesystem interface. It is **not inherently read-only**: local creates, renames and writes exist. | Built-in optional Windows component, no custom driver; assess notifications and local-state ownership. Hydrated/full files introduce plaintext-at-rest concerns unlike the encrypted backing-store contract. |
| [Cloud Files API](https://learn.microsoft.com/en-us/windows/win32/cfapi/build-a-cloud-file-sync-engine) | Designed around sync roots, placeholders and a sync provider, not a drop-in encrypted-volume adapter. Hydration/local caching needs a separate plaintext-at-rest design. | Windows API and sync-provider integration requirements; no assumption that this gives WinFsp-like callback semantics. |
| WSL passthrough | Can reuse the Linux FUSE backend but adds a Linux environment and cross-boundary file access; not a native Windows mount. | Linux backend/deployment requirements still apply. |
| WebDAV | Adds an HTTP service and client/network-filesystem semantics rather than preserving local filesystem behavior. | Server/client dependencies and security surface require their own review. |

## Licensing checkpoint

There are two independent checkpoints, not one:

1. **WinFsp driver/library.** The [WinFsp license](https://github.com/winfsp/winfsp/blob/master/License.txt)
   is GPLv3 with a FLOSS exception; commercial terms are also available. Review
   the exact exception and distribution terms for the chosen WinFsp release.
2. **Rust bindings.** The `winfsp` crate is a separate dependency. As checked on
   2026-10-27, crates.io reports `license: "GPL-3.0"` for both
   [`0.12.6+winfsp-2.1`](https://crates.io/api/v1/crates/winfsp/0.12.6%2Bwinfsp-2.1)
   (the proposed 0.12 line) and
   [`0.13.2+winfsp-2.1`](https://crates.io/api/v1/crates/winfsp/0.13.2%2Bwinfsp-2.1).
   The repository's
   [`LICENSE.md`](https://github.com/SnowflakePowered/winfsp-rs/blob/0cdd86a6f1ecd38c89da6ccf3fe2fc3312e11d8f/LICENSE.md)
   contains the GPLv3 text, without a WinFsp-style FLOSS linking exception.
   Missing registry metadata would not establish permission either; read the
   selected release's actual sources and license, including `winfsp-sys`.

Because rencfs is `MIT OR Apache-2.0`, the binding's GPL terms remain an
**implementation blocker** for the proposed dependency shape until maintainers
choose a supported licensing/distribution approach or another binding/backend.
This is not a claim that the combination is impossible; it is not cleared by
this research note. A commercial license or FLOSS exception for the WinFsp
library does not grant an exception for separately authored Rust bindings.
Do not add or ship the dependency on the assumption that attribution is enough.

If the selected WinFsp FLOSS exception applies, user-facing docs and any UI must
also carry its required attribution (preserved here):

> WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos
> https://github.com/winfsp/winfsp

Requiring users and CI to install WinFsp separately avoids bundling that driver;
it does not settle the license of Rust binding code linked into rencfs.
Maintainers must resolve both checkpoints before implementation/distribution.

## Proposed dependency shape (conditional on licensing clearance)

The following is an API/build sketch, **not an approved dependency addition**.
If the licensing gate is resolved for these bindings, add them only for Windows
targets:

```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = { version = "0.12", default-features = false, features = ["delayload", "windows-61"] }

[target.'cfg(target_os = "windows")'.build-dependencies]
winfsp = { version = "0.12", default-features = false, features = ["build"] }
```

Add `build.rs` or a Windows-only build script path that emits WinFsp delay-load
link flags via `winfsp::build::winfsp_link_delayload()`. The crate documentation
states this is required for `winfsp-rs`.

Use the `system` feature only if the project wants to link against an installed
WinFsp library during build. For CI and contributor ergonomics, delay-loading is
usually friendlier because the executable can produce a clear runtime error when
WinFsp is missing instead of failing at link time.

## Module layout

Keep the current platform split:

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

Do not add a separate Windows CLI parser unless the command line is genuinely
different. The Linux path already goes through `run::run()`, Clap, and
`create_mount_point()`. Reusing that path avoids option drift.

## Runtime architecture

The Windows backend should be a thin adapter around `EncryptedFs`, similar to
`EncryptedFsFuse3`:

1. `MountPointImpl::new(...)` stores mount options.
2. `MountPointImpl::mount()` creates `EncryptedFs::new(...)` with the supplied
   password provider, cipher, and read-only flag.
3. A `WindowsEncryptedFs` context owns `Arc<EncryptedFs>` plus a Tokio runtime or
   runtime handle.
4. WinFsp callbacks synchronously bridge into rencfs async methods with one
   controlled runtime boundary.
5. `MountHandleInnerImpl` owns the WinFsp host/service handle and unmounts it in
   `unmount()`.

Avoid these pitfalls:

- Do not create a Tokio runtime per filesystem callback.
- Do not spawn a thread on every `Future::poll`; that leaks threads and can hang.
- Do not return success for unimplemented callbacks. Return explicit Windows
  errors for unsupported operations.
- Do not parse a second ad-hoc Windows CLI; keep Clap as the single interface.

## Operation mapping

The first useful milestone should support regular files and directories only.
That matches the current `FileType` enum and avoids pretending to support NTFS
features rencfs does not model yet.

- WinFsp `GetSecurityByName` / `GetFileInfo` -> `EncryptedFs::lookup()` and
  `EncryptedFs::get_attr()`.
- WinFsp `Open` -> `EncryptedFs::open()` with read/write flags derived from
  requested access.
- WinFsp `Create` -> `EncryptedFs::create()` using `CreateFileAttr`.
- WinFsp `Read` -> `EncryptedFs::read()`.
- WinFsp `Write` -> `EncryptedFs::write()`.
- WinFsp `Overwrite` / `SetFileSize` -> `EncryptedFs::set_attr()` with
  `SetFileAttr::with_size(...)`.
- WinFsp `ReadDirectory` -> `EncryptedFs::read_dir_plus()` or `read_dir()`.
- WinFsp `Rename` -> `EncryptedFs::rename()`.
- WinFsp `Cleanup` / `Close` -> `EncryptedFs::release()`.
- WinFsp `Unlink` / `RemoveDirectory` -> `EncryptedFs::remove()`.

Unsupported initially:

- reparse points and symlinks;
- alternate data streams;
- extended attributes;
- hard links;
- Windows ACL preservation beyond a simple default descriptor;
- case-insensitive alias lookup or automatic case folding.

These should return clear unsupported-operation errors until the storage layer
has matching semantics.

### Case-sensitive volume policy

The encrypted store distinguishes `Foo` and `foo`. Preserve that identity rather
than merging entries or changing the on-disk name format. Configure
`FSP_FSCTL_VOLUME_PARAMS.CaseSensitiveSearch = TRUE`
(`VolumeParams::case_sensitive_search(true)` in the proposed Rust host API) and
`CasePreservedNames = TRUE` before starting the host. See the
[WinFsp volume-parameter definition](https://github.com/winfsp/winfsp/blob/master/inc/winfsp/fsctl.h)
and the [Rust volume parameters](https://docs.rs/winfsp/0.12.6+winfsp-2.1/winfsp/host/struct.VolumeParams.html).
Do not advertise case-insensitive lookup, lowercase incoming names, or build a
case-folded index that silently aliases distinct encrypted entries.

This is a proposed adapter contract, not a claim of full Windows compatibility.
Some Windows clients do not request case-sensitive opens; Explorer, installers
and applications that assume case-insensitive paths need testing and may fail or
be unable to distinguish both names. Flag that limitation in the README instead
of promising NTFS-like case-insensitive behavior. Before accepting an adapter,
test exact-case lookup, create, enumerate and rename of both `Foo` and `foo`,
remount persistence, and representative Win32 clients on an actual Windows host.

### Reserved and unrepresentable names

Apply a single component validator to create and rename destinations and to
lookups that reach the adapter. Follow the
[Windows naming rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file):

- Reject `< > : " / \\ | ? *`, NUL and control characters U+0001..U+001F.
  Separators delimit paths; they are never part of a filename component. A colon
  must not accidentally enable an unsupported alternate data stream.
- Reject the case-insensitive device names `CON`, `PRN`, `AUX`, `NUL`,
  `COM1`..`COM9`, `LPT1`..`LPT9`, including extensions such as `NUL.txt` and
  the documented superscript-digit device forms. Treat `.` and `..` as path
  syntax, never new entry names.
- Reject trailing dots or spaces; do not trim them into a different stored name.
- Preserve representable Unicode without lossy UTF-8/UTF-16 conversion. Document
  and reject any name the selected API/storage conversion cannot represent.

Return `STATUS_OBJECT_NAME_INVALID` for invalid names that reach callbacks,
not a misleading not-found response (`STATUS_OBJECT_NAME_NOT_FOUND`). Valid but
absent names still get the appropriate not-found error. Win32 may normalize or
reject paths before invoking the filesystem; the adapter cannot promise that
all client requests will reach this validator.

Linux-created encrypted data can already contain incompatible names. The first
Windows implementation should preflight the decrypted namespace and refuse the
mount with an actionable incompatibility report if those names cannot be exposed
faithfully. Keep any decrypted-name diagnostic local, opt-in and outside routine
logs. Do not silently rename, trim, delete, hide or rewrite backing entries.
A lossless escaping/alias scheme would be a separate on-disk/API design decision,
not an implicit workaround in lookup. Until then, rename incompatible entries
through the Linux mount before using that data on Windows.

Required future adapter tests: each forbidden-character class, trailing-dot and
trailing-space names, mixed-case device names with and without extensions,
create/rename/lookup error mapping, unchanged backing entries after rejection,
and an existing Linux-created incompatible namespace. These are proposed tests,
not evidence of current Windows runtime support.

## Windows metadata decisions

rencfs stores Unix-style uid/gid/permission bits in `FileAttr`. Windows needs a
small compatibility layer rather than a lossy one-off conversion in each
callback.

Recommended first pass:

- Treat directories as `FILE_ATTRIBUTE_DIRECTORY`.
- Treat files with no write bit as `FILE_ATTRIBUTE_READONLY`.
- Use `FileAttr::{atime,mtime,ctime,crtime}` for Win32 file times.
- Set a default security descriptor for the mounted volume instead of trying to
  round-trip arbitrary ACLs.
- Document that ACL preservation is not part of the first milestone.

### FILETIME conversion contract

WinFsp file-info timestamps use Windows
[`FILETIME`](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times):
unsigned 64-bit **100-nanosecond** ticks since **1601-01-01 00:00:00 UTC**,
not nanoseconds or seconds since 1970. The epoch offset is exactly
`11644473600` seconds. Map `crtime` to creation, `atime` to last access, `mtime`
to last write, and `ctime` to metadata change time.

Centralize both directions in one checked conversion layer. With signed,
normalized Unix seconds and `0 <= unix_nanos < 1_000_000_000`:

```text
filetime_ticks = (unix_secs + 11644473600) * 10_000_000 + unix_nanos / 100
unix_secs      = filetime_ticks / 10_000_000 - 11644473600
unix_nanos     = (filetime_ticks % 10_000_000) * 100
```

Use a wide signed intermediate and checked arithmetic before narrowing. Normalize
pre-1970 `SystemTime` values correctly instead of unwrapping `duration_since` or
using an absolute duration. Reject dates before 1601 and overflow/unrepresentable
values with an explicit invalid-parameter error, not wrapping or clamping. The
forward conversion truncates to 100 ns precision; a reverse/forward round-trip
must preserve every representable tick. Honor callback-specific timestamp setter
sentinels separately from ordinary timestamps.

Required future adapter tests (not implemented or claimed by this research PR):
1601 epoch -> 0; Unix epoch -> 116444736000000000; a pre-1970 date; leap day;
subsecond values on both sides of a second boundary; a representable modern-date
round-trip; and underflow/overflow of both the tick and rencfs time types. Prove
that any precision loss is less than 100 ns, and separately test setter sentinels.

## Build and CI plan

The current GitHub Actions matrix already includes `windows-latest`, but tests
are skipped there. For the Windows implementation branch:

1. Keep `cargo build --all-targets --all-features` on `windows-latest`.
2. Add a Windows-only check that verifies the binary prints a useful error when
   WinFsp is not installed.
3. Add a manual smoke test job or checklist for a runner with WinFsp installed.
   GitHub-hosted Windows runners should not be assumed to have the WinFsp driver.

A local macOS/Linux cross-compile is not enough for this project because native
Windows dependencies such as `ring` and WinFsp linking need MSVC/Windows SDK
behavior. Use it only as an early syntax check, not as release evidence.

## Manual smoke test

On a Windows machine with Rust and WinFsp developer files installed:

```powershell
rustup default nightly
cargo build --release
mkdir data
$env:RENCFS_PASSWORD = "test-password"
cargo run --release -- mount --mount-point X: --data-dir .\data
```

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

Then unmount, mount again with the same password, and verify that persisted files
are readable and that `data` does not contain plaintext filenames or contents.

## Milestones

1. **Compile-only adapter:** add Windows cfg wiring, WinFsp dependency, build
   script, and a `windows.rs` that mounts only far enough to return a controlled
   "not implemented" error from each callback. CI must pass on `windows-latest`.
2. **Read-only filesystem:** implement lookup, getattr, open, read, and
   directory listing against an existing encrypted data directory.
3. **Writable regular files:** implement create, write, truncate, rename,
   delete, and release.
4. **Windows semantics hardening:** file times, read-only attribute, case
   behavior, error-code mapping, cleanup/close behavior, and explicit unsupported
   paths.
5. **Packaging:** installer notes, WinFsp attribution, and release validation.

## PR acceptance criteria

A first implementation PR should be considered ready only when it can truthfully
check these boxes:

- Maintainers have resolved the WinFsp and Rust-binding licensing checkpoints;
  installing WinFsp separately is not treated as blanket clearance.
- FILETIME epoch/precision/bounds tests and case-sensitive-name round-trips pass.
- Invalid-name create/rename/lookup tests pass without mutating backing entries;
  incompatible Linux-created namespaces get the documented preflight failure.
- The README explains case-sensitive Windows client limitations.
- The project builds on `windows-latest` with the Windows backend enabled.
- The PR does not add a separate Windows CLI surface unless justified.
- Unsupported operations return explicit errors, not success placeholders.
- The smoke test above has been run on a Windows host with WinFsp installed.
- The PR documents whether WinFsp was linked, delay-loaded, or required at
  runtime.
- AI assistance, if used, is disclosed in the PR body.
