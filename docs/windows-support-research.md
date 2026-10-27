# Windows support: implementation research

Status: **research only.** rencfs does not mount on Windows today. This note records what a first
native implementation would have to decide, which parts are cheap, and which parts are not worth
pretending are cheap.

Related: Opire bounty on #3 (`research implementation for Windows`).

---

## 1. Scope and non-goals

In scope: a native Windows mount backend that speaks to `EncryptedFs` through the same `Mount`
abstraction the Linux backend already implements, so the encryption layer stays platform-agnostic.

Out of scope for the first milestone:

- driver development of any kind — the backend rides an existing user-mode filesystem driver;
- symlinks, hardlinks, xattrs, sparse files, reparse points beyond the mount point itself;
- byte-range locks and `LockCtrl` semantics;
- case-insensitive name resolution inside the encrypted store (see §7);
- performance work: the first PR should be correct, not fast.

## 2. Backend choice

| Option | What it gives | Why not (now) |
| --- | --- | --- |
| **WinFsp** | User-mode FS with a stable ABI, FUSE-shaped callback set, mature, used by sshfs-win and rclone | Requires a kernel driver install; GPLv3 with a FLOSS exception (see §3) |
| **Dokany** | FUSE-like API translated to a Dokan driver | Same install burden, smaller ecosystem in Rust (`dokan` crate, last release 0.3.1), LGPL + static-linking exception |
| **Projected File System (ProjFS)** | No custom driver, ships with Windows 10 1809+ | Read-only projection semantics, no real create/write/rename; wrong shape for a writable encrypted FS |
| **Cloud Files API (cldapi)** | Placeholder/dehydration model, Explorer integration | Designed for sync engines, not for arbitrary POSIX-ish semantics; heavy |
| **WSL2 passthrough** | Works today via the Linux build | Not a Windows mount; requires WSL, a Linux distro, and a path inside it |
| **Cygwin / WinFsp-FUSE layer** | Reuses `fuse3` | Needs a POSIX emulation layer that is not present in the build; large binary, odd semantics |

**Recommendation:** WinFsp as the first backend. Its callback set maps almost one-to-one onto the
`fuse3` trait methods already implemented in `src/mount/linux.rs`, which is the whole reason this is
feasible without touching `EncryptedFs`.

## 3. Licensing and attribution checkpoint (blocker, decide before code)

- **WinFsp itself** is distributed under GPLv3 **with a FLOSS exception** that permits use by
  projects under OSI-approved licenses without the GPL propagating to them, plus a paid commercial
  license for closed-source use. rencfs ships `LICENSE-MIT`, `LICENSE-Apache-2.0` and
  `LICENSE-BSD-3-Clause`, which are OSI-approved, so the FLOSS exception is the path that applies.
  This must be confirmed against the exact WinFsp release we pin, and the exception text quoted in
  the PR that adds the dependency.
- Because WinFsp is linked as a **separate installed component** (a DLL plus a kernel driver), the
  practical shape is dynamic loading with delay-load, not vendoring — which also keeps the
  attribution question simple: we ship no WinFsp code.
- **The `winfsp` crate (winfsp-rs) is the open question.** Its crates.io metadata declares
  `license: None` as of `0.13.2+winfsp-2.1`. Until the repository's LICENSE file is read and
  recorded, the crate must not be added to `Cargo.toml`. If it turns out to be incompatible, the
  fallback is a thin hand-written `extern "system"` binding to the FSP API — more work, no license
  risk, and worth costing before we commit to the crate.
- The Windows driver install is a **user-visible step**: the README has to say "install WinFsp
  first" the same way it currently says "install FUSE" on Linux.

## 4. Dependency and build shape

Today `Cargo.toml` gates the FUSE dependency per target:

```toml
[target.'cfg(target_os = "linux")'.dependencies]
fuse3 = { ... }
```

The Windows backend should follow the same pattern, so a normal Linux build resolves exactly what
it resolves today:

```toml
[target.'cfg(windows)'.dependencies]
windows = { version = "0.58", features = ["Win32_Foundation", "Win32_Storage_FileSystem"] }
# winfsp = { version = "0.13", optional = true }   # blocked on §3
```

and the mount module selection becomes:

```rust
// src/mount.rs
#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;
#[cfg(target_os = "linux")]
pub use linux::RencFs;
#[cfg(windows)]
pub use windows::RencFs;
```

Loading: resolve `winfsp-x64.dll` from `%ProgramFiles(x86)%\WinFsp\bin` (the installer's default)
at first mount, and fail with an actionable error — "WinFsp is not installed; see
https://winfsp.dev/rel/" — rather than a raw `LoadLibrary` error. No delay-load import table, no
`build.rs` link step: a `libloading`-style dynamic lookup keeps `cargo build` working on machines
without WinFsp.

## 5. Proposed `src/mount/windows.rs` architecture

`src/mount.rs` already defines the abstraction we need:

```rust
pub trait Mount {
    async fn mount(self) -> FsResult<MountHandle>;
    async fn unmount(self) -> io::Result<()>;
}
```

The Windows adapter mirrors `src/mount/linux.rs`: a struct holding `Arc<EncryptedFs>` plus the
mount point, implementing the WinFsp file-system callbacks and translating them into the same
`EncryptedFs` calls the Linux backend makes.

Two mechanical differences that must be designed for rather than discovered:

1. **Sync vs async.** `fuse3` is async; WinFsp callbacks arrive on WinFsp-owned threads and must
   return before the caller's I/O completes. The adapter therefore owns a Tokio `Handle` and runs
   each callback body with `handle.block_on(...)`. Callbacks must never be run on the runtime's own
   worker threads — `block_on` inside a worker deadlocks. A dedicated multi-thread runtime owned by
   the mount, plus `Handle::block_on` from the FSP threads, is the safe shape.
2. **Thread context.** `EncryptedFs` methods that depend on process-wide state (the keyring) are
   fine, but anything that assumed a single-threaded FUSE loop must be checked. Any `!Send` future
   captured across an `await` will fail to compile here, which is a feature: it surfaces the
   problem at build time.

Sketch, not final code:

```rust
pub struct RencFs {
    fs: Arc<EncryptedFs>,
    mountpoint: PathBuf,
    rt: tokio::runtime::Runtime,
}

impl RencFs {
    pub async fn new(fs: Arc<EncryptedFs>, mountpoint: impl AsRef<Path>) -> FsResult<Self> { ... }
}

// WinFsp callbacks -> EncryptedFs
extern "system" fn get_security_by_name(...) -> NTSTATUS { ... }
extern "system" fn open(...) -> NTSTATUS { ... }   // -> EncryptedFs::find_by_name
extern "system" fn read(...) -> NTSTATUS { ... }   // -> EncryptedFs::read
extern "system" fn write(...) -> NTSTATUS { ... }  // -> EncryptedFs::write
extern "system" fn read_directory(...) -> NTSTATUS { ... } // -> EncryptedFs::read_dir
```

## 6. Operation mapping

The left column is the `fuse3` method already implemented in `src/mount/linux.rs`; the right column
is the WinFsp callback that would take its place, and the `EncryptedFs` call it lands on.

| `fuse3` (linux.rs) | WinFsp callback | `EncryptedFs` |
| --- | --- | --- |
| `lookup` | `GetSecurityByName`, `Open` | `find_by_name`, `exists_by_name` |
| `getattr` | `GetFileInfo` | `get_attr` |
| `setattr` | `SetFileInfo`, `SetFileSize` | `set_attr`, `set_len` |
| `mknod`, `create` | `Create` | `create`, `create_write` |
| `mkdir` | `Create` (directory disposition) | `create` with dir mode |
| `unlink` | `Cleanup` (delete on close) | `remove_file` |
| `rmdir` | `Cleanup` (delete on close) | `remove_dir` |
| `rename` | `Rename`, `SetInformation` | `rename` |
| `open` | `Open` | `open`, `create_read` |
| `read`, `write` | `Read`, `Write` | `read`, `write` |
| `flush`, `release` | `Flush`, `Cleanup`, `Close` | `flush`, `release` |
| `opendir`, `readdir`, `readdirplus` | `Open`, `ReadDirectory` | `read_dir`, `read_dir_plus` |
| `releasedir` | `Close` | `release` |
| `statfs` | `StatFs` (optional) | `len`, free space reported as 0 |
| `copy_file_range` | `SetInformation` (FileAllocationInformation path) | `copy_file_range` |
| `access` | `GetSecurityByName` | mapped from `get_attr` mode bits |

Callbacks with no `EncryptedFs` counterpart in the first milestone must return
`STATUS_INVALID_DEVICE_REQUEST` (or `STATUS_NOT_IMPLEMENTED` where WinFsp expects it) instead of
inventing behaviour: byte-range locks, reparse points, extended attributes, `DeviceControl`.

## 7. Metadata decisions

- **File IDs.** `fuse3` gives an `Inode`; WinFsp wants a 64-bit file ID plus a name. Use a stable
  `u64` derived from the node's identity in `EncryptedFs` (path hash if nothing better exists), and
  keep a mount-local map so `Open` and `GetFileInfo` agree. Do not attempt to reuse Linux inode
  numbers, which are not meaningful across runs.
- **Timestamps.** WinFsp deals in `FILETIME` (100 ns ticks since 1601). Convert from the
  `SystemTime` rencfs already stores; assert round-trip equality in a unit test, because the
  1601-epoch offset is easy to get wrong by exactly 11644473600 seconds.
- **Case sensitivity.** NTFS is case-insensitive by default and WinFsp directories are normally
  exposed as case-insensitive too. rencfs's store is case-sensitive. The first milestone should
  declare `CaseSensitiveSearch = TRUE` in `FSP_FSCTL_VOLUME_PARAMS` so the kernel does not fold
  names before they reach us; the consequence (some installers and older applications behave badly)
  belongs in the README, not in a silent workaround.
- **Names.** Windows rejects a set of characters (`<>:"/\|?*`), reserved device names
  (`CON`, `PRN`, `AUX`, `NUL`, `COM1`…`LPT9`), and trailing dots/spaces. A file created on Linux
  with such a name is not reachable from Windows. Nothing to fix in the first PR — but it has to be
  stated, and ideally surfaced as `STATUS_OBJECT_NAME_INVALID` rather than a confusing not-found.
- **Permissions.** No POSIX mode bits. Report a fixed read/write owner mapping and ignore
  `chmod` (accept and drop), which matches what `EncryptedFs` already does with most attribute
  changes.
- **Unsupported on day one:** symlinks (report as "not a reparse point"), hardlinks, ADS
  (alternate data streams — must return `STATUS_NOT_SUPPORTED`, not silently write to the base
  file), sparse files, quotas.

## 8. Build and CI plan

1. `cargo check --target x86_64-pc-windows-msvc` on Linux CI stays Windows-toolchain-free by
   gating the backend behind `#[cfg(windows)]`; cross-checking needs `cargo-xwin` or a Windows
   runner, so start with the runner.
2. Add a `windows-latest` job that (a) installs WinFsp from its MSI with `/qn`, (b) runs
   `cargo build --all-targets`, (c) runs the unit tests that do not mount. **Do not** mount in CI:
   WinFsp needs a driver install and a service, and a flaky mount test in CI is worse than no test.
3. Keep the Linux job byte-identical in behaviour: the Windows dependency must be invisible to it.
4. Formatting and clippy: the Windows module must pass the same `clippy.toml` config; add
   `#[cfg(windows)]` to the allow-list only if a lint is genuinely Windows-only.

## 9. Manual smoke test (Windows host with WinFsp installed)

```
cargo build --release
target\release\rencfs.exe mount --mountpoint R: <encrypted-dir>
```

then, in another shell:

```
echo hello > R:\hello.txt
type R:\hello.txt                      # expect: hello
dir R:\                                # entry appears, size matches
copy R:\hello.txt R:\copy.txt
ren R:\copy.txt renamed.txt
del R:\renamed.txt
mkdir R:\sub && rmdir R:\sub
```

and the three checks that actually catch backend bugs:

1. **Durability:** unmount, remount, `type R:\hello.txt` still returns `hello`.
2. **Cross-platform agreement:** create the file from Windows, read it from Linux with the Linux
   build on the same directory. A mismatch here means the metadata translation is wrong.
3. **Error paths:** open a non-existent file (expect `ERROR_FILE_NOT_FOUND`, not a panic), create a
   file with a reserved name (expect a clean error), and kill the process while a write is in
   flight (expect no plaintext leakage into the store).

## 10. Acceptance criteria for a truthful first implementation PR

A first PR should be rejectable on any one of these, which is the point of writing them down:

- `cargo build` on Linux resolves **no** new dependency and produces a byte-identical feature set.
- `cargo check --target x86_64-pc-windows-msvc` passes on a machine **without** WinFsp installed
  (dynamic loading, no link-time dependency).
- A mount on a Windows host with WinFsp survives: create, read, write, rename, delete, directory
  listing, durability across remount, and a cross-platform read from Linux.
- Every unimplemented callback returns an explicit status; no `todo!()`, no `unimplemented!()`, no
  silent success.
- The README documents the WinFsp install step and the case-sensitivity and reserved-name caveats.
- The license question in §3 is answered in the PR description — either the crate's license is
  compatible and quoted, or the binding is hand-written.

## 11. Open questions

1. Which WinFsp version do we pin, and does its FLOSS exception text cover a dual
   MIT/Apache-2.0 project without an additional attribution requirement beyond the notice?
2. Is `winfsp-rs` maintained enough to take a dependency, given the last crate release is
   `0.13.2+winfsp-2.1`?
3. Does the `EncryptedFs` keyring require an interactive unlock that a Windows service context
   cannot provide? If yes, the mount has to happen in a user session only, and that is a design
   constraint rather than a bug.
4. Do we need `FSP_FSCTL_VOLUME_PARAMS.SectorSize` and allocation-unit tuning, or are the defaults
   acceptable for a store that is encrypted per-file anyway?
5. Is a read-only first milestone (mount, list, read) worth shipping separately from write support,
   to get a real user testing the metadata translation sooner?

---

This note deliberately stops at research. The next artifact should be a PR that answers §3 and §11.3
before it writes a single callback.