# Windows support — implementation research

This document collects the research for bringing rencfs to Windows natively
(tracking issue: *FUSE (or similar) support on Windows*). It is a research
note, not a claim that rencfs mounts on Windows today. Its goal is to give the
first implementation PR a concrete, verified path and a truthful definition of
done.

## 1. Where rencfs stands today

The crate is split into three layers:

- `src/encryptedfs.rs` — `EncryptedFs`, the platform-independent encrypted
  filesystem core. It exposes an inode-oriented async API:
  `create`, `open`, `read`, `write`, `flush`, `release`, `get_attr`,
  `set_attr`, `set_len`, `read_dir` / `read_dir_plus`, `find_by_name`,
  `exists_by_name`, `remove_file`, `remove_dir`, `rename`,
  `copy_file_range`, plus handle bookkeeping (`is_read_handle`,
  `is_write_handle`). Nothing in this layer depends on Linux.
- `src/mount.rs` — the mount facade. It selects the backend at compile time:
  `#[cfg(target_os = "linux")] mod linux;` and
  `#[cfg(not(target_os = "linux"))] mod dummy;`, both behind the
  `MountPoint` / `MountHandleInner` traits. On non-Linux targets the `dummy`
  backend already compiles, so `cargo build` on Windows succeeds today; it
  just cannot mount anything.
- `src/mount/linux.rs` — the real backend: a `fuse3::raw::Filesystem`
  implementation (`EncryptedFsFuse3`) that translates FUSE requests into
  `EncryptedFs` calls. ~1.5k lines; this is the file a Windows backend must
  mirror conceptually.

So Windows support is exactly one new module plus wiring: a
`src/mount/windows.rs` that plays the role `linux.rs` plays today, selected by
`#[cfg(target_os = "windows")]` in `src/mount.rs`. No changes to the crypto or
storage core are required.

## 2. Choosing the Windows kernel interface

Windows has no FUSE. The realistic options:

| Option | What it is | Verdict |
|---|---|---|
| **WinFsp** | mature FUSE-like userspace FS framework (kernel driver + DLL), used by sshfs-win, rclone mount, Cryptomator (formerly) | **Recommended** |
| Dokany | similar idea, smaller ecosystem, historically less stable under load | Fallback only |
| ProjFS (Windows Projected File System) | Microsoft-native virtualization API used by GVFS; good for on-demand hydration, weak fit for a general encrypted FS with arbitrary local writes | Not recommended for milestone 1 |
| WSL | already works today via the Linux build; not a native solution | Out of scope |

### 2.1 License checkpoint (do not skip)

WinFsp is **GPLv3** (with a commercial license available from its author).
rencfs is `MIT OR Apache-2.0`, and GPLv3 is one-way incompatible with
Apache-2.0 for derivative distribution. This was already flagged on the
tracking issue. The practical reading used by other Rust projects:

- Dynamically linking against the **WinFsp DLL at runtime** (the model the
  `winfsp` crate uses: it loads `winfsp.dll`, optionally delay-loaded, and the
  user installs WinFsp separately) keeps rencfs itself MIT/Apache — the same
  position projects like sshfs-win and rclone take. We do not ship WinFsp.
- If the project ever wants to **bundle** WinFsp, that requires either the
  commercial WinFsp license or a relicense conversation. Not for milestone 1.

Action for the first PR: depend on the `winfsp` crate with runtime/delayed
loading, document that end users install WinFsp themselves, and add an
attribution note. That keeps the license posture unchanged.

### 2.2 Rust bindings

- [`winfsp`](https://crates.io/crates/winfsp) (SnowflakePowered/winfsp-rs) —
  actively maintained, safe wrappers over the WinFsp C API, supports
  delay-loading. This is the crate to build on.
- Prior art worth reading before writing code: `sshfs-win` (C, canonical
  WinFsp usage), `rclone mount` (Go, cgofuse over WinFsp), and the WinFsp
  wiki's known-filesystems list for C samples.

## 3. The one real design problem: paths vs. inodes

`fuse3` (and `EncryptedFs`) are **inode-oriented**; WinFsp's
`FileSystemInterface` is **path-oriented** (callbacks receive
`PWSTR` file names). The Windows backend therefore needs an adapter:

- Keep an `ino ↔ path` map inside the backend (a `DashMap`/RwLock pair).
  `EncryptedFs::find_by_name(parent_ino, name)` resolves a path component by
  component; open handles remember their `ino` in the WinFsp `FileContext`.
- rencfs encrypts file **names**, so path parsing must stay in plaintext-land:
  split the WinFsp path, resolve each component against `EncryptedFs`, never
  expose encrypted names to Windows.
- Case sensitivity: NTFS semantics are case-insensitive. The map and name
  comparisons should use case-insensitive matching (with `EncryptedFs` staying
  the source of truth), matching what Windows apps expect.

This adapter is where most of the effort lives; everything else is plumbing.

## 4. Operation mapping (WinFsp → EncryptedFs)

| WinFsp callback | EncryptedFs call |
|---|---|
| `GetVolumeInfo` | static volume label + `STATFS`-style constants (as in `linux.rs`) |
| `Open` / `Create` | `find_by_name` → `open(ino, read, write)` / `create(...)` |
| `Read` | `read(ino, offset, size, fh)` |
| `Write` | `write(ino, offset, buf, fh)` + `set_len` when extending |
| `Flush` | `flush(fh)` |
| `Cleanup` / `Close` | `release(fh)` |
| `GetFileInfo` | `get_attr(ino)` → fill `FileInfo` |
| `SetBasicInfo` / `SetFileSize` | `set_attr(ino, SetFileAttr{..})` / `set_len` |
| `ReadDirectory` | `read_dir(ino)` iterator |
| `Create` (directory) / `Delete` | `create(.., Directory)` / `remove_file` / `remove_dir` |
| `Rename` | `rename(parent, name, new_parent, new_name)` |
| `GetSecurity` / `SetSecurity` | minimal fixed descriptor for milestone 1 (see §6) |

`copy_file_range` has no direct WinFsp equivalent; skip it initially.

## 5. Metadata mapping

`FileAttr` (rencfs) ↔ WinFsp `FileInfo`/`FILE_ALL_INFORMATION`:

- `size` ↔ `FileSize` / `AllocationSize` (round up to 4 KiB allocation units).
- `atime/mtime/ctime` ↔ `LastAccessTime`/`LastWriteTime`/`ChangeTime`
  (Windows FILETIME, 100-ns ticks since 1601 — conversion helper needed).
- rencfs has no `birthtime` on all filesystems; map `CreationTime` from
  `ctime` as a pragmatic default.
- Unix mode bits ↔ `FileAttributes`: directory ↔ `FILE_ATTRIBUTE_DIRECTORY`,
  read-only mounts ↔ `FILE_ATTRIBUTE_READONLY`. No ACL emulation in
  milestone 1.

## 6. Scope of the first milestone (explicitly out)

To keep the first PR honest and reviewable:

- No NTFS alternate data streams, no reparse points/symlinks, no ACL
  editor integration, no opportunistic locks.
- Fixed permissive security descriptor for `GetSecurity`.
- Read-write mounts only when writable; `read_only` flag maps to
  attribute + write rejection, mirroring the Linux path.

## 7. Build and CI plan

- `Cargo.toml`: move nothing; add
  `[target.'cfg(target_os = "windows")'.dependencies] winfsp = "..."`
  and keep `fuse3` Linux-only (it already effectively is, via cfg).
- `src/mount.rs`: add
  `#[cfg(target_os = "windows")] mod windows;` selecting
  `MountHandleInnerImpl`/`MountPointImpl` from it; `dummy` then covers only
  the remaining non-Linux, non-Windows targets.
- CI: extend the matrix with `windows-latest`; install WinFsp in the job
  (`choco install winfsp`) so at minimum `cargo check`/`clippy` and unit tests
  run, and the mount smoke test can run gated.

## 8. Manual smoke test (first implementation PR)

On a Windows host with WinFsp installed:

1. `cargo run -- mount X: <data_dir>` (or a directory mountpoint).
2. Create/read/write/rename/delete files and directories from Explorer and
   `cmd`; verify contents round-trip and the data dir stays encrypted at rest.
3. Unmount cleanly; remount; confirm data persists.
4. `cargo test` on Windows for the path-adapter unit tests.

## 9. Acceptance criteria for the implementation PR

- [ ] `cargo check` and `cargo clippy` pass on Linux **and** Windows.
- [ ] `src/mount/windows.rs` implements the `MountPoint`/`MountHandleInner`
      traits via WinFsp with the mapping in §4.
- [ ] No changes to `encryptedfs`/`crypto` behavior; Linux tests still pass.
- [ ] WinFsp is runtime-loaded; no GPL code vendored; attribution documented.
- [ ] Smoke test from §8 documented with actual output.

## 10. Effort estimate and risks

- Adapter + backend skeleton: ~1–2 weeks of focused work for someone fluent
  in Rust; the path↔ino adapter and name-resolution loop are the bulk.
- Risks: WinFsp callback semantics differ subtly from FUSE (cleanup/close
  ordering, overwrite flags); case-insensitivity edge cases; AV/Defender
  interference during file scanning; GPL/commercial-license decision if
  bundling is ever wanted.

## References

- Tracking issue with maintainer's original pointers (winfsp crate,
  winfsp-rs, winfuse, known-filesystems wiki).
- WinFsp: https://winfsp.dev/ · sshfs-win: https://github.com/winfsp/sshfs-win
- winfsp-rs: https://github.com/SnowflakePowered/winfsp-rs
- rclone mount (WinFsp in production): https://rclone.org/commands/rclone_mount/
