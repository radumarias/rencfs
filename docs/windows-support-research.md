# Windows Support: Implementation Research

Status: **research note only.** Nothing in this document claims that rencfs mounts on
Windows today. `src/main.rs` still short-circuits with
`not yet ready for this platform`, and `src/mount.rs` still compiles `dummy.rs` on every
non-Linux target. This note records the decisions we would take *before* writing
`src/mount/windows.rs`, so that the first real implementation PR can be reviewed against
explicit criteria instead of being argued about in prose.

Related: issue for Windows support (see "Related" section of the bounty issue).

---

## 1. Scope and non-goals

In scope (first milestone):

- Mount an existing rencfs data directory as a drive letter or directory on Windows 10/11
  (x86_64) through a user-space filesystem driver.
- Reuse the existing `EncryptedFs` layer unchanged: no changes to on-disk format, no new
  crypto, no new metadata schema.
- Support the POSIX-like subset that `EncryptedFs` already implements: create, open,
  read, write, flush, release, rename, remove file, remove dir, read dir, get/set attr,
  set length, copy_file_range (best effort).

Out of scope for the first milestone:

- Symbolic links, hard links, junctions, reparse points.
- NTFS alternate data streams (ADS), sparse files, compression, EFS.
- Byte-range locks, oplocks, USN journal, NTFS ACL preservation semantics.
- Case-insensitive name resolution (see §7.3 — this is a decision, not an oversight).
- Performance parity with the Linux/FUSE backend.

The reason for the ordering is simple: `EncryptedFs` is storage-agnostic and already has a
trait boundary (`MountPoint`) that a second backend can implement without touching it.

---

## 2. Backend selection

| Candidate | How it works | Verdict |
|---|---|---|
| **WinFsp** (`winfsp-rs` crate) | Kernel driver + user-mode DLL; callbacks in Rust | **Recommended** |
| Dokan (`dokan-rs`) | Similar model, older driver, smaller community | Viable fallback; less maintained |
| ProjFS (Projected File System) | Read-only projection with virtualization callbacks | Rejected: write support is not the intended use |
| Cloud Files API | Sync-engine oriented, placeholder files | Rejected: wrong abstraction |
| SMB / Plan9 server | Serve the tree over a local network protocol | Rejected: needs a server loop and a second auth surface |
| WSL2 + existing Linux backend | Run the FUSE backend inside WSL, expose `\\wsl$` | Not a Windows build; users would need WSL and a Linux distro |

Why WinFsp:

1. It is the de-facto user-mode filesystem framework on Windows (used by sshfs-win, rclone,
   git-annex, and others), so user-facing documentation and troubleshooting already exist.
2. Callback shape maps closely to FUSE — the mapping in §6 is largely mechanical.
3. A maintained Rust binding exists (`winfsp` / `winfsp-sys`), with both static and
   delay-load linking.
4. Drive letters, directory mount points, and per-user mounts are all supported without
   administrator rights for the "current session" case.

Why not Dokan as the first choice: driver signing and distribution are heavier, the Rust
binding is less active, and its callback set maps less cleanly onto `EncryptedFs`
(especially `read_directory` with attributes).

---

## 3. Licensing and attribution checkpoint

This matters because rencfs is `MIT OR Apache-2.0` and WinFsp is not.

- **WinFsp license**: GPLv3 **with a special "FLOSS exception"**. The exception exists
  precisely so that free/open-source projects under OSI-approved licenses can use WinFsp
  without their own license being forced to GPL.
- **How rencfs uses it**: as a **runtime dependency** — the user installs the WinFsp MSI;
  rencfs loads `winfsp-x64.dll` at runtime and talks to it through the published C API. We
  do not vendor or link WinFsp source into rencfs.
- **`winfsp-rs` crate**: MIT-licensed Rust bindings; that is compatible with
  `MIT OR Apache-2.0` without any exception.
- **Attribution actions required before any Windows release**:
  1. Add a short "Windows backend" paragraph to `README.md` naming WinFsp and linking to
     `https://winfsp.dev`, stating that WinFsp is a separate runtime dependency under
     GPLv3 + FLOSS exception.
  2. Add `NOTICE`-style attribution next to the existing `LICENSE-*` files (a
     `THIRD_PARTY.md` listing WinFsp and `winfsp-rs`).
  3. Surface the dependency at runtime: if the DLL is missing, the error message must name
     WinFsp, its license, and the download URL — not just "driver not found".
- **Open question for the maintainer**: whether a Windows binary may be distributed at all
  given the GPLv3 driver. The FLOSS exception covers *use*; distribution of the *combined
  work* still deserves a one-line confirmation in the release notes. This is a
  documentation/release decision, not a code decision, and it does not block the first PR.

---

## 4. Dependency and build shape

Current `Cargo.toml` already uses per-target dependency blocks:

```toml
[target.'cfg(target_os = "linux")'.dependencies]
fuse3 = { version = "0.8.1", features = ["tokio-runtime", "unprivileged"] }
```

The Windows counterpart follows the same shape:

```toml
[target.'cfg(windows)'.dependencies]
winfsp = { version = "0.12", features = ["delayload"] }
windows-sys = { version = "0.59", features = ["Win32_Foundation", "Win32_Storage_FileSystem"] }
```

Design points:

- **Delay-load, not static link.** `delayload` keeps `rencfs.exe` startable on machines
  without WinFsp installed; the failure then happens at `winfsp_init()` time, where we can
  emit an actionable message instead of a loader error dialog.
- **No MSVC-only build assumptions in shared code.** Everything platform-specific stays
  behind `#[cfg(windows)]`; `EncryptedFs`, `crypto`, and `keyring` modules must keep
  compiling on Linux unchanged.
- **Toolchain**: `rust-toolchain.toml` currently pins a channel; add
  `x86_64-pc-windows-msvc` to the CI matrix rather than changing the default channel.
- **`build.rs`**: not required for delay-load; if static linking is ever enabled, the
  WinFsp SDK path must be configurable via env var (`WINFSP_ROOT`) instead of a hard-coded
  `C:\Program Files (x86)\WinFsp`.

Runtime preconditions to check in code before mounting:

1. `winfsp_init()` succeeds (DLL present and driver service running);
2. the mount point exists and is empty (or the requested drive letter is free);
3. the data directory is openable and its `-meta`/journal files are not locked by another
   rencfs process.

---

## 5. Proposed `src/mount/windows.rs` architecture

The existing seam is `src/mount.rs`:

```rust
pub trait MountPoint {
    fn new(mountpoint: PathBuf, data_dir: PathBuf, password_provider: Box<dyn PasswordProvider>,
           cipher: Cipher, allow_root: bool, allow_other: bool, read_only: bool) -> Self;
    async fn mount(mut self) -> FsResult<MountHandle>;
}
```

`MountHandle` wraps `MountHandleInnerImpl` and implements `Future<Output = io::Result<()>>`,
so `windows.rs` must provide the same two items. Proposed layout:

```
src/mount.rs               (cfg gates: linux -> linux.rs, windows -> windows.rs, else -> dummy.rs)
src/mount/windows.rs       (new; ~600-800 lines, mirrors linux.rs structurally)
```

Inside `windows.rs`:

- `pub struct MountPointImpl` — same fields as the Linux implementation
  (`mountpoint`, `data_dir`, `password_provider`, `cipher`, read-only/allow flags).
- `struct RenFspContext` — holds `Arc<EncryptedFs>`, the resolved mount point, and the
  read-only flag; passed as user context to every WinFsp callback.
- `impl winfsp::filesystem::FileSystem for RenFspContext` (or the crate's
  `FileSystemContext` trait, depending on the chosen binding version).
- `struct MountHandleInnerImpl` — owns the WinFsp `FileSystemHost`, implements
  `unmount()` (calls host stop, waits for the dispatcher thread to exit) and
  `poll` (resolves when the host stops).
- `fn map_err(FsError) -> NTSTATUS` — a single conversion table (§6.2) used by every
  callback, mirroring how `linux.rs` centralizes `FsError -> Errno`.

Threading model: `EncryptedFs` is already `async`/tokio-based, and the Linux backend drives
it from the fuse3 tokio runtime. WinFsp callbacks are synchronous, so the Windows backend
must own a dedicated multi-threaded tokio runtime and use
`Handle::block_on`/`block_in_place` per callback, with a bounded pool so that a slow
encrypted read cannot starve the dispatcher. This is the single most important structural
difference and should be stated in the PR description.

---

## 6. Operation mapping

### 6.1 Callbacks to `EncryptedFs`

| WinFsp callback | `EncryptedFs` call | Notes |
|---|---|---|
| `get_security_by_name` | `find_by_name` + `get_attr` | Feeds default security descriptor; no ACL persistence in v1 |
| `open` | `open(ino, read, write)` | Reject `FILE_WRITE_DATA` when `read_only` |
| `create` | `create(...)` | Map `FILE_ATTRIBUTE_DIRECTORY` to dir creation |
| `read` | `read(...)` | Offset-based, same semantics as FUSE |
| `write` | `write(...)` | Return bytes written; propagate `FsError::NoSpace` as `STATUS_DISK_FULL` |
| `flush` | `flush(handle)` | Called before `cleanup` |
| `close` / `cleanup` | `release(handle)` | Deletion of "delete-pending" entries happens here |
| `get_file_info` | `get_attr(ino)` | See §6.2 and §7.1 |
| `set_file_info` | `set_attr(ino, SetFileAttr)` | Timestamps, size, read-only flag |
| `rename` | `rename(...)` | Reject cross-directory moves only if `EncryptedFs` does |
| `read_directory` | `read_dir_plus(ino)` | Attributes must be filled in the same call |
| `get_volume_info` | derived from `STATFS` constant | Same numbers as `linux.rs` |
| `set_delete` | recorded per handle | Actual removal in `cleanup` |
| `copy_file_range` (optional) | `copy_file_range(...)` | Can be omitted from milestone 1 |

### 6.2 Error mapping (`FsError` → `NTSTATUS`)

Starting table, to be completed during implementation by reading each variant:

| `FsError` | `NTSTATUS` |
|---|---|
| `NotFound` | `STATUS_OBJECT_NAME_NOT_FOUND` |
| `AlreadyExists` | `STATUS_OBJECT_NAME_COLLISION` |
| `NotDir` | `STATUS_NOT_A_DIRECTORY` |
| `IsDir` | `STATUS_FILE_IS_A_DIRECTORY` |
| `NotEmpty` | `STATUS_DIRECTORY_NOT_EMPTY` |
| `PermissionDenied` | `STATUS_ACCESS_DENIED` |
| `NameTooLong` | `STATUS_OBJECT_NAME_INVALID` |
| `Io` | `STATUS_IO_DEVICE_ERROR` |
| `NoSpace` | `STATUS_DISK_FULL` |

The invariant: **one mapping function**, no ad-hoc `NTSTATUS` literals scattered in
callbacks — the same discipline `linux.rs` applies with its `Errno` constants.

---

## 7. Windows metadata decisions

### 7.1 Timestamps

`FileAttr` carries `UNIX_EPOCH`-based times. Windows wants `FILETIME` (100-ns ticks since
1601-01-01). Conversion must be explicit and tested (leap/none, no timezone involvement),
and sub-second precision should be truncated to the stored resolution rather than invented.

### 7.2 File attributes

| Windows attribute | Source |
|---|---|
| `FILE_ATTRIBUTE_DIRECTORY` | `FileType::Dir` |
| `FILE_ATTRIBUTE_READONLY` | derived from mount-level `read_only` or `SetFileAttr` |
| `FILE_ATTRIBUTE_NORMAL` | fallback for regular files |

`FILE_ATTRIBUTE_HIDDEN`/`SYSTEM`, reparse points, and ADS are **not** derived from rencfs
metadata in milestone 1.

### 7.3 Name handling

Two separate questions, deliberately kept separate:

1. **Encoding**: `EncryptedFs` stores names as encrypted bytes; Windows passes UTF-16.
   Conversion happens at the boundary only, with a single helper, and invalid sequences
   are rejected as `STATUS_OBJECT_NAME_INVALID` rather than lossily converted.
2. **Case sensitivity**: WinFsp can advertise case-sensitive names. Milestone 1 will
   **advertise case-sensitive and document it**, because silently adding case-insensitive
   lookup would change collision behaviour in the encrypted store (two names that differ
   only by case are two distinct entries today). Making it case-insensitive later is a
   feature with its own design note.

### 7.4 Unsupported NTFS features (explicit)

Sparse files, compression, EFS, hard links, junctions, ADS, USN journal, byte-range locks,
oplock/lease semantics. Each must return a clear `STATUS_` error rather than being silently
emulated — silently "working" on Windows while losing data semantics is the worst outcome.

---

## 8. Build, CI, and manual smoke test

CI (GitHub Actions, added in the implementation PR — not in this research PR):

```yaml
windows-build:
  runs-on: windows-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
      with: { targets: x86_64-pc-windows-msvc }
    - run: rustup default stable-x86_64-pc-windows-msvc
    - run: cargo build --target x86_64-pc-windows-msvc
    - run: cargo test  --target x86_64-pc-windows-msvc --lib
```

Unit tests that can run without the driver: timestamp conversion, `FsError` → `NTSTATUS`
mapping, UTF-16 ↔ name conversion, attribute derivation. Integration tests that need the
driver stay behind a feature flag (`--features winfsp-it`) so CI stays green on runners
without WinFsp.

Manual smoke test (documented in `docs/windows-smoke-test.md` later):

1. Install WinFsp from the official MSI (note the version).
2. `rencfs mount C:\rencfs-data R:` (or a directory mount point).
3. `echo hello > R:\a.txt`, `type R:\a.txt`, `dir R:\`, `mkdir R:\d`,
   `ren R:\a.txt b.txt`, `del R:\b.txt`, `rmdir R:\d`.
4. Unmount (`rencfs umount R:`), confirm the process exits and the drive disappears.
5. Repeat with `--read-only` and confirm writes fail with access denied, not with a crash.

Acceptance for the smoke test is "all steps done, output pasted into the PR", not "works".

---

## 9. Acceptance criteria for the first implementation PR

The first code PR should be judged on these, in this order:

1. **Linux unchanged**: `cargo build`, `cargo test`, `cargo clippy` green on Linux, and no
   diff inside `src/mount/linux.rs`, `src/encryptedfs.rs`, `src/crypto/**`.
2. **Windows compiles**: `cargo build --target x86_64-pc-windows-msvc` green in CI.
3. **Delay-load verified**: running the binary on a machine without WinFsp produces the
   documented, actionable error message (screenshot in the PR).
4. **Mapping completeness**: every callback in §6.1 is implemented or explicitly stubbed
   with a `STATUS_NOT_IMPLEMENTED` plus a TODO naming the milestone.
5. **Error mapping centralized**: single `map_err`, no inline `NTSTATUS` literals.
6. **Smoke test recorded**: the §8 checklist executed on a real Windows 10/11 host, with
   command output pasted into the PR.
7. **Docs updated in the same PR**: `README.md` Windows section, `THIRD_PARTY.md`
   attribution, and a statement of what is *not* supported.
8. **No on-disk format change**: a data directory created by a Linux build mounts and
   reads correctly on Windows, and vice versa.

Anything that fails 1, 2, or 8 should not be merged regardless of how well the rest works.

---

## 10. Risks and open questions

| Risk | Mitigation |
|---|---|
| WinFsp driver requires admin install | Document it; do not bundle; detect and instruct |
| Sync callbacks + async `EncryptedFs` deadlocks | Dedicated runtime + bounded blocking pool (§5); load test with concurrent `dir` |
| GPLv3 driver + MIT/Apache project | FLOSS exception + attribution (§3); confirm binary distribution in release notes |
| Case sensitivity surprises users | Advertise case-sensitive in v1 and document it (§7.3) |
| Antivirus scanning the mount slows everything | Document; add a note recommending exclusion during benchmarks |
| `copy_file_range` semantics differ | Optional in milestone 1; fall back to read/write loop |

Open questions for the maintainer:

1. Is per-user (session) mounting acceptable for milestone 1, or is a service-mode mount
   required?
2. Should the Windows backend live behind a cargo feature (`--features windows-mount`) to
   keep default Linux builds dependency-free?
3. Is there a preferred naming for the mount CLI subcommand on Windows (`R:` vs a
   directory)?
