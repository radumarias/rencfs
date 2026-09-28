# Windows Support Research — Issue #3

**Status:** Decided (research complete); proof-of-concept WinFsp backend implemented
**Decision:** Adopt **WinFsp** via the [`winfsp`](https://crates.io/crates/winfsp) crate (winfsp-rs) as the Windows user-mode filesystem backend.
**Scope of this issue:** research, decision record, semantic-mapping spec, build plumbing, and a proof-of-concept mount backend (`src/mount/windows/`, behind the `windows-mount` feature). Hardening, integration tests on a WinFsp-installed runner, and distribution packaging are tracked in the follow-up epic (see §9).

---

## 1. Summary

rencfs today mounts only on Linux: the mount layer is a ~1500-line `fuse3::Filesystem` implementation in `src/mount/linux.rs`, `fuse3` is pulled in only under `[target.'cfg(target_os = "linux")'.dependencies]`, and `src/main.rs` exits early on Windows/macOS. The encrypted core (`encryptedfs`, `crypto`) is platform-agnostic Rust and already compiles on Windows — the gap is confined to the VFS adapter layer, plus a set of POSIX-isms (uid/gid semantics, `umount` shell-outs) that this issue removes or gates.

There is no FUSE on Windows, so the missing piece was a decision on which Windows user-mode filesystem stack to adopt. This document evaluates the options, records the decision for **WinFsp**, specifies the POSIX→Windows semantic mapping, and lays out the implementation plan.

## 2. Current state analysis

| Area | State before this issue | State after this issue |
|---|---|---|
| Mount backend | `src/mount/linux.rs` (fuse3) on Linux; `src/mount/dummy.rs` stub elsewhere | Added `src/mount/windows/` (WinFsp PoC, `cfg(all(windows, feature = "windows-mount"))`); `dummy.rs` remains the fallback for other platforms |
| Mount abstraction | `MountPoint` / `MountHandle` / `MountHandleInner` traits in `src/mount.rs`, backend selected by `cfg` | Unchanged — the abstraction proved sufficient; the WinFsp backend implements the same traits, no Linux regression risk |
| `libc` dependency | Unconditional in `Cargo.toml` | Moved to `[target.'cfg(unix)'.dependencies]`; all uses (`UID`/`GID` in `src/lib.rs`, root-dir ownership in `encryptedfs.rs`) are `cfg(unix)`-gated and return `0` on Windows |
| `umount` | `mount::umount()` shells out to `umount(8)` on every platform | Shell-out is `cfg(unix)`-only; on Windows it returns `io::ErrorKind::Unsupported` (WinFsp volumes are unmounted via the mount handle) |
| CLI | `src/main.rs` prints "not yet ready for this platform" on Windows | With `windows-mount`, the full `run` CLI (`mount`, `passwd`) works on Windows; without the feature it prints build instructions |
| Windows deps | none | Optional `winfsp = "0.13"` under `cfg(target_os = "windows")`, enabled by the new `windows-mount` cargo feature |
| Semantic mapping | n/a | `src/mount/windows_semantics.rs` — pure, platform-independent POSIX→Windows mapping helpers (FILETIME, file attributes, path/name rules, case-insensitive compare), unit-tested on every platform |
| CI | `windows-latest` builds only; no tests run | `windows-latest` additionally runs `cargo test --release --lib` and `cargo check`/`clippy --features windows-mount`, locking the core and the WinFsp backend as Windows-clean |

## 3. Options evaluated

| Option | Rust binding | Verdict | Notes |
|---|---|---|---|
| **WinFsp** | [`winfsp`](https://crates.io/crates/winfsp) (winfsp-rs) | **Chosen** | Mature, actively maintained, FUSE-like callback model, signed driver installer, proven in production by rclone (via cgofuse) and sshfs-win. Crate builds without WinFsp installed (bundled import library, delay-loaded at runtime); optional `system` feature links against an installed WinFsp. |
| Dokany | `dokan` crate | Rejected | Similar callback model, but weaker maintenance cadence and a much thinner Rust ecosystem; no first-class, actively maintained Rust bindings. |
| Windows ProjFS | `windows` crate | Rejected | One-way *projection*/virtualization provider (the OneDrive model), not a real writable filesystem. A writable encrypted vault needs full read/write/create/rename/delete semantics with encrypted backing storage — ProjFS's model is a poor fit. |
| NFS/SMB loopback server | custom | Rejected | Heavy complexity, opens a local network attack surface, authentication/firewall UX problems. |
| WSL2 | n/a (ship a Linux VM) | Rejected | Unacceptable UX and distribution footprint; files live inside a VM disk image, not accessible as a normal Windows drive. |

### 3.1 Why WinFsp

- **FUSE-compatible mental model.** WinFsp exposes an async-capable callback interface (`FileSystemInterface`) that maps almost one-to-one onto the `fuse3::Filesystem` trait the Linux backend already implements (see §6). This minimizes new concepts and lets `src/mount/windows/` mirror the structure of `src/mount/linux.rs`.
- **Production-proven.** WinFsp ships with a signed kernel driver and installer; rclone mount and sshfs-win rely on it at scale.
- **Rust bindings are first-class.** winfsp-rs provides safe wrappers (`FileSystemContext`, `FileSystemHost`), builds on a plain `windows-latest` CI runner without WinFsp installed, and delay-loads `winfsp.dll` at runtime so the binary starts (and can error gracefully) on machines without the driver.
- **Distribution story.** WinFsp's signed installer can be bundled or required as a documented prerequisite — a UX concern, not a code blocker.

## 4. Decision record (ADR)

- **Context:** rencfs needs a Windows mount backend; there is no FUSE on Windows.
- **Decision:** Use WinFsp via the `winfsp` crate, behind the `windows-mount` cargo feature, in a new `src/mount/windows/` module implementing the existing `MountPoint`/`MountHandleInner` traits. `encryptedfs` stays platform-neutral and untouched by the adapter.
- **Consequences:**
  - End users must install WinFsp (signed driver) — documented prerequisite, later bundled in an installer (epic task).
  - The adapter must translate POSIX-ish `FileAttr`/inode semantics to Windows file attributes/security descriptors (§5).
  - Linux behavior is unchanged: all Windows code is `cfg(target_os = "windows")`-gated, and the `MountPoint` trait is untouched.

## 5. POSIX → Windows semantic mapping spec

This is the heart of the port. The adapter translates between WinFsp callbacks and `EncryptedFs`; these mappings are decided here so the implementation is mechanical.

### 5.1 Identity and ownership

- `FileAttr.ino` (u64) maps to the WinFsp file index / `FileContext` key. Inode allocation and lifetime stay inside `encryptedfs` unchanged.
- `uid`/`gid` have no Windows meaning. The crate-level `UID`/`GID` resolve to `0` on Windows (this issue). The adapter reports a synthesized security descriptor (e.g. owner = current user SID, `Everyone:Full` DACL) or relies on WinFsp's default; POSIX `perm` bits map to the readonly file-attribute flag only (`!perm & 0o200 → FILE_ATTRIBUTE_READONLY`). Full ACL fidelity is explicitly out of scope.
- `rdev`, `flags`, `blksize` are dropped (no Windows counterpart).

### 5.2 Error mapping

`FsError` maps to `NTSTATUS` analogously to the current `errno` mapping in `mount/linux.rs`:

| `FsError` | errno (Linux) | NTSTATUS (Windows) |
|---|---|---|
| `NotFound` | `ENOENT` | `STATUS_OBJECT_NAME_NOT_FOUND` |
| `AlreadyExists` | `EEXIST` | `STATUS_OBJECT_NAME_COLLISION` |
| `InvalidInput` | `EINVAL` | `STATUS_INVALID_PARAMETER` |
| `PermissionDenied` | `EACCES` | `STATUS_ACCESS_DENIED` |
| `IsDirectory` / `NotADirectory` | `EISDIR` / `ENOTDIR` | `STATUS_FILE_IS_A_DIRECTORY` / `STATUS_NOT_A_DIRECTORY` |
| `NotEmpty` | `ENOTEMPTY` | `STATUS_DIRECTORY_NOT_EMPTY` |
| other / `Other(_)` | `EIO` | `STATUS_UNEXPECTED_IO_ERROR` |

### 5.3 Names and paths

- **Case sensitivity:** mount in WinFsp's case-**insensitive** mode (the Windows/Explorer expectation), and surface name-collision errors from `encryptedfs` as `STATUS_OBJECT_NAME_COLLISION`. The on-disk (encrypted, hashed) name storage is unaffected because directory entries are keyed by hash of the exact name; case-insensitive lookup is an adapter-level concern (normalized-compare over `read_dir` results) — to be finalized in the epic, defaulting to WinFsp's built-in case-insensitive matching.
- **Illegal characters:** reject names containing `<>:"/\|?*` and control chars with `STATUS_OBJECT_NAME_INVALID` at `create`/`rename` time.
- **Reserved DOS names:** reject `CON`, `PRN`, `AUX`, `NUL`, `COM1–9`, `LPT1–9` (and those names with any extension).
- **Length:** WinFsp supports long paths (not legacy `MAX_PATH`-bound) when the mount opts in; the adapter opts in. Plaintext component limit: 255 UTF-16 code units, matching NTFS. (The encrypted on-disk names are fixed-size hashes/encrypted blobs independent of this limit.)

### 5.4 Timestamps

Windows `FILETIME` (100 ns ticks since 1601) ↔ `SystemTime` conversions happen only in the adapter; `encryptedfs` keeps `SystemTime`. No core change.

### 5.5 Delete and rename semantics

Windows forbids deleting/renaming files with open handles unless opened with delete-sharing. The adapter implements WinFsp's `CanDelete`/`cleanup` with delete-pending semantics: a file deleted while open is marked and physically removed from `encryptedfs` when the last handle closes. This is adapter-local state; no core change.

### 5.6 Mount lifecycle

- `allow_root` / `allow_other` are FUSE-specific and become documented no-ops on Windows (documented in this issue).
- There is no `umount` command: unmount goes through `MountHandle::umount()` → WinFsp host unmount API. `mount::umount()` now returns `Unsupported` off Unix (this issue).
- Mount targets: both a drive letter (`X:`) and an empty NTFS directory mount point are supported by WinFsp; both are in the acceptance matrix.

## 6. Target architecture

```
                 ┌──────────────────────────┐
                 │  src/run.rs (CLI)        │
                 └────────────┬─────────────┘
                              │ create_mount_point()
                 ┌────────────▼─────────────┐
                 │  src/mount.rs            │
                 │  MountPoint/MountHandle  │
                 └─┬──────────────┬─────────┘
        cfg(linux) │   cfg(win)   │  cfg(other)
        ┌──────────▼─┐ ┌──────────▼───────┐ ┌──────────────┐
        │ mount/     │ │ mount/windows/ │ │ mount/       │
        │ linux.rs   │ │ WinFsp           │ │ dummy.rs     │
        │ fuse3      │ │ FileSystemContext│ │ (stub)       │
        └──────────┬─┘ └──────────┬───────┘ └──────────────┘
                   └──────┬───────┘
                 ┌────────▼────────┐
                 │  encryptedfs    │  (platform-neutral, unchanged)
                 └─────────────────┘
```

`src/mount/windows/` implements a WinFsp `FileSystemContext` whose callbacks delegate to `EncryptedFs`:

| WinFsp callback | EncryptedFs call |
|---|---|
| `get_volume_info` | static volume label + free space from data dir |
| `get_security_by_name` | `get_attr` by path lookup + synthesized SD (§5.1) |
| `open` / `create` | `open` / `create` |
| `read` / `write` | `read` / `write` |
| `flush` / `cleanup` / `close` | `flush` / delete-pending handling / `release` |
| `get_file_info` / `set_basic_info` | `get_attr` / `set_attr` |
| `set_file_size` | `set_attr` with size |
| `read_directory` | `read_dir` |
| `rename` | `rename` (with Windows overwrite/delete-pending rules) |
| `can_delete` / delete | `remove_file` / `remove_dir` |

Because WinFsp callbacks are synchronous and `EncryptedFs` is async, the adapter follows the same pattern as the Linux backend: drive calls onto the tokio runtime (block-on or a dedicated runtime handle), with `panic = "abort"` revalidated for the callback model (a panic in a callback must not unwind into the WinFsp dispatcher — the adapter catches and maps to `STATUS_UNEXPECTED_IO_ERROR`).

## 7. Build & dependency plumbing (done in this issue)

1. `libc` moved from unconditional to `[target.'cfg(unix)'.dependencies]`; `UID`/`GID` (`src/lib.rs`) and root-dir ownership (`src/encryptedfs.rs`) re-gated to `cfg(unix)`, returning `0` on Windows.
2. Optional `winfsp = "0.13"` dependency added under `[target.'cfg(target_os = "windows")'.dependencies]`, behind the new `windows-mount` cargo feature. It compiles without WinFsp installed (bundled import library) and delay-loads the driver DLL at runtime, so CI and library consumers (e.g. `java-bridge`) are unaffected unless they opt in. Building the feature needs `bindgen`'s libclang and the Windows SDK headers — both present on `windows-latest` runners (LLVM at `C:\Program Files\LLVM`).
3. `build.rs` emits the WinFsp `/DELAYLOAD` link flags when building for Windows with `windows-mount` (mirrors `winfsp::build::winfsp_link_delayload()`; reimplemented without a build-dependency so it also works when cross-compiling).
4. `mount::umount()` shell-out is `cfg(unix)`-only; off-Unix it returns `io::ErrorKind::Unsupported`.
5. `src/main.rs` gates the `run` CLI on `any(target_os = "linux", all(windows, feature = "windows-mount"))`, so the PoC is demonstrable as `rencfs mount -m X: -d <data-dir>` on Windows.
6. CI (`build_and_tests_reusable.yaml`): `windows-latest` now runs `cargo test --release --lib -- --skip keyring` plus `cargo check`/`clippy --features windows-mount` (with `LIBCLANG_PATH` pointing at the runner's LLVM), locking both the core and the WinFsp backend as Windows-clean.
7. Unit tests added for the gating (`UID`/`GID` platform consistency, `umount` failure paths) and for the semantic-mapping layer (`src/mount/windows_semantics.rs`: FILETIME round-trips incl. pre-1970 dates, attribute mapping, path splitting, Windows filename validation, case-insensitive comparison) — these run on every platform.

Deferred to the epic: making `fuse3` optional behind a `linux-mount` feature (Linux default unchanged to avoid regressions).

## 8. Testing strategy

1. **Compile gate:** `cargo check --target x86_64-pc-windows-msvc` (with and without `--features windows-mount`) — verified green on this branch (cross-checked with the full dependency tree, including `ring` and `bindgen`-generated WinFSP bindings). CI additionally runs `cargo check`/`clippy --features windows-mount` on `windows-latest`.
2. **Core unit tests on Windows:** `cargo test --release --lib` on `windows-latest` (added to CI in this issue).
3. **Semantic-mapping unit tests (all platforms):** the pure mapping layer (`src/mount/windows_semantics.rs`) is compiled under `cfg(test)` on every OS, so FILETIME conversion, attribute mapping, path/name rules, and case folding are covered by the regular `cargo test` runs on Linux/macOS/Windows.
4. **Integration tests:** existing `tests/rencfs_linux_itest.rs` stays Linux-only and must remain green (proves the abstraction wasn't broken). The epic adds `tests/rencfs_windows_itest.rs` mirroring it (create/read/write/rename/delete/dir listing through the mount point), `#[cfg(target_os = "windows")]`, on a CI job that installs WinFsp via `choco install winfsp`.
5. **Manual smoke matrix (epic acceptance):** `cargo build --features windows-mount` on a Windows machine with WinFsp installed, then `rencfs mount -m X: -d <data-dir>`; mount to a drive letter and to a directory mount point; edit a text file from Notepad/Explorer; verify ciphertext round-trip in the data dir; clean unmount; reopen after reboot; case-insensitivity and long-path checks.
6. **Cross-platform on-disk compatibility:** a vault created on Linux must open on Windows and vice versa (the on-disk format is already platform-neutral; this becomes an explicit epic test).

## 9. Task breakdown (follow-up epic)

Done in this issue (spike/PoC):

1. ✅ `src/mount/windows/`: `MountPoint`/`MountHandleInner` impl backed by WinFsp `FileSystemHost` (callbacks per §6, error mapping per §5.2, delete-pending per §5.5, case-insensitive lookup with normalized names per §5.3).
2. ✅ Adapter semantic layer: `src/mount/windows_semantics.rs` — attribute mapping, FILETIME conversion, filename validation, case-insensitive comparison, unit-tested cross-platform.
3. ✅ `build.rs` delay-load wiring + `--features windows-mount` binary path; `src/main.rs` Windows `run` flow (mount to drive letter or directory).
4. ✅ Windows CI: library unit tests on `windows-latest`; core stays `x86_64-pc-windows-msvc`-clean.

Remaining (full implementation):

1. CI: a WinFsp-installed job (`choco install winfsp`) for integration tests (the `cargo check`/`clippy --features windows-mount` gate on `windows-latest` is already in place).
2. `tests/rencfs_windows_itest.rs` + manual smoke matrix (§8.3–8.4): mount via WinFsp, round-trip encrypt/decrypt, concurrent I/O, case-insensitive lookups, long paths.
3. Cross-platform on-disk-format compatibility test (vault created on Linux opens on Windows and vice versa).
4. PoC hardening: path-resolution caching (the PoC resolves paths by walking from the root per operation), case-insensitive-create collision policy, free-space reporting from the data dir, performance pass on `read_directory`.
5. Distribution: document the WinFsp prerequisite; evaluate bundling the signed WinFsp installer / winget packaging.
6. Optional: `linux-mount`/`windows-mount` feature parity so headless consumers never build a mount backend.

## 10. Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| WinFsp requires a signed driver install on end-user machines | Distribution/UX friction | Document prerequisite; bundle signed installer (epic task 6) |
| Semantic mismatch (case sensitivity, ACLs vs mode bits, delete-while-open) could leak into the core FS | Linux regression | All mapping confined to the adapter (§5); Linux itests kept green as the gate |
| `panic = "abort"` release profile + WinFsp callback model | Process abort on adapter panic | Catch-and-map panics in callbacks; revalidate profile in epic task 1 |
| tokio runtime config vs synchronous WinFsp callbacks | Deadlock/latency | Dedicated runtime handle in the adapter (same pattern as the fuse3 backend) |
| Encrypted filename length vs Windows path limits | Overlong on-disk names | Already handled: on-disk names are fixed-size encrypted blobs; adapter enforces the 255-unit plaintext limit |

## 11. References

- WinFsp: <https://winfsp.dev> — design docs: <https://github.com/winfsp/winfsp/wiki/WinFsp-Design>
- winfsp-rs: <https://crates.io/crates/winfsp> / <https://docs.rs/winfsp>
- rclone mount (WinFsp in production): <https://rclone.org/commands/rclone_mount/>
- Dokany: <https://github.com/dokan-dev/dokany>
- ProjFS: <https://learn.microsoft.com/windows/win32/projfs/projected-file-system>
