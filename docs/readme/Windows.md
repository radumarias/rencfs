# Windows support — implementation research

> Status: **research only**. rencfs does **not** mount on Windows today.
> `src/mount/windows.rs` is a compile-only skeleton that returns a controlled
> "not implemented" error. This note documents the recommended path to a
> truthful first implementation PR.

## 1. Recommended backend: WinFsp

On Linux rencfs mounts through `fuse3` (libfuse). Windows has no native FUSE,
so the industry-standard choice is **WinFsp (Windows File System Proxy)**:

- It ships a FUSE-compatibility layer (`winfsp-x64.dll`), so the existing
  `EncryptedFs` bridge used by `src/mount/linux.rs` can be reused with minimal
  reshaping for milestone 1.
- If the FUSE-compat layer proves limiting, the fallback is WinFsp's native
  user-mode filesystem API with a thin `WinFspAdapter` in
  `src/mount/windows.rs` translating callbacks into `EncryptedFs` calls.

Alternatives considered and rejected:

| Alternative | Verdict |
|---|---|
| Dokany / WinFUSE | Smaller community, less maintained than WinFsp |
| WSL2 only | Not a native Windows mount; doesn't satisfy the issue |
| SMB loopback / network redirector | Hacky, poor permission semantics, hard to secure |
| Ports of libfuse alone | Still need a kernel driver on Windows — which is what WinFsp is |

## 2. Licensing / attribution checkpoint (maintainer must confirm)

WinFsp is GPL-licensed (GPLv3). rencfs is `MIT OR Apache-2.0`. To keep the
crate's licensing clean, the recommended shape is:

- **Do not bundle or redistribute** any WinFsp binary with rencfs.
- Treat WinFsp as a **user-installed prerequisite** (like the project already
  treats FUSE on Linux), loaded at runtime via delay-load / dynamic lookup so
  the rencfs binary itself links against nothing GPL'd.
- Document the requirement and attribution in this file and in the install
  docs; add a startup check that prints a clear "install WinFsp" error when
  its DLL is absent.
- Maintainer should confirm this reading (and the exact WinFsp version's terms)
  before merging any implementation PR — this note is research, not legal advice.

## 3. Dependency and build shape (Windows-only, milestone 1: zero new deps)

- This milestone adds **no new dependencies**: `windows.rs` uses only `std`,
  `async-trait`, `tracing`, and crate-internal types.
- When implementation starts, add the WinFsp bindings as a
  `[target.'cfg(windows)'.dependencies]` entry only, so Linux/macOS builds are
  unaffected.
- Never link WinFsp at build time; resolve it at runtime (delay-load style) so
  a stock build still compiles and runs everywhere, failing only at mount time
  on machines without WinFsp.

## 4. Proposed `src/mount/windows.rs` architecture

Follows the existing `src/mount.rs` trait split (`MountPoint`,
`MountHandleInner`), mirroring `linux.rs` / `dummy.rs`:

- `MountPointImpl` stores `mountpoint`, `data_dir`, `password_provider`,
  `cipher`, `allow_root`, `allow_other`, `read_only` — same fields as today.
- `mount()` (future): open `EncryptedFs` on `data_dir`, create the WinFsp
  adapter, mount at `mountpoint` (drive letter or directory), return
  `MountHandle`. Today: returns a controlled "not implemented" error.
- `MountHandleInnerImpl` drives unmount; today it is a no-op future.
- `mount.rs` wiring: `mod windows` under `cfg(target_os = "windows")`,
  `mod dummy` narrowed to `not(any(linux, windows))`, Linux path untouched.

## 5. WinFsp callback → `EncryptedFs` operation mapping (draft)

Based on the public methods in `src/encryptedfs.rs`:

| WinFsp callback | `EncryptedFs` method |
|---|---|
| Create / Open | `create` / `open` (return handle id) |
| Read | `read(ino, offset, size, handle)` |
| Write | `write(ino, offset, buf, handle)` (+ `set_len` for truncate) |
| GetFileInfo | `get_attr(ino)` |
| SetFileInfo (basic info / sizes) | `set_attr(ino, SetFileAttr)` / `set_len` |
| ReadDirectory | `read_dir(ino)` / `read_dir_plus(ino)` |
| Delete / Rename | `remove_file` / `remove_dir` / `rename` |
| Flush / Cleanup / Close | `flush(handle)` / `release(handle)` |
| CopyFileRange (if exposed) | `copy_file_range` |
| Volume info | Constants (same role as `STATFS` in `linux.rs`) |
| Security / ACL queries | No counterpart — see metadata decisions below |

## 6. Windows metadata decisions (first milestone)

- **No NTFS extras in milestone 1**: alternate data streams, ACLs beyond a
  fixed permissive descriptor, compression, EFS flag, reparse points/symlink
  full fidelity are explicitly out of scope; return "not supported" rather
  than corrupt data.
- Map uid/gid to a default owner SID; honor the `read_only` mount flag; fixed
  volume label (e.g. `rencfs`).
- Timestamps: atime/mtime/ctime from `FileAttr`; granularity differences are
  acceptable and documented.
- Filenames: Windows is case-insensitive but preserving — document that two
  names differing only by case in one directory are unsupported in milestone 1.

## 7. Build / CI plan

- Add a `windows-latest` CI job: `cargo check`, `cargo clippy`, `cargo test`
  (unit tests that don't need a mount). Install WinFsp on the runner via
  `choco install winfsp` once implementation PRs land; the research milestone
  needs no WinFsp on CI.
- Gate all WinFsp code behind `cfg(target_os = "windows")` so Linux/macOS CI
  stays green without it.

## 8. Manual smoke test (Windows host with WinFsp installed)

1. `cargo build --release` on the Windows host succeeds.
2. Running the CLI `mount` subcommand without WinFsp installed prints the
   "install WinFsp" error (no crash, no silent no-op).
3. With WinFsp installed (post-implementation): mount an empty `data_dir` to
   an unused drive letter, create/copy/read/delete a file, unmount cleanly,
   remount and verify contents decrypt identically.

## 9. Acceptance criteria for the first implementation PR

- [ ] Mounts a real directory on a Windows host with WinFsp installed (drive
  letter or mount directory), copied files round-trip byte-identical.
- [ ] No new dependencies outside `[target.'cfg(windows)'.dependencies]`;
  Linux build/CI unaffected.
- [ ] Unsupported NTFS features fail loudly, never silently.
- [ ] Includes the smoke-test evidence (steps above) in the PR description.
- [ ] Updates this note from "research" to "supported" with the tested WinFsp
  version.
