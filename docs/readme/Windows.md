# Windows support — implementation research (v0.13.78)

Status: research proposal. Grounded in a static read of rencfs `v0.13.78`
(`Cargo.toml`). No Windows host was available, so every Windows-specific
claim below is marked **VALIDATE-ON-WINDOWS** instead of asserted.
No implementation code is included in this PR on purpose: the goal is to
agree on the backend, the trait shape, and the acceptance bar first.

## 1. Current mount architecture (verified in source)

- `src/mount.rs:28` — `pub trait MountPoint` (+ `MountHandleInner`).
  This trait is the single integration point for any new backend.
- `src/mount.rs:80` — `pub fn create_mount_point(...)` factory that picks
  the backend at mount time; `src/mount.rs:100` free `umount`.
- `src/mount/linux.rs:23` — fuse3-based backend
  (`fuse3::raw::{Filesystem, MountHandle, Request, Session}`), converting to
  the project's `FileAttr` at the boundary.
- `src/mount/dummy.rs` — minimal trait-conformant stub; the shape a
  `windows.rs` should copy (struct + `impl MountPoint for ...`).
- `src/encryptedfs.rs` — backend-agnostic async API a Windows backend would
  consume without crypto changes: `new` (:582), `create` (:675),
  `read_dir` (:1048) / `read_dir_plus` (:1064), `get_attr` (:1278) /
  `set_attr` (:1313), `read` (:1370), `write` (:1603), `open` (:1791),
  `release` (:1477), `flush` (:1711), `rename` (:1992), `set_len` (:1858),
  `remove_file` (:963) / `remove_dir` (:886), `copy_file_range` (:1746).

## 2. Recommended backend: WinFsp (VALIDATE-ON-WINDOWS)

WinFsp (FUSE-compatible, file-system-proxy model) maps onto the existing
`MountPoint` trait the way `linux.rs` maps fuse3, so the Linux backend stays
the structural template.

Alternatives considered and rejected:
- Dokany — smaller community, driver-signing friction.
- Projected Filesystem (ProjFS) — virtualization-only semantics, wrong fit
  for a full encrypted filesystem.
- WSL2 passthrough — not native Windows.

**Licensing checkpoint (maintainer decision, not legal advice):** WinFsp is
GPLv3 with a historical FLOSS-exception path. Before linking, confirm the
exception covers an MIT/Apache-2.0 binary; otherwise ship WinFsp as an
external prerequisite (installer dependency, not linked) — the same pattern
as Linux FUSE (libfuse is a system dependency, not vendored). Record the
chosen model + attribution text here before any code lands.

**Installer story (VALIDATE-ON-WINDOWS):** pin the exact WinFsp version and
decide winget (`winfsp`) vs bundled MSI.

## 3. Dependency + build shape (no impact on other platforms)

- New deps live under `[target.'cfg(windows)'.dependencies]` only.
- Delay-load the WinFsp DLL via explicit dynamic loading (no static link),
  so non-Windows builds are byte-identical to today.
- CI: add a `windows-latest` job that **builds** and runs non-FUSE unit
  tests. Mounting tests stay Linux-only until a Windows runner with WinFsp
  exists.

## 4. Proposed `src/mount/windows.rs` architecture

New `WindowsMount: MountPoint` mirroring `linux.rs`: session-handle wrapper
(`MountHandleInner` equivalent), with `create_mount_point` gaining a
`#[cfg(windows)]` branch. Operation mapping (WinFsp callbacks →
`EncryptedFs`, VALIDATE-ON-WINDOWS for exact signatures):

| WinFsp callback      | `EncryptedFs` target(s)              |
|----------------------|--------------------------------------|
| Create / Open        | `create` / `open`                    |
| Read                 | `read`                               |
| Write                | `write`                              |
| SetInformation       | `set_attr` / `set_len`               |
| Cleanup / Close      | `release` / `flush`                  |
| DirectoryControl     | `read_dir_plus`                      |
| GetVolumeInfo        | static + cached attrs                |
| Rename               | `rename`                             |
| Delete               | `remove_file` / `remove_dir`         |

Error mapping: `FsError`/`FsResult` → NTSTATUS in one conversion module,
unit-tested **without** a mount.

## 5. Metadata decisions + explicitly deferred NTFS features

Support in milestone 1: basic attrs (size, times, readonly/dir flags) via
the existing `FileAttr` plumbing. Explicitly defer: ACLs/security
descriptors (restrictive default), alternate data streams (→ loud error),
compression/encryption flags (rencfs already encrypts at rest — document,
don't double-implement), reparse points/symlink subtleties (document
limits). Unsupported ops must fail **loudly**, never silently.

## 6. Manual smoke test (needs a Windows host + WinFsp)

1. `cargo build --target x86_64-pc-windows-msvc` green.
2. Install WinFsp → init test vault → mount drive letter → create dir/file,
   write 1 MB, read back, byte-compare → rename → delete → unmount →
   re-mount → verify integrity.
3. Negative: kill process mid-write → re-mount → vault opens, no silent
   corruption.

## 7. Acceptance criteria for a truthful first implementation PR

- [ ] `windows.rs` compiles on stable + the repo's pinned nightly,
      clippy-clean under the repo's `-Dwarnings`.
- [ ] Unit tests for NTSTATUS mapping + path/attr conversions (no mount).
- [ ] CI Windows job green (build + unit tests).
- [ ] Maintainer-reproduced smoke-test log attached (needs maintainer's
      Windows host).
- [ ] README + license-checkpoint record updated.
- [ ] Explicit NON-goals list (ADS, ACLs, ProjFS) so reviewers don't
      re-litigate scope.

## 8. What this document does NOT verify

WinFsp exact API signatures against a pinned version, installer behavior,
and the real mount smoke test — all need a Windows host and are marked
above rather than asserted. Line references above are against `v0.13.78`.
