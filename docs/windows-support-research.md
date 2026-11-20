# Windows support — implementation research

> Status: research only. This documents the path to a native Windows mount
> backend for rencfs; it does not claim Windows support exists today.

## 1. Filesystem driver backend

- **Recommended: WinFsp.** It is the de-facto FUSE-like layer on Windows,
  actively maintained, and used by sshfs-win, rclone mount, and similar tools.
  Its C API (`FSP_FILE_SYSTEM`) exposes callbacks that map closely to the FUSE
  operations already implemented for Linux in `src/mount/linux.rs`.
- **Alternative considered: Dokan / Dokany.** Similar goals but a more
  fragmented maintenance story and a different callback model. WinFsp is
  preferred for a FUSE-derived codebase because the operation model is closer.
- **FUSE compatibility shims** were considered and rejected for v1: an extra
  indirection layer complicates error mapping and memory lifetimes without a
  clear benefit.

## 2. Licensing checkpoint (important)

- rencfs is licensed `MIT OR Apache-2.0` (see the repository LICENSE files).
- WinFsp is **GPLv3 with a FLOSS exception** (plus a separate commercial
  license). Linking WinFsp into an MIT/Apache-2.0 binary needs a maintainer
  review: the FLOSS exception permits use by OSI-approved open-source projects
  under specific conditions, but this must be confirmed before distributing a
  WinFsp-linked build.
- Mitigation to document further: keep the WinFsp dependency Windows-only and
  dynamically loaded, so Linux/macOS builds are unaffected and the license
  boundary is explicit.

## 3. Windows-only dependency and delay-load build shape

- Add a `[target.'cfg(target_os = "windows")'.dependencies]` section in
  `Cargo.toml`, mirroring the existing Linux `fuse3` section, for the chosen
  Rust bindings (e.g. the `winfsp` crate or FFI bindings to `winfsp-x64.dll`).
- Gate the module like the current Linux/dummy split in `src/mount.rs`:
  `#[cfg(target_os = "windows")] mod windows;` with the existing `dummy`
  fallback for other non-Linux targets.
- Prefer **delay-loading** the WinFsp DLL so `rencfs` still starts (and prints
  a clear "WinFsp not installed" error) even when WinFsp is absent.

## 4. Proposed architecture

- Reuse the existing `MountPoint` trait in `src/mount.rs`
  (`new(...)` + `async fn mount(...) -> FsResult<MountHandle>`). Implement it in
  `src/mount/windows.rs` exactly as `src/mount/linux.rs` implements it today.
- The Windows implementation holds an `EncryptedFs` instance (the same core
  the Linux backend uses) and translates WinFsp callbacks into `EncryptedFs`
  methods. No encryption/storage core changes are expected for the first
  milestone.

## 5. Operation mapping (WinFsp → EncryptedFs)

| WinFsp callback | EncryptedFs method (intended) |
| --- | --- |
| GetVolumeInfo / GetVolumeParams | statfs-style info |
| Lookup | `find_by_name` |
| GetFileInfo / GetBasicInfo | `get_attr` |
| SetFileInfo (size) | `set_len` / `set_attr` |
| ReadDirectory | `read_dir` / `read_dir_plus` |
| Open | `open` |
| Read | `read` |
| Write | `write` |
| Create | `create` |
| Cleanup / Close | `release` / `flush` |
| SetFileInfo (rename) | `rename` |
| Delete | `remove_file` / `remove_dir` |

(Exact signatures must be confirmed during implementation; this is the
intended mapping, not a tested implementation.)

## 6. Windows metadata and unsupported NTFS features (v1)

- Map `EncryptedFs` inode metadata to WinFsp `FILE_INFO` (size, timestamps,
  file attributes).
- v1 explicitly does NOT promise: alternate data streams (ADS), Windows ACLs,
  symlinks/junctions, or case-sensitive directory support. These must be
  documented as unsupported in the first release.

## 7. Build / CI plan

- Add a `windows-latest` CI job that runs
  `cargo check --target x86_64-pc-windows-msvc` (compilation only, no mount
  test) so the Windows backend keeps compiling.
- Keep the Linux job as the only job that runs the full FUSE test suite.

## 8. Manual smoke test checklist (Windows host with WinFsp installed)

- [ ] `rencfs` starts and reports a clear error when WinFsp is missing.
- [ ] A volume mounts and basic read/write/copy works on plaintext files.
- [ ] Unmount is clean and the on-disk encrypted directory is not plaintext.

## 9. Acceptance criteria for a first implementation PR

- Linux builds remain unchanged and `cargo check` passes on Windows.
- The WinFsp license decision is recorded in the PR description.
- The unsupported-feature list is present in user-facing documentation.
