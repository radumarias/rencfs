# Windows Support — Implementation Research

Research for [rencfs#3](https://github.com/radumarias/rencfs/issues/3) · Opire bounty ($42)

> This document is intentionally framed as **research, not a claim that rencfs
> mounts on Windows today**. It documents the recommended path, the alternatives
> considered, the licensing checkpoint, the build shape, the proposed
> `src/mount/windows.rs` architecture, the WinFsp→`EncryptedFs` operation mapping,
> metadata decisions, and the acceptance criteria for a truthful first
> implementation PR.

---

## 1. Recommended backend: WinFsp

**Recommendation: [WinFsp](https://winfsp.dev/) (Windows File System Proxy).**

WinFsp is the de-facto standard for user-mode filesystems on Windows — the
closest equivalent to FUSE on Linux, which is what `src/mount/linux.rs` already
uses (via the `fuse3` crate). Choosing WinFsp keeps the architecture symmetric:
`EncryptedFs` (platform-independent, async) in the middle, one thin
platform adapter per OS around it.

**Why not the alternatives:**

| Alternative | Verdict |
|---|---|
| **Dokan / Dokany** | Viable second choice. Rust crates exist (`dokan` 0.3.1, `dokan-sys`). But Dokany has had slower release cadence and a smaller maintainer base than WinFsp; WinFsp is the more actively maintained and widely deployed option (used by SSHFS-Win, rclone's `rclone mount`, etc.). |
| **Windows Projected File System (ProjFS)** | Rejected for milestone 1. ProjFS is a *virtualization* API (placeholder/hydration model), not a general read/write filesystem API. Mapping an encrypted FUSE-style FS onto it would fight the API instead of using it. |
| **CBFS Connect / other commercial SDKs** | Rejected: commercial license, incompatible with an MIT/Apache-2.0 open-source project. |
| **SMB loopback / WebDAV server** | Rejected: wrong layer — emulates network shares, loses fidelity (locking, metadata), and adds a network stack for a local problem. |
| **WSL2-only** | Rejected: requires WSL2 installed; not a native Windows mount. |

**Rust binding choice:** the [`winfsp`](https://crates.io/crates/winfsp) crate
(currently `0.13.1+winfsp-2.1`, safe bindings over
[`winfsp-sys`](https://crates.io/crates/winfsp-sys) raw FFI). It exposes the
`FSP_FILE_SYSTEM_INTERFACE` operations as Rust traits, which maps cleanly onto
the existing adapter pattern in `src/mount/`.

---

## 2. Licensing / attribution checkpoint ⚠️

**Status: checkpoint for the maintainer — do not merge a Windows implementation
until this is resolved.**

- rencfs is licensed **`MIT OR Apache-2.0`** (`LICENSE-MIT`, `LICENSE-Apache-2.0`
  in the repo root).
- WinFsp itself is distributed under the **GPLv3** (with its installer/driver
  components under their respective terms; commercial licenses are also sold by
  the WinFsp author).
- The standard industry reading (same as FUSE): a user-mode filesystem talks to
  the WinFsp *driver* through a stable, documented IPC/API boundary and does
  **not** link GPL'd code into the rencfs binary — analogous to proprietary
  filesystems shipping on FUSE. Under this reading there is no license
  contamination of rencfs itself.
- **However**, this is a legal judgment call, not a technical one. The
  maintainer should explicitly confirm the interpretation before accepting a
  Windows PR, and the decision (plus a short rationale) should be recorded in
  this doc / the repo's licensing notes. If the answer is "no GPL-adjacent
  dependencies", the fallback is Dokany (license terms differ — re-evaluate at
  that point).

**Attribution:** the WinFsp project requests attribution in distributions that
bundle or require it; the installer story (section 7) should mention WinFsp and
link https://winfsp.dev.

---

## 3. Windows-only dependency & delay-load build shape

- Add to `Cargo.toml`:
  ```toml
  [target.'cfg(windows)'.dependencies]
  winfsp = "0.13"
  ```
  (plus `windows`/`windows-sys` only for the small pieces the adapter needs,
  e.g. security descriptors — keep the surface minimal).
- `src/mount.rs` today:
  ```rust
  #[cfg(target_os = "linux")] mod linux;
  #[cfg(not(target_os = "linux"))] mod dummy;
  ```
  becomes:
  ```rust
  #[cfg(target_os = "linux")] mod linux;
  #[cfg(target_os = "windows")] mod windows;
  #[cfg(not(any(target_os = "linux", target_os = "windows")))] mod dummy;
  ```
  The `dummy` module stays as the fallback for other platforms.
- **Delay-load:** the `winfsp` crate links against `winfsp_x64.dll` at load
  time. Two options, in order of preference:
  1. **Document the prerequisite** (simplest, standard practice): the Windows
     build requires the [WinFsp installer](https://winfsp.dev/rel/) (MSI) on the
     target machine — exactly like FUSE filesystems require WinFsp/FUSE
     installed. The binary fails fast with a clear message if the DLL is
     missing.
  2. **Explicit dynamic loading** (`libloading` + `winfsp-sys`): load
     `winfsp_x64.dll` at runtime so the same binary can print a friendly
     "install WinFsp" error instead of a Windows loader error. Nice-to-have;
     not required for milestone 1.
- No changes to the Linux build: all Windows code is behind `cfg(windows)`,
  and CI must verify the Linux build is unaffected (section 7).

---

## 4. Proposed `src/mount/windows.rs` architecture

Mirror the existing adapter pattern:

```
                  ┌─────────────────────┐
  WinFsp driver   │  src/mount/windows.rs│   platform adapter
  (kernel)  <────>│  FileSystem impl     │   (WinFsp callbacks)
                  │  (winfsp crate)      │
                  └─────────┬───────────┘
                            │  async bridge
                  ┌─────────▼───────────┐
                  │  EncryptedFs        │   platform-independent,
                  │  (existing, async)  │   unchanged
                  └─────────────────────┘
```

- `windows.rs` defines a struct (e.g. `WinFspFs`) holding `Arc<EncryptedFs>`
  (same ownership shape as `linux.rs`, which wraps the FS in its FUSE
  filesystem struct).
- It implements the `winfsp` crate's filesystem interface; each callback
  translates WinFsp parameters → `EncryptedFs` async methods → WinFsp
  `NTSTATUS`/out-params. Because WinFsp callbacks are synchronous and
  `EncryptedFs` is async, the adapter needs a small blocking bridge
  (e.g. `tokio::task::block_in_place` or a dedicated current-thread runtime
  handle captured at mount — same class of problem `linux.rs` already solves
  against the `fuse3` async API; follow the established pattern).
- Handle/inode bookkeeping: WinFsp identifies open files by context pointers;
  keep a `HashMap<u64, FileHandle>`-style table (the `linux.rs` adapter already
  maintains analogous state — reuse the approach).
- Mount lifecycle (`MountHandle`/`MountPoint` traits in `src/mount.rs`):
  implement `mount()` via `winfsp`'s filesystem start on a drive letter or
  directory mount point, and `umount()` via the corresponding stop call.

---

## 5. Operation mapping: WinFsp callbacks → rencfs methods

| WinFsp (`FSP_FILE_SYSTEM_INTERFACE`) | rencfs (`EncryptedFs`) | Notes |
|---|---|---|
| `GetVolumeInfo` | constants / config | Static volume label, serial, FS name (`"rencfs"`). |
| `GetSecurityByName` | `get_attr` (+ metadata) | Map `FileAttr` → `WIN32_FILE_ATTRIBUTE_DATA`; owner SID → local user SID for M1. |
| `Open` / `Create` | `open` / `create` (`CreateFileAttr`) | Translate `CreateOptions`/`FileAttributes`/`DesiredAccess` → rencfs open flags; `CreateDisposition` → create-vs-open semantics. |
| `Read` | `read` | Offset/length passthrough; WinFsp may issue short reads — loop not needed, return bytes read. |
| `Write` | `write` | Same; report bytes written. |
| `Close` | `close` / release handle | Drop handle-table entry. |
| `GetFileInfo` | `get_attr` | Size, times, attributes; see §6 for what M1 reports. |
| `SetBasicInfo` | `set_attr` (`SetFileAttr`) | Times + attributes subset (see §6). |
| `SetFileSize` | `set_attr` (size) / truncate | Map to rencfs truncate. |
| `CanDelete` / `Rename` | `rename` (+ pre-checks) | WinFsp splits the check (`CanDelete`) from the action; implement check via `get_attr`, action via `rename`. |
| `GetDirInfoByName` | `get_attr` (single entry) | — |
| `ReadDirectory` | readdir iterator | Reuse the `DirectoryEntryIterator` pattern from `linux.rs`; handle the WinFsp marker/pattern filtering. |
| `GetSecurity` / `SetSecurity` | M1: stub | Return a default DACL; full ACL mapping is out of scope for M1 (see §6). |
| `Flush` | `flush`/`sync` | Best-effort; rencfs crypto layer flush semantics. |
| `GetEa` / `SetEa` | M1: `STATUS_NOT_SUPPORTED` | EAs are NTFS-isms with no rencfs counterpart; revisit post-M1. |
| `Overwrite` | open-with-truncate + write | Compose from existing primitives. |

Error mapping: rencfs `FsError` → `NTSTATUS` (`STATUS_OBJECT_NAME_NOT_FOUND`,
`STATUS_ACCESS_DENIED`, `STATUS_DISK_FULL`, …). Centralize in one
`fs_error_to_ntstatus` function with unit tests.

---

## 6. Metadata decisions & unsupported NTFS features (Milestone 1)

**M1 reports a deliberately simple metadata model — truthful, not fake:**

- **Timestamps:** `EncryptedFs` file times → WinFsp create/access/write times.
  If the backend doesn't track one of them, report a fixed sensible value and
  *document* it (do not fabricate per-file values).
- **Attributes:** `FILE_ATTRIBUTE_DIRECTORY` / `ARCHIVE` / `READONLY` derived
  from `FileType` + rencfs permissions. `HIDDEN`/`SYSTEM` never set by M1.
- **Size:** from `FileAttr`; directories report 0.
- **Security:** default DACL granting the mounting user full access
  (`GetSecurity` returns a constructed descriptor; `SetSecurity` accepted but
  stored as no-op with a debug log). **No fake ACL enforcement** — document
  that M1 does not implement Windows ACLs.
- **File IDs:** stable 64-bit IDs derived from the rencfs inode/handle the way
  `linux.rs` derives `Inode`s — WinFsp uses them for its own caching; they must
  be stable for the mount lifetime.

**Explicitly unsupported in M1 (return `STATUS_NOT_SUPPORTED`, never silently
wrong):** NTFS alternate data streams, extended attributes, reparse points /
symlink-reparse interop, file compression/encryption flags, object IDs, hard
links beyond what `EncryptedFs` models, oplocks. Each gets a line in the
user-facing docs so Windows users aren't surprised.

---

## 7. Build / CI plan & manual smoke test

**Build:**
- `cargo build` on Linux must remain green and unchanged (Windows code is
  `cfg(windows)`-gated; add a CI job that at least runs `cargo check` so
  regressions in shared code are caught).
- Add a Windows CI job (`windows-latest`):
  - install WinFsp via the official MSI (choco: `choco install winfsp`,
    or download the release MSI in the workflow),
  - `cargo build --release`,
  - `cargo test` for the non-mount unit tests (the `fs_error_to_ntstatus`
    mapping tests, doc tests).
- Do **not** attempt automated mount tests on CI runners for M1 (mounting
  needs elevated privileges + a real WinFsp driver; flaky on shared runners).
  Gate automated mount tests behind an env var for self-hosted runners later.

**Manual smoke test (Windows host with WinFsp installed):**
1. `rencfs mount <encrypted-dir> X:` (drive-letter mount).
2. `dir X:` lists decrypted filenames; create a text file, write content,
   read it back — bytes identical.
3. Rename a file; delete a file; create a subdirectory and move a file into it.
4. Unmount (`rencfs umount` / Ctrl-C); remount; verify content persisted and
   filenames are still encrypted on disk in `<encrypted-dir>`.
5. Negative checks: opening a nonexistent path errors cleanly; writing past
   quota (if configured) returns disk-full, not a hang.

---

## 8. Acceptance criteria for a truthful first implementation PR

A PR may claim "Windows mount works" **only if all of the following hold**:

1. [ ] `cargo build --release` succeeds on Windows with WinFsp installed; `cargo build`/`cargo test` still green on Linux.
2. [ ] `src/mount/windows.rs` exists behind `cfg(target_os = "windows")`; `src/mount.rs` dispatches to it; `dummy` remains for other platforms.
3. [ ] The §5 operation mapping is implemented; every unimplemented op returns `STATUS_NOT_SUPPORTED` (audited — no silent wrong answers).
4. [ ] `fs_error_to_ntstatus` mapping has unit tests covering at least: not-found, access-denied, already-exists, disk-full, not-a-directory.
5. [ ] The §7 manual smoke test passes on a real Windows host; the PR description pastes the transcript (commands + outputs).
6. [ ] Docs updated: a `docs/windows.md` (or README section) stating the WinFsp prerequisite, install link, M1 limitations from §6, and the licensing checkpoint resolution from §2.
7. [ ] **No claim beyond what was tested.** In particular: no "full NTFS compatibility", no "ACL support", no performance claims without numbers.

---

*Prepared as research for rencfs#3. Implementation PR to follow after the
licensing checkpoint (§2) is confirmed by the maintainer.*
