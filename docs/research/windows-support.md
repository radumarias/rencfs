# Windows support implementation research

> **Status: research only (reviewed 2026-09-15).** rencfs does **not** mount a filesystem
> on Windows today. The Windows build currently selects the dummy mount backend.
> This note is an implementation contract for a first native Windows mount backend;
> it is not a release promise or evidence of Windows runtime testing.

## Current code boundary

The research is deliberately separated from the code that exists today. This
table is the baseline an implementation PR must change and validate rather than
an indication that the items below already work on Windows.

| Area | Current behavior | Implementation consequence |
| --- | --- | --- |
| Platform dispatch | [`src/mount.rs`](../../src/mount.rs) selects `linux` only for Linux and selects `dummy` for every other target, including Windows. | Add a Windows-specific dispatch branch without changing the public `MountPoint` API. |
| Non-Linux mount backend | [`src/mount/dummy.rs`](../../src/mount/dummy.rs) returns `FsError::Other("Dummy implementation")` from `mount`. | Replace the Windows selection with a real backend; do not turn the dummy backend into a partial Windows implementation. |
| Encryption and storage | The Linux adapter already builds on [`EncryptedFs`](../../src/encryptedfs.rs). | Keep WinFsp code as an adapter over the same layer, so encrypted-file and metadata behavior remain shared. |
| Existing tests | Mount integration tests are Linux-specific (`tests/rencfs_linux_itest.rs`). | Add Windows unit coverage first, then a separate WinFsp-enabled integration job; do not represent cross-compilation as mount validation. |

On the current tree, Windows users can build non-mount functionality, but a
native mount request fails through the dummy backend. The Unix `umount` command
is likewise not a Windows unmount mechanism. Until a Windows backend supplies
its own lifecycle, the supported Windows workflow remains WSL as described in
the project documentation.

## Decision

Use [WinFsp](https://winfsp.dev/) through its native filesystem API as the first
Windows backend. WinFsp is a Windows filesystem-proxy framework with a mature
kernel driver and a user-mode API. It is the closest Windows counterpart to the
existing Linux FUSE adapter: the adapter translates filesystem callbacks and
keeps encryption and storage semantics in `EncryptedFs`.

The initial implementation should use a maintained Rust wrapper around the
WinFsp native API (or a thin, reviewed internal binding where the wrapper lacks
an operation). Do not make the encrypted filesystem depend on FUSE protocol
emulation if the native API can express the operation directly.

### Alternatives considered

| Option | Decision | Reason |
| --- | --- | --- |
| WinFsp native API | **Recommended** | Native Windows semantics, Windows service lifecycle, and a FUSE-like callback model. |
| WinFsp FUSE API | Not first choice | May reuse FUSE concepts, but makes Linux-specific request and inode assumptions leak into Windows. |
| Dokany | Fallback only | A viable FUSE-style framework, but requires a separate driver, binding, and lifecycle design. |
| ProjFS / Cloud Files | Not suitable | Virtualization APIs rather than a general writable encrypted filesystem backend. |
| WSL + Linux FUSE | Existing workaround | Useful for development, but it is not a native Windows mount and cannot satisfy Windows support. |

The choice must be revalidated immediately before implementation against the
selected wrapper's maintenance, supported WinFsp version, safety boundary, and
license terms.

## License and redistribution checkpoint

rencfs is licensed `MIT OR Apache-2.0`; adding a Windows backend must preserve
that choice for rencfs source. WinFsp is distributed separately and its driver,
installer, SDK headers/libraries, and any Rust binding may carry additional
license, attribution, notice, and redistribution requirements.

Before merging an implementation PR, the maintainer must:

1. Record the exact WinFsp version and the exact Rust wrapper/binding version.
2. Review their licenses and notices, including the conditions for distributing
   the WinFsp installer, driver, and DLLs with an rencfs release.
3. Decide whether users install WinFsp themselves or whether release artifacts
   bundle a bootstrapper. Do not silently bundle it.
4. Add required third-party notices and installer attribution to release assets.
5. Confirm that the chosen binding's license is compatible with `MIT OR
   Apache-2.0` and with the intended binary distribution model.

This is a release/legal review checkpoint, not legal advice. A successful `cargo
build` does not answer it.

## Build and dependency shape

The normal non-Windows build must not acquire a WinFsp dependency. Add the
binding only under a Windows target dependency section:

```toml
[target.'cfg(windows)'.dependencies]
winfsp = "<reviewed-version>"
windows-sys = { version = "<reviewed-version>", features = [
    "Win32_Foundation",
    "Win32_System_LibraryLoader",
] }
```

The final versions and feature list belong in the implementation PR after the
selected wrapper has been reviewed. Avoid putting the Windows dependency in the
unconditional `[dependencies]` table.

The binary should load the WinFsp DLL only when a Windows mount is requested.
This makes unrelated commands (for example, `--help`, password changes, and
library use that does not mount) usable on systems without WinFsp installed.
Use the wrapper's supported delay-load/dynamic-load mechanism where available;
do not hand-roll DLL loading without an audited ABI boundary. If the DLL is
unavailable, return an actionable error such as:

```text
Windows mounting requires WinFsp. Install a compatible WinFsp runtime and retry.
```

The implementation must document the supported WinFsp version range and
whether the Windows runtime, SDK, or both are needed for build and execution.

## Module architecture

Keep the public API in `src/mount.rs` unchanged. Platform dispatch should be
explicit rather than treating Windows as an unsupported platform:

```rust
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod dummy;
```

`src/mount/windows.rs` should own only the WinFsp-specific adapter and mount
lifecycle. It should construct and retain the same `EncryptedFs` layer used by
the Linux adapter; encryption, filename encoding, metadata persistence, key
handling, and encrypted-file behavior must not be duplicated in callback code.

Suggested components:

- `WindowsMountPoint`: stores the public mount configuration and validates the
  target path/drive-letter form accepted by WinFsp.
- `EncryptedFsWinFsp`: maps WinFsp callbacks to an `Arc<EncryptedFs>` and a
  Windows handle table.
- `WindowsFileHandle`: associates a WinFsp file context with the rencfs open
  file/directory state, access mode, delete-pending state, and synchronization.
- `MountHandleInnerImpl`: owns the dispatcher/filesystem host and implements
  orderly shutdown for both `MountHandle::umount` and its `Future` behavior.
- `error`: maps rencfs `io::Error` values to documented NTSTATUS/Win32 errors
  in one location, with tests for the important mappings.

Callbacks may originate on WinFsp-owned threads. The adapter must not block a
WinFsp dispatch thread on a Tokio executor in a way that can deadlock shutdown.
Choose and document one bridging strategy (a dedicated runtime/worker pool or a
carefully bounded blocking bridge), then exercise unmount while operations are
in flight.

## Operation mapping

The table below is the first-milestone mapping. Exact callback names depend on
the reviewed binding, but the observable behavior must remain this contract.

| WinFsp operation | rencfs responsibility | First-milestone behavior |
| --- | --- | --- |
| Create / Open | Resolve encrypted path; open or create through `EncryptedFs`; allocate file context. | Support files and directories; reject unsupported create dispositions clearly. |
| Cleanup / Close | Flush when required, release context, honor delete-on-close. | Close must be idempotent because Windows may send cleanup and close separately. |
| Read | Read plaintext from the encrypted file at the requested offset. | Respect EOF and partial reads. |
| Write | Write plaintext at offset through encrypted file operations. | Respect append/write-through flags as far as rencfs can faithfully support them. |
| Flush | Flush rencfs file state and backing storage. | Return a failure rather than falsely acknowledging a failed flush. |
| Get file information | Translate rencfs metadata into Windows file information. | Provide file/directory type, length, allocation size, and timestamps. |
| Set file information | Rename, truncate, and set supported timestamps/attributes. | Preserve atomicity expectations where practical; reject unsupported classes. |
| Read directory | Enumerate rencfs directory entries. | Return stable continuation results for a directory handle. |
| Can delete / Delete | Validate then perform deletion through rencfs. | Honor delete-pending semantics; reject non-empty directory deletion. |
| Get/Set security | Windows security descriptor callbacks. | Return an explicit unsupported/access-denied result initially; do not invent ACLs. |
| Reparse point / streams / EA | NTFS-specific metadata. | Explicitly reject; do not expose encrypted backing metadata. |

Error conversion is user-visible API. In particular, distinguish not found,
already exists, access denied, directory-not-empty, invalid name, not a
directory, is a directory, sharing violation, and disk/full-or-quota failures
where rencfs can identify them. Log the rencfs error before conversion without
logging passwords, plaintext paths, keys, or file contents.

## Windows metadata and naming policy

The first milestone should use a deliberately small, documented Windows surface:

- Treat the rencfs mount as case-sensitive unless and until case-insensitive
  lookup has an unambiguous encrypted-name design and tests. Do not silently
  fold Unicode case in the adapter.
- Validate Windows-invalid path components and reserved device names before
  they reach encrypted backing paths. Reject rather than rewrite names in a way
  that breaks round trips.
- Map timestamps using UTC and Windows-compatible precision. Do not claim that
  NTFS creation time or DOS attributes are persisted until their persistence
  format exists in `EncryptedFs`.
- Report normal file/directory attributes only. Archive, hidden, system,
  compression, sparse, offline, and integrity attributes are unsupported in the
  first milestone unless explicitly implemented and tested.
- Support neither alternate data streams, extended attributes, reparse points,
  hard links, named security descriptors, nor byte-range locks initially.
  Return a consistent documented Windows error for each unsupported feature.
- Apply the existing `read_only` option to all mutating callbacks, including
  create, write, truncate, rename, delete, and metadata changes.

Do not expose the encrypted backing directory as a substitute for Windows
metadata. Any metadata rencfs promises must be stored and authenticated by the
rencfs layer, not inferred from ciphertext filenames or backing filesystem
attributes.

## Test and CI plan

Keep the existing cross-platform compile/check matrix. Add a Windows job that
builds and runs unit tests for the Windows adapter without requiring a mounted
filesystem whenever possible. Mount integration tests require a Windows runner
with a compatible WinFsp runtime installed and therefore should be separate
from ordinary compile checks.

The implementation PR should add:

1. Unit tests for path validation, error conversion, file-information mapping,
   read-only rejection, and cleanup/close idempotency.
2. Windows-target compilation in CI (`cargo check --target x86_64-pc-windows-msvc`).
3. A privileged or self-hosted Windows integration job with WinFsp installed,
   marked separately so a missing driver cannot be mistaken for a passing test.
4. A test matrix covering at least current supported Windows, the pinned WinFsp
   version, and the Rust MSRV/current toolchain policy used by this repository.

## Manual Windows smoke test

Run this only on a disposable Windows host after installing the exact supported
WinFsp runtime. It is a checklist for the implementation PR, not verification
performed by this research change.

1. Build rencfs with the supported MSVC Rust target.
2. Create empty `data` and `mount` directories (or the documented drive-letter
   mount target).
3. Mount with a non-secret test password and confirm the mount appears in
   Explorer and PowerShell.
4. Create nested directories; create, read, append, seek, truncate, rename, and
   delete a file from both PowerShell and Explorer.
5. Verify that plaintext names and bytes are available through the mount but
   not readable as plaintext in `data`.
6. Attempt writes, rename, delete, and truncate through a read-only mount and
   confirm each is rejected.
7. Attempt unsupported streams, reparse points, and security changes and
   confirm they fail predictably without corrupting the mount.
8. Unmount while an application still has a file open; verify shutdown either
   completes safely or reports a documented busy error. Remount and check all
   previously committed data.
9. Reboot or terminate the test process during active writes only in a
   disposable test directory, then remount and inspect the resulting behavior.

Record Windows edition/build, architecture, Rust version, WinFsp version,
mount target type, and the exact commands/results with the implementation PR.

## Acceptance criteria for the first implementation PR

The implementation is ready to claim native Windows mount support only when:

- WinFsp installation/runtime requirements and licensing notices are documented.
- Windows selects `src/mount/windows.rs`; it no longer falls through to the
  dummy backend.
- Create/open/read/write/flush/close, directory enumeration, rename, delete,
  and truncate operate correctly against `EncryptedFs` in a real WinFsp mount.
- Unsupported Windows features fail explicitly and safely rather than being
  silently ignored or partially emulated.
- Read-only behavior, error mapping, and concurrent cleanup/unmount have
  automated coverage.
- The smoke test has passed on a supported Windows host with WinFsp installed.
- README and release notes state the exact supported Windows and WinFsp scope,
  including limitations; no documentation suggests that WSL is native support.

Until then, the truthful user-facing statement remains: rencfs mounts with FUSE
on Linux; Windows users may use the documented WSL workflow but do not have a
native rencfs mount backend.
