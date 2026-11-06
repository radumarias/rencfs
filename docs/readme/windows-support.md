# Windows support: the native implementation path

> Research note for issue [#3](https://github.com/radumarias/rencfs/issues/3). This
> describes a path to a Windows mount for rencfs. It does not claim Windows works
> today: only the Linux mount exists, and everything below is unbuilt design.

## 1. Backend: WinFsp, and why not the alternatives

The mount layer needs a userspace filesystem driver Win32 understands. The realistic
options are WinFsp (a kernel driver plus a user-mode API), Dokan, and Callback File
System (CBFS).

WinFsp is recommended, on three properties that matter here rather than on popularity:

1. **The interface is a callback struct, not an RPC protocol.** `FSP_FILE_SYSTEM_INTERFACE`
   is a C vtable with one function per operation, which maps 1:1 onto the existing
   `EncryptedFs` methods. Dokan's interface is close but its callback set is smaller
   (no first-class `read_dir_plus`, weaker rename semantics), and CBFS is commercial
   with per-seat licensing.
2. **Status is returned as NTSTATUS from the callback**, so errors translate at the
   boundary and the object manager sees real Windows errors rather than a generic
   failure. That is what makes `FsError` mapping a design task instead of a hack.
3. **It is already the substrate for the Windows filesystems a Rust project is most
   likely to be compared with**, so the behaviour of `notepad`, `dir` and Explorer
   against it is a known quantity rather than something to discover.

Rejected: a WebDAV or SMB shim (advertises a network filesystem, so Windows applies
cache semantics and byte-range locking that rencfs does not model yet), and a
Cygwin/POSIX layer (mounts below the Win32 surface, so ordinary applications never see
it).

## 2. Licensing checkpoint, before any code

WinFsp ships under **GPLv3 with a FLOSS exception**: a GPL-licensed application may
link it freely, and a FLOSS-licensed one may link it on Windows-only builds without
the GPL infecting the rest. rencfs is `MIT OR Apache-2.0`, which qualifies for that
exception, but the condition is that rencfs stays free software and that the linkage is
documented. Consequences to record in `README.md` and the licence files:

- the WinFsp dependency is **build-time only for Windows targets**, and must not enter
  the default feature set of a Linux build;
- `THIRD-PARTY-NOTICES` needs the WinFsp notice and the exception text;
- the binary that links `winfsp-rs` is distributed under the project licence plus the
  WinFsp notice, not under GPL alone;
- **the installer, not rencfs, installs the driver**, and it may not be bundled into a
  pure-MIT artifact without carrying the notice.

WinFsp being installed is a runtime precondition, exactly as `fuse3` is today. The
mount must fail with a clear message and a link, never a raw `LoadLibrary` error.

## 3. Dependency and build shape

Windows-only, and behind `target.'cfg(windows)'.dependencies`:

```toml
[target.'cfg(windows)'.dependencies]
winfsp-rs = { version = "0.10", features = ["delayed-init"] }
windows = { version = "0.58", features = ["Win32_Storage_FileSystem", "Win32_Foundation"] }
```

Two constraints shape this:

- **`winfsp-rs` must be delay-loaded.** The DLL is absent on a machine without WinFsp,
  so the crate's `delayed-init` feature moves the load to first `mount()`, which lets
  `rencfs --version`, `--help` and the keyring paths run on a stock Windows box.
- **No TypeScript or Go bridge.** The existing `src/mount/linux.rs` binds `fuse3`
  directly; Windows binds `winfsp-rs` directly. The `EncryptedFs` layer is shared and
  unchanged, which is the property that keeps the two mounts honest.

CI needs a `windows-latest` job that installs WinFsp from the official MSI before
`cargo test`, and it must be **non-required** for the first milestone, since the
runner cannot exercise a real driver mount reliably inside a service session.

## 4. Module layout: `src/mount/windows.rs`

Mirrors `src/mount/linux.rs` rather than inventing a third structure:

```text
src/mount/windows.rs
  mod fsp            // FSP_FILE_SYSTEM_INTERFACE vtable: thin, no logic
  mod errors         // FsError -> NTSTATUS, the only place STATUS_* appears
  mod time           // FILETIME <-> SystemTime, integer only, bounds checked
  mod context        // FileContext (inode + handle) allocation and release
impl Mount for WindowsMount { fn mount(), fn unmount() }
```

- The vtable functions do argument validation and then call one `EncryptedFs` method.
  No crypto and no metadata decisions live in the vtable.
- `FileContext` carries `(ino, handle)` and is allocated in `open`/`create`, freed in
  `cleanup`. It is the Windows equivalent of the `fh` the Linux path passes through,
  and it is the object the generation check runs on.
- `EncryptedFs` is `async`; the WinFsp callbacks are not. Each callback builds the
  current Tokio handle and uses `block_on` for one call, with the same
  "mount has its own runtime, work is a single short await" rule the Linux path uses.

## 5. Callback to method mapping

| WinFsp callback | `EncryptedFs` | Notes |
| --- | --- | --- |
| `get_volume_info` | constants | fixed label, 255-char names, 4096 sector |
| `get_security_by_name` | `open` | resolve to inode, return attributes |
| `open` | `open` | allocate `FileContext`, apply `FILE_SUPERSEDE` semantics |
| `create` | `create` | reject when no write handle can be granted |
| `read` | `read(ino, offset, buf, handle)` | exact offset, short read at EOF |
| `write` | `write(ino, offset, buf, handle)` | `STATUS_NOT_SUPPORTED` on appends before M2 |
| `read_directory` | `read_dir` / `read_dir_plus` | `.` and `..` synthesised from the parent inode |
| `set_file_size` | `truncate` | |
| `rename` | `rename` | `ReplaceIfExists` honoured, `STATUS_OBJECT_NAME_COLLISION` otherwise |
| `cleanup`, `close` | `release` | `cleanup` frees the context, `close` is idempotent |
| `get_file_info` | `stat` | `statvfs` equivalents sized from the data dir |
| `set_basic_info`, `set_file_info` | `chmod`, `utimens` | read-only attributes that rencfs cannot store are refused, not faked |
| `flush` | no-op | rencfs writes through; documented, not silent |

## 6. Error mapping

The whole translation lives in `mod errors` and must be total. Indicative rows:

| `FsError` | NTSTATUS |
| --- | --- |
| `NotFound`, `InodeNotFound` | `STATUS_OBJECT_NAME_NOT_FOUND` |
| `AlreadyExists` | `STATUS_OBJECT_NAME_COLLISION` |
| `NotEmpty` | `STATUS_DIRECTORY_NOT_EMPTY` |
| `AlreadyOpenForWrite` | `STATUS_SHARING_VIOLATION` |
| `InvalidFileHandle` | `STATUS_INVALID_HANDLE` |
| `InvalidInput` | `STATUS_INVALID_PARAMETER` |
| `InvalidInodeType` | `STATUS_FILE_IS_A_DIRECTORY` or `STATUS_NOT_A_DIRECTORY` by the requested op |
| `InvalidPassword` | `STATUS_LOGON_FAILURE` |
| `Crypto` | `STATUS_CRC_ERROR` |
| `Io(ErrorKind::PermissionDenied)` | `STATUS_ACCESS_DENIED` |
| `Io(ErrorKind::UnexpectedEof)` | `STATUS_END_OF_FILE` |
| anything unmapped | `STATUS_UNEXPECTED_IO_ERROR`, and logged with the `FsError`'s `Display` |

Unmapped must be loud in the log, because a silent catch-all is how a filesystem ends
up returning the wrong error for a full disk.

## 7. Time and metadata

- `FILETIME` is 100 ns ticks since 1601-01-01 UTC, so conversion is integer arithmetic
  only: add the 11644473600 s epoch offset before scaling, and **bounds-check on the way
  in**, refusing values past `u64::MAX` as `STATUS_INVALID_PARAMETER` instead of
  wrapping.
- Attributes come from the inode type: directory, archive, read-only when the entry has
  no write permission. Time stamps come from the inode and are never invented.
- Two decisions belong to rencfs, not the platform, and must be stated in the note that
  lands with code: **case sensitivity** (rencfs is case-sensitive; the mount does not
  set `FILE_CASE_SENSITIVE_SEARCH` in M1, so a user who expects case-insensitive
  lookups gets a not-found, and that is documented), and **short names** (not
  generated in M1).

## 8. Explicitly unsupported in the first milestone

Alternate data streams, reparse points and symlinks, oplocks and opportunistic locks,
sparse files, and appends. Each returns a defined status rather than an approximation,
and the list is surfaced in `--help` and in `docs/readme/Functionality.md`.

## 9. Acceptance criteria for a truthful first implementation PR

A PR may call Windows "supported" only when all of these hold:

1. `cargo check --target x86_64-pc-windows-msvc` is clean with WinFsp absent.
2. `mod errors` and `mod time` carry `#[cfg(test)]` unit tests that run on **Linux**
   too, because neither depends on the driver: a total-mapping test asserting every
   `FsError` variant yields a status, and round-trip and overflow tests for `FILETIME`.
3. A manual smoke test on a Windows host with WinFsp installed, recorded in the PR with
   the exact commands: `dir` lists, `echo > f` creates, `del` deletes, Explorer
   navigation works, and a wrong password produces a clear failure rather than a hang.
4. The unsupported list above matches the code, checked by reading, not by intent.
5. `THIRD-PARTY-NOTICES` and `README.md` carry the WinFsp notice.
6. The Linux mount still builds and its tests still pass on the same commit.

Until all six are met the Windows job stays non-required in CI.
