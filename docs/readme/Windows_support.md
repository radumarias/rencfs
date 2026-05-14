# Windows support research

This note sketches a native Windows path for rencfs. It is intentionally a
research and implementation plan, not a claim that mounting works on Windows
today. The current mount backend is Linux-only through `fuse3`; Windows should
use a dedicated backend that preserves the existing encrypted filesystem core.

## Recommended backend

The most practical first target is [WinFsp](https://winfsp.dev/). It provides a
FUSE-like userspace filesystem API for Windows and is widely used by projects
that need local drive mounting without writing a kernel driver.

Alternatives considered:

- **Dokan**: viable, but WinFsp has a closer FUSE migration story and clearer
  packaging for this use case.
- **Projected File System**: useful for virtualization, but it is not a general
  encrypted filesystem mount replacement.
- **Native minifilter driver**: powerful, but far too large and risky for a
  first milestone.

WinFsp is distributed under the GPLv3 with a special exception for filesystem
applications. Before shipping binaries, confirm the exact attribution and
redistribution requirements against rencfs' `MIT OR Apache-2.0` crate licensing.

## Build shape

Keep the dependency Windows-only so Linux builds remain unaffected:

```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = "..."
```

The initial implementation should live behind the existing mount abstraction:

```text
src/mount.rs
src/mount/linux.rs
src/mount/windows.rs
src/mount/dummy.rs
```

`src/mount/windows.rs` should implement the same `MountPoint` and
`MountHandleInner` contracts as the Linux backend. That keeps CLI and library
callers on `create_mount_point(...)` while switching only the platform adapter.

## Proposed architecture

```text
WinFsp callbacks
  -> Windows mount adapter
    -> path normalization and handle table
      -> EncryptedFs
        -> encrypted storage directory
```

The Windows adapter should be thin. It should translate WinFsp requests into the
existing `EncryptedFs` operations rather than duplicating encryption, metadata,
chunking, password, or WAL logic.

## Operation mapping

| WinFsp operation | rencfs target |
|---|---|
| create/open | `EncryptedFs` open/create helpers plus a Windows handle table |
| read | encrypted file read path with offset and length |
| write | encrypted file write path with offset and flush behavior |
| cleanup/close | release handle and flush pending metadata |
| get file info | map encrypted metadata to Windows attributes |
| read directory | enumerate decrypted directory entries |
| rename | encrypted metadata/path rename logic |
| delete | encrypted metadata/path delete logic |
| flush | persist file metadata and pending writes |

The first milestone can explicitly skip advanced NTFS behavior such as alternate
data streams, reparse points, hard links, sparse files, oplocks, ACL mapping, and
extended attributes. Returning clear "not supported" errors is preferable to
silently misrepresenting semantics.

## Metadata decisions

Windows needs file attributes and timestamps that do not perfectly match the
current Linux/FUSE path. For the first backend:

- expose directories and regular files only;
- map read-only from mount options first, not from decrypted per-file ACLs;
- preserve created/modified/accessed timestamps only if rencfs metadata already
  has a truthful source for them;
- normalize paths case-insensitively at the adapter boundary, while keeping the
  encrypted storage model unchanged;
- document unsupported NTFS-specific metadata clearly.

## CLI and mount behavior

The existing CLI command can remain:

```bash
rencfs mount --mount-point R: --data-dir C:\Users\me\rencfs-data
```

For Windows, `--mount-point` should accept either a drive letter such as `R:` or
an empty directory path. Startup should check that WinFsp is installed and return
a precise error when it is missing.

## CI and verification plan

1. Add a Windows compile-only job that builds the crate with the Windows mount
   module enabled.
2. Add adapter unit tests that do not require a live WinFsp mount.
3. Add a manual smoke-test checklist for a Windows host with WinFsp installed:
   - install WinFsp;
   - create a data directory;
   - mount to a drive letter;
   - create, read, rename, and delete a file;
   - unmount cleanly;
   - remount and verify persisted encrypted data.
4. Only after the adapter is stable, add an optional Windows integration job on
   a runner image where WinFsp can be installed safely.

## First implementation acceptance criteria

- `cargo check` continues to pass on Linux.
- `cargo check --target x86_64-pc-windows-msvc` reaches the Windows adapter
  without pulling Linux-only `fuse3` symbols.
- `rencfs mount` on Windows fails with a helpful "WinFsp is required" message
  until the real backend is enabled.
- The adapter has tests for path normalization, unsupported feature errors, and
  basic file attribute mapping.
- The README still states clearly that production mounting is Linux-only until
  the Windows backend is complete and manually verified.
