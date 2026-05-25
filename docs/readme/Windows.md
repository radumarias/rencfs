# Windows support research

Status: not implemented yet.

## Current state

- `src/main.rs` exits early on Windows.
- `src/mount.rs` routes non-Linux builds to a dummy backend.
- `Cargo.toml` only enables the mount backend on Linux.
- The crypto + storage layers are platform-agnostic.

## Suggested shape

- keep the encrypted on-disk format unchanged;
- add a `#[cfg(target_os = "windows")]` mount backend;
- use a Windows filesystem layer (likely WinFsp) instead of FUSE;
- keep `encryptedfs` as the core engine;
- add a Windows-specific unmount path.

## Early constraints

- WinFsp install/service may need admin rights;
- paths must stay UTF-16 safe;
- Linux-only semantics (`mode`, `xattr`, some symlink behavior) need explicit mapping;
- smoke tests should focus on CRUD + mount/unmount.

## Minimal milestone

1. compile on Windows;
2. mount a small encrypted dataset;
3. basic CRUD works;
4. graceful unmount;
5. docs + smoke test.
