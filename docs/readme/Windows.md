# Windows support research

The current mount implementation is split by platform:

- Linux uses `src/mount/linux.rs`, which adapts `EncryptedFs` to the `fuse3`
  raw filesystem interface.
- Non-Linux targets use `src/mount/dummy.rs`, which keeps the crate buildable
  but does not expose a mounted filesystem.

Native Windows support should therefore keep `EncryptedFs` as the storage and
crypto backend, then add a Windows-specific mount adapter beside the Linux one.

## Recommended direction

[WinFsp](https://winfsp.dev/) is the most practical Windows equivalent to FUSE
for this project. It provides a user-mode filesystem API, supports current
Windows versions, and is used by existing Windows filesystems such as
[SSHFS-Win](https://github.com/winfsp/sshfs-win).

The likely shape is:

1. Add `src/mount/windows.rs`.
2. Gate it behind `cfg(target_os = "windows")`.
3. Wrap `EncryptedFs` in a Windows adapter similar to `EncryptedFsFuse3`.
4. Map WinFsp callbacks to the existing async `EncryptedFs` operations.
5. Keep `dummy.rs` only for targets without a real mount backend.

## Open questions

- **Rust bindings:** The [`winfsp`](https://crates.io/crates/winfsp) crate and
  [`winfsp-rs`](https://github.com/SnowflakePowered/winfsp-rs) should be tested
  before committing to an API. If the bindings are incomplete, a thin local FFI
  layer may be needed for a proof of concept.
- **License:** WinFsp is GPLv3 with a special exception for FLOSS projects and
  also offers commercial licensing. Before a production implementation lands,
  the project should confirm whether this is compatible with rencfs' current
  `MIT OR Apache-2.0` licensing.
- **Async boundary:** WinFsp callbacks are synchronous from the filesystem
  point of view, while rencfs is built on async `tokio` APIs. The Windows adapter
  should own a runtime or use a controlled blocking bridge rather than creating
  a runtime per operation.
- **Windows metadata:** File attributes, timestamps, permissions, case
  sensitivity, reparse points, and directory enumeration semantics differ from
  Linux FUSE. The first implementation should document unsupported operations
  explicitly.

## Minimal proof of concept

A useful first pull request does not need full parity with Linux. The smallest
valuable slice is:

1. Compile natively on Windows with a real `windows.rs` mount module.
2. Mount a drive or directory with WinFsp.
3. Support creating, listing, reading, writing, and deleting regular files.
4. Return clear unsupported-operation errors for links, extended attributes,
   and advanced metadata.
5. Add a manual smoke-test checklist for Windows until CI has a WinFsp-capable
   runner.

## Manual smoke test

After installing WinFsp with developer files, run:

```powershell
cargo build --release
$env:RENCFS_PASSWORD = "test-password"
cargo run --release -- mount --mount-point X: --data-dir .\data
```

Then, from another PowerShell session:

```powershell
Set-Content X:\hello.txt "hello"
Get-Content X:\hello.txt
New-Item -ItemType Directory X:\dir
Get-ChildItem X:\
Remove-Item X:\hello.txt
```

The same data directory should remain encrypted on disk and readable again after
unmounting and remounting with the same password.
