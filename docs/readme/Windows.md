# Windows support research

Status: research only; not implemented yet.

## What exists today

- `src/main.rs` bails out on Windows.
- `src/mount.rs` routes non-Linux builds to a dummy backend.
- `Cargo.toml` currently gates the mount stack to Linux.
- `encryptedfs` is mostly platform-agnostic; the mount layer is the blocker.

## Recommended backend

Use **WinFsp** first.

Why:

- closest fit to the current FUSE-style mount model;
- mature user-mode filesystem stack;
- easier path to a truthful MVP than a raw NT kernel integration.

Alternatives to keep in mind:

- **Dokan**: similar role, but not the default recommendation here;
- **direct Win32/NT APIs**: more control, much more work.

## License / packaging checkpoint

Before shipping a Windows build:

- verify WinFsp redistribution terms;
- keep attribution notes in docs if required;
- decide whether WinFsp is a runtime dependency or an optional install step.

This repo is `MIT OR Apache-2.0`, so the dependency story must stay compatible.

## Proposed shape

- keep the encrypted on-disk format unchanged;
- add `#[cfg(target_os = "windows")] src/mount/windows.rs`;
- keep `encryptedfs` as the core engine;
- translate WinFsp callbacks into existing async file ops;
- add a Windows-specific unmount path;
- gate Windows-only code so Linux/macOS remain untouched.

## Callback → rencfs mapping

Likely mapping for the first pass:

- `create/open` → `create`, `open`, `open_directory`
- `read` → `read`
- `write` → `write`
- `flush/close` → `flush`, handle teardown
- `rename` → `rename`
- `unlink/rmdir` → delete helpers
- `readdir` → directory listing
- `getattr/setattr` → metadata translation

## Metadata decisions

Start simple:

- preserve inode/file contents + names;
- map POSIX-ish permissions to a stable Windows-friendly default;
- treat `mode`, `uid`, `gid`, `xattr`, and hardlink edge cases as out of scope for MVP;
- keep symlink behavior explicit, not accidental.

## Early constraints

- WinFsp install/service may need admin rights;
- paths must stay UTF-16 safe end-to-end;
- Windows drive-letter / mount-point semantics differ from FUSE;
- antivirus / Defender can affect smoke tests;
- long path support needs explicit attention.

## Build + CI plan

1. add a Windows backend module behind `cfg`;
2. make `cargo check` pass on Windows;
3. add a Windows CI job that builds only first;
4. add a smoke test that mounts, CRUDs, unmounts;
5. expand to read/write regression coverage after the MVP.

## Acceptance criteria for a first implementation PR

- compiles on Windows;
- mounts a small encrypted dataset;
- basic CRUD works;
- clean unmount works;
- no Linux regression;
- docs explain install/runtime limits.
