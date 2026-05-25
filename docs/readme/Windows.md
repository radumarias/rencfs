# Windows support research

Windows mounting is not implemented yet.

This note captures a truthful first-pass plan for native Windows support, without
claiming runtime support today.

## Backend

Best fit: [WinFsp](https://winfsp.dev/).

Why:

- closest native analogue to FUSE on Windows;
- user-mode filesystem host + kernel driver;
- matches the current `EncryptedFs` → mount-adapter design.

## Not recommended for v1

- WebDAV → different semantics, network surface;
- WSL-only → not native Windows support;
- custom kernel work → too large for a first bounty-sized PR.

## Proposed shape

- keep `EncryptedFs` as the core;
- add `src/mount/windows.rs`;
- keep Linux backend unchanged;
- keep unsupported targets on the dummy path.

## Build / packaging

- gate WinFsp deps behind `cfg(target_os = "windows")`;
- prefer delay-load so missing WinFsp fails at runtime, not link-time;
- require separate WinFsp install for dev/CI initially.

## Acceptance for implementation PR

- mount/unmount on a Windows host with WinFsp installed;
- read/write basic files and dirs;
- clear error when WinFsp is missing;
- docs updated with install + smoke-test steps.
