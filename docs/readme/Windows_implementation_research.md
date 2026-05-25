# Windows support implementation research

This document outlines a practical first implementation path for adding Windows mount support in `rencfs`.

The goal is to describe a realistic phase-1 scope that can be implemented incrementally and tested on a Windows host.

## Scope and non-goals

Phase 1 scope:
- add a Windows-specific mount backend;
- reuse existing `EncryptedFs` behavior;
- support regular file and directory operations;
- document known limitations.

Phase 1 non-goals:
- full parity with Linux FUSE behavior;
- support for advanced NTFS features;
- production hardening and performance tuning.

## Backend recommendation

Preferred backend: [WinFsp](https://winfsp.dev/).

Rationale:
- mature user-space filesystem framework for Windows;
- Rust bindings are available via `winfsp`/`winfsp-sys`;
- closest conceptual model to current Linux FUSE-based mount flow.

Alternatives considered:
- Dokan: viable, but less aligned with current architecture and crate ecosystem in this repo;
- Projected File System (ProjFS): not a direct fit for encrypted read/write virtual filesystems.

## Licensing checkpoint

`rencfs` is dual-licensed `MIT OR Apache-2.0`. Before merging Windows runtime support:
- verify redistribution obligations for WinFsp runtime components;
- confirm attribution and installer guidance requirements;
- document any runtime prerequisites in release notes.

## Proposed module structure

Add a Windows mount module similar to Linux split:

```text
src/
  mount.rs
  mount/
    linux.rs
    windows.rs
```

`windows.rs` should:
- initialize a WinFsp filesystem host;
- translate WinFsp callbacks into `EncryptedFs` operations;
- normalize Windows path separators to internal path format;
- map internal errors to meaningful Windows status codes.

## Operation mapping

Initial callback support should focus on:
- create/open/close file;
- read/write with offset;
- create/read/remove directory entries;
- rename;
- metadata reads for file size/type and timestamps.

Unsupported operations in phase 1 should return explicit "not implemented" status.

## Metadata and behavior decisions

Phase 1 guidance:
- treat owner/group/Unix mode bits as unsupported or synthesized;
- support basic Windows timestamps where practical;
- keep symlink/reparse-point behavior out of initial scope;
- define deterministic handling for case-insensitive paths.

## Build and CI shape

Build gating:
- compile Windows-specific code only on `target_os = "windows"`;
- keep Linux behavior unchanged.

Suggested CI increment:
- add `cargo check --target x86_64-pc-windows-msvc`;
- defer runtime mount tests to a later Windows runner milestone.

## Local smoke test checklist (Windows host)

Prerequisites:
- WinFsp installed on host;
- Rust toolchain and Windows target installed.

Smoke test:
1. Build `rencfs` with Windows target.
2. Start mount command with a temporary mount point and data directory.
3. Create a text file, read it back, rename it, and delete it.
4. Create nested folders and list contents.
5. Unmount cleanly and verify encrypted data remains in backing directory.

## Acceptance criteria for first implementation PR

- Windows target compiles in CI;
- mount process starts and stops on a Windows machine with WinFsp installed;
- basic file and directory operations succeed in manual smoke testing;
- unsupported operations fail clearly without process crash;
- documentation lists prerequisites and phase-1 limitations.
