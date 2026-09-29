# Windows Support Implementation Research

## Overview

This document outlines the research and proposed architecture for adding native Windows support to rencfs. It is intentionally framed as research, not a claim that rencfs mounts on Windows today.

## Recommended Backend: WinFsp

[WinFsp](https://github.com/winfsp/winfsp) is the recommended Windows backend. It provides a user-mode filesystem framework that is the Windows equivalent of FUSE.

### Alternatives Considered

| Backend | Status | Notes |
|---------|--------|-------|
| WinFsp | Recommended | Active development, good Rust bindings via `winfsp-sys` |
| Dokan | Deprecated | Dokan 1.x is legacy; Dokan 2.x is a rewrite with limited adoption |
| CBFS | Commercial | Closed-source, licensing cost, no Rust bindings |
| Projected File System | Windows-only | Complex, requires kernel driver signing |

## Licensing and Attribution Checkpoint

rencfs is licensed `MIT OR Apache-2.0`. WinFsp is licensed GPLv3 **with a special FLOSS linking exception**, verified against WinFsp's [`License.txt`](https://github.com/winfsp/winfsp/blob/master/License.txt):

- The exception explicitly permits FLOSS software to link with the WinFsp DLL (`winfsp-a64.dll`, `winfsp-x64.dll`, `winfsp-x86.dll`, `winfsp-msil.dll`) without becoming subject to GPLv3, provided that:
  1. the software is distributed under a license satisfying the FSF Free Software Definition or the Open Source Definition — `MIT OR Apache-2.0` qualifies;
  2. the user interface and any user-facing documentation include the notice `WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos` and a link to the WinFsp repository;
  3. the software is not linked or distributed with proprietary (non-FLOSS) software.
- A commercial license is also available from the WinFsp author for proprietary use. It is **not** required for a FLOSS project such as rencfs.

**Decision**: WinFsp is usable by rencfs under the FLOSS exception. An implementation PR must carry the attribution notice (a small addition to the README/docs), and the project must not be distributed combined with proprietary software. No relicensing of rencfs and no license purchase is required.

## Proposed Architecture: `src/mount/windows.rs`

With the licensing checkpoint resolved via the FLOSS exception, the proposed architecture mirrors the existing `src/mount/linux.rs` pattern:

```
src/mount/
  mod.rs       — platform dispatch
  linux.rs     — FUSE implementation (existing)
  windows.rs   — WinFsp implementation (proposed)
  dummy.rs     — fallback for unsupported platforms (existing)
```

### Operation Mapping

| rencfs operation | Linux (FUSE) | Windows (WinFsp) |
|-----------------|-------------|-------------------|
| `init` | `fuse_operations::init` | `WinFsp::init` |
| `destroy` | `fuse_operations::destroy` | `WinFsp::destroy` |
| `lookup` | `fuse_operations::lookup` | `WinFsp::lookup` |
| `getattr` | `fuse_operations::getattr` | `WinFsp::getattr` |
| `read` | `fuse_operations::read` | `WinFsp::read` |
| `write` | `fuse_operations::write` | `WinFsp::write` |
| `mkdir` | `fuse_operations::mkdir` | `WinFsp::mkdir` |
| `rmdir` | `fuse_operations::rmdir` | `WinFsp::rmdir` |
| `unlink` | `fuse_operations::unlink` | `WinFsp::unlink` |
| `rename` | `fuse_operations::rename` | `WinFsp::rename` |
| `readdir` | `fuse_operations::readdir` | `WinFsp::readdir` |

## Windows Metadata Decisions

NTFS supports the following metadata that maps to rencfs needs:

| Metadata | NTFS Support | Notes |
|----------|-------------|-------|
| File size | Yes | Direct mapping |
| Created time | Yes | Direct mapping |
| Modified time | Yes | Direct mapping |
| Accessed time | Yes | Direct mapping |
| File attributes | Yes | Read-only, hidden, system, archive |
| Security descriptors | Yes | ACLs — not used by rencfs |
| Extended attributes | Yes | Not used by rencfs |
| Hard links | Yes | Not used by rencfs |
| Sparse files | Yes | Not used by rencfs |
| Compression | Yes | Not used by rencfs |
| Encryption (EFS) | Yes | Conflicts with rencfs encryption |

### Unsupported NTFS Features for First Milestone

- Reparse points
- Object IDs
- Volume mount points
- Directory change notifications (use polling instead)

## Build and CI Plan

### Build Shape

```toml
[target.'cfg(windows)'.dependencies]
winfsp-sys = "0.2"
windows-sys = { version = "0.59", features = ["Win32_Storage_FileSystem"] }
```

### CI Plan

Add a Windows runner to `.github/workflows/ci.yml`:

```yaml
windows:
  runs-on: windows-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - run: cargo check
    - run: cargo test
```

### Manual Smoke Test

1. Install WinFsp on a Windows host.
2. Build rencfs: `cargo build --release`
3. Create an encrypted directory: `rencfs mount C:\encrypted C:\mnt`
4. Write a file: `echo "test" > C:\mnt\test.txt`
5. Read it back: `type C:\mnt\test.txt`
6. Unmount: `rencfs unmount C:\mnt`

## Acceptance Criteria for First Implementation PR

A truthful first implementation PR must:

1. **Carry the WinFsp attribution notice** — include the FLOSS-exception copyright notice and repository link in the README and any user-facing documentation.
2. **Implement `src/mount/windows.rs`** with at minimum: `init`, `destroy`, `lookup`, `getattr`, `read`, `write`.
3. **Pass `cargo check` on Windows** without warnings.
4. **Pass `cargo test` on Windows** for the operations implemented.
5. **Include a manual smoke test** performed on a real Windows host with WinFsp installed.
6. **Document reliance on the WinFsp FLOSS exception** in the PR description.

## Open Questions

1. **Licensing**: Confirm the maintainer accepts the WinFsp FLOSS exception obligations (attribution notice, no proprietary mixing). No purchase or relicensing is required.
2. **Scope**: Should the first milestone support all operations, or a subset (read-only)?
3. **Testing**: Is there access to a Windows host for manual smoke testing?
4. **Timeline**: What is the expected timeline for the first implementation PR?

## References

- [WinFsp GitHub](https://github.com/winfsp/winfsp)
- [WinFsp License.txt (GPLv3 + FLOSS linking exception)](https://github.com/winfsp/winfsp/blob/master/License.txt)
- [winfsp-sys Rust bindings](https://crates.io/crates/winfsp-sys)
- [rencfs Linux mount implementation](https://github.com/radumarias/rencfs/blob/main/src/mount/linux.rs)
