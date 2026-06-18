# Windows Support Implementation Research

## Recommended Backend: WinFsp

**WinFsp** (Windows File System Proxy) is the recommended userspace filesystem backend for Windows.

- License: GPLv3 with a FLOSS exception (compatible with MIT/Apache-2.0 for use as a library)
- Mature, actively maintained, used by SSHFS-Win, Rclone, and others
- Provides both a native C API and FUSE compatibility layer

### Alternatives Considered

| Backend | Pros | Cons | Verdict |
|---------|------|------|---------|
| WinFsp | Proven, FUSE-compatible | GPL dependency check | ✅ Recommended |
| Dokany | BSD-licensed | Less actively maintained | ❌ |
| CBFS Connect | Commercial support | Proprietary, expensive | ❌ |

## Licensing Check

WinFsp is GPLv3 with a FLOSS exception. For an MIT OR Apache-2.0 project:
- Dynamic linking: ✅ Allowed under FLOSS exception
- Static linking: ⚠️ May require GPL compliance review
- **Recommendation**: Dynamic link via `winfsp` Rust crate (MIT-licensed bindings)

## Windows-Only Dependency Shape

```toml
[target.'cfg(windows)'.dependencies]
winfsp = "0.3"
windows-sys = { version = "0.52", features = ["Win32_Storage_FileSystem"] }

[target.'cfg(windows)'.build-dependencies]
winfsp-sys = "0.3"
```

Use `#[cfg(windows)]` guards for platform-specific code. Delay-load via conditional compilation.

## Proposed Architecture

```
src/mount/
├── mod.rs           # Platform-agnostic mount interface
├── fuse.rs          # Existing FUSE implementation (Linux/macOS)
└── windows.rs       # WinFsp-based implementation (Windows)
```

### Operation Mapping

| WinFsp Callback | rencfs Method | Notes |
|----------------|---------------|-------|
| GetVolumeInfo | `EncryptedFs::volume_info()` | Direct mapping |
| GetFileInfo | `EncryptedFs::getattr(path)` | Convert FileInfo to stat |
| Open | `EncryptedFs::open(path, flags)` | Map access flags |
| Read | `EncryptedFs::read(handle, offset, len)` | Direct mapping |
| Write | `EncryptedFs::write(handle, offset, data)` | Direct mapping |
| Create | `EncryptedFs::create(path, mode)` | Map creation flags |
| Cleanup/Close | `EncryptedFs::close(handle)` | Direct mapping |

## Windows Metadata Decisions

| Feature | Support | Notes |
|---------|---------|-------|
| File creation time | ✅ | WinFsp supports |
| Last access time | ⚠️ | Optional, perf impact |
| Alternate Data Streams | ❌ | Not supported |
| NTFS compression | ❌ | Not applicable |
| Sparse files | ⚠️ | Research needed |

## Changelog

- Initial Windows research document
- Identified WinFsp as recommended backend
- Documented license compatibility for MIT/Apache-2.0
- Proposed `src/mount/windows.rs` architecture
