# Windows Implementation Research & Architecture Proposal for rencfs

To port `rencfs` successfully to Windows, the architecture must transition from a Linux-centric FUSE model to a cross-platform abstraction layer. This document outlines the technical strategy, dependencies, and structural code refactoring required to implement native Windows support.

## 1. Core Windows Driver Selection: WinFSP vs. Dokany

For virtual file system development on Windows, two major frameworks exist: **WinFSP (Windows File System Proxy)** and **Dokany**. 

### Recommendation: WinFSP
WinFSP is highly recommended for `rencfs` due to the following structural advantages:
* **FUSE Compatibility Layer:** WinFSP includes a native C-level FUSE emulation layer. This minimizes the friction of mapping POSIX-like system calls to the Windows NT subsystem.
* **Rust Ecosystem Support:** The `winfsp` and `winfsp-rs` crates provide safe, actively maintained idiomatic Rust bindings to the underlying native API.
* **Performance:** WinFSP handles concurrent I/O throughput and memory mapping significantly better than older user-mode filesystems under heavy workloads.

## 2. Proposed Architectural Strategy

Currently, `rencfs` couples file system operation logic tightly with the Linux FUSE lifecycle. To support Windows cleanly, we must decouple the core encryption/decryption logic from the operating system platform loop.

### Phase 1: Establish a Unified Virtual File System Trait
We need to isolate the core file routing layer into a platform-agnostic Rust `trait`. This will allow both Linux FUSE and Windows WinFSP to share the exact same logical backend engine.

```rust
pub trait EncryptedFileSystem {
    fn init(&self) -> Result<()>;
    fn lookup(&self, parent: u64, name: &OsStr) -> Result<Entry>;
    fn getattr(&self, ino: u64) -> Result<FileAttr>;
    fn read(&self, ino: u64, fh: u64, offset: i64, size: u32, reply: &mut dyn ReplyData) -> Result<()>;
    fn write(&self, ino: u64, fh: u64, offset: i64, data: &[u8], reply: &mut dyn ReplyWrite) -> Result<()>;
}
```

### Phase 2: Platform-Specific Lifecycle Dispatch
Using Rust's conditional compilation macros (`#[cfg(target_os)]`), we can split the mounting and initialization sequence based on the compilation target.

```rust
#[cfg(target_os = "linux")]
pub fn mount_volume(mountpoint: &Path, fs: impl EncryptedFileSystem) {
    // Current Linux FUSE implementation loop
}

#[cfg(target_os = "windows")]
pub fn mount_volume(mountpoint: &Path, fs: impl EncryptedFileSystem) {
    // New Windows WinFSP implementation loop using winfsp::FileSystem
}
```

### Phase 2: Platform-Specific Lifecycle Dispatch
Using Rust's conditional compilation macros (`#[cfg(target_os)]`), we can split the mounting and initialization sequence based on the compilation target.

```rust
#[cfg(target_os = "linux")]
pub fn mount_volume(mountpoint: &Path, fs: impl EncryptedFileSystem) {
    // Current Linux FUSE implementation loop
}

#[cfg(target_os = "windows")]
pub fn mount_volume(mountpoint: &Path, fs: impl EncryptedFileSystem) {
    // New Windows WinFSP implementation loop using winfsp::FileSystem
}
```

### Phase 3: Refactor Core File Operations into Standalone Testable Functions

Currently, `stream_util.rs` contains the core buffer I/O primitives (`seek_forward`, `copy`, `fill_zeros`, `read`) that operate on raw `Read`/`Write`/`Seek` trait objects. Similarly, `encryptedfs.rs` tightly couples inode management, encryption state, and file I/O into the monolithic `EncryptedFs` struct.

To make these operations independently testable and platform-agnostic, the following functions should be extracted from their current tightly-coupled contexts into a new `src/buffer_ops.rs` module:

```rust
// src/buffer_ops.rs — Standalone, testable buffer operations

use std::io::{self, Read, Write, Seek, SeekFrom};

/// Reads exactly `len` bytes from `r` into `buf`, returning the slice read.
/// Panics if buf.len() < len.
pub fn read_into_buffer(r: &mut impl Read, buf: &mut [u8], len: usize) -> io::Result<usize> {
    let mut total_read = 0;
    while total_read < len {
        let n = r.read(&mut buf[total_read..len])?;
        if n == 0 { break; }
        total_read += n;
    }
    Ok(total_read)
}

/// Writes the contents of `data` into `w`, flushing on completion.
pub fn write_from_buffer(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    w.write_all(data)?;
    w.flush()
}

/// Copies `len` bytes from `r` to `w` using a caller-provided staging buffer.
pub fn buffered_copy(
    r: &mut impl Read,
    w: &mut impl Write,
    len: u64,
    staging: &mut [u8],
) -> io::Result<u64> {
    let mut remaining = len;
    while remaining > 0 {
        let to_read = std::cmp::min(staging.len() as u64, remaining) as usize;
        let n = r.read(&mut staging[..to_read])?;
        if n == 0 { break; }
        w.write_all(&staging[..n])?;
        remaining -= n as u64;
    }
    Ok(len - remaining)
}
```

**Refactoring targets in the existing codebase:**
| Current Location | Function | Refactoring Action |
|---|---|---|
| `stream_util::copy()` | Buffered stream copy with EOF handling | Extract buffer management into `buffered_copy()` |
| `stream_util::read()` | Fill-buffer read with EOF stop | Replace with `read_into_buffer()` |
| `stream_util::fill_zeros()` | Zero-fill writer | Extract as `write_zeros(w, len, staging)` |
| `encryptedfs.rs` L720–737 | Inline `File::create` + `sync_all` in `create()` | Decouple into `create_and_sync_file(path)` |
| `fs_util::open_atomic_write()` | Atomic write with Unix-only options | Gate Unix options with `#[cfg(unix)]` (already done), add Windows fallback |
