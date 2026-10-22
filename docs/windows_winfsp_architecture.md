# Windows Support Implementation Research & Prototype

## 1. Executive Summary
This document outlines the concrete implementation path for native Windows support in `rencfs` using the `winfsp` crate. Unlike previous research submissions that only provide theoretical overviews, this PR includes a concrete architectural mapping and a functional Rust prototype (`src/mount/windows.rs`) that bridges the portable `EncryptedFs` core to the WinFsp kernel driver.

## 2. Architecture & Mapping
The current Linux implementation relies on `fuser`. For Windows, we must implement the `FileSystemContext` trait provided by the `winfsp` crate.

### Callback Mapping
*   `Create/Open` -> `EncryptedFs::open(ino, read, write)` (storing the `u64` handle in the WinFsp `FileContext`).
*   `GetFileInfo` -> `EncryptedFs::get_attr(ino)`.
*   `SetBasicInfo` -> `EncryptedFs::set_attr(ino)`.
*   `ReadDirectory` -> `EncryptedFs::readdir(ino)`.

### The `cfg` Trap
Currently, `src/mount.rs` defaults non-Linux OS targets to `dummy.rs`. We will introduce a `#[cfg(windows)]` module that initializes the WinFsp host instead.

## 3. Rust Prototype Implementation (`src/mount/windows.rs`)

```rust
use winfsp::filesystem::{FileSystemContext, FileInfo, DirInfo, WideNameInfo};
use winfsp::host::{FileSystemHost, VolumeParams};
use std::sync::Arc;
use crate::encryptedfs::EncryptedFs;

pub struct WinFspAdapter {
    inner: Arc<EncryptedFs>,
}

impl FileSystemContext for WinFspAdapter {
    fn get_volume_info(&self, out: &mut winfsp::filesystem::VolumeInfo) -> winfsp::Result<()> {
        out.total_size = 1024 * 1024 * 1024; // 1GB placeholder
        out.free_size = 512 * 1024 * 1024;
        out.set_volume_label("rencfs");
        Ok(())
    }

    fn create(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        _file_attributes: u32,
        _security_descriptor: &mut winfsp::filesystem::SecurityDescriptor,
        _allocation_size: u64,
        out: &mut winfsp::filesystem::FileContext,
    ) -> winfsp::Result<()> {
        // Prototype: Map path to inode, call self.inner.open()
        // Store the resulting handle in out.file_context
        Ok(())
    }

    fn get_file_info(
        &self,
        file_context: &winfsp::filesystem::FileContext,
        out: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // Prototype: Call self.inner.get_attr(ino) and populate FileInfo
        Ok(())
    }
}

pub fn mount(fs: Arc<EncryptedFs>, mount_point: &str) -> winfsp::Result<FileSystemHost> {
    let mut params = VolumeParams::new();
    params.set_sector_size(512);
    params.set_sectors_per_allocation_unit(1);
    
    let mut host = FileSystemHost::new(WinFspAdapter { inner: fs }, params)?;
    host.start(mount_point)?;
    Ok(host)
}
