// src/mount/windows.rs
//
// Windows native mount backend — SKELETON / RESEARCH IMPLEMENTATION
//
// Status: NOT YET FUNCTIONAL. This file is a placeholder that compiles on Windows
// and documents the intended WinFsp integration path. It follows the same
// MountPoint / MountHandle trait pattern used by linux.rs so that the real
// implementation can be dropped in without touching the rest of the codebase.
//
// See docs/readme/Windows.md for the full design rationale.

use async_trait::async_trait;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::{error, info};

use crate::crypto::Cipher;
use crate::encryptedfs::{FsError, FsResult, PasswordProvider};
use crate::mount;
use crate::mount::{MountHandleInner, MountPoint};

// ---------------------------------------------------------------------------
// WinFsp integration notes (for the real implementation)
// ---------------------------------------------------------------------------
//
// Recommended crate: `winfsp` (winfsp-rs on crates.io)
//   https://crates.io/crates/winfsp
//
// Key steps for the real implementation:
//
// 1. Add `winfsp` as a Windows-only dependency in Cargo.toml:
//
//    [target.'cfg(target_os = "windows")'.dependencies]
//    winfsp = { version = "0.3", features = ["system"] }
//
// 2. Create a `RencfsWinFsp` struct that implements `winfsp::FileSystem`
//    (or the `FileSystemContext` trait, depending on the winfsp-rs version).
//    Delegate each callback to the existing `EncryptedFs` storage + crypto layer.
//
// 3. Operation mapping (WinFsp callback → rencfs EncryptedFs method):
//
//    | WinFsp callback          | rencfs method                                  |
//    |--------------------------|------------------------------------------------|
//    | get_volume_info          | statfs()                                       |
//    | get_security_by_name     | getattr() → synthesise Windows SECURITY_DESC   |
//    | open                     | open() / find_by_name()                        |
//    | close                    | release()                                      |
//    | read                     | read()                                         |
//    | write                    | write()                                        |
//    | flush                    | flush()                                        |
//    | get_file_info            | get_attr()                                     |
//    | set_basic_info           | set_attr() (timestamps + attributes)           |
//    | set_file_size            | set_len() / truncate via set_attr()           |
//    | rename                   | rename()                                       |
//    | create                   | create() (file or directory)                   |
//    | overwrite / overwrite_ex | create() with truncate                         |
//    | cleanup / delete         | remove_file() / remove_dir()                   |
//    | read_directory           | read_dir() / read_dir_plus()                   |
//    | get_dir_info_by_name     | find_by_name() within directory                |
//
// 4. Windows metadata decisions (first milestone — keep simple):
//    - All files: FILE_ATTRIBUTE_NORMAL; directories: FILE_ATTRIBUTE_DIRECTORY
//    - Owner SID: current process SID via GetTokenInformation
//    - NTFS permissions: world-readable security descriptor (R/W/X for owner,
//      R for others). Full ACL support is a follow-up milestone.
//    - Unsupported NTFS features for milestone 1:
//        * Alternate data streams (ADS)
//        * Hard links
//        * Reparse points / junctions
//        * Extended attributes
//        * Encrypted / compressed file attributes (NTFS-level; rencfs handles
//          its own crypto at the storage layer)
//
// 5. Drive-letter mount example:
//    winfsp::Service::run("rencfs", |_| {
//        let fs = RencfsWinFsp::new(data_dir, password_provider, cipher)?;
//        let host = winfsp::FileSystemHost::new(fs_params, fs)?;
//        host.mount(mountpoint)?;   // e.g. "Z:" or "C:\\mount\\rencfs"
//        host.start()
//    })
//
// ---------------------------------------------------------------------------

/// Windows mount-point builder. Currently a stub that fails at mount time with
/// a clear message directing users to the WinFsp research document.
#[allow(clippy::struct_excessive_bools)]
#[allow(dead_code)]
pub struct MountPointImpl {
    mountpoint: PathBuf,
    data_dir: PathBuf,
    password_provider: Option<Box<dyn PasswordProvider>>,
    cipher: Cipher,
    allow_root: bool,
    allow_other: bool,
    read_only: bool,
}

#[async_trait]
impl MountPoint for MountPointImpl {
    fn new(
        mountpoint: PathBuf,
        data_dir: PathBuf,
        password_provider: Box<dyn PasswordProvider>,
        cipher: Cipher,
        allow_root: bool,
        allow_other: bool,
        read_only: bool,
    ) -> Self {
        Self {
            mountpoint,
            data_dir,
            password_provider: Some(password_provider),
            cipher,
            allow_root,
            allow_other,
            read_only,
        }
    }

    async fn mount(mut self) -> FsResult<mount::MountHandle> {
        error!(
            "Native Windows mount is not yet implemented. \
             See docs/readme/Windows.md for the proposed WinFsp implementation path."
        );
        info!(
            mountpoint = %self.mountpoint.display(),
            "Windows WinFsp backend: not yet functional. \
             A real implementation would start a WinFsp FileSystemHost here."
        );
        Err(FsError::Other(
            "Windows native mount is not yet implemented. \
             See docs/readme/Windows.md for the WinFsp implementation roadmap.",
        ))
    }
}

/// Future returned when the mount handle is awaited — reports not-implemented.
pub(in crate::mount) struct MountHandleInnerImpl {}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        error!("Windows WinFsp backend: not yet functional.");
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        Ok(())
    }
}
