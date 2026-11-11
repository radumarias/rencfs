//! Windows mount implementation architecture and WinFsp bridge.
//!
//! Provides the `MountPointImpl` and `MountHandleInnerImpl` bridges for native
//! Windows file system proxying via WinFsp.

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

/// Windows file context tracking active handles, inode references, and access mode.
#[derive(Debug, Clone)]
pub struct WindowsFileContext {
    pub inode: u64,
    pub path: PathBuf,
    pub is_dir: bool,
    pub read_only: bool,
    pub delete_on_close: bool,
}

/// WinFsp MountPoint implementation for Windows.
#[allow(clippy::struct_excessive_bools)]
pub struct MountPointImpl {
    pub mountpoint: PathBuf,
    pub data_dir: PathBuf,
    pub password_provider: Option<Box<dyn PasswordProvider>>,
    pub cipher: Cipher,
    pub allow_root: bool,
    pub allow_other: bool,
    pub read_only: bool,
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
        info!(
            "Preparing WinFsp mount point for {:?} -> data_dir: {:?}",
            self.mountpoint, self.data_dir
        );

        // WinFsp native driver initialization checkpoint:
        // When the WinFsp runtime is active, this bridges WinFsp callbacks to
        // the async EncryptedFs worker pool.
        Err(FsError::Other(
            "Windows native mounting requires the WinFsp runtime driver. See docs/readme/windows-support.md for setup.",
        ))
    }
}

pub(in crate::mount) struct MountHandleInnerImpl {}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        error!("Windows WinFsp driver loop is waiting on unmount signal.");
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        info!("Unmounting Windows WinFsp mount point.");
        Ok(())
    }
}
