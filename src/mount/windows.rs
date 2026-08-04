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

/// Windows mount backend (research placeholder).
///
/// Native Windows mounting is not yet functional. This module mirrors the
/// trait structure of [`super::linux`] so that the rest of the codebase
/// (CLI, `create_mount_point`, `MountHandle`) is platform-agnostic. It
/// compiles on `x86_64-pc-windows-msvc` and fails with a descriptive error
/// that points to the implementation research in
/// [`docs/readme/Windows.md`](../../docs/readme/Windows.md).
///
/// # Implementation plan (summary)
///
/// 1. Use [WinFsp](https://winfsp.dev/) via the `winfsp` crate (current
///    version `0.13.0+winfsp-2.1`), gated with
///    `[target.'cfg(target_os = "windows")'.dependencies]`.
/// 2. Implement a `RencfsHost` struct that wraps [`EncryptedFs`] and
///    implements `winfsp::FileSystemContext`.
/// 3. Map WinFsp callbacks to the existing [`EncryptedFs`] methods (see
///    the operation mapping table in `docs/readme/Windows.md`).
///
/// [`EncryptedFs`]: crate::encryptedfs::EncryptedFs
#[allow(dead_code)]
#[allow(clippy::struct_excessive_bools)]
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
        info!(
            mountpoint = %self.mountpoint.display(),
            data_dir = %self.data_dir.display(),
            "native Windows mounting is not implemented yet"
        );
        error!(
            "Native Windows mounting is a research deliverable for now. \
             See docs/readme/Windows.md for the WinFsp implementation plan."
        );
        Err(FsError::Other(
            "Native Windows mounting is not implemented yet. \
             See docs/readme/Windows.md for the WinFsp implementation plan.",
        ))
    }
}

/// Windows mount handle placeholder.
///
/// Kept as a thin type so that `MountHandle` in [`crate::mount`] remains
/// usable on all platforms. A real implementation will hold a WinFsp
/// `FileSystemHost` future here.
pub(in crate::mount) struct MountHandleInnerImpl {}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        Ok(())
    }
}
