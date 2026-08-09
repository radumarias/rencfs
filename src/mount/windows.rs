// src/mount/windows.rs
//
// Windows native mount backend — milestone 1: compile-only adapter.
//
// Status: NOT YET FUNCTIONAL. This file compiles on Windows and lets the CLI
// reach the mount path, but `mount()` always fails with a controlled,
// explicit "not implemented" error. It follows the same `MountPoint` /
// `MountHandleInner` pattern used by `linux.rs` and `dummy.rs` so that the
// real WinFsp implementation can be dropped in without touching the rest of
// the codebase.
//
// See docs/readme/Windows.md for the full implementation plan.

use async_trait::async_trait;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::error;

use crate::crypto::Cipher;
use crate::encryptedfs::{FsError, FsResult, PasswordProvider};
use crate::mount;
use crate::mount::{MountHandleInner, MountPoint};

const NOT_IMPLEMENTED: &str = "Windows native mount is not yet implemented. \
    See docs/readme/Windows.md for the proposed WinFsp implementation path.";

/// Windows mount-point builder.
///
/// Milestone 1 only: `mount()` returns a controlled error so the CLI behaves
/// predictably on Windows until the WinFsp backend lands.
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
            mountpoint = %self.mountpoint.display(),
            "{}",
            NOT_IMPLEMENTED
        );
        Err(FsError::Other(NOT_IMPLEMENTED))
    }
}

/// Future returned when the mount handle is awaited.
///
/// Currently unreachable because `mount()` fails before creating a handle;
/// kept for trait completeness and for the future WinFsp host loop.
pub(in crate::mount) struct MountHandleInnerImpl {}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        error!("{}", NOT_IMPLEMENTED);
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            NOT_IMPLEMENTED,
        )))
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        Ok(())
    }
}
