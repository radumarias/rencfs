//! Windows mount backend (research milestone).
//!
//! This is a compile-only skeleton behind `cfg(target_os = "windows")`.
//! rencfs does **not** mount on Windows today: `mount()` returns a controlled
//! "not implemented" error so the CLI reaches the mount path and fails loudly
//! instead of silently doing nothing.
//!
//! The researched implementation path (see `docs/readme/Windows.md`) is WinFsp:
//! a future `WinFspAdapter` here would wrap the existing `EncryptedFs` layer
//! (the same layer `mount/linux.rs` drives through `fuse3`) and translate
//! WinFsp callbacks into `EncryptedFs` calls. No WinFsp dependency is added in
//! this milestone; this file intentionally depends only on crates the project
//! already uses.

use async_trait::async_trait;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::crypto::Cipher;
use crate::encryptedfs::{FsError, FsResult, PasswordProvider};
use crate::mount;
use crate::mount::{MountHandleInner, MountPoint};

#[allow(clippy::struct_excessive_bools)]
#[allow(dead_code)]
pub struct MountPointImpl {
    // Mirrors `dummy.rs`: fields are stored for the future WinFsp adapter;
    // `mount()` intentionally returns "not implemented" in this milestone.
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
        let _ = self.password_provider.take();
        Err(FsError::Other(
            "Windows mount is not implemented yet (see docs/readme/Windows.md for the WinFsp research plan)",
        ))
    }
}

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
