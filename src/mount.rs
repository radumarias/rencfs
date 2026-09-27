use crate::crypto::Cipher;
use crate::encryptedfs::{FsResult, PasswordProvider};
use async_trait::async_trait;
use futures_util::FutureExt;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
#[cfg(unix)]
use std::process;
use std::task::{Context, Poll};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::MountHandleInnerImpl;
#[cfg(target_os = "linux")]
use linux::MountPointImpl;

#[cfg(not(target_os = "linux"))]
mod dummy;
#[cfg(not(target_os = "linux"))]
use dummy::MountHandleInnerImpl;
#[cfg(not(target_os = "linux"))]
use dummy::MountPointImpl;

#[async_trait]
#[allow(clippy::module_name_repetitions)]
#[allow(clippy::struct_excessive_bools)]
pub trait MountPoint {
    #[allow(clippy::fn_params_excessive_bools)]
    fn new(
        mountpoint: PathBuf,
        data_dir: PathBuf,
        password_provider: Box<dyn PasswordProvider>,
        cipher: Cipher,
        allow_root: bool,
        allow_other: bool,
        read_only: bool,
    ) -> Self
    where
        Self: Sized;
    async fn mount(mut self) -> FsResult<MountHandle>;
}

#[allow(clippy::module_name_repetitions)]
pub struct MountHandle {
    inner: MountHandleInnerImpl,
}
impl MountHandle {
    pub async fn umount(self) -> io::Result<()> {
        self.inner.unmount().await
    }
}

impl Future for MountHandle {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_unpin(cx)
    }
}

#[async_trait]
pub(crate) trait MountHandleInner: Future<Output = io::Result<()>> {
    async fn unmount(mut self) -> io::Result<()>;
}
/// Available arguments
///
/// **`mountpoint`** where it wil mount the filesystem
/// **`data_dir`** the directory where the encrypted files will be stored  
/// **`password_provider`** the password provider  
/// **`cipher`** The encryption algorithm to use.
/// Currently, it supports these ciphers [`Cipher`]
///
/// **`allow_root`** allow root to access the file system (Unix only, ignored on Windows)
/// **`allow_other`** allow other users to access the file system (Unix only, ignored on Windows)
/// **`read_only`** Set FUSE filesystem read-only mount option, default is disabled.
#[must_use]
#[allow(clippy::fn_params_excessive_bools)]
#[allow(clippy::too_long_first_doc_paragraph)]
pub fn create_mount_point(
    mountpoint: &Path,
    data_dir: &Path,
    password_provider: Box<dyn PasswordProvider>,
    cipher: Cipher,
    allow_root: bool,
    allow_other: bool,
    read_only: bool,
) -> impl MountPoint {
    MountPointImpl::new(
        mountpoint.to_path_buf(),
        data_dir.to_path_buf(),
        password_provider,
        cipher,
        allow_root,
        allow_other,
        read_only,
    )
}

/// Best-effort unmount of the filesystem mounted at `mountpoint`.
///
/// On Unix this shells out to `umount(8)`, trying a normal unmount, then
/// force (`-f`), then lazy (`-l`).
///
/// On Windows there is no equivalent shell command: WinFsp volumes are
/// unmounted through the mount handle (see [`MountHandle::umount`]), so this
/// always returns [`io::ErrorKind::Unsupported`]. See
/// `docs/windows_support_research.md` for the Windows unmount design.
pub fn umount(mountpoint: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        // try normal umount
        if process::Command::new("umount")
            .arg(mountpoint)
            .output()?
            .status
            .success()
        {
            return Ok(());
        }
        // force umount
        if process::Command::new("umount")
            .arg("-f")
            .arg(mountpoint)
            .output()?
            .status
            .success()
        {
            return Ok(());
        }
        // lazy umount
        if process::Command::new("umount")
            .arg("-l")
            .arg(mountpoint)
            .output()?
            .status
            .success()
        {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("cannot umount {mountpoint}"),
            ))
        }
    }
    #[cfg(not(unix))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "cannot umount {mountpoint}: no system umount command on this platform, \
                 use MountHandle::umount instead"
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn umount_path_that_is_not_mounted_fails() {
        // a nonexistent path can never be a mountpoint, so this must fail on
        // every platform (Unix: `umount` exits non-zero, or is missing and the
        // spawn fails; elsewhere: Unsupported)
        let res = super::umount("/nonexistent/rencfs/mountpoint/that/is/not/mounted");
        assert!(res.is_err());
    }

    #[cfg(not(unix))]
    #[test]
    fn umount_is_unsupported_off_unix() {
        let err = super::umount("X:").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}
