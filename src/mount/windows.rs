use async_trait::async_trait;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::error;

use crate::crypto::Cipher;
use crate::encryptedfs::{FileAttr, FileType, FsError, FsResult, PasswordProvider};
use crate::mount;
use crate::mount::{MountHandleInner, MountPoint};

/// Difference between the Windows FILETIME epoch (`1601-01-01T00:00:00Z`)
/// and the Unix epoch (`1970-01-01T00:00:00Z`) in 100-nanosecond intervals.
pub const WINDOWS_EPOCH_OFFSET_100NS: u64 = 116_444_736_000_000_000;

/// Windows File Attribute flags required by WinFsp `FSP_FSCTL_FILE_INFO`.
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

/// Canonical Windows `NTSTATUS` codes returned by WinFsp `FileSystemContext` callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WindowsNtStatus {
    Success = 0x0000_0000,
    InvalidHandle = 0xC000_0008,
    InvalidParameter = 0xC000_000D,
    AccessDenied = 0xC000_0022,
    ObjectNameNotFound = 0xC000_0034,
    ObjectNameCollision = 0xC000_0035,
    MediaWriteProtected = 0xC000_00A2,
    UnexpectedIoError = 0xC000_00E9,
    DirectoryNotEmpty = 0xC000_0101,
    NotADirectory = 0xC000_0103,
    FileTooLarge = 0xC000_0904,
}

impl WindowsNtStatus {
    /// Map `rencfs::encryptedfs::FsError` deterministically to a WinFsp `NTSTATUS`.
    #[must_use]
    pub const fn from_fs_error(err: &FsError) -> Self {
        match err {
            FsError::NotFound(_) | FsError::InodeNotFound => Self::ObjectNameNotFound,
            FsError::AlreadyExists => Self::ObjectNameCollision,
            FsError::AlreadyOpenForWrite | FsError::InvalidPassword => Self::AccessDenied,
            FsError::ReadOnly => Self::MediaWriteProtected,
            FsError::NotEmpty => Self::DirectoryNotEmpty,
            FsError::InvalidInodeType => Self::NotADirectory,
            FsError::InvalidFileHandle => Self::InvalidHandle,
            FsError::InvalidInput(_) | FsError::ParseIntError { .. } => Self::InvalidParameter,
            FsError::MaxFilesizeExceeded(_) => Self::FileTooLarge,
            FsError::Io { .. }
            | FsError::SerializeError { .. }
            | FsError::Other(_)
            | FsError::InvalidDataDirStructure
            | FsError::Crypto { .. }
            | FsError::Keyring { .. }
            | FsError::JoinError { .. } => Self::UnexpectedIoError,
        }
    }
}

/// Convert a Rust `SystemTime` into a Windows `FILETIME` (100-ns intervals since 1601-01-01).
#[must_use]
pub fn system_time_to_filetime(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(dur) => {
            let ticks = dur
                .as_secs()
                .saturating_mul(10_000_000)
                .saturating_add(u64::from(dur.subsec_nanos() / 100));
            WINDOWS_EPOCH_OFFSET_100NS.saturating_add(ticks)
        }
        Err(_) => WINDOWS_EPOCH_OFFSET_100NS,
    }
}

/// Convert a Windows `FILETIME` (100-ns intervals since 1601-01-01) into a Rust `SystemTime`.
#[must_use]
pub fn filetime_to_system_time(filetime: u64) -> SystemTime {
    let ticks_since_unix = filetime.saturating_sub(WINDOWS_EPOCH_OFFSET_100NS);
    let secs = ticks_since_unix / 10_000_000;
    let nanos = ((ticks_since_unix % 10_000_000) * 100) as u32;
    UNIX_EPOCH + Duration::new(secs, nanos)
}

/// Map `FileAttr` and read-only mount flag into WinFsp `FileAttributes`.
#[must_use]
pub const fn file_attr_to_windows_attributes(attr: &FileAttr, mount_read_only: bool) -> u32 {
    let base = match attr.kind {
        FileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
        FileType::RegularFile => FILE_ATTRIBUTE_ARCHIVE,
    };
    if mount_read_only || (attr.perm & 0o222 == 0) {
        base | FILE_ATTRIBUTE_READONLY
    } else if base == 0 {
        FILE_ATTRIBUTE_NORMAL
    } else {
        base
    }
}

/// Normalize a WinFsp backslash-delimited path (e.g. `\dir\sub\file.txt`) into
/// ordered path segments suitable for walking `EncryptedFs::find_by_name` from `ROOT_INODE`.
#[must_use]
pub fn split_winfsp_path(path: &str) -> Vec<&str> {
    path.split(['\\', '/'])
        .filter(|seg| !seg.is_empty() && *seg != ".")
        .collect()
}

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
        Err(FsError::Other(
            "Windows WinFsp backend requires winfsp runtime host initialization",
        ))
    }
}

#[allow(dead_code)]
pub(in crate::mount) struct MountHandleInnerImpl {}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        error!("Windows WinFsp mount handle is not yet attached to a live FSP_FILE_SYSTEM dispatcher");
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_winfsp_path_normalization() {
        assert!(split_winfsp_path("\\").is_empty());
        assert_eq!(
            split_winfsp_path("\\vault\\notes\\secret.txt"),
            vec!["vault", "notes", "secret.txt"]
        );
    }

    #[test]
    fn test_filetime_roundtrip() {
        let sample = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_700);
        let ft = system_time_to_filetime(sample);
        let restored = filetime_to_system_time(ft);
        assert_eq!(sample, restored);
    }

    #[test]
    fn test_fs_error_to_ntstatus_mapping() {
        assert_eq!(
            WindowsNtStatus::from_fs_error(&FsError::InodeNotFound),
            WindowsNtStatus::ObjectNameNotFound
        );
        assert_eq!(
            WindowsNtStatus::from_fs_error(&FsError::AlreadyExists),
            WindowsNtStatus::ObjectNameCollision
        );
        assert_eq!(
            WindowsNtStatus::from_fs_error(&FsError::NotEmpty),
            WindowsNtStatus::DirectoryNotEmpty
        );
        assert_eq!(
            WindowsNtStatus::from_fs_error(&FsError::ReadOnly),
            WindowsNtStatus::MediaWriteProtected
        );
    }
}
