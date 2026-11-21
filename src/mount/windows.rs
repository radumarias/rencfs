#![allow(dead_code)]
//! Windows mount support for rencfs (issue #3).
//!
//! Today rencfs mounts with FUSE on Linux only (`src/mount/linux.rs`); on every
//! other platform `src/mount/dummy.rs` answers with "Dummy implementation".
//! This module is the first Windows code in the tree that is actually tested:
//! the platform-independent adapter layer a WinFsp backend needs, plus the
//! `MountPointImpl` used on Windows until that backend lands.
//!
//! # Backend choice
//!
//! WinFsp is the recommended backend: it exposes a user-mode filesystem the
//! same way FUSE does on Linux, it is what the existing research notes
//! converge on, and it keeps the encrypted-filesystem layer untouched. Dokan
//! and a raw `windows-rs` + `std::fs` path were considered and rejected for
//! the first milestone (Dokan has a smaller Rust ecosystem; the raw path
//! cannot present a mountable drive without a kernel driver of its own).
//!
//! # WinFsp callback -> [`EncryptedFs`] mapping (verified against `main`)
//!
//! | WinFsp operation | `EncryptedFs` call | Notes |
//! |---|---|---|
//! | `GetFileInfo` / `Open` by path | [`WindowsFs::lookup`] (`find_by_name`) | exact match first, then a case-insensitive fallback: Windows is case-insensitive but case-preserving, rencfs names are case-sensitive |
//! | `SetEndOfFile` | [`WindowsFs::set_len`] (`set_len`) | logical EOF change only |
//! | `Cleanup` delete file / dir | [`WindowsFs::remove`] (`remove_file` / `remove_dir`) | deletion happens at cleanup, not at close |
//! | `Close` | `release` | handle release only, never deletion |
//! | `GetFileInfo` timestamps | [`filetime_to_system_time`] / [`system_time_to_filetime`] | FILETIME is 100 ns ticks since 1601-01-01 |
//! | `CreateFile` name checks | [`validate_windows_name`] | reserved device names (`CON`, `COM1`...), trailing dot/space, `< > : " / \ | ? *` |
//!
//! # What is NOT in this PR
//!
//! The WinFsp driver binding itself (a `winfsp` crate `FileSystem` impl
//! driving [`WindowsFs`]) is the remaining step and needs a Windows host with
//! WinFsp installed to develop and test; it cannot be verified from Linux.
//! [`MountPointImpl::mount`] therefore still errors on Windows, but with an
//! actionable message instead of the dummy's joke error, and everything
//! underneath it is covered by tests that run on every platform, including
//! `windows-latest` CI (see `.github/workflows/build_and_tests_reusable.yaml`).

use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{io, path::PathBuf};

use async_trait::async_trait;
use shush_rs::{ExposeSecret, SecretString};
use tracing::error;

use crate::crypto::Cipher;
use crate::encryptedfs::{EncryptedFs, FileAttr, FsError, FsResult, PasswordProvider, ROOT_INODE};
use crate::mount;
use crate::mount::{MountHandleInner, MountPoint};

/// Seconds between the FILETIME epoch (1601-01-01) and the Unix epoch.
const FILETIME_UNIX_EPOCH_DIFF_SECS: u64 = 11_644_473_600;
/// FILETIME ticks per second (1 tick = 100 ns).
const FILETIME_TICKS_PER_SEC: u64 = 10_000_000;

/// FILETIME value for the Unix epoch (1970-01-01T00:00:00Z).
const FILETIME_UNIX_EPOCH: u64 = FILETIME_UNIX_EPOCH_DIFF_SECS * FILETIME_TICKS_PER_SEC;

/// Convert a WinFsp FILETIME (100 ns ticks since 1601-01-01) to `SystemTime`.
/// Values before the Unix epoch saturate to [`UNIX_EPOCH`].
#[must_use]
pub(crate) fn filetime_to_system_time(filetime: u64) -> SystemTime {
    let secs = filetime / FILETIME_TICKS_PER_SEC;
    let nanos = (filetime % FILETIME_TICKS_PER_SEC) * 100;
    match secs.checked_sub(FILETIME_UNIX_EPOCH_DIFF_SECS) {
        #[allow(clippy::cast_possible_truncation)]
        Some(secs) => UNIX_EPOCH + Duration::new(secs, nanos as u32),
        None => UNIX_EPOCH,
    }
}

/// Convert a `SystemTime` to a WinFsp FILETIME (100 ns ticks since 1601-01-01).
/// Times before the Unix epoch saturate to 0.
#[must_use]
pub(crate) fn system_time_to_filetime(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration
            .as_secs()
            .saturating_add(FILETIME_UNIX_EPOCH_DIFF_SECS)
            .saturating_mul(FILETIME_TICKS_PER_SEC)
            .saturating_add(u64::from(duration.subsec_nanos() / 100)),
        Err(_) => 0,
    }
}

/// Reserved Windows device names (matched on the part before the first `.`,
/// case-insensitively). `COM10` and friends are *not* reserved.
const WINDOWS_RESERVED_BASE_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Whether a single path segment is a reserved Windows device name.
#[must_use]
pub(crate) fn is_reserved_windows_name(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or(name);
    WINDOWS_RESERVED_BASE_NAMES.contains(&base.to_ascii_uppercase().as_str())
}

/// Validate a single path segment against the Windows naming rules.
/// Returns the reason it is invalid, if any.
pub(crate) fn validate_windows_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("name is empty");
    }
    if name == "." || name == ".." {
        return Err("name cannot be '.' or '..'");
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Err("name cannot end with '.' or ' ' on Windows");
    }
    if name.chars().any(|c| {
        matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || c.is_control()
    }) {
        return Err("name contains a character forbidden on Windows");
    }
    if is_reserved_windows_name(name) {
        return Err("name is a reserved Windows device name");
    }
    Ok(())
}

/// Split a Windows path (`C:\data\docs\file.txt`, `\\?\C:\x`, `/data/docs/`,
/// or a relative path) into its segments, dropping empty segments and `.`.
#[must_use]
pub(crate) fn split_windows_path(path: &str) -> Vec<&str> {
    let mut path = path;
    // Extended-length path prefix `\\?\` first: `\\?\C:\x` still carries a
    // drive prefix underneath it.
    if let Some(rest) = path.strip_prefix(r"\\?\") {
        path = rest;
    }
    // Drive prefix, e.g. `C:` in `C:\data`.
    if path.len() >= 2 && path.as_bytes()[1] == b':' && path.as_bytes()[0].is_ascii_alphabetic() {
        path = &path[2..];
    }
    path.split(['\\', '/'])
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect()
}

/// The Windows adapter over [`EncryptedFs`].
///
/// This is the layer a WinFsp `FileSystem` implementation calls into: it
/// translates Windows path and naming semantics to inode operations, using
/// only the public [`EncryptedFs`] API, so it compiles and tests on every
/// platform without WinFsp installed.
pub(crate) struct WindowsFs {
    fs: Arc<EncryptedFs>,
}

impl WindowsFs {
    /// Wrap an open [`EncryptedFs`].
    pub(crate) fn new(fs: Arc<EncryptedFs>) -> Self {
        Self { fs }
    }

    /// Attributes of an inode.
    pub(crate) async fn get_attr(&self, ino: u64) -> FsResult<FileAttr> {
        self.fs.get_attr(ino).await
    }

    /// Look up `name` in directory `parent`.
    ///
    /// Exact match first (`find_by_name`); on a miss, a case-insensitive
    /// scan of the directory, because Windows lookups are case-insensitive
    /// while rencfs names are case-sensitive.
    pub(crate) async fn lookup(&self, parent: u64, name: &SecretString) -> FsResult<FileAttr> {
        if let Some(attr) = self.fs.find_by_name(parent, name).await? {
            return Ok(attr);
        }
        let wanted = name.expose_secret().to_ascii_lowercase();
        let entries = self.fs.read_dir_plus(parent).await?;
        for entry in entries {
            let entry = entry?;
            if entry.name.expose_secret().to_ascii_lowercase() == wanted {
                return Ok(entry.attr);
            }
        }
        Err(FsError::NotFound("no such file or directory"))
    }

    /// Resolve a Windows path (e.g. `C:\docs\file.txt`) to attributes,
    /// starting at the filesystem root. An empty path resolves to the root.
    pub(crate) async fn resolve_path(&self, path: &str) -> FsResult<FileAttr> {
        let mut ino = ROOT_INODE;
        for segment in split_windows_path(path) {
            validate_windows_name(segment).map_err(FsError::InvalidInput)?;
            let name = SecretString::from_str(segment)
                .map_err(|_| FsError::InvalidInput("invalid name"))?;
            ino = self.lookup(ino, &name).await?.ino;
        }
        self.fs.get_attr(ino).await
    }

    /// Change the logical size of a file (WinFsp `SetEndOfFile`).
    pub(crate) async fn set_len(&self, ino: u64, size: u64) -> FsResult<()> {
        self.fs.set_len(ino, size).await
    }

    /// Delete a file or directory (WinFsp `Cleanup` with delete pending).
    /// Directories go through `remove_dir`, files through `remove_file`.
    pub(crate) async fn remove(
        &self,
        parent: u64,
        name: &SecretString,
        is_dir: bool,
    ) -> FsResult<()> {
        if is_dir {
            self.fs.remove_dir(parent, name).await
        } else {
            self.fs.remove_file(parent, name).await
        }
    }
}

/// Windows mount point. Wires [`WindowsFs`] into the [`MountPoint`] trait.
///
/// The WinFsp driver binding is the remaining step (see the module docs), so
/// [`MountPoint::mount`] currently fails with an actionable error instead of
/// silently doing nothing.
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
        // Keep the fields alive until the binding exists; the password is
        // intentionally dropped here so it is not held past this point.
        let _ = self.password_provider.take();
        let _ = (
            &self.mountpoint,
            &self.data_dir,
            self.cipher,
            self.allow_root,
            self.allow_other,
            self.read_only,
        );
        Err(FsError::Other(
            "Windows mounting is not implemented yet: the WinFsp filesystem binding \
            still needs to be written on top of the WindowsFs adapter in \
            src/mount/windows.rs. Install WinFsp (https://winfsp.dev) and implement \
            the mapping table documented in that module.",
        ))
    }
}

pub(in crate::mount) struct MountHandleInnerImpl {}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        error!("Windows mount handle polled before a WinFsp backend exists");
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
    use crate::crypto::Cipher;
    use crate::encryptedfs::{CreateFileAttr, FileType};
    use crate::test_common::{create_attr, PasswordProviderImpl};
    use tempfile::TempDir;

    async fn test_fs() -> (TempDir, Arc<EncryptedFs>) {
        let dir = TempDir::new().unwrap();
        let fs = EncryptedFs::new(
            dir.path().to_path_buf(),
            Box::new(PasswordProviderImpl {}),
            Cipher::ChaCha20Poly1305,
            false,
        )
        .await
        .unwrap();
        (dir, fs)
    }

    async fn create_file(fs: &EncryptedFs, parent: u64, name: &str) -> FileAttr {
        fs.create(
            parent,
            &SecretString::from_str(name).unwrap(),
            create_attr(FileType::RegularFile),
            false,
            false,
        )
        .await
        .unwrap()
        .1
    }

    async fn create_dir(fs: &EncryptedFs, parent: u64, name: &str) -> FileAttr {
        fs.create(
            parent,
            &SecretString::from_str(name).unwrap(),
            CreateFileAttr {
                kind: FileType::Directory,
                perm: 0,
                uid: 0,
                gid: 0,
                rdev: 0,
                flags: 0,
            },
            false,
            false,
        )
        .await
        .unwrap()
        .1
    }

    #[test]
    fn filetime_conversions_match_known_values() {
        assert_eq!(system_time_to_filetime(UNIX_EPOCH), FILETIME_UNIX_EPOCH);
        assert_eq!(filetime_to_system_time(FILETIME_UNIX_EPOCH), UNIX_EPOCH);
        // 2024-01-01T00:00:00Z == 1704067200 Unix seconds.
        let y2024 = UNIX_EPOCH + Duration::from_secs(1_704_067_200);
        assert_eq!(system_time_to_filetime(y2024), 133_485_408_000_000_000);
        assert_eq!(filetime_to_system_time(133_485_408_000_000_000), y2024);
        // 1 tick = 100 ns.
        assert_eq!(
            filetime_to_system_time(FILETIME_UNIX_EPOCH + 10),
            UNIX_EPOCH + Duration::from_nanos(1_000)
        );
        // Before the Unix epoch saturates instead of underflowing.
        assert_eq!(filetime_to_system_time(0), UNIX_EPOCH);
        assert_eq!(
            system_time_to_filetime(UNIX_EPOCH - Duration::from_secs(1)),
            0
        );
        // Round-trip.
        let now = SystemTime::now();
        let round_tripped = filetime_to_system_time(system_time_to_filetime(now));
        assert!(now.duration_since(round_tripped).unwrap() < Duration::from_micros(1));
    }

    #[test]
    fn reserved_windows_names() {
        for name in [
            "CON", "con", "Con.txt", "PRN", "AUX", "NUL", "COM1", "com9", "LPT1", "lpt9",
        ] {
            assert!(is_reserved_windows_name(name), "{name} should be reserved");
        }
        for name in [
            "config", "COM10", "LPT10", "mycon", "CONTAIN", "file.txt", "nul2",
        ] {
            assert!(
                !is_reserved_windows_name(name),
                "{name} should not be reserved"
            );
        }
    }

    #[test]
    fn windows_name_validation() {
        for name in [
            "", ".", "..", "file.", "file ", "CON", "a<b", "a:b", "a\"b", "a|b", "a?b", "a*b",
        ] {
            assert!(
                validate_windows_name(name).is_err(),
                "{name:?} should be invalid"
            );
        }
        for name in ["file.txt", "my document", "a-b_c d", "COM10", "readme"] {
            assert!(
                validate_windows_name(name).is_ok(),
                "{name:?} should be valid"
            );
        }
    }

    #[test]
    fn windows_path_splitting() {
        assert_eq!(
            split_windows_path(r"C:\data\docs\file.txt"),
            ["data", "docs", "file.txt"]
        );
        assert_eq!(split_windows_path("/data/docs/"), ["data", "docs"]);
        assert_eq!(split_windows_path(r"\\?\C:\x"), ["x"]);
        assert_eq!(split_windows_path(r"relative\path"), ["relative", "path"]);
        assert_eq!(
            split_windows_path(r"mixed/sep\path"),
            ["mixed", "sep", "path"]
        );
        assert_eq!(split_windows_path(""), Vec::<&str>::new());
        assert_eq!(split_windows_path(r"\"), Vec::<&str>::new());
        assert_eq!(split_windows_path(r"C:\"), Vec::<&str>::new());
    }

    #[tokio::test]
    async fn adapter_lookup_set_len_remove_roundtrip() {
        let (_dir, fs) = test_fs().await;
        let wfs = WindowsFs::new(fs.clone());

        // Root resolves from an empty path and from a drive root.
        assert_eq!(wfs.resolve_path("").await.unwrap().ino, ROOT_INODE);
        assert_eq!(wfs.resolve_path(r"C:\").await.unwrap().ino, ROOT_INODE);

        let dir_ino = create_dir(&fs, ROOT_INODE, "docs").await.ino;
        let file_ino = create_file(&fs, dir_ino, "ReadMe.TXT").await.ino;

        // Backslash path + drive prefix resolve through the adapter.
        let attr = wfs.resolve_path(r"C:\docs\ReadMe.TXT").await.unwrap();
        assert_eq!(attr.ino, file_ino);

        // Windows lookups are case-insensitive: exact miss, case-insensitive hit.
        let name = SecretString::from_str("readme.txt").unwrap();
        assert_eq!(wfs.lookup(dir_ino, &name).await.unwrap().ino, file_ino);

        // set_len changes the logical size (WinFsp SetEndOfFile).
        wfs.set_len(file_ino, 10).await.unwrap();
        assert_eq!(wfs.get_attr(file_ino).await.unwrap().size, 10);

        // remove dispatches files to remove_file...
        wfs.remove(
            dir_ino,
            &SecretString::from_str("ReadMe.TXT").unwrap(),
            false,
        )
        .await
        .unwrap();
        assert!(wfs.lookup(dir_ino, &name).await.is_err());
        assert!(wfs.resolve_path(r"C:\docs\ReadMe.TXT").await.is_err());

        // ...and directories to remove_dir.
        wfs.remove(ROOT_INODE, &SecretString::from_str("docs").unwrap(), true)
            .await
            .unwrap();
        assert!(wfs.resolve_path(r"C:\docs").await.is_err());
    }

    #[tokio::test]
    async fn adapter_rejects_invalid_windows_paths() {
        let (_dir, fs) = test_fs().await;
        let wfs = WindowsFs::new(fs);
        assert!(wfs.resolve_path(r"C:\CON").await.is_err());
        assert!(wfs.resolve_path(r"C:\docs\..\secret").await.is_err());
        assert!(wfs.resolve_path(r"C:\no-such-dir\file.txt").await.is_err());
    }
}
