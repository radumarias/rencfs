//! WinFsp-based mount backend for Windows (proof of concept for issue #3).
//!
//! This module is the Windows counterpart of `super::linux` (fuse3). It
//! implements the existing [`MountPoint`]/[`MountHandleInner`] traits, so the
//! public API (`mount::create_mount_point`) is identical on both platforms.
//!
//! Design notes (see `docs/windows_support_research.md` for the full spec):
//!
//! - The adapter implements [`winfsp::filesystem::FileSystemContext`] and
//!   delegates every callback to the platform-neutral
//!   [`crate::encryptedfs::EncryptedFs`]; POSIX → Windows translation lives in
//!   [`super::windows_semantics`].
//! - WinFsp callbacks are synchronous and run on WinFsp dispatcher threads,
//!   while `EncryptedFs` is async. Callbacks drive futures with
//!   [`tokio::runtime::Handle::block_on`] on the caller's runtime, so the
//!   process **must** run a multi-threaded tokio runtime (the `rencfs` binary
//!   and examples do).
//! - The [`winfsp::host::FileSystemHost`] is neither `Send` nor `Sync`, so it
//!   is owned by a dedicated host thread. The [`MountHandleInnerImpl`] (which
//!   backs the public `MountHandle`) controls it over channels, mirroring the
//!   lifecycle of the fuse3 backend.
//! - Delete-while-open follows Windows semantics: `set_delete` only marks the
//!   file context, and the actual removal happens in `cleanup` when WinFsp
//!   reports the last handle closing with the delete flag.

use std::ffi::c_void;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::thread::JoinHandle;

use async_trait::async_trait;
use shush_rs::{ExposeSecret, SecretString};
use tokio::runtime::Handle;
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, error, info, instrument, warn, Level};
use winfsp::constants::FspCleanupFlags;
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo,
    VolumeInfo, WideNameInfo,
};
use winfsp::host::{FileSystemHost, VolumeParams};
use winfsp::{FspError, Result as FspResult, U16CStr};

use crate::encryptedfs::{
    CreateFileAttr, EncryptedFs, FileAttr, FileType, FsError, FsResult, PasswordProvider,
    SetFileAttr, ROOT_INODE,
};
use crate::mount::windows_semantics as sem;
use crate::mount::{self, MountHandleInner, MountPoint};

// Win32 error codes (from `winerror.h`). `FspError::WIN32` maps these to the
// corresponding `NTSTATUS` values via `FspNtStatusFromWin32`, which keeps this
// adapter free of a direct `windows`-crate dependency.
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_WRITE_PROTECT: u32 = 19;
const ERROR_SHARING_VIOLATION: u32 = 32;
const ERROR_FILE_EXISTS: u32 = 80;
const ERROR_INVALID_NAME: u32 = 123;
const ERROR_DIR_NOT_EMPTY: u32 = 145;
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_FILE_TOO_LARGE: u32 = 223;
const ERROR_DIRECTORY: u32 = 267;

/// `STATUS_UNEXPECTED_IO_ERROR`, the catch-all for unmapped core errors.
const STATUS_UNEXPECTED_IO_ERROR: i32 = 0xC00000E9_u32 as i32;

// `CreateOptions` / `GrantedAccess` bits relevant to this adapter.
/// `FILE_DIRECTORY_FILE` — the create request targets a directory.
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
/// `GENERIC_READ` access mask bit.
const GENERIC_READ: u32 = 0x8000_0000;
/// `GENERIC_WRITE` access mask bit.
const GENERIC_WRITE: u32 = 0x4000_0000;

/// Virtual volume capacity reported by `get_volume_info` (1 TiB total,
/// 256 GiB free). The encrypted vault grows on demand inside the data
/// directory, so fixed virtual values are reported, like the Linux backend's
/// static `statfs` reply.
const VOLUME_TOTAL_SIZE: u64 = 1 << 40;
const VOLUME_FREE_SIZE: u64 = 1 << 38;

/// Maps a core [`FsError`] to a WinFsp error (research doc §5.2).
fn to_fsp_error(err: &FsError) -> FspError {
    match err {
        FsError::InodeNotFound | FsError::NotFound(_) => FspError::WIN32(ERROR_FILE_NOT_FOUND),
        FsError::AlreadyExists => FspError::WIN32(ERROR_FILE_EXISTS),
        FsError::InvalidInput(_) => FspError::IO(io::ErrorKind::InvalidInput),
        FsError::InvalidInodeType => FspError::WIN32(ERROR_DIRECTORY),
        FsError::InvalidFileHandle => FspError::IO(io::ErrorKind::InvalidInput),
        FsError::AlreadyOpenForWrite => FspError::WIN32(ERROR_SHARING_VIOLATION),
        FsError::NotEmpty => FspError::WIN32(ERROR_DIR_NOT_EMPTY),
        FsError::ReadOnly => FspError::WIN32(ERROR_WRITE_PROTECT),
        FsError::MaxFilesizeExceeded(_) => FspError::WIN32(ERROR_FILE_TOO_LARGE),
        FsError::Io { source, .. } => FspError::IO(source.kind()),
        other => {
            debug!(err = %other, "unmapped encrypted-fs error");
            FspError::NTSTATUS(STATUS_UNEXPECTED_IO_ERROR)
        }
    }
}

fn secret_name(name: &str) -> FspResult<SecretString> {
    SecretString::from_str(name).map_err(|_| FspError::WIN32(ERROR_INVALID_NAME))
}

/// Fills a WinFsp [`FileInfo`] from core [`FileAttr`].
fn file_info_from_attr(attr: &FileAttr) -> FileInfo {
    FileInfo {
        file_attributes: sem::file_attributes(attr),
        reparse_tag: 0,
        allocation_size: sem::allocation_size(attr.size),
        file_size: attr.size,
        creation_time: sem::system_time_to_filetime(attr.crtime),
        last_access_time: sem::system_time_to_filetime(attr.atime),
        last_write_time: sem::system_time_to_filetime(attr.mtime),
        change_time: sem::system_time_to_filetime(attr.ctime),
        index_number: attr.ino,
        hard_links: 0,
        ea_size: 0,
    }
}

/// Fills an [`OpenFileInfo`]: file information plus the normalized
/// (actual-casing) path WinFsp needs for case-insensitive volumes.
fn set_open_file_info(file_info: &mut OpenFileInfo, attr: &FileAttr, normalized: &str) {
    *file_info.as_mut() = file_info_from_attr(attr);
    let wide: Vec<u16> = normalized.encode_utf16().collect();
    file_info.set_normalized_name(&wide, Some(u16::from(b'\\')));
}

/// Events driving the lifecycle of the WinFsp host thread.
enum HostEvent {
    /// `MountHandle::umount` was called: stop the dispatcher and unmount.
    UnmountRequested,
    /// WinFsp reported the dispatcher stopped (e.g. external unmount).
    DispatcherStopped,
}

/// The WinFsp filesystem context delegating to [`EncryptedFs`].
struct EncryptedFsWinfsp {
    fs: Arc<EncryptedFs>,
    rt: Handle,
    read_only: bool,
    stopped_tx: StdMutex<Option<Sender<HostEvent>>>,
}

/// Per-open-handle state (`FileSystemContext::FileContext`).
#[derive(Debug)]
struct WinfspFileContext {
    ino: u64,
    kind: FileType,
    /// The `EncryptedFs` file handle (regular files only).
    fh: Mutex<Option<u64>>,
    /// Driver-managed directory enumeration buffer (directories only).
    dir_buffer: DirBuffer,
    /// Set by `set_delete`, acted on in `cleanup` (Windows delete semantics).
    delete_pending: AtomicBool,
}

impl EncryptedFsWinfsp {
    /// Drives a future to completion on the caller's tokio runtime. Called
    /// from WinFsp dispatcher threads, never from within the runtime itself.
    fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.rt.block_on(future)
    }

    /// Resolves an absolute WinFsp path to its attributes. This is an
    /// inode-based core, so resolution walks the components from the root;
    /// `.` components are skipped and `..` resolves through the directory
    /// listing (the core stores `..` entries pointing at the parent).
    async fn resolve(&self, path: &str) -> FsResult<Option<(FileAttr, String)>> {
        let mut attr = self.fs.get_attr(ROOT_INODE).await?;
        let mut normalized = String::new();
        for component in sem::split_win_path(path) {
            if component == "." {
                continue;
            }
            let Some((child, actual_name)) = self.find_child(attr.ino, component).await? else {
                return Ok(None);
            };
            normalized.push('\\');
            normalized.push_str(&actual_name);
            attr = child;
        }
        if normalized.is_empty() {
            normalized.push('\\');
        }
        Ok(Some((attr, normalized)))
    }

    /// Finds a single child of `parent` by name, returning the attributes and
    /// the name with its actual on-disk casing. Exact match is tried first
    /// (hash lookup); otherwise the directory is scanned case-insensitively,
    /// which is how Windows/Explorer lookups behave on a case-insensitive
    /// volume (research doc §5.3).
    async fn find_child(&self, parent: u64, name: &str) -> FsResult<Option<(FileAttr, String)>> {
        if name != "." && name != ".." {
            if let Some(attr) = self.fs.find_by_name(parent, &secret_fs(name)?).await? {
                return Ok(Some((attr, name.to_string())));
            }
        }
        let iter = self.fs.read_dir_plus(parent).await?;
        for entry in iter {
            let entry = entry?;
            let entry_name = entry.name.expose_secret().clone();
            if entry_name == name || sem::eq_ignore_case(&entry_name, name) {
                return Ok(Some((entry.attr, entry_name)));
            }
        }
        Ok(None)
    }

    /// Resolves the parent directory of `path` and returns it together with
    /// the final component name.
    async fn resolve_parent(&self, path: &str) -> FsResult<Option<(FileAttr, String)>> {
        let (parent_components, Some(name)) = sem::split_parent(path) else {
            return Ok(None);
        };
        let parent_path = if parent_components.is_empty() {
            "\\".to_string()
        } else {
            format!("\\{}", parent_components.join("\\"))
        };
        let Some((parent_attr, _)) = self.resolve(&parent_path).await? else {
            return Ok(None);
        };
        Ok(Some((parent_attr, name.to_string())))
    }
}

/// [`secret_name`] for use inside `async` contexts (same mapping).
fn secret_fs(name: &str) -> FsResult<SecretString> {
    SecretString::from_str(name).map_err(|_| FsError::InvalidInput("invalid file name"))
}

impl FileSystemContext for EncryptedFsWinfsp {
    type FileContext = WinfspFileContext;

    #[instrument(skip(self, security_descriptor, _reparse_point_resolver), err(level = Level::DEBUG))]
    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> FspResult<FileSecurity> {
        let path = file_name.to_string_lossy();
        let resolved = self.block_on(self.resolve(&path)).map_err(|err| {
            warn!(err = %err, "get_security_by_name: resolve failed");
            to_fsp_error(&err)
        })?;
        let Some((attr, _)) = resolved else {
            return Err(FspError::WIN32(ERROR_FILE_NOT_FOUND));
        };
        // no ACL support (research doc §5.1): report the file attributes and a
        // zero-length security descriptor, WinFsp applies the volume default
        let _ = security_descriptor;
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes: sem::file_attributes(&attr),
        })
    }

    #[instrument(skip(self), err(level = Level::DEBUG))]
    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> FspResult<Self::FileContext> {
        let path = file_name.to_string_lossy();
        let Some((attr, normalized)) = self.block_on(self.resolve(&path)).map_err(|err| {
            warn!(err = %err, "open: resolve failed");
            to_fsp_error(&err)
        })?
        else {
            return Err(FspError::WIN32(ERROR_FILE_NOT_FOUND));
        };
        let write = granted_access & GENERIC_WRITE != 0;
        if write && self.read_only {
            return Err(FspError::WIN32(ERROR_WRITE_PROTECT));
        }
        let fh = if attr.kind == FileType::RegularFile {
            // default to read when no specific access was requested (e.g.
            // attribute-only opens)
            let read = granted_access & GENERIC_READ != 0 || !write;
            Some(
                self.block_on(self.fs.open(attr.ino, read, write))
                    .map_err(|err| {
                        warn!(err = %err, "open failed");
                        to_fsp_error(&err)
                    })?,
            )
        } else {
            None
        };
        set_open_file_info(file_info, &attr, &normalized);
        Ok(WinfspFileContext {
            ino: attr.ino,
            kind: attr.kind,
            fh: Mutex::new(fh),
            dir_buffer: DirBuffer::new(),
            delete_pending: AtomicBool::new(false),
        })
    }

    #[instrument(skip(self, security_descriptor, _extra_buffer), err(level = Level::DEBUG))]
    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: u32,
        _file_attributes: u32,
        security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> FspResult<Self::FileContext> {
        if self.read_only {
            return Err(FspError::WIN32(ERROR_WRITE_PROTECT));
        }
        let _ = security_descriptor;
        let path = file_name.to_string_lossy();
        let Some((parent_attr, name)) =
            self.block_on(self.resolve_parent(&path)).map_err(|err| {
                warn!(err = %err, "create: resolve failed");
                to_fsp_error(&err)
            })?
        else {
            return Err(FspError::WIN32(ERROR_PATH_NOT_FOUND));
        };
        if parent_attr.kind != FileType::Directory {
            return Err(FspError::WIN32(ERROR_DIRECTORY));
        }
        if !sem::is_valid_component(&name) {
            return Err(FspError::WIN32(ERROR_INVALID_NAME));
        }

        let kind = if create_options & FILE_DIRECTORY_FILE != 0 {
            FileType::Directory
        } else {
            FileType::RegularFile
        };
        let create_attr = CreateFileAttr {
            kind,
            perm: if kind == FileType::Directory {
                0o755
            } else {
                0o644
            },
            uid: *crate::UID,
            gid: *crate::GID,
            rdev: 0,
            flags: 0,
        };
        let write = granted_access & GENERIC_WRITE != 0;
        let read = granted_access & GENERIC_READ != 0 || !write;
        // directories don't get an I/O handle in the core (same as the Linux backend's mkdir)
        let (read, write) = if kind == FileType::Directory {
            (false, false)
        } else {
            (read, write)
        };
        let (fh, attr) = self
            .block_on(self.fs.create(
                parent_attr.ino,
                &secret_name(&name)?,
                create_attr,
                read,
                write,
            ))
            .map_err(|err| {
                warn!(err = %err, "create failed");
                to_fsp_error(&err)
            })?;

        let normalized = format!("\\{}", sem::split_win_path(&path).join("\\"));
        set_open_file_info(file_info, &attr, &normalized);
        Ok(WinfspFileContext {
            ino: attr.ino,
            kind: attr.kind,
            fh: Mutex::new(if kind == FileType::RegularFile {
                Some(fh)
            } else {
                None
            }),
            dir_buffer: DirBuffer::new(),
            delete_pending: AtomicBool::new(false),
        })
    }

    fn close(&self, context: Self::FileContext) {
        if let Some(fh) = context.fh.into_inner() {
            if let Err(err) = self.block_on(self.fs.release(fh)) {
                error!(err = %err, "error releasing handle on close");
            }
        }
    }

    fn cleanup(&self, context: &Self::FileContext, file_name: Option<&U16CStr>, flags: u32) {
        // Windows delete semantics: deletion is deferred from set_delete to
        // cleanup, when the last handle is closed (research doc §5.5)
        if self.read_only
            || !context.delete_pending.load(Ordering::SeqCst)
            || !FspCleanupFlags::FspCleanupDelete.is_flagged(flags)
        {
            return;
        }
        let Some(file_name) = file_name else {
            warn!("cleanup with delete flag but no file name");
            return;
        };
        let path = file_name.to_string_lossy();
        let resolved = self.block_on(self.resolve_parent(&path));
        let Ok(Some((parent_attr, name))) = resolved else {
            warn!("cleanup: cannot resolve parent of deleted entry");
            return;
        };
        let Ok(name) = secret_name(&name) else {
            return;
        };
        let result = match context.kind {
            FileType::Directory => self.block_on(self.fs.remove_dir(parent_attr.ino, &name)),
            FileType::RegularFile => self.block_on(self.fs.remove_file(parent_attr.ino, &name)),
        };
        if let Err(err) = result {
            warn!(err = %err, "cleanup: delete failed");
        }
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        if let Some(context) = context {
            let fh = *self.block_on(context.fh.lock());
            if let Some(fh) = fh {
                self.block_on(self.fs.flush(fh)).map_err(|err| {
                    warn!(err = %err, "flush failed");
                    to_fsp_error(&err)
                })?;
            }
            let attr = self
                .block_on(self.fs.get_attr(context.ino))
                .map_err(|err| {
                    warn!(err = %err, "flush: get_attr failed");
                    to_fsp_error(&err)
                })?;
            *file_info = file_info_from_attr(&attr);
        }
        Ok(())
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        let attr = self
            .block_on(self.fs.get_attr(context.ino))
            .map_err(|err| {
                warn!(err = %err, "get_file_info failed");
                to_fsp_error(&err)
            })?;
        *file_info = file_info_from_attr(&attr);
        Ok(())
    }

    #[instrument(skip(self, _extra_buffer), err(level = Level::DEBUG))]
    fn overwrite(
        &self,
        context: &Self::FileContext,
        _file_attributes: u32,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        if self.read_only {
            return Err(FspError::WIN32(ERROR_WRITE_PROTECT));
        }
        if context.kind == FileType::Directory {
            return Err(FspError::IO(io::ErrorKind::IsADirectory));
        }
        self.block_on(self.fs.set_len(context.ino, 0))
            .map_err(|err| {
                warn!(err = %err, "overwrite: truncate failed");
                to_fsp_error(&err)
            })?;
        let attr = self
            .block_on(self.fs.get_attr(context.ino))
            .map_err(|err| {
                warn!(err = %err, "overwrite: get_attr failed");
                to_fsp_error(&err)
            })?;
        *file_info = file_info_from_attr(&attr);
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker<'_>,
        buffer: &mut [u8],
    ) -> FspResult<u32> {
        // refill the driver-managed buffer only when enumerating from the start
        if marker.is_none() {
            let iter = self
                .block_on(self.fs.read_dir_plus(context.ino))
                .map_err(|err| {
                    warn!(err = %err, "read_directory failed");
                    to_fsp_error(&err)
                })?;
            let lock = context.dir_buffer.acquire(true, None)?;
            for entry in iter {
                let entry = entry.map_err(|err| {
                    warn!(err = %err, "read_directory: entry error");
                    to_fsp_error(&err)
                })?;
                let mut dir_info = DirInfo::<255>::new();
                *dir_info.file_info_mut() = file_info_from_attr(&entry.attr);
                if dir_info.set_name(&*entry.name.expose_secret()).is_err() {
                    warn!("read_directory: skipping entry with overlong name");
                    continue;
                }
                if lock.write(&mut dir_info).is_err() {
                    // buffer is full; the driver resumes with the marker
                    break;
                }
            }
            drop(lock);
        }
        Ok(context.dir_buffer.read(marker, buffer))
    }

    #[instrument(skip(self), err(level = Level::DEBUG))]
    fn rename(
        &self,
        _context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> FspResult<()> {
        if self.read_only {
            return Err(FspError::WIN32(ERROR_WRITE_PROTECT));
        }
        let old_path = file_name.to_string_lossy();
        let new_path = new_file_name.to_string_lossy();
        let Some((old_parent, old_name)) =
            self.block_on(self.resolve_parent(&old_path))
                .map_err(|err| {
                    warn!(err = %err, "rename: resolve source failed");
                    to_fsp_error(&err)
                })?
        else {
            return Err(FspError::WIN32(ERROR_FILE_NOT_FOUND));
        };
        let Some((new_parent, new_name)) =
            self.block_on(self.resolve_parent(&new_path))
                .map_err(|err| {
                    warn!(err = %err, "rename: resolve destination failed");
                    to_fsp_error(&err)
                })?
        else {
            return Err(FspError::WIN32(ERROR_PATH_NOT_FOUND));
        };
        if new_parent.kind != FileType::Directory {
            return Err(FspError::WIN32(ERROR_DIRECTORY));
        }
        if !sem::is_valid_component(&new_name) {
            return Err(FspError::WIN32(ERROR_INVALID_NAME));
        }
        if let Some((target, _)) = self
            .block_on(self.find_child(new_parent.ino, &new_name))
            .map_err(|err| {
                warn!(err = %err, "rename: destination lookup failed");
                to_fsp_error(&err)
            })?
        {
            if !replace_if_exists {
                return Err(FspError::WIN32(ERROR_ALREADY_EXISTS));
            }
            if target.kind == FileType::Directory {
                // Windows cannot replace an existing directory by rename
                return Err(FspError::WIN32(ERROR_ACCESS_DENIED));
            }
        }
        self.block_on(self.fs.rename(
            old_parent.ino,
            &secret_name(&old_name)?,
            new_parent.ino,
            &secret_name(&new_name)?,
        ))
        .map_err(|err| {
            warn!(err = %err, "rename failed");
            to_fsp_error(&err)
        })
    }

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        _last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        let attr = self
            .block_on(self.fs.get_attr(context.ino))
            .map_err(|err| {
                warn!(err = %err, "set_basic_info: get_attr failed");
                to_fsp_error(&err)
            })?;
        let mut set_attr = SetFileAttr::default();
        // a zero FILETIME means "leave unchanged"
        if creation_time != 0 {
            set_attr = set_attr.with_crtime(sem::filetime_to_system_time(creation_time));
        }
        if last_access_time != 0 {
            set_attr = set_attr.with_atime(sem::filetime_to_system_time(last_access_time));
        }
        if last_write_time != 0 {
            set_attr = set_attr.with_mtime(sem::filetime_to_system_time(last_write_time));
        }
        // the readonly attribute is the only one with a POSIX-perm counterpart
        if file_attributes != u32::MAX {
            let mut perm = attr.perm;
            if file_attributes & sem::FILE_ATTRIBUTE_READONLY != 0 {
                perm &= !0o222;
            } else {
                perm |= 0o200;
            }
            set_attr = set_attr.with_perm(perm);
        }
        self.block_on(self.fs.set_attr(context.ino, set_attr))
            .map_err(|err| {
                warn!(err = %err, "set_basic_info failed");
                to_fsp_error(&err)
            })?;
        let attr = self
            .block_on(self.fs.get_attr(context.ino))
            .map_err(|err| {
                warn!(err = %err, "set_basic_info: get_attr failed");
                to_fsp_error(&err)
            })?;
        *file_info = file_info_from_attr(&attr);
        Ok(())
    }

    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> FspResult<()> {
        if delete_file && self.read_only {
            return Err(FspError::WIN32(ERROR_WRITE_PROTECT));
        }
        if delete_file && context.kind == FileType::Directory {
            // fail early on non-empty directories; the entry is only marked
            // here and actually removed in cleanup (research doc §5.5)
            let iter = self
                .block_on(self.fs.read_dir(context.ino))
                .map_err(|err| {
                    warn!(err = %err, "set_delete: read_dir failed");
                    to_fsp_error(&err)
                })?;
            for entry in iter {
                let entry = entry.map_err(|err| {
                    warn!(err = %err, "set_delete: entry error");
                    to_fsp_error(&err)
                })?;
                let name = entry.name.expose_secret().clone();
                if name != "." && name != ".." {
                    return Err(FspError::WIN32(ERROR_DIR_NOT_EMPTY));
                }
            }
        }
        context.delete_pending.store(delete_file, Ordering::SeqCst);
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        if self.read_only {
            return Err(FspError::WIN32(ERROR_WRITE_PROTECT));
        }
        self.block_on(self.fs.set_len(context.ino, new_size))
            .map_err(|err| {
                warn!(err = %err, "set_file_size failed");
                to_fsp_error(&err)
            })?;
        let attr = self
            .block_on(self.fs.get_attr(context.ino))
            .map_err(|err| {
                warn!(err = %err, "set_file_size: get_attr failed");
                to_fsp_error(&err)
            })?;
        *file_info = file_info_from_attr(&attr);
        Ok(())
    }

    fn read(&self, context: &Self::FileContext, buffer: &mut [u8], offset: u64) -> FspResult<u32> {
        let fh = *self.block_on(context.fh.lock());
        let Some(fh) = fh else {
            return Err(FspError::IO(io::ErrorKind::InvalidInput));
        };
        let len = self
            .block_on(self.fs.read(context.ino, offset, buffer, fh))
            .map_err(|err| {
                warn!(err = %err, "read failed");
                to_fsp_error(&err)
            })?;
        #[allow(clippy::cast_possible_truncation)]
        Ok(len as u32)
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        _constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> FspResult<u32> {
        if self.read_only {
            return Err(FspError::WIN32(ERROR_WRITE_PROTECT));
        }
        let fh = *self.block_on(context.fh.lock());
        let Some(fh) = fh else {
            return Err(FspError::IO(io::ErrorKind::InvalidInput));
        };
        let offset = if write_to_eof {
            self.block_on(self.fs.get_attr(context.ino))
                .map_err(|err| {
                    warn!(err = %err, "write: get_attr failed");
                    to_fsp_error(&err)
                })?
                .size
        } else {
            offset
        };
        let len = self
            .block_on(self.fs.write(context.ino, offset, buffer, fh))
            .map_err(|err| {
                warn!(err = %err, "write failed");
                to_fsp_error(&err)
            })?;
        let attr = self
            .block_on(self.fs.get_attr(context.ino))
            .map_err(|err| {
                warn!(err = %err, "write: get_attr failed");
                to_fsp_error(&err)
            })?;
        *file_info = file_info_from_attr(&attr);
        #[allow(clippy::cast_possible_truncation)]
        Ok(len as u32)
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> FspResult<()> {
        out_volume_info.total_size = VOLUME_TOTAL_SIZE;
        out_volume_info.free_size = VOLUME_FREE_SIZE;
        out_volume_info.set_volume_label("rencfs");
        Ok(())
    }

    fn dispatcher_stopped(&self, _normally: bool) {
        info!("WinFsp dispatcher stopped");
        if let Ok(mut tx) = self.stopped_tx.lock() {
            if let Some(tx) = tx.take() {
                let _ = tx.send(HostEvent::DispatcherStopped);
            }
        }
    }
}

/// Creates the [`FileSystemHost`], mounts and starts it. Runs on the host
/// thread; all WinFsp objects are confined to that thread.
fn create_and_start_host(
    context: EncryptedFsWinfsp,
    mountpoint: &PathBuf,
    read_only: bool,
) -> io::Result<FileSystemHost<EncryptedFsWinfsp>> {
    let mut volume_params = VolumeParams::new();
    volume_params
        .filesystem_name("rencfs")
        .sector_size(512)
        .sectors_per_allocation_unit(1)
        .max_component_length(255)
        .volume_serial_number(0x5265_6E63)
        .file_info_timeout(1000)
        // Windows/Explorer expect a case-insensitive volume that preserves casing
        .case_sensitive_search(false)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .persistent_acls(false)
        .reparse_points(false)
        .named_streams(false)
        .extended_attributes(false)
        .read_only_volume(read_only)
        .post_cleanup_when_modified_only(true)
        .flush_and_purge_on_cleanup(true)
        .pass_query_directory_pattern(false)
        .pass_query_directory_filename(false)
        .device_control(false);
    let mut host: FileSystemHost<EncryptedFsWinfsp> = FileSystemHost::new(volume_params, context)
        .map_err(|err| {
        io::Error::other(format!("cannot create WinFsp file system host: {err}"))
    })?;
    host.mount(mountpoint).map_err(|err| {
        io::Error::other(format!(
            "cannot mount WinFsp volume at {}: {err}",
            mountpoint.display()
        ))
    })?;
    host.start()
        .map_err(|err| io::Error::other(format!("cannot start WinFsp dispatcher: {err}")))?;
    Ok(host)
}

/// Entry point of the WinFsp host thread: create/mount/start, then service
/// lifecycle events until unmount or dispatcher shutdown.
#[allow(clippy::needless_pass_by_value)]
fn run_host(
    context: EncryptedFsWinfsp,
    mountpoint: PathBuf,
    read_only: bool,
    started_tx: Sender<io::Result<()>>,
    event_rx: Receiver<HostEvent>,
    done_tx: oneshot::Sender<io::Result<()>>,
) {
    let mut host = match create_and_start_host(context, &mountpoint, read_only) {
        Ok(host) => host,
        Err(err) => {
            let msg = err.to_string();
            let kind = err.kind();
            let _ = started_tx.send(Err(err));
            let _ = done_tx.send(Err(io::Error::new(kind, msg)));
            return;
        }
    };
    info!(mountpoint = %mountpoint.display(), "mounted WinFsp volume");
    if started_tx.send(Ok(())).is_err() {
        // the caller gave up waiting; tear down immediately
        host.stop();
        host.unmount();
        let _ = done_tx.send(Ok(()));
        return;
    }
    match event_rx.recv() {
        Ok(HostEvent::DispatcherStopped) => {
            host.unmount();
            let _ = done_tx.send(Ok(()));
        }
        // explicit unmount, or the handle was dropped without unmounting
        Ok(HostEvent::UnmountRequested) | Err(_) => {
            host.stop();
            host.unmount();
            let _ = done_tx.send(Ok(()));
        }
    }
    info!(mountpoint = %mountpoint.display(), "unmounted WinFsp volume");
}

#[allow(clippy::struct_excessive_bools)]
pub struct MountPointImpl {
    mountpoint: PathBuf,
    data_dir: PathBuf,
    password_provider: Option<Box<dyn PasswordProvider>>,
    cipher: crate::crypto::Cipher,
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
        cipher: crate::crypto::Cipher,
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
        // FUSE-specific options, documented no-ops on Windows (research doc §5.6)
        let _ = (self.allow_root, self.allow_other);

        let fs = EncryptedFs::new(
            self.data_dir.clone(),
            self.password_provider.take().unwrap(),
            self.cipher,
            self.read_only,
        )
        .await?;
        let rt = Handle::current();

        winfsp::winfsp_init().map_err(|err| {
            error!(err = %err, "cannot initialize WinFsp; is the WinFsp driver installed? (https://winfsp.dev)");
            FsError::Other("cannot initialize WinFsp; is the WinFsp driver installed?")
        })?;

        let context = EncryptedFsWinfsp {
            fs,
            rt,
            read_only: self.read_only,
            stopped_tx: StdMutex::new(None),
        };
        let (started_tx, started_rx) = channel();
        let (event_tx, event_rx) = channel();
        let (done_tx, done_rx) = oneshot::channel();
        *context.stopped_tx.lock().unwrap() = Some(event_tx.clone());
        let mountpoint = self.mountpoint.clone();
        let read_only = self.read_only;
        let join = std::thread::Builder::new()
            .name("rencfs-winfsp-host".to_string())
            .spawn(move || {
                run_host(
                    context, mountpoint, read_only, started_tx, event_rx, done_tx,
                );
            })
            .map_err(|err| {
                error!(err = %err, "cannot spawn WinFsp host thread");
                FsError::Other("cannot spawn WinFsp host thread")
            })?;

        // wait for the host thread to report mount success/failure without
        // blocking a runtime worker thread
        let started = tokio::task::spawn_blocking(move || started_rx.recv())
            .await
            .map_err(|err| {
                error!(err = %err, "waiting for WinFsp host thread failed");
                FsError::Other("waiting for WinFsp host thread failed")
            })?;
        match started {
            Ok(Ok(())) => Ok(mount::MountHandle {
                inner: MountHandleInnerImpl {
                    event_tx: Some(event_tx),
                    done_rx: Some(done_rx),
                    join: Some(join),
                },
            }),
            Ok(Err(err)) => {
                let _ = join.join();
                Err(err.into())
            }
            Err(_) => {
                let _ = join.join();
                error!("WinFsp host thread terminated before signaling startup");
                Err(FsError::Other(
                    "WinFsp host thread terminated before signaling startup",
                ))
            }
        }
    }
}

pub(in crate::mount) struct MountHandleInnerImpl {
    event_tx: Option<Sender<HostEvent>>,
    done_rx: Option<oneshot::Receiver<io::Result<()>>>,
    join: Option<JoinHandle<()>>,
}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(rx) = self.done_rx.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(rx).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => {
                self.done_rx = None;
                Poll::Ready(result)
            }
            Poll::Ready(Err(_)) => {
                self.done_rx = None;
                Poll::Ready(Err(io::Error::other(
                    "WinFsp host thread terminated unexpectedly",
                )))
            }
        }
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        if let Some(tx) = self.event_tx.take() {
            let _ = tx.send(HostEvent::UnmountRequested);
        }
        if let Some(rx) = self.done_rx.take() {
            match rx.await {
                Ok(result) => result?,
                Err(_) => {
                    return Err(io::Error::other(
                        "WinFsp host thread terminated unexpectedly",
                    ));
                }
            }
        }
        if let Some(join) = self.join.take() {
            // the host thread already signaled completion, so this returns promptly
            let _ = join.join();
        }
        Ok(())
    }
}
