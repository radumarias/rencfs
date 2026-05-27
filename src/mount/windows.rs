//! Windows WinFsp backend for rencfs.
//!
//! Bridges the `winfsp::filesystem::FileSystemContext` trait to the internal
//! `EncryptedFs` engine, providing native Windows filesystem mount support
//! via the WinFsp user-mode filesystem driver.

use std::ffi::c_void;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use shush_rs::{ExposeSecret, SecretString};
use tracing::{debug, error, info, trace, warn};
use widestring::{U16CStr, U16CString};
use windows::Win32::Foundation::{
    NTSTATUS, STATUS_ACCESS_DENIED, STATUS_DIRECTORY_NOT_EMPTY, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND,
};
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileSecurity, FileInfo, FileSystemContext,
    ModificationDescriptor, OpenFileInfo, VolumeInfo,
};
use winfsp::host::{FileSystemHost, FileSystemParams, FineGuard, VolumeParams};

use crate::crypto::Cipher;
use crate::encryptedfs::{
    CreateFileAttr, EncryptedFs, FileAttr, FileType, FsError, FsResult, PasswordProvider,
    SetFileAttr, ROOT_INODE,
};
use crate::mount;
use crate::mount::{MountHandleInner, MountPoint};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// 100-nanosecond intervals between the Windows FILETIME epoch (1601-01-01)
/// and the Unix epoch (1970-01-01).
const FILETIME_EPOCH_DIFF: u64 = 116_444_736_000_000_000;

/// Maximum component length reported to Windows.
const MAX_COMPONENT_LENGTH: u32 = 255;

/// Volume label reported to Windows Explorer.
const VOLUME_LABEL: &str = "EncryptedFs";

/// Sector size for the WinFsp volume.
const SECTOR_SIZE: u16 = 4096;

/// File info timeout in milliseconds for WinFsp caching.
const FILE_INFO_TIMEOUT_MS: u32 = 1000;

/// Windows file attribute constants.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_READONLY: u32 = 0x01;

/// WinFsp cleanup flags — if this flag is set in `cleanup`, the file should
/// be deleted after all handles are closed.
const FSP_CLEANUP_DELETE: u32 = 0x01;

/// Additional NTSTATUS values not always re-exported by the `windows` crate.
const STATUS_SHARING_VIOLATION: NTSTATUS = NTSTATUS(0xC000_0043_u32 as i32);
const STATUS_DISK_FULL: NTSTATUS = NTSTATUS(0xC000_007F_u32 as i32);
const STATUS_MEDIA_WRITE_PROTECTED: NTSTATUS = NTSTATUS(0xC000_00A2_u32 as i32);
const STATUS_INTERNAL_ERROR: NTSTATUS = NTSTATUS(0xC000_00E5_u32 as i32);
const STATUS_NOT_SUPPORTED: NTSTATUS = NTSTATUS(0xC000_00BB_u32 as i32);
const STATUS_FILE_IS_A_DIRECTORY: NTSTATUS = NTSTATUS(0xC000_00BA_u32 as i32);

/// Windows access mask bits.
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;

// ---------------------------------------------------------------------------
// Path Normalization & Resolution
// ---------------------------------------------------------------------------

/// Normalize a WinFsp-style path (`\foo\bar`) to a forward-slash internal path
/// with no leading separator. Root is represented as empty string `""`.
fn normalize_path(win_path: &U16CStr) -> String {
    let s = win_path.to_string_lossy();
    let normalized = s.replace('\\', "/");
    let trimmed = normalized.trim_start_matches('/');
    trimmed.to_string()
}

/// Split a normalized path into `(parent_path, final_component)`.
/// Returns `None` for the root path (empty string).
fn split_path(path: &str) -> Option<(&str, &str)> {
    if path.is_empty() {
        return None;
    }
    match path.rfind('/') {
        Some(pos) => Some((&path[..pos], &path[pos + 1..])),
        None => Some(("", path)),
    }
}

// ---------------------------------------------------------------------------
// Error Mapping
// ---------------------------------------------------------------------------

/// Map an `FsError` to a precise NTSTATUS code.
/// Provides granular error reporting to Windows instead of generic failures.
fn fs_error_to_ntstatus(err: &FsError) -> NTSTATUS {
    match err {
        FsError::InodeNotFound | FsError::NotFound(_) => STATUS_OBJECT_NAME_NOT_FOUND,
        FsError::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        FsError::InvalidInput(_) => STATUS_INVALID_PARAMETER,
        FsError::InvalidInodeType => STATUS_NOT_A_DIRECTORY,
        FsError::InvalidFileHandle => STATUS_INVALID_HANDLE,
        FsError::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        FsError::AlreadyOpenForWrite => STATUS_SHARING_VIOLATION,
        FsError::MaxFilesizeExceeded(_) => STATUS_DISK_FULL,
        FsError::InvalidPassword => STATUS_ACCESS_DENIED,
        FsError::ReadOnly => STATUS_MEDIA_WRITE_PROTECTED,
        FsError::Io { source, .. } => match source.kind() {
            io::ErrorKind::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
            io::ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
            io::ErrorKind::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
            _ => STATUS_INTERNAL_ERROR,
        },
        _ => STATUS_INTERNAL_ERROR,
    }
}

/// Convert an `FsError` into a `winfsp::FspError` for trait return types.
fn fs_err(e: FsError) -> winfsp::FspError {
    let status = fs_error_to_ntstatus(&e);
    error!(err = %e, ntstatus = ?status, "filesystem error");
    status.into()
}

// ---------------------------------------------------------------------------
// Timestamp Conversion
// ---------------------------------------------------------------------------

/// Convert a Rust `SystemTime` to a Windows FILETIME value
/// (100-nanosecond intervals since 1601-01-01 UTC).
fn system_time_to_filetime(st: SystemTime) -> u64 {
    match st.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            // Saturating cast: u128 → u64 (overflows past year ~2554, acceptable).
            let nanos_100 = (d.as_nanos() / 100) as u64;
            nanos_100.saturating_add(FILETIME_EPOCH_DIFF)
        }
        Err(_) => FILETIME_EPOCH_DIFF, // fallback to Unix epoch
    }
}

/// Convert a Windows FILETIME value to a Rust `SystemTime`.
fn filetime_to_system_time(ft: u64) -> SystemTime {
    if ft <= FILETIME_EPOCH_DIFF {
        return UNIX_EPOCH;
    }
    let nanos_100 = ft - FILETIME_EPOCH_DIFF;
    let duration = Duration::from_nanos(nanos_100 * 100);
    UNIX_EPOCH + duration
}

// ---------------------------------------------------------------------------
// FileInfo Population
// ---------------------------------------------------------------------------

/// Populate a WinFsp `FileInfo` struct from an `EncryptedFs` `FileAttr`.
fn populate_file_info(fi: &mut FileInfo, attr: &FileAttr, read_only: bool) {
    let mut file_attributes = if attr.kind == FileType::Directory {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    if read_only {
        file_attributes |= FILE_ATTRIBUTE_READONLY;
    }

    fi.file_attributes = file_attributes;
    fi.creation_time = system_time_to_filetime(attr.crtime);
    fi.last_access_time = system_time_to_filetime(attr.atime);
    fi.last_write_time = system_time_to_filetime(attr.mtime);
    fi.change_time = system_time_to_filetime(attr.ctime);
    fi.file_size = attr.size;
    // Allocation size rounded up to the next sector boundary.
    fi.allocation_size = (attr.size + (SECTOR_SIZE as u64 - 1)) & !(SECTOR_SIZE as u64 - 1);
    fi.index_number = attr.ino;
}

// ---------------------------------------------------------------------------
// File Context — lives for the duration of an open handle
// ---------------------------------------------------------------------------

/// Represents an open file or directory handle in the WinFsp bridge.
///
/// Once created by `open` or `create`, subsequent operations (`read`, `write`,
/// `get_file_info`, `flush`) use `context.ino` directly — no re-walking the
/// path tree. Path resolution only happens during the initial open/create.
pub struct WinFspFileContext {
    /// The inode number in the EncryptedFs.
    ino: u64,
    /// Whether this context represents a directory.
    is_dir: bool,
    /// The EncryptedFs file handle. `None` for directories.
    handle: std::sync::Mutex<Option<u64>>,
    /// The normalized path, kept for logging and cleanup/delete operations.
    path: String,
    /// Persistent directory buffer for paginated `read_directory` calls.
    /// WinFsp calls `read_directory` multiple times for large directories,
    /// sending different markers each time. The buffer MUST survive across
    /// consecutive calls for the same open directory handle.
    ///
    /// `DirBuffer` provides interior mutability via an internal SRW lock,
    /// so the outer `Mutex` is belt-and-suspenders safety for our own code.
    dir_buffer: std::sync::Mutex<DirBuffer>,
}

// ---------------------------------------------------------------------------
// Core Bridge
// ---------------------------------------------------------------------------

/// The WinFsp filesystem bridge. Implements `FileSystemContext` by delegating
/// all operations to an `EncryptedFs` instance through a dedicated tokio runtime.
pub struct EncryptedFsWinFsp {
    fs: Arc<EncryptedFs>,
    /// Dedicated tokio runtime for blocking on async `EncryptedFs` calls.
    /// WinFsp callbacks are synchronous and called from driver threads.
    rt: tokio::runtime::Runtime,
    read_only: bool,
}

impl EncryptedFsWinFsp {
    /// Resolve a normalized path to its `(inode, FileAttr)`.
    ///
    /// For the root (empty string or "/"), returns `ROOT_INODE`'s attributes.
    /// For deeper paths, walks the directory tree component by component.
    ///
    /// Uses **case-insensitive fallback**: if a direct `find_by_name` fails,
    /// enumerates all entries in the directory and matches case-insensitively.
    /// This handles the Windows case-insensitivity expectation while the
    /// underlying EncryptedFs is case-sensitive.
    fn resolve_path(&self, path: &str) -> Result<(u64, FileAttr), FsError> {
        if path.is_empty() {
            let attr = self.rt.block_on(self.fs.get_attr(ROOT_INODE))?;
            return Ok((ROOT_INODE, attr));
        }

        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut current_ino = ROOT_INODE;

        for component in &components {
            let name = SecretString::from_str(component).unwrap();

            // Try exact (case-sensitive) match first — this is the fast path.
            match self.rt.block_on(self.fs.find_by_name(current_ino, &name)) {
                Ok(Some(attr)) => {
                    current_ino = attr.ino;
                    continue;
                }
                Ok(None) => {
                    // Exact match failed — try case-insensitive fallback.
                    match self.case_insensitive_lookup(current_ino, component) {
                        Ok(attr) => {
                            current_ino = attr.ino;
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }

        let attr = self.rt.block_on(self.fs.get_attr(current_ino))?;
        Ok((current_ino, attr))
    }

    /// Case-insensitive directory lookup fallback.
    ///
    /// Reads all entries in `parent_ino` and compares names case-insensitively.
    /// This is the "slow path" — only invoked when the fast exact-match fails.
    fn case_insensitive_lookup(
        &self,
        parent_ino: u64,
        target_name: &str,
    ) -> Result<FileAttr, FsError> {
        let target_lower = target_name.to_lowercase();
        let iter = self.rt.block_on(self.fs.read_dir(parent_ino))?;

        for entry_result in iter {
            let entry = entry_result?;
            let entry_name = entry.name.expose_secret().to_string();
            if entry_name == "." || entry_name == ".." {
                continue;
            }
            if entry_name.to_lowercase() == target_lower {
                let attr = self.rt.block_on(self.fs.get_attr(entry.ino))?;
                return Ok(attr);
            }
        }

        Err(FsError::NotFound("case-insensitive lookup failed"))
    }

    /// Resolve a path to the parent inode and the final component name.
    /// Returns `(parent_ino, component_name)`.
    fn resolve_parent(&self, path: &str) -> Result<(u64, String), FsError> {
        match split_path(path) {
            None => {
                // Root itself — no parent in this context.
                Err(FsError::InvalidInput("cannot resolve parent of root"))
            }
            Some((parent_path, name)) => {
                let (parent_ino, _parent_attr) = self.resolve_path(parent_path)?;
                Ok((parent_ino, name.to_string()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FileSystemContext Implementation
// ---------------------------------------------------------------------------

impl FileSystemContext for EncryptedFsWinFsp {
    type FileContext = WinFspFileContext;

    // -- Required: get_security_by_name --
    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::error::Result<FileSecurity> {
        let path = normalize_path(file_name);
        trace!(path = %path, "get_security_by_name");

        let (_ino, attr) = self.resolve_path(&path).map_err(fs_err)?;

        let mut attributes = if attr.kind == FileType::Directory {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
        if self.read_only {
            attributes |= FILE_ATTRIBUTE_READONLY;
        }

        // We don't implement Windows ACLs — return no security descriptor.
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes,
        })
    }

    // -- Required: open --
    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        granted_access: winfsp_sys::FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::error::Result<Self::FileContext> {
        let path = normalize_path(file_name);
        debug!(path = %path, "open");

        let (ino, attr) = self.resolve_path(&path).map_err(fs_err)?;

        let is_dir = attr.kind == FileType::Directory;
        let handle = if is_dir {
            None // Directories don't use file handles in EncryptedFs.
        } else {
            let read = (granted_access.0 & FILE_READ_DATA) != 0;
            let write = (granted_access.0 & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
            let (read, write) = if !read && !write { (true, false) } else { (read, write) };
            let fh = self
                .rt
                .block_on(self.fs.open(ino, read, write))
                .map_err(fs_err)?;
            Some(fh)
        };

        populate_file_info(file_info.as_mut(), &attr, self.read_only);

        Ok(WinFspFileContext {
            ino,
            is_dir,
            handle: std::sync::Mutex::new(handle),
            path,
            dir_buffer: std::sync::Mutex::new(DirBuffer::new()),
        })
    }

    // -- Required: close --
    fn close(&self, context: Self::FileContext) {
        let handle = context.handle.lock().expect("handle lock poisoned");
        trace!(ino = context.ino, handle = ?*handle, "close");
        if let Some(fh) = *handle {
            if let Err(e) = self.rt.block_on(self.fs.release(fh)) {
                error!(err = %e, ino = context.ino, "failed to release handle on close");
            }
        }
        // `context` is dropped here, freeing resources including DirBuffer.
    }

    // -- create --
    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        granted_access: winfsp_sys::FILE_ACCESS_RIGHTS,
        file_attributes: winfsp_sys::FILE_FLAGS_AND_ATTRIBUTES,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::error::Result<Self::FileContext> {
        let path = normalize_path(file_name);
        debug!(path = %path, "create");

        let (parent_ino, name) = self.resolve_parent(&path).map_err(fs_err)?;

        let is_dir = (file_attributes.0 & FILE_ATTRIBUTE_DIRECTORY) != 0;
        let kind = if is_dir {
            FileType::Directory
        } else {
            FileType::RegularFile
        };

        let create_attr = CreateFileAttr {
            kind,
            perm: if is_dir { 0o777 } else { 0o644 },
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
        };

        let read = (granted_access.0 & FILE_READ_DATA) != 0;
        let write = (granted_access.0 & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
        let (read, write) = if !is_dir && !read && !write {
            (true, true)
        } else {
            (read, write)
        };

        let secret_name = SecretString::from_str(&name).unwrap();
        let (fh, attr) = self
            .rt
            .block_on(
                self.fs
                    .create(parent_ino, &secret_name, create_attr, read, write),
            )
            .map_err(fs_err)?;

        populate_file_info(file_info.as_mut(), &attr, self.read_only);

        Ok(WinFspFileContext {
            ino: attr.ino,
            is_dir,
            handle: std::sync::Mutex::new(if is_dir { None } else { Some(fh) }),
            path,
            dir_buffer: std::sync::Mutex::new(DirBuffer::new()),
        })
    }

    // -- cleanup --
    fn cleanup(
        &self,
        context: &Self::FileContext,
        file_name: Option<&U16CStr>,
        flags: u32,
    ) {
        trace!(ino = context.ino, flags, "cleanup");

        // If the delete flag is set, remove the file/directory.
        if (flags & FSP_CLEANUP_DELETE) != 0 {
            let path = file_name
                .map(normalize_path)
                .unwrap_or_else(|| context.path.clone());

            debug!(path = %path, ino = context.ino, "cleanup: deleting");

            // Release the handle first so the file isn't locked.
            {
                let mut handle_guard = context.handle.lock().expect("handle lock poisoned");
                if let Some(fh) = handle_guard.take() {
                    let _ = self.rt.block_on(self.fs.release(fh));
                }
            }

            if let Ok((parent_ino, name)) = self.resolve_parent(&path) {
                let secret_name = SecretString::from_str(&name).unwrap();
                let result = if context.is_dir {
                    self.rt
                        .block_on(self.fs.remove_dir(parent_ino, &secret_name))
                } else {
                    self.rt
                        .block_on(self.fs.remove_file(parent_ino, &secret_name))
                };
                if let Err(e) = result {
                    error!(err = %e, path = %path, "cleanup: delete failed");
                }
            }
        }
    }

    // -- flush --
    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> winfsp::error::Result<()> {
        if let Some(ctx) = context {
            let handle = ctx.handle.lock().expect("handle lock poisoned");
            trace!(ino = ctx.ino, handle = ?*handle, "flush");

            if let Some(fh) = *handle {
                self.rt.block_on(self.fs.flush(fh)).map_err(fs_err)?;
            }

            // Refresh file info after flush.
            let attr = self
                .rt
                .block_on(self.fs.get_attr(ctx.ino))
                .map_err(fs_err)?;
            populate_file_info(file_info, &attr, self.read_only);
        }
        // Volume flush (context == None): no-op for now.
        Ok(())
    }

    // -- get_file_info --
    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::error::Result<()> {
        // Use context.ino directly — no path re-walking needed.
        let attr = self
            .rt
            .block_on(self.fs.get_attr(context.ino))
            .map_err(fs_err)?;
        populate_file_info(file_info, &attr, self.read_only);
        Ok(())
    }

    // -- get_volume_info (BUG 4 FIX: out-parameter style) --
    fn get_volume_info(
        &self,
        out_volume_info: &mut VolumeInfo,
    ) -> winfsp::error::Result<()> {
        trace!("get_volume_info");
        // Report a fixed-size volume. These numbers are cosmetic —
        // EncryptedFs doesn't track real disk usage.
        out_volume_info.total_size = 1024 * 1024 * 1024; // 1 GiB
        out_volume_info.free_size = 1024 * 1024 * 1024; // 1 GiB
        out_volume_info.set_volume_label(VOLUME_LABEL);
        Ok(())
    }

    // -- read --
    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::error::Result<u32> {
        let handle = context.handle.lock().expect("handle lock poisoned");
        trace!(ino = context.ino, handle = ?*handle, offset, len = buffer.len(), "read");

        if context.is_dir {
            return Err(STATUS_FILE_IS_A_DIRECTORY.into());
        }

        let fh = handle.ok_or_else(|| {
            error!(ino = context.ino, "read: no file handle");
            winfsp::FspError::from(STATUS_INVALID_HANDLE)
        })?;

        // Drop the MutexGuard before the blocking I/O to avoid holding the
        // lock across the `block_on` call.
        drop(handle);

        let bytes_read = self
            .rt
            .block_on(self.fs.read(context.ino, offset, buffer, fh))
            .map_err(fs_err)?;

        #[allow(clippy::cast_possible_truncation)]
        Ok(bytes_read as u32)
    }

    // -- write --
    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        _constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::error::Result<u32> {
        let handle_guard = context.handle.lock().expect("handle lock poisoned");

        if context.is_dir {
            return Err(STATUS_FILE_IS_A_DIRECTORY.into());
        }

        let fh = handle_guard.ok_or_else(|| {
            error!(ino = context.ino, "write: no file handle");
            winfsp::FspError::from(STATUS_INVALID_HANDLE)
        })?;

        // Drop the MutexGuard before the blocking I/O.
        drop(handle_guard);

        let actual_offset = if write_to_eof {
            let attr = self
                .rt
                .block_on(self.fs.get_attr(context.ino))
                .map_err(fs_err)?;
            attr.size
        } else {
            offset
        };

        trace!(ino = context.ino, handle = fh, offset = actual_offset, len = buffer.len(), "write");

        let bytes_written = self
            .rt
            .block_on(self.fs.write(context.ino, actual_offset, buffer, fh))
            .map_err(fs_err)?;

        // Refresh file info after write.
        let attr = self
            .rt
            .block_on(self.fs.get_attr(context.ino))
            .map_err(fs_err)?;
        populate_file_info(file_info, &attr, self.read_only);

        #[allow(clippy::cast_possible_truncation)]
        Ok(bytes_written as u32)
    }

    // -- read_directory (BUGS 1, 2, 3 FIX) --
    //
    // Canonical DirBuffer pattern from the WinFsp C SDK:
    //   1. If marker.is_none() (first call), acquire & fill the DirBuffer.
    //   2. Read from the (already-filled) DirBuffer into the output slice.
    //   3. Return bytes written as u32.
    //
    // The DirBuffer is persisted in the FileContext so it survives across
    // paginated calls. WinFsp handles marker tracking internally.
    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker<'_>,
        buffer: &mut [u8],
    ) -> winfsp::error::Result<u32> {
        trace!(ino = context.ino, "read_directory");

        let db = context.dir_buffer.lock().expect("dir_buffer lock poisoned");

        // On first call (marker is none), fill the DirBuffer with all entries.
        // On subsequent calls (marker is Some), the buffer is already populated;
        // FspFileSystemReadDirectoryBuffer handles pagination via the marker.
        if marker.is_none() {
            let iter = self
                .rt
                .block_on(self.fs.read_dir(context.ino))
                .map_err(fs_err)?;

            // Collect all entries, skipping pseudo-entries and errors.
            let mut entries: Vec<(String, u64)> = Vec::new();
            for entry_result in iter {
                match entry_result {
                    Ok(entry) => {
                        let name = entry.name.expose_secret().to_string();
                        if name == "." || name == ".." {
                            continue;
                        }
                        entries.push((name, entry.ino));
                    }
                    Err(e) => {
                        error!(err = %e, "read_directory: entry error, skipping");
                    }
                }
            }

            // Sort deterministically — required for correct marker pagination.
            entries.sort_by(|a, b| a.0.cmp(&b.0));

            // Acquire the DirBuffer with reset=true to clear stale entries.
            let mut lock = db.acquire(true, None);

            for (name, ino) in &entries {
                let attr = match self.rt.block_on(self.fs.get_attr(*ino)) {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(err = %e, name = %name, "read_directory: skipping, bad attr");
                        continue;
                    }
                };

                let mut fi = FileInfo::default();
                populate_file_info(&mut fi, &attr, self.read_only);

                let wide_name = match U16CString::from_str(name) {
                    Ok(n) => n,
                    Err(e) => {
                        warn!(err = %e, name = %name, "read_directory: invalid encoding");
                        continue;
                    }
                };

                let mut entry = DirInfo::<{ MAX_COMPONENT_LENGTH as usize }>::new();
                entry.set_file_info(fi);
                entry.set_file_name(&wide_name);

                if lock.write(&entry).is_err() {
                    // DirBuffer internal capacity exceeded — unlikely with
                    // reasonable directory sizes, but we handle it gracefully.
                    break;
                }
            }

            // Drop the DirBufferLock (releases the internal SRW write lock).
            drop(lock);
        }

        // Read cached entries from the DirBuffer into the output slice.
        // FspFileSystemReadDirectoryBuffer handles marker-based pagination
        // and returns the number of bytes copied.
        Ok(db.read(&marker, buffer))
    }

    // -- set_basic_info --
    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        _file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        change_time: u64,
        file_info: &mut FileInfo,
    ) -> winfsp::error::Result<()> {
        trace!(ino = context.ino, "set_basic_info");

        let mut set_attr = SetFileAttr::default();

        // Only update timestamps that are non-zero (0 means "don't change").
        if creation_time != 0 {
            set_attr = set_attr.with_crtime(filetime_to_system_time(creation_time));
        }
        if last_access_time != 0 {
            set_attr = set_attr.with_atime(filetime_to_system_time(last_access_time));
        }
        if last_write_time != 0 {
            set_attr = set_attr.with_mtime(filetime_to_system_time(last_write_time));
        }
        if change_time != 0 {
            set_attr = set_attr.with_ctime(filetime_to_system_time(change_time));
        }

        self.rt
            .block_on(self.fs.set_attr(context.ino, set_attr))
            .map_err(fs_err)?;

        let attr = self
            .rt
            .block_on(self.fs.get_attr(context.ino))
            .map_err(fs_err)?;
        populate_file_info(file_info, &attr, self.read_only);

        Ok(())
    }

    // -- set_file_size --
    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::error::Result<()> {
        trace!(ino = context.ino, new_size, set_allocation_size, "set_file_size");

        if !set_allocation_size {
            // Setting the actual file size (truncate/extend).
            self.rt
                .block_on(self.fs.set_len(context.ino, new_size))
                .map_err(fs_err)?;
        }
        // For allocation_size changes, EncryptedFs handles allocation internally.

        let attr = self
            .rt
            .block_on(self.fs.get_attr(context.ino))
            .map_err(fs_err)?;
        populate_file_info(file_info, &attr, self.read_only);
        Ok(())
    }

    // -- rename --
    fn rename(
        &self,
        _context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        _replace_if_exists: bool,
    ) -> winfsp::error::Result<()> {
        let old_path = normalize_path(file_name);
        let new_path = normalize_path(new_file_name);
        debug!(old_path = %old_path, new_path = %new_path, "rename");

        let (old_parent_ino, old_name) = self.resolve_parent(&old_path).map_err(fs_err)?;
        let (new_parent_ino, new_name) = self.resolve_parent(&new_path).map_err(fs_err)?;

        let old_secret = SecretString::from_str(&old_name).unwrap();
        let new_secret = SecretString::from_str(&new_name).unwrap();

        self.rt
            .block_on(self.fs.rename(
                old_parent_ino,
                &old_secret,
                new_parent_ino,
                &new_secret,
            ))
            .map_err(fs_err)?;

        Ok(())
    }

    // -- set_delete (BUG 7 FIX: replaces non-existent can_delete) --
    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> winfsp::error::Result<()> {
        trace!(ino = context.ino, delete_file, "set_delete");

        if delete_file && context.is_dir {
            // Check if the directory is empty before allowing deletion.
            let len = self.fs.len(context.ino).map_err(fs_err)?;
            if len > 0 {
                return Err(STATUS_DIRECTORY_NOT_EMPTY.into());
            }
        }
        // Regular files can always be flagged for deletion
        // (access checks are done by WinFsp).
        Ok(())
    }

    // -- overwrite (BUG 5 FIX: file_attributes is FILE_FLAGS_AND_ATTRIBUTES) --
    fn overwrite(
        &self,
        context: &Self::FileContext,
        _file_attributes: winfsp_sys::FILE_FLAGS_AND_ATTRIBUTES,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::error::Result<()> {
        debug!(ino = context.ino, "overwrite");

        // Truncate the file to zero.
        self.rt
            .block_on(self.fs.set_len(context.ino, 0))
            .map_err(fs_err)?;

        let attr = self
            .rt
            .block_on(self.fs.get_attr(context.ino))
            .map_err(fs_err)?;
        populate_file_info(file_info, &attr, self.read_only);
        Ok(())
    }

    // -- get_security (optional — we don't implement Windows ACLs) --
    fn get_security(
        &self,
        _context: &Self::FileContext,
        _security_descriptor: Option<&mut [c_void]>,
    ) -> winfsp::error::Result<u64> {
        // We don't track Windows security descriptors. Return 0 = no descriptor.
        Ok(0)
    }

    // -- set_security (BUG 6 FIX: owned ModificationDescriptor, not &) --
    fn set_security(
        &self,
        _context: &Self::FileContext,
        _security_information: u32,
        _modification_descriptor: ModificationDescriptor,
    ) -> winfsp::error::Result<()> {
        // Gracefully report that we don't support Windows ACLs.
        Err(STATUS_NOT_SUPPORTED.into())
    }

    // Note: get_extended_attributes, set_extended_attributes, reparse point
    // methods, set_volume_label, and control all use the default implementation
    // which returns STATUS_INVALID_DEVICE_REQUEST — exactly the right behavior
    // for unsupported operations.
}

// ---------------------------------------------------------------------------
// Validates that the mount point is a valid Windows drive letter (e.g., "Z:").
// For the MVP, only drive letter mounts are supported to avoid complex
// directory junction / reparse point issues.
// ---------------------------------------------------------------------------

fn validate_mount_point(mountpoint: &std::path::Path) -> io::Result<()> {
    let s = mountpoint.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "mount point is not valid UTF-8")
    })?;

    let trimmed = s.trim_end_matches('\\');
    if trimmed.len() == 2
        && trimmed.as_bytes()[0].is_ascii_alphabetic()
        && trimmed.as_bytes()[1] == b':'
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("On Windows, mount point must be a drive letter (e.g., Z:). Got: {s}"),
        ))
    }
}

// ---------------------------------------------------------------------------
// MountPointImpl
// ---------------------------------------------------------------------------

#[allow(clippy::struct_excessive_bools)]
pub struct MountPointImpl {
    mountpoint: PathBuf,
    data_dir: PathBuf,
    password_provider: Option<Box<dyn PasswordProvider>>,
    cipher: Cipher,
    #[allow(dead_code)]
    allow_root: bool,
    #[allow(dead_code)]
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
        validate_mount_point(&self.mountpoint)
            .map_err(|_e| FsError::Other("invalid mount point: expected drive letter like Z:"))?;

        info!("Initializing WinFsp filesystem");

        // Build a dedicated tokio runtime for the WinFsp sync callbacks.
        // This is separate from the application's async runtime to avoid
        // block_on panics when called from within a tokio context.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|_e| FsError::Other("failed to create tokio runtime"))?;

        let password_provider = self
            .password_provider
            .take()
            .ok_or(FsError::Other("password provider already consumed"))?;

        info!("Checking password and creating EncryptedFs");
        let fs = rt.block_on(EncryptedFs::new(
            self.data_dir.clone(),
            password_provider,
            self.cipher,
            self.read_only,
        ))?;

        let context = EncryptedFsWinFsp {
            fs,
            rt,
            read_only: self.read_only,
        };

        // Configure WinFsp volume parameters using the builder API.
        let mut volume_params = VolumeParams::new();
        volume_params
            .sector_size(SECTOR_SIZE)
            .volume_serial_number(0x5245_4E43) // "RENC"
            .file_info_timeout(FILE_INFO_TIMEOUT_MS)
            .case_sensitive_search(false)       // Windows-style case insensitive
            .case_preserved_names(true)
            .unicode_on_disk(true)
            .persistent_acls(false)             // We don't implement ACLs
            .reparse_points(false)              // No symlinks
            .named_streams(false)               // No alternate data streams
            .post_cleanup_when_modified_only(true)
            .filesystem_name("rencfs");

        if self.read_only {
            volume_params.read_only_volume(true);
        }

        let fs_params = FileSystemParams::default_params(volume_params);

        let mount_path = self
            .mountpoint
            .to_str()
            .ok_or(FsError::Other("mount point not valid UTF-8"))?;

        info!(mount_point = %mount_path, "Mounting WinFsp filesystem");

        // Create the FileSystemHost and mount.
        let mut host =
            FileSystemHost::<EncryptedFsWinFsp, FineGuard>::new_with_options(fs_params, context)
                .map_err(|e| {
                    error!(err = ?e, "failed to create FileSystemHost");
                    FsError::Other("failed to create WinFsp FileSystemHost")
                })?;

        host.mount(mount_path).map_err(|e| {
            error!(err = ?e, "failed to mount WinFsp filesystem");
            FsError::Other("failed to mount WinFsp filesystem")
        })?;

        host.start().map_err(|e| {
            error!(err = ?e, "failed to start WinFsp dispatcher");
            FsError::Other("failed to start WinFsp dispatcher")
        })?;

        info!("WinFsp filesystem mounted successfully at {}", mount_path);

        Ok(mount::MountHandle {
            inner: MountHandleInnerImpl {
                host: Some(host),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// MountHandleInnerImpl
// ---------------------------------------------------------------------------

pub(in crate::mount) struct MountHandleInnerImpl {
    host: Option<FileSystemHost<EncryptedFsWinFsp, FineGuard>>,
}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // The WinFsp dispatcher runs in its own threads internally.
        // This future never completes on its own — it waits for explicit unmount.
        Poll::Pending
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        info!("Unmounting WinFsp filesystem");
        if let Some(mut host) = self.host.take() {
            host.stop();
            host.unmount().map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("WinFsp unmount error: {e:?}"))
            })?;
        }
        info!("WinFsp filesystem unmounted");
        Ok(())
    }
}
