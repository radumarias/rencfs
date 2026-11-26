use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use async_trait::async_trait;
use shush_rs::{ExposeSecret, SecretString};
use tokio::runtime::Runtime;
use tracing::{debug, error, warn};
use winfsp_wrs::{
    filetime_now, init, CleanupFlags, CreateFileInfo, CreateOptions, DirInfo, FileAccessRights,
    FileAttributes, FileInfo, FileSystem, FileSystemInterface, OperationGuardStrategy,
    PSecurityDescriptor, Params, SecurityDescriptor, U16CStr, U16CString, U16String, VolumeInfo,
    VolumeParams, WriteMode,
};

use crate::crypto::Cipher;
use crate::encryptedfs::{
    CreateFileAttr, DirectoryEntryPlus, EncryptedFs, FileAttr, FileType, FsError, FsResult,
    PasswordProvider, SetFileAttr,
};
use crate::mount::winfsp_util::{
    filetime_to_system_time, parse_windows_path, system_time_to_filetime,
};
use crate::mount::{MountHandleInner, MountPoint};

const ROOT_INODE: u64 = 1;
const VOLUME_SIZE: u64 = 1 << 50;
const NO_CHANGE: u64 = u64::MAX;

const STATUS_FILE_IS_A_DIRECTORY: i32 = 0xC000_00BA_u32 as i32;
const STATUS_NOT_A_DIRECTORY: i32 = 0xC000_0103_u32 as i32;
const STATUS_DIRECTORY_NOT_EMPTY: i32 = 0xC000_0101_u32 as i32;
const STATUS_OBJECT_NAME_INVALID: i32 = 0xC000_0033_u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000D_u32 as i32;
const STATUS_INVALID_HANDLE: i32 = 0xC000_0008_u32 as i32;
const STATUS_SHARING_VIOLATION: i32 = 0xC000_0043_u32 as i32;
const STATUS_MEDIA_WRITE_PROTECTED: i32 = 0xC000_00A2_u32 as i32;
const STATUS_FILE_TOO_LARGE: i32 = 0xC000_0095_u32 as i32;
const STATUS_LOGON_FAILURE: i32 = 0xC000_006D_u32 as i32;
const STATUS_UNEXPECTED_IO_ERROR: i32 = 0xC000_00E9_u32 as i32;

#[derive(Debug, Clone)]
struct EntryLocation {
    parent: u64,
    name: String,
}

struct FileContext {
    ino: u64,
    file_handle: u64,
    kind: FileType,
    location: Mutex<Option<EntryLocation>>,
    delete_pending: AtomicBool,
}

impl FileContext {
    fn new(
        attr: &FileAttr,
        file_handle: u64,
        location: Option<EntryLocation>,
        delete_pending: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            ino: attr.ino,
            file_handle,
            kind: attr.kind,
            location: Mutex::new(location),
            delete_pending: AtomicBool::new(delete_pending),
        })
    }
}

struct EncryptedFsWinFsp {
    fs: Arc<EncryptedFs>,
    runtime: Runtime,
}

impl EncryptedFsWinFsp {
    async fn new(
        data_dir: PathBuf,
        password_provider: Box<dyn PasswordProvider>,
        cipher: Cipher,
        read_only: bool,
    ) -> FsResult<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("rencfs-winfsp")
            .enable_all()
            .build()?;
        let fs = EncryptedFs::new(data_dir, password_provider, cipher, read_only).await?;
        Ok(Self { fs, runtime })
    }

    fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        self.runtime.block_on(future)
    }

    async fn find_child(
        &self,
        parent: u64,
        requested_name: &str,
    ) -> FsResult<Option<(FileAttr, String)>> {
        let requested = SecretString::from_str(requested_name)
            .map_err(|_| FsError::InvalidInput("invalid file name"))?;
        if let Some(attr) = self.fs.find_by_name(parent, &requested).await? {
            return Ok(Some((attr, requested_name.to_owned())));
        }

        // WinFsp volumes are case-insensitive. The encrypted backend stores exact names, so use
        // directory enumeration as the case-insensitive fallback while returning the stored case.
        let entries = self.fs.read_dir(parent).await?;
        let requested_lower = requested_name.to_lowercase();
        for entry in entries {
            let entry = entry?;
            let actual_name = entry.name.expose_secret().clone();
            if actual_name.to_lowercase() == requested_lower {
                let attr = self.fs.get_attr(entry.ino).await?;
                return Ok(Some((attr, actual_name)));
            }
        }
        Ok(None)
    }

    async fn resolve_components(
        &self,
        components: &[String],
    ) -> FsResult<(FileAttr, Option<EntryLocation>)> {
        let mut ino = ROOT_INODE;
        let mut location = None;
        for component in components {
            let (attr, actual_name) = self
                .find_child(ino, component)
                .await?
                .ok_or(FsError::NotFound("file name not found"))?;
            location = Some(EntryLocation {
                parent: ino,
                name: actual_name,
            });
            ino = attr.ino;
        }
        let attr = self.fs.get_attr(ino).await?;
        Ok((attr, location))
    }

    fn resolve_path(&self, file_name: &U16CStr) -> Result<(FileAttr, Option<EntryLocation>), i32> {
        let path = file_name.to_string_lossy();
        let components = parse_windows_path(&path).map_err(|reason| {
            debug!(path = %path, reason, "rejected Windows path");
            STATUS_OBJECT_NAME_INVALID
        })?;
        self.block_on(self.resolve_components(&components))
            .map_err(fs_error_to_ntstatus)
    }

    fn resolve_parent(&self, file_name: &U16CStr) -> Result<(u64, String), i32> {
        let path = file_name.to_string_lossy();
        let mut components = parse_windows_path(&path).map_err(|reason| {
            debug!(path = %path, reason, "rejected Windows path");
            STATUS_OBJECT_NAME_INVALID
        })?;
        let name = components.pop().ok_or(STATUS_OBJECT_NAME_INVALID)?;
        let (parent, _) = self
            .block_on(self.resolve_components(&components))
            .map_err(fs_error_to_ntstatus)?;
        if parent.kind != FileType::Directory {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        Ok((parent.ino, name))
    }
}

impl FileSystemInterface for EncryptedFsWinFsp {
    type FileContext = Arc<FileContext>;

    const GET_VOLUME_INFO_DEFINED: bool = true;
    const GET_SECURITY_BY_NAME_DEFINED: bool = true;
    const CREATE_DEFINED: bool = true;
    const OPEN_DEFINED: bool = true;
    const OVERWRITE_DEFINED: bool = true;
    const CLEANUP_DEFINED: bool = true;
    const CLOSE_DEFINED: bool = true;
    const READ_DEFINED: bool = true;
    const WRITE_DEFINED: bool = true;
    const FLUSH_DEFINED: bool = true;
    const GET_FILE_INFO_DEFINED: bool = true;
    const SET_BASIC_INFO_DEFINED: bool = true;
    const SET_FILE_SIZE_DEFINED: bool = true;
    const RENAME_DEFINED: bool = true;
    const READ_DIRECTORY_DEFINED: bool = true;
    const SET_DELETE_DEFINED: bool = true;
    const DISPATCHER_STOPPED_DEFINED: bool = true;

    fn get_volume_info(&self) -> Result<VolumeInfo, i32> {
        let label = U16String::from_str("rencfs");
        VolumeInfo::new(VOLUME_SIZE, VOLUME_SIZE, label.as_ustr())
            .map_err(|_| STATUS_INVALID_PARAMETER)
    }

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _find_reparse_point: impl Fn() -> Option<FileAttributes>,
    ) -> Result<(FileAttributes, PSecurityDescriptor, bool), i32> {
        let (attr, _) = self.resolve_path(file_name)?;
        Ok((attributes_for(&attr), PSecurityDescriptor::default(), false))
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: CreateOptions,
        granted_access: FileAccessRights,
    ) -> Result<(Self::FileContext, FileInfo), i32> {
        let (attr, location) = self.resolve_path(file_name)?;
        if create_options.is(CreateOptions::FILE_DIRECTORY_FILE) && attr.kind != FileType::Directory
        {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        if create_options.is(CreateOptions::FILE_NON_DIRECTORY_FILE)
            && attr.kind == FileType::Directory
        {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }

        let (read, write) = requested_access(granted_access);
        let file_handle = if attr.kind == FileType::RegularFile && (read || write) {
            self.block_on(self.fs.open(attr.ino, read, write))
                .map_err(fs_error_to_ntstatus)?
        } else {
            0
        };
        let delete_pending = create_options.is(CreateOptions::FILE_DELETE_ON_CLOSE);
        let context = FileContext::new(&attr, file_handle, location, delete_pending);
        Ok((context, file_info_for(&attr)))
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_file_info: CreateFileInfo,
        _security_descriptor: SecurityDescriptor,
    ) -> Result<(Self::FileContext, FileInfo), i32> {
        let (parent, name) = self.resolve_parent(file_name)?;
        if self
            .block_on(self.find_child(parent, &name))
            .map_err(fs_error_to_ntstatus)?
            .is_some()
        {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        let is_directory = create_file_info
            .file_attributes
            .is(FileAttributes::DIRECTORY);
        let kind = if is_directory {
            FileType::Directory
        } else {
            FileType::RegularFile
        };
        let (read, write) = requested_access(create_file_info.granted_access);
        let attr = CreateFileAttr {
            kind,
            perm: if is_directory { 0o755 } else { 0o644 },
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
        };
        let secret_name = SecretString::from_str(&name).map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
        let (file_handle, created_attr) = self
            .block_on(self.fs.create(
                parent,
                &secret_name,
                attr,
                kind == FileType::RegularFile && read,
                kind == FileType::RegularFile && write,
            ))
            .map_err(fs_error_to_ntstatus)?;
        let delete_pending = create_file_info
            .create_options
            .is(CreateOptions::FILE_DELETE_ON_CLOSE);
        let context = FileContext::new(
            &created_attr,
            file_handle,
            Some(EntryLocation { parent, name }),
            delete_pending,
        );
        Ok((context, file_info_for(&created_attr)))
    }

    fn overwrite(
        &self,
        file_context: Self::FileContext,
        file_attributes: FileAttributes,
        replace_file_attributes: bool,
        _allocation_size: u64,
    ) -> Result<FileInfo, i32> {
        if file_context.kind == FileType::Directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        self.block_on(self.fs.set_len(file_context.ino, 0))
            .map_err(fs_error_to_ntstatus)?;
        if replace_file_attributes {
            let current_attr = self
                .block_on(self.fs.get_attr(file_context.ino))
                .map_err(fs_error_to_ntstatus)?;
            self.block_on(
                self.fs.set_attr(
                    file_context.ino,
                    SetFileAttr::default()
                        .with_perm(permissions_for(file_attributes, current_attr.perm)),
                ),
            )
            .map_err(fs_error_to_ntstatus)?;
        }
        self.file_info(file_context.ino)
    }

    fn cleanup(
        &self,
        file_context: Self::FileContext,
        _file_name: Option<&U16CStr>,
        flags: CleanupFlags,
    ) {
        let should_delete =
            file_context.delete_pending.load(Ordering::Acquire) || flags.is(CleanupFlags::DELETE);
        if !should_delete {
            return;
        }
        let location = file_context
            .location
            .lock()
            .expect("entry location lock poisoned")
            .clone();
        let Some(location) = location else {
            warn!("refusing to delete filesystem root");
            return;
        };
        let name = match SecretString::from_str(&location.name) {
            Ok(name) => name,
            Err(_) => {
                error!("invalid stored file name while cleaning up");
                return;
            }
        };
        let result = match file_context.kind {
            FileType::Directory => self.block_on(self.fs.remove_dir(location.parent, &name)),
            FileType::RegularFile => self.block_on(self.fs.remove_file(location.parent, &name)),
        };
        if let Err(err) = result {
            error!(err = %err, ino = file_context.ino, "WinFsp cleanup delete failed");
        } else {
            file_context.delete_pending.store(false, Ordering::Release);
        }
    }

    fn close(&self, file_context: Self::FileContext) {
        if file_context.file_handle == 0 {
            return;
        }
        if self.block_on(self.fs.is_write_handle(file_context.file_handle)) {
            if let Err(err) = self.block_on(self.fs.flush(file_context.file_handle)) {
                error!(err = %err, ino = file_context.ino, "WinFsp close flush failed");
            }
        }
        if let Err(err) = self.block_on(self.fs.release(file_context.file_handle)) {
            error!(err = %err, ino = file_context.ino, "WinFsp close release failed");
        }
    }

    fn read(
        &self,
        file_context: Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> Result<usize, i32> {
        if file_context.file_handle == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.block_on(
            self.fs
                .read(file_context.ino, offset, buffer, file_context.file_handle),
        )
        .map_err(fs_error_to_ntstatus)
    }

    fn write(
        &self,
        file_context: Self::FileContext,
        buffer: &[u8],
        mode: WriteMode,
    ) -> Result<(usize, FileInfo), i32> {
        if file_context.file_handle == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        let attr = self
            .block_on(self.fs.get_attr(file_context.ino))
            .map_err(fs_error_to_ntstatus)?;
        let (offset, buffer) = match mode {
            WriteMode::Normal { offset } => (offset, buffer),
            WriteMode::ConstrainedIO { offset } => {
                let available = attr.size.saturating_sub(offset);
                let length = usize::try_from(available)
                    .unwrap_or(usize::MAX)
                    .min(buffer.len());
                (offset, &buffer[..length])
            }
            WriteMode::WriteToEOF => (attr.size, buffer),
        };
        let written = self
            .block_on(
                self.fs
                    .write(file_context.ino, offset, buffer, file_context.file_handle),
            )
            .map_err(fs_error_to_ntstatus)?;
        Ok((written, self.file_info(file_context.ino)?))
    }

    fn flush(&self, file_context: Self::FileContext) -> Result<FileInfo, i32> {
        if file_context.file_handle != 0
            && self.block_on(self.fs.is_write_handle(file_context.file_handle))
        {
            self.block_on(self.fs.flush(file_context.file_handle))
                .map_err(fs_error_to_ntstatus)?;
        }
        self.file_info(file_context.ino)
    }

    fn get_file_info(&self, file_context: Self::FileContext) -> Result<FileInfo, i32> {
        self.file_info(file_context.ino)
    }

    fn set_basic_info(
        &self,
        file_context: Self::FileContext,
        file_attributes: FileAttributes,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        change_time: u64,
    ) -> Result<FileInfo, i32> {
        let current_attr = self
            .block_on(self.fs.get_attr(file_context.ino))
            .map_err(fs_error_to_ntstatus)?;
        let mut set_attr =
            SetFileAttr::default().with_perm(permissions_for(file_attributes, current_attr.perm));
        if creation_time != NO_CHANGE {
            set_attr = set_attr.with_crtime(filetime_to_system_time(creation_time));
        }
        if last_access_time != NO_CHANGE {
            set_attr = set_attr.with_atime(filetime_to_system_time(last_access_time));
        }
        if last_write_time != NO_CHANGE {
            set_attr = set_attr.with_mtime(filetime_to_system_time(last_write_time));
        }
        if change_time != NO_CHANGE {
            set_attr = set_attr.with_ctime(filetime_to_system_time(change_time));
        }
        self.block_on(self.fs.set_attr(file_context.ino, set_attr))
            .map_err(fs_error_to_ntstatus)?;
        self.file_info(file_context.ino)
    }

    fn set_file_size(
        &self,
        file_context: Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
    ) -> Result<FileInfo, i32> {
        if file_context.kind == FileType::Directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        if !set_allocation_size {
            self.block_on(self.fs.set_len(file_context.ino, new_size))
                .map_err(fs_error_to_ntstatus)?;
        }
        self.file_info(file_context.ino)
    }

    fn rename(
        &self,
        file_context: Self::FileContext,
        _file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> Result<(), i32> {
        let location = file_context
            .location
            .lock()
            .expect("entry location lock poisoned")
            .clone()
            .ok_or(STATUS_ACCESS_DENIED)?;
        let (new_parent, new_name) = self.resolve_parent(new_file_name)?;
        if let Some((existing, existing_name)) = self
            .block_on(self.find_child(new_parent, &new_name))
            .map_err(fs_error_to_ntstatus)?
        {
            let case_only_rename =
                existing.ino == file_context.ino && new_parent == location.parent;
            if !replace_if_exists && !case_only_rename {
                return Err(STATUS_OBJECT_NAME_COLLISION);
            }
            if !case_only_rename {
                if existing.kind != file_context.kind {
                    return Err(if existing.kind == FileType::Directory {
                        STATUS_FILE_IS_A_DIRECTORY
                    } else {
                        STATUS_NOT_A_DIRECTORY
                    });
                }
                if existing.kind == FileType::Directory
                    && self.fs.len(existing.ino).map_err(fs_error_to_ntstatus)? != 0
                {
                    return Err(STATUS_DIRECTORY_NOT_EMPTY);
                }
                let existing_name = SecretString::from_str(&existing_name)
                    .map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
                let removed = match existing.kind {
                    FileType::Directory => {
                        self.block_on(self.fs.remove_dir(new_parent, &existing_name))
                    }
                    FileType::RegularFile => {
                        self.block_on(self.fs.remove_file(new_parent, &existing_name))
                    }
                };
                removed.map_err(fs_error_to_ntstatus)?;
            }
        }
        let old_name =
            SecretString::from_str(&location.name).map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
        let secret_new_name =
            SecretString::from_str(&new_name).map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
        self.block_on(
            self.fs
                .rename(location.parent, &old_name, new_parent, &secret_new_name),
        )
        .map_err(fs_error_to_ntstatus)?;
        *file_context
            .location
            .lock()
            .expect("entry location lock poisoned") = Some(EntryLocation {
            parent: new_parent,
            name: new_name,
        });
        Ok(())
    }

    fn read_directory(
        &self,
        file_context: Self::FileContext,
        marker: Option<&U16CStr>,
        mut add_dir_info: impl FnMut(DirInfo) -> bool,
    ) -> Result<(), i32> {
        if file_context.kind != FileType::Directory {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        let entries = self
            .block_on(collect_directory(self.fs.clone(), file_context.ino))
            .map_err(fs_error_to_ntstatus)?;
        let marker = marker.map(U16CStr::to_string_lossy);
        let mut skip = marker.is_some();
        for entry in entries {
            let name = entry.name.expose_secret();
            if skip {
                if marker
                    .as_ref()
                    .is_some_and(|marker| marker == name.as_str())
                {
                    skip = false;
                }
                continue;
            }
            if matches!(name.as_str(), "." | "..") {
                continue;
            }
            if !add_dir_info(DirInfo::from_str(file_info_for(&entry.attr), name.as_str())) {
                break;
            }
        }
        Ok(())
    }

    fn set_delete(
        &self,
        file_context: Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> Result<(), i32> {
        if file_context.ino == ROOT_INODE {
            return Err(STATUS_ACCESS_DENIED);
        }
        if delete_file
            && file_context.kind == FileType::Directory
            && self
                .fs
                .len(file_context.ino)
                .map_err(fs_error_to_ntstatus)?
                != 0
        {
            return Err(STATUS_DIRECTORY_NOT_EMPTY);
        }
        file_context
            .delete_pending
            .store(delete_file, Ordering::Release);
        Ok(())
    }

    fn dispatcher_stopped(&self, normally: bool) {
        debug!(normally, "rencfs WinFsp dispatcher stopped");
    }
}

impl EncryptedFsWinFsp {
    fn file_info(&self, ino: u64) -> Result<FileInfo, i32> {
        let attr = self
            .block_on(self.fs.get_attr(ino))
            .map_err(fs_error_to_ntstatus)?;
        Ok(file_info_for(&attr))
    }
}

async fn collect_directory(fs: Arc<EncryptedFs>, ino: u64) -> FsResult<Vec<DirectoryEntryPlus>> {
    let iterator = fs.read_dir_plus(ino).await?;
    let mut entries = Vec::new();
    for entry in iterator {
        entries.push(entry?);
    }
    Ok(entries)
}

fn requested_access(access: FileAccessRights) -> (bool, bool) {
    if access.is(FileAccessRights::FILE_ALL_ACCESS) {
        return (true, true);
    }
    let read_mask = FileAccessRights::FILE_READ_DATA.0
        | FileAccessRights::FILE_READ_EA.0
        | FileAccessRights::FILE_EXECUTE.0
        | FileAccessRights::FILE_GENERIC_READ.0;
    let write_mask = FileAccessRights::FILE_WRITE_DATA.0
        | FileAccessRights::FILE_APPEND_DATA.0
        | FileAccessRights::FILE_WRITE_EA.0
        | FileAccessRights::FILE_WRITE_ATTRIBUTES.0
        | FileAccessRights::FILE_GENERIC_WRITE.0;
    (access.0 & read_mask != 0, access.0 & write_mask != 0)
}

fn permissions_for(attributes: FileAttributes, current_permissions: u16) -> u16 {
    if attributes.is(FileAttributes::READONLY) {
        current_permissions & !0o222
    } else {
        current_permissions | 0o222
    }
}

fn attributes_for(attr: &FileAttr) -> FileAttributes {
    let mut attributes = if attr.kind == FileType::Directory {
        FileAttributes::DIRECTORY
    } else {
        FileAttributes::ARCHIVE
    };
    if attr.perm & 0o222 == 0 {
        attributes |= FileAttributes::READONLY;
    }
    attributes
}

fn file_info_for(attr: &FileAttr) -> FileInfo {
    let allocation_size = if attr.kind == FileType::Directory {
        0
    } else {
        attr.size.saturating_add(4095) / 4096 * 4096
    };
    let mut info = FileInfo::default();
    info.set_file_attributes(attributes_for(attr))
        .set_allocation_size(allocation_size)
        .set_file_size(attr.size)
        .set_creation_time(system_time_to_filetime(attr.crtime))
        .set_last_access_time(system_time_to_filetime(attr.atime))
        .set_last_write_time(system_time_to_filetime(attr.mtime))
        .set_change_time(system_time_to_filetime(attr.ctime))
        .set_index_number(attr.ino)
        .set_hard_links(0)
        .set_ea_size(0);
    info
}

fn fs_error_to_ntstatus(error: FsError) -> i32 {
    match error {
        FsError::NotFound(_) | FsError::InodeNotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        FsError::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        FsError::InvalidInput(_) => STATUS_INVALID_PARAMETER,
        FsError::InvalidInodeType => STATUS_NOT_A_DIRECTORY,
        FsError::InvalidFileHandle => STATUS_INVALID_HANDLE,
        FsError::AlreadyOpenForWrite => STATUS_SHARING_VIOLATION,
        FsError::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        FsError::ReadOnly => STATUS_MEDIA_WRITE_PROTECTED,
        FsError::MaxFilesizeExceeded(_) => STATUS_FILE_TOO_LARGE,
        FsError::InvalidPassword | FsError::InvalidDataDirStructure => STATUS_LOGON_FAILURE,
        FsError::Io { source, .. } => io_error_to_ntstatus(source.kind()),
        _ => STATUS_UNEXPECTED_IO_ERROR,
    }
}

fn io_error_to_ntstatus(kind: io::ErrorKind) -> i32 {
    match kind {
        io::ErrorKind::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        io::ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
        io::ErrorKind::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        io::ErrorKind::InvalidInput => STATUS_INVALID_PARAMETER,
        io::ErrorKind::InvalidData => STATUS_OBJECT_NAME_INVALID,
        io::ErrorKind::IsADirectory => STATUS_FILE_IS_A_DIRECTORY,
        io::ErrorKind::NotADirectory => STATUS_NOT_A_DIRECTORY,
        _ => STATUS_UNEXPECTED_IO_ERROR,
    }
}

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

    async fn mount(mut self) -> FsResult<crate::mount::MountHandle> {
        if self.allow_root || self.allow_other {
            debug!("WinFsp manages access with Windows ACLs; FUSE allow-root/allow-other flags are ignored");
        }
        let provider = self
            .password_provider
            .take()
            .ok_or(FsError::Other("password provider already consumed"))?;
        let context =
            EncryptedFsWinFsp::new(self.data_dir, provider, self.cipher, self.read_only).await?;
        init().map_err(|err| {
            error!(err = %err, "cannot initialize WinFsp");
            FsError::Other("cannot initialize WinFsp; install WinFsp 2.x")
        })?;

        let mountpoint = U16CString::from_os_str(self.mountpoint.as_os_str()).map_err(|err| {
            error!(err = %err, "invalid WinFsp mount point");
            FsError::InvalidInput("invalid WinFsp mount point")
        })?;
        let mut volume_params = VolumeParams::default();
        let filesystem_name = U16CString::from_str("rencfs")
            .map_err(|_| FsError::Other("invalid WinFsp filesystem name"))?;
        let _ = volume_params.set_file_system_name(filesystem_name.as_ucstr());
        volume_params
            .set_case_sensitive_search(false)
            .set_case_preserved_names(true)
            .set_unicode_on_disk(true)
            .set_persistent_acls(false)
            .set_read_only_volume(self.read_only)
            .set_reparse_point(false)
            .set_named_streams(false)
            .set_hard_links(false)
            .set_extended_attributes(false)
            .set_flush_and_purge_on_cleanup(true)
            .set_supports_posix_unlink_rename(true)
            .set_always_use_double_buffering(true)
            .set_allow_open_in_kernel_mode(false)
            .set_sector_size(4096)
            .set_sectors_per_allocation_unit(1)
            .set_max_component_length(255)
            .set_volume_creation_time(filetime_now())
            .set_volume_serial_number(0x5245_4E43)
            .set_file_info_timeout(1_000);

        let filesystem = FileSystem::start(
            Params {
                volume_params,
                guard_strategy: OperationGuardStrategy::Fine,
            },
            Some(mountpoint.as_ucstr()),
            context,
        )
        .map_err(|status| {
            error!(
                status = format!("0x{:08X}", status as u32),
                "cannot start WinFsp"
            );
            FsError::Other("cannot start WinFsp filesystem")
        })?;
        Ok(crate::mount::MountHandle {
            inner: MountHandleInnerImpl {
                filesystem: Some(filesystem),
            },
        })
    }
}

pub(in crate::mount) struct MountHandleInnerImpl {
    filesystem: Option<FileSystem>,
}

impl MountHandleInnerImpl {
    fn stop(&mut self) {
        if let Some(filesystem) = self.filesystem.take() {
            filesystem.stop();
        }
    }
}

impl Drop for MountHandleInnerImpl {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        self.stop();
        Ok(())
    }
}
