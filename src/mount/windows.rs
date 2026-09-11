use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::{debug, error, instrument, trace, warn, Level};
use winfsp::fuse::{
    DirectoryEntry, DirectoryEntryPlus, ReplyAttr, ReplyCopyFileRange, ReplyCreated, ReplyData,
    ReplyDirectory, ReplyDirectoryPlus, ReplyEntry, ReplyInit, ReplyOpen, ReplyStatFs, ReplyWrite,
};
use winfsp::fuse::{Filesystem, MountHandle, Request, Session};
use winfsp::FuseContext;
use winfsp::Result as WinFspResult;
use winfsp::FileAttributes as WinFspFileAttributes;
use winfsp::FileSystemContext;
use winfsp::FileSystemHost;
use winfsp::OpenFileInfo;
use winfsp::OperationContext;
use winfsp::FileName;

use crate::crypto::Cipher;
use crate::encryptedfs::{
    CopyFileRangeReq, CreateFileAttr, EncryptedFs, FileAttr, FileType, FsError, FsResult,
    PasswordProvider, SetFileAttr,
};
use crate::mount;
use crate::mount::{MountHandleInner, MountPoint};

const TTL: std::time::Duration = std::time::Duration::from_secs(1);

const FMODE_EXEC: i32 = 0x20;

struct EncryptedFsWinFsp {
    fs: Arc<EncryptedFs>,
}

impl EncryptedFsWinFsp {
    pub async fn new(
        data_dir: PathBuf,
        password_provider: Box<dyn PasswordProvider>,
        cipher: Cipher,
        read_only: bool,
    ) -> FsResult<Self> {
        Ok(Self {
            fs: EncryptedFs::new(data_dir, password_provider, cipher, read_only).await?,
        })
    }

    fn get_fs(&self) -> Arc<EncryptedFs> {
        self.fs.clone()
    }

    #[allow(clippy::cast_possible_truncation)]
    const fn creation_mode(&self, mode: u32) -> u16 {
        (mode & !(0o4000 | 0o2000)) as u16
    }

    #[instrument(skip(self, name), fields(name = name.to_str().unwrap()), err(level = Level::WARN), ret(level = Level::DEBUG))]
    async fn create_nod(
        &self,
        parent: u64,
        mut mode: u32,
        req: &Request,
        name: &OsStr,
        read: bool,
        write: bool,
    ) -> std::result::Result<(u64, FileAttr), io::Error> {
        let parent_attr = match self.get_fs().get_attr(parent).await {
            Err(err) => {
                error!(err = %err);
                return Err(io::Error::new(io::ErrorKind::NotFound, err));
            }
            Ok(parent_attr) => parent_attr,
        };

        if !check_access(
            parent_attr.uid,
            parent_attr.gid,
            parent_attr.perm,
            req.uid,
            req.gid,
            libc::W_OK,
        ) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "access denied"));
        }

        if req.uid != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID);
        }

        let kind = as_file_kind(mode);
        let mut attr = if kind == FileType::Directory {
            dir_attr()
        } else {
            file_attr()
        };
        attr.perm = self.creation_mode(mode);
        attr.uid = req.uid;
        attr.gid = creation_gid(&parent_attr, req.gid);

        let (fh, attr) = self
            .get_fs()
            .create(
                parent,
                &shush_rs::SecretString::from_str(name.to_str().unwrap()).unwrap(),
                attr,
                read,
                write,
            )
            .await
            .map_err(|err| {
                error!(err = %err);
                match err {
                    FsError::AlreadyExists => io::Error::new(io::ErrorKind::AlreadyExists, err),
                    FsError::Io { source, .. } => source,
                    _ => io::Error::new(io::ErrorKind::Other, err),
                }
            })?;
        Ok((fh, attr))
    }
}

#[allow(clippy::cast_possible_truncation)]
const fn creation_gid(parent: &FileAttr, gid: u32) -> u32 {
    if parent.perm & (libc::S_ISGID as u16) != 0 {
        return parent.gid;
    }
    gid
}

impl From<FileAttr> for winfsp::fuse::FileAttr {
    fn from(from: FileAttr) -> Self {
        Self {
            ino: from.ino,
            size: from.size,
            blocks: from.blocks,
            atime: from.atime,
            mtime: from.mtime,
            ctime: from.ctime,
            kind: if from.kind == FileType::Directory {
                winfsp::fuse::FileType::Directory
            } else {
                winfsp::fuse::FileType::RegularFile
            },
            perm: from.perm,
            nlink: from.nlink,
            uid: from.uid,
            gid: from.gid,
            rdev: from.rdev,
            blksize: from.blksize,
        }
    }
}

#[derive(Debug)]
pub struct DirectoryEntryIterator(crate::encryptedfs::DirectoryEntryIterator, u64);

impl Iterator for DirectoryEntryIterator {
    type Item = WinFspResult<DirectoryEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0.next() {
            Some(Ok(entry)) => {
                let kind = if entry.kind == FileType::Directory {
                    winfsp::fuse::FileType::Directory
                } else {
                    winfsp::fuse::FileType::RegularFile
                };
                self.1 += 1;
                Some(Ok(DirectoryEntry {
                    inode: entry.ino,
                    kind,
                    name: OsString::from(&*entry.name.expose_secret()),
                    offset: self.1 as i64,
                }))
            }
            Some(Err(FsError::Io { source, .. })) => {
                error!(err = %source);
                Some(Err(source.into()))
            }
            Some(Err(err)) => {
                error!(err = %err);
                Some(Err(winfsp::FspError::IO.into()))
            }
            None => None,
        }
    }
}

#[derive(Debug)]
pub struct DirectoryEntryPlusIterator(crate::encryptedfs::DirectoryEntryPlusIterator, u64);

impl Iterator for DirectoryEntryPlusIterator {
    type Item = WinFspResult<DirectoryEntryPlus>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0.next() {
            Some(Ok(entry)) => {
                let kind = if entry.kind == FileType::Directory {
                    winfsp::fuse::FileType::Directory
                } else {
                    winfsp::fuse::FileType::RegularFile
                };
                self.1 += 1;
                Some(Ok(DirectoryEntryPlus {
                    inode: entry.ino,
                    generation: 0,
                    kind,
                    name: OsString::from(&*entry.name.expose_secret()),
                    offset: self.1 as i64,
                    attr: entry.attr.into(),
                    entry_ttl: TTL,
                    attr_ttl: TTL,
                }))
            }
            Some(Err(FsError::Io { source, .. })) => {
                error!(err = %source);
                Some(Err(source.into()))
            }
            Some(Err(err)) => {
                error!(err = %err);
                Some(Err(winfsp::FspError::IO.into()))
            }
            None => None,
        }
    }
}

struct EncryptedFsHost {
    fs: Arc<EncryptedFsWinFsp>,
}

impl EncryptedFsHost {
    pub async fn new(
        data_dir: PathBuf,
        password_provider: Box<dyn PasswordProvider>,
        cipher: Cipher,
        read_only: bool,
    ) -> FsResult<Self> {
        Ok(Self {
            fs: Arc::new(EncryptedFsWinFsp::new(data_dir, password_provider, cipher, read_only).await?),
        })
    }
}

#[async_trait]
impl FileSystemContext for EncryptedFsHost {
    type ReadDirIter = DirectoryEntryIterator;
    type ReadDirPlusIter = DirectoryEntryPlusIterator;

    #[instrument(skip(self), err(level = Level::WARN), ret(level = Level::INFO))]
    async fn init(&self, _req: &Request) -> WinFspResult<ReplyInit> {
        trace!("");
        Ok(ReplyInit {
            max_write: NonZeroU32::new(1024 * 1024).unwrap(),
        })
    }

    #[instrument(skip(self))]
    async fn destroy(&self, _req: &Request) {
        trace!("");
    }

    #[instrument(skip(self, name), fields(name = name.to_str().unwrap()), err(level = Level::WARN), ret(level = Level::DEBUG))]
    async fn lookup(&self, req: &Request, parent: u64, name: &FileName) -> WinFspResult<ReplyEntry> {
        trace!("");

        let parent_attr = match self.fs.get_attr(parent).await {
            Err(err) => {
                error!(parent, err = %err, "not found");
                return Err(winfsp::FspError::NotFound);
            }
            Ok(parent_attr) => parent_attr,
        };

        if !check_access(
            parent_attr.uid,
            parent_attr.gid,
            parent_attr.perm,
            req.uid,
            req.gid,
            libc::X_OK,
        ) {
            return Err(winfsp::FspError::AccessDenied);
        }

        let attr = match self
            .fs
            .find_by_name(
                parent,
                &shush_rs::SecretString::from_str(name.to_str().unwrap()).unwrap(),
            )
            .await
        {
            Ok(Some(attr)) => attr,
            Err(err) => {
                error!(err = %err);
                return Err(winfsp::FspError::NotFound);
            }
            _ => {
                return Err(winfsp::FspError::NotFound);
            }
        };

        Ok(ReplyEntry {
            ttl: TTL,
            attr: attr.into(),
            generation: 0,
        })
    }

    #[instrument(skip(self))]
    async fn forget(&self, _req: &Request, _inode: u64, _nlookup: u64) {
        trace!("");
    }

    #[instrument(skip(self), err(level = Level::WARN), ret(level = Level::DEBUG))]
    async fn getattr(
        &self,
        req: &Request,
        inode: u64,
        _fh: Option<u64>,
        _flags: u32,
    ) -> WinFspResult<ReplyAttr> {
        trace!("");

        match self.fs.get_attr(inode).await {
            Err(err) => {
                error!(err = %err);
                return Err(winfsp::FspError::NotFound);
            }
            Ok(attr) => Ok(ReplyAttr {
                ttl: TTL,
                attr: attr.into(),
            }),
        }
    }

    #[instrument(skip(self), err(level = Level::WARN), ret(level = Level::DEBUG))]
    #[allow(clippy::cast_possible_truncation)]
    async fn setattr(
        &self,
        req: &Request,
        inode: u64,
        _fh: Option<u64>,
        set_attr: winfsp::fuse::SetAttr,
    ) -> WinFspResult<ReplyAttr> {
        trace!("");
        debug!("{set_attr:#?}");

        let attr = self.fs.get_attr(inode).await.map_err(|err| {
            error!(err = %err);
            winfsp::FspError::NotFound
        })?;

        let mut set_attr2 = SetFileAttr::default();

        if let Some(mode) = set_attr.mode {
            debug!("chmod mode={mode:o}");
            if req.uid != 0 && req.uid != attr.uid {
                return Err(winfsp::FspError::PermissionDenied);
            }
            set_attr2 = set_attr2.with_perm(mode as u16);
            set_attr2 = set_attr2.with_atime(std::time::SystemTime::now());
            self.fs
                .set_attr(inode, set_attr2)
                .await
                .map_err(|err| {
                    error!(err = %err);
                    winfsp::FspError::IO
                })?;
            return Ok(ReplyAttr {
                ttl: TTL,
                attr: self
                    .fs
                    .get_attr(inode)
                    .await
                    .map_err(|_err| winfsp::FspError::NotFound)?
                    .into(),
            });
        }

        if set_attr.uid.is_some() || set_attr.gid.is_some() {
            debug!("chown");
            if let Some(uid) = set_attr.uid {
                if req.uid != 0 && uid != attr.uid {
                    return Err(winfsp::FspError::PermissionDenied);
                }
            }
            set_attr2 = set_attr2.with_perm(attr.perm);
            if let Some(uid) = set_attr.uid {
                set_attr2 = set_attr2.with_uid(uid);
                let perm = set_attr2.perm.unwrap_or(attr.perm);
                set_attr2 = set_attr2.with_perm(perm & !(libc::S_ISUID as u16));
            }
            if let Some(gid) = set_attr.gid {
                set_attr2 = set_attr2.with_gid(gid);
                if req.uid != 0 {
                    let perm = set_attr2.perm.unwrap_or(attr.perm);
                    set_attr2 = set_attr2.with_perm(perm & !(libc::S_ISGID as u16));
                }
            }
            set_attr2 = set_attr2.with_atime(std::time::SystemTime::now());
            self.fs
                .set_attr(inode, set_attr2)
                .await
                .map_err(|err| {
                    error!(err = %err);
                    winfsp::FspError::IO
                })?;
            return Ok(ReplyAttr {
                ttl: TTL,
                attr: self
                    .fs
                    .get_attr(inode)
                    .await
                    .map_err(|_err| winfsp::FspError::NotFound)?
                    .into(),
            });
        }

        if let Some(size) = set_attr.size {
            debug!("truncate size={size}");
            self.fs.set_len(inode, size).await.map_err(|err| {
                error!(err = %err);
                winfsp::FspError::IO
            })?;
            set_attr2 = set_attr2.with_size(size);
            set_attr2 = set_attr2.with_perm(clear_suid_sgid(attr.perm));
        }

        if let Some(atime) = set_attr.atime {
            if attr.uid != req.uid
                && !check_access(attr.uid, attr.gid, attr.perm, req.uid, req.gid, libc::W_OK)
            {
                return Err(winfsp::FspError::AccessDenied);
            }
            set_attr2 = set_attr2.with_atime(atime);
            set_attr2 = set_attr2.with_ctime(std::time::SystemTime::now());
        }

        if let Some(mtime) = set_attr.mtime {
            if attr.uid != req.uid
                && !check_access(attr.uid, attr.gid, attr.perm, req.uid, req.gid, libc::W_OK)
            {
                return Err(winfsp::FspError::AccessDenied);
            }
            set_attr2 = set_attr2.with_mtime(mtime);
            set_attr2 = set_attr2.with_ctime(std::time::SystemTime::now());
        }

        self.fs
            .set_attr(inode, set_attr2)
            .await
            .map_err(|err| {
                error!(err = %err);
                winfsp::FspError::IO
            })?;

        Ok(ReplyAttr {
            ttl: TTL,
            attr: self
                .fs
                .get_attr(inode)
                .await
                .map_err(|_err| winfsp::FspError::NotFound)?
                .into(),
        })
    }

    #[instrument(skip(self))]
    async fn mknod(
        &self,
        req: &Request,
        parent: u64,
        name: &FileName,
        mode: u32,
        rdev: u32,
    ) -> WinFspResult<ReplyEntry> {
        trace!("");
        debug!("mode={mode:o}");

        let file_type = mode & libc::S_IFMT;
        if file_type != libc::S_IFREG && file_type != libc::S_IFDIR {
            warn!("implementation is incomplete. Only supports regular files and directories. Got mode={mode:o}");
            return Err(winfsp::FspError::OperationNotSupported);
        }

        self.fs
            .create_nod(parent, mode, req, name, false, false)
            .await
            .map_err(|err| {
                error!(err = %err);
                winfsp::FspError::from_io_error(err)
            })
            .map(|(_, attr)| {
                Ok(ReplyEntry {
                    ttl: TTL,
                    attr: attr.into(),
                    generation: 0,
                })
            })?
    }

    #[instrument(skip(self, name), fields(name = name.to_str().unwrap()), err(level = Level::WARN), ret(level = Level::DEBUG))]
    async fn mkdir(
        &self,
        req: &Request,
        parent: u64,
        name: &FileName,
        mode: u32,
        _umask: u32,
    ) -> WinFspResult<ReplyEntry> {
        trace!("");
        debug!("mode={mode:o}");

        let parent_attr = match self.fs.get_attr(parent).await {
            Err(err) => {
                error!(err = %err);
                return Err(winfsp::FspError::NotFound);
            }
            Ok(parent_attr) => parent_attr,
        };

        if !check_access(
            parent_attr.uid,
            parent_attr.gid,
            parent_attr.perm,
            req.uid,
            req.gid,
            libc::W_OK,
        ) {
            return Err(winfsp::FspError::AccessDenied);
        }

        let mut attr = dir_attr();
        let mut mode = mode;
        if req.uid != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID);
        }
        #[allow(clippy::cast_possible_truncation)]
        if parent_attr.perm & (libc::S_ISGID as u16) != 0 {
            mode |= libc::S_ISGID;
        }
        attr.perm = self.creation_mode(mode);
        attr.uid = req.uid;
        attr.gid = creation_gid(&parent_attr, req.gid);

        let (_, attr) = self
            .fs
            .create(
                parent,
                &shush_rs::SecretString::from_str(name.to_str().unwrap()).unwrap(),
                attr,
                false,
                false,
            )
            .await
            .map_err(|err| {
                error!(err = %err);
                winfsp::FspError::NotFound
            })?;
        Ok(ReplyEntry {
            ttl: TTL,
            attr: attr.into(),
            generation: 0,
        })
    }

    #[instrument(skip(self, name), fields(name = name.to_str().unwrap()), err(level = Level::WARN), ret(level = Level::DEBUG))]
    async fn unlink(&self, req: &Request, parent: u64, name: &FileName) -> WinFspResult<()> {
        trace!("");

        let parent_attr = match self.fs.get_attr(parent).await {
            Err(err) => {
                error!(err = %err);
                return Err(winfsp::FspError::NotFound);
            }
            Ok(attr) => attr,
        };

        if !check_access(
            parent_attr.uid,
            parent_attr.gid,
            parent_attr.perm,
            req.uid,
            req.gid,
            libc::W_OK,
        ) {
            return Err(winfsp::FspError::AccessDenied);
        }

        let attr = match self
            .fs
            .find_by_name(
                parent,
                &shush_rs::SecretString::from_str(name.to_str().unwrap()).unwrap(),
            )
            .await
        {
            Ok(Some(attr)) => attr,
            Err(err) => {
                error!(err = %err);
                return Err(winfsp::FspError::NotFound);
            }
            _ => return Err(winfsp::FspError::NotFound),
        };

        let uid = req.uid;
        if parent_attr.perm & (libc::S_ISVTX as u16) != 0
            && uid != 0
            && uid != parent_attr.uid
            && uid != attr.uid
        {
            return Err(winfsp::FspError::AccessDenied);
        }

        if let Err(err) = self
            .fs
            .remove_file(
                parent,
                &shush_rs::SecretString::from_str(name.to_str().unwrap()).unwrap(),
            )
            .await
        {
            error!(err = %err);
            return Err(winfsp::FspError::NotFound);
        }

        Ok(())
    }

    #[instrument(skip(self, name), fields(name = name.to_str().unwrap()), err(level = Level::WARN), ret(level = Level::DEBUG))]
    async fn rmdir(&self, req: &Request, parent: u64, name: &FileName) -> WinFspResult<()> {
        trace!("");

        let parent_attr = match self.fs.get_attr(parent).await {
            Err(_) => {
                return Err(winfsp::FspError::NotFound);
            }
            Ok(attr) => attr,
        };

        if !check_access(
            parent_attr.uid,
            parent_attr.gid,
            parent_attr.perm,
            req.uid,
            req.gid,
            libc::W_OK,
        ) {
            return Err(winfsp::FspError::AccessDenied);
        }

        let attr = match self
            .fs
            .find_by_name(
                parent,
                &shush_rs::SecretString::from_str(name.to_str().unwrap()).unwrap(),
            )
            .await
        {
            Ok(Some(attr)) => attr,
            _ => return Err(winfsp::FspError::NotFound),
        };

        if attr.kind != FileType::Directory {
            return Err(winfsp::FspError::WrongType);
        }

        let uid = req.uid;
        if parent_attr.perm & (libc::S_ISVTX as u16) != 0
            && uid != 0
            && uid != parent_attr.uid
            && uid != attr.uid
        {
            return Err(winfsp::FspError::AccessDenied);
        }

        if let Err(err) = self
            .fs
            .remove_dir(
                parent,
                &shush_rs::SecretString::from_str(name.to_str().unwrap()).unwrap(),
            )
            .await
        {
            error!(err = %err);
            return match err {
                FsError::NotEmpty => Err(winfsp::FspError::NotEmpty),
                _ => Err(winfsp::FspError::IO),
            };
        }

        Ok(())
    }

    #[instrument(skip(self, name, new_name), fields(name = name.to_str().unwrap(), new_name = new_name.to_str().unwrap()), err(level = Level::WARN), ret(level = Level::DEBUG))]
    async fn rename(
        &self,
        req: &Request,
        parent: u64,
        name: &FileName,
        new_parent: u64,
        new_name: &FileName,
    ) -> WinFspResult<()> {
        trace!("");

        let attr = match self
            .fs
            .find_by_name(
                parent,
                &shush_rs::SecretString::from_str(name.to_str().unwrap()).unwrap(),
            )
            .await
        {
            Ok(Some(attr)) => attr,
            _ => return Err(winfsp::FspError::NotFound),
        };

        let parent_attr = match self.fs.get_attr(parent).await {
            Ok(attr) => attr,
            _ => return Err(winfsp::FspError::NotFound),
        };

        if !check_access(
            parent_attr.uid,
            parent_attr.gid,
            parent_attr.perm,
            req.uid,
            req.gid,
            libc::W_OK,
        ) {
            return Err(winfsp::FspError::AccessDenied);
        }

        let new_parent_attr = match self.fs.get_attr(new_parent).await {
            Ok(attr) => attr,
            _ => return Err(winfsp::FspError::NotFound),
        };

        if !check_access(
            new_parent_attr.uid,
            new_parent_attr.gid,
            new_parent_attr.perm,
            req.uid,
            req.gid,
            libc::W_OK,
        ) {
            return Err(winfsp::FspError::AccessDenied);
        }

        match self
            .fs
            .rename(
                parent,
                &shush_rs::SecretString::from_str(name.to_str().unwrap()).unwrap(),
                new_parent,
                &shush_rs::SecretString::from_str(new_name.to_str().unwrap()).unwrap(),
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(FsError::NotEmpty) => Err(winfsp::FspError::NotEmpty),
            _ => Err(winfsp::FspError::NotFound),
        }
    }

    #[instrument(skip(self), err(level = Level::WARN), ret(level = Level::DEBUG))]
    async fn open(&self, req: &Request, inode: u64, flags: u32) -> WinFspResult<ReplyOpen> {
        trace!("");

        let (access_mask, read, write) = match flags as i32 & libc::O_ACCMODE {
            libc::O_RDONLY => {
                if flags & libc::O_TRUNC as u32 != 0 {
                    return Err(winfsp::FspError::AccessDenied);
                }
                if flags & FMODE_EXEC as u32 != 0 {
                    (libc::X_OK, true, false)
                } else {
                    (libc::R_OK, true, false)
                }
            }
            libc::O_WRONLY => (libc::W_OK, false, true),
            libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
            _ => return Err(winfsp::FspError::InvalidParameter),
        };

        let truncate = flags & libc::O_TRUNC as u32 != 0;
        let attr = self.fs.get_attr(inode).await.map_err(|err| {
            error!(err = %err);
            winfsp::FspError::IO
        })?;

        if check_access(attr.uid, attr.gid, attr.perm, req.uid, req.gid, access_mask) {
            if truncate {
                self.fs.set_len(attr.ino, 0).await.map_err(|err| {
                    error!(err = %err);
                    winfsp::FspError::IO
                })?;
            }
            let fh = self
                .fs
                .open(inode, read, write)
                .await
                .map_err(|err| {
                    error!(err = %err);
                    winfsp::FspError::IO
                })?;
            Ok(ReplyOpen { fh, flags: 0 })
        } else {
            Err(winfsp::FspError::AccessDenied)
        }
    }

    #[instrument(skip(self), err(level = Level::WARN))]
    async fn read(
        &self,
        _req: &Request,
        inode: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> WinFspResult<ReplyData> {
        trace!("");

        let mut buf = vec![0; size as usize];
        match self.fs.read(inode, offset, &mut buf, fh).await {
            Err(err) => {
                error!(err = %err);
                return Err(winfsp::FspError::IO);
            }
            Ok(len) => Ok(ReplyData {
                data: Bytes::copy_from_slice(&buf[..len]),
            }),
        }
    }

    #[instrument(skip(self, data), err(level = Level::WARN), ret(level = Level::DEBUG))]
    async fn write(
        &self,
        _req: &Request,
        inode: u64,
        fh: u64,
        offset: u64,
        data: &[u8],
        _write_flags: u32,
        _flags: u32,
    ) -> WinFspResult<ReplyWrite> {
        trace!("");
        debug!(size = data.len());

        let len = self
            .fs
            .write(inode, offset, data, fh)
            .await
            .map_err(|err| {
                error!(err = %err);
                match err {
                    FsError::MaxFilesizeExceeded(_) => winfsp::FspError::FileSizeTooLarge,
                    _ => winfsp::FspError::IO,
                }
            })?;

        Ok(ReplyWrite {
            written: len as u32,
        })
    }

    #[instrument(skip(self))]
    async fn statfs(&self, _req: &Request, _inode: u64) -> WinFspResult<ReplyStatFs> {
        trace!("");
        warn!("implementation is a stub");
        Ok(ReplyStatFs {
            blocks: 1,
            bfree: 0,
            bavail: 0,
            files: 1,
            ffree: 0,
            bsize: 4096,
            namelen: u32::MAX,
            frsize: 0,
        })
    }

    #[instrument(skip(self), err(level = Level::WARN), ret(level = Level::DEBUG))]
    async fn release(
        &self,
        _req: &Request,
        inode: u64,
        fh: u64,
        _flags: u32,
        _lock_owner: u64,
        flush: bool,
    ) -> WinFspResult<()> {
        trace!("");

        let fs = self.fs.get_fs();

        if flush {
            if let Err(err) = fs.flush(fh).await {
                error!(err = %err);
                return Err(winfsp::FspError::IO);
            }
        }

        let is_write_handle = fs.is_write_handle(fh);

        if let Err(err) = fs.release(fh).await {
            error!(err = %err);
            return Err(winfsp::FspError::IO);
        }

        tokio::spawn(async move {
            if is_write_handle.await {
                let attr = match fs.get_attr(inode).await {
                    Ok(attr) => attr,
                    Err(_) => return,
                };
                let mut set_attr = SetFileAttr::default();
                set_attr = set_attr.with_perm(clear_suid_sgid(attr.perm));
                let _ = fs.set_attr(inode, set_attr).await;
            }
        });

        Ok(())
    }

    #[instrument(skip(self))]
    async fn flush(&self, _req: &Request, _inode: u64, fh: u64, _lock_owner: u64) -> WinFspResult<()> {
        trace!("");

        if let Err(err) = self.fs.flush(fh).await {
            error!(err = %err, fh);
            return Err(winfsp::FspError::IO);
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn opendir(&self, req: &Request, inode: u64, flags: u32) -> WinFspResult<ReplyOpen> {
        trace!("");

        let (access_mask, _read, _write) = match flags as i32 & libc::O_ACCMODE {
            libc::O_RDONLY => {
                if flags & libc::O_TRUNC as u32 != 0 {
                    return Err(winfsp::FspError::AccessDenied);
                }
                (libc::R_OK, true, false)
            }
            libc::O_WRONLY => (libc::W_OK, false, true),
            libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
            _ => return Err(winfsp::FspError::InvalidParameter),
        };

        let attr = match self.fs.get_attr(inode).await {
            Err(err) => {
                error!(err = %err);
                return Err(winfsp::FspError::NotFound);
            }
            Ok(attr) => attr,
        };

        if check_access(attr.uid, attr.gid, attr.perm, req.uid, req.gid, access_mask) {
            Ok(ReplyOpen { fh: 0, flags: 0 })
        } else {
            Err(winfsp::FspError::AccessDenied)
        }
    }

    type DirEntryStream<'a> = DirectoryEntryIterator where Self: 'a;

    #[instrument(skip(self), err(level = Level::DEBUG))]
    async fn readdir(
        &self,
        _req: &Request,
        inode: u64,
        _fh: u64,
        offset: i64,
    ) -> WinFspResult<ReplyDirectory<Self::DirEntryStream<'_>>> {
        trace!("");

        let iter = match self.fs.read_dir(inode).await {
            Err(err) => {
                error!(err = %err);
                return Err(winfsp::FspError::IO);
            }
            Ok(iter) => iter,
        };
        let iter = DirectoryEntryIterator(iter, 0);

        Ok(ReplyDirectory {
            entries: std::iter::once(Ok(DirectoryEntry {
                inode: 0,
                kind: winfsp::fuse::FileType::Directory,
                name: OsString::from("."),
                offset: 0,
            }))
            .chain(std::iter::once(Ok(DirectoryEntry {
                inode: 0,
                kind: winfsp::fuse::FileType::Directory,
                name: OsString::from(".."),
                offset: 1,
            })))
            .chain(iter.skip(offset as usize)),
        })
    }

    #[instrument(skip(self))]
    async fn releasedir(&self, _req: &Request, _inode: u64, _fh: u64, _flags: u32) -> WinFspResult<()> {
        trace!("");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn access(&self, req: &Request, inode: u64, mask: u32) -> WinFspResult<()> {
        trace!("");

        self.fs.get_attr(inode).await.map_or_else(
            |_| Err(winfsp::FspError::NotFound),
            |attr| {
                #[allow(clippy::cast_possible_wrap)]
                if check_access(attr.uid, attr.gid, attr.perm, req.uid, req.gid, mask as i32) {
                    Ok(())
                } else {
                    Err(winfsp::FspError::AccessDenied)
                }
            },
        )
    }

    #[instrument(skip(self, name), fields(name = name.to_str().unwrap()), err(level = Level::WARN), ret(level = Level::DEBUG))]
    async fn create(
        &self,
        req: &Request,
        parent: u64,
        name: &FileName,
        mode: u32,
        flags: u32,
    ) -> WinFspResult<ReplyCreated> {
        trace!("");

        let (read, write) = match flags as i32 & libc::O_ACCMODE {
            libc::O_RDONLY => (true, false),
            libc::O_WRONLY => (false, true),
            libc::O_RDWR => (true, true),
            _ => return Err(winfsp::FspError::InvalidParameter),
        };

        let (handle, attr) = self
            .fs
            .create_nod(parent, mode, req, name, read, write)
            .await
            .map_err(|err| {
                error!(err = %err);
                winfsp::FspError::NotFound
            })?;
        Ok(ReplyCreated {
            ttl: TTL,
            attr: attr.into(),
            generation: 0,
            fh: handle,
            flags: 0,
        })
    }

    type DirEntryPlusStream<'a> = DirectoryEntryPlusIterator where Self: 'a;

    #[instrument(skip(self), err(level = Level::DEBUG))]
    async fn readdirplus(
        &self,
        _req: &Request,
        parent: u64,
        _fh: u64,
        offset: u64,
        _lock_owner: u64,
    ) -> WinFspResult<ReplyDirectoryPlus<Self::DirEntryPlusStream<'_>>> {
        trace!("");

        let iter = match self.fs.read_dir_plus(parent).await {
            Err(err) => {
                error!(err = %err);
                return Err(winfsp::FspError::IO);
            }
            Ok(iter) => iter,
        };
        let iter = DirectoryEntryPlusIterator(iter, 0);

        Ok(ReplyDirectoryPlus {
            entries: std::iter::once(Ok(DirectoryEntryPlus {
                inode: 0,
                generation: 0,
                kind: winfsp::fuse::FileType::Directory,
                name: OsString::from("."),
                offset: 0,
                attr: FileAttr {
                    ino: 0,
                    size: 0,
                    blocks: 0,
                    atime: std::time::SystemTime::now(),
                    mtime: std::time::SystemTime::now(),
                    ctime: std::time::SystemTime::now(),
                    crtime: std::time::SystemTime::now(),
                    kind: FileType::Directory,
                    perm: 0o777,
                    nlink: 2,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 0,
                    flags: 0,
                }.into(),
                entry_ttl: TTL,
                attr_ttl: TTL,
            }))
            .chain(std::iter::once(Ok(DirectoryEntryPlus {
                inode: 0,
                generation: 0,
                kind: winfsp::fuse::FileType::Directory,
                name: OsString::from(".."),
                offset: 1,
                attr: FileAttr {
                    ino: 0,
                    size: 0,
                    blocks: 0,
                    atime: std::time::SystemTime::now(),
                    mtime: std::time::SystemTime::now(),
                    ctime: std::time::SystemTime::now(),
                    crtime: std::time::SystemTime::now(),
                    kind: FileType::Directory,
                    perm: 0o777,
                    nlink: 2,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 0,
                    flags: 0,
                }.into(),
                entry_ttl: TTL,
                attr_ttl: TTL,
            })))
            .chain(iter.skip(offset as usize)),
        })
    }

    #[instrument(skip(self))]
    async fn copy_file_range(
        &self,
        _req: &Request,
        inode: u64,
        fh_in: u64,
        off_in: u64,
        inode_out: u64,
        fh_out: u64,
        off_out: u64,
        length: u64,
        _flags: u64,
    ) -> WinFspResult<ReplyCopyFileRange> {
        trace!("");
        let file_range_req = CopyFileRangeReq::builder()
            .src_ino(inode)
            .src_offset(off_in)
            .dest_ino(inode_out)
            .dest_offset(off_out)
            .src_fh(fh_in)
            .dest_fh(fh_out)
            .build();
        #[allow(clippy::cast_possible_truncation)]
        match self
            .fs
            .copy_file_range(&file_range_req, length as usize)
            .await
        {
            Err(err) => {
                error!(err = %err);
                return Err(winfsp::FspError::IO);
            }
            Ok(len) => Ok(ReplyCopyFileRange { copied: len as u64 }),
        }
    }
}

fn check_access(
    file_uid: u32,
    file_gid: u32,
    file_mode: u16,
    uid: u32,
    gid: u32,
    access_mask: i32,
) -> bool {
    if access_mask == libc::F_OK {
        return true;
    }
    let file_mode = i32::from(file_mode);

    if uid == 0 {
        let mut mask = access_mask & libc::X_OK;
        mask -= mask & (file_mode >> 6);
        mask -= mask & (file_mode >> 3);
        mask -= mask & file_mode;
        return mask == 0;
    }

    if uid == file_uid {
        access_mask -= access_mask & (file_mode >> 6);
    } else if gid == file_gid {
        access_mask -= access_mask & (file_mode >> 3);
    } else {
        access_mask -= access_mask & file_mode;
    }

    access_mask == 0
}

#[allow(clippy::cast_possible_truncation)]
const fn clear_suid_sgid(mut perm: u16) -> u16 {
    perm &= !(libc::S_ISUID as u16);
    if perm & (libc::S_IXGRP as u16) != 0 {
        perm &= !(libc::S_ISGID as u16);
    }
    perm
}

fn as_file_kind(mut mode: u32) -> FileType {
    mode &= libc::S_IFMT;
    if mode == libc::S_IFREG {
        FileType::RegularFile
    } else if mode == libc::S_IFDIR {
        FileType::Directory
    } else {
        unimplemented!("{mode}");
    }
}

const fn dir_attr() -> CreateFileAttr {
    CreateFileAttr {
        kind: FileType::Directory,
        perm: 0o777,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    }
}

const fn file_attr() -> CreateFileAttr {
    CreateFileAttr {
        kind: FileType::RegularFile,
        perm: 0o644,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    }
}

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
        let handle = mount_winfsp(
            self.mountpoint.clone(),
            self.data_dir.clone(),
            self.password_provider.take().unwrap(),
            self.cipher,
            self.allow_root,
            self.allow_other,
            self.read_only,
        )
        .await?;
        Ok(mount::MountHandle {
            inner: MountHandleInnerImpl { inner: handle },
        })
    }
}

pub(in crate::mount) struct MountHandleInnerImpl {
    inner: MountHandle,
}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_unpin(cx)
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        self.inner.unmount().await
    }
}

#[instrument(skip(password_provider))]
async fn mount_winfsp(
    mountpoint: PathBuf,
    data_dir: PathBuf,
    password_provider: Box<dyn PasswordProvider>,
    cipher: Cipher,
    allow_root: bool,
    allow_other: bool,
    read_only: bool,
) -> FsResult<MountHandle> {
    if !mountpoint.exists() {
        std::fs::create_dir_all(&mountpoint)?;
    }

    let mount_options = winfsp::MountOptions::default()
        .read_only(read_only)
        .allow_root(allow_root)
        .allow_other(allow_other)
        .fs_name("rencfs");

    let mount_path = winfsp::FileName::from(mountpoint.to_str().unwrap());

    info!("Checking password and mounting WinFSP filesystem");
    Ok(Session::new(mount_options)
        .mount_with_unprivileged(
            EncryptedFsHost::new(data_dir, password_provider, cipher, read_only).await?,
            &mount_path,
        )
        .await?)
}
