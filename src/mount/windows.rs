use std::collections::HashMap;
use std::ffi::OsStr;
use std::future::Future;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::runtime::Handle;
use tokio::sync::oneshot;
use tracing::{debug, info, instrument, warn};

use crate::crypto::Cipher;
use crate::encryptedfs::{
    DirectoryEntry, EncryptedFs, FileAttr, FileType, FsError, FsResult, PasswordProvider,
};
use crate::mount::{MountHandle, MountHandleInner, MountPoint};

const ROOT_INODE: u64 = 1;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const WINDOWS_TICK: u64 = 10_000_000;
const SEC_TO_UNIX_EPOCH: u64 = 11_644_473_600;

/// Windows file metadata representation compatible with WinFsp `FSP_FSCTL_FILE_INFO`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinFspFileInfo {
    pub file_attributes: u32,
    pub allocation_size: u64,
    pub file_size: u64,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub index_number: u64,
}

impl WinFspFileInfo {
    #[must_use]
    pub fn from_attr(attr: &FileAttr, read_only_mount: bool) -> Self {
        let mut file_attributes = match attr.kind {
            FileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
            FileType::RegularFile => FILE_ATTRIBUTE_NORMAL,
        };
        if read_only_mount || (attr.perm & 0o200 == 0) {
            file_attributes |= FILE_ATTRIBUTE_READONLY;
        }
        let allocation_size = ((attr.size + 4095) / 4096) * 4096;
        Self {
            file_attributes,
            allocation_size,
            file_size: attr.size,
            creation_time: system_time_to_filetime(attr.crtime),
            last_access_time: system_time_to_filetime(attr.atime),
            last_write_time: system_time_to_filetime(attr.mtime),
            change_time: system_time_to_filetime(attr.ctime),
            index_number: attr.ino,
        }
    }
}

/// Converts a `SystemTime` into a Windows 64-bit `FILETIME` (100-ns intervals since 1601-01-01).
#[must_use]
pub fn system_time_to_filetime(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs().saturating_add(SEC_TO_UNIX_EPOCH);
            let nanos_100 = u64::from(d.subsec_nanos() / 100);
            secs.saturating_mul(WINDOWS_TICK).saturating_add(nanos_100)
        }
        Err(_) => SEC_TO_UNIX_EPOCH * WINDOWS_TICK,
    }
}

/// Converts a Windows 64-bit `FILETIME` back to `SystemTime`.
#[must_use]
pub fn filetime_to_system_time(filetime: u64) -> SystemTime {
    let total_secs = filetime / WINDOWS_TICK;
    let subsec_100ns = filetime % WINDOWS_TICK;
    if total_secs >= SEC_TO_UNIX_EPOCH {
        let unix_secs = total_secs - SEC_TO_UNIX_EPOCH;
        UNIX_EPOCH + Duration::new(unix_secs, (subsec_100ns as u32) * 100)
    } else {
        UNIX_EPOCH
    }
}

/// Resolves a Windows relative path (e.g. `\dir\sub\file.txt`) into normalized path segments.
#[must_use]
pub fn split_windows_path(win_path: &str) -> Vec<String> {
    let normalized = win_path.replace('\\', "/");
    Path::new(&normalized)
        .components()
        .filter_map(|c| match c {
            Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

/// Open context tracked for each WinFsp file or directory handle.
#[derive(Debug, Clone)]
pub struct WinFspOpenContext {
    pub ino: u64,
    pub fh: u64,
    pub is_directory: bool,
    pub delete_on_close: bool,
    pub parent_ino: u64,
    pub name: String,
}

/// Bridge translating path-based WinFsp callbacks onto the inode-based `EncryptedFs`.
pub struct WinFspBridge {
    fs: Arc<EncryptedFs>,
    read_only: bool,
    path_cache: RwLock<HashMap<String, u64>>,
}

impl WinFspBridge {
    #[must_use]
    pub fn new(fs: Arc<EncryptedFs>, read_only: bool) -> Self {
        let mut map = HashMap::new();
        map.insert(String::from("/"), ROOT_INODE);
        Self {
            fs,
            read_only,
            path_cache: RwLock::new(map),
        }
    }

    /// Resolves a Windows path (`\a\b\c`) to `(parent_inode, leaf_name, target_inode)`.
    pub async fn resolve_path(&self, win_path: &str) -> FsResult<(u64, String, u64)> {
        let segments = split_windows_path(win_path);
        if segments.is_empty() {
            return Ok((ROOT_INODE, String::new(), ROOT_INODE));
        }

        let mut current_ino = ROOT_INODE;
        let mut parent_ino = ROOT_INODE;
        let mut current_key = String::new();

        for seg in &segments {
            parent_ino = current_ino;
            current_key.push('/');
            current_key.push_str(seg);

            if let Some(&cached) = self.path_cache.read().unwrap().get(&current_key) {
                if self.fs.exists(cached) {
                    current_ino = cached;
                    continue;
                }
            }

            let attr = self.fs.find_by_name(parent_ino, seg).await?.ok_or(FsError::NotFound("path segment not found"))?;
            current_ino = attr.ino;
            self.path_cache.write().unwrap().insert(current_key.clone(), current_ino);
        }

        let leaf = segments.last().cloned().unwrap_or_default();
        Ok((parent_ino, leaf, current_ino))
    }

    pub async fn get_file_info(&self, win_path: &str) -> FsResult<WinFspFileInfo> {
        let (_, _, ino) = self.resolve_path(win_path).await?;
        let attr = self.fs.get_attr(ino).await?;
        Ok(WinFspFileInfo::from_attr(&attr, self.read_only))
    }

    pub async fn read_directory(&self, win_path: &str) -> FsResult<Vec<(String, WinFspFileInfo)>> {
        let (_, _, dir_ino) = self.resolve_path(win_path).await?;
        let iter = self.fs.read_dir(dir_ino).await?;
        let mut entries = Vec::new();
        for item in iter {
            let DirectoryEntry { name, kind, ino } = item?;
            let attr = self.fs.get_attr(ino).await?;
            let mut info = WinFspFileInfo::from_attr(&attr, self.read_only);
            if matches!(kind, FileType::Directory) {
                info.file_attributes |= FILE_ATTRIBUTE_DIRECTORY;
            }
            entries.push((name, info));
        }
        Ok(entries)
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

    #[instrument(skip(self))]
    async fn mount(mut self) -> FsResult<MountHandle> {
        let password_provider = self
            .password_provider
            .take()
            .ok_or(FsError::Other("Password provider already consumed"))?;

        let fs = Arc::new(
            EncryptedFs::new(
                &self.data_dir,
                password_provider,
                self.cipher,
                self.read_only,
            )
            .await?,
        );
        let bridge = Arc::new(WinFspBridge::new(fs.clone(), self.read_only));
        info!(
            mountpoint = %self.mountpoint.display(),
            read_only = self.read_only,
            allow_root = self.allow_root,
            allow_other = self.allow_other,
            "Initialized Windows WinFsp encrypted filesystem bridge"
        );

        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let mounted = Arc::new(AtomicBool::new(true));
        let mounted_bg = mounted.clone();
        let bridge_bg = bridge.clone();
        let _rt = Handle::current();

        let join_handle = tokio::spawn(async move {
            let _ = bridge_bg.get_file_info("\").await;
            let _ = stop_rx.await;
            debug!("Stopping Windows WinFsp mount session");
            if let Err(err) = fs.flush_all().await {
                warn!(error = %err, "Failed to flush all open handles during Windows unmount");
            }
            mounted_bg.store(false, Ordering::SeqCst);
            Ok::<(), io::Error>(())
        });

        Ok(MountHandle {
            inner: MountHandleInnerImpl {
                stop_tx: Some(stop_tx),
                join_handle,
                mounted,
            },
        })
    }
}

pub(in crate::mount) struct MountHandleInnerImpl {
    stop_tx: Option<oneshot::Sender<()>>,
    join_handle: tokio::task::JoinHandle<io::Result<()>>,
    mounted: Arc<AtomicBool>,
}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.join_handle)
            .poll(cx)
            .map(|res| res.unwrap_or_else(|err| Err(io::Error::new(io::ErrorKind::Other, err))))
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        self.mounted.store(false, Ordering::SeqCst);
        match self.join_handle.await {
            Ok(res) => res,
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, err)),
        }
    }
}
