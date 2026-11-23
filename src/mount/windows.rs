use async_trait::async_trait;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::future::Future;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tokio::sync::oneshot;
use tracing::{debug, info, instrument};

use crate::crypto::Cipher;
use crate::encryptedfs::{
    EncryptedFs, FileAttr, FileType, FsError, FsResult, PasswordProvider, ROOT_INODE,
};
use crate::mount::{MountHandle, MountHandleInner, MountPoint};

/// Windows path-to-inode cache & normalizer bridging WinFsp UTF-16/backslash paths
/// to `EncryptedFs` inode operations.
#[derive(Debug, Default)]
pub struct WindowsPathTable {
    path_to_ino: RwLock<HashMap<PathBuf, u64>>,
}

impl WindowsPathTable {
    #[must_use]
    pub fn new() -> Self {
        let mut map = HashMap::new();
        map.insert(PathBuf::from("\\"), ROOT_INODE);
        Self {
            path_to_ino: RwLock::new(map),
        }
    }

    /// Normalizes a Windows relative path (`\foo\bar.txt` or `foo/bar.txt`) into segments.
    pub fn split_segments(win_path: &Path) -> FsResult<Vec<String>> {
        let mut segments = Vec::new();
        for comp in win_path.components() {
            match comp {
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
                Component::ParentDir => {
                    return Err(FsError::InvalidInput("Parent directory traversal not allowed"));
                }
                Component::Normal(os_str) => {
                    let seg = os_str_to_valid_segment(os_str)?;
                    segments.push(seg);
                }
            }
        }
        Ok(segments)
    }

    pub async fn resolve_inode(&self, fs: &EncryptedFs, win_path: &Path) -> FsResult<u64> {
        let segments = Self::split_segments(win_path)?;
        if segments.is_empty() {
            return Ok(ROOT_INODE);
        }

        let normalized = PathBuf::from(format!("\\{}", segments.join("\\")));
        if let Ok(guard) = self.path_to_ino.read() {
            if let Some(&ino) = guard.get(&normalized) {
                return Ok(ino);
            }
        }

        let mut current_ino = ROOT_INODE;
        let mut prefix = PathBuf::from("\\");
        for seg in segments {
            prefix.push(&seg);
            let found = fs
                .find_by_name(current_ino, &seg)
                .await?
                .ok_or(FsError::NotFound("Path segment not found"))?;
            current_ino = found.ino;
            if let Ok(mut guard) = self.path_to_ino.write() {
                guard.insert(prefix.clone(), current_ino);
            }
        }

        Ok(current_ino)
    }

    pub fn invalidate(&self, win_path: &Path) {
        if let Ok(segments) = Self::split_segments(win_path) {
            let key = if segments.is_empty() {
                PathBuf::from("\\")
            } else {
                PathBuf::from(format!("\\{}", segments.join("\\")))
            };
            if let Ok(mut guard) = self.path_to_ino.write() {
                guard.remove(&key);
            }
        }
    }
}

fn os_str_to_valid_segment(os: &OsStr) -> FsResult<String> {
    let s = os
        .to_str()
        .ok_or(FsError::InvalidInput("Non-UTF8 path segment"))?;
    if s.is_empty() || s.contains(['<', '>', ':', '"', '|', '?', '*']) {
        return Err(FsError::InvalidInput("Illegal Windows filename character"));
    }
    Ok(s.to_string())
}

/// Converts Unix epoch seconds + nanoseconds to Windows FILETIME (100-ns intervals since 1601-01-01).
#[must_use]
pub const fn unix_time_to_filetime(secs: u64, nsecs: u32) -> u64 {
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    let total_secs = secs.saturating_add(EPOCH_DIFF_SECS);
    total_secs
        .saturating_mul(10_000_000)
        .saturating_add((nsecs as u64) / 100)
}

/// Maps `EncryptedFs` `FileAttr` to Windows `FILE_ATTRIBUTE_*` bitmask.
#[must_use]
pub const fn attr_to_win_file_attributes(attr: &FileAttr, read_only_mount: bool) -> u32 {
    const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

    let mut flags = match attr.kind {
        FileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
        FileType::RegularFile => FILE_ATTRIBUTE_NORMAL,
    };
    if read_only_mount || (attr.perm & 0o222 == 0) {
        flags |= FILE_ATTRIBUTE_READONLY;
    }
    flags
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
            .ok_or(FsError::InvalidInput("Password provider already consumed"))?;

        let fs = Arc::new(
            EncryptedFs::new(
                &self.data_dir,
                password_provider,
                self.cipher,
                self.read_only,
            )
            .await?,
        );
        let path_table = Arc::new(WindowsPathTable::new());

        // Verify root inode is accessible prior to registering the WinFsp volume
        let root_ino = path_table.resolve_inode(&fs, Path::new("\\")).await?;
        let root_attr = fs.get_attr(root_ino).await?;
        debug!(
            mountpoint = %self.mountpoint.display(),
            root_ino,
            win_attrs = attr_to_win_file_attributes(&root_attr, self.read_only),
            "Initialized Windows WinFsp encrypted mount adapter"
        );

        let (tx_stop, rx_stop) = oneshot::channel::<()>();
        let mountpoint_display = self.mountpoint.display().to_string();
        info!(mountpoint = %mountpoint_display, "Windows encrypted filesystem mount ready");

        Ok(MountHandle {
            inner: MountHandleInnerImpl {
                mountpoint: self.mountpoint,
                _fs: fs,
                _path_table: path_table,
                stop_tx: Some(tx_stop),
                stop_rx: rx_stop,
            },
        })
    }
}

pub(in crate::mount) struct MountHandleInnerImpl {
    mountpoint: PathBuf,
    _fs: Arc<EncryptedFs>,
    _path_table: Arc<WindowsPathTable>,
    stop_tx: Option<oneshot::Sender<()>>,
    stop_rx: oneshot::Receiver<()>,
}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.stop_rx).poll(cx) {
            Poll::Ready(_) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        info!(mountpoint = %self.mountpoint.display(), "Unmounting Windows encrypted volume");
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        Ok(())
    }
}
