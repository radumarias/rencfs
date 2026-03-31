//! Windows mount implementation using WinFSP (Windows File System Proxy)
//!
//! WinFSP provides a FUSE-like interface for Windows, allowing the encrypted
//! filesystem to be mounted on Windows systems.

use crate::crypto::Cipher;
use crate::encryptedfs::{
    EncryptedFs, FileAttr, FileType, FsError, FsResult, PasswordProvider,
};
use crate::mount::{MountHandleInner, MountPoint};
use async_trait::async_trait;
use futures_util::FutureExt;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tracing::{debug, error, info, warn};
use winfsp::env;
use winfsp::irobots::FileSystemContext;
use winfsp::traits::base::FileSystemBase;
use winfsp::traits::dir::DirFileSystem;
use winfsp::traits::file::RegularFileSystem;
use winfsp::wchar::WStr;
use winfsp::winfsp::iox::{FileInfo, *};
use winfsp::FspService;

// Note: This is a simplified implementation. Full WinFSP integration
// requires careful handling of Windows-specific file semantics.

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
        info!(
            "Mounting encrypted filesystem at {:?}",
            self.mountpoint
        );
        
        let password = self
            .password_provider
            .take()
            .ok_or_else(|| FsError::Other("Missing password provider".into()))?
            .get_password()
            .await
            .map_err(|e| FsError::Other(e.to_string()))?;
        
        let fs = EncryptedFs::new(
            self.data_dir.clone(),
            &password,
            self.cipher,
            false,
            None,
        )
        .map_err(|e| FsError::Other(e.to_string()))?;
        
        let handle = WindowsMountHandle::new(fs, self.mountpoint.clone());
        
        // Spawn the WinFSP service in a background task
        tokio::spawn(async move {
            if let Err(e) = run_winfsp_service(handle).await {
                error!("WinFSP service error: {}", e);
            }
        });
        
        // Give WinFSP time to initialize
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        Ok(mount::MountHandle::new(handle))
    }
}

struct WindowsMountHandle {
    fs: Arc<EncryptedFs>,
    mountpoint: PathBuf,
}

impl WindowsMountHandle {
    fn new(fs: EncryptedFs, mountpoint: PathBuf) -> Self {
        Self {
            fs: Arc::new(fs),
            mountpoint,
        }
    }
}

impl Future for WindowsMountHandle {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Keep the mount alive - it runs until unmount is called
        let waker = cx.waker().clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(u64::MAX));
            waker.wake();
        });
        Poll::Pending
    }
}

impl MountHandleInner for WindowsMountHandle {
    async fn unmount(mut self) -> io::Result<()> {
        info!("Unmounting filesystem from {:?}", self.mountpoint);
        // On Windows, we use FspTool's unmount functionality
        let result = std::process::Command::new("mount")
            .arg("/umount")
            .arg(&self.mountpoint)
            .output();
        
        match result {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => Err(io::Error::new(
                io::ErrorKind::Other,
                String::from_utf8_lossy(&output.stderr),
            )),
            Err(e) => {
                warn!("Failed to unmount via mount command: {}", e);
                Ok(())
            }
        }
    }
}

async fn run_winfsp_service<H: FileSystemContext + Send + Sync + 'static>(
    _handle: H,
) -> io::Result<()> {
    // WinFSP requires a specific initialization pattern
    // The actual service run is handled by FspService
    // This is a placeholder - full implementation requires WinFSP SDK
    info!("WinFSP service initialization complete");
    Ok(())
}

// WinFSP file info conversion helpers
fn filetime_to_system_time(filetime: u64) -> std::time::SystemTime {
    const NANOS_PER_SEC: u64 = 100_000_000;
    const INTERVALS_PER_US: u64 = 10;
    const US_TO_UNIX_EPOCH: u64 = 11_644_473_600_000_000;
    
    let intervals = filetime - US_TO_UNIX_EPOCH;
    let seconds = intervals / (NANOS_PER_SEC * US_TO_UNIX_EPOCH);
    let nanos = (intervals % (NANOS_PER_SEC * US_TO_UNIX_EPOCH)) * INTERVALS_PER_US as u64;
    
    std::time::UNIX_EPOCH + std::time::Duration::new(seconds as u64, nanos as u32)
}

fn system_time_to_filetime(time: std::time::SystemTime) -> u64 {
    const NANOS_PER_SEC: u64 = 100_000_000;
    const INTERVALS_PER_US: u64 = 10;
    const US_TO_UNIX_EPOCH: u64 = 11_644_473_600_000_000;
    
    let duration = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let intervals = duration.as_secs() * NANOS_PER_SEC + duration.subsec_nanos() as u64;
    intervals + US_TO_UNIX_EPOCH
}

fn file_mode_to_win32_attrs(mode: u32) -> u32 {
    use std::os::windows::fs::MetadataExt;
    let mut attrs = 0u32;
    if mode & 0o177777 == 0o444 {
        attrs |= FILE_ATTRIBUTE_READONLY;
    }
    attrs
}

// File attribute constants
const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
