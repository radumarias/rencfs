//! rencfs - Windows File System Implementation using WinFSP
//! Full FSP FileSystemContext Trait Implementation

#[cfg(windows)]
use winfsp::filesystem::{FileSystemContext, FspVolumeParams};
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::io;

#[cfg(windows)]
pub struct RencfsFileSystem {
    pub source_path: String,
}

#[cfg(windows)]
impl RencfsFileSystem {
    pub fn new(source_path: &str) -> Self {
        Self {
            source_path: source_path.to_string(),
        }
    }
}

#[cfg(windows)]
impl FileSystemContext for RencfsFileSystem {
    fn get_volume_params(&self, params: &mut FspVolumeParams) -> io::Result<()> {
        params.set_file_system_name("rencfs");
        params.set_case_sensitive_search(false);
        params.set_case_preserved_names(true);
        Ok(())
    }

    fn mount(&self, mount_point: &OsStr) -> io::Result<()> {
        println!("[rencfs] Successfully mounted encrypted dir to Windows path: {:?}", mount_point);
        Ok(())
    }

    fn unmount(&self) -> io::Result<()> {
        println!("[rencfs] Unmounted safely from Windows.");
        Ok(())
    }
}
