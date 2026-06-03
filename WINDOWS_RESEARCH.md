# Windows Implementation Research for rencfs

## 1. The Core Problem
Currently, rencfs relies heavily on Linux FUSE to mount the encrypted directories. Windows does not natively support FUSE, meaning we need a user-mode file system driver that acts as an equivalent.

## 2. The Contenders: WinFSP vs. Dokany
When migrating Rust FUSE projects to Windows, there are two primary options:

* **Dokany (dokan-rust):** The older standard. While it works, the Rust bindings are notoriously tricky to maintain, and performance under heavy I/O can suffer.
* **WinFSP (winfsp-rs):** WinFSP is significantly faster, more stable, and acts exactly like FUSE for Windows. Using native Rust bindings via winfsp-rs is the safest, most performant route.

## 3. Security & Memory Wiping (The zeroize Requirement)
Because rencfs zeroes out encryption keys and buffers from memory, the chosen Windows framework must allow us to safely handle raw byte buffers before handing them off to the OS. winfsp-rs allows us to intercept read/write buffers directly in Rust, meaning we can apply our zeroize logic immediately after the encrypted data is passed to the Windows file manager, preventing memory leaks.

## 4. Architectural Path Forward
Instead of maintaining two entirely separate codebases, rencfs should use Rust's conditional compilation. 

1. Abstract the file system operations into a core trait.
2. On Linux, the fuser crate implements this trait.
3. On Windows, winfsp-rs implements this trait. 

## 5. Basic Proof of Concept (Rust + WinFSP)

```rust
#[cfg(target_os = "windows")]
use winfsp::filesystem::{FileSystemContext, FileSystemFlags};
#[cfg(target_os = "windows")]
use winfsp::service::WinFspService;

#[cfg(target_os = "windows")]
pub struct RencfsWindows {
    mount_path: String,
}

#[cfg(target_os = "windows")]
impl FileSystemContext for RencfsWindows {}

#[cfg(target_os = "windows")]
pub fn mount_windows_drive(mount_point: &str) {
    let fs = RencfsWindows {
        mount_path: mount_point.to_string(),
    };
    
    let service = WinFspService::new(mount_point, fs, FileSystemFlags::default());
    println!("Mounted rencfs on Windows at {}", mount_point);
    
    service.start().expect("Failed to start WinFSP service");
}
