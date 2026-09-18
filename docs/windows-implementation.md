# Windows Implementation & Deployment Research for rencfs

This document details the architectural design and deployment options for running `rencfs` on Windows.

## 1. Cross-Platform Configuration Path Resolution
On Windows, configuration should be stored in `%APPDATA%\rencfs\config.yaml` or `%LOCALAPPDATA%\rencfs\config.yaml`.

Using the `dirs` crate:
```rust
use std::path::PathBuf;

pub fn get_config_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        dirs::data_dir()
            .map(|p| p.join("rencfs"))
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\rencfs"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        dirs::config_dir()
            .map(|p| p.join("rencfs"))
            .unwrap_or_else(|| PathBuf::from("/etc/rencfs"))
    }
}
2. Deployment Models for Windows
Option A: Windows Service Controller via NSSM (Recommended)
NSSM (Non-Sucking Service Manager) allows managing the binary as a background Windows Service with auto-restart and logging:


# Install service
nssm install rencfs-daemon "C:\Program Files\rencfs\rencfs-daemon.exe" "--config" "$env:APPDATA\rencfs\config.yaml"
nssm set rencfs-daemon AppStdout "$env:APPDATA\rencfs\daemon.log"
nssm set rencfs-daemon AppStderr "$env:APPDATA\rencfs\error.log"
nssm set rencfs-daemon Start SERVICE_AUTO_START

# Start service
nssm start rencfs-daemon
Option B: Native Windows Service via windows-service Crate
Add dependency for Windows targets in Cargo.toml:


[target.'cfg(windows)'.dependencies]
windows-service = "0.7"
