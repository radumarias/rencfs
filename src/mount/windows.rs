use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tracing::error;

use crate::crypto::Cipher;
use crate::encryptedfs::{FsError, FsResult, PasswordProvider};
use crate::mount;
use crate::mount::{MountHandleInner, MountPoint};

/// Seconds between the Windows FILETIME epoch (1601-01-01 00:00:00 UTC)
/// and the Unix epoch (1970-01-01 00:00:00 UTC).
pub const FILETIME_UNIX_EPOCH_DIFF_SECS: u64 = 11_644_473_600;

/// Number of 100-nanosecond ticks in one second.
pub const FILETIME_TICKS_PER_SEC: u64 = 10_000_000;

/// Windows FILETIME value for the Unix epoch (1970-01-01 00:00:00 UTC).
pub const FILETIME_AT_UNIX_EPOCH: u64 = FILETIME_UNIX_EPOCH_DIFF_SECS * FILETIME_TICKS_PER_SEC;

/// Convert a Windows FILETIME (100-nanosecond intervals since 1601-01-01)
/// into a standard [`SystemTime`].
///
/// Values before the Unix epoch saturate to [`UNIX_EPOCH`].
#[must_use]
pub fn filetime_to_system_time(filetime: u64) -> SystemTime {
    let secs = filetime / FILETIME_TICKS_PER_SEC;
    let nanos = (filetime % FILETIME_TICKS_PER_SEC) * 100;
    match secs.checked_sub(FILETIME_UNIX_EPOCH_DIFF_SECS) {
        #[allow(clippy::cast_possible_truncation)]
        Some(secs) => UNIX_EPOCH + Duration::new(secs, nanos as u32),
        None => UNIX_EPOCH,
    }
}

/// Convert a [`SystemTime`] into a Windows FILETIME (100-nanosecond intervals
/// since 1601-01-01 00:00:00 UTC).
///
/// Timestamps preceding the Unix epoch saturate to 0.
#[must_use]
pub fn system_time_to_filetime(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration
            .as_secs()
            .saturating_add(FILETIME_UNIX_EPOCH_DIFF_SECS)
            .saturating_mul(FILETIME_TICKS_PER_SEC)
            .saturating_add(u64::from(duration.subsec_nanos() / 100)),
        Err(_) => 0,
    }
}

/// Reserved Windows 8.3 and Win32 legacy device base names.
/// Matches are performed case-insensitively on the stem preceding any file extension.
const WINDOWS_RESERVED_DEVICE_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Checks whether a filename represents a reserved Windows device name
/// (e.g. `CON`, `PRN`, `aux.txt`, `com1.dat`).
#[must_use]
pub fn is_reserved_windows_name(name: &str) -> bool {
    let base = match name.find('.') {
        Some(idx) => &name[..idx],
        None => name,
    };
    WINDOWS_RESERVED_DEVICE_NAMES
        .iter()
        .any(|&reserved| base.eq_ignore_ascii_case(reserved))
}

/// Validate that a filename segment adheres to Windows NTFS/Win32 naming constraints.
///
/// Returns `Err` with a human-readable explanation if the name contains invalid
/// characters, trailing dots/spaces, or reserved device names.
pub fn validate_windows_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("Filename cannot be empty");
    }
    if name == "." || name == ".." {
        return Err("Filename cannot be '.' or '..'");
    }
    if name.ends_with('.') {
        return Err("Filename cannot end with a period");
    }
    if name.ends_with(' ') {
        return Err("Filename cannot end with a space");
    }
    for ch in name.chars() {
        if (ch as u32) < 32 {
            return Err("Filename cannot contain ASCII control characters");
        }
        match ch {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => {
                return Err("Filename contains forbidden characters (<> : \" / \\ | ? *)");
            }
            _ => {}
        }
    }
    if is_reserved_windows_name(name) {
        return Err("Filename is a reserved Windows device name");
    }
    Ok(())
}

/// Split and normalize a Windows path string into clean directory/file components.
/// Strips drive letters (`C:`), extended-length prefixes (`\\?\`), and handles both `/` and `\`.
#[must_use]
pub fn split_windows_path(path: &str) -> Vec<&str> {
    let mut p = path;
    // Strip Windows extended length prefix \\?\ or \\.\
    if p.starts_with(r"\\?\") || p.starts_with(r"\\.\") {
        p = &p[4..];
    }
    // Strip drive letter if present (e.g., C:\ -> \)
    let bytes = p.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        p = &p[2..];
    }
    p.split(['/', '\\'])
        .filter(|segment| !segment.is_empty())
        .collect()
}

/// Windows mount point implementation.
///
/// Live filesystem mounting on Windows requires a Windows user-mode filesystem
/// host such as WinFsp. In the absence of an active WinFsp driver runtime,
/// attempting to mount returns a descriptive [`FsError::Other`].
#[allow(clippy::struct_excessive_bools)]
#[allow(dead_code)]
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
        // Native Windows mounting requires the WinFsp kernel driver and runtime service.
        // Return an actionable error describing the prerequisite.
        Err(FsError::Other(
            "Windows native filesystem mounting requires WinFsp driver runtime. Live mount backend is not yet attached.",
        ))
    }
}

pub(in crate::mount) struct MountHandleInnerImpl {}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        error!("Windows mount handle polling is not active");
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime_epoch_and_roundtrip() {
        // Known epoch equivalence:
        // Unix epoch (1970-01-01T00:00:00Z) == 11644473600 seconds * 10^7 ticks
        assert_eq!(system_time_to_filetime(UNIX_EPOCH), FILETIME_AT_UNIX_EPOCH);
        assert_eq!(filetime_to_system_time(FILETIME_AT_UNIX_EPOCH), UNIX_EPOCH);

        // Pre-Unix-epoch time should saturate to 0 for filetime, and 0 maps to UNIX_EPOCH
        assert_eq!(filetime_to_system_time(0), UNIX_EPOCH);
        assert_eq!(
            system_time_to_filetime(UNIX_EPOCH - Duration::from_secs(10)),
            0
        );

        // Known timestamp: 2024-01-01T00:00:00Z == 1,704,067,200 Unix seconds
        let y2024 = UNIX_EPOCH + Duration::from_secs(1_704_067_200);
        let expected_ft = (1_704_067_200 + FILETIME_UNIX_EPOCH_DIFF_SECS) * FILETIME_TICKS_PER_SEC;
        assert_eq!(system_time_to_filetime(y2024), expected_ft);
        assert_eq!(filetime_to_system_time(expected_ft), y2024);

        // Subsecond tick resolution: 10 ticks = 1000 ns (1 microsecond)
        let subsecond_time = filetime_to_system_time(FILETIME_AT_UNIX_EPOCH + 10);
        assert_eq!(subsecond_time, UNIX_EPOCH + Duration::from_nanos(1000));

        // Roundtrip with current system time (within 100ns precision loss)
        let now = SystemTime::now();
        let ft = system_time_to_filetime(now);
        let roundtripped = filetime_to_system_time(ft);
        let diff = if now >= roundtripped {
            now.duration_since(roundtripped).unwrap()
        } else {
            roundtripped.duration_since(now).unwrap()
        };
        assert!(diff <= Duration::from_nanos(100));
    }

    #[test]
    fn test_reserved_windows_names() {
        let reserved_cases = [
            "CON",
            "con",
            "Con.txt",
            "PRN",
            "prn.log",
            "AUX",
            "NUL",
            "nul.tar.gz",
            "COM1",
            "com1.txt",
            "COM9",
            "com9.dat",
            "LPT1",
            "lpt1.prn",
            "LPT9",
        ];
        for name in reserved_cases {
            assert!(
                is_reserved_windows_name(name),
                "Expected '{name}' to be recognized as reserved"
            );
        }

        let non_reserved_cases = [
            "console",
            "prn2",
            "COM10",
            "com10.txt",
            "LPT10",
            "nulfile",
            "normal.txt",
            "my_document.pdf",
            "auxiliary",
        ];
        for name in non_reserved_cases {
            assert!(
                !is_reserved_windows_name(name),
                "Expected '{name}' to NOT be reserved"
            );
        }
    }

    #[test]
    fn test_validate_windows_name() {
        let valid_names = [
            "document.txt",
            "notes",
            "my file (1).zip",
            "a-b_c.d",
            "COM10.txt",
            "report_2026.docx",
        ];
        for name in valid_names {
            assert!(
                validate_windows_name(name).is_ok(),
                "Expected valid name '{name}' to pass"
            );
        }

        assert_eq!(validate_windows_name(""), Err("Filename cannot be empty"));
        assert_eq!(
            validate_windows_name("."),
            Err("Filename cannot be '.' or '..'")
        );
        assert_eq!(
            validate_windows_name(".."),
            Err("Filename cannot be '.' or '..'")
        );
        assert_eq!(
            validate_windows_name("trailing_dot."),
            Err("Filename cannot end with a period")
        );
        assert_eq!(
            validate_windows_name("trailing_space "),
            Err("Filename cannot end with a space")
        );
        assert_eq!(
            validate_windows_name("CON"),
            Err("Filename is a reserved Windows device name")
        );
        assert_eq!(
            validate_windows_name("con.txt"),
            Err("Filename is a reserved Windows device name")
        );
        assert_eq!(
            validate_windows_name("invalid<name"),
            Err("Filename contains forbidden characters (<> : \" / \\ | ? *)")
        );
        assert_eq!(
            validate_windows_name("bad:file"),
            Err("Filename contains forbidden characters (<> : \" / \\ | ? *)")
        );
        assert_eq!(
            validate_windows_name("hello\x01world"),
            Err("Filename cannot contain ASCII control characters")
        );
    }

    #[test]
    fn test_split_windows_path() {
        assert_eq!(
            split_windows_path(r"C:\Users\User\file.txt"),
            vec!["Users", "User", "file.txt"]
        );
        assert_eq!(
            split_windows_path(r"D:/Documents/Photos/"),
            vec!["Documents", "Photos"]
        );
        assert_eq!(
            split_windows_path(r"\\?\C:\Data\secret.bin"),
            vec!["Data", "secret.bin"]
        );
        assert_eq!(
            split_windows_path(r"\\.\D:\Data\log.txt"),
            vec!["Data", "log.txt"]
        );
        assert_eq!(
            split_windows_path(r"relative\path/to\item"),
            vec!["relative", "path", "to", "item"]
        );
        assert_eq!(split_windows_path(r""), Vec::<&str>::new());
        assert_eq!(split_windows_path(r"C:\"), Vec::<&str>::new());
        assert_eq!(split_windows_path(r"/"), Vec::<&str>::new());
        assert_eq!(split_windows_path(r"\\\\"), Vec::<&str>::new());
    }

    #[tokio::test]
    async fn test_windows_mount_diagnostics() {
        let mp = MountPointImpl::new(
            PathBuf::from(r"X:\"),
            PathBuf::from(r"C:\enc_data"),
            Box::new(DummyPasswordProvider),
            Cipher::ChaCha20Poly1305,
            false,
            false,
            false,
        );

        let result = mp.mount().await;
        match result {
            Err(FsError::Other(msg)) => {
                assert!(
                    msg.contains("WinFsp"),
                    "Expected diagnostic error message referencing WinFsp"
                );
            }
            _ => panic!("Expected FsError::Other with WinFsp diagnostic"),
        }
    }

    struct DummyPasswordProvider;
    impl PasswordProvider for DummyPasswordProvider {
        fn get_password(&self) -> Option<shush_rs::SecretString> {
            None
        }
    }
}
