//! Pure POSIX → Windows semantic-mapping helpers for the WinFsp mount backend.
//!
//! This module has **no** dependency on the `winfsp` crate or any Windows API,
//! so it compiles (and is unit-tested) on every platform. The WinFsp adapter
//! (`windows` module, `cfg(windows)`) maps between [`crate::encryptedfs`]
//! types and WinFSP/NT concepts through these functions. See
//! `docs/windows_support_research.md` §5 for the mapping specification.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::encryptedfs::{FileAttr, FileType};

// `FILE_ATTRIBUTE_*` constants from `winnt.h`, defined locally so this module
// stays free of Windows-only dependencies.
/// `FILE_ATTRIBUTE_READONLY` — file/directory is read-only.
pub(crate) const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
/// `FILE_ATTRIBUTE_DIRECTORY` — identifies a directory.
pub(crate) const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
/// `FILE_ATTRIBUTE_ARCHIVE` — regular file, marked for backup (the usual flag
/// for plain files on NTFS-like volumes).
pub(crate) const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;

/// Number of 100 ns `FILETIME` ticks per second.
const WINDOWS_TICKS_PER_SEC: u64 = 10_000_000;
/// Seconds between the `FILETIME` epoch (1601-01-01) and the Unix epoch.
const SECS_1601_TO_1970: u64 = 11_644_473_600;
/// Allocation granularity reported to Windows, matching [`VolumeParams::sector_size`].
const ALLOCATION_GRANULARITY: u64 = 512;

/// Converts a [`SystemTime`] to a Windows `FILETIME` (100 ns ticks since
/// 1601-01-01 UTC). Values outside the representable range are clamped.
pub(crate) fn system_time_to_filetime(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            (d.as_secs() + SECS_1601_TO_1970) * WINDOWS_TICKS_PER_SEC
                + u64::from(d.subsec_nanos()) / 100
        }
        Err(err) => {
            // before 1970: subtract, clamping at the FILETIME epoch
            let d = err.duration();
            let ticks = d.as_secs() * WINDOWS_TICKS_PER_SEC + u64::from(d.subsec_nanos()) / 100;
            (SECS_1601_TO_1970 * WINDOWS_TICKS_PER_SEC).saturating_sub(ticks)
        }
    }
}

/// Converts a Windows `FILETIME` back to a [`SystemTime`]. This is the exact
/// inverse of [`system_time_to_filetime`] (modulo the 100 ns resolution).
pub(crate) fn filetime_to_system_time(filetime: u64) -> SystemTime {
    let secs = filetime / WINDOWS_TICKS_PER_SEC;
    #[allow(clippy::cast_possible_truncation)]
    let nanos = ((filetime % WINDOWS_TICKS_PER_SEC) * 100) as u32;
    if secs >= SECS_1601_TO_1970 {
        UNIX_EPOCH + Duration::new(secs - SECS_1601_TO_1970, nanos)
    } else {
        UNIX_EPOCH - Duration::new(SECS_1601_TO_1970 - secs, nanos)
    }
}

/// Maps encrypted-FS attributes to Windows `FILE_ATTRIBUTE_*` flags.
///
/// Directories get `FILE_ATTRIBUTE_DIRECTORY`, regular files
/// `FILE_ATTRIBUTE_ARCHIVE`. When no write permission bit is set (`0o222`),
/// the entry is additionally flagged `FILE_ATTRIBUTE_READONLY` — the only
/// POSIX permission bit with a direct Windows file-attribute counterpart
/// (see research doc §5.1).
pub(crate) fn file_attributes(attr: &FileAttr) -> u32 {
    let mut attributes = match attr.kind {
        FileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
        FileType::RegularFile => FILE_ATTRIBUTE_ARCHIVE,
    };
    if attr.perm & 0o222 == 0 {
        attributes |= FILE_ATTRIBUTE_READONLY;
    }
    attributes
}

/// The `AllocationSize` reported to Windows: `size` rounded up to the
/// allocation granularity, as Windows expects a multiple of the sector size.
pub(crate) fn allocation_size(size: u64) -> u64 {
    size.div_ceil(ALLOCATION_GRANULARITY) * ALLOCATION_GRANULARITY
}

/// Splits an absolute WinFsp path (`\dir\file.txt`, rooted at the volume
/// root) into its components. Both `\` and `/` are accepted as separators and
/// empty components are dropped, so `\`, `/` and `\\` all split to nothing
/// (the volume root). `.` and `..` components are preserved for the caller to
/// interpret.
pub(crate) fn split_win_path(path: &str) -> Vec<&str> {
    path.split(['\\', '/'])
        .filter(|component| !component.is_empty())
        .collect()
}

/// Splits an absolute WinFsp path into `(parent_components, final_name)`.
/// `final_name` is `None` when the path denotes the volume root.
pub(crate) fn split_parent(path: &str) -> (Vec<&str>, Option<&str>) {
    let mut components = split_win_path(path);
    let name = components.pop();
    (components, name)
}

/// Reserved DOS device names that cannot be used as file names on Windows,
/// with or without an extension.
const RESERVED_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validates a single file name component against Windows naming rules
/// (research doc §5.3): no illegal characters (`<>:"/\|?*` or control
/// characters), no trailing space or dot, no reserved DOS device names, and at
/// most 255 UTF-16 code units (the NTFS per-component limit).
pub(crate) fn is_valid_component(name: &str) -> bool {
    if name.is_empty() || name.encode_utf16().count() > 255 {
        return false;
    }
    if name.ends_with([' ', '.']) {
        return false;
    }
    if name
        .chars()
        .any(|c| c < ' ' || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'))
    {
        return false;
    }
    // reserved names apply to the stem, with or without an extension
    let stem = name.split('.').next().unwrap_or(name);
    !RESERVED_NAMES.iter().any(|r| stem.eq_ignore_ascii_case(r))
}

/// Case-insensitive comparison matching Windows/WinFsp behavior for volumes
/// mounted with `CaseSensitiveSearch = FALSE` (Unicode-aware, locale-independent).
pub(crate) fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryptedfs::FileType;

    fn attr(kind: FileType, perm: u16) -> FileAttr {
        FileAttr {
            ino: 42,
            size: 0,
            blocks: 0,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind,
            perm,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 0,
            flags: 0,
        }
    }

    #[test]
    fn unix_epoch_maps_to_filetime_epoch_offset() {
        assert_eq!(
            system_time_to_filetime(UNIX_EPOCH),
            SECS_1601_TO_1970 * WINDOWS_TICKS_PER_SEC
        );
    }

    #[test]
    fn filetime_roundtrip_after_unix_epoch() {
        for secs in [0, 1, 1_234_567_890, 1_700_000_000] {
            let time = UNIX_EPOCH + Duration::new(secs, 123_456_700);
            let back = filetime_to_system_time(system_time_to_filetime(time));
            assert_eq!(time, back, "roundtrip failed for {secs}");
        }
    }

    #[test]
    fn filetime_roundtrip_before_unix_epoch() {
        // 1900-01-01 and the FILETIME epoch itself (1601-01-01)
        let before_epoch = UNIX_EPOCH - Duration::new(70 * 365 * 24 * 3600, 0);
        let back = filetime_to_system_time(system_time_to_filetime(before_epoch));
        assert_eq!(before_epoch, back);
        assert_eq!(
            filetime_to_system_time(0),
            UNIX_EPOCH - Duration::new(SECS_1601_TO_1970, 0)
        );
    }

    #[test]
    fn directory_gets_directory_attribute() {
        assert_eq!(
            file_attributes(&attr(FileType::Directory, 0o755)),
            FILE_ATTRIBUTE_DIRECTORY
        );
    }

    #[test]
    fn regular_file_gets_archive_attribute() {
        assert_eq!(
            file_attributes(&attr(FileType::RegularFile, 0o644)),
            FILE_ATTRIBUTE_ARCHIVE
        );
    }

    #[test]
    fn missing_write_bits_map_to_readonly() {
        assert_eq!(
            file_attributes(&attr(FileType::RegularFile, 0o444)),
            FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_READONLY
        );
        assert_eq!(
            file_attributes(&attr(FileType::Directory, 0o555)),
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY
        );
    }

    #[test]
    fn allocation_size_rounds_up_to_sector() {
        assert_eq!(allocation_size(0), 0);
        assert_eq!(allocation_size(1), 512);
        assert_eq!(allocation_size(512), 512);
        assert_eq!(allocation_size(513), 1024);
    }

    #[test]
    fn split_handles_root_and_separators() {
        assert_eq!(split_win_path("\\"), Vec::<&str>::new());
        assert_eq!(split_win_path(""), Vec::<&str>::new());
        assert_eq!(split_win_path("\\\\"), Vec::<&str>::new());
        assert_eq!(split_win_path("\\file.txt"), vec!["file.txt"]);
        assert_eq!(
            split_win_path("\\dir\\sub dir\\file.txt"),
            vec!["dir", "sub dir", "file.txt"]
        );
        // forward slashes are tolerated, consecutive separators collapse
        assert_eq!(split_win_path("/a//b/"), vec!["a", "b"]);
    }

    #[test]
    fn split_parent_extracts_final_component() {
        assert_eq!(split_parent("\\"), (Vec::<&str>::new(), None));
        assert_eq!(
            split_parent("\\file.txt"),
            (Vec::<&str>::new(), Some("file.txt"))
        );
        assert_eq!(split_parent("\\a\\b"), (vec!["a"], Some("b")));
    }

    #[test]
    fn valid_components_are_accepted() {
        for name in [
            "file.txt",
            "a",
            ".hidden",
            "with space",
            "üñïçödé",
            "CON0",
            "COM10",
        ] {
            assert!(is_valid_component(name), "{name} should be valid");
        }
    }

    #[test]
    fn invalid_components_are_rejected() {
        for name in [
            "",
            "file.",
            "file ",
            "a<b",
            "a>b",
            "a:b",
            "a\"b",
            "a/b",
            "a\\b",
            "a|b",
            "a?b",
            "a*b",
            "tab\there",
        ] {
            assert!(!is_valid_component(name), "{name:?} should be invalid");
        }
        // control characters
        assert!(!is_valid_component("bad\u{7}name"));
        // reserved DOS device names, case-insensitive, with or without extension
        for name in [
            "CON", "con", "con.txt", "PRN", "aux", "NUL", "com1", "LPT9.log",
        ] {
            assert!(!is_valid_component(name), "{name} should be invalid");
        }
        // longer than 255 UTF-16 code units
        assert!(!is_valid_component(&"a".repeat(256)));
        assert!(is_valid_component(&"a".repeat(255)));
    }

    #[test]
    fn case_insensitive_comparison() {
        assert!(eq_ignore_case("File.TXT", "file.txt"));
        assert!(eq_ignore_case("FILE", "file"));
        assert!(eq_ignore_case("Ä", "ä"));
        assert!(!eq_ignore_case("file", "other"));
    }
}
