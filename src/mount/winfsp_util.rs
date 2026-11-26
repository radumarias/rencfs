use std::time::{Duration, SystemTime, UNIX_EPOCH};

const WINDOWS_EPOCH_OFFSET_100NS: u64 = 116_444_736_000_000_000;
const MAX_COMPONENT_UTF16: usize = 255;

/// Convert a WinFsp/CreateFile path into validated encrypted-filesystem components.
pub fn parse_windows_path(path: &str) -> Result<Vec<String>, &'static str> {
    let path = path.trim_start_matches(['\\', '/']);
    if path.is_empty() {
        return Ok(Vec::new());
    }
    if path.ends_with(['\\', '/']) {
        return Err("file name must not end with a path separator");
    }

    path.split(['\\', '/'])
        .map(|component| {
            validate_component(component)?;
            Ok(component.to_owned())
        })
        .collect()
}

fn validate_component(component: &str) -> Result<(), &'static str> {
    if component.is_empty() {
        return Err("empty path component");
    }
    if component == "." || component == ".." {
        return Err("relative path components are not supported");
    }
    if component.encode_utf16().count() > MAX_COMPONENT_UTF16 {
        return Err("file name exceeds 255 UTF-16 code units");
    }
    if component.ends_with([' ', '.']) {
        return Err("Windows file names cannot end with a space or dot");
    }
    if component.chars().any(|character| {
        matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*') || (character as u32) < 32
    }) {
        return Err("file name contains a character forbidden by Windows");
    }
    Ok(())
}

/// Convert a Rust timestamp to a Windows FILETIME (100 ns ticks since 1601).
pub fn system_time_to_filetime(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration
            .as_nanos()
            .checked_div(100)
            .and_then(|ticks| u64::try_from(ticks).ok())
            .unwrap_or(u64::MAX)
            .saturating_add(WINDOWS_EPOCH_OFFSET_100NS),
        Err(error) => WINDOWS_EPOCH_OFFSET_100NS.saturating_sub(
            error
                .duration()
                .as_nanos()
                .checked_div(100)
                .and_then(|ticks| u64::try_from(ticks).ok())
                .unwrap_or(u64::MAX),
        ),
    }
}

/// Convert a Windows FILETIME to a Rust timestamp. Invalid pre-1601 values map to the epoch.
pub fn filetime_to_system_time(filetime: u64) -> SystemTime {
    let ticks_since_unix_epoch = filetime.saturating_sub(WINDOWS_EPOCH_OFFSET_100NS);
    let seconds = ticks_since_unix_epoch / 10_000_000;
    let ticks = ticks_since_unix_epoch % 10_000_000;
    UNIX_EPOCH + Duration::from_secs(seconds) + Duration::from_nanos(ticks * 100)
}

#[cfg(test)]
mod tests {
    use super::{filetime_to_system_time, parse_windows_path, system_time_to_filetime};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn parses_root_and_nested_paths() {
        assert!(parse_windows_path("\\").unwrap().is_empty());
        assert_eq!(
            parse_windows_path("\\docs\\notes.txt").unwrap(),
            ["docs", "notes.txt"]
        );
        assert_eq!(
            parse_windows_path("/docs/notes.txt").unwrap(),
            ["docs", "notes.txt"]
        );
    }

    #[test]
    fn rejects_components_windows_cannot_represent() {
        for path in [
            "\\a\\\\b",
            "\\a\\.\\b",
            "\\a.txt.",
            "\\bad:name",
            "\\bad*name",
            "\\bad\nname",
        ] {
            assert!(parse_windows_path(path).is_err(), "accepted {path:?}");
        }
    }

    #[test]
    fn filetime_round_trip_preserves_100ns_precision() {
        let timestamp =
            UNIX_EPOCH + Duration::from_secs(1_725_000_000) + Duration::from_nanos(123_456_700);
        let encoded = system_time_to_filetime(timestamp);
        let decoded = filetime_to_system_time(encoded);
        assert_eq!(decoded, timestamp);
    }

    #[test]
    fn unix_epoch_has_expected_filetime() {
        assert_eq!(system_time_to_filetime(UNIX_EPOCH), 116_444_736_000_000_000);
    }
}
