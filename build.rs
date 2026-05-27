fn main() {
    // WinFsp requires delay-load linking for the winfsp DLL.
    // This must be called from build.rs at the project root level.
    #[cfg(target_os = "windows")]
    {
        winfsp::build::winfsp_link_delayload();
    }
}
