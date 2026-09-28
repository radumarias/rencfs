# Task Workspace Context Protocol

## Workspace Sandbox Root
`/Users/fangqq/.bounty_agent_platform/workspaces/opire-01J42C08V4J78ZAWH8JH2RQS8G`

## Task Info
- Repository: radumarias/rencfs
- Issue: #3
- Title: research implementation for Windows

## Git Branch Protocol
- Feature Branch: `fix/issue-3`
- Target Base Branch: `main`

## Issue Description


## Step 2 PRD Specifications
- Root Cause: rencfs was designed and implemented strictly for Linux systems with direct coupling to FUSE (fuse3::Filesystem), creating several architectural barriers on Windows: (1) Absence of a Windows user-mode filesystem driver/adapter, falling back to a dummy stub on non-Linux OSes; (2) Unconditional compile-time and runtime dependencies on POSIX libc, specifically libc::getuid() and libc::getgid() in src/lib.rs and src/encryptedfs.rs; (3) Hardcoded shell-out to the Unix `umount(8)` command in src/mount.rs; (4) Hardcoded OS check in src/main.rs and src/run.rs terminating with 'not yet ready for this platform' on Windows; (5) Lack of a formal research evaluation, ADR, and POSIX-to-Windows filesystem semantic translation specification for Windows file attributes, FILETIME conversions, case-insensitivity, illegal path characters (<>:"/\|?*), and DOS reserved device names.
- Proposed Fix: 1. Conduct research and formulate an Architecture Decision Record (ADR) adopting WinFsp via the `winfsp` crate (winfsp-rs) under an optional `windows-mount` feature flag, keeping the encrypted core platform-neutral.
2. Spec and implement a pure, platform-independent semantic translation module (src/mount/windows_semantics.rs) handling FILETIME <-> SystemTime conversions, Windows file attributes, path validation (rejecting illegal chars and DOS names), and case folding.
3. Decouple POSIX libc by moving it to `[target.'cfg(unix)'.dependencies]`, gating `UID`/`GID` in `src/lib.rs` and `encryptedfs.rs` to return 0 on Windows, and updating `mount::umount()` to return `io::ErrorKind::Unsupported` on Windows.
4. Configure `build.rs` to emit `/DELAYLOAD` linker arguments for WinFsp DLLs on Windows MSVC targets so that binaries build without requiring a pre-installed WinFsp SDK.
5. Implement a proof-of-concept WinFsp filesystem backend in `src/mount/windows/mod.rs` implementing `winfsp::FileSystemContext` and the `MountPoint`/`MountHandleInner` traits.
6. Update `src/main.rs` and `src/run.rs` to enable the CLI run pipeline on Windows when `windows-mount` is enabled.
7. Expand CI on `windows-latest` to run unit tests and check the `windows-mount` feature.
- Test Command/Strategy: cargo test

## Demand-to-Code Mapping
- Requirement: Research and architectural evaluation of Windows user-mode filesystem technologies
  Affected: ["docs/windows_support_research.md"]
  Action: Author `docs/windows_support_research.md` containing an ADR selecting WinFsp over Dokany/ProjFS/NFS/WSL2, architecture diagrams, POSIX-to-Windows mapping specifications, and follow-up epic milestones.
- Requirement: POSIX-to-Windows filesystem semantic translation layer
  Affected: ["src/mount/windows_semantics.rs", "docs/windows_support_research.md"]
  Action: Implement `src/mount/windows_semantics.rs` providing pure helper functions for FILETIME, file attributes, path validation, illegal characters (<>:"/\|?*), DOS reserved names, and case-insensitive matching with unit tests.
- Requirement: Decouple POSIX libc and platform-specific assumptions in core
  Affected: ["Cargo.toml", "src/lib.rs", "src/encryptedfs.rs", "src/mount.rs"]
  Action: Move `libc` to `[target.'cfg(unix)'.dependencies]`, gate UID/GID to return 0 on Windows, and update `mount::umount()` to return `ErrorKind::Unsupported` on Windows.
- Requirement: WinFsp mount backend PoC and build plumbing
  Affected: ["Cargo.toml", "build.rs", "src/mount.rs", "src/mount/windows/mod.rs"]
  Action: Add `winfsp` dependency behind `windows-mount` feature, emit delayload link flags in `build.rs`, and implement `winfsp::FileSystemContext` in `src/mount/windows/mod.rs`.
- Requirement: CLI enablement for Windows
  Affected: ["src/main.rs", "src/run.rs"]
  Action: Update `src/main.rs` and `src/run.rs` to allow execution on Windows when compiled with the `windows-mount` feature.
- Requirement: CI pipeline test and clippy gates on Windows
  Affected: [".github/workflows/build_and_tests_reusable.yaml"]
  Action: Update `.github/workflows/build_and_tests_reusable.yaml` to run library unit tests and `clippy --features windows-mount` on `windows-latest`.

## Actionable Task Checklist
1. Task 1: Author comprehensive Windows support research document (`docs/windows_support_research.md`) documenting options evaluated (WinFsp, Dokany, ProjFS, NFS/SMB, WSL2), ADR, and POSIX->Windows semantic mapping.
2. Task 2: Refactor `Cargo.toml` to gate `libc` under `cfg(unix)` and introduce optional `winfsp` dependency under `windows-mount` feature.
3. Task 3: Refactor `src/lib.rs` and `src/encryptedfs.rs` to make `UID` and `GID` platform-aware (returning 0 on non-Unix) and add cross-platform tests.
4. Task 4: Update `src/mount.rs` to gate unix shell `umount` and return `io::ErrorKind::Unsupported` on Windows.
5. Task 5: Implement pure semantic mapping helper functions and unit tests in `src/mount/windows_semantics.rs` (FILETIME conversions, attribute mapping, invalid filename chars, DOS reserved names, case folding).
6. Task 6: Configure `build.rs` to emit delay-load linker flags (`/DELAYLOAD:winfsp-x64.dll`) when targeting Windows with `windows-mount`.
7. Task 7: Implement the WinFsp user-mode filesystem adapter in `src/mount/windows/mod.rs` implementing `winfsp::FileSystemContext`, `MountPoint`, and `MountHandleInner`.
8. Task 8: Update `src/main.rs` and `src/run.rs` CLI entrypoint to support execution on Windows when `windows-mount` is enabled.
9. Task 9: Update GitHub Actions CI workflow (`.github/workflows/build_and_tests_reusable.yaml`) to run Windows library unit tests and `windows-mount` clippy checks.

## Strict Guidelines
1. All modifications MUST be made inside `/Users/fangqq/.bounty_agent_platform/workspaces/opire-01J42C08V4J78ZAWH8JH2RQS8G`.
2. Implement complete code with ZERO stubs or placeholders.
3. Run `cargo test` to verify all tests pass.
