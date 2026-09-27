# PRD: #3: Research Implementation for Windows

## Background
rencfs is an encrypted filesystem in Rust, currently mountable only on Linux via FUSE (the `fuse3` crate, gated under `cfg(target_os = "linux")` in Cargo.toml). Issue #3 asks for research into a Windows implementation. There is no Windows support today: the mount layer depends on `fuse3`, POSIX/inode semantics are baked into the core FS logic, `libc` is an unconditional dependency, and all integration tests (`tests/rencfs_linux_itest.rs`) assume Linux FUSE.

## Goals
1. Produce a research/design document evaluating Windows user-mode filesystem options for rencfs.
2. Select and justify one framework.
3. Define the architecture (abstraction layer) that lets rencfs support Windows without regressing Linux.
4. Provide a minimal proof-of-concept spike that compiles on Windows and mounts a volume.
5. Output a task breakdown for the full implementation.

## Non-Goals
- A complete, production-ready Windows port (this issue is research only).
- GUI/tray integration.
- macOS/BSD support (may be noted as future work where it shares the abstraction).

## Options to Evaluate
| Option | Rust binding | Notes |
|---|---|---|
| WinFsp | `winfsp` crate | Mature, FUSE-like API, actively maintained; proven by rclone (via cgofuse). **Preferred.** |
| Dokany | `dokan` crate | Similar model, less active maintenance and thinner Rust ecosystem. |
| ProjFS | `windows` crate | Virtualization provider model (like OneDrive), not a real FS; poor fit for an encrypted vault. |
| NFS/SMB server loopback | custom | Heavy complexity, security concerns; reject. |

## Proposed Architecture
1. **Backend abstraction**: extract a mount-backend trait in the core crate so `encryptedfs` no longer depends on `fuse3::Filesystem` types directly. Linux adapter = existing fuse3 code; Windows adapter = new `winfsp`-based module under `cfg(windows)`.
2. **Semantic mapping layer**: POSIX→Windows translation — synthesized inodes/file IDs, mode bits → file attributes/ACLs, case-insensitive name handling, Windows path normalization, locking semantics differences.
3. **Dependency hygiene**: move `libc` under `[target.'cfg(unix)'.dependencies]`; add `winfsp` under `[target.'cfg(windows)'.dependencies]`; audit core modules for Unix-only `std::os::unix` usage and gate or shim them.
4. **Cargo features**: optional `windows-mount`/`linux-mount` features so library consumers (e.g., `java-bridge`) can build headless on either OS.

## Deliverables
- `docs/windows_support_research.md` — option comparison, decision record, semantic-mapping spec, risk register.
- Spike branch: `cargo check --target x86_64-pc-windows-msvc` passes; WinFsp passthrough (or minimal encrypted) mount demo on Windows.
- GitHub task list/epic for the full port (abstraction refactor, adapter impl, tests, installer/signing, CI).

## Testing Plan
- CI: `windows-latest` job running `cargo check` and unit tests (non-mount) after cfg-gating.
- Refactor existing integration tests so core FS operations run without a mount; keep FUSE-specific tests Linux-only.
- Windows integration suite (WinFsp mount, encrypt/decrypt round-trip, concurrency, case-insensitivity, long paths) in a follow-up implementation issue.
- Cross-platform on-disk format compatibility: vault created on one OS must open on the other.

## Risks
- WinFsp requires a signed driver install on end-user machines (distribution/UX concern, not a code blocker).
- Semantic mismatches (case sensitivity, ACLs vs mode bits, delete-while-open) may require core-FS behavior changes; must be gated so Linux behavior is unchanged.
- `panic = "abort"` in the release profile and tokio runtime configuration must be revalidated for the WinFsp callback model.

## Acceptance Criteria
- [ ] Research document merged under `docs/` with a justified framework decision.
- [ ] `cargo check` succeeds for `x86_64-pc-windows-msvc` on the spike branch (core logic only).
- [ ] PoC mount demonstrated on Windows with WinFsp.
- [ ] Epic/task breakdown for full implementation created and linked from this issue.
- [ ] Linux build and `tests/rencfs_linux_itest.rs` continue to pass unchanged.