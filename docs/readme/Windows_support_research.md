# Windows support research (implementation path)

This note captures the recommended implementation path for adding **native Windows mount support** to `rencfs`.
It is research and planning material, not a claim that Windows mounting works today.

## Goals and non-goals

- Goal: define a practical first milestone for a working Windows mount.
- Goal: keep core crypto and filesystem logic reused from `EncryptedFs`.
- Non-goal: full parity with Linux metadata and every NTFS feature on day one.

## Backend options considered

### 1) WinFsp (recommended)

- Widely used user-space filesystem framework for Windows (FUSE-like model).
- Mature callback model for `create/open/read/write/readdir/rename/unlink/...`.
- Existing Rust bindings/ecosystem options can be wrapped behind a local adapter.

Why recommended:

- Lowest risk path to a usable first implementation.
- Clear mapping from mount callbacks to existing `rencfs` operations.

### 2) Dokan

- Viable alternative, but typically less preferred for new projects than WinFsp.
- Keep as fallback if WinFsp integration risk increases.

## Licensing and attribution checkpoint

`rencfs` uses `MIT OR Apache-2.0` licensing. Before merging implementation:

- Verify chosen WinFsp Rust bindings and transitives are compatible.
- Document required notices/attribution for distributed binaries.
- Keep this verification as an explicit PR checklist item.

## Proposed code shape

## Target module layout

- `src/mount/mod.rs` (platform selection)
- `src/mount/linux.rs` (existing)
- `src/mount/windows.rs` (new)
- optional `src/mount/windows/adapter.rs` for callback bridging

### First implementation slice

1. Add a Windows-only `MountPointImpl` stub that returns a clear unsupported/error path.
2. Wire `cfg(target_os = "windows")` dispatch so Windows builds compile without Linux FUSE code.
3. Add a Windows CI job that only runs `cargo check` until mount integration lands.

### Platform dispatch

- Use `cfg(target_os = "windows")` gates to compile Windows adapter only on Windows.
- Keep unsupported targets returning clear runtime/compile errors.

### Data flow

- WinFsp callback receives request.
- Adapter resolves mount context + path translation.
- Adapter calls corresponding `EncryptedFs` methods.
- Adapter maps Rust errors to Windows error codes.

## Operation mapping (first milestone)

- `Create/Open` -> `create/open` wrappers backed by `EncryptedFs`.
- `Read/Write` -> chunk-aware `read` and `write` calls.
- `Flush/Close` -> flush and handle cleanup.
- `GetFileInfo` -> map encrypted metadata to stable file attributes.
- `ReadDir` -> enumerate decrypted names for listing.
- `Rename/Move` -> mapped to existing rename semantics.
- `Unlink/Rmdir/Mkdir` -> mapped to delete/create operations.

## Windows metadata policy (first milestone)

- Preserve required timestamps and file size semantics as accurately as possible.
- Start with a minimal supported attribute set (`readonly`, `directory`, basic times).
- Document unsupported features initially (ADS, reparse points, EAs, ACL nuance).

## Dependency and build strategy

- Add Windows-only dependencies under target-specific Cargo sections.
- Delay-load dynamic dependencies where possible to improve startup errors.
- Keep Linux/macOS paths unaffected by Windows-specific code.

## CI and validation plan

### CI

- Add a `windows-latest` job with at least `cargo check` and unit tests that do not require a real mount.
- Keep mount smoke tests optional/manual if CI runner constraints apply.

### Manual smoke test

1. Install WinFsp on a Windows machine.
2. Build `rencfs` with Windows mount feature enabled.
3. Mount an encrypted directory.
4. Create/read/write/rename/delete files and folders.
5. Unmount cleanly and remount to verify persistence.

## Risks and mitigations

- **Path normalization and separators**: centralize path conversion helpers and test them.
- **Handle lifecycle differences**: maintain explicit handle table and cleanup strategy.
- **Error mapping mismatch**: keep a single translation layer with tests for common failures.
- **Performance regressions**: benchmark read/write throughput after MVP lands.

## Acceptance criteria for first Windows implementation PR

- `src/mount/windows.rs` compiles on Windows.
- Basic mount lifecycle works (mount, list, read/write file, unmount).
- Linux build and tests stay green.
- Unsupported Windows features are clearly documented.
- CI includes Windows compile coverage.
