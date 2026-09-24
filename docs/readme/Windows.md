# Windows support — implementation research

> Status: **research note, not a claim that rencfs mounts on Windows today.**
> Scope: the native implementation path for
> [`FUSE` (or similar) support on `Windows`](https://github.com/xoriors/rencfs/issues/3)
> (Opire reward: "research implementation for Windows").
> Last verified against the ecosystem: 2026-09-24.

## 1. Where rencfs stands today

- rencfs is a Rust userspace encrypted filesystem. On Linux it mounts through the
  [`fuse3`](https://crates.io/crates/fuse3) crate: `src/mount/linux.rs` defines
  `EncryptedFsFuse3`, which implements `fuse3::raw::Filesystem` as the async bridge
  between the kernel FUSE protocol and the internal `EncryptedFs` layer.
- `src/mount.rs` selects the backend at compile time: `linux.rs` on
  `cfg(target_os = "linux")`, a no-op `dummy.rs` everywhere else. The public surface a
  Windows backend must satisfy is small and already pinned down:
  `MountPointImpl` (with `MountPoint::new(...) -> mount() -> MountHandle`) and
  `MountHandleInnerImpl` (with `unmount()` plus a `Future` impl that resolves when the
  filesystem session ends).
- The crate is licensed `MIT OR Apache-2.0`, which drives the licensing checkpoint in §4.
- Everything above `EncryptedFs` (crypto, storage layout, expiry, keyring) is
  platform-neutral Rust; the Windows work is confined to the mount backend, CLI
  argument handling (drive letters instead of paths), and storage-name edge cases
  (e.g. `|` and trailing dots are not valid in Win32 names).

## 2. Backend options considered

### Option A — WinFsp native API via `winfsp-rs` (recommended)

[WinFsp](https://github.com/winfsp/winfsp) (Windows File System Proxy) is the de-facto
FUSE equivalent on Windows: a signed kernel driver plus a user-mode DLL
(`winfsp-x64.dll`) exposing a native filesystem API and optional FUSE2/FUSE3
compatibility layers. It is actively maintained (upstream commits through
September 2026) and is the runtime behind SSHFS-Win, rclone mount, and
[many shipping filesystems](https://github.com/winfsp/winfsp/wiki/Known-File-Systems).

Rust bindings: [`SnowflakePowered/winfsp-rs`](https://github.com/SnowflakePowered/winfsp-rs)
(crate `winfsp`, `0.13.1+winfsp-2.1`, released 2026-08-19, actively maintained).
The workspace ships two reference implementations that double as the missing
"examples" the issue mentions:

- `filesystems/ntptfs-winfsp-rs` — a passthrough filesystem: the closest analogue to
  what rencfs needs (every operation forwarded to an underlying store).
- `filesystems/memfs-winfsp-rs` — an in-memory filesystem, useful as a minimal
  callback checklist.

Note that the `fuse3` crate **cannot** be reused on Windows: it speaks the Linux
`/dev/fuse` protocol directly. WinFsp's FUSE compatibility layers target Cygwin/MSYS2
builds, not the `fuse3` Rust crate. A Windows backend must implement WinFsp's
`FileSystemContext` trait natively.

### Option B — Dokan via `dokan-rust`

[Dokany](https://github.com/dokan-dev/dokany) is the other mature user-mode filesystem
framework for Windows; [`dokan-dev/dokan-rust`](https://github.com/dokan-dev/dokan-rust)
provides maintained bindings (commits through 2026-07). Callback surface is comparable
to WinFsp. Downsides: smaller Rust ecosystem, fewer reference Rust filesystems, and its
own licensing obligations (§4). Keep as fallback if a WinFsp blocker appears.

### Option C — ProjFS (Windows Projected File System)

Microsoft's native virtualization API. Wrong shape for rencfs: ProjFS projects an
on-demand view of a backing store with provider callbacks for hydration, whereas
rencfs must intercept *every* read/write to en/decrypt. Rejected.

### Option D — `billziss-gh/winfuse`

FUSE-protocol-over-TCP approach aimed at WSL interoperability. Unmaintained since
2020 and no Rust bindings. Rejected.

### Option E — status quo: run under WSL2

Works today but is not "Windows support": files live in the WSL VM, no drive-letter
integration, no Win32 app transparency. Remains the documented workaround until a
native backend lands.

## 3. Proposed architecture (`src/mount/windows.rs`)

Mirror the existing `mount.rs` selection pattern:

```rust
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::{MountHandleInnerImpl, MountPointImpl};

#[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
mod dummy;
// ... existing dummy selection for the remaining platforms
```

Inside `src/mount/windows.rs`:

```text
MountPointImpl
  └─ mount() -> MountHandle
       └─ EncryptedFsWinFsp  (implements winfsp::FileSystemContext)
            └─ Arc<EncryptedFs>   (existing, unchanged crypto/storage core)
       └─ winfsp FileSystemHost started on dispatcher threads
       └─ MountHandleInnerImpl { host }  // Future::poll waits on host; unmount() stops it
```

Key design points:

1. **Sync/async bridge.** `EncryptedFs` methods are `async` (tokio). WinFsp calls
   `FileSystemContext` callbacks synchronously from its own dispatcher threads. Bridge
   with a dedicated tokio runtime (or `Handle::block_on` on a current-thread runtime
   owned by the mount) so callbacks never block the process-wide runtime used by the
   CLI. Pin this down in the PoC: a deadlock here is the most likely first bug.
2. **Operation mapping** (first milestone):

   | WinFsp callback | rencfs / `EncryptedFs` method |
   |---|---|
   | `get_volume_info` | static label/serial; sizes from `data_dir` free space |
   | `get_security_by_name`, `get_file_info` | `lookup` / `getattr` equivalents → `FileAttributes` |
   | `open`, `create` | `open` / `create` |
   | `read`, `write` | `read` / `write` |
   | `flush`, `close`, `cleanup` | `flush` / `release` semantics |
   | `set_file_size`, `set_basic_info` | `setattr` equivalents |
   | `read_directory` | directory enumeration (cache a snapshot per open directory handle) |
   | `rename` | rename (serialize with create/remove to avoid namespace races) |
   | delete (`set_delete` in `cleanup`) | remove file / rmdir |

3. **Windows metadata decisions (milestone 1).** Report fixed timestamps and Unix-mode
   → `FILE_ATTRIBUTE_*` mapping; disable 8.3 names; treat the namespace as
   case-insensitive-preserving (Windows default); scope the default ACL to the mounting
   user, `SYSTEM`, and `Administrators` — never `Everyone`. Unsupported in milestone 1:
   reparse points/symlinks (rencfs has no symlink support yet — see xoriors/rencfs#231),
   hardlinks, alternate data streams, oplocks, and named security attributes beyond the
   default ACL.
4. **Storage-name edge cases.** Win32 forbids `|` and trailing dots in path components
   while legacy rencfs storage names can contain them; the backend must translate or
   escape these names at the mount boundary (and keep legacy entries readable).
5. **Delay-load, don't bundle.** Link against `winfsp-x64.dll` with the MSVC
   `/DELAYLOAD` linker flag and detect WinFsp at runtime (registry/service presence),
   printing an install hint (https://winfsp.dev/rel/) when missing. This keeps `cargo
   check`/CI usable on machines without WinFsp and matters for licensing (§4).

## 4. Licensing checkpoint (decision gate for the maintainer)

- rencfs: `MIT OR Apache-2.0`.
- WinFsp: **GPLv3**, with a commercial license available from the author.
  Apache-2.0 is one-way compatible *into* GPLv3 per the FSF, but a rencfs binary
  distributed with a GPLv3 component linked in would have to be distributed under
  GPLv3 terms — incompatible with the project's current dual permissive license.
- **Recommended resolution:** the same model SSHFS-Win and rclone use — WinFsp is a
  **prerequisite the end user installs separately**, and rencfs delay-loads
  `winfsp-x64.dll` at runtime. rencfs never redistributes WinFsp binaries, so the
  released crate/installer stays `MIT OR Apache-2.0` and no GPL obligations attach to
  the rencfs code itself. The maintainer should explicitly confirm this reading (or
  budget for a commercial WinFsp license) before the implementation PR is merged.
- Fallback Dokan: dokany v2+ is LGPL-3.0 / commercial dual-licensed; dynamic linking
  is permitted under LGPL with relinkability obligations — lighter than GPLv3 but
  still not zero.

## 5. Build & CI plan

- `Cargo.toml`:

  ```toml
  [target.'cfg(windows)'.dependencies]
  winfsp = "0.13"
  ```

  plus `cargo rustc` / `.cargo/config.toml` link args for
  `/DELAYLOAD:winfsp-x64.dll` (target-aware so cross-compiles keep working).
- CI (GitHub Actions):
  1. `cargo check --target x86_64-pc-windows-msvc` on every PR (no WinFsp needed).
  2. `windows-latest` job with `choco install winfsp` running the unit tests plus a
     scripted mount smoke test.
  3. Keep the existing Linux matrix untouched; `dummy.rs` stays for other platforms.
- Manual smoke test (Windows host with WinFsp installed):
  1. `rencfs mount --mount-point R: --data-dir C:\data\vault` → drive `R:` appears.
  2. Create/edit/copy files in Explorer and from `cmd`; verify round-trip content.
  3. Unmount, remount, confirm ciphertext at rest in `data_dir` and plaintext via mount.
  4. Kill the process mid-write; remount and verify no corruption (mirrors the
     power-loss concern tracked in xoriors/rencfs#309).

## 6. Milestones and acceptance criteria

1. **M1 — compiles on Windows**: `cargo check`/tests green on `windows-latest`;
   mount/unmount of an empty vault; drive letter appears and disappears cleanly.
2. **M2 — core I/O**: create/read/write/rename/delete round-trips, including >4 GiB
   files and non-ASCII names; smoke test above scripted in CI.
3. **M3 — hardening**: legacy storage-name compatibility, crash-consistency checks,
   README/docs for WinFsp installation and drive-letter usage.

A truthful first implementation PR states explicitly what was executed on a real
Windows host versus only `cargo check`-verified, and does not claim runtime validation
that did not happen.

## 7. Cross-repo bookkeeping noticed during this research

- The canonical repository is now [`xoriors/rencfs`](https://github.com/xoriors/rencfs);
  `radumarias/rencfs` is a stale fork (last push 2024-12-21, issues disabled).
- The Opire reward for this task is still registered against the fork
  (GitHub repo ID `906513469`) instead of the canonical repo (ID `782253071`), and
  OpireBot is not installed on the fork — which is why `/try` and `/claim` comments
  there receive no bot response. Updating the reward's repository mapping at
  [app.opire.dev](https://app.opire.dev) would make the bounty claimable against the
  canonical repo, where PRs [#322](https://github.com/xoriors/rencfs/pull/322) and
  [#327](https://github.com/xoriors/rencfs/pull/327) already contain WinFsp
  implementation work consistent with this plan.

## References

- WinFsp: https://github.com/winfsp/winfsp · https://winfsp.dev
- Rust bindings: https://github.com/SnowflakePowered/winfsp-rs · https://crates.io/crates/winfsp
- Dokan: https://github.com/dokan-dev/dokany · https://github.com/dokan-dev/dokan-rust
- fuse3 (current Linux backend): https://crates.io/crates/fuse3
- Canonical issue: https://github.com/xoriors/rencfs/issues/3

---

*AI-assistance disclosure: this research note was drafted with AI assistance
(Toledo Technologies LLC dev operation) from public repository sources and upstream
documentation linked above; all version/maintenance claims were re-verified against
crates.io and the GitHub API on 2026-09-24.*
