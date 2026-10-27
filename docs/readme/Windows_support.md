# Windows Support — Implementation Research Note

> **Status:** Research only. This note documents how rencfs *could* mount on Windows
> natively; it does **not** claim that rencfs mounts on Windows today. The Linux
> backend (`src/mount/linux.rs`, via `fuse3`) is the only real mount implementation.
> On every non-Linux target rencfs currently falls back to the `dummy` backend
> (`src/mount/dummy.rs`), which returns `Err(FsError::Other("Dummy implementation"))`
> from `mount()`.

This note is intentionally written as a first milestone *proposal*: the goal is a
**truthful, minimal, verifiable** Windows implementation that can be reviewed and
merged, not a premature claim of full parity with the Linux backend.

---

## 1. Goal and scope of the first milestone

The Linux backend implements the `MountPoint` trait (defined in `src/mount.rs`):

```rust
pub trait MountPoint {
    fn new(
        mountpoint: PathBuf,
        data_dir: PathBuf,
        password_provider: Arc<dyn PasswordProvider>,
        cipher: Cipher,
        allow_root: bool,
        allow_other: bool,
        read_only: bool,
    ) -> Self where Self: Sized;
    async fn mount(mut self) -> FsResult<MountHandle>;
}
```

A Windows backend must implement this same trait behind a `#[cfg(target_os = "windows")]`
gate, mirroring how `linux.rs` is gated with `#[cfg(target_os = "linux")]` in
`src/mount.rs`. The trait boundary itself is clean: `EncryptedFs`
(`src/encryptedfs.rs`) is backend-agnostic and exposes all the operations a
mount driver needs, and the mount-side work is confined to a new `src/mount/windows.rs`.
One real exception exists, though, and must be settled before coding: the ciphertext
names `EncryptedFs` writes into the data dir contain `|`, which NTFS forbids — see §7.

**First-milestone scope (must be truthful):**

- Mount a real directory on Windows via WinFsp, backed by `EncryptedFs`.
- Read + write files, list directories, create/remove files and directories.
- Correctly handle the *common* metadata (size, mtime, read-only flag).
- Not claim support for advanced/uncommon NTFS features (see §7).

---

## 2. Backend options (recommended first, alternatives considered)

### 2.1 Recommended: `winfsp-rs` (`winfsp` crate)

The most widely used safe Rust binding to WinFsp. Provides a `Filesystem` trait whose
methods mirror the WinFsp C++ `FileSystemContext` callbacks (get file info, open, read,
write, read directory, etc.), plus an event-loop `FileSystemHost`.

- **Pros:** Mature, documented, actively used; maps 1:1 onto WinFsp's model; async
  bridging is handled by the crate's own runtime integration; many examples (memfs,
  passthrough) to crib from.
- **Cons:** The `winfsp` crate is **GPL-3.0** licensed (see §3 licensing for the
  verified metadata trail). It pulls in a large dependency tree.

### 2.2 Alternative: `unifuse` (MIT, cross-platform)

A cross-platform async FUSE abstraction with a `UniFuseFilesystem` trait and two
adapters: `Rfuse3Adapter` (Linux/macOS) and `WinfspAdapter` (Windows). It is MIT
licensed, `#![forbid(unsafe_code)]`, and path-based (no inode map needed on Windows,
since WinFsp is natively path-based).

- **Pros:** Cleaner licensing (MIT); one trait for both platforms (potential future
  unification of the mount layer); zero unsafe.
- **Cons:** Requires **nightly** Rust (edition 2024, RPITIT); it is a *new* abstraction,
  so adopting it means reworking the existing `MountPoint`/`MountHandle` surface rather
  than just adding a Windows module. Its trait is path-based, which does not match the
  inode-based `EncryptedFs` API (needs a path→inode translation layer, which the Linux
  backend does inside `linux.rs`).

### 2.3 Not recommended for the first milestone

- **`winfsp_wrs`** — safe-ish wrapper but requires `rust-bindgen` + Clang at build time
  to parse WinFsp C++ headers; heavier build, smaller ecosystem.
- **Direct WinFsp C API via `windows`/`windows-sys`** — maximum control but the most
  code to hand-write; not worth it until the binding crates prove inadequate.

### 2.4 Other Windows mount mechanisms — evaluated, rejected

Recorded here so the WinFsp choice is a decision someone can re-open with full
information, not an assumption:

| Mechanism | What it is | Why it is not the right backend for rencfs |
|---|---|---|
| **Dokany** | User-mode filesystem library for Windows (dokany2). Its user-mode library and driver are **LGPL-3.0**, samples MIT (per the repo's `license.lgpl.txt` / `license.mit.txt` and README licensing section). | LGPL is a softer boundary than GPL-3 but still a license review, and the Rust ecosystem around Dokany is smaller and less maintained than around WinFsp; Dokany's callback model is FUSE-shaped, which fits rencfs's existing Linux code less cleanly than WinFsp's native NT-style semantics. |
| **ProjFS** (Windows Projection File System) | Microsoft's placeholder/projection API for cloud files. | Projection semantics: the provider materializes placeholders; it is designed for sync providers, not for a transparent, always-live encrypted mount (create/rename/write paths are awkward to map onto an `EncryptedFs` inode store). |
| **Cloud Files API** (`cldapi`) | The sync-engine framework OneDrive-style providers build on. | Same shape problem: it models a local-cache + sync-engine, which would force rencfs to pretend to be a sync client. rencfs is a live passthrough crypto layer; there is no remote to sync. |
| **WSL passthrough** | Exposing Linux mounts to Windows via WSL. | Not a Windows-native mount: visibility/perf/semantics for regular Win32 apps (Explorer, antivirus, installers) depend on the WSL9P broker, and it requires WSL to be installed and running. It hides the problem, it does not implement the backend. |

**Decision:** implement the first milestone with **`winfsp-rs`**, because it is the
closest match to the existing inode-based design and has the richest examples. Keep
`unifuse` as the fallback if the GPL-3 license boundary becomes a blocker (§3).

---

## 3. Licensing / attribution checkpoint (MIT OR Apache-2.0 project)

This is the single most important design constraint and must be settled *before* writing
code, because it determines which crate we may link.

| Component | License | Impact on rencfs (MIT OR Apache-2.0) |
|---|---|---|
| **WinFsp** (C++ runtime) | **GPLv3 + FLOSS special exception** | ✅ Usable. The FLOSS exception explicitly permits use by free/open-source software. rencfs is FLOSS, so no GPL contagion from WinFsp itself. |
| **`winfsp` (winfsp-rs) crate** | **GPL-3.0** (verified, see below) | ⚠️ GPL is contagious. Linking it makes the *Windows build* GPL-3. For an `MIT OR Apache-2.0` project this is a license-boundary decision the maintainers must accept or avoid. |
| **`unifuse` crate** | **MIT** | ✅ No contagion. |

**License verification trail for the `winfsp` crate** (checked 2026-10-27, because
"what license is the crate actually under" has circulated with conflicting answers):

- crates.io **version metadata** for every current release — `0.13.2+winfsp-2.1`
  (published 2026-10-20), `0.13.1`, `0.13.0`, `0.12.6` — declares `GPL-3.0`.
- The crates.io **crate-level** `license` field is `null` even though every version
  declares GPL-3.0 — the crate-level field is legacy metadata and must not be read as
  "no license declared"; the authoritative sources are the version metadata and the
  repository `LICENSE`.
- The source repository (`SnowflakePowered/winfsp-rs`) reports **GPL-3.0** via the
  GitHub license API.

So: the crate is GPL-3.0 on all three evidence layers; treat any "license: None" claim
as a metadata-reading artifact, and still read the repo `LICENSE` before shipping.

Two viable paths:

1. **Accept GPL-3 for the Windows module** (recommended if we use `winfsp-rs`).
   This is defensible because rencfs is *dual-licensed* `MIT OR Apache-2.0`; the Windows
   mount module can be distributed as GPL-3 without affecting the rest of the crate,
   provided the crate's overall license statement is clarified (e.g. note in README that
   the `windows` feature pulls in GPL-3 code). This mirrors how other projects (e.g.
   `winfsp-fs-skeleton`) deliberately keep the GPL boundary at the consumer's link line.
2. **Avoid GPL entirely** by using `unifuse` (MIT), at the cost of adopting nightly Rust
   and a new abstraction.

**Attribution requirement:** WinFsp's FLOSS exception requires that any user-facing
interface/documentation include the copyright notice
`"WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos"` and a link to
the WinFsp repository. This must be added to rencfs's docs/README and (if applicable) a
NOTICE file. The `winfsp-rs` crate also carries this attribution requirement.

**Recommendation:** Proceed with `winfsp-rs` (GPL-3) for the first milestone and clearly
document the license boundary. If the maintainers reject GPL-3, switch the Windows
backend to `unifuse` (MIT) — the `MountPoint` abstraction isolates the swap.

---

## 4. Proposed architecture — `src/mount/windows.rs`

Mirror the structure of `src/mount/linux.rs`. The Windows module implements the same
`MountPoint` trait and exposes a `MountPointImpl` / `MountHandleInnerImpl` pair.

```
src/mount.rs
 ├─ #[cfg(target_os = "linux")] mod linux;          (existing)
 ├─ #[cfg(target_os = "windows")] mod windows;      (NEW)
 └─ #[cfg(not(any(target_os = "linux", target_os = "windows")))] mod dummy;  (existing)
```

`src/mount/windows.rs` outline:

- `MountPointImpl` holds the same fields as the Linux impl: `mountpoint`, `data_dir`,
  `password_provider`, `cipher`, `allow_root`, `allow_other`, `read_only`.
- `mount()` builds an `Arc<EncryptedFs>` (via `EncryptedFs::new(...)`, same as
  `linux.rs`), then constructs a `winfsp::FileSystemContext`-backed filesystem and starts
  the `FileSystemHost` event loop. It returns a `MountHandle` whose inner future resolves
  when the host exits (mirroring how `MountHandleInnerImpl` in `linux.rs` is a `Future`).
- Because WinFsp callbacks are synchronous and `EncryptedFs` methods are async, the
  Windows module must bridge sync→async, e.g. via `tokio::runtime::Handle::block_on(...)`
  (the same approach `unifuse`'s `WinfspAdapter` uses). This is the main technical
  complexity and must be carefully tested.

### 4.1 Gate changes in `src/mount.rs`

The current gate is:

```rust
#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(target_os = "linux"))]
mod dummy;
```

Change to:

```rust
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod dummy;
```

and select the impl types accordingly. `MountHandle`/`MountHandleInner` need no change.

---

## 5. Operation mapping: WinFsp callbacks → `EncryptedFs` methods

The `EncryptedFs` API is inode-based; the mapping below is the contract the Windows
backend must honor. This is the most error-prone part and must be validated by tests.

| WinFsp callback | `EncryptedFs` method | Notes |
|---|---|---|
| `get_file_info` | `get_attr(ino)` | Return `FileAttr` → WinFsp `FileInfo`. |
| `open` / `create` | `open(ino, read, write)` / `create(...)` | Returns a handle (`u64`). |
| `read` | `read(ino, offset, buf, handle)` | Honor the read handle; return bytes read. |
| `write` | `write(ino, offset, buf, handle)` | Return bytes written. |
| `read_directory` | `read_dir(ino)` → `DirectoryEntryIterator` | Iterate entries; translate names to `FileInfo`. |
| `get_security_by_name` / `get_security` | `get_attr` (map uid/gid/permissions) | Windows uses SIDs; see §7. |
| `rename` | `rename(...)` | Map `REPLACE_EXISTING`/`EXCLUSIVE` flags. |
| `set_file_info` | `set_attr(ino, SetFileAttr)` | Set size/timestamps; read-only via attribute. |
| `cleanup` / `flush` / `close` | `flush(handle)` / `release(handle)` | Ensure data is flushed. |
| `read_directory` plus `get_file_info` | `read_dir_plus(ino)` | If needed for efficiency. |
| `statfs` | — (compute from `EncryptedFs`) | WinFsp has no direct statfs; provide sensible defaults. |

The full set of `EncryptedFs` methods available for the mapping (from
`src/encryptedfs.rs`): `create`, `find_by_name`, `remove_dir`, `remove_file`,
`exists_by_name`, `read_dir`, `read_dir_plus`, `get_attr`, `set_attr`, `read`, `write`,
`flush`, `release`, `open`, `set_len`, `rename`, `copy_file_range`, plus
`create_write`/`create_read` helpers.

**Key mapping decisions:**

- **Names are encrypted** (the encrypted filesystem stores ciphertext filenames). The
  `EncryptedFs` layer handles name encryption/decryption internally; the mount layer must
  pass *plaintext* names to/from the OS and let `EncryptedFs` translate. Do **not**
  re-encrypt in the Windows module. (The Win32-legality problem with the *ciphertext*
  alphabet — `|` — is a data-dir/on-disk-format issue, not a mount-boundary issue; see
  §7 and §11 Q5.)
- **Inodes:** `EncryptedFs` uses `u64` inodes internally. WinFsp is path-based, so the
  Windows module needs a path↔inode translation layer (like the one inside `linux.rs`).
  Maintain a `HashMap<PathBuf, u64>` or resolve via `find_by_name` walking from the root.

---

## 6. Windows-only dependency and build shape

- Add a Windows-only dependency in `Cargo.toml`:

  ```toml
  [target.'cfg(target_os = "windows")'.dependencies]
  winfsp = { version = "...", features = [...] }   # or unifuse if license chosen
  ```

  This mirrors the existing Linux-only dep:

  ```toml
  [target.'cfg(target_os = "linux")'.dependencies]
  fuse3 = { version = "0.8.1", features = ["tokio-runtime", "unprivileged"] }
  ```

- **Delay-load / runtime dependency:** WinFsp must be installed on the host
  (`choco install winfsp`). The Rust crate links against the WinFsp DLL at runtime; the
  build itself does not require WinFsp headers when using `winfsp-rs` (unlike
  `winfsp_wrs`, which needs Clang + bindgen). This keeps CI on Linux/macOS unaffected —
  the `windows` module only compiles on `cfg(target_os = "windows")`.
- **MSRV / toolchain:** rencfs's `rust-toolchain.toml` must be checked. If `unifuse` is
  chosen, nightly is required; with `winfsp-rs`, stable should suffice.
- **Feature gate (optional):** Consider a cargo feature `windows-support` so the GPL-3
  dependency is opt-in, keeping the default `MIT OR Apache-2.0` build free of GPL. This
  is the cleanest way to satisfy the license checkpoint.

---

## 7. Windows metadata decisions and unsupported NTFS features (first milestone)

**What we can truthfully support in milestone 1:**

- Regular file read/write and directory listing/creation/removal.
- Basic metadata: size, last-write time, read-only attribute.
- A single security identity (map everything to the current user's SID; ignore
  fine-grained ACLs initially).

**What we explicitly do NOT support in milestone 1 (document, don't claim):**

- **NTFS alternate data streams** (ADS, `name:stream`). Map to a "not supported" /
  single default stream.
- **Hard links** (`GetFileInformation` link count). Report `nlink = 1`; hard-link
  semantics on encrypted filenames are non-trivial.
- **Symlinks / reparse points** — only if the Linux backend's symlink handling is
  replicated; otherwise report as unsupported.
- **POSIX permissions ↔ Windows ACLs** — the Linux backend uses mode bits
  (`allow_root`/`allow_other`). On Windows, map these to a coarse ACL (e.g. owner full
  control, others read-only) rather than attempting full POSIX→NTFS ACL translation.
- **Case sensitivity** — the encrypted store is case-sensitive (two ciphertext names
  differing only in case are distinct entries), and Windows must be told so explicitly:
  `FSP_FSCTL_VOLUME_PARAMS` carries a `CaseSensitiveSearch:1` bit (see
  `inc/winfsp/fsctl.h` in the WinFsp repo) that maps to
  `FILE_CASE_SENSITIVE_SEARCH`. If the flag is left off, callers may treat `Foo.txt` and
  `foo.txt` as the same file before the request ever reaches our callbacks, collapsing
  two distinct encrypted entries into one visible file — silent data loss, not a cosmetic
  issue. Recommended: set `CaseSensitiveSearch = TRUE` to match the Linux backend, and
  document in the README that installers/legacy software which assume case-insensitive
  lookups may misbehave on this mount, rather than papering over it with a name-folding
  workaround. This must still be a deliberate, documented choice.
- **On-disk ciphertext names use a Windows-illegal character (verified against the
  code — this is the deepest Windows issue in rencfs).** `encrypt_file_name`
  (`src/crypto.rs`) encodes names with `base64(STANDARD)` (NO_PAD) and rewrites `/` to
  `|` so the name is safe as a *Linux* filename. But `|` is in the forbidden Win32 set
  (`<>:"/\|?*`) — so when the **data dir itself** lives on NTFS, `EncryptedFs` cannot
  even create its own backing files for every entry. This is not something
  `windows.rs` can escape at the mount boundary; it reaches the on-disk format.
  Options, in rough order of cleanliness:
  1. **Change the rewrite target**, or move to **base64url**: the current scheme's
     `/`→`|` choice was only ever constrained by "legal on Linux"; `/`→`-` (or full
     base64url `-`/`_`) is legal on Linux *and* Windows and keeps the same
     unambiguity property (`-` never appears in the STANDARD alphabet) — one format
     everywhere. Breaking for existing Linux stores (whose files are already spelled
     with `|`) unless `find_by_name` grows a dual-alphabet fallback (cheap: try the
     new spelling, then the legacy one).
  2. **Target-aware alphabet** (STANDARD+`|` on Linux, URL-safe on Windows) with a
     decoder that accepts both — avoids breaking existing dirs but forks the format
     per platform, which bites whenever a USB/backup data dir crosses OSes.
  3. Percent-style escaping of `|` at the `EncryptedFs` layer only — works but
     reintroduces an encoding scheme inside the crypto module, which §5 wants to
     keep out.
  Whichever path wins is the maintainer's call (§11 Q5); the milestone must not
  pretend the problem is mount-layer-local, because it is not.
- **Windows reserved device names** — `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`,
  `LPT1`–`LPT9` are rejected by Win32 (case-insensitive; trailing dots/spaces ignored).
  Analysis against the actual code: a *name-collision* with these is unreachable,
  because `encrypt` output always carries the ring AEAD nonce + tag overhead (≥27
  bytes → ≥36 base64 chars), far past the 4-char shape of `COM1`. But a caller *on*
  the mount can still try to create `NUL.txt`; that must fail with a precise status
  (`STATUS_OBJECT_NAME_INVALID`-class), not a confusing "file not found", and this
  deserves an explicit test so the driver's behaviour is specified, not emergent.
- **Trailing dots/spaces** — worth stating explicitly because it is a *non*-hazard with
  rencfs's alphabet: the on-disk charset is base64-standard plus `|` (after the `/`
  rewrite), which contains no dot and no space, so trailing normalization cannot
  silently corrupt existing entries. Any escape scheme introduced for the `|` problem
  above must preserve that property (never emit a trailing `.`/space), and a round-trip
  fuzz test over the full ciphertext-name alphabet should assert it.
- **`.` / `..` handling.** rencfs already renames `.`/`..` to `$.`/`$..` on disk
  (`hash_file_name`/`encrypt_file_name`); plaintext names literally starting with `$`
  collide with that scheme on Linux today — a pre-existing quirk the Windows milestone
  inherits, worth one sentence in the README rather than a silent surprise.
- **`statfs`** — provide plausible defaults; no real block accounting.
- **Timestamps / FILETIME epoch** — Windows timestamps are `FILETIME`: 100 ns ticks since
  **1601-01-01**, not the Unix epoch. The offset between the two epochs is exactly
  `11644473600` seconds (134774 days × 86400). rencfs stores Unix-epoch `SystemTime`
  (via `SetFileAttr`/`FileAttr` on Linux), so every conversion in `windows.rs` must apply
  this offset with 100 ns granularity and truncate gracefully (NTFS FILETIME precision is
  higher than what the Linux backend has historically used). Getting the epoch wrong
  shifts every displayed timestamp by ~369 years and *still looks plausible in Explorer*
  until someone compares against Linux — so a **round-trip unit test** (unix epoch →
  FILETIME → back, including the 1601/1970 boundaries and post-2038 dates) is mandatory,
  not optional polish.

Every "not supported" item above must be handled by returning a graceful error or a
sensible default — **never a panic or silent wrong data** — so the first PR is honest.

---

## 8. Build / CI plan

1. **Local dev on Windows:** install WinFsp (`choco install winfsp`), then
   `cargo run --release -- <mountpoint> <data_dir>`.
2. **CI:** keep the existing Linux/macOS jobs untouched (the `windows` module is
   `cfg`-gated and won't compile on non-Windows). Add a **Windows runner** job
   (`windows-latest`) that:
   - installs WinFsp (`choco install winfsp`),
   - runs `cargo test --target x86_64-pc-windows-msvc`,
   - runs the smoke test (below) if a mount can be performed in CI (may need a
     Windows-specific integration test that skips gracefully when no mount is possible).
3. **Feature-gated build:** if `windows-support` is an opt-in feature, ensure the default
   build stays `cargo check`-clean on Linux/macOS without the WinFsp dependency.
4. **Clippy / fmt:** follow the project's existing `clippy.toml` and `rustfmt`
   conventions; run `cargo clippy --all-targets` and `cargo fmt --check`.

---

## 9. Manual smoke test (Windows host with WinFsp installed)

A reviewer must be able to reproduce this exactly:

1. Install WinFsp: `choco install winfsp`.
2. Build: `cargo build --release`.
3. Create an empty data dir and a mountpoint dir, e.g.:
   ```
   rencfs.exe C:\mnt C:\data
   ```
   (adjust to the actual CLI argument order used by `src/main.rs`).
4. In another shell, verify the mount is live:
   - `dir C:\mnt` → empty.
   - `echo hello > C:\mnt\hello.txt` → then `dir C:\data` shows a ciphertext entry.
   - `type C:\mnt\hello.txt` → prints `hello` (proves read/write round-trip).
   - `mkdir C:\mnt\sub` and create a file inside it, then re-list.
   - Delete the file/dir, confirm the ciphertext disappears from `C:\data`.
5. Unmount (Ctrl-C or `umount` equivalent) and confirm `C:\mnt` is released.
6. **Name-safety test:** from Linux, create a handful of files — because ciphertext
   names are base64 (≈36+ chars at typical lengths), roughly half of them will contain
   at least one `|` (the `/` rewrite); verify every such entry is listable and readable
   through the chosen escape scheme on Windows, and that
   trying to create `NUL.txt` / `COM1` on the mount fails with a precise name-invalid
   status rather than "not found".
7. **Timestamp test:** write a file, `set` its mtime to a known unix epoch value,
   read it back through `dir /q` and through Linux after remount — the FILETIME
   round-trip must be exact (§7); additionally run the unit round-trip test over the
   1601/1970/2038 boundaries.
8. **Negative test:** confirm that unsupported features (e.g. an ADS) do not crash the
   driver — they return a graceful error.

If any step fails, the PR must say so explicitly rather than claiming success.

---

## 10. Acceptance criteria for a truthful first implementation PR

A PR that legitimately earns this bounty must:

- [ ] Implement `src/mount/windows.rs` behind `#[cfg(target_os = "windows")]` and wire it
      into `src/mount.rs`. `EncryptedFs` itself stays backend-agnostic, **except** for
      the ciphertext-name `|`/NTFS legality decision settled per §7 / §11 Q5 — that is
      the one on-disk-format question the Windows milestone must answer, not a mount-layer detail.
- [ ] Implement the `MountPoint` trait and return a real `MountHandle`.
- [ ] Map the WinFsp callbacks to `EncryptedFs` methods per §5, with a path↔inode
      translation layer.
- [ ] Handle the licensing checkpoint: document the GPL-3 boundary (or use `unifuse`/MIT)
      and add the WinFsp attribution notice.
- [ ] Define the ciphertext-name alphabet decision for NTFS-hosted data dirs (§7):
      rewrite target or base64url, with a cross-platform decode fallback, plus a
      round-trip fuzz test over the full name alphabet.
- [ ] Set `FSP_FSCTL_VOLUME_PARAMS.CaseSensitiveSearch` per the §7 decision and
      document the consequence.
- [ ] FILETIME↔unix round-trip unit test including 1601/1970/2038 boundary values.
- [ ] Add the Windows-only dependency (feature-gated if the GPL boundary requires it).
- [ ] Compile on `x86_64-pc-windows-msvc` (add a Windows CI job).
- [ ] Pass the smoke test in §9 — read/write/list/create/delete round-trip on a real
      Windows host.
- [ ] Explicitly document unsupported NTFS features (§7) and return graceful errors for
      them.
- [ ] Self-review: no new panics, no silent data corruption, tests pass, no new warnings.

---

## 11. Open questions for the maintainer

1. **License:** accept the GPL-3 boundary for the Windows module (`winfsp-rs`), or prefer
   the MIT `unifuse` path (nightly Rust + new abstraction)? This decides the crate choice.
2. **CLI args:** confirm the exact mountpoint/data-dir argument order the Windows binary
   should accept (match `src/main.rs` / `src/run.rs`).
3. **Case sensitivity:** recommend yes — set
   `FSP_FSCTL_VOLUME_PARAMS.CaseSensitiveSearch` so Windows does not fold two distinct
   ciphertext names into one visible file (§7). Confirm the maintainer accepts the
   installer-compat consequence.
4. **CI:** is a Windows runner acceptable, and can a real mount be exercised there, or
   should the Windows integration test skip gracefully when no mount is possible?
5. **Ciphertext-name alphabet (§7):** the `/`→`|` rewrite makes on-disk names illegal on
   NTFS, which blocks Windows-hosted data dirs. Prefer (1) a rewrite-target change /
   base64url with a legacy-decode fallback, (2) a target-aware dual-alphabet decoder,
   or (3) an escape confined to the crypto layer? This is an on-disk-format decision —
   it shapes whether a data dir can ever move between OSes — so it should not be
   defaulted inside a Windows-only PR.

---

*This is a research note; it deliberately does not claim Windows support exists today.
The next step is a first implementation PR that satisfies §10.*
