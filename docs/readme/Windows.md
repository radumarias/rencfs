# Windows support research

This document is research for adding a native Windows mount backend to
`rencfs`. It is not a claim that Windows mounting works today — today every
non-Linux target falls back to the stub in `src/mount/dummy.rs`, which
returns `FsError::Other("Dummy implementation")` from `MountPoint::mount`.

## TL;DR

- **Backend**: [WinFsp](https://winfsp.dev/) via the `winfsp` crate, added as a
  Windows-only dependency with delay-loading so the binary starts (and fails
    gracefully) on machines without the WinFsp runtime.
    - **Seam**: the existing `MountPoint` / `MountHandle` / `MountHandleInner`
      traits in `src/mount.rs` are already the right abstraction boundary. A new
        `src/mount/windows.rs` plugs in exactly where `linux.rs` and `dummy.rs`
          plug in today, and drives the same `EncryptedFs` core.
          - **Biggest real design decision**: `EncryptedFs` is fully async (tokio),
            while WinFsp `FileSystemContext` callbacks are synchronous calls driven by
              the kernel dispatcher's thread pool. The Windows backend needs an explicit
                sync→async bridge (`tokio::runtime::Handle::block_on` on a dedicated
                  runtime, or `futures::executor::block_on` per call). This is the part most
                    port attempts underestimate.
                    - **Scope for milestone 1**: regular files + directories only; no ACL
                      translation, no ADS, no reparse points. Everything unsupported must fail
                        with an explicit NTSTATUS/`STATUS_NOT_IMPLEMENTED`-style error rather than
                          being silently approximated.

                          ## Backend choice and alternatives considered

                          | Option | Verdict |
                          |---|---|
                          | **WinFsp** (`winfsp` crate) | **Recommended.** Mature, actively maintained, BSD-style-licensed kernel driver + user-mode DLL, native Rust bindings, supports both drive letters and directory mount points, async file-system model with its own dispatcher. Closest analogue to the `fuse3` crate used on Linux. |
                          | Dokan | Viable second choice. Similar model, but the Rust binding story (`dokan` crate) is thinner and less actively developed than `winfsp`. |
                          | ProjFS (Windows Projected File System) | Wrong shape: it virtualizes a view over a backing store with hydration semantics. rencfs' backing store holds *encrypted* data; ProjFS would fight the design rather than help it. |
                          | WSL2 + existing Linux build | Good development shortcut, not a product: requires WSL install, doesn't give native Explorer integration, and file access crosses the 9P boundary. Keep it as a dev/CI option only. |
                          | Cloud Files API (`cfapi`) | Optimized for sync clients with placeholder files; hydration-on-demand is the opposite of an always-decrypted mount. |

                          ## Licensing checkpoint

                          - `rencfs` is `MIT OR Apache-2.0` (`Cargo.toml`, `LICENSE-*` files).
                          - The `winfsp` Rust crate is `MIT`/`Apache-2.0`-compatible as a dependency.
                          - The **WinFsp runtime** (kernel driver + `winfsp-x64.dll`) is GPLv3 with a
                            redistribution/commercial-use license from its vendor. Dynamically linking
                              to a separately-installed WinFsp runtime is the normal consumption model
                                and does not force rencfs relicensing, but **bundling the WinFsp installer
                                  or driver inside a rencfs installer needs the vendor's redistribution
                                    terms reviewed first**.
                                    - Safe posture for milestone 1: document WinFsp as a prerequisite installed
                                      separately (like FUSE-on-macOS users install macFUSE), check for the DLL at
                                        runtime, and emit a clear error + docs link if missing.

                                        ## Where the port actually lands in this codebase

                                        `src/mount.rs` already defines the platform seam:

                                        ```rust
                                        #[cfg(target_os = "linux")]
                                        mod linux;
                                        #[cfg(not(target_os = "linux"))]
                                        mod dummy;
                                        ```

                                        `MountPoint::new(mountpoint, data_dir, password_provider, cipher,
                                        allow_root, allow_other, read_only)` and `mount() -> FsResult<MountHandle>`
                                        are the only contract a backend must satisfy. A Windows module becomes:

                                        ```rust
                                        #[cfg(target_os = "windows")]
                                        mod windows;
                                        #[cfg(target_os = "windows")]
                                        use windows::MountHandleInnerImpl;
                                        #[cfg(target_os = "windows")]
                                        use windows::MountPointImpl;
                                        ```

                                        and `dummy.rs` continues to cover everything else.

                                        ### Proposed `src/mount/windows.rs` shape

                                        - `MountPointImpl`  same fields as the Linux impl; `mount()` validates the
                                          WinFsp runtime, builds `EncryptedFs` via `EncryptedFs::new(data_dir,
                                            password_provider, cipher, read_only)` (identical to `mount_fuse` in
                                              `src/mount/linux.rs`), wraps it in the WinFsp context, and starts the
                                                `FileSystemHost`.
                                                - `EncryptedFsWinFsp` — the WinFsp `FileSystemContext` implementation holding
                                                  `Arc<EncryptedFs>` plus a `tokio::runtime::Handle` for the sync→async
                                                    bridge.
                                                    - `MountHandleInnerImpl` — wraps the `FileSystemHost`; `unmount()` calls
                                                      `host.unmount()`, and `Future::poll` resolves when the host stops (WinFsp
                                                        already unparks its own dispatcher; the handle mainly needs to hold the
                                                          host alive and report errors).
                                                          - Small helpers: `os_str_to_secret_name(&OsStr) -> FsResult<SecretString>`
                                                            (UTF-16 → UTF-8, reject unpaired surrogates and empty names),
                                                              `file_attr_to_fs_info(FileAttr) -> winfsp::host::FileInfo` and the reverse
                                                                for `set_basic_info`.

                                                                ## Callback mapping: `fuse3::Filesystem` → `winfsp::host::FileSystemContext`

                                                                `src/mount/linux.rs` implements `fuse3::raw::Filesystem` on
                                                                `EncryptedFsFuse3`. The Windows port maps the same operations onto the
                                                                winfsp host trait. This table is the real work list:

                                                                | fuse3 op (linux.rs) | EncryptedFs call(s) | winfsp `FileSystemContext` method |
                                                                |---|---|---|
                                                                | `lookup` | `get_attr(parent)` + `find_by_name` | `get_file_info` / `open` for dir entries, `read_directory` names |
                                                                | `getattr` | `get_attr` | `get_file_info` |
                                                                | `setattr` | `set_attr` (`SetFileAttr` size/atime/mtime/…) | `set_basic_info` + `set_file_size` |
                                                                | `mknod`/`mkdir` | `create` (`CreateFileAttr`) | `create` (file vs dir by `FILE_DIRECTORY_FILE` option) |
                                                                | `unlink`/`rmdir` | `remove_file` / `remove_dir` | `cleanup` honoring the delete-pending flag + `can_delete` |
                                                                | `rename` | `rename` | `rename` (with `ReplaceIfExists` → POSIX replace semantics) |
                                                                | `open`/`create` | `open(ino, read, write)` → `fh` | `open`/`create` returning a `FileContext` that stores the `fh` |
                                                                | `read` | `read(ino, offset, size, fh)` | `read` |
                                                                | `write` | `write(ino, offset, buf, fh)` | `write`/`overwrite` |
                                                                | `flush`/`fsync` | `flush(fh)` | `flush` |
                                                                | `release` | `release(fh)` | `close` |
                                                                | `opendir`/`readdir(+plus)`/`releasedir` | `read_dir`/`read_dir_plus` | `read_directory` (buffered `DirectoryInfo` pattern) |
                                                                | `statfs` | static `ReplyStatFs` | `get_volume_info` (label `rencfs`, total/free from data dir disk) |
                                                                | `access` | `check_access(uid, gid, perm, …)` | map to `get_security` stub or fixed-access grant for milestone 1 |
                                                                | `copy_file_range` | `copy_file_range` | optional — WinFsp has no direct equivalent; can be implemented as read+write on open handles or skipped |

                                                                Two `linux.rs` specifics that must be ported deliberately:

                                                                1. **Filename encryption boundary.** Every FUSE `&OsStr` name is converted
                                                                   with `SecretString::from_str(name.to_str().unwrap())` before hitting
                                                                      `EncryptedFs`, and `readdir` results come back as secrets exposed via
                                                                         `expose_secret()`. Windows names arrive as UTF-16 `&U16CStr`; the helper
                                                                            above must lossily-or-explicitly handle non-UTF-8 names (decision:
                                                                               return `STATUS_OBJECT_NAME_INVALID` — do not mojibake them through).
                                                                               2. **Access checks are POSIX.** `check_access(uid/gid/perm)` has no Windows
                                                                                  meaning; milestone 1 should grant access to the mounting user and map
                                                                                     `read_only` to `FILE_ATTRIBUTE_READONLY` + `set_file_size`/`write`
                                                                                        rejection, leaving real ACLs for a later milestone.

                                                                                        ## Windows metadata model (milestone 1)

                                                                                        - `FileAttr` already carries `ino`, `size`, `atime`, `mtime`, `ctime`,
                                                                                          `crtime`, `perm`, `uid`, `gid`. Map: `ino` → `IndexNumber`, times →
                                                                                            `FILETIME` (100-ns ticks since 1601), `kind` → `FileAttributes`
                                                                                              (`FILE_ATTRIBUTE_DIRECTORY`/`FILE_ATTRIBUTE_NORMAL`), `perm & 0o444 == 0`
                                                                                                or `read_only` → `FILE_ATTRIBUTE_READONLY`.
                                                                                                - `uid`/`gid`/`perm` stay in the on-disk inode metadata (they're part of the
                                                                                                  serialized format) but are not surfaced as Windows concepts; document them
                                                                                                    as advisory-only.
                                                                                                    - Explicitly **out of scope** for milestone 1 and to be documented as such:
                                                                                                      NTFS ACLs (`get_security`/`set_security`), alternate data streams, reparse
                                                                                                        points/symlinks/junctions, short (8.3) names, opportunistic locking
                                                                                                          semantics beyond WinFsp's defaults, named streams, EA.
                                                                                                          
                                                                                                          ## Non-obvious `cfg` gaps to close (found by reading the code)
                                                                                                          
                                                                                                          - `src/encryptedfs.rs:~2314` — `ensure_root_exists` calls
                                                                                                            `libc::getuid()/getgid()` under `cfg(any(linux, macos))`; on Windows these
                                                                                                              must fall back to constants (e.g. `0`) — the call sites are already the
                                                                                                                only `libc` usage in the core.
                                                                                                                - `src/mount.rs:100` — `umount()` shells out to the `umount` binary (normal,
                                                                                                                  `-f`, `-l`); needs a `cfg(windows)` variant that calls
                                                                                                                    `FileSystemHost::unmount` on the live host instead of a subprocess.
                                                                                                                    - `src/fs_util.rs` — `#[cfg(unix)]` `OpenOptionsExt::preserve_mode/
                                                                                                                      preserve_owner` on `atomic_write_file`; already gated correctly but worth
                                                                                                                        a Windows-side `cargo check` pass to confirm nothing else in
                                                                                                                          `fs_util`/`encryptedfs` assumes `unix`.
                                                                                                                          - `src/main.rs` + `src/run.rs` — the CLI is `cfg(target_os = "linux")`-gated;
                                                                                                                            the mount subcommand and umount-on-start flags must be re-enabled for
                                                                                                                              Windows with `--mount-point` accepting `X:` or a directory path.
                                                                                                                              - `Cargo.toml` — `fuse3` is already under
                                                                                                                                `[target.'cfg(target_os = "linux")'.dependencies]`; add the mirror section
                                                                                                                                  for Windows (see below).
                                                                                                                                  - Nightly toolchain is pinned by `rust-toolchain.toml` (`#![feature(test)]`
                                                                                                                                    and friends in `lib.rs`); keep CI pinned the same way on Windows.
                                                                                                                                    
                                                                                                                                    ## Dependency/build shape
                                                                                                                                    
                                                                                                                                    ```toml
                                                                                                                                    [target.'cfg(target_os = "windows")'.dependencies]
                                                                                                                                    winfsp = { version = "0.12", features = ["delayload"] }
                                                                                                                                    widestring = "1"
                                                                                                                                    ```
                                                                                                                                    
                                                                                                                                    - `delayload` makes `winfsp-x64.dll` resolve at first use, so `rencfs.exe`
                                                                                                                                      can print "WinFsp is not installed — install it from https://winfsp.dev"
                                                                                                                                        instead of failing at process start. Verify the feature name against the
                                                                                                                                          released crate version during implementation.
                                                                                                                                          - The sync→async bridge: store a `tokio::runtime::Handle` (the runtime the
                                                                                                                                            CLI already creates) inside `EncryptedFsWinFsp` and call
                                                                                                                                              `Handle::block_on` per callback, or run a dedicated single-threaded
                                                                                                                                                runtime if blocking on the shared runtime is unacceptable. WinFsp calls
                                                                                                                                                  arrive on dispatcher threads, so this is safe as long as no callback
                                                                                                                                                    waits on another dispatcher call.
                                                                                                                                                    - `EncrytedFs` uses `tokio::fs`/`tokio::sync` internally — bridging must
                                                                                                                                                      land on a real tokio runtime, not `futures::executor`, or those internals
                                                                                                                                                        will panic.
                                                                                                                                                        
                                                                                                                                                        ## Build/CI plan
                                                                                                                                                        
                                                                                                                                                        1. `cargo check --target x86_64-pc-windows-msvc` as the first compile gate.
                                                                                                                                                        2. `cargo check --target x86_64-pc-windows-gnu` optional (WinFsp ships MSVC
                                                                                                                                                           import libs; MSVC is the realistic first target).
                                                                                                                                                           3. GitHub Actions `windows-latest` job: install Rust nightly (per
                                                                                                                                                              `rust-toolchain.toml`), install WinFsp via `winget install winfsp` or
                                                                                                                                                                 choco, run `cargo test` for the non-mount parts plus a gated smoke test.
                                                                                                                                                                 4. Keep Linux CI untouched; all new code behind `cfg(windows)`.
                                                                                                                                                                 
                                                                                                                                                                 ## Manual smoke test (Windows host)
                                                                                                                                                                 
                                                                                                                                                                 1. Install WinFsp, build with MSVC target.
                                                                                                                                                                 2. `rencfs mount --mount-point X: --data-dir C:\enc` — mount appears in
                                                                                                                                                                    Explorer as a volume.
                                                                                                                                                                    3. Create/edit/rename/delete text files via Explorer and `powershell.exe`;
                                                                                                                                                                       `notepad` round-trip on a file.
                                                                                                                                                                       4. `robocopy` a nested tree in and out; verify hashes match.
                                                                                                                                                                       5. Unmount via the documented path; remount; confirm files decrypt and
                                                                                                                                                                          directory structure survives.
                                                                                                                                                                          6. Negative test: unplug-style stop (kill process), remount, confirm no
                                                                                                                                                                             corruption beyond the documented atomicity guarantees.
                                                                                                                                                                             
                                                                                                                                                                             ## Acceptance criteria for the first implementation PR
                                                                                                                                                                             
                                                                                                                                                                             - Compiles for `x86_64-pc-windows-msvc` with only `cfg`-gated additions.
                                                                                                                                                                             - Mounts on a native Windows host with WinFsp installed; clean error without
                                                                                                                                                                               it.
                                                                                                                                                                               - Explorer can browse, create, read, overwrite, rename, delete files and
                                                                                                                                                                                 directories.
                                                                                                                                                                                 - Survives unmount/remount with data intact.
                                                                                                                                                                                 - README/docs clearly state which NTFS features are unsupported.
                                                                                                                                                                                 
