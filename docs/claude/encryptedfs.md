# encryptedfs module

Files: `src/encryptedfs.rs` (main implementation, ~2700 lines), `src/encryptedfs/test.rs`, `src/encryptedfs/bench.rs`

`EncryptedFs` is the core encrypted filesystem: an inode-based store that encrypts all content, metadata, and file names. It is independent of FUSE — the `mount` module adapts it to fuse3, and it can be used directly as a library (see `examples/encryptedfs.rs` and the rustdoc examples in `src/lib.rs`).

## Data directory layout

```
data_dir/
├── inodes/            # encrypted, bincode-serialized FileAttr per inode (file name = inode number)
├── contents/          # per-inode content
│   └── <ino>          # encrypted file content (block-based, see crypto.md)
│   └── <ino>/ls/      # for directories: one entry per child (encrypted name + meta)
│   └── <ino>/hash/    # for directories: children indexed by blake3 hash of name
└── security/
    ├── key.enc        # master key, encrypted with the Argon2 password-derived key
    └── key.salt       # salt for key derivation
```

Constants in `src/encryptedfs.rs`: `INODES_DIR`, `CONTENTS_DIR`, `SECURITY_DIR`, `KEY_ENC_FILENAME`, `KEY_SALT_FILENAME`, `LS_DIR`, `HASH_DIR`, `ROOT_INODE = 1`.

## Key management

- The master encryption key lives in `security/key.enc`, encrypted with a key derived (Argon2) from the user password + `key.salt`. Changing the password (`EncryptedFs::passwd`, a static method) only re-encrypts the master key — data is untouched.
- The decrypted key is held in an `ExpireValue` with a **10-minute expiry**; after inactivity it is dropped (zeroized by `shush-rs`) and re-derived on next use via `PasswordProvider`.
- `PasswordProvider` is the trait callers implement to supply the password on demand.

## Public API surface

- Constructor: `EncryptedFs::new(data_dir, password_provider, cipher, read_only) -> FsResult<Arc<Self>>` — validates the password by decrypting the key, creates the dir structure and root inode.
- File ops (all async, inode + file-handle based, mirroring FUSE semantics): `create`, `open`, `read`, `write`, `flush`, `release`, `set_len`, `copy_file_range`, `rename`, `remove_file`, `remove_dir`
- Lookup/metadata: `find_by_name`, `exists_by_name`, `read_dir`, `read_dir_plus`, `get_attr`, `set_attr`, `exists`, `is_dir`, `is_file`, `len`
- Raw streams over the fs crypto: `create_write`, `create_write_seek`, `create_read`, `create_read_seek`
- Password change: `EncryptedFs::passwd(data_dir, old, new, cipher)`
- Helpers: `write_all_string_to_fs`, `write_all_bytes_to_fs` (free functions)

Types: `FileAttr`, `SetFileAttr` (builder-style setters), `CreateFileAttr`, `FileType` (**only `Directory` and `RegularFile` are supported** — symlinks, sockets, devices are commented out), `DirectoryEntry`/`DirectoryEntryPlus` and their iterators, `FsError`/`FsResult`, `CopyFileRangeReq` (built with `bon` builder).

## Concurrency & caching

- Per-inode serialization locks kept in `ArcHashMap` (see `src/arc_hashmap.rs`): inode writes, inode updates, dir-entry `ls`/`hash` writes, and read/write locks.
- Parallel writes to the same file are supported; file handles are `u64` from an atomic counter.
- Caches, each LRU (2000 entries) inside a 10-minute `ExpireValue`: attr cache, dir-entry name cache, dir-entry meta cache.
- Two dedicated multi-thread Tokio runtimes (`DIR_ENTRIES_RT`, `NOD_RT`) back sync iterator types that must call async code.

## Tests & benches

- `src/encryptedfs/test.rs` — unit tests (gated `#[cfg(test)]`); shared helpers in `src/test_common.rs`
- `src/encryptedfs/bench.rs` — nightly benches
- Remember `BLOCK_SIZE` is 100 bytes under test builds, so multi-block behavior is exercised with small files.
