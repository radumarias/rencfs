# crypto module

Files: `src/crypto.rs` (module root), `src/crypto/read.rs`, `src/crypto/write.rs`, `src/crypto/buf_mut.rs`

Cryptographic primitives built on the `ring` crate (AEAD), `argon2` (key derivation), `blake3` (hashing), and `rand_chacha` (secure RNG). All secrets flow through `shush_rs::SecretString` / `SecretVec` (mlock/mprotect/zeroize).

## Ciphers (`Cipher` enum in `src/crypto.rs`)

- `ChaCha20Poly1305` (default) — constant-time in software, SIMD-friendly
- `Aes256Gcm` — faster where AES-NI hardware acceleration exists

Both are 256-bit keys with 96-bit nonces (`ring`'s `NONCE_LEN`). `Cipher::key_len()` and `Cipher::max_plaintext_len()` expose per-cipher limits.

## Block-based streaming

Content is encrypted in independent blocks so seeks don't require decrypting the whole file:

- `BLOCK_SIZE` (in `src/crypto/write.rs`): **256 KB** normally, **100 bytes under `#[cfg(test)]`** (easier debugging). Don't hardcode either value in tests or docs.
- On-disk block layout: `NONCE_LEN + BLOCK_SIZE + tag_len` per ciphertext block.
- Writer uses `RandomNonceSequence` (fresh random nonce per block); reader replays them via `ExistingNonceSequence`.

## Key types and traits

- `CryptoWrite` / `CryptoWriteSeek` (in `write.rs`) — encrypting writer wrapping any inner writer. **`finish()` must be called after the last write** to flush the final block.
- `CryptoRead` / `CryptoReadSeek` (in `read.rs`) — decrypting reader; `RingCryptoRead` is the implementation.
- `CryptoInnerWriter` + `WriteSeekRead` (in `write.rs`) — traits the inner writer must satisfy; blanket impls exist for `Write + Seek + Read + 'static`, so plain `File` works out of the box. (See `examples/magic_of_blanket_impl.rs`.)
- `BufMut` (in `buf_mut.rs`) — internal reusable buffer, zeroized on drop.

## Public functions in `src/crypto.rs`

- Stream constructors: `create_write`, `create_write_seek`, `create_read`, `create_read_seek`
- String/name encryption: `encrypt`, `decrypt` (base64 via the `BASE64` engine, no padding), `encrypt_file_name`, `decrypt_file_name`, `hash_file_name` (`.`/`..` get a `$` prefix instead of hashing)
- Key derivation: `derive_key` (Argon2 over password + salt)
- Hashing: `hash`, `hash_reader`, `hash_secret_string`, `hash_secret_vec` — all blake3, 32-byte output
- Misc: `create_rng` (ChaCha20Rng from entropy), `serialize_encrypt_into`, `atomic_serialize_encrypt_into` (bincode + encryption, the atomic variant uses `atomic-write-file`), `copy_from_file`, `copy_from_file_exact`

## Tests and benchmarks

- `src/crypto/read/test.rs`, `src/crypto/write/test.rs` — unit tests
- `src/crypto/write/bench.rs` — nightly `#![feature(test)]` benches
- `benches/crypto_read.rs` — criterion bench (`harness = false`)
