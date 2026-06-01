# oxicrypto-hash — Pure-Rust hash functions and XOFs for OxiCrypto

[![Crates.io](https://img.shields.io/crates/v/oxicrypto-hash.svg)](https://crates.io/crates/oxicrypto-hash)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxicrypto-hash` is the hashing layer of the OxiCrypto stack. It implements the [`oxicrypto_core::Hash`](https://crates.io/crates/oxicrypto-core) and `StreamingHash` traits over the SHA-2, SHA-3, BLAKE2, and BLAKE3 families, and adds the SHA-3-derived extendable-output and customizable functions from NIST SP 800-185 — SHAKE128/256, cSHAKE128/256, TupleHash128/256, ParallelHash128/256 — plus BLAKE3's keyed-hash, key-derivation, and XOF modes and a BLAKE2b keyed-hash (MAC) mode.

The crate is **Pure Rust** and `#![no_std]` (with `alloc`), declaring `#![forbid(unsafe_code)]`. It is built on the RustCrypto `sha2`, `sha3`, `blake2`, `digest`, `shake`, and `cshake` crates plus the official `blake3` crate. There is no `ring`, no `aws-lc`, and no C/C++/Fortran in the default build. All `digest 0.11`-compatible one-shot hashers also expose a generic streaming adapter (`DigestStreamingAdapter`) that implements `StreamingHash` (and, with the `std` feature, `std::io::Write`), so the same algorithm can be used one-shot or incrementally.

## Installation

```toml
[dependencies]
oxicrypto-hash = "0.1.0"
```

```toml
# Enable file-hashing helpers and std::io::Write integrations
oxicrypto-hash = { version = "0.1.0", features = ["std"] }
```

## Quick Start

```rust
use oxicrypto_hash::{Sha256, Sha256Streaming};
use oxicrypto_core::{Hash, StreamingHash, CryptoError};

// One-shot
let digest = Sha256.hash_to_vec(b"abc")?;
assert_eq!(digest.len(), 32);

// Streaming — equivalent to hashing the concatenation
let mut hasher = Sha256Streaming::new();
hasher.update(b"hello");
hasher.update(b" world");
let mut out = [0u8; 32];
hasher.finalize(&mut out)?;
assert_eq!(out.as_slice(), Sha256.hash_to_vec(b"hello world")?.as_slice());
# Ok::<(), CryptoError>(())
```

## API Overview

### One-shot hashes (`oxicrypto_core::Hash`)

Each type implements `Hash` and exposes `DIGEST_LEN` and `BLOCK_SIZE` associated constants.

| Type | Algorithm | Output | Block size | Standard |
|------|-----------|--------|------------|----------|
| `Sha256` | SHA-256 | 32 | 64 | FIPS 180-4 |
| `Sha384` | SHA-384 | 48 | 128 | FIPS 180-4 |
| `Sha512` | SHA-512 | 64 | 128 | FIPS 180-4 |
| `Sha512_256` | SHA-512/256 | 32 | 128 | FIPS 180-4 §6.7 |
| `Sha3_256` | SHA3-256 | 32 | 136 (rate) | FIPS 202 |
| `Sha3_384` | SHA3-384 | 48 | 104 (rate) | FIPS 202 |
| `Sha3_512` | SHA3-512 | 64 | 72 (rate) | FIPS 202 |
| `Blake2b256` | BLAKE2b-256 | 32 | 128 | RFC 7693 |
| `Blake2b512` | BLAKE2b-512 | 64 | 128 | RFC 7693 |
| `Blake2s256` | BLAKE2s-256 | 32 | 64 | RFC 7693 |
| `Blake3` | BLAKE3 | 32 | 64 | BLAKE3 spec |

`Hash` provides `name`, `output_len`, `hash`, plus the convenience defaults `hash_to_vec` and `hash_to_array<N>`.

### Streaming hashers (`oxicrypto_core::StreamingHash`)

`DigestStreamingAdapter<D: Digest + Default>` is the generic adapter backing every `digest`-based streaming type; BLAKE3 uses its own incremental API via `Blake3Streaming`. All implement `update`, `finalize`, and `reset` (and `Clone`; with `std`, `std::io::Write`).

| Type alias / struct | Backing hash |
|---------------------|--------------|
| `Sha256Streaming`, `Sha384Streaming`, `Sha512Streaming`, `Sha512_256Streaming` | SHA-2 family |
| `Sha3_256Streaming`, `Sha3_384Streaming`, `Sha3_512Streaming` | SHA-3 family |
| `Blake2b256Streaming`, `Blake2b512Streaming`, `Blake2s256Streaming` | BLAKE2 family |
| `Blake3Streaming` | BLAKE3 (struct, not an alias) |

### BLAKE3 modes

| Item | Description |
|------|-------------|
| `Blake3Keyed::new(key: [u8; 32])` / `.hash(msg) -> [u8; 32]` | BLAKE3 keyed-hash (MAC-like) under a 32-byte key |
| `blake3_keyed_hash(key: &[u8; 32], msg) -> [u8; 32]` | Free-function equivalent of `Blake3Keyed` |
| `blake3_derive_key(context: &str, key_material) -> [u8; 32]` | BLAKE3 key-derivation mode (context must be a fixed, unique string) |
| `blake3_xof(msg, output_len) -> Vec<u8>` | Extendable output; the first 32 bytes equal the standard BLAKE3 hash |

### SHA-3 derived functions — NIST SP 800-185 (`xof` module)

| Function / type | Description |
|-----------------|-------------|
| `shake128(msg, out)` / `shake256(msg, out)` | SHAKE XOF, fixed output length |
| `shake128_start(msg) -> Shake128Reader` / `shake256_start(msg) -> Shake256Reader` | Incremental XOF reader (`.read(out)`) for unbounded output |
| `cshake128(msg, function_name, customization, out)` / `cshake256(...)` | Customizable SHAKE |
| `tuple_hash128(...)` / `tuple_hash256(...)` | TupleHash over an unambiguously-encoded sequence of strings |
| `Blake2bKeyed::new(key)` / `.hash(msg, out)` and `blake2b_keyed(key, msg, out)` | BLAKE2b keyed-hash (RFC 7693 MAC mode) |

### ParallelHash — NIST SP 800-185 (`parallelhash` module)

| Item | Description |
|------|-------------|
| `ParallelHash128::new(block_size, customization)` / `ParallelHash256::new(...)` | Parallelizable hash over fixed-size blocks; `.hash(data, out)` and `.hash_xof(data, out)` |
| `parallel_hash128(...)`, `parallel_hash256(...)` | One-shot fixed-length ParallelHash |
| `parallel_hash128_xof(...)`, `parallel_hash256_xof(...)` | One-shot ParallelHash in XOF mode |

### Runtime algorithm selection (`hash_builder` module)

| Item | Description |
|------|-------------|
| `HashAlgorithm` | Enum of supported algorithms with a `const fn output_len()` |
| `HashBuilder` | `const fn` constructors (`sha256()`, `sha384()`, `sha512()`, `sha512_256()`, `sha3_256()`, `sha3_384()`, `sha3_512()`, `blake3()`); `.build() -> Box<dyn Hash>` for runtime dispatch |
| `StreamingHashBuilder` | Streaming counterpart; `.build() -> DynStreamingHash` |
| `DynStreamingHash` | Type-erased streaming hasher selectable at runtime |

### `std`-only convenience helpers

Available with the `std` feature: `sha256_hex`, `sha384_hex`, `sha512_hex`, `sha3_256_hex`, `blake3_hex` (lowercase hex `String`); and `hash_file_sha256`, `hash_file_sha512`, `hash_file_blake3` (hash a file by path).

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | off | Enables hex-digest helpers (`sha256_hex`, …), file-hashing helpers (`hash_file_*`), and `std::io::Write` for streaming hashers. Forwards to `blake3/std` and `oxicrypto-core/std`. |

## Cross-references

- [`oxicrypto-core`](https://crates.io/crates/oxicrypto-core) — defines the `Hash`, `StreamingHash`, and `CryptoError` types used here.
- [`oxicrypto-mac`](https://crates.io/crates/oxicrypto-mac) — HMAC, KMAC, and other keyed MACs built on these hashes.
- [`oxicrypto-kdf`](https://crates.io/crates/oxicrypto-kdf) — HKDF / PBKDF2 / Argon2 / scrypt key derivation.
- [`oxicrypto`](https://crates.io/crates/oxicrypto) — the top-level façade for the OxiCrypto stack.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
