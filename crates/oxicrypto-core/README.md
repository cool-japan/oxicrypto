# oxicrypto-core — Trait surface, error types, and secret wrappers for OxiCrypto

[![Crates.io](https://img.shields.io/crates/v/oxicrypto-core.svg)](https://crates.io/crates/oxicrypto-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxicrypto-core` defines the public API surface shared by every `oxicrypto-*` sub-crate in the OxiCrypto stack: the algorithm trait objects (`Aead`, `Hash`, `Mac`, `Kdf`, `Signer`, …), the unified `CryptoError` enum, constant-time comparison utilities, the canonical `AlgorithmId` registry, and zeroize-on-drop secret wrappers. No cryptographic algorithm is implemented here — concrete implementations live in `oxicrypto-aead`, `oxicrypto-hash`, `oxicrypto-kdf`, `oxicrypto-mac`, `oxicrypto-sig`, `oxicrypto-kex`, `oxicrypto-pq`, and `oxicrypto-rand`.

The crate is **Pure Rust** and `#![no_std]` (with `alloc`) — it pulls in only `subtle` (constant-time primitives) and `zeroize` (secure memory wiping), and declares `#![forbid(unsafe_code)]`. There is no `ring`, no `aws-lc`, and no C/C++/Fortran in the default build. The constant-time helpers are built on RustCrypto's `subtle` crate so equality checks do not leak the position of the first differing byte.

## Installation

```toml
[dependencies]
oxicrypto-core = "0.1.0"
```

```toml
# Enable std integrations (e.g. `From<CryptoError> for std::io::Error`)
oxicrypto-core = { version = "0.1.0", features = ["std"] }
```

## Quick Start

```rust
use oxicrypto_core::{ct_eq, CryptoError, SecretKey};

// Fixed-size secret, zeroized automatically on drop.
let key = SecretKey::<32>::from_slice(&[0xAA; 32])?;
assert_eq!(key.as_bytes().len(), 32);

// Constant-time equality — runtime is independent of where the bytes differ.
assert!(ct_eq(b"tag-bytes", b"tag-bytes"));
assert!(!ct_eq(b"tag-bytes", b"different"));
# Ok::<(), CryptoError>(())
```

## API Overview

### Algorithm traits

Every concrete algorithm in OxiCrypto implements one of these traits. The `dyn`-safe traits are `Send + Sync` so they can be type-erased behind `Box<dyn …>`.

| Trait | Object-safe | Key methods | Implemented by |
|-------|-------------|-------------|----------------|
| `Aead` | yes | `name`, `key_len`, `nonce_len`, `tag_len`, `seal`, `open`, `seal_to_vec`, `open_to_vec` | `oxicrypto-aead` |
| `StreamingAead` | no (`Sized`) | `init`, `encrypt_update`, `encrypt_finalize`, `decrypt_update`, `decrypt_finalize`, `reset` | `oxicrypto-aead` |
| `Hash` | yes | `name`, `output_len`, `hash`, `hash_to_vec`, `hash_to_array<N>` | `oxicrypto-hash` |
| `StreamingHash` | yes | `update`, `finalize`, `reset` | `oxicrypto-hash` |
| `Mac` | yes | `name`, `key_len`, `output_len`, `mac`, `verify`, `mac_to_vec` | `oxicrypto-mac` |
| `StreamingMac` | no (`Sized`) | `update`, `finalize`, `verify` | `oxicrypto-mac` |
| `Kdf` | yes | `name`, `derive` | `oxicrypto-kdf` |
| `PasswordHash` | yes | `name`, `hash_password` | `oxicrypto-kdf` |
| `PasswordHashParams` | yes | `memory_cost`, `time_cost`, `parallelism` | `oxicrypto-kdf` |
| `KeyAgreement` | yes | `name`, `scalar_len`, `point_len`, `shared_secret_len`, `agree`, `agree_to_vec` | `oxicrypto-kex` |
| `Signer` | yes | `name`, `signature_len`, `sign` | `oxicrypto-sig` |
| `Verifier` | yes | `name`, `verify` | `oxicrypto-sig` |
| `KeyGenerator` | yes | `name`, `generate_keypair` | `oxicrypto-sig` |
| `Kem` | no (assoc. types) | `kem_generate`, `kem_encapsulate`, `kem_decapsulate` | `oxicrypto-pq` |
| `Rng` | yes | `fill` | `oxicrypto-rand` |

The `Aead`, `Hash`, `Mac`, and `KeyAgreement` traits provide `*_to_vec` convenience methods as default implementations that allocate the output buffer for you. `Hash::hash_to_array<N>` returns a fixed-size array and is gated on `Self: Sized` to preserve `dyn Hash` object safety. `Kem` uses associated types (`EncapKey`, `DecapKey`, `Ciphertext`, `SharedSecret`) rather than a `dyn`-safe interface.

### `CryptoError` — unified error enum

`#[derive(Debug, Clone, PartialEq, Eq)]`, implements `Display` and `core::error::Error` (unconditionally). With the `std` feature it also implements `From<CryptoError> for std::io::Error`.

| Variant | Meaning |
|---------|---------|
| `InvalidKey` | Key has the wrong length or is otherwise invalid |
| `InvalidNonce` | Nonce/IV has the wrong length or is otherwise invalid |
| `InvalidTag` | AEAD open / MAC verify / password verify failed authentication |
| `BufferTooSmall` | Output buffer is too small for the requested operation |
| `BadInput` | General bad-input condition (e.g. zero-length KDF output requested) |
| `Internal(&'static str)` | Internal or backend error with a static message |
| `Kex` | Key-exchange or encapsulation/decapsulation failure |
| `Sign` | Signature generation or verification failure |
| `Rng` | RNG-specific failure (e.g. `getrandom` unavailable) |
| `Encoding` | Encoding/decoding failure (DER, PEM, SEC1, …) |
| `UnsupportedAlgorithm` | Requested algorithm is not compiled-in or unsupported at runtime |

### Constant-time utilities (`ct` module)

| Function | Description |
|----------|-------------|
| `ct_eq(a, b) -> bool` | Constant-time byte-slice equality; returns `false` immediately on length mismatch, otherwise compares in time proportional to the shorter slice |
| `ct_is_zero(data) -> bool` | Constant-time all-zero check; runtime is proportional to `data.len()` regardless of content |
| `ct_select(a, b, choice) -> u8` | Returns `a` if `choice == 0`, else `b` (any non-`0` low bit selects `b`) |

### Secret wrappers (`secret` module)

All three wrappers implement `Zeroize` + `ZeroizeOnDrop` and have a redacted `Debug` impl that never prints key material.

| Type | Description | Key methods |
|------|-------------|-------------|
| `SecretKey<const N: usize>` | Fixed-size secret wrapping `[u8; N]` | `new`, `from_slice` (errors `InvalidKey` on length mismatch), `as_bytes` |
| `SecretVec` | Heap-allocated, variable-length secret | `new`, `from_slice`, `as_bytes`, `len`, `is_empty` |
| `KeyPair<SK: Zeroize, PK>` | Bundles a secret half (zeroized on drop) with a public half | `new`, `secret`, `public` |

### Algorithm registry (`algo_id` module)

`AlgorithmId` is a `#[non_exhaustive]` enum cataloguing every algorithm family across the OxiCrypto stack (70+ variants spanning hashes, AEADs, MACs, signatures, key exchange, KDFs, and post-quantum primitives). Each variant exposes:

| Method | Description |
|--------|-------------|
| `name() -> &'static str` | Canonical IANA/NIST string (e.g. `"AES-256-GCM"`, `"ML-KEM-768"`) |
| `category() -> AlgorithmCategory` | Maps the algorithm to its `AlgorithmCategory` |

`AlgorithmCategory` variants: `Hash`, `Aead`, `Mac`, `Signature`, `KeyExchange`, `Kdf`, `PostQuantum`.

Coverage by category includes SHA-2 / SHA-3 / BLAKE2 / BLAKE3 hashes; AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV, XChaCha20-Poly1305, AES-CCM, Deoxys-II, and AES key wrap (AEAD category); HMAC, Poly1305, CMAC, and KMAC MACs; Ed25519/Ed448, ECDSA P-256/384/521, RSA PKCS#1v1.5 / PSS, and BIP-340 Schnorr signatures; X25519/X448 and ECDH key exchange; HKDF, PBKDF2, Argon2id, scrypt, and Balloon KDFs; and ML-KEM, ML-DSA, SLH-DSA, plus hybrid KEMs (X-Wing) in the post-quantum category.

### Re-exports

For convenience the crate root re-exports `Box`, `String`, `Vec` (from `alloc`), `subtle::ConstantTimeEq`, and `zeroize::{Zeroize, ZeroizeOnDrop}` so downstream crates share a single version of each dependency.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | off | Enables `From<CryptoError> for std::io::Error`. The crate is otherwise `no_std + alloc`. |

## Cross-references

- [`oxicrypto`](https://crates.io/crates/oxicrypto) — the top-level façade re-exporting every algorithm family.
- [`oxicrypto-aead`](https://crates.io/crates/oxicrypto-aead), [`oxicrypto-cipher`](https://crates.io/crates/oxicrypto-cipher), [`oxicrypto-hash`](https://crates.io/crates/oxicrypto-hash), [`oxicrypto-kdf`](https://crates.io/crates/oxicrypto-kdf), [`oxicrypto-mac`](https://crates.io/crates/oxicrypto-mac), [`oxicrypto-sig`](https://crates.io/crates/oxicrypto-sig), [`oxicrypto-kex`](https://crates.io/crates/oxicrypto-kex), [`oxicrypto-pq`](https://crates.io/crates/oxicrypto-pq), [`oxicrypto-rand`](https://crates.io/crates/oxicrypto-rand) — concrete implementations of the traits defined here.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
