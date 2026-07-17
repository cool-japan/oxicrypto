# oxicrypto — The COOLJAPAN Pure-Rust cryptography facade

[![Crates.io](https://img.shields.io/crates/v/oxicrypto.svg)](https://crates.io/crates/oxicrypto)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxicrypto` is the top-level façade crate for the OxiCrypto stack. It aggregates the individual Pure-Rust primitive crates (hashes, AEADs, ciphers, MACs, signatures, key exchange, KDFs, CSPRNG, and an optional post-quantum preview) behind one coherent API: trait re-exports from [`oxicrypto-core`](../oxicrypto-core), `*Algo` selector enums with `*_impl()` factory functions returning trait objects, convenience one-shot helpers, runtime feature/algorithm introspection, and named algorithm suites. Everything in the default build is `#![forbid(unsafe_code)]` and 100% Pure Rust — no C, C++, or Fortran.

As of **0.2.0**, the non-Pure-Rust adapters (`aws-lc-rs` and PKCS#11 HSM) are **not** re-exported through this facade. To use them, depend on [`oxicrypto-adapter-aws-lc`](../oxicrypto-adapter-aws-lc) or [`oxicrypto-adapter-pkcs11`](../oxicrypto-adapter-pkcs11) directly. The default build and `--all-features` on this crate are 100% Pure Rust.

## Sub-crates aggregated by `oxicrypto`

| Sub-crate | Re-exported as | Gate |
|-----------|----------------|------|
| [`oxicrypto-core`](../oxicrypto-core) | crate root (traits, `CryptoError`, `AlgorithmId`, secure wrappers, CT utilities) | always |
| [`oxicrypto-hash`](../oxicrypto-hash) | crate root + `HashAlgo`/`hash_impl` | `pure` |
| [`oxicrypto-aead`](../oxicrypto-aead) | crate root + `AeadAlgo`/`aead_impl` | `pure` |
| [`oxicrypto-cipher`](../oxicrypto-cipher) | `oxicrypto::cipher` | `pure` |
| [`oxicrypto-mac`](../oxicrypto-mac) | crate root + `MacAlgo`/`mac_impl` | `pure` |
| [`oxicrypto-sig`](../oxicrypto-sig) | crate root + `SigAlgo`/`signer_impl`/`verifier_impl` | `pure` |
| [`oxicrypto-kex`](../oxicrypto-kex) | crate root + `oxicrypto::hpke` + `KexAlgo`/`kex_impl` | `pure` |
| [`oxicrypto-kdf`](../oxicrypto-kdf) | crate root + `KdfAlgo`/`kdf_impl` | `pure` |
| [`oxicrypto-rand`](../oxicrypto-rand) | crate root (`random_bytes`, `new_rng`, …) | `pure` |
| [`oxicrypto-pq`](../oxicrypto-pq) | `oxicrypto::pq` + `PqKemAlgo`/`PqSigAlgo` | `pq-preview` |

## Installation

```toml
[dependencies]
# Default: all Pure-Rust primitives (hash, aead, cipher, mac, sig, kex, kdf, rand).
oxicrypto = "0.2.1"

# Trait surface only — no algorithm implementations.
oxicrypto = { version = "0.2.1", default-features = false }

# Add explicit runtime CPU-feature detection (oxicrypto::simd::cpu_info()).
oxicrypto = { version = "0.2.1", features = ["simd"] }

# Add the post-quantum preview (ML-KEM, ML-DSA, SLH-DSA, X-Wing).
oxicrypto = { version = "0.2.1", features = ["pq-preview"] }

# Non-Pure-Rust adapters are NOT part of the oxicrypto facade from 0.2.0.
# Add the adapter crates directly if needed:
#   oxicrypto-adapter-aws-lc = { version = "0.2.1", features = ["aws-lc"] }
#   oxicrypto-adapter-pkcs11 = { version = "0.2.1", features = ["pkcs11"] }
```

## Quick Start

Derive a session key with HKDF-SHA-256, then encrypt and decrypt with AES-256-GCM:

```rust
use oxicrypto::{aead_impl, kdf_impl, AeadAlgo, KdfAlgo};
use oxicrypto::prelude::*;

# fn main() -> Result<(), oxicrypto::CryptoError> {
// 1. Derive a 32-byte AES-256-GCM key from input key material.
let kdf = kdf_impl(KdfAlgo::HkdfSha256);
let mut session_key = [0u8; 32];
kdf.derive(b"input-key-material", b"salt", b"context v1", &mut session_key)?;

// 2. Encrypt (seal_to_vec returns ciphertext || 16-byte tag).
let aead = aead_impl(AeadAlgo::Aes256Gcm);
let nonce = [0x42u8; 12];
let ct = aead.seal_to_vec(&session_key, &nonce, b"header", b"secret payload")?;

// 3. Decrypt (verifies the tag, then decrypts).
let pt = aead.open_to_vec(&session_key, &nonce, b"header", &ct)?;
assert_eq!(pt, b"secret payload");
# Ok(())
# }
```

One-shot hashing and runtime introspection:

```rust
# #[cfg(feature = "pure")]
# {
let digest = oxicrypto::sha256(b"hello");        // [u8; 32]
assert_eq!(digest.len(), 32);

let features = oxicrypto::enabled_features();      // e.g. ["pure"]
let algos = oxicrypto::available_algorithms();     // Vec<AlgorithmId>
assert!(features.contains(&"pure"));
assert!(!algos.is_empty());
# }
```

Post-quantum hybrid public-key encryption (`pq-preview`): X-Wing768
(ML-KEM-768 + X25519) encapsulate, derive an AES-256-GCM key with
HKDF-SHA-256, then seal/open a payload. The same KEM-DEM construction is
exercised end-to-end — both directions, plus tamper-detection — in
[`tests/pq_hybrid_encryption.rs`](tests/pq_hybrid_encryption.rs):

```rust
# #[cfg(all(feature = "pq-preview", feature = "pure"))]
# {
use oxicrypto::hybrid::{Kem, XWing768};
use oxicrypto::{aead_impl, hkdf_sha256_expand, hkdf_sha256_extract, AeadAlgo};

// 1. Recipient publishes an X-Wing768 encapsulation key.
let (decap_key, encap_key) = XWing768::kem_generate().expect("keygen");

// 2. Sender encapsulates, then derives an AES-256-GCM key via HKDF-SHA-256.
let (ciphertext, shared_secret) = XWing768::kem_encapsulate(&encap_key).expect("encapsulate");
let prk = hkdf_sha256_extract(b"oxicrypto-hybrid-example", shared_secret.as_ref());
let mut key = [0u8; 32];
hkdf_sha256_expand(&prk, b"aes-256-gcm key", &mut key).expect("hkdf expand");
let ct = aead_impl(AeadAlgo::Aes256Gcm)
    .seal_to_vec(&key, &[0u8; 12], b"header", b"secret payload")
    .expect("seal");

// 3. Recipient decapsulates, re-derives the same key, and opens the payload.
let recovered_secret = XWing768::kem_decapsulate(&decap_key, &ciphertext).expect("decapsulate");
let recovered_prk = hkdf_sha256_extract(b"oxicrypto-hybrid-example", recovered_secret.as_ref());
let mut recovered_key = [0u8; 32];
hkdf_sha256_expand(&recovered_prk, b"aes-256-gcm key", &mut recovered_key).expect("hkdf expand");
let pt = aead_impl(AeadAlgo::Aes256Gcm)
    .open_to_vec(&recovered_key, &[0u8; 12], b"header", &ct)
    .expect("open");
assert_eq!(pt, b"secret payload");
# }
```

## Top-level API

### Convenience functions (`pure` feature)

| Function | Returns | Description |
|----------|---------|-------------|
| `sha256(msg)` | `[u8; 32]` | One-shot SHA-256. |
| `sha512(msg)` | `[u8; 64]` | One-shot SHA-512. |
| `blake3(msg)` | `[u8; 32]` | One-shot BLAKE3. |
| `new_rng()` | `Result<Box<dyn Rng>, CryptoError>` | OS-seeded CSPRNG as a boxed trait object. |

### Factory functions (`pure` feature)

Each returns a boxed `Send + Sync` trait object for the selected algorithm.

| Function | Selector | Returns |
|----------|----------|---------|
| `hash_impl(HashAlgo)` | `HashAlgo` | `Box<dyn Hash + Send + Sync>` |
| `aead_impl(AeadAlgo)` | `AeadAlgo` | `Box<dyn Aead + Send + Sync>` |
| `mac_impl(MacAlgo)` | `MacAlgo` | `Box<dyn Mac + Send + Sync>` |
| `signer_impl(SigAlgo)` | `SigAlgo` | `Box<dyn Signer + Send + Sync>` |
| `verifier_impl(SigAlgo)` | `SigAlgo` | `Box<dyn Verifier + Send + Sync>` |
| `kex_impl(KexAlgo)` | `KexAlgo` | `Box<dyn KeyAgreement + Send + Sync>` |
| `kdf_impl(KdfAlgo)` | `KdfAlgo` | `Box<dyn Kdf + Send + Sync>` |

### Introspection & version (`version` module)

| Item | Description |
|------|-------------|
| `version()` | Returns `VersionInfo { major, minor, patch, pre }` (parsed at compile time). |
| `VersionInfo` | Semantic-version struct; implements `Display`. |
| `enabled_features()` | `Vec<&'static str>` of compiled-in features (`pure`, `simd`, `pq-preview`, `std`). |
| `available_algorithms()` | `Vec<AlgorithmId>` of every algorithm compiled into the build. |

### Algorithm suites (`version` module)

| Item | Description |
|------|-------------|
| `Suite` | Bundles `aead`, `mac`, `hash`, `kex`, `kdf` selections; implements `Display`. |
| `Suite::TLS13` | TLS 1.3 default: AES-256-GCM + HMAC-SHA-384 + SHA-384 + X25519 + HKDF-SHA-384. |
| `PqSuite` *(pq-preview)* | Extends a `Suite` with `pq_kem` + `pq_sig`. |
| `PqSuite::PQ_TLS13` *(pq-preview)* | `Suite::TLS13` + ML-KEM-768 + ML-DSA-65 (NIST category 3). |
| `PqSuite::PQ_TLS13_HASH_BASED` *(pq-preview)* | `Suite::TLS13` + ML-KEM-768 + SLH-DSA-SHAKE-128f (hash-based signatures). |

### `simd` module (`simd` feature)

| Item | Description |
|------|-------------|
| `cpu_info()` | Probe the CPU and return a `CpuInfo` (never panics; results cached). |
| `CpuInfo` | `{ has_aes_ni, has_sha_ni, has_avx2, has_neon }` (`Debug + Clone + Copy + Eq`). |

### Post-quantum helpers (`pq-preview` feature)

Re-exported from `oxicrypto::pq::*` plus selector enums and free functions:

| Item | Description |
|------|-------------|
| `pq_kem_generate(PqKemAlgo)` | Generate an ML-KEM key pair → `(decap_key_bytes, encap_key_bytes)`. |
| `pq_sig_generate(PqSigAlgo)` | Generate a PQ signing key pair → `(signing_key_bytes, verifying_key_bytes)`. |
| `pq_sign(PqSigAlgo, sk_bytes, msg)` | Sign with a PQ signature scheme → signature bytes. |
| `pq_verify(PqSigAlgo, vk_bytes, msg, sig_bytes)` | Verify a PQ signature. |

## Selector enums

All `*Algo` enums are `#[non_exhaustive]`, `Copy`, and implement `Display`,
`FromStr`, and `TryFrom<&str>` (case-insensitive aliases supported).

### `HashAlgo`

`Sha256`, `Sha384`, `Sha512`, `Sha3_256`, `Sha3_384`, `Sha3_512`, `Sha512_256`,
`Blake2b256`, `Blake2b512`, `Blake2s256`, `Blake3`.

### `AeadAlgo`

`Aes128Gcm`, `Aes256Gcm`, `ChaCha20Poly1305`, `Aes128GcmSiv`, `Aes256GcmSiv`,
`XChaCha20Poly1305`, `Aes128Ccm`, `Aes256Ccm`, `Aes128Ocb3`, `Aes256Ocb3`,
`DeoxysII128`. `aead_impl` returns a working implementation for every variant.

### `MacAlgo`

`HmacSha256`, `HmacSha384`, `HmacSha512`, `HmacSha3_256`, `HmacSha3_512`,
`Poly1305`, `CmacAes128`, `CmacAes256`, `Kmac128 { output_len }`,
`Kmac256 { output_len }`.

### `SigAlgo`

`Ed25519`, `Ed448`, `EcdsaP256`, `EcdsaP384`, `EcdsaP521`, `RsaPkcs1v15Sha256`,
`RsaPkcs1v15Sha384`, `RsaPkcs1v15Sha512`, `RsaPssSha256`, `RsaPssSha384`,
`RsaPssSha512`, `SchnorrBip340`.

### `KexAlgo`

`X25519`, `EcdhP256`, `EcdhP384`, `EcdhP521`, `X448`.

### `KdfAlgo`

`HkdfSha256`, `HkdfSha384`, `HkdfSha512`, `Pbkdf2Sha256`, `Pbkdf2Sha512`,
`Argon2id`, `Scrypt`, `Balloon`.

### `PqKemAlgo` / `PqSigAlgo` *(pq-preview)*

- `PqKemAlgo`: `MlKem512`, `MlKem768`, `MlKem1024`, plus two hybrid KEMs:
  `XWing768` (ML-KEM-768 + X25519, draft-connolly-cfrg-xwing-kem-04) and
  `HybridKem1024P384` (ML-KEM-1024 + ECDH P-384).
- `PqSigAlgo`: `MlDsa44`, `MlDsa65`, `MlDsa87`, plus the ten SLH-DSA parameter
  sets (`SlhDsaSha2_{128,192,256}{s,f}`, `SlhDsaShake{128,256}{s,f}`).

## Re-exports at the crate root

### From `oxicrypto-core` (always)

- Traits: `Aead`, `Hash`, `Mac`, `Signer`, `Verifier`, `Kdf`, `KeyAgreement`, `KeyPair`, `Rng`, `StreamingHash`, `StreamingMac`, `ConstantTimeEq`.
- Identifiers: `AlgorithmId`, `AlgorithmCategory`.
- Secure wrappers: `SecretKey`, `SecretVec`; zeroize: `Zeroize`, `ZeroizeOnDrop`.
- Constant-time utilities: `ct_eq`, `ct_is_zero`, `ct_select`.
- Errors: `CryptoError`.

### From the primitive crates (`pure`)

- Hash: `ParallelHash128`, `ParallelHash256`, `parallel_hash128`, `parallel_hash128_xof`, `parallel_hash256`, `parallel_hash256_xof`, `HashBuilder`.
- AEAD: `AesGcmSiv128`, `AesGcmSiv256`, `XChaCha20Poly1305`, `Deoxys2_128`, `seal_box`, `open_box`, `seal_with_random_nonce`, `aes128_key_wrap`/`aes128_key_unwrap`, `aes256_key_wrap`/`aes256_key_unwrap`.
- KDF: `argon2id_derive`, `scrypt_derive`, `pbkdf2_sha256`, `pbkdf2_sha512`, `balloon_sha256`, `balloon_sha512`, the `hkdf_sha{256,384,512}_{extract,expand}` family, `hkdf_expand_label_sha{256,384}`, plus `Argon2Params`, `BalloonHasher`/`BalloonParams`/`BalloonVariant`, `HkdfSha384`, the `KeyStretcher`/`Stretcher`/`StretchParams` abstraction, and per-algorithm `*StretchParams`.
- Cipher (`oxicrypto::cipher`): `aes128_encrypt_block`, `aes256_encrypt_block`, `chacha20_keystream_block`, and the `*_KEY_LEN` / `*_BLOCK_LEN` / `*_NONCE_LEN` constants (QUIC header-protection building blocks).
- Signatures: ECDSA P-256/384/521 signer + verifier types, `Ed448SigningKey`/`Ed448VerifyingKey`, the RSA PKCS#1v15 and RSA-PSS signer/verifier types (SHA-256/384/512 for both), `SchnorrBip340`, `schnorr_bip340_sign_with_aux`.
- MAC: `HmacSha384`; TLS cipher-suite negotiation via `negotiate_mac`, `mac_name_for_suite`, `TlsCipherSuite` (maps a TLS 1.3/1.2 cipher suite to its HMAC/PRF — see the crate-level rustdoc for the full TLS 1.3 algorithm-selection guide).
- KEX: `EcdhP256`, `EcdhP384`; HPKE (`oxicrypto::hpke`): `HpkeSuite`, `HpkeContextS`, `HpkeContextR`, `KemId`, `KdfId`, `AeadId` (RFC 9180).
- RNG: `random_bytes`, `random_nonce`, `random_range`, `reseed`.

## Optional modules

| Module | Feature | Pure Rust? | Description |
|--------|---------|-----------|-------------|
| `oxicrypto::pq` | `pq-preview` | Yes | Re-exports [`oxicrypto-pq`](../oxicrypto-pq): ML-KEM, ML-DSA, SLH-DSA, X-Wing. API may change. |
| `oxicrypto::hybrid` | `pq-preview` | Yes | Direct access to the fully-implemented hybrid KEM types: `XWing768` (ML-KEM-768 + X25519) and `HybridKem1024P384` (ML-KEM-1024 + ECDH P-384), plus the `Kem` trait they implement. |

> **0.2.0 change:** The `oxicrypto::aws_lc` and `oxicrypto::pkcs11` modules have been removed from this facade. Users needing the aws-lc-rs FIPS backend or PKCS#11 HSM support must depend on [`oxicrypto-adapter-aws-lc`](../oxicrypto-adapter-aws-lc) and [`oxicrypto-adapter-pkcs11`](../oxicrypto-adapter-pkcs11) directly.

## Feature Flags

| Feature | Default | Pure Rust? | Description |
|---------|---------|-----------|-------------|
| `pure` | **on** | Yes | Enables all Pure-Rust sub-crates: hash, aead, cipher, mac, sig, kex, kdf, rand. |
| `std` | off | Yes | Propagates `std` to the sub-crates (thread-local RNG, etc.). |
| `simd` | off | Yes | Exposes `oxicrypto::simd::cpu_info()` for explicit runtime CPU-feature detection (AES-NI, SHA-NI, AVX2, NEON). The RustCrypto crates already dispatch internally; this makes it visible/testable. |
| `pq-preview` | off | Yes | Post-quantum preview: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), X-Wing. Adds `oxicrypto::pq`, `PqKemAlgo`/`PqSigAlgo`, the `pq_*` helpers, and `PqSuite`. |

### Feature → algorithm matrix

| Feature | Algorithms |
|---------|-----------|
| `pure` (default) | AEAD: AES-GCM-128/256, ChaCha20-Poly1305, AES-CCM-128/256, AES-GCM-SIV-128/256, XChaCha20-Poly1305, AES-OCB3-128/256, Deoxys-II-128, AES Key Wrap 128/256. MAC: HMAC-SHA2-256/384/512, HMAC-SHA3-256/512, CMAC-AES-128/256, KMAC128/256, Poly1305. Hash: SHA-256/384/512, SHA3-256/384/512, SHA-512/256, BLAKE2b-256/512, BLAKE2s-256, BLAKE3. Sig: Ed25519, Ed448, ECDSA P-256/384/521, RSA PKCS1v15 (SHA-256/384/512), RSA-PSS (SHA-256/384/512), Schnorr-BIP340. KEX: X25519, X448, ECDH P-256/384/521 (+ HPKE). KDF: HKDF-SHA256/384/512, Argon2id, PBKDF2-SHA256/512, scrypt, Balloon. |
| `pq-preview` | ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204), SLH-DSA (all 10 param sets, FIPS 205), X-Wing hybrid KEM (ML-KEM-768 + X25519), ML-KEM-1024 + ECDH P-384 hybrid KEM. |
| `simd` | Runtime SIMD dispatch reporting via `simd::cpu_info()`. |
| `std` | Propagates `std` to all sub-crates. |

## Error variants

The crate uses the shared [`oxicrypto_core::CryptoError`](../oxicrypto-core),
re-exported at the root.

| Variant | Description |
|---------|-------------|
| `InvalidKey` | Key has wrong length or is otherwise invalid. |
| `InvalidNonce` | Nonce/IV has wrong length or is otherwise invalid. |
| `InvalidTag` | AEAD open / MAC verify authentication failed. |
| `BufferTooSmall` | Output buffer too small for the operation. |
| `BadInput` | General bad-input condition (e.g. zero-length KDF output). |
| `Internal(&'static str)` | Internal or backend error with a static message. |
| `Kex` | Key-exchange / encapsulation / decapsulation failure. |
| `Sign` | Signature generation or verification failure. |
| `Rng` | RNG-specific failure (e.g. `getrandom` unavailable). |
| `Encoding` | Encoding / decoding failure (DER, PEM, SEC1, …). |
| `UnsupportedAlgorithm` | Algorithm not compiled-in or not supported at runtime (also returned by `FromStr`/`TryFrom` on unknown names). |

## Prelude

```rust
use oxicrypto::prelude::*;
```

Imports the core traits (`Aead`, `Hash`, `Mac`, `Signer`, `Verifier`, `Kdf`,
`KeyAgreement`, `KeyPair`, `Kem`, `PasswordHash`, `Rng`, `StreamingAead`,
`StreamingHash`, `StreamingMac`, `ConstantTimeEq`, `SecretKey`, `SecretVec`,
`Zeroize`, `ZeroizeOnDrop`, `AlgorithmId`, `AlgorithmCategory`, `CryptoError`),
the selector enums (`AeadAlgo`, `HashAlgo`, `KdfAlgo`, `KexAlgo`, `MacAlgo`,
`SigAlgo`; plus `PqKemAlgo`/`PqSigAlgo` under `pq-preview`), the factory and
convenience functions (under `pure`), and `version`/`available_algorithms`/
`VersionInfo`.

## Examples

Runnable examples live under `examples/`:

```bash
cargo run -p oxicrypto --example encrypt   # HKDF-SHA-256 + AES-256-GCM round trip
cargo run -p oxicrypto --example hash      # one-shot hashing
cargo run -p oxicrypto --example sign      # signature sign/verify
cargo run -p oxicrypto --example kex       # key exchange
cargo run -p oxicrypto --example pq_kem --features pq-preview  # ML-KEM (PQ)
```

`tests/pq_hybrid_encryption.rs` (behind `pq-preview`) is a further worked
example beyond the `examples/` binaries above: a complete ML-KEM-768 /
X-Wing768 → HKDF-SHA-256 → AES-256-GCM hybrid public-key encryption round
trip, including tamper-detection and a distinct-ciphertexts-derive-distinct-keys
check. Run it directly with:

```bash
cargo test -p oxicrypto --features pq-preview --test pq_hybrid_encryption
```

## Cross-references

- [`oxicrypto-core`](../oxicrypto-core) — trait surface, `CryptoError`, `AlgorithmId`, secure wrappers.
- [`oxicrypto-hash`](../oxicrypto-hash), [`oxicrypto-aead`](../oxicrypto-aead), [`oxicrypto-cipher`](../oxicrypto-cipher), [`oxicrypto-mac`](../oxicrypto-mac), [`oxicrypto-sig`](../oxicrypto-sig), [`oxicrypto-kex`](../oxicrypto-kex), [`oxicrypto-kdf`](../oxicrypto-kdf), [`oxicrypto-rand`](../oxicrypto-rand) — the Pure-Rust primitive crates.
- [`oxicrypto-pq`](../oxicrypto-pq) — post-quantum primitives (`pq-preview`).
- [`oxicrypto-adapter-aws-lc`](../oxicrypto-adapter-aws-lc), [`oxicrypto-adapter-pkcs11`](../oxicrypto-adapter-pkcs11) — standalone non-Pure-Rust adapters (not re-exported via this facade from 0.2.0; depend on them directly).
- [`oxicrypto-bench`](../oxicrypto-bench) — Criterion benchmarks against `ring`.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
