# oxicrypto-adapter-aws-lc — aws-lc-rs backend for OxiCrypto

[![Crates.io](https://img.shields.io/crates/v/oxicrypto-adapter-aws-lc.svg)](https://crates.io/crates/oxicrypto-adapter-aws-lc)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxicrypto-adapter-aws-lc` implements the core OxiCrypto traits (`Aead`, `Hash`, `Signer`, `Verifier`, `Kdf`, `Mac` from [`oxicrypto-core`](../oxicrypto-core)) on top of [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs), the FIPS-validated cryptographic library maintained by AWS. It lets an application that is already written against the OxiCrypto trait surface swap selected primitives for the hardware-accelerated, FIPS-mode `aws-lc-rs` implementations without changing call sites.

> **Not Pure Rust.** `aws-lc-rs` wraps the AWS-LC C library (a BoringSSL/OpenSSL derivative) and pulls in a C toolchain (or a prebuilt binary) at build time. This adapter is therefore **C/FFI-backed**, in deliberate contrast to the default Pure-Rust OxiCrypto stack. It is **opt-in and non-default**: the crate exposes **no types** unless the `aws-lc` feature is enabled, and from **0.2.0** the parent `oxicrypto` facade no longer re-exports it — depend on this crate directly. Use it when FIPS 140 validation or AWS-LC parity is a hard requirement; otherwise prefer the Pure-Rust crates.

## Installation

```toml
[dependencies]
# Types are only compiled in when the `aws-lc` feature is on.
oxicrypto-adapter-aws-lc = { version = "0.2.1", features = ["aws-lc"] }
```

From **oxicrypto 0.2.0**, the `aws-lc` feature is no longer available on the `oxicrypto` facade. Depend on this adapter crate directly instead of going via the facade.

A C compiler / build environment compatible with `aws-lc-rs` is required at
build time. See the [`aws-lc-rs` requirements](https://crates.io/crates/aws-lc-rs)
for platform details.

## Quick Start

```rust
# #[cfg(feature = "aws-lc")]
# {
use oxicrypto_adapter_aws_lc::aead::AwsLcAead;
use oxicrypto_core::Aead;

let cipher = AwsLcAead::aes256_gcm();
let key = vec![0x42u8; cipher.key_len()];   // 32 bytes
let nonce = vec![0x11u8; cipher.nonce_len()]; // 12 bytes
let aad = b"associated data";
let plaintext = b"secret payload";

// ct buffer must hold plaintext + tag_len() bytes.
let mut ct = vec![0u8; plaintext.len() + cipher.tag_len()];
let written = cipher.seal(&key, &nonce, aad, plaintext, &mut ct)?;

let mut recovered = vec![0u8; plaintext.len()];
cipher.open(&key, &nonce, aad, &ct[..written], &mut recovered)?;
assert_eq!(&recovered, plaintext);
# }
# Ok::<(), oxicrypto_core::CryptoError>(())
```

Signing with the aws-lc-rs Ed25519 backend:

```rust
# #[cfg(feature = "aws-lc")]
# {
use oxicrypto_adapter_aws_lc::sign::{AwsLcEd25519Signer, AwsLcEd25519Verifier};
use oxicrypto_core::{Signer, Verifier};

let signer = AwsLcEd25519Signer;
let seed = [0x5au8; 32];          // 32-byte Ed25519 seed
let msg = b"message to sign";
let mut sig = [0u8; 64];
signer.sign(&seed, msg, &mut sig)?;

// (public key derived out-of-band, e.g. via aws-lc-rs Ed25519KeyPair)
# }
# Ok::<(), oxicrypto_core::CryptoError>(())
```

## API Overview

All items below are compiled **only** when the `aws-lc` feature is enabled.

### `aead` module

| Item | Implements | Description |
|------|-----------|-------------|
| `AwsLcAead` | `oxicrypto_core::Aead` | AEAD cipher backed by aws-lc-rs. Variant chosen via constructor. |
| `AwsLcAead::aes128_gcm()` | — | AES-128-GCM (key 16 B, nonce 12 B, tag 16 B). |
| `AwsLcAead::aes256_gcm()` | — | AES-256-GCM (key 32 B, nonce 12 B, tag 16 B). |
| `AwsLcAead::chacha20_poly1305()` | — | ChaCha20-Poly1305 (key 32 B, nonce 12 B, tag 16 B). |

The `Aead` impl provides `name()`, `key_len()`, `nonce_len()`, `tag_len()`,
`seal(...)`, and `open(...)` (plus the `*_to_vec` default helpers from the
trait). `nonce_len()` is 12 and `tag_len()` is 16 for every variant.

### `hash` module

| Type | Implements | Output |
|------|-----------|--------|
| `AwsLcSha256` | `oxicrypto_core::Hash` | SHA-256, 32 bytes |
| `AwsLcSha384` | `oxicrypto_core::Hash` | SHA-384, 48 bytes |
| `AwsLcSha512` | `oxicrypto_core::Hash` | SHA-512, 64 bytes |

Each is a unit struct (`Debug + Default + Clone + Copy`) exposing the `Hash`
trait methods `name()`, `output_len()`, `hash()` (and the `hash_to_vec`
default helper).

### `sign` module

| Type | Implements | Notes |
|------|-----------|-------|
| `AwsLcEd25519Signer` | `oxicrypto_core::Signer` | Deterministic Ed25519; `sk` is the 32-byte seed; 64-byte signature. Byte-comparable with RustCrypto. |
| `AwsLcEd25519Verifier` | `oxicrypto_core::Verifier` | Verifies Ed25519 over a raw 32-byte public key. |
| `AwsLcEcdsaP256Signer` | `oxicrypto_core::Signer` | ECDSA P-256 / SHA-256, fixed `r‖s` (64-byte) signature. `sk` is a raw 32-byte big-endian scalar. Uses a random per-message nonce (**not** deterministic RFC 6979) → not byte-comparable. |
| `AwsLcEcdsaP256Verifier` | `oxicrypto_core::Verifier` | Verifies ECDSA P-256 fixed signatures; `pk` is the 65-byte uncompressed SEC1 key (`0x04` prefix). |
| `AwsLcEcdsaP384Signer` | `oxicrypto_core::Signer` | ECDSA P-384 / SHA-384, fixed `r‖s` (96-byte) signature. `sk` is a raw 48-byte big-endian scalar. Random per-message nonce (not RFC 6979) → not byte-comparable. |
| `AwsLcEcdsaP384Verifier` | `oxicrypto_core::Verifier` | Verifies ECDSA P-384 fixed signatures; `pk` is the 97-byte uncompressed SEC1 key (`0x04` prefix). |
| `AwsLcRsaPkcs1Sha256Signer` | `oxicrypto_core::Signer` | RSA PKCS#1 v1.5 + SHA-256. `sk` is a PKCS#8 DER private key (2048–8192-bit modulus); signature length equals the modulus size. |
| `AwsLcRsaPssSha256Signer` | `oxicrypto_core::Signer` | RSA-PSS + SHA-256. `sk` is a PKCS#8 DER private key (2048–8192-bit modulus); signature length equals the modulus size. |
| `AwsLcRsaPkcs1Sha256Verifier` | `oxicrypto_core::Verifier` | Verifies RSA PKCS#1 v1.5 + SHA-256 (2048–8192-bit moduli); `pk` is a DER `RSAPublicKey` or X.509 SubjectPublicKeyInfo. |
| `AwsLcRsaPssSha256Verifier` | `oxicrypto_core::Verifier` | Verifies RSA-PSS + SHA-256 (2048–8192-bit moduli); `pk` is a DER `RSAPublicKey` or X.509 SubjectPublicKeyInfo. |

All ten are unit structs (`Debug + Default + Clone + Copy`) with a `Display` impl delegating to `name()`.

### `hkdf` module

| Type | Implements | Description |
|------|-----------|-------------|
| `AwsLcHkdf` | `oxicrypto_core::Kdf` | HKDF backed by aws-lc-rs. Construct via `AwsLcHkdf::sha256()` / `sha384()` / `sha512()`. |

`Kdf::derive(ikm, salt, info, okm_out)` runs HKDF-Extract then HKDF-Expand in one call; `okm_out` must be non-empty (`CryptoError::BadInput` otherwise).

### `mac` module

| Type | Implements | Description |
|------|-----------|-------------|
| `AwsLcHmac` | `oxicrypto_core::Mac` | HMAC backed by aws-lc-rs. Construct via `AwsLcHmac::sha256()` / `sha384()` / `sha512()`; `key_len()` / `output_len()` equal the underlying digest length (32/48/64 bytes). |

`Mac::mac(key, msg, out)` computes the tag (`CryptoError::BufferTooSmall` if `out` is short); `Mac::verify(key, msg, tag)` checks it (`CryptoError::InvalidTag` on mismatch).

### `AwsLcCryptoProvider`

An aggregate struct with one factory method per primitive — `aes128_gcm()`, `aes256_gcm()`, `aes256_gcm_siv()`, `chacha20_poly1305()`, `sha256()`/`sha384()`/`sha512()`, `ed25519_signer()`/`ed25519_verifier()`, `ecdsa_p256_signer()`/`ecdsa_p256_verifier()`, `ecdsa_p384_signer()`/`ecdsa_p384_verifier()`, `rsa_pkcs1_sha256_signer()`/`rsa_pkcs1_sha256_verifier()`, `rsa_pss_sha256_signer()`/`rsa_pss_sha256_verifier()`, `hkdf_sha256()`/`hkdf_sha384()`/`hkdf_sha512()`, `hmac_sha256()`/`hmac_sha384()`/`hmac_sha512()` — for dependency-injection call sites that want a single aws-lc-rs provider handle instead of importing each type individually.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `aws-lc` | off | Activates the `aead`, `hash`, `sign`, `hkdf`, and `mac` modules (pulls in the `aws-lc-rs` C-backed dependency). With this flag off, the crate compiles to an empty surface (verified by the `oxicrypto_default_closure_is_pure` test). |

## Error variants

This adapter returns the shared [`oxicrypto_core::CryptoError`](../oxicrypto-core).
The variants it actually produces are:

| Variant | When it is returned |
|---------|---------------------|
| `InvalidKey` | Key length/format rejected by aws-lc-rs (`UnboundKey::new`, EC key parse, ≠ 32-byte scalar). |
| `InvalidNonce` | Nonce not accepted by `Nonce::try_assume_unique_for_key`. |
| `InvalidTag` | AEAD `open` authentication failure, or signature verification failure. |
| `BufferTooSmall` | Output buffer smaller than required (`pt.len() + tag_len()`, or `< 64` for signatures). |
| `BadInput` | Ciphertext shorter than `tag_len()`; overflow computing required length; empty HKDF output buffer. |
| `Sign` | ECDSA signing call failed. |
| `Internal(&'static str)` | Unexpected aws-lc-rs error or signature-length mismatch. |

## Cross-references

- [`oxicrypto-core`](../oxicrypto-core) — the `Aead`, `Hash`, `Signer`, `Verifier`, `Kdf`, `Mac`, and `CryptoError` definitions this adapter implements.
- [`oxicrypto`](../oxicrypto) — Pure-Rust facade; from 0.2.0 this adapter must be depended on directly (no longer re-exported via `oxicrypto::aws_lc`).
- [`oxicrypto-aead`](../oxicrypto-aead) / [`oxicrypto-hash`](../oxicrypto-hash) / [`oxicrypto-sig`](../oxicrypto-sig) / [`oxicrypto-kdf`](../oxicrypto-kdf) — the Pure-Rust counterparts these primitives can substitute for.
- [`oxicrypto-adapter-pkcs11`](../oxicrypto-adapter-pkcs11) — the other opt-in, non-Pure-Rust adapter (HSM via PKCS#11).
- [`oxicrypto-bench`](../oxicrypto-bench) — benchmarks that compare OxiCrypto against `aws-lc-rs` and `ring`.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
