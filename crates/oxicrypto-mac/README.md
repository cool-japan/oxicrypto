# oxicrypto-mac — Pure-Rust message authentication codes for OxiCrypto

[![Crates.io](https://img.shields.io/crates/v/oxicrypto-mac.svg)](https://crates.io/crates/oxicrypto-mac)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxicrypto-mac` is the MAC (message authentication code) layer of the OxiCrypto stack. It wraps the RustCrypto `hmac`, `cmac`, `poly1305`, `tiny-keccak`, and `blake3` primitives behind the `oxicrypto_core::{Mac, StreamingMac}` traits, providing HMAC (SHA-2 and SHA-3 families), Poly1305, CMAC-AES, KMAC (SP 800-185), and BLAKE3 keyed-hash authentication, plus a hash-agnostic generic HMAC adapter and TLS 1.3/1.2 cipher-suite MAC negotiation (see below).

The crate is Pure Rust (`#![forbid(unsafe_code)]`) and written in a `no_std`-portable style — production code uses explicit `alloc::` paths and no direct `std::` API. **Note:** unlike `oxicrypto-core` and `oxicrypto-hash`, `src/lib.rs` does not currently declare `#![no_std]`, so today the crate links `std` unconditionally regardless of the `std` feature; `alloc` is used unconditionally too (there is no feature to opt out of it). Every `verify` path uses **constant-time** comparison via the `subtle` crate, so tag checks do not leak timing information. One-shot, streaming, and truncated variants are provided, along with `*_to_vec` convenience helpers.

## Installation

```toml
[dependencies]
oxicrypto-mac = "0.2.1"
```

## Quick Start

```rust
use oxicrypto_core::Mac;
use oxicrypto_mac::HmacSha256;

fn main() -> Result<(), oxicrypto_core::CryptoError> {
    let key = b"my-32-byte-secret-key-0123456789";
    let msg = b"authenticate me";

    // One-shot HMAC-SHA-256 (32-byte tag).
    let mut tag = [0u8; 32];
    HmacSha256.mac(key, msg, &mut tag)?;

    // Constant-time verification.
    HmacSha256.verify(key, msg, &tag)?;
    Ok(())
}
```

Streaming and BLAKE3 keyed MAC:

```rust
use oxicrypto_core::StreamingMac;
use oxicrypto_mac::{blake3_keyed_mac, HmacSha256Streaming};

fn main() -> Result<(), oxicrypto_core::CryptoError> {
    // Feed the message in chunks, then finalize.
    let mut mac = HmacSha256Streaming::new(b"streaming-key")?;
    mac.update(b"hello ");
    mac.update(b"world");
    let mut out = [0u8; 32];
    mac.finalize(&mut out)?;

    // BLAKE3 native keyed-hash MAC (32-byte key, 32-byte tag).
    let tag = blake3_keyed_mac(&[0x42u8; 32], b"message");
    let _ = tag;
    Ok(())
}
```

## API Overview

### `Mac`-trait implementations (one-shot)

All of these are zero-size unit structs implementing `oxicrypto_core::Mac` (`name`, `key_len`, `output_len`, `mac`, `verify`, `min_key_len`, and `mac_to_vec`).

| Type | Algorithm | Key length | Tag length | Standard / notes |
|------|-----------|-----------|-----------|------------------|
| `HmacSha256` | HMAC-SHA-256 | 32 (recommended) | 32 | RFC 2104 / FIPS 198-1 |
| `HmacSha384` | HMAC-SHA-384 | 48 (recommended) | 48 | RFC 2104 / FIPS 198-1 |
| `HmacSha512` | HMAC-SHA-512 | 64 (recommended) | 64 | RFC 2104 / FIPS 198-1 |
| `HmacSha3_256` | HMAC-SHA3-256 | 32 (recommended) | 32 | Uses `hmac::SimpleHmac` |
| `HmacSha3_512` | HMAC-SHA3-512 | 64 (recommended) | 64 | Uses `hmac::SimpleHmac` |
| `Poly1305Mac` | Poly1305 | 32 (exact) | 16 | RFC 8439; **one-time** MAC (see warning) |
| `CmacAes128` | CMAC-AES-128 | 16 | 16 | NIST SP 800-38B |
| `CmacAes256` | CMAC-AES-256 | 32 | 16 | NIST SP 800-38B |
| `Kmac128` | KMAC128 | ≥ 16 (recommended) | configurable (default 32) | NIST SP 800-185 |
| `Kmac256` | KMAC256 | ≥ 32 (recommended) | configurable (default 64) | NIST SP 800-185 |

> **Poly1305 is a one-time MAC.** The 32-byte key MUST NOT be reused across messages; derive a fresh per-message key (e.g. from a stream cipher or KDF). Key reuse destroys all security.

`Kmac128` / `Kmac256` are constructed with a customization string and output length: `Kmac128::new(custom: &[u8], output_len: usize)` (returns `CryptoError::BadInput` if `output_len == 0`). They carry a domain-separation `custom` field and implement `Debug` (output length only).

### Truncated HMAC (inherent methods)

`HmacSha256`, `HmacSha384`, and `HmacSha512` each provide:

| Method | Description |
|--------|-------------|
| `mac_truncated(key, msg, out)` | Write the first `out.len()` bytes of the full tag; rejects `out.len() < 16` with `BadInput` (NIST SP 800-117 minimum) |
| `verify_truncated(key, msg, tag)` | Constant-time verify of a truncated tag; rejects `tag.len() < 16` with `BadInput` |

### Streaming MACs

| Type / item | Description |
|-------------|-------------|
| `HmacStreamingAdapter<D>` | Generic `StreamingMac` over `hmac::Hmac<D>`; `new(key)`, `update`, `finalize`, `verify` |
| `HmacSha256Streaming` | Type alias `HmacStreamingAdapter<sha2::Sha256>` |
| `HmacSha384Streaming` | Type alias `HmacStreamingAdapter<sha2::Sha384>` |
| `HmacSha512Streaming` | Type alias `HmacStreamingAdapter<sha2::Sha512>` |
| `HmacSha256::new_keyed(key)` / `HmacSha384::new_keyed(key)` / `HmacSha512::new_keyed(key)` | Pre-keyed constructors returning `HmacSha256Keyed` / `HmacSha384Keyed` / `HmacSha512Keyed`, which cache the keyed `hmac::Hmac<D>` state and expose their own `update`/`finalize` pair for repeated use with the same key |

`StreamingMac` (from `oxicrypto-core`): `update(&mut self, data)`, `finalize(self, out)`, `verify(self, expected)` (constant-time).

### Hash-agnostic HMAC (`hmac_streaming_hash` module)

A structurally-correct RFC 2104 HMAC built directly on [`oxicrypto_core::StreamingHash`] rather than the `digest` crate, so it works with **any** `oxicrypto-hash` streaming hasher (SHA-2, SHA-3, BLAKE2, BLAKE3, …) without adding a hash-crate dependency edge. All items below are also re-exported at the crate root.

| Item | Description |
|------|-------------|
| `StreamingHashHmac::new(key, block_size, output_len, factory)` | Construct an HMAC over any `H: StreamingHash` produced by `factory: Fn() -> H`; pre-hashes `key` with a fresh `H` if longer than `block_size`, then zero-pads to `block_size` |
| `StreamingHashHmac::mac_oneshot(msg, out)` / `.verify(msg, expected)` | One-shot MAC / constant-time verify |
| `StreamingHashHmac::streaming_session()` | Returns a `StreamingHashHmacSession` (requires `F: Clone`) for incremental `update`/`finalize` |
| `hmac_with_streaming_hash(key, block_size, output_len, msg, factory)` | Free-function, one-shot convenience wrapper returning `Vec<u8>` |

### Free functions

| Function | Description |
|----------|-------------|
| `kmac128_xof(key, custom, msg, output_len)` | KMAC128 XOF mode (SP 800-185 §4.3.1), returns owned `Vec<u8>` |
| `kmac256_xof(key, custom, msg, output_len)` | KMAC256 XOF mode, returns owned `Vec<u8>` |
| `blake3_keyed_mac(key: &[u8; 32], msg) -> [u8; 32]` | BLAKE3 native keyed-hash MAC (not HMAC-BLAKE3) |
| `blake3_keyed_mac_verify(key, msg, expected) -> Result<()>` | Constant-time BLAKE3 keyed-MAC verification |
| `hmac_sha256_verify_truncated(key, msg, truncated_tag)` | Permissive truncated HMAC-SHA-256 verify (accepts 1–32 byte tags) |
| `hmac_sha256_to_vec(key, msg) -> Result<Vec<u8>>` | HMAC-SHA-256 returning an owned 32-byte vector |
| `hmac_sha384_to_vec(key, msg) -> Result<Vec<u8>>` | HMAC-SHA-384 returning an owned 48-byte vector |
| `hmac_sha512_to_vec(key, msg) -> Result<Vec<u8>>` | HMAC-SHA-512 returning an owned 64-byte vector |

### TLS cipher-suite MAC negotiation (`tls` module)

Maps a TLS cipher suite to the HMAC primitive its handshake uses (the HKDF and Finished-message MAC, RFC 8446 §7.1 / §4.4.4), so higher-level OxiTLS code isn't hard-coded to a specific hash function. All items below are also re-exported at the crate root.

| Item | Description |
|------|-------------|
| `TlsCipherSuite` | `#[non_exhaustive]` enum: all 5 RFC 8446 §B.4 TLS 1.3 suites (`Aes128GcmSha256`, `Aes256GcmSha384`, `Chacha20Poly1305Sha256`, `Aes128CcmSha256`, `Aes128Ccm8Sha256`) plus generic TLS 1.2 PRF markers (`Sha256Prf`, `Sha384Prf`, `Sha512Prf`) |
| `TlsCipherSuite::from_iana_name(name) -> Option<Self>` | Parse an IANA cipher-suite name, e.g. `"TLS_AES_256_GCM_SHA384"` |
| `mac_name_for_suite(suite) -> &'static str` | Canonical MAC name for a suite, e.g. `"HMAC-SHA-384"` |
| `negotiate_mac(suite) -> Result<Box<dyn Mac + Send + Sync>, CryptoError>` | Boxed `HmacSha256` / `HmacSha384` / `HmacSha512` for the suite's HKDF/Finished MAC; currently infallible (reserved for future variants) |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | off | Forwards to `oxicrypto-core/std` (enabling `From<CryptoError> for std::io::Error` there). Has no effect inside `oxicrypto-mac` itself — no code in this crate is gated on `feature = "std"`. |

`alloc` is used unconditionally (KMAC, the `*_to_vec` helpers, the hash-agnostic HMAC module, and the TLS module all need it) and cannot currently be disabled. As noted above, the crate does not yet declare `#![no_std]`, so it links `std` regardless of this feature.

## Error Variants

All fallible operations return `oxicrypto_core::CryptoError`:

| Variant | When |
|---------|------|
| `BufferTooSmall` | The output buffer is shorter than the algorithm's tag length |
| `InvalidKey` | The underlying primitive rejected the key (e.g. wrong Poly1305 key length) |
| `InvalidTag` | Constant-time `verify` failed, or the supplied tag had the wrong length |
| `BadInput` | Truncation length below the 16-byte minimum, or KMAC `output_len == 0` |

## Cross-References

- [`oxicrypto-core`](../oxicrypto-core) — defines the `Mac` and `StreamingMac` traits and `CryptoError`.
- [`oxicrypto-hash`](../oxicrypto-hash) — the underlying hash functions (SHA-2, SHA-3, BLAKE3).
- [`oxicrypto-aead`](../oxicrypto-aead) — ChaCha20Poly1305 / AES-GCM, which compose ciphers with Poly1305 / GMAC internally.
- [`oxicrypto`](../oxicrypto) — the facade re-exports `HmacSha384` at the crate root.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
