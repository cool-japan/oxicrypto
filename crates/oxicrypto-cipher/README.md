# oxicrypto-cipher — Raw block/stream cipher primitives for OxiCrypto

[![Crates.io](https://img.shields.io/crates/v/oxicrypto-cipher.svg)](https://crates.io/crates/oxicrypto-cipher)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxicrypto-cipher` provides the deliberately *low-level*, **unauthenticated** cipher building blocks used by the OxiCrypto stack — a single AES-ECB block encryption and a ChaCha20 keystream generator. These are distinct from the authenticated ciphers in [`oxicrypto-aead`](https://crates.io/crates/oxicrypto-aead): they exist specifically for **QUIC header protection** (RFC 9001 §5.4), which masks packet headers with a 5-byte sample of either an AES single-block ECB encryption (§5.4.3) or a ChaCha20 keystream block (§5.4.4).

The crate is **Pure Rust** with `#![forbid(unsafe_code)]`, wrapping the RustCrypto `aes` and `chacha20` crates whose safe constructors (`KeyInit::new`, `KeyIvInit::new`) and operations (`BlockEncrypt::encrypt_block`, `StreamCipher::apply_keystream`) do the actual work. There is no `ring`, no `aws-lc`, and no C/C++ in the build. Because these primitives provide **no authentication**, they should only be used to implement protocols that specify them — do not use them for general-purpose encryption; reach for `oxicrypto-aead` instead.

## Installation

```toml
[dependencies]
oxicrypto-cipher = "0.2.1"
```

```toml
# Inherit std from oxicrypto-core
oxicrypto-cipher = { version = "0.2.1", features = ["std"] }
```

## Quick Start

```rust
use oxicrypto_cipher::{aes128_encrypt_block, chacha20_keystream_block, AES_BLOCK_LEN};
use oxicrypto_core::CryptoError;

// AES-128 single-block ECB (QUIC AES header-protection mask, RFC 9001 §5.4.3).
let hp_key = [0x11u8; 16];
let sample = [0x22u8; AES_BLOCK_LEN]; // 16-byte header-protection sample
let mut mask = [0u8; AES_BLOCK_LEN];
aes128_encrypt_block(&hp_key, &sample, &mut mask)?;

// ChaCha20 keystream (QUIC ChaCha20 header-protection mask, RFC 9001 §5.4.4).
// counter = sample[0..4] as little-endian u32; nonce = sample[4..16].
let cc_key = [0x33u8; 32];
let nonce = [0x44u8; 12];
let mut hp_mask = [0u8; 5];
chacha20_keystream_block(&cc_key, 0, &nonce, &mut hp_mask)?;
# Ok::<(), CryptoError>(())
```

## API Overview

### Functions

| Function | Signature | Notes |
|----------|-----------|-------|
| `aes128_encrypt_block` | `(key: &[u8], block: &[u8], out: &mut [u8]) -> Result<(), CryptoError>` | One 16-byte AES-128 ECB block; QUIC AES mask primitive (RFC 9001 §5.4.3) |
| `aes256_encrypt_block` | `(key: &[u8], block: &[u8], out: &mut [u8]) -> Result<(), CryptoError>` | One 16-byte AES-256 ECB block; same role for the AES-256 suite |
| `chacha20_keystream_block` | `(key: &[u8], counter: u32, nonce: &[u8], out: &mut [u8]) -> Result<(), CryptoError>` | Raw ChaCha20 keystream starting at 32-bit block `counter` (RFC 8439 / RFC 9001 §5.4.4) |

`aes{128,256}_encrypt_block` require `block` and `out` to be exactly / at least 16 bytes (`AES_BLOCK_LEN`). `chacha20_keystream_block` fills `out` (any non-empty length up to one keystream block past the counter) with raw keystream by XORing the keystream over a zeroed buffer; for QUIC the caller passes a 5-byte `out`.

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `AES_BLOCK_LEN` | `16` | AES block size in bytes |
| `AES128_KEY_LEN` | `16` | AES-128 key length in bytes |
| `AES256_KEY_LEN` | `32` | AES-256 key length in bytes |
| `CHACHA20_KEY_LEN` | `32` | ChaCha20 key length in bytes |
| `CHACHA20_NONCE_LEN` | `12` | ChaCha20 nonce length in bytes (IETF / RFC 8439 variant) |

### Errors

All three functions return [`oxicrypto_core::CryptoError`]:

| Variant | Raised when |
|---------|-------------|
| `InvalidKey` | `key` length does not match the required AES/ChaCha20 key length |
| `InvalidNonce` | `nonce` is not 12 bytes (ChaCha20 only) |
| `BadInput` | `block` is not 16 bytes (AES), or `out` is empty (ChaCha20) |
| `BufferTooSmall` | `out` is shorter than 16 bytes (AES only) |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | off | Forwards to `oxicrypto-core/std`. The crate is otherwise `no_std`-friendly. |

## Cross-references

- [`oxicrypto-aead`](https://crates.io/crates/oxicrypto-aead) — **authenticated** ciphers (AES-GCM, ChaCha20-Poly1305, …); use these for confidentiality + integrity.
- [`oxicrypto-core`](https://crates.io/crates/oxicrypto-core) — defines the shared `CryptoError` type returned here.
- [`oxicrypto`](https://crates.io/crates/oxicrypto) — the top-level façade for the OxiCrypto stack.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
