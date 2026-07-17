# oxicrypto-aead — Pure-Rust AEAD ciphers for OxiCrypto

[![Crates.io](https://img.shields.io/crates/v/oxicrypto-aead.svg)](https://crates.io/crates/oxicrypto-aead)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxicrypto-aead` is the Authenticated-Encryption-with-Associated-Data layer of the OxiCrypto stack. It implements the [`oxicrypto_core::Aead`](https://crates.io/crates/oxicrypto-core) and `StreamingAead` traits over a broad family of AEAD constructions — AES-GCM, ChaCha20-Poly1305, the misuse-resistant AES-GCM-SIV and Deoxys-II, extended-nonce XChaCha20-Poly1305, AES-CCM, and AES-OCB3 — plus RFC 3394 key wrap, a STREAM chunked construction, monotonic nonce sequences, and a self-describing SealedBox wire format.

The crate is **Pure Rust** with `#![forbid(unsafe_code)]`, built on the RustCrypto `aes-gcm`, `chacha20poly1305`, `aes-gcm-siv`, `ocb3`, `aes-kw`, and `aead` crates (the `aead 0.6` chain). There is no `ring`, no `aws-lc`, and no C/C++/Fortran in the default build. The detached seal/open helpers operate in place (via `AeadInOut`) to minimise heap traffic, and tag verification on `open` is delegated to the underlying constant-time RustCrypto implementations; Deoxys-II additionally verifies its tag via [`oxicrypto_core::ct_eq`].

## Installation

```toml
[dependencies]
oxicrypto-aead = "0.2.1"
```

```toml
# Inherit std from oxicrypto-core
oxicrypto-aead = { version = "0.2.1", features = ["std"] }
```

## Quick Start

```rust
use oxicrypto_aead::Aes256Gcm;
use oxicrypto_core::{Aead, CryptoError};

let aead = Aes256Gcm;
let key = [0x42u8; 32];   // 32-byte key
let nonce = [0x24u8; 12]; // 12-byte nonce
let aad = b"associated data";

// seal_to_vec / open_to_vec allocate the output for you (ciphertext || tag).
let ct = aead.seal_to_vec(&key, &nonce, aad, b"hello, oxicrypto!")?;
let pt = aead.open_to_vec(&key, &nonce, aad, &ct)?;
assert_eq!(pt, b"hello, oxicrypto!");
# Ok::<(), CryptoError>(())
```

### Sealed box (nonce prepended to ciphertext)

```rust,ignore
use oxicrypto_aead::{seal_box, open_box, Aes256Gcm};

// seal_box draws a fresh random nonce and returns `nonce || ciphertext || tag`.
let sealed = seal_box(&Aes256Gcm, &key, b"aad", b"secret", &mut rng)?;
let opened = open_box(&Aes256Gcm, &key, b"aad", &sealed)?;
```

## API Overview

### AEAD algorithms (`oxicrypto_core::Aead`)

All of the following implement the `Aead` trait. Key, nonce, and tag sizes are in bytes.

| Type | Algorithm | Key | Nonce | Tag | Standard / notes |
|------|-----------|-----|-------|-----|------------------|
| `Aes128Gcm` | AES-128-GCM | 16 | 12 | 16 | NIST SP 800-38D, RFC 5116 (inline) |
| `Aes256Gcm` | AES-256-GCM | 32 | 12 | 16 | NIST SP 800-38D, RFC 5116 (inline) |
| `ChaCha20Poly1305` | ChaCha20-Poly1305 | 32 | 12 | 16 | RFC 8439 (inline) |
| `AesGcmSiv128` | AES-128-GCM-SIV | 16 | 12 | 16 | RFC 8452, nonce-misuse resistant |
| `AesGcmSiv256` | AES-256-GCM-SIV | 32 | 12 | 16 | RFC 8452, nonce-misuse resistant |
| `XChaCha20Poly1305` | XChaCha20-Poly1305 | 32 | 24 | 16 | 192-bit nonce — safe for random nonces |
| `Aes128Ccm` | AES-128-CCM | 16 | 13 | 16 | RFC 3610 (L=2, messages up to 2¹⁶−1 bytes) |
| `Aes256Ccm` | AES-256-CCM | 32 | 13 | 16 | RFC 3610 |
| `Aes128Ocb3` | AES-128-OCB3 | 16 | 12 | 16 | RFC 7253 (single-pass; see patent note) |
| `Aes256Ocb3` | AES-256-OCB3 | 32 | 12 | 16 | RFC 7253 (single-pass; see patent note) |
| `Deoxys2_128` | Deoxys-II-128-128 | 16 | 16 | 16 | CAESAR final portfolio, nonce-misuse resistant (SCT-2 mode) |

> **Misuse resistance**: `AesGcmSiv128/256` and `Deoxys2_128` are SIV-style constructions where reusing a nonce leaks only whether two messages were identical — it does not expose the keystream the way a nonce collision does for GCM/ChaCha20-Poly1305.

> **OCB3 patent note**: OCB3 is covered by patents held by Phillip Rogaway; a royalty-free licence is available for open-source software and for military use (RFC 7253 §1.1).

The `Aead` trait methods are `name`, `key_len`, `nonce_len`, `tag_len`, `seal`, `open`, the allocating convenience defaults `seal_to_vec`/`open_to_vec`, detached-tag `seal_detached`/`open_detached`, buffer-reusing `seal_in_place`, and the `max_plaintext_len` size-limit accessor (an RFC-correct per-algorithm ceiling; `u64::MAX` by default). `seal` writes `ciphertext || tag` and returns `pt.len() + tag_len`; `open` returns `ct.len() - tag_len`.

### Streaming AEAD (`oxicrypto_core::StreamingAead`)

STREAM chunked construction (Hoang-Reyhanitabar-Rogaway-Vizár 2015) — each chunk gets a unique nonce derived from a nonce prefix and a 32-bit counter, with the final chunk distinguished by a flag byte.

| Type | Underlying AEAD | Nonce-prefix length |
|------|-----------------|---------------------|
| `Aes256GcmStream` | AES-256-GCM | 7 bytes (`NONCE_FULL − 5`) |
| `ChaCha20Poly1305Stream` | ChaCha20-Poly1305 | 7 bytes |

Lifecycle: `init(key, nonce_prefix, aad)` → `encrypt_update` / `decrypt_update` per chunk → `encrypt_finalize` / `decrypt_finalize` → optional `reset`.

### Key wrap — RFC 3394 (`keywrap` module)

Standalone API that does **not** implement `Aead` (key wrapping has no nonce). Wrapped output is always `data.len() + 8` bytes; input must be ≥ 16 bytes and a multiple of 8.

| Function | Description |
|----------|-------------|
| `aes128_key_wrap(kek, data, out)` | Wrap key material with a 128-bit KEK |
| `aes128_key_unwrap(kek, wrapped, out)` | Unwrap key material (128-bit KEK) |
| `aes256_key_wrap(kek, data, out)` | Wrap key material with a 256-bit KEK |
| `aes256_key_unwrap(kek, wrapped, out)` | Unwrap key material (256-bit KEK) |

### Nonce sequences (`nonce_seq` module)

`NonceSequence<const N: usize>` produces unique, monotonic `N`-byte nonces with the layout `[ (N−8)-byte fixed prefix ‖ 8-byte big-endian counter ]`. `generate` returns `CryptoError::Internal` on counter overflow to prevent reuse.

| Item | Description |
|------|-------------|
| `NonceSequence<N>::new(prefix)` | Construct from a fixed prefix (length `N − 8`) |
| `NonceSequence<N>::with_random_prefix()` | Construct with a cryptographically random prefix drawn from `oxicrypto-rand`'s `OxiRng` (requires the `rand` feature) |
| `NonceSequence<N>::generate()` | Produce the next `[u8; N]` nonce |
| `NonceSequence<N>::count()` | Current counter value (`u64`) |
| `Nonce12` | `NonceSequence<12>` — AES-GCM, ChaCha20-Poly1305 |
| `Nonce24` | `NonceSequence<24>` — XChaCha20-Poly1305 |

Separately, [`NonceBytes<N>`] (aliases `Nonce12Bytes = NonceBytes<12>`, `Nonce24Bytes = NonceBytes<24>`) is a type-safe fixed-size nonce newtype — `Deref<Target = [u8]>`, `From<[u8; N]>`, `TryFrom<&[u8]>` — for callers who want a typed nonce value instead of a raw slice; it does not track a counter the way `NonceSequence` does.

### Misuse-resistant & key-committing extensions

| Type | Description |
|------|-------------|
| `SyntheticIvAes256Gcm` | Deterministic AES-256-GCM: `K_enc`/`K_mac` are split from the master key via HKDF-SHA-256, and the nonce is `HMAC-SHA-256(K_mac, aad ‖ pt)[..12]`. Implements `Aead`; callers **must** pass `nonce = &[]` (it is derived internally, and `open` re-derives and constant-time-compares it for a key-committing side effect). `tag_len()` returns 28 (12-byte nonce prefix + 16-byte GCM tag). **Weaker than RFC 8452 AES-GCM-SIV** — prefer `AesGcmSiv256` when nonce-misuse resistance is the goal; this type exists for environments that require standard AES-GCM but cannot guarantee unique nonces. |
| `CommittingAead<'a>` | Wraps any `&dyn Aead` with the **UtC** (Bellare–Hoang, "Efficient Schemes for Committing AE", EUROCRYPT 2022) **CMT-1** key-committing transform: output is `commitment(32 bytes) ‖ inner_ciphertext`, where `commitment` and the inner sub-key are both derived from the wrapping key via HKDF-SHA-256. Defends against invisible-salamander / partitioning-oracle attacks (Grubbs et al., CCS 2017). `new(inner)`, `seal(key, nonce, aad, pt)`, `open(key, nonce, aad, ct)`, `overhead()` (always 32). |

### SealedBox & random-nonce helpers

| Function | Returns | Description |
|----------|---------|-------------|
| `seal_box(aead, key, aad, plaintext, rng)` | `Vec<u8>` | Draw a random nonce and return `nonce ‖ ciphertext ‖ tag` as one opaque blob |
| `open_box(aead, key, aad, sealed)` | `Vec<u8>` | Split `sealed` at `aead.nonce_len()`, then decrypt and authenticate |
| `seal_with_random_nonce(aead, key, aad, plaintext, rng)` | `(Vec<u8>, Vec<u8>)` | Encrypt with a fresh random nonce, returning `(nonce, ciphertext_with_tag)` **separately** (for transports that carry the nonce in its own field) |

Both `seal_box` and `seal_with_random_nonce` take `aead: &dyn Aead` and `rng: &mut dyn oxicrypto_core::Rng`, so any algorithm above and any CSPRNG can be combined at runtime.

### Re-exports at crate root

`Aes128Gcm`, `Aes256Gcm`, `ChaCha20Poly1305` (inline); `AesGcmSiv128`, `AesGcmSiv256`; `XChaCha20Poly1305`; `Aes128Ccm`, `Aes256Ccm`; `Aes128Ocb3`, `Aes256Ocb3`; `Deoxys2_128`; `SyntheticIvAes256Gcm`; `CommittingAead`; `Aes256GcmStream`, `ChaCha20Poly1305Stream`; `Nonce12`, `Nonce24`, `NonceSequence`; `NonceBytes`, `Nonce12Bytes`, `Nonce24Bytes`; `aes128_key_wrap`/`aes128_key_unwrap`/`aes256_key_wrap`/`aes256_key_unwrap`; `seal_box`, `open_box`; and `seal_with_random_nonce`.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | off | Forwards to `oxicrypto-core/std`. |
| `rand` | off | Pulls in `oxicrypto-rand` and enables `NonceSequence::with_random_prefix()`. |

The crate does not currently declare `#![no_std]` at its crate root, so it links the standard library regardless of the `std` feature; `std` only forwards the flag to `oxicrypto-core`. (`oxicrypto-core` itself is genuinely `no_std` — see its README.)

## Cross-references

- [`oxicrypto-core`](https://crates.io/crates/oxicrypto-core) — defines the `Aead`, `StreamingAead`, `Rng`, and `CryptoError` types used here.
- [`oxicrypto-cipher`](https://crates.io/crates/oxicrypto-cipher) — raw **unauthenticated** AES/ChaCha20 primitives for QUIC header protection.
- [`oxicrypto-kdf`](https://crates.io/crates/oxicrypto-kdf) — key derivation to feed AEAD keys.
- [`oxicrypto`](https://crates.io/crates/oxicrypto) — the top-level façade for the OxiCrypto stack.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
