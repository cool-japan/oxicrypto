# oxicrypto-kdf — Pure-Rust key derivation and password hashing for OxiCrypto

[![Crates.io](https://img.shields.io/crates/v/oxicrypto-kdf.svg)](https://crates.io/crates/oxicrypto-kdf)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxicrypto-kdf` is the key-derivation and password-hashing layer of the OxiCrypto stack. It implements the [`oxicrypto_core::Kdf`](https://crates.io/crates/oxicrypto-core) and `PasswordHash` traits over the extract-and-expand HKDF (SHA-256/384/512), the iteration-hard PBKDF2 (SHA-256/512), and the memory-hard Argon2id, scrypt, and Balloon functions. It also provides the protocol building blocks `HKDF-Expand-Label` (TLS 1.3 / QUIC) and KBKDF counter mode (NIST SP 800-108), plus a runtime-selectable `KeyStretcher` abstraction and a constant-time `verify_password` helper.

The crate is **Pure Rust** with `#![forbid(unsafe_code)]`, built on the RustCrypto `hkdf`, `pbkdf2`, `argon2`, `scrypt`, `hmac`, `sha2`, `subtle`, and `password-hash` crates. There is no `ring`, no `aws-lc`, and no C/C++/Fortran in the default build. Password verification uses `subtle::ConstantTimeEq` so the comparison does not leak the position of the first differing byte, and derived key material from the Balloon and KBKDF helpers is wrapped in [`oxicrypto_core::SecretVec`] so it is zeroized on drop.

## Installation

```toml
[dependencies]
oxicrypto-kdf = "0.1.0"
```

```toml
# Inherit std from sha2 / oxicrypto-core
oxicrypto-kdf = { version = "0.1.0", features = ["std"] }
```

## Quick Start

```rust
use oxicrypto_kdf::{HkdfSha256, hkdf_sha256_derive_to_vec};
use oxicrypto_core::{Kdf, CryptoError};

// Trait-based: derive into a caller-provided buffer.
let mut okm = [0u8; 42];
HkdfSha256.derive(b"input key material", b"salt", b"context info", &mut okm)?;

// Convenience: derive an owned Vec of `len` bytes.
let key = hkdf_sha256_derive_to_vec(b"ikm", b"salt", b"info", 32)?;
assert_eq!(key.len(), 32);
# Ok::<(), CryptoError>(())
```

### Password hashing with Argon2id

```rust,ignore
use oxicrypto_kdf::{Argon2idHasher, Argon2Params, verify_password};
use oxicrypto_core::PasswordHash;

let hasher = Argon2idHasher::new(Argon2Params::interactive());
let salt = oxicrypto_kdf::generate_salt_16()?;
let mut hash = [0u8; 32];
hasher.hash_password(b"correct horse", &salt, &hasher.params, &mut hash)?;

// Constant-time verification (returns Err(InvalidTag) on mismatch).
verify_password(&hasher, b"correct horse", &salt, &hash)?;
```

## API Overview

### HKDF — RFC 5869 (`oxicrypto_core::Kdf` + free functions)

| Item | Description |
|------|-------------|
| `HkdfSha256`, `HkdfSha384`, `HkdfSha512` | `Kdf` implementations (full extract+expand) |
| `hkdf_sha256_extract(salt, ikm) -> [u8; 32]` (and `_sha384 -> [u8;48]`, `_sha512 -> [u8;64]`) | Extract phase only (RFC 5869 §2.2) |
| `hkdf_sha256_expand(prk, info, out)` (and `_sha384`, `_sha512`) | Expand phase only (RFC 5869 §2.3) |
| `hkdf_sha256_derive_to_vec(ikm, salt, info, len)` (and `_sha384`, `_sha512`) | Allocating full-derive convenience returning `Vec<u8>` |

### HKDF-Expand-Label — TLS 1.3 / QUIC (`hkdf_label` module)

Wraps bare HKDF-Expand with the structured `HkdfLabel` info parameter (RFC 8446 §7.1, reused by RFC 9001). The `"tls13 "` prefix is prepended to the supplied label inside the structure.

| Function | Description |
|----------|-------------|
| `hkdf_expand_label_sha256(prk, label, context, out)` | HKDF-Expand-Label over SHA-256 |
| `hkdf_expand_label_sha384(prk, label, context, out)` | HKDF-Expand-Label over SHA-384 |

### KBKDF counter mode — NIST SP 800-108 (`kbkdf` module)

| Function | Description |
|----------|-------------|
| `kbkdf_counter_hmac_sha256(...)`, `kbkdf_counter_hmac_sha384(...)`, `kbkdf_counter_hmac_sha512(...)` | HMAC-based KBKDF counter mode (§4.1) |
| `kbkdf_counter_hmac_sha256_secret(...)` | As above, returning derived bytes in a zeroizing `SecretVec` |

> The module documents that no independently-verified external HMAC-SHA-2 KAT is bundled (CAVP vectors use CMAC-AES); the input encoding matches SP 800-108 §4.1.

### PBKDF2 — RFC 8018 (`pbkdf2_kdf` module)

| Item | Description |
|------|-------------|
| `pbkdf2_sha256(...)`, `pbkdf2_sha512(...)` | One-shot derive functions |
| `Pbkdf2Sha256Hasher`, `Pbkdf2Sha512Hasher` | `PasswordHash` + `Kdf` implementations; presets `interactive()`, `moderate()`, `sensitive()`, plus `new(iterations)` and `params()` |
| `Pbkdf2Params` | `PasswordHashParams` (time cost = iterations) |
| `PBKDF2_SHA256_MIN_ITERATIONS = 600_000`, `PBKDF2_SHA512_MIN_ITERATIONS = 210_000` | OWASP 2023 minimums |

### Argon2 — RFC 9106 (`argon2_kdf` module)

| Item | Description |
|------|-------------|
| `argon2id_derive(...)`, `argon2d_derive(...)`, `argon2i_derive(...)` | One-shot derive functions (salt must be ≥ 8 bytes; output 1–64 bytes) |
| `Argon2idHasher` | `PasswordHash` implementation (public `params` field); presets `interactive()`, `moderate()`, `sensitive()`, plus `new(params)` |
| `Argon2Params` | Cost parameters; `validate()` enforces OWASP 2023 / RFC 9106 minimums; presets `interactive()`/`moderate()`/`sensitive()`; `TEST_PARAMS` (intentionally below the minimum, for tests only) |
| `argon2id_to_phc_string(...)`, `argon2id_verify_phc(phc, password)` | PHC-string encoding / verification |

### scrypt — RFC 7914 (`scrypt_kdf` module)

| Item | Description |
|------|-------------|
| `scrypt_derive(...)` | One-shot derive function |
| `ScryptHasher` | `PasswordHash` implementation; `new(params)` (checked), `new_checked(params)`, presets `interactive()`/`moderate()`/`sensitive()` |
| `ScryptParams` | Explicit `new(log_n, r, p)` cost parameters; presets |

### Balloon — ASIACRYPT 2016 (`balloon` module)

Pure-Rust single-buffer Balloon (Algorithm 1, Boneh-Corrigan-Gibbs-Schechter) over SHA-256 / SHA-512; verified against the reference vectors.

| Item | Description |
|------|-------------|
| `balloon_sha256(...)`, `balloon_sha512(...)` | One-shot derive functions |
| `balloon_sha256_secret(...)`, `balloon_sha512_secret(...)` | As above, returning a zeroizing `SecretVec` |
| `BalloonHasher` | `PasswordHash` implementation; `new_sha256(params)` / `new_sha512(params)` |
| `BalloonParams` | `new(space_cost, time_cost)`; `PasswordHashParams` impl |
| `BalloonVariant` | `Sha256` / `Sha512` |
| `BALLOON_DELTA = 3` | Pseudo-random dependencies per block |

### Runtime key stretching (`stretcher` module)

| Item | Description |
|------|-------------|
| `KeyStretcher` | Object-safe trait (`Box<dyn KeyStretcher>`); `stretch(password, salt) -> SecretVec` |
| `Stretcher` | Built-in implementation; `new(params)`, `params()` |
| `StretchParams` | Enum delegating to Argon2id / scrypt / PBKDF2-SHA-256 / Balloon-SHA-256; `output_len()`, `name()` |
| `Argon2idStretchParams`, `ScryptStretchParams`, `Pbkdf2StretchParams`, `BalloonStretchParams` | Per-algorithm parameter structs |

### Salt generation & verification helpers

| Function | Description |
|----------|-------------|
| `generate_salt_16() -> Result<[u8; 16], CryptoError>` | 16-byte CSPRNG salt (PBKDF2/Argon2id minimum) |
| `generate_salt_32() -> Result<[u8; 32], CryptoError>` | 32-byte CSPRNG salt (Argon2id/scrypt) |
| `verify_password(hasher, password, salt, expected)` | Re-hash and compare in constant time; `Err(InvalidTag)` on mismatch, `Err(BadInput)` if `expected` is empty |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | off | Forwards to `sha2/alloc` and `oxicrypto-core/std`. |

## Cross-references

- [`oxicrypto-core`](https://crates.io/crates/oxicrypto-core) — defines the `Kdf`, `PasswordHash`, `PasswordHashParams`, `SecretVec`, and `CryptoError` types used here.
- [`oxicrypto-rand`](https://crates.io/crates/oxicrypto-rand) — the CSPRNG backing `generate_salt_16` / `generate_salt_32`.
- [`oxicrypto-hash`](https://crates.io/crates/oxicrypto-hash) — the hash functions underlying HKDF, PBKDF2, and Balloon.
- [`oxicrypto`](https://crates.io/crates/oxicrypto) — the top-level façade for the OxiCrypto stack.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
