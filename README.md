# OxiCrypto

**Version 0.1.1 — 2026-06-04**

OxiCrypto is the COOLJAPAN-blessed Pure Rust cryptographic primitives layer:
hashes, MACs, AEADs, signatures, key exchange, KDFs, password hashing, PRNGs,
and post-quantum primitives. It is the foundation that **OxiTLS**, **OxiStore**,
**OxiSQL**, **oxify**, **oxionnx** (model signing), and **oxirag** (content
addressing) depend on.

The non-negotiable goal: a fresh `rust:slim` container running
`cargo build --no-default-features` succeeds with zero `apt-get install` and no
C toolchain.

## Status: v0.1.1 — All milestones M0–M5 complete

| Milestone | Description | Status |
|-----------|-------------|--------|
| M0 | Workspace skeleton, trait surface, deny.toml, FFI audit | Done |
| M1 | SHA-2/3, BLAKE3, AES-GCM, ChaCha20-Poly1305, Ed25519, X25519, HMAC, HKDF, CSPRNG | Done |
| M2 | RSA, ECDSA P-256/384/521, Ed448, PBKDF2, Argon2id, scrypt, AES-GCM-SIV, XChaCha20 | Done |
| M3 | ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204) | Done |
| M4 | cpufeatures SIMD dispatch, criterion benchmarks vs. ring/aws-lc-rs | Done |
| M5 | Bounded FFI: aws-lc adapter (FIPS), PKCS#11 HSM adapter | Done |
| Post-M5 | BLAKE2, XOFs, KMAC, HPKE, SLH-DSA, hybrid KEMs, BIP-340, FROST | Done |

**Test coverage:** 1558 tests pass (25 slow SLH-DSA `-s` parameter tests marked `#[ignore]`).
**SLOC:** ~31,500 lines of Rust across 14 crates (160 files).

## Workspace Crates

| Crate | Description |
|-------|-------------|
| [`oxicrypto-core`](crates/oxicrypto-core) | Trait surface: `Hasher`, `Mac`, `Aead`, `Signer`, `Verifier`, `Kex`, `Kem`, `Kdf`, `PasswordHasher`, `CryptoRng` |
| [`oxicrypto-hash`](crates/oxicrypto-hash) | SHA-2, SHA-3, BLAKE2b/s, BLAKE3, SHAKE/cSHAKE/KMAC XOFs, ParallelHash, TupleHash |
| [`oxicrypto-aead`](crates/oxicrypto-aead) | AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV, XChaCha20-Poly1305, AES-CCM, OCB3, Deoxys-II, HPKE (RFC 9180) |
| [`oxicrypto-cipher`](crates/oxicrypto-cipher) | AES single-block ECB, ChaCha20 keystream (QUIC header protection) |
| [`oxicrypto-mac`](crates/oxicrypto-mac) | HMAC-SHA-{256,384,512}, HMAC-SHA3-{256,512}, CMAC-AES, Poly1305, KMAC128/256 |
| [`oxicrypto-sig`](crates/oxicrypto-sig) | Ed25519, Ed448, ECDSA (P-256/384/521), BIP-340 Schnorr, RSA PKCS#1v15/PSS, FROST (RFC 9591) |
| [`oxicrypto-kex`](crates/oxicrypto-kex) | X25519, X448, ECDH (P-256/384/521) |
| [`oxicrypto-kdf`](crates/oxicrypto-kdf) | HKDF, PBKDF2, Argon2id, scrypt, Balloon, KBKDF |
| [`oxicrypto-rand`](crates/oxicrypto-rand) | ChaCha20 CSPRNG, fork-safe reseeding RNG, thread-local RNG |
| [`oxicrypto-pq`](crates/oxicrypto-pq) | ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), hybrid X-Wing/ML-KEM+P-384 |
| [`oxicrypto`](crates/oxicrypto) | Unified façade re-exporting all sub-crates |
| [`oxicrypto-bench`](crates/oxicrypto-bench) | Criterion benchmarks vs. `ring` and `aws-lc-rs` (dev-only) |
| [`oxicrypto-adapter-aws-lc`](crates/oxicrypto-adapter-aws-lc) | Bounded FFI: FIPS-leaning primitives via `aws-lc-rs` (feature-gated) |
| [`oxicrypto-adapter-pkcs11`](crates/oxicrypto-adapter-pkcs11) | Bounded FFI: HSM sign/decrypt via `cryptoki` (feature-gated) |

## Quick Start

```toml
[dependencies]
oxicrypto = "0.1.1"

# Post-quantum primitives (off by default):
oxicrypto = { version = "0.1.1", features = ["pq-preview"] }
```

### Hash

```rust
use oxicrypto::hash::{sha256, sha3_256, blake3};

let digest = sha256(b"hello world");
let digest = sha3_256(b"hello world");
let digest = blake3(b"hello world");
```

### AEAD

```rust
use oxicrypto::aead::{AesGcm256, CryptoRng};
use oxicrypto_rand::OsRng;

let key = AesGcm256::generate_key(&mut OsRng);
let nonce = AesGcm256::generate_nonce(&mut OsRng);
let ct = AesGcm256::encrypt(&key, &nonce, b"plaintext", b"aad")?;
let pt = AesGcm256::decrypt(&key, &nonce, &ct, b"aad")?;
```

### Signatures

```rust
use oxicrypto::sig::{Ed25519, Signer, Verifier};
use oxicrypto_rand::OsRng;

let (sk, vk) = Ed25519::generate(&mut OsRng);
let sig = sk.sign(b"message")?;
vk.verify(b"message", &sig)?;
```

### Post-quantum KEM

```rust
use oxicrypto::pq::mlkem::{MlKem768, SharedKey};
use oxicrypto_rand::OsRng;

let (dk, ek) = MlKem768::generate(&mut OsRng);
let (ct, ss_sender) = ek.encapsulate(&mut OsRng);
let ss_receiver = dk.decapsulate(&ct)?;
assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
```

## Pure Rust Guarantee

The default feature set pulls **zero** `*-sys` crates. Verify with:

```sh
cargo tree -p oxicrypto --edges normal 2>&1 | grep -E '\-sys'
# Should print nothing
```

C/C++ dependencies (`aws-lc-sys`, `cryptoki-sys`) appear only on feature-gated
adapter edges and never in the default closure.

## Feature Flags

| Feature | Description |
|---------|-------------|
| `pq-preview` | Enable post-quantum primitives (ML-KEM, ML-DSA, SLH-DSA, hybrid KEMs) |
| `simd` | Runtime CPU feature detection (AES-NI, SHA-NI, AVX2) via `cpufeatures` |
| `aws-lc` | Bounded FFI: use `aws-lc-rs` as backend for selected primitives |
| `pkcs11` | Bounded FFI: use PKCS#11 HSM as backend |

## Replaces (FFI being eliminated)

- `ring`
- `aws-lc-rs`
- `openssl`
- `mbedtls`
- `boringssl`

…as direct crypto primitive providers in the COOLJAPAN ecosystem.

## MSRV

Rust **1.89** (edition 2021).

## Inter-Oxi Dependencies

- **Depends on:** nothing. OxiCrypto is the foundation layer.
- **Depended on by:** OxiTLS, OxiStore, OxiSQL, oxify, oxionnx, oxirag.

## License

Apache-2.0 — Copyright COOLJAPAN OU (Team Kitasan)
