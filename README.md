# OxiCrypto

**Version 0.2.1 — Released 2026-07-17**

OxiCrypto is the COOLJAPAN-blessed Pure Rust cryptographic primitives layer:
hashes, MACs, AEADs, signatures, key exchange, KDFs, password hashing, PRNGs,
and post-quantum primitives. It is the foundation that **OxiTLS**, **OxiStore**,
**OxiSQL**, **oxify**, **oxionnx** (model signing), and **oxirag** (content
addressing) depend on.

The non-negotiable goal: a fresh `rust:slim` container running
`cargo build --no-default-features` succeeds with zero `apt-get install` and no
C toolchain.

## Status: v0.2.1 — All milestones M0–M5 complete

| Milestone | Description | Status |
|-----------|-------------|--------|
| M0 | Workspace skeleton, trait surface, deny.toml, FFI audit | Done |
| M1 | SHA-2/3, BLAKE3, AES-GCM, ChaCha20-Poly1305, Ed25519, X25519, HMAC, HKDF, CSPRNG | Done |
| M2 | RSA, ECDSA P-256/384/521, Ed448, PBKDF2, Argon2id, scrypt, AES-GCM-SIV, XChaCha20 | Done |
| M3 | ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204) | Done |
| M4 | cpufeatures SIMD dispatch, criterion benchmarks vs. ring/aws-lc-rs | Done |
| M5 | Bounded FFI: aws-lc adapter (FIPS), PKCS#11 HSM adapter | Done |
| Post-M5 | BLAKE2, XOFs, KMAC, HPKE, SLH-DSA, hybrid KEMs, BIP-340, FROST | Done |

**Test coverage:** 1736 tests pass with `cargo nextest run --all-features --workspace` (1612 with default features), plus 28 passing doctests (9 `#[ignore]`d). 32 tests are `#[ignore]`-gated as slow or environment-dependent: 18 SLH-DSA `-s`-parameter variants + 2 ML-KEM-1024 property tests (`oxicrypto-pq`), 7 SoftHSM-hardware-dependent integration tests (`oxicrypto-adapter-pkcs11`), 4 RSA-2048-keygen-latency tests (`oxicrypto-sig`), and 1 large-vector (~1 GiB) scrypt KAT (`oxicrypto-kdf`). Includes RFC 8032 §7.4 KATs for Ed448ph and Ed448ctx.
**SLOC:** ~48,023 lines of Rust across 14 crates (220 files).

## Workspace Crates

Status: `Stable` = feature-complete and well-tested with no functional changes
across several releases; `Alpha` = functional, well-tested, but pre-1.0 and
still gaining API surface. Test counts are from `cargo nextest run -p <crate>
--all-features` (2026-07-17).

| Crate | Status | Tests | Description |
|-------|--------|-------|-------------|
| [`oxicrypto-core`](crates/oxicrypto-core) | Alpha | 66 passing | Trait surface: `Hasher`, `Mac`, `Aead`, `Signer`, `Verifier`, `Kex`, `Kem`, `Kdf`, `PasswordHasher`, `CryptoRng` |
| [`oxicrypto-hash`](crates/oxicrypto-hash) | Alpha | 252 passing | SHA-2, SHA-3, BLAKE2b/s, BLAKE3, SHAKE/cSHAKE/KMAC XOFs, ParallelHash, TupleHash |
| [`oxicrypto-aead`](crates/oxicrypto-aead) | Alpha | 183 passing | AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV, XChaCha20-Poly1305, AES-CCM, OCB3, Deoxys-II, HPKE (RFC 9180) |
| [`oxicrypto-cipher`](crates/oxicrypto-cipher) | Stable | 6 passing | AES single-block ECB, ChaCha20 keystream (QUIC header protection) |
| [`oxicrypto-mac`](crates/oxicrypto-mac) | Alpha | 184 passing | HMAC-SHA-{256,384,512}, HMAC-SHA3-{256,512}, CMAC-AES, Poly1305, KMAC128/256 |
| [`oxicrypto-sig`](crates/oxicrypto-sig) | Alpha | 226 passing, 4 skipped | Ed25519, Ed448, ECDSA (P-256/384/521), BIP-340 Schnorr, RSA PKCS#1v15/PSS, FROST (RFC 9591) |
| [`oxicrypto-kex`](crates/oxicrypto-kex) | Alpha | 124 passing | X25519, X448, ECDH (P-256/384/521) |
| [`oxicrypto-kdf`](crates/oxicrypto-kdf) | Alpha | 229 passing, 1 skipped | HKDF, PBKDF2, Argon2id, scrypt, Balloon, KBKDF |
| [`oxicrypto-rand`](crates/oxicrypto-rand) | Stable | 79 passing | ChaCha20 CSPRNG, fork-safe reseeding RNG, thread-local RNG |
| [`oxicrypto-pq`](crates/oxicrypto-pq) | Alpha (preview) | 176 passing, 20 skipped | ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), hybrid X-Wing/ML-KEM+P-384 |
| [`oxicrypto`](crates/oxicrypto) | Alpha | 116 passing | Unified façade re-exporting all sub-crates |
| [`oxicrypto-bench`](crates/oxicrypto-bench) | Alpha (dev-only) | 22 passing | Criterion benchmarks vs. `ring` and `aws-lc-rs` (dev-only, `publish = false`) |
| [`oxicrypto-adapter-aws-lc`](crates/oxicrypto-adapter-aws-lc) | Alpha (opt-in, C-FFI) | 45 passing | Bounded FFI: FIPS-leaning primitives via `aws-lc-rs` (feature-gated, off by default) |
| [`oxicrypto-adapter-pkcs11`](crates/oxicrypto-adapter-pkcs11) | Alpha (opt-in, C-FFI) | 28 passing, 7 skipped | Bounded FFI: HSM sign/decrypt via `cryptoki` (feature-gated, off by default) |

## Quick Start

```toml
[dependencies]
oxicrypto = "0.2.1"

# Post-quantum primitives (off by default):
oxicrypto = { version = "0.2.1", features = ["pq-preview"] }
```

### Hash

```rust
use oxicrypto::{blake3, sha256, sha512};

let digest = sha256(b"hello world");
let digest = sha512(b"hello world");
let digest = blake3(b"hello world");
```

Other algorithms (SHA-3, BLAKE2, SHA-512/256, …) go through the `HashAlgo`
selector and `hash_impl()` factory, which returns a boxed `Hash` trait object:

```rust
use oxicrypto::{hash_impl, HashAlgo};

let hasher = hash_impl(HashAlgo::Sha3_256);
let mut out = vec![0u8; hasher.output_len()];
hasher.hash(b"hello world", &mut out)?;
```

### AEAD

```rust
use oxicrypto::{aead_impl, random_bytes, random_nonce, AeadAlgo};

let aead = aead_impl(AeadAlgo::Aes256Gcm);
let key = random_bytes(32)?;       // 32 bytes for AES-256-GCM
let nonce = random_nonce::<12>()?; // 12-byte nonce; must never repeat for a given key

let ct = aead.seal_to_vec(&key, &nonce, b"aad", b"plaintext")?;
let pt = aead.open_to_vec(&key, &nonce, b"aad", &ct)?;
assert_eq!(pt, b"plaintext");
```

### Signatures

```rust
use oxicrypto::{signer_impl, verifier_impl, SigAlgo};

// Keygen is not part of the facade (Ed25519 needs a `rand_core::TryCryptoRng`
// source); `seed` / `verifying_key_bytes` come from `ed25519-dalek` or another
// keygen path -- see `crates/oxicrypto/examples/sign.rs` for the full example.
let signer = signer_impl(SigAlgo::Ed25519);
let mut signature = vec![0u8; signer.signature_len()];
let sig_len = signer.sign(&seed, b"message", &mut signature)?;

let verifier = verifier_impl(SigAlgo::Ed25519);
verifier.verify(&verifying_key_bytes, b"message", &signature[..sig_len])?;
```

### Post-quantum KEM

```rust
use oxicrypto::pq::{DecapKey768, EncapKey768};
use oxicrypto::{pq_kem_generate, PqKemAlgo};

let (decap_bytes, encap_bytes) = pq_kem_generate(PqKemAlgo::MlKem768)?;
let encap_key = EncapKey768::from_bytes(&encap_bytes)?;
let decap_key = DecapKey768::from_bytes(&decap_bytes)?;

// rng must impl `rand_core::TryCryptoRng`, e.g. a `rand_chacha::ChaCha20Rng`
// seeded from `getrandom` -- see `crates/oxicrypto/examples/pq_kem.rs`.
let (ct, ss_sender) = encap_key.encapsulate(&mut rng)?;
let ss_receiver = decap_key.decapsulate(&ct)?;
assert_eq!(ss_sender.as_slice(), ss_receiver.as_slice());
```

## Pure Rust Guarantee

The default feature set pulls **zero** `*-sys` crates. Verify with:

```sh
cargo tree -p oxicrypto --edges normal 2>&1 | grep -E '\-sys'
# Should print nothing
```

C/C++ dependencies (`aws-lc-sys`, `cryptoki-sys`) appear only on feature-gated
adapter edges and never in the default closure.

### `core`-only builds (new in 0.2.1)

`oxicrypto-core` and `oxicrypto-hash` now ship a default-on `alloc` Cargo
feature. Building either crate with `--no-default-features` links only
`core` — no heap allocator required — while keeping an alloc-free API surface
available (`SecretKey<N>`, `Hash::hash` / `hash_to_array::<N>()`, the
constant-time utilities, `CryptoError`, `AlgorithmId`). This supersedes
`oxicrypto-hash`'s old `no_std` feature, which was a documentation-only
signal with no link-time effect. See `crates/oxicrypto-hash/tests/no_alloc.rs`
for a worked example over SHA-256, SHA-512, and BLAKE3.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `pure` | on | Enables all pure-Rust sub-crates (hash, aead, mac, sig, kex, kdf, rand) |
| `pq-preview` | off | Post-quantum primitives (ML-KEM, ML-DSA, SLH-DSA, hybrid KEMs) |
| `simd` | off | Explicit runtime CPU feature detection (AES-NI, SHA-NI, AVX2, NEON) via `cpufeatures`, exposed as `oxicrypto::simd::cpu_info()` |
| `std` | off | Propagates the `std` feature to sub-crates (e.g. thread-local RNG) |

From **0.2.0**, the `aws-lc` and `pkcs11` features are no longer part of the `oxicrypto` facade. Applications requiring FIPS-validated (`aws-lc-rs`) or HSM-backed (`cryptoki`) primitives must add the adapter crates directly:

```toml
# FIPS / aws-lc-rs backend (C/FFI, not Pure Rust)
oxicrypto-adapter-aws-lc = { version = "0.2.1", features = ["aws-lc"] }

# PKCS#11 HSM backend (C/FFI, not Pure Rust)
oxicrypto-adapter-pkcs11 = { version = "0.2.1", features = ["pkcs11"] }
```

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
