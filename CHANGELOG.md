# Changelog

All notable changes to OxiCrypto are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-06-01

Initial public release of the OxiCrypto Pure Rust cryptographic primitive
workspace. All milestones M0–M5 are complete.

### Crates

| Crate | Description |
|---|---|
| `oxicrypto-core` | Trait surface: `Hasher`, `Mac`, `Aead`, `Signer`, `Verifier`, `Kex`, `Kem`, `Kdf`, `PasswordHasher`, `CryptoRng` |
| `oxicrypto-hash` | SHA-2, SHA-3, BLAKE2, BLAKE3, SHAKE/cSHAKE/KMAC XOFs, ParallelHash, TupleHash |
| `oxicrypto-aead` | AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV, XChaCha20-Poly1305, AES-CCM, OCB3, Deoxys-II, HPKE (RFC 9180) |
| `oxicrypto-cipher` | AES single-block ECB, ChaCha20 keystream (QUIC header protection) |
| `oxicrypto-mac` | HMAC-SHA-{256,384,512}, HMAC-SHA3-{256,512}, CMAC-AES, Poly1305, KMAC128/256 |
| `oxicrypto-sig` | Ed25519, Ed448, ECDSA (P-256/384/521), BIP-340 Schnorr (secp256k1), RSA PKCS#1v15/PSS, FROST threshold (RFC 9591) |
| `oxicrypto-kex` | X25519, X448, ECDH (P-256/384/521), HPKE key exchange |
| `oxicrypto-kdf` | HKDF, PBKDF2 (SHA-256/512), Argon2id, scrypt, Balloon, KBKDF |
| `oxicrypto-rand` | ChaCha20 CSPRNG, fork-safe reseeding RNG, thread-local RNG |
| `oxicrypto-pq` | ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204), SLH-DSA all 12 param sets (FIPS 205), hybrid X-Wing/ML-KEM+P-384 |
| `oxicrypto` | Unified façade re-exporting all sub-crates; `pq-preview` feature for post-quantum primitives |
| `oxicrypto-bench` | Criterion benchmarks vs. `ring` and `aws-lc-rs` (dev-only) |
| `oxicrypto-adapter-aws-lc` | Bounded FFI adapter: FIPS-leaning AES-GCM/ChaCha20/Ed25519/ECDSA via `aws-lc-rs` (off by default) |
| `oxicrypto-adapter-pkcs11` | Bounded FFI adapter: HSM sign/decrypt via `cryptoki` (off by default) |

### Added

**M0 — Workspace skeleton (2026-05-24)**
- Workspace Cargo.toml with `resolver = "2"`, MSRV 1.89, edition 2021
- `oxicrypto-core` trait surface: `CryptoError`, `Hasher`, `Mac`, `Aead`, `Signer`,
  `Verifier`, `Kex`, `Kem`, `Kdf`, `PasswordHasher`, `CryptoRng`
- `SecretKey<N>`, `SecretVec` with `Zeroize + ZeroizeOnDrop`
- `deny.toml` — cargo-deny policy (zero `*-sys` on default closure)
- `Dockerfile.ffi-audit` — FFI audit container

**M1 — Core symmetric + asymmetric primitives (2026-05-24)**
- SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE3 hashing
- AES-128/256-GCM, ChaCha20-Poly1305 AEAD
- Ed25519 sign/verify (dalek ecosystem)
- X25519 key exchange
- HMAC-SHA-256, HMAC-SHA-512
- HKDF-SHA-256, HKDF-SHA-512
- ChaCha20 CSPRNG seeded via `getrandom`
- 45 tests, zero `*-sys` in default closure

**M2 — Full RustCrypto coverage parity (2026-05-25)**
- RSA PKCS#1v15 and PSS signatures (SHA-256/384/512)
- ECDSA P-256, P-384, P-521
- Ed448 sign/verify (goldilocks curve)
- PBKDF2 (SHA-256/512), Argon2id, scrypt
- AES-GCM-SIV, XChaCha20-Poly1305 AEAD
- 81 tests pass

**M3 — Post-quantum preview (2026-05-25)**
- `oxicrypto-pq` sub-crate: ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204)
- `pq-preview` feature on `oxicrypto` façade
- KAT vectors from NIST ACVP

**M4 — SIMD dispatch + criterion benchmarks (2026-05-25)**
- `simd` feature: `cpufeatures` runtime detection of AES-NI, SHA-NI, AVX2
- `oxicrypto-bench`: criterion groups for AES-GCM, ChaCha20-Poly1305,
  SHA-256/512, Ed25519, X25519 vs. `ring` and `aws-lc-rs`
- `ring` and `aws-lc-rs` appear only as bench dev-dependencies (never on default closure)

**M5 — Bounded FFI adapters (2026-05-25)**
- `oxicrypto-adapter-aws-lc`: AES-128/256-GCM, ChaCha20-Poly1305, Ed25519,
  ECDSA P-256/P-384, SHA-256/384/512 via `aws-lc-rs 1.17.0`; off by default
- `oxicrypto-adapter-pkcs11`: `Pkcs11Provider` (C_Initialize, C_OpenSession,
  C_Sign, C_Decrypt) via `cryptoki 0.12.0`; off by default
- KAT parity: aws-lc adapter produces byte-identical outputs to RustCrypto default

**Post-M5 extensions (2026-05-25 – 2026-05-31)**
- BLAKE2b/BLAKE2s keyed-hash, SHAKE128/256 XOFs, cSHAKE, KMAC128/256, TupleHash,
  ParallelHash (SP 800-185)
- CMAC-AES (RFC 4493), Poly1305 standalone
- AES-CCM, AES-OCB3, Deoxys-II AEAD
- HPKE RFC 9180 (Base, PSK, Auth, AuthPSK modes; X25519+SHA-256+AES-128-GCM,
  X25519+SHA-256+ChaCha20-Poly1305, P-256+SHA-256+AES-128-GCM)
- SLH-DSA all 12 parameter sets (SHA2/SHAKE × 128/192/256 × s/f) — FIPS 205
- Hybrid KEMs: X-Wing (ML-KEM-768 + X25519), ML-KEM-768 + P-384
- BIP-340 Schnorr signatures (secp256k1/k256)
- FROST Ed25519 threshold signatures (RFC 9591)
- Balloon password hashing, KBKDF (SP 800-108)
- X448 key exchange
- 1116 tests pass; 24 slow SLH-DSA `-s` parameter tests marked `#[ignore]`

### Security

All algorithms are implemented via reviewed RustCrypto crates pinned at exact
versions in `Cargo.toml`. No custom cryptographic primitives are written.
The default feature set is 100% Pure Rust with zero `*-sys` crates.
Bounded FFI adapters (aws-lc, pkcs11) are strictly feature-gated.

[0.1.0]: https://github.com/cool-japan/oxicrypto/releases/tag/v0.1.0
