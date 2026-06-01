# oxicrypto-pq — Pure-Rust post-quantum cryptography for OxiCrypto

[![Crates.io](https://img.shields.io/crates/v/oxicrypto-pq.svg)](https://crates.io/crates/oxicrypto-pq)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxicrypto-pq` is the post-quantum layer of the OxiCrypto stack. It implements the NIST-standardized PQC primitives — **ML-KEM** (FIPS 203, key encapsulation), **ML-DSA** (FIPS 204, lattice signatures), and **SLH-DSA** (FIPS 205, hash-based signatures) — plus two **hybrid** KEMs that combine ML-KEM with classical ECDH for defence-in-depth during the migration period.

The crate is Pure Rust (`#![forbid(unsafe_code)]`), building on the RustCrypto `ml-kem`, `ml-dsa`, and `slh-dsa` crates, with `sha3` for SHAKE/SHA-3, `x25519-dalek` for the X-Wing hybrid, and `zeroize` for secret hygiene. ML-KEM and ML-DSA expose both random (RNG-driven) and deterministic (KAT) key generation; the deterministic helpers are gated behind the `hazmat-test-vectors` feature.

## Installation

```toml
[dependencies]
oxicrypto-pq = "0.1.0"

# Enable deterministic keygen/encap helpers for known-answer tests:
oxicrypto-pq = { version = "0.1.0", features = ["hazmat-test-vectors"] }
```

## Quick Start

ML-KEM-768 encapsulate / decapsulate:

```rust
use oxicrypto_pq::MlKem768;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn main() -> Result<(), oxicrypto_core::CryptoError> {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);

    let (decap_key, encap_key) = MlKem768::generate(&mut rng);
    let (ciphertext, shared_enc) = encap_key.encapsulate(&mut rng)?;
    let shared_dec = decap_key.decapsulate(&ciphertext)?;

    assert_eq!(shared_enc.as_bytes(), shared_dec.as_bytes());
    Ok(())
}
```

ML-DSA-65 sign / verify:

```rust
use oxicrypto_pq::MlDsa65;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn main() -> Result<(), oxicrypto_core::CryptoError> {
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);

    let (signing_key, verifying_key) = MlDsa65::generate(&mut rng);
    let sig = signing_key.sign(b"message")?;
    verifying_key.verify(b"message", &sig)?;
    Ok(())
}
```

X-Wing hybrid KEM (ML-KEM-768 + X25519), via the `oxicrypto_core::Kem` trait:

```rust
use oxicrypto_core::Kem;
use oxicrypto_pq::XWing768;

fn main() -> Result<(), oxicrypto_core::CryptoError> {
    let (dk, ek) = XWing768::kem_generate()?;
    let (ct, ss_enc) = XWing768::kem_encapsulate(&ek)?;
    let ss_dec = XWing768::kem_decapsulate(&dk, &ct)?;

    assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    Ok(())
}
```

## API Overview

### ML-KEM — FIPS 203 (`mlkem`)

Each parameter set is a unit struct with a `generate(rng) -> (DecapKey, EncapKey)` constructor; encapsulation/decapsulation are methods on the key types. Key/ciphertext types expose `to_bytes` / `from_bytes`.

| Type | Security category | Encap key | Decap key | Ciphertext | Shared secret |
|------|-------------------|-----------|-----------|------------|---------------|
| `MlKem512` | 1 | 800 B | 1632 B | 768 B | 32 B |
| `MlKem768` | 3 | 1184 B | 2400 B | 1088 B | 32 B |
| `MlKem1024` | 5 | 1568 B | 3168 B | 1568 B | 32 B |

Key types: `EncapKey512/768/1024`, `DecapKey512/768/1024`, `Ciphertext512/768/1024`, and the 32-byte `SharedSecret` (`as_bytes`). `EncapKey::encapsulate(rng) -> (Ciphertext, SharedSecret)`; `DecapKey::decapsulate(ct) -> SharedSecret`. Size constants are available as associated consts (e.g. `MlKem768::ENCAP_KEY_LEN`). Each parameter set also exposes the byte-length consts `ENCAP_KEY_LEN`, `DECAP_KEY_LEN`, `CIPHERTEXT_LEN`, `SHARED_SECRET_LEN`.

> `SharedKeyPq` is re-exported but **deprecated** in favour of `SharedSecret`.

### ML-DSA — FIPS 204 (`mldsa`)

Each parameter set is a unit struct with `generate(rng) -> (SigningKey, VerifyingKey)`. Signing/verification are methods; signature and key types expose `to_bytes` / `from_bytes`.

| Type | Signing key | Verifying key | Signature |
|------|-------------|---------------|-----------|
| `MlDsa44` | 2560 B | 1312 B | 2420 B |
| `MlDsa65` | 4032 B | 1952 B | 3309 B |
| `MlDsa87` | 4896 B | 2592 B | 4627 B |

Key/signature types: `SigningKey44/65/87`, `VerifyingKey44/65/87`, `Signature44/65/87`. `SigningKey::sign(msg) -> Signature`; `VerifyingKey::verify(msg, &sig)`. Context-string variants are provided as free functions: `mldsa44_sign_ctx` / `mldsa44_verify_ctx` (and the `65` / `87` equivalents).

### SLH-DSA — FIPS 205 (`slh_dsa`)

Hash-based signatures in SHA-2 and SHAKE families, each in a small (`s`) and fast (`f`) tradeoff. Each is a unit struct with `generate(rng) -> (SigningKey, VerifyingKey)`; signing/verification are methods, and key/signature types expose `to_bytes` / `from_bytes`.

| Parameter set struct | Family / category | Signature struct |
|----------------------|-------------------|------------------|
| `SlhDsaSha2_128s` / `SlhDsaSha2_128f` | SHA-2, cat. 1 | `SlhDsaSignature128s` / `…128f` |
| `SlhDsaSha2_192s` / `SlhDsaSha2_192f` | SHA-2, cat. 3 | `SlhDsaSignature192s` / `…192f` |
| `SlhDsaSha2_256s` / `SlhDsaSha2_256f` | SHA-2, cat. 5 | `SlhDsaSignature256s` / `…256f` |
| `SlhDsaShake128s` / `SlhDsaShake128f` | SHAKE, cat. 1 | `SlhDsaSignatureShake128s` / `…128f` |
| `SlhDsaShake256s` / `SlhDsaShake256f` | SHAKE, cat. 5 | `SlhDsaSignatureShake256s` / `…256f` |

Signing-key types `SlhDsaSigningKey*` and verifying-key types `SlhDsaVerifyingKey*` are exported for every set, along with byte-length constants `SLH_DSA_<SET>_SK_LEN`, `SLH_DSA_<SET>_VK_LEN`, and `SLH_DSA_<SET>_SIG_LEN` (e.g. `SLH_DSA_SHA2_128S_SIG_LEN`).

### Hybrid KEMs (`hybrid`)

Both implement the `oxicrypto_core::Kem` trait (`kem_generate`, `kem_encapsulate`, `kem_decapsulate`), seeding their own RNG internally.

| Type | Composition | KDF / combiner |
|------|-------------|----------------|
| `XWing768` | ML-KEM-768 + X25519 | SHA3-256 (draft-connolly-cfrg-xwing-kem-04) |
| `HybridKem1024P384` | ML-KEM-1024 + ECDH P-384 | HKDF-SHA-384 (CNSA 2.0 / ounsworth-style) |

Associated key/ciphertext types: `XWing768EncapKey`, `XWing768DecapKey`, `XWing768Ciphertext`, `XWingSharedSecret` (and the `HybridKem1024P384*` / `HybridP384SharedSecret` equivalents). Shared secrets expose `as_slice()`.

The module also provides TLS 1.3 `key_share` wire helpers:

| Item | Description |
|------|-------------|
| `PqGroup` | Named group enum: `MlKem768` (`0x0201`), `MlKem1024` (`0x0202`), `XWing768X25519` (`0x11EB`), `HybridMlKem1024P384` (`0x0300`) |
| `PqKeyShare` | `encode_encap_key(group, bytes)`, `encode_ciphertext(group, bytes)`, `to_wire()`, `from_wire(bytes)`, `expected_encap_key_len(group)` |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `hazmat-test-vectors` | off | Enables deterministic `generate_deterministic` / `encapsulate_deterministic` helpers for known-answer tests. **Hazardous**: deterministic keygen requires unique seeds; reuse is catastrophically insecure. |

## Error Variants

All fallible operations return `oxicrypto_core::CryptoError`:

| Variant | When |
|---------|------|
| `Kex` | KEM encapsulation/decapsulation failure (e.g. an invalid ML-KEM ciphertext) |
| `Sign` | Signature generation or verification failure (ML-DSA / SLH-DSA) |
| `InvalidKey` | A key has the wrong length or is malformed (`from_bytes` parse failure) |
| `Encoding` | Serialization/deserialization failure (wire formats, key/signature decoding) |
| `BadInput` | Invalid parameters (e.g. wrong wire-format length) |

## Cross-References

- [`oxicrypto-core`](../oxicrypto-core) — defines the `Kem` / `Signer` / `Verifier` traits and `CryptoError`.
- [`oxicrypto-kex`](../oxicrypto-kex) — the X25519 and ECDH P-384 classical halves of the hybrid KEMs.
- [`oxicrypto-kdf`](../oxicrypto-kdf) — HKDF-SHA-384 used by `HybridKem1024P384`.
- [`oxicrypto-sig`](../oxicrypto-sig) — classical signatures (Ed25519, ECDSA, RSA), complementary to ML-DSA / SLH-DSA.
- [`oxicrypto`](../oxicrypto) — the facade re-exports the post-quantum API under a `pq` module.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
