# oxicrypto-sig — Pure-Rust digital signatures for OxiCrypto

[![Crates.io](https://img.shields.io/crates/v/oxicrypto-sig.svg)](https://crates.io/crates/oxicrypto-sig)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxicrypto-sig` is the (classical) digital-signature layer of the OxiCrypto stack. It provides Ed25519, Ed448 (pure / `ctx` / `ph`), ECDSA over NIST P-256 / P-384 / P-521, RSA PKCS#1 v1.5 and RSA-PSS (SHA-256/384/512), Schnorr BIP-340, FROST(Ed25519, SHA-512) threshold signatures, and MuSig2 (Ed25519 n-of-n multi-signature) — all behind the `oxicrypto_core::{Signer, Verifier}` traits where applicable. A `tls` module additionally maps TLS 1.3 `SignatureScheme` wire codes to a boxed signer/verifier pair for protocol-level negotiation.

The crate is Pure Rust (`#![forbid(unsafe_code)]`), building on `ed25519-dalek`, `ed448-goldilocks`, `curve25519-dalek`, the RustCrypto `p256`/`p384`/`p521`/`k256` curves, and `rsa`. Post-quantum signatures (ML-DSA, SLH-DSA) live in the sibling [`oxicrypto-pq`](../oxicrypto-pq) crate.

## Installation

```toml
[dependencies]
oxicrypto-sig = "0.2.1"
```

## Quick Start

Ed25519 sign / verify via the trait-dispatched primitives:

```rust
use oxicrypto_core::{Signer, Verifier};
use oxicrypto_sig::{ed25519_generate_keypair, Ed25519, Ed25519Verifier};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn main() -> Result<(), oxicrypto_core::CryptoError> {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (sk, pk) = ed25519_generate_keypair(&mut rng)?;

    let msg = b"sign me";
    let mut sig = [0u8; 64];
    let len = Ed25519.sign(sk.as_bytes(), msg, &mut sig)?;
    assert_eq!(len, 64);

    Ed25519Verifier.verify(&pk, msg, &sig)?;
    Ok(())
}
```

ECDSA P-256 via the stateful key types:

```rust
use oxicrypto_sig::{ecdsa_p256_generate_keypair, EcdsaP256Signer, EcdsaP256Verifier};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn main() -> Result<(), oxicrypto_core::CryptoError> {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let (sk, pk) = ecdsa_p256_generate_keypair(&mut rng)?;

    let signer = EcdsaP256Signer::from_bytes(sk.as_bytes())?;
    let sig = signer.sign(b"message")?; // DER-encoded

    let verifier = EcdsaP256Verifier::from_sec1_bytes(&pk)?;
    verifier.verify(b"message", &sig)?;
    Ok(())
}
```

## API Overview

### Trait-dispatched primitives (`Signer` / `Verifier`)

Zero-size unit structs implementing `oxicrypto_core::Signer` (`name`, `signature_len`, `sign`) and `oxicrypto_core::Verifier` (`name`, `verify`). The signer parses raw key bytes on each call; `sign()` returns the number of bytes written.

| Signer | Verifier | Algorithm | Secret-key input | Public-key input | `signature_len()` |
|--------|----------|-----------|------------------|------------------|-------------------|
| `Ed25519` | `Ed25519Verifier` | Ed25519 | 32-byte seed | 32-byte point | 64 (exact) |
| `Ed448` | `Ed448Verify` | Ed448 | 57-byte seed | 57-byte point | 114 (exact) |
| `EcdsaP256` | `EcdsaP256Verify` | ECDSA P-256 | 32-byte scalar | SEC1 (33/65) | 72 (DER max) |
| `EcdsaP384` | `EcdsaP384Verify` | ECDSA P-384 | 48-byte scalar | SEC1 (49/97) | 104 (DER max) |
| `EcdsaP521` | `EcdsaP521Verify` | ECDSA P-521 | 66-byte scalar | SEC1 (67/133) | 139 (DER max) |
| `RsaPkcs1v15Sha256` | `RsaPkcs1v15Sha256Verify` | RSA PKCS#1 v1.5 + SHA-256 | PKCS#8 DER | SPKI DER | 512 (≤4096-bit key) |
| `RsaPkcs1v15Sha384` | `RsaPkcs1v15Sha384Verify` | RSA PKCS#1 v1.5 + SHA-384 | PKCS#8 DER | SPKI DER | 512 |
| `RsaPkcs1v15Sha512` | `RsaPkcs1v15Sha512Verify` | RSA PKCS#1 v1.5 + SHA-512 | PKCS#8 DER | SPKI DER | 512 |
| `RsaPssSha256` | `RsaPssSha256Verify` | RSA-PSS + SHA-256 | PKCS#8 DER | SPKI DER | 512 |
| `RsaPssSha384` | `RsaPssSha384Verify` | RSA-PSS + SHA-384 | PKCS#8 DER | SPKI DER | 512 |
| `RsaPssSha512` | `RsaPssSha512Verify` | RSA-PSS + SHA-512 | PKCS#8 DER | SPKI DER | 512 |

> ECDSA / RSA `signature_len()` reports the **maximum** DER length; ECDSA DER signatures are variable-length, so use the value returned by `sign()` for the true size.

### Stateful key types (pre-parsed keys)

For callers who prefer to parse a key once and reuse it:

| Signer / Verifier | Constructor | Module |
|-------------------|-------------|--------|
| `EcdsaP256Signer` / `EcdsaP256Verifier` | `from_bytes` / `from_sec1_bytes` | `ecdsa_p256` |
| `EcdsaP384Signer` / `EcdsaP384Verifier` | `from_bytes` / `from_sec1_bytes` | `ecdsa_p384` |
| `EcdsaP521Signer` / `EcdsaP521Verifier` | `from_bytes` / `from_sec1_bytes` | `ecdsa_p521` |
| `Ed448SigningKey` / `Ed448VerifyingKey` | `from_bytes` (57-byte seed / point) | `ed448` |
| `RsaPkcs1v15Sha{256,384,512}Signer` / `…Verifier` | `from_pkcs8_der` / `from_spki_der` | `rsa_sig` |
| `RsaPssSha{256,384,512}Signer` / `…Verifier` | `from_pkcs8_der` / `from_spki_der` | `rsa_sig` |

ECDSA signers also expose `verifying_key_bytes()`; `Ed448SigningKey` exposes `verifying_key_bytes() -> [u8; 57]`.

### Unified ECDSA construction (`CurveId`)

A runtime-selectable alternative to the per-curve signer/verifier types above, for callers that only know the curve at runtime (protocol negotiation, config-driven selection). Prefer the per-curve types when the curve is known at compile time.

| Item | Description |
|------|-------------|
| `CurveId` | `P256` / `P384` / `P521` curve selector enum |
| `with_ecdsa_signer(CurveId) -> EcdsaSignerFn` | Returns a boxed `Fn(sk_bytes, msg) -> Result<Vec<u8>, CryptoError>` closure (DER-encoded signature, deterministic per RFC 6979) |
| `with_ecdsa_verifier(CurveId) -> EcdsaVerifierFn` | Returns a boxed `Fn(pk_sec1_bytes, msg, der_sig) -> Result<(), CryptoError>` closure |

### ECDSA signature format selection (`SignatureFormat`)

`EcdsaP256Signer`/`Verifier`, `EcdsaP384Signer`/`Verifier`, and `EcdsaP521Signer`/`Verifier` each expose `sign_fmt(message, fmt)` / `verify_fmt(message, sig, fmt)` inherent methods alongside the DER-only `sign`/`verify`.

| Variant | Encoding |
|---------|----------|
| `SignatureFormat::Der` | ASN.1 DER, variable length (the default used by `sign`/`verify`) |
| `SignatureFormat::Raw` | Fixed-width `r ‖ s` big-endian: 64 bytes (P-256), 96 bytes (P-384), 132 bytes (P-521) |

### Key generation

All accept any `R: rand_core::TryCryptoRng + ?Sized`.

| Function | Returns |
|----------|---------|
| `ed25519_generate_keypair(rng)` | `(SecretKey<32>, [u8; 32])` |
| `ed448_generate_keypair(rng)` | `(SecretVec, [u8; 57])` |
| `ecdsa_p256_generate_keypair(rng)` | `(SecretVec, Vec<u8>)` — scalar + SEC1 compressed public key |
| `ecdsa_p384_generate_keypair(rng)` | `(SecretVec, Vec<u8>)` |
| `ecdsa_p521_generate_keypair(rng)` | `(SecretVec, Vec<u8>)` |
| `schnorr_bip340_generate_keypair(rng)` | `(SecretKey<32>, [u8; 32])` — secp256k1 scalar + x-only public key |
| `rsa_generate_keypair(bit_size)` | `(Vec<u8>, Vec<u8>)` — PKCS#8 DER private + SPKI DER public |

### Ed25519 batch verification

| Function | Description |
|----------|-------------|
| `ed25519_verify_batch(messages, signatures, verifying_keys)` | Verify a batch sequentially; `BadInput` on length mismatch, `Sign` if any signature is invalid, `Ok` for an empty batch |

### Ed448 extended modes (`ed448_ext`)

| Function | Description |
|----------|-------------|
| `ed448ph_sign(...)` / `ed448ph_verify(...)` | Ed448ph (pre-hashed) signing / verification |
| `ed448ctx_sign(sk, msg, context)` / `ed448ctx_verify(...)` | Ed448 with an explicit context string |

### RSA OAEP (encryption, in `rsa_sig`)

| Function | Description |
|----------|-------------|
| `rsa_oaep_sha256_encrypt(pk_der, plaintext)` | RSA-OAEP-SHA-256 encryption (SPKI DER public key) |
| `rsa_oaep_sha256_decrypt(sk_der, ciphertext)` | RSA-OAEP-SHA-256 decryption (PKCS#8 DER private key) |

### Schnorr BIP-340 (`schnorr`)

`SchnorrBip340` is a unit struct. Constants: `SECRET_KEY_LEN = 32`, `PUBLIC_KEY_LEN = 32`, `SIGNATURE_LEN = 64`.

| Method / function | Description |
|-------------------|-------------|
| `SchnorrBip340::parse_secret_key(sk)` | Parse a 32-byte secret key into `SecretKey<32>` |
| `derive_public_key(&self, sk)` | Derive the 32-byte x-only public key |
| `SchnorrBip340::parse_public_key(pk)` | Validate a 32-byte x-only public key |
| `sign_with_aux(...)` / `schnorr_bip340_sign_with_aux(...)` | BIP-340 sign with explicit auxiliary randomness |
| `verify_message(&self, pk, msg, sig)` | Verify a BIP-340 signature |
| `sign_sha256(&self, sk, msg)` / `verify_sha256(&self, pk, msg, sig)` | Sign / verify a SHA-256-prehashed message |

### FROST threshold signatures (`frost`)

FROST(Ed25519, SHA-512) `t`-of-`n` threshold Schnorr signatures (RFC 9591). Aggregate signatures are byte-for-byte ordinary Ed25519 signatures. Context string: `"FROST-ED25519-SHA512-v1"`. Constants: `SCALAR_LEN = 32`, `ELEMENT_LEN = 32`, `SIGNATURE_LEN = 64`.

| Stage | Item | Description |
|-------|------|-------------|
| Identifiers | `Identifier` | Non-zero participant id; `new(u16)`, `from_scalar`, `from_bytes`, `as_scalar`, `to_bytes` |
| Key generation | `trusted_dealer_keygen(t, n, rng)` | Trusted-dealer Shamir split → `(Vec<SecretShare>, PublicKeyPackage)` |
| | `trusted_dealer_keygen_with_coefficients(...)` | Deterministic variant with explicit polynomial coefficients |
| | `SecretShare`, `KeyPackage`, `PublicKeyPackage` | Per-participant key material and the group public key |
| Round 1 | `commit(rng)` | Generate `(SigningNonces, SigningCommitments)` |
| Round 2 | `sign(...)` | Produce a `SignatureShare`; `verify_signature_share(...)` checks one share |
| Aggregation | `aggregate(...)` | Combine shares into a `Signature` (`r`, `z`); `verify_signature(...)` verifies it |
| Helper | `sort_commitments(&[SigningCommitments])` | Sort ascending by identifier and reject duplicates |

`KeyPackage`, `SecretShare`, `PublicKeyPackage`, `SigningCommitments`, `SigningNonces`, `SignatureShare`, and `Signature` all provide accessors and `to_bytes` / `from_bytes` serialization (RFC 9591 §6.1 encodings).

### MuSig2 multi-signatures (`musig2`)

MuSig2 (Nick–Ruffing–Seurin 2021) n-of-n multi-signatures over Ed25519. The aggregated signature is byte-for-byte an ordinary Ed25519 signature, verifiable via `ed25519_dalek` against the aggregated public key. Context string: `"MuSig2-Ed25519-SHA512-v1"`. Two-round protocol; nonces are single-use by construction (consumed by value).

| Stage | Item | Description |
|-------|------|-------------|
| Keys | `MuSig2SecretKey`, `MuSig2PublicKey` | `from_bytes`/`to_bytes`/`as_bytes`; secret key zeroizes on drop |
| Key aggregation | `aggregate_keys(public_keys)` | Rogue-key-resistant aggregation (`H_agg_coeff`-weighted sum) → `(aggregate_key_bytes, per_key_coefficients)` |
| Round 1 | `musig2_commit(sk, rng)` / `musig2_commit_from_seed(sk, seed)` | Generate `(SecNonce, PubNonce)`; the seeded variant is deterministic (reproducible nonces for tests) |
| Round 2 | `musig2_sign(sk, sec_nonce, public_keys, all_pub_nonces, my_index, msg)` | Consumes `sk` and `SecNonce` to enforce single-use; returns a `PartialSig` |
| Aggregation | `musig2_aggregate(partial_sigs, public_keys, all_pub_nonces, msg)` | Combine partial signatures into a `MuSig2Signature` (64 bytes: `R ‖ s`) |
| Verification | `musig2_verify(agg_pk, msg, sig)` / `musig2_verify_ed25519(agg_pk, msg, sig)` | Internal Schnorr-equation check, or cross-check via the `ed25519_dalek` verifier |

No standard Ed25519-MuSig2 known-answer test exists (BIP-327 vectors are secp256k1-only); validation is property-based (round-trip, rogue-key-coefficient non-triviality, tamper negatives, deterministic-nonce reproducibility).

### TLS signature scheme negotiation (`tls`)

Maps TLS 1.3 (RFC 8446 §4.2.3) `SignatureScheme` IANA wire codes to a boxed `Signer`/`Verifier` pair, for higher-level protocol code (e.g. OxiTLS) that selects the signature algorithm at runtime.

| Item | Description |
|------|-------------|
| `TlsSignatureScheme` | Enum covering all 11 TLS 1.3 schemes: ECDSA P-256/P-384/P-521, RSA PKCS#1v1.5 SHA-256/384/512, RSA-PSS SHA-256/384/512, Ed25519, Ed448 |
| `TlsSignatureScheme::from_wire(u16)` / `to_wire()` | Decode/encode the 2-byte IANA wire value |
| `TlsSignatureScheme::from_iana_name(&str)` / `algorithm_name()` | Parse/format the IANA scheme name (e.g. `"ecdsa_secp256r1_sha256"`) |
| `negotiate_sig(scheme) -> Result<SigPair, CryptoError>` | `SigPair = (Box<dyn Signer + Send + Sync>, Box<dyn Verifier + Send + Sync>)` for the scheme; all 11 variants are currently supported |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | off | Propagates `std` to `ed25519-dalek` and `oxicrypto-core` |

## Error Variants

All fallible operations return `oxicrypto_core::CryptoError`:

| Variant | When |
|---------|------|
| `InvalidKey` | A key has the wrong length or is malformed (raw scalar, SEC1, DER, FROST scalar/point) |
| `InvalidTag` | A signature/share has the wrong length, or Ed25519 verification failed |
| `BufferTooSmall` | The signature output buffer is shorter than the signature |
| `BadInput` | Batch length mismatch, zero FROST identifier, or invalid protocol parameters |
| `Sign` | Signature generation/verification failure (batch verify, FROST share/signature) |
| `Rng` | RNG failure during key generation |
| `Encoding` | DER/SEC1 encoding or decoding failure |

## Cross-References

- [`oxicrypto-core`](../oxicrypto-core) — defines `Signer`, `Verifier`, `SecretKey`, `SecretVec`, and `CryptoError`.
- [`oxicrypto-rand`](../oxicrypto-rand) — `OxiRng` is a ready-made `TryCryptoRng` for the key-generation helpers.
- [`oxicrypto-pq`](../oxicrypto-pq) — post-quantum signatures (ML-DSA / FIPS 204, SLH-DSA / FIPS 205).
- [`oxicrypto`](../oxicrypto) — the facade re-exports the signature primitives.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
