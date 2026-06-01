#![forbid(unsafe_code)]

//! Pure Rust digital signature implementations for the OxiCrypto stack.
//!
//! # Algorithms
//!
//! | Algorithm | Module | Key sizes |
//! |-----------|--------|-----------|
//! | Ed25519 | (inline) | 32-byte scalar / 32-byte point |
//! | Ed448 | [`ed448`] | 57-byte scalar / 57-byte point |
//! | ECDSA P-256 | [`ecdsa_p256`] | 32-byte scalar / 33-byte SEC1 point |
//! | ECDSA P-384 | [`ecdsa_p384`] | 48-byte scalar / 49-byte SEC1 point |
//! | ECDSA P-521 | [`ecdsa_p521`] | 66-byte scalar / 67-byte SEC1 point |
//! | RSA PKCS#1v15 | [`rsa_sig`] | DER PKCS#8 / DER SPKI |
//! | RSA-PSS | [`rsa_sig`] | DER PKCS#8 / DER SPKI |
//! | Schnorr BIP-340 | [`schnorr`] | 32-byte scalar / 32-byte x-only point / 64-byte sig |
//! | FROST(Ed25519, SHA-512) | [`frost`] | `t`-of-`n` threshold Ed25519 (RFC 9591) |

pub mod ecdsa_p256;
pub mod ecdsa_p384;
pub mod ecdsa_p521;
pub mod ed448;
pub mod ed448_ext;
pub mod frost;
pub mod rsa_sig;
pub mod schnorr;

pub use ecdsa_p256::{EcdsaP256Signer, EcdsaP256Verifier};
pub use ecdsa_p384::{EcdsaP384Signer, EcdsaP384Verifier};
pub use ecdsa_p521::{EcdsaP521Signer, EcdsaP521Verifier};
pub use ed448::{Ed448SigningKey, Ed448VerifyingKey};
pub use ed448_ext::{ed448ctx_sign, ed448ctx_verify, ed448ph_sign, ed448ph_verify};
pub use rsa_sig::{
    rsa_generate_keypair, rsa_oaep_sha256_decrypt, rsa_oaep_sha256_encrypt,
    RsaPkcs1v15Sha256Signer, RsaPkcs1v15Sha256Verifier, RsaPkcs1v15Sha384Signer,
    RsaPkcs1v15Sha384Verifier, RsaPkcs1v15Sha512Signer, RsaPkcs1v15Sha512Verifier,
    RsaPssSha256Signer, RsaPssSha256Verifier, RsaPssSha384Signer, RsaPssSha384Verifier,
    RsaPssSha512Signer, RsaPssSha512Verifier,
};
pub use schnorr::{schnorr_bip340_sign_with_aux, SchnorrBip340};

// Trait-dispatched unit-struct wrappers (re-exports for convenience)
// These are defined below after the Ed25519 impls.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use oxicrypto_core::{CryptoError, SecretKey, SecretVec, Signer, Verifier};
use p256::elliptic_curve::Generate;

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate an Ed25519 key pair.
///
/// Returns `(signing_key_bytes, verifying_key_bytes)`.
/// `signing_key_bytes` is a 32-byte seed wrapped in [`SecretKey`].
///
/// This function uses the supplied RNG to fill a 32-byte seed and constructs
/// the key pair from it, avoiding the `rand_core` 0.6/0.10 version boundary.
#[must_use = "key pair result must be used"]
pub fn ed25519_generate_keypair<R: rand_core::TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<(SecretKey<32>, [u8; 32]), CryptoError> {
    let mut seed = [0u8; 32];
    rng.try_fill_bytes(&mut seed)
        .map_err(|_| CryptoError::Rng)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    Ok((SecretKey::new(seed), *verifying_key.as_bytes()))
}

/// Generate an ECDSA P-256 key pair.
///
/// Returns `(secret_key_bytes, sec1_compressed_public_key_bytes)`.
/// The secret key bytes are wrapped in [`SecretVec`] (zeroized on drop).
#[must_use = "key pair result must be used"]
pub fn ecdsa_p256_generate_keypair<R: rand_core::TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<(SecretVec, Vec<u8>), CryptoError> {
    let secret_key = p256::SecretKey::try_generate_from_rng(rng).map_err(|_| CryptoError::Rng)?;
    let public_key = secret_key.public_key();
    let sk_bytes = SecretVec::from_slice(secret_key.to_bytes().as_slice());
    let pk_bytes = public_key.to_sec1_bytes().to_vec();
    Ok((sk_bytes, pk_bytes))
}

/// Generate an ECDSA P-384 key pair.
///
/// Returns `(secret_key_bytes, sec1_compressed_public_key_bytes)`.
/// The secret key bytes are wrapped in [`SecretVec`] (zeroized on drop).
#[must_use = "key pair result must be used"]
pub fn ecdsa_p384_generate_keypair<R: rand_core::TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<(SecretVec, Vec<u8>), CryptoError> {
    let secret_key = p384::SecretKey::try_generate_from_rng(rng).map_err(|_| CryptoError::Rng)?;
    let public_key = secret_key.public_key();
    let sk_bytes = SecretVec::from_slice(secret_key.to_bytes().as_slice());
    let pk_bytes = public_key.to_sec1_bytes().to_vec();
    Ok((sk_bytes, pk_bytes))
}

/// Generate an ECDSA P-521 key pair.
///
/// Returns `(secret_key_bytes, sec1_compressed_public_key_bytes)`.
/// The secret key bytes are wrapped in [`SecretVec`] (zeroized on drop).
#[must_use = "key pair result must be used"]
pub fn ecdsa_p521_generate_keypair<R: rand_core::TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<(SecretVec, Vec<u8>), CryptoError> {
    let secret_key = p521::SecretKey::try_generate_from_rng(rng).map_err(|_| CryptoError::Rng)?;
    let public_key = secret_key.public_key();
    let sk_bytes = SecretVec::from_slice(secret_key.to_bytes().as_slice());
    let pk_bytes = public_key.to_sec1_bytes().to_vec();
    Ok((sk_bytes, pk_bytes))
}

// ── Ed25519 batch verification ────────────────────────────────────────────────

/// Verify a batch of Ed25519 signatures in a single call (sequential).
///
/// Returns `Ok(())` if every signature is valid.
/// Returns `Err(CryptoError::BadInput)` if the slice lengths differ.
/// Returns `Err(CryptoError::Sign)` if any signature is invalid.
/// An empty batch returns `Ok(())`.
#[must_use = "batch verification result must be checked"]
pub fn ed25519_verify_batch(
    messages: &[&[u8]],
    signatures: &[Signature],
    verifying_keys: &[VerifyingKey],
) -> Result<(), CryptoError> {
    use ed25519_dalek::Verifier as DalekVerifier;
    if messages.len() != signatures.len() || messages.len() != verifying_keys.len() {
        return Err(CryptoError::BadInput);
    }
    for ((msg, sig), vk) in messages
        .iter()
        .zip(signatures.iter())
        .zip(verifying_keys.iter())
    {
        vk.verify(msg, sig).map_err(|_| CryptoError::Sign)?;
    }
    Ok(())
}

// ── Trait-dispatched unit-struct wrappers ─────────────────────────────────────
//
// Each ECDSA / Ed448 / RSA algorithm gets a zero-size unit struct implementing
// `Signer` and `Verifier` from `oxicrypto-core`.  These parse raw key bytes on
// each call, matching the trait surface expected by the facade factory functions.
// The existing stateful structs (`EcdsaP256Signer`, `RsaPkcs1v15Sha256Signer`,
// etc.) remain available for callers who prefer a pre-parsed key.

// ── ECDSA P-256 trait wrappers ───────────────────────────────────────────────

/// ECDSA P-256 signing primitive (trait-dispatched).
///
/// `sign(sk, msg, sig_out)`: `sk` is 32-byte raw scalar, returns DER signature.
///
/// Note: `signature_len()` returns 72, the DER **maximum** length.  Actual DER
/// signatures are variable-length (typically 70--72 bytes).  Callers should
/// use the return value of `sign()` for the true written length.
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaP256;

impl Signer for EcdsaP256 {
    fn name(&self) -> &'static str {
        "ECDSA-P256"
    }
    fn signature_len(&self) -> usize {
        72
    } // DER max length; actual is variable
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        let signer = EcdsaP256Signer::from_bytes(sk)?;
        let sig_bytes = signer.sign(msg)?;
        if sig_out.len() < sig_bytes.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        sig_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
        Ok(sig_bytes.len())
    }
}

/// ECDSA P-256 verification primitive (trait-dispatched).
///
/// `verify(pk, msg, sig)`: `pk` is SEC1-encoded (compressed 33 or uncompressed 65 bytes).
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaP256Verify;

impl Verifier for EcdsaP256Verify {
    fn name(&self) -> &'static str {
        "ECDSA-P256"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let verifier = EcdsaP256Verifier::from_sec1_bytes(pk)?;
        verifier.verify(msg, sig)
    }
}

// ── ECDSA P-384 trait wrappers ───────────────────────────────────────────────

/// ECDSA P-384 signing primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaP384;

impl Signer for EcdsaP384 {
    fn name(&self) -> &'static str {
        "ECDSA-P384"
    }
    fn signature_len(&self) -> usize {
        104
    } // DER max length
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        let signer = EcdsaP384Signer::from_bytes(sk)?;
        let sig_bytes = signer.sign(msg)?;
        if sig_out.len() < sig_bytes.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        sig_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
        Ok(sig_bytes.len())
    }
}

/// ECDSA P-384 verification primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaP384Verify;

impl Verifier for EcdsaP384Verify {
    fn name(&self) -> &'static str {
        "ECDSA-P384"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let verifier = EcdsaP384Verifier::from_sec1_bytes(pk)?;
        verifier.verify(msg, sig)
    }
}

// ── ECDSA P-521 trait wrappers ───────────────────────────────────────────────

/// ECDSA P-521 signing primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaP521;

impl Signer for EcdsaP521 {
    fn name(&self) -> &'static str {
        "ECDSA-P521"
    }
    fn signature_len(&self) -> usize {
        139
    } // DER max length
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        let signer = EcdsaP521Signer::from_bytes(sk)?;
        let sig_bytes = signer.sign(msg)?;
        if sig_out.len() < sig_bytes.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        sig_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
        Ok(sig_bytes.len())
    }
}

/// ECDSA P-521 verification primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaP521Verify;

impl Verifier for EcdsaP521Verify {
    fn name(&self) -> &'static str {
        "ECDSA-P521"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let verifier = EcdsaP521Verifier::from_sec1_bytes(pk)?;
        verifier.verify(msg, sig)
    }
}

// ── Ed448 trait wrappers ─────────────────────────────────────────────────────

/// Ed448 signing primitive (trait-dispatched).
///
/// `sign(sk, msg, sig_out)`: `sk` is 57-byte raw seed, returns 114-byte signature.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed448;

impl Signer for Ed448 {
    fn name(&self) -> &'static str {
        "Ed448"
    }
    fn signature_len(&self) -> usize {
        114
    }
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        if sig_out.len() < 114 {
            return Err(CryptoError::BufferTooSmall);
        }
        let signer = Ed448SigningKey::from_bytes(sk)?;
        let sig_bytes = signer.sign(msg)?;
        sig_out[..114].copy_from_slice(&sig_bytes);
        Ok(114)
    }
}

/// Ed448 verification primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed448Verify;

impl Verifier for Ed448Verify {
    fn name(&self) -> &'static str {
        "Ed448"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let verifier = Ed448VerifyingKey::from_bytes(pk)?;
        verifier.verify(msg, sig)
    }
}

// ── RSA PKCS#1v15 SHA-256 trait wrappers ─────────────────────────────────────

/// RSA PKCS#1v15 SHA-256 signing primitive (trait-dispatched).
///
/// `sign(sk, msg, sig_out)`: `sk` is DER-encoded PKCS#8 private key.
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaPkcs1v15Sha256;

impl Signer for RsaPkcs1v15Sha256 {
    fn name(&self) -> &'static str {
        "RSA-PKCS1v15-SHA256"
    }
    fn signature_len(&self) -> usize {
        512
    } // up to 4096-bit key = 512 bytes
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        let signer = RsaPkcs1v15Sha256Signer::from_pkcs8_der(sk)?;
        let sig_bytes = signer.sign(msg)?;
        if sig_out.len() < sig_bytes.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        sig_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
        Ok(sig_bytes.len())
    }
}

/// RSA PKCS#1v15 SHA-256 verification primitive (trait-dispatched).
///
/// `verify(pk, msg, sig)`: `pk` is DER-encoded SubjectPublicKeyInfo.
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaPkcs1v15Sha256Verify;

impl Verifier for RsaPkcs1v15Sha256Verify {
    fn name(&self) -> &'static str {
        "RSA-PKCS1v15-SHA256"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let verifier = RsaPkcs1v15Sha256Verifier::from_spki_der(pk)?;
        verifier.verify(msg, sig)
    }
}

// ── RSA PKCS#1v15 SHA-384 trait wrappers ─────────────────────────────────────

/// RSA PKCS#1v15 SHA-384 signing primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaPkcs1v15Sha384;

impl Signer for RsaPkcs1v15Sha384 {
    fn name(&self) -> &'static str {
        "RSA-PKCS1v15-SHA384"
    }
    fn signature_len(&self) -> usize {
        512
    }
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        let signer = RsaPkcs1v15Sha384Signer::from_pkcs8_der(sk)?;
        let sig_bytes = signer.sign(msg)?;
        if sig_out.len() < sig_bytes.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        sig_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
        Ok(sig_bytes.len())
    }
}

/// RSA PKCS#1v15 SHA-384 verification primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaPkcs1v15Sha384Verify;

impl Verifier for RsaPkcs1v15Sha384Verify {
    fn name(&self) -> &'static str {
        "RSA-PKCS1v15-SHA384"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let verifier = RsaPkcs1v15Sha384Verifier::from_spki_der(pk)?;
        verifier.verify(msg, sig)
    }
}

// ── RSA PKCS#1v15 SHA-512 trait wrappers ─────────────────────────────────────

/// RSA PKCS#1v15 SHA-512 signing primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaPkcs1v15Sha512;

impl Signer for RsaPkcs1v15Sha512 {
    fn name(&self) -> &'static str {
        "RSA-PKCS1v15-SHA512"
    }
    fn signature_len(&self) -> usize {
        512
    }
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        let signer = RsaPkcs1v15Sha512Signer::from_pkcs8_der(sk)?;
        let sig_bytes = signer.sign(msg)?;
        if sig_out.len() < sig_bytes.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        sig_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
        Ok(sig_bytes.len())
    }
}

/// RSA PKCS#1v15 SHA-512 verification primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaPkcs1v15Sha512Verify;

impl Verifier for RsaPkcs1v15Sha512Verify {
    fn name(&self) -> &'static str {
        "RSA-PKCS1v15-SHA512"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let verifier = RsaPkcs1v15Sha512Verifier::from_spki_der(pk)?;
        verifier.verify(msg, sig)
    }
}

// ── RSA-PSS SHA-256 trait wrappers ───────────────────────────────────────────

/// RSA-PSS SHA-256 signing primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaPssSha256;

impl Signer for RsaPssSha256 {
    fn name(&self) -> &'static str {
        "RSA-PSS-SHA256"
    }
    fn signature_len(&self) -> usize {
        512
    }
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        let signer = RsaPssSha256Signer::from_pkcs8_der(sk)?;
        let sig_bytes = signer.sign(msg)?;
        if sig_out.len() < sig_bytes.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        sig_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
        Ok(sig_bytes.len())
    }
}

/// RSA-PSS SHA-256 verification primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaPssSha256Verify;

impl Verifier for RsaPssSha256Verify {
    fn name(&self) -> &'static str {
        "RSA-PSS-SHA256"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let verifier = RsaPssSha256Verifier::from_spki_der(pk)?;
        verifier.verify(msg, sig)
    }
}

// ── RSA-PSS SHA-384 trait wrappers ───────────────────────────────────────────

/// RSA-PSS SHA-384 signing primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaPssSha384;

impl Signer for RsaPssSha384 {
    fn name(&self) -> &'static str {
        "RSA-PSS-SHA384"
    }
    fn signature_len(&self) -> usize {
        512
    }
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        let signer = RsaPssSha384Signer::from_pkcs8_der(sk)?;
        let sig_bytes = signer.sign(msg)?;
        if sig_out.len() < sig_bytes.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        sig_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
        Ok(sig_bytes.len())
    }
}

/// RSA-PSS SHA-384 verification primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaPssSha384Verify;

impl Verifier for RsaPssSha384Verify {
    fn name(&self) -> &'static str {
        "RSA-PSS-SHA384"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let verifier = RsaPssSha384Verifier::from_spki_der(pk)?;
        verifier.verify(msg, sig)
    }
}

// ── RSA-PSS SHA-512 trait wrappers ───────────────────────────────────────────

/// RSA-PSS SHA-512 signing primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaPssSha512;

impl Signer for RsaPssSha512 {
    fn name(&self) -> &'static str {
        "RSA-PSS-SHA512"
    }
    fn signature_len(&self) -> usize {
        512
    }
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        let signer = RsaPssSha512Signer::from_pkcs8_der(sk)?;
        let sig_bytes = signer.sign(msg)?;
        if sig_out.len() < sig_bytes.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        sig_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
        Ok(sig_bytes.len())
    }
}

/// RSA-PSS SHA-512 verification primitive (trait-dispatched).
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaPssSha512Verify;

impl Verifier for RsaPssSha512Verify {
    fn name(&self) -> &'static str {
        "RSA-PSS-SHA512"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let verifier = RsaPssSha512Verifier::from_spki_der(pk)?;
        verifier.verify(msg, sig)
    }
}

/// Ed25519 signing primitive.
///
/// `sign(sk, msg, sig_out)` — `sk` must be 32 bytes (the raw seed / secret scalar).
/// `sig_out` must be at least 64 bytes; returns 64.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519;

impl Signer for Ed25519 {
    fn name(&self) -> &'static str {
        "Ed25519"
    }
    fn signature_len(&self) -> usize {
        64
    }
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        if sig_out.len() < 64 {
            return Err(CryptoError::BufferTooSmall);
        }
        let sk_bytes: &[u8; 32] = sk.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let signing_key = SigningKey::from_bytes(sk_bytes);

        use ed25519_dalek::Signer as DalekSigner;
        let signature: Signature = signing_key.sign(msg);
        sig_out[..64].copy_from_slice(&signature.to_bytes());
        Ok(64)
    }
}

/// Ed25519 verification primitive.
///
/// `verify(pk, msg, sig)` — `pk` must be 32 bytes (compressed Edwards-y point).
/// `sig` must be 64 bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn name(&self) -> &'static str {
        "Ed25519"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let pk_bytes: &[u8; 32] = pk.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let sig_bytes: &[u8; 64] = sig.try_into().map_err(|_| CryptoError::InvalidTag)?;

        let verifying_key =
            VerifyingKey::from_bytes(pk_bytes).map_err(|_| CryptoError::InvalidKey)?;
        let signature = Signature::from_bytes(sig_bytes);

        use ed25519_dalek::Verifier as DalekVerifier;
        verifying_key
            .verify(msg, &signature)
            .map_err(|_| CryptoError::InvalidTag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn keypair_seed() -> ([u8; 32], [u8; 32]) {
        // Deterministic seed for tests.
        let seed = [0x5au8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let pk = signing_key.verifying_key().to_bytes();
        (seed, pk)
    }

    fn test_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([42u8; 32])
    }

    #[test]
    fn ed25519_sign_verify_round_trip() {
        let signer = Ed25519;
        let verifier = Ed25519Verifier;
        let (sk, pk) = keypair_seed();
        let msg = b"test message for oxicrypto";

        let mut sig = [0u8; 64];
        let len = signer.sign(&sk, msg, &mut sig).expect("sign failed");
        assert_eq!(len, 64);
        verifier
            .verify(&pk, msg, &sig)
            .expect("verify should succeed");
    }

    #[test]
    fn ed25519_corrupted_sig_fails() {
        let signer = Ed25519;
        let verifier = Ed25519Verifier;
        let (sk, pk) = keypair_seed();
        let msg = b"another test message";

        let mut sig = [0u8; 64];
        signer.sign(&sk, msg, &mut sig).expect("sign failed");
        // Corrupt the signature
        sig[0] ^= 0xff;

        let result = verifier.verify(&pk, msg, &sig);
        assert_eq!(result, Err(CryptoError::InvalidTag));
    }

    #[test]
    fn ed25519_wrong_key_fails() {
        let signer = Ed25519;
        let verifier = Ed25519Verifier;
        let (sk, _pk) = keypair_seed();
        // Different key pair for verification
        let other_seed = [0xabu8; 32];
        let other_sk = SigningKey::from_bytes(&other_seed);
        let other_pk = other_sk.verifying_key().to_bytes();

        let msg = b"message signed with sk";
        let mut sig = [0u8; 64];
        signer.sign(&sk, msg, &mut sig).expect("sign failed");

        let result = verifier.verify(&other_pk, msg, &sig);
        assert_eq!(result, Err(CryptoError::InvalidTag));
    }

    #[test]
    fn ed25519_invalid_sk_length_errors() {
        let signer = Ed25519;
        let msg = b"msg";
        let mut sig = [0u8; 64];
        let result = signer.sign(&[0u8; 16], msg, &mut sig);
        assert_eq!(result, Err(CryptoError::InvalidKey));
    }

    // ── Ed25519 key generation ────────────────────────────────────────────────

    #[test]
    fn ed25519_keygen_sign_verify() {
        let mut rng = test_rng();
        let (sk_secret, pk_bytes) =
            ed25519_generate_keypair(&mut rng).expect("ed25519 keygen failed");

        let msg = b"hello from ed25519 keygen test";
        let signer = Ed25519;
        let verifier = Ed25519Verifier;

        let mut sig_buf = [0u8; 64];
        let len = signer
            .sign(sk_secret.as_bytes(), msg, &mut sig_buf)
            .expect("sign failed");
        assert_eq!(len, 64);
        verifier
            .verify(&pk_bytes, msg, &sig_buf)
            .expect("verify failed");
    }

    // ── ECDSA key generation ──────────────────────────────────────────────────

    #[test]
    fn ecdsa_p256_keygen_sign_verify() {
        let mut rng = test_rng();
        let (sk_secret, pk_bytes) =
            ecdsa_p256_generate_keypair(&mut rng).expect("p256 keygen failed");

        let msg = b"hello from p256 keygen test";
        let signer_struct =
            EcdsaP256Signer::from_bytes(sk_secret.as_bytes()).expect("p256 signer from bytes");
        let sig_bytes = signer_struct.sign(msg).expect("p256 sign failed");

        let verifier_struct =
            EcdsaP256Verifier::from_sec1_bytes(&pk_bytes).expect("p256 verifier from sec1");
        verifier_struct
            .verify(msg, &sig_bytes)
            .expect("p256 verify failed");
    }

    #[test]
    fn ecdsa_p384_keygen_sign_verify() {
        let mut rng = test_rng();
        let (sk_secret, pk_bytes) =
            ecdsa_p384_generate_keypair(&mut rng).expect("p384 keygen failed");

        let msg = b"hello from p384 keygen test";
        let signer_struct =
            EcdsaP384Signer::from_bytes(sk_secret.as_bytes()).expect("p384 signer from bytes");
        let sig_bytes = signer_struct.sign(msg).expect("p384 sign failed");

        let verifier_struct =
            EcdsaP384Verifier::from_sec1_bytes(&pk_bytes).expect("p384 verifier from sec1");
        verifier_struct
            .verify(msg, &sig_bytes)
            .expect("p384 verify failed");
    }

    #[test]
    fn ecdsa_p521_keygen_sign_verify() {
        let mut rng = test_rng();
        let (sk_secret, pk_bytes) =
            ecdsa_p521_generate_keypair(&mut rng).expect("p521 keygen failed");

        let msg = b"hello from p521 keygen test";
        let signer_struct =
            EcdsaP521Signer::from_bytes(sk_secret.as_bytes()).expect("p521 signer from bytes");
        let sig_bytes = signer_struct.sign(msg).expect("p521 sign failed");

        let verifier_struct =
            EcdsaP521Verifier::from_sec1_bytes(&pk_bytes).expect("p521 verifier from sec1");
        verifier_struct
            .verify(msg, &sig_bytes)
            .expect("p521 verify failed");
    }

    // ── Ed25519 batch verification ────────────────────────────────────────────

    #[test]
    fn ed25519_batch_verify_all_valid() {
        use ed25519_dalek::Signer as DalekSigner;
        let seeds: [[u8; 32]; 5] = [[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32]];
        let signing_keys: Vec<SigningKey> = seeds.iter().map(SigningKey::from_bytes).collect();
        let verifying_keys: Vec<VerifyingKey> =
            signing_keys.iter().map(|sk| sk.verifying_key()).collect();

        let messages: [&[u8]; 5] = [b"msg1", b"msg2", b"msg3", b"msg4", b"msg5"];
        let signatures: Vec<Signature> = signing_keys
            .iter()
            .zip(messages.iter())
            .map(|(sk, msg)| sk.sign(msg))
            .collect();

        let msg_refs: Vec<&[u8]> = messages.to_vec();
        ed25519_verify_batch(&msg_refs, &signatures, &verifying_keys)
            .expect("batch verify of 5 valid sigs should succeed");
    }

    #[test]
    fn ed25519_batch_verify_one_tampered() {
        use ed25519_dalek::Signer as DalekSigner;
        let seeds: [[u8; 32]; 3] = [[0x11; 32], [0x22; 32], [0x33; 32]];
        let signing_keys: Vec<SigningKey> = seeds.iter().map(SigningKey::from_bytes).collect();
        let verifying_keys: Vec<VerifyingKey> =
            signing_keys.iter().map(|sk| sk.verifying_key()).collect();

        let messages: [&[u8]; 3] = [b"alpha", b"beta", b"gamma"];
        let mut signatures: Vec<Signature> = signing_keys
            .iter()
            .zip(messages.iter())
            .map(|(sk, msg)| sk.sign(msg))
            .collect();

        // Tamper the second signature
        let mut tampered_bytes = signatures[1].to_bytes();
        tampered_bytes[0] ^= 0xff;
        signatures[1] = Signature::from_bytes(&tampered_bytes);

        let msg_refs: Vec<&[u8]> = messages.to_vec();
        let result = ed25519_verify_batch(&msg_refs, &signatures, &verifying_keys);
        assert!(
            result.is_err(),
            "batch verify with tampered sig should fail"
        );
    }

    #[test]
    fn ed25519_batch_verify_empty() {
        let result = ed25519_verify_batch(&[], &[], &[]);
        assert!(result.is_ok(), "empty batch should succeed");
    }

    #[test]
    fn ed25519_batch_verify_mismatched_lengths() {
        let seed = [0x99u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        use ed25519_dalek::Signer as DalekSigner;
        let sig = sk.sign(b"test");
        let vk = sk.verifying_key();

        // messages.len() != signatures.len()
        let result = ed25519_verify_batch(&[b"test", b"extra"], &[sig], &[vk]);
        assert_eq!(result, Err(CryptoError::BadInput));
    }
}
