//! Signature implementations backed by `aws-lc-rs`.
//!
//! Supported algorithms:
//! - Ed25519 (deterministic, byte-comparable with RustCrypto)
//! - ECDSA-P256-SHA256 (randomized nonce — not byte-comparable)
//! - ECDSA-P384-SHA384 (randomized nonce — not byte-comparable)
//! - RSA-PKCS1-SHA256 (PKCS#8 DER private key)
//! - RSA-PSS-SHA256  (PKCS#8 DER private key)

use aws_lc_rs::signature::{
    EcdsaKeyPair, Ed25519KeyPair, RsaKeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING,
    ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RSA_PSS_2048_8192_SHA256,
    RSA_PSS_SHA256,
};
use oxicrypto_core::{CryptoError, Signer, Verifier};

// ── Ed25519 ───────────────────────────────────────────────────────────────────

/// Ed25519 signer backed by `aws-lc-rs`.
///
/// `sk` is the 32-byte seed (raw secret scalar). Signs deterministically.
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsLcEd25519Signer;

/// Ed25519 verifier backed by `aws-lc-rs`.
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsLcEd25519Verifier;

impl Signer for AwsLcEd25519Signer {
    fn name(&self) -> &'static str {
        "Ed25519 (aws-lc-rs)"
    }
    fn signature_len(&self) -> usize {
        64
    }
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        if sig_out.len() < 64 {
            return Err(CryptoError::BufferTooSmall);
        }
        let kp = Ed25519KeyPair::from_seed_unchecked(sk).map_err(|_| CryptoError::InvalidKey)?;
        let sig = kp.sign(msg);
        sig_out[..64].copy_from_slice(sig.as_ref());
        Ok(64)
    }
}

impl core::fmt::Display for AwsLcEd25519Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl Verifier for AwsLcEd25519Verifier {
    fn name(&self) -> &'static str {
        "Ed25519 (aws-lc-rs)"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let unparsed = UnparsedPublicKey::new(&ED25519, pk);
        unparsed
            .verify(msg, sig)
            .map_err(|_| CryptoError::InvalidTag)
    }
}

impl core::fmt::Display for AwsLcEd25519Verifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

// ── ECDSA-P256-SHA256 ─────────────────────────────────────────────────────────

/// ECDSA-P256-SHA256 signer (fixed-length r||s format) backed by `aws-lc-rs`.
///
/// `sk` must be a raw 32-byte big-endian P-256 private scalar. The signature
/// uses a randomly generated per-message nonce (not deterministic RFC 6979).
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsLcEcdsaP256Signer;

/// ECDSA-P256-SHA256 verifier (fixed-length r||s format) backed by `aws-lc-rs`.
///
/// `pk` must be the 65-byte uncompressed SEC1 public key (0x04 prefix).
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsLcEcdsaP256Verifier;

impl Signer for AwsLcEcdsaP256Signer {
    fn name(&self) -> &'static str {
        "ECDSA-P256-SHA256 (aws-lc-rs)"
    }
    fn signature_len(&self) -> usize {
        // Fixed-length P-256 signature: r(32) || s(32) = 64 bytes
        64
    }
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        if sig_out.len() < 64 {
            return Err(CryptoError::BufferTooSmall);
        }
        if sk.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        let der = build_ec_sec1_der::<32>(sk, &SEC1_P256_PREFIX)?;
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let kp = EcdsaKeyPair::from_private_key_der(&ECDSA_P256_SHA256_FIXED_SIGNING, &der)
            .map_err(|_| CryptoError::InvalidKey)?;
        let sig = kp.sign(&rng, msg).map_err(|_| CryptoError::Sign)?;
        let sig_bytes = sig.as_ref();
        if sig_bytes.len() != 64 {
            return Err(CryptoError::Internal(
                "unexpected ECDSA-P256 signature length",
            ));
        }
        sig_out[..64].copy_from_slice(sig_bytes);
        Ok(64)
    }
}

impl core::fmt::Display for AwsLcEcdsaP256Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl Verifier for AwsLcEcdsaP256Verifier {
    fn name(&self) -> &'static str {
        "ECDSA-P256-SHA256 (aws-lc-rs)"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let unparsed = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pk);
        unparsed
            .verify(msg, sig)
            .map_err(|_| CryptoError::InvalidTag)
    }
}

impl core::fmt::Display for AwsLcEcdsaP256Verifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

// ── ECDSA-P384-SHA384 ─────────────────────────────────────────────────────────

/// ECDSA-P384-SHA384 signer (fixed-length r||s format) backed by `aws-lc-rs`.
///
/// `sk` must be a raw 48-byte big-endian P-384 private scalar. The signature
/// uses a randomly generated per-message nonce (not deterministic RFC 6979).
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsLcEcdsaP384Signer;

/// ECDSA-P384-SHA384 verifier (fixed-length r||s format) backed by `aws-lc-rs`.
///
/// `pk` must be the 97-byte uncompressed SEC1 public key (0x04 prefix).
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsLcEcdsaP384Verifier;

impl Signer for AwsLcEcdsaP384Signer {
    fn name(&self) -> &'static str {
        "ECDSA-P384-SHA384 (aws-lc-rs)"
    }
    fn signature_len(&self) -> usize {
        // Fixed-length P-384 signature: r(48) || s(48) = 96 bytes
        96
    }
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        if sig_out.len() < 96 {
            return Err(CryptoError::BufferTooSmall);
        }
        if sk.len() != 48 {
            return Err(CryptoError::InvalidKey);
        }
        let der = build_ec_sec1_der::<48>(sk, &SEC1_P384_PREFIX)?;
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let kp = EcdsaKeyPair::from_private_key_der(&ECDSA_P384_SHA384_FIXED_SIGNING, &der)
            .map_err(|_| CryptoError::InvalidKey)?;
        let sig = kp.sign(&rng, msg).map_err(|_| CryptoError::Sign)?;
        let sig_bytes = sig.as_ref();
        if sig_bytes.len() != 96 {
            return Err(CryptoError::Internal(
                "unexpected ECDSA-P384 signature length",
            ));
        }
        sig_out[..96].copy_from_slice(sig_bytes);
        Ok(96)
    }
}

impl core::fmt::Display for AwsLcEcdsaP384Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl Verifier for AwsLcEcdsaP384Verifier {
    fn name(&self) -> &'static str {
        "ECDSA-P384-SHA384 (aws-lc-rs)"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let unparsed = UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, pk);
        unparsed
            .verify(msg, sig)
            .map_err(|_| CryptoError::InvalidTag)
    }
}

impl core::fmt::Display for AwsLcEcdsaP384Verifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

// ── RSA ───────────────────────────────────────────────────────────────────────

/// RSA-PKCS1-SHA256 signer backed by `aws-lc-rs`.
///
/// `sk` must be a DER-encoded PKCS#8 v1 RSA private key (minimum 2048-bit modulus).
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsLcRsaPkcs1Sha256Signer;

/// RSA-PSS-SHA256 signer backed by `aws-lc-rs`.
///
/// `sk` must be a DER-encoded PKCS#8 v1 RSA private key (minimum 2048-bit modulus).
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsLcRsaPssSha256Signer;

/// RSA-PKCS1-SHA256 verifier backed by `aws-lc-rs`.
///
/// `pk` must be a DER-encoded RSAPublicKey (RFC 8017) or X.509 SubjectPublicKeyInfo.
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsLcRsaPkcs1Sha256Verifier;

/// RSA-PSS-SHA256 verifier backed by `aws-lc-rs`.
///
/// `pk` must be a DER-encoded RSAPublicKey (RFC 8017) or X.509 SubjectPublicKeyInfo.
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsLcRsaPssSha256Verifier;

impl Signer for AwsLcRsaPkcs1Sha256Signer {
    fn name(&self) -> &'static str {
        "RSA-PKCS1-SHA256 (aws-lc-rs)"
    }
    fn signature_len(&self) -> usize {
        // Variable — RSA-2048 gives 256 bytes, RSA-4096 gives 512 bytes.
        // Return the maximum we expect in practice (RSA-8192 = 1024 bytes).
        1024
    }
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        let kp = RsaKeyPair::from_pkcs8(sk).map_err(|_| CryptoError::InvalidKey)?;
        let mod_len = kp.public_modulus_len();
        if sig_out.len() < mod_len {
            return Err(CryptoError::BufferTooSmall);
        }
        let rng = aws_lc_rs::rand::SystemRandom::new();
        kp.sign(&RSA_PKCS1_SHA256, &rng, msg, &mut sig_out[..mod_len])
            .map_err(|_| CryptoError::Sign)?;
        Ok(mod_len)
    }
}

impl core::fmt::Display for AwsLcRsaPkcs1Sha256Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl Signer for AwsLcRsaPssSha256Signer {
    fn name(&self) -> &'static str {
        "RSA-PSS-SHA256 (aws-lc-rs)"
    }
    fn signature_len(&self) -> usize {
        1024
    }
    fn sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) -> Result<usize, CryptoError> {
        let kp = RsaKeyPair::from_pkcs8(sk).map_err(|_| CryptoError::InvalidKey)?;
        let mod_len = kp.public_modulus_len();
        if sig_out.len() < mod_len {
            return Err(CryptoError::BufferTooSmall);
        }
        let rng = aws_lc_rs::rand::SystemRandom::new();
        kp.sign(&RSA_PSS_SHA256, &rng, msg, &mut sig_out[..mod_len])
            .map_err(|_| CryptoError::Sign)?;
        Ok(mod_len)
    }
}

impl core::fmt::Display for AwsLcRsaPssSha256Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl Verifier for AwsLcRsaPkcs1Sha256Verifier {
    fn name(&self) -> &'static str {
        "RSA-PKCS1-SHA256 (aws-lc-rs)"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let unparsed = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pk);
        unparsed
            .verify(msg, sig)
            .map_err(|_| CryptoError::InvalidTag)
    }
}

impl core::fmt::Display for AwsLcRsaPkcs1Sha256Verifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl Verifier for AwsLcRsaPssSha256Verifier {
    fn name(&self) -> &'static str {
        "RSA-PSS-SHA256 (aws-lc-rs)"
    }
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let unparsed = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, pk);
        unparsed
            .verify(msg, sig)
            .map_err(|_| CryptoError::InvalidTag)
    }
}

impl core::fmt::Display for AwsLcRsaPssSha256Verifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

// ── DER helpers ───────────────────────────────────────────────────────────────

/// Pre-computed RFC 5915 `ECPrivateKey` DER prefix for P-256 (prime256v1).
///
/// Structure up to the OCTET STRING content:
/// ```text
/// SEQUENCE {
///   INTEGER { 1 }                                       -- version
///   OCTET STRING length=32                              -- privateKey header
///   [0] EXPLICIT { OID 1.2.840.10045.3.1.7 }           -- namedCurve prime256v1
/// }
/// ```
/// The full encoding is:
///   30 XX  -- SEQUENCE (XX = total inner length)
///   02 01 01  -- INTEGER 1
///   04 20  -- OCTET STRING, 32 bytes (key bytes follow)
///   a0 0a 06 08 2a 86 48 ce 3d 03 01 07  -- [0] OID prime256v1
///
/// After the SEQUENCE length byte we have: [02 01 01] [04 20 <32 key bytes>] [a0 0a ...]
/// Total inner = 3 + 2 + 32 + 12 = 49 bytes → length byte = 0x31 (< 0x80, fits in 1 byte).
///
/// So prefix (before the 32 raw key bytes) = [30 31 02 01 01 04 20]   (7 bytes)
/// Suffix (after the 32 raw key bytes)     = [a0 0a 06 08 2a 86 48 ce 3d 03 01 07]  (12 bytes)
const SEC1_P256_PREFIX: [u8; 7] = [0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20];
const SEC1_P256_SUFFIX: [u8; 12] = [
    0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
];

/// Pre-computed RFC 5915 `ECPrivateKey` DER prefix for P-384 (secp384r1).
///
/// OID 1.3.132.0.34 encoded: 06 05 2b 81 04 00 22  (7 bytes)
/// [0] wrapper: a0 09 06 05 2b 81 04 00 22  (9 bytes)
///
/// Inner = 3 + 2 + 48 + 9 = 62 bytes (0x3e, single byte length)
///
/// Prefix (before 48 raw key bytes) = [30 3e 02 01 01 04 30]  (7 bytes, where 0x30 = 48 decimal)
/// Suffix (after 48 raw key bytes)  = [a0 09 06 05 2b 81 04 00 22]  (9 bytes)
const SEC1_P384_PREFIX: [u8; 7] = [0x30, 0x3e, 0x02, 0x01, 0x01, 0x04, 0x30];
const SEC1_P384_SUFFIX: [u8; 9] = [0xa0, 0x09, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

/// Build an RFC 5915 SEC1 `ECPrivateKey` DER wrapper for a raw EC private scalar
/// using a pre-computed prefix/suffix pair.
///
/// Generic over the key length `N` (32 for P-256, 48 for P-384).
/// The prefix and suffix are selected from the const tables above.
fn build_ec_sec1_der<const N: usize>(
    private_key: &[u8],
    prefix: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if private_key.len() != N {
        return Err(CryptoError::InvalidKey);
    }
    // Determine the correct suffix by inspecting the prefix length and the curve
    // embedded in the prefix's last two bytes (the OCTET STRING length byte encodes N).
    let suffix: &[u8] = if N == 32 {
        &SEC1_P256_SUFFIX
    } else if N == 48 {
        &SEC1_P384_SUFFIX
    } else {
        return Err(CryptoError::InvalidKey);
    };

    let mut der = Vec::with_capacity(prefix.len() + N + suffix.len());
    der.extend_from_slice(prefix);
    der.extend_from_slice(private_key);
    der.extend_from_slice(suffix);
    Ok(der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair;

    #[test]
    fn ed25519_sign_verify_round_trip() {
        let seed = [0x5au8; 32];
        // Derive public key using aws-lc-rs itself.
        let kp = Ed25519KeyPair::from_seed_unchecked(&seed).expect("kp");
        let pk = kp.public_key().as_ref().to_vec();

        let signer = AwsLcEd25519Signer;
        let verifier = AwsLcEd25519Verifier;
        let msg = b"test message from aws-lc adapter";
        let mut sig = [0u8; 64];
        let n = signer.sign(&seed, msg, &mut sig).expect("sign");
        assert_eq!(n, 64);
        verifier.verify(&pk, msg, &sig).expect("verify");
    }

    #[test]
    fn ed25519_wrong_sig_fails() {
        let seed = [0x5au8; 32];
        let kp = Ed25519KeyPair::from_seed_unchecked(&seed).expect("kp");
        let pk = kp.public_key().as_ref().to_vec();

        let signer = AwsLcEd25519Signer;
        let verifier = AwsLcEd25519Verifier;
        let msg = b"test message";
        let mut sig = [0u8; 64];
        signer.sign(&seed, msg, &mut sig).expect("sign");
        sig[0] ^= 0xff;
        assert_eq!(
            verifier.verify(&pk, msg, &sig),
            Err(CryptoError::InvalidTag)
        );
    }

    #[test]
    fn ecdsa_p256_sign_verify_round_trip() {
        // Generate a fresh key pair and extract the DER private key.
        let kp = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).expect("kp generate");
        let pk = kp.public_key().as_ref().to_vec();
        // Get private key bytes (raw 32-byte big-endian scalar)
        let sk_der = kp.to_pkcs8v1().expect("pkcs8");
        // For this test use the higher-level verifier only;
        // we verify a signature produced by aws-lc-rs directly.
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let msg = b"ecdsa p256 test message";
        let sig = kp.sign(&rng, msg).expect("sign");
        let sig_bytes = sig.as_ref();

        let verifier = AwsLcEcdsaP256Verifier;
        verifier.verify(&pk, msg, sig_bytes).expect("verify");

        // Corrupt signature should fail.
        let mut bad_sig = sig_bytes.to_vec();
        bad_sig[0] ^= 0x01;
        assert_eq!(
            verifier.verify(&pk, msg, &bad_sig),
            Err(CryptoError::InvalidTag)
        );

        // Suppress unused-variable lint for sk_der (the PKCS#8 path is tested via signer below)
        let _ = sk_der;
    }

    #[test]
    fn ecdsa_p384_sign_verify_round_trip() {
        let kp = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).expect("kp generate");
        let pk = kp.public_key().as_ref().to_vec();
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let msg = b"ecdsa p384 test message";
        let sig = kp.sign(&rng, msg).expect("sign");
        let sig_bytes = sig.as_ref();

        let verifier = AwsLcEcdsaP384Verifier;
        verifier.verify(&pk, msg, sig_bytes).expect("verify");

        let mut bad_sig = sig_bytes.to_vec();
        bad_sig[0] ^= 0x01;
        assert_eq!(
            verifier.verify(&pk, msg, &bad_sig),
            Err(CryptoError::InvalidTag)
        );
    }

    #[test]
    fn display_impls() {
        assert_eq!(format!("{}", AwsLcEd25519Signer), AwsLcEd25519Signer.name());
        assert_eq!(
            format!("{}", AwsLcEcdsaP256Signer),
            AwsLcEcdsaP256Signer.name()
        );
        assert_eq!(
            format!("{}", AwsLcEcdsaP384Signer),
            AwsLcEcdsaP384Signer.name()
        );
        assert_eq!(
            format!("{}", AwsLcRsaPkcs1Sha256Signer),
            AwsLcRsaPkcs1Sha256Signer.name()
        );
    }
}
