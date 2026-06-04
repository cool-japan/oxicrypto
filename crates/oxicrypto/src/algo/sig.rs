//! Signature algorithm selector enum + factory functions.

use crate::CryptoError;

/// Signature algorithm selector.
///
/// For the trait-dispatched `Signer`/`Verifier` factory functions,
/// each variant specifies the key format expected:
/// - Ed25519/Ed448: raw seed bytes
/// - ECDSA: raw scalar bytes (signing) / SEC1-encoded public key (verifying)
/// - RSA: DER PKCS#8 (signing) / DER SPKI (verifying)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SigAlgo {
    /// Ed25519 (32-byte key, 64-byte signature).
    Ed25519,
    /// Ed448 (57-byte key, 114-byte signature).
    Ed448,
    /// ECDSA P-256 with SHA-256 (32-byte scalar, DER signature).
    EcdsaP256,
    /// ECDSA P-384 with SHA-384 (48-byte scalar, DER signature).
    EcdsaP384,
    /// ECDSA P-521 with SHA-512 (66-byte scalar, DER signature).
    EcdsaP521,
    /// RSA PKCS#1 v1.5 with SHA-256.
    RsaPkcs1v15Sha256,
    /// RSA PKCS#1 v1.5 with SHA-384.
    RsaPkcs1v15Sha384,
    /// RSA PKCS#1 v1.5 with SHA-512.
    RsaPkcs1v15Sha512,
    /// RSA-PSS with SHA-256.
    RsaPssSha256,
    /// RSA-PSS with SHA-384.
    RsaPssSha384,
    /// RSA-PSS with SHA-512.
    RsaPssSha512,
    /// Schnorr signatures over secp256k1 per BIP-340 (32-byte secret key,
    /// 32-byte x-only public key, 64-byte signature). The message is signed
    /// directly (no pre-hashing); the same type provides both signing and
    /// verification.
    SchnorrBip340,
}

/// Return a boxed [`oxicrypto_core::Signer`] implementation for `algo`.
///
/// The returned signer expects raw key bytes in the format appropriate for the
/// algorithm -- see [`SigAlgo`] for details.
#[cfg(feature = "pure")]
#[must_use]
#[inline(always)]
pub fn signer_impl(algo: SigAlgo) -> oxicrypto_core::Box<dyn oxicrypto_core::Signer + Send + Sync> {
    match algo {
        SigAlgo::Ed25519 => oxicrypto_core::Box::new(oxicrypto_sig::Ed25519),
        SigAlgo::Ed448 => oxicrypto_core::Box::new(oxicrypto_sig::Ed448),
        SigAlgo::EcdsaP256 => oxicrypto_core::Box::new(oxicrypto_sig::EcdsaP256),
        SigAlgo::EcdsaP384 => oxicrypto_core::Box::new(oxicrypto_sig::EcdsaP384),
        SigAlgo::EcdsaP521 => oxicrypto_core::Box::new(oxicrypto_sig::EcdsaP521),
        SigAlgo::RsaPkcs1v15Sha256 => oxicrypto_core::Box::new(oxicrypto_sig::RsaPkcs1v15Sha256),
        SigAlgo::RsaPkcs1v15Sha384 => oxicrypto_core::Box::new(oxicrypto_sig::RsaPkcs1v15Sha384),
        SigAlgo::RsaPkcs1v15Sha512 => oxicrypto_core::Box::new(oxicrypto_sig::RsaPkcs1v15Sha512),
        SigAlgo::RsaPssSha256 => oxicrypto_core::Box::new(oxicrypto_sig::RsaPssSha256),
        SigAlgo::RsaPssSha384 => oxicrypto_core::Box::new(oxicrypto_sig::RsaPssSha384),
        SigAlgo::RsaPssSha512 => oxicrypto_core::Box::new(oxicrypto_sig::RsaPssSha512),
        SigAlgo::SchnorrBip340 => oxicrypto_core::Box::new(oxicrypto_sig::SchnorrBip340),
    }
}

/// Return a boxed [`oxicrypto_core::Verifier`] implementation for `algo`.
#[cfg(feature = "pure")]
#[must_use]
#[inline(always)]
pub fn verifier_impl(
    algo: SigAlgo,
) -> oxicrypto_core::Box<dyn oxicrypto_core::Verifier + Send + Sync> {
    match algo {
        SigAlgo::Ed25519 => oxicrypto_core::Box::new(oxicrypto_sig::Ed25519Verifier),
        SigAlgo::Ed448 => oxicrypto_core::Box::new(oxicrypto_sig::Ed448Verify),
        SigAlgo::EcdsaP256 => oxicrypto_core::Box::new(oxicrypto_sig::EcdsaP256Verify),
        SigAlgo::EcdsaP384 => oxicrypto_core::Box::new(oxicrypto_sig::EcdsaP384Verify),
        SigAlgo::EcdsaP521 => oxicrypto_core::Box::new(oxicrypto_sig::EcdsaP521Verify),
        SigAlgo::RsaPkcs1v15Sha256 => {
            oxicrypto_core::Box::new(oxicrypto_sig::RsaPkcs1v15Sha256Verify)
        }
        SigAlgo::RsaPkcs1v15Sha384 => {
            oxicrypto_core::Box::new(oxicrypto_sig::RsaPkcs1v15Sha384Verify)
        }
        SigAlgo::RsaPkcs1v15Sha512 => {
            oxicrypto_core::Box::new(oxicrypto_sig::RsaPkcs1v15Sha512Verify)
        }
        SigAlgo::RsaPssSha256 => oxicrypto_core::Box::new(oxicrypto_sig::RsaPssSha256Verify),
        SigAlgo::RsaPssSha384 => oxicrypto_core::Box::new(oxicrypto_sig::RsaPssSha384Verify),
        SigAlgo::RsaPssSha512 => oxicrypto_core::Box::new(oxicrypto_sig::RsaPssSha512Verify),
        SigAlgo::SchnorrBip340 => oxicrypto_core::Box::new(oxicrypto_sig::SchnorrBip340),
    }
}

// ── Display ───────────────────────────────────────────────────────────────────

impl core::fmt::Display for SigAlgo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            SigAlgo::Ed25519 => "Ed25519",
            SigAlgo::Ed448 => "Ed448",
            SigAlgo::EcdsaP256 => "ECDSA-P256",
            SigAlgo::EcdsaP384 => "ECDSA-P384",
            SigAlgo::EcdsaP521 => "ECDSA-P521",
            SigAlgo::RsaPkcs1v15Sha256 => "RSA-PKCS1v15-SHA-256",
            SigAlgo::RsaPkcs1v15Sha384 => "RSA-PKCS1v15-SHA-384",
            SigAlgo::RsaPkcs1v15Sha512 => "RSA-PKCS1v15-SHA-512",
            SigAlgo::RsaPssSha256 => "RSA-PSS-SHA-256",
            SigAlgo::RsaPssSha384 => "RSA-PSS-SHA-384",
            SigAlgo::RsaPssSha512 => "RSA-PSS-SHA-512",
            SigAlgo::SchnorrBip340 => "Schnorr-BIP340",
        })
    }
}

// ── FromStr ───────────────────────────────────────────────────────────────────

impl core::str::FromStr for SigAlgo {
    type Err = CryptoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Ed25519" | "ed25519" | "ED25519" => Ok(SigAlgo::Ed25519),
            "Ed448" | "ed448" | "ED448" => Ok(SigAlgo::Ed448),
            "ECDSA-P256" | "ecdsa-p256" | "ECDSAP256" => Ok(SigAlgo::EcdsaP256),
            "ECDSA-P384" | "ecdsa-p384" | "ECDSAP384" => Ok(SigAlgo::EcdsaP384),
            "ECDSA-P521" | "ecdsa-p521" | "ECDSAP521" => Ok(SigAlgo::EcdsaP521),
            "RSA-PKCS1v15-SHA-256" | "rsa-pkcs1v15-sha-256" => Ok(SigAlgo::RsaPkcs1v15Sha256),
            "RSA-PKCS1v15-SHA-384" | "rsa-pkcs1v15-sha-384" => Ok(SigAlgo::RsaPkcs1v15Sha384),
            "RSA-PKCS1v15-SHA-512" | "rsa-pkcs1v15-sha-512" => Ok(SigAlgo::RsaPkcs1v15Sha512),
            "RSA-PSS-SHA-256" | "rsa-pss-sha-256" => Ok(SigAlgo::RsaPssSha256),
            "RSA-PSS-SHA-384" | "rsa-pss-sha-384" => Ok(SigAlgo::RsaPssSha384),
            "RSA-PSS-SHA-512" | "rsa-pss-sha-512" => Ok(SigAlgo::RsaPssSha512),
            "Schnorr-BIP340" | "schnorr-bip340" | "bip340" => Ok(SigAlgo::SchnorrBip340),
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }
}

// ── TryFrom<&str> ─────────────────────────────────────────────────────────────

impl TryFrom<&str> for SigAlgo {
    type Error = CryptoError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}
