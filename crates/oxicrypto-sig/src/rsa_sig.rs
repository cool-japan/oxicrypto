#![forbid(unsafe_code)]

//! RSA PKCS#1 v1.5, PSS, OAEP, and key generation for the OxiCrypto stack.
//!
//! Provides both signing and verifying types for:
//! - RSA-PKCS1v15 with SHA-256, SHA-384, SHA-512
//! - RSA-PSS with SHA-256, SHA-384, SHA-512
//! - RSA-OAEP encryption/decryption with SHA-256
//! - RSA key pair generation
//!
//! Keys are imported via DER-encoded bytes (PKCS#8 for private keys, SubjectPublicKeyInfo
//! for public keys) using the `rsa::pkcs8` encoding traits.
//!
//! # Randomness
//!
//! Signing and OAEP encryption use `getrandom::SysRng` (OS entropy) for blinding factors.
//! RSA key generation uses `rand_core::UnwrapErr(SysRng)` to bridge `TryCryptoRng` →
//! `CryptoRng` (panics on getrandom failure, which is fatal in any real environment).

use getrandom::SysRng;
use oxicrypto_core::{CryptoError, Vec};
use rand_core::UnwrapErr;
use rsa::oaep;
use rsa::pkcs1v15;
use rsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rsa::pss;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier as RsaVerifierTrait};
use rsa::traits::{Decryptor, RandomizedEncryptor};
use sha2::{Sha256, Sha384, Sha512};

/// Shared helper: import `RsaPrivateKey` from PKCS#1 DER bytes.
fn rsa_private_key_from_pkcs1_der(der: &[u8]) -> Result<rsa::RsaPrivateKey, CryptoError> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    rsa::RsaPrivateKey::from_pkcs1_der(der).map_err(|_| CryptoError::InvalidKey)
}

/// Shared helper: export `RsaPrivateKey` to PKCS#1 DER bytes.
fn rsa_private_key_to_pkcs1_der(key: &rsa::RsaPrivateKey) -> Result<Vec<u8>, CryptoError> {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    let doc = key.to_pkcs1_der().map_err(|_| CryptoError::InvalidKey)?;
    Ok(doc.as_bytes().to_vec())
}

/// Shared helper: import `RsaPrivateKey` from PKCS#8 PEM string.
fn rsa_private_key_from_pkcs8_pem(pem: &str) -> Result<rsa::RsaPrivateKey, CryptoError> {
    rsa::RsaPrivateKey::from_pkcs8_pem(pem).map_err(|_| CryptoError::InvalidKey)
}

/// Shared helper: export `RsaPrivateKey` to PKCS#8 PEM string.
fn rsa_private_key_to_pkcs8_pem(key: &rsa::RsaPrivateKey) -> Result<String, CryptoError> {
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(pem.to_string())
}

/// Shared helper: import `RsaPrivateKey` from PKCS#1 PEM string.
fn rsa_private_key_from_pkcs1_pem(pem: &str) -> Result<rsa::RsaPrivateKey, CryptoError> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    rsa::RsaPrivateKey::from_pkcs1_pem(pem).map_err(|_| CryptoError::InvalidKey)
}

/// Shared helper: import `RsaPublicKey` from PKCS#1 DER bytes.
fn rsa_public_key_from_pkcs1_der(der: &[u8]) -> Result<rsa::RsaPublicKey, CryptoError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    rsa::RsaPublicKey::from_pkcs1_der(der).map_err(|_| CryptoError::InvalidKey)
}

/// Shared helper: export `RsaPublicKey` to PKCS#1 DER bytes.
fn rsa_public_key_to_pkcs1_der(key: &rsa::RsaPublicKey) -> Result<Vec<u8>, CryptoError> {
    use rsa::pkcs1::EncodeRsaPublicKey;
    let doc = key.to_pkcs1_der().map_err(|_| CryptoError::InvalidKey)?;
    Ok(doc.as_bytes().to_vec())
}

/// Shared helper: import `RsaPublicKey` from SPKI PEM string.
fn rsa_public_key_from_spki_pem(pem: &str) -> Result<rsa::RsaPublicKey, CryptoError> {
    rsa::RsaPublicKey::from_public_key_pem(pem).map_err(|_| CryptoError::InvalidKey)
}

/// Shared helper: export `RsaPublicKey` to SPKI PEM string.
fn rsa_public_key_to_spki_pem(key: &rsa::RsaPublicKey) -> Result<String, CryptoError> {
    let pem = key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(pem)
}

/// Shared helper: import `RsaPublicKey` from PKCS#1 PEM string.
fn rsa_public_key_from_pkcs1_pem(pem: &str) -> Result<rsa::RsaPublicKey, CryptoError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    rsa::RsaPublicKey::from_pkcs1_pem(pem).map_err(|_| CryptoError::InvalidKey)
}

// ── RSA PKCS#1v15 SHA-256 ──────────────────────────────────────────────────

/// RSA PKCS#1 v1.5 signing key parameterised with SHA-256.
///
/// Import via DER-encoded PKCS#8 private key bytes.
pub struct RsaPkcs1v15Sha256Signer {
    signing_key: pkcs1v15::SigningKey<Sha256>,
}

impl RsaPkcs1v15Sha256Signer {
    /// Construct from DER-encoded PKCS#8 private key bytes.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        let private_key =
            rsa::RsaPrivateKey::from_pkcs8_der(der).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            signing_key: pkcs1v15::SigningKey::<Sha256>::new(private_key),
        })
    }

    /// Construct from a PKCS#8 PEM string (e.g. `"-----BEGIN PRIVATE KEY-----\n..."`).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs8_pem(pem)?;
        Ok(Self {
            signing_key: pkcs1v15::SigningKey::<Sha256>::new(sk),
        })
    }

    /// Export as PKCS#8 PEM string.
    pub fn to_pkcs8_pem(&self) -> Result<String, CryptoError> {
        rsa_private_key_to_pkcs8_pem(self.signing_key.as_ref())
    }

    /// Construct from PKCS#1 DER bytes (traditional `RSAPrivateKey` format).
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs1_der(der)?;
        Ok(Self {
            signing_key: pkcs1v15::SigningKey::<Sha256>::new(sk),
        })
    }

    /// Export as PKCS#1 DER bytes.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, CryptoError> {
        rsa_private_key_to_pkcs1_der(self.signing_key.as_ref())
    }

    /// Construct from a PKCS#1 PEM string (e.g. `"-----BEGIN RSA PRIVATE KEY-----\n..."`).
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs1_pem(pem)?;
        Ok(Self {
            signing_key: pkcs1v15::SigningKey::<Sha256>::new(sk),
        })
    }

    /// Sign `message` and return the signature bytes.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut rng = SysRng;
        let sig = RandomizedSigner::try_sign_with_rng(&self.signing_key, &mut rng, message)
            .map_err(|_| CryptoError::Internal("RSA PKCS1v15-SHA256 sign failed"))?;
        Ok(sig.to_bytes().into_vec())
    }
}

/// RSA PKCS#1 v1.5 verifying key parameterised with SHA-256.
pub struct RsaPkcs1v15Sha256Verifier {
    verifying_key: pkcs1v15::VerifyingKey<Sha256>,
}

impl RsaPkcs1v15Sha256Verifier {
    /// Construct from DER-encoded SubjectPublicKeyInfo bytes.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, CryptoError> {
        let public_key =
            rsa::RsaPublicKey::from_public_key_der(der).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            verifying_key: pkcs1v15::VerifyingKey::<Sha256>::new(public_key),
        })
    }

    /// Construct from a SPKI PEM string.
    pub fn from_spki_pem(pem: &str) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_spki_pem(pem)?;
        Ok(Self {
            verifying_key: pkcs1v15::VerifyingKey::<Sha256>::new(pk),
        })
    }

    /// Export as SPKI PEM string.
    pub fn to_spki_pem(&self) -> Result<String, CryptoError> {
        rsa_public_key_to_spki_pem(self.verifying_key.as_ref())
    }

    /// Construct from PKCS#1 DER bytes.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_pkcs1_der(der)?;
        Ok(Self {
            verifying_key: pkcs1v15::VerifyingKey::<Sha256>::new(pk),
        })
    }

    /// Export as PKCS#1 DER bytes.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, CryptoError> {
        rsa_public_key_to_pkcs1_der(self.verifying_key.as_ref())
    }

    /// Construct from a PKCS#1 PEM string.
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_pkcs1_pem(pem)?;
        Ok(Self {
            verifying_key: pkcs1v15::VerifyingKey::<Sha256>::new(pk),
        })
    }

    /// Verify `signature` over `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig = pkcs1v15::Signature::try_from(signature).map_err(|_| CryptoError::InvalidTag)?;
        RsaVerifierTrait::verify(&self.verifying_key, message, &sig)
            .map_err(|_| CryptoError::InvalidTag)
    }
}

// ── RSA PKCS#1v15 SHA-384 ──────────────────────────────────────────────────

/// RSA PKCS#1 v1.5 signing key parameterised with SHA-384.
pub struct RsaPkcs1v15Sha384Signer {
    signing_key: pkcs1v15::SigningKey<Sha384>,
}

impl RsaPkcs1v15Sha384Signer {
    /// Construct from DER-encoded PKCS#8 private key bytes.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        let private_key =
            rsa::RsaPrivateKey::from_pkcs8_der(der).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            signing_key: pkcs1v15::SigningKey::<Sha384>::new(private_key),
        })
    }

    /// Construct from a PKCS#8 PEM string.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs8_pem(pem)?;
        Ok(Self {
            signing_key: pkcs1v15::SigningKey::<Sha384>::new(sk),
        })
    }

    /// Export as PKCS#8 PEM string.
    pub fn to_pkcs8_pem(&self) -> Result<String, CryptoError> {
        rsa_private_key_to_pkcs8_pem(self.signing_key.as_ref())
    }

    /// Construct from PKCS#1 DER bytes.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs1_der(der)?;
        Ok(Self {
            signing_key: pkcs1v15::SigningKey::<Sha384>::new(sk),
        })
    }

    /// Export as PKCS#1 DER bytes.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, CryptoError> {
        rsa_private_key_to_pkcs1_der(self.signing_key.as_ref())
    }

    /// Construct from a PKCS#1 PEM string.
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs1_pem(pem)?;
        Ok(Self {
            signing_key: pkcs1v15::SigningKey::<Sha384>::new(sk),
        })
    }

    /// Sign `message` and return the signature bytes.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut rng = SysRng;
        let sig = RandomizedSigner::try_sign_with_rng(&self.signing_key, &mut rng, message)
            .map_err(|_| CryptoError::Internal("RSA PKCS1v15-SHA384 sign failed"))?;
        Ok(sig.to_bytes().into_vec())
    }
}

/// RSA PKCS#1 v1.5 verifying key parameterised with SHA-384.
pub struct RsaPkcs1v15Sha384Verifier {
    verifying_key: pkcs1v15::VerifyingKey<Sha384>,
}

impl RsaPkcs1v15Sha384Verifier {
    /// Construct from DER-encoded SubjectPublicKeyInfo bytes.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, CryptoError> {
        let public_key =
            rsa::RsaPublicKey::from_public_key_der(der).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            verifying_key: pkcs1v15::VerifyingKey::<Sha384>::new(public_key),
        })
    }

    /// Construct from a SPKI PEM string.
    pub fn from_spki_pem(pem: &str) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_spki_pem(pem)?;
        Ok(Self {
            verifying_key: pkcs1v15::VerifyingKey::<Sha384>::new(pk),
        })
    }

    /// Export as SPKI PEM string.
    pub fn to_spki_pem(&self) -> Result<String, CryptoError> {
        rsa_public_key_to_spki_pem(self.verifying_key.as_ref())
    }

    /// Construct from PKCS#1 DER bytes.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_pkcs1_der(der)?;
        Ok(Self {
            verifying_key: pkcs1v15::VerifyingKey::<Sha384>::new(pk),
        })
    }

    /// Export as PKCS#1 DER bytes.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, CryptoError> {
        rsa_public_key_to_pkcs1_der(self.verifying_key.as_ref())
    }

    /// Construct from a PKCS#1 PEM string.
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_pkcs1_pem(pem)?;
        Ok(Self {
            verifying_key: pkcs1v15::VerifyingKey::<Sha384>::new(pk),
        })
    }

    /// Verify `signature` over `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig = pkcs1v15::Signature::try_from(signature).map_err(|_| CryptoError::InvalidTag)?;
        RsaVerifierTrait::verify(&self.verifying_key, message, &sig)
            .map_err(|_| CryptoError::InvalidTag)
    }
}

// ── RSA PKCS#1v15 SHA-512 ──────────────────────────────────────────────────

/// RSA PKCS#1 v1.5 signing key parameterised with SHA-512.
pub struct RsaPkcs1v15Sha512Signer {
    signing_key: pkcs1v15::SigningKey<Sha512>,
}

impl RsaPkcs1v15Sha512Signer {
    /// Construct from DER-encoded PKCS#8 private key bytes.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        let private_key =
            rsa::RsaPrivateKey::from_pkcs8_der(der).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            signing_key: pkcs1v15::SigningKey::<Sha512>::new(private_key),
        })
    }

    /// Construct from a PKCS#8 PEM string.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs8_pem(pem)?;
        Ok(Self {
            signing_key: pkcs1v15::SigningKey::<Sha512>::new(sk),
        })
    }

    /// Export as PKCS#8 PEM string.
    pub fn to_pkcs8_pem(&self) -> Result<String, CryptoError> {
        rsa_private_key_to_pkcs8_pem(self.signing_key.as_ref())
    }

    /// Construct from PKCS#1 DER bytes.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs1_der(der)?;
        Ok(Self {
            signing_key: pkcs1v15::SigningKey::<Sha512>::new(sk),
        })
    }

    /// Export as PKCS#1 DER bytes.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, CryptoError> {
        rsa_private_key_to_pkcs1_der(self.signing_key.as_ref())
    }

    /// Construct from a PKCS#1 PEM string.
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs1_pem(pem)?;
        Ok(Self {
            signing_key: pkcs1v15::SigningKey::<Sha512>::new(sk),
        })
    }

    /// Sign `message` and return the signature bytes.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut rng = SysRng;
        let sig = RandomizedSigner::try_sign_with_rng(&self.signing_key, &mut rng, message)
            .map_err(|_| CryptoError::Internal("RSA PKCS1v15-SHA512 sign failed"))?;
        Ok(sig.to_bytes().into_vec())
    }
}

/// RSA PKCS#1 v1.5 verifying key parameterised with SHA-512.
pub struct RsaPkcs1v15Sha512Verifier {
    verifying_key: pkcs1v15::VerifyingKey<Sha512>,
}

impl RsaPkcs1v15Sha512Verifier {
    /// Construct from DER-encoded SubjectPublicKeyInfo bytes.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, CryptoError> {
        let public_key =
            rsa::RsaPublicKey::from_public_key_der(der).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            verifying_key: pkcs1v15::VerifyingKey::<Sha512>::new(public_key),
        })
    }

    /// Construct from a SPKI PEM string.
    pub fn from_spki_pem(pem: &str) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_spki_pem(pem)?;
        Ok(Self {
            verifying_key: pkcs1v15::VerifyingKey::<Sha512>::new(pk),
        })
    }

    /// Export as SPKI PEM string.
    pub fn to_spki_pem(&self) -> Result<String, CryptoError> {
        rsa_public_key_to_spki_pem(self.verifying_key.as_ref())
    }

    /// Construct from PKCS#1 DER bytes.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_pkcs1_der(der)?;
        Ok(Self {
            verifying_key: pkcs1v15::VerifyingKey::<Sha512>::new(pk),
        })
    }

    /// Export as PKCS#1 DER bytes.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, CryptoError> {
        rsa_public_key_to_pkcs1_der(self.verifying_key.as_ref())
    }

    /// Construct from a PKCS#1 PEM string.
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_pkcs1_pem(pem)?;
        Ok(Self {
            verifying_key: pkcs1v15::VerifyingKey::<Sha512>::new(pk),
        })
    }

    /// Verify `signature` over `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig = pkcs1v15::Signature::try_from(signature).map_err(|_| CryptoError::InvalidTag)?;
        RsaVerifierTrait::verify(&self.verifying_key, message, &sig)
            .map_err(|_| CryptoError::InvalidTag)
    }
}

// ── RSA-PSS SHA-256 ────────────────────────────────────────────────────────

/// RSA-PSS signing key parameterised with SHA-256.
pub struct RsaPssSha256Signer {
    signing_key: pss::SigningKey<Sha256>,
}

impl RsaPssSha256Signer {
    /// Construct from DER-encoded PKCS#8 private key bytes.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        let private_key =
            rsa::RsaPrivateKey::from_pkcs8_der(der).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            signing_key: pss::SigningKey::<Sha256>::new(private_key),
        })
    }

    /// Construct from a PKCS#8 PEM string.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs8_pem(pem)?;
        Ok(Self {
            signing_key: pss::SigningKey::<Sha256>::new(sk),
        })
    }

    /// Export as PKCS#8 PEM string.
    pub fn to_pkcs8_pem(&self) -> Result<String, CryptoError> {
        rsa_private_key_to_pkcs8_pem(self.signing_key.as_ref())
    }

    /// Construct from PKCS#1 DER bytes.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs1_der(der)?;
        Ok(Self {
            signing_key: pss::SigningKey::<Sha256>::new(sk),
        })
    }

    /// Export as PKCS#1 DER bytes.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, CryptoError> {
        rsa_private_key_to_pkcs1_der(self.signing_key.as_ref())
    }

    /// Construct from a PKCS#1 PEM string.
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs1_pem(pem)?;
        Ok(Self {
            signing_key: pss::SigningKey::<Sha256>::new(sk),
        })
    }

    /// Sign `message` and return the signature bytes.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut rng = SysRng;
        let sig = RandomizedSigner::try_sign_with_rng(&self.signing_key, &mut rng, message)
            .map_err(|_| CryptoError::Internal("RSA-PSS sign failed"))?;
        Ok(sig.to_bytes().into_vec())
    }
}

/// RSA-PSS verifying key parameterised with SHA-256.
pub struct RsaPssSha256Verifier {
    verifying_key: pss::VerifyingKey<Sha256>,
}

impl RsaPssSha256Verifier {
    /// Construct from DER-encoded SubjectPublicKeyInfo bytes.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, CryptoError> {
        let public_key =
            rsa::RsaPublicKey::from_public_key_der(der).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            verifying_key: pss::VerifyingKey::<Sha256>::new(public_key),
        })
    }

    /// Construct from a SPKI PEM string.
    pub fn from_spki_pem(pem: &str) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_spki_pem(pem)?;
        Ok(Self {
            verifying_key: pss::VerifyingKey::<Sha256>::new(pk),
        })
    }

    /// Export as SPKI PEM string.
    pub fn to_spki_pem(&self) -> Result<String, CryptoError> {
        rsa_public_key_to_spki_pem(self.verifying_key.as_ref())
    }

    /// Construct from PKCS#1 DER bytes.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_pkcs1_der(der)?;
        Ok(Self {
            verifying_key: pss::VerifyingKey::<Sha256>::new(pk),
        })
    }

    /// Export as PKCS#1 DER bytes.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, CryptoError> {
        rsa_public_key_to_pkcs1_der(self.verifying_key.as_ref())
    }

    /// Construct from a PKCS#1 PEM string.
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_pkcs1_pem(pem)?;
        Ok(Self {
            verifying_key: pss::VerifyingKey::<Sha256>::new(pk),
        })
    }

    /// Verify `signature` over `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig = pss::Signature::try_from(signature).map_err(|_| CryptoError::InvalidTag)?;
        RsaVerifierTrait::verify(&self.verifying_key, message, &sig)
            .map_err(|_| CryptoError::InvalidTag)
    }
}

// ── RSA-PSS SHA-384 ────────────────────────────────────────────────────────

/// RSA-PSS signing key parameterised with SHA-384.
pub struct RsaPssSha384Signer {
    signing_key: pss::SigningKey<Sha384>,
}

impl RsaPssSha384Signer {
    /// Construct from DER-encoded PKCS#8 private key bytes.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        let private_key =
            rsa::RsaPrivateKey::from_pkcs8_der(der).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            signing_key: pss::SigningKey::<Sha384>::new(private_key),
        })
    }

    /// Construct from a PKCS#8 PEM string.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs8_pem(pem)?;
        Ok(Self {
            signing_key: pss::SigningKey::<Sha384>::new(sk),
        })
    }

    /// Export as PKCS#8 PEM string.
    pub fn to_pkcs8_pem(&self) -> Result<String, CryptoError> {
        rsa_private_key_to_pkcs8_pem(self.signing_key.as_ref())
    }

    /// Construct from PKCS#1 DER bytes.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs1_der(der)?;
        Ok(Self {
            signing_key: pss::SigningKey::<Sha384>::new(sk),
        })
    }

    /// Export as PKCS#1 DER bytes.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, CryptoError> {
        rsa_private_key_to_pkcs1_der(self.signing_key.as_ref())
    }

    /// Construct from a PKCS#1 PEM string.
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs1_pem(pem)?;
        Ok(Self {
            signing_key: pss::SigningKey::<Sha384>::new(sk),
        })
    }

    /// Sign `message` and return the signature bytes.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut rng = SysRng;
        let sig = RandomizedSigner::try_sign_with_rng(&self.signing_key, &mut rng, message)
            .map_err(|_| CryptoError::Internal("RSA-PSS-SHA384 sign failed"))?;
        Ok(sig.to_bytes().into_vec())
    }
}

/// RSA-PSS verifying key parameterised with SHA-384.
pub struct RsaPssSha384Verifier {
    verifying_key: pss::VerifyingKey<Sha384>,
}

impl RsaPssSha384Verifier {
    /// Construct from DER-encoded SubjectPublicKeyInfo bytes.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, CryptoError> {
        let public_key =
            rsa::RsaPublicKey::from_public_key_der(der).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            verifying_key: pss::VerifyingKey::<Sha384>::new(public_key),
        })
    }

    /// Construct from a SPKI PEM string.
    pub fn from_spki_pem(pem: &str) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_spki_pem(pem)?;
        Ok(Self {
            verifying_key: pss::VerifyingKey::<Sha384>::new(pk),
        })
    }

    /// Export as SPKI PEM string.
    pub fn to_spki_pem(&self) -> Result<String, CryptoError> {
        rsa_public_key_to_spki_pem(self.verifying_key.as_ref())
    }

    /// Construct from PKCS#1 DER bytes.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_pkcs1_der(der)?;
        Ok(Self {
            verifying_key: pss::VerifyingKey::<Sha384>::new(pk),
        })
    }

    /// Export as PKCS#1 DER bytes.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, CryptoError> {
        rsa_public_key_to_pkcs1_der(self.verifying_key.as_ref())
    }

    /// Construct from a PKCS#1 PEM string.
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_pkcs1_pem(pem)?;
        Ok(Self {
            verifying_key: pss::VerifyingKey::<Sha384>::new(pk),
        })
    }

    /// Verify `signature` over `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig = pss::Signature::try_from(signature).map_err(|_| CryptoError::InvalidTag)?;
        RsaVerifierTrait::verify(&self.verifying_key, message, &sig)
            .map_err(|_| CryptoError::InvalidTag)
    }
}

// ── RSA-PSS SHA-512 ────────────────────────────────────────────────────────

/// RSA-PSS signing key parameterised with SHA-512.
pub struct RsaPssSha512Signer {
    signing_key: pss::SigningKey<Sha512>,
}

impl RsaPssSha512Signer {
    /// Construct from DER-encoded PKCS#8 private key bytes.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        let private_key =
            rsa::RsaPrivateKey::from_pkcs8_der(der).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            signing_key: pss::SigningKey::<Sha512>::new(private_key),
        })
    }

    /// Construct from a PKCS#8 PEM string.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs8_pem(pem)?;
        Ok(Self {
            signing_key: pss::SigningKey::<Sha512>::new(sk),
        })
    }

    /// Export as PKCS#8 PEM string.
    pub fn to_pkcs8_pem(&self) -> Result<String, CryptoError> {
        rsa_private_key_to_pkcs8_pem(self.signing_key.as_ref())
    }

    /// Construct from PKCS#1 DER bytes.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs1_der(der)?;
        Ok(Self {
            signing_key: pss::SigningKey::<Sha512>::new(sk),
        })
    }

    /// Export as PKCS#1 DER bytes.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, CryptoError> {
        rsa_private_key_to_pkcs1_der(self.signing_key.as_ref())
    }

    /// Construct from a PKCS#1 PEM string.
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, CryptoError> {
        let sk = rsa_private_key_from_pkcs1_pem(pem)?;
        Ok(Self {
            signing_key: pss::SigningKey::<Sha512>::new(sk),
        })
    }

    /// Sign `message` and return the signature bytes.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut rng = SysRng;
        let sig = RandomizedSigner::try_sign_with_rng(&self.signing_key, &mut rng, message)
            .map_err(|_| CryptoError::Internal("RSA-PSS-SHA512 sign failed"))?;
        Ok(sig.to_bytes().into_vec())
    }
}

/// RSA-PSS verifying key parameterised with SHA-512.
pub struct RsaPssSha512Verifier {
    verifying_key: pss::VerifyingKey<Sha512>,
}

impl RsaPssSha512Verifier {
    /// Construct from DER-encoded SubjectPublicKeyInfo bytes.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, CryptoError> {
        let public_key =
            rsa::RsaPublicKey::from_public_key_der(der).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            verifying_key: pss::VerifyingKey::<Sha512>::new(public_key),
        })
    }

    /// Construct from a SPKI PEM string.
    pub fn from_spki_pem(pem: &str) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_spki_pem(pem)?;
        Ok(Self {
            verifying_key: pss::VerifyingKey::<Sha512>::new(pk),
        })
    }

    /// Export as SPKI PEM string.
    pub fn to_spki_pem(&self) -> Result<String, CryptoError> {
        rsa_public_key_to_spki_pem(self.verifying_key.as_ref())
    }

    /// Construct from PKCS#1 DER bytes.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_pkcs1_der(der)?;
        Ok(Self {
            verifying_key: pss::VerifyingKey::<Sha512>::new(pk),
        })
    }

    /// Export as PKCS#1 DER bytes.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, CryptoError> {
        rsa_public_key_to_pkcs1_der(self.verifying_key.as_ref())
    }

    /// Construct from a PKCS#1 PEM string.
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, CryptoError> {
        let pk = rsa_public_key_from_pkcs1_pem(pem)?;
        Ok(Self {
            verifying_key: pss::VerifyingKey::<Sha512>::new(pk),
        })
    }

    /// Verify `signature` over `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig = pss::Signature::try_from(signature).map_err(|_| CryptoError::InvalidTag)?;
        RsaVerifierTrait::verify(&self.verifying_key, message, &sig)
            .map_err(|_| CryptoError::InvalidTag)
    }
}

// ── RSA Key Generation ─────────────────────────────────────────────────────

/// Generate an RSA key pair with the specified modulus bit size.
///
/// Returns `(pkcs8_der_private_key, spki_der_public_key)`.
///
/// # Security
///
/// - Minimum 2048 bits for current security (pre-2030).
/// - 3072 bits or more recommended for post-2030 security.
/// - The RSA crate enforces a minimum of 1024 bits; this function enforces 2048.
///
/// # Errors
///
/// Returns [`CryptoError::BadInput`] if `bit_size` < 2048.
/// Returns [`CryptoError::Internal`] if key generation or DER encoding fails.
///
/// # Warning
///
/// RSA key generation is computationally expensive. 2048-bit keys typically
/// take 0.5–2 seconds; 4096-bit keys may take 10–30 seconds.
#[must_use = "generated key pair must be used"]
pub fn rsa_generate_keypair(bit_size: usize) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    if bit_size < 2048 {
        return Err(CryptoError::BadInput);
    }
    // Use UnwrapErr to bridge TryCryptoRng → CryptoRng (Error = Infallible).
    // SysRng failures are fatal (OS entropy unavailable), so panicking is appropriate.
    let mut rng = UnwrapErr(SysRng);
    let private_key = rsa::RsaPrivateKey::new(&mut rng, bit_size)
        .map_err(|_| CryptoError::Internal("RSA key generation failed"))?;
    let public_key = private_key.to_public_key();

    let sk_der = private_key
        .to_pkcs8_der()
        .map_err(|_| CryptoError::Internal("RSA private key DER encoding failed"))?
        .as_bytes()
        .to_vec();
    let pk_der = public_key
        .to_public_key_der()
        .map_err(|_| CryptoError::Internal("RSA public key DER encoding failed"))?
        .as_bytes()
        .to_vec();

    Ok((sk_der, pk_der))
}

// ── RSA-OAEP SHA-256 Encryption/Decryption ────────────────────────────────

/// Encrypt `plaintext` using RSA-OAEP with SHA-256.
///
/// `pk_der` is a DER-encoded SubjectPublicKeyInfo (SPKI) public key.
/// Randomised padding is applied using OS entropy.
///
/// Maximum plaintext size: `key_bits / 8 - 2 * 32 - 2` bytes.
/// For a 2048-bit key: 190 bytes maximum.
#[must_use = "encryption result must be checked"]
pub fn rsa_oaep_sha256_encrypt(pk_der: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let public_key =
        rsa::RsaPublicKey::from_public_key_der(pk_der).map_err(|_| CryptoError::InvalidKey)?;
    let encrypting_key = oaep::EncryptingKey::<Sha256>::new(public_key);
    let mut rng = UnwrapErr(SysRng);
    encrypting_key
        .encrypt_with_rng(&mut rng, plaintext)
        .map_err(|_| CryptoError::Internal("RSA-OAEP encrypt failed"))
}

/// Decrypt `ciphertext` using RSA-OAEP with SHA-256.
///
/// `sk_der` is a DER-encoded PKCS#8 private key.
#[must_use = "decryption result must be checked"]
pub fn rsa_oaep_sha256_decrypt(sk_der: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let private_key =
        rsa::RsaPrivateKey::from_pkcs8_der(sk_der).map_err(|_| CryptoError::InvalidKey)?;
    let decrypting_key = oaep::DecryptingKey::<Sha256>::new(private_key);
    decrypting_key
        .decrypt(ciphertext)
        .map_err(|_| CryptoError::Internal("RSA-OAEP decrypt failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};

    /// Generate a 2048-bit key pair and return (sk_pkcs8_der, pk_spki_der).
    fn gen_2048() -> (Vec<u8>, Vec<u8>) {
        rsa_generate_keypair(2048).unwrap()
    }

    #[test]
    fn rsa_pkcs1v15_sha256_pem_roundtrip() {
        let (sk_der, _pk_der) = gen_2048();
        let signer = RsaPkcs1v15Sha256Signer::from_pkcs8_der(&sk_der).unwrap();

        // Export PKCS#8 PEM and re-import.
        let pem = signer.to_pkcs8_pem().unwrap();
        let signer2 = RsaPkcs1v15Sha256Signer::from_pkcs8_pem(&pem).unwrap();

        // Build matching verifier via SPKI PEM round-trip.
        let pk_pem = rsa::RsaPrivateKey::from_pkcs8_der(&sk_der)
            .unwrap()
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let verifier = RsaPkcs1v15Sha256Verifier::from_spki_pem(&pk_pem).unwrap();

        let msg = b"hello pem roundtrip";
        let sig = signer2.sign(msg).unwrap();
        verifier.verify(msg, &sig).unwrap();
    }

    #[test]
    fn rsa_pss_sha256_pkcs1_der_roundtrip() {
        use rsa::pkcs1::EncodeRsaPublicKey;

        let (sk_der, _pk_der) = gen_2048();
        let signer = RsaPssSha256Signer::from_pkcs8_der(&sk_der).unwrap();

        // Export PKCS#1 DER and re-import.
        let pkcs1_der = signer.to_pkcs1_der().unwrap();
        let signer2 = RsaPssSha256Signer::from_pkcs1_der(&pkcs1_der).unwrap();

        // Build verifier from PKCS#1 DER of public key.
        let rsa_sk = rsa::RsaPrivateKey::from_pkcs8_der(&sk_der).unwrap();
        let pk_pkcs1_der = rsa_sk.to_public_key().to_pkcs1_der().unwrap();
        let verifier = RsaPssSha256Verifier::from_pkcs1_der(pk_pkcs1_der.as_bytes()).unwrap();

        let msg = b"hello pss pkcs1 roundtrip";
        let sig = signer2.sign(msg).unwrap();
        verifier.verify(msg, &sig).unwrap();
    }

    #[test]
    fn rsa_pkcs8_pem_parity_with_pkcs8_der() {
        let (sk_der, pk_der) = gen_2048();

        // Load signer from DER; export to PEM; reload from PEM.
        let signer_der = RsaPkcs1v15Sha256Signer::from_pkcs8_der(&sk_der).unwrap();
        let pem = signer_der.to_pkcs8_pem().unwrap();
        let signer_pem = RsaPkcs1v15Sha256Signer::from_pkcs8_pem(&pem).unwrap();

        let verifier = RsaPkcs1v15Sha256Verifier::from_spki_der(&pk_der).unwrap();
        let msg = b"parity test message";

        // Both signers must produce verifiable signatures (key identity check via verify).
        let sig_pem_imported = signer_pem.sign(msg).unwrap();
        verifier.verify(msg, &sig_pem_imported).unwrap();
    }

    #[test]
    fn rsa_malformed_pem_returns_error() {
        let result = RsaPkcs1v15Sha256Signer::from_pkcs8_pem("not a pem string");
        assert!(result.is_err(), "expected error for malformed PEM");

        let result_v = RsaPkcs1v15Sha256Verifier::from_spki_pem(
            "-----BEGIN garbage-----\nabc\n-----END garbage-----\n",
        );
        assert!(result_v.is_err(), "expected error for garbage PEM");
    }

    #[test]
    fn rsa_malformed_pkcs1_der_returns_error() {
        let result = RsaPkcs1v15Sha256Signer::from_pkcs1_der(&[0x00; 10]);
        assert!(result.is_err(), "expected error for malformed PKCS#1 DER");

        let result_pss = RsaPssSha256Signer::from_pkcs1_der(&[0xff; 32]);
        assert!(
            result_pss.is_err(),
            "expected error for malformed PKCS#1 DER (PSS)"
        );
    }

    #[test]
    fn rsa_pkcs1v15_sha256_pkcs1_pem_roundtrip() {
        use rsa::pkcs1::EncodeRsaPrivateKey;

        let (sk_der, pk_der) = gen_2048();
        let signer = RsaPkcs1v15Sha256Signer::from_pkcs8_der(&sk_der).unwrap();

        // Export to PKCS#1 DER then import.
        let pkcs1_der = signer.to_pkcs1_der().unwrap();
        let signer2 = RsaPkcs1v15Sha256Signer::from_pkcs1_der(&pkcs1_der).unwrap();

        // Export PKCS#1 PEM and import that too.
        let rsa_sk = rsa::RsaPrivateKey::from_pkcs8_der(&sk_der).unwrap();
        let pkcs1_pem = rsa_sk.to_pkcs1_pem(LineEnding::LF).unwrap();
        let signer3 = RsaPkcs1v15Sha256Signer::from_pkcs1_pem(pkcs1_pem.as_str()).unwrap();

        let verifier = RsaPkcs1v15Sha256Verifier::from_spki_der(&pk_der).unwrap();
        let msg = b"pkcs1 pem round trip";

        verifier.verify(msg, &signer2.sign(msg).unwrap()).unwrap();
        verifier.verify(msg, &signer3.sign(msg).unwrap()).unwrap();
    }
}
