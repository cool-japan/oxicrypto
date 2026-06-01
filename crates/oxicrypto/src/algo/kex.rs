//! Key-exchange algorithm selector enum + factory function.

use crate::CryptoError;

/// Key-exchange algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KexAlgo {
    /// X25519 Diffie-Hellman (32-byte scalar, 32-byte point).
    X25519,
    /// ECDH P-256 (32-byte scalar, SEC1 public key).
    EcdhP256,
    /// ECDH P-384 (48-byte scalar, SEC1 public key).
    EcdhP384,
    /// ECDH P-521 (66-byte scalar, SEC1 public key).
    EcdhP521,
}

/// Return a boxed [`oxicrypto_core::KeyAgreement`] implementation for `algo`.
#[cfg(feature = "pure")]
#[must_use]
pub fn kex_impl(
    algo: KexAlgo,
) -> oxicrypto_core::Box<dyn oxicrypto_core::KeyAgreement + Send + Sync> {
    match algo {
        KexAlgo::X25519 => oxicrypto_core::Box::new(oxicrypto_kex::X25519),
        KexAlgo::EcdhP256 => oxicrypto_core::Box::new(oxicrypto_kex::EcdhP256),
        KexAlgo::EcdhP384 => oxicrypto_core::Box::new(oxicrypto_kex::EcdhP384),
        KexAlgo::EcdhP521 => oxicrypto_core::Box::new(oxicrypto_kex::EcdhP521),
    }
}

// ── Display ───────────────────────────────────────────────────────────────────

impl core::fmt::Display for KexAlgo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            KexAlgo::X25519 => "X25519",
            KexAlgo::EcdhP256 => "ECDH-P256",
            KexAlgo::EcdhP384 => "ECDH-P384",
            KexAlgo::EcdhP521 => "ECDH-P521",
        })
    }
}

// ── FromStr ───────────────────────────────────────────────────────────────────

impl core::str::FromStr for KexAlgo {
    type Err = CryptoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "X25519" | "x25519" => Ok(KexAlgo::X25519),
            "ECDH-P256" | "ecdh-p256" | "ECDHP256" => Ok(KexAlgo::EcdhP256),
            "ECDH-P384" | "ecdh-p384" | "ECDHP384" => Ok(KexAlgo::EcdhP384),
            "ECDH-P521" | "ecdh-p521" | "ECDHP521" => Ok(KexAlgo::EcdhP521),
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }
}

// ── TryFrom<&str> ─────────────────────────────────────────────────────────────

impl TryFrom<&str> for KexAlgo {
    type Error = CryptoError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}
