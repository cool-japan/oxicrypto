//! Hash algorithm selector enum + factory function.

use crate::CryptoError;

/// Hash algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlgo {
    /// SHA-256 (32-byte output).
    Sha256,
    /// SHA-384 (48-byte output).
    Sha384,
    /// SHA-512 (64-byte output).
    Sha512,
    /// SHA3-256 (32-byte output).
    Sha3_256,
    /// SHA3-384 (48-byte output).
    Sha3_384,
    /// SHA3-512 (64-byte output).
    Sha3_512,
    /// SHA-512/256 (32-byte output).
    Sha512_256,
    /// BLAKE2b-256 (32-byte output).
    Blake2b256,
    /// BLAKE2b-512 (64-byte output).
    Blake2b512,
    /// BLAKE2s-256 (32-byte output).
    Blake2s256,
    /// BLAKE3 (32-byte output).
    Blake3,
}

/// Return a boxed [`Hash`] implementation for `algo`.
#[cfg(feature = "pure")]
#[must_use]
#[inline(always)]
pub fn hash_impl(algo: HashAlgo) -> oxicrypto_core::Box<dyn oxicrypto_core::Hash + Send + Sync> {
    match algo {
        HashAlgo::Sha256 => oxicrypto_core::Box::new(oxicrypto_hash::Sha256),
        HashAlgo::Sha384 => oxicrypto_core::Box::new(oxicrypto_hash::Sha384),
        HashAlgo::Sha512 => oxicrypto_core::Box::new(oxicrypto_hash::Sha512),
        HashAlgo::Sha3_256 => oxicrypto_core::Box::new(oxicrypto_hash::Sha3_256),
        HashAlgo::Sha3_384 => oxicrypto_core::Box::new(oxicrypto_hash::Sha3_384),
        HashAlgo::Sha3_512 => oxicrypto_core::Box::new(oxicrypto_hash::Sha3_512),
        HashAlgo::Sha512_256 => oxicrypto_core::Box::new(oxicrypto_hash::Sha512_256),
        HashAlgo::Blake2b256 => oxicrypto_core::Box::new(oxicrypto_hash::Blake2b256),
        HashAlgo::Blake2b512 => oxicrypto_core::Box::new(oxicrypto_hash::Blake2b512),
        HashAlgo::Blake2s256 => oxicrypto_core::Box::new(oxicrypto_hash::Blake2s256),
        HashAlgo::Blake3 => oxicrypto_core::Box::new(oxicrypto_hash::Blake3),
    }
}

// ── Display ───────────────────────────────────────────────────────────────────

impl core::fmt::Display for HashAlgo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            HashAlgo::Sha256 => "SHA-256",
            HashAlgo::Sha384 => "SHA-384",
            HashAlgo::Sha512 => "SHA-512",
            HashAlgo::Sha3_256 => "SHA3-256",
            HashAlgo::Sha3_384 => "SHA3-384",
            HashAlgo::Sha3_512 => "SHA3-512",
            HashAlgo::Sha512_256 => "SHA-512/256",
            HashAlgo::Blake2b256 => "BLAKE2b-256",
            HashAlgo::Blake2b512 => "BLAKE2b-512",
            HashAlgo::Blake2s256 => "BLAKE2s-256",
            HashAlgo::Blake3 => "BLAKE3",
        })
    }
}

// ── FromStr ───────────────────────────────────────────────────────────────────

impl core::str::FromStr for HashAlgo {
    type Err = CryptoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SHA-256" | "SHA256" | "sha256" | "sha-256" => Ok(HashAlgo::Sha256),
            "SHA-384" | "SHA384" | "sha384" | "sha-384" => Ok(HashAlgo::Sha384),
            "SHA-512" | "SHA512" | "sha512" | "sha-512" => Ok(HashAlgo::Sha512),
            "SHA3-256" | "SHA3_256" | "sha3-256" | "sha3_256" => Ok(HashAlgo::Sha3_256),
            "SHA3-384" | "SHA3_384" | "sha3-384" | "sha3_384" => Ok(HashAlgo::Sha3_384),
            "SHA3-512" | "SHA3_512" | "sha3-512" | "sha3_512" => Ok(HashAlgo::Sha3_512),
            "SHA-512/256" | "SHA512-256" | "sha512-256" | "sha-512/256" => Ok(HashAlgo::Sha512_256),
            "BLAKE2b-256" | "blake2b-256" | "BLAKE2B256" => Ok(HashAlgo::Blake2b256),
            "BLAKE2b-512" | "blake2b-512" | "BLAKE2B512" => Ok(HashAlgo::Blake2b512),
            "BLAKE2s-256" | "blake2s-256" | "BLAKE2S256" => Ok(HashAlgo::Blake2s256),
            "BLAKE3" | "blake3" => Ok(HashAlgo::Blake3),
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }
}

// ── TryFrom<&str> ─────────────────────────────────────────────────────────────

impl TryFrom<&str> for HashAlgo {
    type Error = CryptoError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}
