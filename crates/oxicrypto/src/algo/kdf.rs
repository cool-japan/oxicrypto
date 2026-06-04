//! KDF algorithm selector enum + factory function + password KDF adapters.

use crate::CryptoError;

/// KDF algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KdfAlgo {
    /// HKDF-SHA-256.
    HkdfSha256,
    /// HKDF-SHA-384.
    HkdfSha384,
    /// HKDF-SHA-512.
    HkdfSha512,
    /// PBKDF2-SHA-256 with 600,000 iterations (OWASP 2023 recommendation).
    Pbkdf2Sha256,
    /// PBKDF2-SHA-512 with 210,000 iterations (OWASP 2023 recommendation).
    Pbkdf2Sha512,
    /// Argon2id with m=65536 KiB, t=3 passes, p=4 lanes (RFC 9106 §4).
    Argon2id,
    /// scrypt with N=131072, r=8, p=1 (log2(N)=17).
    Scrypt,
    /// Balloon (memory-hard) over SHA-256, composed as a 32-byte Balloon
    /// extract followed by HKDF-SHA-256 expansion to fill arbitrary output.
    /// Uses the `interactive` preset (space_cost=16384, time_cost=3).
    Balloon,
}

// ── Password KDF adapters ─────────────────────────────────────────────────────

/// Adapter implementing [`Kdf`] for PBKDF2-SHA-256.
///
/// Uses 600,000 iterations per OWASP 2023 recommendation.
/// `ikm` is treated as the password, `salt` as the salt; `info` is ignored.
#[cfg(feature = "pure")]
#[derive(Debug)]
struct Pbkdf2Sha256Adapter;

#[cfg(feature = "pure")]
impl oxicrypto_core::Kdf for Pbkdf2Sha256Adapter {
    fn name(&self) -> &'static str {
        "PBKDF2-SHA-256"
    }
    fn derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        _info: &[u8],
        okm_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        oxicrypto_kdf::pbkdf2_sha256(ikm, salt, 600_000, okm_out)
    }
}

/// Adapter implementing [`Kdf`] for PBKDF2-SHA-512.
///
/// Uses 210,000 iterations per OWASP 2023 recommendation.
#[cfg(feature = "pure")]
#[derive(Debug)]
struct Pbkdf2Sha512Adapter;

#[cfg(feature = "pure")]
impl oxicrypto_core::Kdf for Pbkdf2Sha512Adapter {
    fn name(&self) -> &'static str {
        "PBKDF2-SHA-512"
    }
    fn derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        _info: &[u8],
        okm_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        oxicrypto_kdf::pbkdf2_sha512(ikm, salt, 210_000, okm_out)
    }
}

/// Adapter implementing [`Kdf`] for Argon2id.
///
/// Uses m=65536 KiB, t=3 passes, p=4 lanes (RFC 9106 §4 offline recommendation).
/// Salt must be at least 8 bytes. `info` is ignored.
#[cfg(feature = "pure")]
#[derive(Debug)]
struct Argon2idAdapter;

#[cfg(feature = "pure")]
impl oxicrypto_core::Kdf for Argon2idAdapter {
    fn name(&self) -> &'static str {
        "Argon2id"
    }
    fn derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        _info: &[u8],
        okm_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let params = oxicrypto_kdf::Argon2Params {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 4,
        };
        oxicrypto_kdf::argon2id_derive(ikm, salt, params, okm_out)
    }
}

/// Adapter implementing [`Kdf`] for scrypt.
///
/// Uses log_n=17 (N=131072), r=8, p=1. `info` is ignored.
#[cfg(feature = "pure")]
#[derive(Debug)]
struct ScryptAdapter;

#[cfg(feature = "pure")]
impl oxicrypto_core::Kdf for ScryptAdapter {
    fn name(&self) -> &'static str {
        "scrypt"
    }
    fn derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        _info: &[u8],
        okm_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        // N = 2^17 = 131072; log_n = 17
        oxicrypto_kdf::scrypt_derive(ikm, salt, 17, 8, 1, okm_out)
    }
}

/// Adapter implementing [`Kdf`] for the Balloon memory-hard function over
/// SHA-256.
///
/// Balloon natively produces a fixed 32-byte digest, but the [`Kdf`] contract
/// requires filling an arbitrary-length `okm_out`. To honour that contract this
/// adapter composes **Balloon (memory-hard extract) + HKDF-SHA-256 expand**:
/// it first derives a 32-byte Balloon PRK from `ikm`/`salt` using
/// [`oxicrypto_kdf::balloon_sha256`], then runs
/// [`oxicrypto_kdf::hkdf_sha256_expand`] over that PRK to stretch it to the
/// requested length. `info` is forwarded as the HKDF-Expand context/label.
///
/// Cost parameters use [`oxicrypto_kdf::BalloonParams::interactive`]
/// (`space_cost = 16384`, `time_cost = 3`; ≈ 512 KiB of working memory), the
/// lightest hardened preset — chosen so the adapter stays fast in the facade's
/// test suite while remaining memory-hard.
#[cfg(feature = "pure")]
#[derive(Debug)]
struct BalloonAdapter;

#[cfg(feature = "pure")]
impl oxicrypto_core::Kdf for BalloonAdapter {
    fn name(&self) -> &'static str {
        "Balloon-SHA256"
    }
    fn derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        okm_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let p = oxicrypto_kdf::BalloonParams::interactive();
        let mut prk = [0u8; 32];
        oxicrypto_kdf::balloon_sha256(ikm, salt, p.space_cost, p.time_cost, &mut prk)?;
        oxicrypto_kdf::hkdf_sha256_expand(&prk, info, okm_out)
    }
}

/// Return a boxed [`oxicrypto_core::Kdf`] implementation for `algo`.
#[cfg(feature = "pure")]
#[must_use]
#[inline(always)]
pub fn kdf_impl(algo: KdfAlgo) -> oxicrypto_core::Box<dyn oxicrypto_core::Kdf + Send + Sync> {
    match algo {
        KdfAlgo::HkdfSha256 => oxicrypto_core::Box::new(oxicrypto_kdf::HkdfSha256),
        KdfAlgo::HkdfSha384 => oxicrypto_core::Box::new(oxicrypto_kdf::HkdfSha384),
        KdfAlgo::HkdfSha512 => oxicrypto_core::Box::new(oxicrypto_kdf::HkdfSha512),
        KdfAlgo::Pbkdf2Sha256 => oxicrypto_core::Box::new(Pbkdf2Sha256Adapter),
        KdfAlgo::Pbkdf2Sha512 => oxicrypto_core::Box::new(Pbkdf2Sha512Adapter),
        KdfAlgo::Argon2id => oxicrypto_core::Box::new(Argon2idAdapter),
        KdfAlgo::Scrypt => oxicrypto_core::Box::new(ScryptAdapter),
        KdfAlgo::Balloon => oxicrypto_core::Box::new(BalloonAdapter),
    }
}

// ── Display ───────────────────────────────────────────────────────────────────

impl core::fmt::Display for KdfAlgo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            KdfAlgo::HkdfSha256 => "HKDF-SHA-256",
            KdfAlgo::HkdfSha384 => "HKDF-SHA-384",
            KdfAlgo::HkdfSha512 => "HKDF-SHA-512",
            KdfAlgo::Pbkdf2Sha256 => "PBKDF2-SHA-256",
            KdfAlgo::Pbkdf2Sha512 => "PBKDF2-SHA-512",
            KdfAlgo::Argon2id => "Argon2id",
            KdfAlgo::Scrypt => "scrypt",
            KdfAlgo::Balloon => "Balloon-SHA256",
        })
    }
}

// ── FromStr ───────────────────────────────────────────────────────────────────

impl core::str::FromStr for KdfAlgo {
    type Err = CryptoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "HKDF-SHA-256" | "hkdf-sha-256" | "HKDFSHA256" => Ok(KdfAlgo::HkdfSha256),
            "HKDF-SHA-384" | "hkdf-sha-384" | "HKDFSHA384" => Ok(KdfAlgo::HkdfSha384),
            "HKDF-SHA-512" | "hkdf-sha-512" | "HKDFSHA512" => Ok(KdfAlgo::HkdfSha512),
            "PBKDF2-SHA-256" | "pbkdf2-sha-256" | "PBKDF2SHA256" => Ok(KdfAlgo::Pbkdf2Sha256),
            "PBKDF2-SHA-512" | "pbkdf2-sha-512" | "PBKDF2SHA512" => Ok(KdfAlgo::Pbkdf2Sha512),
            "Argon2id" | "argon2id" | "ARGON2ID" => Ok(KdfAlgo::Argon2id),
            "scrypt" | "SCRYPT" => Ok(KdfAlgo::Scrypt),
            "Balloon-SHA256" | "balloon-sha256" | "balloon" => Ok(KdfAlgo::Balloon),
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }
}

// ── TryFrom<&str> ─────────────────────────────────────────────────────────────

impl TryFrom<&str> for KdfAlgo {
    type Error = CryptoError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}
