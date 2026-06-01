//! Version information and algorithm enumeration for the `oxicrypto` facade.

use oxicrypto_core::{AlgorithmId, Vec};

// ── VersionInfo ───────────────────────────────────────────────────────────────

/// Version information for the `oxicrypto` facade crate.
///
/// Obtained via [`version()`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionInfo {
    /// Major version number (semantic versioning).
    pub major: u32,
    /// Minor version number (semantic versioning).
    pub minor: u32,
    /// Patch version number (semantic versioning).
    pub patch: u32,
    /// Pre-release label, if any (e.g. `"alpha.1"`), or `""` for stable releases.
    pub pre: &'static str,
}

impl core::fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.pre.is_empty() {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        } else {
            write!(
                f,
                "{}.{}.{}-{}",
                self.major, self.minor, self.patch, self.pre
            )
        }
    }
}

/// Returns a list of compile-time feature flags that are enabled in this build.
///
/// Useful for logging, diagnostics, and build introspection.  The list contains
/// only feature names that were active when the crate was compiled; an empty
/// list means no feature-gated capabilities are compiled in (unlikely given the
/// default `pure` feature, but possible when `default-features = false`).
///
/// # Example
///
/// ```rust
/// let features = oxicrypto::enabled_features();
/// println!("active features: {:?}", features);
/// ```
#[must_use]
#[allow(clippy::vec_init_then_push)] // conditional cfg pushes cannot use vec![] macro
pub fn enabled_features() -> Vec<&'static str> {
    let mut features = Vec::new();

    #[cfg(feature = "pure")]
    features.push("pure");

    #[cfg(feature = "simd")]
    features.push("simd");

    #[cfg(feature = "pq-preview")]
    features.push("pq-preview");

    #[cfg(feature = "std")]
    features.push("std");

    features
}

/// Return the compile-time version of the `oxicrypto` crate.
///
/// The version is parsed from the `CARGO_PKG_VERSION_*` environment variables
/// at compile time and embedded in the binary.
#[must_use]
pub fn version() -> VersionInfo {
    VersionInfo {
        major: env!("CARGO_PKG_VERSION_MAJOR")
            .parse::<u32>()
            .ok()
            .unwrap_or(0),
        minor: env!("CARGO_PKG_VERSION_MINOR")
            .parse::<u32>()
            .ok()
            .unwrap_or(0),
        patch: env!("CARGO_PKG_VERSION_PATCH")
            .parse::<u32>()
            .ok()
            .unwrap_or(0),
        pre: env!("CARGO_PKG_VERSION_PRE"),
    }
}

// ── available_algorithms() ────────────────────────────────────────────────────

/// Return the list of algorithm identifiers compiled into this build.
///
/// The returned list includes all algorithms enabled by the active feature flags:
/// - Hash, AEAD, MAC, signature, key-exchange, and KDF algorithms are included
///   when the `pure` feature is active (the default).
/// - Post-quantum algorithms (`ML-KEM-*`, `ML-DSA-*`) are included when the
///   `pq-preview` feature is active.
#[must_use]
pub fn available_algorithms() -> Vec<AlgorithmId> {
    let mut ids = Vec::new();

    // Hash
    ids.extend_from_slice(&[
        AlgorithmId::Sha256,
        AlgorithmId::Sha384,
        AlgorithmId::Sha512,
        AlgorithmId::Sha3_256,
        AlgorithmId::Sha3_384,
        AlgorithmId::Sha3_512,
        AlgorithmId::Blake3,
    ]);

    // AEAD
    ids.extend_from_slice(&[
        AlgorithmId::Aes128Gcm,
        AlgorithmId::Aes256Gcm,
        AlgorithmId::ChaCha20Poly1305,
        AlgorithmId::Aes128GcmSiv,
        AlgorithmId::Aes256GcmSiv,
        AlgorithmId::XChaCha20Poly1305,
        AlgorithmId::Aes128Ccm,
        AlgorithmId::Aes256Ccm,
        AlgorithmId::DeoxysII128,
        // AES Key Wrap (RFC 3394) — always included with the pure feature.
        AlgorithmId::AesKeyWrap128,
        AlgorithmId::AesKeyWrap256,
    ]);

    // MAC
    ids.extend_from_slice(&[
        AlgorithmId::HmacSha256,
        AlgorithmId::HmacSha384,
        AlgorithmId::HmacSha512,
        AlgorithmId::HmacSha3_256,
        AlgorithmId::HmacSha3_512,
        AlgorithmId::Poly1305,
        AlgorithmId::CmacAes128,
        AlgorithmId::CmacAes256,
        AlgorithmId::Kmac128,
        AlgorithmId::Kmac256,
    ]);

    // Signature
    ids.extend_from_slice(&[
        AlgorithmId::Ed25519,
        AlgorithmId::Ed448,
        AlgorithmId::EcdsaP256,
        AlgorithmId::EcdsaP384,
        AlgorithmId::EcdsaP521,
        AlgorithmId::RsaPkcs1v15Sha256,
        AlgorithmId::RsaPkcs1v15Sha384,
        AlgorithmId::RsaPkcs1v15Sha512,
        AlgorithmId::RsaPssSha256,
        AlgorithmId::SchnorrBip340,
    ]);

    // Key exchange
    ids.extend_from_slice(&[
        AlgorithmId::X25519,
        AlgorithmId::EcdhP256,
        AlgorithmId::EcdhP384,
        AlgorithmId::EcdhP521,
    ]);

    // KDF
    ids.extend_from_slice(&[
        AlgorithmId::HkdfSha256,
        AlgorithmId::HkdfSha384,
        AlgorithmId::HkdfSha512,
        AlgorithmId::Pbkdf2Sha256,
        AlgorithmId::Pbkdf2Sha512,
        AlgorithmId::Argon2id,
        AlgorithmId::Scrypt,
        AlgorithmId::Balloon,
    ]);

    // Post-quantum (pq-preview feature)
    #[cfg(feature = "pq-preview")]
    ids.extend_from_slice(&[
        AlgorithmId::MlKem512,
        AlgorithmId::MlKem768,
        AlgorithmId::MlKem1024,
        AlgorithmId::MlDsa44,
        AlgorithmId::MlDsa65,
        AlgorithmId::MlDsa87,
        // SLH-DSA (FIPS 205) — hash-based signatures.
        AlgorithmId::SlhDsaSha2_128s,
        AlgorithmId::SlhDsaSha2_128f,
        AlgorithmId::SlhDsaSha2_192s,
        AlgorithmId::SlhDsaSha2_192f,
        AlgorithmId::SlhDsaSha2_256s,
        AlgorithmId::SlhDsaSha2_256f,
        AlgorithmId::SlhDsaShake128s,
        AlgorithmId::SlhDsaShake128f,
        AlgorithmId::SlhDsaShake256s,
        AlgorithmId::SlhDsaShake256f,
    ]);

    ids
}

// ── Suite presets ─────────────────────────────────────────────────────────────

/// A complete algorithm suite bundling AEAD, MAC, hash, key-exchange, and KDF
/// selections into a single, named configuration.
///
/// Predefined suites like [`Suite::TLS13`] encode well-known interoperable
/// configurations so that callers do not need to assemble them by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suite {
    /// Authenticated encryption algorithm.
    pub aead: crate::AeadAlgo,
    /// Message authentication / PRF algorithm.
    pub mac: crate::MacAlgo,
    /// Hash algorithm (used for transcript, key derivation, etc.).
    pub hash: crate::HashAlgo,
    /// Key-exchange algorithm.
    pub kex: crate::KexAlgo,
    /// Key derivation function.
    pub kdf: crate::KdfAlgo,
}

impl Suite {
    /// TLS 1.3 default suite.
    ///
    /// Combines TLS_AES_256_GCM_SHA384 cipher suite with X25519 key exchange
    /// and HKDF-SHA-384 key derivation, matching RFC 8446 §B.4 mandatory
    /// cipher suite requirements and widespread deployment practice.
    pub const TLS13: Suite = Suite {
        aead: crate::AeadAlgo::Aes256Gcm,
        mac: crate::MacAlgo::HmacSha384,
        hash: crate::HashAlgo::Sha384,
        kex: crate::KexAlgo::X25519,
        kdf: crate::KdfAlgo::HkdfSha384,
    };
}

impl core::fmt::Display for Suite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Suite {{ aead: {}, mac: {}, hash: {}, kex: {}, kdf: {} }}",
            self.aead, self.mac, self.hash, self.kex, self.kdf
        )
    }
}

/// A post-quantum hybrid algorithm suite, extending a classical [`Suite`] with
/// ML-KEM and ML-DSA selections.
///
/// Available only when the `pq-preview` feature is enabled.
#[cfg(feature = "pq-preview")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqSuite {
    /// The classical algorithm base suite.
    pub classical: Suite,
    /// Post-quantum key encapsulation mechanism.
    pub pq_kem: crate::PqKemAlgo,
    /// Post-quantum signature algorithm.
    pub pq_sig: crate::PqSigAlgo,
}

#[cfg(feature = "pq-preview")]
impl PqSuite {
    /// Post-quantum TLS 1.3 hybrid suite.
    ///
    /// Extends [`Suite::TLS13`] with ML-KEM-768 (FIPS 203) for key exchange
    /// and ML-DSA-65 (FIPS 204) for authentication, targeting NIST security
    /// category 3 (comparable to AES-192 / P-384).
    pub const PQ_TLS13: PqSuite = PqSuite {
        classical: Suite::TLS13,
        pq_kem: crate::PqKemAlgo::MlKem768,
        pq_sig: crate::PqSigAlgo::MlDsa65,
    };

    /// Post-quantum TLS 1.3 hybrid suite with hash-based signatures.
    ///
    /// Extends [`Suite::TLS13`] with ML-KEM-768 (FIPS 203) for key exchange
    /// and SLH-DSA-SHAKE-128f (FIPS 205) for authentication.  SLH-DSA is a
    /// stateless hash-based signature scheme; its security relies on the
    /// collision-resistance of SHAKE rather than the algebraic hardness
    /// assumed by ML-DSA.  Use this suite when diversity of PQ assumptions
    /// is a deployment requirement.
    pub const PQ_TLS13_HASH_BASED: PqSuite = PqSuite {
        classical: Suite::TLS13,
        pq_kem: crate::PqKemAlgo::MlKem768,
        pq_sig: crate::PqSigAlgo::SlhDsaShake128f,
    };
}

#[cfg(feature = "pq-preview")]
impl core::fmt::Display for PqSuite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "PqSuite {{ classical: {}, pq_kem: {}, pq_sig: {} }}",
            self.classical, self.pq_kem, self.pq_sig
        )
    }
}
