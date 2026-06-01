/// Canonical algorithm category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmCategory {
    /// Cryptographic hash functions (SHA-2, SHA-3, BLAKE2, BLAKE3).
    Hash,
    /// Authenticated encryption with associated data.
    Aead,
    /// Message authentication codes.
    Mac,
    /// Digital signature schemes.
    Signature,
    /// Key agreement / Diffie-Hellman.
    KeyExchange,
    /// Key derivation functions.
    Kdf,
    /// Post-quantum primitives (ML-KEM, ML-DSA, hybrid KEMs).
    PostQuantum,
}

/// Canonical algorithm identifier covering all OxiCrypto algorithm families.
///
/// This enum is `#[non_exhaustive]` so that future algorithm additions do not
/// constitute a breaking change for crates that match on it in external code.
/// Inside this crate all matches are exhaustive (no wildcard fallback needed).
///
/// Each variant's `name()` returns the canonical IANA/NIST string representation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, core::hash::Hash)]
pub enum AlgorithmId {
    // ------ Hash algorithms ------
    /// SHA-256 (FIPS 180-4)
    Sha256,
    /// SHA-384 (FIPS 180-4)
    Sha384,
    /// SHA-512 (FIPS 180-4)
    Sha512,
    /// SHA-512/256 (FIPS 180-4 §6.7)
    Sha512_256,
    /// SHA3-256 (FIPS 202)
    Sha3_256,
    /// SHA3-384 (FIPS 202)
    Sha3_384,
    /// SHA3-512 (FIPS 202)
    Sha3_512,
    /// BLAKE2b-256
    Blake2b256,
    /// BLAKE2b-512
    Blake2b512,
    /// BLAKE3
    Blake3,

    // ------ AEAD algorithms ------
    /// AES-128-GCM (NIST SP 800-38D, RFC 5116)
    Aes128Gcm,
    /// AES-256-GCM (NIST SP 800-38D, RFC 5116)
    Aes256Gcm,
    /// ChaCha20-Poly1305 (RFC 8439)
    ChaCha20Poly1305,
    /// AES-128-GCM-SIV (RFC 8452)
    Aes128GcmSiv,
    /// AES-256-GCM-SIV (RFC 8452)
    Aes256GcmSiv,
    /// XChaCha20-Poly1305
    XChaCha20Poly1305,
    /// AES-128-CCM (NIST SP 800-38C)
    Aes128Ccm,
    /// AES-256-CCM (NIST SP 800-38C)
    Aes256Ccm,
    /// Deoxys-II-128-128 (CAESAR final portfolio, nonce-misuse resistant)
    DeoxysII128,
    /// AES-128-KW — AES Key Wrap with 128-bit key (RFC 3394)
    AesKeyWrap128,
    /// AES-256-KW — AES Key Wrap with 256-bit key (RFC 3394)
    AesKeyWrap256,

    // ------ MAC algorithms ------
    /// HMAC-SHA-256 (RFC 2104)
    HmacSha256,
    /// HMAC-SHA-384 (RFC 2104)
    HmacSha384,
    /// HMAC-SHA-512 (RFC 2104)
    HmacSha512,
    /// HMAC-SHA3-256
    HmacSha3_256,
    /// HMAC-SHA3-512
    HmacSha3_512,
    /// Poly1305 (RFC 8439)
    Poly1305,
    /// CMAC-AES-128 (NIST SP 800-38B)
    CmacAes128,
    /// CMAC-AES-256 (NIST SP 800-38B)
    CmacAes256,
    /// KMAC128 (NIST SP 800-185)
    Kmac128,
    /// KMAC256 (NIST SP 800-185)
    Kmac256,

    // ------ Signature algorithms ------
    /// Ed25519 (RFC 8032)
    Ed25519,
    /// Ed448 (RFC 8032)
    Ed448,
    /// ECDSA over P-256 (FIPS 186-4)
    EcdsaP256,
    /// ECDSA over P-384 (FIPS 186-4)
    EcdsaP384,
    /// ECDSA over P-521 (FIPS 186-4)
    EcdsaP521,
    /// RSA PKCS#1 v1.5 with SHA-256
    RsaPkcs1v15Sha256,
    /// RSA PKCS#1 v1.5 with SHA-384
    RsaPkcs1v15Sha384,
    /// RSA PKCS#1 v1.5 with SHA-512
    RsaPkcs1v15Sha512,
    /// RSA-PSS with SHA-256 (RFC 8017)
    RsaPssSha256,
    /// BIP-340 Schnorr over secp256k1
    SchnorrBip340,

    // ------ Key exchange ------
    /// X25519 (RFC 7748)
    X25519,
    /// X448 (RFC 7748)
    X448,
    /// ECDH over P-256
    EcdhP256,
    /// ECDH over P-384
    EcdhP384,
    /// ECDH over P-521
    EcdhP521,

    // ------ KDF ------
    /// HKDF-SHA-256 (RFC 5869)
    HkdfSha256,
    /// HKDF-SHA-384 (RFC 5869)
    HkdfSha384,
    /// HKDF-SHA-512 (RFC 5869)
    HkdfSha512,
    /// PBKDF2-SHA-256 (RFC 8018)
    Pbkdf2Sha256,
    /// PBKDF2-SHA-512 (RFC 8018)
    Pbkdf2Sha512,
    /// Argon2id (RFC 9106)
    Argon2id,
    /// scrypt (RFC 7914)
    Scrypt,
    /// Balloon memory-hard hashing (SHA-256), Boneh-Corrigan-Gibbs-Schechter
    Balloon,

    // ------ Post-quantum ------
    /// ML-KEM-512 (FIPS 203)
    MlKem512,
    /// ML-KEM-768 (FIPS 203)
    MlKem768,
    /// ML-KEM-1024 (FIPS 203)
    MlKem1024,
    /// ML-DSA-44 (FIPS 204)
    MlDsa44,
    /// ML-DSA-65 (FIPS 204)
    MlDsa65,
    /// ML-DSA-87 (FIPS 204)
    MlDsa87,
    /// Hybrid KEM: ML-KEM-768 + X25519 (X-Wing draft)
    XWing768X25519,
    /// Hybrid KEM: ML-KEM-1024 + P-384
    HybridKem1024P384,
    /// SLH-DSA-SHA2-128s (FIPS 205)
    SlhDsaSha2_128s,
    /// SLH-DSA-SHA2-128f (FIPS 205)
    SlhDsaSha2_128f,
    /// SLH-DSA-SHA2-192s (FIPS 205, security category 3)
    SlhDsaSha2_192s,
    /// SLH-DSA-SHA2-192f (FIPS 205, security category 3)
    SlhDsaSha2_192f,
    /// SLH-DSA-SHA2-256s (FIPS 205)
    SlhDsaSha2_256s,
    /// SLH-DSA-SHA2-256f (FIPS 205)
    SlhDsaSha2_256f,
    /// SLH-DSA-SHAKE-128s (FIPS 205)
    SlhDsaShake128s,
    /// SLH-DSA-SHAKE-128f (FIPS 205)
    SlhDsaShake128f,
    /// SLH-DSA-SHAKE-256s (FIPS 205, security category 5)
    SlhDsaShake256s,
    /// SLH-DSA-SHAKE-256f (FIPS 205, security category 5)
    SlhDsaShake256f,
}

impl AlgorithmId {
    /// Return the canonical IANA/NIST name string for this algorithm.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Sha512_256 => "SHA-512/256",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_384 => "SHA3-384",
            Self::Sha3_512 => "SHA3-512",
            Self::Blake2b256 => "BLAKE2b-256",
            Self::Blake2b512 => "BLAKE2b-512",
            Self::Blake3 => "BLAKE3",
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Self::Aes128GcmSiv => "AES-128-GCM-SIV",
            Self::Aes256GcmSiv => "AES-256-GCM-SIV",
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Self::Aes128Ccm => "AES-128-CCM",
            Self::Aes256Ccm => "AES-256-CCM",
            Self::DeoxysII128 => "Deoxys-II-128-128",
            Self::AesKeyWrap128 => "AES-KW-128",
            Self::AesKeyWrap256 => "AES-KW-256",
            Self::HmacSha256 => "HMAC-SHA-256",
            Self::HmacSha384 => "HMAC-SHA-384",
            Self::HmacSha512 => "HMAC-SHA-512",
            Self::HmacSha3_256 => "HMAC-SHA3-256",
            Self::HmacSha3_512 => "HMAC-SHA3-512",
            Self::Poly1305 => "Poly1305",
            Self::CmacAes128 => "CMAC-AES-128",
            Self::CmacAes256 => "CMAC-AES-256",
            Self::Kmac128 => "KMAC128",
            Self::Kmac256 => "KMAC256",
            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "Ed448",
            Self::EcdsaP256 => "ECDSA-P256",
            Self::EcdsaP384 => "ECDSA-P384",
            Self::EcdsaP521 => "ECDSA-P521",
            Self::RsaPkcs1v15Sha256 => "RSA-PKCS1v15-SHA-256",
            Self::RsaPkcs1v15Sha384 => "RSA-PKCS1v15-SHA-384",
            Self::RsaPkcs1v15Sha512 => "RSA-PKCS1v15-SHA-512",
            Self::RsaPssSha256 => "RSA-PSS-SHA-256",
            Self::SchnorrBip340 => "Schnorr-BIP340",
            Self::X25519 => "X25519",
            Self::X448 => "X448",
            Self::EcdhP256 => "ECDH-P256",
            Self::EcdhP384 => "ECDH-P384",
            Self::EcdhP521 => "ECDH-P521",
            Self::HkdfSha256 => "HKDF-SHA-256",
            Self::HkdfSha384 => "HKDF-SHA-384",
            Self::HkdfSha512 => "HKDF-SHA-512",
            Self::Pbkdf2Sha256 => "PBKDF2-SHA-256",
            Self::Pbkdf2Sha512 => "PBKDF2-SHA-512",
            Self::Argon2id => "Argon2id",
            Self::Scrypt => "scrypt",
            Self::Balloon => "Balloon-SHA256",
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
            Self::XWing768X25519 => "X-Wing-768-X25519",
            Self::HybridKem1024P384 => "Hybrid-ML-KEM-1024-P384",
            Self::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
            Self::SlhDsaSha2_128f => "SLH-DSA-SHA2-128f",
            Self::SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
            Self::SlhDsaSha2_192f => "SLH-DSA-SHA2-192f",
            Self::SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
            Self::SlhDsaSha2_256f => "SLH-DSA-SHA2-256f",
            Self::SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
            Self::SlhDsaShake128f => "SLH-DSA-SHAKE-128f",
            Self::SlhDsaShake256s => "SLH-DSA-SHAKE-256s",
            Self::SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
        }
    }

    /// Return the [`AlgorithmCategory`] for this algorithm.
    #[must_use]
    pub fn category(&self) -> AlgorithmCategory {
        match self {
            Self::Sha256
            | Self::Sha384
            | Self::Sha512
            | Self::Sha512_256
            | Self::Sha3_256
            | Self::Sha3_384
            | Self::Sha3_512
            | Self::Blake2b256
            | Self::Blake2b512
            | Self::Blake3 => AlgorithmCategory::Hash,

            Self::Aes128Gcm
            | Self::Aes256Gcm
            | Self::ChaCha20Poly1305
            | Self::Aes128GcmSiv
            | Self::Aes256GcmSiv
            | Self::XChaCha20Poly1305
            | Self::Aes128Ccm
            | Self::Aes256Ccm
            | Self::DeoxysII128
            | Self::AesKeyWrap128
            | Self::AesKeyWrap256 => AlgorithmCategory::Aead,

            Self::HmacSha256
            | Self::HmacSha384
            | Self::HmacSha512
            | Self::HmacSha3_256
            | Self::HmacSha3_512
            | Self::Poly1305
            | Self::CmacAes128
            | Self::CmacAes256
            | Self::Kmac128
            | Self::Kmac256 => AlgorithmCategory::Mac,

            Self::Ed25519
            | Self::Ed448
            | Self::EcdsaP256
            | Self::EcdsaP384
            | Self::EcdsaP521
            | Self::RsaPkcs1v15Sha256
            | Self::RsaPkcs1v15Sha384
            | Self::RsaPkcs1v15Sha512
            | Self::RsaPssSha256
            | Self::SchnorrBip340 => AlgorithmCategory::Signature,

            Self::X25519 | Self::X448 | Self::EcdhP256 | Self::EcdhP384 | Self::EcdhP521 => {
                AlgorithmCategory::KeyExchange
            }

            Self::HkdfSha256
            | Self::HkdfSha384
            | Self::HkdfSha512
            | Self::Pbkdf2Sha256
            | Self::Pbkdf2Sha512
            | Self::Argon2id
            | Self::Scrypt
            | Self::Balloon => AlgorithmCategory::Kdf,

            Self::MlKem512
            | Self::MlKem768
            | Self::MlKem1024
            | Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87
            | Self::XWing768X25519
            | Self::HybridKem1024P384
            | Self::SlhDsaSha2_128s
            | Self::SlhDsaSha2_128f
            | Self::SlhDsaSha2_192s
            | Self::SlhDsaSha2_192f
            | Self::SlhDsaSha2_256s
            | Self::SlhDsaSha2_256f
            | Self::SlhDsaShake128s
            | Self::SlhDsaShake128f
            | Self::SlhDsaShake256s
            | Self::SlhDsaShake256f => AlgorithmCategory::PostQuantum,
        }
    }
}

impl core::fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}
