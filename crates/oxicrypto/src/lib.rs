#![forbid(unsafe_code)]

//! `oxicrypto` -- Pure Rust cryptography facade for the OxiCrypto stack.
//!
//! # Feature flags
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `pure` | **on** | Enables all pure-Rust sub-crates (hash, aead, mac, sig, kex, kdf, rand). |
//! | `std` | off | Propagates `std` features to subcrates. |
//! | `simd` | off | Enables explicit runtime CPU-feature detection (`AES-NI`, `SHA-NI`, `AVX2`, `NEON`). Exposes `oxicrypto::simd::cpu_info()`. The underlying RustCrypto crates already perform runtime dispatch via `cpufeatures` internally; this flag makes it visible and testable. |
//! | `pq-preview` | off | Post-quantum preview: ML-KEM (FIPS 203) + ML-DSA (FIPS 204). |
//!
//! With `default-features = false` on this crate, only the trait surface from
//! `oxicrypto-core` is available; no algorithm implementations are included.
//!
//! # Runtime feature introspection
//!
//! Use [`enabled_features()`] at runtime to see which features were compiled in.
//! Use [`available_algorithms()`] to enumerate all algorithms available in the current build.
//!
//! ## Feature flag algorithm matrix
//!
//! | Feature | Algorithms |
//! |---------|-----------|
//! | `pure` (default) | AES-GCM-128/256, ChaCha20-Poly1305, AES-CCM-128/256, AES-GCM-SIV-128/256, XChaCha20-Poly1305, AES Key Wrap 128/256; HMAC-SHA2-256/384/512, HMAC-SHA3-256/512, CMAC-AES128/256, KMAC128/256, Poly1305; SHA-256/384/512, SHA3-256/384/512, BLAKE3; Ed25519, Ed448, ECDSA P-256/384/521, RSA PKCS1v15/PSS (SHA-256/384/512); X25519, ECDH P-256/384/521; HKDF-SHA256/384/512, Argon2id, PBKDF2-SHA256/512, scrypt |
//! | `pq-preview` | ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204), SLH-DSA (all 10 param sets — SHA2/SHAKE × 128s/128f/192s/192f/256s/256f, FIPS 205), X-Wing hybrid KEM |
//! | `simd` | Explicit runtime SIMD dispatch via `simd::cpu_info()` (AES-NI, SHA-NI, AVX2, NEON) |
//! | `std` | Propagates `std` feature to all sub-crates (thread-local RNG, etc.) |

// ── Core trait surface ────────────────────────────────────────────────────────

// Re-export the trait surface, error type, and utilities from core.
pub use oxicrypto_core::{
    // Constant-time utilities.
    ct_eq,
    ct_is_zero,
    ct_select,
    Aead,
    AlgorithmCategory,
    // Algorithm identifiers.
    AlgorithmId,
    ConstantTimeEq,
    CryptoError,
    Hash,
    Kdf,
    KeyAgreement,
    KeyPair,
    Mac,
    Rng,
    // Secure wrappers.
    SecretKey,
    SecretVec,
    Signer,
    // Streaming traits.
    StreamingHash,
    StreamingMac,
    Verifier,
    // Zeroize re-exports.
    Zeroize,
    ZeroizeOnDrop,
};

// ── Concrete type re-exports (M2 — pure feature) ──────────────────────────────

#[cfg(feature = "pure")]
pub use oxicrypto_hash::{
    // ParallelHash (NIST SP 800-185 §6): fixed-output + XOF, 128- and 256-bit security.
    parallel_hash128,
    parallel_hash128_xof,
    parallel_hash256,
    parallel_hash256_xof,
    // Fluent hash construction.
    HashBuilder,
    ParallelHash128,
    ParallelHash256,
};

#[cfg(feature = "pure")]
pub use oxicrypto_aead::{
    aes128_key_unwrap,
    // AES Key Wrap (RFC 3394).
    aes128_key_wrap,
    aes256_key_unwrap,
    aes256_key_wrap,
    open_box,
    // SealedBox: nonce-prepended single-blob helpers.
    seal_box,
    // Random-nonce helper: returns (nonce, ciphertext_with_tag) separately.
    seal_with_random_nonce,
    AesGcmSiv128,
    AesGcmSiv256,
    // Deoxys-II-128-128: nonce-misuse-resistant AEAD (CAESAR portfolio).
    Deoxys2_128,
    XChaCha20Poly1305,
};

#[cfg(feature = "pure")]
pub use oxicrypto_kdf::{
    argon2id_derive,
    // Balloon (memory-hard) password hashing over SHA-256 / SHA-512.
    balloon_sha256,
    balloon_sha512,
    // TLS 1.3 / QUIC HKDF-Expand-Label (RFC 8446 §7.1).
    hkdf_expand_label_sha256,
    hkdf_expand_label_sha384,
    hkdf_sha256_expand,
    hkdf_sha256_extract,
    hkdf_sha384_expand,
    hkdf_sha384_extract,
    hkdf_sha512_expand,
    hkdf_sha512_extract,
    pbkdf2_sha256,
    pbkdf2_sha512,
    scrypt_derive,
    Argon2Params,
    // Unified key-stretching abstraction over the memory-/iteration-hard KDFs.
    Argon2idStretchParams,
    // Balloon hasher + cost parameters / variant selector.
    BalloonHasher,
    BalloonParams,
    BalloonStretchParams,
    BalloonVariant,
    // HKDF-SHA-384 and extract/expand.
    HkdfSha384,
    KeyStretcher,
    Pbkdf2StretchParams,
    ScryptStretchParams,
    StretchParams,
    Stretcher,
};

/// Raw single-block / stream cipher primitives (AES-ECB block, ChaCha20
/// keystream) used by QUIC header protection (RFC 9001 §5.4). These are
/// low-level building blocks, distinct from the authenticated AEAD ciphers.
#[cfg(feature = "pure")]
pub mod cipher {
    pub use oxicrypto_cipher::{
        aes128_encrypt_block, aes256_encrypt_block, chacha20_keystream_block, AES128_KEY_LEN,
        AES256_KEY_LEN, AES_BLOCK_LEN, CHACHA20_KEY_LEN, CHACHA20_NONCE_LEN,
    };
}

#[cfg(feature = "pure")]
pub use oxicrypto_sig::{
    // BIP-340 Schnorr over secp256k1: combined Signer+Verifier type + sign-with-aux helper.
    schnorr_bip340_sign_with_aux,
    EcdsaP256Signer,
    EcdsaP256Verifier,
    EcdsaP384Signer,
    EcdsaP384Verifier,
    EcdsaP521Signer,
    EcdsaP521Verifier,
    Ed448SigningKey,
    Ed448VerifyingKey,
    RsaPkcs1v15Sha256Signer,
    RsaPkcs1v15Sha256Verifier,
    RsaPkcs1v15Sha384Signer,
    RsaPkcs1v15Sha384Verifier,
    RsaPkcs1v15Sha512Signer,
    RsaPkcs1v15Sha512Verifier,
    RsaPssSha256Signer,
    RsaPssSha256Verifier,
    SchnorrBip340,
};

#[cfg(feature = "pure")]
pub use oxicrypto_mac::HmacSha384;

#[cfg(feature = "pure")]
pub use oxicrypto_kex::{EcdhP256, EcdhP384};

/// Hybrid Public Key Encryption (HPKE) — RFC 9180.
///
/// Complete HPKE over DHKEM(X25519/P-256, HKDF-SHA256): all four modes
/// (Base/PSK/Auth/AuthPSK), the stateful `Seal`/`Open`/`Export` context, and
/// single-shot helpers. See [`oxicrypto_kex::hpke`] for full documentation.
#[cfg(feature = "pure")]
pub mod hpke {
    pub use oxicrypto_kex::hpke::{AeadId, HpkeContextR, HpkeContextS, HpkeSuite, KdfId, KemId};
}

#[cfg(feature = "pure")]
pub use oxicrypto_rand::{random_bytes, random_nonce, random_range, reseed};

// ── Algorithm selector enums + factory functions ──────────────────────────────

pub mod algo;
pub use algo::*;

// ── Version info + available_algorithms + Suite presets ───────────────────────

pub mod version;
#[cfg(feature = "pq-preview")]
pub use version::PqSuite;
pub use version::{available_algorithms, enabled_features, version, Suite, VersionInfo};

// ── Optional adapters ─────────────────────────────────────────────────────────

/// AEAD, signature, and hash implementations backed by aws-lc-rs.
///
/// Enable with `features = ["aws-lc"]`.  The underlying aws-lc-rs library
/// is FIPS-validated and provides hardware-accelerated implementations.
/// This module is **not** activated by the `pure` default features.
#[cfg(feature = "aws-lc")]
pub mod aws_lc {
    pub use oxicrypto_adapter_aws_lc::*;
}

/// Provider, signer, and symmetric cipher backed by a PKCS#11 HSM.
///
/// Enable with `features = ["pkcs11"]`.  Requires a PKCS#11 module (e.g.
/// SoftHSM2, nShield, Thales Luna) at runtime.
/// This module is **not** activated by the `pure` default features.
#[cfg(feature = "pkcs11")]
pub mod pkcs11 {
    pub use oxicrypto_adapter_pkcs11::*;
}

/// Post-quantum cryptography preview: ML-KEM (FIPS 203) + ML-DSA (FIPS 204).
///
/// Enable with `features = ["pq-preview"]`.  API may change in future releases.
#[cfg(feature = "pq-preview")]
pub mod pq {
    pub use oxicrypto_pq::*;
}

// ── SIMD / CPU-feature detection (only when `simd` feature is on) ────────────

/// Runtime CPU feature detection for hardware-accelerated cryptography.
///
/// Available when the `simd` feature is enabled.  The underlying RustCrypto
/// crates (`aes`, `sha2`, `chacha20`) already perform this dispatch internally;
/// this module makes it **explicit and testable**.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "simd")]
/// # {
/// let info = oxicrypto::simd::cpu_info();
/// println!("AES-NI available: {}", info.has_aes_ni);
/// # }
/// ```
#[cfg(feature = "simd")]
pub mod simd {
    /// CPU feature flags relevant to cryptographic acceleration.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CpuInfo {
        /// Hardware AES instruction support (`AES-NI` on x86_64, `aes` on aarch64).
        pub has_aes_ni: bool,
        /// Hardware SHA acceleration (`SHA-NI` on x86_64, `sha2` on aarch64).
        pub has_sha_ni: bool,
        /// Advanced vector extension 2 (AVX2) on x86_64.
        pub has_avx2: bool,
        /// NEON SIMD available on aarch64.
        /// Always `true` on aarch64 (NEON is mandatory per the architecture spec).
        pub has_neon: bool,
    }

    /// Probe the current CPU at runtime and return the available feature flags.
    ///
    /// Detection uses the `cpufeatures` crate which caches results in a
    /// thread-safe atomic -- subsequent calls are cheap.  This function never
    /// panics.
    #[must_use]
    pub fn cpu_info() -> CpuInfo {
        cpu_info_impl()
    }

    // ── x86_64 ───────────────────────────────────────────────────────────────

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    fn cpu_info_impl() -> CpuInfo {
        cpufeatures::new!(oxi_aes_det, "aes");
        cpufeatures::new!(oxi_sha_det, "sha");
        cpufeatures::new!(oxi_avx2_det, "avx2");

        CpuInfo {
            has_aes_ni: oxi_aes_det::get(),
            has_sha_ni: oxi_sha_det::get(),
            has_avx2: oxi_avx2_det::get(),
            has_neon: false,
        }
    }

    // ── aarch64 ──────────────────────────────────────────────────────────────

    #[cfg(target_arch = "aarch64")]
    fn cpu_info_impl() -> CpuInfo {
        cpufeatures::new!(oxi_aes_det, "aes");
        cpufeatures::new!(oxi_sha2_det, "sha2");

        CpuInfo {
            has_aes_ni: oxi_aes_det::get(),
            has_sha_ni: oxi_sha2_det::get(),
            has_avx2: false,
            has_neon: true,
        }
    }

    // ── other architectures ──────────────────────────────────────────────────

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64",)))]
    fn cpu_info_impl() -> CpuInfo {
        CpuInfo {
            has_aes_ni: false,
            has_sha_ni: false,
            has_avx2: false,
            has_neon: false,
        }
    }
}

// ── RNG factory ───────────────────────────────────────────────────────────────

/// Create a new OS-seeded CSPRNG.
#[cfg(feature = "pure")]
pub fn new_rng() -> Result<oxicrypto_core::Box<dyn Rng>, CryptoError> {
    oxicrypto_rand::OxiRng::new()
        .map(|r| oxicrypto_core::Box::new(r) as oxicrypto_core::Box<dyn Rng>)
}

// ── Convenience one-shot hash functions ───────────────────────────────────────

/// Compute SHA-256 of `msg`, returning a 32-byte array.
#[cfg(feature = "pure")]
#[must_use]
#[inline]
pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let h = hash_impl(HashAlgo::Sha256);
    let mut out = [0u8; 32];
    h.hash(msg, &mut out)
        .expect("SHA-256 cannot fail: buffer is always correct size");
    out
}

/// Compute SHA-512 of `msg`, returning a 64-byte array.
#[cfg(feature = "pure")]
#[must_use]
#[inline]
pub fn sha512(msg: &[u8]) -> [u8; 64] {
    let h = hash_impl(HashAlgo::Sha512);
    let mut out = [0u8; 64];
    h.hash(msg, &mut out)
        .expect("SHA-512 cannot fail: buffer is always correct size");
    out
}

/// Compute BLAKE3 of `msg`, returning a 32-byte array.
#[cfg(feature = "pure")]
#[must_use]
#[inline]
pub fn blake3(msg: &[u8]) -> [u8; 32] {
    let h = hash_impl(HashAlgo::Blake3);
    let mut out = [0u8; 32];
    h.hash(msg, &mut out)
        .expect("BLAKE3 cannot fail: buffer is always correct size");
    out
}

// ── Prelude module ────────────────────────────────────────────────────────────

/// Convenient re-exports of the most commonly used traits and enums.
///
/// ```
/// use oxicrypto::prelude::*;
/// ```
pub mod prelude {
    // Core traits
    pub use oxicrypto_core::{
        Aead, AlgorithmCategory, AlgorithmId, ConstantTimeEq, CryptoError, Hash, Kdf, Kem,
        KeyAgreement, KeyPair, Mac, PasswordHash, Rng, SecretKey, SecretVec, Signer, StreamingAead,
        StreamingHash, StreamingMac, Verifier, Zeroize, ZeroizeOnDrop,
    };

    // Algorithm selector enums
    pub use crate::{AeadAlgo, HashAlgo, KdfAlgo, KexAlgo, MacAlgo, SigAlgo};

    #[cfg(feature = "pq-preview")]
    pub use crate::{PqKemAlgo, PqSigAlgo};

    // Factory functions (pure feature)
    #[cfg(feature = "pure")]
    pub use crate::{
        aead_impl, blake3, hash_impl, kdf_impl, kex_impl, mac_impl, new_rng, sha256, sha512,
        signer_impl, verifier_impl,
    };

    // Version info
    pub use crate::{available_algorithms, version, VersionInfo};
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(feature = "pure")]
mod tests;
