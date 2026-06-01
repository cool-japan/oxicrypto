#![forbid(unsafe_code)]

//! `oxicrypto-pq` — Post-quantum cryptography for the OxiCrypto stack.
//!
//! Implements FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) using the RustCrypto
//! `ml-kem` and `ml-dsa` crates.
//!
//! # Feature flags
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `default` | empty | No extra features; all public API is available. |
//! | `hazmat-test-vectors` | off | Enables deterministic keygen/encap helpers for KAT tests. |
//!
//! # Algorithms
//!
//! | Module | Standard | Parameter sets |
//! |--------|----------|---------------|
//! | [`mlkem`] | FIPS 203 | ML-KEM-512, ML-KEM-768, ML-KEM-1024 |
//! | [`mldsa`] | FIPS 204 | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
//! | [`slh_dsa`] | FIPS 205 | SLH-DSA-SHA2-128s/f, SLH-DSA-SHA2-192s/f, SLH-DSA-SHA2-256s/f, SLH-DSA-SHAKE-128s/f, SLH-DSA-SHAKE-256s/f |
//! | [`hybrid`] | Hybrid | X-Wing (ML-KEM-768 + X25519), Hybrid ML-KEM-1024 + P-384 |

pub mod hybrid;
pub mod mldsa;
pub mod mlkem;
pub mod slh_dsa;

pub use hybrid::{
    HybridKem1024P384, HybridKem1024P384Ciphertext, HybridKem1024P384DecapKey,
    HybridKem1024P384EncapKey, HybridP384SharedSecret, PqGroup, PqKeyShare, XWing768,
    XWing768Ciphertext, XWing768DecapKey, XWing768EncapKey, XWingSharedSecret,
};
pub use mldsa::{
    mldsa44_sign_ctx, mldsa44_verify_ctx, mldsa65_sign_ctx, mldsa65_verify_ctx, mldsa87_sign_ctx,
    mldsa87_verify_ctx, MlDsa44, MlDsa65, MlDsa87, Signature44, Signature65, Signature87,
    SigningKey44, SigningKey65, SigningKey87, VerifyingKey44, VerifyingKey65, VerifyingKey87,
};
#[allow(deprecated)]
pub use mlkem::SharedKeyPq;
pub use mlkem::{
    Ciphertext1024, Ciphertext512, Ciphertext768, DecapKey1024, DecapKey512, DecapKey768,
    EncapKey1024, EncapKey512, EncapKey768, MlKem1024, MlKem512, MlKem768, SharedSecret,
};
pub use slh_dsa::{
    // SHA2-128f
    SlhDsaSha2_128f,
    // SHA2-128s
    SlhDsaSha2_128s,
    // SHA2-192f
    SlhDsaSha2_192f,
    // SHA2-192s
    SlhDsaSha2_192s,
    // SHA2-256f
    SlhDsaSha2_256f,
    // SHA2-256s
    SlhDsaSha2_256s,
    // SHAKE-128f
    SlhDsaShake128f,
    // SHAKE-128s
    SlhDsaShake128s,
    // SHAKE-256f
    SlhDsaShake256f,
    // SHAKE-256s
    SlhDsaShake256s,
    SlhDsaSignature128f,
    SlhDsaSignature128s,
    SlhDsaSignature192f,
    SlhDsaSignature192s,
    SlhDsaSignature256f,
    SlhDsaSignature256s,
    SlhDsaSignatureShake128f,
    SlhDsaSignatureShake128s,
    SlhDsaSignatureShake256f,
    SlhDsaSignatureShake256s,
    SlhDsaSigningKey128f,
    SlhDsaSigningKey128s,
    SlhDsaSigningKey192f,
    SlhDsaSigningKey192s,
    SlhDsaSigningKey256f,
    SlhDsaSigningKey256s,
    SlhDsaSigningKeyShake128f,
    SlhDsaSigningKeyShake128s,
    SlhDsaSigningKeyShake256f,
    SlhDsaSigningKeyShake256s,
    SlhDsaVerifyingKey128f,
    SlhDsaVerifyingKey128s,
    SlhDsaVerifyingKey192f,
    SlhDsaVerifyingKey192s,
    SlhDsaVerifyingKey256f,
    SlhDsaVerifyingKey256s,
    SlhDsaVerifyingKeyShake128f,
    SlhDsaVerifyingKeyShake128s,
    SlhDsaVerifyingKeyShake256f,
    SlhDsaVerifyingKeyShake256s,
    SLH_DSA_SHA2_128F_SIG_LEN,
    SLH_DSA_SHA2_128F_SK_LEN,
    SLH_DSA_SHA2_128F_VK_LEN,
    SLH_DSA_SHA2_128S_SIG_LEN,
    // Size constants
    SLH_DSA_SHA2_128S_SK_LEN,
    SLH_DSA_SHA2_128S_VK_LEN,
    SLH_DSA_SHA2_192F_SIG_LEN,
    SLH_DSA_SHA2_192F_SK_LEN,
    SLH_DSA_SHA2_192F_VK_LEN,
    SLH_DSA_SHA2_192S_SIG_LEN,
    SLH_DSA_SHA2_192S_SK_LEN,
    SLH_DSA_SHA2_192S_VK_LEN,
    SLH_DSA_SHA2_256F_SIG_LEN,
    SLH_DSA_SHA2_256F_SK_LEN,
    SLH_DSA_SHA2_256F_VK_LEN,
    SLH_DSA_SHA2_256S_SIG_LEN,
    SLH_DSA_SHA2_256S_SK_LEN,
    SLH_DSA_SHA2_256S_VK_LEN,
    SLH_DSA_SHAKE_128F_SIG_LEN,
    SLH_DSA_SHAKE_128F_SK_LEN,
    SLH_DSA_SHAKE_128F_VK_LEN,
    SLH_DSA_SHAKE_128S_SIG_LEN,
    SLH_DSA_SHAKE_128S_SK_LEN,
    SLH_DSA_SHAKE_128S_VK_LEN,
    SLH_DSA_SHAKE_256F_SIG_LEN,
    SLH_DSA_SHAKE_256F_SK_LEN,
    SLH_DSA_SHAKE_256F_VK_LEN,
    SLH_DSA_SHAKE_256S_SIG_LEN,
    SLH_DSA_SHAKE_256S_SK_LEN,
    SLH_DSA_SHAKE_256S_VK_LEN,
};
