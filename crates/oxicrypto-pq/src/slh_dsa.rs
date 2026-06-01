//! SLH-DSA (FIPS 205) stateless hash-based digital signatures.
//!
//! Implements ten of the twelve FIPS 205 parameter sets using the `slh-dsa` crate.
//! Deterministic signing (`try_sign`) is used throughout, which is safe for
//! stateless hash-based signatures.
//!
//! | Wrapper type | Parameter set | SK bytes | VK bytes | Sig bytes |
//! |---|---|---:|---:|---:|
//! | [`SlhDsaSha2_128s`] | SLH-DSA-SHA2-128s | 64 | 32 | 7 856 |
//! | [`SlhDsaSha2_128f`] | SLH-DSA-SHA2-128f | 64 | 32 | 17 088 |
//! | [`SlhDsaSha2_192s`] | SLH-DSA-SHA2-192s | 96 | 48 | 16 224 |
//! | [`SlhDsaSha2_192f`] | SLH-DSA-SHA2-192f | 96 | 48 | 35 664 |
//! | [`SlhDsaSha2_256s`] | SLH-DSA-SHA2-256s | 128 | 64 | 29 792 |
//! | [`SlhDsaSha2_256f`] | SLH-DSA-SHA2-256f | 128 | 64 | 49 856 |
//! | [`SlhDsaShake128s`] | SLH-DSA-SHAKE-128s | 64 | 32 | 7 856 |
//! | [`SlhDsaShake128f`] | SLH-DSA-SHAKE-128f | 64 | 32 | 17 088 |
//! | [`SlhDsaShake256s`] | SLH-DSA-SHAKE-256s | 128 | 64 | 29 792 |
//! | [`SlhDsaShake256f`] | SLH-DSA-SHAKE-256f | 128 | 64 | 49 856 |
//!
//! # Usage
//!
//! ```rust
//! use rand_chacha::ChaCha20Rng;
//! use rand_core::SeedableRng;
//! use oxicrypto_pq::slh_dsa::{SlhDsaSha2_128s, SlhDsaSigningKey128s, SlhDsaVerifyingKey128s};
//!
//! let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
//! let (sk, vk) = SlhDsaSha2_128s::generate(&mut rng);
//! let sig = sk.sign(b"hello world").unwrap();
//! vk.verify(b"hello world", &sig).unwrap();
//! ```

use oxicrypto_core::CryptoError;
use rand_core::CryptoRng;
use slh_dsa::signature::{Keypair, Signer as SlhSigner, Verifier as SlhVerifier};
use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake256f, Shake256s, SigningKey, VerifyingKey,
};
use zeroize::ZeroizeOnDrop;

// ─────────────────────────────────────────────────────────────────────────────
//  FIPS 205 key/signature sizes (bytes)
// ─────────────────────────────────────────────────────────────────────────────

/// SLH-DSA-SHA2-128s signing key byte length.
pub const SLH_DSA_SHA2_128S_SK_LEN: usize = 64;
/// SLH-DSA-SHA2-128s verifying key byte length.
pub const SLH_DSA_SHA2_128S_VK_LEN: usize = 32;
/// SLH-DSA-SHA2-128s signature byte length.
pub const SLH_DSA_SHA2_128S_SIG_LEN: usize = 7856;

/// SLH-DSA-SHA2-128f signing key byte length.
pub const SLH_DSA_SHA2_128F_SK_LEN: usize = 64;
/// SLH-DSA-SHA2-128f verifying key byte length.
pub const SLH_DSA_SHA2_128F_VK_LEN: usize = 32;
/// SLH-DSA-SHA2-128f signature byte length.
pub const SLH_DSA_SHA2_128F_SIG_LEN: usize = 17088;

/// SLH-DSA-SHA2-256s signing key byte length.
pub const SLH_DSA_SHA2_256S_SK_LEN: usize = 128;
/// SLH-DSA-SHA2-256s verifying key byte length.
pub const SLH_DSA_SHA2_256S_VK_LEN: usize = 64;
/// SLH-DSA-SHA2-256s signature byte length.
pub const SLH_DSA_SHA2_256S_SIG_LEN: usize = 29792;

/// SLH-DSA-SHA2-256f signing key byte length.
pub const SLH_DSA_SHA2_256F_SK_LEN: usize = 128;
/// SLH-DSA-SHA2-256f verifying key byte length.
pub const SLH_DSA_SHA2_256F_VK_LEN: usize = 64;
/// SLH-DSA-SHA2-256f signature byte length.
pub const SLH_DSA_SHA2_256F_SIG_LEN: usize = 49856;

/// SLH-DSA-SHAKE-128s signing key byte length.
pub const SLH_DSA_SHAKE_128S_SK_LEN: usize = 64;
/// SLH-DSA-SHAKE-128s verifying key byte length.
pub const SLH_DSA_SHAKE_128S_VK_LEN: usize = 32;
/// SLH-DSA-SHAKE-128s signature byte length.
pub const SLH_DSA_SHAKE_128S_SIG_LEN: usize = 7856;

/// SLH-DSA-SHAKE-128f signing key byte length.
pub const SLH_DSA_SHAKE_128F_SK_LEN: usize = 64;
/// SLH-DSA-SHAKE-128f verifying key byte length.
pub const SLH_DSA_SHAKE_128F_VK_LEN: usize = 32;
/// SLH-DSA-SHAKE-128f signature byte length.
pub const SLH_DSA_SHAKE_128F_SIG_LEN: usize = 17088;

/// SLH-DSA-SHA2-192s signing key byte length (FIPS 205, category 3).
pub const SLH_DSA_SHA2_192S_SK_LEN: usize = 96;
/// SLH-DSA-SHA2-192s verifying key byte length.
pub const SLH_DSA_SHA2_192S_VK_LEN: usize = 48;
/// SLH-DSA-SHA2-192s signature byte length.
pub const SLH_DSA_SHA2_192S_SIG_LEN: usize = 16224;

/// SLH-DSA-SHA2-192f signing key byte length (FIPS 205, category 3).
pub const SLH_DSA_SHA2_192F_SK_LEN: usize = 96;
/// SLH-DSA-SHA2-192f verifying key byte length.
pub const SLH_DSA_SHA2_192F_VK_LEN: usize = 48;
/// SLH-DSA-SHA2-192f signature byte length.
pub const SLH_DSA_SHA2_192F_SIG_LEN: usize = 35664;

/// SLH-DSA-SHAKE-256s signing key byte length (FIPS 205, category 5).
pub const SLH_DSA_SHAKE_256S_SK_LEN: usize = 128;
/// SLH-DSA-SHAKE-256s verifying key byte length.
pub const SLH_DSA_SHAKE_256S_VK_LEN: usize = 64;
/// SLH-DSA-SHAKE-256s signature byte length.
pub const SLH_DSA_SHAKE_256S_SIG_LEN: usize = 29792;

/// SLH-DSA-SHAKE-256f signing key byte length (FIPS 205, category 5).
pub const SLH_DSA_SHAKE_256F_SK_LEN: usize = 128;
/// SLH-DSA-SHAKE-256f verifying key byte length.
pub const SLH_DSA_SHAKE_256F_VK_LEN: usize = 64;
/// SLH-DSA-SHAKE-256f signature byte length.
pub const SLH_DSA_SHAKE_256F_SIG_LEN: usize = 49856;

// ─────────────────────────────────────────────────────────────────────────────
//  Helper macro — generate the boilerplate for one parameter set
// ─────────────────────────────────────────────────────────────────────────────

/// Internal macro that expands a full parameter-set implementation given:
/// - `$unit`   : unit struct name (e.g. `SlhDsaSha2_128s`)
/// - `$sk`     : signing-key newtype (e.g. `SlhDsaSigningKey128s`)
/// - `$vk`     : verifying-key newtype (e.g. `SlhDsaVerifyingKey128s`)
/// - `$sig`    : signature newtype (e.g. `SlhDsaSignature128s`)
/// - `$params` : slh_dsa parameter type (e.g. `Sha2_128s`)
/// - `$sk_len` : signing-key length constant
/// - `$vk_len` : verifying-key length constant
/// - `$sig_len`: signature length constant
/// - `$name`   : NIST algorithm name string
macro_rules! impl_slh_dsa_param {
    (
        unit    = $unit:ident,
        sk      = $sk:ident,
        vk      = $vk:ident,
        sig     = $sig:ident,
        params  = $params:ty,
        sk_len  = $sk_len:ident,
        vk_len  = $vk_len:ident,
        sig_len = $sig_len:ident,
        name    = $name:literal $(,)?
    ) => {
        // ── Signing key ────────────────────────────────────────────────────

        /// Signing (private) key for $name.
        pub struct $sk(SigningKey<$params>);

        impl ZeroizeOnDrop for $sk {}

        impl $sk {
            /// Sign `msg` deterministically, returning a detached signature.
            pub fn sign(&self, msg: &[u8]) -> Result<$sig, CryptoError> {
                self.0
                    .try_sign(msg)
                    .map($sig)
                    .map_err(|_| CryptoError::Sign)
            }

            /// Serialize the signing key to raw bytes.
            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.to_bytes().to_vec()
            }

            /// Deserialize a signing key from raw bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
                SigningKey::<$params>::try_from(bytes)
                    .map(Self)
                    .map_err(|_| CryptoError::Encoding)
            }
        }

        impl core::fmt::Debug for $sk {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}(***)", stringify!($sk))
            }
        }

        // ── Verifying key ──────────────────────────────────────────────────

        /// Verifying (public) key for $name.
        pub struct $vk(VerifyingKey<$params>);

        impl $vk {
            /// Verify `sig` over `msg`.
            pub fn verify(&self, msg: &[u8], sig: &$sig) -> Result<(), CryptoError> {
                self.0.verify(msg, &sig.0).map_err(|_| CryptoError::Sign)
            }

            /// Serialize the verifying key to raw bytes.
            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.to_bytes().to_vec()
            }

            /// Deserialize a verifying key from raw bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
                VerifyingKey::<$params>::try_from(bytes)
                    .map(Self)
                    .map_err(|_| CryptoError::Encoding)
            }
        }

        impl core::fmt::Debug for $vk {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}(len={})", stringify!($vk), $vk_len)
            }
        }

        // ── Signature ──────────────────────────────────────────────────────

        /// Signature produced by the corresponding signing key's `sign` method.
        pub struct $sig(slh_dsa::Signature<$params>);

        impl $sig {
            /// Serialize the signature to raw bytes.
            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.to_bytes().to_vec()
            }

            /// Deserialize a signature from raw bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
                slh_dsa::Signature::<$params>::try_from(bytes)
                    .map(Self)
                    .map_err(|_| CryptoError::Encoding)
            }
        }

        impl core::fmt::Debug for $sig {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}(len={})", stringify!($sig), $sig_len)
            }
        }

        // ── Unit struct + keygen ───────────────────────────────────────────

        /// $name parameter set unit struct — use for keygen and trait dispatch.
        #[derive(Debug, Default, Clone, Copy)]
        pub struct $unit;

        impl $unit {
            /// Generate a fresh $name key pair using the provided CSPRNG.
            pub fn generate<R: CryptoRng>(rng: &mut R) -> ($sk, $vk) {
                let sk = SigningKey::<$params>::new(rng);
                let vk = sk.verifying_key();
                ($sk(sk), $vk(vk))
            }
        }

        // ── Signer / Verifier trait impls ──────────────────────────────────

        impl oxicrypto_core::Signer for $unit {
            fn name(&self) -> &'static str {
                $name
            }

            fn signature_len(&self) -> usize {
                $sig_len
            }

            fn sign(
                &self,
                sk: &[u8],
                msg: &[u8],
                sig_out: &mut [u8],
            ) -> Result<usize, CryptoError> {
                if sig_out.len() < $sig_len {
                    return Err(CryptoError::BufferTooSmall);
                }
                let signing_key = $sk::from_bytes(sk)?;
                let sig = signing_key.sign(msg)?;
                let sig_bytes = sig.to_bytes();
                sig_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
                Ok(sig_bytes.len())
            }
        }

        impl oxicrypto_core::Verifier for $unit {
            fn name(&self) -> &'static str {
                $name
            }

            fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
                let vk = $vk::from_bytes(pk)?;
                let signature = $sig::from_bytes(sig)?;
                vk.verify(msg, &signature)
            }
        }
    };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Expand all ten parameter sets
// ─────────────────────────────────────────────────────────────────────────────

impl_slh_dsa_param! {
    unit    = SlhDsaSha2_128s,
    sk      = SlhDsaSigningKey128s,
    vk      = SlhDsaVerifyingKey128s,
    sig     = SlhDsaSignature128s,
    params  = Sha2_128s,
    sk_len  = SLH_DSA_SHA2_128S_SK_LEN,
    vk_len  = SLH_DSA_SHA2_128S_VK_LEN,
    sig_len = SLH_DSA_SHA2_128S_SIG_LEN,
    name    = "SLH-DSA-SHA2-128s",
}

impl_slh_dsa_param! {
    unit    = SlhDsaSha2_128f,
    sk      = SlhDsaSigningKey128f,
    vk      = SlhDsaVerifyingKey128f,
    sig     = SlhDsaSignature128f,
    params  = Sha2_128f,
    sk_len  = SLH_DSA_SHA2_128F_SK_LEN,
    vk_len  = SLH_DSA_SHA2_128F_VK_LEN,
    sig_len = SLH_DSA_SHA2_128F_SIG_LEN,
    name    = "SLH-DSA-SHA2-128f",
}

impl_slh_dsa_param! {
    unit    = SlhDsaSha2_256s,
    sk      = SlhDsaSigningKey256s,
    vk      = SlhDsaVerifyingKey256s,
    sig     = SlhDsaSignature256s,
    params  = Sha2_256s,
    sk_len  = SLH_DSA_SHA2_256S_SK_LEN,
    vk_len  = SLH_DSA_SHA2_256S_VK_LEN,
    sig_len = SLH_DSA_SHA2_256S_SIG_LEN,
    name    = "SLH-DSA-SHA2-256s",
}

impl_slh_dsa_param! {
    unit    = SlhDsaSha2_256f,
    sk      = SlhDsaSigningKey256f,
    vk      = SlhDsaVerifyingKey256f,
    sig     = SlhDsaSignature256f,
    params  = Sha2_256f,
    sk_len  = SLH_DSA_SHA2_256F_SK_LEN,
    vk_len  = SLH_DSA_SHA2_256F_VK_LEN,
    sig_len = SLH_DSA_SHA2_256F_SIG_LEN,
    name    = "SLH-DSA-SHA2-256f",
}

impl_slh_dsa_param! {
    unit    = SlhDsaShake128s,
    sk      = SlhDsaSigningKeyShake128s,
    vk      = SlhDsaVerifyingKeyShake128s,
    sig     = SlhDsaSignatureShake128s,
    params  = Shake128s,
    sk_len  = SLH_DSA_SHAKE_128S_SK_LEN,
    vk_len  = SLH_DSA_SHAKE_128S_VK_LEN,
    sig_len = SLH_DSA_SHAKE_128S_SIG_LEN,
    name    = "SLH-DSA-SHAKE-128s",
}

impl_slh_dsa_param! {
    unit    = SlhDsaShake128f,
    sk      = SlhDsaSigningKeyShake128f,
    vk      = SlhDsaVerifyingKeyShake128f,
    sig     = SlhDsaSignatureShake128f,
    params  = Shake128f,
    sk_len  = SLH_DSA_SHAKE_128F_SK_LEN,
    vk_len  = SLH_DSA_SHAKE_128F_VK_LEN,
    sig_len = SLH_DSA_SHAKE_128F_SIG_LEN,
    name    = "SLH-DSA-SHAKE-128f",
}

impl_slh_dsa_param! {
    unit    = SlhDsaSha2_192s,
    sk      = SlhDsaSigningKey192s,
    vk      = SlhDsaVerifyingKey192s,
    sig     = SlhDsaSignature192s,
    params  = Sha2_192s,
    sk_len  = SLH_DSA_SHA2_192S_SK_LEN,
    vk_len  = SLH_DSA_SHA2_192S_VK_LEN,
    sig_len = SLH_DSA_SHA2_192S_SIG_LEN,
    name    = "SLH-DSA-SHA2-192s",
}

impl_slh_dsa_param! {
    unit    = SlhDsaSha2_192f,
    sk      = SlhDsaSigningKey192f,
    vk      = SlhDsaVerifyingKey192f,
    sig     = SlhDsaSignature192f,
    params  = Sha2_192f,
    sk_len  = SLH_DSA_SHA2_192F_SK_LEN,
    vk_len  = SLH_DSA_SHA2_192F_VK_LEN,
    sig_len = SLH_DSA_SHA2_192F_SIG_LEN,
    name    = "SLH-DSA-SHA2-192f",
}

impl_slh_dsa_param! {
    unit    = SlhDsaShake256s,
    sk      = SlhDsaSigningKeyShake256s,
    vk      = SlhDsaVerifyingKeyShake256s,
    sig     = SlhDsaSignatureShake256s,
    params  = Shake256s,
    sk_len  = SLH_DSA_SHAKE_256S_SK_LEN,
    vk_len  = SLH_DSA_SHAKE_256S_VK_LEN,
    sig_len = SLH_DSA_SHAKE_256S_SIG_LEN,
    name    = "SLH-DSA-SHAKE-256s",
}

impl_slh_dsa_param! {
    unit    = SlhDsaShake256f,
    sk      = SlhDsaSigningKeyShake256f,
    vk      = SlhDsaVerifyingKeyShake256f,
    sig     = SlhDsaSignatureShake256f,
    params  = Shake256f,
    sk_len  = SLH_DSA_SHAKE_256F_SK_LEN,
    vk_len  = SLH_DSA_SHAKE_256F_VK_LEN,
    sig_len = SLH_DSA_SHAKE_256F_SIG_LEN,
    name    = "SLH-DSA-SHAKE-256f",
}

// ─────────────────────────────────────────────────────────────────────────────
//  Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const TEST_MSG: &[u8] = b"oxicrypto-pq SLH-DSA test message";

    // ── SHA2-128s ────────────────────────────────────────────────────────────

    #[test]
    #[ignore] // Slow: SHA2-128s signing takes ~280s; run with --ignored
    fn test_slh_dsa_sha2_128s_round_trip() {
        // Small stack; 128s signatures fit in ~8 KiB
        let mut rng = ChaCha20Rng::from_seed([0xA1u8; 32]);
        let (sk, vk) = SlhDsaSha2_128s::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sha2_128s sign failed");
        vk.verify(TEST_MSG, &sig).expect("sha2_128s verify failed");
    }

    #[test]
    #[ignore] // Slow: SHA2-128s signing takes ~280s; run with --ignored
    fn test_slh_dsa_sha2_128s_wrong_message_fails() {
        let mut rng = ChaCha20Rng::from_seed([0xA2u8; 32]);
        let (sk, vk) = SlhDsaSha2_128s::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        let mut altered = TEST_MSG.to_vec();
        altered[0] ^= 0x01;
        assert!(
            vk.verify(&altered, &sig).is_err(),
            "sha2_128s verify should fail on altered message"
        );
    }

    // ── SHA2-128f ────────────────────────────────────────────────────────────

    #[test]
    fn test_slh_dsa_sha2_128f_round_trip() {
        let mut rng = ChaCha20Rng::from_seed([0xB1u8; 32]);
        let (sk, vk) = SlhDsaSha2_128f::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sha2_128f sign failed");
        vk.verify(TEST_MSG, &sig).expect("sha2_128f verify failed");
    }

    #[test]
    fn test_slh_dsa_sha2_128f_wrong_message_fails() {
        let mut rng = ChaCha20Rng::from_seed([0xB2u8; 32]);
        let (sk, vk) = SlhDsaSha2_128f::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        let mut altered = TEST_MSG.to_vec();
        altered[0] ^= 0xFF;
        assert!(
            vk.verify(&altered, &sig).is_err(),
            "sha2_128f verify should fail on altered message"
        );
    }

    // ── SHA2-256s (needs extra stack) ────────────────────────────────────────

    #[test]
    #[ignore] // Slow: SHA2-256s signing takes >260s; run with --ignored
    fn test_slh_dsa_sha2_256s_round_trip() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0xC1u8; 32]);
                let (sk, vk) = SlhDsaSha2_256s::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("sha2_256s sign failed");
                vk.verify(TEST_MSG, &sig).expect("sha2_256s verify failed");
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    // ── SHA2-256f (needs extra stack) ────────────────────────────────────────

    #[test]
    fn test_slh_dsa_sha2_256f_round_trip() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0xD1u8; 32]);
                let (sk, vk) = SlhDsaSha2_256f::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("sha2_256f sign failed");
                vk.verify(TEST_MSG, &sig).expect("sha2_256f verify failed");
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    // ── SHAKE-128s ───────────────────────────────────────────────────────────

    #[test]
    #[ignore] // Slow: SHAKE-128s signing takes ~150s; run with --ignored
    fn test_slh_dsa_shake_128s_round_trip() {
        let mut rng = ChaCha20Rng::from_seed([0xE1u8; 32]);
        let (sk, vk) = SlhDsaShake128s::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("shake_128s sign failed");
        vk.verify(TEST_MSG, &sig).expect("shake_128s verify failed");
    }

    #[test]
    #[ignore] // Slow: SHAKE-128s signing takes ~150s; run with --ignored
    fn test_slh_dsa_shake_128s_wrong_message_fails() {
        let mut rng = ChaCha20Rng::from_seed([0xE2u8; 32]);
        let (sk, vk) = SlhDsaShake128s::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        let mut altered = TEST_MSG.to_vec();
        altered[3] ^= 0x55;
        assert!(
            vk.verify(&altered, &sig).is_err(),
            "shake_128s verify should fail on altered message"
        );
    }

    // ── SHAKE-128f ───────────────────────────────────────────────────────────

    #[test]
    fn test_slh_dsa_shake_128f_round_trip() {
        let mut rng = ChaCha20Rng::from_seed([0xF1u8; 32]);
        let (sk, vk) = SlhDsaShake128f::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("shake_128f sign failed");
        vk.verify(TEST_MSG, &sig).expect("shake_128f verify failed");
    }

    #[test]
    fn test_slh_dsa_shake_128f_wrong_message_fails() {
        let mut rng = ChaCha20Rng::from_seed([0xF2u8; 32]);
        let (sk, vk) = SlhDsaShake128f::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        let mut altered = TEST_MSG.to_vec();
        altered[5] ^= 0x11;
        assert!(
            vk.verify(&altered, &sig).is_err(),
            "shake_128f verify should fail on altered message"
        );
    }

    // ── SHA2-192s (category 3, needs extra stack) ────────────────────────────

    #[test]
    #[ignore] // Slow: SHA2-192s signing is computationally intensive
    fn test_slh_dsa_sha2_192s_round_trip() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0x91u8; 32]);
                let (sk, vk) = SlhDsaSha2_192s::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("sha2_192s sign failed");
                vk.verify(TEST_MSG, &sig).expect("sha2_192s verify failed");
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    #[ignore] // Slow: SHA2-192s signing is computationally intensive
    fn test_slh_dsa_sha2_192s_wrong_message_fails() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0x92u8; 32]);
                let (sk, vk) = SlhDsaSha2_192s::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("sign failed");
                let mut altered = TEST_MSG.to_vec();
                altered[2] ^= 0xAA;
                assert!(
                    vk.verify(&altered, &sig).is_err(),
                    "sha2_192s verify should fail on altered message"
                );
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    // ── SHA2-192f (category 3, needs extra stack) ────────────────────────────

    #[test]
    #[ignore] // Slow: SHA2-192f signing is computationally intensive
    fn test_slh_dsa_sha2_192f_round_trip() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0x93u8; 32]);
                let (sk, vk) = SlhDsaSha2_192f::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("sha2_192f sign failed");
                vk.verify(TEST_MSG, &sig).expect("sha2_192f verify failed");
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    #[ignore] // Slow: SHA2-192f signing is computationally intensive
    fn test_slh_dsa_sha2_192f_wrong_message_fails() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0x94u8; 32]);
                let (sk, vk) = SlhDsaSha2_192f::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("sign failed");
                let mut altered = TEST_MSG.to_vec();
                altered[7] ^= 0xBB;
                assert!(
                    vk.verify(&altered, &sig).is_err(),
                    "sha2_192f verify should fail on altered message"
                );
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    // ── SHAKE-256s (category 5, needs extra stack) ───────────────────────────

    #[test]
    #[ignore] // Slow: SHAKE-256s signing is computationally intensive
    fn test_slh_dsa_shake_256s_round_trip() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0x95u8; 32]);
                let (sk, vk) = SlhDsaShake256s::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("shake_256s sign failed");
                vk.verify(TEST_MSG, &sig).expect("shake_256s verify failed");
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    #[ignore] // Slow: SHAKE-256s signing is computationally intensive
    fn test_slh_dsa_shake_256s_wrong_message_fails() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0x96u8; 32]);
                let (sk, vk) = SlhDsaShake256s::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("sign failed");
                let mut altered = TEST_MSG.to_vec();
                altered[1] ^= 0xCC;
                assert!(
                    vk.verify(&altered, &sig).is_err(),
                    "shake_256s verify should fail on altered message"
                );
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    // ── SHAKE-256f (category 5, needs extra stack) ───────────────────────────

    #[test]
    #[ignore] // Slow: SHAKE-256f signing is computationally intensive
    fn test_slh_dsa_shake_256f_round_trip() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0x97u8; 32]);
                let (sk, vk) = SlhDsaShake256f::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("shake_256f sign failed");
                vk.verify(TEST_MSG, &sig).expect("shake_256f verify failed");
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    #[ignore] // Slow: SHAKE-256f signing is computationally intensive
    fn test_slh_dsa_shake_256f_wrong_message_fails() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0x98u8; 32]);
                let (sk, vk) = SlhDsaShake256f::generate(&mut rng);
                let sig = sk.sign(TEST_MSG).expect("sign failed");
                let mut altered = TEST_MSG.to_vec();
                altered[4] ^= 0xDD;
                assert!(
                    vk.verify(&altered, &sig).is_err(),
                    "shake_256f verify should fail on altered message"
                );
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    // ── Serialization round-trips ────────────────────────────────────────────

    #[test]
    #[ignore] // Slow: uses SHA2-128s which takes ~340s total; run with --ignored
    fn test_slh_dsa_serialization_round_trip() {
        // SHA2-128s for fast test; all param sets use same (de)serialization path
        let mut rng = ChaCha20Rng::from_seed([0x11u8; 32]);
        let (sk, vk) = SlhDsaSha2_128s::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");

        // Round-trip signing key
        let sk_bytes = sk.to_bytes();
        let sk2 = SlhDsaSigningKey128s::from_bytes(&sk_bytes).expect("sk from_bytes failed");
        let sig2 = sk2
            .sign(TEST_MSG)
            .expect("sign with deserialized sk failed");

        // Round-trip verifying key
        let vk_bytes = vk.to_bytes();
        let vk2 = SlhDsaVerifyingKey128s::from_bytes(&vk_bytes).expect("vk from_bytes failed");
        vk2.verify(TEST_MSG, &sig)
            .expect("verify with deserialized vk failed");
        vk2.verify(TEST_MSG, &sig2)
            .expect("verify sig2 with deserialized vk failed");

        // Round-trip signature
        let sig_bytes = sig.to_bytes();
        let sig3 = SlhDsaSignature128s::from_bytes(&sig_bytes).expect("sig from_bytes failed");
        vk2.verify(TEST_MSG, &sig3)
            .expect("verify deserialized sig failed");
    }

    // ── Tamper detection ─────────────────────────────────────────────────────

    #[test]
    fn test_slh_dsa_tamper_message_fails() {
        let mut rng = ChaCha20Rng::from_seed([0x22u8; 32]);
        let (sk, vk) = SlhDsaShake128f::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");

        let mut tampered = TEST_MSG.to_vec();
        tampered[0] ^= 0x01;
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "verify must fail when message is tampered"
        );
    }

    #[test]
    fn test_slh_dsa_tamper_signature_fails() {
        let mut rng = ChaCha20Rng::from_seed([0x33u8; 32]);
        let (sk, vk) = SlhDsaShake128f::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");

        let mut sig_bytes = sig.to_bytes();
        // Flip a byte near the start of the signature
        sig_bytes[4] ^= 0xFF;
        let tampered_sig =
            SlhDsaSignatureShake128f::from_bytes(&sig_bytes).expect("from_bytes failed");
        assert!(
            vk.verify(TEST_MSG, &tampered_sig).is_err(),
            "verify must fail when signature is tampered"
        );
    }

    #[test]
    fn test_slh_dsa_wrong_verifying_key_fails() {
        let mut rng = ChaCha20Rng::from_seed([0x44u8; 32]);
        let (sk, _vk) = SlhDsaSha2_128s::generate(&mut rng);
        let (_, wrong_vk) = SlhDsaSha2_128s::generate(&mut rng);
        let sig = sk.sign(TEST_MSG).expect("sign failed");
        assert!(
            wrong_vk.verify(TEST_MSG, &sig).is_err(),
            "verify must fail with wrong verifying key"
        );
    }

    // ── Key/signature size validation ────────────────────────────────────────

    #[test]
    #[ignore] // Slow: signs with SHA2/SHAKE-128s which takes >340s; run with --ignored
    fn test_slh_dsa_param_set_key_sizes() {
        let mut rng = ChaCha20Rng::from_seed([0x55u8; 32]);

        // SHA2-128s
        let (sk, vk) = SlhDsaSha2_128s::generate(&mut rng);
        let sig = sk.sign(b"size-check").expect("sign failed");
        assert_eq!(
            sk.to_bytes().len(),
            SLH_DSA_SHA2_128S_SK_LEN,
            "SHA2-128s SK size"
        );
        assert_eq!(
            vk.to_bytes().len(),
            SLH_DSA_SHA2_128S_VK_LEN,
            "SHA2-128s VK size"
        );
        assert_eq!(
            sig.to_bytes().len(),
            SLH_DSA_SHA2_128S_SIG_LEN,
            "SHA2-128s sig size"
        );

        // SHA2-128f
        let (sk, vk) = SlhDsaSha2_128f::generate(&mut rng);
        let sig = sk.sign(b"size-check").expect("sign failed");
        assert_eq!(
            sk.to_bytes().len(),
            SLH_DSA_SHA2_128F_SK_LEN,
            "SHA2-128f SK size"
        );
        assert_eq!(
            vk.to_bytes().len(),
            SLH_DSA_SHA2_128F_VK_LEN,
            "SHA2-128f VK size"
        );
        assert_eq!(
            sig.to_bytes().len(),
            SLH_DSA_SHA2_128F_SIG_LEN,
            "SHA2-128f sig size"
        );

        // SHAKE-128s
        let (sk, vk) = SlhDsaShake128s::generate(&mut rng);
        let sig = sk.sign(b"size-check").expect("sign failed");
        assert_eq!(
            sk.to_bytes().len(),
            SLH_DSA_SHAKE_128S_SK_LEN,
            "SHAKE-128s SK size"
        );
        assert_eq!(
            vk.to_bytes().len(),
            SLH_DSA_SHAKE_128S_VK_LEN,
            "SHAKE-128s VK size"
        );
        assert_eq!(
            sig.to_bytes().len(),
            SLH_DSA_SHAKE_128S_SIG_LEN,
            "SHAKE-128s sig size"
        );

        // SHAKE-128f
        let (sk, vk) = SlhDsaShake128f::generate(&mut rng);
        let sig = sk.sign(b"size-check").expect("sign failed");
        assert_eq!(
            sk.to_bytes().len(),
            SLH_DSA_SHAKE_128F_SK_LEN,
            "SHAKE-128f SK size"
        );
        assert_eq!(
            vk.to_bytes().len(),
            SLH_DSA_SHAKE_128F_VK_LEN,
            "SHAKE-128f VK size"
        );
        assert_eq!(
            sig.to_bytes().len(),
            SLH_DSA_SHAKE_128F_SIG_LEN,
            "SHAKE-128f sig size"
        );
    }

    // ── Size checks for the 4 new (192/SHAKE-256) param sets ─────────────────
    //  These use a larger stack thread because the underlying slh-dsa crate
    //  uses deep recursion during tree computation.

    #[test]
    fn test_slh_dsa_sha2_192s_key_sizes() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0xA3u8; 32]);
                let (sk, vk) = SlhDsaSha2_192s::generate(&mut rng);
                assert_eq!(
                    sk.to_bytes().len(),
                    SLH_DSA_SHA2_192S_SK_LEN,
                    "SHA2-192s SK size"
                );
                assert_eq!(
                    vk.to_bytes().len(),
                    SLH_DSA_SHA2_192S_VK_LEN,
                    "SHA2-192s VK size"
                );
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    fn test_slh_dsa_sha2_192f_key_sizes() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0xA4u8; 32]);
                let (sk, vk) = SlhDsaSha2_192f::generate(&mut rng);
                assert_eq!(
                    sk.to_bytes().len(),
                    SLH_DSA_SHA2_192F_SK_LEN,
                    "SHA2-192f SK size"
                );
                assert_eq!(
                    vk.to_bytes().len(),
                    SLH_DSA_SHA2_192F_VK_LEN,
                    "SHA2-192f VK size"
                );
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    #[ignore] // Slow: SHAKE-256s key generation takes >60s; run with --ignored
    fn test_slh_dsa_shake_256s_key_sizes() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0xA5u8; 32]);
                let (sk, vk) = SlhDsaShake256s::generate(&mut rng);
                assert_eq!(
                    sk.to_bytes().len(),
                    SLH_DSA_SHAKE_256S_SK_LEN,
                    "SHAKE-256s SK size"
                );
                assert_eq!(
                    vk.to_bytes().len(),
                    SLH_DSA_SHAKE_256S_VK_LEN,
                    "SHAKE-256s VK size"
                );
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    fn test_slh_dsa_shake_256f_key_sizes() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed([0xA6u8; 32]);
                let (sk, vk) = SlhDsaShake256f::generate(&mut rng);
                assert_eq!(
                    sk.to_bytes().len(),
                    SLH_DSA_SHAKE_256F_SK_LEN,
                    "SHAKE-256f SK size"
                );
                assert_eq!(
                    vk.to_bytes().len(),
                    SLH_DSA_SHAKE_256F_VK_LEN,
                    "SHAKE-256f VK size"
                );
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    // ── Signer / Verifier trait tests ────────────────────────────────────────

    #[test]
    #[ignore] // Slow: SHA2-128s signing takes ~280s; run with --ignored
    fn test_slh_dsa_signer_verifier_trait_sha2_128s() {
        use oxicrypto_core::{Signer, Verifier};

        let mut rng = ChaCha20Rng::from_seed([0x66u8; 32]);
        let (sk_typed, vk_typed) = SlhDsaSha2_128s::generate(&mut rng);
        let sk_bytes = sk_typed.to_bytes();
        let vk_bytes = vk_typed.to_bytes();

        let signer = SlhDsaSha2_128s;
        let verifier = SlhDsaSha2_128s;

        let mut sig_buf = vec![0u8; SLH_DSA_SHA2_128S_SIG_LEN];
        let written = signer
            .sign(&sk_bytes, TEST_MSG, &mut sig_buf)
            .expect("trait sign failed");
        assert_eq!(written, SLH_DSA_SHA2_128S_SIG_LEN);
        verifier
            .verify(&vk_bytes, TEST_MSG, &sig_buf)
            .expect("trait verify failed");
    }

    #[test]
    #[ignore] // Slow: SHAKE-128f signing can exceed 20s under load; run with --ignored
    fn test_slh_dsa_signer_verifier_trait_shake_128f() {
        use oxicrypto_core::{Signer, Verifier};

        let mut rng = ChaCha20Rng::from_seed([0x77u8; 32]);
        let (sk_typed, vk_typed) = SlhDsaShake128f::generate(&mut rng);
        let sk_bytes = sk_typed.to_bytes();
        let vk_bytes = vk_typed.to_bytes();

        let signer = SlhDsaShake128f;
        let verifier = SlhDsaShake128f;

        let mut sig_buf = vec![0u8; SLH_DSA_SHAKE_128F_SIG_LEN];
        let written = signer
            .sign(&sk_bytes, TEST_MSG, &mut sig_buf)
            .expect("trait sign failed");
        assert_eq!(written, SLH_DSA_SHAKE_128F_SIG_LEN);
        verifier
            .verify(&vk_bytes, TEST_MSG, &sig_buf)
            .expect("trait verify failed");
    }

    #[test]
    fn test_slh_dsa_signer_trait_buffer_too_small() {
        use oxicrypto_core::Signer;

        let mut rng = ChaCha20Rng::from_seed([0x88u8; 32]);
        let (sk_typed, _) = SlhDsaSha2_128s::generate(&mut rng);
        let sk_bytes = sk_typed.to_bytes();

        let signer = SlhDsaSha2_128s;
        let mut tiny = vec![0u8; 16];
        let result = signer.sign(&sk_bytes, TEST_MSG, &mut tiny);
        assert_eq!(result, Err(CryptoError::BufferTooSmall));
    }

    #[test]
    fn test_slh_dsa_deserialization_invalid_bytes_fail() {
        // Each from_bytes call with wrong-length input must return Encoding error
        assert!(SlhDsaSigningKey128s::from_bytes(&[0u8; 16]).is_err());
        assert!(SlhDsaVerifyingKey128s::from_bytes(&[0u8; 16]).is_err());
        assert!(SlhDsaSignature128s::from_bytes(&[0u8; 16]).is_err());
    }
}
