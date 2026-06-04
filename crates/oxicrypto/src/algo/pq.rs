//! Post-quantum algorithm selector enums + factory functions.

#[cfg(feature = "pq-preview")]
use crate::CryptoError;

/// Post-quantum KEM algorithm selector.
#[cfg(feature = "pq-preview")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PqKemAlgo {
    /// ML-KEM-512 (FIPS 203, security category 1).
    MlKem512,
    /// ML-KEM-768 (FIPS 203, security category 3).
    MlKem768,
    /// ML-KEM-1024 (FIPS 203, security category 5).
    MlKem1024,
    /// X-Wing hybrid KEM: ML-KEM-768 + X25519 (draft-connolly-cfrg-xwing-kem-04).
    XWing768,
    /// Hybrid KEM: ML-KEM-1024 + ECDH P-384 (CNSA 2.0 target).
    HybridKem1024P384,
}

/// Post-quantum signature algorithm selector.
#[cfg(feature = "pq-preview")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PqSigAlgo {
    /// ML-DSA-44 (FIPS 204, security category 2).
    MlDsa44,
    /// ML-DSA-65 (FIPS 204, security category 3).
    MlDsa65,
    /// ML-DSA-87 (FIPS 204, security category 5).
    MlDsa87,
    /// SLH-DSA-SHA2-128s (FIPS 205, security category 1, small signature).
    SlhDsaSha2_128s,
    /// SLH-DSA-SHA2-128f (FIPS 205, security category 1, fast signing).
    SlhDsaSha2_128f,
    /// SLH-DSA-SHA2-192s (FIPS 205, security category 3, small signature).
    SlhDsaSha2_192s,
    /// SLH-DSA-SHA2-192f (FIPS 205, security category 3, fast signing).
    SlhDsaSha2_192f,
    /// SLH-DSA-SHA2-256s (FIPS 205, security category 5, small signature).
    SlhDsaSha2_256s,
    /// SLH-DSA-SHA2-256f (FIPS 205, security category 5, fast signing).
    SlhDsaSha2_256f,
    /// SLH-DSA-SHAKE-128s (FIPS 205, security category 1, small signature).
    SlhDsaShake128s,
    /// SLH-DSA-SHAKE-128f (FIPS 205, security category 1, fast signing).
    SlhDsaShake128f,
    /// SLH-DSA-SHAKE-256s (FIPS 205, security category 5, small signature).
    SlhDsaShake256s,
    /// SLH-DSA-SHAKE-256f (FIPS 205, security category 5, fast signing).
    SlhDsaShake256f,
}

/// Build an OS-seeded ChaCha20 CSPRNG for PQ key generation.
#[cfg(feature = "pq-preview")]
fn pq_os_rng() -> Result<rand_chacha::ChaCha20Rng, crate::CryptoError> {
    use rand_core::SeedableRng;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| CryptoError::Rng)?;
    Ok(rand_chacha::ChaCha20Rng::from_seed(seed))
}

/// Generate a KEM key pair, returning `(decap_key_bytes, encap_key_bytes)`.
///
/// For ML-KEM variants the decap key is a 64-byte seed; the encap key is the
/// full public key.  For hybrid variants the key material is concatenated as
/// documented per variant.
#[cfg(feature = "pq-preview")]
pub fn pq_kem_generate(
    algo: PqKemAlgo,
) -> Result<(oxicrypto_core::Vec<u8>, oxicrypto_core::Vec<u8>), CryptoError> {
    match algo {
        PqKemAlgo::MlKem512 => {
            let mut rng = pq_os_rng()?;
            let (dk, ek) = oxicrypto_pq::MlKem512::generate(&mut rng);
            let dk_bytes = dk.to_bytes()?;
            let ek_bytes = ek.to_bytes();
            Ok((dk_bytes, ek_bytes))
        }
        PqKemAlgo::MlKem768 => {
            let mut rng = pq_os_rng()?;
            let (dk, ek) = oxicrypto_pq::MlKem768::generate(&mut rng);
            let dk_bytes = dk.to_bytes()?;
            let ek_bytes = ek.to_bytes();
            Ok((dk_bytes, ek_bytes))
        }
        PqKemAlgo::MlKem1024 => {
            let mut rng = pq_os_rng()?;
            let (dk, ek) = oxicrypto_pq::MlKem1024::generate(&mut rng);
            let dk_bytes = dk.to_bytes()?;
            let ek_bytes = ek.to_bytes();
            Ok((dk_bytes, ek_bytes))
        }
        PqKemAlgo::XWing768 => {
            use oxicrypto_core::Kem;
            let (dk, ek) = oxicrypto_pq::XWing768::kem_generate()?;
            // Serialize ek: mlkem_ek (1184 B) || x25519_pk (32 B)
            let mut ek_bytes = ek.mlkem_ek.to_bytes();
            ek_bytes.extend_from_slice(&ek.x25519_pk);
            // Serialize dk: mlkem_dk seed (64 B) || x25519_sk (32 B) || x25519_pk (32 B)
            let mut dk_bytes = dk.mlkem_dk.to_bytes()?;
            dk_bytes.extend_from_slice(dk.x25519_sk.as_bytes());
            dk_bytes.extend_from_slice(&dk.x25519_pk);
            Ok((dk_bytes, ek_bytes))
        }
        PqKemAlgo::HybridKem1024P384 => {
            use oxicrypto_core::Kem;
            let (dk, ek) = oxicrypto_pq::HybridKem1024P384::kem_generate()?;
            // Serialize ek: mlkem_ek (1568 B) || p384_pk (49 B)
            let mut ek_bytes = ek.mlkem_ek.to_bytes();
            ek_bytes.extend_from_slice(&ek.p384_pk);
            // Serialize dk: mlkem_dk seed (64 B) || p384_sk || p384_pk (49 B) || mlkem_ek_bytes (1568 B)
            let mut dk_bytes = dk.mlkem_dk.to_bytes()?;
            dk_bytes.extend_from_slice(dk.p384_sk.as_bytes());
            dk_bytes.extend_from_slice(&dk.p384_pk);
            dk_bytes.extend_from_slice(&dk.mlkem_ek_bytes);
            Ok((dk_bytes, ek_bytes))
        }
    }
}

/// Generate a PQ signing key pair, returning `(signing_key_bytes, verifying_key_bytes)`.
///
/// For ML-DSA variants the signing key is the seed-expanded secret key.
/// For SLH-DSA variants the signing key is the raw secret key bytes.
#[cfg(feature = "pq-preview")]
pub fn pq_sig_generate(
    algo: PqSigAlgo,
) -> Result<(oxicrypto_core::Vec<u8>, oxicrypto_core::Vec<u8>), CryptoError> {
    let mut rng = pq_os_rng()?;

    match algo {
        PqSigAlgo::MlDsa44 => {
            let (sk, vk) = oxicrypto_pq::MlDsa44::generate(&mut rng);
            Ok((sk.to_bytes(), vk.to_bytes()))
        }
        PqSigAlgo::MlDsa65 => {
            let (sk, vk) = oxicrypto_pq::MlDsa65::generate(&mut rng);
            Ok((sk.to_bytes(), vk.to_bytes()))
        }
        PqSigAlgo::MlDsa87 => {
            let (sk, vk) = oxicrypto_pq::MlDsa87::generate(&mut rng);
            Ok((sk.to_bytes(), vk.to_bytes()))
        }
        PqSigAlgo::SlhDsaSha2_128s => {
            let (sk, vk) = oxicrypto_pq::SlhDsaSha2_128s::generate(&mut rng);
            Ok((sk.to_bytes(), vk.to_bytes()))
        }
        PqSigAlgo::SlhDsaSha2_128f => {
            let (sk, vk) = oxicrypto_pq::SlhDsaSha2_128f::generate(&mut rng);
            Ok((sk.to_bytes(), vk.to_bytes()))
        }
        PqSigAlgo::SlhDsaSha2_256s => {
            let (sk, vk) = oxicrypto_pq::SlhDsaSha2_256s::generate(&mut rng);
            Ok((sk.to_bytes(), vk.to_bytes()))
        }
        PqSigAlgo::SlhDsaSha2_256f => {
            let (sk, vk) = oxicrypto_pq::SlhDsaSha2_256f::generate(&mut rng);
            Ok((sk.to_bytes(), vk.to_bytes()))
        }
        PqSigAlgo::SlhDsaSha2_192s => {
            let (sk, vk) = oxicrypto_pq::SlhDsaSha2_192s::generate(&mut rng);
            Ok((sk.to_bytes(), vk.to_bytes()))
        }
        PqSigAlgo::SlhDsaSha2_192f => {
            let (sk, vk) = oxicrypto_pq::SlhDsaSha2_192f::generate(&mut rng);
            Ok((sk.to_bytes(), vk.to_bytes()))
        }
        PqSigAlgo::SlhDsaShake128s => {
            let (sk, vk) = oxicrypto_pq::SlhDsaShake128s::generate(&mut rng);
            Ok((sk.to_bytes(), vk.to_bytes()))
        }
        PqSigAlgo::SlhDsaShake128f => {
            let (sk, vk) = oxicrypto_pq::SlhDsaShake128f::generate(&mut rng);
            Ok((sk.to_bytes(), vk.to_bytes()))
        }
        PqSigAlgo::SlhDsaShake256s => {
            let (sk, vk) = oxicrypto_pq::SlhDsaShake256s::generate(&mut rng);
            Ok((sk.to_bytes(), vk.to_bytes()))
        }
        PqSigAlgo::SlhDsaShake256f => {
            let (sk, vk) = oxicrypto_pq::SlhDsaShake256f::generate(&mut rng);
            Ok((sk.to_bytes(), vk.to_bytes()))
        }
    }
}

// ── Display ───────────────────────────────────────────────────────────────────

#[cfg(feature = "pq-preview")]
impl core::fmt::Display for PqKemAlgo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            PqKemAlgo::MlKem512 => "ML-KEM-512",
            PqKemAlgo::MlKem768 => "ML-KEM-768",
            PqKemAlgo::MlKem1024 => "ML-KEM-1024",
            PqKemAlgo::XWing768 => "X-Wing-768",
            PqKemAlgo::HybridKem1024P384 => "Hybrid-ML-KEM-1024-P384",
        })
    }
}

#[cfg(feature = "pq-preview")]
impl core::fmt::Display for PqSigAlgo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            PqSigAlgo::MlDsa44 => "ML-DSA-44",
            PqSigAlgo::MlDsa65 => "ML-DSA-65",
            PqSigAlgo::MlDsa87 => "ML-DSA-87",
            PqSigAlgo::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
            PqSigAlgo::SlhDsaSha2_128f => "SLH-DSA-SHA2-128f",
            PqSigAlgo::SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
            PqSigAlgo::SlhDsaSha2_192f => "SLH-DSA-SHA2-192f",
            PqSigAlgo::SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
            PqSigAlgo::SlhDsaSha2_256f => "SLH-DSA-SHA2-256f",
            PqSigAlgo::SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
            PqSigAlgo::SlhDsaShake128f => "SLH-DSA-SHAKE-128f",
            PqSigAlgo::SlhDsaShake256s => "SLH-DSA-SHAKE-256s",
            PqSigAlgo::SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
        })
    }
}

// ── FromStr ───────────────────────────────────────────────────────────────────

#[cfg(feature = "pq-preview")]
impl core::str::FromStr for PqKemAlgo {
    type Err = CryptoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ML-KEM-512" | "ml-kem-512" | "MLKEM512" => Ok(PqKemAlgo::MlKem512),
            "ML-KEM-768" | "ml-kem-768" | "MLKEM768" => Ok(PqKemAlgo::MlKem768),
            "ML-KEM-1024" | "ml-kem-1024" | "MLKEM1024" => Ok(PqKemAlgo::MlKem1024),
            "X-Wing-768" | "x-wing-768" | "XWing768" => Ok(PqKemAlgo::XWing768),
            "Hybrid-ML-KEM-1024-P384" | "hybrid-ml-kem-1024-p384" => {
                Ok(PqKemAlgo::HybridKem1024P384)
            }
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }
}

#[cfg(feature = "pq-preview")]
impl core::str::FromStr for PqSigAlgo {
    type Err = CryptoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ML-DSA-44" | "ml-dsa-44" | "MLDSA44" => Ok(PqSigAlgo::MlDsa44),
            "ML-DSA-65" | "ml-dsa-65" | "MLDSA65" => Ok(PqSigAlgo::MlDsa65),
            "ML-DSA-87" | "ml-dsa-87" | "MLDSA87" => Ok(PqSigAlgo::MlDsa87),
            "SLH-DSA-SHA2-128s" | "slh-dsa-sha2-128s" | "SLHDSASHA2128S" => {
                Ok(PqSigAlgo::SlhDsaSha2_128s)
            }
            "SLH-DSA-SHA2-128f" | "slh-dsa-sha2-128f" | "SLHDSASHA2128F" => {
                Ok(PqSigAlgo::SlhDsaSha2_128f)
            }
            "SLH-DSA-SHA2-256s" | "slh-dsa-sha2-256s" | "SLHDSASHA2256S" => {
                Ok(PqSigAlgo::SlhDsaSha2_256s)
            }
            "SLH-DSA-SHA2-256f" | "slh-dsa-sha2-256f" | "SLHDSASHA2256F" => {
                Ok(PqSigAlgo::SlhDsaSha2_256f)
            }
            "SLH-DSA-SHA2-192s" | "slh-dsa-sha2-192s" | "SLHDSASHA2192S" => {
                Ok(PqSigAlgo::SlhDsaSha2_192s)
            }
            "SLH-DSA-SHA2-192f" | "slh-dsa-sha2-192f" | "SLHDSASHA2192F" => {
                Ok(PqSigAlgo::SlhDsaSha2_192f)
            }
            "SLH-DSA-SHAKE-128s" | "slh-dsa-shake-128s" | "SLHDSASHAKE128S" => {
                Ok(PqSigAlgo::SlhDsaShake128s)
            }
            "SLH-DSA-SHAKE-128f" | "slh-dsa-shake-128f" | "SLHDSASHAKE128F" => {
                Ok(PqSigAlgo::SlhDsaShake128f)
            }
            "SLH-DSA-SHAKE-256s" | "slh-dsa-shake-256s" | "SLHDSASHAKE256S" => {
                Ok(PqSigAlgo::SlhDsaShake256s)
            }
            "SLH-DSA-SHAKE-256f" | "slh-dsa-shake-256f" | "SLHDSASHAKE256F" => {
                Ok(PqSigAlgo::SlhDsaShake256f)
            }
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }
}

// ── TryFrom<&str> ─────────────────────────────────────────────────────────────

#[cfg(feature = "pq-preview")]
impl TryFrom<&str> for PqKemAlgo {
    type Error = CryptoError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

#[cfg(feature = "pq-preview")]
impl TryFrom<&str> for PqSigAlgo {
    type Error = CryptoError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

// ── pq_sign / pq_verify ───────────────────────────────────────────────────────

/// Sign `msg` with `sk_bytes` using the given PQ signature algorithm.
///
/// `sk_bytes` must be the signing key bytes produced by [`pq_sig_generate`]:
/// - For ML-DSA variants: a 32-byte seed.
/// - For SLH-DSA variants: the full raw secret key bytes.
///
/// Returns the signature bytes on success.
///
/// # Errors
/// Returns [`CryptoError::Sign`] if the key bytes are invalid or signing fails.
#[cfg(feature = "pq-preview")]
pub fn pq_sign(
    algo: PqSigAlgo,
    sk_bytes: &[u8],
    msg: &[u8],
) -> Result<oxicrypto_core::Vec<u8>, CryptoError> {
    use oxicrypto_pq::mldsa::{SigningKey44, SigningKey65, SigningKey87};
    use oxicrypto_pq::slh_dsa::{
        SlhDsaSigningKey128f, SlhDsaSigningKey128s, SlhDsaSigningKey192f, SlhDsaSigningKey192s,
        SlhDsaSigningKey256f, SlhDsaSigningKey256s, SlhDsaSigningKeyShake128f,
        SlhDsaSigningKeyShake128s, SlhDsaSigningKeyShake256f, SlhDsaSigningKeyShake256s,
    };

    match algo {
        PqSigAlgo::MlDsa44 => {
            let sk = SigningKey44::from_bytes(sk_bytes)?;
            let sig = sk.sign(msg)?;
            Ok(sig.to_bytes())
        }
        PqSigAlgo::MlDsa65 => {
            let sk = SigningKey65::from_bytes(sk_bytes)?;
            let sig = sk.sign(msg)?;
            Ok(sig.to_bytes())
        }
        PqSigAlgo::MlDsa87 => {
            let sk = SigningKey87::from_bytes(sk_bytes)?;
            let sig = sk.sign(msg)?;
            Ok(sig.to_bytes())
        }
        PqSigAlgo::SlhDsaSha2_128s => {
            let sk = SlhDsaSigningKey128s::from_bytes(sk_bytes)?;
            let sig = sk.sign(msg)?;
            Ok(sig.to_bytes())
        }
        PqSigAlgo::SlhDsaSha2_128f => {
            let sk = SlhDsaSigningKey128f::from_bytes(sk_bytes)?;
            let sig = sk.sign(msg)?;
            Ok(sig.to_bytes())
        }
        PqSigAlgo::SlhDsaSha2_192s => {
            let sk = SlhDsaSigningKey192s::from_bytes(sk_bytes)?;
            let sig = sk.sign(msg)?;
            Ok(sig.to_bytes())
        }
        PqSigAlgo::SlhDsaSha2_192f => {
            let sk = SlhDsaSigningKey192f::from_bytes(sk_bytes)?;
            let sig = sk.sign(msg)?;
            Ok(sig.to_bytes())
        }
        PqSigAlgo::SlhDsaSha2_256s => {
            let sk = SlhDsaSigningKey256s::from_bytes(sk_bytes)?;
            let sig = sk.sign(msg)?;
            Ok(sig.to_bytes())
        }
        PqSigAlgo::SlhDsaSha2_256f => {
            let sk = SlhDsaSigningKey256f::from_bytes(sk_bytes)?;
            let sig = sk.sign(msg)?;
            Ok(sig.to_bytes())
        }
        PqSigAlgo::SlhDsaShake128s => {
            let sk = SlhDsaSigningKeyShake128s::from_bytes(sk_bytes)?;
            let sig = sk.sign(msg)?;
            Ok(sig.to_bytes())
        }
        PqSigAlgo::SlhDsaShake128f => {
            let sk = SlhDsaSigningKeyShake128f::from_bytes(sk_bytes)?;
            let sig = sk.sign(msg)?;
            Ok(sig.to_bytes())
        }
        PqSigAlgo::SlhDsaShake256s => {
            let sk = SlhDsaSigningKeyShake256s::from_bytes(sk_bytes)?;
            let sig = sk.sign(msg)?;
            Ok(sig.to_bytes())
        }
        PqSigAlgo::SlhDsaShake256f => {
            let sk = SlhDsaSigningKeyShake256f::from_bytes(sk_bytes)?;
            let sig = sk.sign(msg)?;
            Ok(sig.to_bytes())
        }
    }
}

/// Verify `sig` over `msg` using `vk_bytes` and the given PQ signature algorithm.
///
/// `vk_bytes` must be the verifying key bytes produced by [`pq_sig_generate`].
/// `sig_bytes` must be the signature bytes produced by [`pq_sign`].
///
/// # Errors
/// Returns [`CryptoError::Sign`] if the signature is invalid, or
/// [`CryptoError::Encoding`] if the key or signature bytes cannot be decoded.
#[cfg(feature = "pq-preview")]
pub fn pq_verify(
    algo: PqSigAlgo,
    vk_bytes: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
) -> Result<(), CryptoError> {
    use oxicrypto_pq::mldsa::{
        Signature44, Signature65, Signature87, VerifyingKey44, VerifyingKey65, VerifyingKey87,
    };
    use oxicrypto_pq::slh_dsa::{
        SlhDsaSignature128f, SlhDsaSignature128s, SlhDsaSignature192f, SlhDsaSignature192s,
        SlhDsaSignature256f, SlhDsaSignature256s, SlhDsaSignatureShake128f,
        SlhDsaSignatureShake128s, SlhDsaSignatureShake256f, SlhDsaSignatureShake256s,
        SlhDsaVerifyingKey128f, SlhDsaVerifyingKey128s, SlhDsaVerifyingKey192f,
        SlhDsaVerifyingKey192s, SlhDsaVerifyingKey256f, SlhDsaVerifyingKey256s,
        SlhDsaVerifyingKeyShake128f, SlhDsaVerifyingKeyShake128s, SlhDsaVerifyingKeyShake256f,
        SlhDsaVerifyingKeyShake256s,
    };

    match algo {
        PqSigAlgo::MlDsa44 => {
            let vk = VerifyingKey44::from_bytes(vk_bytes)?;
            let sig = Signature44::from_bytes(sig_bytes)?;
            vk.verify(msg, &sig)
        }
        PqSigAlgo::MlDsa65 => {
            let vk = VerifyingKey65::from_bytes(vk_bytes)?;
            let sig = Signature65::from_bytes(sig_bytes)?;
            vk.verify(msg, &sig)
        }
        PqSigAlgo::MlDsa87 => {
            let vk = VerifyingKey87::from_bytes(vk_bytes)?;
            let sig = Signature87::from_bytes(sig_bytes)?;
            vk.verify(msg, &sig)
        }
        PqSigAlgo::SlhDsaSha2_128s => {
            let vk = SlhDsaVerifyingKey128s::from_bytes(vk_bytes)?;
            let sig = SlhDsaSignature128s::from_bytes(sig_bytes)?;
            vk.verify(msg, &sig)
        }
        PqSigAlgo::SlhDsaSha2_128f => {
            let vk = SlhDsaVerifyingKey128f::from_bytes(vk_bytes)?;
            let sig = SlhDsaSignature128f::from_bytes(sig_bytes)?;
            vk.verify(msg, &sig)
        }
        PqSigAlgo::SlhDsaSha2_192s => {
            let vk = SlhDsaVerifyingKey192s::from_bytes(vk_bytes)?;
            let sig = SlhDsaSignature192s::from_bytes(sig_bytes)?;
            vk.verify(msg, &sig)
        }
        PqSigAlgo::SlhDsaSha2_192f => {
            let vk = SlhDsaVerifyingKey192f::from_bytes(vk_bytes)?;
            let sig = SlhDsaSignature192f::from_bytes(sig_bytes)?;
            vk.verify(msg, &sig)
        }
        PqSigAlgo::SlhDsaSha2_256s => {
            let vk = SlhDsaVerifyingKey256s::from_bytes(vk_bytes)?;
            let sig = SlhDsaSignature256s::from_bytes(sig_bytes)?;
            vk.verify(msg, &sig)
        }
        PqSigAlgo::SlhDsaSha2_256f => {
            let vk = SlhDsaVerifyingKey256f::from_bytes(vk_bytes)?;
            let sig = SlhDsaSignature256f::from_bytes(sig_bytes)?;
            vk.verify(msg, &sig)
        }
        PqSigAlgo::SlhDsaShake128s => {
            let vk = SlhDsaVerifyingKeyShake128s::from_bytes(vk_bytes)?;
            let sig = SlhDsaSignatureShake128s::from_bytes(sig_bytes)?;
            vk.verify(msg, &sig)
        }
        PqSigAlgo::SlhDsaShake128f => {
            let vk = SlhDsaVerifyingKeyShake128f::from_bytes(vk_bytes)?;
            let sig = SlhDsaSignatureShake128f::from_bytes(sig_bytes)?;
            vk.verify(msg, &sig)
        }
        PqSigAlgo::SlhDsaShake256s => {
            let vk = SlhDsaVerifyingKeyShake256s::from_bytes(vk_bytes)?;
            let sig = SlhDsaSignatureShake256s::from_bytes(sig_bytes)?;
            vk.verify(msg, &sig)
        }
        PqSigAlgo::SlhDsaShake256f => {
            let vk = SlhDsaVerifyingKeyShake256f::from_bytes(vk_bytes)?;
            let sig = SlhDsaSignatureShake256f::from_bytes(sig_bytes)?;
            vk.verify(msg, &sig)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "pq-preview"))]
mod tests {
    use super::{pq_sig_generate, pq_sign, pq_verify, PqSigAlgo};

    /// Stack size for ML-DSA tests.  ML-DSA key/sig operations require ~4–8 MiB
    /// of stack in debug builds; we use 8 MiB uniformly.
    const MLDSA_STACK: usize = 8 * 1024 * 1024;

    /// Verify that `pq_sign` + `pq_verify` round-trips correctly for ML-DSA-65.
    ///
    /// ML-DSA-65 is chosen as a representative ML-DSA parameter set.  A
    /// tampered-message check confirms that verification actually validates content.
    ///
    /// Spawned in an 8 MiB thread because ML-DSA key operations exceed the
    /// default Rust test stack in debug builds.
    #[test]
    fn pq_sign_verify_round_trip_mldsa65() {
        std::thread::Builder::new()
            .stack_size(MLDSA_STACK)
            .spawn(|| {
                let (sk, vk) =
                    pq_sig_generate(PqSigAlgo::MlDsa65).expect("ML-DSA-65 key generation failed");
                let sig = pq_sign(PqSigAlgo::MlDsa65, &sk, b"hello oxicrypto")
                    .expect("ML-DSA-65 sign failed");
                pq_verify(PqSigAlgo::MlDsa65, &vk, b"hello oxicrypto", &sig)
                    .expect("ML-DSA-65 verify failed on correct message");
                assert!(
                    pq_verify(PqSigAlgo::MlDsa65, &vk, b"tampered message", &sig).is_err(),
                    "ML-DSA-65 verify must reject a tampered message"
                );
            })
            .expect("thread spawn failed")
            .join()
            .expect("ML-DSA-65 round-trip thread panicked");
    }

    /// Verify that `pq_sign` + `pq_verify` round-trips correctly for
    /// SLH-DSA-SHA2-128s (the smallest/fastest SLH-DSA SHA-2 parameter set).
    ///
    /// Spawned in an 8 MiB thread: SLH-DSA operations also exceed the default
    /// Rust test stack in debug builds.  This exercises the macro-generated
    /// SHA-2 type names at runtime.
    #[test]
    fn pq_sign_verify_round_trip_slhdsa_sha2_128s() {
        std::thread::Builder::new()
            .stack_size(MLDSA_STACK)
            .spawn(|| {
                let (sk, vk) = pq_sig_generate(PqSigAlgo::SlhDsaSha2_128s)
                    .expect("SLH-DSA-SHA2-128s key generation failed");
                let sig = pq_sign(PqSigAlgo::SlhDsaSha2_128s, &sk, b"hello oxicrypto")
                    .expect("SLH-DSA-SHA2-128s sign failed");
                pq_verify(PqSigAlgo::SlhDsaSha2_128s, &vk, b"hello oxicrypto", &sig)
                    .expect("SLH-DSA-SHA2-128s verify failed on correct message");
                assert!(
                    pq_verify(PqSigAlgo::SlhDsaSha2_128s, &vk, b"tampered message", &sig).is_err(),
                    "SLH-DSA-SHA2-128s verify must reject a tampered message"
                );
            })
            .expect("thread spawn failed")
            .join()
            .expect("SLH-DSA-SHA2-128s round-trip thread panicked");
    }

    /// Verify that `pq_sign` + `pq_verify` round-trips correctly for
    /// SLH-DSA-SHAKE-128s, exercising the SHAKE variant macro-generated type names.
    ///
    /// Spawned in an 8 MiB thread for the same reason as the SHA-2 variant.
    #[test]
    fn pq_sign_verify_round_trip_slhdsa_shake128s() {
        std::thread::Builder::new()
            .stack_size(MLDSA_STACK)
            .spawn(|| {
                let (sk, vk) = pq_sig_generate(PqSigAlgo::SlhDsaShake128s)
                    .expect("SLH-DSA-SHAKE-128s key generation failed");
                let sig = pq_sign(PqSigAlgo::SlhDsaShake128s, &sk, b"hello oxicrypto")
                    .expect("SLH-DSA-SHAKE-128s sign failed");
                pq_verify(PqSigAlgo::SlhDsaShake128s, &vk, b"hello oxicrypto", &sig)
                    .expect("SLH-DSA-SHAKE-128s verify failed on correct message");
                assert!(
                    pq_verify(PqSigAlgo::SlhDsaShake128s, &vk, b"tampered message", &sig).is_err(),
                    "SLH-DSA-SHAKE-128s verify must reject a tampered message"
                );
            })
            .expect("thread spawn failed")
            .join()
            .expect("SLH-DSA-SHAKE-128s round-trip thread panicked");
    }
}
