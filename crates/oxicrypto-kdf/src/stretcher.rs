#![forbid(unsafe_code)]

//! A unifying [`KeyStretcher`] abstraction over the crate's memory-hard and
//! iteration-hard password-based key-derivation functions.
//!
//! [`KeyStretcher`] is an **object-safe** trait — `Box<dyn KeyStretcher>` works
//! — exposing a single `stretch(password, salt) -> SecretVec` entry point so
//! callers can select an algorithm at runtime without committing to a concrete
//! type. [`Stretcher`] is the built-in implementation; it wraps a
//! [`StretchParams`] enum that delegates to:
//!
//! - **Argon2id** ([`crate::argon2id_derive`])
//! - **scrypt** ([`crate::scrypt_derive`])
//! - **PBKDF2-HMAC-SHA-256** ([`crate::pbkdf2_sha256`])
//! - **Balloon-SHA-256** ([`crate::balloon_sha256`])
//!
//! Each variant carries its own cost parameters and the desired derived-key
//! length; the result is wrapped in a [`SecretVec`] that zeroizes on drop.
//!
//! ```
//! use oxicrypto_kdf::{KeyStretcher, Stretcher, StretchParams};
//! use oxicrypto_kdf::Pbkdf2StretchParams;
//!
//! let stretcher: Box<dyn KeyStretcher> = Box::new(Stretcher::new(
//!     StretchParams::Pbkdf2Sha256(Pbkdf2StretchParams { iterations: 1000, out_len: 32 }),
//! ));
//! let key = stretcher.stretch(b"password", b"salt").expect("derive");
//! assert_eq!(key.len(), 32);
//! ```

use oxicrypto_core::{CryptoError, SecretVec};

use crate::argon2_kdf::{argon2id_derive, Argon2Params};
use crate::balloon::balloon_sha256;
use crate::pbkdf2_kdf::pbkdf2_sha256;
use crate::scrypt_kdf::scrypt_derive;

/// Parameters for the Argon2id stretching backend.
#[derive(Debug, Clone, Copy)]
pub struct Argon2idStretchParams {
    /// Argon2 cost parameters (`m_cost`, `t_cost`, `p_cost`).
    pub params: Argon2Params,
    /// Derived-key length in bytes (1..=64, per the Argon2 spec).
    pub out_len: usize,
}

/// Parameters for the scrypt stretching backend.
#[derive(Debug, Clone, Copy)]
pub struct ScryptStretchParams {
    /// CPU/memory cost factor as log₂(N).
    pub log_n: u8,
    /// Block size (RFC 7914 recommends `r = 8`).
    pub r: u32,
    /// Parallelization factor (RFC 7914 recommends `p = 1`).
    pub p: u32,
    /// Derived-key length in bytes (> 0).
    pub out_len: usize,
}

/// Parameters for the PBKDF2-HMAC-SHA-256 stretching backend.
#[derive(Debug, Clone, Copy)]
pub struct Pbkdf2StretchParams {
    /// Iteration count (> 0).
    pub iterations: u32,
    /// Derived-key length in bytes (> 0).
    pub out_len: usize,
}

/// Parameters for the Balloon-SHA-256 stretching backend.
///
/// Balloon-SHA-256's output length is fixed at 32 bytes (the SHA-256 digest
/// size), so no `out_len` field is exposed.
#[derive(Debug, Clone, Copy)]
pub struct BalloonStretchParams {
    /// Number of 32-byte blocks held in memory (`>= 1`).
    pub space_cost: u64,
    /// Number of mixing rounds (`>= 1`).
    pub time_cost: u64,
}

/// Algorithm + parameter selection for a [`Stretcher`].
#[derive(Debug, Clone, Copy)]
pub enum StretchParams {
    /// Argon2id (memory-hard, side-channel-resistant; RFC 9106).
    Argon2id(Argon2idStretchParams),
    /// scrypt (memory-hard; RFC 7914).
    Scrypt(ScryptStretchParams),
    /// PBKDF2-HMAC-SHA-256 (iteration-hard; RFC 8018 / NIST SP 800-132).
    Pbkdf2Sha256(Pbkdf2StretchParams),
    /// Balloon-SHA-256 (memory-hard, cache-hard; ASIACRYPT 2016). 32-byte output.
    BalloonSha256(BalloonStretchParams),
}

impl StretchParams {
    /// Length in bytes of the key this configuration derives.
    #[must_use]
    pub fn output_len(&self) -> usize {
        match self {
            StretchParams::Argon2id(p) => p.out_len,
            StretchParams::Scrypt(p) => p.out_len,
            StretchParams::Pbkdf2Sha256(p) => p.out_len,
            StretchParams::BalloonSha256(_) => 32,
        }
    }

    /// Stable, human-readable algorithm name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            StretchParams::Argon2id(_) => "argon2id",
            StretchParams::Scrypt(_) => "scrypt",
            StretchParams::Pbkdf2Sha256(_) => "pbkdf2-sha256",
            StretchParams::BalloonSha256(_) => "balloon-sha256",
        }
    }
}

/// An object-safe key-stretching interface.
///
/// Implemented by [`Stretcher`]. Stretch a low-entropy `password` together with
/// a `salt` into a high-cost-derived key returned as a [`SecretVec`].
pub trait KeyStretcher {
    /// Derive a key from `password` and `salt`.
    ///
    /// # Errors
    /// Returns the underlying [`CryptoError`] from the selected backend (e.g.
    /// [`CryptoError::BadInput`] for invalid parameters or salt length).
    fn stretch(&self, password: &[u8], salt: &[u8]) -> Result<SecretVec, CryptoError>;

    /// Length in bytes of the derived key.
    fn output_len(&self) -> usize;

    /// Stable, human-readable algorithm name.
    fn name(&self) -> &'static str;
}

/// The built-in [`KeyStretcher`] implementation, parameterized by
/// [`StretchParams`].
#[derive(Debug, Clone, Copy)]
pub struct Stretcher {
    params: StretchParams,
}

impl Stretcher {
    /// Construct a stretcher from an algorithm + parameter selection.
    #[must_use]
    pub fn new(params: StretchParams) -> Self {
        Self { params }
    }

    /// Borrow the underlying parameter selection.
    #[must_use]
    pub fn params(&self) -> &StretchParams {
        &self.params
    }
}

impl KeyStretcher for Stretcher {
    fn stretch(&self, password: &[u8], salt: &[u8]) -> Result<SecretVec, CryptoError> {
        match self.params {
            StretchParams::Argon2id(p) => {
                if p.out_len == 0 {
                    return Err(CryptoError::BadInput);
                }
                let mut out = vec![0u8; p.out_len];
                argon2id_derive(password, salt, p.params, &mut out)?;
                Ok(SecretVec::new(out))
            }
            StretchParams::Scrypt(p) => {
                if p.out_len == 0 {
                    return Err(CryptoError::BadInput);
                }
                let mut out = vec![0u8; p.out_len];
                scrypt_derive(password, salt, p.log_n, p.r, p.p, &mut out)?;
                Ok(SecretVec::new(out))
            }
            StretchParams::Pbkdf2Sha256(p) => {
                if p.out_len == 0 {
                    return Err(CryptoError::BadInput);
                }
                let mut out = vec![0u8; p.out_len];
                pbkdf2_sha256(password, salt, p.iterations, &mut out)?;
                Ok(SecretVec::new(out))
            }
            StretchParams::BalloonSha256(p) => {
                let mut out = vec![0u8; 32];
                balloon_sha256(password, salt, p.space_cost, p.time_cost, &mut out)?;
                Ok(SecretVec::new(out))
            }
        }
    }

    fn output_len(&self) -> usize {
        self.params.output_len()
    }

    fn name(&self) -> &'static str {
        self.params.name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT16: &[u8] = b"0123456789abcdef";

    fn check_backend(params: StretchParams, expect_len: usize) {
        let stretcher = Stretcher::new(params);
        assert_eq!(stretcher.output_len(), expect_len);

        // Determinism through the trait.
        let k1 = stretcher.stretch(b"password", SALT16).expect("stretch 1");
        let k2 = stretcher.stretch(b"password", SALT16).expect("stretch 2");
        assert_eq!(k1.as_bytes(), k2.as_bytes(), "{}", stretcher.name());
        assert_eq!(k1.len(), expect_len);
        assert_ne!(k1.as_bytes(), vec![0u8; expect_len].as_slice());

        // Different salt ⇒ different key.
        let k3 = stretcher
            .stretch(b"password", b"fedcba9876543210")
            .expect("stretch 3");
        assert_ne!(
            k1.as_bytes(),
            k3.as_bytes(),
            "{} salt sensitivity",
            stretcher.name()
        );
    }

    #[test]
    fn argon2id_backend() {
        check_backend(
            StretchParams::Argon2id(Argon2idStretchParams {
                params: Argon2Params::TEST_PARAMS,
                out_len: 32,
            }),
            32,
        );
    }

    #[test]
    fn scrypt_backend() {
        check_backend(
            StretchParams::Scrypt(ScryptStretchParams {
                log_n: 4,
                r: 8,
                p: 1,
                out_len: 32,
            }),
            32,
        );
    }

    #[test]
    fn pbkdf2_backend() {
        check_backend(
            StretchParams::Pbkdf2Sha256(Pbkdf2StretchParams {
                iterations: 1000,
                out_len: 48,
            }),
            48,
        );
    }

    #[test]
    fn balloon_backend() {
        check_backend(
            StretchParams::BalloonSha256(BalloonStretchParams {
                space_cost: 8,
                time_cost: 3,
            }),
            32,
        );
    }

    #[test]
    fn trait_object_dispatch() {
        // Heterogeneous list of boxed stretchers exercises object-safety.
        let backends: Vec<Box<dyn KeyStretcher>> = vec![
            Box::new(Stretcher::new(StretchParams::Argon2id(
                Argon2idStretchParams {
                    params: Argon2Params::TEST_PARAMS,
                    out_len: 32,
                },
            ))),
            Box::new(Stretcher::new(StretchParams::Scrypt(ScryptStretchParams {
                log_n: 4,
                r: 8,
                p: 1,
                out_len: 32,
            }))),
            Box::new(Stretcher::new(StretchParams::Pbkdf2Sha256(
                Pbkdf2StretchParams {
                    iterations: 1000,
                    out_len: 32,
                },
            ))),
            Box::new(Stretcher::new(StretchParams::BalloonSha256(
                BalloonStretchParams {
                    space_cost: 8,
                    time_cost: 3,
                },
            ))),
        ];
        for b in &backends {
            let key = b.stretch(b"password", SALT16).expect("dispatch stretch");
            assert_eq!(key.len(), b.output_len(), "{}", b.name());
        }
        // Each algorithm should produce a distinct derived key for identical input.
        let outs: Vec<Vec<u8>> = backends
            .iter()
            .map(|b| {
                b.stretch(b"password", SALT16)
                    .expect("k")
                    .as_bytes()
                    .to_vec()
            })
            .collect();
        for i in 0..outs.len() {
            for j in (i + 1)..outs.len() {
                assert_ne!(outs[i], outs[j], "backends {i} and {j} collided");
            }
        }
    }

    #[test]
    fn matches_standalone_pbkdf2() {
        // Trait output must equal the standalone function for the same params.
        let stretcher = Stretcher::new(StretchParams::Pbkdf2Sha256(Pbkdf2StretchParams {
            iterations: 1000,
            out_len: 32,
        }));
        let via_trait = stretcher.stretch(b"password", b"salt").expect("trait");
        let mut direct = [0u8; 32];
        pbkdf2_sha256(b"password", b"salt", 1000, &mut direct).expect("direct");
        assert_eq!(via_trait.as_bytes(), &direct[..]);
    }

    #[test]
    fn zero_output_len_rejected() {
        let stretcher = Stretcher::new(StretchParams::Pbkdf2Sha256(Pbkdf2StretchParams {
            iterations: 1000,
            out_len: 0,
        }));
        assert_eq!(
            stretcher.stretch(b"pw", SALT16).err(),
            Some(CryptoError::BadInput)
        );
    }
}
