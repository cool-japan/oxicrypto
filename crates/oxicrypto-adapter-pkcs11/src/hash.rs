//! PKCS#11 hash (digest) operations via `C_Digest`.

use std::sync::Arc;

use cryptoki::mechanism::Mechanism;
use oxicrypto_core::{CryptoError, Hash};

use crate::provider::Pkcs11Provider;

// ---------------------------------------------------------------------------
// DigestMechanism — Send + Sync wrapper for hash mechanism selection
// ---------------------------------------------------------------------------

/// A `Send + Sync` description of the hash mechanism to use.
///
/// `cryptoki::mechanism::Mechanism` is `!Send` because some variants contain
/// raw pointers (e.g. `AesGcm`).  This unit enum covers only the digest
/// mechanisms and converts to `Mechanism` at call time.
#[derive(Debug, Clone, Copy)]
pub enum DigestMechanism {
    /// SHA-256 mechanism.
    Sha256,
    /// SHA-384 mechanism.
    Sha384,
    /// SHA-512 mechanism.
    Sha512,
}

impl DigestMechanism {
    fn to_mechanism(self) -> Mechanism<'static> {
        match self {
            DigestMechanism::Sha256 => Mechanism::Sha256,
            DigestMechanism::Sha384 => Mechanism::Sha384,
            DigestMechanism::Sha512 => Mechanism::Sha512,
        }
    }
}

// ---------------------------------------------------------------------------
// Pkcs11Hash
// ---------------------------------------------------------------------------

/// A PKCS#11-backed hash (digest) implementation.
///
/// Uses `C_DigestInit` + `C_Digest` (single-part) via the `cryptoki` session.
/// The supported mechanisms are SHA-256, SHA-384, and SHA-512.
///
/// # Thread safety
/// `Pkcs11Hash` holds an `Arc<Pkcs11Provider>` which serialises concurrent
/// session access via an internal `Mutex`.
#[derive(Debug)]
pub struct Pkcs11Hash {
    provider: Arc<Pkcs11Provider>,
    digest_mechanism: DigestMechanism,
    name: &'static str,
    output_len: usize,
}

impl Pkcs11Hash {
    /// Construct a SHA-256 hasher backed by the given provider.
    pub fn sha256(provider: Arc<Pkcs11Provider>) -> Self {
        Self {
            provider,
            digest_mechanism: DigestMechanism::Sha256,
            name: "SHA-256-PKCS11",
            output_len: 32,
        }
    }

    /// Construct a SHA-384 hasher backed by the given provider.
    pub fn sha384(provider: Arc<Pkcs11Provider>) -> Self {
        Self {
            provider,
            digest_mechanism: DigestMechanism::Sha384,
            name: "SHA-384-PKCS11",
            output_len: 48,
        }
    }

    /// Construct a SHA-512 hasher backed by the given provider.
    pub fn sha512(provider: Arc<Pkcs11Provider>) -> Self {
        Self {
            provider,
            digest_mechanism: DigestMechanism::Sha512,
            name: "SHA-512-PKCS11",
            output_len: 64,
        }
    }
}

impl Hash for Pkcs11Hash {
    fn name(&self) -> &'static str {
        self.name
    }

    fn output_len(&self) -> usize {
        self.output_len
    }

    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < self.output_len {
            return Err(CryptoError::BufferTooSmall);
        }

        let mechanism = self.digest_mechanism.to_mechanism();
        let digest = self
            .provider
            .with_session(|session| session.digest(&mechanism, msg))
            .map_err(|_| CryptoError::Internal("pkcs11 digest failed"))?;

        let n = digest.len().min(out.len());
        out[..n].copy_from_slice(&digest[..n]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    /// Verify SHA output-length constants are consistent with NIST definitions.
    #[test]
    fn output_lens_are_correct() {
        // SHA-256: 256 bits = 32 bytes
        const SHA256_LEN: usize = 256 / 8;
        // SHA-384: 384 bits = 48 bytes
        const SHA384_LEN: usize = 384 / 8;
        // SHA-512: 512 bits = 64 bytes
        const SHA512_LEN: usize = 512 / 8;

        assert_eq!(SHA256_LEN, 32);
        assert_eq!(SHA384_LEN, 48);
        assert_eq!(SHA512_LEN, 64);
    }
}
