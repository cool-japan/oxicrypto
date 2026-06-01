use alloc::vec::Vec;

use crate::CryptoError;

/// Authenticated Encryption with Associated Data (AEAD).
pub trait Aead: Send + Sync {
    /// Human-readable algorithm identifier (e.g. `"AES-256-GCM"`).
    #[must_use]
    fn name(&self) -> &'static str;
    /// Required key length in bytes.
    #[must_use]
    fn key_len(&self) -> usize;
    /// Required nonce length in bytes.
    #[must_use]
    fn nonce_len(&self) -> usize;
    /// Authentication tag length in bytes appended to ciphertext.
    #[must_use]
    fn tag_len(&self) -> usize;
    /// Encrypt `pt` and write `ciphertext || tag` into `ct_out`.
    ///
    /// Returns the number of bytes written (plaintext length + tag length).
    #[must_use = "result must be checked"]
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError>;
    /// Decrypt and authenticate `ct` (ciphertext || tag) into `pt_out`.
    ///
    /// Returns the number of bytes written (ciphertext length - tag length).
    #[must_use = "result must be checked"]
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError>;

    /// Convenience: encrypt and return `ciphertext || tag` as a [`Vec<u8>`].
    #[must_use = "result must be checked"]
    fn seal_to_vec(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut out = alloc::vec![0u8; plaintext.len() + self.tag_len()];
        self.seal(key, nonce, aad, plaintext, &mut out)?;
        Ok(out)
    }

    /// Convenience: decrypt and authenticate, returning plaintext as [`Vec<u8>`].
    ///
    /// Returns [`CryptoError::BufferTooSmall`] if `ciphertext` is shorter than
    /// `self.tag_len()`.
    #[must_use = "result must be checked"]
    fn open_to_vec(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let tag_len = self.tag_len();
        if ciphertext.len() < tag_len {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut out = alloc::vec![0u8; ciphertext.len() - tag_len];
        self.open(key, nonce, aad, ciphertext, &mut out)?;
        Ok(out)
    }
}

/// Chunked authenticated encryption with associated data.
///
/// Lifecycle: call `init` once, feed chunks with `encrypt_update` /
/// `decrypt_update`, then call `encrypt_finalize` / `decrypt_finalize`.
/// Call `reset` to reuse the object.
pub trait StreamingAead: Sized + Send {
    /// Initialise the streaming AEAD with key, nonce, and AAD.
    #[must_use = "result must be checked"]
    fn init(key: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Self, CryptoError>;
    /// Feed a plaintext chunk; write ciphertext bytes into `out`.
    /// Returns the number of bytes written.
    #[must_use = "result must be checked"]
    fn encrypt_update(&mut self, chunk: &[u8], out: &mut [u8]) -> Result<usize, CryptoError>;
    /// Flush remaining ciphertext into `out` and return the 16-byte authentication tag.
    #[must_use = "result must be checked"]
    fn encrypt_finalize(self, out: &mut [u8]) -> Result<[u8; 16], CryptoError>;
    /// Feed a ciphertext chunk; write plaintext bytes into `out`.
    /// Returns the number of bytes written.
    #[must_use = "result must be checked"]
    fn decrypt_update(&mut self, chunk: &[u8], out: &mut [u8]) -> Result<usize, CryptoError>;
    /// Verify `expected_tag` in constant time and flush remaining plaintext.
    #[must_use = "result must be checked"]
    fn decrypt_finalize(self, expected_tag: &[u8]) -> Result<(), CryptoError>;
    /// Reset to initial (un-initialised) state for reuse.
    fn reset(&mut self);
}
