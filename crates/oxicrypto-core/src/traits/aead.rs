use alloc::vec::Vec;

use crate::CryptoError;

/// Authenticated Encryption with Associated Data (AEAD).
///
/// When the `debug` Cargo feature is enabled, `Aead` gains `Debug` as a
/// supertrait so `Box<dyn Aead>` can be formatted with `{:?}`.
///
/// # Minimum key lengths
///
/// AEAD algorithms use **fixed-length** symmetric keys.  `key.len()` passed to
/// [`seal`](Aead::seal) / [`open`](Aead::open) must equal `key_len()` exactly:
///
/// | Algorithm | Key length |
/// |-----------|-----------|
/// | AES-128-GCM / AES-128-GCM-SIV / AES-128-CCM / AES-128-OCB3 | 16 bytes |
/// | AES-256-GCM / AES-256-GCM-SIV / AES-256-CCM / AES-256-OCB3 / Deoxys-II-128 | 32 bytes |
/// | ChaCha20-Poly1305 | 32 bytes |
/// | XChaCha20-Poly1305 | 32 bytes |
///
/// Providing a shorter or longer key will result in
/// [`CryptoError::InvalidKey`].
pub trait Aead: Send + Sync + crate::traits::MaybeDebug {
    /// Human-readable algorithm identifier (e.g. `"AES-256-GCM"`).
    #[must_use]
    fn name(&self) -> &'static str;
    /// Required key length in bytes.
    ///
    /// The `key` argument to [`seal`](Aead::seal) / [`open`](Aead::open)
    /// must have exactly this length.
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

    /// Encrypt `pt` into `ct_out` (length must equal `pt.len()`) and return
    /// the authentication tag as a [`Vec<u8>`] of length `self.tag_len()`.
    ///
    /// The default implementation seals into a combined buffer and then splits
    /// off the tag.  Implementations that have a native detached mode may
    /// override this to avoid the intermediate allocation.
    #[must_use = "result must be checked"]
    fn seal_detached(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<alloc::vec::Vec<u8>, CryptoError> {
        if ct_out.len() != pt.len() {
            return Err(CryptoError::BadInput);
        }
        let combined_len = pt
            .len()
            .checked_add(self.tag_len())
            .ok_or(CryptoError::BadInput)?;
        let mut combined = alloc::vec![0u8; combined_len];
        self.seal(key, nonce, aad, pt, &mut combined)?;
        ct_out.copy_from_slice(&combined[..pt.len()]);
        Ok(combined[pt.len()..].to_vec())
    }

    /// Authenticate and decrypt `ct` using the separately transmitted `tag`,
    /// writing plaintext into `pt_out` (length must equal `ct.len()`).
    ///
    /// Returns [`CryptoError::InvalidTag`] if authentication fails.
    ///
    /// The default implementation reassembles `ct ‖ tag` then calls [`Self::open`].
    /// Implementations with a native detached mode may override this.
    #[must_use = "result must be checked"]
    fn open_detached(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8],
        pt_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let combined_len = ct
            .len()
            .checked_add(tag.len())
            .ok_or(CryptoError::BadInput)?;
        let mut combined = alloc::vec![0u8; combined_len];
        combined[..ct.len()].copy_from_slice(ct);
        combined[ct.len()..].copy_from_slice(tag);
        let n = self.open(key, nonce, aad, &combined, pt_out)?;
        let _ = n;
        Ok(())
    }

    /// Maximum plaintext length (in bytes) for a single call with a given
    /// `(key, nonce)` pair.
    ///
    /// Returns `u64::MAX` by default.  Concrete implementations override
    /// with the RFC-specified limits for their algorithm.
    fn max_plaintext_len(&self) -> u64 {
        u64::MAX
    }

    /// Encrypt `buf` in place, appending the authentication tag.
    ///
    /// On entry `buf` contains the plaintext.  On exit `buf` contains
    /// `ciphertext || tag` (length grows by `self.tag_len()` bytes).
    ///
    /// The default implementation makes one extra allocation (copies the
    /// plaintext).  Concrete implementations should override this with a true
    /// in-place path.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BadInput`] if the resulting length would overflow
    /// `usize`, or any error propagated from [`Self::seal`].
    #[must_use = "result must be checked"]
    fn seal_in_place(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        buf: &mut alloc::vec::Vec<u8>,
    ) -> Result<(), CryptoError> {
        let pt_len = buf.len();
        let ct_len = pt_len
            .checked_add(self.tag_len())
            .ok_or(CryptoError::BadInput)?;
        // Copy plaintext to avoid aliasing issues in the default path.
        let pt = buf[..pt_len].to_vec();
        buf.resize(ct_len, 0u8);
        self.seal(key, nonce, aad, &pt, buf)?;
        Ok(())
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
