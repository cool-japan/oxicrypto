//! SealedBox — nonce-prefixed AEAD ciphertext format.
//!
//! A sealed box bundles a randomly-generated nonce together with its
//! associated ciphertext and tag into a single `Vec<u8>`.
//!
//! # Wire format
//!
//! ```text
//! +--------- nonce_len bytes ---------+----------- ct_len bytes ----------+
//! |           nonce (random)          |   ciphertext ‖ authentication tag  |
//! +-----------------------------------+------------------------------------+
//! ```
//!
//! The receiver can recover `nonce_len` from the algorithm (via [`Aead::nonce_len`]).
//!
//! # Example
//!
//! ```text
//! // See integration tests for usage examples.
//! ```

use alloc::vec::Vec;
use oxicrypto_core::{Aead, CryptoError, Rng};

/// Seal `plaintext` using a freshly-generated random nonce.
///
/// The returned buffer contains `nonce || ciphertext || tag` as a contiguous
/// byte string.  Pass it directly to [`open_box`] for decryption.
///
/// # Arguments
///
/// * `aead`      — AEAD algorithm instance.
/// * `key`       — symmetric key (must have length `aead.key_len()`).
/// * `aad`       — additional authenticated data (may be empty).
/// * `plaintext` — message to encrypt.
/// * `rng`       — cryptographically-secure random source for nonce generation.
///
/// # Errors
///
/// Propagates any error from `rng.fill`, `aead.seal_to_vec`, or integer
/// overflow in the output-length calculation.
pub fn seal_box(
    aead: &dyn Aead,
    key: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut dyn Rng,
) -> Result<Vec<u8>, CryptoError> {
    let nonce_len = aead.nonce_len();
    let mut nonce = alloc::vec![0u8; nonce_len];
    rng.fill(&mut nonce)?;

    let ct = aead.seal_to_vec(key, &nonce, aad, plaintext)?;

    let total = nonce_len
        .checked_add(ct.len())
        .ok_or(CryptoError::BadInput)?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed box produced by [`seal_box`].
///
/// Splits the `sealed` buffer at `nonce_len` bytes, then decrypts and
/// authenticates the remaining ciphertext.
///
/// # Arguments
///
/// * `aead`   — AEAD algorithm instance (must match the one used to seal).
/// * `key`    — symmetric key (must have length `aead.key_len()`).
/// * `aad`    — additional authenticated data (must match what was sealed with).
/// * `sealed` — output from [`seal_box`]: `nonce || ciphertext || tag`.
///
/// # Errors
///
/// * [`CryptoError::BadInput`]  — `sealed` is shorter than `nonce_len`.
/// * Propagates any authentication / decryption errors from `aead.open_to_vec`.
pub fn open_box(
    aead: &dyn Aead,
    key: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce_len = aead.nonce_len();
    if sealed.len() < nonce_len {
        return Err(CryptoError::BadInput);
    }
    let (nonce, ciphertext) = sealed.split_at(nonce_len);
    aead.open_to_vec(key, nonce, aad, ciphertext)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use oxicrypto_core::CryptoError;

    // ── Minimal deterministic RNG for tests ───────────────────────────────────

    /// Deterministic "counter" RNG — fills with incrementing bytes.
    /// Not suitable for production; fine for testing round-trips.
    #[derive(Debug)]
    struct CounterRng {
        counter: u8,
    }

    impl CounterRng {
        fn new() -> Self {
            Self { counter: 0xAA }
        }
    }

    impl Rng for CounterRng {
        fn fill(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
            for b in dst.iter_mut() {
                *b = self.counter;
                self.counter = self.counter.wrapping_add(1);
            }
            Ok(())
        }
    }

    // ── Failing RNG for error-path tests ─────────────────────────────────────

    #[derive(Debug)]
    struct FailingRng;

    impl Rng for FailingRng {
        fn fill(&mut self, _dst: &mut [u8]) -> Result<(), CryptoError> {
            Err(CryptoError::Rng)
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn aes128_gcm() -> crate::Aes128Gcm {
        crate::Aes128Gcm
    }

    fn aes256_gcm() -> crate::Aes256Gcm {
        crate::Aes256Gcm
    }

    fn chacha20() -> crate::ChaCha20Poly1305 {
        crate::ChaCha20Poly1305
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_seal_open_round_trip_aes128gcm() {
        let aead = aes128_gcm();
        let key = [0x42u8; 16];
        let aad = b"header";
        let plaintext = b"hello sealed box";
        let mut rng = CounterRng::new();

        let sealed = seal_box(&aead, &key, aad, plaintext, &mut rng).expect("seal_box failed");

        // Sealed length = nonce (12) + ciphertext (16) + tag (16) = 44
        assert_eq!(
            sealed.len(),
            aead.nonce_len() + plaintext.len() + aead.tag_len()
        );

        let recovered = open_box(&aead, &key, aad, &sealed).expect("open_box failed");
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn test_seal_open_round_trip_aes256gcm() {
        let aead = aes256_gcm();
        let key = [0x55u8; 32];
        let aad = b"aad256";
        let plaintext = b"AES-256-GCM sealed message";
        let mut rng = CounterRng::new();

        let sealed = seal_box(&aead, &key, aad, plaintext, &mut rng).expect("seal_box failed");
        let recovered = open_box(&aead, &key, aad, &sealed).expect("open_box failed");
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn test_seal_open_round_trip_chacha20poly1305() {
        let aead = chacha20();
        let key = [0x77u8; 32];
        let aad = b"";
        let plaintext = b"ChaCha20-Poly1305 sealed box test";
        let mut rng = CounterRng::new();

        let sealed = seal_box(&aead, &key, aad, plaintext, &mut rng).expect("seal_box failed");
        let recovered = open_box(&aead, &key, aad, &sealed).expect("open_box failed");
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn test_open_box_wrong_key_fails() {
        let aead = aes128_gcm();
        let key = [0x42u8; 16];
        let wrong_key = [0x99u8; 16];
        let aad = b"aad";
        let plaintext = b"secret";
        let mut rng = CounterRng::new();

        let sealed = seal_box(&aead, &key, aad, plaintext, &mut rng).expect("seal_box failed");
        let result = open_box(&aead, &wrong_key, aad, &sealed);
        assert!(result.is_err(), "wrong key must cause open_box to fail");
    }

    #[test]
    fn test_open_box_tampered_ciphertext_fails() {
        let aead = aes128_gcm();
        let key = [0x42u8; 16];
        let aad = b"aad";
        let plaintext = b"tamper me";
        let mut rng = CounterRng::new();

        let mut sealed = seal_box(&aead, &key, aad, plaintext, &mut rng).expect("seal_box failed");
        // Flip a byte in the ciphertext area (after the nonce)
        let nonce_len = aead.nonce_len();
        sealed[nonce_len] ^= 0xFF;
        let result = open_box(&aead, &key, aad, &sealed);
        assert!(result.is_err(), "tampered ciphertext must be rejected");
    }

    #[test]
    fn test_open_box_too_short_fails() {
        let aead = aes128_gcm();
        let key = [0u8; 16];
        let aad = b"";
        // Only 5 bytes — shorter than nonce_len (12)
        let short = [0u8; 5];
        let result = open_box(&aead, &key, aad, &short);
        assert_eq!(
            result,
            Err(CryptoError::BadInput),
            "truncated sealed box must return BadInput"
        );
    }

    #[test]
    fn test_rng_failure_propagates() {
        let aead = aes128_gcm();
        let key = [0u8; 16];
        let aad = b"";
        let plaintext = b"test";
        let result = seal_box(&aead, &key, aad, plaintext, &mut FailingRng);
        assert_eq!(result, Err(CryptoError::Rng), "RNG failure must propagate");
    }

    #[test]
    fn test_sealed_box_wire_format() {
        let aead = aes128_gcm();
        let key = [0x11u8; 16];
        let aad = b"wire-format";
        let plaintext = b"check nonce prefix";
        let mut rng = CounterRng::new();

        let sealed = seal_box(&aead, &key, aad, plaintext, &mut rng).expect("seal_box failed");

        let nonce_len = aead.nonce_len(); // 12

        // First 12 bytes must be the nonce (filled by our counter rng starting at 0xAA)
        let expected_nonce: alloc::vec::Vec<u8> =
            (0u8..12).map(|i| 0xAA_u8.wrapping_add(i)).collect();
        assert_eq!(
            &sealed[..nonce_len],
            expected_nonce.as_slice(),
            "nonce prefix must match RNG output"
        );

        // Remainder must be ciphertext + tag
        assert_eq!(
            sealed.len() - nonce_len,
            plaintext.len() + aead.tag_len(),
            "ciphertext+tag length must be pt.len() + tag_len()"
        );
    }

    #[test]
    fn test_seal_open_empty_plaintext() {
        let aead = aes128_gcm();
        let key = [0x22u8; 16];
        let aad = b"empty-pt";
        let plaintext = b"";
        let mut rng = CounterRng::new();

        let sealed = seal_box(&aead, &key, aad, plaintext, &mut rng)
            .expect("seal_box with empty plaintext failed");
        let recovered =
            open_box(&aead, &key, aad, &sealed).expect("open_box with empty plaintext failed");
        assert!(recovered.is_empty(), "recovered plaintext must be empty");
    }
}
