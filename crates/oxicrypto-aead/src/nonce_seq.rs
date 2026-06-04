//! Monotonic nonce sequence generator.
//!
//! [`NonceSequence<N>`] produces a sequence of unique, collision-resistant
//! nonces of exactly `N` bytes.  The nonce layout is:
//!
//! ```text
//! ┌──── N-8 bytes ────┬──────── 8 bytes ────────┐
//! │    fixed prefix   │  counter (big-endian u64) │
//! └───────────────────┴─────────────────────────┘
//! ```
//!
//! The counter starts at 0 and increments by 1 with each [`generate`] call.
//! [`generate`] returns [`CryptoError::Internal`] if the counter would overflow
//! past `u64::MAX`, preventing nonce reuse.
//!
//! # Type aliases
//!
//! | Alias      | `N` | Suited for                     |
//! |------------|-----|--------------------------------|
//! | [`Nonce12`] | 12 | AES-GCM, ChaCha20-Poly1305     |
//! | [`Nonce24`] | 24 | XChaCha20-Poly1305             |
//!
//! [`generate`]: NonceSequence::generate

extern crate alloc;

use oxicrypto_core::CryptoError;

/// A stateful nonce generator that produces sequentially unique nonces.
///
/// # Panics
///
/// This type does not panic; all errors are returned as [`CryptoError`].
///
/// # Example
///
/// ```rust
/// use oxicrypto_aead::nonce_seq::Nonce12;
///
/// let prefix = [0u8; 4]; // 4-byte prefix for a 12-byte nonce
/// let mut seq = Nonce12::new(&prefix).unwrap();
/// let n0 = seq.generate().unwrap();
/// let n1 = seq.generate().unwrap();
/// assert_ne!(n0, n1);
/// ```
///
/// # Random-prefix Construction (requires `rand` feature)
///
/// When the `rand` feature is enabled, `NonceSequence::with_random_prefix`
/// creates a sequence with a cryptographically secure random prefix.  This is
/// the recommended approach for session-level nonce management where no shared
/// prefix is required:
///
/// ```rust,ignore
/// // Only available with feature = "rand"
/// let mut seq = Nonce12::with_random_prefix()?;
/// let n = seq.generate()?;
/// ```
pub struct NonceSequence<const N: usize> {
    /// The full nonce buffer: prefix in `[0..N-8]`, counter in `[N-8..N]`.
    nonce: [u8; N],
    /// Current counter value (monotonically increasing).
    counter: u64,
}

impl<const N: usize> core::fmt::Debug for NonceSequence<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NonceSequence<{}>(counter={})", N, self.counter)
    }
}

impl<const N: usize> NonceSequence<N> {
    const PREFIX_LEN: usize = N - 8;

    /// Create a new `NonceSequence` with the given prefix.
    ///
    /// `prefix` must be exactly `N - 8` bytes long; otherwise
    /// [`CryptoError::InvalidNonce`] is returned.
    ///
    /// The initial counter value is 0.
    pub fn new(prefix: &[u8]) -> Result<Self, CryptoError> {
        if N < 8 {
            return Err(CryptoError::InvalidNonce);
        }
        if prefix.len() != Self::PREFIX_LEN {
            return Err(CryptoError::InvalidNonce);
        }
        let mut nonce = [0u8; N];
        nonce[..Self::PREFIX_LEN].copy_from_slice(prefix);
        // Counter bytes start at 0; they will be written on first `generate()`.
        Ok(Self { nonce, counter: 0 })
    }

    /// Return the next nonce and advance the counter.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Internal`] if the counter has wrapped around
    /// `u64::MAX` (i.e., `2^64` nonces have been generated).
    pub fn generate(&mut self) -> Result<[u8; N], CryptoError> {
        // Snapshot the current counter value for this nonce.
        let current = self.counter;

        // Advance, detecting overflow.
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(CryptoError::Internal("NonceSequence counter overflow"))?;

        // Write the counter into the last 8 bytes of the nonce (big-endian).
        let counter_bytes = current.to_be_bytes();
        self.nonce[Self::PREFIX_LEN..].copy_from_slice(&counter_bytes);
        Ok(self.nonce)
    }

    /// Return the current counter value (number of nonces generated so far).
    #[must_use]
    pub fn count(&self) -> u64 {
        self.counter
    }

    /// Create a new `NonceSequence` with a **cryptographically secure random prefix**.
    ///
    /// The `N - 8` prefix bytes are drawn from `oxicrypto-rand`'s OS-seeded
    /// ChaCha20 CSPRNG.  The counter starts at 0.
    ///
    /// Requires the `rand` feature of this crate.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Rng`] if the OS random source is unavailable.
    /// Returns [`CryptoError::InvalidNonce`] if `N < 8`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use oxicrypto_aead::nonce_seq::Nonce12;
    /// let mut seq = Nonce12::with_random_prefix().expect("RNG available");
    /// let n0 = seq.generate().unwrap();
    /// let n1 = seq.generate().unwrap();
    /// assert_ne!(n0, n1);
    /// # }
    /// ```
    #[cfg(feature = "rand")]
    pub fn with_random_prefix() -> Result<Self, CryptoError> {
        if N < 8 {
            return Err(CryptoError::InvalidNonce);
        }
        let prefix_len = N - 8;
        let mut prefix = alloc::vec![0u8; prefix_len];
        use oxicrypto_core::Rng as _;
        let mut rng = oxicrypto_rand::OxiRng::new()?;
        rng.fill(&mut prefix)?;
        Self::new(&prefix)
    }
}

/// 12-byte nonce sequence (4-byte prefix + 8-byte counter).
///
/// Suitable for AES-GCM and ChaCha20-Poly1305.
pub type Nonce12 = NonceSequence<12>;

/// 24-byte nonce sequence (16-byte prefix + 8-byte counter).
///
/// Suitable for XChaCha20-Poly1305.
pub type Nonce24 = NonceSequence<24>;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce12_sequential_uniqueness() {
        let prefix = [0xABu8; 4]; // 4-byte prefix for 12-byte nonces
        let mut seq = Nonce12::new(&prefix).expect("new");

        let nonces: alloc::vec::Vec<[u8; 12]> =
            (0..10).map(|_| seq.generate().expect("generate")).collect();

        // All must be unique.
        for i in 0..nonces.len() {
            for j in i + 1..nonces.len() {
                assert_ne!(nonces[i], nonces[j], "nonces[{i}] == nonces[{j}]");
            }
        }

        // Prefix is preserved in all nonces.
        for n in &nonces {
            assert_eq!(&n[..4], &prefix);
        }

        // Counter bytes (last 8) must differ monotonically.
        for (idx, n) in nonces.iter().enumerate() {
            let counter = u64::from_be_bytes(n[4..].try_into().expect("slice"));
            assert_eq!(counter, idx as u64, "counter byte mismatch at index {idx}");
        }
    }

    #[test]
    fn nonce24_sequential_uniqueness() {
        let prefix = [0xCDu8; 16]; // 16-byte prefix for 24-byte nonces
        let mut seq = Nonce24::new(&prefix).expect("new");

        let n0 = seq.generate().expect("n0");
        let n1 = seq.generate().expect("n1");
        assert_ne!(n0, n1);
        assert_eq!(&n0[..16], &prefix);
        assert_eq!(&n1[..16], &prefix);
    }

    #[test]
    fn nonce12_counter_overflow_detected() {
        let prefix = [0u8; 4];
        let mut seq = Nonce12::new(&prefix).expect("new");
        // Force counter to u64::MAX - 1 to trigger overflow on the second call.
        seq.counter = u64::MAX - 1;

        // Should succeed (returns the nonce at counter = u64::MAX - 1).
        seq.generate().expect("penultimate nonce");

        // Counter is now u64::MAX; next generate() must detect overflow.
        let result = seq.generate();
        assert!(
            matches!(result, Err(CryptoError::Internal(_))),
            "should have detected overflow, got: {:?}",
            result
        );
    }

    #[test]
    fn nonce12_wrong_prefix_length() {
        let result = Nonce12::new(&[0u8; 5]);
        assert!(
            matches!(result, Err(CryptoError::InvalidNonce)),
            "expected InvalidNonce, got: {:?}",
            result.as_ref().err()
        );
    }

    #[test]
    fn nonce24_wrong_prefix_length() {
        let result = Nonce24::new(&[0u8; 8]);
        assert!(
            matches!(result, Err(CryptoError::InvalidNonce)),
            "expected InvalidNonce, got: {:?}",
            result.as_ref().err()
        );
    }

    #[test]
    fn nonce12_count_tracks_generated() {
        let prefix = [0u8; 4];
        let mut seq = Nonce12::new(&prefix).expect("new");
        assert_eq!(seq.count(), 0);
        seq.generate().expect("generate 1");
        assert_eq!(seq.count(), 1);
        seq.generate().expect("generate 2");
        assert_eq!(seq.count(), 2);
    }

    // ── with_random_prefix tests (requires `rand` feature) ───────────────────

    #[cfg(feature = "rand")]
    #[test]
    fn nonce12_with_random_prefix_uniqueness() {
        // Two independently constructed sequences should have different prefixes
        // (with overwhelming probability) and produce unique nonces within each.
        let mut seq_a = Nonce12::with_random_prefix().expect("with_random_prefix seq_a");
        let mut seq_b = Nonce12::with_random_prefix().expect("with_random_prefix seq_b");

        let n_a0 = seq_a.generate().expect("a0");
        let n_a1 = seq_a.generate().expect("a1");
        let _n_b0 = seq_b.generate().expect("b0");

        // Within a single sequence, nonces must be unique.
        assert_ne!(n_a0, n_a1, "same-sequence nonces must differ");
    }

    #[cfg(feature = "rand")]
    #[test]
    fn nonce24_with_random_prefix_counter_increments() {
        let mut seq = Nonce24::with_random_prefix().expect("with_random_prefix");
        let n0 = seq.generate().expect("n0");
        let n1 = seq.generate().expect("n1");
        assert_ne!(n0, n1, "sequential nonces must differ");
        // Counter occupies the last 8 bytes and starts at 0.
        assert_eq!(u64::from_be_bytes(n0[16..].try_into().expect("counter")), 0);
        assert_eq!(u64::from_be_bytes(n1[16..].try_into().expect("counter")), 1);
    }

    #[cfg(feature = "rand")]
    #[test]
    fn nonce12_with_random_prefix_counter_starts_at_zero() {
        let seq = Nonce12::with_random_prefix().expect("with_random_prefix");
        assert_eq!(seq.count(), 0, "counter must start at zero");
    }
}
