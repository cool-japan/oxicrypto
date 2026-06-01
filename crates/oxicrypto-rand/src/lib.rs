#![forbid(unsafe_code)]

//! Pure Rust CSPRNG for the OxiCrypto stack.
//!
//! Provides [`OxiRng`], a ChaCha20-based CSPRNG seeded from the OS
//! via `getrandom`.
//!
//! # Fork Safety
//!
//! On Unix platforms, [`OxiRng`] tracks the process PID and automatically
//! reseeds after a `fork()` to prevent parent/child CSPRNG state sharing.
//!
//! # Thread-Local RNG
//!
//! Use `with_thread_rng` (available with the `std` feature) for a convenient
//! per-thread RNG (lazily initialized, no explicit RNG management required).
//!
//! # ChaCha Variants
//!
//! [`OxiRng8`] and [`OxiRng12`] provide ChaCha8 and ChaCha12-based CSPRNGs
//! for higher throughput when the full 20-round version is not required.
//!
//! # Entropy Health Check
//!
//! [`check_entropy`] performs a basic OS-entropy smoke test (two independent
//! draws must be non-zero and differ). This is not a NIST SP 800-90B test.

mod helpers;
mod oxirng;
mod read;
mod reseeding;
mod thread_rng;

// ── Public type re-exports ────────────────────────────────────────────────────

pub use oxirng::{OxiRng, OxiRng12, OxiRng8};
pub use reseeding::ReseedingRng;

// ── Public function re-exports ────────────────────────────────────────────────

pub use helpers::{
    check_entropy, random_bool, random_bool_with_rng, random_bytes, random_nonce, random_range,
    random_range_to, random_range_unbiased, random_u128, random_u32, random_u64, reseed, shuffle,
    weighted_choice, weighted_choice_with_rng,
};

#[cfg(feature = "std")]
pub use thread_rng::with_thread_rng;

// ── Deterministic test RNG ───────────────────────────────────────────────────

/// Deterministic RNG for reproducible tests.
///
/// Only compiled when `#[cfg(test)]`. Never use in production code.
#[cfg(test)]
pub mod test_rng {
    use rand_chacha::ChaCha20Rng;
    use rand_core::{SeedableRng, TryCryptoRng, TryRng};

    use oxicrypto_core::{CryptoError, Rng};

    /// A deterministic RNG for test reproducibility.
    ///
    /// Wraps [`ChaCha20Rng`] with a fixed seed. Available only in test builds.
    pub struct TestRng(ChaCha20Rng);

    impl TestRng {
        /// Create a deterministic RNG from a 32-byte seed.
        pub fn from_seed(seed: [u8; 32]) -> Self {
            Self(ChaCha20Rng::from_seed(seed))
        }
    }

    impl Rng for TestRng {
        fn fill(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
            use rand_core::TryRng;
            self.0.try_fill_bytes(dst).map_err(|_| CryptoError::Rng)
        }
    }

    impl TryRng for TestRng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.0.try_next_u32()
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0.try_next_u64()
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            self.0.try_fill_bytes(dest)
        }
    }

    impl TryCryptoRng for TestRng {}
}

// ── Unit tests for lib.rs-specific items ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use oxicrypto_core::Rng;

    #[test]
    fn test_rng_deterministic() {
        use test_rng::TestRng;

        let seed = [42u8; 32];
        let mut rng1 = TestRng::from_seed(seed);
        let mut rng2 = TestRng::from_seed(seed);

        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        rng1.fill(&mut out1).expect("TestRng fill 1 failed");
        rng2.fill(&mut out2).expect("TestRng fill 2 failed");

        assert_eq!(out1, out2, "Same seed must produce same output");
    }

    #[test]
    fn test_rng_different_seeds_differ() {
        use test_rng::TestRng;

        let mut rng_a = TestRng::from_seed([1u8; 32]);
        let mut rng_b = TestRng::from_seed([2u8; 32]);

        let mut out_a = [0u8; 64];
        let mut out_b = [0u8; 64];
        rng_a.fill(&mut out_a).expect("TestRng fill a failed");
        rng_b.fill(&mut out_b).expect("TestRng fill b failed");

        assert_ne!(
            out_a, out_b,
            "Different seeds must produce different output"
        );
    }
}
