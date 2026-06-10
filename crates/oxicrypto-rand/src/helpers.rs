//! Convenience free functions: `random_bytes`, `random_nonce`, `random_range`,
//! `reseed`, `shuffle`, and related helpers.

use oxicrypto_core::{CryptoError, Zeroize};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::OxiRng;

// ── random_bytes ──────────────────────────────────────────────────────────────

/// Allocate and fill a `Vec<u8>` with `len` cryptographically secure random
/// bytes.
///
/// Returns [`CryptoError::Rng`] if the OS random source is unavailable.
#[must_use = "random bytes should be used; discarding them is likely a bug"]
pub fn random_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut rng = OxiRng::new()?;
    let mut buf = vec![0u8; len];
    use oxicrypto_core::Rng;
    rng.fill(&mut buf)?;
    Ok(buf)
}

// ── random_range ──────────────────────────────────────────────────────────────

/// Generate a random integer in `[min, max)` using rejection sampling to
/// eliminate modulo bias.
///
/// Returns [`CryptoError::BadInput`] if `min >= max`.
///
/// # Note
///
/// The old single-argument form `random_range(max)` has been renamed to
/// [`random_range_to`].  Any existing callers should update to the two-argument
/// form or use [`random_range_to`] explicitly.
#[must_use = "random range value should be used; discarding it is likely a bug"]
pub fn random_range(min: u64, max: u64) -> Result<u64, CryptoError> {
    let mut rng = OxiRng::new()?;
    random_range_unbiased(&mut rng, min, max)
}

/// Generate a random integer in `[0, max)` using rejection sampling.
///
/// This is the renamed form of the old single-argument `random_range(max)`.
/// Returns [`CryptoError::BadInput`] if `max == 0`.
#[must_use = "random range value should be used; discarding it is likely a bug"]
pub fn random_range_to(max: u64) -> Result<u64, CryptoError> {
    if max == 0 {
        return Err(CryptoError::BadInput);
    }
    let mut rng = OxiRng::new()?;
    random_range_unbiased(&mut rng, 0, max)
}

/// Generate a random integer in `[min, max)` using an existing RNG, with
/// rejection sampling to eliminate modulo bias.
///
/// Returns [`CryptoError::BadInput`] if `min >= max`.
pub fn random_range_unbiased(rng: &mut OxiRng, min: u64, max: u64) -> Result<u64, CryptoError> {
    if min >= max {
        return Err(CryptoError::BadInput);
    }
    let range = max - min;
    if range == 1 {
        return Ok(min);
    }
    // Rejection threshold: largest value such that the number of valid values
    // is an exact multiple of `range`, eliminating modulo bias.
    let threshold = u64::MAX - (u64::MAX % range);
    loop {
        let mut buf = [0u8; 8];
        use oxicrypto_core::Rng;
        rng.fill(&mut buf)?;
        let val = u64::from_le_bytes(buf);
        if val < threshold {
            return Ok(min + (val % range));
        }
    }
}

/// Internal helper: generate random in `[0, max)` using the provided rng.
/// Kept for use by [`shuffle`].
pub(crate) fn random_range_with_rng(max: u64, rng: &mut OxiRng) -> Result<u64, CryptoError> {
    if max == 0 {
        return Err(CryptoError::BadInput);
    }
    if max == 1 {
        return Ok(0);
    }
    let threshold = u64::MAX - (u64::MAX % max);
    loop {
        let mut buf = [0u8; 8];
        use oxicrypto_core::Rng;
        rng.fill(&mut buf)?;
        let val = u64::from_le_bytes(buf);
        if val < threshold {
            return Ok(val % max);
        }
    }
}

// ── random_bool ───────────────────────────────────────────────────────────────

/// Generate a random `bool` with the given probability of being `true`.
///
/// - `probability == 0.0` always returns `false`.
/// - `probability == 1.0` always returns `true`.
/// - Returns [`CryptoError::BadInput`] if `probability` is outside `[0.0, 1.0]`.
pub fn random_bool(probability: f64) -> Result<bool, CryptoError> {
    let mut rng = OxiRng::new()?;
    random_bool_with_rng(&mut rng, probability)
}

/// Generate a random `bool` using an existing RNG, with the given probability
/// of being `true`.
///
/// Returns [`CryptoError::BadInput`] if `probability` is outside `[0.0, 1.0]`.
pub fn random_bool_with_rng(rng: &mut OxiRng, probability: f64) -> Result<bool, CryptoError> {
    if !(0.0..=1.0).contains(&probability) {
        return Err(CryptoError::BadInput);
    }
    if probability == 0.0 {
        return Ok(false);
    }
    if probability == 1.0 {
        return Ok(true);
    }
    let threshold = (probability * (u64::MAX as f64)) as u64;
    let mut buf = [0u8; 8];
    use oxicrypto_core::Rng;
    rng.fill(&mut buf)?;
    let val = u64::from_le_bytes(buf);
    Ok(val < threshold)
}

// ── weighted_choice ───────────────────────────────────────────────────────────

/// Sample an index from a weighted distribution.
///
/// Given a slice of non-negative integer weights, returns a random index `i`
/// such that the probability of each index is proportional to `weights[i]`.
///
/// Returns [`CryptoError::BadInput`] if:
/// - `weights` is empty, or
/// - all weights are zero.
pub fn weighted_choice(weights: &[u64]) -> Result<usize, CryptoError> {
    let mut rng = OxiRng::new()?;
    weighted_choice_with_rng(&mut rng, weights)
}

/// Sample an index from a weighted distribution using an existing RNG.
///
/// See [`weighted_choice`] for details.
pub fn weighted_choice_with_rng(rng: &mut OxiRng, weights: &[u64]) -> Result<usize, CryptoError> {
    if weights.is_empty() {
        return Err(CryptoError::BadInput);
    }
    let total: u64 = weights
        .iter()
        .try_fold(0u64, |acc, &w| acc.checked_add(w))
        .ok_or(CryptoError::BadInput)?;
    if total == 0 {
        return Err(CryptoError::BadInput);
    }
    let pick = random_range_unbiased(rng, 0, total)?;
    let mut cumulative: u64 = 0;
    for (i, &w) in weights.iter().enumerate() {
        cumulative = cumulative.saturating_add(w);
        if pick < cumulative {
            return Ok(i);
        }
    }
    // Should never be reached if `total` and cumulative sums are consistent.
    Err(CryptoError::Internal(
        "weighted_choice: internal invariant violated",
    ))
}

// ── random_nonce ──────────────────────────────────────────────────────────────

/// Generate a random nonce of `N` bytes for use with AEAD algorithms.
///
/// Returns [`CryptoError::Rng`] if the OS random source is unavailable.
#[must_use = "random nonce should be used; discarding it is likely a bug"]
pub fn random_nonce<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut rng = OxiRng::new()?;
    let mut nonce = [0u8; N];
    use oxicrypto_core::Rng;
    rng.fill(&mut nonce)?;
    Ok(nonce)
}

// ── reseed ────────────────────────────────────────────────────────────────────

/// Perform a manual reseed of the given `OxiRng` from OS entropy.
///
/// This replaces the internal ChaCha20 state with a fresh 32-byte seed and
/// updates the stored PID to the current process.
pub fn reseed(rng: &mut OxiRng) -> Result<(), CryptoError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| CryptoError::Rng)?;
    rng.inner = ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    #[cfg(unix)]
    {
        rng.last_pid = std::process::id();
    }
    Ok(())
}

// ── random_u32 / random_u64 / random_u128 ────────────────────────────────────

/// Generate a cryptographically secure random `u32`.
///
/// Returns [`CryptoError::Rng`] if the OS random source is unavailable.
pub fn random_u32() -> Result<u32, CryptoError> {
    let mut rng = OxiRng::new()?;
    let mut buf = [0u8; 4];
    use oxicrypto_core::Rng;
    rng.fill(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Generate a cryptographically secure random `u64`.
///
/// Returns [`CryptoError::Rng`] if the OS random source is unavailable.
pub fn random_u64() -> Result<u64, CryptoError> {
    let mut rng = OxiRng::new()?;
    let mut buf = [0u8; 8];
    use oxicrypto_core::Rng;
    rng.fill(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Generate a cryptographically secure random `u128`.
///
/// Returns [`CryptoError::Rng`] if the OS random source is unavailable.
pub fn random_u128() -> Result<u128, CryptoError> {
    let mut rng = OxiRng::new()?;
    let mut buf = [0u8; 16];
    use oxicrypto_core::Rng;
    rng.fill(&mut buf)?;
    Ok(u128::from_le_bytes(buf))
}

// ── shuffle ───────────────────────────────────────────────────────────────────

/// Cryptographically secure in-place Fisher-Yates shuffle.
///
/// Returns `Ok(())` on success, `Err(CryptoError::Rng)` if the RNG fails.
pub fn shuffle<T>(slice: &mut [T], rng: &mut OxiRng) -> Result<(), CryptoError> {
    let n = slice.len();
    if n <= 1 {
        return Ok(());
    }
    // Fisher-Yates: for i from n-1 down to 1, swap slice[i] with slice[rand(0..=i)]
    for i in (1..n).rev() {
        let j = random_range_with_rng(i as u64 + 1, rng)? as usize;
        slice.swap(i, j);
    }
    Ok(())
}

// ── check_entropy ──────────────────────────────────────────────────────────────

/// Perform a basic OS-entropy smoke test.
///
/// Draws two 32-byte samples from `getrandom` and verifies:
/// 1. Neither buffer is all-zero (a sign of catastrophic RNG failure).
/// 2. Both buffers differ from each other (two identical draws would also
///    indicate a catastrophic failure).
///
/// # Note
///
/// This is a smoke test, **not** a cryptographic NIST SP 800-90B health test.
/// It catches the most obvious hardware/OS RNG failures only.
///
/// Returns [`CryptoError::Rng`] if either check fails.
pub fn check_entropy() -> Result<(), CryptoError> {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    getrandom::fill(&mut a).map_err(|_| CryptoError::Rng)?;
    getrandom::fill(&mut b).map_err(|_| CryptoError::Rng)?;
    if a == [0u8; 32] || b == [0u8; 32] {
        return Err(CryptoError::Rng);
    }
    if a == b {
        return Err(CryptoError::Rng);
    }
    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_returns_correct_length() {
        let bytes = random_bytes(64).expect("random_bytes failed");
        assert_eq!(bytes.len(), 64);
        assert_ne!(bytes, vec![0u8; 64]);
    }

    #[test]
    fn random_bytes_zero_length() {
        let bytes = random_bytes(0).expect("random_bytes(0) failed");
        assert!(bytes.is_empty());
    }

    #[test]
    fn random_range_to_zero_errors() {
        let result = random_range_to(0);
        assert_eq!(result, Err(CryptoError::BadInput));
    }

    #[test]
    fn random_range_to_one_returns_zero() {
        let val = random_range_to(1).expect("random_range_to(1) failed");
        assert_eq!(val, 0);
    }

    #[test]
    fn random_range_to_bounded() {
        for _ in 0..100 {
            let val = random_range_to(10).expect("random_range_to(10) failed");
            assert!(val < 10, "random_range_to(10) returned {val} >= 10");
        }
    }

    #[test]
    fn random_range_two_arg_in_bounds() {
        for _ in 0..200 {
            let val = random_range(5, 10).expect("random_range(5, 10) failed");
            assert!((5..10).contains(&val), "random_range(5, 10) returned {val}");
        }
    }

    #[test]
    fn random_range_two_arg_min_ge_max_errors() {
        assert_eq!(random_range(10, 5), Err(CryptoError::BadInput));
        assert_eq!(random_range(5, 5), Err(CryptoError::BadInput));
    }

    #[test]
    fn random_range_two_arg_zero_one_always_zero() {
        for _ in 0..50 {
            let val = random_range(0, 1).expect("random_range(0, 1) failed");
            assert_eq!(val, 0, "random_range(0, 1) must always be 0");
        }
    }

    #[test]
    fn random_bool_zero_always_false() {
        for _ in 0..50 {
            let b = random_bool(0.0).expect("random_bool(0.0) failed");
            assert!(!b, "random_bool(0.0) must always be false");
        }
    }

    #[test]
    fn random_bool_one_always_true() {
        for _ in 0..50 {
            let b = random_bool(1.0).expect("random_bool(1.0) failed");
            assert!(b, "random_bool(1.0) must always be true");
        }
    }

    #[test]
    fn random_bool_invalid_probability() {
        assert_eq!(random_bool(-0.1), Err(CryptoError::BadInput));
        assert_eq!(random_bool(1.1), Err(CryptoError::BadInput));
        assert_eq!(random_bool(f64::NAN), Err(CryptoError::BadInput));
    }

    #[test]
    fn random_bool_half_has_both_outcomes() {
        let mut trues = 0u32;
        let mut falses = 0u32;
        for _ in 0..1000 {
            if random_bool(0.5).expect("random_bool(0.5) failed") {
                trues += 1;
            } else {
                falses += 1;
            }
        }
        assert!(
            trues > 300 && falses > 300,
            "Expected roughly equal trues/falses, got {trues}/{falses}"
        );
    }

    #[test]
    fn weighted_choice_single_nonzero_always_returns_it() {
        for _ in 0..50 {
            let idx = weighted_choice(&[0, 1, 0]).expect("weighted_choice failed");
            assert_eq!(idx, 1, "Only index 1 has non-zero weight");
        }
    }

    #[test]
    fn weighted_choice_empty_errors() {
        assert_eq!(weighted_choice(&[]), Err(CryptoError::BadInput));
    }

    #[test]
    fn weighted_choice_all_zero_errors() {
        assert_eq!(weighted_choice(&[0, 0]), Err(CryptoError::BadInput));
    }

    #[test]
    fn weighted_choice_proportional() {
        let mut count0 = 0u32;
        let mut count1 = 0u32;
        for _ in 0..1000 {
            match weighted_choice(&[3, 1]).expect("weighted_choice failed") {
                0 => count0 += 1,
                1 => count1 += 1,
                _ => panic!("unexpected index"),
            }
        }
        assert!(
            count0 > count1,
            "Index 0 (weight 3) should win more than index 1 (weight 1); got {count0} vs {count1}"
        );
    }

    #[test]
    fn random_nonce_12_works() {
        let nonce: [u8; 12] = random_nonce().expect("random_nonce failed");
        assert_ne!(nonce, [0u8; 12]);
    }

    #[test]
    fn random_nonce_24_works() {
        let nonce: [u8; 24] = random_nonce().expect("random_nonce failed");
        assert_ne!(nonce, [0u8; 24]);
    }

    #[test]
    fn reseed_free_fn_changes_output() {
        let mut rng = OxiRng::new().expect("new failed");
        let mut buf1 = [0u8; 32];
        use oxicrypto_core::Rng;
        rng.fill(&mut buf1).expect("fill 1 failed");
        reseed(&mut rng).expect("reseed failed");
        let mut buf2 = [0u8; 32];
        rng.fill(&mut buf2).expect("fill 2 failed");
        assert_ne!(buf1, buf2, "Output after reseed should differ");
    }

    #[test]
    fn random_u32_nonzero_variance() {
        let vals: Vec<u32> = (0..1000)
            .map(|_| random_u32().expect("random_u32 failed"))
            .collect();
        let first = vals[0];
        assert!(
            vals.iter().any(|&v| v != first),
            "1000 consecutive random_u32() values must not all be equal"
        );
    }

    #[test]
    fn random_u64_type_check() {
        let v: u64 = random_u64().expect("random_u64 failed");
        let _ = v;
    }

    #[test]
    fn random_u128_type_check() {
        let v: u128 = random_u128().expect("random_u128 failed");
        let _ = v;
    }

    #[test]
    fn shuffle_preserves_elements() {
        let mut rng = OxiRng::new().expect("OxiRng::new failed");
        let original: Vec<i32> = (0..100).collect();
        let mut shuffled = original.clone();
        shuffle(&mut shuffled, &mut rng).expect("shuffle failed");
        let mut sorted_original = original.clone();
        let mut sorted_shuffled = shuffled.clone();
        sorted_original.sort_unstable();
        sorted_shuffled.sort_unstable();
        assert_eq!(
            sorted_original, sorted_shuffled,
            "Shuffle must preserve all elements"
        );
    }

    #[test]
    fn shuffle_empty() {
        let mut rng = OxiRng::new().expect("OxiRng::new failed");
        let mut empty: Vec<u8> = Vec::new();
        let result = shuffle(&mut empty, &mut rng);
        assert!(result.is_ok(), "Shuffling an empty slice should be Ok");
    }

    #[test]
    fn check_entropy_passes_on_healthy_system() {
        check_entropy().expect("check_entropy() should pass on a healthy system");
    }

    #[test]
    fn test_random_range_bounds() {
        for _ in 0..100 {
            let v = random_range(5, 10).expect("random_range(5, 10)");
            assert!((5..10).contains(&v), "value {v} out of [5, 10)");
        }
    }

    #[test]
    fn test_random_range_min_equals_max_errors() {
        assert_eq!(random_range(5, 5), Err(CryptoError::BadInput));
    }

    #[test]
    fn test_random_range_min_greater_than_max_errors() {
        assert_eq!(random_range(10, 5), Err(CryptoError::BadInput));
    }

    #[test]
    fn test_random_range_wide_range() {
        for _ in 0..50 {
            let v = random_range(0, u64::MAX).expect("random_range(0, u64::MAX)");
            let _ = v;
        }
    }
}
