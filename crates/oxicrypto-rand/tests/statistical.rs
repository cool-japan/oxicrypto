//! Statistical and behavioral tests for oxicrypto-rand.
//!
//! These tests validate distributional properties of [`OxiRng`] and edge-case
//! correctness of the convenience API.  They are probabilistic but bounded with
//! extremely loose thresholds to avoid CI flakiness while still catching
//! catastrophic biases.

use oxicrypto_core::Rng;
use oxicrypto_rand::{
    check_entropy, random_range, random_range_to, random_range_unbiased, random_u64, OxiRng,
    ReseedingRng,
};

// ── Chi-squared byte-distribution test ───────────────────────────────────────

/// Verify that OxiRng produces roughly uniform byte distribution.
///
/// We draw 256,000 bytes and run a chi-squared goodness-of-fit test.  For a
/// uniform source over 256 buckets with 255 degrees of freedom, the statistic
/// is expected to lie within approximately [150, 400] with overwhelming
/// probability.  The bounds here are intentionally loose to avoid flakiness.
#[test]
fn test_chi_squared_byte_distribution() {
    let mut rng = OxiRng::new().expect("OxiRng::new must succeed");
    const N: usize = 256 * 1000; // 256 000 bytes
    let mut counts = [0u64; 256];

    let mut buf = [0u8; 4096];
    // Generate N bytes in 4 KiB chunks.
    for _ in 0..(N / buf.len()) {
        rng.fill(&mut buf).expect("fill must succeed");
        for &b in &buf {
            counts[b as usize] += 1;
        }
    }

    // Chi-squared statistic: Σ((observed − expected)² / expected)
    let expected = N as f64 / 256.0;
    let chi_sq: f64 = counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected
        })
        .sum();

    // For χ²(255): 99.9% confidence interval is roughly [186, 330].
    // We use very loose bounds (150, 400) to avoid flakiness.
    assert!(
        chi_sq < 400.0,
        "chi-squared {chi_sq:.2} too high — potential bias in OxiRng"
    );
    assert!(
        chi_sq > 150.0,
        "chi-squared {chi_sq:.2} suspiciously low — check for zero-fill or identical bytes"
    );
}

// ── Independent-instances test ────────────────────────────────────────────────

/// Two independently created OxiRng instances must produce different output.
///
/// They are seeded from independent OS entropy draws; identical seeds would
/// indicate a catastrophic RNG failure at the OS level.
#[test]
fn test_independent_instances_differ() {
    let mut rng1 = OxiRng::new().expect("rng1");
    let mut rng2 = OxiRng::new().expect("rng2");

    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    rng1.fill(&mut buf1).expect("fill1");
    rng2.fill(&mut buf2).expect("fill2");

    assert_ne!(
        buf1, buf2,
        "two independently seeded OxiRng instances must not produce identical 32-byte output"
    );
}

// ── ReseedingRng threshold-crossing test ─────────────────────────────────────

/// After crossing the reseed threshold, ReseedingRng must still produce valid
/// output and its byte counter must reflect the post-reseed state (i.e. it
/// must be strictly less than `total bytes generated`, proving a reset occurred).
#[test]
fn test_reseeding_rng_reseeds_on_threshold() {
    // Use a small threshold of 1024 bytes so the test is fast.
    const THRESHOLD: u64 = 1024;
    let mut rng =
        ReseedingRng::with_threshold(THRESHOLD).expect("ReseedingRng::with_threshold must succeed");

    // Sanity: before any output the counter is zero.
    assert_eq!(rng.bytes_generated(), 0);

    // Generate 5 × 512 = 2560 bytes total.  With a 1024-byte threshold, at
    // least two fills will trigger a reseed (at bytes 1024 and 2048).
    let mut buf = [0u8; 512];
    let mut total: u64 = 0;
    for _ in 0..5 {
        rng.fill(&mut buf)
            .expect("ReseedingRng fill must succeed after reseed");
        total += buf.len() as u64;
    }

    // After 2560 bytes with a 1024-byte threshold, at least two reseeds must
    // have fired.  The counter must be strictly less than `total` because
    // each reseed resets it to 0.  Concretely: total=2560, counter≤512.
    assert!(
        rng.bytes_generated() < total,
        "bytes_generated() ({}) should be less than total ({}) after reseeding",
        rng.bytes_generated(),
        total
    );
    // And the counter must be <= 512 (at most one chunk after the last reset).
    assert!(
        rng.bytes_generated() <= 512,
        "bytes_generated() ({}) after last reseed must be ≤512 (one chunk since last reseed)",
        rng.bytes_generated()
    );
}

// ── Edge case: random_range(0, 1) always returns 0 ───────────────────────────

/// The half-open range [0, 1) contains only one value: 0.
/// `random_range_unbiased` should always return 0.
#[test]
fn test_random_range_0_to_1_always_0() {
    let mut rng = OxiRng::new().expect("rng");
    for _ in 0..20 {
        let v = random_range_unbiased(&mut rng, 0, 1).expect("range [0,1)");
        assert_eq!(
            v, 0u64,
            "random_range_unbiased(rng, 0, 1) must always return 0"
        );
    }
}

/// `random_range(0, 1)` (free function, no explicit rng) also always returns 0.
#[test]
fn test_random_range_free_fn_0_to_1_always_0() {
    for _ in 0..20 {
        let v = random_range(0, 1).expect("range [0,1)");
        assert_eq!(v, 0u64, "random_range(0, 1) must always return 0");
    }
}

// ── Edge case: fill with zero-length buffer ───────────────────────────────────

/// Filling an empty buffer must succeed without error.
#[test]
fn test_fill_zero_length_buffer() {
    let mut rng = OxiRng::new().expect("rng");
    let mut buf: [u8; 0] = [];
    rng.fill(&mut buf)
        .expect("fill on a zero-length buffer must succeed");
}

// ── Edge case: random_range_to(0) returns BadInput ───────────────────────────

#[test]
fn test_random_range_to_zero_is_error() {
    let result = random_range_to(0);
    assert!(
        result.is_err(),
        "random_range_to(0) must return an error; got Ok({:?})",
        result.ok()
    );
}

// ── Edge case: random_range with min >= max is error ─────────────────────────

#[test]
fn test_random_range_min_equals_max_is_error() {
    let result = random_range(5, 5);
    assert!(
        result.is_err(),
        "random_range(5, 5) must return an error (empty range)"
    );
}

#[test]
fn test_random_range_min_gt_max_is_error() {
    let result = random_range(10, 3);
    assert!(
        result.is_err(),
        "random_range(10, 3) must return an error (inverted range)"
    );
}

// ── random_u64 basic sanity ───────────────────────────────────────────────────

/// Consecutive random_u64 calls must almost certainly differ (probability of
/// collision is 2⁻⁶⁴ — negligible in testing contexts).
#[test]
fn test_random_u64_produces_different_values() {
    let v1 = random_u64().expect("random_u64 #1");
    let v2 = random_u64().expect("random_u64 #2");
    assert_ne!(v1, v2, "two consecutive random_u64 calls must differ");
}

// ── check_entropy smoke test ──────────────────────────────────────────────────

#[test]
fn test_check_entropy_passes() {
    check_entropy().expect("check_entropy must succeed on a functioning OS RNG");
}

// ── NIST SP 800-22 Runs Test ──────────────────────────────────────────────────

/// Count runs of consecutive identical bits in 1 MiB of random data.
///
/// For a truly random sequence, the number of runs should be ~(N/2 + 1).
/// We allow ±10% tolerance — intentionally loose for non-adversarial CI.
#[test]
fn test_runs_nist_sp800_22_1mib() {
    let n_bytes = 1024 * 1024;
    let data = oxicrypto_rand::random_bytes(n_bytes).expect("random_bytes failed");

    let total_bits = n_bytes * 8;
    let mut runs = 1u64;
    let mut prev_bit = (data[0] >> 7) & 1;
    for byte in &data {
        for shift in (0..8).rev() {
            let bit = (byte >> shift) & 1;
            if bit != prev_bit {
                runs += 1;
            }
            prev_bit = bit;
        }
    }

    let expected = (total_bits as f64) / 2.0 + 1.0;
    let tolerance = expected * 0.10;
    assert!(
        (runs as f64 - expected).abs() < tolerance,
        "Runs test failed: {runs} runs, expected ~{expected:.0} ± {tolerance:.0}"
    );
}

// ── Serial Correlation Test ───────────────────────────────────────────────────

/// Compute the serial correlation coefficient for 10,000 consecutive bytes.
///
/// For a good CSPRNG the correlation should be very close to 0.
#[test]
fn test_serial_correlation() {
    let data = oxicrypto_rand::random_bytes(10_000).expect("random_bytes failed");
    let n = data.len() as f64;
    let mean = data.iter().map(|&b| b as f64).sum::<f64>() / n;
    let variance = data.iter().map(|&b| (b as f64 - mean).powi(2)).sum::<f64>() / n;

    let covariance = data
        .windows(2)
        .map(|w| (w[0] as f64 - mean) * (w[1] as f64 - mean))
        .sum::<f64>()
        / (n - 1.0);

    let corr = if variance > 0.0 {
        covariance / variance
    } else {
        0.0
    };
    assert!(
        corr.abs() < 0.05,
        "Serial correlation too high: {corr:.4} (expected < 0.05)"
    );
}

// ── Fork-safe sequential-output test ─────────────────────────────────────────

/// Two sequential `random_bytes` calls in the same process must produce
/// different output.  (A real fork-in-separate-process test is out of scope
/// for a library integration test; this verifies the basic liveness property.)
#[cfg(unix)]
#[test]
fn test_fork_produces_different_output() {
    let result1 = oxicrypto_rand::random_bytes(32).expect("random_bytes failed");
    let result2 = oxicrypto_rand::random_bytes(32).expect("random_bytes failed");
    assert_ne!(
        result1, result2,
        "Sequential random_bytes calls should differ"
    );
}

// ── std::io::Read test (std feature only) ────────────────────────────────────

#[cfg(feature = "std")]
mod std_read {
    use oxicrypto_rand::{OxiRng, ReseedingRng};
    use std::io::Read;

    #[test]
    fn test_oxi_rng_read_fills_buffer() {
        let mut rng = OxiRng::new().expect("rng");
        let mut buf = [0u8; 64];
        let n = rng.read(&mut buf).expect("Read::read must succeed");
        assert_eq!(n, 64, "Read::read must return buf.len()");
        // The buffer must not be all zeros (extremely improbable for a live RNG).
        assert_ne!(buf, [0u8; 64], "read buffer must not be all zeros");
    }

    #[test]
    fn test_oxi_rng_read_empty_buffer() {
        let mut rng = OxiRng::new().expect("rng");
        let mut buf: [u8; 0] = [];
        let n = rng
            .read(&mut buf)
            .expect("Read::read on empty buffer must succeed");
        assert_eq!(n, 0);
    }

    #[test]
    fn test_reseeding_rng_read_fills_buffer() {
        let mut rng = ReseedingRng::new().expect("ReseedingRng::new");
        let mut buf = [0u8; 128];
        let n = rng
            .read(&mut buf)
            .expect("ReseedingRng Read::read must succeed");
        assert_eq!(n, 128, "Read::read must return buf.len()");
    }
}

// ── fill() buffer size coverage ───────────────────────────────────────────────

/// `fill()` must work correctly for buffer sizes of 1, 31, 32, 33, 1024,
/// and 1_000_000 bytes.
#[test]
fn test_fill_various_buffer_sizes() {
    let mut rng = OxiRng::new().expect("OxiRng::new");
    for &size in &[1usize, 31, 32, 33, 1024, 1_000_000] {
        let mut buf = vec![0u8; size];
        rng.fill(&mut buf)
            .expect("fill must succeed for all buffer sizes");
        if size > 4 {
            // With overwhelming probability a live CSPRNG will not produce all zeros.
            let all_zero = buf.iter().all(|&b| b == 0);
            assert!(
                !all_zero,
                "fill({size}) produced all-zero output — CSPRNG appears broken"
            );
        }
    }
}

// ── random_range bounds test ──────────────────────────────────────────────────

/// `random_range(min, max)` must never produce values outside `[min, max)`.
#[test]
fn test_random_range_never_out_of_bounds() {
    let min: u64 = 100;
    let max: u64 = 200;

    for _ in 0..1000 {
        let v = random_range(min, max).expect("random_range must succeed");
        assert!(
            v >= min && v < max,
            "random_range({min}, {max}) produced {v} which is out of bounds"
        );
    }
}

/// `random_range(0, max)` with small `max` must never produce values ≥ max.
#[test]
fn test_random_range_small_max_never_exceeds() {
    for max in [2u64, 3, 7, 10, 100] {
        for _ in 0..500 {
            let v = random_range(0, max).expect("random_range must succeed");
            assert!(
                v < max,
                "random_range(0, {max}) produced {v} which is ≥ max"
            );
        }
    }
}

// ── shuffle() permutation coverage ───────────────────────────────────────────

/// `shuffle()` must leave all elements present in the slice and must produce
/// different orderings over many runs (not always the same permutation).
#[test]
fn test_shuffle_preserves_elements_and_varies() {
    let mut rng = OxiRng::new().expect("OxiRng::new");
    let original: Vec<u32> = (0..8).collect();

    let mut seen_different = false;
    let first_order: Vec<u32>;

    // Run 50 shuffles and collect the first result for comparison.
    {
        let mut slice = original.clone();
        oxicrypto_rand::shuffle(&mut slice, &mut rng).expect("shuffle must succeed");
        first_order = slice.clone();

        // All elements must still be present.
        let mut sorted = slice.clone();
        sorted.sort();
        assert_eq!(sorted, original, "shuffle must not add/remove elements");
    }

    for _ in 0..50 {
        let mut slice = original.clone();
        oxicrypto_rand::shuffle(&mut slice, &mut rng).expect("shuffle must succeed");

        // Verify element preservation.
        let mut sorted = slice.clone();
        sorted.sort();
        assert_eq!(sorted, original, "shuffle must not add/remove elements");

        // Check that we see at least one different ordering.
        if slice != first_order {
            seen_different = true;
        }
    }

    assert!(
        seen_different,
        "shuffle must produce different orderings across 50 runs"
    );
}

/// `shuffle()` on a single-element slice must succeed and not change the element.
#[test]
fn test_shuffle_single_element() {
    let mut rng = OxiRng::new().expect("OxiRng::new");
    let mut slice = [42u64];
    oxicrypto_rand::shuffle(&mut slice, &mut rng).expect("shuffle single element must succeed");
    assert_eq!(
        slice[0], 42,
        "single-element shuffle must not change the value"
    );
}

/// `shuffle()` on an empty slice must succeed without panicking.
#[test]
fn test_shuffle_empty_slice() {
    let mut rng = OxiRng::new().expect("OxiRng::new");
    let mut empty: Vec<i32> = Vec::new();
    oxicrypto_rand::shuffle(&mut empty, &mut rng).expect("shuffle empty slice must succeed");
}

// ── Fuzz: fill() never panics ─────────────────────────────────────────────────

/// `fill()` must never panic for any buffer size from 0 to 64 KiB.
///
/// This iterates over a range of buffer sizes including edge cases (0, 1,
/// block-aligned, etc.) to confirm that the RNG handles all sizes gracefully.
#[test]
fn fuzz_fill_never_panics_various_sizes() {
    let mut rng = OxiRng::new().expect("OxiRng::new");
    for &size in &[
        0usize, 1, 15, 16, 17, 31, 32, 63, 64, 65, 255, 256, 512, 1024, 4096, 65536,
    ] {
        let mut buf = vec![0u8; size];
        // Must return Ok or a structured Err — never panic.
        let _ = rng.fill(&mut buf);
    }
}
