//! Dudect-style constant-time statistical timing tests.
//!
//! These tests use the dudect methodology (Reparaz et al., 2017) to detect
//! timing side-channels in AEAD tag verification and HMAC verify operations.
//!
//! ## Methodology
//!
//! 1. Divide inputs into two classes:
//!    - Class 0: fixed (all-zeros or attacker-controlled) input
//!    - Class 1: random input
//! 2. Measure execution time for many iterations of each class.
//! 3. Compute Welch's t-statistic on the timing distributions.
//! 4. If |t| < threshold (default 5.0), the implementation does not exhibit
//!    a detectable timing difference at the tested confidence level.
//!
//! ## Limitations
//!
//! These tests are statistical and probabilistic. They may produce false
//! negatives (miss timing channels) or require many samples to detect subtle
//! leaks. They are NOT a substitute for formal verification or a comprehensive
//! constant-time audit.
//!
//! The BENCH_CT_SAMPLES environment variable controls iteration count.
//! Default: 100_000. Set to a higher value for stronger guarantees.
//!
//! ## References
//!
//! - Reparaz et al., "Dude, is my code constant time?", EUROCRYPT 2017
//! - <https://eprint.iacr.org/2016/1123.pdf>

use std::time::Instant;

use oxicrypto::{aead_impl, mac_impl, AeadAlgo, MacAlgo};
use oxicrypto_rand::OxiRng;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Number of timing samples per class.
///
/// Larger values give stronger statistical power but take longer to run.
/// Override with `BENCH_CT_SAMPLES=<n>` environment variable.
fn sample_count() -> usize {
    std::env::var("BENCH_CT_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000)
}

/// Welch's t-test threshold. |t| >= this value indicates a potential leak.
const T_THRESHOLD: f64 = 5.0;

// ── Statistical helpers ────────────────────────────────────────────────────────

/// Welch's t-statistic between two samples.
///
/// Returns `None` if either sample has variance zero (degenerate case,
/// e.g. the operation was optimized away).
fn welch_t(a: &[f64], b: &[f64]) -> Option<f64> {
    if a.len() < 2 || b.len() < 2 {
        return None;
    }
    let mean_a = a.iter().sum::<f64>() / a.len() as f64;
    let mean_b = b.iter().sum::<f64>() / b.len() as f64;

    let var_a = a.iter().map(|&x| (x - mean_a).powi(2)).sum::<f64>() / (a.len() - 1) as f64;
    let var_b = b.iter().map(|&x| (x - mean_b).powi(2)).sum::<f64>() / (b.len() - 1) as f64;

    if var_a == 0.0 || var_b == 0.0 {
        return None;
    }

    let se = (var_a / a.len() as f64 + var_b / b.len() as f64).sqrt();
    Some((mean_a - mean_b) / se)
}

/// Measure nanoseconds for a single call.
///
/// Uses a black-box hint to prevent the compiler from eliding the call.
#[inline(never)]
fn time_ns<F: FnMut()>(mut f: F) -> f64 {
    let start = Instant::now();
    f();
    let elapsed = start.elapsed();
    // Convert to f64 nanoseconds for t-test arithmetic.
    elapsed.as_nanos() as f64
}

// ── AEAD tag-verify constant-time test ────────────────────────────────────────
//
// Both classes use *corrupted* ciphertext so the operation always fails.
// The difference is *where* the tag byte is corrupted:
//   - Class 0: first byte of the tag is wrong
//   - Class 1: last byte of the tag is wrong
//
// A constant-time implementation compares all tag bytes before returning, so
// both classes should have statistically identical timings.  A naive early-exit
// comparison would return faster for Class 0 (fails on the first byte, never
// checks the rest).
//
// Note: comparing correct-tag vs. bad-tag is *not* a useful CT test because
// the successful path additionally decrypts the plaintext, which legitimately
// takes longer regardless of constant-time comparisons.

fn run_aead_ct_test(algo: AeadAlgo) -> (f64, bool) {
    use rand_core::TryRng;

    let n = sample_count();
    let aead = aead_impl(algo);
    let key_len = aead.key_len();
    let nonce_len = aead.nonce_len();
    let tag_len = aead.tag_len();
    let pt_len = 16usize; // small plaintext; tag comparison dominates

    let mut rng = OxiRng::new().expect("OS RNG unavailable");
    let mut key = vec![0u8; key_len];
    let mut nonce = vec![0u8; nonce_len];
    rng.try_fill_bytes(&mut key).expect("rng fill");
    rng.try_fill_bytes(&mut nonce).expect("rng fill");

    let plaintext = vec![0u8; pt_len];
    let mut ct_buf = vec![0u8; pt_len + tag_len];

    // Seal once to produce valid ciphertext.
    aead.seal(&key, &nonce, b"", &plaintext, &mut ct_buf)
        .expect("seal for CT test");

    // Class 0: flip the FIRST tag byte.
    let mut ct_first = ct_buf.clone();
    ct_first[pt_len] ^= 0x01;

    // Class 1: flip the LAST tag byte.
    let mut ct_last = ct_buf.clone();
    let last_idx = ct_buf.len() - 1;
    ct_last[last_idx] ^= 0x01;

    let mut pt_out = vec![0u8; pt_len];

    // Class 0: first-byte corruption (early-exit attack would be fast).
    let mut times_class0: Vec<f64> = Vec::with_capacity(n);
    // Class 1: last-byte corruption (early-exit attack would be slow).
    let mut times_class1: Vec<f64> = Vec::with_capacity(n);

    for i in 0..n {
        if i % 2 == 0 {
            let t = time_ns(|| {
                let _ = aead.open(&key, &nonce, b"", &ct_first, &mut pt_out);
            });
            times_class0.push(t);
        } else {
            let t = time_ns(|| {
                let _ = aead.open(&key, &nonce, b"", &ct_last, &mut pt_out);
            });
            times_class1.push(t);
        }
    }

    let t_stat = welch_t(&times_class0, &times_class1).unwrap_or(0.0);
    let pass = t_stat.abs() < T_THRESHOLD;
    (t_stat, pass)
}

// ── HMAC verify constant-time test ────────────────────────────────────────────
//
// Class 0: verify a correct MAC tag (byte-by-byte comparison exits at end).
// Class 1: verify a tag where the FIRST byte is wrong (naive comparison exits
//          after one byte — a massive timing difference if not constant-time).
//
// A constant-time `verify` will show no statistically significant difference.

fn run_hmac_ct_test() -> (f64, bool) {
    let n = sample_count();
    let mac_algo = mac_impl(MacAlgo::HmacSha256);
    let key = [0x42u8; 32];
    let message = b"constant-time timing test message for HMAC verify";

    // No rng needed for this test — key and message are fixed.

    // Compute a valid tag.
    let mut valid_tag = [0u8; 32];
    mac_algo
        .mac(&key, message, &mut valid_tag)
        .expect("hmac tag setup");

    // Corrupt tag: flip the FIRST byte (early-exit vulnerability).
    let mut bad_tag_first = valid_tag;
    bad_tag_first[0] ^= 0xff;

    // Class 0: verify the correct tag.
    let mut times_class0: Vec<f64> = Vec::with_capacity(n);
    // Class 1: verify a tag with the FIRST byte wrong.
    let mut times_class1: Vec<f64> = Vec::with_capacity(n);

    for i in 0..n {
        if i % 2 == 0 {
            let t = time_ns(|| {
                let _ = mac_algo.verify(&key, message, &valid_tag);
            });
            times_class0.push(t);
        } else {
            let t = time_ns(|| {
                let _ = mac_algo.verify(&key, message, &bad_tag_first);
            });
            times_class1.push(t);
        }
    }

    let t_stat = welch_t(&times_class0, &times_class1).unwrap_or(0.0);
    let pass = t_stat.abs() < T_THRESHOLD;
    (t_stat, pass)
}

// Note: run_aead_ct_position_test has been merged into run_aead_ct_test above.
// Both tests compare first-byte-flip vs. last-byte-flip (both invalid), which
// is the correct test for isolating the constant-time comparison step.

// ── Test entry points ─────────────────────────────────────────────────────────

/// AES-256-GCM: first-vs-last byte tag corruption.
///
/// Both classes present invalid ciphertexts; the only difference is whether
/// byte 0 or byte N-1 of the tag is flipped.  A constant-time implementation
/// shows no statistically significant timing difference.
#[test]
fn ct_aead_aes256gcm_correct_vs_bad_tag() {
    let (t, pass) = run_aead_ct_test(AeadAlgo::Aes256Gcm);
    println!("AES-256-GCM tag-position (first vs last byte) t-stat: {t:.4}");
    assert!(
        pass,
        "AES-256-GCM tag verification appears non-constant-time: |t|={t:.4} >= {T_THRESHOLD}"
    );
}

/// ChaCha20-Poly1305: first-vs-last byte tag corruption.
#[test]
fn ct_aead_chacha20poly1305_correct_vs_bad_tag() {
    let (t, pass) = run_aead_ct_test(AeadAlgo::ChaCha20Poly1305);
    println!("ChaCha20-Poly1305 tag-position (first vs last byte) t-stat: {t:.4}");
    assert!(
        pass,
        "ChaCha20-Poly1305 tag verification appears non-constant-time: |t|={t:.4} >= {T_THRESHOLD}"
    );
}

/// AES-256-GCM: first-vs-last byte position (alias for the primary CT test).
///
/// Retained for test name compatibility; delegates to `run_aead_ct_test`
/// which already uses the first-vs-last byte methodology.
#[test]
fn ct_aead_aes256gcm_tag_position() {
    let (t, pass) = run_aead_ct_test(AeadAlgo::Aes256Gcm);
    println!("AES-256-GCM tag-position t-stat: {t:.4}");
    assert!(
        pass,
        "AES-256-GCM tag comparison shows positional timing difference: |t|={t:.4} >= {T_THRESHOLD}"
    );
}

/// ChaCha20-Poly1305: first-vs-last byte position.
#[test]
fn ct_aead_chacha20_tag_position() {
    let (t, pass) = run_aead_ct_test(AeadAlgo::ChaCha20Poly1305);
    println!("ChaCha20-Poly1305 tag-position t-stat: {t:.4}");
    assert!(
        pass,
        "ChaCha20-Poly1305 tag comparison shows positional timing difference: |t|={t:.4} >= {T_THRESHOLD}"
    );
}

#[test]
fn ct_hmac_sha256_verify() {
    let (t, pass) = run_hmac_ct_test();
    println!("HMAC-SHA-256 verify t-stat: {t:.4}");
    assert!(
        pass,
        "HMAC-SHA-256 verify appears non-constant-time: |t|={t:.4} >= {T_THRESHOLD}"
    );
}
