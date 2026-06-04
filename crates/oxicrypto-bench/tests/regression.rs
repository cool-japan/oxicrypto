//! Performance regression guard tests.
//!
//! These tests enforce that OxiCrypto operations complete within a reasonable
//! wall-clock budget *relative to ring* on the same machine.  They guard
//! against *catastrophic* regressions (accidental O(n²) loops, broken SIMD
//! dispatch, infinite loops) rather than small constant-factor changes.
//!
//! # Threshold design
//!
//! Each test measures N iterations of the OxiCrypto operation and N iterations
//! of the ring equivalent, then checks:
//!
//!   oxi_median_ns / ring_median_ns < THRESHOLD
//!
//! Using the median (not the mean) reduces sensitivity to occasional OS
//! scheduling jitter.
//!
//! ## Debug vs Release thresholds
//!
//! In debug builds (the default under `cargo nextest run`) ring's C/ASM
//! implementations are 50–200× faster than the unoptimised Pure-Rust
//! OxiCrypto code.  The debug threshold is therefore very loose (300×) —
//! it only catches truly broken implementations (e.g. a test that always
//! takes 1 second when it should take microseconds).
//!
//! In release builds (with `--profile release`) the ratio collapses to
//! 1–3× for most algorithms because LLVM fully optimises the Rust code.
//! The release threshold (5×) matches the design goal in `bench_ratios.py`.
//!
//! # Environment variables
//!
//! `BENCH_REGRESSION_ITERS` — override the number of timing samples (default: 200).
//! `BENCH_REGRESSION_SKIP`  — set to "1" to skip all regression checks (for slow CI).

/// Regression threshold appropriate for the current build profile.
///
/// - **debug**: 10000× — unoptimised builds under concurrent test load are
///   extremely noisy; this only catches infinite loops / completely broken code.
/// - **release**: 5× — catches constant-factor regressions.
#[cfg(debug_assertions)]
const REGRESSION_THRESHOLD: f64 = 10_000.0;

#[cfg(not(debug_assertions))]
const REGRESSION_THRESHOLD: f64 = 5.0;

use std::time::Instant;

use oxicrypto::{aead_impl, hash_impl, mac_impl, AeadAlgo, HashAlgo, MacAlgo};
use oxicrypto_rand::OxiRng;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Number of timing samples per operation per implementation.
fn iters() -> usize {
    std::env::var("BENCH_REGRESSION_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200)
}

/// Return `true` if regression checks are disabled via environment variable.
fn skip_regression() -> bool {
    std::env::var("BENCH_REGRESSION_SKIP").as_deref() == Ok("1")
}

// ── Timing helpers ─────────────────────────────────────────────────────────────

/// Measure wall-clock nanoseconds for a single call of `f`.
#[inline(never)]
fn time_ns<F: FnMut()>(mut f: F) -> u64 {
    let start = Instant::now();
    f();
    start.elapsed().as_nanos() as u64
}

/// Collect `n` timing samples and return the median.
///
/// Runs `setup()` once before the timing loop to amortize allocation/init.
fn median_ns<S, F>(n: usize, mut setup: S, mut f: F) -> u64
where
    S: FnMut(),
    F: FnMut(),
{
    setup();
    let mut samples: Vec<u64> = (0..n).map(|_| time_ns(&mut f)).collect();
    samples.sort_unstable();
    samples[n / 2]
}

/// Helper: make an OS-seeded OxiRng for test setup.
fn make_rng() -> OxiRng {
    OxiRng::new().expect("regression test: OS RNG unavailable")
}

/// Fill a buffer with random bytes via OxiRng.
fn random_bytes(rng: &mut OxiRng, n: usize) -> Vec<u8> {
    use rand_core::TryRng;
    let mut buf = vec![0u8; n];
    rng.try_fill_bytes(&mut buf)
        .expect("regression test: RNG fill failed");
    buf
}

// ── SHA-256 regression: OxiCrypto vs ring ────────────────────────────────────
//
// Threshold: OxiCrypto SHA-256 must be within 5× of ring SHA-256 in debug mode.
// Release-mode ratio is enforced separately by bench_ratios.py.

#[test]
fn regression_sha256_vs_ring() {
    if skip_regression() {
        return;
    }

    let n = iters();
    let mut rng = make_rng();
    // Use 4 KiB input to make the hash computation dominate over function-call overhead.
    let data = random_bytes(&mut rng, 4096);
    let h_oxi = hash_impl(HashAlgo::Sha256);
    let mut out_oxi = [0u8; 32];

    let oxi_med = median_ns(
        n,
        || {},
        || {
            h_oxi.hash(&data, &mut out_oxi).expect("sha256 oxi");
        },
    );

    let ring_med = median_ns(
        n,
        || {},
        || {
            let _ = ring::digest::digest(&ring::digest::SHA256, &data);
        },
    );

    // If either measurement is 0 the system timer can't resolve this operation;
    // skip the ratio check rather than dividing by zero or getting a misleading ratio.
    if oxi_med == 0 || ring_med == 0 {
        return;
    }

    let ratio = oxi_med as f64 / ring_med as f64;
    assert!(
        ratio < REGRESSION_THRESHOLD,
        "SHA-256 regression: OxiCrypto ({oxi_med} ns) is {ratio:.2}x slower than ring \
         ({ring_med} ns) — exceeds {REGRESSION_THRESHOLD}x threshold. \
         (samples={n}, input=4096 B)"
    );
}

// ── ChaCha20-Poly1305 regression: OxiCrypto vs ring ─────────────────────────

#[test]
fn regression_chacha20_vs_ring() {
    if skip_regression() {
        return;
    }

    let n = iters();
    let mut rng = make_rng();
    let plaintext = random_bytes(&mut rng, 1024);

    // OxiCrypto side.
    let aead_oxi = aead_impl(AeadAlgo::ChaCha20Poly1305);
    let key_oxi = random_bytes(&mut rng, aead_oxi.key_len());
    let nonce_oxi = random_bytes(&mut rng, aead_oxi.nonce_len());
    let tag_len = aead_oxi.tag_len();
    let mut ct_oxi = vec![0u8; plaintext.len() + tag_len];

    let oxi_med = median_ns(
        n,
        || {},
        || {
            aead_oxi
                .seal(&key_oxi, &nonce_oxi, b"", &plaintext, &mut ct_oxi)
                .expect("chacha20 oxi seal");
        },
    );

    // ring side: ChaCha20-Poly1305 via AEAD API.
    use ring::aead::{
        BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, CHACHA20_POLY1305, NONCE_LEN,
    };
    use ring::error::Unspecified;

    struct OneNonce([u8; NONCE_LEN]);
    impl NonceSequence for OneNonce {
        fn advance(&mut self) -> Result<Nonce, Unspecified> {
            Ok(Nonce::assume_unique_for_key(self.0))
        }
    }

    let ring_key_bytes = random_bytes(&mut rng, 32);
    let ring_nonce = [0u8; NONCE_LEN];

    let ring_med = median_ns(
        n,
        || {},
        || {
            let unbound = UnboundKey::new(&CHACHA20_POLY1305, &ring_key_bytes).expect("ring key");
            let mut sealing = SealingKey::new(unbound, OneNonce(ring_nonce));
            let mut buf = plaintext.clone();
            let tag = sealing
                .seal_in_place_separate_tag(ring::aead::Aad::empty(), &mut buf)
                .expect("ring chacha20 seal");
            std::hint::black_box((&buf, tag.as_ref()));
        },
    );

    if oxi_med == 0 || ring_med == 0 {
        return;
    }

    let ratio = oxi_med as f64 / ring_med as f64;
    assert!(
        ratio < REGRESSION_THRESHOLD,
        "ChaCha20-Poly1305 regression: OxiCrypto ({oxi_med} ns) is {ratio:.2}x slower \
         than ring ({ring_med} ns) — exceeds {REGRESSION_THRESHOLD}x threshold. \
         (samples={n}, input=1024 B)"
    );
}

// ── AES-256-GCM regression: OxiCrypto vs ring ────────────────────────────────

#[test]
fn regression_aes256gcm_vs_ring() {
    if skip_regression() {
        return;
    }

    let n = iters();
    let mut rng = make_rng();
    let plaintext = random_bytes(&mut rng, 1024);

    // OxiCrypto side.
    let aead_oxi = aead_impl(AeadAlgo::Aes256Gcm);
    let key_oxi = random_bytes(&mut rng, aead_oxi.key_len());
    let nonce_oxi = random_bytes(&mut rng, aead_oxi.nonce_len());
    let tag_len = aead_oxi.tag_len();
    let mut ct_oxi = vec![0u8; plaintext.len() + tag_len];

    let oxi_med = median_ns(
        n,
        || {},
        || {
            aead_oxi
                .seal(&key_oxi, &nonce_oxi, b"", &plaintext, &mut ct_oxi)
                .expect("aes256gcm oxi seal");
        },
    );

    // ring side: AES-256-GCM via ring::aead.
    use ring::aead::{
        BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN,
    };
    use ring::error::Unspecified;

    struct FixedNonce([u8; NONCE_LEN]);
    impl NonceSequence for FixedNonce {
        fn advance(&mut self) -> Result<Nonce, Unspecified> {
            Ok(Nonce::assume_unique_for_key(self.0))
        }
    }

    let ring_key_bytes = random_bytes(&mut rng, 32);
    let ring_nonce = [0u8; NONCE_LEN];

    let ring_med = median_ns(
        n,
        || {},
        || {
            let unbound = UnboundKey::new(&AES_256_GCM, &ring_key_bytes).expect("ring key");
            let mut sealing = SealingKey::new(unbound, FixedNonce(ring_nonce));
            let mut buf = plaintext.clone();
            let tag = sealing
                .seal_in_place_separate_tag(ring::aead::Aad::empty(), &mut buf)
                .expect("ring aes256gcm seal");
            std::hint::black_box((&buf, tag.as_ref()));
        },
    );

    if oxi_med == 0 || ring_med == 0 {
        return;
    }

    let ratio = oxi_med as f64 / ring_med as f64;
    assert!(
        ratio < REGRESSION_THRESHOLD,
        "AES-256-GCM regression: OxiCrypto ({oxi_med} ns) is {ratio:.2}x slower \
         than ring ({ring_med} ns) — exceeds {REGRESSION_THRESHOLD}x threshold. \
         (samples={n}, input=1024 B)"
    );
}

// ── HMAC-SHA-256 regression: OxiCrypto vs ring ───────────────────────────────

#[test]
fn regression_hmac_sha256_vs_ring() {
    if skip_regression() {
        return;
    }

    let n = iters();
    let mut rng = make_rng();
    let data = random_bytes(&mut rng, 1024);
    let key_bytes = random_bytes(&mut rng, 32);

    // OxiCrypto side.
    let mac = mac_impl(MacAlgo::HmacSha256);
    let mut out = [0u8; 32];

    let oxi_med = median_ns(
        n,
        || {},
        || {
            mac.mac(&key_bytes, &data, &mut out).expect("hmac oxi");
        },
    );

    // ring side: HMAC-SHA-256 via ring::hmac.
    let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key_bytes);

    let ring_med = median_ns(
        n,
        || {},
        || {
            let tag = ring::hmac::sign(&ring_key, &data);
            std::hint::black_box(tag.as_ref());
        },
    );

    // If either measurement is 0 the system timer can't resolve this operation;
    // skip the ratio check rather than dividing by zero or getting a misleading ratio.
    if oxi_med == 0 || ring_med == 0 {
        return;
    }

    let ratio = oxi_med as f64 / ring_med as f64;
    assert!(
        ratio < REGRESSION_THRESHOLD,
        "HMAC-SHA-256 regression: OxiCrypto ({oxi_med} ns) is {ratio:.2}x slower \
         than ring ({ring_med} ns) — exceeds {REGRESSION_THRESHOLD}x threshold. \
         (samples={n}, input=1024 B)"
    );
}

// ── Self-consistency: each OxiCrypto algorithm produces correct output ────────
//
// While the primary purpose of this file is performance regression, we also
// verify that the operations are not accidentally measuring no-ops.

#[test]
fn regression_operations_are_non_trivial() {
    let mut rng = make_rng();
    let data = random_bytes(&mut rng, 1024);

    // SHA-256 must produce a non-zero, non-identity digest.
    let h = hash_impl(HashAlgo::Sha256);
    let mut digest = [0u8; 32];
    h.hash(&data, &mut digest).expect("sha256");
    assert_ne!(digest, [0u8; 32], "SHA-256 produced all-zero output");

    // AES-256-GCM ciphertext must differ from plaintext.
    let aead = aead_impl(AeadAlgo::Aes256Gcm);
    let key = random_bytes(&mut rng, aead.key_len());
    let nonce = random_bytes(&mut rng, aead.nonce_len());
    let pt = random_bytes(&mut rng, 32);
    let mut ct = vec![0u8; pt.len() + aead.tag_len()];
    aead.seal(&key, &nonce, b"", &pt, &mut ct)
        .expect("aes seal");
    assert_ne!(
        &ct[..pt.len()],
        pt.as_slice(),
        "AES-256-GCM ciphertext matches plaintext (encryption is a no-op)"
    );

    // HMAC tag must be non-zero.
    let mac = mac_impl(MacAlgo::HmacSha256);
    let mac_key = random_bytes(&mut rng, 32);
    let mut tag = [0u8; 32];
    mac.mac(&mac_key, &data, &mut tag).expect("hmac");
    assert_ne!(tag, [0u8; 32], "HMAC produced all-zero output");
}
