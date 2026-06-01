//! Post-quantum benchmarks: ML-KEM-768 and ML-DSA-65.
//!
//! Requires the `pq-preview` feature.  Operations are expensive in debug builds;
//! run with `--release`.  ML-DSA sign/verify are spawned in an 8 MiB thread to
//! avoid stack overflow in debug builds.
//!
//! Benchmark groups:
//!   - `pq/ML-KEM-768`: keygen, encapsulate, decapsulate
//!   - `pq/ML-DSA-65`:  keygen, sign, verify
//!
//! Criterion is configured with `sample_size(10)` for all groups because
//! ML-DSA key generation and signing are order-of-magnitude slower than
//! classical counterparts.

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode};
use oxicrypto_pq::{MlDsa65, MlKem768, Signature65, SigningKey65, VerifyingKey65};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// ── CSPRNG helper ─────────────────────────────────────────────────────────────

/// Build an OS-seeded ChaCha20 CSPRNG suitable for ML-KEM/ML-DSA key generation.
///
/// `MlKem768::generate` and `MlDsa65::generate` require a `CryptoRng`.
/// `OxiRng` implements only `TryCryptoRng`, so we use `ChaCha20Rng` instead.
fn make_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("bench setup: getrandom failed");
    ChaCha20Rng::from_seed(seed)
}

// ── ML-KEM-768 benchmarks ─────────────────────────────────────────────────────

fn bench_mlkem768(c: &mut Criterion) {
    let mut rng = make_rng();

    // Pre-generate key material for encap/decap benches.
    let (setup_dk, setup_ek) = MlKem768::generate(&mut rng);
    let (setup_ct, _) = setup_ek.encapsulate(&mut rng).expect("encap setup failed");

    let mut group = c.benchmark_group("pq/ML-KEM-768");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    group.bench_function("keygen", |b| {
        b.iter(|| {
            let _ = MlKem768::generate(&mut rng);
        });
    });

    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            setup_ek.encapsulate(&mut rng).expect("encapsulate failed");
        });
    });

    group.bench_function("decapsulate", |b| {
        b.iter(|| {
            setup_dk.decapsulate(&setup_ct).expect("decapsulate failed");
        });
    });

    group.finish();
}

// ── ML-DSA-65 benchmarks ──────────────────────────────────────────────────────
//
// ML-DSA key operations require ~4–8 MiB of stack in debug builds.  We spawn
// an 8 MiB thread for each group setup call so the Criterion loop itself runs
// in that same thread context.

fn bench_mldsa65(c: &mut Criterion) {
    const STACK: usize = 8 * 1024 * 1024;
    let msg = b"oxicrypto benchmark message for ML-DSA-65 signature operations";

    // Pre-generate keys for sign/verify benches.  Keygen requires large stack
    // in debug; use a thread with expanded stack to be safe.
    let (signing_key_bytes, verifying_key_bytes) = std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(|| {
            let mut rng = make_rng();
            let (sk, vk) = MlDsa65::generate(&mut rng);
            (sk.to_bytes(), vk.to_bytes())
        })
        .expect("thread spawn failed")
        .join()
        .expect("ML-DSA-65 keygen thread panicked");

    let sk = SigningKey65::from_bytes(&signing_key_bytes).expect("sk from bytes");
    let vk = VerifyingKey65::from_bytes(&verifying_key_bytes).expect("vk from bytes");

    // Pre-compute a signature for the verify bench.
    let sig_bytes = std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || {
            let sk_inner = SigningKey65::from_bytes(&signing_key_bytes).expect("sk inner");
            sk_inner.sign(msg).expect("mldsa65 pre-sign").to_bytes()
        })
        .expect("thread spawn failed")
        .join()
        .expect("ML-DSA-65 sign thread panicked");

    let sig = Signature65::from_bytes(&sig_bytes).expect("sig from bytes");

    let mut group = c.benchmark_group("pq/ML-DSA-65");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    group.bench_function("keygen", |b| {
        b.iter(|| {
            let mut rng = make_rng();
            let _ = MlDsa65::generate(&mut rng);
        });
    });

    group.bench_function("sign", |b| {
        b.iter(|| {
            sk.sign(msg).expect("mldsa65 sign");
        });
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            vk.verify(msg, &sig).expect("mldsa65 verify");
        });
    });

    group.finish();
}

// ── Criterion wiring ──────────────────────────────────────────────────────────

criterion_group!(benches, bench_mlkem768, bench_mldsa65);
criterion_main!(benches);
