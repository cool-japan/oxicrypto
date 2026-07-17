//! Criterion benchmarks for oxicrypto-pq post-quantum algorithms.
//!
//! Covers:
//! - ML-KEM-512/768/1024: keygen, encapsulate, decapsulate
//! - ML-DSA-44/65/87: keygen, sign, verify
//! - Hybrid KEM: X-Wing (ML-KEM-768 + X25519), HybridKem1024P384
//! - SLH-DSA-SHA2-128s/f: sign, verify (expected ~100x slower than ML-DSA)
//!
//! # Running
//!
//! ```text
//! cargo bench -p oxicrypto-pq
//! ```

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use oxicrypto_core::Kem;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use x25519_dalek::PublicKey as X25519PublicKey;

use oxicrypto_pq::{
    hybrid::{HybridKem1024P384, XWing768},
    mldsa::{MlDsa44, MlDsa65, MlDsa87},
    mlkem::{MlKem1024, MlKem512, MlKem768},
    slh_dsa::{SlhDsaSha2_128f, SlhDsaSha2_128s},
};

const BENCH_SEED: [u8; 32] = [0x42u8; 32];
const MSG: &[u8] = b"benchmark test message for post-quantum signature schemes";

// ─────────────────────────────────────────────────────────────────────────────
//  ML-KEM-512
// ─────────────────────────────────────────────────────────────────────────────

fn bench_mlkem512(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-512");

    group.bench_function("keygen", |b| {
        b.iter_batched(
            || ChaCha20Rng::from_seed(BENCH_SEED),
            |mut rng| MlKem512::generate(&mut rng),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("encapsulate", |b| {
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        let (_, ek) = MlKem512::generate(&mut rng);
        b.iter_batched(
            || ChaCha20Rng::from_seed(BENCH_SEED),
            |mut rng| ek.encapsulate(&mut rng),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("decapsulate", |b| {
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        let (dk, ek) = MlKem512::generate(&mut rng);
        let (ct, _ss) = ek.encapsulate(&mut rng).expect("encap");
        b.iter(|| dk.decapsulate(&ct));
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-KEM-768
// ─────────────────────────────────────────────────────────────────────────────

fn bench_mlkem768(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-768");

    group.bench_function("keygen", |b| {
        b.iter_batched(
            || ChaCha20Rng::from_seed(BENCH_SEED),
            |mut rng| MlKem768::generate(&mut rng),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("encapsulate", |b| {
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        let (_, ek) = MlKem768::generate(&mut rng);
        b.iter_batched(
            || ChaCha20Rng::from_seed(BENCH_SEED),
            |mut rng| ek.encapsulate(&mut rng),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("decapsulate", |b| {
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, _ss) = ek.encapsulate(&mut rng).expect("encap");
        b.iter(|| dk.decapsulate(&ct));
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-KEM-1024
// ─────────────────────────────────────────────────────────────────────────────

fn bench_mlkem1024(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-1024");

    group.bench_function("keygen", |b| {
        b.iter_batched(
            || ChaCha20Rng::from_seed(BENCH_SEED),
            |mut rng| MlKem1024::generate(&mut rng),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("encapsulate", |b| {
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        let (_, ek) = MlKem1024::generate(&mut rng);
        b.iter_batched(
            || ChaCha20Rng::from_seed(BENCH_SEED),
            |mut rng| ek.encapsulate(&mut rng),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("decapsulate", |b| {
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        let (dk, ek) = MlKem1024::generate(&mut rng);
        let (ct, _ss) = ek.encapsulate(&mut rng).expect("encap");
        b.iter(|| dk.decapsulate(&ct));
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-44
// ─────────────────────────────────────────────────────────────────────────────

fn bench_mldsa44(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA-44");

    group.bench_function("keygen", |b| {
        b.iter_batched(
            || ChaCha20Rng::from_seed(BENCH_SEED),
            |mut rng| MlDsa44::generate(&mut rng),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("sign", |b| {
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        let (sk, _vk) = MlDsa44::generate(&mut rng);
        b.iter(|| sk.sign(MSG).expect("sign"));
    });

    group.bench_function("verify", |b| {
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        let (sk, vk) = MlDsa44::generate(&mut rng);
        let sig = sk.sign(MSG).expect("sign");
        b.iter(|| vk.verify(MSG, &sig).expect("verify"));
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-65
// ─────────────────────────────────────────────────────────────────────────────

fn bench_mldsa65(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA-65");

    group.bench_function("keygen", |b| {
        b.iter_batched(
            || ChaCha20Rng::from_seed(BENCH_SEED),
            |mut rng| MlDsa65::generate(&mut rng),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("sign", |b| {
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        let (sk, _vk) = MlDsa65::generate(&mut rng);
        b.iter(|| sk.sign(MSG).expect("sign"));
    });

    group.bench_function("verify", |b| {
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        let (sk, vk) = MlDsa65::generate(&mut rng);
        let sig = sk.sign(MSG).expect("sign");
        b.iter(|| vk.verify(MSG, &sig).expect("verify"));
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-DSA-87 (larger stack required — wrap in high-stack threads)
// ─────────────────────────────────────────────────────────────────────────────

fn bench_mldsa87(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA-87");
    // ML-DSA-87 keygen/sign/verify build large transient buffers on the stack.
    // Each benchmark iteration re-spawns a worker thread sized to
    // `OXICRYPTO_MLDSA_STACK` (2 MiB, ~2.7x the measured worst-case footprint).
    // Thread-spawn overhead is included but unavoidable here.

    group.bench_function("keygen+sign (2MiB stack)", |b| {
        b.iter(|| {
            std::thread::Builder::new()
                .stack_size(oxicrypto_pq::OXICRYPTO_MLDSA_STACK)
                .spawn(|| {
                    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
                    let (sk, _vk) = MlDsa87::generate(&mut rng);
                    sk.sign(MSG).expect("sign")
                })
                .expect("spawn")
                .join()
                .expect("thread panicked")
        });
    });

    group.bench_function("verify (2MiB stack)", |b| {
        // Pre-generate sig bytes outside the loop (serialised form for Send).
        let sig_bytes = std::thread::Builder::new()
            .stack_size(oxicrypto_pq::OXICRYPTO_MLDSA_STACK)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
                let (sk, _vk) = MlDsa87::generate(&mut rng);
                sk.sign(MSG).expect("sign").to_bytes()
            })
            .expect("spawn")
            .join()
            .expect("thread panicked");
        let vk_bytes = std::thread::Builder::new()
            .stack_size(oxicrypto_pq::OXICRYPTO_MLDSA_STACK)
            .spawn(|| {
                let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
                let (_sk, vk) = MlDsa87::generate(&mut rng);
                vk.to_bytes()
            })
            .expect("spawn")
            .join()
            .expect("thread panicked");
        b.iter(|| {
            use oxicrypto_pq::mldsa::{Signature87, VerifyingKey87};
            let vk = VerifyingKey87::from_bytes(&vk_bytes).expect("from_bytes");
            let sig = Signature87::from_bytes(&sig_bytes).expect("from_bytes");
            vk.verify(MSG, &sig).expect("verify")
        });
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Hybrid KEM: X-Wing (ML-KEM-768 + X25519) — uses internal OS RNG
// ─────────────────────────────────────────────────────────────────────────────

fn bench_xwing768(c: &mut Criterion) {
    let mut group = c.benchmark_group("X-Wing (ML-KEM-768+X25519)");

    group.bench_function("keygen", |b| {
        b.iter(|| XWing768::kem_generate().expect("XWing768 keygen"));
    });

    group.bench_function("encapsulate", |b| {
        let (_dk, ek) = XWing768::kem_generate().expect("XWing768 keygen");
        b.iter(|| XWing768::kem_encapsulate(&ek).expect("XWing768 encapsulate"));
    });

    group.bench_function("decapsulate", |b| {
        let (dk, ek) = XWing768::kem_generate().expect("XWing768 keygen");
        let (ct, _ss) = XWing768::kem_encapsulate(&ek).expect("XWing768 encapsulate");
        b.iter(|| XWing768::kem_decapsulate(&dk, &ct).expect("XWing768 decapsulate"));
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Hybrid KEM: ML-KEM-1024 + P-384 — uses internal OS RNG
// ─────────────────────────────────────────────────────────────────────────────

fn bench_hybrid_mlkem1024_p384(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid (ML-KEM-1024+P-384)");

    group.bench_function("keygen", |b| {
        b.iter(|| HybridKem1024P384::kem_generate().expect("HybridKem1024P384 keygen"));
    });

    group.bench_function("encapsulate", |b| {
        let (_dk, ek) = HybridKem1024P384::kem_generate().expect("HybridKem1024P384 keygen");
        b.iter(|| HybridKem1024P384::kem_encapsulate(&ek).expect("HybridKem1024P384 encapsulate"));
    });

    group.bench_function("decapsulate", |b| {
        let (dk, ek) = HybridKem1024P384::kem_generate().expect("HybridKem1024P384 keygen");
        let (ct, _ss) =
            HybridKem1024P384::kem_encapsulate(&ek).expect("HybridKem1024P384 encapsulate");
        b.iter(|| {
            HybridKem1024P384::kem_decapsulate(&dk, &ct).expect("HybridKem1024P384 decapsulate")
        });
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  SLH-DSA: SHA2-128s (small/slow) and SHA2-128f (fast)
//  Expected ~100x slower than ML-DSA for signing; faster verify
// ─────────────────────────────────────────────────────────────────────────────

fn bench_slh_dsa_sha2_128s(c: &mut Criterion) {
    let mut group = c.benchmark_group("SLH-DSA-SHA2-128s (small)");
    // SHA2-128s has very slow signing (~10–100 ms) so use fewer samples.
    group.sample_size(10);

    group.bench_function("keygen", |b| {
        b.iter_batched(
            || ChaCha20Rng::from_seed(BENCH_SEED),
            |mut rng| SlhDsaSha2_128s::generate(&mut rng),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("sign", |b| {
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        let (sk, _vk) = SlhDsaSha2_128s::generate(&mut rng);
        b.iter(|| sk.sign(MSG).expect("SLH-DSA-SHA2-128s sign"));
    });

    group.bench_function("verify", |b| {
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        let (sk, vk) = SlhDsaSha2_128s::generate(&mut rng);
        let sig = sk.sign(MSG).expect("SLH-DSA-SHA2-128s sign");
        b.iter(|| vk.verify(MSG, &sig).expect("SLH-DSA-SHA2-128s verify"));
    });

    group.finish();
}

fn bench_slh_dsa_sha2_128f(c: &mut Criterion) {
    let mut group = c.benchmark_group("SLH-DSA-SHA2-128f (fast)");
    // SHA2-128f is faster than 128s (~1–10 ms signing).
    group.sample_size(20);

    group.bench_function("keygen", |b| {
        b.iter_batched(
            || ChaCha20Rng::from_seed(BENCH_SEED),
            |mut rng| SlhDsaSha2_128f::generate(&mut rng),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("sign", |b| {
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        let (sk, _vk) = SlhDsaSha2_128f::generate(&mut rng);
        b.iter(|| sk.sign(MSG).expect("SLH-DSA-SHA2-128f sign"));
    });

    group.bench_function("verify", |b| {
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        let (sk, vk) = SlhDsaSha2_128f::generate(&mut rng);
        let sig = sk.sign(MSG).expect("SLH-DSA-SHA2-128f sign");
        b.iter(|| vk.verify(MSG, &sig).expect("SLH-DSA-SHA2-128f verify"));
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Classical comparison: X25519 key exchange (compare with ML-KEM-768)
//
//  X25519 is the fastest classical DH; ML-KEM-768 is the NIST-recommended
//  post-quantum alternative.  These benches run in the same process so the
//  latency numbers are directly comparable.
//
//  Note: x25519-dalek uses rand_core 0.6.x which is incompatible with the
//  workspace rand_core 0.10.x.  We therefore drive keygen via fixed-byte
//  arrays (StaticSecret::from([u8;32])) to avoid a version-mismatch error
//  while still benchmarking the actual X25519 math.
// ─────────────────────────────────────────────────────────────────────────────

fn bench_x25519(c: &mut Criterion) {
    use x25519_dalek::StaticSecret;

    let mut group = c.benchmark_group("X25519 (classical, cf. ML-KEM-768)");

    // Different 32-byte seeds used to simulate distinct key derivations.
    const ALICE_SEED: [u8; 32] = [0x11u8; 32];
    const BOB_SEED: [u8; 32] = [0x22u8; 32];

    group.bench_function("keygen (StaticSecret+PublicKey)", |b| {
        // Derive a fresh secret and its public key from a fixed 32-byte seed.
        // The conversion is the actual X25519 scalar multiplication — same
        // cost as random keygen.
        b.iter(|| {
            let secret = StaticSecret::from(ALICE_SEED);
            let public = X25519PublicKey::from(&secret);
            (secret, public)
        });
    });

    group.bench_function("key-exchange (DH)", |b| {
        // Simulate one side of the X25519 handshake:
        // Alice has her static secret; she performs DH with Bob's public key.
        let bob_public = X25519PublicKey::from(&StaticSecret::from(BOB_SEED));
        b.iter(|| {
            let alice_secret = StaticSecret::from(ALICE_SEED);
            alice_secret.diffie_hellman(&bob_public)
        });
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Classical comparison: Ed25519 sign/verify (compare with ML-DSA-65)
//
//  Ed25519 is the fastest classical signature scheme; ML-DSA-65 is the
//  NIST-recommended post-quantum alternative at category-3 security.
//
//  Note: ed25519-dalek uses rand_core 0.6.x; we use `SigningKey::from_bytes`
//  with a fixed 32-byte seed to avoid the rand_core version mismatch while
//  still benchmarking the actual Ed25519 sign / verify operations.
// ─────────────────────────────────────────────────────────────────────────────

fn bench_ed25519(c: &mut Criterion) {
    use ed25519_dalek::Signer as _;
    use ed25519_dalek::Verifier as _;

    let mut group = c.benchmark_group("Ed25519 (classical, cf. ML-DSA-65)");

    // Derive a signing key from a fixed 32-byte seed (deterministic keygen).
    let sk = Ed25519SigningKey::from_bytes(&BENCH_SEED);
    let vk = sk.verifying_key();
    let sig = sk.sign(MSG);

    group.bench_function("keygen (from_bytes)", |b| {
        b.iter(|| Ed25519SigningKey::from_bytes(&BENCH_SEED));
    });

    group.bench_function("sign", |b| {
        b.iter(|| sk.sign(MSG));
    });

    group.bench_function("verify", |b| {
        b.iter(|| vk.verify(MSG, &sig).expect("ed25519 verify"));
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Registration
// ─────────────────────────────────────────────────────────────────────────────

criterion_group!(
    benches_mlkem,
    bench_mlkem512,
    bench_mlkem768,
    bench_mlkem1024,
);
criterion_group!(benches_mldsa, bench_mldsa44, bench_mldsa65, bench_mldsa87,);
criterion_group!(benches_hybrid, bench_xwing768, bench_hybrid_mlkem1024_p384,);
criterion_group!(
    benches_slh_dsa,
    bench_slh_dsa_sha2_128s,
    bench_slh_dsa_sha2_128f,
);
criterion_group!(benches_classical_comparison, bench_x25519, bench_ed25519,);
criterion_main!(
    benches_mlkem,
    benches_mldsa,
    benches_hybrid,
    benches_slh_dsa,
    benches_classical_comparison,
);
