//! Key-exchange benchmarks: X25519, X448, and ECDH P-256/P-384/P-521.
//!
//! Measures key generation and agreement latency per-operation.
//! Results are in nanoseconds (no throughput metric — KEX is inherently
//! per-handshake, not per-byte).
//!
//! # ring comparison
//!
//! The X25519 group includes `ring-agree` sub-benchmarks using `ring 0.17`
//! as a reference implementation.  ring is a dev-dependency of this bench
//! crate only and never appears on the default dependency closure.

use criterion::{criterion_group, criterion_main, Criterion};
use oxicrypto::{kex_impl, KexAlgo};
use oxicrypto_kex::{
    ecdh_p256_generate_keypair, ecdh_p384_generate_keypair, ecdh_p521_generate_keypair,
    x25519_generate_keypair, x448_generate_keypair,
};
use oxicrypto_rand::OxiRng;

// ── Quick-mode helper ─────────────────────────────────────────────────────────
//
// When BENCH_QUICK=1 is set, reduce sample size to 10 for CI smoke testing.

fn apply_quick_mode(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    if std::env::var("BENCH_QUICK").as_deref() == Ok("1") {
        group.sample_size(10);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_rng() -> OxiRng {
    OxiRng::new().expect("bench setup: OS RNG unavailable")
}

// ── X25519 ────────────────────────────────────────────────────────────────────

fn bench_x25519(c: &mut Criterion) {
    let mut rng = make_rng();

    let (alice_sk, alice_pk) =
        x25519_generate_keypair(&mut rng).expect("alice x25519 keygen (setup)");
    let (bob_sk, bob_pk) = x25519_generate_keypair(&mut rng).expect("bob x25519 keygen (setup)");

    let kex = kex_impl(KexAlgo::X25519);
    let mut shared = [0u8; 32];

    let alice_sk_bytes = *alice_sk.as_bytes();
    let bob_sk_bytes = *bob_sk.as_bytes();

    let mut group = c.benchmark_group("kex/X25519");
    apply_quick_mode(&mut group);

    group.bench_function("keygen", |b| {
        b.iter(|| {
            x25519_generate_keypair(&mut rng).expect("x25519 keygen");
        });
    });

    group.bench_function("agree", |b| {
        b.iter(|| {
            kex.agree(&alice_sk_bytes, &bob_pk, &mut shared)
                .expect("x25519 agree");
        });
    });

    // Measure a full round-trip (both sides compute their shared secret).
    group.bench_function("agree-round-trip", |b| {
        b.iter(|| {
            kex.agree(&alice_sk_bytes, &bob_pk, &mut shared)
                .expect("alice agree");
            kex.agree(&bob_sk_bytes, &alice_pk, &mut shared)
                .expect("bob agree");
        });
    });

    // ── ring comparison ────────────────────────────────────────────────────────
    // ring 0.17 X25519: EphemeralKeyPair + agree_ephemeral.
    {
        use ring::agreement::{
            agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519 as RingX25519,
        };
        use ring::rand::SystemRandom;

        let rng_ring = SystemRandom::new();

        // Pre-generate Bob's ephemeral public key for the agree bench.
        let bob_ring_sk =
            EphemeralPrivateKey::generate(&RingX25519, &rng_ring).expect("ring bob keygen");
        let bob_ring_pk_bytes = bob_ring_sk
            .compute_public_key()
            .expect("ring bob pubkey")
            .as_ref()
            .to_vec();

        group.bench_function("ring-agree", |b| {
            b.iter(|| {
                let alice_ring_sk =
                    EphemeralPrivateKey::generate(&RingX25519, &rng_ring).expect("ring alice gen");
                let bob_ring_pk = UnparsedPublicKey::new(&RingX25519, &bob_ring_pk_bytes);
                agree_ephemeral(alice_ring_sk, &bob_ring_pk, |_secret| ())
                    .expect("ring x25519 agree");
            });
        });
    }

    group.finish();
}

// ── X448 ──────────────────────────────────────────────────────────────────────

fn bench_x448(c: &mut Criterion) {
    let mut rng = make_rng();

    let (alice_sk, alice_pk) = x448_generate_keypair(&mut rng).expect("alice x448 keygen (setup)");
    let (bob_sk, bob_pk) = x448_generate_keypair(&mut rng).expect("bob x448 keygen (setup)");

    let kex = kex_impl(KexAlgo::X448);
    let mut shared = [0u8; 56];

    let alice_sk_bytes = *alice_sk.as_bytes();
    let bob_sk_bytes = *bob_sk.as_bytes();

    let mut group = c.benchmark_group("kex/X448");
    apply_quick_mode(&mut group);

    group.bench_function("keygen", |b| {
        b.iter(|| {
            x448_generate_keypair(&mut rng).expect("x448 keygen");
        });
    });

    group.bench_function("agree", |b| {
        b.iter(|| {
            kex.agree(&alice_sk_bytes, &bob_pk, &mut shared)
                .expect("x448 agree");
        });
    });

    // Measure a full round-trip (both sides compute their shared secret).
    group.bench_function("agree-round-trip", |b| {
        b.iter(|| {
            kex.agree(&alice_sk_bytes, &bob_pk, &mut shared)
                .expect("alice x448 agree");
            kex.agree(&bob_sk_bytes, &alice_pk, &mut shared)
                .expect("bob x448 agree");
        });
    });

    group.finish();
}

// ── ECDH P-256 ────────────────────────────────────────────────────────────────

fn bench_ecdh_p256(c: &mut Criterion) {
    let mut rng = make_rng();

    let (alice_sk, alice_pk) =
        ecdh_p256_generate_keypair(&mut rng).expect("alice p256 keygen (setup)");
    let (bob_sk, bob_pk) = ecdh_p256_generate_keypair(&mut rng).expect("bob p256 keygen (setup)");

    let kex = kex_impl(KexAlgo::EcdhP256);
    // P-256 shared secret is 32 bytes.
    let mut shared = [0u8; 32];

    let alice_sk_bytes = alice_sk.as_bytes().to_vec();
    let bob_sk_bytes = bob_sk.as_bytes().to_vec();

    let mut group = c.benchmark_group("kex/ECDH-P256");
    apply_quick_mode(&mut group);

    group.bench_function("keygen", |b| {
        b.iter(|| {
            ecdh_p256_generate_keypair(&mut rng).expect("p256 keygen");
        });
    });

    group.bench_function("agree", |b| {
        b.iter(|| {
            kex.agree(&alice_sk_bytes, &bob_pk, &mut shared)
                .expect("ecdh-p256 agree");
        });
    });

    group.bench_function("agree-round-trip", |b| {
        b.iter(|| {
            kex.agree(&alice_sk_bytes, &bob_pk, &mut shared)
                .expect("alice agree");
            kex.agree(&bob_sk_bytes, &alice_pk, &mut shared)
                .expect("bob agree");
        });
    });

    // ── ring comparison ────────────────────────────────────────────────────────
    // ring 0.17 ECDH P-256 via agree_ephemeral.
    {
        use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256};
        use ring::rand::SystemRandom;

        let rng_ring = SystemRandom::new();

        // Pre-generate Bob's ephemeral P-256 public key for the agree bench.
        let bob_ring_sk =
            EphemeralPrivateKey::generate(&ECDH_P256, &rng_ring).expect("ring bob p256 keygen");
        let bob_ring_pk_bytes = bob_ring_sk
            .compute_public_key()
            .expect("ring bob p256 pubkey")
            .as_ref()
            .to_vec();

        group.bench_function("ring-agree", |b| {
            b.iter(|| {
                let alice_ring_sk = EphemeralPrivateKey::generate(&ECDH_P256, &rng_ring)
                    .expect("ring alice p256 gen");
                let bob_ring_pk = UnparsedPublicKey::new(&ECDH_P256, &bob_ring_pk_bytes);
                agree_ephemeral(alice_ring_sk, &bob_ring_pk, |_secret| ())
                    .expect("ring ecdh-p256 agree");
            });
        });
    }

    group.finish();
}

// ── ECDH P-384 ────────────────────────────────────────────────────────────────

fn bench_ecdh_p384(c: &mut Criterion) {
    let mut rng = make_rng();

    let (alice_sk, alice_pk) =
        ecdh_p384_generate_keypair(&mut rng).expect("alice p384 keygen (setup)");
    let (bob_sk, bob_pk) = ecdh_p384_generate_keypair(&mut rng).expect("bob p384 keygen (setup)");

    let kex = kex_impl(KexAlgo::EcdhP384);
    // P-384 shared secret is 48 bytes.
    let mut shared = [0u8; 48];

    let alice_sk_bytes = alice_sk.as_bytes().to_vec();
    let bob_sk_bytes = bob_sk.as_bytes().to_vec();

    let mut group = c.benchmark_group("kex/ECDH-P384");
    apply_quick_mode(&mut group);

    group.bench_function("keygen", |b| {
        b.iter(|| {
            ecdh_p384_generate_keypair(&mut rng).expect("p384 keygen");
        });
    });

    group.bench_function("agree", |b| {
        b.iter(|| {
            kex.agree(&alice_sk_bytes, &bob_pk, &mut shared)
                .expect("ecdh-p384 agree");
        });
    });

    group.bench_function("agree-round-trip", |b| {
        b.iter(|| {
            kex.agree(&alice_sk_bytes, &bob_pk, &mut shared)
                .expect("alice agree");
            kex.agree(&bob_sk_bytes, &alice_pk, &mut shared)
                .expect("bob agree");
        });
    });

    group.finish();
}

// ── ECDH P-521 ────────────────────────────────────────────────────────────────

fn bench_ecdh_p521(c: &mut Criterion) {
    let mut rng = make_rng();

    let (alice_sk, alice_pk) =
        ecdh_p521_generate_keypair(&mut rng).expect("alice p521 keygen (setup)");
    let (bob_sk, bob_pk) = ecdh_p521_generate_keypair(&mut rng).expect("bob p521 keygen (setup)");

    let kex = kex_impl(KexAlgo::EcdhP521);
    // P-521 shared secret is 66 bytes.
    let mut shared = [0u8; 66];

    let alice_sk_bytes = alice_sk.as_bytes().to_vec();
    let bob_sk_bytes = bob_sk.as_bytes().to_vec();

    let mut group = c.benchmark_group("kex/ECDH-P521");
    apply_quick_mode(&mut group);

    group.bench_function("keygen", |b| {
        b.iter(|| {
            ecdh_p521_generate_keypair(&mut rng).expect("p521 keygen");
        });
    });

    group.bench_function("agree", |b| {
        b.iter(|| {
            kex.agree(&alice_sk_bytes, &bob_pk, &mut shared)
                .expect("ecdh-p521 agree");
        });
    });

    group.bench_function("agree-round-trip", |b| {
        b.iter(|| {
            kex.agree(&alice_sk_bytes, &bob_pk, &mut shared)
                .expect("alice agree");
            kex.agree(&bob_sk_bytes, &alice_pk, &mut shared)
                .expect("bob agree");
        });
    });

    group.finish();
}

// ── Criterion wiring ──────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_x25519,
    bench_x448,
    bench_ecdh_p256,
    bench_ecdh_p384,
    bench_ecdh_p521
);
criterion_main!(benches);
