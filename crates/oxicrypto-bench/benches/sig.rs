//! Signature benchmarks: Ed25519, ECDSA P-256/P-384/P-521, and RSA PKCS#1v15.
//!
//! Key generation, sign, and verify operations are measured separately so that
//! per-operation latency is visible independent of setup cost.
//!
//! RSA operations use `sample_size(10)` because 2048-bit key generation takes
//! 0.5–2 seconds and sign/verify is order-of-magnitude slower than ECC.

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode};
use oxicrypto::{signer_impl, verifier_impl, SigAlgo};
use oxicrypto_rand::OxiRng;
use oxicrypto_sig::{
    ecdsa_p256_generate_keypair, ecdsa_p384_generate_keypair, ecdsa_p521_generate_keypair,
    ed25519_generate_keypair, rsa_generate_keypair,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_rng() -> OxiRng {
    OxiRng::new().expect("bench setup: OS RNG unavailable")
}

// ── Ed25519 ───────────────────────────────────────────────────────────────────

fn bench_ed25519(c: &mut Criterion) {
    let mut rng = make_rng();
    let msg = b"oxicrypto benchmark message for signature operations -- Ed25519";

    let (ed_sk, ed_pk) = ed25519_generate_keypair(&mut rng).expect("ed25519 keygen");
    let ed_signer = signer_impl(SigAlgo::Ed25519);
    let ed_verifier = verifier_impl(SigAlgo::Ed25519);

    // Pre-compute a valid signature for the verify bench.
    let mut ed_sig = [0u8; 64];
    let ed_sk_bytes = *ed_sk.as_bytes();
    ed_signer
        .sign(&ed_sk_bytes, msg, &mut ed_sig)
        .expect("ed25519 pre-sign failed");

    let mut group = c.benchmark_group("sig/Ed25519");

    group.bench_function("keygen", |b| {
        b.iter(|| {
            ed25519_generate_keypair(&mut rng).expect("ed25519 keygen");
        });
    });

    group.bench_function("sign", |b| {
        let mut buf = [0u8; 64];
        b.iter(|| {
            ed_signer
                .sign(&ed_sk_bytes, msg, &mut buf)
                .expect("ed25519 sign");
        });
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            ed_verifier
                .verify(&ed_pk, msg, &ed_sig)
                .expect("ed25519 verify");
        });
    });

    group.finish();
}

// ── ECDSA P-256 ───────────────────────────────────────────────────────────────

fn bench_ecdsa_p256(c: &mut Criterion) {
    let mut rng = make_rng();
    let msg = b"oxicrypto benchmark message -- ECDSA P-256";

    let (p256_sk, p256_pk) = ecdsa_p256_generate_keypair(&mut rng).expect("p256 keygen");
    let p256_signer = signer_impl(SigAlgo::EcdsaP256);
    let p256_verifier = verifier_impl(SigAlgo::EcdsaP256);

    // DER signature is variable length (≤72 bytes).
    let mut p256_sig_buf = [0u8; 72];
    let p256_sk_bytes = p256_sk.as_bytes().to_vec();
    let sig_len = p256_signer
        .sign(&p256_sk_bytes, msg, &mut p256_sig_buf)
        .expect("p256 pre-sign failed");
    let p256_sig = p256_sig_buf[..sig_len].to_vec();

    let mut group = c.benchmark_group("sig/ECDSA-P256");

    group.bench_function("keygen", |b| {
        b.iter(|| {
            ecdsa_p256_generate_keypair(&mut rng).expect("p256 keygen");
        });
    });

    group.bench_function("sign", |b| {
        let mut buf = [0u8; 72];
        b.iter(|| {
            p256_signer
                .sign(&p256_sk_bytes, msg, &mut buf)
                .expect("p256 sign");
        });
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            p256_verifier
                .verify(&p256_pk, msg, &p256_sig)
                .expect("p256 verify");
        });
    });

    group.finish();
}

// ── ECDSA P-384 ───────────────────────────────────────────────────────────────

fn bench_ecdsa_p384(c: &mut Criterion) {
    let mut rng = make_rng();
    let msg = b"oxicrypto benchmark message -- ECDSA P-384";

    let (p384_sk, p384_pk) = ecdsa_p384_generate_keypair(&mut rng).expect("p384 keygen");
    let p384_signer = signer_impl(SigAlgo::EcdsaP384);
    let p384_verifier = verifier_impl(SigAlgo::EcdsaP384);

    // DER signature for P-384 is ≤104 bytes.
    let mut p384_sig_buf = [0u8; 104];
    let p384_sk_bytes = p384_sk.as_bytes().to_vec();
    let sig_len = p384_signer
        .sign(&p384_sk_bytes, msg, &mut p384_sig_buf)
        .expect("p384 pre-sign failed");
    let p384_sig = p384_sig_buf[..sig_len].to_vec();

    let mut group = c.benchmark_group("sig/ECDSA-P384");

    group.bench_function("keygen", |b| {
        b.iter(|| {
            ecdsa_p384_generate_keypair(&mut rng).expect("p384 keygen");
        });
    });

    group.bench_function("sign", |b| {
        let mut buf = [0u8; 104];
        b.iter(|| {
            p384_signer
                .sign(&p384_sk_bytes, msg, &mut buf)
                .expect("p384 sign");
        });
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            p384_verifier
                .verify(&p384_pk, msg, &p384_sig)
                .expect("p384 verify");
        });
    });

    group.finish();
}

// ── ECDSA P-521 ───────────────────────────────────────────────────────────────

fn bench_ecdsa_p521(c: &mut Criterion) {
    let mut rng = make_rng();
    let msg = b"oxicrypto benchmark message -- ECDSA P-521";

    let (p521_sk, p521_pk) = ecdsa_p521_generate_keypair(&mut rng).expect("p521 keygen");
    let p521_signer = signer_impl(SigAlgo::EcdsaP521);
    let p521_verifier = verifier_impl(SigAlgo::EcdsaP521);

    // DER signature for P-521 is ≤139 bytes.
    let mut p521_sig_buf = [0u8; 139];
    let p521_sk_bytes = p521_sk.as_bytes().to_vec();
    let sig_len = p521_signer
        .sign(&p521_sk_bytes, msg, &mut p521_sig_buf)
        .expect("p521 pre-sign failed");
    let p521_sig = p521_sig_buf[..sig_len].to_vec();

    let mut group = c.benchmark_group("sig/ECDSA-P521");

    group.bench_function("keygen", |b| {
        b.iter(|| {
            ecdsa_p521_generate_keypair(&mut rng).expect("p521 keygen");
        });
    });

    group.bench_function("sign", |b| {
        let mut buf = [0u8; 139];
        b.iter(|| {
            p521_signer
                .sign(&p521_sk_bytes, msg, &mut buf)
                .expect("p521 sign");
        });
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            p521_verifier
                .verify(&p521_pk, msg, &p521_sig)
                .expect("p521 verify");
        });
    });

    group.finish();
}

// ── RSA-2048 PKCS#1v15 ────────────────────────────────────────────────────────

fn bench_rsa_pkcs1v15(c: &mut Criterion) {
    let msg = b"oxicrypto benchmark message -- RSA-2048 PKCS#1v15";

    // RSA key generation is expensive; generate once before the bench groups.
    // rsa_generate_keypair returns (PKCS#8-DER secret key, SPKI-DER public key).
    let (rsa_sk_der, rsa_pk_der) =
        rsa_generate_keypair(2048).expect("rsa-2048 keygen (bench setup)");

    let rsa_signer = signer_impl(SigAlgo::RsaPkcs1v15Sha256);
    let rsa_verifier = verifier_impl(SigAlgo::RsaPkcs1v15Sha256);

    // RSA-2048 signature is exactly 256 bytes.
    let mut rsa_sig_buf = [0u8; 512];
    let sig_len = rsa_signer
        .sign(&rsa_sk_der, msg, &mut rsa_sig_buf)
        .expect("rsa pre-sign failed");
    let rsa_sig = rsa_sig_buf[..sig_len].to_vec();

    let mut group = c.benchmark_group("sig/RSA-PKCS1v15-SHA256");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    // Keygen is too slow to measure in a tight loop; include as single-shot.
    group.bench_function("keygen-2048", |b| {
        b.iter(|| {
            rsa_generate_keypair(2048).expect("rsa-2048 keygen");
        });
    });

    group.bench_function("sign-2048", |b| {
        let mut buf = [0u8; 512];
        b.iter(|| {
            rsa_signer
                .sign(&rsa_sk_der, msg, &mut buf)
                .expect("rsa sign");
        });
    });

    group.bench_function("verify-2048", |b| {
        b.iter(|| {
            rsa_verifier
                .verify(&rsa_pk_der, msg, &rsa_sig)
                .expect("rsa verify");
        });
    });

    group.finish();
}

// ── Criterion wiring ──────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_ed25519,
    bench_ecdsa_p256,
    bench_ecdsa_p384,
    bench_ecdsa_p521,
    bench_rsa_pkcs1v15,
);
criterion_main!(benches);
