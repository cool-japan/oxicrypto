//! Criterion benchmarks: signature sign + verify latency for aws-lc-rs adapters.
//!
//! Tests Ed25519 sign/verify latency and ECDSA P-256 sign/verify latency,
//! compared against the Pure-Rust oxicrypto-sig implementations.
//!
//! Requires the `aws-lc` feature: `cargo bench -p oxicrypto-adapter-aws-lc
//!     --features aws-lc --bench aws_lc_sig`

use criterion::{criterion_group, criterion_main, Criterion};
use oxicrypto_adapter_aws_lc::sign::{
    AwsLcEcdsaP256Signer, AwsLcEcdsaP256Verifier, AwsLcEd25519Signer, AwsLcEd25519Verifier,
};
use oxicrypto_core::{Signer, Verifier};
use oxicrypto_sig::{EcdsaP256Signer, EcdsaP256Verifier, Ed25519, Ed25519Verifier};

// ── Quick-mode helper ─────────────────────────────────────────────────────────

fn apply_quick_mode(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    if std::env::var("BENCH_QUICK").as_deref() == Ok("1") {
        group.sample_size(10);
    }
}

// ── Shared test key material ──────────────────────────────────────────────────

/// RFC 8032 §6.1 test seed (32 bytes) and the corresponding public key (32 bytes).
const ED25519_SEED: &[u8] = &[
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x3d, 0x55,
];
const ED25519_PK: &[u8] = &[
    0x70, 0x0e, 0x2c, 0xe7, 0xc4, 0xb6, 0x74, 0x42, 0x7e, 0xab, 0x27, 0xba, 0x82, 0x0b, 0xcf, 0x6f,
    0x0f, 0xae, 0xbe, 0x68, 0xe0, 0x9f, 0xe8, 0x56, 0x42, 0x92, 0x11, 0x4e, 0x41, 0xdc, 0x6a, 0x41,
];

/// ECDSA P-256 scalar (32 bytes, same key used in kat_ecdsa_wycheproof.rs).
const ECDSA_P256_SK: &[u8; 32] = &[
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93,
    0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21,
];

// ── Ed25519 benchmarks ────────────────────────────────────────────────────────

/// Head-to-head: aws-lc-rs Ed25519 sign latency vs Pure-Rust oxicrypto-sig.
fn bench_ed25519_sign(c: &mut Criterion) {
    let msg = b"benchmark: Ed25519 sign latency comparison";
    let mut group = c.benchmark_group("aws_lc_sig/Ed25519/sign");
    apply_quick_mode(&mut group);

    // aws-lc-rs
    group.bench_function("aws-lc-rs", |b| {
        let signer = AwsLcEd25519Signer;
        let mut sig_out = [0u8; 64];
        b.iter(|| {
            signer
                .sign(ED25519_SEED, msg, &mut sig_out)
                .expect("aws-lc Ed25519 sign");
        });
    });

    // Pure-Rust (trait dispatch)
    group.bench_function("pure-rust", |b| {
        let signer = Ed25519;
        let mut sig_out = [0u8; 64];
        b.iter(|| {
            signer
                .sign(ED25519_SEED, msg, &mut sig_out)
                .expect("pure-rust Ed25519 sign");
        });
    });

    group.finish();
}

/// Head-to-head: aws-lc-rs Ed25519 verify latency vs Pure-Rust oxicrypto-sig.
fn bench_ed25519_verify(c: &mut Criterion) {
    // Pre-compute a valid signature.
    let msg = b"benchmark: Ed25519 verify latency comparison";
    let aws_signer = AwsLcEd25519Signer;
    let mut sig_bytes = [0u8; 64];
    aws_signer
        .sign(ED25519_SEED, msg, &mut sig_bytes)
        .expect("setup sign");

    let mut group = c.benchmark_group("aws_lc_sig/Ed25519/verify");
    apply_quick_mode(&mut group);

    // aws-lc-rs verify
    group.bench_function("aws-lc-rs", |b| {
        let verifier = AwsLcEd25519Verifier;
        b.iter(|| {
            verifier
                .verify(ED25519_PK, msg, &sig_bytes)
                .expect("aws-lc verify");
        });
    });

    // Pure-Rust verify
    group.bench_function("pure-rust", |b| {
        let verifier = Ed25519Verifier;
        b.iter(|| {
            verifier
                .verify(ED25519_PK, msg, &sig_bytes)
                .expect("pure-rust verify");
        });
    });

    group.finish();
}

// ── ECDSA P-256 benchmarks ────────────────────────────────────────────────────

/// Head-to-head: aws-lc-rs ECDSA P-256 sign latency vs Pure-Rust oxicrypto-sig.
///
/// Head-to-head: aws-lc-rs ECDSA P-256 sign latency vs Pure-Rust oxicrypto-sig.
///
/// The aws-lc-rs adapter's `AwsLcEcdsaP256Signer` takes a raw 32-byte scalar
/// as the secret key (same as the pure-rust implementation).
fn bench_ecdsa_p256_sign(c: &mut Criterion) {
    let msg = b"benchmark: ECDSA P-256 sign latency comparison";
    let mut group = c.benchmark_group("aws_lc_sig/ECDSA-P256/sign");
    apply_quick_mode(&mut group);

    // aws-lc-rs: uses same 32-byte scalar as pure-rust
    group.bench_function("aws-lc-rs", |b| {
        let signer = AwsLcEcdsaP256Signer;
        let mut sig_out = [0u8; 64];
        b.iter(|| {
            signer
                .sign(ECDSA_P256_SK, msg, &mut sig_out)
                .expect("aws-lc ECDSA sign");
        });
    });

    // Pure-Rust
    group.bench_function("pure-rust", |b| {
        let signer =
            EcdsaP256Signer::from_bytes(ECDSA_P256_SK).expect("pure-rust P-256 signer setup");
        b.iter(|| {
            signer.sign(msg).expect("pure-rust ECDSA sign");
        });
    });

    group.finish();
}

/// Head-to-head: aws-lc-rs ECDSA P-256 verify latency vs Pure-Rust oxicrypto-sig.
///
/// Both implementations are benchmarked on the same key material (same scalar).
/// The aws-lc-rs verifier takes the uncompressed SEC1 public key (65 bytes);
/// the pure-rust verifier accepts both compressed (33) and uncompressed (65).
fn bench_ecdsa_p256_verify(c: &mut Criterion) {
    let msg = b"benchmark: ECDSA P-256 verify latency comparison";

    // Use the same scalar for both paths to keep the comparison fair.
    let pure_signer =
        EcdsaP256Signer::from_bytes(ECDSA_P256_SK).expect("pure-rust P-256 signer setup");
    let pk_bytes = pure_signer.verifying_key_bytes(); // compressed SEC1 (33 bytes)

    // aws-lc-rs: sign with the scalar directly, verify with the SEC1 public key.
    let aws_signer = AwsLcEcdsaP256Signer;
    let mut aws_sig = [0u8; 64];
    aws_signer
        .sign(ECDSA_P256_SK, msg, &mut aws_sig)
        .expect("setup aws-lc sign");

    // pure-rust: sign and produce DER sig.
    let pure_sig = pure_signer.sign(msg).expect("pure-rust sign");

    let mut group = c.benchmark_group("aws_lc_sig/ECDSA-P256/verify");
    apply_quick_mode(&mut group);

    // aws-lc-rs verify (uncompressed SEC1, fixed format)
    {
        let pk = pk_bytes.clone();
        let sig = aws_sig;
        group.bench_function("aws-lc-rs", |b| {
            let verifier = AwsLcEcdsaP256Verifier;
            b.iter(|| {
                verifier.verify(&pk, msg, &sig).expect("aws-lc verify");
            });
        });
    }

    // Pure-Rust verify (DER)
    {
        let pk = pk_bytes.clone();
        let sig = pure_sig.clone();
        group.bench_function("pure-rust", |b| {
            let verifier = EcdsaP256Verifier::from_sec1_bytes(&pk).expect("P256 verifier setup");
            b.iter(|| {
                verifier.verify(msg, &sig).expect("pure-rust verify");
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_ecdsa_p256_sign,
    bench_ecdsa_p256_verify,
);
criterion_main!(benches);
