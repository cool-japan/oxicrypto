//! Criterion benchmarks: AEAD throughput for aws-lc-rs vs Pure-Rust oxicrypto-aead.
//!
//! Tests AES-128-GCM, AES-256-GCM, AES-256-GCM-SIV, and ChaCha20-Poly1305
//! at 1 KiB, 64 KiB, and 1 MiB payload sizes.
//!
//! Requires the `aws-lc` feature: `cargo bench -p oxicrypto-adapter-aws-lc
//!     --features aws-lc --bench aws_lc_aead`

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxicrypto_adapter_aws_lc::aead::AwsLcAead;
use oxicrypto_aead::Aes256Gcm;
use oxicrypto_core::Aead;

// ── Quick-mode helper ─────────────────────────────────────────────────────────

fn apply_quick_mode(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    if std::env::var("BENCH_QUICK").as_deref() == Ok("1") {
        group.sample_size(10);
    }
}

// ── AEAD throughput benchmarks ────────────────────────────────────────────────

/// Benchmark all four aws-lc-rs AEAD algorithms at standard payload sizes.
fn bench_aws_lc_aead_throughput(c: &mut Criterion) {
    let sizes: &[usize] = &[1024, 65536, 1024 * 1024];

    let variants: &[(&str, AwsLcAead)] = &[
        ("AES-128-GCM", AwsLcAead::aes128_gcm()),
        ("AES-256-GCM", AwsLcAead::aes256_gcm()),
        ("AES-256-GCM-SIV", AwsLcAead::aes256_gcm_siv()),
        ("ChaCha20-Poly1305", AwsLcAead::chacha20_poly1305()),
    ];

    for (algo_name, aead) in variants {
        let key = vec![0u8; aead.key_len()];
        let nonce = vec![0u8; aead.nonce_len()];
        let tag_len = aead.tag_len();

        let mut group = c.benchmark_group(format!("aws_lc_aead/{algo_name}"));
        apply_quick_mode(&mut group);

        for &sz in sizes {
            let pt = vec![0xABu8; sz];
            let mut ct = vec![0u8; sz + tag_len];
            group.throughput(Throughput::Bytes(sz as u64));
            group.bench_with_input(BenchmarkId::from_parameter(sz), &sz, |b, _| {
                b.iter(|| {
                    aead.seal(&key, &nonce, b"", &pt, &mut ct)
                        .expect("aws-lc seal");
                });
            });
        }
        group.finish();
    }
}

/// Head-to-head: aws-lc-rs AES-256-GCM vs Pure-Rust oxicrypto-aead AES-256-GCM
/// at 1 KiB, 64 KiB, and 1 MiB.
///
/// This gives a direct comparison of the FIPS-validated C implementation
/// against the pure-Rust implementation for the same algorithm.
fn bench_aws_lc_vs_pure_rust_aes256gcm(c: &mut Criterion) {
    let sizes: &[usize] = &[1024, 65536, 1024 * 1024];

    let aws_lc_aead = AwsLcAead::aes256_gcm();
    let pure_rust_aead = Aes256Gcm;

    let aws_key = vec![0u8; aws_lc_aead.key_len()]; // 32 bytes
    let aws_nonce = vec![0u8; aws_lc_aead.nonce_len()]; // 12 bytes
    let pure_key = vec![0u8; pure_rust_aead.key_len()];
    let pure_nonce = vec![0u8; pure_rust_aead.nonce_len()];

    for &sz in sizes {
        let pt = vec![0xBBu8; sz];
        let mut group = c.benchmark_group(format!("aws_lc_vs_pure_rust/AES-256-GCM/{sz}"));
        apply_quick_mode(&mut group);
        group.throughput(Throughput::Bytes(sz as u64));

        // aws-lc-rs implementation
        {
            let pt_clone = pt.clone();
            let mut ct = vec![0u8; sz + aws_lc_aead.tag_len()];
            group.bench_function("aws-lc-rs", |b| {
                b.iter(|| {
                    aws_lc_aead
                        .seal(&aws_key, &aws_nonce, b"", &pt_clone, &mut ct)
                        .expect("aws-lc seal");
                });
            });
        }

        // Pure-Rust oxicrypto-aead implementation
        {
            let pt_clone = pt.clone();
            let mut ct = vec![0u8; sz + pure_rust_aead.tag_len()];
            group.bench_function("pure-rust", |b| {
                b.iter(|| {
                    pure_rust_aead
                        .seal(&pure_key, &pure_nonce, b"", &pt_clone, &mut ct)
                        .expect("pure-rust seal");
                });
            });
        }

        group.finish();
    }
}

/// aws-lc-rs AEAD open (decrypt+verify) throughput at standard sizes.
fn bench_aws_lc_aead_open_throughput(c: &mut Criterion) {
    let sizes: &[usize] = &[1024, 65536, 1024 * 1024];
    let aead = AwsLcAead::aes256_gcm();
    let key = vec![0u8; aead.key_len()];
    let nonce = vec![0u8; aead.nonce_len()];

    let mut group = c.benchmark_group("aws_lc_aead/AES-256-GCM/open");
    apply_quick_mode(&mut group);

    for &sz in sizes {
        let pt = vec![0xCCu8; sz];
        let mut ct = vec![0u8; sz + aead.tag_len()];
        aead.seal(&key, &nonce, b"", &pt, &mut ct)
            .expect("setup: seal");

        let mut pt_out = vec![0u8; sz];
        group.throughput(Throughput::Bytes(sz as u64));
        group.bench_with_input(BenchmarkId::from_parameter(sz), &sz, |b, _| {
            b.iter(|| {
                aead.open(&key, &nonce, b"", &ct, &mut pt_out)
                    .expect("aws-lc open");
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_aws_lc_aead_throughput,
    bench_aws_lc_vs_pure_rust_aes256gcm,
    bench_aws_lc_aead_open_throughput,
);
criterion_main!(benches);
