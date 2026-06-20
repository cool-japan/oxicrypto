//! Criterion benchmarks: hashing throughput for aws-lc-rs vs Pure-Rust oxicrypto-hash.
//!
//! Tests SHA-256, SHA-384, and SHA-512 at 1 KiB and 1 MiB payload sizes,
//! head-to-head against the Pure-Rust `oxicrypto-hash` implementations.
//!
//! Requires the `aws-lc` feature: `cargo bench -p oxicrypto-adapter-aws-lc
//!     --features aws-lc --bench aws_lc_hash`

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxicrypto_adapter_aws_lc::hash::{AwsLcSha256, AwsLcSha384, AwsLcSha512};
use oxicrypto_core::Hash;
use oxicrypto_hash::{Sha256, Sha384, Sha512};

// ── Quick-mode helper ─────────────────────────────────────────────────────────

fn apply_quick_mode(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    if std::env::var("BENCH_QUICK").as_deref() == Ok("1") {
        group.sample_size(10);
    }
}

// ── Hash throughput benchmarks ────────────────────────────────────────────────

/// Benchmark aws-lc-rs SHA-256/384/512 throughput at 1 KiB and 1 MiB.
fn bench_aws_lc_hash_throughput(c: &mut Criterion) {
    let sizes: &[usize] = &[1024, 1024 * 1024];

    // SHA-256
    {
        let hash = AwsLcSha256;
        let mut group = c.benchmark_group("aws_lc_hash/SHA-256");
        apply_quick_mode(&mut group);

        for &sz in sizes {
            let data = vec![0xAAu8; sz];
            group.throughput(Throughput::Bytes(sz as u64));
            group.bench_with_input(BenchmarkId::from_parameter(sz), &sz, |b, _| {
                b.iter(|| {
                    let mut out = [0u8; 32];
                    hash.hash(&data, &mut out).expect("aws-lc SHA-256");
                });
            });
        }
        group.finish();
    }

    // SHA-384
    {
        let hash = AwsLcSha384;
        let mut group = c.benchmark_group("aws_lc_hash/SHA-384");
        apply_quick_mode(&mut group);

        for &sz in sizes {
            let data = vec![0xBBu8; sz];
            group.throughput(Throughput::Bytes(sz as u64));
            group.bench_with_input(BenchmarkId::from_parameter(sz), &sz, |b, _| {
                b.iter(|| {
                    let mut out = [0u8; 48];
                    hash.hash(&data, &mut out).expect("aws-lc SHA-384");
                });
            });
        }
        group.finish();
    }

    // SHA-512
    {
        let hash = AwsLcSha512;
        let mut group = c.benchmark_group("aws_lc_hash/SHA-512");
        apply_quick_mode(&mut group);

        for &sz in sizes {
            let data = vec![0xCCu8; sz];
            group.throughput(Throughput::Bytes(sz as u64));
            group.bench_with_input(BenchmarkId::from_parameter(sz), &sz, |b, _| {
                b.iter(|| {
                    let mut out = [0u8; 64];
                    hash.hash(&data, &mut out).expect("aws-lc SHA-512");
                });
            });
        }
        group.finish();
    }
}

/// Head-to-head: aws-lc-rs SHA-256 vs Pure-Rust oxicrypto-hash SHA-256.
fn bench_aws_lc_vs_pure_rust_sha256(c: &mut Criterion) {
    let sizes: &[usize] = &[1024, 1024 * 1024];

    for &sz in sizes {
        let data = vec![0xDDu8; sz];
        let mut group = c.benchmark_group(format!("aws_lc_vs_pure_rust/SHA-256/{sz}"));
        apply_quick_mode(&mut group);
        group.throughput(Throughput::Bytes(sz as u64));

        group.bench_function("aws-lc-rs", |b| {
            let hash = AwsLcSha256;
            let mut out = [0u8; 32];
            let data_ref = &data;
            b.iter(|| {
                hash.hash(data_ref, &mut out).expect("aws-lc SHA-256");
            });
        });

        group.bench_function("pure-rust", |b| {
            let hash = Sha256;
            let mut out = [0u8; 32];
            let data_ref = &data;
            b.iter(|| {
                hash.hash(data_ref, &mut out).expect("pure-rust SHA-256");
            });
        });

        group.finish();
    }
}

/// Head-to-head: aws-lc-rs SHA-512 vs Pure-Rust oxicrypto-hash SHA-512.
fn bench_aws_lc_vs_pure_rust_sha512(c: &mut Criterion) {
    let sizes: &[usize] = &[1024, 1024 * 1024];

    for &sz in sizes {
        let data = vec![0xEEu8; sz];
        let mut group = c.benchmark_group(format!("aws_lc_vs_pure_rust/SHA-512/{sz}"));
        apply_quick_mode(&mut group);
        group.throughput(Throughput::Bytes(sz as u64));

        group.bench_function("aws-lc-rs", |b| {
            let hash = AwsLcSha512;
            let mut out = [0u8; 64];
            let data_ref = &data;
            b.iter(|| {
                hash.hash(data_ref, &mut out).expect("aws-lc SHA-512");
            });
        });

        group.bench_function("pure-rust", |b| {
            let hash = Sha512;
            let mut out = [0u8; 64];
            let data_ref = &data;
            b.iter(|| {
                hash.hash(data_ref, &mut out).expect("pure-rust SHA-512");
            });
        });

        group.finish();
    }
}

/// SHA-384 head-to-head: aws-lc-rs vs Pure-Rust.
fn bench_aws_lc_vs_pure_rust_sha384(c: &mut Criterion) {
    let sizes: &[usize] = &[1024, 1024 * 1024];

    for &sz in sizes {
        let data = vec![0xFFu8; sz];
        let mut group = c.benchmark_group(format!("aws_lc_vs_pure_rust/SHA-384/{sz}"));
        apply_quick_mode(&mut group);
        group.throughput(Throughput::Bytes(sz as u64));

        group.bench_function("aws-lc-rs", |b| {
            let hash = AwsLcSha384;
            let mut out = [0u8; 48];
            let data_ref = &data;
            b.iter(|| {
                hash.hash(data_ref, &mut out).expect("aws-lc SHA-384");
            });
        });

        group.bench_function("pure-rust", |b| {
            let hash = Sha384;
            let mut out = [0u8; 48];
            let data_ref = &data;
            b.iter(|| {
                hash.hash(data_ref, &mut out).expect("pure-rust SHA-384");
            });
        });

        group.finish();
    }
}

criterion_group!(
    benches,
    bench_aws_lc_hash_throughput,
    bench_aws_lc_vs_pure_rust_sha256,
    bench_aws_lc_vs_pure_rust_sha512,
    bench_aws_lc_vs_pure_rust_sha384,
);
criterion_main!(benches);
