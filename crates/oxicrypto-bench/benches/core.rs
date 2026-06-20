//! Criterion benchmarks for `oxicrypto-core` primitives.
//!
//! Covers two orthogonal concerns:
//!
//! 1. **`ct_eq` overhead** — constant-time byte-slice equality via
//!    `subtle::ConstantTimeEq` compared against a naïve `==` comparison,
//!    measured at several sizes (16 B, 32 B, 64 B, 256 B, 4096 B).
//!    Both equal-inputs and unequal-inputs cases are benchmarked so the
//!    comparison is fair: naïve `==` may short-circuit on the first differing
//!    byte while `ct_eq` runs to completion regardless.
//!
//! 2. **`Zeroize` drop overhead on `SecretVec`** — measures the wall-time
//!    cost of zeroing the secret bytes on drop vs a plain `Vec<u8>` drop.
//!    This isolates the Zeroize overhead from allocation cost by pre-allocating
//!    both vecs outside the measured loop.
//!
//! Run:
//! ```bash
//! cargo bench -p oxicrypto-bench --bench core
//! ```

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxicrypto_core::{ct_eq, SecretVec};

// ── Quick-mode helper ─────────────────────────────────────────────────────────

fn apply_quick_mode(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    if std::env::var("BENCH_QUICK").as_deref() == Ok("1") {
        group.sample_size(10);
    }
}

// ── Bench 1: ct_eq overhead ───────────────────────────────────────────────────

/// Lengths to exercise: tag-sized (16), key-sized (32, 64), KDF-output (256),
/// and a larger block to show linear scaling (4096).
const CT_EQ_SIZES: &[usize] = &[16, 32, 64, 256, 4096];

/// Measure `ct_eq(a, b)` vs naïve `a == b` for **equal** byte slices.
///
/// Equal inputs are the interesting case for `ct_eq` — naïve `==` is fast for
/// equal slices (scan to end), so the overhead here shows the true constant-time
/// cost per byte.
fn bench_ct_eq_equal(c: &mut Criterion) {
    let mut group = c.benchmark_group("core/ct_eq/equal_inputs");
    apply_quick_mode(&mut group);

    for &size in CT_EQ_SIZES {
        group.throughput(Throughput::Bytes(size as u64));

        let a = vec![0x5A_u8; size];
        let b = vec![0x5A_u8; size];

        group.bench_with_input(BenchmarkId::new("ct_eq", size), &size, |bench, _| {
            bench.iter(|| {
                let _ = ct_eq(&a, &b);
            });
        });

        group.bench_with_input(BenchmarkId::new("naive_eq", size), &size, |bench, _| {
            bench.iter(|| {
                let _ = a == b;
            });
        });
    }

    group.finish();
}

/// Measure `ct_eq(a, b)` vs naïve `a == b` for **unequal** byte slices
/// (last byte differs).
///
/// For naïve `==` the last-byte-differs case is the worst case (scans the full
/// slice). This measures whether `ct_eq` has meaningful overhead vs worst-case
/// `==`.
fn bench_ct_eq_unequal(c: &mut Criterion) {
    let mut group = c.benchmark_group("core/ct_eq/unequal_inputs");
    apply_quick_mode(&mut group);

    for &size in CT_EQ_SIZES {
        group.throughput(Throughput::Bytes(size as u64));

        let a = vec![0x5A_u8; size];
        let mut b = vec![0x5A_u8; size];
        // Flip only the last byte — this is the worst case for naïve == (full scan).
        b[size - 1] ^= 0xFF;

        group.bench_with_input(BenchmarkId::new("ct_eq", size), &size, |bench, _| {
            bench.iter(|| {
                let _ = ct_eq(&a, &b);
            });
        });

        group.bench_with_input(BenchmarkId::new("naive_eq", size), &size, |bench, _| {
            bench.iter(|| {
                let _ = a == b;
            });
        });
    }

    group.finish();
}

// ── Bench 2: Zeroize drop overhead ───────────────────────────────────────────

/// Payload sizes for the Zeroize drop bench.
///
/// Chosen to span: small secrets (32 B / typical key), medium (256 B), large
/// (4 KiB / a buffer), and very large (64 KiB / for extrapolation).
const ZEROIZE_SIZES: &[usize] = &[32, 256, 4096, 65536];

/// Benchmark `SecretVec` drop (which zeroes the underlying buffer via
/// `Zeroize + ZeroizeOnDrop`) vs a plain `Vec<u8>` drop.
///
/// The measurement isolates the zeroize cost: both vectors are allocated
/// *outside* the timing loop (`iter_batched`), so allocation is not included.
///
/// `SmallInput` batch mode is used to amortise criterion's overhead while
/// keeping each iteration to a single allocation drop.
fn bench_secretvec_drop(c: &mut Criterion) {
    let mut group = c.benchmark_group("core/zeroize/secretvec_drop");
    apply_quick_mode(&mut group);

    for &size in ZEROIZE_SIZES {
        group.throughput(Throughput::Bytes(size as u64));

        // SecretVec drop (zeroes on drop)
        group.bench_with_input(BenchmarkId::new("SecretVec", size), &size, |bench, &sz| {
            bench.iter_batched(
                || SecretVec::new(vec![0x5A_u8; sz]),
                drop,
                criterion::BatchSize::SmallInput,
            );
        });

        // Plain Vec<u8> drop (no zeroing)
        group.bench_with_input(BenchmarkId::new("Vec", size), &size, |bench, &sz| {
            bench.iter_batched(|| vec![0x5A_u8; sz], drop, criterion::BatchSize::SmallInput);
        });
    }

    group.finish();
}

// ── Bench 3: ct_eq linear scaling verification ────────────────────────────────

/// Confirm that `ct_eq` scales linearly with input length (not faster, since a
/// faster-than-linear curve would indicate the comparison is short-circuiting
/// on some inputs, breaking the constant-time property).
///
/// This is a data-collection bench — post-process with `scripts/bench_ratios.py`
/// to verify the relationship.
fn bench_ct_eq_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("core/ct_eq/scaling");
    apply_quick_mode(&mut group);

    // Cover a decade of sizes: 16 → 16384 (1024x range)
    for &size in &[
        16usize, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384,
    ] {
        group.throughput(Throughput::Bytes(size as u64));
        let a = vec![0xAB_u8; size];
        let b = vec![0xAB_u8; size]; // always equal (worst-case for naive ==)
        group.bench_with_input(BenchmarkId::new("ct_eq", size), &size, |bench, _| {
            bench.iter(|| {
                let _ = ct_eq(&a, &b);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_ct_eq_equal,
    bench_ct_eq_unequal,
    bench_secretvec_drop,
    bench_ct_eq_scaling,
);
criterion_main!(benches);
