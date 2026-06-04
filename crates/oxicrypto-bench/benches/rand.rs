//! CSPRNG benchmarks: OxiRng fill throughput, variant comparison,
//! ReseedingRng overhead, random_range rejection sampling,
//! thread-local RNG initialization, and OS `/dev/urandom` comparison.
//!
//! Groups:
//!  - `rand_fill/<variant>/<bytes>` — fill() throughput for OxiRng, OxiRng8, OxiRng12.
//!  - `rand_fill_vs_urandom/<bytes>` — OxiRng vs OS getrandom direct reads.
//!  - `rand_reseeding/<threshold_kb>` — ReseedingRng overhead at various thresholds.
//!  - `rand_range/<algo>` — random_range rejection sampling vs simple modulo.
//!  - `rand_thread_rng` — thread-local RNG initialization (first call) and subsequent calls.
//!
//! All sizes reported in MiB/s via Criterion's `Throughput::Bytes` mode.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxicrypto_rand::{random_range, random_range_to, OxiRng, OxiRng12, OxiRng8, ReseedingRng};

use oxicrypto_core::Rng;

// ── OxiRng::fill() throughput ─────────────────────────────────────────────────

/// Benchmark OxiRng (ChaCha20) fill() throughput for common buffer sizes.
fn bench_oxi_rng_fill(c: &mut Criterion) {
    let mut group = c.benchmark_group("rand_fill/chacha20");
    let sizes: &[usize] = &[32, 1024, 65536, 1_048_576];

    for &size in sizes {
        let mut rng = OxiRng::new().expect("bench setup: OxiRng::new failed");
        let mut buf = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                rng.fill(&mut buf).expect("fill failed");
            });
        });
    }
    group.finish();
}

/// Benchmark OxiRng8 (ChaCha8) fill() throughput.
fn bench_oxi_rng8_fill(c: &mut Criterion) {
    let mut group = c.benchmark_group("rand_fill/chacha8");
    let sizes: &[usize] = &[32, 1024, 65536, 1_048_576];

    for &size in sizes {
        let mut rng = OxiRng8::new().expect("bench setup: OxiRng8::new failed");
        let mut buf = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                rng.fill(&mut buf).expect("fill failed");
            });
        });
    }
    group.finish();
}

/// Benchmark OxiRng12 (ChaCha12) fill() throughput.
fn bench_oxi_rng12_fill(c: &mut Criterion) {
    let mut group = c.benchmark_group("rand_fill/chacha12");
    let sizes: &[usize] = &[32, 1024, 65536, 1_048_576];

    for &size in sizes {
        let mut rng = OxiRng12::new().expect("bench setup: OxiRng12::new failed");
        let mut buf = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                rng.fill(&mut buf).expect("fill failed");
            });
        });
    }
    group.finish();
}

// ── OxiRng vs OS getrandom direct reads ──────────────────────────────────────

/// Compare OxiRng::fill() throughput against direct getrandom OS reads.
///
/// OxiRng expands a 32-byte seed using ChaCha20 in software; getrandom makes
/// a syscall for each invocation.  For large buffers, ChaCha20 is expected to
/// be substantially faster.
fn bench_rand_vs_getrandom(c: &mut Criterion) {
    let mut group = c.benchmark_group("rand_fill_vs_urandom");
    let sizes: &[usize] = &[32, 1024, 65536, 1_048_576];

    for &size in sizes {
        let mut oxi_rng = OxiRng::new().expect("bench setup: OxiRng::new failed");
        let mut buf = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        // OxiRng::fill (ChaCha20 in-process expansion)
        group.bench_with_input(BenchmarkId::new("oxirng_chacha20", size), &size, |b, _| {
            b.iter(|| {
                oxi_rng.fill(&mut buf).expect("fill failed");
            });
        });

        // getrandom::fill (direct OS entropy read — syscall per call)
        group.bench_with_input(BenchmarkId::new("getrandom_direct", size), &size, |b, _| {
            b.iter(|| {
                getrandom::fill(&mut buf).expect("getrandom failed");
            });
        });
    }
    group.finish();
}

// ── ReseedingRng overhead at various thresholds ───────────────────────────────

/// Benchmark ReseedingRng at different reseed thresholds.
///
/// A smaller threshold reseeds more frequently (higher overhead); a larger
/// threshold approaches bare OxiRng performance.  The benchmark generates 64 KiB
/// per iteration to include at least one reseed event at the smaller thresholds.
fn bench_reseeding_rng(c: &mut Criterion) {
    let mut group = c.benchmark_group("rand_reseeding");

    // Thresholds in KiB: 4 KiB (very frequent), 64 KiB (one reseed per iter),
    // 1 MiB (default, no reseed), baseline (plain OxiRng).
    let fill_size: usize = 65536; // 64 KiB per iteration
    let thresholds_kb: &[u64] = &[4, 64, 1024];

    group.throughput(Throughput::Bytes(fill_size as u64));

    // Baseline: plain OxiRng with no reseeding overhead.
    {
        let mut rng = OxiRng::new().expect("bench setup: OxiRng::new failed");
        let mut buf = vec![0u8; fill_size];
        group.bench_function("baseline_oxirng", |b| {
            b.iter(|| {
                rng.fill(&mut buf).expect("fill failed");
            });
        });
    }

    for &threshold_kb in thresholds_kb {
        let threshold_bytes = threshold_kb * 1024;
        let mut rng = ReseedingRng::with_threshold(threshold_bytes)
            .expect("bench setup: ReseedingRng::with_threshold failed");
        let mut buf = vec![0u8; fill_size];
        group.bench_with_input(
            BenchmarkId::new("reseeding_threshold_kb", threshold_kb),
            &threshold_kb,
            |b, _| {
                b.iter(|| {
                    rng.fill(&mut buf).expect("fill failed");
                });
            },
        );
    }
    group.finish();
}

// ── random_range: rejection sampling vs simple modulo ────────────────────────

/// Compare random_range() (rejection sampling, no modulo bias) against a
/// naive modulo operation on a fresh random u64.
///
/// Rejection sampling has a small overhead when range is not a power of two,
/// but eliminates modulo bias.  This benchmark quantifies that cost.
fn bench_random_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("rand_range");

    // Small power-of-2 range: rejection sampling almost never rejects.
    group.bench_function("rejection_sampling_256", |b| {
        b.iter(|| {
            random_range(0, 256).expect("random_range failed");
        });
    });

    // Non-power-of-2 range: rejection sampling has non-trivial rejection rate.
    group.bench_function("rejection_sampling_300", |b| {
        b.iter(|| {
            random_range(0, 300).expect("random_range failed");
        });
    });

    // Large range covering most of u64: almost no rejections.
    group.bench_function("rejection_sampling_large", |b| {
        b.iter(|| {
            random_range(0, u64::MAX - 1).expect("random_range failed");
        });
    });

    // random_range_to (single-arg form): same algorithm, different entry point.
    group.bench_function("rejection_sampling_range_to_256", |b| {
        b.iter(|| {
            random_range_to(256).expect("random_range_to failed");
        });
    });

    // Naive modulo (comparison baseline — NOT cryptographically unbiased).
    {
        let mut rng = OxiRng::new().expect("bench setup: OxiRng::new failed");
        let mut raw_buf = [0u8; 8];
        group.bench_function("naive_modulo_256", |b| {
            b.iter(|| {
                rng.fill(&mut raw_buf).expect("fill failed");
                let v = u64::from_le_bytes(raw_buf);
                // INTENTIONALLY BIASED — for timing comparison only, not for production use.
                std::hint::black_box(v % 256)
            });
        });
    }
    group.finish();
}

// ── Thread-local RNG ──────────────────────────────────────────────────────────

/// Benchmark thread-local RNG via `with_thread_rng`.
///
/// The first call per thread initializes the RNG (one getrandom call); subsequent
/// calls reuse the cached instance.  Both paths are benchmarked separately by
/// checking whether the thread-local has already been seeded.
fn bench_thread_rng(c: &mut Criterion) {
    use oxicrypto_rand::with_thread_rng;

    let mut group = c.benchmark_group("rand_thread_rng");

    // Warm the thread-local on this thread first so subsequent calls measure
    // only the lookup + fill overhead, not the initialization.
    {
        let mut warmup_buf = [0u8; 32];
        with_thread_rng(|rng| rng.fill(&mut warmup_buf)).expect("warmup failed");
    }

    // Subsequent call: thread-local already initialized.
    {
        let mut buf = [0u8; 32];
        group.throughput(Throughput::Bytes(32));
        group.bench_function("subsequent_call_32b", |b| {
            b.iter(|| {
                with_thread_rng(|rng| rng.fill(&mut buf)).expect("with_thread_rng failed");
            });
        });
    }

    // Larger fill via thread-local.
    {
        let mut buf = vec![0u8; 1024];
        group.throughput(Throughput::Bytes(1024));
        group.bench_function("subsequent_call_1kib", |b| {
            b.iter(|| {
                with_thread_rng(|rng| rng.fill(&mut buf)).expect("with_thread_rng failed");
            });
        });
    }

    group.finish();
}

// ── Criterion registration ─────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_oxi_rng_fill,
    bench_oxi_rng8_fill,
    bench_oxi_rng12_fill,
    bench_rand_vs_getrandom,
    bench_reseeding_rng,
    bench_random_range,
    bench_thread_rng,
);

criterion_main!(benches);
