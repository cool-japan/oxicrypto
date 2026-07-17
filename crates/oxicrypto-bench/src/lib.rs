//! `oxicrypto-bench` — dev-only helpers for the OxiCrypto Criterion benchmark suite.
//!
//! This `[lib]` target exists solely to satisfy Cargo's requirement for a
//! library crate when `[lib] bench = false` is set; the real benchmarks are
//! the criterion harnesses under `benches/` that compare OxiCrypto against
//! `ring` and `aws-lc-rs`. `publish = false` — this crate is never published
//! to crates.io. The functions below are small `--quick`-mode helpers shared
//! by those benchmark binaries.

/// Apply optional `--quick` mode to a Criterion benchmark group.
///
/// When the environment variable `BENCH_QUICK=1` is set, the group's
/// sample size is reduced to 10 samples.  This is useful for CI smoke
/// testing where only compilation and basic execution correctness matter,
/// not statistical accuracy.
///
/// # Usage
///
/// ```rust,no_run
/// use criterion::Criterion;
/// use oxicrypto_bench::apply_quick_mode;
///
/// fn my_bench(c: &mut Criterion) {
///     let mut group = c.benchmark_group("my-group");
///     apply_quick_mode(&mut group);
///     // ... add bench functions ...
///     group.finish();
/// }
/// ```
pub fn apply_quick_mode(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
) {
    if std::env::var("BENCH_QUICK").as_deref() == Ok("1") {
        group.sample_size(10);
    }
}

/// Returns `true` when `BENCH_QUICK=1` is set.
///
/// Use this to skip expensive setup in quick mode.
pub fn is_quick_mode() -> bool {
    std::env::var("BENCH_QUICK").as_deref() == Ok("1")
}
