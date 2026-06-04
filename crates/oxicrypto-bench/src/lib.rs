// placeholder — required by Cargo for [lib] bench = false

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
