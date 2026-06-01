//! Hash benchmarks: SHA-2, SHA-3, and BLAKE3.
//!
//! Measures throughput of every hash variant for input sizes 64 B, 1 KiB,
//! 4 KiB, and 64 KiB.  Results are reported in MiB/s via Criterion's
//! `Throughput::Bytes` mode.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxicrypto::{hash_impl, HashAlgo};
use oxicrypto_rand::OxiRng;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_rng() -> OxiRng {
    OxiRng::new().expect("bench setup: OS RNG unavailable")
}

fn random_bytes(rng: &mut OxiRng, n: usize) -> Vec<u8> {
    use rand_core::TryRng;
    let mut buf = vec![0u8; n];
    rng.try_fill_bytes(&mut buf)
        .expect("bench setup: RNG fill failed");
    buf
}

// ── Hash benchmarks ───────────────────────────────────────────────────────────

fn bench_hash(c: &mut Criterion) {
    let mut rng = make_rng();
    // Input sizes: 64 B (small/auth token), 1 KiB, 4 KiB, 64 KiB.
    let sizes: &[usize] = &[64, 1024, 4096, 65536];

    let algos = [
        HashAlgo::Sha256,
        HashAlgo::Sha384,
        HashAlgo::Sha512,
        HashAlgo::Sha3_256,
        HashAlgo::Sha3_384,
        HashAlgo::Sha3_512,
        HashAlgo::Blake3,
    ];

    for algo in algos {
        let name = format!("{algo}");
        let h = hash_impl(algo);
        let mut out = vec![0u8; h.output_len()];
        let mut group = c.benchmark_group(format!("hash/{name}"));

        for &sz in sizes {
            let data = random_bytes(&mut rng, sz);
            group.throughput(Throughput::Bytes(sz as u64));
            group.bench_with_input(BenchmarkId::from_parameter(sz), &data, |b, data| {
                b.iter(|| {
                    h.hash(data, &mut out).expect("hash failed");
                });
            });
        }
        group.finish();
    }
}

// ── Criterion wiring ──────────────────────────────────────────────────────────

criterion_group!(benches, bench_hash);
criterion_main!(benches);
