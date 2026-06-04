//! Hash benchmarks: SHA-2, SHA-3, BLAKE3, streaming vs one-shot, keyed, SHAKE.
//!
//! Groups:
//!  - `hash/<algo>/<bytes>` — one-shot throughput for 64 B, 1 KiB, 4 KiB, 64 KiB, 1 MiB.
//!  - `hash_streaming/<algo>/<bytes>` — streaming throughput (64 KB write chunks).
//!  - `hash_streaming_vs_oneshot/<algo>` — ratio helper at 4 KiB.
//!  - `blake3_keyed/<bytes>` — BLAKE3 keyed-hash throughput.
//!  - `blake3_parallel_vs_sequential/<bytes>` — BLAKE3 rayon parallel vs serial.
//!  - `hash_vs_ring/<algo>/<bytes>` — OxiCrypto SHA-256/SHA-512 throughput vs `ring`.
//!  - `shake_xof/<variant>/<out_len>` — SHAKE XOF generation for 32/64/128/256-byte output.
//!
//! Results are reported in MiB/s via Criterion's `Throughput::Bytes` mode.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxicrypto::{hash_impl, HashAlgo, StreamingHash};
use oxicrypto_hash::{
    blake3_keyed_hash, shake128, shake256, Blake3Streaming, Sha256Streaming, Sha512Streaming,
};
use oxicrypto_rand::OxiRng;

// ── Quick-mode helper ─────────────────────────────────────────────────────────

fn apply_quick_mode(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    if std::env::var("BENCH_QUICK").as_deref() == Ok("1") {
        group.sample_size(10);
    }
}

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

// ── One-shot hash benchmarks ──────────────────────────────────────────────────

fn bench_hash(c: &mut Criterion) {
    let mut rng = make_rng();
    // Input sizes: 64 B (small/auth token), 1 KiB, 4 KiB, 64 KiB, 1 MiB.
    let sizes: &[usize] = &[64, 1024, 4096, 65536, 1_048_576];

    let algos = [
        HashAlgo::Sha256,
        HashAlgo::Sha384,
        HashAlgo::Sha512,
        HashAlgo::Sha512_256,
        HashAlgo::Sha3_256,
        HashAlgo::Sha3_384,
        HashAlgo::Sha3_512,
        HashAlgo::Blake2b256,
        HashAlgo::Blake2b512,
        HashAlgo::Blake2s256,
        HashAlgo::Blake3,
    ];

    for algo in algos {
        let name = format!("{algo}");
        let h = hash_impl(algo);
        let mut out = vec![0u8; h.output_len()];
        let mut group = c.benchmark_group(format!("hash/{name}"));
        apply_quick_mode(&mut group);

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

// ── Streaming hash benchmarks (SHA-256, SHA-512, BLAKE3) ─────────────────────
//
// Each benchmark feeds the input in 64 KiB chunks via the streaming API so
// that large inputs exercise the streaming path identically to how a real
// application would use it (e.g. hashing a file in blocks).

fn bench_streaming_sha256(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[1024, 4096, 65536, 1_048_576];
    let chunk = 65536; // 64 KiB write chunk

    let mut group = c.benchmark_group("hash_streaming/SHA-256");
    apply_quick_mode(&mut group);
    for &sz in sizes {
        let data = random_bytes(&mut rng, sz);
        group.throughput(Throughput::Bytes(sz as u64));
        group.bench_with_input(BenchmarkId::from_parameter(sz), &data, |b, data| {
            b.iter(|| {
                let mut h = Sha256Streaming::new();
                for block in data.chunks(chunk) {
                    h.update(block);
                }
                let mut out = [0u8; 32];
                h.finalize(&mut out).expect("finalize");
                out
            });
        });
    }
    group.finish();
}

fn bench_streaming_sha512(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[1024, 4096, 65536, 1_048_576];
    let chunk = 65536;

    let mut group = c.benchmark_group("hash_streaming/SHA-512");
    apply_quick_mode(&mut group);
    for &sz in sizes {
        let data = random_bytes(&mut rng, sz);
        group.throughput(Throughput::Bytes(sz as u64));
        group.bench_with_input(BenchmarkId::from_parameter(sz), &data, |b, data| {
            b.iter(|| {
                let mut h = Sha512Streaming::new();
                for block in data.chunks(chunk) {
                    h.update(block);
                }
                let mut out = [0u8; 64];
                h.finalize(&mut out).expect("finalize");
                out
            });
        });
    }
    group.finish();
}

fn bench_streaming_blake3(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[1024, 4096, 65536, 1_048_576];
    let chunk = 65536;

    let mut group = c.benchmark_group("hash_streaming/BLAKE3");
    for &sz in sizes {
        let data = random_bytes(&mut rng, sz);
        group.throughput(Throughput::Bytes(sz as u64));
        group.bench_with_input(BenchmarkId::from_parameter(sz), &data, |b, data| {
            b.iter(|| {
                let mut h = Blake3Streaming::new();
                for block in data.chunks(chunk) {
                    h.update(block);
                }
                let mut out = [0u8; 32];
                h.finalize(&mut out).expect("finalize");
                out
            });
        });
    }
    group.finish();
}

// ── BLAKE3 keyed-hash benchmarks ──────────────────────────────────────────────
//
// BLAKE3 keyed-hash is MAC-like (HMAC replacement candidate).  These benchmarks
// measure throughput at input sizes matching the HMAC-SHA-256 bench for apples-
// to-apples comparison.

fn bench_blake3_keyed(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[64, 1024, 4096, 65536, 1_048_576];
    let key = [0x42u8; 32]; // fixed bench key (not a secret)

    let mut group = c.benchmark_group("blake3_keyed");
    for &sz in sizes {
        let data = random_bytes(&mut rng, sz);
        group.throughput(Throughput::Bytes(sz as u64));
        group.bench_with_input(BenchmarkId::from_parameter(sz), &data, |b, data| {
            b.iter(|| blake3_keyed_hash(&key, data));
        });
    }
    group.finish();
}

// ── SHAKE XOF output-generation benchmarks ───────────────────────────────────
//
// These benchmarks isolate the XOF output-generation phase: a fixed 32-byte
// input is absorbed once, then varying lengths of output are squeezed.

fn bench_shake128_xof(c: &mut Criterion) {
    let msg = b"benchmark input for SHAKE128 XOF generation";
    let out_lens: &[usize] = &[32, 64, 128, 256];

    let mut group = c.benchmark_group("shake_xof/SHAKE128");
    for &out_len in out_lens {
        let mut out = vec![0u8; out_len];
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(out_len),
            &out_len,
            |b, &_out_len| {
                b.iter(|| {
                    shake128(msg, &mut out);
                });
            },
        );
    }
    group.finish();
}

fn bench_shake256_xof(c: &mut Criterion) {
    let msg = b"benchmark input for SHAKE256 XOF generation";
    let out_lens: &[usize] = &[32, 64, 128, 256];

    let mut group = c.benchmark_group("shake_xof/SHAKE256");
    for &out_len in out_lens {
        let mut out = vec![0u8; out_len];
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(out_len),
            &out_len,
            |b, &_out_len| {
                b.iter(|| {
                    shake256(msg, &mut out);
                });
            },
        );
    }
    group.finish();
}

// ── BLAKE3 parallel vs sequential ────────────────────────────────────────────
//
// BLAKE3 supports true data-parallel tree hashing via its `rayon` feature,
// using Rayon's work-stealing thread pool to compress sub-trees concurrently.
// These benchmarks compare `Hasher::update` (serial) against
// `Hasher::update_rayon` (parallel) for large inputs where parallelism pays.

fn bench_blake3_parallel_vs_sequential(c: &mut Criterion) {
    let mut rng = make_rng();
    // Parallelism only benefits large inputs; measure 256 KiB, 1 MiB, 4 MiB.
    let sizes: &[usize] = &[262_144, 1_048_576, 4_194_304];

    let mut group = c.benchmark_group("blake3_parallel_vs_sequential");
    apply_quick_mode(&mut group);

    for &sz in sizes {
        let data = random_bytes(&mut rng, sz);
        group.throughput(Throughput::Bytes(sz as u64));

        // Serial path (no rayon).
        group.bench_with_input(BenchmarkId::new("serial", sz), &data, |b, data| {
            b.iter(|| {
                let mut h = blake3::Hasher::new();
                h.update(data);
                h.finalize()
            });
        });

        // Parallel path via blake3's Rayon integration.
        group.bench_with_input(BenchmarkId::new("parallel-rayon", sz), &data, |b, data| {
            b.iter(|| {
                let mut h = blake3::Hasher::new();
                h.update_rayon(data);
                h.finalize()
            });
        });
    }

    group.finish();
}

// ── OxiCrypto hash vs ring (SHA-256 / SHA-512) ────────────────────────────────
//
// `ring` uses platform-optimised SIMD/SHA-NI intrinsics where available.
// These benchmarks measure OxiCrypto (RustCrypto sha2 crate) alongside
// `ring::digest` for the same algorithm, letting users quantify any
// throughput gap on their hardware.

fn bench_hash_vs_ring(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[64, 1024, 4096, 65536, 1_048_576];

    // SHA-256 comparison.
    {
        let h_oxi = hash_impl(HashAlgo::Sha256);
        let mut out_oxi = vec![0u8; 32];
        let mut group = c.benchmark_group("hash_vs_ring/SHA-256");
        apply_quick_mode(&mut group);
        for &sz in sizes {
            let data = random_bytes(&mut rng, sz);
            group.throughput(Throughput::Bytes(sz as u64));

            group.bench_with_input(BenchmarkId::new("oxicrypto", sz), &data, |b, data| {
                b.iter(|| {
                    h_oxi.hash(data, &mut out_oxi).expect("sha256 hash");
                });
            });

            group.bench_with_input(BenchmarkId::new("ring", sz), &data, |b, data| {
                b.iter(|| {
                    ring::digest::digest(&ring::digest::SHA256, data);
                });
            });
        }
        group.finish();
    }

    // SHA-512 comparison.
    {
        let h_oxi = hash_impl(HashAlgo::Sha512);
        let mut out_oxi = vec![0u8; 64];
        let mut group = c.benchmark_group("hash_vs_ring/SHA-512");
        apply_quick_mode(&mut group);
        for &sz in sizes {
            let data = random_bytes(&mut rng, sz);
            group.throughput(Throughput::Bytes(sz as u64));

            group.bench_with_input(BenchmarkId::new("oxicrypto", sz), &data, |b, data| {
                b.iter(|| {
                    h_oxi.hash(data, &mut out_oxi).expect("sha512 hash");
                });
            });

            group.bench_with_input(BenchmarkId::new("ring", sz), &data, |b, data| {
                b.iter(|| {
                    ring::digest::digest(&ring::digest::SHA512, data);
                });
            });
        }
        group.finish();
    }
}

// ── Criterion wiring ──────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_hash,
    bench_streaming_sha256,
    bench_streaming_sha512,
    bench_streaming_blake3,
    bench_blake3_keyed,
    bench_blake3_parallel_vs_sequential,
    bench_hash_vs_ring,
    bench_shake128_xof,
    bench_shake256_xof,
);
criterion_main!(benches);
