//! MAC benchmarks: HMAC-SHA-256/384/512 and Poly1305.
//!
//! Measures MAC throughput for 64-byte, 1-KiB, and 64-KiB messages.
//! CMAC-AES-128/256 and KMAC128/256 are also included as oxicrypto-only variants.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxicrypto::{mac_impl, MacAlgo};
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

// ── MAC benchmarks ────────────────────────────────────────────────────────────

fn bench_hmac(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[64, 1024, 65536];

    let algos = [
        MacAlgo::HmacSha256,
        MacAlgo::HmacSha384,
        MacAlgo::HmacSha512,
    ];

    for algo in algos {
        let name = format!("{algo}");
        let m = mac_impl(algo);
        let key = random_bytes(&mut rng, 32);
        let mut out = vec![0u8; m.output_len()];
        let mut group = c.benchmark_group(format!("mac/{name}"));

        for &sz in sizes {
            let data = random_bytes(&mut rng, sz);
            group.throughput(Throughput::Bytes(sz as u64));
            group.bench_with_input(BenchmarkId::from_parameter(sz), &data, |b, data| {
                b.iter(|| {
                    m.mac(&key, data, &mut out).expect("mac failed");
                });
            });
        }
        group.finish();
    }
}

fn bench_hmac_sha3(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[64, 1024, 65536];

    let algos = [MacAlgo::HmacSha3_256, MacAlgo::HmacSha3_512];

    for algo in algos {
        let name = format!("{algo}");
        let m = mac_impl(algo);
        let key = random_bytes(&mut rng, 32);
        let mut out = vec![0u8; m.output_len()];
        let mut group = c.benchmark_group(format!("mac/{name}"));

        for &sz in sizes {
            let data = random_bytes(&mut rng, sz);
            group.throughput(Throughput::Bytes(sz as u64));
            group.bench_with_input(BenchmarkId::from_parameter(sz), &data, |b, data| {
                b.iter(|| {
                    m.mac(&key, data, &mut out).expect("hmac-sha3 failed");
                });
            });
        }
        group.finish();
    }
}

fn bench_poly1305(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[64, 1024, 65536];

    let m = mac_impl(MacAlgo::Poly1305);
    // Poly1305 key must be 32 bytes (one-time key; here we re-use for bench).
    let key = random_bytes(&mut rng, 32);
    let mut out = vec![0u8; m.output_len()];
    let mut group = c.benchmark_group("mac/Poly1305");

    for &sz in sizes {
        let data = random_bytes(&mut rng, sz);
        group.throughput(Throughput::Bytes(sz as u64));
        group.bench_with_input(BenchmarkId::from_parameter(sz), &data, |b, data| {
            b.iter(|| {
                m.mac(&key, data, &mut out).expect("poly1305 failed");
            });
        });
    }
    group.finish();
}

fn bench_cmac(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[64, 1024, 65536];

    // CMAC-AES-128: 16-byte key, CMAC-AES-256: 32-byte key.
    let algos_keys: &[(MacAlgo, usize)] = &[(MacAlgo::CmacAes128, 16), (MacAlgo::CmacAes256, 32)];

    for &(algo, key_len) in algos_keys {
        let name = format!("{algo}");
        let m = mac_impl(algo);
        let key = random_bytes(&mut rng, key_len);
        let mut out = vec![0u8; m.output_len()];
        let mut group = c.benchmark_group(format!("mac/{name}"));

        for &sz in sizes {
            let data = random_bytes(&mut rng, sz);
            group.throughput(Throughput::Bytes(sz as u64));
            group.bench_with_input(BenchmarkId::from_parameter(sz), &data, |b, data| {
                b.iter(|| {
                    m.mac(&key, data, &mut out).expect("cmac failed");
                });
            });
        }
        group.finish();
    }
}

fn bench_kmac(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[64, 1024, 65536];

    let algos: &[(MacAlgo, &str)] = &[
        (MacAlgo::Kmac128 { output_len: 32 }, "KMAC128/32"),
        (MacAlgo::Kmac256 { output_len: 32 }, "KMAC256/32"),
    ];

    for &(algo, label) in algos {
        let m = mac_impl(algo);
        let key = random_bytes(&mut rng, 32);
        let mut out = vec![0u8; m.output_len()];
        let mut group = c.benchmark_group(format!("mac/{label}"));

        for &sz in sizes {
            let data = random_bytes(&mut rng, sz);
            group.throughput(Throughput::Bytes(sz as u64));
            group.bench_with_input(BenchmarkId::from_parameter(sz), &data, |b, data| {
                b.iter(|| {
                    m.mac(&key, data, &mut out).expect("kmac failed");
                });
            });
        }
        group.finish();
    }
}

// ── Criterion wiring ──────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_hmac,
    bench_hmac_sha3,
    bench_poly1305,
    bench_cmac,
    bench_kmac
);
criterion_main!(benches);
