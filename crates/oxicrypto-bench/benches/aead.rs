//! AEAD benchmarks: encryption throughput for all AEAD variants.
//!
//! Covers AES-GCM (128/256), ChaCha20-Poly1305, AES-GCM-SIV (128/256),
//! XChaCha20-Poly1305, AES-CCM (128/256), and AES-OCB3 (128/256).
//! Input sizes: 1 KiB, 64 KiB, and 1 MiB (large-payload scalability).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxicrypto::{aead_impl, AeadAlgo};
use oxicrypto_rand::OxiRng;

// ── Quick-mode helper ─────────────────────────────────────────────────────────
//
// When BENCH_QUICK=1 is set, reduce sample size to 10 for CI smoke testing.
// This keeps total bench time under a few seconds while still verifying that
// the benchmarks compile and execute without errors.

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

struct AeadFixture {
    key: Vec<u8>,
    nonce: Vec<u8>,
}

fn aead_fixture(rng: &mut OxiRng, algo: AeadAlgo) -> AeadFixture {
    let a = aead_impl(algo);
    AeadFixture {
        key: random_bytes(rng, a.key_len()),
        nonce: random_bytes(rng, a.nonce_len()),
    }
}

// ── AEAD seal benchmarks ──────────────────────────────────────────────────────

fn bench_aead_standard(c: &mut Criterion) {
    let mut rng = make_rng();
    // 1 KiB, 64 KiB, 1 MiB — exercises both cache-friendly and large-payload paths.
    let sizes: &[usize] = &[1024, 65536, 1024 * 1024];

    let algos = [
        AeadAlgo::Aes128Gcm,
        AeadAlgo::Aes256Gcm,
        AeadAlgo::ChaCha20Poly1305,
    ];

    for algo in algos {
        let name = format!("{algo}");
        let a = aead_impl(algo);
        let fix = aead_fixture(&mut rng, algo);
        let tag_len = a.tag_len();
        let mut group = c.benchmark_group(format!("aead/{name}"));
        apply_quick_mode(&mut group);

        for &sz in sizes {
            let pt = random_bytes(&mut rng, sz);
            let mut ct = vec![0u8; sz + tag_len];
            group.throughput(Throughput::Bytes(sz as u64));
            group.bench_with_input(BenchmarkId::from_parameter(sz), &pt, |b, pt| {
                b.iter(|| {
                    a.seal(&fix.key, &fix.nonce, b"", pt, &mut ct)
                        .expect("seal failed");
                });
            });
        }
        group.finish();
    }
}

fn bench_aead_siv(c: &mut Criterion) {
    let mut rng = make_rng();
    // GCM-SIV is misuse-resistant but slightly slower; benchmark at realistic sizes.
    let sizes: &[usize] = &[1024, 65536];

    let algos = [AeadAlgo::Aes128GcmSiv, AeadAlgo::Aes256GcmSiv];

    for algo in algos {
        let name = format!("{algo}");
        let a = aead_impl(algo);
        let fix = aead_fixture(&mut rng, algo);
        let tag_len = a.tag_len();
        let mut group = c.benchmark_group(format!("aead/{name}"));
        apply_quick_mode(&mut group);

        for &sz in sizes {
            let pt = random_bytes(&mut rng, sz);
            let mut ct = vec![0u8; sz + tag_len];
            group.throughput(Throughput::Bytes(sz as u64));
            group.bench_with_input(BenchmarkId::from_parameter(sz), &pt, |b, pt| {
                b.iter(|| {
                    a.seal(&fix.key, &fix.nonce, b"", pt, &mut ct)
                        .expect("seal failed");
                });
            });
        }
        group.finish();
    }
}

fn bench_aead_xchacha(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[1024, 65536, 1024 * 1024];

    let algo = AeadAlgo::XChaCha20Poly1305;
    let name = format!("{algo}");
    let a = aead_impl(algo);
    let fix = aead_fixture(&mut rng, algo);
    let tag_len = a.tag_len();
    let mut group = c.benchmark_group(format!("aead/{name}"));
    apply_quick_mode(&mut group);

    for &sz in sizes {
        let pt = random_bytes(&mut rng, sz);
        let mut ct = vec![0u8; sz + tag_len];
        group.throughput(Throughput::Bytes(sz as u64));
        group.bench_with_input(BenchmarkId::from_parameter(sz), &pt, |b, pt| {
            b.iter(|| {
                a.seal(&fix.key, &fix.nonce, b"", pt, &mut ct)
                    .expect("seal failed");
            });
        });
    }
    group.finish();
}

fn bench_aead_ccm(c: &mut Criterion) {
    let mut rng = make_rng();
    // CCM max payload is bounded by the tag/nonce combination; test at 1 KiB.
    let sizes: &[usize] = &[1024];

    let algos = [AeadAlgo::Aes128Ccm, AeadAlgo::Aes256Ccm];

    for algo in algos {
        let name = format!("{algo}");
        let a = aead_impl(algo);
        let fix = aead_fixture(&mut rng, algo);
        let tag_len = a.tag_len();
        let mut group = c.benchmark_group(format!("aead/{name}"));
        apply_quick_mode(&mut group);

        for &sz in sizes {
            let pt = random_bytes(&mut rng, sz);
            let mut ct = vec![0u8; sz + tag_len];
            group.throughput(Throughput::Bytes(sz as u64));
            group.bench_with_input(BenchmarkId::from_parameter(sz), &pt, |b, pt| {
                b.iter(|| {
                    a.seal(&fix.key, &fix.nonce, b"", pt, &mut ct)
                        .expect("seal failed");
                });
            });
        }
        group.finish();
    }
}

fn bench_aead_ocb3(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[1024, 65536];

    let algos = [AeadAlgo::Aes128Ocb3, AeadAlgo::Aes256Ocb3];

    for algo in algos {
        let name = format!("{algo}");
        let a = aead_impl(algo);
        let fix = aead_fixture(&mut rng, algo);
        let tag_len = a.tag_len();
        let mut group = c.benchmark_group(format!("aead/{name}"));
        apply_quick_mode(&mut group);

        for &sz in sizes {
            let pt = random_bytes(&mut rng, sz);
            let mut ct = vec![0u8; sz + tag_len];
            group.throughput(Throughput::Bytes(sz as u64));
            group.bench_with_input(BenchmarkId::from_parameter(sz), &pt, |b, pt| {
                b.iter(|| {
                    a.seal(&fix.key, &fix.nonce, b"", pt, &mut ct)
                        .expect("seal failed");
                });
            });
        }
        group.finish();
    }
}

// ── Deoxys-II benchmarks ──────────────────────────────────────────────────────
//
// Deoxys-II-128-128 is the CAESAR final-portfolio winner for the defence-in-depth
// use case (nonce-misuse-resistant AEAD).  OxiCrypto-only; no ring/aws-lc-rs
// equivalent.
//
// Nonce is 16 bytes (128-bit) — larger than standard 12-byte AEAD nonces.
// Benchmark at 1 KiB and 64 KiB to cover both cache-resident and larger payloads.

fn bench_aead_deoxys(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[1024, 65536];

    let algo = AeadAlgo::DeoxysII128;
    let name = format!("{algo}");
    let a = aead_impl(algo);
    let fix = aead_fixture(&mut rng, algo);
    let tag_len = a.tag_len();
    let mut group = c.benchmark_group(format!("aead/{name}"));
    apply_quick_mode(&mut group);

    for &sz in sizes {
        let pt = random_bytes(&mut rng, sz);
        let mut ct = vec![0u8; sz + tag_len];
        group.throughput(Throughput::Bytes(sz as u64));
        group.bench_with_input(BenchmarkId::from_parameter(sz), &pt, |b, pt| {
            b.iter(|| {
                a.seal(&fix.key, &fix.nonce, b"", pt, &mut ct)
                    .expect("deoxys-ii seal failed");
            });
        });
    }
    group.finish();
}

// ── Criterion wiring ──────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_aead_standard,
    bench_aead_siv,
    bench_aead_xchacha,
    bench_aead_ccm,
    bench_aead_ocb3,
    bench_aead_deoxys,
);
criterion_main!(benches);
