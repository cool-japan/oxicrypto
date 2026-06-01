//! KDF benchmarks: HKDF-SHA-256/384/512, PBKDF2, Argon2id, and scrypt.
//!
//! HKDF is measured per extract+expand cycle (common TLS 1.3 usage).
//! Password KDFs (PBKDF2, Argon2id, scrypt) are measured at their OWASP-
//! recommended parameters; each takes hundreds of milliseconds — `sample_size(10)`
//! keeps total bench time acceptable.

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use oxicrypto::{kdf_impl, KdfAlgo};
use oxicrypto_kdf::{
    hkdf_sha256_expand, hkdf_sha256_extract, hkdf_sha384_expand, hkdf_sha384_extract,
    hkdf_sha512_expand, hkdf_sha512_extract,
};
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

// ── HKDF extract+expand benchmarks (low-level API) ───────────────────────────

fn bench_hkdf_extract_expand(c: &mut Criterion) {
    let mut rng = make_rng();
    let ikm = random_bytes(&mut rng, 32);
    let salt = random_bytes(&mut rng, 16);
    let info = b"bench-hkdf-context";

    let mut group = c.benchmark_group("kdf/hkdf-raw");

    // HKDF-SHA-256: extract returns [u8; 32] (not a Result).
    group.bench_function("extract+expand-sha256/32", |b| {
        let mut okm = [0u8; 32];
        b.iter(|| {
            let prk = hkdf_sha256_extract(&salt, &ikm);
            hkdf_sha256_expand(&prk, info, &mut okm).expect("hkdf-sha256 expand failed");
        });
    });

    // HKDF-SHA-384: extract returns [u8; 48].
    group.bench_function("extract+expand-sha384/48", |b| {
        let mut okm = [0u8; 48];
        b.iter(|| {
            let prk = hkdf_sha384_extract(&salt, &ikm);
            hkdf_sha384_expand(&prk, info, &mut okm).expect("hkdf-sha384 expand failed");
        });
    });

    // HKDF-SHA-512: extract returns [u8; 64].
    group.bench_function("extract+expand-sha512/64", |b| {
        let mut okm = [0u8; 64];
        b.iter(|| {
            let prk = hkdf_sha512_extract(&salt, &ikm);
            hkdf_sha512_expand(&prk, info, &mut okm).expect("hkdf-sha512 expand failed");
        });
    });

    group.finish();
}

// ── HKDF trait-dispatched benchmarks ─────────────────────────────────────────

fn bench_hkdf_derive(c: &mut Criterion) {
    let mut rng = make_rng();
    let ikm = random_bytes(&mut rng, 32);
    let salt = random_bytes(&mut rng, 16);
    let info = b"bench-hkdf-info";

    // Vary output length to show scaling.
    let output_sizes: &[usize] = &[16, 32, 64];

    let algos = [
        (KdfAlgo::HkdfSha256, "HKDF-SHA-256"),
        (KdfAlgo::HkdfSha384, "HKDF-SHA-384"),
        (KdfAlgo::HkdfSha512, "HKDF-SHA-512"),
    ];

    for (algo, label) in algos {
        let kdf = kdf_impl(algo);
        let mut group = c.benchmark_group(format!("kdf/{label}"));

        for &sz in output_sizes {
            group.throughput(Throughput::Bytes(sz as u64));
            group.bench_with_input(BenchmarkId::new("derive", sz), &sz, |b, &sz| {
                let mut okm = vec![0u8; sz];
                b.iter(|| {
                    kdf.derive(&ikm, &salt, info, &mut okm)
                        .expect("kdf derive failed");
                });
            });
        }
        group.finish();
    }
}

// ── Password KDFs (slow — small sample size) ──────────────────────────────────

fn bench_pbkdf2(c: &mut Criterion) {
    let mut rng = make_rng();
    let password = b"bench-password-12345";
    let salt = random_bytes(&mut rng, 16);
    let mut okm = [0u8; 32];

    let mut group = c.benchmark_group("kdf/password");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    let pbkdf2_sha256 = kdf_impl(KdfAlgo::Pbkdf2Sha256);
    group.bench_function("PBKDF2-SHA256/600k-iters/32B", |b| {
        b.iter(|| {
            pbkdf2_sha256
                .derive(password, &salt, b"", &mut okm)
                .expect("pbkdf2-sha256 failed");
        });
    });

    let pbkdf2_sha512 = kdf_impl(KdfAlgo::Pbkdf2Sha512);
    group.bench_function("PBKDF2-SHA512/210k-iters/32B", |b| {
        b.iter(|| {
            pbkdf2_sha512
                .derive(password, &salt, b"", &mut okm)
                .expect("pbkdf2-sha512 failed");
        });
    });

    group.finish();
}

fn bench_argon2id(c: &mut Criterion) {
    let mut rng = make_rng();
    let password = b"bench-password-argon2";
    // Argon2id requires salt >= 8 bytes.
    let salt = random_bytes(&mut rng, 16);
    let mut okm = [0u8; 32];

    let mut group = c.benchmark_group("kdf/password");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    let argon2 = kdf_impl(KdfAlgo::Argon2id);
    group.bench_function("Argon2id/m=65536/t=3/p=4/32B", |b| {
        b.iter(|| {
            argon2
                .derive(password, &salt, b"", &mut okm)
                .expect("argon2id failed");
        });
    });

    group.finish();
}

fn bench_scrypt(c: &mut Criterion) {
    let mut rng = make_rng();
    let password = b"bench-password-scrypt";
    let salt = random_bytes(&mut rng, 16);
    let mut okm = [0u8; 32];

    let mut group = c.benchmark_group("kdf/password");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    let scrypt = kdf_impl(KdfAlgo::Scrypt);
    group.bench_function("scrypt/N=131072/r=8/p=1/32B", |b| {
        b.iter(|| {
            scrypt
                .derive(password, &salt, b"", &mut okm)
                .expect("scrypt failed");
        });
    });

    group.finish();
}

// ── Criterion wiring ──────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_hkdf_extract_expand,
    bench_hkdf_derive,
    bench_pbkdf2,
    bench_argon2id,
    bench_scrypt,
);
criterion_main!(benches);
