//! Performance benchmarks for oxicrypto-kdf.
//!
//! Covers:
//! - Argon2id vs scrypt vs PBKDF2 at equivalent security levels
//! - HKDF-SHA-256 vs HKDF-SHA-512 derive throughput
//! - Balloon hashing vs Argon2id for equivalent memory usage
//! - PBKDF2 at 310k / 600k / 1M iterations
//! - bcrypt cost=12 vs Argon2id INTERACTIVE latency
//!
//! Run with:
//!   cargo bench -p oxicrypto-kdf
//!
//! Note: Password-hashing benchmarks (Argon2id, scrypt, bcrypt) are slow by
//! design. They use `sample_size(10)` to keep CI runtimes bounded.

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use oxicrypto_core::Kdf;
use oxicrypto_kdf::{
    argon2_kdf::{argon2id_derive, Argon2Params},
    balloon::{balloon_sha256, BalloonParams},
    bcrypt_kdf::bcrypt_hash,
    hkdf_sha256_derive_to_vec, hkdf_sha512_derive_to_vec,
    pbkdf2_kdf::pbkdf2_sha256,
    scrypt_kdf::scrypt_derive,
    HkdfSha256, HkdfSha512,
};

// ── HKDF throughput: SHA-256 vs SHA-512 ───────────────────────────────────────

fn bench_hkdf_throughput(c: &mut Criterion) {
    let ikm = [0x42u8; 32];
    let salt = [0x13u8; 16];
    let info = b"bench-hkdf-context";

    let output_sizes: &[usize] = &[16, 32, 64, 128];

    let mut group = c.benchmark_group("hkdf/throughput");
    for &sz in output_sizes {
        group.throughput(Throughput::Bytes(sz as u64));

        group.bench_with_input(BenchmarkId::new("HKDF-SHA-256", sz), &sz, |b, &sz| {
            let mut okm = vec![0u8; sz];
            let kdf = HkdfSha256;
            b.iter(|| {
                kdf.derive(&ikm, &salt, info, &mut okm)
                    .expect("HKDF-SHA-256 derive");
            });
        });

        group.bench_with_input(BenchmarkId::new("HKDF-SHA-512", sz), &sz, |b, &sz| {
            let mut okm = vec![0u8; sz];
            let kdf = HkdfSha512;
            b.iter(|| {
                kdf.derive(&ikm, &salt, info, &mut okm)
                    .expect("HKDF-SHA-512 derive");
            });
        });

        group.bench_with_input(
            BenchmarkId::new("hkdf_sha256_derive_to_vec", sz),
            &sz,
            |b, &sz| {
                b.iter(|| {
                    hkdf_sha256_derive_to_vec(&ikm, &salt, info, sz)
                        .expect("hkdf_sha256_derive_to_vec");
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("hkdf_sha512_derive_to_vec", sz),
            &sz,
            |b, &sz| {
                b.iter(|| {
                    hkdf_sha512_derive_to_vec(&ikm, &salt, info, sz)
                        .expect("hkdf_sha512_derive_to_vec");
                });
            },
        );
    }
    group.finish();
}

// ── PBKDF2 iteration count scaling ────────────────────────────────────────────

fn bench_pbkdf2_iterations(c: &mut Criterion) {
    let password = b"bench-password-12345";
    let salt = [0xabu8; 16];
    let mut okm = [0u8; 32];

    let mut group = c.benchmark_group("pbkdf2/iteration-scaling");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    for &iters in &[310_000u32, 600_000, 1_000_000] {
        group.bench_with_input(
            BenchmarkId::new("PBKDF2-SHA-256", iters),
            &iters,
            |b, &iters| {
                b.iter(|| {
                    pbkdf2_sha256(password, &salt, iters, &mut okm).expect("pbkdf2_sha256");
                });
            },
        );
    }
    group.finish();
}

// ── Argon2id vs scrypt vs PBKDF2 at equivalent security levels ───────────────

fn bench_password_kdfs_equivalent_security(c: &mut Criterion) {
    let password = b"bench-password-security";
    let salt = [0x99u8; 16];
    let mut okm = [0u8; 32];

    let mut group = c.benchmark_group("password-kdf/security-comparison");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    // Argon2id interactive preset: m=65536 KiB (64 MiB), t=2, p=1
    let argon2_params = Argon2Params::interactive();
    group.bench_function("Argon2id/interactive/m=64MiB/t=2/p=1", |b| {
        b.iter(|| {
            argon2id_derive(password, &salt, argon2_params, &mut okm).expect("argon2id_derive");
        });
    });

    // scrypt interactive preset: N=32768 (log_n=15), r=8, p=1 (~32 MiB)
    group.bench_function("scrypt/interactive/N=32768/r=8/p=1", |b| {
        b.iter(|| {
            scrypt_derive(password, &salt, 15, 8, 1, &mut okm).expect("scrypt_derive");
        });
    });

    // PBKDF2 at OWASP 2023 minimum: 600k iterations (low memory, CPU-only)
    group.bench_function("PBKDF2-SHA256/OWASP2023/600k-iters", |b| {
        b.iter(|| {
            pbkdf2_sha256(password, &salt, 600_000, &mut okm).expect("pbkdf2_sha256");
        });
    });

    group.finish();
}

// ── Balloon hashing vs Argon2id for equivalent memory usage ──────────────────

fn bench_balloon_vs_argon2id(c: &mut Criterion) {
    let password = b"bench-password-balloon";
    let salt = [0x77u8; 16];

    let mut group = c.benchmark_group("password-kdf/balloon-vs-argon2id");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    // Balloon-SHA-256 interactive preset: space=16384 blocks * 32B = ~512 KiB, t=3
    let balloon_params = BalloonParams::interactive();
    group.bench_function("Balloon-SHA-256/interactive/s=16384/t=3", |b| {
        let mut out = [0u8; 32];
        b.iter(|| {
            balloon_sha256(
                password,
                &salt,
                balloon_params.space_cost,
                balloon_params.time_cost,
                &mut out,
            )
            .expect("balloon_sha256");
        });
    });

    // Balloon-SHA-256 at moderate preset: space=65536 blocks * 32B = ~2 MiB, t=3
    let balloon_moderate = BalloonParams::moderate();
    group.bench_function("Balloon-SHA-256/moderate/s=65536/t=3", |b| {
        let mut out = [0u8; 32];
        b.iter(|| {
            balloon_sha256(
                password,
                &salt,
                balloon_moderate.space_cost,
                balloon_moderate.time_cost,
                &mut out,
            )
            .expect("balloon_sha256 moderate");
        });
    });

    // Argon2id at roughly equivalent memory (~64 MiB is the standard interactive
    // preset; use TEST_PARAMS here for a fast comparison at the same code path).
    // For an accurate memory-equivalent comparison, Balloon interactive uses ~512 KiB;
    // Argon2id at m=512 (512 KiB), t=2, p=1 is a fair counterpart.
    let argon2_low_mem = Argon2Params {
        m_cost: 512,
        t_cost: 2,
        p_cost: 1,
    };
    group.bench_function("Argon2id/m=512KiB/t=2/p=1", |b| {
        let mut out = [0u8; 32];
        b.iter(|| {
            argon2id_derive(password, &salt, argon2_low_mem, &mut out).expect("argon2id low_mem");
        });
    });

    group.finish();
}

// ── bcrypt cost=12 vs Argon2id INTERACTIVE latency ────────────────────────────

fn bench_bcrypt_vs_argon2id(c: &mut Criterion) {
    let password = b"bench-password-bcrypt";
    // bcrypt uses exactly 16 bytes of salt.
    let salt = [0x55u8; 16];

    let mut group = c.benchmark_group("password-kdf/bcrypt-vs-argon2id");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    // bcrypt cost=12 (2^12 = 4096 Eksblowfish rounds — typical for web auth).
    group.bench_function("bcrypt/cost=12", |b| {
        b.iter(|| {
            bcrypt_hash(password, 12, &salt).expect("bcrypt_hash cost=12");
        });
    });

    // Argon2id at the interactive preset (m=65536 KiB, t=2, p=1).
    let argon2_params = Argon2Params::interactive();
    group.bench_function("Argon2id/interactive/m=64MiB/t=2/p=1", |b| {
        let mut out = [0u8; 32];
        b.iter(|| {
            argon2id_derive(password, &salt, argon2_params, &mut out)
                .expect("argon2id interactive");
        });
    });

    group.finish();
}

// ── Argon2id memory allocation profiling ─────────────────────────────────────

fn bench_argon2id_memory_profiles(c: &mut Criterion) {
    let password = b"bench-password-argon2-mem";
    let salt = [0xbbu8; 16];
    let mut okm = [0u8; 32];

    let mut group = c.benchmark_group("argon2id/memory-profiles");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    // Sweep m_cost values to show allocation vs latency tradeoff.
    for &m_cost in &[1024u32, 4096, 16384, 65536] {
        let params = Argon2Params {
            m_cost,
            t_cost: 2,
            p_cost: 1,
        };
        group.bench_with_input(
            BenchmarkId::new("m_cost_KiB", m_cost),
            &params,
            |b, &params| {
                b.iter(|| {
                    argon2id_derive(password, &salt, params, &mut okm)
                        .expect("argon2id memory profile");
                });
            },
        );
    }
    group.finish();
}

// ── Criterion wiring ──────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_hkdf_throughput,
    bench_pbkdf2_iterations,
    bench_password_kdfs_equivalent_security,
    bench_balloon_vs_argon2id,
    bench_bcrypt_vs_argon2id,
    bench_argon2id_memory_profiles,
);
criterion_main!(benches);
