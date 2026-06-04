//! Factory function overhead benchmarks.
//!
//! Measures the overhead of the facade factory functions (`hash_impl`,
//! `aead_impl`, `mac_impl`, `kdf_impl`, `kex_impl`) compared to direct
//! instantiation of the underlying concrete types.  Also measures dynamic
//! dispatch overhead of `Box<dyn Hash>` vs a monomorphized generic call path.
//!
//! # What is measured
//!
//! - **factory_construction/hash_impl_sha256**: time to call `hash_impl(HashAlgo::Sha256)`
//!   and discard the returned `Box<dyn Hash>`.
//! - **factory_construction/direct_sha256**: time to heap-box `oxicrypto_hash::Sha256`
//!   directly, bypassing the facade selector match.
//! - **dispatch_overhead/dynamic_sha256_1kib**: SHA-256 of a 1 KiB buffer via
//!   `Box<dyn Hash>` (vtable call per `hash()`).
//! - **dispatch_overhead/monomorphic_sha256_1kib**: SHA-256 of a 1 KiB buffer via
//!   a generic function `fn hash_generic<H: Hash>(h: &H, ...)` (no vtable).
//! - **factory_construction/aead_impl_aes256gcm**: same pattern for the AEAD factory.
//! - **factory_construction/direct_aes256gcm**: same for direct AEAD instantiation.
//! - **factory_construction/mac_impl_hmacsha256**: MAC factory overhead.
//! - **factory_construction/kdf_impl_hkdfsha256**: KDF factory overhead.
//! - **factory_construction/kex_impl_x25519**: KEX factory overhead.
//!
//! # Interpretation
//!
//! Factory construction overhead should be O(1) and essentially equal to a
//! `Box::new(ZeroSizedType)` allocation.  With `#[inline(always)]` on the factory
//! functions the branch-selection in `hash_impl`/etc. should be folded at the
//! call site when the `algo` variant is a compile-time constant.
//!
//! Dynamic dispatch overhead shows the vtable indirection cost per call vs a
//! monomorphized path.  For bulk operations (1 KiB+) this should be negligible
//! compared to the actual cryptographic work.
//!
//! Run with:
//!   cargo bench -p oxicrypto-bench --bench factory_overhead

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxicrypto::{
    aead_impl, hash_impl, kdf_impl, kex_impl, mac_impl, AeadAlgo, HashAlgo, KdfAlgo, KexAlgo,
    MacAlgo,
};
use oxicrypto_aead::Aes256Gcm as DirectAes256Gcm;
use oxicrypto_core::{Aead, Hash, Kdf};
use oxicrypto_hash::Sha256 as DirectSha256;
use std::hint::black_box;

// ── Quick-mode helper ─────────────────────────────────────────────────────────

fn apply_quick_mode(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    if std::env::var("BENCH_QUICK").as_deref() == Ok("1") {
        group.sample_size(10);
    }
}

// ── Factory construction overhead ─────────────────────────────────────────────

/// Benchmark the overhead of calling `hash_impl(HashAlgo::Sha256)` to obtain
/// a `Box<dyn Hash>` vs directly boxing `oxicrypto_hash::Sha256`.
///
/// `Sha256` is a zero-sized type (ZST) so the "direct" allocation is a
/// `Box::new(ZST)` = allocating 0 or 1 bytes with no copy.  The `hash_impl`
/// path goes through a `#[inline(always)]` match arm; at a call site with a
/// literal variant the optimizer should eliminate the branch entirely.
fn bench_factory_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("factory_construction");
    apply_quick_mode(&mut group);

    // ── Hash ─────────────────────────────────────────────────────────────────
    group.bench_function("hash_impl_sha256", |b| {
        b.iter(|| {
            let h = hash_impl(black_box(HashAlgo::Sha256));
            black_box(h);
        })
    });

    group.bench_function("direct_sha256", |b| {
        b.iter(|| {
            let h = oxicrypto_core::Box::new(DirectSha256);
            black_box(h);
        })
    });

    group.bench_function("hash_impl_blake3", |b| {
        b.iter(|| {
            let h = hash_impl(black_box(HashAlgo::Blake3));
            black_box(h);
        })
    });

    // ── AEAD ─────────────────────────────────────────────────────────────────
    group.bench_function("aead_impl_aes256gcm", |b| {
        b.iter(|| {
            let a = aead_impl(black_box(AeadAlgo::Aes256Gcm));
            black_box(a);
        })
    });

    group.bench_function("direct_aes256gcm", |b| {
        b.iter(|| {
            let a = oxicrypto_core::Box::new(DirectAes256Gcm);
            black_box(a);
        })
    });

    group.bench_function("aead_impl_chacha20poly1305", |b| {
        b.iter(|| {
            let a = aead_impl(black_box(AeadAlgo::ChaCha20Poly1305));
            black_box(a);
        })
    });

    // ── MAC ──────────────────────────────────────────────────────────────────
    group.bench_function("mac_impl_hmacsha256", |b| {
        b.iter(|| {
            let m = mac_impl(black_box(MacAlgo::HmacSha256));
            black_box(m);
        })
    });

    group.bench_function("mac_impl_hmacsha512", |b| {
        b.iter(|| {
            let m = mac_impl(black_box(MacAlgo::HmacSha512));
            black_box(m);
        })
    });

    // ── KDF ──────────────────────────────────────────────────────────────────
    group.bench_function("kdf_impl_hkdfsha256", |b| {
        b.iter(|| {
            let k = kdf_impl(black_box(KdfAlgo::HkdfSha256));
            black_box(k);
        })
    });

    group.bench_function("kdf_impl_hkdfsha384", |b| {
        b.iter(|| {
            let k = kdf_impl(black_box(KdfAlgo::HkdfSha384));
            black_box(k);
        })
    });

    // ── KEX ──────────────────────────────────────────────────────────────────
    group.bench_function("kex_impl_x25519", |b| {
        b.iter(|| {
            let k = kex_impl(black_box(KexAlgo::X25519));
            black_box(k);
        })
    });

    group.bench_function("kex_impl_ecdhp256", |b| {
        b.iter(|| {
            let k = kex_impl(black_box(KexAlgo::EcdhP256));
            black_box(k);
        })
    });

    group.finish();
}

// ── Dynamic dispatch overhead (Box<dyn Hash> vs generic monomorphization) ────

/// Compare SHA-256 throughput via dynamic dispatch (`Box<dyn Hash>`) vs a
/// monomorphized generic path.  For large inputs the cryptographic work
/// dominates; for tiny inputs the vtable overhead may be measurable.
fn bench_dispatch_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("dispatch_overhead");
    apply_quick_mode(&mut group);

    let sizes: &[usize] = &[64, 256, 1024, 4096];

    for &sz in sizes {
        let data = vec![0x5au8; sz];

        // ── Dynamic dispatch (Box<dyn Hash>) ──────────────────────────────────
        group.throughput(Throughput::Bytes(sz as u64));
        group.bench_with_input(BenchmarkId::new("dynamic_sha256", sz), &data, |b, data| {
            let h = hash_impl(HashAlgo::Sha256);
            let mut out = [0u8; 32];
            b.iter(|| {
                h.hash(black_box(data), &mut out).expect("hash failed");
                black_box(&out);
            });
        });

        // ── Monomorphized generic (no vtable) ─────────────────────────────────
        group.bench_with_input(
            BenchmarkId::new("monomorphic_sha256", sz),
            &data,
            |b, data| {
                let h = DirectSha256;
                let mut out = [0u8; 32];
                b.iter(|| {
                    hash_generic(&h, black_box(data), &mut out);
                    black_box(&out);
                });
            },
        );

        // ── Direct method call (no trait object, no generics) ─────────────────
        group.bench_with_input(BenchmarkId::new("direct_sha256", sz), &data, |b, data| {
            let h = DirectSha256;
            let mut out = [0u8; 32];
            b.iter(|| {
                h.hash(black_box(data), &mut out).expect("hash failed");
                black_box(&out);
            });
        });
    }

    group.finish();
}

/// Generic helper: receives `H: Hash` by reference — monomorphized at the call
/// site with `DirectSha256`, so no vtable is used.
fn hash_generic<H: Hash>(h: &H, msg: &[u8], out: &mut [u8]) {
    h.hash(msg, out).expect("hash failed");
}

// ── AEAD dispatch overhead ────────────────────────────────────────────────────

/// Compare AES-256-GCM throughput via `Box<dyn Aead>` vs the concrete type.
fn bench_aead_dispatch_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_dispatch_overhead");
    apply_quick_mode(&mut group);

    let key = [0x42u8; 32];
    let nonce = [0x00u8; 12];
    let aad = b"additional authenticated data";
    let sizes: &[usize] = &[64, 1024, 4096];

    for &sz in sizes {
        let plaintext = vec![0x5au8; sz];

        group.throughput(Throughput::Bytes(sz as u64));

        // ── Dynamic dispatch (Box<dyn Aead>) ──────────────────────────────────
        group.bench_with_input(
            BenchmarkId::new("dynamic_aes256gcm", sz),
            &plaintext,
            |b, plaintext| {
                let aead = aead_impl(AeadAlgo::Aes256Gcm);
                b.iter(|| {
                    let ct = aead
                        .seal_to_vec(&key, &nonce, aad, black_box(plaintext))
                        .expect("seal failed");
                    black_box(ct);
                });
            },
        );

        // ── Direct concrete type (no vtable) ─────────────────────────────────
        group.bench_with_input(
            BenchmarkId::new("direct_aes256gcm", sz),
            &plaintext,
            |b, plaintext| {
                let aead = DirectAes256Gcm;
                b.iter(|| {
                    let ct = aead
                        .seal_to_vec(&key, &nonce, aad, black_box(plaintext))
                        .expect("seal failed");
                    black_box(ct);
                });
            },
        );
    }

    group.finish();
}

// ── KDF dispatch overhead ─────────────────────────────────────────────────────

/// Compare HKDF-SHA-256 throughput via `Box<dyn Kdf>` vs direct type call.
fn bench_kdf_dispatch_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf_dispatch_overhead");
    apply_quick_mode(&mut group);

    let ikm = [0x11u8; 32];
    let salt = [0x22u8; 32];
    let info = b"oxicrypto factory overhead bench";

    let out_sizes: &[usize] = &[16, 32, 64];

    for &sz in out_sizes {
        // ── Dynamic dispatch (Box<dyn Kdf>) ───────────────────────────────────
        group.bench_with_input(BenchmarkId::new("dynamic_hkdfsha256", sz), &sz, |b, &sz| {
            let kdf = kdf_impl(KdfAlgo::HkdfSha256);
            let mut out = vec![0u8; sz];
            b.iter(|| {
                kdf.derive(&ikm, &salt, info, black_box(&mut out))
                    .expect("derive failed");
                black_box(&out);
            });
        });

        // ── Direct concrete type ──────────────────────────────────────────────
        group.bench_with_input(BenchmarkId::new("direct_hkdfsha256", sz), &sz, |b, &sz| {
            let kdf = oxicrypto_kdf::HkdfSha256;
            let mut out = vec![0u8; sz];
            b.iter(|| {
                kdf.derive(&ikm, &salt, info, black_box(&mut out))
                    .expect("derive failed");
                black_box(&out);
            });
        });
    }

    group.finish();
}

// ── Criterion wiring ──────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_factory_construction,
    bench_dispatch_overhead,
    bench_aead_dispatch_overhead,
    bench_kdf_dispatch_overhead,
);
criterion_main!(benches);
