//! AEAD benchmarks: encryption throughput for all AEAD variants.
//!
//! Covers AES-GCM (128/256), ChaCha20-Poly1305, AES-GCM-SIV (128/256),
//! XChaCha20-Poly1305, AES-CCM (128/256), AES-OCB3 (128/256), and Deoxys-II.
//! Input sizes: 64 B, 1 KiB, 4 KiB, 64 KiB, 1 MiB (full sweep).
//! Also includes comparison groups: AES-GCM-SIV vs AES-GCM, XChaCha20 vs ChaCha20,
//! streaming AEAD chunk-size sweep, and in-place vs copy-based seal.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxicrypto::{aead_impl, AeadAlgo};
use oxicrypto_aead::{Aes256GcmStream, ChaCha20Poly1305Stream};
use oxicrypto_core::StreamingAead;
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
    // Full size sweep: 64 B (short message), 1 KiB, 4 KiB (typical TLS record),
    // 64 KiB, 1 MiB (large-payload scalability).
    let sizes: &[usize] = &[64, 1024, 4096, 65536, 1024 * 1024];

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

// ── AES-GCM-SIV vs AES-GCM comparison ────────────────────────────────────────
//
// AES-GCM-SIV (RFC 8452) provides nonce-misuse resistance at the cost of ~2×
// overhead (two passes: synthetic-IV derivation + encrypt). This group puts both
// algorithms side-by-side at the same input sizes so the overhead is directly
// measurable.

fn bench_aead_siv_vs_gcm(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[64, 1024, 65536];

    let pairs = [
        (AeadAlgo::Aes256Gcm, "AES-256-GCM"),
        (AeadAlgo::Aes256GcmSiv, "AES-256-GCM-SIV"),
    ];

    for &sz in sizes {
        let mut group = c.benchmark_group(format!("aead_siv_vs_gcm/{sz}"));
        apply_quick_mode(&mut group);
        group.throughput(Throughput::Bytes(sz as u64));

        for (algo, label) in pairs {
            let a = aead_impl(algo);
            let fix = aead_fixture(&mut rng, algo);
            let tag_len = a.tag_len();
            let pt = random_bytes(&mut rng, sz);
            let mut ct = vec![0u8; sz + tag_len];
            group.bench_function(label, |b| {
                b.iter(|| {
                    a.seal(&fix.key, &fix.nonce, b"", &pt, &mut ct)
                        .expect("seal failed");
                });
            });
        }
        group.finish();
    }
}

// ── XChaCha20-Poly1305 vs ChaCha20-Poly1305 comparison ───────────────────────
//
// XChaCha20-Poly1305 requires a HChaCha20 subkey derivation step before the
// main encryption, adding a small but measurable overhead. This group measures
// that overhead head-to-head.

fn bench_xchacha_vs_chacha(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[64, 1024, 65536, 1024 * 1024];

    let pairs = [
        (AeadAlgo::ChaCha20Poly1305, "ChaCha20-Poly1305"),
        (AeadAlgo::XChaCha20Poly1305, "XChaCha20-Poly1305"),
    ];

    for &sz in sizes {
        let mut group = c.benchmark_group(format!("aead_chacha_vs_xchacha/{sz}"));
        apply_quick_mode(&mut group);
        group.throughput(Throughput::Bytes(sz as u64));

        for (algo, label) in pairs {
            let a = aead_impl(algo);
            let fix = aead_fixture(&mut rng, algo);
            let tag_len = a.tag_len();
            let pt = random_bytes(&mut rng, sz);
            let mut ct = vec![0u8; sz + tag_len];
            group.bench_function(label, |b| {
                b.iter(|| {
                    a.seal(&fix.key, &fix.nonce, b"", &pt, &mut ct)
                        .expect("seal failed");
                });
            });
        }
        group.finish();
    }
}

// ── Streaming AEAD chunk size sweep ──────────────────────────────────────────
//
// For a fixed 1 MiB payload, vary the chunk size to find the optimal chunk
// granularity for the STREAM construction. Smaller chunks reduce memory usage
// but add per-chunk nonce/tag overhead; larger chunks amortise the overhead.
//
// Chunk sizes tested: 4 KiB (TLS record), 16 KiB, 64 KiB, 256 KiB.
//
// STREAM protocol note: the API uses a "look-ahead by one chunk" pattern.
// `encrypt_update(chunk, out)` buffers `chunk` and encrypts the **previous**
// buffered chunk into `out` (0 bytes on the first call).
// `encrypt_finalize(out)` encrypts the last buffered chunk (final flag) and
// returns the 16-byte authentication tag.

/// Encrypt `data` in streaming mode with the given `chunk_sz` using AES-256-GCM-STREAM.
///
/// The STREAM "look-ahead by one chunk" protocol:
///  - `encrypt_update(chunk_N, out)` stores `chunk_N` and emits the *previous* chunk
///    (chunk_{N-1}) as ciphertext + tag into `out`.
///  - `encrypt_finalize(out)` emits the last buffered chunk with the final flag.
///
/// The loop processes `chunks[0 .. n-1]`; the last chunk is handled outside the
/// loop to allow `encrypt_finalize` (which consumes `self`) to be called exactly
/// once without rustc seeing a potential second iteration.
fn aes_gcm_stream_encrypt(key: &[u8], prefix: &[u8], data: &[u8], chunk_sz: usize) -> Vec<u8> {
    let mut s = Aes256GcmStream::init(key, prefix, b"").expect("stream init");
    // Worst-case capacity: data.len() + (num_chunks * 16) for each encrypted chunk.
    let num_chunks = data.len().div_ceil(chunk_sz).max(1);
    let mut ciphertext = Vec::with_capacity(data.len() + num_chunks * 16);

    let chunks: Vec<&[u8]> = data.chunks(chunk_sz).collect();
    let n_chunks = chunks.len();

    // Feed all but the last chunk through encrypt_update, collecting emitted output.
    // On call i (0-indexed), out receives the ciphertext for chunk_{i-1} (or 0 bytes on i==0).
    for i in 0..n_chunks.saturating_sub(1) {
        let prev_len = if i == 0 { 0 } else { chunks[i - 1].len() };
        let mut out = vec![0u8; prev_len.max(1) + 16];
        let n = s.encrypt_update(chunks[i], &mut out).expect("update");
        ciphertext.extend_from_slice(&out[..n]);
    }

    // Feed the final chunk through encrypt_update (emits chunk_{n-2} if n > 1),
    // then call encrypt_finalize to emit chunk_{n-1} with the final flag.
    let last_idx = n_chunks - 1;
    let pre_last_len = if last_idx == 0 {
        0
    } else {
        chunks[last_idx - 1].len()
    };
    let mut out = vec![0u8; pre_last_len.max(1) + 16];
    let n = s
        .encrypt_update(chunks[last_idx], &mut out)
        .expect("last update");
    ciphertext.extend_from_slice(&out[..n]);

    let last_len = chunks[last_idx].len();
    let mut fin_out = vec![0u8; last_len + 16];
    let _tag = s.encrypt_finalize(&mut fin_out).expect("finalize");
    ciphertext.extend_from_slice(&fin_out);

    ciphertext
}

/// Encrypt `data` in streaming mode with the given `chunk_sz` using ChaCha20-Poly1305-STREAM.
///
/// Same look-ahead protocol as `aes_gcm_stream_encrypt`, using
/// `ChaCha20Poly1305Stream` (nonce_prefix must be exactly 19 bytes).
fn chacha20_stream_encrypt(key: &[u8], prefix: &[u8], data: &[u8], chunk_sz: usize) -> Vec<u8> {
    let mut s = ChaCha20Poly1305Stream::init(key, prefix, b"").expect("stream init");
    let num_chunks = data.len().div_ceil(chunk_sz).max(1);
    let mut ciphertext = Vec::with_capacity(data.len() + num_chunks * 16);

    let chunks: Vec<&[u8]> = data.chunks(chunk_sz).collect();
    let n_chunks = chunks.len();

    for i in 0..n_chunks.saturating_sub(1) {
        let prev_len = if i == 0 { 0 } else { chunks[i - 1].len() };
        let mut out = vec![0u8; prev_len.max(1) + 16];
        let n = s.encrypt_update(chunks[i], &mut out).expect("update");
        ciphertext.extend_from_slice(&out[..n]);
    }

    let last_idx = n_chunks - 1;
    let pre_last_len = if last_idx == 0 {
        0
    } else {
        chunks[last_idx - 1].len()
    };
    let mut out = vec![0u8; pre_last_len.max(1) + 16];
    let n = s
        .encrypt_update(chunks[last_idx], &mut out)
        .expect("last update");
    ciphertext.extend_from_slice(&out[..n]);

    let last_len = chunks[last_idx].len();
    let mut fin_out = vec![0u8; last_len + 16];
    let _tag = s.encrypt_finalize(&mut fin_out).expect("finalize");
    ciphertext.extend_from_slice(&fin_out);

    ciphertext
}

fn bench_aead_streaming_chunk_sizes(c: &mut Criterion) {
    let mut rng = make_rng();
    let payload_len: usize = 1024 * 1024; // 1 MiB fixed payload
                                          // chunk_sizes: 4 KiB (TLS record size), 16 KiB, 64 KiB, 256 KiB.
    let chunk_sizes: &[usize] = &[4096, 16384, 65536, 262144];

    let payload = random_bytes(&mut rng, payload_len);

    // AES-256-GCM stream (nonce prefix must be exactly 7 bytes)
    {
        let key = random_bytes(&mut rng, 32);
        let prefix = random_bytes(&mut rng, 7);

        let mut group = c.benchmark_group("aead_streaming_chunk/AES-256-GCM");
        apply_quick_mode(&mut group);
        group.throughput(Throughput::Bytes(payload_len as u64));

        for &chunk_sz in chunk_sizes {
            let payload_ref = payload.clone();
            let key_ref = key.clone();
            let prefix_ref = prefix.clone();
            group.bench_with_input(
                BenchmarkId::from_parameter(chunk_sz),
                &chunk_sz,
                move |b, &csz| {
                    b.iter(|| aes_gcm_stream_encrypt(&key_ref, &prefix_ref, &payload_ref, csz));
                },
            );
        }
        group.finish();
    }

    // ChaCha20-Poly1305 stream (nonce prefix must be exactly 19 bytes)
    {
        let key = random_bytes(&mut rng, 32);
        let prefix = random_bytes(&mut rng, 19);

        let mut group = c.benchmark_group("aead_streaming_chunk/ChaCha20-Poly1305");
        apply_quick_mode(&mut group);
        group.throughput(Throughput::Bytes(payload_len as u64));

        for &chunk_sz in chunk_sizes {
            let payload_ref = payload.clone();
            let key_ref = key.clone();
            let prefix_ref = prefix.clone();
            group.bench_with_input(
                BenchmarkId::from_parameter(chunk_sz),
                &chunk_sz,
                move |b, &csz| {
                    b.iter(|| chacha20_stream_encrypt(&key_ref, &prefix_ref, &payload_ref, csz));
                },
            );
        }
        group.finish();
    }
}

// ── In-place vs copy-based seal comparison ────────────────────────────────────
//
// `seal_in_place` avoids a copy of the plaintext by encrypting the Vec in-place
// (the Vec is extended by tag_len bytes and the contents are encrypted
// in-situ). `seal` writes into a separate output buffer. This group quantifies
// the allocation / copy difference.

fn bench_aead_inplace_vs_copy(c: &mut Criterion) {
    let mut rng = make_rng();
    let sizes: &[usize] = &[64, 1024, 65536];

    let algos = [AeadAlgo::Aes256Gcm, AeadAlgo::ChaCha20Poly1305];

    for algo in algos {
        let name = format!("{algo}");
        let a = aead_impl(algo);
        let fix = aead_fixture(&mut rng, algo);
        let tag_len = a.tag_len();

        for &sz in sizes {
            let pt = random_bytes(&mut rng, sz);
            let mut group = c.benchmark_group(format!("aead_inplace_vs_copy/{name}/{sz}"));
            apply_quick_mode(&mut group);
            group.throughput(Throughput::Bytes(sz as u64));

            // copy-based: plaintext and ciphertext are separate buffers
            {
                let pt_clone = pt.clone();
                let mut ct = vec![0u8; sz + tag_len];
                group.bench_function("copy", |b| {
                    b.iter(|| {
                        a.seal(&fix.key, &fix.nonce, b"", &pt_clone, &mut ct)
                            .expect("seal failed");
                    });
                });
            }

            // in-place: Vec<u8> extended by tag_len in-situ
            {
                let pt_clone = pt.clone();
                group.bench_function("in_place", |b| {
                    b.iter(|| {
                        let mut buf = pt_clone.clone();
                        a.seal_in_place(&fix.key, &fix.nonce, b"", &mut buf)
                            .expect("seal_in_place failed");
                        buf
                    });
                });
            }

            group.finish();
        }
    }
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
    bench_aead_siv_vs_gcm,
    bench_xchacha_vs_chacha,
    bench_aead_streaming_chunk_sizes,
    bench_aead_inplace_vs_copy,
);
criterion_main!(benches);
