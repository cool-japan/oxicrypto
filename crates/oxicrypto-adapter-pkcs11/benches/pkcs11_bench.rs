//! Criterion benchmarks for `oxicrypto-adapter-pkcs11`.
//!
//! # Running
//!
//! ## Without SoftHSM2 (always-available software baselines only):
//! ```sh
//! cargo bench -p oxicrypto-adapter-pkcs11 --features bench
//! ```
//!
//! ## With SoftHSM2 (includes HSM-backed groups):
//! ```sh
//! export SOFTHSM2_MODULE=/usr/local/lib/softhsm/libsofthsm2.so
//! cargo bench -p oxicrypto-adapter-pkcs11 --features bench
//! ```
//!
//! All HSM-backed benchmark groups gracefully skip (log a message and return
//! without measurements) when `SOFTHSM2_MODULE` is not set, so `cargo bench`
//! always succeeds in CI.
//!
//! # Benchmark Groups
//!
//! 1. **ecdsa_p256_sign** — ECDSA-P256 sign latency: Pure-Rust software baseline
//!    (always) vs PKCS#11/SoftHSM2 path (when `SOFTHSM2_MODULE` is set).
//! 2. **aes256_gcm_encrypt / aes256_gcm_decrypt** — AES-256-GCM latency for
//!    1 KB and 64 KB payloads via PKCS#11/SoftHSM2 (skipped without SoftHSM2).
//! 3. **session_pool_checkout** — `Pkcs11SessionPool` checkout/checkin overhead
//!    vs idle_count query, measuring the `Arc<Mutex<Vec>>` round-trip cost
//!    without any HSM (pure-Rust, always runs).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;

// ---------------------------------------------------------------------------
// Group 1: ECDSA-P256 sign latency — software baseline (always runs)
// ---------------------------------------------------------------------------

/// Pure-Rust ECDSA-P256 signing baseline using the `p256` crate.
fn bench_ecdsa_p256_software(c: &mut Criterion) {
    use p256::{
        ecdsa::{signature::Signer as _, SigningKey},
        SecretKey,
    };

    // Fixed signing key (deterministic, not HSM-backed).
    let sk_bytes = [0x42u8; 32];
    let secret_key = SecretKey::from_slice(&sk_bytes).expect("valid P-256 secret key bytes");
    let signing_key = SigningKey::from(secret_key);

    let message = b"benchmark message for ECDSA-P256 sign";

    let mut group = c.benchmark_group("ecdsa_p256_sign");
    group.bench_function("pure_rust_p256", |b| {
        b.iter(|| {
            use p256::ecdsa::Signature;
            let sig: Signature = signing_key.sign(black_box(message));
            black_box(sig)
        })
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Group 1b: ECDSA-P256 via PKCS#11 (SoftHSM2 — skips if no module)
// ---------------------------------------------------------------------------

fn bench_ecdsa_p256_pkcs11(c: &mut Criterion) {
    use cryptoki::{mechanism::Mechanism, slot::Slot};
    use oxicrypto_adapter_pkcs11::{
        provider::Pkcs11Provider,
        sign::{Pkcs11SignerBuilder, SignMechanism},
    };
    use std::sync::Arc;

    let module_path = match std::env::var("SOFTHSM2_MODULE") {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => {
            eprintln!("[bench ecdsa_p256_pkcs11] SOFTHSM2_MODULE not set — skipping HSM group");
            return;
        }
    };

    let slot = Slot::try_from(0u64).expect("slot 0");
    let provider = match Pkcs11Provider::new(&module_path, slot, "1234") {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!("[bench ecdsa_p256_pkcs11] provider open failed: {e} — skipping");
            return;
        }
    };

    // P-256 named-curve OID: 1.2.840.10045.3.1.7
    let p256_params: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let key_label = "bench-ecdsa-p256";

    let priv_handle = match provider
        .generate_ec_keypair(p256_params, key_label)
        .map(|(_, priv_h)| priv_h)
        .or_else(|_| provider.find_private_key(key_label))
    {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[bench ecdsa_p256_pkcs11] key setup failed: {e} — skipping");
            return;
        }
    };

    let message = b"benchmark message for ECDSA-P256 sign";
    let signer = Pkcs11SignerBuilder::new(Arc::clone(&provider))
        .mechanism(SignMechanism::EcdsaSha256)
        .build();

    let mut group = c.benchmark_group("ecdsa_p256_sign");
    group.bench_function("pkcs11_softhsm2", |b| {
        b.iter(|| {
            signer
                .sign_with_handle(Mechanism::EcdsaSha256, priv_handle, black_box(message))
                .expect("pkcs11 sign")
        })
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Group 2: AES-256-GCM encrypt + decrypt (SoftHSM2 — skips if no module)
// ---------------------------------------------------------------------------

fn bench_aes_gcm_pkcs11(c: &mut Criterion) {
    use cryptoki::{
        mechanism::{aead::GcmParams, Mechanism},
        slot::Slot,
        types::Ulong,
    };
    use oxicrypto_adapter_pkcs11::{provider::Pkcs11Provider, sym::Pkcs11SymOp};

    let module_path = match std::env::var("SOFTHSM2_MODULE") {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => {
            eprintln!("[bench aes_gcm_pkcs11] SOFTHSM2_MODULE not set — skipping");
            return;
        }
    };

    let slot = Slot::try_from(0u64).expect("slot 0");
    let provider = match Pkcs11Provider::new(&module_path, slot, "1234") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[bench aes_gcm_pkcs11] provider open failed: {e} — skipping");
            return;
        }
    };

    let key_label = "bench-aes256-gcm";
    let key_handle = match provider
        .generate_aes_key(256, key_label)
        .or_else(|_| provider.find_secret_key(key_label))
    {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[bench aes_gcm_pkcs11] key setup failed: {e} — skipping");
            return;
        }
    };

    let sym = Pkcs11SymOp::new(&provider);
    let nonce = [0xBBu8; 12];
    let aad: &[u8] = b"bench-aad";
    let tag_bits = Ulong::from(128u64);

    // Encrypt benchmarks.
    for &payload_bytes in &[1024usize, 65536usize] {
        let plaintext = vec![0x42u8; payload_bytes];
        let label = format!("{payload_bytes}B");

        let mut group = c.benchmark_group("aes256_gcm_encrypt");
        group.throughput(criterion::Throughput::Bytes(payload_bytes as u64));
        group.bench_with_input(
            BenchmarkId::new("pkcs11_softhsm2", &label),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    let mut iv = nonce.to_vec();
                    let gcm = GcmParams::new(&mut iv, aad, tag_bits).expect("GcmParams");
                    let mech = Mechanism::AesGcm(gcm);
                    sym.encrypt(mech, key_handle, black_box(pt))
                        .expect("encrypt")
                })
            },
        );
        group.finish();
    }

    // Decrypt benchmarks.
    for &payload_bytes in &[1024usize, 65536usize] {
        let plaintext = vec![0x42u8; payload_bytes];
        let label = format!("{payload_bytes}B");

        // Pre-encrypt once to get the ciphertext for the decrypt bench.
        let ciphertext = {
            let mut iv = nonce.to_vec();
            let gcm = GcmParams::new(&mut iv, aad, tag_bits).expect("GcmParams");
            let mech = Mechanism::AesGcm(gcm);
            sym.encrypt(mech, key_handle, &plaintext)
                .expect("pre-encrypt")
        };

        let mut group = c.benchmark_group("aes256_gcm_decrypt");
        group.throughput(criterion::Throughput::Bytes(payload_bytes as u64));
        group.bench_with_input(
            BenchmarkId::new("pkcs11_softhsm2", &label),
            &ciphertext,
            |b, ct| {
                b.iter(|| {
                    let mut iv = nonce.to_vec();
                    let gcm = GcmParams::new(&mut iv, aad, tag_bits).expect("GcmParams");
                    let mech = Mechanism::AesGcm(gcm);
                    sym.decrypt(mech, key_handle, black_box(ct))
                        .expect("decrypt")
                })
            },
        );
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// Group 3: session pool checkout overhead (always runs — no HSM required)
// ---------------------------------------------------------------------------

/// Measure the `Arc<Mutex<Vec<Session>>>` checkout and idle_count overhead.
///
/// Hardware-free — always runs regardless of `SOFTHSM2_MODULE`.
/// Isolates the synchronisation cost from actual PKCS#11 operations.
fn bench_session_pool_checkout(c: &mut Criterion) {
    use oxicrypto_adapter_pkcs11::pool::Pkcs11SessionPool;

    let pool = Pkcs11SessionPool::new();

    let mut group = c.benchmark_group("session_pool_checkout");

    // Checkout from an empty pool: mutex acquire + VecDeque::pop + immediate drop.
    group.bench_function("empty_pool_checkout_return", |b| {
        b.iter(|| {
            let leased = pool.checkout().expect("checkout");
            // session is None — drop just releases the pool reference.
            black_box(leased.session.is_none())
        })
    });

    // idle_count: mutex acquire + VecDeque::len + release.
    group.bench_function("idle_count_query", |b| {
        b.iter(|| black_box(pool.idle_count().expect("idle_count")))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// criterion_group / criterion_main
// ---------------------------------------------------------------------------

criterion_group!(
    pkcs11_benches,
    bench_ecdsa_p256_software,
    bench_ecdsa_p256_pkcs11,
    bench_aes_gcm_pkcs11,
    bench_session_pool_checkout,
);
criterion_main!(pkcs11_benches);
