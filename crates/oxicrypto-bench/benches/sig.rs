//! Signature benchmarks: all OxiCrypto signature algorithms.
//!
//! Covers Ed25519, Ed448, ECDSA P-256/P-384/P-521, RSA PKCS#1v15/PSS,
//! Schnorr BIP-340, and Ed25519 batch verification.
//!
//! Key generation, sign, and verify operations are measured separately so that
//! per-operation latency is visible independent of setup cost.
//!
//! RSA operations use `sample_size(10)` because 2048-bit key generation takes
//! 0.5–2 seconds and sign/verify is order-of-magnitude slower than ECC.
//!
//! # ring comparison
//!
//! Ed25519 and ECDSA P-256 groups include a `ring-*` sub-benchmark using
//! `ring 0.17` as a reference implementation. ring is a dev-dependency of
//! this bench crate only and never appears on the default dependency closure.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};
use oxicrypto::{signer_impl, verifier_impl, SigAlgo};
use oxicrypto_rand::OxiRng;
use oxicrypto_sig::{
    ecdsa_p256_generate_keypair, ecdsa_p384_generate_keypair, ecdsa_p521_generate_keypair,
    ed25519_generate_keypair, ed25519_verify_batch, ed448_generate_keypair, rsa_generate_keypair,
    schnorr_bip340_generate_keypair, Ed448SigningKey, Ed448VerifyingKey,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_rng() -> OxiRng {
    OxiRng::new().expect("bench setup: OS RNG unavailable")
}

// ── Ed25519 ───────────────────────────────────────────────────────────────────

fn bench_ed25519(c: &mut Criterion) {
    let mut rng = make_rng();
    let msg = b"oxicrypto benchmark message for signature operations -- Ed25519";

    let (ed_sk, ed_pk) = ed25519_generate_keypair(&mut rng).expect("ed25519 keygen");
    let ed_signer = signer_impl(SigAlgo::Ed25519);
    let ed_verifier = verifier_impl(SigAlgo::Ed25519);

    // Pre-compute a valid signature for the verify bench.
    let mut ed_sig = [0u8; 64];
    let ed_sk_bytes = *ed_sk.as_bytes();
    ed_signer
        .sign(&ed_sk_bytes, msg, &mut ed_sig)
        .expect("ed25519 pre-sign failed");

    let mut group = c.benchmark_group("sig/Ed25519");

    group.bench_function("keygen", |b| {
        b.iter(|| {
            ed25519_generate_keypair(&mut rng).expect("ed25519 keygen");
        });
    });

    group.bench_function("sign", |b| {
        let mut buf = [0u8; 64];
        b.iter(|| {
            ed_signer
                .sign(&ed_sk_bytes, msg, &mut buf)
                .expect("ed25519 sign");
        });
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            ed_verifier
                .verify(&ed_pk, msg, &ed_sig)
                .expect("ed25519 verify");
        });
    });

    // ── ring comparison ────────────────────────────────────────────────────────
    // ring 0.17 Ed25519: sign via Ed25519KeyPair, verify via signature::UnparsedPublicKey.
    {
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

        let rng_ring = SystemRandom::new();
        let pkcs8_bytes =
            Ed25519KeyPair::generate_pkcs8(&rng_ring).expect("ring ed25519 keygen (bench setup)");
        let ring_kp = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).expect("ring ed25519 parse");
        let ring_pk_bytes = ring_kp.public_key().as_ref().to_vec();
        let ring_sig = ring_kp.sign(msg);
        let ring_sig_bytes = ring_sig.as_ref().to_vec();

        group.bench_function("ring-sign", |b| {
            b.iter(|| {
                ring_kp.sign(msg);
            });
        });

        group.bench_function("ring-verify", |b| {
            b.iter(|| {
                let pk = UnparsedPublicKey::new(&ED25519, &ring_pk_bytes);
                pk.verify(msg, &ring_sig_bytes)
                    .expect("ring ed25519 verify");
            });
        });
    }

    group.finish();
}

// ── Ed448 ─────────────────────────────────────────────────────────────────────

fn bench_ed448(c: &mut Criterion) {
    let mut rng = make_rng();
    let msg = b"oxicrypto benchmark message -- Ed448 RFC 8032";

    let (ed448_sk_vec, ed448_pk) = ed448_generate_keypair(&mut rng).expect("ed448 keygen");
    let ed448_sk_bytes = ed448_sk_vec.as_bytes().to_vec();

    // Pre-compute a valid signature.
    let signing_key =
        Ed448SigningKey::from_bytes(&ed448_sk_bytes).expect("ed448 sk parse (bench setup)");
    let ed448_sig = signing_key.sign(msg).expect("ed448 pre-sign (bench setup)");
    let verifying_key =
        Ed448VerifyingKey::from_bytes(&ed448_pk).expect("ed448 vk parse (bench setup)");

    let mut group = c.benchmark_group("sig/Ed448");

    group.bench_function("keygen", |b| {
        b.iter(|| {
            ed448_generate_keypair(&mut rng).expect("ed448 keygen");
        });
    });

    group.bench_function("sign", |b| {
        b.iter(|| {
            signing_key.sign(msg).expect("ed448 sign");
        });
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            verifying_key.verify(msg, &ed448_sig).expect("ed448 verify");
        });
    });

    group.finish();
}

// ── Ed25519 batch verification ────────────────────────────────────────────────

fn bench_ed25519_batch_verify(c: &mut Criterion) {
    use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

    let mut rng = make_rng();
    // Maximum batch size for the most expensive benchmark.
    const MAX_BATCH: usize = 1000;

    // Generate MAX_BATCH key pairs and pre-sign messages.
    let msg_template = b"oxicrypto batch verification benchmark message -- fixed";
    let mut signing_keys: Vec<SigningKey> = Vec::with_capacity(MAX_BATCH);
    let mut verifying_keys_all: Vec<VerifyingKey> = Vec::with_capacity(MAX_BATCH);
    let mut signatures_all: Vec<Signature> = Vec::with_capacity(MAX_BATCH);
    let mut messages_all: Vec<Vec<u8>> = Vec::with_capacity(MAX_BATCH);

    for i in 0..MAX_BATCH {
        let (sk_secret, _) = ed25519_generate_keypair(&mut rng).expect("ed25519 keygen batch");
        let sk = SigningKey::from_bytes(sk_secret.as_bytes());
        let vk = sk.verifying_key();
        // Vary the message by appending an index to prevent trivial optimization.
        let mut m = msg_template.to_vec();
        m.extend_from_slice(&(i as u64).to_le_bytes());
        let sig: Signature = {
            use ed25519_dalek::Signer;
            sk.sign(&m)
        };
        messages_all.push(m);
        signatures_all.push(sig);
        verifying_keys_all.push(vk);
        signing_keys.push(sk);
    }

    let mut group = c.benchmark_group("sig/Ed25519-BatchVerify");

    for &batch_size in &[10usize, 100, 1000] {
        let msgs: Vec<&[u8]> = messages_all[..batch_size]
            .iter()
            .map(|v| v.as_slice())
            .collect();
        let sigs = &signatures_all[..batch_size];
        let vks = &verifying_keys_all[..batch_size];

        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    ed25519_verify_batch(&msgs, sigs, vks).expect("batch verify");
                });
            },
        );
    }

    group.finish();
}

// ── ECDSA P-256 ───────────────────────────────────────────────────────────────

fn bench_ecdsa_p256(c: &mut Criterion) {
    let mut rng = make_rng();
    let msg = b"oxicrypto benchmark message -- ECDSA P-256";

    let (p256_sk, p256_pk) = ecdsa_p256_generate_keypair(&mut rng).expect("p256 keygen");
    let p256_signer = signer_impl(SigAlgo::EcdsaP256);
    let p256_verifier = verifier_impl(SigAlgo::EcdsaP256);

    // DER signature is variable length (≤72 bytes).
    let mut p256_sig_buf = [0u8; 72];
    let p256_sk_bytes = p256_sk.as_bytes().to_vec();
    let sig_len = p256_signer
        .sign(&p256_sk_bytes, msg, &mut p256_sig_buf)
        .expect("p256 pre-sign failed");
    let p256_sig = p256_sig_buf[..sig_len].to_vec();

    let mut group = c.benchmark_group("sig/ECDSA-P256");

    group.bench_function("keygen", |b| {
        b.iter(|| {
            ecdsa_p256_generate_keypair(&mut rng).expect("p256 keygen");
        });
    });

    group.bench_function("sign", |b| {
        let mut buf = [0u8; 72];
        b.iter(|| {
            p256_signer
                .sign(&p256_sk_bytes, msg, &mut buf)
                .expect("p256 sign");
        });
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            p256_verifier
                .verify(&p256_pk, msg, &p256_sig)
                .expect("p256 verify");
        });
    });

    // ── ring comparison ────────────────────────────────────────────────────────
    // ring 0.17 ECDSA P-256 SHA-256 (fixed-length signature).
    {
        use ring::rand::SystemRandom;
        use ring::signature::{
            EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
            ECDSA_P256_SHA256_ASN1_SIGNING,
        };

        let rng_ring = SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng_ring)
            .expect("ring p256 keygen (bench setup)");
        let ring_kp = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8_bytes.as_ref(),
            &rng_ring,
        )
        .expect("ring p256 parse");
        let ring_pk_bytes = ring_kp.public_key().as_ref().to_vec();
        let ring_sig = ring_kp
            .sign(&rng_ring, msg)
            .expect("ring p256 sign (setup)");
        let ring_sig_bytes = ring_sig.as_ref().to_vec();

        group.bench_function("ring-sign", |b| {
            b.iter(|| {
                ring_kp.sign(&rng_ring, msg).expect("ring p256 sign");
            });
        });

        group.bench_function("ring-verify", |b| {
            b.iter(|| {
                let pk = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &ring_pk_bytes);
                pk.verify(msg, &ring_sig_bytes).expect("ring p256 verify");
            });
        });
    }

    group.finish();
}

// ── ECDSA P-384 ───────────────────────────────────────────────────────────────

fn bench_ecdsa_p384(c: &mut Criterion) {
    let mut rng = make_rng();
    let msg = b"oxicrypto benchmark message -- ECDSA P-384";

    let (p384_sk, p384_pk) = ecdsa_p384_generate_keypair(&mut rng).expect("p384 keygen");
    let p384_signer = signer_impl(SigAlgo::EcdsaP384);
    let p384_verifier = verifier_impl(SigAlgo::EcdsaP384);

    // DER signature for P-384 is ≤104 bytes.
    let mut p384_sig_buf = [0u8; 104];
    let p384_sk_bytes = p384_sk.as_bytes().to_vec();
    let sig_len = p384_signer
        .sign(&p384_sk_bytes, msg, &mut p384_sig_buf)
        .expect("p384 pre-sign failed");
    let p384_sig = p384_sig_buf[..sig_len].to_vec();

    let mut group = c.benchmark_group("sig/ECDSA-P384");

    group.bench_function("keygen", |b| {
        b.iter(|| {
            ecdsa_p384_generate_keypair(&mut rng).expect("p384 keygen");
        });
    });

    group.bench_function("sign", |b| {
        let mut buf = [0u8; 104];
        b.iter(|| {
            p384_signer
                .sign(&p384_sk_bytes, msg, &mut buf)
                .expect("p384 sign");
        });
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            p384_verifier
                .verify(&p384_pk, msg, &p384_sig)
                .expect("p384 verify");
        });
    });

    group.finish();
}

// ── ECDSA P-521 ───────────────────────────────────────────────────────────────

fn bench_ecdsa_p521(c: &mut Criterion) {
    let mut rng = make_rng();
    let msg = b"oxicrypto benchmark message -- ECDSA P-521";

    let (p521_sk, p521_pk) = ecdsa_p521_generate_keypair(&mut rng).expect("p521 keygen");
    let p521_signer = signer_impl(SigAlgo::EcdsaP521);
    let p521_verifier = verifier_impl(SigAlgo::EcdsaP521);

    // DER signature for P-521 is ≤139 bytes.
    let mut p521_sig_buf = [0u8; 139];
    let p521_sk_bytes = p521_sk.as_bytes().to_vec();
    let sig_len = p521_signer
        .sign(&p521_sk_bytes, msg, &mut p521_sig_buf)
        .expect("p521 pre-sign failed");
    let p521_sig = p521_sig_buf[..sig_len].to_vec();

    let mut group = c.benchmark_group("sig/ECDSA-P521");

    group.bench_function("keygen", |b| {
        b.iter(|| {
            ecdsa_p521_generate_keypair(&mut rng).expect("p521 keygen");
        });
    });

    group.bench_function("sign", |b| {
        let mut buf = [0u8; 139];
        b.iter(|| {
            p521_signer
                .sign(&p521_sk_bytes, msg, &mut buf)
                .expect("p521 sign");
        });
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            p521_verifier
                .verify(&p521_pk, msg, &p521_sig)
                .expect("p521 verify");
        });
    });

    group.finish();
}

// ── Schnorr BIP-340 ───────────────────────────────────────────────────────────

fn bench_schnorr_bip340(c: &mut Criterion) {
    let mut rng = make_rng();
    let msg = b"oxicrypto benchmark message -- BIP-340 Schnorr secp256k1";

    let (sk_secret, pk) =
        schnorr_bip340_generate_keypair(&mut rng).expect("schnorr keygen (bench setup)");
    let sk_bytes = *sk_secret.as_bytes();

    let schnorr = signer_impl(SigAlgo::SchnorrBip340);
    let schnorr_v = verifier_impl(SigAlgo::SchnorrBip340);

    let mut sig_buf = [0u8; 64];
    schnorr
        .sign(&sk_bytes, msg, &mut sig_buf)
        .expect("schnorr pre-sign (bench setup)");
    let schnorr_sig = sig_buf;

    let mut group = c.benchmark_group("sig/Schnorr-BIP340");

    group.bench_function("keygen", |b| {
        b.iter(|| {
            schnorr_bip340_generate_keypair(&mut rng).expect("schnorr keygen");
        });
    });

    group.bench_function("sign", |b| {
        let mut buf = [0u8; 64];
        b.iter(|| {
            schnorr
                .sign(&sk_bytes, msg, &mut buf)
                .expect("schnorr sign");
        });
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            schnorr_v
                .verify(&pk, msg, &schnorr_sig)
                .expect("schnorr verify");
        });
    });

    group.finish();
}

// ── RSA-2048 PKCS#1v15 ────────────────────────────────────────────────────────

fn bench_rsa_pkcs1v15(c: &mut Criterion) {
    let msg = b"oxicrypto benchmark message -- RSA-2048 PKCS#1v15";

    // RSA key generation is expensive; generate once before the bench groups.
    // rsa_generate_keypair returns (PKCS#8-DER secret key, SPKI-DER public key).
    let (rsa_sk_der, rsa_pk_der) =
        rsa_generate_keypair(2048).expect("rsa-2048 keygen (bench setup)");

    let rsa_signer = signer_impl(SigAlgo::RsaPkcs1v15Sha256);
    let rsa_verifier = verifier_impl(SigAlgo::RsaPkcs1v15Sha256);

    // RSA-2048 signature is exactly 256 bytes.
    let mut rsa_sig_buf = [0u8; 512];
    let sig_len = rsa_signer
        .sign(&rsa_sk_der, msg, &mut rsa_sig_buf)
        .expect("rsa pre-sign failed");
    let rsa_sig = rsa_sig_buf[..sig_len].to_vec();

    let mut group = c.benchmark_group("sig/RSA-PKCS1v15-SHA256");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    // Keygen is too slow to measure in a tight loop; include as single-shot.
    group.bench_function("keygen-2048", |b| {
        b.iter(|| {
            rsa_generate_keypair(2048).expect("rsa-2048 keygen");
        });
    });

    group.bench_function("sign-2048", |b| {
        let mut buf = [0u8; 512];
        b.iter(|| {
            rsa_signer
                .sign(&rsa_sk_der, msg, &mut buf)
                .expect("rsa sign");
        });
    });

    group.bench_function("verify-2048", |b| {
        b.iter(|| {
            rsa_verifier
                .verify(&rsa_pk_der, msg, &rsa_sig)
                .expect("rsa verify");
        });
    });

    group.finish();
}

// ── RSA key generation: 2048 / 3072 / 4096 bits ──────────────────────────────

fn bench_rsa_keygen(c: &mut Criterion) {
    // Profiling RSA key generation across bit sizes.
    // Each sample is extremely slow (2–30 seconds) so use minimal iteration counts.
    let mut group = c.benchmark_group("sig/RSA-keygen");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    for &bits in &[2048usize, 3072, 4096] {
        group.bench_with_input(BenchmarkId::from_parameter(bits), &bits, |b, &bits| {
            b.iter(|| {
                rsa_generate_keypair(bits).expect("rsa keygen");
            });
        });
    }

    group.finish();
}

// ── RSA-PSS SHA-256 ───────────────────────────────────────────────────────────

fn bench_rsa_pss(c: &mut Criterion) {
    let msg = b"oxicrypto benchmark message -- RSA-PSS-SHA256 sign/verify";

    let (rsa_sk_der, rsa_pk_der) =
        rsa_generate_keypair(2048).expect("rsa-2048 keygen (bench setup)");

    let pss_signer = signer_impl(SigAlgo::RsaPssSha256);
    let pss_verifier = verifier_impl(SigAlgo::RsaPssSha256);

    let mut rsa_sig_buf = [0u8; 512];
    let sig_len = pss_signer
        .sign(&rsa_sk_der, msg, &mut rsa_sig_buf)
        .expect("rsa-pss pre-sign failed");
    let rsa_pss_sig = rsa_sig_buf[..sig_len].to_vec();

    let mut group = c.benchmark_group("sig/RSA-PSS-SHA256");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    group.bench_function("sign-2048", |b| {
        let mut buf = [0u8; 512];
        b.iter(|| {
            pss_signer
                .sign(&rsa_sk_der, msg, &mut buf)
                .expect("rsa-pss sign");
        });
    });

    group.bench_function("verify-2048", |b| {
        b.iter(|| {
            pss_verifier
                .verify(&rsa_pk_der, msg, &rsa_pss_sig)
                .expect("rsa-pss verify");
        });
    });

    group.finish();
}

// ── Criterion wiring ──────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_ed25519,
    bench_ed448,
    bench_ed25519_batch_verify,
    bench_ecdsa_p256,
    bench_ecdsa_p384,
    bench_ecdsa_p521,
    bench_schnorr_bip340,
    bench_rsa_pkcs1v15,
    bench_rsa_pss,
    bench_rsa_keygen,
);
criterion_main!(benches);
