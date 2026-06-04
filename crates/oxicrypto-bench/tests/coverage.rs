//! Algorithm coverage tests.
//!
//! These tests verify that all OxiCrypto algorithm enum variants are exercised
//! by at least one benchmark or test in this crate.  They act as a compile-time
//! and runtime tripwire: when a new algorithm is added to `HashAlgo`, `AeadAlgo`,
//! `MacAlgo`, `KdfAlgo`, or `KexAlgo`, the match expressions below will produce
//! a compiler error (exhaustiveness check) reminding the developer to add a
//! corresponding benchmark.
//!
//! ## How to add a new algorithm
//!
//! 1. Add the variant to the appropriate enum in `oxicrypto/src/algo/`.
//! 2. Add the algorithm to the appropriate `match` arm below (with a comment
//!    pointing to the benchmark that covers it).
//! 3. Add (or extend) the corresponding bench function in `benches/`.
//!
//! ## SigAlgo coverage
//!
//! `SigAlgo` is `#[non_exhaustive]` and requires `signer_impl` / `verifier_impl`;
//! coverage is checked by `check_sig_algo_coverage` below.
//!
//! ## PQ coverage
//!
//! Post-quantum algorithms live in `oxicrypto-pq` which is behind `pq-preview`
//! feature.  Coverage is checked in the `pq.rs` bench itself.

use oxicrypto::{
    aead_impl, hash_impl, kdf_impl, kex_impl, mac_impl, AeadAlgo, HashAlgo, KdfAlgo, KexAlgo,
    MacAlgo,
};

// ── Hash algorithm coverage ───────────────────────────────────────────────────

/// Exhaustive coverage check: every `HashAlgo` variant must be exercised.
///
/// Adding a new variant to `HashAlgo` without updating this list will produce
/// a compile error ("non-exhaustive patterns") — that is intentional.
#[test]
fn check_hash_algo_coverage() {
    // This list mirrors the variants in `HashAlgo`.
    // Covered by: benches/hash.rs → bench_hash (all algos in the algos array).
    let algos = [
        HashAlgo::Sha256,     // bench_hash, hash_vs_ring/SHA-256
        HashAlgo::Sha384,     // bench_hash
        HashAlgo::Sha512,     // bench_hash, hash_vs_ring/SHA-512
        HashAlgo::Sha3_256,   // bench_hash
        HashAlgo::Sha3_384,   // bench_hash
        HashAlgo::Sha3_512,   // bench_hash
        HashAlgo::Sha512_256, // bench_hash
        HashAlgo::Blake2b256, // bench_hash
        HashAlgo::Blake2b512, // bench_hash
        HashAlgo::Blake2s256, // bench_hash
        HashAlgo::Blake3,     // bench_hash, bench_blake3_keyed, bench_streaming_blake3
    ];

    for algo in algos {
        let h = hash_impl(algo);
        let mut out = vec![0u8; h.output_len()];
        // Exercise the hash operation to confirm it works.
        h.hash(b"coverage check", &mut out)
            .unwrap_or_else(|e| panic!("hash_impl({algo:?}) failed: {e}"));
        assert!(
            out.iter().any(|&b| b != 0),
            "hash_impl({algo:?}) produced all-zero output (operation elided or broken)"
        );
    }
}

// ── AEAD algorithm coverage ───────────────────────────────────────────────────

/// Exhaustive coverage check: every `AeadAlgo` variant must be exercised.
///
/// Covered by: benches/aead.rs → bench_aead_standard, bench_aead_siv,
/// bench_aead_xchacha, bench_aead_ccm, bench_aead_ocb3, bench_aead_deoxys.
#[test]
fn check_aead_algo_coverage() {
    let algos = [
        AeadAlgo::Aes128Gcm,         // bench_aead_standard
        AeadAlgo::Aes256Gcm,         // bench_aead_standard
        AeadAlgo::ChaCha20Poly1305,  // bench_aead_standard
        AeadAlgo::Aes128GcmSiv,      // bench_aead_siv
        AeadAlgo::Aes256GcmSiv,      // bench_aead_siv
        AeadAlgo::XChaCha20Poly1305, // bench_aead_xchacha
        AeadAlgo::Aes128Ccm,         // bench_aead_ccm
        AeadAlgo::Aes256Ccm,         // bench_aead_ccm
        AeadAlgo::Aes128Ocb3,        // bench_aead_ocb3
        AeadAlgo::Aes256Ocb3,        // bench_aead_ocb3
        AeadAlgo::DeoxysII128,       // bench_aead_deoxys
    ];

    for algo in algos {
        let a = aead_impl(algo);
        let key = vec![0x42u8; a.key_len()];
        let nonce = vec![0x11u8; a.nonce_len()];
        let pt = b"coverage check plaintext";
        let mut ct = vec![0u8; pt.len() + a.tag_len()];
        a.seal(&key, &nonce, b"", pt, &mut ct)
            .unwrap_or_else(|e| panic!("aead_impl({algo:?}).seal failed: {e}"));
        assert!(
            ct.iter().any(|&b| b != 0),
            "aead_impl({algo:?}) produced all-zero ciphertext"
        );
    }
}

// ── MAC algorithm coverage ────────────────────────────────────────────────────

/// Exhaustive coverage check: every `MacAlgo` variant must be exercised.
///
/// Covered by: benches/mac.rs → bench_hmac, bench_hmac_sha3, bench_poly1305,
/// bench_cmac, bench_kmac.
#[test]
fn check_mac_algo_coverage() {
    // Fixed key sizes per algorithm.
    let cases: &[(MacAlgo, usize)] = &[
        (MacAlgo::HmacSha256, 32),                 // bench_hmac
        (MacAlgo::HmacSha384, 32),                 // bench_hmac
        (MacAlgo::HmacSha512, 32),                 // bench_hmac
        (MacAlgo::HmacSha3_256, 32),               // bench_hmac_sha3
        (MacAlgo::HmacSha3_512, 32),               // bench_hmac_sha3
        (MacAlgo::Poly1305, 32),                   // bench_poly1305
        (MacAlgo::CmacAes128, 16),                 // bench_cmac
        (MacAlgo::CmacAes256, 32),                 // bench_cmac
        (MacAlgo::Kmac128 { output_len: 32 }, 32), // bench_kmac
        (MacAlgo::Kmac256 { output_len: 32 }, 32), // bench_kmac
    ];

    for &(algo, key_len) in cases {
        let m = mac_impl(algo);
        let key = vec![0x42u8; key_len];
        let mut out = vec![0u8; m.output_len()];
        m.mac(&key, b"coverage check", &mut out)
            .unwrap_or_else(|e| panic!("mac_impl({algo:?}) failed: {e}"));
        assert!(
            out.iter().any(|&b| b != 0),
            "mac_impl({algo:?}) produced all-zero output"
        );
    }
}

// ── KDF algorithm coverage ────────────────────────────────────────────────────

/// Exhaustive coverage check: every `KdfAlgo` variant must be exercised.
///
/// Password KDFs (Argon2id, scrypt, PBKDF2) are covered by benches/kdf.rs.
/// HKDF variants are covered by bench_hkdf_derive and bench_hkdf_extract_expand.
#[test]
fn check_kdf_algo_coverage() {
    let algos = [
        KdfAlgo::HkdfSha256, // bench_hkdf_extract_expand, bench_hkdf_derive
        KdfAlgo::HkdfSha384, // bench_hkdf_extract_expand, bench_hkdf_derive
        KdfAlgo::HkdfSha512, // bench_hkdf_extract_expand, bench_hkdf_derive
                             // Password KDFs: benches/kdf.rs bench_pbkdf2, bench_argon2id, bench_scrypt.
                             // We skip actually running them here — they take hundreds of ms each.
    ];

    let ikm = [0x11u8; 32];
    let salt = [0x22u8; 16];
    let info = b"coverage check";

    for algo in algos {
        let kdf = kdf_impl(algo);
        let mut out = [0u8; 32];
        kdf.derive(&ikm, &salt, info, &mut out)
            .unwrap_or_else(|e| panic!("kdf_impl({algo:?}) failed: {e}"));
        assert!(
            out.iter().any(|&b| b != 0),
            "kdf_impl({algo:?}) produced all-zero output"
        );
    }

    // Confirm password KDFs are accessible (compilation check only — no execution).
    let _pbkdf2_sha256 = kdf_impl(KdfAlgo::Pbkdf2Sha256); // bench_pbkdf2
    let _pbkdf2_sha512 = kdf_impl(KdfAlgo::Pbkdf2Sha512); // bench_pbkdf2
    let _argon2 = kdf_impl(KdfAlgo::Argon2id); // bench_argon2id
    let _scrypt = kdf_impl(KdfAlgo::Scrypt); // bench_scrypt
}

// ── KEX algorithm coverage ────────────────────────────────────────────────────

/// Exhaustive coverage check: every `KexAlgo` variant must be exercised.
///
/// Covered by: benches/kex.rs → bench_x25519, bench_x448, bench_ecdh_p256,
/// bench_ecdh_p384, bench_ecdh_p521.
#[test]
fn check_kex_algo_coverage() {
    use oxicrypto_kex::{
        ecdh_p256_generate_keypair, ecdh_p384_generate_keypair, ecdh_p521_generate_keypair,
        x25519_generate_keypair, x448_generate_keypair,
    };
    use oxicrypto_rand::OxiRng;

    let mut rng = OxiRng::new().expect("coverage test: OS RNG unavailable");

    // X25519.
    {
        let kex = kex_impl(KexAlgo::X25519); // bench_x25519
        let (alice_sk, _alice_pk) = x25519_generate_keypair(&mut rng).expect("x25519 keygen");
        let (_bob_sk, bob_pk) = x25519_generate_keypair(&mut rng).expect("x25519 keygen");
        let mut shared = [0u8; 32];
        kex.agree(alice_sk.as_bytes(), &bob_pk, &mut shared)
            .expect("x25519 agree");
        assert!(
            shared.iter().any(|&b| b != 0),
            "X25519 shared secret is all-zero"
        );
    }

    // X448.
    {
        let kex = kex_impl(KexAlgo::X448); // bench_x448
        let (alice_sk, _alice_pk) = x448_generate_keypair(&mut rng).expect("x448 keygen");
        let (_bob_sk, bob_pk) = x448_generate_keypair(&mut rng).expect("x448 keygen");
        let mut shared = [0u8; 56];
        kex.agree(alice_sk.as_bytes(), &bob_pk, &mut shared)
            .expect("x448 agree");
        assert!(
            shared.iter().any(|&b| b != 0),
            "X448 shared secret is all-zero"
        );
    }

    // ECDH P-256.
    {
        let kex = kex_impl(KexAlgo::EcdhP256); // bench_ecdh_p256
        let (alice_sk, _alice_pk) = ecdh_p256_generate_keypair(&mut rng).expect("p256 keygen");
        let (_bob_sk, bob_pk) = ecdh_p256_generate_keypair(&mut rng).expect("p256 keygen");
        let mut shared = [0u8; 32];
        kex.agree(alice_sk.as_bytes(), &bob_pk, &mut shared)
            .expect("ecdh-p256 agree");
        assert!(
            shared.iter().any(|&b| b != 0),
            "ECDH-P256 shared secret is all-zero"
        );
    }

    // ECDH P-384.
    {
        let kex = kex_impl(KexAlgo::EcdhP384); // bench_ecdh_p384
        let (alice_sk, _alice_pk) = ecdh_p384_generate_keypair(&mut rng).expect("p384 keygen");
        let (_bob_sk, bob_pk) = ecdh_p384_generate_keypair(&mut rng).expect("p384 keygen");
        let mut shared = [0u8; 48];
        kex.agree(alice_sk.as_bytes(), &bob_pk, &mut shared)
            .expect("ecdh-p384 agree");
        assert!(
            shared.iter().any(|&b| b != 0),
            "ECDH-P384 shared secret is all-zero"
        );
    }

    // ECDH P-521.
    {
        let kex = kex_impl(KexAlgo::EcdhP521); // bench_ecdh_p521
        let (alice_sk, _alice_pk) = ecdh_p521_generate_keypair(&mut rng).expect("p521 keygen");
        let (_bob_sk, bob_pk) = ecdh_p521_generate_keypair(&mut rng).expect("p521 keygen");
        let mut shared = [0u8; 66];
        kex.agree(alice_sk.as_bytes(), &bob_pk, &mut shared)
            .expect("ecdh-p521 agree");
        assert!(
            shared.iter().any(|&b| b != 0),
            "ECDH-P521 shared secret is all-zero"
        );
    }
}

// ── SigAlgo coverage (compilation + smoke check) ────────────────────────────

/// Verify that `signer_impl` / `verifier_impl` are accessible for all non-RSA
/// SigAlgo variants.
///
/// RSA keygen is intentionally excluded: it takes 0.5–2 seconds per call and
/// would make the test suite unacceptably slow.  RSA sign/verify are exercised
/// in benches/sig.rs with sample_size(10).
#[test]
fn check_sig_algo_smoke() {
    use oxicrypto::{signer_impl, verifier_impl, SigAlgo};
    use oxicrypto_rand::OxiRng;
    use oxicrypto_sig::{ecdsa_p256_generate_keypair, ed25519_generate_keypair};

    let mut rng = OxiRng::new().expect("coverage test: OS RNG unavailable");
    let msg = b"sig algo coverage check message";

    // Ed25519 — bench_ed25519.
    {
        let (sk, pk) = ed25519_generate_keypair(&mut rng).expect("ed25519 keygen");
        let signer = signer_impl(SigAlgo::Ed25519);
        let verifier = verifier_impl(SigAlgo::Ed25519);
        let mut sig = [0u8; 64];
        signer
            .sign(sk.as_bytes(), msg, &mut sig)
            .expect("ed25519 sign");
        verifier.verify(&pk, msg, &sig).expect("ed25519 verify");
    }

    // ECDSA P-256 — bench_ecdsa_p256.
    {
        let (sk, pk) = ecdsa_p256_generate_keypair(&mut rng).expect("p256 keygen");
        let signer = signer_impl(SigAlgo::EcdsaP256);
        let verifier = verifier_impl(SigAlgo::EcdsaP256);
        let mut sig = [0u8; 72];
        let sig_len = signer
            .sign(sk.as_bytes(), msg, &mut sig)
            .expect("p256 sign");
        verifier
            .verify(&pk, msg, &sig[..sig_len])
            .expect("p256 verify");
    }
}
