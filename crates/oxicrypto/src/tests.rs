use crate::*;

// ── Hash round-trips ──────────────────────────────────────────────────────

#[test]
fn all_hash_algos_produce_output() {
    let algos = [
        HashAlgo::Sha256,
        HashAlgo::Sha384,
        HashAlgo::Sha512,
        HashAlgo::Sha3_256,
        HashAlgo::Sha3_384,
        HashAlgo::Sha3_512,
        HashAlgo::Blake3,
    ];
    for algo in algos {
        let h = hash_impl(algo);
        let out = h.hash_to_vec(b"test").expect("hash failed");
        assert_eq!(
            out.len(),
            h.output_len(),
            "{} output length mismatch",
            h.name()
        );
    }
}

// ── AEAD round-trips ──────────────────────────────────────────────────────

fn aead_round_trip(algo: AeadAlgo, key: &[u8]) {
    let a = aead_impl(algo);
    let nonce = vec![0x11u8; a.nonce_len()];
    let pt = b"facade round-trip test";
    let aad = b"facade aad";
    let mut ct = vec![0u8; pt.len() + a.tag_len()];
    let written = a.seal(key, &nonce, aad, pt, &mut ct).expect("seal failed");
    let mut pt2 = vec![0u8; pt.len()];
    let recovered = a
        .open(key, &nonce, aad, &ct[..written], &mut pt2)
        .expect("open failed");
    assert_eq!(&pt2[..recovered], pt.as_ref());
}

#[test]
fn aes128gcm_facade_round_trip() {
    aead_round_trip(AeadAlgo::Aes128Gcm, &[0x42u8; 16]);
}

#[test]
fn aes256gcm_facade_round_trip() {
    aead_round_trip(AeadAlgo::Aes256Gcm, &[0x42u8; 32]);
}

#[test]
fn chacha20poly1305_facade_round_trip() {
    aead_round_trip(AeadAlgo::ChaCha20Poly1305, &[0x42u8; 32]);
}

#[test]
fn aes128gcm_siv_facade_round_trip() {
    aead_round_trip(AeadAlgo::Aes128GcmSiv, &[0x42u8; 16]);
}

#[test]
fn aes256gcm_siv_facade_round_trip() {
    aead_round_trip(AeadAlgo::Aes256GcmSiv, &[0x42u8; 32]);
}

#[test]
fn xchacha20poly1305_facade_round_trip() {
    aead_round_trip(AeadAlgo::XChaCha20Poly1305, &[0x42u8; 32]);
}

#[test]
fn aes128ccm_facade_round_trip() {
    // CCM uses 13-byte nonces; aead_round_trip uses a.nonce_len() so this Just Works.
    aead_round_trip(AeadAlgo::Aes128Ccm, &[0x42u8; 16]);
}

#[test]
fn aes256ccm_facade_round_trip() {
    aead_round_trip(AeadAlgo::Aes256Ccm, &[0x42u8; 32]);
}

#[test]
fn aes128ocb3_facade_round_trip() {
    aead_round_trip(AeadAlgo::Aes128Ocb3, &[0x42u8; 16]);
}

#[test]
fn aes256ocb3_facade_round_trip() {
    aead_round_trip(AeadAlgo::Aes256Ocb3, &[0x42u8; 32]);
}

#[test]
fn deoxys_ii_128_facade_round_trip() {
    // Deoxys-II-128-128 uses a 16-byte key and 16-byte nonce; aead_round_trip
    // pulls the nonce length from a.nonce_len() so this Just Works.
    aead_round_trip(AeadAlgo::DeoxysII128, &[0u8; 16]);
}

#[test]
fn aead_nonce_lengths() {
    assert_eq!(
        aead_impl(AeadAlgo::Aes128Ccm).nonce_len(),
        13,
        "AES-128-CCM nonce must be 13 bytes"
    );
    assert_eq!(
        aead_impl(AeadAlgo::Aes256Ccm).nonce_len(),
        13,
        "AES-256-CCM nonce must be 13 bytes"
    );
    assert_eq!(
        aead_impl(AeadAlgo::Aes128Ocb3).nonce_len(),
        12,
        "AES-128-OCB3 nonce must be 12 bytes"
    );
    assert_eq!(
        aead_impl(AeadAlgo::Aes256Ocb3).nonce_len(),
        12,
        "AES-256-OCB3 nonce must be 12 bytes"
    );
    assert_eq!(
        aead_impl(AeadAlgo::XChaCha20Poly1305).nonce_len(),
        24,
        "XChaCha20 nonce must be 24 bytes"
    );
}

// ── MAC round-trips ───────────────────────────────────────────────────────

fn mac_round_trip(algo: MacAlgo) {
    let m = mac_impl(algo);
    let key = vec![0x55u8; m.key_len()];
    let mut tag = vec![0u8; m.output_len()];
    m.mac(&key, b"msg", &mut tag).expect("mac failed");
    m.verify(&key, b"msg", &tag).expect("verify failed");
    // Verify wrong message fails
    let result = m.verify(&key, b"bad", &tag);
    assert_eq!(
        result,
        Err(CryptoError::InvalidTag),
        "wrong msg must fail verify for {}",
        m.name()
    );
}

#[test]
fn all_mac_algos_verify_ok() {
    // Standard HMAC variants
    for algo in [
        MacAlgo::HmacSha256,
        MacAlgo::HmacSha384,
        MacAlgo::HmacSha512,
    ] {
        mac_round_trip(algo);
    }
}

#[test]
fn mac_hmac_sha3_variants() {
    mac_round_trip(MacAlgo::HmacSha3_256);
    mac_round_trip(MacAlgo::HmacSha3_512);
}

#[test]
fn mac_poly1305_round_trip() {
    // Poly1305 one-time MAC: key must be 32 bytes, tag is 16 bytes
    let m = mac_impl(MacAlgo::Poly1305);
    assert_eq!(m.key_len(), 32);
    assert_eq!(m.output_len(), 16);
    let key = vec![0xAAu8; 32];
    let mut tag = [0u8; 16];
    m.mac(&key, b"one-time test", &mut tag)
        .expect("poly1305 mac failed");
    m.verify(&key, b"one-time test", &tag)
        .expect("poly1305 verify failed");
}

#[test]
fn mac_cmac_variants() {
    mac_round_trip(MacAlgo::CmacAes128);
    mac_round_trip(MacAlgo::CmacAes256);
}

#[test]
fn mac_kmac128_round_trip() {
    mac_round_trip(MacAlgo::Kmac128 { output_len: 32 });
}

#[test]
fn mac_kmac256_round_trip() {
    mac_round_trip(MacAlgo::Kmac256 { output_len: 64 });
}

#[test]
fn mac_kmac_variable_output() {
    // KMAC can produce any output length >= 1
    for &output_len in &[16usize, 32, 48, 64] {
        let m = mac_impl(MacAlgo::Kmac128 { output_len });
        assert_eq!(m.output_len(), output_len, "Kmac128 output_len mismatch");
        let key = vec![0x42u8; 16];
        let mut tag = vec![0u8; output_len];
        m.mac(&key, b"variable length test", &mut tag)
            .expect("kmac128 mac failed");
        m.verify(&key, b"variable length test", &tag)
            .expect("kmac128 verify failed");
    }
}

// ── Signature round-trip ──────────────────────────────────────────────────

#[test]
fn ed25519_facade_sign_verify() {
    use ed25519_dalek::SigningKey;
    let seed = [0xddu8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pk = signing_key.verifying_key().to_bytes();

    let signer = signer_impl(SigAlgo::Ed25519);
    let verifier = verifier_impl(SigAlgo::Ed25519);
    let msg = b"facade Ed25519 test";
    let mut sig = vec![0u8; signer.signature_len()];
    signer.sign(&seed, msg, &mut sig).expect("sign failed");
    verifier.verify(&pk, msg, &sig).expect("verify failed");
}

#[test]
fn schnorr_bip340_facade_sign_verify() {
    // BIP-340 secret key: any valid 32-byte secp256k1 scalar in 1..n.
    let sk = [0x42u8; 32];
    // Derive the x-only public key via the same combined Signer+Verifier type.
    let pk = oxicrypto_sig::SchnorrBip340
        .derive_public_key(&sk)
        .expect("derive x-only public key failed");

    let signer = signer_impl(SigAlgo::SchnorrBip340);
    let verifier = verifier_impl(SigAlgo::SchnorrBip340);
    assert_eq!(signer.name(), "Schnorr-BIP340");
    assert_eq!(verifier.name(), "Schnorr-BIP340");

    // BIP-340 signs the message directly (no pre-hashing); use a 32-byte message.
    let msg = [0x9au8; 32];
    let mut sig = vec![0u8; signer.signature_len()];
    let n = signer.sign(&sk, &msg, &mut sig).expect("sign failed");
    assert_eq!(n, 64, "BIP-340 signature must be 64 bytes");
    verifier.verify(&pk, &msg, &sig).expect("verify failed");

    // A tampered message must fail verification.
    let bad_msg = [0x9bu8; 32];
    assert!(
        verifier.verify(&pk, &bad_msg, &sig).is_err(),
        "verification of a tampered message must fail"
    );
}

// ── KEX round-trips ──────────────────────────────────────────────────────

#[test]
fn x25519_facade_agree() {
    use x25519_dalek::{PublicKey, StaticSecret};
    let alice_sk = [0xaau8; 32];
    let bob_sk = [0xbbu8; 32];
    let alice_pub = *PublicKey::from(&StaticSecret::from(alice_sk)).as_bytes();
    let bob_pub = *PublicKey::from(&StaticSecret::from(bob_sk)).as_bytes();

    let kex = kex_impl(KexAlgo::X25519);
    let mut s1 = [0u8; 32];
    let mut s2 = [0u8; 32];
    kex.agree(&alice_sk, &bob_pub, &mut s1)
        .expect("agree 1 failed");
    kex.agree(&bob_sk, &alice_pub, &mut s2)
        .expect("agree 2 failed");
    assert_eq!(s1, s2);
}

#[test]
fn ecdh_p256_facade_agree() {
    let kex = kex_impl(KexAlgo::EcdhP256);
    assert_eq!(kex.name(), "ECDH-P256");
    assert_eq!(kex.scalar_len(), 32);
}

#[test]
fn ecdh_p384_facade_agree() {
    let kex = kex_impl(KexAlgo::EcdhP384);
    assert_eq!(kex.name(), "ECDH-P384");
    assert_eq!(kex.scalar_len(), 48);
}

// ── KDF round-trips ───────────────────────────────────────────────────────

#[test]
fn all_kdf_algos_produce_output() {
    for algo in [
        KdfAlgo::HkdfSha256,
        KdfAlgo::HkdfSha384,
        KdfAlgo::HkdfSha512,
    ] {
        let kdf = kdf_impl(algo);
        let mut okm = vec![0u8; 32];
        kdf.derive(b"ikm", b"salt", b"info", &mut okm)
            .expect("derive failed");
        assert_ne!(okm, vec![0u8; 32]);
    }
}

// ── RNG ───────────────────────────────────────────────────────────────────

#[test]
fn new_rng_fills_buffer() {
    let mut rng = new_rng().expect("new_rng failed");
    let mut buf = [0u8; 32];
    rng.fill(&mut buf).expect("fill failed");
    assert_ne!(buf, [0u8; 32]);
}

// ── SIMD / cpu_info ──────────────────────────────────────────────────────

#[cfg(feature = "simd")]
#[test]
fn simd_cpu_info_non_panic() {
    let info1 = crate::simd::cpu_info();
    let info2 = crate::simd::cpu_info();
    assert_eq!(
        info1, info2,
        "cpu_info() must be deterministic across calls"
    );
}

/// AES-256-GCM Known-Answer Test -- NIST SP 800-38D Test Case 14.
#[test]
fn aes256gcm_kat_sp800_38d_tc14() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let pt: &[u8] = b"";
    let aad: &[u8] = b"";
    let expected_tag: [u8; 16] = [
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73,
        0x8b,
    ];

    let aead = aead_impl(AeadAlgo::Aes256Gcm);
    let mut ct = vec![0u8; pt.len() + aead.tag_len()];
    let written = aead
        .seal(&key, &nonce, aad, pt, &mut ct)
        .expect("AES-256-GCM seal failed (KAT TC14)");
    assert_eq!(written, 16, "TC14: expected 16 bytes out (tag only)");
    assert_eq!(ct[..16], expected_tag, "TC14: tag mismatch");

    let mut dec = vec![0u8; 0];
    let n = aead
        .open(&key, &nonce, aad, &ct[..written], &mut dec)
        .expect("AES-256-GCM open failed (KAT TC14)");
    assert_eq!(n, 0, "TC14: empty PT expected after decryption");
}

// ── Enum completeness ────────────────────────────────────────────────────

#[test]
fn all_sig_algos_have_signer_and_verifier() {
    let algos = [
        SigAlgo::Ed25519,
        SigAlgo::Ed448,
        SigAlgo::EcdsaP256,
        SigAlgo::EcdsaP384,
        SigAlgo::EcdsaP521,
        SigAlgo::RsaPkcs1v15Sha256,
        SigAlgo::RsaPkcs1v15Sha384,
        SigAlgo::RsaPkcs1v15Sha512,
        SigAlgo::RsaPssSha256,
        SigAlgo::SchnorrBip340,
    ];
    for algo in algos {
        let s = signer_impl(algo);
        let v = verifier_impl(algo);
        assert_eq!(
            s.name(),
            v.name(),
            "{algo:?} name mismatch between signer and verifier"
        );
        assert!(
            s.signature_len() > 0,
            "{algo:?} signature_len must be positive"
        );
    }
}

// ── Display/FromStr round-trips ──────────────────────────────────────────

#[test]
fn hash_algo_display_roundtrip() {
    let algos = [
        HashAlgo::Sha256,
        HashAlgo::Sha384,
        HashAlgo::Sha512,
        HashAlgo::Sha3_256,
        HashAlgo::Sha3_384,
        HashAlgo::Sha3_512,
        HashAlgo::Blake3,
    ];
    for algo in algos {
        let s = algo.to_string();
        let parsed: HashAlgo = s.parse().expect("parse failed");
        assert_eq!(parsed, algo, "round-trip failed for {s}");
    }
}

#[test]
fn aead_algo_display_roundtrip() {
    let algos = [
        AeadAlgo::Aes128Gcm,
        AeadAlgo::Aes256Gcm,
        AeadAlgo::ChaCha20Poly1305,
        AeadAlgo::Aes128GcmSiv,
        AeadAlgo::Aes256GcmSiv,
        AeadAlgo::XChaCha20Poly1305,
        AeadAlgo::Aes128Ccm,
        AeadAlgo::Aes256Ccm,
        AeadAlgo::Aes128Ocb3,
        AeadAlgo::Aes256Ocb3,
        AeadAlgo::DeoxysII128,
    ];
    for algo in algos {
        let s = algo.to_string();
        let parsed: AeadAlgo = s.parse().expect("parse failed");
        assert_eq!(parsed, algo, "round-trip failed for {s}");
    }
}

#[test]
fn mac_algo_display_roundtrip() {
    let simple_algos = [
        MacAlgo::HmacSha256,
        MacAlgo::HmacSha384,
        MacAlgo::HmacSha512,
        MacAlgo::HmacSha3_256,
        MacAlgo::HmacSha3_512,
        MacAlgo::Poly1305,
        MacAlgo::CmacAes128,
        MacAlgo::CmacAes256,
    ];
    for algo in simple_algos {
        let s = algo.to_string();
        let parsed: MacAlgo = s.parse().expect("parse failed");
        assert_eq!(parsed, algo, "round-trip failed for {s}");
    }
    // KMAC variants carry output_len in the Display string
    for &output_len in &[16usize, 32, 64] {
        let algo128 = MacAlgo::Kmac128 { output_len };
        let s128 = algo128.to_string();
        let parsed128: MacAlgo = s128.parse().expect("parse KMAC128 failed");
        assert_eq!(parsed128, algo128, "round-trip failed for {s128}");

        let algo256 = MacAlgo::Kmac256 { output_len };
        let s256 = algo256.to_string();
        let parsed256: MacAlgo = s256.parse().expect("parse KMAC256 failed");
        assert_eq!(parsed256, algo256, "round-trip failed for {s256}");
    }
}

#[test]
fn sig_algo_display_roundtrip() {
    let algos = [
        SigAlgo::Ed25519,
        SigAlgo::Ed448,
        SigAlgo::EcdsaP256,
        SigAlgo::EcdsaP384,
        SigAlgo::EcdsaP521,
        SigAlgo::RsaPkcs1v15Sha256,
        SigAlgo::RsaPkcs1v15Sha384,
        SigAlgo::RsaPkcs1v15Sha512,
        SigAlgo::RsaPssSha256,
        SigAlgo::SchnorrBip340,
    ];
    for algo in algos {
        let s = algo.to_string();
        let parsed: SigAlgo = s.parse().expect("parse failed");
        assert_eq!(parsed, algo, "round-trip failed for {s}");
    }
}

#[test]
fn kex_algo_display_roundtrip() {
    let algos = [
        KexAlgo::X25519,
        KexAlgo::EcdhP256,
        KexAlgo::EcdhP384,
        KexAlgo::EcdhP521,
    ];
    for algo in algos {
        let s = algo.to_string();
        let parsed: KexAlgo = s.parse().expect("parse failed");
        assert_eq!(parsed, algo, "round-trip failed for {s}");
    }
}

#[test]
fn kdf_algo_display_roundtrip() {
    let algos = [
        KdfAlgo::HkdfSha256,
        KdfAlgo::HkdfSha384,
        KdfAlgo::HkdfSha512,
        KdfAlgo::Pbkdf2Sha256,
        KdfAlgo::Pbkdf2Sha512,
        KdfAlgo::Argon2id,
        KdfAlgo::Scrypt,
        KdfAlgo::Balloon,
    ];
    for algo in algos {
        let s = algo.to_string();
        let parsed: KdfAlgo = s.parse().expect("parse failed");
        assert_eq!(parsed, algo, "round-trip failed for {s}");
    }
}

// ── Convenience hash functions ────────────────────────────────────────────

#[test]
fn sha256_known_vector() {
    // NIST FIPS 180-4 test vector: SHA-256("abc")
    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    assert_eq!(sha256(b"abc"), expected);
}

#[test]
fn sha512_output_length() {
    let out = sha512(b"abc");
    assert_eq!(out.len(), 64);
    assert_ne!(out, [0u8; 64]);
}

#[test]
fn blake3_known_vector() {
    // Official BLAKE3 test vector for "abc":
    // https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
    let out = blake3(b"abc");
    assert_eq!(out.len(), 32);
    let expected: [u8; 32] = [
        0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33, 0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a, 0x8d,
        0xb5, 0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03, 0xfd, 0x35, 0x9c, 0x6c, 0xd5, 0xbd,
        0x9d, 0x85,
    ];
    assert_eq!(out, expected);
}

// ── KDF PBKDF2/Argon2/scrypt adapters ───────────────────────────────────

#[test]
fn kdf_pbkdf2_sha256_derives() {
    let kdf = kdf_impl(KdfAlgo::Pbkdf2Sha256);
    let mut okm = [0u8; 32];
    kdf.derive(b"password", b"somesalt", b"", &mut okm)
        .expect("derive failed");
    assert_ne!(okm, [0u8; 32]);
}

#[test]
fn kdf_pbkdf2_sha512_derives() {
    let kdf = kdf_impl(KdfAlgo::Pbkdf2Sha512);
    let mut okm = [0u8; 32];
    kdf.derive(b"password", b"somesalt", b"", &mut okm)
        .expect("derive failed");
    assert_ne!(okm, [0u8; 32]);
}

#[test]
fn kdf_argon2id_derives() {
    let kdf = kdf_impl(KdfAlgo::Argon2id);
    let mut okm = [0u8; 32];
    // Argon2id requires salt >= 8 bytes.
    kdf.derive(b"password", b"saltsalt", b"", &mut okm)
        .expect("derive failed");
    assert_ne!(okm, [0u8; 32]);
}

#[test]
fn kdf_scrypt_derives() {
    let kdf = kdf_impl(KdfAlgo::Scrypt);
    let mut okm = [0u8; 32];
    kdf.derive(b"password", b"NaCl", b"", &mut okm)
        .expect("derive failed");
    assert_ne!(okm, [0u8; 32]);
}

#[test]
fn kdf_balloon_derives_variable_length() {
    // Balloon adapter = Balloon-SHA-256 extract + HKDF-SHA-256 expand, so it
    // honours the arbitrary-length Kdf contract. Exercise 16/32/64-byte output.
    let kdf = kdf_impl(KdfAlgo::Balloon);
    assert_eq!(kdf.name(), "Balloon-SHA256");
    let mut prev: Option<Vec<u8>> = None;
    for &len in &[16usize, 32, 64] {
        let mut okm = vec![0u8; len];
        kdf.derive(b"password", b"saltsalt", b"info", &mut okm)
            .expect("derive failed");
        assert_ne!(
            okm,
            vec![0u8; len],
            "okm must not be all-zero for len {len}"
        );
        // HKDF expand is a prefix stream, so shorter outputs are prefixes of
        // longer ones — this also proves determinism across calls.
        if let Some(p) = &prev {
            assert_eq!(
                &okm[..p.len()],
                &p[..],
                "Balloon adapter must be deterministic"
            );
        }
        prev = Some(okm);
    }
}

// ── New hash variants (Sha512_256, Blake2b256, Blake2b512, Blake2s256) ────

#[test]
fn hash_sha512_256_produces_output() {
    let out = hash_impl(HashAlgo::Sha512_256)
        .hash_to_vec(b"")
        .expect("Sha512_256 hash failed");
    assert!(!out.is_empty(), "Sha512_256 output must not be empty");
    assert_eq!(out.len(), 32, "Sha512_256 output must be 32 bytes");
}

#[test]
fn hash_blake2b256_produces_output() {
    let out = hash_impl(HashAlgo::Blake2b256)
        .hash_to_vec(b"")
        .expect("Blake2b256 hash failed");
    assert!(!out.is_empty(), "Blake2b256 output must not be empty");
    assert_eq!(out.len(), 32, "Blake2b256 output must be 32 bytes");
}

#[test]
fn hash_blake2b512_produces_output() {
    let out = hash_impl(HashAlgo::Blake2b512)
        .hash_to_vec(b"")
        .expect("Blake2b512 hash failed");
    assert!(!out.is_empty(), "Blake2b512 output must not be empty");
    assert_eq!(out.len(), 64, "Blake2b512 output must be 64 bytes");
}

#[test]
fn hash_blake2s256_produces_output() {
    let out = hash_impl(HashAlgo::Blake2s256)
        .hash_to_vec(b"")
        .expect("Blake2s256 hash failed");
    assert!(!out.is_empty(), "Blake2s256 output must not be empty");
    assert_eq!(out.len(), 32, "Blake2s256 output must be 32 bytes");
}

// ── RsaPssSha384 and RsaPssSha512 sign/verify ─────────────────────────────

#[test]
fn rsa_pss_sha384_facade_sign_verify() {
    let (sk_der, pk_der) =
        oxicrypto_sig::rsa_generate_keypair(2048).expect("RSA-2048 key generation failed");
    let msg = b"facade RSA-PSS-SHA384 test";
    let signer = signer_impl(SigAlgo::RsaPssSha384);
    let verifier = verifier_impl(SigAlgo::RsaPssSha384);
    let mut sig = vec![0u8; signer.signature_len()];
    let n = signer
        .sign(&sk_der, msg, &mut sig)
        .expect("RSA-PSS-SHA384 sign failed");
    verifier
        .verify(&pk_der, msg, &sig[..n])
        .expect("RSA-PSS-SHA384 verify failed");
}

#[test]
fn rsa_pss_sha512_facade_sign_verify() {
    let (sk_der, pk_der) =
        oxicrypto_sig::rsa_generate_keypair(2048).expect("RSA-2048 key generation failed");
    let msg = b"facade RSA-PSS-SHA512 test";
    let signer = signer_impl(SigAlgo::RsaPssSha512);
    let verifier = verifier_impl(SigAlgo::RsaPssSha512);
    let mut sig = vec![0u8; signer.signature_len()];
    let n = signer
        .sign(&sk_der, msg, &mut sig)
        .expect("RSA-PSS-SHA512 sign failed");
    verifier
        .verify(&pk_der, msg, &sig[..n])
        .expect("RSA-PSS-SHA512 verify failed");
}

// ── X448 key exchange ─────────────────────────────────────────────────────

#[test]
fn x448_facade_agree() {
    use rand_core::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x42u8; 32]);
    let (alice_sk, alice_pk) =
        oxicrypto_kex::x448_generate_keypair(&mut rng).expect("X448 alice keygen failed");
    let (bob_sk, bob_pk) =
        oxicrypto_kex::x448_generate_keypair(&mut rng).expect("X448 bob keygen failed");

    let kex = kex_impl(KexAlgo::X448);
    assert_eq!(kex.name(), "X448");
    assert_eq!(kex.scalar_len(), 56);

    let mut s1 = [0u8; 56];
    let mut s2 = [0u8; 56];
    kex.agree(alice_sk.as_bytes(), &bob_pk, &mut s1)
        .expect("X448 agree alice→bob failed");
    kex.agree(bob_sk.as_bytes(), &alice_pk, &mut s2)
        .expect("X448 agree bob→alice failed");
    assert_eq!(s1, s2, "X448 shared secrets must match");
}

// ── available_algorithms completeness ─────────────────────────────────────

#[test]
fn available_algorithms_contains_new_algo_ids() {
    let ids = available_algorithms();

    assert!(
        ids.contains(&AlgorithmId::Sha512_256),
        "Sha512_256 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::Blake2b256),
        "Blake2b256 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::Blake2b512),
        "Blake2b512 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::Blake2s256),
        "Blake2s256 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::X448),
        "X448 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::Aes128Ocb3),
        "Aes128Ocb3 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::Aes256Ocb3),
        "Aes256Ocb3 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::RsaPssSha384),
        "RsaPssSha384 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::RsaPssSha512),
        "RsaPssSha512 must be in available_algorithms"
    );
}

// ── Unknown algo parse error ──────────────────────────────────────────────

#[test]
fn unknown_algo_parse_error() {
    let result: Result<HashAlgo, _> = "INVALID-ALGO".parse();
    assert!(result.is_err(), "parsing unknown algo must fail");
    assert_eq!(result.unwrap_err(), CryptoError::UnsupportedAlgorithm);
}

// ── EcdhP521 via kex_impl ────────────────────────────────────────────────

#[test]
fn ecdh_p521_facade_agree() {
    let kex = kex_impl(KexAlgo::EcdhP521);
    assert_eq!(kex.name(), "ECDH-P521");
    assert_eq!(kex.scalar_len(), 66);
}

// ── VersionInfo ──────────────────────────────────────────────────────────

#[test]
fn version_info_is_valid() {
    let v = version();
    // Major version must be >= 0 (trivially true for u32, but we check Display)
    let s = v.to_string();
    assert!(!s.is_empty(), "version Display must not be empty");
    // Basic sanity: must contain dots for major.minor.patch
    assert!(s.contains('.'), "version string must contain dots: {s}");
}

#[test]
fn version_info_display_formats_correctly() {
    let v = VersionInfo {
        major: 1,
        minor: 2,
        patch: 3,
        pre: "",
    };
    assert_eq!(v.to_string(), "1.2.3");

    let v_pre = VersionInfo {
        major: 0,
        minor: 1,
        patch: 0,
        pre: "alpha.1",
    };
    assert_eq!(v_pre.to_string(), "0.1.0-alpha.1");
}

// ── available_algorithms ─────────────────────────────────────────────────

#[test]
fn available_algorithms_includes_all_families() {
    let ids = available_algorithms();
    assert!(!ids.is_empty(), "available_algorithms must not be empty");

    // Check that all main algorithm families are represented
    let has_hash = ids
        .iter()
        .any(|id| id.category() == AlgorithmCategory::Hash);
    let has_aead = ids
        .iter()
        .any(|id| id.category() == AlgorithmCategory::Aead);
    let has_mac = ids.iter().any(|id| id.category() == AlgorithmCategory::Mac);
    let has_sig = ids
        .iter()
        .any(|id| id.category() == AlgorithmCategory::Signature);
    let has_kex = ids
        .iter()
        .any(|id| id.category() == AlgorithmCategory::KeyExchange);
    let has_kdf = ids.iter().any(|id| id.category() == AlgorithmCategory::Kdf);
    assert!(has_hash, "must include hash algorithms");
    assert!(has_aead, "must include AEAD algorithms");
    assert!(has_mac, "must include MAC algorithms");
    assert!(has_sig, "must include signature algorithms");
    assert!(has_kex, "must include KEX algorithms");
    assert!(has_kdf, "must include KDF algorithms");
}

#[test]
fn available_algorithms_contains_new_mac_entries() {
    let ids = available_algorithms();
    assert!(
        ids.contains(&AlgorithmId::HmacSha3_256),
        "HmacSha3_256 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::HmacSha3_512),
        "HmacSha3_512 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::Poly1305),
        "Poly1305 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::CmacAes128),
        "CmacAes128 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::CmacAes256),
        "CmacAes256 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::Kmac128),
        "Kmac128 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::Kmac256),
        "Kmac256 must be in available_algorithms"
    );
}

#[test]
fn available_algorithms_contains_aead_ccm() {
    let ids = available_algorithms();
    assert!(
        ids.contains(&AlgorithmId::Aes128Ccm),
        "Aes128Ccm must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::Aes256Ccm),
        "Aes256Ccm must be in available_algorithms"
    );
}

#[test]
fn available_algorithms_contains_new_entries() {
    let ids = available_algorithms();
    assert!(
        ids.contains(&AlgorithmId::DeoxysII128),
        "DeoxysII128 must be in available_algorithms"
    );
    assert_eq!(AlgorithmId::DeoxysII128.category(), AlgorithmCategory::Aead);
    assert!(
        ids.contains(&AlgorithmId::SchnorrBip340),
        "SchnorrBip340 must be in available_algorithms"
    );
    assert_eq!(
        AlgorithmId::SchnorrBip340.category(),
        AlgorithmCategory::Signature
    );
    assert!(
        ids.contains(&AlgorithmId::Balloon),
        "Balloon must be in available_algorithms"
    );
    assert_eq!(AlgorithmId::Balloon.category(), AlgorithmCategory::Kdf);
}

// ── TryFrom<&str> for *Algo enums ───────────────────────────────────────

#[test]
fn tryfrom_str_hash_algo() {
    let algo = HashAlgo::try_from("SHA-256").expect("TryFrom should succeed");
    assert_eq!(algo, HashAlgo::Sha256);
    let err = HashAlgo::try_from("BOGUS");
    assert_eq!(err, Err(CryptoError::UnsupportedAlgorithm));
}

#[test]
fn tryfrom_str_aead_algo() {
    let algo = AeadAlgo::try_from("AES-128-GCM").expect("TryFrom should succeed");
    assert_eq!(algo, AeadAlgo::Aes128Gcm);
    let algo_ccm = AeadAlgo::try_from("AES-128-CCM").expect("CCM TryFrom should succeed");
    assert_eq!(algo_ccm, AeadAlgo::Aes128Ccm);
    let algo_ocb3 = AeadAlgo::try_from("AES-256-OCB3").expect("OCB3 TryFrom should succeed");
    assert_eq!(algo_ocb3, AeadAlgo::Aes256Ocb3);
}

#[test]
fn tryfrom_str_mac_algo() {
    let algo = MacAlgo::try_from("HMAC-SHA-256").expect("TryFrom should succeed");
    assert_eq!(algo, MacAlgo::HmacSha256);
    let algo3 = MacAlgo::try_from("HMAC-SHA3-256").expect("SHA3 TryFrom should succeed");
    assert_eq!(algo3, MacAlgo::HmacSha3_256);
    let kmac = MacAlgo::try_from("KMAC128/32").expect("KMAC128 TryFrom should succeed");
    assert_eq!(kmac, MacAlgo::Kmac128 { output_len: 32 });
    let kmac256 = MacAlgo::try_from("KMAC256/64").expect("KMAC256 TryFrom should succeed");
    assert_eq!(kmac256, MacAlgo::Kmac256 { output_len: 64 });
}

#[test]
fn tryfrom_str_sig_kex_kdf_algos() {
    assert_eq!(
        SigAlgo::try_from("Ed25519").expect("SigAlgo"),
        SigAlgo::Ed25519
    );
    assert_eq!(
        KexAlgo::try_from("X25519").expect("KexAlgo"),
        KexAlgo::X25519
    );
    assert_eq!(
        KdfAlgo::try_from("HKDF-SHA-256").expect("KdfAlgo"),
        KdfAlgo::HkdfSha256
    );
}

// ── prelude module ───────────────────────────────────────────────────────

#[test]
fn prelude_exports_are_usable() {
    use crate::prelude::*;

    // Traits should be in scope (verify indirectly by calling them)
    let h = hash_impl(HashAlgo::Sha256);
    assert_eq!(h.name(), "SHA-256");

    let a = aead_impl(AeadAlgo::Aes256Gcm);
    assert_eq!(a.name(), "AES-256-GCM");

    let m = mac_impl(MacAlgo::HmacSha256);
    assert_eq!(m.name(), "HMAC-SHA-256");

    // Version and available_algorithms from prelude
    let v = version();
    // version() must succeed (trivially, but exercises the function)
    let _ver_str = v.to_string();

    let ids = available_algorithms();
    assert!(!ids.is_empty());

    // AlgorithmId and AlgorithmCategory accessible
    let _id: AlgorithmId = AlgorithmId::Sha256;
    let _cat: AlgorithmCategory = AlgorithmCategory::Hash;
}

// ── Suite and PqSuite ────────────────────────────────────────────────────

#[test]
fn suite_tls13_has_expected_algos() {
    let s = Suite::TLS13;
    assert_eq!(s.aead, AeadAlgo::Aes256Gcm);
    assert_eq!(s.mac, MacAlgo::HmacSha384);
    assert_eq!(s.hash, HashAlgo::Sha384);
    assert_eq!(s.kex, KexAlgo::X25519);
    assert_eq!(s.kdf, KdfAlgo::HkdfSha384);
}

#[test]
fn suite_display_includes_algo_names() {
    let s = Suite::TLS13.to_string();
    assert!(
        s.contains("AES-256-GCM"),
        "Suite display must include AEAD: {s}"
    );
    assert!(
        s.contains("HMAC-SHA-384"),
        "Suite display must include MAC: {s}"
    );
    assert!(
        s.contains("SHA-384"),
        "Suite display must include hash: {s}"
    );
    assert!(s.contains("X25519"), "Suite display must include KEX: {s}");
    assert!(
        s.contains("HKDF-SHA-384"),
        "Suite display must include KDF: {s}"
    );
}

#[test]
fn suite_tls13_is_copy() {
    let s1 = Suite::TLS13;
    let s2 = s1; // Copy semantics
    assert_eq!(s1, s2);
}

// ── Facade re-export reachability (ParallelHash + Stretcher) ──────────────

#[test]
fn parallelhash_and_stretcher_reexports_reachable() {
    // ParallelHash128 fixed-output, reachable straight off the crate root
    // (`crate::` here is the in-crate spelling of `oxicrypto::`).
    let data = b"facade parallelhash reachability";
    let mut out32 = [0u8; 32];
    crate::parallel_hash128(data, 8, b"", &mut out32).expect("parallel_hash128 failed");
    assert_ne!(out32, [0u8; 32], "ParallelHash128 output must be non-zero");

    // KeyStretcher / Stretcher / StretchParams / BalloonStretchParams reachable
    // off the crate root. Use small Balloon params for test speed.
    let stretcher = crate::Stretcher::new(crate::StretchParams::BalloonSha256(
        crate::BalloonStretchParams {
            space_cost: 16,
            time_cost: 2,
        },
    ));
    let key = stretcher
        .stretch(b"pw", b"saltsalt")
        .expect("stretch failed");
    assert_eq!(key.len(), 32, "Balloon-SHA-256 derives a 32-byte key");
}

// ── Facade re-export reachability (HPKE / RFC 9180) ───────────────────────

#[test]
fn hpke_facade_reexport_round_trip() {
    use crate::hpke::{AeadId, HpkeSuite, KdfId, KemId};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    // Construct a suite straight off the facade and run a Base round-trip.
    let suite = HpkeSuite::new(
        KemId::DhkemX25519HkdfSha256,
        KdfId::HkdfSha256,
        AeadId::Aes128Gcm,
    );
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);

    let (sk_r, pk_r) = suite.generate_key_pair(&mut rng).expect("keygen");
    let info = b"facade hpke reachability";
    let (enc, ct) = suite
        .seal_base(&pk_r, info, b"aad", b"facade secret", &mut rng)
        .expect("seal_base");
    let pt = suite
        .open_base(&enc, sk_r.as_bytes(), info, b"aad", &ct)
        .expect("open_base");
    assert_eq!(pt, b"facade secret");
}

// ── PQ-preview: XWing768 and HybridKem1024P384 ────────────────────────────

#[cfg(feature = "pq-preview")]
#[test]
fn pq_kem_xwing768_generate_produces_keys() {
    let (dk_bytes, ek_bytes) =
        crate::pq_kem_generate(PqKemAlgo::XWing768).expect("XWing768 key generation failed");
    assert!(!dk_bytes.is_empty(), "XWing768 dk must not be empty");
    assert!(!ek_bytes.is_empty(), "XWing768 ek must not be empty");
}

#[cfg(feature = "pq-preview")]
#[test]
fn pq_kem_xwing768_encap_decap_round_trip() {
    use oxicrypto_core::Kem;
    let (dk, ek) = oxicrypto_pq::XWing768::kem_generate().expect("XWing768 kem_generate failed");
    let (ct, ss_enc) =
        oxicrypto_pq::XWing768::kem_encapsulate(&ek).expect("XWing768 encapsulate failed");
    let ss_dec =
        oxicrypto_pq::XWing768::kem_decapsulate(&dk, &ct).expect("XWing768 decapsulate failed");
    assert_eq!(
        ss_enc.as_slice(),
        ss_dec.as_slice(),
        "XWing768 encap/decap shared secrets must match"
    );
}

#[cfg(feature = "pq-preview")]
#[test]
fn pq_kem_hybrid1024p384_generate_produces_keys() {
    let (dk_bytes, ek_bytes) = crate::pq_kem_generate(PqKemAlgo::HybridKem1024P384)
        .expect("HybridKem1024P384 key generation failed");
    assert!(
        !dk_bytes.is_empty(),
        "HybridKem1024P384 dk must not be empty"
    );
    assert!(
        !ek_bytes.is_empty(),
        "HybridKem1024P384 ek must not be empty"
    );
}

#[cfg(feature = "pq-preview")]
#[test]
fn pq_kem_hybrid1024p384_encap_decap_round_trip() {
    use oxicrypto_core::Kem;
    let (dk, ek) = oxicrypto_pq::HybridKem1024P384::kem_generate()
        .expect("HybridKem1024P384 kem_generate failed");
    let (ct, ss_enc) = oxicrypto_pq::HybridKem1024P384::kem_encapsulate(&ek)
        .expect("HybridKem1024P384 encapsulate failed");
    let ss_dec = oxicrypto_pq::HybridKem1024P384::kem_decapsulate(&dk, &ct)
        .expect("HybridKem1024P384 decapsulate failed");
    assert_eq!(
        ss_enc.as_slice(),
        ss_dec.as_slice(),
        "HybridKem1024P384 encap/decap shared secrets must match"
    );
}

#[cfg(feature = "pq-preview")]
#[test]
fn available_algorithms_contains_hybrid_kem_ids() {
    let ids = available_algorithms();
    assert!(
        ids.contains(&AlgorithmId::XWing768X25519),
        "XWing768X25519 must be in available_algorithms"
    );
    assert!(
        ids.contains(&AlgorithmId::HybridKem1024P384),
        "HybridKem1024P384 must be in available_algorithms"
    );
}

// ── hybrid facade module reachability ────────────────────────────────────────

/// Verify `crate::hybrid::XWing768` is reachable via the facade and that
/// a full keygen → encaps → decaps round-trip produces equal shared secrets.
#[cfg(feature = "pq-preview")]
#[test]
fn hybrid_xwing768_roundtrip() {
    use crate::hybrid::{Kem, XWing768};

    // Key generation
    let (dk, ek) = XWing768::kem_generate().expect("XWing768::kem_generate must succeed");

    // Encapsulation (sender side)
    let (ct, ss_enc) =
        XWing768::kem_encapsulate(&ek).expect("XWing768::kem_encapsulate must succeed");

    // Decapsulation (recipient side)
    let ss_dec =
        XWing768::kem_decapsulate(&dk, &ct).expect("XWing768::kem_decapsulate must succeed");

    assert_eq!(
        ss_enc.as_slice(),
        ss_dec.as_slice(),
        "XWing768 round-trip: encapsulator and decapsulator must agree on the shared secret"
    );
    assert_eq!(
        ss_enc.as_slice().len(),
        32,
        "XWing768 shared secret must be 32 bytes"
    );
}

/// Verify `crate::hybrid::HybridKem1024P384` is reachable via the facade
/// and that a full keygen → encaps → decaps round-trip produces equal shared
/// secrets.
#[cfg(feature = "pq-preview")]
#[test]
fn hybrid_p384_roundtrip() {
    use crate::hybrid::{HybridKem1024P384, Kem};

    // Key generation
    let (dk, ek) =
        HybridKem1024P384::kem_generate().expect("HybridKem1024P384::kem_generate must succeed");

    // Encapsulation (sender side)
    let (ct, ss_enc) = HybridKem1024P384::kem_encapsulate(&ek)
        .expect("HybridKem1024P384::kem_encapsulate must succeed");

    // Decapsulation (recipient side)
    let ss_dec = HybridKem1024P384::kem_decapsulate(&dk, &ct)
        .expect("HybridKem1024P384::kem_decapsulate must succeed");

    assert_eq!(
        ss_enc.as_slice(),
        ss_dec.as_slice(),
        "HybridKem1024P384 round-trip: encapsulator and decapsulator must agree on the shared secret"
    );
}
