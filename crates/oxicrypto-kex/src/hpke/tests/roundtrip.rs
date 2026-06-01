//! HPKE round-trip and negative tests across all modes and suites.

use oxicrypto_core::CryptoError;
use p256::elliptic_curve::sec1::ToSec1Point;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::hpke::{AeadId, HpkeSuite, KdfId, KemId};

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

const INFO: &[u8] = b"hpke round-trip info";
const PSK: &[u8] = b"\x02\x47\xfd\x33\xb9\x13\x76\x0f\xa1\xfa\x51\xe1\x89\x2d\x9f\x30\x7f\xbe\x65\xeb\x17\x1e\x81\x32\xc2\xaf\x18\x55\x5a\x73\x8b\x82";
const PSK_ID: &[u8] = b"Ennyn Durin aran Moria";

fn x25519_aes128() -> HpkeSuite {
    HpkeSuite::new(
        KemId::DhkemX25519HkdfSha256,
        KdfId::HkdfSha256,
        AeadId::Aes128Gcm,
    )
}

// ── Base mode round-trips per curve / AEAD ─────────────────────────────────────

fn base_round_trip(suite: HpkeSuite) {
    let mut r = rng(1);
    let (sk_r, pk_r) = suite.generate_key_pair(&mut r).expect("keygen");

    let (enc, mut sctx) = suite.setup_base_s(&pk_r, INFO, &mut r).expect("setup S");
    let m0 = b"first message";
    let m1 = b"second, longer message payload";
    let c0 = sctx.seal(b"aad0", m0).expect("seal0");
    let c1 = sctx.seal(b"aad1", m1).expect("seal1");

    let mut rctx = suite
        .setup_base_r(&enc, sk_r.as_bytes(), INFO)
        .expect("setup R");
    assert_eq!(rctx.open(b"aad0", &c0).expect("open0"), m0);
    assert_eq!(rctx.open(b"aad1", &c1).expect("open1"), m1);

    // Sender / recipient exporters agree.
    let es = sctx.export(b"exp ctx", 48).expect("export S");
    let er = rctx.export(b"exp ctx", 48).expect("export R");
    assert_eq!(es, er);
    assert_eq!(es.len(), 48);
}

#[test]
fn base_x25519_aes128_round_trip() {
    base_round_trip(x25519_aes128());
}

#[test]
fn base_x25519_aes256_round_trip() {
    base_round_trip(HpkeSuite::new(
        KemId::DhkemX25519HkdfSha256,
        KdfId::HkdfSha256,
        AeadId::Aes256Gcm,
    ));
}

#[test]
fn base_x25519_chacha20_round_trip() {
    base_round_trip(HpkeSuite::new(
        KemId::DhkemX25519HkdfSha256,
        KdfId::HkdfSha256,
        AeadId::ChaCha20Poly1305,
    ));
}

#[test]
fn base_p256_aes128_round_trip() {
    base_round_trip(HpkeSuite::new(
        KemId::DhkemP256HkdfSha256,
        KdfId::HkdfSha256,
        AeadId::Aes128Gcm,
    ));
}

#[test]
fn base_p256_chacha20_sha512_round_trip() {
    // Mix KEM/KDF/AEAD to exercise non-default combinations.
    base_round_trip(HpkeSuite::new(
        KemId::DhkemP256HkdfSha256,
        KdfId::HkdfSha512,
        AeadId::ChaCha20Poly1305,
    ));
}

// ── All four modes over X25519 ─────────────────────────────────────────────────

#[test]
fn all_modes_x25519_round_trip() {
    let suite = x25519_aes128();
    let mut r = rng(2);
    let (sk_r, pk_r) = suite.generate_key_pair(&mut r).expect("recipient keygen");
    let (sk_s, pk_s) = suite.generate_key_pair(&mut r).expect("sender keygen");

    let m0 = b"msg zero";
    let m1 = b"msg one (a bit longer)";

    // Base.
    {
        let (enc, mut s) = suite.setup_base_s(&pk_r, INFO, &mut r).expect("base S");
        let c0 = s.seal(b"a0", m0).expect("seal");
        let c1 = s.seal(b"a1", m1).expect("seal");
        let mut rc = suite
            .setup_base_r(&enc, sk_r.as_bytes(), INFO)
            .expect("base R");
        assert_eq!(rc.open(b"a0", &c0).expect("open"), m0);
        assert_eq!(rc.open(b"a1", &c1).expect("open"), m1);
        assert_eq!(s.export(b"x", 32).unwrap(), rc.export(b"x", 32).unwrap());
    }
    // PSK.
    {
        let (enc, mut s) = suite
            .setup_psk_s(&pk_r, INFO, PSK, PSK_ID, &mut r)
            .expect("psk S");
        let c0 = s.seal(b"a0", m0).expect("seal");
        let c1 = s.seal(b"a1", m1).expect("seal");
        let mut rc = suite
            .setup_psk_r(&enc, sk_r.as_bytes(), INFO, PSK, PSK_ID)
            .expect("psk R");
        assert_eq!(rc.open(b"a0", &c0).expect("open"), m0);
        assert_eq!(rc.open(b"a1", &c1).expect("open"), m1);
        assert_eq!(s.export(b"x", 32).unwrap(), rc.export(b"x", 32).unwrap());
    }
    // Auth.
    {
        let (enc, mut s) = suite
            .setup_auth_s(&pk_r, INFO, sk_s.as_bytes(), &mut r)
            .expect("auth S");
        let c0 = s.seal(b"a0", m0).expect("seal");
        let c1 = s.seal(b"a1", m1).expect("seal");
        let mut rc = suite
            .setup_auth_r(&enc, sk_r.as_bytes(), INFO, &pk_s)
            .expect("auth R");
        assert_eq!(rc.open(b"a0", &c0).expect("open"), m0);
        assert_eq!(rc.open(b"a1", &c1).expect("open"), m1);
        assert_eq!(s.export(b"x", 32).unwrap(), rc.export(b"x", 32).unwrap());
    }
    // AuthPSK.
    {
        let (enc, mut s) = suite
            .setup_auth_psk_s(&pk_r, INFO, PSK, PSK_ID, sk_s.as_bytes(), &mut r)
            .expect("authpsk S");
        let c0 = s.seal(b"a0", m0).expect("seal");
        let c1 = s.seal(b"a1", m1).expect("seal");
        let mut rc = suite
            .setup_auth_psk_r(&enc, sk_r.as_bytes(), INFO, PSK, PSK_ID, &pk_s)
            .expect("authpsk R");
        assert_eq!(rc.open(b"a0", &c0).expect("open"), m0);
        assert_eq!(rc.open(b"a1", &c1).expect("open"), m1);
        assert_eq!(s.export(b"x", 32).unwrap(), rc.export(b"x", 32).unwrap());
    }
}

// ── Single-shot Base ───────────────────────────────────────────────────────────

#[test]
fn single_shot_seal_open_base() {
    let suite = x25519_aes128();
    let mut r = rng(3);
    let (sk_r, pk_r) = suite.generate_key_pair(&mut r).expect("keygen");
    let (enc, ct) = suite
        .seal_base(&pk_r, INFO, b"aad", b"one shot", &mut r)
        .expect("seal_base");
    let pt = suite
        .open_base(&enc, sk_r.as_bytes(), INFO, b"aad", &ct)
        .expect("open_base");
    assert_eq!(pt, b"one shot");
}

// ── Export-only suite ──────────────────────────────────────────────────────────

#[test]
fn export_only_suite() {
    let suite = HpkeSuite::new(
        KemId::DhkemX25519HkdfSha256,
        KdfId::HkdfSha256,
        AeadId::ExportOnly,
    );
    let mut r = rng(4);
    let (sk_r, pk_r) = suite.generate_key_pair(&mut r).expect("keygen");
    let (enc, mut sctx) = suite.setup_base_s(&pk_r, INFO, &mut r).expect("setup S");
    let mut rctx = suite
        .setup_base_r(&enc, sk_r.as_bytes(), INFO)
        .expect("setup R");

    // Exports agree across both ends.
    assert_eq!(
        sctx.export(b"label", 64).expect("S export"),
        rctx.export(b"label", 64).expect("R export"),
    );

    // Seal / open are unsupported for the export-only AEAD.
    assert_eq!(
        sctx.seal(b"aad", b"x"),
        Err(CryptoError::UnsupportedAlgorithm)
    );
    assert_eq!(
        rctx.open(b"aad", &[0u8; 16]),
        Err(CryptoError::UnsupportedAlgorithm)
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn tampered_ciphertext_fails_open() {
    let suite = x25519_aes128();
    let mut r = rng(5);
    let (sk_r, pk_r) = suite.generate_key_pair(&mut r).expect("keygen");
    let (enc, mut sctx) = suite.setup_base_s(&pk_r, INFO, &mut r).expect("setup S");
    let mut ct = sctx.seal(b"aad", b"secret").expect("seal");
    ct[0] ^= 0x01; // flip one bit

    let mut rctx = suite
        .setup_base_r(&enc, sk_r.as_bytes(), INFO)
        .expect("setup R");
    assert_eq!(rctx.open(b"aad", &ct), Err(CryptoError::InvalidTag));
}

#[test]
fn wrong_psk_or_psk_id_fails_open() {
    let suite = x25519_aes128();
    let mut r = rng(6);
    let (sk_r, pk_r) = suite.generate_key_pair(&mut r).expect("keygen");
    let (enc, mut sctx) = suite
        .setup_psk_s(&pk_r, INFO, PSK, PSK_ID, &mut r)
        .expect("psk S");
    let ct = sctx.seal(b"aad", b"secret").expect("seal");

    // Wrong PSK at receiver: key schedule diverges → tag mismatch.
    let wrong_psk: &[u8] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let mut rc = suite
        .setup_psk_r(&enc, sk_r.as_bytes(), INFO, wrong_psk, PSK_ID)
        .expect("psk R wrong psk");
    assert_eq!(rc.open(b"aad", &ct), Err(CryptoError::InvalidTag));

    // Wrong PSK id at receiver.
    let mut rc2 = suite
        .setup_psk_r(&enc, sk_r.as_bytes(), INFO, PSK, b"wrong id")
        .expect("psk R wrong id");
    assert_eq!(rc2.open(b"aad", &ct), Err(CryptoError::InvalidTag));
}

#[test]
fn psk_input_validation_errors() {
    let suite = x25519_aes128();
    let mut r = rng(7);
    let (_sk_r, pk_r) = suite.generate_key_pair(&mut r).expect("keygen");

    // PSK mode with non-empty psk but empty psk_id → BadInput.
    let mut r2 = rng(8);
    assert_eq!(
        suite
            .setup_psk_s(&pk_r, INFO, PSK, b"", &mut r2)
            .map(|_| ()),
        Err(CryptoError::BadInput)
    );
    // PSK mode with empty psk but non-empty psk_id → BadInput.
    let mut r3 = rng(9);
    assert_eq!(
        suite
            .setup_psk_s(&pk_r, INFO, b"", PSK_ID, &mut r3)
            .map(|_| ()),
        Err(CryptoError::BadInput)
    );
    // Base mode given a PSK → BadInput (Base requires empty psk/psk_id).
    // Reached via the receiver path which also runs the key schedule.
    let mut r4 = rng(10);
    let (sk_r, pk_r2) = suite.generate_key_pair(&mut r4).expect("keygen2");
    let mut r5 = rng(11);
    let (enc, _s) = suite.setup_base_s(&pk_r2, INFO, &mut r5).expect("base S");
    // setup_base_r forces empty psk; to test rejection we drive the PSK receiver
    // path with Base-incompatible inputs is N/A — instead confirm AuthPSK with
    // empty psk fails.
    assert_eq!(
        suite
            .setup_auth_psk_r(&enc, sk_r.as_bytes(), INFO, b"", b"", &pk_r2)
            .map(|_| ()),
        Err(CryptoError::BadInput)
    );
}

#[test]
fn auth_wrong_sender_key_fails_open() {
    let suite = x25519_aes128();
    let mut r = rng(12);
    let (sk_r, pk_r) = suite.generate_key_pair(&mut r).expect("recipient keygen");
    let (sk_s, _pk_s) = suite.generate_key_pair(&mut r).expect("sender keygen");
    let (_sk_w, pk_w) = suite
        .generate_key_pair(&mut r)
        .expect("wrong sender keygen");

    let (enc, mut sctx) = suite
        .setup_auth_s(&pk_r, INFO, sk_s.as_bytes(), &mut r)
        .expect("auth S");
    let ct = sctx.seal(b"aad", b"secret").expect("seal");

    // Receiver authenticates against the WRONG sender public key.
    let mut rctx = suite
        .setup_auth_r(&enc, sk_r.as_bytes(), INFO, &pk_w)
        .expect("auth R");
    assert_eq!(rctx.open(b"aad", &ct), Err(CryptoError::InvalidTag));
}

#[test]
fn sequence_number_overflow_is_kex_error() {
    let suite = x25519_aes128();
    let mut r = rng(13);
    let (_sk_r, pk_r) = suite.generate_key_pair(&mut r).expect("keygen");
    let (_enc, mut sctx) = suite.setup_base_s(&pk_r, INFO, &mut r).expect("setup S");

    // Nn = 12 → limit = 2^96 - 1. Drive the counter to the limit.
    let limit = (1u128 << (8 * 12)) - 1;
    sctx.set_sequence_number(limit);
    assert_eq!(sctx.seal(b"aad", b"x"), Err(CryptoError::Kex));
}

#[test]
fn p256_compressed_or_truncated_enc_is_invalid_key() {
    let suite = HpkeSuite::new(
        KemId::DhkemP256HkdfSha256,
        KdfId::HkdfSha256,
        AeadId::Aes128Gcm,
    );
    let mut r = rng(14);
    let (sk_r, pk_r) = suite.generate_key_pair(&mut r).expect("keygen");

    // Compressed (33-byte) form of pk_r is not a valid HPKE enc for P-256.
    let compressed = p256::PublicKey::from_sec1_bytes(&pk_r)
        .expect("valid uncompressed")
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    assert_eq!(compressed.len(), 33);
    assert_eq!(
        suite
            .setup_base_r(&compressed, sk_r.as_bytes(), INFO)
            .map(|_| ()),
        Err(CryptoError::InvalidKey)
    );

    // Truncated 64-byte enc is also rejected.
    let truncated = &pk_r[..64];
    assert_eq!(
        suite
            .setup_base_r(truncated, sk_r.as_bytes(), INFO)
            .map(|_| ()),
        Err(CryptoError::InvalidKey)
    );
}
