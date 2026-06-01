//! Known-answer tests for AES-128-GCM and AES-256-GCM.
//!
//! Vectors are drawn from two authoritative sources, all using 96-bit IVs
//! (the only IV length the `Aes128Gcm` / `Aes256Gcm` wrappers accept):
//!
//! * **NIST SP 800-38D / McGrew-Viega GCM specification, Appendix B** — the
//!   canonical AES-GCM test cases (TC1-TC4 for AES-128, TC13-TC16 for AES-256).
//!   These cover empty plaintext / empty AAD, a single ciphertext block, a
//!   four-block plaintext with no AAD, and a partial-final-block plaintext with
//!   AAD.
//! * **NIST CAVP `gcmEncryptExtIV{128,256}.rsp`** — the AAD-only group
//!   (`PTlen = 0, AADlen = 128`), exercising authentication of associated data
//!   with no plaintext.
//!
//! Each vector drives `seal` (asserting the exact `ciphertext ‖ tag`) and
//! `open` (asserting the exact recovered plaintext). A final negative test
//! flips a tag byte and asserts `CryptoError::InvalidTag`.

use oxicrypto_aead::{Aes128Gcm, Aes256Gcm};
use oxicrypto_core::{Aead, CryptoError};

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Drive a single GCM KAT vector: seal must yield `expected_ct ‖ expected_tag`
/// exactly, and open must recover the plaintext exactly.
fn check_vector(
    aead: &dyn Aead,
    key_hex: &str,
    iv_hex: &str,
    aad_hex: &str,
    pt_hex: &str,
    expected_ct_hex: &str,
    expected_tag_hex: &str,
) {
    let key = hex_decode(key_hex);
    let iv = hex_decode(iv_hex);
    let aad = hex_decode(aad_hex);
    let pt = hex_decode(pt_hex);
    let tag_len = aead.tag_len();

    let mut ct_out = vec![0u8; pt.len() + tag_len];
    let written = aead
        .seal(&key, &iv, &aad, &pt, &mut ct_out)
        .expect("GCM seal failed");
    assert_eq!(written, pt.len() + tag_len, "output length mismatch");

    assert_eq!(
        to_hex(&ct_out[..pt.len()]),
        expected_ct_hex.replace(' ', ""),
        "ciphertext mismatch"
    );
    assert_eq!(
        to_hex(&ct_out[pt.len()..written]),
        expected_tag_hex.replace(' ', ""),
        "tag mismatch"
    );

    let mut pt_out = vec![0u8; pt.len()];
    let recovered = aead
        .open(&key, &iv, &aad, &ct_out[..written], &mut pt_out)
        .expect("GCM open failed");
    assert_eq!(recovered, pt.len(), "recovered length mismatch");
    assert_eq!(
        to_hex(&pt_out),
        to_hex(&pt),
        "round-trip plaintext mismatch"
    );
}

// ── AES-128-GCM — NIST SP 800-38D / McGrew-Viega Appendix B ───────────────────

/// Test Case 1: empty plaintext, empty AAD (authentication of nothing).
#[test]
fn aes128gcm_nist_tc1_empty() {
    check_vector(
        &Aes128Gcm,
        "00000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "",
        "",
        "58e2fccefa7e3061367f1d57a4e7455a",
    );
}

/// Test Case 2: single all-zero plaintext block, empty AAD.
#[test]
fn aes128gcm_nist_tc2_one_block() {
    check_vector(
        &Aes128Gcm,
        "00000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "00000000000000000000000000000000",
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf",
    );
}

/// Test Case 3: four-block plaintext, no AAD (multi-block).
#[test]
fn aes128gcm_nist_tc3_multiblock_no_aad() {
    check_vector(
        &Aes128Gcm,
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "",
        "d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b391aafd255",
        "42831ec2217774244b7221b784d0d49c\
         e3aa212f2c02a4e035c17e2329aca12e\
         21d514b25466931c7d8f6a5aac84aa05\
         1ba30b396a0aac973d58e091473f5985",
        "4d5c2af327cd64a62cf35abd2ba6fab4",
    );
}

/// Test Case 4: partial final block plaintext (60 bytes) with AAD (multi-block + AAD).
#[test]
fn aes128gcm_nist_tc4_partial_block_with_aad() {
    check_vector(
        &Aes128Gcm,
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b39",
        "42831ec2217774244b7221b784d0d49c\
         e3aa212f2c02a4e035c17e2329aca12e\
         21d514b25466931c7d8f6a5aac84aa05\
         1ba30b396a0aac973d58e091",
        "5bc94fbc3221a5db94fae95ae7121a47",
    );
}

// ── AES-128-GCM — NIST CAVP gcmEncryptExtIV128.rsp (AAD-only group) ───────────

/// CAVP PTlen=0, AADlen=128 — Count 0: AAD authenticated, no plaintext.
#[test]
fn aes128gcm_cavp_aad_only_count0() {
    check_vector(
        &Aes128Gcm,
        "77be63708971c4e240d1cb79e8d77feb",
        "e0e00f19fed7ba0136a797f3",
        "7a43ec1d9c0a5a78a0b16533a6213cab",
        "",
        "",
        "209fcc8d3675ed938e9c7166709dd946",
    );
}

/// CAVP PTlen=0, AADlen=128 — Count 1.
#[test]
fn aes128gcm_cavp_aad_only_count1() {
    check_vector(
        &Aes128Gcm,
        "7680c5d3ca6154758e510f4d25b98820",
        "f8f105f9c3df4965780321f8",
        "c94c410194c765e3dcc7964379758ed3",
        "",
        "",
        "94dca8edfcf90bb74b153c8d48a17930",
    );
}

// ── AES-256-GCM — NIST SP 800-38D / McGrew-Viega Appendix B ───────────────────

/// Test Case 13: empty plaintext, empty AAD.
#[test]
fn aes256gcm_nist_tc13_empty() {
    check_vector(
        &Aes256Gcm,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "",
        "",
        "530f8afbc74536b9a963b4f1c4cb738b",
    );
}

/// Test Case 14: single all-zero plaintext block, empty AAD.
#[test]
fn aes256gcm_nist_tc14_one_block() {
    check_vector(
        &Aes256Gcm,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "00000000000000000000000000000000",
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919",
    );
}

/// Test Case 15: four-block plaintext, no AAD (multi-block).
#[test]
fn aes256gcm_nist_tc15_multiblock_no_aad() {
    check_vector(
        &Aes256Gcm,
        "feffe9928665731c6d6a8f9467308308\
         feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "",
        "d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b391aafd255",
        "522dc1f099567d07f47f37a32a84427d\
         643a8cdcbfe5c0c97598a2bd2555d1aa\
         8cb08e48590dbb3da7b08b1056828838\
         c5f61e6393ba7a0abcc9f662898015ad",
        "b094dac5d93471bdec1a502270e3cc6c",
    );
}

/// Test Case 16: partial final block plaintext (60 bytes) with AAD.
#[test]
fn aes256gcm_nist_tc16_partial_block_with_aad() {
    check_vector(
        &Aes256Gcm,
        "feffe9928665731c6d6a8f9467308308\
         feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b39",
        "522dc1f099567d07f47f37a32a84427d\
         643a8cdcbfe5c0c97598a2bd2555d1aa\
         8cb08e48590dbb3da7b08b1056828838\
         c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b",
    );
}

// ── AES-256-GCM — NIST CAVP gcmEncryptExtIV256.rsp (AAD-only group) ───────────

/// CAVP PTlen=0, AADlen=128 — Count 0.
#[test]
fn aes256gcm_cavp_aad_only_count0() {
    check_vector(
        &Aes256Gcm,
        "78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223",
        "d79cf22d504cc793c3fb6c8a",
        "b96baa8c1c75a671bfb2d08d06be5f36",
        "",
        "",
        "3e5d486aa2e30b22e040b85723a06e76",
    );
}

/// CAVP PTlen=0, AADlen=128 — Count 1.
#[test]
fn aes256gcm_cavp_aad_only_count1() {
    check_vector(
        &Aes256Gcm,
        "4457ff33683cca6ca493878bdc00373893a9763412eef8cddb54f91318e0da88",
        "699d1f29d7b8c55300bb1fd2",
        "6749daeea367d0e9809e2dc2f309e6e3",
        "",
        "",
        "d60c74d2517fde4a74e0cd4709ed43a9",
    );
}

// ── Negative: tamper detection ────────────────────────────────────────────────

/// Flipping a single tag byte must cause `open` to return `InvalidTag`
/// for both key sizes.
#[test]
fn gcm_tag_tamper_rejected() {
    // AES-128 TC2.
    let key = hex_decode("00000000000000000000000000000000");
    let iv = hex_decode("000000000000000000000000");
    let pt = hex_decode("00000000000000000000000000000000");
    let mut ct = vec![0u8; pt.len() + 16];
    let written = Aes128Gcm
        .seal(&key, &iv, &[], &pt, &mut ct)
        .expect("seal 128");
    ct[written - 1] ^= 0x01; // flip a tag byte
    let mut pt_out = vec![0u8; pt.len()];
    assert_eq!(
        Aes128Gcm.open(&key, &iv, &[], &ct[..written], &mut pt_out),
        Err(CryptoError::InvalidTag),
        "AES-128-GCM must reject a flipped tag byte"
    );

    // AES-256 TC14.
    let key = hex_decode("0000000000000000000000000000000000000000000000000000000000000000");
    let mut ct = vec![0u8; pt.len() + 16];
    let written = Aes256Gcm
        .seal(&key, &iv, &[], &pt, &mut ct)
        .expect("seal 256");
    ct[written - 1] ^= 0x80; // flip a tag bit
    let mut pt_out = vec![0u8; pt.len()];
    assert_eq!(
        Aes256Gcm.open(&key, &iv, &[], &ct[..written], &mut pt_out),
        Err(CryptoError::InvalidTag),
        "AES-256-GCM must reject a flipped tag byte"
    );
}
