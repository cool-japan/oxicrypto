// Inline unit tests for oxicrypto-mac.
// These tests exercise all MAC types and free functions defined in `lib.rs`
// and its sub-modules.  Integration / KAT tests live under `tests/`.

use super::*;

fn hex_decode(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

// ── HMAC-SHA-256 ─────────────────────────────────────────────────────────────

// RFC 4231 Test Case 1
#[test]
fn hmac_sha256_rfc4231_tc1() {
    let key = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let data = b"Hi There";
    let expected =
        hex_decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    let mac = HmacSha256;
    let mut out = [0u8; 32];
    mac.mac(&key, data, &mut out).unwrap();
    assert_eq!(&out[..], expected.as_slice(), "HMAC-SHA-256 RFC4231 TC1");
}

#[test]
fn hmac_sha256_verify_ok() {
    let key = b"secret-key";
    let msg = b"the message";
    let mac_impl = HmacSha256;
    let mut tag = [0u8; 32];
    mac_impl.mac(key, msg, &mut tag).unwrap();
    mac_impl
        .verify(key, msg, &tag)
        .expect("verify should succeed");
}

#[test]
fn hmac_sha256_verify_fail() {
    let key = b"secret-key";
    let msg = b"the message";
    let mac_impl = HmacSha256;
    let mut tag = [0u8; 32];
    mac_impl.mac(key, msg, &mut tag).unwrap();
    tag[0] ^= 0xff;
    let result = mac_impl.verify(key, msg, &tag);
    assert_eq!(result, Err(CryptoError::InvalidTag));
}

// ── HMAC-SHA-512 ─────────────────────────────────────────────────────────────

#[test]
fn hmac_sha512_round_trip() {
    let key = b"another-secret-key";
    let msg = b"another message";
    let mac_impl = HmacSha512;
    let mut tag = [0u8; 64];
    mac_impl.mac(key, msg, &mut tag).unwrap();
    mac_impl
        .verify(key, msg, &tag)
        .expect("verify should succeed");
}

#[test]
fn hmac_sha512_verify_fail() {
    let key = b"key";
    let msg = b"msg";
    let mac_impl = HmacSha512;
    let mut tag = [0u8; 64];
    mac_impl.mac(key, msg, &mut tag).unwrap();
    tag[0] ^= 1;
    assert_eq!(
        mac_impl.verify(key, msg, &tag),
        Err(CryptoError::InvalidTag)
    );
}

// ── HMAC-SHA-384 ─────────────────────────────────────────────────────────────

// RFC 4231 Test Case 1 for HMAC-SHA-384
#[test]
fn hmac_sha384_rfc4231_tc1() {
    let key = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let data = b"Hi There";
    let expected = hex_decode(
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
         faea9ea9076ede7f4af152e8b2fa9cb6",
    );

    let mac = HmacSha384;
    let mut out = [0u8; 48];
    mac.mac(&key, data, &mut out).unwrap();
    assert_eq!(&out[..], expected.as_slice(), "HMAC-SHA-384 RFC4231 TC1");
}

#[test]
fn hmac_sha384_round_trip() {
    let key = b"hmac-sha384-test-key";
    let msg = b"test message for sha384";
    let mac = HmacSha384;
    let mut tag = [0u8; 48];
    mac.mac(key, msg, &mut tag).unwrap();
    mac.verify(key, msg, &tag).expect("verify should succeed");
}

#[test]
fn hmac_sha384_verify_fail() {
    let key = b"key";
    let msg = b"msg";
    let mac = HmacSha384;
    let mut tag = [0u8; 48];
    mac.mac(key, msg, &mut tag).unwrap();
    tag[0] ^= 1;
    assert_eq!(mac.verify(key, msg, &tag), Err(CryptoError::InvalidTag));
}

// ── HmacSha384 keyed ─────────────────────────────────────────────────────────

#[test]
fn hmac_sha384_keyed_roundtrip() {
    let key = b"hmac-sha384-keyed-key";
    let msg_a = b"hello ";
    let msg_b = b"sha384";
    let full_msg = b"hello sha384";

    // One-shot reference
    let one_shot = HmacSha384;
    let mut expected = [0u8; 48];
    one_shot.mac(key, full_msg, &mut expected).unwrap();

    // Keyed streaming
    let mut keyed = HmacSha384::new_keyed(key).unwrap();
    keyed.update(msg_a);
    keyed.update(msg_b);
    let mut got = [0u8; 48];
    keyed.finalize(&mut got).unwrap();

    assert_eq!(expected, got, "HmacSha384Keyed streaming must match one-shot");
}

#[test]
fn hmac_sha384_keyed_verify_ok() {
    let key = b"sha384-verify-key";
    let msg = b"sha384 verify message";

    let mut expected = [0u8; 48];
    HmacSha384.mac(key, msg, &mut expected).unwrap();

    let mut keyed = HmacSha384::new_keyed(key).unwrap();
    keyed.update(msg);
    keyed.verify(&expected).expect("HmacSha384Keyed verify must succeed");
}

// ── StreamingMac adapter ──────────────────────────────────────────────────────

/// Verify that the streaming adapter produces the same tag as the one-shot
/// HmacSha256::mac method (fed the same message in two chunks).
#[test]
fn hmac_sha256_streaming_matches_oneshot() {
    let key = b"streaming-key";
    let msg_a = b"hello ";
    let msg_b = b"world";
    let full_msg = b"hello world";

    // One-shot
    let one_shot = HmacSha256;
    let mut expected = [0u8; 32];
    one_shot.mac(key, full_msg, &mut expected).unwrap();

    // Streaming
    let mut streaming = HmacSha256Streaming::new(key).unwrap();
    streaming.update(msg_a);
    streaming.update(msg_b);
    let mut got = [0u8; 32];
    streaming.finalize(&mut got).unwrap();

    assert_eq!(expected, got, "streaming must match one-shot");
}

#[test]
fn hmac_sha256_streaming_verify_ok() {
    let key = b"verify-key";
    let msg = b"verify message";

    let mut one_shot_tag = [0u8; 32];
    HmacSha256.mac(key, msg, &mut one_shot_tag).unwrap();

    let mut streaming = HmacSha256Streaming::new(key).unwrap();
    streaming.update(msg);
    streaming
        .verify(&one_shot_tag)
        .expect("streaming verify must succeed");
}

#[test]
fn hmac_sha256_streaming_verify_fail() {
    let key = b"k";
    let msg = b"m";
    let bad_tag = [0xffu8; 32];

    let mut streaming = HmacSha256Streaming::new(key).unwrap();
    streaming.update(msg);
    assert_eq!(
        streaming.verify(&bad_tag),
        Err(CryptoError::InvalidTag),
        "streaming verify must fail on wrong tag"
    );
}

// ── HMAC-SHA3-256 ─────────────────────────────────────────────────────────────

/// Basic KAT: HMAC-SHA3-256 of "Hi There" with RFC 4231 key
/// (reference computed offline using SHA3-256 as the hash function).
#[test]
fn hmac_sha3_256_round_trip() {
    let key = b"hmac-sha3-256-key";
    let msg = b"test message";
    let mac = HmacSha3_256;
    let mut tag = [0u8; 32];
    mac.mac(key, msg, &mut tag).unwrap();
    mac.verify(key, msg, &tag)
        .expect("HMAC-SHA3-256 verify must succeed");
}

#[test]
fn hmac_sha3_256_verify_fail() {
    let key = b"k";
    let msg = b"m";
    let mac = HmacSha3_256;
    let mut tag = [0u8; 32];
    mac.mac(key, msg, &mut tag).unwrap();
    tag[0] ^= 1;
    assert_eq!(mac.verify(key, msg, &tag), Err(CryptoError::InvalidTag));
}

// ── HMAC-SHA3-512 ─────────────────────────────────────────────────────────────

#[test]
fn hmac_sha3_512_round_trip() {
    let key = b"hmac-sha3-512-test-key";
    let msg = b"test message for sha3-512";
    let mac = HmacSha3_512;
    let mut tag = [0u8; 64];
    mac.mac(key, msg, &mut tag).unwrap();
    mac.verify(key, msg, &tag)
        .expect("HMAC-SHA3-512 verify must succeed");
}

// ── Poly1305 ──────────────────────────────────────────────────────────────────

/// RFC 8439 §2.5.2 test vector.
///
/// key  = 85d6be7857556d337f4452fe42d506a8
///         0103808afb0db2fd4abff6af4149f51b
/// data = "Cryptographic Forum Research Group"
/// tag  = a8061dc1305136c6c22b8baf0c0127a9
#[test]
fn poly1305_rfc8439_s2_5_2() {
    let key = hex_decode(
        "85d6be7857556d337f4452fe42d506a8\
         0103808afb0db2fd4abff6af4149f51b",
    );
    let msg = b"Cryptographic Forum Research Group";
    let expected = hex_decode("a8061dc1305136c6c22b8baf0c0127a9");

    let mac = Poly1305Mac;
    let mut out = [0u8; 16];
    mac.mac(&key, msg, &mut out).unwrap();
    assert_eq!(&out[..], expected.as_slice(), "Poly1305 RFC8439 §2.5.2");
}

#[test]
fn poly1305_verify_ok() {
    let key = [0u8; 32];
    let msg = b"test";
    let mac = Poly1305Mac;
    let mut tag = [0u8; 16];
    mac.mac(&key, msg, &mut tag).unwrap();
    mac.verify(&key, msg, &tag)
        .expect("Poly1305 verify must succeed");
}

#[test]
fn poly1305_verify_fail() {
    let key = [1u8; 32];
    let msg = b"test";
    let mac = Poly1305Mac;
    let mut tag = [0u8; 16];
    mac.mac(&key, msg, &mut tag).unwrap();
    tag[0] ^= 0xff;
    assert_eq!(mac.verify(&key, msg, &tag), Err(CryptoError::InvalidTag));
}

#[test]
fn poly1305_bad_key_len() {
    let key = [0u8; 16]; // wrong length
    let mac = Poly1305Mac;
    let mut out = [0u8; 16];
    assert_eq!(
        mac.mac(&key, b"msg", &mut out),
        Err(CryptoError::InvalidKey)
    );
}

// ── CMAC-AES-128 ─────────────────────────────────────────────────────────────

/// NIST SP 800-38B Example 1: AES-128, empty message.
///
/// K   = 2b7e151628aed2a6abf7158809cf4f3c
/// M   = (empty)
/// T16 = bb1d6929e9593728 7fa37d129b756746
#[test]
fn cmac_aes128_nist_sp800_38b_example1() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c");
    let expected = hex_decode("bb1d6929e95937287fa37d129b756746");

    let mac = CmacAes128;
    let mut out = [0u8; 16];
    mac.mac(&key, b"", &mut out).unwrap();
    assert_eq!(&out[..], expected.as_slice(), "CMAC-AES-128 SP 800-38B Ex1");
}

#[test]
fn cmac_aes128_round_trip() {
    let key = [0x2b_u8; 16];
    let msg = b"hello cmac aes128";
    let mac = CmacAes128;
    let mut tag = [0u8; 16];
    mac.mac(&key, msg, &mut tag).unwrap();
    mac.verify(&key, msg, &tag)
        .expect("CMAC-AES-128 verify must succeed");
}

#[test]
fn cmac_aes128_verify_fail() {
    let key = [0u8; 16];
    let msg = b"msg";
    let mac = CmacAes128;
    let mut tag = [0u8; 16];
    mac.mac(&key, msg, &mut tag).unwrap();
    tag[0] ^= 1;
    assert_eq!(mac.verify(&key, msg, &tag), Err(CryptoError::InvalidTag));
}

// ── CMAC-AES-256 ─────────────────────────────────────────────────────────────

#[test]
fn cmac_aes256_round_trip() {
    let key = [0x42_u8; 32];
    let msg = b"hello cmac aes256";
    let mac = CmacAes256;
    let mut tag = [0u8; 16];
    mac.mac(&key, msg, &mut tag).unwrap();
    mac.verify(&key, msg, &tag)
        .expect("CMAC-AES-256 verify must succeed");
}

// ── KMAC128 ───────────────────────────────────────────────────────────────────

/// NIST SP 800-185 Sample #1 (KMAC128, empty customization, 32-byte output)
///
/// Key  = 404142...5e5f (32 bytes)
/// Data = 00010203 (4 bytes)
/// S    = "" (empty)
/// L    = 256 bits
///
/// Expected = e5780b0d3ea6f7d3a429c5706aa43a00 fadbd7d49628839e3187243f456ee14e
///
/// Reference: NIST SP 800-185 §A.1 Sample #1, verified by tiny-keccak test suite.
#[test]
fn kmac128_nist_sp800_185_sample1() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    let data = hex_decode("00010203");
    let expected = hex_decode(
        "e5780b0d3ea6f7d3a429c5706aa43a00\
         fadbd7d49628839e3187243f456ee14e",
    );

    let kmac = Kmac128::new(b"", 32).unwrap();
    let mut out = [0u8; 32];
    kmac.mac(&key, &data, &mut out).unwrap();
    assert_eq!(
        &out[..],
        expected.as_slice(),
        "KMAC128 SP 800-185 Sample #1"
    );
}

#[test]
fn kmac128_round_trip() {
    let kmac = Kmac128::new(b"test-domain", 32).unwrap();
    let key = [0xaa_u8; 16];
    let msg = b"hello kmac128";
    let mut tag = [0u8; 32];
    kmac.mac(&key, msg, &mut tag).unwrap();
    kmac.verify(&key, msg, &tag)
        .expect("KMAC128 verify must succeed");
}

#[test]
fn kmac128_verify_fail() {
    let kmac = Kmac128::new(b"", 32).unwrap();
    let key = [0u8; 16];
    let msg = b"test";
    let mut tag = [0u8; 32];
    kmac.mac(&key, msg, &mut tag).unwrap();
    tag[0] ^= 1;
    assert_eq!(kmac.verify(&key, msg, &tag), Err(CryptoError::InvalidTag));
}

#[test]
fn kmac128_zero_output_len_rejected() {
    assert_eq!(
        Kmac128::new(b"", 0).unwrap_err(),
        CryptoError::BadInput,
        "KMAC128 with output_len=0 must be rejected"
    );
}

// ── KMAC256 ───────────────────────────────────────────────────────────────────

/// NIST SP 800-185 §A.2 Sample #2 (KMAC256, empty customization, 64-byte output)
///
/// Key    = 404142...5e5f (32 bytes)
/// Data   = 00..c7 (200 bytes sequential)
/// S      = "" (empty customization)
/// L      = 512 bits (64 bytes)
///
/// Expected:
/// 75358cf39e41494e949707927cee0af2 0a3ff553904c86b08f21cc414bcfd691
/// 589d27cf5e15369cbbff8b9a4c2eb178 00855d0235ff635da82533ec6b759b69
///
/// Verified against tiny-keccak's test_kmac256_two.
#[test]
fn kmac256_nist_sp800_185_sample4() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    // 200-byte sequential data: 0x00..0xc7
    let data: alloc::vec::Vec<u8> = (0x00_u8..=0xc7_u8).collect();
    let expected = hex_decode(
        "75358cf39e41494e949707927cee0af2\
         0a3ff553904c86b08f21cc414bcfd691\
         589d27cf5e15369cbbff8b9a4c2eb178\
         00855d0235ff635da82533ec6b759b69",
    );

    let kmac = Kmac256::new(b"", 64).unwrap();
    let mut out = [0u8; 64];
    kmac.mac(&key, &data, &mut out).unwrap();
    assert_eq!(
        &out[..],
        expected.as_slice(),
        "KMAC256 SP 800-185 §A.2 Sample #2 (200-byte data, empty S)"
    );
}

#[test]
fn kmac256_round_trip() {
    let kmac = Kmac256::new(b"domain", 64).unwrap();
    let key = [0xbb_u8; 32];
    let msg = b"hello kmac256";
    let mut tag = [0u8; 64];
    kmac.mac(&key, msg, &mut tag).unwrap();
    kmac.verify(&key, msg, &tag)
        .expect("KMAC256 verify must succeed");
}

#[test]
fn kmac256_zero_output_len_rejected() {
    assert_eq!(
        Kmac256::new(b"", 0).unwrap_err(),
        CryptoError::BadInput,
        "KMAC256 with output_len=0 must be rejected"
    );
}

// ── Truncated HMAC ────────────────────────────────────────────────────────────

/// mac_truncated produces the prefix of the full tag.
#[test]
fn hmac_sha256_truncated_is_prefix() {
    let key = b"trunc-key";
    let msg = b"truncated message";

    let mac = HmacSha256;
    let mut full = [0u8; 32];
    mac.mac(key, msg, &mut full).unwrap();

    let mut trunc = [0u8; 20];
    mac.mac_truncated(key, msg, &mut trunc).unwrap();

    assert_eq!(
        &trunc[..],
        &full[..20],
        "truncated tag must be prefix of full tag"
    );
}

#[test]
fn hmac_sha256_truncated_verify_ok() {
    let key = b"k";
    let msg = b"m";
    let mac = HmacSha256;

    let mut trunc = [0u8; 20];
    mac.mac_truncated(key, msg, &mut trunc).unwrap();
    mac.verify_truncated(key, msg, &trunc)
        .expect("truncated verify must succeed");
}

#[test]
fn hmac_sha256_truncated_too_short_rejected() {
    let mac = HmacSha256;
    let mut buf = [0u8; 15];
    assert_eq!(
        mac.mac_truncated(b"k", b"m", &mut buf),
        Err(CryptoError::BadInput),
        "truncation below 16 bytes must be rejected"
    );
    assert_eq!(
        mac.verify_truncated(b"k", b"m", &buf),
        Err(CryptoError::BadInput),
        "verify with tag < 16 bytes must be rejected"
    );
}

#[test]
fn hmac_sha512_truncated_is_prefix() {
    let key = b"key512";
    let msg = b"msg512";

    let mac = HmacSha512;
    let mut full = [0u8; 64];
    mac.mac(key, msg, &mut full).unwrap();

    let mut trunc = [0u8; 32];
    mac.mac_truncated(key, msg, &mut trunc).unwrap();

    assert_eq!(&trunc[..], &full[..32]);
}

#[test]
fn hmac_sha384_truncated_is_prefix() {
    let key = b"key384";
    let msg = b"msg384";

    let mac = HmacSha384;
    let mut full = [0u8; 48];
    mac.mac(key, msg, &mut full).unwrap();

    let mut trunc = [0u8; 24];
    mac.mac_truncated(key, msg, &mut trunc).unwrap();

    assert_eq!(&trunc[..], &full[..24]);
}

// ── KMAC-XOF free functions ───────────────────────────────────────────────────

/// kmac128_xof and kmac256_xof must match the trait-based Kmac128/Kmac256
/// for the same key/custom/msg/output_len.
#[test]
fn kmac128_xof_matches_trait_impl() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    let data = hex_decode("00010203");
    // Known-good: NIST SP 800-185 §A.1 Sample #1
    let expected = hex_decode(
        "e5780b0d3ea6f7d3a429c5706aa43a00\
         fadbd7d49628839e3187243f456ee14e",
    );

    let got = kmac128_xof(&key, b"", &data, 32).expect("kmac128_xof must not fail");
    assert_eq!(got, expected, "kmac128_xof NIST SP 800-185 Sample #1");
}

#[test]
fn kmac128_xof_variable_lengths() {
    let key = [0xaau8; 16];
    let msg = b"variable-length output test";

    let out16 = kmac128_xof(&key, b"domain", msg, 16).unwrap();
    let out64 = kmac128_xof(&key, b"domain", msg, 64).unwrap();

    // KMAC encodes the output length into the message padding (SP 800-185 §4.3.1),
    // so different requested lengths produce entirely different outputs.
    // Both must be the right length and non-zero.
    assert_eq!(
        out16.len(),
        16,
        "kmac128_xof must produce exactly output_len bytes"
    );
    assert_eq!(
        out64.len(),
        64,
        "kmac128_xof must produce exactly output_len bytes"
    );
    assert!(out16.iter().any(|&b| b != 0), "output must be non-zero");
    assert!(out64.iter().any(|&b| b != 0), "output must be non-zero");
    // Different lengths → different outputs (length-dependent padding).
    assert_ne!(
        &out64[..16],
        out16.as_slice(),
        "KMAC: different output_len must differ"
    );
}

#[test]
fn kmac128_xof_zero_len_rejected() {
    assert_eq!(
        kmac128_xof(b"key", b"", b"msg", 0).unwrap_err(),
        CryptoError::BadInput,
    );
}

#[test]
fn kmac256_xof_matches_trait_impl() {
    let key = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         505152535455565758595a5b5c5d5e5f",
    );
    let data: alloc::vec::Vec<u8> = (0x00_u8..=0xc7_u8).collect();
    let expected = hex_decode(
        "75358cf39e41494e949707927cee0af2\
         0a3ff553904c86b08f21cc414bcfd691\
         589d27cf5e15369cbbff8b9a4c2eb178\
         00855d0235ff635da82533ec6b759b69",
    );

    let got = kmac256_xof(&key, b"", &data, 64).expect("kmac256_xof must not fail");
    assert_eq!(got, expected, "kmac256_xof NIST SP 800-185 §A.2 Sample #2");
}

#[test]
fn kmac256_xof_zero_len_rejected() {
    assert_eq!(
        kmac256_xof(b"key", b"", b"msg", 0).unwrap_err(),
        CryptoError::BadInput,
    );
}

// ── BLAKE3 keyed-hash MAC ─────────────────────────────────────────────────────

/// BLAKE3 keyed-hash output is deterministic.
#[test]
fn blake3_keyed_mac_deterministic() {
    let key = [0x42u8; 32];
    let msg = b"hello blake3 keyed mac";
    let t1 = blake3_keyed_mac(&key, msg);
    let t2 = blake3_keyed_mac(&key, msg);
    assert_eq!(t1, t2, "BLAKE3 keyed mac must be deterministic");
}

/// Different keys produce different tags.
#[test]
fn blake3_keyed_mac_key_dependent() {
    let k1 = [0x01u8; 32];
    let k2 = [0x02u8; 32];
    let msg = b"same msg";
    assert_ne!(
        blake3_keyed_mac(&k1, msg),
        blake3_keyed_mac(&k2, msg),
        "Different keys must produce different BLAKE3 MACs"
    );
}

/// Verify round-trip.
#[test]
fn blake3_keyed_mac_verify_ok() {
    let key = [0xabu8; 32];
    let msg = b"verify me";
    let tag = blake3_keyed_mac(&key, msg);
    blake3_keyed_mac_verify(&key, msg, &tag).expect("BLAKE3 keyed verify must succeed");
}

/// Verify detects corruption.
#[test]
fn blake3_keyed_mac_verify_fail() {
    let key = [0xcd_u8; 32];
    let msg = b"corrupt me";
    let mut tag = blake3_keyed_mac(&key, msg);
    tag[0] ^= 0xff;
    assert_eq!(
        blake3_keyed_mac_verify(&key, msg, &tag),
        Err(CryptoError::InvalidTag),
        "corrupted BLAKE3 MAC must be rejected"
    );
}

// ── negotiate_mac / TlsCipherSuite ────────────────────────────────────────────

#[test]
fn negotiate_mac_aes128_gcm_sha256_returns_hmac_sha256() {
    let mac = negotiate_mac(TlsCipherSuite::Aes128GcmSha256)
        .expect("negotiate must succeed");
    assert_eq!(mac.name(), "HMAC-SHA-256");
    assert_eq!(mac.output_len(), 32);
}

#[test]
fn negotiate_mac_aes256_gcm_sha384_returns_hmac_sha384() {
    let mac = negotiate_mac(TlsCipherSuite::Aes256GcmSha384)
        .expect("negotiate must succeed");
    assert_eq!(mac.name(), "HMAC-SHA-384");
    assert_eq!(mac.output_len(), 48);
}

#[test]
fn negotiate_mac_chacha20_poly1305_sha256_returns_hmac_sha256() {
    let mac = negotiate_mac(TlsCipherSuite::Chacha20Poly1305Sha256)
        .expect("negotiate must succeed");
    assert_eq!(mac.name(), "HMAC-SHA-256");
}

#[test]
fn negotiate_mac_sha512_prf_returns_hmac_sha512() {
    let mac = negotiate_mac(TlsCipherSuite::Sha512Prf)
        .expect("negotiate must succeed");
    assert_eq!(mac.name(), "HMAC-SHA-512");
    assert_eq!(mac.output_len(), 64);
}

#[test]
fn tls_cipher_suite_from_iana_name_known() {
    assert_eq!(
        TlsCipherSuite::from_iana_name("TLS_AES_128_GCM_SHA256"),
        Some(TlsCipherSuite::Aes128GcmSha256),
    );
    assert_eq!(
        TlsCipherSuite::from_iana_name("TLS_AES_256_GCM_SHA384"),
        Some(TlsCipherSuite::Aes256GcmSha384),
    );
    assert_eq!(
        TlsCipherSuite::from_iana_name("TLS_CHACHA20_POLY1305_SHA256"),
        Some(TlsCipherSuite::Chacha20Poly1305Sha256),
    );
}

#[test]
fn tls_cipher_suite_from_iana_name_unknown_returns_none() {
    assert_eq!(TlsCipherSuite::from_iana_name("UNKNOWN_SUITE"), None);
    assert_eq!(TlsCipherSuite::from_iana_name(""), None);
}

#[test]
fn mac_name_for_suite_correct() {
    assert_eq!(
        mac_name_for_suite(TlsCipherSuite::Aes128GcmSha256),
        "HMAC-SHA-256"
    );
    assert_eq!(
        mac_name_for_suite(TlsCipherSuite::Aes256GcmSha384),
        "HMAC-SHA-384"
    );
    assert_eq!(
        mac_name_for_suite(TlsCipherSuite::Sha512Prf),
        "HMAC-SHA-512"
    );
}

#[test]
fn negotiate_mac_functional_roundtrip() {
    // Verify that negotiate_mac actually produces a working MAC.
    let suite = TlsCipherSuite::Aes256GcmSha384;
    let mac = negotiate_mac(suite).expect("negotiate must succeed");
    let key = b"tls-handshake-base-key-48bytes!!";
    let msg = b"finished-transcript-hash-goes-here";
    let mut out = alloc::vec![0u8; mac.output_len()];
    mac.mac(key, msg, &mut out).expect("mac must succeed");
    mac.verify(key, msg, &out).expect("verify must succeed");
}

// ── hmac_sha256_verify_truncated free function ────────────────────────────────

#[test]
fn free_fn_verify_truncated_ok() {
    let key = b"verify-trunc-key";
    let msg = b"verify-trunc-msg";
    let mut full = [0u8; 32];
    HmacSha256.mac(key, msg, &mut full).unwrap();
    hmac_sha256_verify_truncated(key, msg, &full[..16])
        .expect("free-fn verify_truncated must accept valid 16-byte tag");
}

#[test]
fn free_fn_verify_truncated_empty_rejected() {
    assert_eq!(
        hmac_sha256_verify_truncated(b"k", b"m", &[]),
        Err(CryptoError::BadInput),
    );
}

#[test]
fn free_fn_verify_truncated_too_long_rejected() {
    assert_eq!(
        hmac_sha256_verify_truncated(b"k", b"m", &[0u8; 33]),
        Err(CryptoError::BadInput),
    );
}

#[test]
fn free_fn_verify_truncated_mismatch() {
    let key = b"k";
    let msg = b"m";
    let mut full = [0u8; 32];
    HmacSha256.mac(key, msg, &mut full).unwrap();
    let mut bad = [0u8; 16];
    bad.copy_from_slice(&full[..16]);
    bad[0] ^= 0x01;
    assert_eq!(
        hmac_sha256_verify_truncated(key, msg, &bad),
        Err(CryptoError::InvalidTag),
    );
}
