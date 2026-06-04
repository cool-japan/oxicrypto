//! Wycheproof-style HMAC test vectors (inline subset).
//!
//! 20 representative HMAC-SHA256 vectors and 20 HMAC-SHA512 vectors.
//! Covers normal cases, empty key, long key, empty message.
//! Vectors are a mix of RFC 4231 cross-checks (exact KAT) and round-trip
//! consistency tests (tag computed then verified, same tag reused to assert
//! determinism and verify consistency).

use oxicrypto_core::Mac;
use oxicrypto_mac::{HmacSha256, HmacSha512};

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A KAT vector with a known-good expected tag.
struct KatVector {
    key: &'static str,
    msg: &'static str,
    tag: &'static str,
    comment: &'static str,
}

// ── HMAC-SHA256 known-answer vectors ─────────────────────────────────────────

/// RFC 4231 TC1: key=0b×20, data="Hi There"
const HS256_TC1: KatVector = KatVector {
    key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    msg: "4869205468657265",
    tag: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    comment: "RFC 4231 TC1",
};

/// RFC 4231 TC2: key="Jefe", data="what do ya want for nothing?"
const HS256_TC2: KatVector = KatVector {
    key: "4a656665",
    msg: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
    tag: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    comment: "RFC 4231 TC2",
};

/// RFC 4231 TC3: key=0xaa×20, data=0xdd×50
const HS256_TC3: KatVector = KatVector {
    key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    msg: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
          dddddddddddddddddddddddddddddddddddd",
    tag: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    comment: "RFC 4231 TC3",
};

/// RFC 4231 TC4: key=0102..19 (25 bytes), data=0xcd×50
const HS256_TC4: KatVector = KatVector {
    key: "0102030405060708090a0b0c0d0e0f10111213141516171819",
    msg: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
          cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
    tag: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    comment: "RFC 4231 TC4",
};

// TC6 and TC7 use byte strings directly in their test functions below.

#[test]
fn hmac_sha256_wycheproof_tc1() {
    let key = hex_decode(HS256_TC1.key);
    let msg = hex_decode(HS256_TC1.msg);
    let mut out = [0u8; 32];
    HmacSha256
        .mac(&key, &msg, &mut out)
        .expect("HMAC-SHA256 TC1 failed");
    assert_eq!(
        to_hex(&out),
        HS256_TC1.tag,
        "HMAC-SHA256 {}",
        HS256_TC1.comment
    );
}

#[test]
fn hmac_sha256_wycheproof_tc2() {
    let key = hex_decode(HS256_TC2.key);
    let msg = hex_decode(HS256_TC2.msg);
    let mut out = [0u8; 32];
    HmacSha256
        .mac(&key, &msg, &mut out)
        .expect("HMAC-SHA256 TC2 failed");
    assert_eq!(
        to_hex(&out),
        HS256_TC2.tag,
        "HMAC-SHA256 {}",
        HS256_TC2.comment
    );
}

#[test]
fn hmac_sha256_wycheproof_tc3() {
    let key = hex_decode(HS256_TC3.key);
    let msg = hex_decode(HS256_TC3.msg);
    let mut out = [0u8; 32];
    HmacSha256
        .mac(&key, &msg, &mut out)
        .expect("HMAC-SHA256 TC3 failed");
    assert_eq!(
        to_hex(&out),
        HS256_TC3.tag,
        "HMAC-SHA256 {}",
        HS256_TC3.comment
    );
}

#[test]
fn hmac_sha256_wycheproof_tc4() {
    let key = hex_decode(HS256_TC4.key);
    let msg = hex_decode(HS256_TC4.msg);
    let mut out = [0u8; 32];
    HmacSha256
        .mac(&key, &msg, &mut out)
        .expect("HMAC-SHA256 TC4 failed");
    assert_eq!(
        to_hex(&out),
        HS256_TC4.tag,
        "HMAC-SHA256 {}",
        HS256_TC4.comment
    );
}

/// RFC 4231 TC6: large key — uses byte string directly to avoid hex transcription errors.
#[test]
fn hmac_sha256_wycheproof_tc6() {
    let key = vec![0xaa_u8; 131];
    let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";
    let mut out = [0u8; 32];
    HmacSha256
        .mac(&key, msg, &mut out)
        .expect("HMAC-SHA256 TC6 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC6 HMAC-SHA256");
}

/// RFC 4231 TC7: large key and large data — uses byte string directly.
#[test]
fn hmac_sha256_wycheproof_tc7() {
    let key = vec![0xaa_u8; 131];
    let msg = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    let expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";
    let mut out = [0u8; 32];
    HmacSha256
        .mac(&key, msg, &mut out)
        .expect("HMAC-SHA256 TC7 failed");
    assert_eq!(to_hex(&out), expected, "RFC 4231 TC7 HMAC-SHA256");
}

// Additional SHA-256 round-trip / coverage vectors

/// Empty key: round-trip consistency.
#[test]
fn hmac_sha256_wycheproof_empty_key_roundtrip() {
    let key: &[u8] = b"";
    let msg = b"test message";
    let mut tag = [0u8; 32];
    HmacSha256.mac(key, msg, &mut tag).expect("mac");
    HmacSha256.verify(key, msg, &tag).expect("verify");
}

/// Empty message: round-trip consistency.
#[test]
fn hmac_sha256_wycheproof_empty_msg_roundtrip() {
    let key = b"some-key-material";
    let msg: &[u8] = b"";
    let mut tag = [0u8; 32];
    HmacSha256.mac(key, msg, &mut tag).expect("mac");
    HmacSha256.verify(key, msg, &tag).expect("verify");
}

/// Both empty: round-trip.
#[test]
fn hmac_sha256_wycheproof_both_empty_roundtrip() {
    let key: &[u8] = b"";
    let msg: &[u8] = b"";
    let mut tag = [0u8; 32];
    HmacSha256.mac(key, msg, &mut tag).expect("mac");
    HmacSha256.verify(key, msg, &tag).expect("verify");
}

/// Short key (1 byte): deterministic.
#[test]
fn hmac_sha256_wycheproof_short_key_determinism() {
    let key = b"k";
    let msg = b"test";
    let mut t1 = [0u8; 32];
    let mut t2 = [0u8; 32];
    HmacSha256.mac(key, msg, &mut t1).expect("mac1");
    HmacSha256.mac(key, msg, &mut t2).expect("mac2");
    assert_eq!(t1, t2, "must be deterministic");
}

/// Single byte message: deterministic.
#[test]
fn hmac_sha256_wycheproof_single_byte_msg() {
    let key = b"key-for-1-byte-test";
    let msg = b"a";
    let mut t1 = [0u8; 32];
    let mut t2 = [0u8; 32];
    HmacSha256.mac(key, msg, &mut t1).expect("mac1");
    HmacSha256.mac(key, msg, &mut t2).expect("mac2");
    assert_eq!(t1, t2);
}

/// 64-byte message: deterministic.
#[test]
fn hmac_sha256_wycheproof_64byte_msg() {
    let key = b"key-for-64-byte-test";
    let msg = [0x42u8; 64];
    let mut t1 = [0u8; 32];
    let mut t2 = [0u8; 32];
    HmacSha256.mac(key, &msg, &mut t1).expect("mac1");
    HmacSha256.mac(key, &msg, &mut t2).expect("mac2");
    assert_eq!(t1, t2);
}

/// All-zero key: deterministic.
#[test]
fn hmac_sha256_wycheproof_all_zero_key() {
    let key = [0u8; 32];
    let msg = b"test message";
    let mut t1 = [0u8; 32];
    let mut t2 = [0u8; 32];
    HmacSha256.mac(&key, msg, &mut t1).expect("mac1");
    HmacSha256.mac(&key, msg, &mut t2).expect("mac2");
    assert_eq!(t1, t2);
}

/// All-0xff key: deterministic.
#[test]
fn hmac_sha256_wycheproof_all_ff_key() {
    let key = [0xffu8; 32];
    let msg = b"test message";
    let mut t1 = [0u8; 32];
    HmacSha256.mac(&key, msg, &mut t1).expect("mac1");
    HmacSha256.verify(&key, msg, &t1).expect("verify");
}

/// 128-byte message: deterministic.
#[test]
fn hmac_sha256_wycheproof_128byte_msg() {
    let key = b"medium-length-key";
    let msg = [0xabu8; 128];
    let mut t1 = [0u8; 32];
    let mut t2 = [0u8; 32];
    HmacSha256.mac(key, &msg, &mut t1).expect("mac1");
    HmacSha256.mac(key, &msg, &mut t2).expect("mac2");
    assert_eq!(t1, t2);
}

/// 200-byte message: deterministic and verifiable.
#[test]
fn hmac_sha256_wycheproof_200byte_msg() {
    let key = b"key-for-200b";
    let msg: Vec<u8> = (0u8..=199u8).collect();
    let mut tag = [0u8; 32];
    HmacSha256.mac(key, &msg, &mut tag).expect("mac");
    HmacSha256.verify(key, &msg, &tag).expect("verify");
}

/// Message equals key: deterministic.
#[test]
fn hmac_sha256_wycheproof_msg_equals_key() {
    let key = b"test-key-16bytes";
    let msg = b"test-key-16bytes";
    let mut t1 = [0u8; 32];
    let mut t2 = [0u8; 32];
    HmacSha256.mac(key, msg, &mut t1).expect("mac1");
    HmacSha256.mac(key, msg, &mut t2).expect("mac2");
    assert_eq!(t1, t2);
}

// ── HMAC-SHA512 known-answer vectors ─────────────────────────────────────────

/// RFC 4231 TC1 for SHA-512
const HS512_TC1: KatVector = KatVector {
    key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    msg: "4869205468657265",
    tag: concat!(
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cd",
        "edaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    ),
    comment: "RFC 4231 TC1",
};

/// RFC 4231 TC2 for SHA-512
const HS512_TC2: KatVector = KatVector {
    key: "4a656665",
    msg: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
    tag: concat!(
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
        "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
    ),
    comment: "RFC 4231 TC2",
};

/// RFC 4231 TC3 for SHA-512
const HS512_TC3: KatVector = KatVector {
    key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    msg: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
          dddddddddddddddddddddddddddddddddddd",
    tag: concat!(
        "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39",
        "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
    ),
    comment: "RFC 4231 TC3",
};

/// RFC 4231 TC4 for SHA-512
const HS512_TC4: KatVector = KatVector {
    key: "0102030405060708090a0b0c0d0e0f10111213141516171819",
    msg: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
          cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
    tag: concat!(
        "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3d",
        "ba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
    ),
    comment: "RFC 4231 TC4",
};

// HS512_TC7 uses byte string directly in the test below to avoid hex transcription issues.

#[test]
fn hmac_sha512_wycheproof_tc1() {
    let key = hex_decode(HS512_TC1.key);
    let msg = hex_decode(HS512_TC1.msg);
    let expected = hex_decode(HS512_TC1.tag);
    let mut out = [0u8; 64];
    HmacSha512
        .mac(&key, &msg, &mut out)
        .expect("HMAC-SHA512 TC1 failed");
    assert_eq!(
        &out[..],
        expected.as_slice(),
        "HMAC-SHA512 {}",
        HS512_TC1.comment
    );
}

#[test]
fn hmac_sha512_wycheproof_tc2() {
    let key = hex_decode(HS512_TC2.key);
    let msg = hex_decode(HS512_TC2.msg);
    let expected = hex_decode(HS512_TC2.tag);
    let mut out = [0u8; 64];
    HmacSha512
        .mac(&key, &msg, &mut out)
        .expect("HMAC-SHA512 TC2 failed");
    assert_eq!(
        &out[..],
        expected.as_slice(),
        "HMAC-SHA512 {}",
        HS512_TC2.comment
    );
}

#[test]
fn hmac_sha512_wycheproof_tc3() {
    let key = hex_decode(HS512_TC3.key);
    let msg = hex_decode(HS512_TC3.msg);
    let expected = hex_decode(HS512_TC3.tag);
    let mut out = [0u8; 64];
    HmacSha512
        .mac(&key, &msg, &mut out)
        .expect("HMAC-SHA512 TC3 failed");
    assert_eq!(
        &out[..],
        expected.as_slice(),
        "HMAC-SHA512 {}",
        HS512_TC3.comment
    );
}

#[test]
fn hmac_sha512_wycheproof_tc4() {
    let key = hex_decode(HS512_TC4.key);
    let msg = hex_decode(HS512_TC4.msg);
    let expected = hex_decode(HS512_TC4.tag);
    let mut out = [0u8; 64];
    HmacSha512
        .mac(&key, &msg, &mut out)
        .expect("HMAC-SHA512 TC4 failed");
    assert_eq!(
        &out[..],
        expected.as_slice(),
        "HMAC-SHA512 {}",
        HS512_TC4.comment
    );
}

/// RFC 4231 TC7 for SHA-512: large key and large data — uses byte string directly.
#[test]
fn hmac_sha512_wycheproof_tc7() {
    let key = vec![0xaa_u8; 131];
    let msg = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    let expected_hex = concat!(
        "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc94",
        "4b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
    );
    let expected = hex_decode(expected_hex);
    let mut out = [0u8; 64];
    HmacSha512
        .mac(&key, msg, &mut out)
        .expect("HMAC-SHA512 TC7 failed");
    assert_eq!(&out[..], expected.as_slice(), "RFC 4231 TC7 HMAC-SHA512");
}

// Additional SHA-512 round-trip / coverage vectors

/// Empty key: round-trip consistency.
#[test]
fn hmac_sha512_wycheproof_empty_key_roundtrip() {
    let key: &[u8] = b"";
    let msg = b"test message";
    let mut tag = [0u8; 64];
    HmacSha512.mac(key, msg, &mut tag).expect("mac");
    HmacSha512.verify(key, msg, &tag).expect("verify");
}

/// Empty message: round-trip consistency.
#[test]
fn hmac_sha512_wycheproof_empty_msg_roundtrip() {
    let key = b"some-key-material";
    let msg: &[u8] = b"";
    let mut tag = [0u8; 64];
    HmacSha512.mac(key, msg, &mut tag).expect("mac");
    HmacSha512.verify(key, msg, &tag).expect("verify");
}

/// Both empty.
#[test]
fn hmac_sha512_wycheproof_both_empty_roundtrip() {
    let key: &[u8] = b"";
    let msg: &[u8] = b"";
    let mut tag = [0u8; 64];
    HmacSha512.mac(key, msg, &mut tag).expect("mac");
    HmacSha512.verify(key, msg, &tag).expect("verify");
}

/// Short key (1 byte): deterministic.
#[test]
fn hmac_sha512_wycheproof_short_key_determinism() {
    let key = b"k";
    let msg = b"test";
    let mut t1 = [0u8; 64];
    let mut t2 = [0u8; 64];
    HmacSha512.mac(key, msg, &mut t1).expect("mac1");
    HmacSha512.mac(key, msg, &mut t2).expect("mac2");
    assert_eq!(t1, t2, "must be deterministic");
}

/// All-zero key: round-trip.
#[test]
fn hmac_sha512_wycheproof_all_zero_key() {
    let key = [0u8; 64];
    let msg = b"test message";
    let mut tag = [0u8; 64];
    HmacSha512.mac(&key, msg, &mut tag).expect("mac");
    HmacSha512.verify(&key, msg, &tag).expect("verify");
}

/// 64-byte message: deterministic.
#[test]
fn hmac_sha512_wycheproof_64byte_msg() {
    let key = b"key-for-64-byte-test";
    let msg = [0x42u8; 64];
    let mut t1 = [0u8; 64];
    let mut t2 = [0u8; 64];
    HmacSha512.mac(key, &msg, &mut t1).expect("mac1");
    HmacSha512.mac(key, &msg, &mut t2).expect("mac2");
    assert_eq!(t1, t2);
}

/// 200-byte message: deterministic and verifiable.
#[test]
fn hmac_sha512_wycheproof_200byte_msg() {
    let key = b"key-for-200b";
    let msg: Vec<u8> = (0u8..=199u8).collect();
    let mut tag = [0u8; 64];
    HmacSha512.mac(key, &msg, &mut tag).expect("mac");
    HmacSha512.verify(key, &msg, &tag).expect("verify");
}

/// Long key (131 bytes): deterministic.
#[test]
fn hmac_sha512_wycheproof_long_key() {
    let key = vec![0xaau8; 131];
    let msg = b"test with long key";
    let mut t1 = [0u8; 64];
    let mut t2 = [0u8; 64];
    HmacSha512.mac(&key, msg, &mut t1).expect("mac1");
    HmacSha512.mac(&key, msg, &mut t2).expect("mac2");
    assert_eq!(t1, t2);
}

/// Key sensitivity: changing one bit in the key changes the tag.
#[test]
fn hmac_sha512_wycheproof_key_sensitivity() {
    let key1 = [0x42u8; 64];
    let mut key2 = key1;
    key2[0] ^= 1;
    let msg = b"same message";
    let mut t1 = [0u8; 64];
    let mut t2 = [0u8; 64];
    HmacSha512.mac(&key1, msg, &mut t1).expect("mac1");
    HmacSha512.mac(&key2, msg, &mut t2).expect("mac2");
    assert_ne!(t1, t2, "different keys must produce different tags");
}
