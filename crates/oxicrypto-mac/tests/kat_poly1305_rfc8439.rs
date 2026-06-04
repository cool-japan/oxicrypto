//! Known-answer tests for Poly1305 (RFC 8439).
//!
//! RFC 8439 §2.5.2 test vector and Appendix A.3 vectors.

use oxicrypto_core::Mac;
use oxicrypto_mac::Poly1305Mac;

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

// ── RFC 8439 §2.5.2 ──────────────────────────────────────────────────────────

/// RFC 8439 §2.5.2 test vector:
///
/// key  = 85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b
/// data = "Cryptographic Forum Research Group"
/// tag  = a8061dc1305136c6c22b8baf0c0127a9
#[test]
fn poly1305_rfc8439_s2_5_2() {
    let key = hex_decode(concat!(
        "85d6be7857556d337f4452fe42d506a8",
        "0103808afb0db2fd4abff6af4149f51b"
    ));
    let msg = b"Cryptographic Forum Research Group";
    let expected = "a8061dc1305136c6c22b8baf0c0127a9";

    let mut out = [0u8; 16];
    Poly1305Mac
        .mac(&key, msg, &mut out)
        .expect("Poly1305 §2.5.2 failed");
    assert_eq!(to_hex(&out), expected, "RFC 8439 §2.5.2 Poly1305 mismatch");
}

// ── RFC 8439 Appendix A.3 ─────────────────────────────────────────────────────

/// RFC 8439 Appendix A.3 Test Vector #1:
///
/// key  = 0000...00 (32 zero bytes)
/// data = 0000...00 (64 zero bytes)
/// tag  = 00000000000000000000000000000000
#[test]
fn poly1305_rfc8439_a3_tv1() {
    let key = [0u8; 32];
    let msg = [0u8; 64];
    let expected = "00000000000000000000000000000000";

    let mut out = [0u8; 16];
    Poly1305Mac
        .mac(&key, &msg, &mut out)
        .expect("Poly1305 A.3 TV1 failed");
    assert_eq!(to_hex(&out), expected, "RFC 8439 A.3 TV1 Poly1305 mismatch");
}

/// RFC 8439 Appendix A.3 Test Vector #4 (Jabberwocky poem excerpt):
///
/// key  = 1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0
/// data = (Lewis Carroll's Jabberwocky hexencoded as per RFC 8439 A.3)
/// tag  = 4541669a7eaaee61e708dc7cbcc5eb62
#[test]
fn poly1305_rfc8439_a3_tv4() {
    let key = hex_decode(concat!(
        "1c9240a5eb55d38af333888604f6b5f0",
        "473917c1402b80099dca5cbc207075c0"
    ));
    // Jabberwocky stanza (raw bytes exactly as in RFC 8439 Appendix A.3)
    let msg = hex_decode(concat!(
        "2754776173206272696c6c69672c2061",
        "6e642074686520736c6974687920746f",
        "7665730a446964206779726520616e64",
        "2067696d626c6520696e207468652077",
        "6162653a0a416c6c206d696d73792077",
        "6572652074686520626f726f676f7665",
        "732c0a416e6420746865206d6f6d6520",
        "7261746873206f757467726162652e"
    ));
    let expected = "4541669a7eaaee61e708dc7cbcc5eb62";

    let mut out = [0u8; 16];
    Poly1305Mac
        .mac(&key, &msg, &mut out)
        .expect("Poly1305 A.3 TV4 failed");
    assert_eq!(to_hex(&out), expected, "RFC 8439 A.3 TV4 Poly1305 mismatch");
}

/// §2.5.2 verify round-trip.
#[test]
fn poly1305_verify_roundtrip() {
    let key = hex_decode(concat!(
        "85d6be7857556d337f4452fe42d506a8",
        "0103808afb0db2fd4abff6af4149f51b"
    ));
    let msg = b"Cryptographic Forum Research Group";
    let mut tag = [0u8; 16];
    Poly1305Mac.mac(&key, msg, &mut tag).expect("mac");
    Poly1305Mac
        .verify(&key, msg, &tag)
        .expect("verify must succeed");
}

/// All-zero key, empty message: deterministic.
#[test]
fn poly1305_empty_msg_zero_key() {
    let key = [0u8; 32];
    let msg: &[u8] = b"";
    let mut t1 = [0u8; 16];
    let mut t2 = [0u8; 16];
    Poly1305Mac.mac(&key, msg, &mut t1).expect("mac1");
    Poly1305Mac.mac(&key, msg, &mut t2).expect("mac2");
    assert_eq!(t1, t2, "must be deterministic");
}

/// All-zero key, single-byte message.
#[test]
fn poly1305_single_byte_msg() {
    let key = [0u8; 32];
    let msg = b"a";
    let mut tag = [0u8; 16];
    Poly1305Mac.mac(&key, msg, &mut tag).expect("mac");
    Poly1305Mac.verify(&key, msg, &tag).expect("verify");
}

/// Wrong key length (16 bytes) must fail.
#[test]
fn poly1305_bad_key_len_rejected() {
    let key = [0u8; 16];
    let mut out = [0u8; 16];
    assert!(
        Poly1305Mac.mac(&key, b"msg", &mut out).is_err(),
        "16-byte key must be rejected"
    );
}

/// Key sensitivity: changing one byte in the key changes the tag.
#[test]
fn poly1305_key_sensitivity() {
    let key1 = hex_decode(concat!(
        "85d6be7857556d337f4452fe42d506a8",
        "0103808afb0db2fd4abff6af4149f51b"
    ));
    let mut key2 = key1.clone();
    key2[0] ^= 0x01;
    let msg = b"Cryptographic Forum Research Group";
    let mut t1 = [0u8; 16];
    let mut t2 = [0u8; 16];
    Poly1305Mac.mac(&key1, msg, &mut t1).expect("mac1");
    Poly1305Mac.mac(&key2, msg, &mut t2).expect("mac2");
    assert_ne!(t1, t2, "different keys must produce different tags");
}
