//! Message authentication with `oxicrypto-mac`: HMAC-SHA-256 via the [`Mac`]
//! trait, and the standalone BLAKE3 keyed-hash MAC helpers.
//!
//! Run with:
//!   cargo run -p oxicrypto-mac --example mac_basics

use oxicrypto_core::Mac;
use oxicrypto_mac::{blake3_keyed_mac, blake3_keyed_mac_verify, HmacSha256};

fn main() {
    hmac_sha256_roundtrip();
    blake3_keyed_mac_roundtrip();
}

fn hmac_sha256_roundtrip() {
    let key = [0x42u8; 32];
    let msg = b"transfer 100 credits to account #7";

    let mut tag = [0u8; 32];
    HmacSha256
        .mac(&key, msg, &mut tag)
        .expect("HMAC-SHA-256 mac");
    println!("HMAC-SHA-256 tag: {}", hex(&tag));

    // The receiver recomputes and constant-time-compares the tag.
    HmacSha256
        .verify(&key, msg, &tag)
        .expect("genuine tag must verify");
    println!("Genuine tag verified OK");

    // A tampered message must be rejected.
    let tampered_msg = b"transfer 900 credits to account #7";
    let result = HmacSha256.verify(&key, tampered_msg, &tag);
    assert!(result.is_err(), "tampered message must fail verification");
    println!("Tampered message correctly rejected: {result:?}");

    // A wrong key must also be rejected.
    let wrong_key = [0x43u8; 32];
    let result = HmacSha256.verify(&wrong_key, msg, &tag);
    assert!(result.is_err(), "wrong key must fail verification");
    println!("Wrong key correctly rejected: {result:?}");
}

fn blake3_keyed_mac_roundtrip() {
    let key = [0x99u8; 32];
    let msg = b"session-cookie=abc123";

    let tag = blake3_keyed_mac(&key, msg);
    println!("BLAKE3 keyed-MAC tag: {}", hex(&tag));

    blake3_keyed_mac_verify(&key, msg, &tag).expect("genuine BLAKE3 tag must verify");
    println!("Genuine BLAKE3 tag verified OK");

    let mut bad_tag = tag;
    bad_tag[0] ^= 0xFF;
    let result = blake3_keyed_mac_verify(&key, msg, &bad_tag);
    assert!(result.is_err(), "corrupted tag must fail verification");
    println!("Corrupted BLAKE3 tag correctly rejected: {result:?}");
}

/// Format a byte slice as a lowercase hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
