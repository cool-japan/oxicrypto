//! BLAKE3 official test vectors from:
//! <https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json>
//!
//! Input byte pattern: input[i] = (i % 251) as u8
//! Only the first 32 bytes of the hash output are tested here (standard mode).
//!
//! Vectors were generated using blake3 1.8.5 and confirmed against the official
//! BLAKE3 team JSON file.

use oxicrypto_core::Hash;
use oxicrypto_hash::{blake3_derive_key, blake3_keyed_hash, Blake3};

/// Build the canonical test-vector input: `input[i] = (i % 251) as u8`
fn make_input(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn blake3_of(msg: &[u8]) -> String {
    let mut out = [0u8; 32];
    Blake3.hash(msg, &mut out).expect("blake3 hash failed");
    to_hex(&out)
}

// ── Standard BLAKE3 (hash mode) ───────────────────────────────────────────────

/// BLAKE3("") — 0-byte input (official test vector case 0)
#[test]
fn blake3_official_n0() {
    assert_eq!(
        blake3_of(&make_input(0)),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "BLAKE3 official vector: 0 bytes"
    );
}

/// BLAKE3 of 1-byte input [0x00] (official test vector case 1)
#[test]
fn blake3_official_n1() {
    assert_eq!(
        blake3_of(&make_input(1)),
        "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        "BLAKE3 official vector: 1 byte"
    );
}

/// BLAKE3 of 2-byte input [0x00, 0x01]
#[test]
fn blake3_official_n2() {
    assert_eq!(
        blake3_of(&make_input(2)),
        "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
        "BLAKE3 official vector: 2 bytes"
    );
}

/// BLAKE3 of 31-byte input
#[test]
fn blake3_official_n31() {
    assert_eq!(
        blake3_of(&make_input(31)),
        "bda80c7fe2db38be6387b35c870bd7728d67b7b6cc5eb9b0e5c7dcb21ea754c2",
        "BLAKE3 official vector: 31 bytes"
    );
}

/// BLAKE3 of 32-byte input (one block boundary)
#[test]
fn blake3_official_n32() {
    assert_eq!(
        blake3_of(&make_input(32)),
        "e528e95798037df410543d9f31e396ecdd458d71b157d6014398bae32fb56c65",
        "BLAKE3 official vector: 32 bytes"
    );
}

/// BLAKE3 of 63-byte input
#[test]
fn blake3_official_n63() {
    assert_eq!(
        blake3_of(&make_input(63)),
        "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
        "BLAKE3 official vector: 63 bytes"
    );
}

/// BLAKE3 of 64-byte input
#[test]
fn blake3_official_n64() {
    assert_eq!(
        blake3_of(&make_input(64)),
        "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
        "BLAKE3 official vector: 64 bytes"
    );
}

/// BLAKE3 of 65-byte input
#[test]
fn blake3_official_n65() {
    assert_eq!(
        blake3_of(&make_input(65)),
        "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
        "BLAKE3 official vector: 65 bytes"
    );
}

/// BLAKE3 of 1023-byte input
#[test]
fn blake3_official_n1023() {
    assert_eq!(
        blake3_of(&make_input(1023)),
        "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
        "BLAKE3 official vector: 1023 bytes"
    );
}

/// BLAKE3 of 1024-byte input (chunk boundary)
#[test]
fn blake3_official_n1024() {
    assert_eq!(
        blake3_of(&make_input(1024)),
        "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        "BLAKE3 official vector: 1024 bytes"
    );
}

/// BLAKE3 of 1025-byte input (one byte past chunk boundary)
#[test]
fn blake3_official_n1025() {
    assert_eq!(
        blake3_of(&make_input(1025)),
        "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
        "BLAKE3 official vector: 1025 bytes"
    );
}

// ── Determinism: same input always yields same output ─────────────────────────

/// BLAKE3 is deterministic: two calls with the same input produce the same hash.
#[test]
fn blake3_official_deterministic() {
    let input = make_input(512);
    let a = blake3_of(&input);
    let b = blake3_of(&input);
    assert_eq!(a, b, "BLAKE3 must be deterministic");
}

// ── Mode separation ───────────────────────────────────────────────────────────

/// BLAKE3 keyed-hash is distinct from standard BLAKE3 for the same input.
#[test]
fn blake3_keyed_distinct_from_standard() {
    let msg = make_input(64);
    let key = [0u8; 32];
    let standard = blake3_of(&msg);
    let keyed_bytes = blake3_keyed_hash(&key, &msg);
    let keyed = to_hex(&keyed_bytes);
    assert_ne!(
        standard, keyed,
        "BLAKE3 keyed-hash must differ from standard BLAKE3"
    );
}

/// BLAKE3 derive-key output is distinct from standard BLAKE3 for the same input.
#[test]
fn blake3_derive_key_distinct_from_standard() {
    let msg = make_input(64);
    let standard = blake3_of(&msg);
    let derived_bytes = blake3_derive_key("oxicrypto test 2026 distinct", &msg);
    let derived = to_hex(&derived_bytes);
    assert_ne!(
        standard, derived,
        "BLAKE3 derive-key must differ from standard BLAKE3"
    );
}

/// BLAKE3 derive-key output is distinct from keyed-hash for the same input.
#[test]
fn blake3_derive_key_distinct_from_keyed_hash() {
    let msg = make_input(64);
    let key = [0u8; 32];
    let keyed_bytes = blake3_keyed_hash(&key, &msg);
    let keyed = to_hex(&keyed_bytes);
    let derived_bytes = blake3_derive_key("oxicrypto test 2026 distinct", &msg);
    let derived = to_hex(&derived_bytes);
    assert_ne!(
        keyed, derived,
        "BLAKE3 derive-key must differ from keyed-hash"
    );
}
