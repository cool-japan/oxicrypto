//! Wycheproof-style known-answer tests for SHA-256 and SHA-512.
//!
//! These vectors are a curated subset of the Wycheproof test suite
//! (https://github.com/google/wycheproof), testing edge cases including:
//! - Empty input
//! - Single-byte inputs spanning 0x00–0xff
//! - Messages with lengths that cross SHA-256 block boundaries (64 bytes)
//! - Messages with lengths that cross SHA-512 block boundaries (128 bytes)
//! - Messages containing only zero bytes
//! - Messages containing only 0xff bytes
//! - The classic NIST CAVS / FIPS 180-4 vectors
//!
//! Expected values verified with:
//!   `echo -n "" | sha256sum`
//!   `python3 -c "import hashlib; print(hashlib.sha256(b'').hexdigest())"`

use oxicrypto_core::Hash;
use oxicrypto_hash::{Sha256, Sha512};

// ── Hex helper (no unwrap in production code; test helper panics clearly) ─────

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("kat_wycheproof: invalid hex {s:?}: {e}"))
}

fn sha256_of(msg: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 32];
    Sha256.hash(msg, &mut out).expect("sha256 hash");
    out.to_vec()
}

fn sha512_of(msg: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 64];
    Sha512.hash(msg, &mut out).expect("sha512 hash");
    out.to_vec()
}

// ── SHA-256 Wycheproof vectors ────────────────────────────────────────────────

/// SHA-256 of empty input (Wycheproof / FIPS 180-4).
#[test]
fn sha256_wycheproof_empty() {
    assert_eq!(
        sha256_of(b""),
        from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
}

/// SHA-256 of single zero byte.
#[test]
fn sha256_wycheproof_zero_byte() {
    assert_eq!(
        sha256_of(&[0x00]),
        from_hex("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
    );
}

/// SHA-256 of single 0xff byte.
#[test]
fn sha256_wycheproof_ff_byte() {
    assert_eq!(
        sha256_of(&[0xff]),
        from_hex("a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89")
    );
}

/// SHA-256 of 0x61 ("a") — single ASCII 'a'.
#[test]
fn sha256_wycheproof_single_a() {
    assert_eq!(
        sha256_of(b"a"),
        from_hex("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")
    );
}

/// SHA-256 of "abc" — FIPS 180-4 Appendix B.1.
#[test]
fn sha256_wycheproof_abc() {
    assert_eq!(
        sha256_of(b"abc"),
        from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

/// SHA-256 of "message digest".
#[test]
fn sha256_wycheproof_message_digest() {
    assert_eq!(
        sha256_of(b"message digest"),
        from_hex("f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650")
    );
}

/// SHA-256 of ASCII alphabet "abcdefghijklmnopqrstuvwxyz".
#[test]
fn sha256_wycheproof_alphabet() {
    assert_eq!(
        sha256_of(b"abcdefghijklmnopqrstuvwxyz"),
        from_hex("71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73")
    );
}

/// SHA-256 of exactly 55 zero bytes (one less than needed to trigger a second
/// compression block; the padding fits exactly in the first block).
#[test]
fn sha256_wycheproof_55_zeros() {
    let msg = vec![0u8; 55];
    assert_eq!(
        sha256_of(&msg),
        from_hex("02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7")
    );
}

/// SHA-256 of exactly 56 zero bytes (triggers a second compression block
/// because the 8-byte length field does not fit after padding in 64 bytes).
#[test]
fn sha256_wycheproof_56_zeros() {
    let msg = vec![0u8; 56];
    assert_eq!(
        sha256_of(&msg),
        from_hex("d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb")
    );
}

/// SHA-256 of exactly 64 zero bytes (exactly one full SHA-256 block of zeros).
#[test]
fn sha256_wycheproof_64_zeros() {
    let msg = vec![0u8; 64];
    assert_eq!(
        sha256_of(&msg),
        from_hex("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b")
    );
}

/// SHA-256 of exactly 64 bytes of 0xff.
#[test]
fn sha256_wycheproof_64_ff() {
    let msg = vec![0xffu8; 64];
    assert_eq!(
        sha256_of(&msg),
        from_hex("8667e718294e9e0df1d30600ba3eeb201f764aad2dad72748643e4a285e1d1f7")
    );
}

/// SHA-256 of 128 zero bytes (two full blocks).
#[test]
fn sha256_wycheproof_128_zeros() {
    let msg = vec![0u8; 128];
    assert_eq!(
        sha256_of(&msg),
        from_hex("38723a2e5e8a17aa7950dc008209944e898f69a7bd10a23c839d341e935fd5ca")
    );
}

/// SHA-256 of the hex bytes 000102...ff (256 bytes, all byte values).
#[test]
fn sha256_wycheproof_all_bytes() {
    let msg: Vec<u8> = (0u8..=255u8).collect();
    assert_eq!(
        sha256_of(&msg),
        from_hex("40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880")
    );
}

/// SHA-256("The quick brown fox jumps over the lazy dog").
#[test]
fn sha256_wycheproof_quick_brown_fox() {
    assert_eq!(
        sha256_of(b"The quick brown fox jumps over the lazy dog"),
        from_hex("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")
    );
}

/// SHA-256("The quick brown fox jumps over the lazy dog.") — one byte longer.
#[test]
fn sha256_wycheproof_quick_brown_fox_dot() {
    assert_eq!(
        sha256_of(b"The quick brown fox jumps over the lazy dog."),
        from_hex("ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c")
    );
}

/// SHA-256 of 1000 zero bytes.
#[test]
fn sha256_wycheproof_1000_zeros() {
    let msg = vec![0u8; 1000];
    assert_eq!(
        sha256_of(&msg),
        from_hex("541b3e9daa09b20bf85fa273e5cbd3e80185aa4ec298e765db87742b70138a53")
    );
}

// ── SHA-512 Wycheproof vectors ────────────────────────────────────────────────

/// SHA-512 of empty input (FIPS 180-4 / Wycheproof).
#[test]
fn sha512_wycheproof_empty() {
    assert_eq!(
        sha512_of(b""),
        from_hex(concat!(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        ))
    );
}

/// SHA-512 of "abc" (FIPS 180-4).
#[test]
fn sha512_wycheproof_abc() {
    assert_eq!(
        sha512_of(b"abc"),
        from_hex(concat!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        ))
    );
}

/// SHA-512 of exactly 111 zero bytes (triggers the two-block padding case
/// for SHA-512 with 128-byte blocks: 111 + 1 pad + 16 length = 128 bytes).
#[test]
fn sha512_wycheproof_111_zeros() {
    let msg = vec![0u8; 111];
    assert_eq!(
        sha512_of(&msg),
        from_hex(concat!(
            "77ddd3a542e530fd047b8977c657ba6ce72f1492e360b2b2212cd264e75ec038",
            "82e4ff0525517ab4207d14c70c2259ba88d4d335ee0e7e20543d22102ab1788c"
        ))
    );
}

/// SHA-512 of exactly 112 zero bytes (triggers a third block because the
/// 16-byte length field spills beyond 128 bytes).
#[test]
fn sha512_wycheproof_112_zeros() {
    let msg = vec![0u8; 112];
    assert_eq!(
        sha512_of(&msg),
        from_hex(concat!(
            "2be2e788c8a8adeaa9c89a7f78904cacea6e39297d75e0573a73c756234534d6",
            "627ab4156b48a6657b29ab8beb73334040ad39ead81446bb09c70704ec707952"
        ))
    );
}

/// SHA-512 of exactly 128 zero bytes (exactly one full SHA-512 block).
#[test]
fn sha512_wycheproof_128_zeros() {
    let msg = vec![0u8; 128];
    assert_eq!(
        sha512_of(&msg),
        from_hex(concat!(
            "ab942f526272e456ed68a979f50202905ca903a141ed98443567b11ef0bf25a5",
            "52d639051a01be58558122c58e3de07d749ee59ded36acf0c55cd91924d6ba11"
        ))
    );
}

/// SHA-512("The quick brown fox jumps over the lazy dog").
#[test]
fn sha512_wycheproof_quick_brown_fox() {
    assert_eq!(
        sha512_of(b"The quick brown fox jumps over the lazy dog"),
        from_hex(concat!(
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64",
            "2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
        ))
    );
}
