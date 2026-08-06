//! Key derivation with `oxicrypto-kdf`: HKDF-SHA-256 (RFC 5869) for
//! deriving symmetric keys from existing key material, and bcrypt for
//! password hashing/verification.
//!
//! Run with:
//!   cargo run -p oxicrypto-kdf --example kdf_basics

use oxicrypto_kdf::{bcrypt_hash, bcrypt_verify, generate_salt_16, hkdf_sha256_derive_to_vec};

fn main() {
    hkdf_session_key();
    bcrypt_password_hashing();
}

/// HKDF-SHA-256 turns non-uniform input key material (e.g. a Diffie-Hellman
/// shared secret) into one or more uniformly-random, purpose-bound keys.
fn hkdf_session_key() {
    let ikm = b"shared-secret-input-key-material";
    let salt = b"oxicrypto-kdf-example-salt";

    // The `info` parameter binds the derived key to its intended purpose —
    // deriving two different-purpose keys from the same IKM with different
    // `info` values yields unrelated outputs.
    let encryption_key = hkdf_sha256_derive_to_vec(ikm, salt, b"encryption key v1", 32)
        .expect("HKDF derive encryption key");
    let mac_key =
        hkdf_sha256_derive_to_vec(ikm, salt, b"mac key v1", 32).expect("HKDF derive MAC key");

    assert_ne!(
        encryption_key, mac_key,
        "different info strings must yield unrelated keys"
    );
    println!("HKDF-SHA-256 encryption key: {}", hex(&encryption_key));
    println!("HKDF-SHA-256 MAC key:        {}", hex(&mac_key));

    // Deriving with the same inputs again must be deterministic.
    let encryption_key_again = hkdf_sha256_derive_to_vec(ikm, salt, b"encryption key v1", 32)
        .expect("HKDF derive encryption key again");
    assert_eq!(
        encryption_key, encryption_key_again,
        "HKDF must be deterministic for identical inputs"
    );
    println!("HKDF-SHA-256 is deterministic for identical (ikm, salt, info) inputs");
}

/// bcrypt hashes a password with a per-hash random salt and a tunable cost
/// factor, producing a self-describing `$2b$cost$salt+hash` string suitable
/// for storage alongside a user account.
fn bcrypt_password_hashing() {
    // Cost 4 (the minimum) keeps this example fast; production systems
    // should use a cost tuned to take roughly 100-250ms on their hardware
    // (commonly 10-12).
    let cost = 4;
    let salt = generate_salt_16().expect("generate bcrypt salt");

    let password_hash =
        bcrypt_hash(b"correct horse battery staple", cost, &salt).expect("bcrypt hash");
    println!("bcrypt hash: {password_hash}");

    let matches =
        bcrypt_verify(b"correct horse battery staple", &password_hash).expect("bcrypt verify");
    assert!(matches, "the correct password must verify");
    println!("Correct password verified OK");

    let matches = bcrypt_verify(b"wrong password", &password_hash).expect("bcrypt verify");
    assert!(!matches, "an incorrect password must not verify");
    println!("Incorrect password correctly rejected");
}

/// Format a byte slice as a lowercase hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
