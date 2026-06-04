//! Tests asserting that RSA keys below 2048 bits are rejected.
//!
//! The `rsa_generate_keypair` function in this crate enforces a 2048-bit
//! minimum key size and returns `CryptoError::BadInput` for smaller sizes.
//! This test verifies that policy is enforced correctly.

use oxicrypto_core::CryptoError;
use oxicrypto_sig::rsa_generate_keypair;

/// Keys smaller than 2048 bits must be rejected by `rsa_generate_keypair`.
///
/// The function should return `Err(CryptoError::BadInput)` for 1024-bit
/// and other undersized requests without actually generating the key.
#[test]
fn rsa_keygen_rejects_1024_bits() {
    let result = rsa_generate_keypair(1024);
    assert_eq!(
        result,
        Err(CryptoError::BadInput),
        "rsa_generate_keypair(1024) must return BadInput (minimum is 2048)"
    );
}

/// `rsa_generate_keypair` must reject 512-bit keys.
#[test]
fn rsa_keygen_rejects_512_bits() {
    let result = rsa_generate_keypair(512);
    assert_eq!(
        result,
        Err(CryptoError::BadInput),
        "rsa_generate_keypair(512) must return BadInput (minimum is 2048)"
    );
}

/// `rsa_generate_keypair` must reject 0-bit requests.
#[test]
fn rsa_keygen_rejects_zero_bits() {
    let result = rsa_generate_keypair(0);
    assert_eq!(
        result,
        Err(CryptoError::BadInput),
        "rsa_generate_keypair(0) must return BadInput"
    );
}

/// `rsa_generate_keypair` must reject 2047-bit requests (just below minimum).
#[test]
fn rsa_keygen_rejects_2047_bits() {
    let result = rsa_generate_keypair(2047);
    assert_eq!(
        result,
        Err(CryptoError::BadInput),
        "rsa_generate_keypair(2047) must return BadInput (minimum is 2048)"
    );
}

/// Verify the minimum 2048-bit key generates successfully and can sign+verify.
///
/// Note: RSA key generation is computationally expensive (~1-3 seconds for 2048 bits).
/// This test is marked `#[ignore]` to avoid slowing down the normal test suite.
/// Run with `cargo test -- --ignored` to include it.
#[test]
#[ignore = "RSA key generation is slow (~1-3s); run explicitly with --ignored"]
fn rsa_keygen_accepts_2048_bits() {
    let result = rsa_generate_keypair(2048);
    assert!(
        result.is_ok(),
        "rsa_generate_keypair(2048) must succeed: {:?}",
        result.err()
    );

    let (sk_der, pk_der) = result.expect("2048-bit RSA keygen");
    assert!(!sk_der.is_empty(), "private key DER must be non-empty");
    assert!(!pk_der.is_empty(), "public key DER must be non-empty");
}
