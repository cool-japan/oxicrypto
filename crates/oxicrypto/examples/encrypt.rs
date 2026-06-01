//! Encryption example: HKDF-SHA-256 key derivation then AES-256-GCM encrypt/decrypt.
//!
//! Demonstrates the typical pattern:
//!   1. Derive a 32-byte session key from raw input key material (IKM) using HKDF-SHA-256.
//!   2. Encrypt plaintext with AES-256-GCM using the derived key.
//!   3. Decrypt the ciphertext and verify the recovered plaintext matches the original.
//!
//! Run with:
//!   cargo run -p oxicrypto --example encrypt

use oxicrypto::{aead_impl, kdf_impl, AeadAlgo, KdfAlgo};

fn main() {
    // ── Key Derivation ────────────────────────────────────────────────────────
    // In practice, IKM could be a shared DH secret, a password hash, etc.
    let ikm = b"shared-secret-input-key-material";
    // Salt and info are application-specific context bindings.
    let salt = b"oxicrypto-encrypt-example-salt";
    let info = b"aes-256-gcm session key v1";

    let kdf = kdf_impl(KdfAlgo::HkdfSha256);

    let mut session_key = [0u8; 32]; // AES-256-GCM requires a 32-byte key.
    kdf.derive(ikm, salt, info, &mut session_key)
        .expect("HKDF-SHA-256 key derivation failed");

    println!("Derived 32-byte AES-256-GCM session key via HKDF-SHA-256");

    // ── Encryption ───────────────────────────────────────────────────────────
    let aead = aead_impl(AeadAlgo::Aes256Gcm);

    // Nonce must be unique per (key, message) pair.
    // Here we use a fixed nonce for illustration; production code should
    // generate a random nonce (e.g. via oxicrypto::random_nonce()).
    let nonce = [0x42u8; 12]; // AES-GCM uses 12-byte nonces.

    // Additional authenticated data (AAD) is authenticated but not encrypted.
    let aad = b"example-plaintext-header";
    let plaintext = b"Hello, post-quantum world! This message is confidential.";

    // seal_to_vec returns ciphertext || authentication-tag as a Vec<u8>.
    let ciphertext = aead
        .seal_to_vec(&session_key, &nonce, aad, plaintext)
        .expect("AES-256-GCM encryption failed");

    println!(
        "Encrypted {} bytes of plaintext into {} bytes of ciphertext (incl. 16-byte tag)",
        plaintext.len(),
        ciphertext.len()
    );

    // ── Decryption ───────────────────────────────────────────────────────────
    // open_to_vec verifies the authentication tag, then decrypts.
    let recovered = aead
        .open_to_vec(&session_key, &nonce, aad, &ciphertext)
        .expect("AES-256-GCM decryption/authentication failed");

    assert_eq!(
        recovered.as_slice(),
        plaintext.as_ref(),
        "Recovered plaintext does not match original"
    );
    println!(
        "Decryption succeeded. Recovered: {:?}",
        core::str::from_utf8(&recovered).unwrap_or("<binary>")
    );

    // ── Tamper detection ─────────────────────────────────────────────────────
    // Flipping a byte in the ciphertext must cause open_to_vec to return an error.
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0xff;
    let tamper_result = aead.open_to_vec(&session_key, &nonce, aad, &tampered);
    assert!(
        tamper_result.is_err(),
        "AES-256-GCM must reject tampered ciphertext"
    );
    println!("Tamper detection: correctly rejected modified ciphertext");
}
