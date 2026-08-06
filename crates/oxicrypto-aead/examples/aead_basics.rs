//! Authenticated encryption with `oxicrypto-aead`: AES-256-GCM and
//! ChaCha20-Poly1305 via the [`Aead`] trait, plus tamper detection.
//!
//! Run with:
//!   cargo run -p oxicrypto-aead --example aead_basics

use oxicrypto_aead::{Aes256Gcm, ChaCha20Poly1305};
use oxicrypto_core::Aead;

fn main() {
    aes256_gcm_roundtrip();
    chacha20_poly1305_roundtrip();
}

fn aes256_gcm_roundtrip() {
    let key = [0x11u8; 32]; // AES-256-GCM key (32 bytes).
                            // A nonce MUST be unique per (key, message) pair; production code should
                            // generate one randomly or from a monotonic counter (see `NonceSequence`
                            // in this crate) rather than hardcoding it as this example does.
    let nonce = [0x22u8; 12];
    let aad = b"message-header-v1";
    let plaintext = b"the treasure is buried under the old oak tree";

    let ciphertext = Aes256Gcm
        .seal_to_vec(&key, &nonce, aad, plaintext)
        .expect("AES-256-GCM seal");
    println!(
        "AES-256-GCM: {} bytes plaintext -> {} bytes ciphertext (incl. 16-byte tag)",
        plaintext.len(),
        ciphertext.len()
    );

    let recovered = Aes256Gcm
        .open_to_vec(&key, &nonce, aad, &ciphertext)
        .expect("AES-256-GCM open");
    assert_eq!(
        recovered, plaintext,
        "recovered plaintext must match original"
    );
    println!("Decryption succeeded, plaintext recovered correctly");

    // Tamper detection: flipping any ciphertext byte must fail authentication.
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0xFF;
    let result = Aes256Gcm.open_to_vec(&key, &nonce, aad, &tampered);
    assert!(result.is_err(), "tampered ciphertext must be rejected");
    println!("Tampered ciphertext correctly rejected: {result:?}");

    // Wrong AAD must also fail, even with an untouched ciphertext.
    let result = Aes256Gcm.open_to_vec(&key, &nonce, b"wrong-header", &ciphertext);
    assert!(result.is_err(), "mismatched AAD must be rejected");
    println!("Mismatched AAD correctly rejected: {result:?}");
}

fn chacha20_poly1305_roundtrip() {
    let key = [0x33u8; 32];
    let nonce = [0x44u8; 12];
    let aad = b"";
    let plaintext = b"ChaCha20-Poly1305 works the same way via the Aead trait";

    let ciphertext = ChaCha20Poly1305
        .seal_to_vec(&key, &nonce, aad, plaintext)
        .expect("ChaCha20-Poly1305 seal");
    let recovered = ChaCha20Poly1305
        .open_to_vec(&key, &nonce, aad, &ciphertext)
        .expect("ChaCha20-Poly1305 open");

    assert_eq!(recovered, plaintext);
    println!(
        "ChaCha20-Poly1305: round trip OK ({} bytes plaintext, empty AAD)",
        plaintext.len()
    );
}
