//! Integration tests: HKDF-derived keys with AEAD algorithms.
//!
//! Validates TODO item §Integration: "Ensure `oxicrypto-kdf` HKDF can be used
//! for AEAD key derivation (HKDF-Expand → AEAD key)".
//!
//! These tests exercise the documented pattern:
//!   shared_secret → HKDF-SHA-256 → AEAD key → AES-256-GCM / ChaCha20-Poly1305

use oxicrypto_aead::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, XChaCha20Poly1305};
use oxicrypto_core::{Aead, Kdf};
use oxicrypto_kdf::HkdfSha256;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Derive an AEAD key of `KEY_LEN` bytes from `shared_secret` using
/// HKDF-SHA-256 with a domain-specific label.
fn derive_aead_key<const KEY_LEN: usize>(shared_secret: &[u8], label: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    HkdfSha256
        .derive(shared_secret, b"oxicrypto-test-salt", label, &mut key)
        .expect("HKDF derive must not fail for small output");
    key
}

// ── AES-256-GCM with HKDF-derived key ─────────────────────────────────────────

#[test]
fn hkdf_derived_key_aes256gcm_round_trip() {
    let shared_secret = [0x55u8; 32]; // simulated X25519 / ML-KEM shared secret
    let key = derive_aead_key::<32>(&shared_secret, b"aes256gcm-enc-key");
    let nonce = [0xAAu8; 12];
    let plaintext = b"HKDF + AES-256-GCM integration test";
    let aad = b"test AAD";

    let aead = Aes256Gcm;
    let ct = aead
        .seal_to_vec(&key, &nonce, aad, plaintext)
        .expect("seal must succeed");

    let recovered = aead
        .open_to_vec(&key, &nonce, aad, &ct)
        .expect("open must succeed");

    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn hkdf_derived_key_aes256gcm_wrong_secret_fails() {
    let secret_a = [0x11u8; 32];
    let secret_b = [0x22u8; 32]; // different secret → different key
    let key_a = derive_aead_key::<32>(&secret_a, b"aes256gcm-enc-key");
    let key_b = derive_aead_key::<32>(&secret_b, b"aes256gcm-enc-key");

    let nonce = [0xBBu8; 12];
    let plaintext = b"secret message";

    let aead = Aes256Gcm;
    let ct = aead
        .seal_to_vec(&key_a, &nonce, b"", plaintext)
        .expect("seal");

    // Decrypting with a key derived from a different secret must fail.
    let result = aead.open_to_vec(&key_b, &nonce, b"", &ct);
    assert_eq!(
        result,
        Err(oxicrypto_core::CryptoError::InvalidTag),
        "wrong derived key must produce InvalidTag"
    );
}

// ── AES-128-GCM with HKDF-derived key ─────────────────────────────────────────

#[test]
fn hkdf_derived_key_aes128gcm_round_trip() {
    let shared_secret = [0x77u8; 32];
    let key = derive_aead_key::<16>(&shared_secret, b"aes128gcm-enc-key");
    let nonce = [0xCCu8; 12];
    let plaintext = b"HKDF + AES-128-GCM integration";

    let aead = Aes128Gcm;
    let ct = aead
        .seal_to_vec(&key, &nonce, b"", plaintext)
        .expect("seal");
    let recovered = aead.open_to_vec(&key, &nonce, b"", &ct).expect("open");
    assert_eq!(recovered.as_slice(), plaintext);
}

// ── ChaCha20-Poly1305 with HKDF-derived key ───────────────────────────────────

#[test]
fn hkdf_derived_key_chacha20poly1305_round_trip() {
    let shared_secret = [0x33u8; 32];
    let key = derive_aead_key::<32>(&shared_secret, b"chacha20-enc-key");
    let nonce = [0xDDu8; 12];
    let plaintext = b"HKDF + ChaCha20-Poly1305 integration test";

    let aead = ChaCha20Poly1305;
    let ct = aead
        .seal_to_vec(&key, &nonce, b"authenticated data", plaintext)
        .expect("seal");
    let recovered = aead
        .open_to_vec(&key, &nonce, b"authenticated data", &ct)
        .expect("open");
    assert_eq!(recovered.as_slice(), plaintext);
}

// ── XChaCha20-Poly1305 with HKDF-derived key ─────────────────────────────────

#[test]
fn hkdf_derived_key_xchacha20poly1305_round_trip() {
    let shared_secret = [0x44u8; 32];
    let key = derive_aead_key::<32>(&shared_secret, b"xchacha20-enc-key");
    let nonce = [0xEEu8; 24]; // 24-byte nonce for XChaCha20
    let plaintext = b"HKDF + XChaCha20-Poly1305 integration test";

    let aead = XChaCha20Poly1305;
    let ct = aead
        .seal_to_vec(&key, &nonce, b"", plaintext)
        .expect("seal");
    let recovered = aead.open_to_vec(&key, &nonce, b"", &ct).expect("open");
    assert_eq!(recovered.as_slice(), plaintext);
}

// ── Key determinism: same inputs → identical derived keys ─────────────────────

#[test]
fn hkdf_derived_key_is_deterministic() {
    let shared_secret = [0x99u8; 32];
    let label = b"determinism-test";

    let key1 = derive_aead_key::<32>(&shared_secret, label);
    let key2 = derive_aead_key::<32>(&shared_secret, label);

    assert_eq!(key1, key2, "HKDF must be deterministic");
}

// ── Domain separation: different labels → different keys ──────────────────────

#[test]
fn hkdf_different_labels_produce_different_keys() {
    let shared_secret = [0xFEu8; 32];

    let key_enc = derive_aead_key::<32>(&shared_secret, b"encryption-key");
    let key_mac = derive_aead_key::<32>(&shared_secret, b"mac-key");

    assert_ne!(
        key_enc, key_mac,
        "different labels must produce different HKDF outputs"
    );
}
