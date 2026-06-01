//! Key-exchange example: X25519 DH + HKDF-SHA-256 + AES-256-GCM session encryption.
//!
//! Demonstrates the classic Diffie-Hellman + KDF + AEAD pattern:
//!   1. Alice and Bob each generate an X25519 keypair (using x25519_dalek dev-dep
//!      for key generation, since the facade's `Rng` trait is not TryCryptoRng).
//!   2. Both sides compute the same shared secret via `kex_impl(KexAlgo::X25519)`.
//!   3. The raw DH secret is fed through `kdf_impl(KdfAlgo::HkdfSha256)` to
//!      derive a 32-byte AES-256-GCM session key.
//!   4. Alice encrypts a message; Bob decrypts it.
//!
//! Run with:
//!   cargo run -p oxicrypto --example kex

use oxicrypto::{aead_impl, kdf_impl, kex_impl, AeadAlgo, KdfAlgo, KexAlgo};
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    // ── Key Generation ────────────────────────────────────────────────────────
    // Use hard-coded seeds for reproducibility. In production, seed from OsRng.
    let alice_secret_bytes: [u8; 32] = {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0xaa);
        }
        s
    };
    let bob_secret_bytes: [u8; 32] = {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0xbb);
        }
        s
    };

    // x25519_dalek: derive the public key (point) from each private scalar.
    let alice_public_bytes = *PublicKey::from(&StaticSecret::from(alice_secret_bytes)).as_bytes();
    let bob_public_bytes = *PublicKey::from(&StaticSecret::from(bob_secret_bytes)).as_bytes();

    println!("Alice public: {}", hex(&alice_public_bytes));
    println!("Bob   public: {}", hex(&bob_public_bytes));

    // ── Diffie-Hellman Agreement ──────────────────────────────────────────────
    let kex = kex_impl(KexAlgo::X25519);

    let mut alice_shared = [0u8; 32];
    kex.agree(&alice_secret_bytes, &bob_public_bytes, &mut alice_shared)
        .expect("Alice's X25519 agree failed");

    let mut bob_shared = [0u8; 32];
    kex.agree(&bob_secret_bytes, &alice_public_bytes, &mut bob_shared)
        .expect("Bob's X25519 agree failed");

    assert_eq!(
        alice_shared, bob_shared,
        "X25519: Alice and Bob must derive the same shared secret"
    );
    println!("Shared DH secret: {}", hex(&alice_shared));

    // ── Key Derivation ────────────────────────────────────────────────────────
    // Do not use the raw DH output directly; run it through a KDF to produce
    // a uniformly-distributed session key.
    let kdf = kdf_impl(KdfAlgo::HkdfSha256);
    let salt = b"oxicrypto-kex-example-salt";
    let info = b"x25519+hkdf+aes256gcm session key";

    let mut session_key = [0u8; 32];
    kdf.derive(&alice_shared, salt, info, &mut session_key)
        .expect("HKDF-SHA-256 key derivation failed");

    // Bob performs the same derivation (with identical salt + info).
    let mut bob_session_key = [0u8; 32];
    kdf.derive(&bob_shared, salt, info, &mut bob_session_key)
        .expect("Bob's HKDF-SHA-256 key derivation failed");

    assert_eq!(
        session_key, bob_session_key,
        "Both sides must derive the same session key"
    );
    println!("Derived AES-256-GCM session key (32 bytes)");

    // ── Encrypted Session Communication ───────────────────────────────────────
    let aead = aead_impl(AeadAlgo::Aes256Gcm);

    // Fixed nonce for the example; in production use a unique random nonce per message.
    let nonce = [0x01u8; 12];
    let aad = b"alice-to-bob message #1";
    let plaintext = b"Secret message from Alice to Bob via X25519 + HKDF + AES-256-GCM";

    // Alice encrypts.
    let ciphertext = aead
        .seal_to_vec(&session_key, &nonce, aad, plaintext)
        .expect("AES-256-GCM encryption (Alice) failed");

    println!(
        "Alice encrypted {} bytes -> {} bytes ciphertext",
        plaintext.len(),
        ciphertext.len()
    );

    // Bob decrypts.
    let recovered = aead
        .open_to_vec(&bob_session_key, &nonce, aad, &ciphertext)
        .expect("AES-256-GCM decryption (Bob) failed");

    assert_eq!(
        recovered.as_slice(),
        plaintext.as_ref(),
        "Bob's recovered plaintext must match Alice's original"
    );
    println!(
        "Bob decrypted successfully: {:?}",
        core::str::from_utf8(&recovered).unwrap_or("<binary>")
    );
}

/// Format a byte slice as a lowercase hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
