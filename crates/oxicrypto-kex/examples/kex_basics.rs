//! X25519 key agreement with `oxicrypto-kex`, followed by HKDF-SHA-256
//! session-key derivation (`oxicrypto-kdf`, already a direct dependency of
//! this crate) — the standard "ECDH then KDF" pattern used to turn a raw
//! Diffie-Hellman shared secret into a symmetric key.
//!
//! Run with:
//!   cargo run -p oxicrypto-kex --example kex_basics

use oxicrypto_core::KeyAgreement;
use oxicrypto_kdf::hkdf_sha256_derive_to_vec;
use oxicrypto_kex::{x25519_generate_keypair, X25519};
use oxicrypto_rand::OxiRng;

fn main() {
    let mut rng = OxiRng::new().expect("OS-seeded RNG init");

    // Each party generates an ephemeral X25519 key pair.
    let (alice_secret, alice_public) = x25519_generate_keypair(&mut rng).expect("Alice keygen");
    let (bob_secret, bob_public) = x25519_generate_keypair(&mut rng).expect("Bob keygen");

    // Each party combines their own secret with the other's public key.
    let mut alice_shared = [0u8; 32];
    X25519
        .agree(alice_secret.as_bytes(), &bob_public, &mut alice_shared)
        .expect("Alice X25519 agree");

    let mut bob_shared = [0u8; 32];
    X25519
        .agree(bob_secret.as_bytes(), &alice_public, &mut bob_shared)
        .expect("Bob X25519 agree");

    assert_eq!(
        alice_shared, bob_shared,
        "both parties must derive the same X25519 shared secret"
    );
    println!(
        "X25519 shared secret agreed by both parties: {}",
        hex(&alice_shared)
    );

    // Turn the raw DH output into a symmetric session key via HKDF-SHA-256
    // (RFC 5869) — never use a raw ECDH shared secret directly as a cipher key.
    let salt = b"oxicrypto-kex-example-salt";
    let info = b"aes-256-gcm session key v1";
    let alice_session_key =
        hkdf_sha256_derive_to_vec(&alice_shared, salt, info, 32).expect("Alice HKDF derive");
    let bob_session_key =
        hkdf_sha256_derive_to_vec(&bob_shared, salt, info, 32).expect("Bob HKDF derive");

    assert_eq!(
        alice_session_key, bob_session_key,
        "both parties must derive the same session key"
    );
    println!(
        "HKDF-SHA-256 session key ({} bytes): {}",
        alice_session_key.len(),
        hex(&alice_session_key)
    );

    // A third party (Eve) with her own key pair must NOT be able to derive
    // the same shared secret as Alice and Bob.
    let (eve_secret, _eve_public) = x25519_generate_keypair(&mut rng).expect("Eve keygen");
    let mut eve_shared = [0u8; 32];
    X25519
        .agree(eve_secret.as_bytes(), &bob_public, &mut eve_shared)
        .expect("Eve X25519 agree");
    assert_ne!(
        eve_shared, alice_shared,
        "an unrelated key pair must not reproduce Alice/Bob's shared secret"
    );
    println!("Eve's shared secret (with her own key) correctly differs from Alice/Bob's");
}

/// Format a byte slice as a lowercase hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
