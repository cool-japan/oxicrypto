//! Ed25519 signature example: keygen, sign, verify.
//!
//! Ed25519 key generation is not part of the oxicrypto facade API (it requires
//! a `rand_core::TryCryptoRng` source, which the facade's `Rng` trait does not
//! expose). This example uses the `ed25519_dalek` dev-dependency for key
//! generation and then exercises the oxicrypto `signer_impl` / `verifier_impl`
//! factory functions for the actual sign/verify operations.
//!
//! Run with:
//!   cargo run -p oxicrypto --example sign

use ed25519_dalek::SigningKey;
use oxicrypto::{signer_impl, verifier_impl, SigAlgo};

fn main() {
    // ── Key generation ────────────────────────────────────────────────────────
    // ed25519_dalek::SigningKey::from_bytes takes a 32-byte seed.
    // In production, generate a cryptographically random seed via OsRng.
    // Here we derive the seed from a hard-coded value for reproducibility.
    let seed: [u8; 32] = {
        let mut s = [0u8; 32];
        // XOR a recognisable pattern into the seed bytes.
        for (i, byte) in s.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(0x5a);
        }
        s
    };

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key_bytes = signing_key.verifying_key().to_bytes(); // 32-byte compressed Edwards-y

    println!("Ed25519 verifying key: {}", hex(&verifying_key_bytes));

    // ── Sign ─────────────────────────────────────────────────────────────────
    // The oxicrypto Signer trait uses the 32-byte seed as the secret key.
    let signer = signer_impl(SigAlgo::Ed25519);

    let message = b"oxicrypto Ed25519 signature example";

    let mut signature = vec![0u8; signer.signature_len()]; // Ed25519 signature is 64 bytes.
    let sig_len = signer
        .sign(&seed, message, &mut signature)
        .expect("Ed25519 signing failed");

    println!("Signature ({sig_len} bytes): {}...", hex(&signature[..8]));

    // ── Verify ───────────────────────────────────────────────────────────────
    let verifier = verifier_impl(SigAlgo::Ed25519);

    verifier
        .verify(&verifying_key_bytes, message, &signature[..sig_len])
        .expect("Ed25519 verification failed on valid signature");

    println!("Signature verified successfully");

    // ── Reject tampered message ───────────────────────────────────────────────
    let tampered_message = b"TAMPERED Ed25519 signature example";
    let reject_result = verifier.verify(
        &verifying_key_bytes,
        tampered_message,
        &signature[..sig_len],
    );
    assert!(
        reject_result.is_err(),
        "Verifier must reject signature over a different message"
    );
    println!("Tamper detection: correctly rejected signature for wrong message");

    // ── Reject wrong key ─────────────────────────────────────────────────────
    let wrong_key = [0u8; 32];
    let wrong_result = verifier.verify(&wrong_key, message, &signature[..sig_len]);
    assert!(
        wrong_result.is_err(),
        "Verifier must reject signature verified under a different key"
    );
    println!("Key binding: correctly rejected signature for wrong public key");
}

/// Format a byte slice as a lowercase hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
