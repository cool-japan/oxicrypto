//! Post-quantum KEM example: ML-KEM-768 encapsulate/decapsulate.
//!
//! Requires the `pq-preview` feature:
//!   cargo run -p oxicrypto --example pq_kem --features pq-preview
//!
//! Demonstrates:
//!   1. Key pair generation via the high-level facade `pq_kem_generate`.
//!   2. Reconstruction of typed `EncapKey768` / `DecapKey768` from bytes.
//!   3. Encapsulation by the sender (returns ciphertext + shared secret).
//!   4. Decapsulation by the receiver (recovers shared secret from ciphertext).
//!   5. Verification that both sides hold the same 32-byte shared secret.

#[cfg(feature = "pq-preview")]
fn main() {
    use oxicrypto::pq::{DecapKey768, EncapKey768};
    use oxicrypto::{pq_kem_generate, PqKemAlgo};

    // ── Key Generation ────────────────────────────────────────────────────────
    // pq_kem_generate seeds its own OS RNG internally.
    // Returns (decap_key_bytes, encap_key_bytes).
    let (decap_bytes, encap_bytes) =
        pq_kem_generate(PqKemAlgo::MlKem768).expect("ML-KEM-768 key generation failed");

    println!("ML-KEM-768 key pair generated");
    println!("  Decap key: {} bytes", decap_bytes.len());
    println!("  Encap key: {} bytes", encap_bytes.len());

    // ── Reconstruct Typed Keys from Bytes ─────────────────────────────────────
    // In a real protocol the encap key is published; the decap key is kept secret.
    let encap_key = EncapKey768::from_bytes(&encap_bytes)
        .expect("Failed to deserialize ML-KEM-768 encapsulation key");

    let decap_key = DecapKey768::from_bytes(&decap_bytes)
        .expect("Failed to deserialize ML-KEM-768 decapsulation key");

    // ── Encapsulation (Sender) ────────────────────────────────────────────────
    // The sender calls encapsulate on the recipient's public encap key.
    // Returns (ciphertext, sender_shared_secret).
    let mut rng = {
        use rand_core::SeedableRng;
        // Seed from the OS for real randomness.
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS RNG failed");
        rand_chacha::ChaCha20Rng::from_seed(seed)
    };

    let (ciphertext, sender_secret) = encap_key
        .encapsulate(&mut rng)
        .expect("ML-KEM-768 encapsulation failed");

    println!("Encapsulation complete");
    println!("  Ciphertext: {} bytes", ciphertext.to_bytes().len());
    println!("  Sender shared secret: {}", hex(sender_secret.as_slice()));

    // ── Decapsulation (Receiver) ──────────────────────────────────────────────
    // The receiver uses their private decap key to recover the shared secret.
    let receiver_secret = decap_key
        .decapsulate(&ciphertext)
        .expect("ML-KEM-768 decapsulation failed");

    println!(
        "  Receiver shared secret: {}",
        hex(receiver_secret.as_slice())
    );

    // ── Verify Shared Secret Agreement ───────────────────────────────────────
    assert_eq!(
        sender_secret.as_slice(),
        receiver_secret.as_slice(),
        "ML-KEM-768: sender and receiver must derive the same shared secret"
    );
    println!("Shared secret agreement verified (32 bytes match)");
}

#[cfg(not(feature = "pq-preview"))]
fn main() {
    eprintln!(
        "This example requires the `pq-preview` feature.\n\
         Run: cargo run -p oxicrypto --example pq_kem --features pq-preview"
    );
    std::process::exit(1);
}

/// Format a byte slice as a lowercase hex string.
#[cfg(feature = "pq-preview")]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
