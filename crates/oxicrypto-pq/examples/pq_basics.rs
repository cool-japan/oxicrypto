//! Post-quantum cryptography with `oxicrypto-pq`: ML-KEM-768 key
//! encapsulation (FIPS 203) and ML-DSA-65 digital signatures (FIPS 204).
//!
//! Run with:
//!   cargo run -p oxicrypto-pq --example pq_basics

use oxicrypto_core::Kem;
use oxicrypto_pq::{MlDsa65, MlKem768};
use oxicrypto_rand::OxiRng;

fn main() {
    ml_kem_768_encapsulation();
    ml_dsa_65_signing();
}

/// ML-KEM-768 (FIPS 203, NIST security category 3): the sender encapsulates
/// a shared secret under the receiver's public key; the receiver recovers
/// the identical secret using their private key.
fn ml_kem_768_encapsulation() {
    // kem_generate() self-seeds an OS RNG internally.
    let (decap_key, encap_key) = MlKem768::kem_generate().expect("ML-KEM-768 keygen");

    // The sender only needs the public encapsulation key.
    let (ciphertext, sender_secret) =
        MlKem768::kem_encapsulate(&encap_key).expect("ML-KEM-768 encapsulate");
    println!(
        "ML-KEM-768: sender shared secret: {}",
        hex(sender_secret.as_ref())
    );

    // The receiver uses their private decapsulation key to recover the secret.
    let receiver_secret =
        MlKem768::kem_decapsulate(&decap_key, &ciphertext).expect("ML-KEM-768 decapsulate");
    println!(
        "ML-KEM-768: receiver shared secret: {}",
        hex(receiver_secret.as_ref())
    );

    assert_eq!(
        sender_secret.as_ref(),
        receiver_secret.as_ref(),
        "sender and receiver must agree on the same ML-KEM-768 shared secret"
    );
    println!("ML-KEM-768 shared secret agreement verified (32 bytes match)");
}

/// ML-DSA-65 (FIPS 204, NIST security category 3): sign a message with the
/// private signing key, verify it with the public verifying key.
fn ml_dsa_65_signing() {
    // ML-DSA's `generate` takes an infallible `CryptoRng`; `OxiRng` is
    // fallible (`TryCryptoRng`), so it is bridged via `rand_core::UnwrapErr`
    // (panics only on OS-entropy failure, which `kem_generate()` above
    // reports as a `CryptoError::Rng` instead — this is the one PQ API in
    // this crate that requires the infallible bound directly).
    let mut rng = rand_core::UnwrapErr(OxiRng::new().expect("OS-seeded RNG init"));
    let (signing_key, verifying_key) = MlDsa65::generate(&mut rng);

    let msg = b"ratify treaty section 4.2";
    let signature = signing_key.sign(msg).expect("ML-DSA-65 sign");
    println!(
        "ML-DSA-65 signature computed for a {}-byte message",
        msg.len()
    );

    verifying_key
        .verify(msg, &signature)
        .expect("genuine ML-DSA-65 signature must verify");
    println!("Genuine ML-DSA-65 signature verified OK");

    let result = verifying_key.verify(b"ratify treaty section 4.3", &signature);
    assert!(
        result.is_err(),
        "signature over a different message must fail"
    );
    println!("Wrong message correctly rejected: {result:?}");
}

/// Format a byte slice as a lowercase hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
