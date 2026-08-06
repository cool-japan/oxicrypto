//! Digital signatures with `oxicrypto-sig`: Ed25519 and ECDSA P-256 via the
//! [`Signer`]/[`Verifier`] traits, both keyed by an OS-seeded [`OxiRng`].
//!
//! Run with:
//!   cargo run -p oxicrypto-sig --example sig_basics

use oxicrypto_core::{Signer, Verifier};
use oxicrypto_rand::OxiRng;
use oxicrypto_sig::{
    ecdsa_p256_generate_keypair, ed25519_generate_keypair, EcdsaP256, EcdsaP256Verify, Ed25519,
    Ed25519Verifier,
};

fn main() {
    let mut rng = OxiRng::new().expect("OS-seeded RNG init");

    ed25519_roundtrip(&mut rng);
    ecdsa_p256_roundtrip(&mut rng);
}

fn ed25519_roundtrip(rng: &mut OxiRng) {
    let (signing_key, verifying_key) = ed25519_generate_keypair(rng).expect("Ed25519 keygen");
    let msg = b"transfer 100 credits to account #7";

    let mut sig = [0u8; 64];
    let written = Ed25519
        .sign(signing_key.as_bytes(), msg, &mut sig)
        .expect("Ed25519 sign");
    assert_eq!(written, 64);
    println!("Ed25519 signature ({written} bytes): {}", hex(&sig));

    Ed25519Verifier
        .verify(&verifying_key, msg, &sig)
        .expect("genuine Ed25519 signature must verify");
    println!("Genuine Ed25519 signature verified OK");

    // A signature over a different message must not verify.
    let result = Ed25519Verifier.verify(&verifying_key, b"transfer 900 credits", &sig);
    assert!(
        result.is_err(),
        "signature over the wrong message must fail"
    );
    println!("Wrong message correctly rejected: {result:?}");
}

fn ecdsa_p256_roundtrip(rng: &mut OxiRng) {
    let (signing_key, verifying_key) =
        ecdsa_p256_generate_keypair(rng).expect("ECDSA P-256 keygen");
    let msg = b"approve invoice #42";

    // ECDSA signatures are DER-encoded and variable-length; signature_len()
    // returns the DER maximum, and sign() returns the true written length.
    let mut sig = vec![0u8; EcdsaP256.signature_len()];
    let written = EcdsaP256
        .sign(signing_key.as_bytes(), msg, &mut sig)
        .expect("ECDSA P-256 sign");
    sig.truncate(written);
    println!("ECDSA P-256 DER signature ({written} bytes): {}", hex(&sig));

    EcdsaP256Verify
        .verify(&verifying_key, msg, &sig)
        .expect("genuine ECDSA P-256 signature must verify");
    println!("Genuine ECDSA P-256 signature verified OK");

    // A corrupted signature must be rejected.
    let mut bad_sig = sig.clone();
    let last = bad_sig.len() - 1;
    bad_sig[last] ^= 0xFF;
    let result = EcdsaP256Verify.verify(&verifying_key, msg, &bad_sig);
    assert!(result.is_err(), "corrupted signature must fail");
    println!("Corrupted ECDSA P-256 signature correctly rejected: {result:?}");
}

/// Format a byte slice as a lowercase hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
