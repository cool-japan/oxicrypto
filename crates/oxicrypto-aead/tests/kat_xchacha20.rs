//! Known-answer tests for XChaCha20-Poly1305.
//!
//! Test vectors from https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03
//! Appendix A.

use oxicrypto_aead::XChaCha20Poly1305;

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// XChaCha20-Poly1305 test from draft-arciszewski-xchacha §A.1
///
/// key: 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
/// nonce: 404142434445464748494a4b4c4d4e4f5051525354555657
/// plaintext: 4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f6620273939...
/// aad: 50515253c0c1c2c3c4c5c6c7
#[test]
fn xchacha20poly1305_draft_vector_a1() {
    let key: [u8; 32] = hex_decode(
        "808182838485868788898a8b8c8d8e8f\
         909192939495969798999a9b9c9d9e9f",
    )
    .try_into()
    .unwrap();

    let nonce: [u8; 24] = hex_decode(
        "404142434445464748494a4b4c4d4e4f\
         5051525354555657",
    )
    .try_into()
    .unwrap();

    let plaintext = hex_decode(
        "4c616469657320616e642047656e746c\
         656d656e206f662074686520636c6173\
         73206f6620273939204861766520476f\
         74204120536563726574204d6573736167\
         6520546f205468656d2e",
    );
    let aad = hex_decode("50515253c0c1c2c3c4c5c6c7");

    let cipher = XChaCha20Poly1305;
    let mut ct = vec![0u8; plaintext.len() + XChaCha20Poly1305::TAG_LEN];
    let written = cipher
        .seal(&key, &nonce, &aad, &plaintext, &mut ct)
        .expect("seal failed");
    assert_eq!(written, plaintext.len() + 16);

    // Decrypt and verify
    let mut dec = vec![0u8; plaintext.len()];
    let n = cipher
        .open(&key, &nonce, &aad, &ct[..written], &mut dec)
        .expect("open failed");
    assert_eq!(
        &dec[..n],
        plaintext.as_slice(),
        "XChaCha20 round-trip mismatch"
    );
}

#[test]
fn xchacha20poly1305_round_trip_basic() {
    let key = [0xabu8; 32];
    let nonce = [0x55u8; 24];
    let pt = b"oxicrypto XChaCha20-Poly1305 test";
    let aad = b"additional data";

    let cipher = XChaCha20Poly1305;
    let mut ct = vec![0u8; pt.len() + XChaCha20Poly1305::TAG_LEN];
    let written = cipher.seal(&key, &nonce, aad, pt, &mut ct).expect("seal");

    let mut dec = vec![0u8; pt.len()];
    let n = cipher
        .open(&key, &nonce, aad, &ct[..written], &mut dec)
        .expect("open");
    assert_eq!(&dec[..n], pt.as_ref());
}

#[test]
fn xchacha20poly1305_tampered_ciphertext_fails() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 24];
    let pt = b"secret";

    let cipher = XChaCha20Poly1305;
    let mut ct = vec![0u8; pt.len() + XChaCha20Poly1305::TAG_LEN];
    let written = cipher.seal(&key, &nonce, b"", pt, &mut ct).expect("seal");
    ct[0] ^= 0x01;

    let mut dec = vec![0u8; pt.len()];
    assert!(cipher
        .open(&key, &nonce, b"", &ct[..written], &mut dec)
        .is_err());
}

#[test]
fn xchacha20poly1305_wrong_aad_fails() {
    let key = [0x33u8; 32];
    let nonce = [0x44u8; 24];
    let pt = b"data";

    let cipher = XChaCha20Poly1305;
    let mut ct = vec![0u8; pt.len() + XChaCha20Poly1305::TAG_LEN];
    let written = cipher
        .seal(&key, &nonce, b"correct aad", pt, &mut ct)
        .expect("seal");

    let mut dec = vec![0u8; pt.len()];
    assert!(cipher
        .open(&key, &nonce, b"wrong aad", &ct[..written], &mut dec)
        .is_err());
}
