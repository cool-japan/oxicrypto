use oxicrypto_aead::SyntheticIvAes256Gcm;
use oxicrypto_core::{Aead, CryptoError};

const KEY: [u8; 32] = [0x42u8; 32];
const AAD: &[u8] = b"additional authenticated data";
const PT: &[u8] = b"hello synthetic IV";

fn seal(pt: &[u8], aad: &[u8]) -> Vec<u8> {
    let aead = SyntheticIvAes256Gcm;
    let mut out = vec![0u8; pt.len() + aead.tag_len()];
    aead.seal(&KEY, &[], aad, pt, &mut out)
        .expect("seal failed");
    out
}

fn open(ct: &[u8], aad: &[u8]) -> Vec<u8> {
    let aead = SyntheticIvAes256Gcm;
    let tag_len = aead.tag_len();
    let pt_len = ct.len() - tag_len;
    let mut out = vec![0u8; pt_len];
    aead.open(&KEY, &[], aad, ct, &mut out)
        .expect("open failed");
    out
}

#[test]
fn synthetic_iv_gcm_round_trip() {
    let ct = seal(PT, AAD);
    let recovered = open(&ct, AAD);
    assert_eq!(recovered.as_slice(), PT);
}

#[test]
fn synthetic_iv_gcm_deterministic() {
    // Same inputs must produce exactly the same ciphertext (synthetic IV = deterministic).
    let ct1 = seal(PT, AAD);
    let ct2 = seal(PT, AAD);
    assert_eq!(ct1, ct2, "same inputs must produce same ciphertext");
}

#[test]
fn synthetic_iv_gcm_diff_messages_diff_nonces() {
    let ct1 = seal(b"message one", AAD);
    let ct2 = seal(b"message two", AAD);

    // Extract the nonce (first 12 bytes) and verify they differ.
    assert_ne!(
        &ct1[..12],
        &ct2[..12],
        "different messages must produce different nonces"
    );
    // Ciphertexts should also differ.
    assert_ne!(ct1, ct2);
}

#[test]
fn synthetic_iv_gcm_wrong_key_fails() {
    let ct = seal(PT, AAD);

    let aead = SyntheticIvAes256Gcm;
    let wrong_key = [0xFFu8; 32];
    let pt_len = ct.len() - aead.tag_len();
    let mut pt_out = vec![0u8; pt_len];
    let result = aead.open(&wrong_key, &[], AAD, &ct, &mut pt_out);
    assert_eq!(result, Err(CryptoError::InvalidTag), "wrong key must fail");
}

#[test]
fn synthetic_iv_gcm_tampered_ciphertext_fails() {
    let mut ct = seal(PT, AAD);
    // Flip a byte in the ciphertext (after the 12-byte nonce prefix).
    ct[12] ^= 0xFF;

    let aead = SyntheticIvAes256Gcm;
    let pt_len = ct.len() - aead.tag_len();
    let mut pt_out = vec![0u8; pt_len];
    let result = aead.open(&KEY, &[], AAD, &ct, &mut pt_out);
    assert!(result.is_err(), "tampered ciphertext must fail");
}

#[test]
fn synthetic_iv_gcm_wrong_aad_fails() {
    let ct = seal(PT, AAD);

    let aead = SyntheticIvAes256Gcm;
    let pt_len = ct.len() - aead.tag_len();
    let mut pt_out = vec![0u8; pt_len];
    let result = aead.open(&KEY, &[], b"wrong aad", &ct, &mut pt_out);
    assert!(result.is_err(), "wrong AAD must fail");
}

#[test]
fn synthetic_iv_gcm_empty_plaintext() {
    let aead = SyntheticIvAes256Gcm;
    let mut ct = vec![0u8; aead.tag_len()];
    aead.seal(&KEY, &[], AAD, b"", &mut ct)
        .expect("seal empty failed");
    assert_eq!(ct.len(), aead.tag_len());

    let mut pt_out: Vec<u8> = Vec::new();
    let n = aead
        .open(&KEY, &[], AAD, &ct, &mut pt_out)
        .expect("open empty failed");
    assert_eq!(n, 0);
}

#[test]
fn synthetic_iv_gcm_metadata() {
    let aead = SyntheticIvAes256Gcm;
    assert_eq!(aead.name(), "AES-256-GCM-SIV-Synthetic");
    assert_eq!(aead.key_len(), 32);
    assert_eq!(aead.nonce_len(), 0);
    assert_eq!(aead.tag_len(), 28);
}

#[test]
fn synthetic_iv_gcm_nonempty_nonce_rejected() {
    let aead = SyntheticIvAes256Gcm;
    let mut ct = vec![0u8; PT.len() + aead.tag_len()];
    let result = aead.seal(&KEY, &[0u8; 12], AAD, PT, &mut ct);
    assert_eq!(
        result,
        Err(CryptoError::InvalidNonce),
        "non-empty nonce must be rejected"
    );
}
