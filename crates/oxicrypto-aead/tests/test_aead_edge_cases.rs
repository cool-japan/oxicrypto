use oxicrypto_aead::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, SyntheticIvAes256Gcm};
use oxicrypto_core::{Aead, CryptoError};

const KEY_128: [u8; 16] = [0x42u8; 16];
const KEY_256: [u8; 32] = [0x42u8; 32];
const NONCE_12: [u8; 12] = [0x11u8; 12];
const AAD: &[u8] = b"aad";
const PT: &[u8] = b"test plaintext for edge cases";

// ── seal_in_place tests ───────────────────────────────────────────────────────

#[test]
fn seal_in_place_aes128gcm() {
    let aead = Aes128Gcm;
    let pt: Vec<u8> = PT.to_vec();
    let mut buf = pt.clone();

    aead.seal_in_place(&KEY_128, &NONCE_12, AAD, &mut buf)
        .expect("seal_in_place failed");

    assert_eq!(buf.len(), PT.len() + aead.tag_len());

    // Round-trip: open the in-place result.
    let mut recovered = vec![0u8; PT.len()];
    aead.open(&KEY_128, &NONCE_12, AAD, &buf, &mut recovered)
        .expect("open after seal_in_place failed");
    assert_eq!(recovered.as_slice(), PT);
}

#[test]
fn seal_in_place_aes256gcm() {
    let aead = Aes256Gcm;
    let mut buf = PT.to_vec();

    aead.seal_in_place(&KEY_256, &NONCE_12, AAD, &mut buf)
        .expect("seal_in_place failed");

    assert_eq!(buf.len(), PT.len() + aead.tag_len());

    let mut recovered = vec![0u8; PT.len()];
    aead.open(&KEY_256, &NONCE_12, AAD, &buf, &mut recovered)
        .expect("open after seal_in_place failed");
    assert_eq!(recovered.as_slice(), PT);
}

#[test]
fn seal_in_place_chacha20poly1305() {
    let aead = ChaCha20Poly1305;
    let mut buf = PT.to_vec();

    aead.seal_in_place(&KEY_256, &NONCE_12, AAD, &mut buf)
        .expect("seal_in_place failed");

    assert_eq!(buf.len(), PT.len() + aead.tag_len());

    let mut recovered = vec![0u8; PT.len()];
    aead.open(&KEY_256, &NONCE_12, AAD, &buf, &mut recovered)
        .expect("open after seal_in_place failed");
    assert_eq!(recovered.as_slice(), PT);
}

#[test]
fn seal_in_place_result_matches_seal() {
    // The in-place result must exactly match the regular seal output.
    let aead = Aes256Gcm;

    let mut inplace_buf = PT.to_vec();
    aead.seal_in_place(&KEY_256, &NONCE_12, AAD, &mut inplace_buf)
        .expect("seal_in_place failed");

    let mut combined = vec![0u8; PT.len() + aead.tag_len()];
    aead.seal(&KEY_256, &NONCE_12, AAD, PT, &mut combined)
        .expect("seal failed");

    assert_eq!(
        inplace_buf, combined,
        "seal_in_place must equal seal output"
    );
}

#[test]
fn seal_in_place_synthetic_iv_gcm() {
    let aead = SyntheticIvAes256Gcm;
    let mut buf = PT.to_vec();

    aead.seal_in_place(&KEY_256, &[], AAD, &mut buf)
        .expect("seal_in_place failed");

    assert_eq!(buf.len(), PT.len() + aead.tag_len());

    let mut recovered = vec![0u8; PT.len()];
    aead.open(&KEY_256, &[], AAD, &buf, &mut recovered)
        .expect("open after seal_in_place failed");
    assert_eq!(recovered.as_slice(), PT);
}

// ── Empty plaintext / empty AAD ───────────────────────────────────────────────

fn check_empty_pt_empty_aad<A: Aead>(aead: &A, key: &[u8], nonce: &[u8]) {
    let mut ct = vec![0u8; aead.tag_len()];
    aead.seal(key, nonce, b"", b"", &mut ct)
        .expect("seal empty-pt empty-aad failed");

    // Should be only the tag — no plaintext bytes.
    assert_eq!(ct.len(), aead.tag_len());

    let mut pt_out: Vec<u8> = Vec::new();
    let n = aead
        .open(key, nonce, b"", &ct, &mut pt_out)
        .expect("open empty-pt empty-aad failed");
    assert_eq!(n, 0);
}

#[test]
fn aead_empty_plaintext_empty_aad_aes128gcm() {
    check_empty_pt_empty_aad(&Aes128Gcm, &KEY_128, &NONCE_12);
}

#[test]
fn aead_empty_plaintext_empty_aad_aes256gcm() {
    check_empty_pt_empty_aad(&Aes256Gcm, &KEY_256, &NONCE_12);
}

#[test]
fn aead_empty_plaintext_empty_aad_chacha20poly1305() {
    check_empty_pt_empty_aad(&ChaCha20Poly1305, &KEY_256, &NONCE_12);
}

#[test]
fn aead_empty_plaintext_with_aad() {
    // Empty plaintext but non-empty AAD should still authenticate.
    let aead = Aes256Gcm;
    let mut ct = vec![0u8; aead.tag_len()];
    aead.seal(&KEY_256, &NONCE_12, AAD, b"", &mut ct)
        .expect("seal failed");

    let mut pt_out: Vec<u8> = Vec::new();
    let n = aead
        .open(&KEY_256, &NONCE_12, AAD, &ct, &mut pt_out)
        .expect("open failed");
    assert_eq!(n, 0);

    // Wrong AAD must fail.
    let result = aead.open(&KEY_256, &NONCE_12, b"wrong", &ct, &mut pt_out);
    assert_eq!(result, Err(CryptoError::InvalidTag));
}

// ── Nonce reuse detection ─────────────────────────────────────────────────────

#[test]
fn aead_nonce_reuse_different_ciphertexts() {
    // Two different plaintexts encrypted under the same (key, nonce) should
    // produce different ciphertexts (this is expected GCM behaviour — GCM is
    // not nonce-misuse resistant, but still produces different bytes).
    let aead = Aes256Gcm;
    let pt1 = b"first message";
    let pt2 = b"second message!!";

    let ct1 = aead
        .seal_to_vec(&KEY_256, &NONCE_12, AAD, pt1)
        .expect("seal1 failed");
    let ct2 = aead
        .seal_to_vec(&KEY_256, &NONCE_12, AAD, pt2)
        .expect("seal2 failed");

    assert_ne!(
        ct1, ct2,
        "different plaintexts must produce different ciphertexts"
    );
}

#[test]
fn aead_nonce_reuse_same_message_same_ciphertext() {
    // Determinism: same (key, nonce, aad, pt) → same ciphertext.
    let aead = Aes256Gcm;
    let ct1 = aead
        .seal_to_vec(&KEY_256, &NONCE_12, AAD, PT)
        .expect("seal1 failed");
    let ct2 = aead
        .seal_to_vec(&KEY_256, &NONCE_12, AAD, PT)
        .expect("seal2 failed");
    assert_eq!(ct1, ct2);
}

// ── Buffer size errors ────────────────────────────────────────────────────────

#[test]
fn seal_buffer_too_small() {
    let aead = Aes256Gcm;
    // Output buffer is one byte too small.
    let mut ct = vec![0u8; PT.len() + aead.tag_len() - 1];
    let result = aead.seal(&KEY_256, &NONCE_12, AAD, PT, &mut ct);
    assert_eq!(result, Err(CryptoError::BufferTooSmall));
}

#[test]
fn open_ciphertext_too_short() {
    let aead = Aes256Gcm;
    // Ciphertext shorter than tag_len — must error without panicking.
    let short_ct = vec![0u8; aead.tag_len() - 1];
    let mut pt_out = vec![0u8; 0];
    let result = aead.open(&KEY_256, &NONCE_12, AAD, &short_ct, &mut pt_out);
    assert!(result.is_err(), "too-short ciphertext must error");
}
