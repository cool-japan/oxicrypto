//! Known-answer tests for AES-CCM.
//!
//! Reference vectors generated with OpenSSL 3.6.2 (AES-CCM EVP API).
//! Parameters: nonce = 13 bytes, tag = 16 bytes, max-message-len = 65535.
//!
//! OpenSSL command reference (C code used):
//! ```c
//! EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, NULL);      // t=16
//! EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 13, NULL);    // L=2
//! ```

use oxicrypto_aead::{Aes128Ccm, Aes256Ccm};
use oxicrypto_core::Aead;

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

// ── Vector 1: AES-128-CCM, key=all-zeros, nonce=all-zeros, no AAD ─────────────
//
// Key:       00000000000000000000000000000000
// Nonce:     00000000000000000000000000
// AAD:       (empty)
// Plaintext: 68656C6C6F2043434D  ("hello CCM")
// Expected ciphertext || tag (OpenSSL reference):
//   BD1D9E616FB5CF2F1D A60DB7AB4DB126B7151A9F9500BA4D19

#[test]
fn aes128ccm_kat_all_zeros_no_aad() {
    let aead = Aes128Ccm;
    let key = hex_decode("00000000000000000000000000000000");
    let nonce = hex_decode("00000000000000000000000000");
    let plaintext = b"hello CCM";
    let expected_ct_tag = hex_decode(
        "BD1D9E616FB5CF2F1D\
         A60DB7AB4DB126B7151A9F9500BA4D19",
    );

    let mut ct_out = vec![0u8; plaintext.len() + aead.tag_len()];
    let written = aead
        .seal(&key, &nonce, b"", plaintext, &mut ct_out)
        .expect("seal failed");
    assert_eq!(written, expected_ct_tag.len(), "output length mismatch");
    assert_eq!(
        &ct_out[..written],
        expected_ct_tag.as_slice(),
        "ciphertext+tag mismatch — possible CCM encoding bug"
    );

    // Verify the inverse (open) also succeeds.
    let mut pt_out = vec![0u8; plaintext.len()];
    let recovered = aead
        .open(&key, &nonce, b"", &ct_out[..written], &mut pt_out)
        .expect("open failed");
    assert_eq!(&pt_out[..recovered], plaintext.as_ref());
}

// ── Vector 2: AES-128-CCM, RFC 3610 key/nonce, 8-byte AAD ───────────────────
//
// Key:       C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF
// Nonce:     00000003020100A0A1A2A3A4A5
// AAD:       0001020304050607
// Plaintext: 08090A0B0C0D0E0F101112131415161718191A1B1C1D1E (23 bytes)
// Expected ciphertext || tag (OpenSSL reference, t=16):
//   588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384
//   509DA654E32DEAC369C2DAE7133CB08D

#[test]
fn aes128ccm_kat_rfc3610_key_with_aad() {
    let aead = Aes128Ccm;
    let key = hex_decode("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
    let nonce = hex_decode("00000003020100A0A1A2A3A4A5");
    let aad_bytes = hex_decode("0001020304050607");
    let plaintext = hex_decode("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
    let expected_ct_tag = hex_decode(
        "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384\
         509DA654E32DEAC369C2DAE7133CB08D",
    );

    let mut ct_out = vec![0u8; plaintext.len() + aead.tag_len()];
    let written = aead
        .seal(&key, &nonce, &aad_bytes, &plaintext, &mut ct_out)
        .expect("seal failed");
    assert_eq!(written, expected_ct_tag.len(), "output length mismatch");
    assert_eq!(
        &ct_out[..written],
        expected_ct_tag.as_slice(),
        "ciphertext+tag mismatch — AAD CCM encoding bug"
    );

    // Verify open.
    let mut pt_out = vec![0u8; plaintext.len()];
    let recovered = aead
        .open(&key, &nonce, &aad_bytes, &ct_out[..written], &mut pt_out)
        .expect("open failed");
    assert_eq!(&pt_out[..recovered], plaintext.as_slice());
}

// ── Vector 3: AES-256-CCM, key=all-zeros, nonce=all-zeros, no AAD ─────────────
//
// Key:       0000000000000000000000000000000000000000000000000000000000000000
// Nonce:     00000000000000000000000000
// AAD:       (empty)
// Plaintext: 68656C6C6F2043434D20323536  ("hello CCM 256")
// Expected ciphertext || tag (OpenSSL reference):
//   B5FB28C467DB459B051C1C2C0C
//   145B8BE1343EA29C9E99557DD02796E5

#[test]
fn aes256ccm_kat_all_zeros_no_aad() {
    let aead = Aes256Ccm;
    let key = hex_decode("0000000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex_decode("00000000000000000000000000");
    let plaintext = b"hello CCM 256";
    let expected_ct_tag = hex_decode(
        "B5FB28C467DB459B051C1C2C0C\
         145B8BE1343EA29C9E99557DD02796E5",
    );

    let mut ct_out = vec![0u8; plaintext.len() + aead.tag_len()];
    let written = aead
        .seal(&key, &nonce, b"", plaintext, &mut ct_out)
        .expect("seal failed");
    assert_eq!(written, expected_ct_tag.len(), "output length mismatch");
    assert_eq!(
        &ct_out[..written],
        expected_ct_tag.as_slice(),
        "AES-256-CCM ciphertext+tag mismatch"
    );

    // Verify open.
    let mut pt_out = vec![0u8; plaintext.len()];
    let recovered = aead
        .open(&key, &nonce, b"", &ct_out[..written], &mut pt_out)
        .expect("open failed");
    assert_eq!(&pt_out[..recovered], plaintext.as_ref());
}

// ── Vector 4: AES-128-CCM, empty plaintext with 9-byte AAD ──────────────────
//
// Key:       00000000000000000000000000000000
// Nonce:     0102030405060708090A0B0C0D
// AAD:       68656C6C6F20616164  ("hello aad")
// Plaintext: (empty)
// Expected ciphertext || tag (OpenSSL reference):
//   99C7420E0F13769069D9F7A4677FA5B7  (tag only, no ciphertext)

#[test]
fn aes128ccm_kat_empty_plaintext_with_aad() {
    let aead = Aes128Ccm;
    let key = hex_decode("00000000000000000000000000000000");
    let nonce = hex_decode("0102030405060708090A0B0C0D");
    let aad_bytes = b"hello aad";
    // Empty plaintext → output is tag only.
    let expected_tag = hex_decode("99C7420E0F13769069D9F7A4677FA5B7");

    let mut ct_out = vec![0u8; aead.tag_len()];
    let written = aead
        .seal(&key, &nonce, aad_bytes, b"", &mut ct_out)
        .expect("seal failed");
    assert_eq!(written, expected_tag.len(), "output length mismatch");
    assert_eq!(
        &ct_out[..written],
        expected_tag.as_slice(),
        "empty-plaintext tag mismatch — AAD MAC encoding bug"
    );

    // Verify open returns empty plaintext.
    let mut pt_out = vec![];
    let recovered = aead
        .open(&key, &nonce, aad_bytes, &ct_out[..written], &mut pt_out)
        .expect("open failed");
    assert_eq!(recovered, 0);
}

// ── Tamper-detection: wrong tag bytes rejected ────────────────────────────────

#[test]
fn aes128ccm_kat_tampered_tag_rejected() {
    let aead = Aes128Ccm;
    let key = hex_decode("00000000000000000000000000000000");
    let nonce = hex_decode("00000000000000000000000000");
    let plaintext = b"hello CCM";

    let mut ct_out = vec![0u8; plaintext.len() + aead.tag_len()];
    let written = aead
        .seal(&key, &nonce, b"", plaintext, &mut ct_out)
        .expect("seal");
    // Flip last tag byte.
    ct_out[written - 1] ^= 0x01;

    let mut pt_out = vec![0u8; plaintext.len()];
    let result = aead.open(&key, &nonce, b"", &ct_out[..written], &mut pt_out);
    assert!(
        matches!(result, Err(oxicrypto_core::CryptoError::InvalidTag)),
        "expected InvalidTag, got: {:?}",
        result
    );
}
