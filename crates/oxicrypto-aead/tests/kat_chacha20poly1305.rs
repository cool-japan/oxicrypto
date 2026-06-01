//! Known-answer tests for ChaCha20-Poly1305 (RFC 8439).
//!
//! Test vectors from RFC 8439 §2.8.2 (the canonical AEAD encryption example)
//! and Appendix A.5 (the AEAD decryption example). Both are transcribed
//! verbatim from RFC 8439 and are self-checking against the implementation.

use oxicrypto_aead::ChaCha20Poly1305;
use oxicrypto_core::Aead;

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// RFC 8439 §2.8.2 complete AEAD_CHACHA20_POLY1305 test vector.
///
/// Key   = 808182838485868788898a8b8c8d8e8f
///         909192939495969798999a9b9c9d9e9f
/// Nonce = 07000000 40414243 44454647 (12 bytes)
/// AAD   = 50515253 c0c1c2c3 c4c5c6c7 (12 bytes)
/// PT    = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
///         (114 bytes)
///
/// Expected ciphertext (114 bytes) + tag (16 bytes) per RFC 8439 §2.8.2.
#[test]
fn chacha20poly1305_rfc8439_s2_8_2() {
    let key: [u8; 32] = hex_decode(
        "808182838485868788898a8b8c8d8e8f\
         909192939495969798999a9b9c9d9e9f",
    )
    .try_into()
    .expect("key must be 32 bytes");

    // Nonce: 07 00 00 00 | 40 41 42 43 | 44 45 46 47
    let nonce: [u8; 12] = hex_decode("070000004041424344454647")
        .try_into()
        .expect("nonce must be 12 bytes");

    let aad = hex_decode("50515253c0c1c2c3c4c5c6c7");
    let pt =
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let expected_ct = concat!(
        "d31a8d34648e60db7b86afbc53ef7ec2",
        "a4aded51296e08fea9e2b5a736ee62d6",
        "3dbea45e8ca9671282fafb69da92728b",
        "1a71de0a9e060b2905d6a5b67ecd3b36",
        "92ddbd7f2d778b8c9803aee328091b58",
        "fab324e4fad675945585808b4831d7bc",
        "3ff4def08e4b7a9de576d26586cec64b",
        "6116",
    );
    let expected_tag = "1ae10b594f09e26a7e902ecbd0600691";

    let tag_len = ChaCha20Poly1305.tag_len();
    let mut ct_out = vec![0u8; pt.len() + tag_len];
    let written = ChaCha20Poly1305
        .seal(&key, &nonce, &aad, pt, &mut ct_out)
        .expect("ChaCha20-Poly1305 seal failed");

    assert_eq!(written, pt.len() + 16);
    assert_eq!(
        to_hex(&ct_out[..pt.len()]),
        expected_ct,
        "RFC 8439 §2.8.2 ciphertext mismatch"
    );
    assert_eq!(
        to_hex(&ct_out[pt.len()..written]),
        expected_tag,
        "RFC 8439 §2.8.2 tag mismatch"
    );

    // Verify decryption round-trip.
    let mut pt_out = vec![0u8; pt.len()];
    let recovered = ChaCha20Poly1305
        .open(&key, &nonce, &aad, &ct_out[..written], &mut pt_out)
        .expect("ChaCha20-Poly1305 open failed");
    assert_eq!(recovered, pt.len());
    assert_eq!(&pt_out, pt.as_ref(), "RFC 8439 §2.8.2 round-trip failed");
}

/// RFC 8439 Appendix A.5 — ChaCha20-Poly1305 AEAD *decryption* example.
///
/// A second independent official vector (distinct key/nonce/AAD from §2.8.2),
/// transcribed verbatim from RFC 8439 Appendix A.5. The 265-byte ciphertext
/// decrypts to the "Internet-Drafts are draft documents…" text (whose tail
/// contains the U+201C/U+201D smart-quote bytes `2f e2 80 9c` / `2f e2 80 9d`,
/// hence the plaintext is assembled from its ASCII body plus the explicit
/// quote bytes). We verify both directions: open of the published
/// ciphertext+tag recovers the plaintext, and seal of that plaintext
/// reproduces the exact ciphertext+tag.
#[test]
fn chacha20poly1305_rfc8439_a5_decryption() {
    let key: [u8; 32] = hex_decode(
        "1c9240a5eb55d38af333888604f6b5f0\
         473917c1402b80099dca5cbc207075c0",
    )
    .try_into()
    .expect("key must be 32 bytes");

    let nonce: [u8; 12] = hex_decode("000000000102030405060708")
        .try_into()
        .expect("nonce must be 12 bytes");

    let aad = hex_decode("f33388860000000000004e91");

    let expected_ct = concat!(
        "64a0861575861af460f062c79be643bd",
        "5e805cfd345cf389f108670ac76c8cb2",
        "4c6cfc18755d43eea09ee94e382d26b0",
        "bdb7b73c321b0100d4f03b7f355894cf",
        "332f830e710b97ce98c8a84abd0b9481",
        "14ad176e008d33bd60f982b1ff37c855",
        "9797a06ef4f0ef61c186324e2b350638",
        "3606907b6a7c02b0f9f6157b53c867e4",
        "b9166c767b804d46a59b5216cde7a4e9",
        "9040c5a40433225ee282a1b0a06c523e",
        "af4534d7f83fa1155b0047718cbc546a",
        "0d072b04b3564eea1b422273f548271a",
        "0bb2316053fa76991955ebd63159434e",
        "cebb4e466dae5a1073a6727627097a10",
        "49e617d91d361094fa68f0ff77987130",
        "305beaba2eda04df997b714d6c6f2c29",
        "a6ad5cb4022b02709b",
    );
    let expected_tag = "eead9d67890cbb22392336fea1851f38";

    // Plaintext (RFC 8439 A.5). The tail contains the non-ASCII U+201C/U+201D
    // smart-quote bytes (`2f e2 80 9c` / `2f e2 80 9d`), so we assemble it from
    // its ASCII body plus the explicit quote bytes rather than a hex blob.
    let pt: Vec<u8> = {
        let head: &[u8] = b"Internet-Drafts are draft documents valid for a maximum of six months and may be updated, replaced, or obsoleted by other documents at any time. It is inappropriate to use Internet-Drafts as reference material or to cite them other than as ";
        let mut v = head.to_vec();
        v.extend_from_slice(&[0x2f, 0xe2, 0x80, 0x9c]); // '/' + U+201C
        v.extend_from_slice(b"work in progress.");
        v.extend_from_slice(&[0x2f, 0xe2, 0x80, 0x9d]); // '/' + U+201D
        v
    };

    // Decrypt the published ciphertext ‖ tag and check the plaintext.
    let mut wire = hex_decode(expected_ct);
    wire.extend_from_slice(&hex_decode(expected_tag));
    let mut pt_out = vec![0u8; pt.len()];
    let recovered = ChaCha20Poly1305
        .open(&key, &nonce, &aad, &wire, &mut pt_out)
        .expect("RFC 8439 A.5 open failed");
    assert_eq!(recovered, pt.len(), "A.5 recovered length mismatch");
    assert_eq!(
        to_hex(&pt_out),
        to_hex(&pt),
        "RFC 8439 A.5 plaintext mismatch"
    );

    // Re-encrypt and confirm we reproduce the exact ciphertext ‖ tag.
    let mut ct_out = vec![0u8; pt.len() + ChaCha20Poly1305.tag_len()];
    let written = ChaCha20Poly1305
        .seal(&key, &nonce, &aad, &pt, &mut ct_out)
        .expect("RFC 8439 A.5 seal failed");
    assert_eq!(
        to_hex(&ct_out[..pt.len()]),
        expected_ct,
        "RFC 8439 A.5 ciphertext mismatch"
    );
    assert_eq!(
        to_hex(&ct_out[pt.len()..written]),
        expected_tag,
        "RFC 8439 A.5 tag mismatch"
    );
}

/// Tampered tag must be rejected.
#[test]
fn chacha20poly1305_rejects_tampered_tag() {
    let key = [0xabu8; 32];
    let nonce = [0x01u8; 12];
    let pt = b"authenticated plaintext";

    let mut ct = vec![0u8; pt.len() + 16];
    let written = ChaCha20Poly1305
        .seal(&key, &nonce, &[], pt, &mut ct)
        .expect("seal");

    // Tamper the last byte of the tag.
    ct[written - 1] ^= 0xff;

    let mut pt_out = vec![0u8; pt.len()];
    let result = ChaCha20Poly1305.open(&key, &nonce, &[], &ct[..written], &mut pt_out);
    assert!(result.is_err(), "tampered tag must be rejected");
}

/// Different nonces must produce different ciphertexts.
#[test]
fn chacha20poly1305_nonce_sensitivity() {
    let key = [0x42u8; 32];
    let pt = b"same plaintext";

    let mut ct1 = vec![0u8; pt.len() + 16];
    let mut ct2 = vec![0u8; pt.len() + 16];

    ChaCha20Poly1305
        .seal(&key, &[0u8; 12], &[], pt, &mut ct1)
        .expect("seal1");
    ChaCha20Poly1305
        .seal(&key, &[1u8; 12], &[], pt, &mut ct2)
        .expect("seal2");

    assert_ne!(
        ct1, ct2,
        "Different nonces must produce different ciphertexts"
    );
}

/// AAD mismatch must fail decryption.
#[test]
fn chacha20poly1305_aad_mismatch_rejected() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let pt = b"data";

    let mut ct = vec![0u8; pt.len() + 16];
    let written = ChaCha20Poly1305
        .seal(&key, &nonce, b"correct-aad", pt, &mut ct)
        .expect("seal");

    let mut pt_out = vec![0u8; pt.len()];
    let result = ChaCha20Poly1305.open(&key, &nonce, b"wrong-aad", &ct[..written], &mut pt_out);
    assert!(result.is_err(), "wrong AAD must cause decryption failure");
}
