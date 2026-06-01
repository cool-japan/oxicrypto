//! Known-answer tests for Ed448 against RFC 8032 §7.4 test vectors.
//!
//! RFC 8032 Section 7.4 specifies six test vectors for Ed448.
//! Test vector 1 (empty message, empty context) and test vector 2
//! (1-byte message, empty context) are included here with exact expected
//! signature bytes from the RFC, verified against ed448-goldilocks
//! 0.14.0-pre.12.
//!
//! Note: The oxicrypto-sig Ed448 wrapper uses the default (no context,
//! no pre-hash) signing mode matching RFC 8032 §5.2.6 "Ed448".
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc8032#section-7.4>

use oxicrypto_core::{Signer, Verifier};
use oxicrypto_sig::{Ed448, Ed448SigningKey, Ed448Verify, Ed448VerifyingKey};

// ── helper ───────────────────────────────────────────────────────────────────

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(hex.len().is_multiple_of(2), "odd hex length: {}", hex.len());
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

// ── RFC 8032 §7.4 Test Vector 1 — empty message ──────────────────────────────
//
// Private key seed (57 bytes):
//   6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3
//   528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b
// Public key (57 bytes):
//   5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778
//   edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180
// Message: (empty), Context: (empty)
// Expected signature (114 bytes):
//   533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f
//   2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a
//   9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db
//   b61149f05a7363268c71d95808ff2e652600
//
// Source: RFC 8032 §7.4 (also verified in ed448-goldilocks source)
#[test]
fn ed448_rfc8032_tv1_sign() {
    let sk_hex = concat!(
        "6c82a562cb808d10d632be89c8513ebf",
        "6c929f34ddfa8c9f63c9960ef6e348a3",
        "528c8a3fcc2f044e39a3fc5b94492f8f",
        "032e7549a20098f95b",
    );
    let expected_sig_hex = concat!(
        "533a37f6bbe457251f023c0d88f976ae",
        "2dfb504a843e34d2074fd823d41a591f",
        "2b233f034f628281f2fd7a22ddd47d78",
        "28c59bd0a21bfd3980ff0d2028d4b18a",
        "9df63e006c5d1c2d345b925d8dc00b41",
        "04852db99ac5c7cdda8530a113a0f4db",
        "b61149f05a7363268c71d95808ff2e65",
        "2600",
    );

    let sk_bytes = hex_to_bytes(sk_hex);
    let expected_sig = hex_to_bytes(expected_sig_hex);

    assert_eq!(sk_bytes.len(), 57, "tv1 sk length must be 57");
    assert_eq!(
        expected_sig.len(),
        114,
        "tv1 expected sig must be 114 bytes"
    );

    let signing_key = Ed448SigningKey::from_bytes(&sk_bytes).expect("tv1 from_bytes");
    let sig_bytes = signing_key.sign(b"").expect("tv1 sign");

    assert_eq!(sig_bytes.len(), 114, "tv1 output sig length");
    assert_eq!(
        sig_bytes.as_slice(),
        expected_sig.as_slice(),
        "tv1 signature mismatch"
    );
}

#[test]
fn ed448_rfc8032_tv1_verify() {
    let pk_hex = concat!(
        "5fd7449b59b461fd2ce787ec616ad46a",
        "1da1342485a70e1f8a0ea75d80e96778",
        "edf124769b46c7061bd6783df1e50f6c",
        "d1fa1abeafe8256180",
    );
    let sig_hex = concat!(
        "533a37f6bbe457251f023c0d88f976ae",
        "2dfb504a843e34d2074fd823d41a591f",
        "2b233f034f628281f2fd7a22ddd47d78",
        "28c59bd0a21bfd3980ff0d2028d4b18a",
        "9df63e006c5d1c2d345b925d8dc00b41",
        "04852db99ac5c7cdda8530a113a0f4db",
        "b61149f05a7363268c71d95808ff2e65",
        "2600",
    );

    let pk_bytes = hex_to_bytes(pk_hex);
    let sig_bytes = hex_to_bytes(sig_hex);

    assert_eq!(pk_bytes.len(), 57, "tv1 pk length must be 57");
    assert_eq!(sig_bytes.len(), 114, "tv1 sig length must be 114");

    let verifying_key = Ed448VerifyingKey::from_bytes(&pk_bytes).expect("tv1 vk from_bytes");
    verifying_key
        .verify(b"", &sig_bytes)
        .expect("tv1 verify failed");
}

// ── RFC 8032 §7.4 Test Vector 2 — 1-byte message, empty context ──────────────
//
// Private key seed (57 bytes):
//   c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a
//   fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e
// Public key (57 bytes):
//   43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086
//   6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480
// Message: 0x03, Context: (empty)
// Expected signature (114 bytes): 26b8f91727bd62897af15e41eb43c377...
#[test]
fn ed448_rfc8032_tv2_sign_verify() {
    let sk_hex = concat!(
        "c4eab05d357007c632f3dbb48489924d",
        "552b08fe0c353a0d4a1f00acda2c463a",
        "fbea67c5e8d2877c5e3bc397a659949e",
        "f8021e954e0a12274e",
    );
    let pk_hex = concat!(
        "43ba28f430cdff456ae531545f7ecd0a",
        "c834a55d9358c0372bfa0c6c6798c086",
        "6aea01eb00742802b8438ea4cb82169c",
        "235160627b4c3a9480",
    );
    let expected_sig_hex = concat!(
        "26b8f91727bd62897af15e41eb43c377",
        "efb9c610d48f2335cb0bd0087810f435",
        "2541b143c4b981b7e18f62de8ccdf633",
        "fc1bf037ab7cd779805e0dbcc0aae1cb",
        "cee1afb2e027df36bc04dcecbf154336",
        "c19f0af7e0a6472905e799f1953d2a0f",
        "f3348ab21aa4adafd1d234441cf807c0",
        "3a00",
    );

    let sk_bytes = hex_to_bytes(sk_hex);
    let pk_bytes = hex_to_bytes(pk_hex);
    let expected_sig = hex_to_bytes(expected_sig_hex);

    assert_eq!(sk_bytes.len(), 57, "tv2 sk length");
    assert_eq!(pk_bytes.len(), 57, "tv2 pk length");
    assert_eq!(expected_sig.len(), 114, "tv2 sig length");

    let msg = [0x03u8];

    let signing_key = Ed448SigningKey::from_bytes(&sk_bytes).expect("tv2 from_bytes");
    let verifying_key = Ed448VerifyingKey::from_bytes(&pk_bytes).expect("tv2 vk from_bytes");

    let sig_bytes = signing_key.sign(&msg).expect("tv2 sign");
    assert_eq!(sig_bytes.len(), 114, "tv2 output sig length");
    assert_eq!(
        sig_bytes.as_slice(),
        expected_sig.as_slice(),
        "tv2 signature mismatch"
    );

    verifying_key.verify(&msg, &sig_bytes).expect("tv2 verify");
}

// ── Trait-dispatched wrappers ─────────────────────────────────────────────────

/// Test the `Ed448` / `Ed448Verify` trait-dispatched unit structs.
#[test]
fn ed448_trait_dispatch_sign_verify() {
    let signer = Ed448;
    let verifier = Ed448Verify;

    // Use RFC 8032 §7.4 TV1 key pair
    let sk_hex = concat!(
        "6c82a562cb808d10d632be89c8513ebf",
        "6c929f34ddfa8c9f63c9960ef6e348a3",
        "528c8a3fcc2f044e39a3fc5b94492f8f",
        "032e7549a20098f95b",
    );
    let pk_hex = concat!(
        "5fd7449b59b461fd2ce787ec616ad46a",
        "1da1342485a70e1f8a0ea75d80e96778",
        "edf124769b46c7061bd6783df1e50f6c",
        "d1fa1abeafe8256180",
    );

    let sk_bytes = hex_to_bytes(sk_hex);
    let pk_bytes = hex_to_bytes(pk_hex);
    let msg = b"trait dispatch round-trip test";

    let mut sig_out = [0u8; 114];
    let len = signer
        .sign(&sk_bytes, msg, &mut sig_out)
        .expect("trait dispatch sign failed");
    assert_eq!(len, 114);

    verifier
        .verify(&pk_bytes, msg, &sig_out)
        .expect("trait dispatch verify failed");
}

// ── Negative tests ────────────────────────────────────────────────────────────

/// Tampering with the signature must cause verify to fail.
#[test]
fn ed448_tampered_sig_rejected() {
    let sk_hex = concat!(
        "6c82a562cb808d10d632be89c8513ebf",
        "6c929f34ddfa8c9f63c9960ef6e348a3",
        "528c8a3fcc2f044e39a3fc5b94492f8f",
        "032e7549a20098f95b",
    );
    let pk_hex = concat!(
        "5fd7449b59b461fd2ce787ec616ad46a",
        "1da1342485a70e1f8a0ea75d80e96778",
        "edf124769b46c7061bd6783df1e50f6c",
        "d1fa1abeafe8256180",
    );

    let sk_bytes = hex_to_bytes(sk_hex);
    let pk_bytes = hex_to_bytes(pk_hex);
    let signing_key = Ed448SigningKey::from_bytes(&sk_bytes).expect("from_bytes");
    let verifying_key = Ed448VerifyingKey::from_bytes(&pk_bytes).expect("vk from_bytes");

    let mut sig_bytes = signing_key.sign(b"tamper test").expect("sign");
    assert_eq!(sig_bytes.len(), 114);

    // Corrupt the middle of the signature
    sig_bytes[57] ^= 0xff;

    let result = verifying_key.verify(b"tamper test", &sig_bytes);
    assert!(result.is_err(), "tampered sig should fail");
}

/// Using the wrong public key must cause verify to fail.
#[test]
fn ed448_wrong_pk_rejected() {
    // TV1 signing key
    let sk1_hex = concat!(
        "6c82a562cb808d10d632be89c8513ebf",
        "6c929f34ddfa8c9f63c9960ef6e348a3",
        "528c8a3fcc2f044e39a3fc5b94492f8f",
        "032e7549a20098f95b",
    );
    // TV2 public key (different key pair)
    let pk2_hex = concat!(
        "43ba28f430cdff456ae531545f7ecd0a",
        "c834a55d9358c0372bfa0c6c6798c086",
        "6aea01eb00742802b8438ea4cb82169c",
        "235160627b4c3a9480",
    );

    let sk1_bytes = hex_to_bytes(sk1_hex);
    let pk2_bytes = hex_to_bytes(pk2_hex);

    let signing_key1 = Ed448SigningKey::from_bytes(&sk1_bytes).expect("sk1");
    let verifying_key2 = Ed448VerifyingKey::from_bytes(&pk2_bytes).expect("vk2");

    let sig = signing_key1.sign(b"cross-key test").expect("sign");
    let result = verifying_key2.verify(b"cross-key test", &sig);
    assert!(result.is_err(), "wrong key verify should fail");
}

/// Invalid key length must return an error.
#[test]
fn ed448_invalid_sk_length_rejected() {
    // 56 bytes instead of 57
    let result = Ed448SigningKey::from_bytes(&[0u8; 56]);
    assert!(result.is_err(), "short sk should be rejected");
}
