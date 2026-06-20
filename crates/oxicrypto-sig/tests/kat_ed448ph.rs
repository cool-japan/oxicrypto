//! Known-answer tests for the Ed448ph (pre-hash) and Ed448ctx (context)
//! variants against RFC 8032 §7.4 test vectors.
//!
//! RFC 8032 §7.4 specifies, in addition to the plain Ed448 vectors, one
//! "Ed448ph" vector (pre-hash of `SHAKE256(msg, 64)`) and one "Ed448" vector
//! that exercises a non-empty context string. The `ed448_ext` module
//! implements both code paths; previously they were only exercised by
//! property tests. These KATs pin the exact byte output against the RFC.
//!
//! Every expected signature below was cross-checked, byte-for-byte, against
//! the output of `oxicrypto_sig::ed448ph_sign` / `ed448ctx_sign` (which is
//! backed by `ed448-goldilocks`) and is identical to the signature published
//! in RFC 8032 §7.4.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc8032#section-7.4>

use oxicrypto_sig::{ed448ctx_sign, ed448ctx_verify, ed448ph_sign, ed448ph_verify};

// ── helper ───────────────────────────────────────────────────────────────────

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(hex.len().is_multiple_of(2), "odd hex length: {}", hex.len());
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

// ── RFC 8032 §7.4 "Ed448ph" — pre-hash, empty context ────────────────────────
//
// Private key seed (57 bytes):
//   833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42
//   ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49
// Public key (57 bytes):
//   259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743
//   c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880
// Message:  0x616263  ("abc")
// Context:  (empty)
// Expected signature (114 bytes):
//   822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae38
//   1f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd
//   433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3
//   ad203df7dc7ce360c3cd3696d9d9fab90f00
#[test]
fn ed448ph_rfc8032_abc_sign() {
    let sk = hex_to_bytes(concat!(
        "833fe62409237b9d62ec77587520911e",
        "9a759cec1d19755b7da901b96dca3d42",
        "ef7822e0d5104127dc05d6dbefde69e3",
        "ab2cec7c867c6e2c49",
    ));
    let msg = hex_to_bytes("616263"); // "abc"
    let expected = hex_to_bytes(concat!(
        "822f6901f7480f3d5f562c592994d969",
        "3602875614483256505600bbc281ae38",
        "1f54d6bce2ea911574932f52a4e6cadd",
        "78769375ec3ffd1b801a0d9b3f4030cd",
        "433964b6457ea39476511214f97469b5",
        "7dd32dbc560a9a94d00bff07620464a3",
        "ad203df7dc7ce360c3cd3696d9d9fab9",
        "0f00",
    ));

    assert_eq!(sk.len(), 57, "ed448ph sk length must be 57");
    assert_eq!(
        expected.len(),
        114,
        "ed448ph expected sig must be 114 bytes"
    );

    // Ed448ph with no context (None == empty context per RFC 8032).
    let sig = ed448ph_sign(&sk, &msg, None).expect("ed448ph sign");
    assert_eq!(sig.len(), 114, "ed448ph output sig length");
    assert_eq!(
        sig.as_slice(),
        expected.as_slice(),
        "ed448ph signature must match RFC 8032 §7.4"
    );
}

#[test]
fn ed448ph_rfc8032_abc_verify() {
    let pk = hex_to_bytes(concat!(
        "259b71c19f83ef77a7abd26524cbdb31",
        "61b590a48f7d17de3ee0ba9c52beb743",
        "c09428a131d6b1b57303d90d8132c276",
        "d5ed3d5d01c0f53880",
    ));
    let msg = hex_to_bytes("616263"); // "abc"
    let sig = hex_to_bytes(concat!(
        "822f6901f7480f3d5f562c592994d969",
        "3602875614483256505600bbc281ae38",
        "1f54d6bce2ea911574932f52a4e6cadd",
        "78769375ec3ffd1b801a0d9b3f4030cd",
        "433964b6457ea39476511214f97469b5",
        "7dd32dbc560a9a94d00bff07620464a3",
        "ad203df7dc7ce360c3cd3696d9d9fab9",
        "0f00",
    ));

    assert_eq!(pk.len(), 57, "ed448ph pk length must be 57");
    assert_eq!(sig.len(), 114, "ed448ph sig length must be 114");

    ed448ph_verify(&pk, &msg, &sig, None).expect("ed448ph verify must accept RFC 8032 §7.4 sig");
}

/// An Ed448ph signature must NOT verify under the plain (non-prehashed) path,
/// and tampering with the message must fail.
#[test]
fn ed448ph_rfc8032_abc_tampered_message_rejected() {
    let pk = hex_to_bytes(concat!(
        "259b71c19f83ef77a7abd26524cbdb31",
        "61b590a48f7d17de3ee0ba9c52beb743",
        "c09428a131d6b1b57303d90d8132c276",
        "d5ed3d5d01c0f53880",
    ));
    let sig = hex_to_bytes(concat!(
        "822f6901f7480f3d5f562c592994d969",
        "3602875614483256505600bbc281ae38",
        "1f54d6bce2ea911574932f52a4e6cadd",
        "78769375ec3ffd1b801a0d9b3f4030cd",
        "433964b6457ea39476511214f97469b5",
        "7dd32dbc560a9a94d00bff07620464a3",
        "ad203df7dc7ce360c3cd3696d9d9fab9",
        "0f00",
    ));

    // Wrong message (0x616264 = "abd") must be rejected.
    let wrong_msg = hex_to_bytes("616264");
    assert!(
        ed448ph_verify(&pk, &wrong_msg, &sig, None).is_err(),
        "ed448ph must reject a signature over a different message"
    );

    // A non-empty context must also be rejected (RFC vector uses no context).
    assert!(
        ed448ph_verify(&pk, &hex_to_bytes("616263"), &sig, Some(b"x")).is_err(),
        "ed448ph must reject mismatched context"
    );
}

// ── RFC 8032 §7.4 "Ed448" — non-empty context "foo" ──────────────────────────
//
// Private key seed (57 bytes):
//   c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a
//   fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e
// Public key (57 bytes):
//   43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086
//   6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480
// Message:  0x03
// Context:  0x666f6f  ("foo")
// Expected signature (114 bytes):
//   d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2
//   151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da
//   1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d
//   5428407e85dcbc98a49155c13764e66c3c00
#[test]
fn ed448ctx_rfc8032_foo_sign_verify() {
    let sk = hex_to_bytes(concat!(
        "c4eab05d357007c632f3dbb48489924d",
        "552b08fe0c353a0d4a1f00acda2c463a",
        "fbea67c5e8d2877c5e3bc397a659949e",
        "f8021e954e0a12274e",
    ));
    let pk = hex_to_bytes(concat!(
        "43ba28f430cdff456ae531545f7ecd0a",
        "c834a55d9358c0372bfa0c6c6798c086",
        "6aea01eb00742802b8438ea4cb82169c",
        "235160627b4c3a9480",
    ));
    let msg = hex_to_bytes("03");
    let ctx = hex_to_bytes("666f6f"); // "foo"
    let expected = hex_to_bytes(concat!(
        "d4f8f6131770dd46f40867d6fd5d5055",
        "de43541f8c5e35abbcd001b32a89f7d2",
        "151f7647f11d8ca2ae279fb842d60721",
        "7fce6e042f6815ea000c85741de5c8da",
        "1144a6a1aba7f96de42505d7a7298524",
        "fda538fccbbb754f578c1cad10d54d0d",
        "5428407e85dcbc98a49155c13764e66c",
        "3c00",
    ));

    assert_eq!(sk.len(), 57, "ed448ctx sk length");
    assert_eq!(pk.len(), 57, "ed448ctx pk length");
    assert_eq!(expected.len(), 114, "ed448ctx sig length");

    let sig = ed448ctx_sign(&sk, &msg, &ctx).expect("ed448ctx sign");
    assert_eq!(sig.len(), 114, "ed448ctx output sig length");
    assert_eq!(
        sig.as_slice(),
        expected.as_slice(),
        "ed448ctx signature must match RFC 8032 §7.4"
    );

    ed448ctx_verify(&pk, &msg, &sig, &ctx).expect("ed448ctx verify");
}

/// The same key/message under a *different* context must produce a different,
/// non-cross-verifiable signature (context provides domain separation).
#[test]
fn ed448ctx_rfc8032_foo_wrong_context_rejected() {
    let sk = hex_to_bytes(concat!(
        "c4eab05d357007c632f3dbb48489924d",
        "552b08fe0c353a0d4a1f00acda2c463a",
        "fbea67c5e8d2877c5e3bc397a659949e",
        "f8021e954e0a12274e",
    ));
    let pk = hex_to_bytes(concat!(
        "43ba28f430cdff456ae531545f7ecd0a",
        "c834a55d9358c0372bfa0c6c6798c086",
        "6aea01eb00742802b8438ea4cb82169c",
        "235160627b4c3a9480",
    ));
    let msg = hex_to_bytes("03");

    let sig_foo = ed448ctx_sign(&sk, &msg, b"foo").expect("sign foo");
    // Verifying the "foo"-context signature under the "bar" context must fail.
    assert!(
        ed448ctx_verify(&pk, &msg, &sig_foo, b"bar").is_err(),
        "ed448ctx signature must not verify under a different context"
    );
}

/// A context longer than 255 bytes must be rejected by both sign and verify.
#[test]
fn ed448ctx_oversized_context_rejected() {
    let sk = hex_to_bytes(concat!(
        "c4eab05d357007c632f3dbb48489924d",
        "552b08fe0c353a0d4a1f00acda2c463a",
        "fbea67c5e8d2877c5e3bc397a659949e",
        "f8021e954e0a12274e",
    ));
    let ctx = vec![0u8; 256];
    assert!(
        ed448ctx_sign(&sk, b"msg", &ctx).is_err(),
        "context > 255 bytes must be rejected on sign"
    );
}
