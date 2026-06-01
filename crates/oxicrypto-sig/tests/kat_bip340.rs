//! Known-answer tests for BIP-340 Schnorr signatures over secp256k1.
//!
//! Transcribes the official BIP-340 `test-vectors.csv` (indices 0–18, the
//! canonical set including valid signatures, `lift_x` / even-`Y` edge cases,
//! public-key-not-on-curve rejection, and `R`/`s` malleability/invalid-encoding
//! rejections). Each vector is exercised as follows:
//!
//! * **Verification** — every vector runs through [`SchnorrBip340::verify_message`]
//!   and the result is asserted against the CSV `verification result` column
//!   (`TRUE` ⇒ `Ok(())`, `FALSE` ⇒ `Err(..)`).
//! * **Signing** — vectors that carry a secret key additionally sign the message
//!   with the CSV `aux_rand` via [`SchnorrBip340::sign_with_aux`] and assert the
//!   produced 64-byte signature equals the CSV `signature` byte-for-byte, that
//!   the derived x-only public key equals the CSV `public key`, and that the
//!   freshly produced signature verifies.
//!
//! Plus: sign→verify round-trip, wrong-key negative, tampered-signature
//! negative, x-only public-key parse round-trip, and the SHA-256 pre-hash
//! convenience round-trip.
//!
//! Reference: <https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv>

use oxicrypto_core::{Signer, Verifier};
use oxicrypto_sig::SchnorrBip340;

// ── helpers ────────────────────────────────────────────────────────────────

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(hex.len().is_multiple_of(2), "odd hex length: {}", hex.len());
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

fn hex_to_aux32(hex: &str) -> [u8; 32] {
    let bytes = hex_to_bytes(hex);
    assert_eq!(bytes.len(), 32, "aux_rand must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// One row of the official BIP-340 `test-vectors.csv`.
struct Vector {
    index: u32,
    /// Secret key hex (32 bytes) or empty if the vector provides only a sig.
    secret_key: &'static str,
    /// 32-byte x-only public key hex.
    public_key: &'static str,
    /// 32-byte auxiliary randomness hex (only meaningful when `secret_key` set).
    aux_rand: &'static str,
    /// Message hex (may be empty / arbitrary length).
    message: &'static str,
    /// 64-byte signature hex.
    signature: &'static str,
    /// Expected verification result.
    valid: bool,
    /// Free-text comment from the CSV.
    comment: &'static str,
}

/// The canonical BIP-340 vectors, indices 0–18, verbatim from the upstream CSV.
const VECTORS: &[Vector] = &[
    Vector {
        index: 0,
        secret_key: "0000000000000000000000000000000000000000000000000000000000000003",
        public_key: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        aux_rand: "0000000000000000000000000000000000000000000000000000000000000000",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        valid: true,
        comment: "",
    },
    Vector {
        index: 1,
        secret_key: "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        aux_rand: "0000000000000000000000000000000000000000000000000000000000000001",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
        valid: true,
        comment: "",
    },
    Vector {
        index: 2,
        secret_key: "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
        public_key: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        aux_rand: "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
        message: "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
        signature: "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
        valid: true,
        comment: "",
    },
    Vector {
        index: 3,
        secret_key: "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
        public_key: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
        aux_rand: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        message: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        signature: "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
        valid: true,
        comment: "test fails if msg is reduced modulo p or n",
    },
    Vector {
        index: 4,
        secret_key: "",
        public_key: "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
        aux_rand: "",
        message: "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
        signature: "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
        valid: true,
        comment: "",
    },
    Vector {
        index: 5,
        secret_key: "",
        public_key: "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
        aux_rand: "",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        valid: false,
        comment: "public key not on the curve",
    },
    Vector {
        index: 6,
        secret_key: "",
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        aux_rand: "",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
        valid: false,
        comment: "has_even_y(R) is false",
    },
    Vector {
        index: 7,
        secret_key: "",
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        aux_rand: "",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
        valid: false,
        comment: "negated message",
    },
    Vector {
        index: 8,
        secret_key: "",
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        aux_rand: "",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
        valid: false,
        comment: "negated s value",
    },
    Vector {
        index: 9,
        secret_key: "",
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        aux_rand: "",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
        valid: false,
        comment: "sG - eP is infinite; has_even_y(inf) test",
    },
    Vector {
        index: 10,
        secret_key: "",
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        aux_rand: "",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
        valid: false,
        comment: "sG - eP is infinite; x(inf) as 1 test",
    },
    Vector {
        index: 11,
        secret_key: "",
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        aux_rand: "",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        valid: false,
        comment: "sig[0:32] is not an X coordinate on the curve",
    },
    Vector {
        index: 12,
        secret_key: "",
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        aux_rand: "",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        valid: false,
        comment: "sig[0:32] is equal to field size",
    },
    Vector {
        index: 13,
        secret_key: "",
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        aux_rand: "",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        valid: false,
        comment: "sig[32:64] is equal to curve order",
    },
    Vector {
        index: 14,
        secret_key: "",
        public_key: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        aux_rand: "",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        valid: false,
        comment: "public key is not a valid X coordinate because it exceeds the field size",
    },
    Vector {
        index: 15,
        secret_key: "0340034003400340034003400340034003400340034003400340034003400340",
        public_key: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
        aux_rand: "0000000000000000000000000000000000000000000000000000000000000000",
        message: "",
        signature: "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63",
        valid: true,
        comment: "message of size 0",
    },
    Vector {
        index: 16,
        secret_key: "0340034003400340034003400340034003400340034003400340034003400340",
        public_key: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
        aux_rand: "0000000000000000000000000000000000000000000000000000000000000000",
        message: "11",
        signature: "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF",
        valid: true,
        comment: "message of size 1",
    },
    Vector {
        index: 17,
        secret_key: "0340034003400340034003400340034003400340034003400340034003400340",
        public_key: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
        aux_rand: "0000000000000000000000000000000000000000000000000000000000000000",
        message: "0102030405060708090A0B0C0D0E0F1011",
        signature: "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5",
        valid: true,
        comment: "message of size 17",
    },
    Vector {
        index: 18,
        secret_key: "0340034003400340034003400340034003400340034003400340034003400340",
        public_key: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
        aux_rand: "0000000000000000000000000000000000000000000000000000000000000000",
        message: "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
        signature: "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367",
        valid: true,
        comment: "message of size 100",
    },
];

#[test]
fn bip340_official_vectors_verify() {
    let scheme = SchnorrBip340;
    for v in VECTORS {
        let pk = hex_to_bytes(v.public_key);
        let msg = hex_to_bytes(v.message);
        let sig = hex_to_bytes(v.signature);

        let result = scheme.verify_message(&pk, &msg, &sig);
        if v.valid {
            assert!(
                result.is_ok(),
                "vector {} ({}) expected VALID but verification failed: {result:?}",
                v.index,
                v.comment
            );
        } else {
            assert!(
                result.is_err(),
                "vector {} ({}) expected INVALID but verification accepted",
                v.index,
                v.comment
            );
        }

        // The trait-dispatched `verify` must agree with `verify_message`.
        let trait_result = Verifier::verify(&scheme, &pk, &msg, &sig);
        assert_eq!(
            trait_result.is_ok(),
            v.valid,
            "vector {} ({}) trait verify disagreed with expected",
            v.index,
            v.comment
        );
    }
}

#[test]
fn bip340_official_vectors_sign() {
    let scheme = SchnorrBip340;
    for v in VECTORS {
        if v.secret_key.is_empty() {
            continue;
        }
        let sk = hex_to_bytes(v.secret_key);
        let aux = hex_to_aux32(v.aux_rand);
        let msg = hex_to_bytes(v.message);
        let expected_sig = hex_to_bytes(v.signature);
        let expected_pk = hex_to_bytes(v.public_key);

        // Derived x-only public key must match the CSV public key.
        let derived_pk = scheme
            .derive_public_key(&sk)
            .expect("derive x-only public key from secret");
        assert_eq!(
            &derived_pk[..],
            &expected_pk[..],
            "vector {} derived public key mismatch",
            v.index
        );

        // Signing with the CSV aux_rand must reproduce the exact signature.
        let produced = scheme
            .sign_with_aux(&sk, &msg, &aux)
            .expect("sign_with_aux");
        assert_eq!(
            &produced[..],
            &expected_sig[..],
            "vector {} signature mismatch",
            v.index
        );

        // The freshly produced signature must verify against the public key.
        scheme
            .verify_message(&expected_pk, &msg, &produced)
            .unwrap_or_else(|e| {
                panic!("vector {} fresh signature failed to verify: {e:?}", v.index)
            });
    }
}

#[test]
fn bip340_sign_verify_round_trip() {
    let scheme = SchnorrBip340;
    let sk = hex_to_bytes("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
    let pk = scheme.derive_public_key(&sk).expect("derive pk");

    let msg = b"oxicrypto schnorr round trip 32B"; // 32 bytes
    let mut sig = [0u8; 64];
    let n = Signer::sign(&scheme, &sk, msg, &mut sig).expect("sign");
    assert_eq!(n, 64);
    scheme
        .verify(&pk, msg, &sig)
        .expect("verify should succeed");
}

#[test]
fn bip340_sign_verify_arbitrary_length_round_trip() {
    let scheme = SchnorrBip340;
    let sk = hex_to_bytes("0340034003400340034003400340034003400340034003400340034003400340");
    let pk = scheme.derive_public_key(&sk).expect("derive pk");

    for len in [0usize, 1, 17, 33, 100, 255] {
        let msg = vec![0xABu8; len];
        let mut sig = [0u8; 64];
        Signer::sign(&scheme, &sk, &msg, &mut sig).expect("sign");
        scheme
            .verify(&pk, &msg, &sig)
            .unwrap_or_else(|e| panic!("verify failed for msg len {len}: {e:?}"));
    }
}

#[test]
fn bip340_wrong_key_rejected() {
    let scheme = SchnorrBip340;
    let sk = hex_to_bytes("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
    let other_pk = scheme
        .derive_public_key(&hex_to_bytes(
            "0340034003400340034003400340034003400340034003400340034003400340",
        ))
        .expect("derive other pk");

    let msg = b"message signed with sk #1 only!!";
    let mut sig = [0u8; 64];
    Signer::sign(&scheme, &sk, msg, &mut sig).expect("sign");

    let result = scheme.verify(&other_pk, msg, &sig);
    assert_eq!(result, Err(oxicrypto_core::CryptoError::Sign));
}

#[test]
fn bip340_tampered_signature_rejected() {
    let scheme = SchnorrBip340;
    let sk = hex_to_bytes("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
    let pk = scheme.derive_public_key(&sk).expect("derive pk");

    let msg = b"tamper test message exactly 32by";
    let mut sig = [0u8; 64];
    Signer::sign(&scheme, &sk, msg, &mut sig).expect("sign");

    // Flip a bit in the s-half of the signature.
    sig[63] ^= 0x01;
    let result = scheme.verify(&pk, msg, &sig);
    assert!(result.is_err(), "tampered signature must be rejected");
}

#[test]
fn bip340_tampered_message_rejected() {
    let scheme = SchnorrBip340;
    let sk = hex_to_bytes("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
    let pk = scheme.derive_public_key(&sk).expect("derive pk");

    let msg = b"original message, 32 bytes long!";
    let mut sig = [0u8; 64];
    Signer::sign(&scheme, &sk, msg, &mut sig).expect("sign");

    let tampered = b"original message, 32 bytes XXXX!";
    let result = scheme.verify(&pk, tampered, &sig);
    assert!(
        result.is_err(),
        "signature over different message must fail"
    );
}

#[test]
fn bip340_xonly_pubkey_parse_round_trip() {
    // Valid x-only key from vector 1 must round-trip through parse_public_key.
    let pk = hex_to_bytes("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
    let parsed = SchnorrBip340::parse_public_key(&pk).expect("parse valid x-only key");
    assert_eq!(&parsed[..], &pk[..]);

    // Derived key round-trips too.
    let scheme = SchnorrBip340;
    let derived = scheme
        .derive_public_key(&hex_to_bytes(
            "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        ))
        .expect("derive");
    let reparsed = SchnorrBip340::parse_public_key(&derived).expect("reparse derived");
    assert_eq!(derived, reparsed);
}

#[test]
fn bip340_invalid_xonly_pubkey_rejected() {
    // Vector 5: public key not on the curve.
    let off_curve =
        hex_to_bytes("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34");
    assert!(
        SchnorrBip340::parse_public_key(&off_curve).is_err(),
        "off-curve x-only key must be rejected"
    );

    // Wrong length.
    assert!(
        SchnorrBip340::parse_public_key(&[0u8; 31]).is_err(),
        "31-byte key must be rejected"
    );
    assert!(
        SchnorrBip340::parse_public_key(&[0u8; 33]).is_err(),
        "33-byte key must be rejected"
    );
}

#[test]
fn bip340_invalid_secret_key_rejected() {
    let scheme = SchnorrBip340;
    // All-zero scalar is not a valid secp256k1 signing key.
    let result = scheme.derive_public_key(&[0u8; 32]);
    assert_eq!(result, Err(oxicrypto_core::CryptoError::InvalidKey));

    // Wrong length.
    let result = scheme.derive_public_key(&[0x01u8; 16]);
    assert_eq!(result, Err(oxicrypto_core::CryptoError::InvalidKey));
}

#[test]
fn bip340_malformed_signature_length_rejected() {
    let scheme = SchnorrBip340;
    let pk = hex_to_bytes("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
    let msg = hex_to_bytes("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");

    // 63-byte signature → InvalidTag.
    let result = scheme.verify_message(&pk, &msg, &[0u8; 63]);
    assert_eq!(result, Err(oxicrypto_core::CryptoError::InvalidTag));
}

#[test]
fn bip340_buffer_too_small_rejected() {
    let scheme = SchnorrBip340;
    let sk = hex_to_bytes("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
    let mut short = [0u8; 63];
    let result = Signer::sign(&scheme, &sk, b"msg", &mut short);
    assert_eq!(result, Err(oxicrypto_core::CryptoError::BufferTooSmall));
}

#[test]
fn bip340_sha256_prehash_convenience_round_trip() {
    let scheme = SchnorrBip340;
    let sk = hex_to_bytes("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
    let pk = scheme.derive_public_key(&sk).expect("derive pk");

    // Arbitrary-length application message.
    let app_msg = b"an arbitrary length application message of more than 32 bytes here";
    let sig = scheme.sign_sha256(&sk, app_msg).expect("sign_sha256");
    scheme
        .verify_sha256(&pk, app_msg, &sig)
        .expect("verify_sha256 round-trip");

    // The prehash signature must NOT verify against the raw message.
    assert!(
        scheme.verify_message(&pk, app_msg, &sig).is_err(),
        "prehash sig must not verify as a raw-message sig"
    );
}

#[test]
fn bip340_deterministic_zero_aux_is_stable() {
    // The trait `sign` (aux = 0) must be deterministic for a fixed (sk, msg).
    let scheme = SchnorrBip340;
    let sk = hex_to_bytes("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
    let msg = b"determinism check, exactly 32 by";

    let mut sig_a = [0u8; 64];
    let mut sig_b = [0u8; 64];
    Signer::sign(&scheme, &sk, msg, &mut sig_a).expect("sign a");
    Signer::sign(&scheme, &sk, msg, &mut sig_b).expect("sign b");
    assert_eq!(sig_a, sig_b, "zero-aux signing must be deterministic");
}
