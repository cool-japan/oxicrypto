//! Ed25519 low-order public key rejection tests.
//!
//! Ed25519 over edwards25519 has a cofactor of 8. The 8 low-order group
//! elements (points of order 1, 2, 4, 8 in the torsion subgroup) are
//! well-known and any Ed25519 implementation SHOULD reject them as
//! public keys to prevent small-subgroup / cofactor attacks.
//!
//! The 8 low-order points in compressed Edwards-y form are listed below.
//! Source: RFC 8032 §5.1, IETF guidance, and `ed25519-dalek` test suite.
//!
//! When used as a public key for verification the dalek library should
//! either reject them at construction time or at verification time.
//! This test suite asserts that `verify()` does NOT succeed (returns Err)
//! when the public key is one of these low-order points, preventing an
//! attacker from forging signatures against such keys.

use oxicrypto_core::Verifier;
use oxicrypto_sig::Ed25519Verifier;

/// The 8 known low-order points of edwards25519 in compressed form
/// (32 bytes, little-endian Edwards-y with sign bit).
///
/// These are the elements of the 8-torsion subgroup of edwards25519.
/// Reference: https://github.com/golang/crypto/blob/master/ed25519/ed25519_test.go
/// and https://hyperelliptic.org/EFD/g1p/auto-edwards.html
const LOW_ORDER_POINTS: [[u8; 32]; 8] = [
    // Order 1: identity / neutral point (0, 1)
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // Order 2: (0, -1)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // Order 4: (sqrt(-1), 0) — two variants (sign bit 0 and 1)
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x80,
    ],
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // Order 8: 4 more torsion points
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x85,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0xfa,
    ],
];

/// A 64-byte all-zero "signature" used to probe verification against low-order keys.
/// Any implementation that doesn't reject low-order points at parse time will try
/// to verify this against the key; it should always fail the scalar equation.
const DUMMY_SIG: [u8; 64] = [0u8; 64];

/// A valid-looking 64-byte signature (first byte non-zero to avoid trivial rejection).
const NONZERO_SIG: [u8; 64] = {
    let mut s = [0u8; 64];
    s[0] = 1;
    s
};

/// Assert that verify returns Err for every low-order Ed25519 public key.
///
/// The test uses a fixed message and dummy signatures. We don't expect a
/// signature to be valid — we expect `verify` to return an error either because
/// the public key is rejected at construction or because verification fails.
#[test]
fn ed25519_low_order_points_rejected() {
    let verifier = Ed25519Verifier;
    let msg = b"low-order point rejection test";

    for (i, pk_bytes) in LOW_ORDER_POINTS.iter().enumerate() {
        // A valid signature over `msg` doesn't exist for these keys (and even if
        // one could be constructed, it would require the secret key). We just
        // assert that `verify` does NOT return Ok(()) for the dummy signatures —
        // either key parsing fails or signature verification fails.
        let result_zero = verifier.verify(pk_bytes, msg, &DUMMY_SIG);
        let result_nonzero = verifier.verify(pk_bytes, msg, &NONZERO_SIG);

        assert!(
            result_zero.is_err() || result_nonzero.is_err(),
            "Low-order point #{i} must not produce a valid verification result"
        );

        // More strongly: neither should succeed
        assert!(
            result_zero.is_err(),
            "Low-order point #{i}: zero-sig verify must fail"
        );
        assert!(
            result_nonzero.is_err(),
            "Low-order point #{i}: nonzero-sig verify must fail"
        );
    }
}
