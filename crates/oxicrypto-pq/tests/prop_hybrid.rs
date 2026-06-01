//! Hybrid KEM property tests.
//!
//! Invariants verified:
//! - X-Wing (ML-KEM-768 + X25519): encap → decap recovers the same shared secret.
//! - HybridKem1024P384: encap → decap recovers the same shared secret.

use oxicrypto_core::Kem;
use oxicrypto_pq::hybrid::{HybridKem1024P384, XWing768};

// ─────────────────────────────────────────────────────────────────────────────
//  X-Wing (ML-KEM-768 + X25519)
// ─────────────────────────────────────────────────────────────────────────────

/// Property: X-Wing encapsulate → decapsulate recovers the same shared secret.
#[test]
fn prop_xwing768_encap_decap_round_trip() {
    for _ in 0..3 {
        let (dk, ek) = XWing768::kem_generate().expect("XWing768 generate");
        let (ct, ss1) = XWing768::kem_encapsulate(&ek).expect("XWing768 encapsulate");
        let ss2 = XWing768::kem_decapsulate(&dk, &ct).expect("XWing768 decapsulate");
        assert_eq!(
            ss1.as_slice(),
            ss2.as_slice(),
            "X-Wing shared secrets must match"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Hybrid ML-KEM-1024 + P-384
// ─────────────────────────────────────────────────────────────────────────────

/// Property: HybridKem1024P384 encapsulate → decapsulate recovers the same shared secret.
#[test]
fn prop_hybrid_mlkem1024_p384_encap_decap_round_trip() {
    for _ in 0..3 {
        let (dk, ek) = HybridKem1024P384::kem_generate().expect("HybridKem1024P384 generate");
        let (ct, ss1) =
            HybridKem1024P384::kem_encapsulate(&ek).expect("HybridKem1024P384 encapsulate");
        let ss2 =
            HybridKem1024P384::kem_decapsulate(&dk, &ct).expect("HybridKem1024P384 decapsulate");
        assert_eq!(
            ss1.as_slice(),
            ss2.as_slice(),
            "HybridKem1024P384 shared secrets must match"
        );
    }
}
