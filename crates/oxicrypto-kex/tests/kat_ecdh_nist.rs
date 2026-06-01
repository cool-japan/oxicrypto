//! ECDH Known-Answer Tests for NIST P-256, P-384, P-521.
//!
//! These vectors were generated from the same RustCrypto `p256`, `p384`, and
//! `p521` crates used in production, with deterministic seeds via `ChaCha20Rng`.
//! They verify end-to-end correctness of the `EcdhP256`, `EcdhP384`, and
//! `EcdhP521` implementations against known-good outputs.
//!
//! Additionally, this file includes NIST SP 800-56A style self-consistency tests
//! (DH commutativity property) which are guaranteed by elliptic-curve mathematics
//! but confirm the implementation is correct.
//!
//! The SEC1 public key format used in the `agree()` API:
//!   - P-256: 0x04 prefix + 32-byte X + 32-byte Y = 65 bytes (uncompressed)
//!     OR 33-byte compressed SEC1. Our test vectors use compressed (crate default).
//!   - P-384: 0x04 prefix + 48-byte X + 48-byte Y = 97 bytes, or 49-byte compressed.
//!   - P-521: 0x04 prefix + 66-byte X + 66-byte Y = 133 bytes, or 67-byte compressed.

use oxicrypto_core::{CryptoError, KeyAgreement};
use oxicrypto_kex::{EcdhP256, EcdhP384, EcdhP521};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hex_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex string")
}

// ── P-256 KAT vectors ─────────────────────────────────────────────────────────
//
// Generated with ChaCha20Rng(seed=[0x11; 32]), calling ecdh_p256_generate_keypair
// twice per test case, then agree(a_sk, b_pk).
//
// Each vector: (d_iut, b_pk_sec1_compressed, z_shared_32)
// b_pk_sec1 is the SEC1-compressed public key (33 bytes, prefix 0x02 or 0x03)
// z is the 32-byte shared x-coordinate.

const P256_KAT: &[(&str, &str, &str)] = &[
    // vector 0
    (
        "e462b8c160b3ab527a8f4a8c5d9bc0da890f4ece9296664be99198aa592d220c",
        "0432c5e64d412d5a5e0172b953ac160852843a2394a242f8785dfef0eea7cf4f09875712841a4d3fae0ce755148c44a8ba4d138e6de4f3b0f03568e1f939c95b21",
        "eb3a91b0679c83d90bccad65bd09c12ee1c5e75184e98b30b2c61c668ba6a9fb",
    ),
    // vector 1
    (
        "bb12993166ca683bf00d390c063031a13e172fea024842c7599399799697bca5",
        "0415c919d61579997a676bde9753245d32b9372cb8e73376780e7b66873c83be91d8c2b32581f310f2a9dd74ae9ba5283b565961132e432ae18bbb7a6a25928a2a",
        "c415885f1dbffd3ab29fe98981d518715117dfa41f8f0891b7e92dbdfe91ec78",
    ),
    // vector 2
    (
        "a69ec59424a1903104527b20a5238405f0d422c05351fa89bc6fa3cccbac2896",
        "04646f1b3b99fac87de01c89276075ec9745490cf2fe4443819f8689403633370f8afb6a93601a4c7e3da77e5e5744353c6b84c4ebfa5a4bdc6584ea37650ab211",
        "8d05785b0c3a25359922031f7d4325f747d8d698ffea792b08fa9d80ec366eda",
    ),
];

/// ECDH P-256 known-answer test with deterministic vectors.
#[test]
fn ecdh_p256_kat_deterministic() {
    let kex = EcdhP256;
    for (i, (d_iut_hex, b_pk_hex, z_hex)) in P256_KAT.iter().enumerate() {
        let d_iut = hex_bytes(d_iut_hex);
        let b_pk = hex_bytes(b_pk_hex);
        let expected_z: [u8; 32] = {
            let v = hex_bytes(z_hex);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            arr
        };

        let mut shared = [0u8; 32];
        kex.agree(&d_iut, &b_pk, &mut shared)
            .unwrap_or_else(|e| panic!("P-256 KAT vector {i} failed: {e:?}"));

        assert_eq!(
            shared, expected_z,
            "P-256 KAT vector {i}: shared secret mismatch"
        );
    }
}

// ── P-384 KAT vectors ─────────────────────────────────────────────────────────
//
// Generated with ChaCha20Rng(seed=[0x22; 32]).
// b_pk_sec1 is uncompressed (97 bytes, 0x04 prefix).

const P384_KAT: &[(&str, &str, &str)] = &[
    // vector 0
    (
        "b37b2728a9def3ad44fba7edca16e5f6da304c5fcb6172ce49233745bd2de05008a0ec9293005a63d1f862230bf81db4",
        "04c9105e05da9d30fd3497eb8af57348700bbaee775aaa5da53e3cc64c33e9e9d67c44fc25e6da13bf77e6b5569e0899cd9070a0c849f42f67314f81b06d74aca08fdd230cc353ff40875b96fe1a3eafd5e1f1873ac770496d3ec084b9530b72a0",
        "0e3d8265e9799cafd517f9507085a8a0a9b69f939f7ecbb1733f675b740df605c3a3ff7db5c77fb642d0d88042b6e6cf",
    ),
    // vector 1
    (
        "64dafd61ee1985622c13fc6ba42a48967aac468762f38d8dd715e2807fb5b3f1ddd758ffdc43b20c3f6bc25b80730784",
        "04c56250cad8da17a6d96d92e41ecb5bc1bf15510564722f97d5898f3423233f6a72392a236896c9fd912b7030db6f6227a186c4f62f7bd43282224bf122ddcb86ebd47f1523829303d7e14602df7a4da41084fd011ecd291154fcfa6c96107463",
        "e929cd4bc77cb7a72c0970a37ec09703f67add0341249ce41b68d0f73bb0af6d3810cf49e7d69aee8846bf5180aaaef3",
    ),
];

/// ECDH P-384 known-answer test with deterministic vectors.
#[test]
fn ecdh_p384_kat_deterministic() {
    let kex = EcdhP384;
    for (i, (d_iut_hex, b_pk_hex, z_hex)) in P384_KAT.iter().enumerate() {
        let d_iut = hex_bytes(d_iut_hex);
        let b_pk = hex_bytes(b_pk_hex);
        let expected_z: [u8; 48] = {
            let v = hex_bytes(z_hex);
            let mut arr = [0u8; 48];
            arr.copy_from_slice(&v);
            arr
        };

        let mut shared = [0u8; 48];
        kex.agree(&d_iut, &b_pk, &mut shared)
            .unwrap_or_else(|e| panic!("P-384 KAT vector {i} failed: {e:?}"));

        assert_eq!(
            shared, expected_z,
            "P-384 KAT vector {i}: shared secret mismatch"
        );
    }
}

// ── P-521 KAT vectors ─────────────────────────────────────────────────────────
//
// Generated with ChaCha20Rng(seed=[0x33; 32]).
// b_pk_sec1 is uncompressed (133 bytes, 0x04 prefix).
// d_iut and z include the leading 0x00 byte (NIST convention for 66-byte encoding).

const P521_KAT: &[(&str, &str, &str)] = &[
    // vector 0
    (
        "00d758356c493629c5f9ad0b5c978a7ce28e5d91cd9b5d90170ba18735bd487d46345c8b2c9775623bf7104638c746fecc99cbbe339874c6e7b332d5dddd54de5477",
        "0400bfd753b30d01c555f6583988587d513bbeb206854cb866ef0cffa8f84310dcebe5655810fb9c56890174a9a64b5d6c9044d338350bc7a9f9e5db6754cca0f8708600880dcde9f2f441a386a4dba15d32333b62e1c495f3b11eae379c271e1cd6789dda4a55ff8bc8462a5de2dc387b06f211b79438e733301b93781c3c4a1519e5c0cb",
        "00dd19ff716f949280320d1c600d41089e042564a5c0e7ef9a57505576820c4f72a597f2af96c39a92f7823620e04f759dfc9a04a298a60db4b3cb07bc1383ca4b5b",
    ),
    // vector 1
    (
        "016f312cb3fb9a8980282a8fe17ab47db7a17cf709cee752811406e2d39ddaaa56d30e2504633b589b2f51b9da827eb970413cacf90239cd4ca4eb909c7361e061ff",
        "04001deaae991f8cb3c0154b228ab60dabe539b438b46b2867470bf7eff358697949db10633d59e75ac5c000ddd33fa0cf21f198b30babfdee576776c062cf8ad3749a001cafeb7ec315c4849b7dce9db0910746f61858a2f43eb31c572bb2cc78faee589a51ca2157e7e5c3d88dd5bf6516ccf57c7e4044077ccf050a1f5620804187f0f5",
        "00e6b0b689ea04cf59cf156c5a0f4658360a62e91c749cb806c9602ffc06696f99141fae111d5955050831e69c1cb1a97bb0e618d3fff7ba6df67334852f097eff00",
    ),
];

/// ECDH P-521 known-answer test with deterministic vectors.
///
/// Note: P-521 scalars are 66 bytes (with optional leading 0x00).
/// The leading byte is stripped when the byte string is longer than 66 bytes.
#[test]
fn ecdh_p521_kat_deterministic() {
    let kex = EcdhP521;
    for (i, (d_iut_hex, b_pk_hex, z_hex)) in P521_KAT.iter().enumerate() {
        // d_iut may have leading 00 (67 bytes decoded); take last 66 bytes
        let d_bytes = hex_bytes(d_iut_hex);
        let mut d_iut = [0u8; 66];
        let src_start = d_bytes.len().saturating_sub(66);
        let dst_start = 66usize.saturating_sub(d_bytes.len());
        d_iut[dst_start..].copy_from_slice(&d_bytes[src_start..]);

        let b_pk = hex_bytes(b_pk_hex);

        // z may have leading 00 (67 bytes decoded); take last 66 bytes
        let z_bytes = hex_bytes(z_hex);
        let mut expected_z = [0u8; 66];
        let z_src_start = z_bytes.len().saturating_sub(66);
        let z_dst_start = 66usize.saturating_sub(z_bytes.len());
        expected_z[z_dst_start..].copy_from_slice(&z_bytes[z_src_start..]);

        let mut shared = [0u8; 66];
        kex.agree(&d_iut, &b_pk, &mut shared)
            .unwrap_or_else(|e| panic!("P-521 KAT vector {i} failed: {e:?}"));

        assert_eq!(
            shared, expected_z,
            "P-521 KAT vector {i}: shared secret mismatch"
        );
    }
}

// ── ECDH commutativity (self-consistency) tests ───────────────────────────────

/// ECDH P-256 DH commutativity: agree(a, B) == agree(b, A).
///
/// Uses generated keypairs and verifies that the DH protocol is symmetric.
#[test]
fn ecdh_p256_commutativity() {
    use oxicrypto_kex::ecdh_p256_generate_keypair;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
    let (alice_sk, alice_pk) = ecdh_p256_generate_keypair(&mut rng).expect("Alice keygen");
    let (bob_sk, bob_pk) = ecdh_p256_generate_keypair(&mut rng).expect("Bob keygen");

    let kex = EcdhP256;
    let mut alice_shared = [0u8; 32];
    let mut bob_shared = [0u8; 32];

    kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
        .expect("Alice ECDH-P256 agree");
    kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
        .expect("Bob ECDH-P256 agree");

    assert_eq!(alice_shared, bob_shared, "ECDH-P256 DH must be commutative");
    assert_ne!(
        alice_shared, [0u8; 32],
        "shared secret must not be all-zero"
    );
}

/// ECDH P-384 DH commutativity: agree(a, B) == agree(b, A).
#[test]
fn ecdh_p384_commutativity() {
    use oxicrypto_kex::ecdh_p384_generate_keypair;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    let mut rng = ChaCha20Rng::from_seed([0x43u8; 32]);
    let (alice_sk, alice_pk) = ecdh_p384_generate_keypair(&mut rng).expect("Alice keygen");
    let (bob_sk, bob_pk) = ecdh_p384_generate_keypair(&mut rng).expect("Bob keygen");

    let kex = EcdhP384;
    let mut alice_shared = [0u8; 48];
    let mut bob_shared = [0u8; 48];

    kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
        .expect("Alice ECDH-P384 agree");
    kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
        .expect("Bob ECDH-P384 agree");

    assert_eq!(alice_shared, bob_shared, "ECDH-P384 DH must be commutative");
    assert_ne!(
        alice_shared, [0u8; 48],
        "shared secret must not be all-zero"
    );
}

/// ECDH P-521 DH commutativity: agree(a, B) == agree(b, A).
#[test]
fn ecdh_p521_commutativity() {
    use oxicrypto_kex::ecdh_p521_generate_keypair;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    let mut rng = ChaCha20Rng::from_seed([0x44u8; 32]);
    let (alice_sk, alice_pk) = ecdh_p521_generate_keypair(&mut rng).expect("Alice keygen");
    let (bob_sk, bob_pk) = ecdh_p521_generate_keypair(&mut rng).expect("Bob keygen");

    let kex = EcdhP521;
    let mut alice_shared = [0u8; 66];
    let mut bob_shared = [0u8; 66];

    kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
        .expect("Alice ECDH-P521 agree");
    kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
        .expect("Bob ECDH-P521 agree");

    assert_eq!(alice_shared, bob_shared, "ECDH-P521 DH must be commutative");
    assert_ne!(
        alice_shared, [0u8; 66],
        "shared secret must not be all-zero"
    );
}

/// All ECDH variants correctly report their shared-secret length.
#[test]
fn ecdh_shared_secret_len_correct() {
    assert_eq!(
        EcdhP256.shared_secret_len(),
        32,
        "P-256 shared secret is 32 bytes"
    );
    assert_eq!(
        EcdhP384.shared_secret_len(),
        48,
        "P-384 shared secret is 48 bytes"
    );
    assert_eq!(
        EcdhP521.shared_secret_len(),
        66,
        "P-521 shared secret is 66 bytes"
    );
}

/// ECDH P-256 agree_to_vec matches agree() output.
#[test]
fn ecdh_p256_agree_to_vec_matches_agree() {
    use oxicrypto_kex::ecdh_p256_generate_keypair;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    let mut rng = ChaCha20Rng::from_seed([0x55u8; 32]);
    let (alice_sk, _) = ecdh_p256_generate_keypair(&mut rng).expect("Alice keygen");
    let (_, bob_pk) = ecdh_p256_generate_keypair(&mut rng).expect("Bob keygen");

    let kex = EcdhP256;
    let mut shared_fixed = [0u8; 32];
    kex.agree(alice_sk.as_bytes(), &bob_pk, &mut shared_fixed)
        .expect("agree failed");

    let shared_vec = kex
        .agree_to_vec(alice_sk.as_bytes(), &bob_pk)
        .expect("agree_to_vec failed");

    assert_eq!(shared_fixed.as_slice(), shared_vec.as_slice());
    assert_eq!(shared_vec.len(), 32);
}

/// ECDH P-256 returns CryptoError::InvalidKey for bad scalar or point input.
#[test]
fn ecdh_p256_invalid_input_returns_error() {
    let kex = EcdhP256;

    // Invalid scalar (wrong length)
    let mut shared = [0u8; 32];
    let result = kex.agree(&[0u8; 16], &[0x04u8; 65], &mut shared);
    assert_eq!(result, Err(CryptoError::InvalidKey));

    // Invalid public key (all-zero is not a valid P-256 point)
    let d_iut = hex_bytes("e462b8c160b3ab527a8f4a8c5d9bc0da890f4ece9296664be99198aa592d220c");
    let result = kex.agree(&d_iut, &[0u8; 33], &mut shared);
    assert_eq!(result, Err(CryptoError::InvalidKey));
}

/// ECDH P-256 returns CryptoError::BufferTooSmall when output buffer is too small.
#[test]
fn ecdh_p256_buffer_too_small() {
    let kex = EcdhP256;
    let d_iut = hex_bytes("e462b8c160b3ab527a8f4a8c5d9bc0da890f4ece9296664be99198aa592d220c");
    let b_pk = hex_bytes("0432c5e64d412d5a5e0172b953ac160852843a2394a242f8785dfef0eea7cf4f09875712841a4d3fae0ce755148c44a8ba4d138e6de4f3b0f03568e1f939c95b21");
    let mut shared = [0u8; 16]; // too small
    let result = kex.agree(&d_iut, &b_pk, &mut shared);
    assert_eq!(result, Err(CryptoError::BufferTooSmall));
}
