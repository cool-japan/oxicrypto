//! End-to-end hybrid public-key encryption: PQ KEM → HKDF → AEAD.
//!
//! This is the concrete cross-crate deliverable that closes three sub-TODO
//! integration items at once, without introducing a dependency cycle:
//!
//! * `oxicrypto-pq`: "coordinate with `oxicrypto-kdf` for shared-secret-to-AEAD-key
//!   derivation (HKDF after KEM)";
//! * `oxicrypto-pq`: "coordinate with `oxicrypto-aead` for hybrid encryption";
//! * `oxicrypto-aead`: "coordinate with `oxicrypto-pq` for hybrid encryption:
//!   ML-KEM shared secret → HKDF → AEAD key".
//!
//! The facade crate (`oxicrypto`) is the only place that can see `pq`, `kdf`,
//! and `aead` simultaneously — wiring any of these into each other directly
//! would invert the dependency graph.  The flow implemented here is the classic
//! KEM-DEM construction:
//!
//! 1. Recipient publishes a KEM encapsulation (public) key.
//! 2. Sender encapsulates → `(ciphertext, shared_secret)`.
//! 3. Both sides run HKDF-SHA-256 over the shared secret to derive a 32-byte
//!    AES-256-GCM key (Extract-then-Expand, RFC 5869).
//! 4. Sender AEAD-seals the payload; recipient decapsulates, derives the same
//!    key, and AEAD-opens it.
//!
//! Tampering with the AEAD ciphertext must yield `InvalidTag`.

#![cfg(all(feature = "pq-preview", feature = "pure"))]

use oxicrypto::hybrid::Kem;
use oxicrypto::{aead_impl, hkdf_sha256_expand, hkdf_sha256_extract, AeadAlgo, CryptoError};

/// Domain-separation salt and info string for the KEM-DEM key schedule.
const HKDF_SALT: &[u8] = b"oxicrypto-pq-hybrid-encryption/v1";
const HKDF_INFO: &[u8] = b"aes-256-gcm key";

/// Derive a 32-byte AES-256-GCM key from a KEM shared secret using
/// HKDF-SHA-256 (Extract then Expand).
fn derive_aead_key(shared_secret: &[u8]) -> Result<[u8; 32], CryptoError> {
    let prk = hkdf_sha256_extract(HKDF_SALT, shared_secret);
    let mut key = [0u8; 32];
    hkdf_sha256_expand(&prk, HKDF_INFO, &mut key)?;
    Ok(key)
}

/// Run the full KEM-DEM round trip for a given [`Kem`] implementation.
///
/// Returns `Ok(())` if the recipient recovers the exact plaintext AND a
/// single-byte flip in the AEAD ciphertext is rejected with `InvalidTag`.
fn hybrid_encrypt_round_trip<K: Kem>() {
    // ── 1. Recipient key pair ────────────────────────────────────────────────
    let (decap_key, encap_key) = K::kem_generate().expect("KEM keygen");

    // ── 2. Sender encapsulates ───────────────────────────────────────────────
    let (ciphertext, sender_ss) = K::kem_encapsulate(&encap_key).expect("encapsulate");

    // ── 3a. Sender derives the AEAD key + seals a payload ─────────────────────
    let sender_key = derive_aead_key(sender_ss.as_ref()).expect("sender key derivation");
    let aead = aead_impl(AeadAlgo::Aes256Gcm);
    let nonce = vec![0u8; aead.nonce_len()];
    let aad = b"associated header";
    let plaintext = b"post-quantum hybrid encryption payload";

    let mut sealed = vec![0u8; plaintext.len() + aead.tag_len()];
    let written = aead
        .seal(&sender_key, &nonce, aad, plaintext, &mut sealed)
        .expect("AEAD seal");
    assert_eq!(written, sealed.len());

    // ── 3b. Recipient decapsulates → same shared secret ──────────────────────
    let recipient_ss = K::kem_decapsulate(&decap_key, &ciphertext).expect("decapsulate");
    assert_eq!(
        sender_ss.as_ref(),
        recipient_ss.as_ref(),
        "KEM shared secrets must agree"
    );

    // ── 3c. Recipient derives the identical AEAD key ─────────────────────────
    let recipient_key = derive_aead_key(recipient_ss.as_ref()).expect("recipient key derivation");
    assert_eq!(
        sender_key, recipient_key,
        "HKDF must derive identical AEAD keys on both sides"
    );

    // ── 4. Recipient opens the payload ───────────────────────────────────────
    let mut recovered = vec![0u8; plaintext.len()];
    let n = aead
        .open(&recipient_key, &nonce, aad, &sealed, &mut recovered)
        .expect("AEAD open");
    assert_eq!(&recovered[..n], plaintext, "plaintext must round-trip");

    // ── 5. Tampered ciphertext must be rejected ──────────────────────────────
    let mut tampered = sealed.clone();
    tampered[0] ^= 0xFF;
    let mut sink = vec![0u8; plaintext.len()];
    let result = aead.open(&recipient_key, &nonce, aad, &tampered, &mut sink);
    assert_eq!(
        result,
        Err(CryptoError::InvalidTag),
        "a tampered ciphertext must fail authentication"
    );
}

#[test]
fn mlkem768_hybrid_encryption() {
    hybrid_encrypt_round_trip::<oxicrypto::pq::MlKem768>();
}

#[test]
fn xwing768_hybrid_encryption() {
    // X-Wing (ML-KEM-768 + X25519) exercises the hybrid-KEM path end to end.
    hybrid_encrypt_round_trip::<oxicrypto::pq::XWing768>();
}

#[test]
fn distinct_ciphertexts_derive_distinct_keys() {
    // Two independent encapsulations under the same recipient key must produce
    // different shared secrets and therefore different AEAD keys — a smoke test
    // that the derivation is bound to the KEM output, not a constant.
    type K = oxicrypto::pq::MlKem768;
    let (_dk, ek) = K::kem_generate().expect("keygen");
    let (_ct1, ss1) = K::kem_encapsulate(&ek).expect("encap 1");
    let (_ct2, ss2) = K::kem_encapsulate(&ek).expect("encap 2");
    let k1 = derive_aead_key(ss1.as_ref()).expect("derive 1");
    let k2 = derive_aead_key(ss2.as_ref()).expect("derive 2");
    assert_ne!(
        k1, k2,
        "independent encapsulations must derive distinct keys"
    );
}
