#![forbid(unsafe_code)]

//! Pure Rust key-exchange implementations for the OxiCrypto stack.
//!
//! Provides a [`KeyAgreement`]-trait wrapper for X25519 Diffie-Hellman,
//! X448 Diffie-Hellman, ECDH over NIST P-256, P-384, and P-521, plus key
//! generation helpers.
//!
//! # Key generation
//!
//! All `generate_keypair` functions accept any RNG implementing
//! [`rand_core::TryCryptoRng`] (rand_core 0.10+).
//!
//! ## Shared-secret rejection
//!
//! Every `agree()` implementation rejects all-zero shared secrets via
//! constant-time comparison.  An all-zero output indicates a low-order
//! (small subgroup) public key attack; callers will receive
//! [`CryptoError::Kex`] in that case.

use oxicrypto_core::{CryptoError, KeyAgreement, SecretKey, SecretVec};
use p256::elliptic_curve::Generate;
use x25519_dalek::{PublicKey, StaticSecret};

pub mod hpke;

// ── Type-safe public key wrappers ─────────────────────────────────────────────

/// A type-safe 32-byte X25519 public key.
///
/// Wraps the raw Montgomery-form u-coordinate used by the X25519 function
/// (RFC 7748 §6.1).  Use [`as_bytes`](X25519PublicKey::as_bytes) to access
/// the inner bytes for [`KeyAgreement::agree`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519PublicKey(pub [u8; 32]);

impl X25519PublicKey {
    /// Borrow the 32-byte public key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume the wrapper and return the inner 32-byte array.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for X25519PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A type-safe 56-byte X448 public key.
///
/// Wraps the raw Montgomery-form u-coordinate used by the X448 function
/// (RFC 7748 §6.2).  Use [`as_bytes`](X448PublicKey::as_bytes) to access
/// the inner bytes for [`KeyAgreement::agree`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X448PublicKey(pub [u8; 56]);

impl X448PublicKey {
    /// Borrow the 56-byte public key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 56] {
        &self.0
    }

    /// Consume the wrapper and return the inner 56-byte array.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 56] {
        self.0
    }
}

impl From<[u8; 56]> for X448PublicKey {
    fn from(bytes: [u8; 56]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for X448PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ── X25519 ────────────────────────────────────────────────────────────────────

/// X25519 Diffie-Hellman key agreement.
///
/// `agree(my_secret_bytes, their_public_bytes, shared_out)`:
/// - `my_secret_bytes` — 32-byte static secret scalar
/// - `their_public_bytes` — 32-byte public point
/// - `shared_out` — must be at least 32 bytes; receives the shared secret
#[derive(Debug, Default, Clone, Copy)]
pub struct X25519;

impl KeyAgreement for X25519 {
    fn name(&self) -> &'static str {
        "X25519"
    }
    fn scalar_len(&self) -> usize {
        32
    }
    fn point_len(&self) -> usize {
        32
    }
    fn agree(
        &self,
        my_secret: &[u8],
        their_public: &[u8],
        shared_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if shared_out.len() < 32 {
            return Err(CryptoError::BufferTooSmall);
        }
        let secret_bytes: [u8; 32] = my_secret.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let public_bytes: [u8; 32] = their_public
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;

        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(public_bytes);
        let shared = secret.diffie_hellman(&public);
        // Reject all-zero shared secret (low-order point attack).
        if oxicrypto_core::ct_is_zero(shared.as_bytes()) {
            return Err(CryptoError::Kex);
        }
        shared_out[..32].copy_from_slice(shared.as_bytes());
        Ok(())
    }
}

// ── ECDH P-256 ───────────────────────────────────────────────────────────────

/// ECDH key agreement over NIST P-256 (secp256r1).
///
/// - `my_secret`: 32-byte raw scalar
/// - `their_public`: SEC1-encoded public key (compressed 33 bytes or uncompressed 65 bytes)
/// - `shared_out`: receives the 32-byte x-coordinate of the shared point
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdhP256;

impl KeyAgreement for EcdhP256 {
    fn name(&self) -> &'static str {
        "ECDH-P256"
    }
    fn scalar_len(&self) -> usize {
        32
    }
    fn point_len(&self) -> usize {
        33 // compressed SEC1
    }
    fn agree(
        &self,
        my_secret: &[u8],
        their_public: &[u8],
        shared_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if shared_out.len() < 32 {
            return Err(CryptoError::BufferTooSmall);
        }
        let sk = p256::SecretKey::from_slice(my_secret).map_err(|_| CryptoError::InvalidKey)?;
        let pk =
            p256::PublicKey::from_sec1_bytes(their_public).map_err(|_| CryptoError::InvalidKey)?;

        let shared_secret = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
        let raw = shared_secret.raw_secret_bytes();
        // Reject all-zero shared secret (low-order point attack).
        if oxicrypto_core::ct_is_zero(raw) {
            return Err(CryptoError::Kex);
        }
        shared_out[..32].copy_from_slice(raw);
        Ok(())
    }
}

// ── ECDH P-384 ───────────────────────────────────────────────────────────────

/// ECDH key agreement over NIST P-384 (secp384r1).
///
/// - `my_secret`: 48-byte raw scalar
/// - `their_public`: SEC1-encoded public key (compressed 49 bytes or uncompressed 97 bytes)
/// - `shared_out`: receives the 48-byte x-coordinate of the shared point
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdhP384;

impl KeyAgreement for EcdhP384 {
    fn name(&self) -> &'static str {
        "ECDH-P384"
    }
    fn scalar_len(&self) -> usize {
        48
    }
    fn point_len(&self) -> usize {
        49 // compressed SEC1
    }
    fn agree(
        &self,
        my_secret: &[u8],
        their_public: &[u8],
        shared_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if shared_out.len() < 48 {
            return Err(CryptoError::BufferTooSmall);
        }
        let sk = p384::SecretKey::from_slice(my_secret).map_err(|_| CryptoError::InvalidKey)?;
        let pk =
            p384::PublicKey::from_sec1_bytes(their_public).map_err(|_| CryptoError::InvalidKey)?;

        let shared_secret = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
        let raw = shared_secret.raw_secret_bytes();
        if oxicrypto_core::ct_is_zero(raw) {
            return Err(CryptoError::Kex);
        }
        shared_out[..48].copy_from_slice(raw);
        Ok(())
    }
}

// ── ECDH P-521 ───────────────────────────────────────────────────────────────

/// ECDH key agreement over NIST P-521 (secp521r1).
///
/// - `my_secret`: 66-byte raw scalar
/// - `their_public`: SEC1-encoded public key (uncompressed 133 bytes or compressed 67 bytes)
/// - `shared_out`: receives the 66-byte x-coordinate of the shared point
///
/// Note: NIST P-521 keys generated by this crate use **uncompressed** SEC1
/// encoding (133 bytes) because `p521` sets `COMPRESS_POINTS = false`.
/// Both compressed (67 bytes) and uncompressed (133 bytes) inputs are accepted
/// by `agree()`.
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdhP521;

impl KeyAgreement for EcdhP521 {
    fn name(&self) -> &'static str {
        "ECDH-P521"
    }
    fn scalar_len(&self) -> usize {
        66
    }
    fn point_len(&self) -> usize {
        133 // uncompressed SEC1: 0x04 prefix + 2 × 66 coordinate bytes
    }
    fn agree(
        &self,
        my_secret: &[u8],
        their_public: &[u8],
        shared_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if shared_out.len() < 66 {
            return Err(CryptoError::BufferTooSmall);
        }
        let sk = p521::SecretKey::from_slice(my_secret).map_err(|_| CryptoError::InvalidKey)?;
        let pk =
            p521::PublicKey::from_sec1_bytes(their_public).map_err(|_| CryptoError::InvalidKey)?;
        let shared_secret = p521::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
        let raw = shared_secret.raw_secret_bytes();
        if oxicrypto_core::ct_is_zero(raw) {
            return Err(CryptoError::Kex);
        }
        shared_out[..66].copy_from_slice(raw);
        Ok(())
    }
}

// ── Key generation helpers ────────────────────────────────────────────────────

/// Generate an X25519 key pair.
///
/// Returns `(SecretKey<32>, [u8; 32])` — the 32-byte static secret scalar and
/// the 32-byte public point.
///
/// # Errors
///
/// Returns [`CryptoError::Rng`] if the RNG fails to produce random bytes.
#[must_use = "result must be checked"]
pub fn x25519_generate_keypair<R>(rng: &mut R) -> Result<(SecretKey<32>, [u8; 32]), CryptoError>
where
    R: rand_core::TryCryptoRng + ?Sized,
{
    let mut seed = [0u8; 32];
    rng.try_fill_bytes(&mut seed)
        .map_err(|_| CryptoError::Rng)?;
    let secret = StaticSecret::from(seed);
    let public = PublicKey::from(&secret);
    Ok((SecretKey::new(seed), *public.as_bytes()))
}

/// Generate an ECDH P-256 key pair.
///
/// Returns `(SecretVec, Vec<u8>)` — the 32-byte raw scalar wrapped in a
/// zeroize-on-drop container, and the SEC1-encoded public key (compressed,
/// 33 bytes for P-256).
///
/// # Errors
///
/// Returns [`CryptoError::Rng`] if the RNG fails.
#[must_use = "result must be checked"]
pub fn ecdh_p256_generate_keypair<R>(rng: &mut R) -> Result<(SecretVec, Vec<u8>), CryptoError>
where
    R: rand_core::TryCryptoRng + ?Sized,
{
    let secret_key = p256::SecretKey::try_generate_from_rng(rng).map_err(|_| CryptoError::Rng)?;
    let public_key = secret_key.public_key();
    let sk_bytes = SecretVec::from_slice(secret_key.to_bytes().as_slice());
    let pk_bytes = public_key.to_sec1_bytes().to_vec();
    Ok((sk_bytes, pk_bytes))
}

/// Generate an ECDH P-384 key pair.
///
/// Returns `(SecretVec, Vec<u8>)` — the 48-byte raw scalar and the
/// SEC1-encoded public key (compressed, 49 bytes for P-384).
///
/// # Errors
///
/// Returns [`CryptoError::Rng`] if the RNG fails.
#[must_use = "result must be checked"]
pub fn ecdh_p384_generate_keypair<R>(rng: &mut R) -> Result<(SecretVec, Vec<u8>), CryptoError>
where
    R: rand_core::TryCryptoRng + ?Sized,
{
    let secret_key = p384::SecretKey::try_generate_from_rng(rng).map_err(|_| CryptoError::Rng)?;
    let public_key = secret_key.public_key();
    let sk_bytes = SecretVec::from_slice(secret_key.to_bytes().as_slice());
    let pk_bytes = public_key.to_sec1_bytes().to_vec();
    Ok((sk_bytes, pk_bytes))
}

/// Generate an ECDH P-521 key pair.
///
/// Returns `(SecretVec, Vec<u8>)` — the 66-byte raw scalar and the
/// SEC1-encoded public key (uncompressed, 133 bytes for P-521).
///
/// Note: P-521 uses uncompressed SEC1 encoding by default.
///
/// # Errors
///
/// Returns [`CryptoError::Rng`] if the RNG fails.
#[must_use = "result must be checked"]
pub fn ecdh_p521_generate_keypair<R>(rng: &mut R) -> Result<(SecretVec, Vec<u8>), CryptoError>
where
    R: rand_core::TryCryptoRng + ?Sized,
{
    let secret_key = p521::SecretKey::try_generate_from_rng(rng).map_err(|_| CryptoError::Rng)?;
    let public_key = secret_key.public_key();
    let sk_bytes = SecretVec::from_slice(secret_key.to_bytes().as_slice());
    let pk_bytes = public_key.to_sec1_bytes().to_vec();
    Ok((sk_bytes, pk_bytes))
}

// ── X448 ─────────────────────────────────────────────────────────────────────

/// X448 Diffie-Hellman key agreement (RFC 7748 §5).
///
/// - `my_secret`: 56-byte scalar (clamped per RFC 7748)
/// - `their_public`: 56-byte Montgomery-form public point
/// - `shared_out`: must be at least 56 bytes; receives the shared secret
///
/// Low-order public keys are rejected with [`CryptoError::Kex`].
#[derive(Debug, Default, Clone, Copy)]
pub struct X448;

impl KeyAgreement for X448 {
    fn name(&self) -> &'static str {
        "X448"
    }
    fn scalar_len(&self) -> usize {
        56
    }
    fn point_len(&self) -> usize {
        56
    }
    /// Perform X448 DH and write the 56-byte shared secret into `shared_out`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] if either `my_secret` or
    /// `their_public` is not exactly 56 bytes, and [`CryptoError::Kex`] if
    /// `their_public` is a low-order point or the resulting shared secret is
    /// all-zero.
    fn agree(
        &self,
        my_secret: &[u8],
        their_public: &[u8],
        shared_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if shared_out.len() < 56 {
            return Err(CryptoError::BufferTooSmall);
        }
        // Length validation: both inputs must be exactly 56 bytes.
        let scalar: [u8; 56] = my_secret.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let point: [u8; 56] = their_public
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        // x448() applies RFC 7748 clamping and rejects low-order points.
        let shared = x448::x448(scalar, point).ok_or(CryptoError::Kex)?;
        // Reject all-zero shared secret (low-order point attack defence in depth).
        if oxicrypto_core::ct_is_zero(&shared) {
            return Err(CryptoError::Kex);
        }
        shared_out[..56].copy_from_slice(&shared);
        Ok(())
    }
}

/// Generate an X448 key pair from raw random bytes.
///
/// Fills 56 bytes from `rng`, applies RFC 7748 clamping, and derives the
/// public key via base-point multiplication.
///
/// Returns `(SecretKey<56>, [u8; 56])` — the clamped secret scalar and the
/// 56-byte public point.
///
/// # Errors
///
/// Returns [`CryptoError::Rng`] if the RNG fails to produce random bytes.
#[must_use = "result must be checked"]
pub fn x448_generate_keypair<R>(rng: &mut R) -> Result<(SecretKey<56>, [u8; 56]), CryptoError>
where
    R: rand_core::TryCryptoRng + ?Sized,
{
    let mut seed = [0u8; 56];
    rng.try_fill_bytes(&mut seed)
        .map_err(|_| CryptoError::Rng)?;
    // Apply RFC 7748 §5 clamping: clear bits 0-1 of byte 0, set bit 7 of byte 55.
    seed[0] &= 252;
    seed[55] |= 128;
    // Derive the public key: X448(seed, base_point). x448() re-clamps the scalar;
    // clamping is idempotent so the round-trip is safe.
    let public = x448::x448(seed, x448::X448_BASEPOINT_BYTES).ok_or(CryptoError::Rng)?;
    Ok((SecretKey::new(seed), public))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const ALICE_SECRET: [u8; 32] = [0xaau8; 32];
    const BOB_SECRET: [u8; 32] = [0xbbu8; 32];

    fn public_from_secret(secret_bytes: &[u8; 32]) -> [u8; 32] {
        let secret = StaticSecret::from(*secret_bytes);
        let public = PublicKey::from(&secret);
        *public.as_bytes()
    }

    fn test_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([42u8; 32])
    }

    // ── X25519 basic tests ────────────────────────────────────────────────────

    #[test]
    fn x25519_both_parties_agree() {
        let kex = X25519;

        let alice_pub = public_from_secret(&ALICE_SECRET);
        let bob_pub = public_from_secret(&BOB_SECRET);

        let mut alice_shared = [0u8; 32];
        kex.agree(&ALICE_SECRET, &bob_pub, &mut alice_shared)
            .expect("Alice agree failed");

        let mut bob_shared = [0u8; 32];
        kex.agree(&BOB_SECRET, &alice_pub, &mut bob_shared)
            .expect("Bob agree failed");

        assert_eq!(
            alice_shared, bob_shared,
            "Alice and Bob must derive the same shared secret"
        );
    }

    #[test]
    fn x25519_shared_is_32_bytes() {
        let kex = X25519;
        assert_eq!(kex.scalar_len(), 32);
        assert_eq!(kex.point_len(), 32);

        let bob_pub = public_from_secret(&BOB_SECRET);
        let mut shared = [0u8; 32];
        kex.agree(&ALICE_SECRET, &bob_pub, &mut shared)
            .expect("X25519 agree failed");
        assert_ne!(shared, [0u8; 32], "Shared secret should not be all zeros");
    }

    #[test]
    fn x25519_invalid_key_length() {
        let kex = X25519;
        let mut shared = [0u8; 32];
        let result = kex.agree(&[0u8; 16], &[0u8; 32], &mut shared);
        assert_eq!(result, Err(CryptoError::InvalidKey));
    }

    #[test]
    fn x25519_buffer_too_small() {
        let kex = X25519;
        let bob_pub = public_from_secret(&BOB_SECRET);
        let mut shared = [0u8; 16];
        let result = kex.agree(&ALICE_SECRET, &bob_pub, &mut shared);
        assert_eq!(result, Err(CryptoError::BufferTooSmall));
    }

    /// Verify that X25519 with the all-zero public key (a known low-order point
    /// on Curve25519) returns an error instead of the all-zero shared secret.
    #[test]
    fn x25519_zero_rejection() {
        let kex = X25519;
        let zero_pk = [0u8; 32]; // all-zero is a low-order point on Curve25519
        let mut shared = [0u8; 32];
        let result = kex.agree(&ALICE_SECRET, &zero_pk, &mut shared);
        assert_eq!(
            result,
            Err(CryptoError::Kex),
            "X25519 must reject all-zero shared secret from low-order public key"
        );
    }

    // ── X25519 key generation ─────────────────────────────────────────────────

    /// Generate two X25519 keypairs from an RNG, run DH in both directions,
    /// and verify the shared secrets match.
    #[test]
    fn x25519_keygen_then_agree() {
        let mut rng = test_rng();
        let (alice_sk, alice_pk) = x25519_generate_keypair(&mut rng).expect("Alice keygen");
        let (bob_sk, bob_pk) = x25519_generate_keypair(&mut rng).expect("Bob keygen");

        let kex = X25519;
        let mut alice_shared = [0u8; 32];
        kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
            .expect("Alice agree");

        let mut bob_shared = [0u8; 32];
        kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
            .expect("Bob agree");

        assert_eq!(
            alice_shared, bob_shared,
            "x25519_keygen: Alice and Bob must derive the same shared secret"
        );
        assert_ne!(alice_shared, [0u8; 32]);
    }

    // ── ECDH P-256 tests ─────────────────────────────────────────────────────

    fn p256_keypair(scalar_bytes: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let sk = p256::SecretKey::from_slice(scalar_bytes).expect("valid P-256 scalar");
        let pk = sk.public_key();
        (scalar_bytes.to_vec(), pk.to_sec1_bytes().to_vec())
    }

    #[test]
    fn ecdh_p256_both_parties_agree() {
        // Two deterministic scalars (must be valid non-zero mod n).
        let alice_scalar: [u8; 32] = {
            let mut s = [0u8; 32];
            s[0] = 0x01;
            s[31] = 0x01;
            s
        };
        let bob_scalar: [u8; 32] = {
            let mut s = [0u8; 32];
            s[0] = 0x02;
            s[31] = 0x02;
            s
        };
        let (_alice_sk, alice_pk) = p256_keypair(&alice_scalar);
        let (_bob_sk, bob_pk) = p256_keypair(&bob_scalar);

        let kex = EcdhP256;
        let mut alice_shared = [0u8; 32];
        kex.agree(&alice_scalar, &bob_pk, &mut alice_shared)
            .expect("Alice ECDH-P256 agree failed");

        let mut bob_shared = [0u8; 32];
        kex.agree(&bob_scalar, &alice_pk, &mut bob_shared)
            .expect("Bob ECDH-P256 agree failed");

        assert_eq!(
            alice_shared, bob_shared,
            "ECDH-P256: Alice and Bob must derive the same shared secret"
        );
        assert_ne!(alice_shared, [0u8; 32]);
    }

    #[test]
    fn ecdh_p256_buffer_too_small() {
        let kex = EcdhP256;
        let scalar: [u8; 32] = {
            let mut s = [0u8; 32];
            s[0] = 0x01;
            s[31] = 0x01;
            s
        };
        let (_, pk) = p256_keypair(&scalar);
        let mut shared = [0u8; 16];
        let result = kex.agree(&scalar, &pk, &mut shared);
        assert_eq!(result, Err(CryptoError::BufferTooSmall));
    }

    /// Generate a P-256 keypair, run ECDH in both directions, verify secrets match.
    #[test]
    fn ecdh_p256_keygen_agree() {
        let mut rng = test_rng();
        let (alice_sk, alice_pk) =
            ecdh_p256_generate_keypair(&mut rng).expect("Alice P-256 keygen");
        let (bob_sk, bob_pk) = ecdh_p256_generate_keypair(&mut rng).expect("Bob P-256 keygen");

        let kex = EcdhP256;
        let mut alice_shared = [0u8; 32];
        kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
            .expect("Alice P-256 agree");

        let mut bob_shared = [0u8; 32];
        kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
            .expect("Bob P-256 agree");

        assert_eq!(
            alice_shared, bob_shared,
            "ecdh_p256_keygen_agree: secrets must match"
        );
        assert_ne!(alice_shared, [0u8; 32]);
    }

    // ── ECDH P-384 tests ─────────────────────────────────────────────────────

    fn p384_keypair(scalar_bytes: &[u8; 48]) -> (Vec<u8>, Vec<u8>) {
        let sk = p384::SecretKey::from_slice(scalar_bytes).expect("valid P-384 scalar");
        let pk = sk.public_key();
        (scalar_bytes.to_vec(), pk.to_sec1_bytes().to_vec())
    }

    #[test]
    fn ecdh_p384_both_parties_agree() {
        let alice_scalar: [u8; 48] = {
            let mut s = [0u8; 48];
            s[0] = 0x01;
            s[47] = 0x01;
            s
        };
        let bob_scalar: [u8; 48] = {
            let mut s = [0u8; 48];
            s[0] = 0x02;
            s[47] = 0x02;
            s
        };
        let (_alice_sk, alice_pk) = p384_keypair(&alice_scalar);
        let (_bob_sk, bob_pk) = p384_keypair(&bob_scalar);

        let kex = EcdhP384;
        let mut alice_shared = [0u8; 48];
        kex.agree(&alice_scalar, &bob_pk, &mut alice_shared)
            .expect("Alice ECDH-P384 agree failed");

        let mut bob_shared = [0u8; 48];
        kex.agree(&bob_scalar, &alice_pk, &mut bob_shared)
            .expect("Bob ECDH-P384 agree failed");

        assert_eq!(
            alice_shared, bob_shared,
            "ECDH-P384: Alice and Bob must derive the same shared secret"
        );
        assert_ne!(alice_shared, [0u8; 48]);
    }

    #[test]
    fn ecdh_p384_invalid_key() {
        let kex = EcdhP384;
        let mut shared = [0u8; 48];
        let result = kex.agree(&[0u8; 16], &[0u8; 49], &mut shared);
        assert_eq!(result, Err(CryptoError::InvalidKey));
    }

    /// Generate a P-384 keypair, run ECDH in both directions, verify secrets match.
    #[test]
    fn ecdh_p384_keygen_agree() {
        let mut rng = test_rng();
        let (alice_sk, alice_pk) =
            ecdh_p384_generate_keypair(&mut rng).expect("Alice P-384 keygen");
        let (bob_sk, bob_pk) = ecdh_p384_generate_keypair(&mut rng).expect("Bob P-384 keygen");

        let kex = EcdhP384;
        let mut alice_shared = [0u8; 48];
        kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
            .expect("Alice P-384 agree");

        let mut bob_shared = [0u8; 48];
        kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
            .expect("Bob P-384 agree");

        assert_eq!(
            alice_shared, bob_shared,
            "ecdh_p384_keygen_agree: secrets must match"
        );
        assert_ne!(alice_shared, [0u8; 48]);
    }

    // ── ECDH P-521 tests ─────────────────────────────────────────────────────

    fn p521_keypair_from_scalar(scalar_bytes: &[u8; 66]) -> (Vec<u8>, Vec<u8>) {
        let sk = p521::SecretKey::from_slice(scalar_bytes).expect("valid P-521 scalar");
        let pk = sk.public_key();
        (scalar_bytes.to_vec(), pk.to_sec1_bytes().to_vec())
    }

    /// Verify that two P-521 parties performing ECDH derive the same shared secret.
    #[test]
    fn ecdh_p521_both_parties_agree() {
        // Construct valid P-521 scalars: non-zero, well under the group order.
        // P-521 order ≈ 2^521; first byte 0x01 makes the value ≈ 2^520, valid.
        // We keep the first byte at 0x00 and use bytes further right so the
        // scalar is unambiguously small relative to the order.
        let alice_scalar: [u8; 66] = {
            let mut s = [0u8; 66];
            s[63] = 0xAB;
            s[64] = 0xCD;
            s[65] = 0x01;
            s
        };
        let bob_scalar: [u8; 66] = {
            let mut s = [0u8; 66];
            s[63] = 0x12;
            s[64] = 0x34;
            s[65] = 0x56;
            s
        };
        let (_alice_sk, alice_pk) = p521_keypair_from_scalar(&alice_scalar);
        let (_bob_sk, bob_pk) = p521_keypair_from_scalar(&bob_scalar);

        let kex = EcdhP521;
        let mut alice_shared = [0u8; 66];
        kex.agree(&alice_scalar, &bob_pk, &mut alice_shared)
            .expect("Alice ECDH-P521 agree failed");

        let mut bob_shared = [0u8; 66];
        kex.agree(&bob_scalar, &alice_pk, &mut bob_shared)
            .expect("Bob ECDH-P521 agree failed");

        assert_eq!(
            alice_shared, bob_shared,
            "ECDH-P521: Alice and Bob must derive the same shared secret"
        );
        assert_ne!(alice_shared, [0u8; 66]);
    }

    /// Verify that agree() returns BufferTooSmall when the output buffer is insufficient.
    #[test]
    fn ecdh_p521_buffer_too_small() {
        let alice_scalar: [u8; 66] = {
            let mut s = [0u8; 66];
            s[63] = 0xAB;
            s[64] = 0xCD;
            s[65] = 0x01;
            s
        };
        let (_alice_sk, alice_pk) = p521_keypair_from_scalar(&alice_scalar);
        let kex = EcdhP521;
        let mut shared = [0u8; 32]; // too small (need 66)
        let result = kex.agree(&alice_scalar, &alice_pk, &mut shared);
        assert_eq!(result, Err(CryptoError::BufferTooSmall));
    }

    /// Generate a P-521 keypair, run ECDH in both directions, verify secrets match.
    #[test]
    fn ecdh_p521_keygen_agree() {
        let mut rng = test_rng();
        let (alice_sk, alice_pk) =
            ecdh_p521_generate_keypair(&mut rng).expect("Alice P-521 keygen");
        let (bob_sk, bob_pk) = ecdh_p521_generate_keypair(&mut rng).expect("Bob P-521 keygen");

        let kex = EcdhP521;
        let mut alice_shared = [0u8; 66];
        kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
            .expect("Alice P-521 agree");

        let mut bob_shared = [0u8; 66];
        kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
            .expect("Bob P-521 agree");

        assert_eq!(
            alice_shared, bob_shared,
            "ecdh_p521_keygen_agree: secrets must match"
        );
        assert_ne!(alice_shared, [0u8; 66]);
    }

    // ── X448 tests ────────────────────────────────────────────────────────────

    /// Verify that two X448 parties using DH agree on the same shared secret.
    #[test]
    fn x448_both_parties_agree() {
        let kex = X448;
        let mut rng = test_rng();
        let (alice_sk, alice_pk) = x448_generate_keypair(&mut rng).expect("Alice X448 keygen");
        let (bob_sk, bob_pk) = x448_generate_keypair(&mut rng).expect("Bob X448 keygen");

        let mut alice_shared = [0u8; 56];
        kex.agree(alice_sk.as_bytes(), &bob_pk, &mut alice_shared)
            .expect("Alice X448 agree");

        let mut bob_shared = [0u8; 56];
        kex.agree(bob_sk.as_bytes(), &alice_pk, &mut bob_shared)
            .expect("Bob X448 agree");

        assert_eq!(
            alice_shared, bob_shared,
            "X448: Alice and Bob must derive the same shared secret"
        );
        assert_ne!(alice_shared, [0u8; 56]);
    }

    /// Verify X448 trait metadata.
    #[test]
    fn x448_metadata() {
        let kex = X448;
        assert_eq!(kex.name(), "X448");
        assert_eq!(kex.scalar_len(), 56);
        assert_eq!(kex.point_len(), 56);
        assert_eq!(kex.shared_secret_len(), 56);
    }

    /// Verify X448 agree_to_vec works correctly.
    #[test]
    fn x448_agree_to_vec_matches_agree() {
        let kex = X448;
        let mut rng = test_rng();
        let (alice_sk, _) = x448_generate_keypair(&mut rng).expect("Alice X448 keygen");
        let (_, bob_pk) = x448_generate_keypair(&mut rng).expect("Bob X448 keygen");

        let mut shared_fixed = [0u8; 56];
        kex.agree(alice_sk.as_bytes(), &bob_pk, &mut shared_fixed)
            .expect("agree failed");

        let shared_vec = kex
            .agree_to_vec(alice_sk.as_bytes(), &bob_pk)
            .expect("agree_to_vec failed");

        assert_eq!(shared_fixed.as_slice(), shared_vec.as_slice());
        assert_eq!(shared_vec.len(), 56);
    }

    /// Verify X448 rejects an invalid-length secret.
    #[test]
    fn x448_invalid_secret_length() {
        let kex = X448;
        let mut shared = [0u8; 56];
        let result = kex.agree(&[0u8; 32], &[5u8; 56], &mut shared);
        assert_eq!(result, Err(CryptoError::InvalidKey));
    }

    /// Verify X448 rejects a public key of invalid length.
    #[test]
    fn x448_invalid_public_length() {
        let kex = X448;
        let mut shared = [0u8; 56];
        // 32-byte public key is wrong length → InvalidKey (not Kex)
        let result = kex.agree(&[0u8; 56], &[5u8; 32], &mut shared);
        assert_eq!(result, Err(CryptoError::InvalidKey));
    }

    /// Verify X448 rejects a buffer that is too small.
    #[test]
    fn x448_buffer_too_small() {
        let kex = X448;
        let mut rng = test_rng();
        let (alice_sk, _) = x448_generate_keypair(&mut rng).expect("keygen");
        let (_, bob_pk) = x448_generate_keypair(&mut rng).expect("keygen");
        let mut shared = [0u8; 32];
        let result = kex.agree(alice_sk.as_bytes(), &bob_pk, &mut shared);
        assert_eq!(result, Err(CryptoError::BufferTooSmall));
    }

    /// Verify X448 rejects the all-zero low-order public key.
    #[test]
    fn x448_zero_public_key_rejection() {
        let kex = X448;
        let mut rng = test_rng();
        let (alice_sk, _) = x448_generate_keypair(&mut rng).expect("keygen");
        let zero_pk = [0u8; 56];
        let mut shared = [0u8; 56];
        let result = kex.agree(alice_sk.as_bytes(), &zero_pk, &mut shared);
        assert_eq!(
            result,
            Err(CryptoError::Kex),
            "X448 must reject all-zero (low-order) public key"
        );
    }
}
