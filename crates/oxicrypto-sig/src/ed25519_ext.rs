#![forbid(unsafe_code)]

//! Ed25519ctx and Ed25519ph (pre-hash) signature variants per RFC 8032 §5.1.5–5.1.6.
//!
//! # Ed25519ctx
//!
//! Ed25519ctx (RFC 8032 §5.1.5) is the "context" variant of Ed25519. It signs
//! over `dom2(0, ctx) ‖ message`, where:
//!
//! ```text
//! dom2(phflag, ctx) = "SigEd25519 no Ed25519 collisions" ‖ 0x00 ‖ phflag ‖ len(ctx) ‖ ctx
//! ```
//!
//! - `phflag = 0` for Ed25519ctx (not prehashed)
//! - `ctx` is the context string, 0–255 bytes, providing protocol-level domain separation
//!
//! # Ed25519ph
//!
//! Ed25519ph (RFC 8032 §5.1.6) is the "prehash" variant. It signs over
//! `dom2(1, ctx) ‖ SHA-512(message)`, where `phflag = 1`. The message is
//! pre-hashed with SHA-512 before signing, allowing streaming of large messages.
//!
//! # Architecture note
//!
//! This implementation uses the `curve25519-dalek 4.x` group primitives and
//! SHA-512 directly, bypassing `ed25519-dalek`'s `sign_prehashed`/`with_context`
//! APIs which are gated behind the `digest` feature on `digest 0.10` — a version
//! incompatible with the workspace's `digest 0.11` chain. The underlying Ed25519
//! arithmetic follows RFC 8032 §5.1 exactly.
//!
//! RFC reference: <https://www.rfc-editor.org/rfc/rfc8032.html>

use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::clamp_integer, EdwardsPoint, Scalar};
use oxicrypto_core::{CryptoError, Vec};
use sha2::{Digest, Sha512};

// ── dom2 helper ───────────────────────────────────────────────────────────────

/// Construct `dom2(phflag, ctx)` per RFC 8032 §5.1.
///
/// ```text
/// dom2(x, y) = "SigEd25519 no Ed25519 collisions" ‖ octet(x) ‖ octet(OLEN(y)) ‖ y
/// ```
///
/// where `x` is 0 for Ed25519ctx and 1 for Ed25519ph.
/// `y` is the context, at most 255 bytes.
fn dom2(phflag: u8, ctx: &[u8]) -> Vec<u8> {
    // The DOM_PREFIX is defined in RFC 8032 §5.1.5 as this exact ASCII string.
    const DOM_PREFIX: &[u8] = b"SigEd25519 no Ed25519 collisions";
    // ctx.len() <= 255 is enforced by callers.
    let ctx_len = ctx.len() as u8;
    let mut out = Vec::with_capacity(DOM_PREFIX.len() + 2 + ctx.len());
    out.extend_from_slice(DOM_PREFIX);
    out.push(phflag);
    out.push(ctx_len);
    out.extend_from_slice(ctx);
    out
}

// ── key expansion ─────────────────────────────────────────────────────────────

/// Expand a 32-byte Ed25519 seed into `(scalar, nonce_prefix)`.
///
/// Follows RFC 8032 §5.1.5:
/// 1. Compute `h = SHA-512(seed)` (64 bytes)
/// 2. Scalar bytes = first 32 bytes of `h`, clamped to the Ed25519 scalar format
/// 3. Nonce prefix = last 32 bytes of `h`
fn expand_seed(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let h: [u8; 64] = Sha512::digest(seed).into();
    // clamp_integer clears/sets the co-factor and high bits per RFC 8032 §5.1.5.
    let scalar_bytes: [u8; 32] =
        clamp_integer(h[..32].try_into().expect("infallible 32-byte slice"));
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h[32..]);
    (scalar, prefix)
}

// ── Ed25519ctx ────────────────────────────────────────────────────────────────

/// Sign `message` using Ed25519ctx per RFC 8032 §5.1.5.
///
/// `sk` must be 32 bytes (the raw seed). `context` is 0–255 bytes providing
/// protocol-level domain separation. Returns a 64-byte signature.
///
/// Ed25519ctx differs from plain Ed25519 in that signatures include a domain-
/// separation prefix `dom2(0, ctx)`, preventing cross-protocol signature reuse.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] if `sk.len() != 32`.
/// Returns [`CryptoError::BadInput`] if `context.len() > 255`.
#[must_use = "signature result must be checked"]
pub fn ed25519ctx_sign(sk: &[u8], message: &[u8], context: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if context.len() > 255 {
        return Err(CryptoError::BadInput);
    }
    let seed: &[u8; 32] = sk.try_into().map_err(|_| CryptoError::InvalidKey)?;

    let (scalar_s, nonce_prefix) = expand_seed(seed);

    // Public key A = s·B
    let public_key_point = EdwardsPoint::mul_base(&scalar_s);
    let pk_bytes = public_key_point.compress().to_bytes();

    // Nonce r = SHA-512(dom2(0, ctx) ‖ nonce_prefix ‖ message) mod ℓ
    let dom = dom2(0, context);
    let r_hash: [u8; 64] = {
        let mut h = Sha512::new();
        Digest::update(&mut h, dom.as_slice());
        Digest::update(&mut h, nonce_prefix.as_ref());
        Digest::update(&mut h, message);
        Sha512::finalize(h).into()
    };
    let r = Scalar::from_bytes_mod_order_wide(&r_hash);

    // R = r·B
    let r_point = EdwardsPoint::mul_base(&r);
    let r_bytes = r_point.compress().to_bytes();

    // Challenge k = SHA-512(dom2(0, ctx) ‖ R ‖ A ‖ message) mod ℓ
    let k_hash: [u8; 64] = {
        let mut h = Sha512::new();
        Digest::update(&mut h, dom.as_slice());
        Digest::update(&mut h, r_bytes.as_ref());
        Digest::update(&mut h, pk_bytes.as_ref());
        Digest::update(&mut h, message);
        Sha512::finalize(h).into()
    };
    let k = Scalar::from_bytes_mod_order_wide(&k_hash);

    // s = r + k · scalar_s  (mod ℓ)
    let s = r + k * scalar_s;
    let s_bytes = s.to_bytes();

    // Signature = R ‖ s (64 bytes)
    let mut sig = Vec::with_capacity(64);
    sig.extend_from_slice(&r_bytes);
    sig.extend_from_slice(&s_bytes);
    Ok(sig)
}

/// Verify an Ed25519ctx signature per RFC 8032 §5.1.5.
///
/// `pk` must be 32 bytes (compressed Edwards-y public key).
/// `sig` must be 64 bytes.
/// `context` must match what was used during signing.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] on malformed public key.
/// Returns [`CryptoError::InvalidTag`] on malformed or invalid signature.
/// Returns [`CryptoError::BadInput`] if `context.len() > 255`.
#[must_use = "verification result must be checked"]
pub fn ed25519ctx_verify(
    pk: &[u8],
    message: &[u8],
    sig: &[u8],
    context: &[u8],
) -> Result<(), CryptoError> {
    if context.len() > 255 {
        return Err(CryptoError::BadInput);
    }
    verify_ed25519_variant(pk, message, sig, context, false)
}

// ── Ed25519ph ─────────────────────────────────────────────────────────────────

/// Sign `message` using Ed25519ph (prehash) per RFC 8032 §5.1.6.
///
/// `sk` must be 32 bytes (the raw seed). `context` is 0–255 bytes (may be
/// empty). Returns a 64-byte signature.
///
/// Internally the message is pre-hashed with SHA-512 before signing:
/// `ph_message = SHA-512(message)`, then the signature computation uses
/// `dom2(1, ctx) ‖ ph_message`. This is useful for large messages where
/// the message can be streamed and hashed independently.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] if `sk.len() != 32`.
/// Returns [`CryptoError::BadInput`] if `context.len() > 255`.
#[must_use = "signature result must be checked"]
pub fn ed25519ph_sign(sk: &[u8], message: &[u8], context: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if context.len() > 255 {
        return Err(CryptoError::BadInput);
    }
    // Pre-hash the message with SHA-512
    let ph_message: [u8; 64] = Sha512::digest(message).into();
    sign_ed25519_variant(sk, &ph_message, context, true)
}

/// Sign over an already-prehashed message digest using Ed25519ph.
///
/// `sk` must be 32 bytes. `prehash` must be 64 bytes (the SHA-512 digest of
/// the message). `context` is 0–255 bytes (may be empty).
///
/// Use this when you have already computed the SHA-512 digest externally (e.g.,
/// when hashing a large streaming message). The result is identical to
/// [`ed25519ph_sign`] when `prehash = SHA-512(message)`.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] if `sk.len() != 32`.
/// Returns [`CryptoError::BadInput`] if `context.len() > 255` or `prehash.len() != 64`.
#[must_use = "signature result must be checked"]
pub fn ed25519ph_sign_prehash(
    sk: &[u8],
    prehash: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if context.len() > 255 {
        return Err(CryptoError::BadInput);
    }
    if prehash.len() != 64 {
        return Err(CryptoError::BadInput);
    }
    sign_ed25519_variant(sk, prehash, context, true)
}

/// Verify an Ed25519ph signature per RFC 8032 §5.1.6.
///
/// `pk` must be 32 bytes. `sig` must be 64 bytes. `context` must match.
///
/// The `message` is automatically pre-hashed with SHA-512 before verification,
/// mirroring [`ed25519ph_sign`].
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] on malformed public key.
/// Returns [`CryptoError::InvalidTag`] on malformed or invalid signature.
/// Returns [`CryptoError::BadInput`] if `context.len() > 255`.
#[must_use = "verification result must be checked"]
pub fn ed25519ph_verify(
    pk: &[u8],
    message: &[u8],
    sig: &[u8],
    context: &[u8],
) -> Result<(), CryptoError> {
    if context.len() > 255 {
        return Err(CryptoError::BadInput);
    }
    // Pre-hash the message
    let ph_message: [u8; 64] = Sha512::digest(message).into();
    verify_ed25519_variant(pk, &ph_message, sig, context, true)
}

/// Verify an Ed25519ph signature over an already-prehashed digest.
///
/// `pk` must be 32 bytes. `prehash` must be 64 bytes. `sig` must be 64 bytes.
/// `context` must match what was used during signing.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] on malformed public key.
/// Returns [`CryptoError::InvalidTag`] on malformed or invalid signature.
/// Returns [`CryptoError::BadInput`] if `context.len() > 255` or `prehash.len() != 64`.
#[must_use = "verification result must be checked"]
pub fn ed25519ph_verify_prehash(
    pk: &[u8],
    prehash: &[u8],
    sig: &[u8],
    context: &[u8],
) -> Result<(), CryptoError> {
    if context.len() > 255 {
        return Err(CryptoError::BadInput);
    }
    if prehash.len() != 64 {
        return Err(CryptoError::BadInput);
    }
    verify_ed25519_variant(pk, prehash, sig, context, true)
}

// ── Shared sign / verify core ─────────────────────────────────────────────────

/// Core sign operation for both Ed25519ctx and Ed25519ph.
///
/// `phflag`: `false` for Ed25519ctx (message is plaintext), `true` for Ed25519ph
/// (message is the SHA-512 prehash).
fn sign_ed25519_variant(
    sk: &[u8],
    msg_or_prehash: &[u8],
    context: &[u8],
    phflag: bool,
) -> Result<Vec<u8>, CryptoError> {
    let seed: &[u8; 32] = sk.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let flag_byte: u8 = if phflag { 1 } else { 0 };

    let (scalar_s, nonce_prefix) = expand_seed(seed);
    let public_key_point = EdwardsPoint::mul_base(&scalar_s);
    let pk_bytes = public_key_point.compress().to_bytes();

    let dom = dom2(flag_byte, context);

    // r = SHA-512(dom2 ‖ nonce_prefix ‖ msg_or_prehash) mod ℓ
    let r_hash: [u8; 64] = {
        let mut h = Sha512::new();
        Digest::update(&mut h, dom.as_slice());
        Digest::update(&mut h, nonce_prefix.as_ref());
        Digest::update(&mut h, msg_or_prehash);
        Sha512::finalize(h).into()
    };
    let r = Scalar::from_bytes_mod_order_wide(&r_hash);

    // R = r·B
    let r_point = EdwardsPoint::mul_base(&r);
    let r_bytes = r_point.compress().to_bytes();

    // k = SHA-512(dom2 ‖ R ‖ A ‖ msg_or_prehash) mod ℓ
    let k_hash: [u8; 64] = {
        let mut h = Sha512::new();
        Digest::update(&mut h, dom.as_slice());
        Digest::update(&mut h, r_bytes.as_ref());
        Digest::update(&mut h, pk_bytes.as_ref());
        Digest::update(&mut h, msg_or_prehash);
        Sha512::finalize(h).into()
    };
    let k = Scalar::from_bytes_mod_order_wide(&k_hash);

    // s = r + k · scalar_s  (mod ℓ)
    let s = r + k * scalar_s;

    let mut sig = Vec::with_capacity(64);
    sig.extend_from_slice(&r_bytes);
    sig.extend_from_slice(&s.to_bytes());
    Ok(sig)
}

/// Core verify operation for both Ed25519ctx and Ed25519ph.
///
/// `phflag`: `false` for Ed25519ctx, `true` for Ed25519ph.
fn verify_ed25519_variant(
    pk: &[u8],
    msg_or_prehash: &[u8],
    sig: &[u8],
    context: &[u8],
    phflag: bool,
) -> Result<(), CryptoError> {
    let flag_byte: u8 = if phflag { 1 } else { 0 };

    // Parse public key
    let pk_arr: &[u8; 32] = pk.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let a_compressed =
        CompressedEdwardsY::from_slice(pk_arr).map_err(|_| CryptoError::InvalidKey)?;
    let a_point = a_compressed.decompress().ok_or(CryptoError::InvalidKey)?;

    // Parse signature: R (32 bytes) ‖ s (32 bytes)
    if sig.len() != 64 {
        return Err(CryptoError::InvalidTag);
    }
    let r_bytes: [u8; 32] = sig[..32].try_into().map_err(|_| CryptoError::InvalidTag)?;
    let s_bytes: [u8; 32] = sig[32..].try_into().map_err(|_| CryptoError::InvalidTag)?;

    let r_compressed =
        CompressedEdwardsY::from_slice(&r_bytes).map_err(|_| CryptoError::InvalidTag)?;
    let r_point = r_compressed.decompress().ok_or(CryptoError::InvalidTag)?;

    // Reject non-canonical s: must be < group order ℓ
    let s = Scalar::from_canonical_bytes(s_bytes)
        .into_option()
        .ok_or(CryptoError::InvalidTag)?;

    let dom = dom2(flag_byte, context);

    // k = SHA-512(dom2 ‖ R ‖ A ‖ msg_or_prehash) mod ℓ
    let k_hash: [u8; 64] = {
        let mut h = Sha512::new();
        Digest::update(&mut h, dom.as_slice());
        Digest::update(&mut h, r_bytes.as_ref());
        Digest::update(&mut h, pk_arr.as_ref());
        Digest::update(&mut h, msg_or_prehash);
        Sha512::finalize(h).into()
    };
    let k = Scalar::from_bytes_mod_order_wide(&k_hash);

    // Verify: s·B == R + k·A  (RFC 8032 §5.1.7 check equation)
    let check_point = r_point + k * a_point;
    let lhs = EdwardsPoint::mul_base(&s);

    // Use compressed coordinates for equality (avoids timing issues with point repr)
    if lhs.compress() != check_point.compress() {
        return Err(CryptoError::InvalidTag);
    }

    // Cofactor check: reject small-subgroup points in R (R must be in the prime-order subgroup)
    // RFC 8032 §5.1.7 final check: 8·s·B == 8·R + k·8·A.
    // Since s is canonical (checked above) and we do the full equation check,
    // the comparison above is sufficient. Additionally verify R is not a low-order point.
    let r_order_check = r_point.mul_by_cofactor();
    if r_order_check == curve25519_dalek::traits::Identity::identity() {
        // R is a torsion point → reject
        return Err(CryptoError::InvalidTag);
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Derive the public key from a 32-byte seed using our Ed25519 scalar expansion.
    fn pubkey_from_seed(seed: &[u8; 32]) -> [u8; 32] {
        let (scalar, _) = expand_seed(seed);
        EdwardsPoint::mul_base(&scalar).compress().to_bytes()
    }

    // ── Ed25519ctx round-trip ─────────────────────────────────────────────────

    #[test]
    fn ed25519ctx_sign_verify_round_trip() {
        let seed = [0x5au8; 32];
        let pk = pubkey_from_seed(&seed);
        let ctx = b"test-protocol-v1";
        let msg = b"hello Ed25519ctx";

        let sig = ed25519ctx_sign(&seed, msg, ctx).expect("ctx sign failed");
        assert_eq!(sig.len(), 64);

        ed25519ctx_verify(&pk, msg, &sig, ctx).expect("ctx verify should succeed");
    }

    #[test]
    fn ed25519ctx_wrong_context_fails() {
        let seed = [0x7bu8; 32];
        let pk = pubkey_from_seed(&seed);
        let msg = b"domain separated";

        let sig = ed25519ctx_sign(&seed, msg, b"ctx-a").expect("sign");
        let result = ed25519ctx_verify(&pk, msg, &sig, b"ctx-b");
        assert!(result.is_err(), "different context must fail verification");
    }

    #[test]
    fn ed25519ctx_empty_context_allowed() {
        let seed = [0x11u8; 32];
        let pk = pubkey_from_seed(&seed);
        let msg = b"empty context test";

        let sig = ed25519ctx_sign(&seed, msg, b"").expect("sign with empty ctx");
        ed25519ctx_verify(&pk, msg, &sig, b"").expect("verify with empty ctx");
    }

    #[test]
    fn ed25519ctx_corrupted_sig_fails() {
        let seed = [0x22u8; 32];
        let pk = pubkey_from_seed(&seed);
        let ctx = b"corruption-test";
        let msg = b"message to corrupt";

        let mut sig = ed25519ctx_sign(&seed, msg, ctx).expect("sign");
        sig[0] ^= 0xff; // corrupt R component

        assert!(
            ed25519ctx_verify(&pk, msg, &sig, ctx).is_err(),
            "corrupted sig must fail"
        );
    }

    #[test]
    fn ed25519ctx_wrong_message_fails() {
        let seed = [0x33u8; 32];
        let pk = pubkey_from_seed(&seed);
        let ctx = b"protocol";
        let msg = b"original message";
        let other = b"different message";

        let sig = ed25519ctx_sign(&seed, msg, ctx).expect("sign");
        assert!(
            ed25519ctx_verify(&pk, other, &sig, ctx).is_err(),
            "wrong message must fail"
        );
    }

    #[test]
    fn ed25519ctx_context_too_long_rejected() {
        let seed = [0x44u8; 32];
        let ctx = [0xffu8; 256]; // 256 bytes — exceeds max 255
        let result = ed25519ctx_sign(&seed, b"msg", &ctx);
        assert_eq!(result, Err(CryptoError::BadInput));
    }

    #[test]
    fn ed25519ctx_invalid_key_length_rejected() {
        let result = ed25519ctx_sign(&[0u8; 16], b"msg", b"ctx");
        assert_eq!(result, Err(CryptoError::InvalidKey));
    }

    #[test]
    fn ed25519ctx_deterministic() {
        // Same inputs must always produce the same signature (no randomness in sign).
        let seed = [0x55u8; 32];
        let ctx = b"determinism";
        let msg = b"deterministic test";

        let sig1 = ed25519ctx_sign(&seed, msg, ctx).expect("sign 1");
        let sig2 = ed25519ctx_sign(&seed, msg, ctx).expect("sign 2");
        assert_eq!(sig1, sig2, "Ed25519ctx must be deterministic");
    }

    // ── Ed25519ph round-trip ──────────────────────────────────────────────────

    #[test]
    fn ed25519ph_sign_verify_round_trip() {
        let seed = [0x66u8; 32];
        let pk = pubkey_from_seed(&seed);
        let ctx = b"prehash-protocol";
        let msg = b"hello Ed25519ph - long message that benefits from prehashing";

        let sig = ed25519ph_sign(&seed, msg, ctx).expect("ph sign failed");
        assert_eq!(sig.len(), 64);

        ed25519ph_verify(&pk, msg, &sig, ctx).expect("ph verify should succeed");
    }

    #[test]
    fn ed25519ph_empty_context_allowed() {
        let seed = [0x77u8; 32];
        let pk = pubkey_from_seed(&seed);
        let msg = b"prehash with empty context";

        let sig = ed25519ph_sign(&seed, msg, b"").expect("sign");
        ed25519ph_verify(&pk, msg, &sig, b"").expect("verify");
    }

    #[test]
    fn ed25519ph_wrong_context_fails() {
        let seed = [0x88u8; 32];
        let pk = pubkey_from_seed(&seed);
        let msg = b"prehash domain separation";

        let sig = ed25519ph_sign(&seed, msg, b"ctx-a").expect("sign");
        let result = ed25519ph_verify(&pk, msg, &sig, b"ctx-b");
        assert!(result.is_err(), "different context must fail");
    }

    #[test]
    fn ed25519ph_corrupted_sig_fails() {
        let seed = [0x99u8; 32];
        let pk = pubkey_from_seed(&seed);
        let ctx = b"ph-corruption-test";
        let msg = b"message to corrupt in prehash";

        let mut sig = ed25519ph_sign(&seed, msg, ctx).expect("sign");
        sig[32] ^= 0x01; // corrupt s component
        assert!(
            ed25519ph_verify(&pk, msg, &sig, ctx).is_err(),
            "corrupted s must fail"
        );
    }

    #[test]
    fn ed25519ph_prehash_api_matches_sign_api() {
        // ed25519ph_sign_prehash(seed, SHA-512(msg), ctx) must equal ed25519ph_sign(seed, msg, ctx)
        let seed = [0xaau8; 32];
        let ctx = b"prehash-api-test";
        let msg = b"API consistency check";

        let prehash: [u8; 64] = Sha512::digest(msg).into();
        let sig1 = ed25519ph_sign(&seed, msg, ctx).expect("sign via msg");
        let sig2 = ed25519ph_sign_prehash(&seed, &prehash, ctx).expect("sign via prehash");
        assert_eq!(sig1, sig2, "both APIs must produce identical signatures");
    }

    #[test]
    fn ed25519ph_verify_prehash_api_matches_verify_api() {
        let seed = [0xbbu8; 32];
        let pk = pubkey_from_seed(&seed);
        let ctx = b"verify-api-test";
        let msg = b"verify API consistency";

        let prehash: [u8; 64] = Sha512::digest(msg).into();
        let sig = ed25519ph_sign(&seed, msg, ctx).expect("sign");

        ed25519ph_verify(&pk, msg, &sig, ctx).expect("verify via msg");
        ed25519ph_verify_prehash(&pk, &prehash, &sig, ctx).expect("verify via prehash");
    }

    #[test]
    fn ed25519ph_different_from_ed25519ctx() {
        // Ed25519ctx(phflag=0) and Ed25519ph(phflag=1) must produce different sigs for same inputs.
        let seed = [0xccu8; 32];
        let ctx = b"same-ctx";
        let msg = b"same message";

        let sig_ctx = ed25519ctx_sign(&seed, msg, ctx).expect("ctx sign");
        let sig_ph = ed25519ph_sign(&seed, msg, ctx).expect("ph sign");
        assert_ne!(
            sig_ctx, sig_ph,
            "ctx and ph must produce different signatures"
        );
    }

    #[test]
    fn ed25519ctx_different_from_plain_ed25519() {
        // Ed25519ctx signatures (with dom2 prefix) must not verify as plain Ed25519.
        let seed = [0xddu8; 32];
        let ctx = b"ctx-for-separation-test";
        let msg = b"domain separation must work";

        let sig_ctx = ed25519ctx_sign(&seed, msg, ctx).expect("ctx sign");

        // Plain Ed25519 verification via ed25519-dalek must reject Ed25519ctx signatures.
        let signing_key = SigningKey::from_bytes(&seed);
        let pk = signing_key.verifying_key();
        let result = pk.verify_strict(
            msg,
            &ed25519_dalek::Signature::from_slice(&sig_ctx).expect("parse sig"),
        );
        // Ed25519ctx sigs (with dom2) must NOT verify under plain Ed25519.
        assert!(
            result.is_err(),
            "Ed25519ctx sig must not verify under plain Ed25519"
        );
    }

    #[test]
    fn ed25519ph_deterministic() {
        let seed = [0xeeu8; 32];
        let ctx = b"ph-det";
        let msg = b"deterministic prehash";

        let sig1 = ed25519ph_sign(&seed, msg, ctx).expect("sign 1");
        let sig2 = ed25519ph_sign(&seed, msg, ctx).expect("sign 2");
        assert_eq!(sig1, sig2, "Ed25519ph must be deterministic");
    }

    #[test]
    fn ed25519ctx_max_context_length() {
        let seed = [0x01u8; 32];
        let pk = pubkey_from_seed(&seed);
        let ctx = [0x42u8; 255]; // exactly 255 bytes — maximum allowed
        let msg = b"max context test";

        let sig = ed25519ctx_sign(&seed, msg, &ctx).expect("sign with 255-byte ctx");
        ed25519ctx_verify(&pk, msg, &sig, &ctx).expect("verify with 255-byte ctx");
    }
}
