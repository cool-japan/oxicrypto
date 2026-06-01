//! TLS 1.3 `HKDF-Expand-Label` (RFC 8446 §7.1).
//!
//! `HKDF-Expand-Label` wraps the bare `HKDF-Expand` (RFC 5869 §2.3) with the
//! structured `HkdfLabel` info parameter mandated by TLS 1.3 and reused by
//! QUIC (RFC 9001 §5.1/§5.2):
//!
//! ```text
//! struct {
//!     uint16 length = Length;
//!     opaque label<7..255> = "tls13 " + Label;
//!     opaque context<0..255> = Context;
//! } HkdfLabel;
//! ```
//!
//! The `"tls13 "` prefix is prepended to the caller-supplied `label` *inside*
//! the structure (so QUIC's `"client in"` becomes `"tls13 client in"` on the
//! wire). These helpers build that structure and drive the SHA-256 / SHA-384
//! HKDF expanders already provided by this crate.

use hkdf::Hkdf;
use oxicrypto_core::CryptoError;

/// Fixed TLS 1.3 label prefix from RFC 8446 §7.1.
const LABEL_PREFIX: &[u8] = b"tls13 ";

/// Maximum encoded `HkdfLabel` length.
///
/// `2` (length) + `1` (label length octet) + `255` (max label) + `1`
/// (context length octet) + `255` (max context) = `514`.
const MAX_HKDF_LABEL_LEN: usize = 2 + 1 + 255 + 1 + 255;

/// Serialize the TLS 1.3 `HkdfLabel` structure into `out`, returning the
/// number of bytes written.
///
/// `length` is the requested output length (the `okm` length the caller will
/// expand to). `label` is the bare label (without the `"tls13 "` prefix, which
/// is added here). `context` is the (possibly empty) context / hash input.
///
/// # Errors
/// Returns [`CryptoError::BadInput`] if the prefixed label exceeds 255 bytes,
/// the context exceeds 255 bytes, or `length` exceeds `u16::MAX`.
fn encode_hkdf_label<'a>(
    length: u16,
    label: &[u8],
    context: &[u8],
    out: &'a mut [u8; MAX_HKDF_LABEL_LEN],
) -> Result<&'a [u8], CryptoError> {
    let label_len = LABEL_PREFIX
        .len()
        .checked_add(label.len())
        .ok_or(CryptoError::BadInput)?;
    if label_len > 255 || context.len() > 255 {
        return Err(CryptoError::BadInput);
    }

    let mut pos = 0usize;
    // uint16 length (big-endian)
    out[pos] = (length >> 8) as u8;
    out[pos + 1] = (length & 0xff) as u8;
    pos += 2;
    // opaque label<7..255>: one length octet then "tls13 " + label
    out[pos] = label_len as u8;
    pos += 1;
    out[pos..pos + LABEL_PREFIX.len()].copy_from_slice(LABEL_PREFIX);
    pos += LABEL_PREFIX.len();
    out[pos..pos + label.len()].copy_from_slice(label);
    pos += label.len();
    // opaque context<0..255>: one length octet then context
    out[pos] = context.len() as u8;
    pos += 1;
    out[pos..pos + context.len()].copy_from_slice(context);
    pos += context.len();

    Ok(&out[..pos])
}

/// `HKDF-Expand-Label` with SHA-256 (RFC 8446 §7.1).
///
/// `prk` is a pre-extracted pseudorandom key (e.g. from
/// [`crate::hkdf_sha256_extract`]); 32 bytes for SHA-256-based secrets, though
/// any HKDF-SHA-256 PRK is accepted. The TLS 1.3 `HkdfLabel` is built from
/// `label` (prefixed with `"tls13 "`), `context`, and `okm_out.len()`, then
/// fed to `HKDF-Expand`.
///
/// # Errors
/// Returns [`CryptoError::BadInput`] for an empty output buffer, an output
/// longer than `u16::MAX`, or an over-long label/context. Returns
/// [`CryptoError::InvalidKey`] if `prk` is too short to be a SHA-256 PRK, and
/// [`CryptoError::Internal`] if the HKDF expansion fails.
pub fn hkdf_expand_label_sha256(
    prk: &[u8],
    label: &[u8],
    context: &[u8],
    okm_out: &mut [u8],
) -> Result<(), CryptoError> {
    if okm_out.is_empty() {
        return Err(CryptoError::BadInput);
    }
    let length = u16::try_from(okm_out.len()).map_err(|_| CryptoError::BadInput)?;
    let mut buf = [0u8; MAX_HKDF_LABEL_LEN];
    let info = encode_hkdf_label(length, label, context, &mut buf)?;

    let hk = Hkdf::<sha2::Sha256>::from_prk(prk).map_err(|_| CryptoError::InvalidKey)?;
    hk.expand(info, okm_out)
        .map_err(|_| CryptoError::Internal("HKDF-Expand-Label (SHA-256) failed"))?;
    Ok(())
}

/// `HKDF-Expand-Label` with SHA-384 (RFC 8446 §7.1).
///
/// `prk` is a pre-extracted pseudorandom key (e.g. from
/// [`crate::hkdf_sha384_extract`]); typically 48 bytes.
///
/// # Errors
/// Identical to [`hkdf_expand_label_sha256`].
pub fn hkdf_expand_label_sha384(
    prk: &[u8],
    label: &[u8],
    context: &[u8],
    okm_out: &mut [u8],
) -> Result<(), CryptoError> {
    if okm_out.is_empty() {
        return Err(CryptoError::BadInput);
    }
    let length = u16::try_from(okm_out.len()).map_err(|_| CryptoError::BadInput)?;
    let mut buf = [0u8; MAX_HKDF_LABEL_LEN];
    let info = encode_hkdf_label(length, label, context, &mut buf)?;

    let hk = Hkdf::<sha2::Sha384>::from_prk(prk).map_err(|_| CryptoError::InvalidKey)?;
    hk.expand(info, okm_out)
        .map_err(|_| CryptoError::Internal("HKDF-Expand-Label (SHA-384) failed"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hkdf_sha256_extract;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    // RFC 8446 §7.1 HkdfLabel encoding, checked byte-for-byte.
    // length=16, label="quic key" -> "tls13 quic key" (14 bytes), empty context.
    #[test]
    fn encode_hkdf_label_quic_key() {
        let mut buf = [0u8; MAX_HKDF_LABEL_LEN];
        let info = encode_hkdf_label(16, b"quic key", &[], &mut buf).expect("encode");
        // 00 10 | 0e | "tls13 quic key" | 00
        let mut expected = vec![0x00, 0x10, 0x0e];
        expected.extend_from_slice(b"tls13 quic key");
        expected.push(0x00);
        assert_eq!(info, &expected[..]);
    }

    #[test]
    fn encode_hkdf_label_with_context() {
        let mut buf = [0u8; MAX_HKDF_LABEL_LEN];
        let ctx = [0xaa, 0xbb, 0xcc];
        let info = encode_hkdf_label(32, b"derived", &ctx, &mut buf).expect("encode");
        let mut expected = vec![0x00, 0x20, b"tls13 derived".len() as u8];
        expected.extend_from_slice(b"tls13 derived");
        expected.push(0x03);
        expected.extend_from_slice(&ctx);
        assert_eq!(info, &expected[..]);
    }

    #[test]
    fn label_too_long_errors() {
        let mut buf = [0u8; MAX_HKDF_LABEL_LEN];
        let long = [b'x'; 250]; // 250 + 6 ("tls13 ") = 256 > 255
        assert_eq!(
            encode_hkdf_label(16, &long, &[], &mut buf),
            Err(CryptoError::BadInput)
        );
    }

    #[test]
    fn empty_output_errors() {
        let prk = [0u8; 32];
        assert_eq!(
            hkdf_expand_label_sha256(&prk, b"x", &[], &mut []),
            Err(CryptoError::BadInput)
        );
    }

    // RFC 9001 §A.1: derive the QUIC v1 client Initial secret and then the
    // client packet key / iv / hp, checking against the published vectors.
    // This exercises HKDF-Extract + HKDF-Expand-Label end to end.
    //
    // initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
    // DCID         = 0x8394c8f03e515708
    // initial_secret = HKDF-Extract(initial_salt, DCID)
    // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    #[test]
    fn rfc9001_a1_client_initial_keys() {
        let salt = hex_decode("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
        let dcid = hex_decode("8394c8f03e515708");

        let initial_secret = hkdf_sha256_extract(&salt, &dcid);
        // RFC 9001 A.1 initial_secret
        assert_eq!(
            initial_secret.to_vec(),
            hex_decode("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"),
            "initial_secret mismatch"
        );

        let mut client_secret = [0u8; 32];
        hkdf_expand_label_sha256(&initial_secret, b"client in", &[], &mut client_secret)
            .expect("client in");
        assert_eq!(
            client_secret.to_vec(),
            hex_decode("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"),
            "client_initial_secret mismatch"
        );

        // key = HKDF-Expand-Label(client_secret, "quic key", "", 16)
        let mut key = [0u8; 16];
        hkdf_expand_label_sha256(&client_secret, b"quic key", &[], &mut key).expect("quic key");
        assert_eq!(
            key.to_vec(),
            hex_decode("1f369613dd76d5467730efcbe3b1a22d"),
            "client quic key mismatch"
        );

        // iv = HKDF-Expand-Label(client_secret, "quic iv", "", 12)
        let mut iv = [0u8; 12];
        hkdf_expand_label_sha256(&client_secret, b"quic iv", &[], &mut iv).expect("quic iv");
        assert_eq!(
            iv.to_vec(),
            hex_decode("fa044b2f42a3fd3b46fb255c"),
            "client quic iv mismatch"
        );

        // hp = HKDF-Expand-Label(client_secret, "quic hp", "", 16)
        let mut hp = [0u8; 16];
        hkdf_expand_label_sha256(&client_secret, b"quic hp", &[], &mut hp).expect("quic hp");
        assert_eq!(
            hp.to_vec(),
            hex_decode("9f50449e04a0e810283a1e9933adedd2"),
            "client quic hp mismatch"
        );
    }

    // RFC 9001 §A.1: server Initial secret + key/iv/hp.
    #[test]
    fn rfc9001_a1_server_initial_keys() {
        let salt = hex_decode("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
        let dcid = hex_decode("8394c8f03e515708");
        let initial_secret = hkdf_sha256_extract(&salt, &dcid);

        let mut server_secret = [0u8; 32];
        hkdf_expand_label_sha256(&initial_secret, b"server in", &[], &mut server_secret)
            .expect("server in");
        assert_eq!(
            server_secret.to_vec(),
            hex_decode("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"),
            "server_initial_secret mismatch"
        );

        let mut key = [0u8; 16];
        hkdf_expand_label_sha256(&server_secret, b"quic key", &[], &mut key).expect("quic key");
        assert_eq!(
            key.to_vec(),
            hex_decode("cf3a5331653c364c88f0f379b6067e37"),
            "server quic key mismatch"
        );

        let mut iv = [0u8; 12];
        hkdf_expand_label_sha256(&server_secret, b"quic iv", &[], &mut iv).expect("quic iv");
        assert_eq!(
            iv.to_vec(),
            hex_decode("0ac1493ca1905853b0bba03e"),
            "server quic iv mismatch"
        );

        let mut hp = [0u8; 16];
        hkdf_expand_label_sha256(&server_secret, b"quic hp", &[], &mut hp).expect("quic hp");
        assert_eq!(
            hp.to_vec(),
            hex_decode("c206b8d9b9f0f37644430b490eeaa314"),
            "server quic hp mismatch"
        );
    }

    // SHA-384 sanity: HKDF-Expand-Label is deterministic and length-correct.
    #[test]
    fn hkdf_expand_label_sha384_deterministic() {
        let prk = crate::hkdf_sha384_extract(b"salt", b"ikm");
        let mut a = [0u8; 48];
        let mut b = [0u8; 48];
        hkdf_expand_label_sha384(&prk, b"derived", &[], &mut a).expect("a");
        hkdf_expand_label_sha384(&prk, b"derived", &[], &mut b).expect("b");
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 48]);
    }
}
