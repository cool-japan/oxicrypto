//! `rustls` `SigningKey` implementation backed by a PKCS#11 HSM session.
//!
//! This module is only compiled when the `tls` feature is enabled, which
//! pulls in the `rustls` crate.
//!
//! # Overview
//!
//! [`Pkcs11TlsSigningKey`] implements [`rustls::sign::SigningKey`], routing
//! each TLS signature operation through a live PKCS#11 session via the
//! `cryptoki` crate.  The private key never leaves the HSM.
//!
//! Supported `SignatureScheme` values:
//!
//! | Scheme | Mechanism |
//! |--------|-----------|
//! | `ECDSA_NISTP256_SHA256` | `CKM_ECDSA_SHA256` |
//! | `ECDSA_NISTP384_SHA384` | `CKM_ECDSA_SHA384` |
//! | `RSA_PKCS1_SHA256` | `CKM_SHA256_RSA_PKCS` |
//! | `RSA_PKCS1_SHA384` | `CKM_SHA384_RSA_PKCS` |
//! | `RSA_PKCS1_SHA512` | `CKM_SHA512_RSA_PKCS` |
//! | `RSA_PSS_SHA256` | `CKM_SHA256_RSA_PKCS_PSS` |
//! | `RSA_PSS_SHA384` | `CKM_SHA384_RSA_PKCS_PSS` |
//! | `RSA_PSS_SHA512` | `CKM_SHA512_RSA_PKCS_PSS` |
//!
//! # Usage
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use oxicrypto_adapter_pkcs11::provider::Pkcs11Provider;
//! # use oxicrypto_adapter_pkcs11::tls::Pkcs11TlsSigningKey;
//! # fn example(provider: Arc<Pkcs11Provider>) {
//! let signing_key = Pkcs11TlsSigningKey::new_ecdsa(provider, "my-ecdsa-key")
//!     .expect("signing key");
//! // Pass `signing_key` to a `rustls::ServerConfig` builder.
//! # let _ = signing_key;
//! # }
//! ```
//!
//! # ECDSA DER encoding
//!
//! Many PKCS#11 tokens return ECDSA signatures as raw concatenated r||s bytes.
//! `rustls` requires DER-encoded ECDSA signatures.  This module detects raw
//! format (first byte ≠ `0x30`) and converts via a minimal hand-written
//! ASN.1 encoder.  If the token already returns DER the conversion is skipped.

use std::sync::Arc;

use cryptoki::{
    mechanism::{
        rsa::{PkcsMgfType, PkcsPssParams},
        Mechanism, MechanismType,
    },
    object::ObjectHandle,
};
use rustls::{Error as RustlsError, SignatureAlgorithm, SignatureScheme};

use crate::provider::{Pkcs11Provider, PkcsError};

// ---------------------------------------------------------------------------
// ECDSA raw r||s → DER conversion
// ---------------------------------------------------------------------------

/// Convert a raw r||s ECDSA signature to DER/ASN.1 SEQUENCE format.
///
/// `rustls` requires DER-encoded ECDSA signatures, but many HSMs produce raw
/// concatenated r||s bytes.  If the token already returns DER (first byte is
/// `0x30`) the caller should skip this function.
///
/// # Format
///
/// ```text
/// SEQUENCE {
///   INTEGER r,
///   INTEGER s,
/// }
/// ```
///
/// Each component has a `0x00` leading byte prepended if the high bit is set
/// (to preserve the unsigned representation in DER).
fn raw_ecdsa_to_der(raw: &[u8]) -> Result<Vec<u8>, RustlsError> {
    if !raw.len().is_multiple_of(2) || raw.is_empty() {
        return Err(RustlsError::General(format!(
            "pkcs11 tls: raw ECDSA signature has odd/zero length: {}",
            raw.len()
        )));
    }
    let half = raw.len() / 2;
    let r = &raw[..half];
    let s = &raw[half..];

    fn encode_int(v: &[u8]) -> Vec<u8> {
        // Strip leading zeros but keep at least one byte.
        let trimmed =
            v.iter().position(|&b| b != 0).map_or(
                1,
                |p| {
                    if p == v.len() {
                        v.len() - 1
                    } else {
                        p
                    }
                },
            );
        let v = &v[trimmed..];
        let needs_pad = v.first().copied().unwrap_or(0) >= 0x80;
        let content_len = v.len() + usize::from(needs_pad);
        let mut enc = Vec::with_capacity(2 + content_len);
        enc.push(0x02); // INTEGER tag
        enc.push(content_len as u8);
        if needs_pad {
            enc.push(0x00);
        }
        enc.extend_from_slice(v);
        enc
    }

    let r_enc = encode_int(r);
    let s_enc = encode_int(s);
    let seq_len = r_enc.len() + s_enc.len();

    if seq_len > 0xFF {
        return Err(RustlsError::General(
            "pkcs11 tls: DER SEQUENCE length overflow".to_string(),
        ));
    }

    let mut der = Vec::with_capacity(2 + seq_len);
    der.push(0x30); // SEQUENCE tag
    der.push(seq_len as u8);
    der.extend_from_slice(&r_enc);
    der.extend_from_slice(&s_enc);
    Ok(der)
}

// ---------------------------------------------------------------------------
// scheme_to_mechanism
// ---------------------------------------------------------------------------

/// Map a rustls `SignatureScheme` to the corresponding `cryptoki::Mechanism`.
///
/// # Errors
/// Returns an error string for any scheme not listed in the supported table.
fn scheme_to_mechanism(scheme: SignatureScheme) -> Result<Mechanism<'static>, String> {
    match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => Ok(Mechanism::EcdsaSha256),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Ok(Mechanism::EcdsaSha384),
        SignatureScheme::RSA_PKCS1_SHA256 => Ok(Mechanism::Sha256RsaPkcs),
        SignatureScheme::RSA_PKCS1_SHA384 => Ok(Mechanism::Sha384RsaPkcs),
        SignatureScheme::RSA_PKCS1_SHA512 => Ok(Mechanism::Sha512RsaPkcs),
        SignatureScheme::RSA_PSS_SHA256 => Ok(Mechanism::RsaPkcsPss(PkcsPssParams {
            hash_alg: MechanismType::SHA256,
            mgf: PkcsMgfType::MGF1_SHA256,
            s_len: 32_u64.into(),
        })),
        SignatureScheme::RSA_PSS_SHA384 => Ok(Mechanism::RsaPkcsPss(PkcsPssParams {
            hash_alg: MechanismType::SHA384,
            mgf: PkcsMgfType::MGF1_SHA384,
            s_len: 48_u64.into(),
        })),
        SignatureScheme::RSA_PSS_SHA512 => Ok(Mechanism::RsaPkcsPss(PkcsPssParams {
            hash_alg: MechanismType::SHA512,
            mgf: PkcsMgfType::MGF1_SHA512,
            s_len: 64_u64.into(),
        })),
        other => Err(format!(
            "pkcs11 tls: unsupported SignatureScheme: {other:?}"
        )),
    }
}

// ---------------------------------------------------------------------------
// Preferred schemes per key algorithm
// ---------------------------------------------------------------------------

/// Return the ordered list of `SignatureScheme`s to try for a given algorithm.
fn preferred_schemes(algorithm: SignatureAlgorithm) -> &'static [SignatureScheme] {
    match algorithm {
        SignatureAlgorithm::ECDSA => &[
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ],
        SignatureAlgorithm::RSA => &[
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ],
        _ => &[],
    }
}

// ---------------------------------------------------------------------------
// Pkcs11TlsSigner (per-signature, implements rustls::sign::Signer)
// ---------------------------------------------------------------------------

/// A single-use [`rustls::sign::Signer`] backed by a PKCS#11 session.
///
/// Created by `Pkcs11TlsSigningKey::choose_scheme` (via [`rustls::sign::SigningKey`]) and discarded after one
/// signature operation.  The signing key handle and mechanism are fixed at
/// construction.
#[derive(Debug)]
pub struct Pkcs11TlsSigner {
    provider: Arc<Pkcs11Provider>,
    key_handle: ObjectHandle,
    scheme: SignatureScheme,
}

impl Pkcs11TlsSigner {
    fn new(
        provider: Arc<Pkcs11Provider>,
        key_handle: ObjectHandle,
        scheme: SignatureScheme,
    ) -> Self {
        Self {
            provider,
            key_handle,
            scheme,
        }
    }
}

impl rustls::sign::Signer for Pkcs11TlsSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        let mechanism = scheme_to_mechanism(self.scheme).map_err(RustlsError::General)?;

        let raw_sig = self
            .provider
            .with_session(|session| session.sign(&mechanism, self.key_handle, message))
            .map_err(|e: PkcsError| RustlsError::General(e.to_string()))?;

        // ECDSA: convert raw r||s → DER if needed.
        match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 | SignatureScheme::ECDSA_NISTP384_SHA384 => {
                if raw_sig.first().copied() == Some(0x30) {
                    // Already DER-encoded.
                    Ok(raw_sig)
                } else {
                    raw_ecdsa_to_der(&raw_sig)
                }
            }
            // RSA: no encoding conversion needed.
            _ => Ok(raw_sig),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

// ---------------------------------------------------------------------------
// Pkcs11TlsSigningKey (implements rustls::sign::SigningKey)
// ---------------------------------------------------------------------------

/// A PKCS#11-backed [`rustls::sign::SigningKey`] for use in TLS server or
/// client configurations.
///
/// The private key is identified by a `CKA_LABEL` string on the HSM token.
/// The key material never leaves the HSM — only signature bytes cross the
/// boundary.
///
/// # Thread safety
///
/// `Pkcs11TlsSigningKey` is `Send + Sync` because it holds an
/// `Arc<Pkcs11Provider>` which serialises PKCS#11 session access via an
/// internal `Mutex<Session>`.
///
/// # Limitations
///
/// - Only ECDSA (P-256, P-384) and RSA (PKCS1v1.5, PSS) are supported.
/// - Ed25519 is not supported (PKCS#11 v2.40 has no standardised EdDSA
///   mechanism; `cryptoki` 0.12 supports it via `Mechanism::Eddsa` but
///   `rustls` does not expose Ed25519 in `SignatureScheme`).
pub struct Pkcs11TlsSigningKey {
    provider: Arc<Pkcs11Provider>,
    key_handle: ObjectHandle,
    algorithm: SignatureAlgorithm,
}

impl std::fmt::Debug for Pkcs11TlsSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11TlsSigningKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl Pkcs11TlsSigningKey {
    /// Create a new `Pkcs11TlsSigningKey` backed by the private key labelled
    /// `key_label` on the token.
    ///
    /// The `algorithm` is used to choose which `SignatureScheme`s to advertise
    /// to `rustls`.  Use `SignatureAlgorithm::ECDSA` for EC keys and
    /// `SignatureAlgorithm::RSA` for RSA keys.
    ///
    /// # Errors
    /// Returns `PkcsError::KeyNotFound` if no private key with `key_label`
    /// exists on the token.
    pub fn new(
        provider: Arc<Pkcs11Provider>,
        key_label: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self, PkcsError> {
        let key_handle = provider.find_private_key(key_label)?;
        Ok(Self {
            provider,
            key_handle,
            algorithm,
        })
    }

    /// Convenience constructor for ECDSA keys.
    pub fn new_ecdsa(provider: Arc<Pkcs11Provider>, key_label: &str) -> Result<Self, PkcsError> {
        Self::new(provider, key_label, SignatureAlgorithm::ECDSA)
    }

    /// Convenience constructor for RSA keys.
    pub fn new_rsa(provider: Arc<Pkcs11Provider>, key_label: &str) -> Result<Self, PkcsError> {
        Self::new(provider, key_label, SignatureAlgorithm::RSA)
    }
}

impl rustls::sign::SigningKey for Pkcs11TlsSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        let preferred = preferred_schemes(self.algorithm);
        preferred
            .iter()
            .find(|&&s| offered.contains(&s))
            .map(|&scheme| {
                Box::new(Pkcs11TlsSigner::new(
                    Arc::clone(&self.provider),
                    self.key_handle,
                    scheme,
                )) as Box<dyn rustls::sign::Signer>
            })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify `raw_ecdsa_to_der` produces a valid DER SEQUENCE for a
    /// synthetic P-256 raw signature (64 bytes).
    #[test]
    fn raw_ecdsa_to_der_valid_output() {
        // Synthetic 64-byte r||s (non-zero values to exercise the encoder).
        let r = [0x1A; 32];
        let s = [0x2B; 32];
        let mut raw = Vec::with_capacity(64);
        raw.extend_from_slice(&r);
        raw.extend_from_slice(&s);

        let der = raw_ecdsa_to_der(&raw).expect("raw_ecdsa_to_der should succeed");
        assert_eq!(der[0], 0x30, "must start with DER SEQUENCE tag");
        assert!(der.len() > 4, "DER output must be non-trivial");
    }

    /// Verify `raw_ecdsa_to_der` correctly handles high-bit set (needs 0x00 pad).
    #[test]
    fn raw_ecdsa_to_der_high_bit_padding() {
        // r and s both have high bit set — each INTEGER needs a 0x00 pad byte.
        let r = [0xFFu8; 32];
        let s = [0xEEu8; 32];
        let mut raw = Vec::with_capacity(64);
        raw.extend_from_slice(&r);
        raw.extend_from_slice(&s);

        let der = raw_ecdsa_to_der(&raw).expect("should succeed");
        assert_eq!(der[0], 0x30);
        // Find first INTEGER and check for padding.
        let r_tag_pos = 2usize; // SEQUENCE(2) + first INTEGER
        assert_eq!(der[r_tag_pos], 0x02, "must be INTEGER tag");
        let r_len = der[r_tag_pos + 1] as usize;
        // With high-bit set and 32-byte r, length must be 33.
        assert_eq!(r_len, 33, "r INTEGER must be 33 bytes (32 + 0x00 pad)");
        assert_eq!(der[r_tag_pos + 2], 0x00, "first byte of r must be 0x00 pad");
    }

    /// Verify `raw_ecdsa_to_der` rejects odd-length input.
    #[test]
    fn raw_ecdsa_to_der_rejects_odd_length() {
        let odd = vec![0x11u8; 63];
        let result = raw_ecdsa_to_der(&odd);
        assert!(result.is_err(), "odd-length input must return Err");
    }

    /// Verify `raw_ecdsa_to_der` rejects empty input.
    #[test]
    fn raw_ecdsa_to_der_rejects_empty() {
        let result = raw_ecdsa_to_der(&[]);
        assert!(result.is_err(), "empty input must return Err");
    }

    /// Verify `scheme_to_mechanism` maps all supported schemes without error.
    #[test]
    fn scheme_to_mechanism_supported_schemes() {
        let supported = [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ];
        for scheme in supported {
            assert!(
                scheme_to_mechanism(scheme).is_ok(),
                "scheme_to_mechanism must succeed for {scheme:?}"
            );
        }
    }

    /// Verify `preferred_schemes` returns non-empty lists for ECDSA and RSA.
    #[test]
    fn preferred_schemes_non_empty() {
        assert!(!preferred_schemes(SignatureAlgorithm::ECDSA).is_empty());
        assert!(!preferred_schemes(SignatureAlgorithm::RSA).is_empty());
    }

    /// Verify `Pkcs11TlsSigningKey` is `Send + Sync`.
    #[test]
    fn pkcs11_tls_signing_key_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Pkcs11TlsSigningKey>();
    }
}
