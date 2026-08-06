//! TLS AEAD negotiation: map TLS 1.3 cipher suite identifiers to AEAD
//! implementations.
//!
//! In TLS 1.3 (RFC 8446 §B.4) each cipher suite fully specifies the
//! record-protection AEAD (algorithm, key length and tag length). The types
//! and functions in this module let higher-level OxiTLS code select the correct
//! [`Aead`] implementation without being hard-coded to a particular algorithm.
//!
//! This mirrors the sibling helpers `oxicrypto_mac::negotiate_mac` (Finished
//! MAC / HKDF hash), `oxicrypto_sig::negotiate_sig` (handshake signature) and
//! `oxicrypto_kex::negotiate_kex` (key exchange), completing the set so a
//! consumer can resolve every leg of a TLS 1.3 cipher suite through the same
//! pattern.
//!
//! | [`TlsCipherSuite`] variant | IANA hex | AEAD | Key | Tag |
//! |---|---|---|---:|---:|
//! | `Aes128GcmSha256`        | 0x1301 | AES-128-GCM | 16 | 16 |
//! | `Aes256GcmSha384`        | 0x1302 | AES-256-GCM | 32 | 16 |
//! | `Chacha20Poly1305Sha256` | 0x1303 | ChaCha20-Poly1305 | 32 | 16 |
//! | `Aes128CcmSha256`        | 0x1304 | AES-128-CCM | 16 | 16 |
//! | `Aes128Ccm8Sha256`       | 0x1305 | AES-128-CCM-8 (8-byte tag) | 16 | 8 |

extern crate alloc;

use oxicrypto_core::{Aead, CryptoError};

use crate::{Aes128Ccm, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305};

// ── TlsCipherSuite ────────────────────────────────────────────────────────────

/// TLS 1.3 cipher suite identifier for AEAD negotiation.
///
/// Covers the five TLS 1.3 cipher suites (RFC 8446 §B.4). Each variant fully
/// determines the record-protection AEAD; unlike the MAC/hash side, the
/// TLS 1.2 PRF markers are intentionally omitted here because a bare PRF hash
/// does not identify a single AEAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TlsCipherSuite {
    /// TLS_AES_128_GCM_SHA256 (0x1301) — AES-128-GCM record protection.
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384 (0x1302) — AES-256-GCM record protection.
    Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256 (0x1303) — ChaCha20-Poly1305 record protection.
    Chacha20Poly1305Sha256,
    /// TLS_AES_128_CCM_SHA256 (0x1304) — AES-128-CCM (16-byte tag) record protection.
    Aes128CcmSha256,
    /// TLS_AES_128_CCM_8_SHA256 (0x1305) — AES-128-CCM with an 8-byte tag.
    Aes128Ccm8Sha256,
}

impl TlsCipherSuite {
    /// Parse a TLS cipher suite IANA name into a [`TlsCipherSuite`].
    ///
    /// Returns `None` if the string is not a recognized TLS 1.3 cipher suite name.
    ///
    /// # Examples
    ///
    /// ```
    /// use oxicrypto_aead::TlsCipherSuite;
    ///
    /// assert_eq!(
    ///     TlsCipherSuite::from_iana_name("TLS_AES_256_GCM_SHA384"),
    ///     Some(TlsCipherSuite::Aes256GcmSha384),
    /// );
    /// assert_eq!(TlsCipherSuite::from_iana_name("nonsense"), None);
    /// ```
    #[must_use]
    pub fn from_iana_name(name: &str) -> Option<Self> {
        match name {
            "TLS_AES_128_GCM_SHA256" => Some(Self::Aes128GcmSha256),
            "TLS_AES_256_GCM_SHA384" => Some(Self::Aes256GcmSha384),
            "TLS_CHACHA20_POLY1305_SHA256" => Some(Self::Chacha20Poly1305Sha256),
            "TLS_AES_128_CCM_SHA256" => Some(Self::Aes128CcmSha256),
            "TLS_AES_128_CCM_8_SHA256" => Some(Self::Aes128Ccm8Sha256),
            _ => None,
        }
    }

    /// Return the IANA-assigned two-byte cipher suite wire code.
    #[must_use]
    pub fn wire_code(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
            Self::Chacha20Poly1305Sha256 => 0x1303,
            Self::Aes128CcmSha256 => 0x1304,
            Self::Aes128Ccm8Sha256 => 0x1305,
        }
    }
}

// ── aead_name_for_suite ────────────────────────────────────────────────────────

/// Return the canonical AEAD algorithm name used for a given TLS cipher suite.
///
/// This is a pure naming helper; use [`negotiate_aead`] to obtain a boxed
/// [`Aead`] implementation.
#[must_use]
pub fn aead_name_for_suite(suite: TlsCipherSuite) -> &'static str {
    match suite {
        TlsCipherSuite::Aes128GcmSha256 => "AES-128-GCM",
        TlsCipherSuite::Aes256GcmSha384 => "AES-256-GCM",
        TlsCipherSuite::Chacha20Poly1305Sha256 => "ChaCha20-Poly1305",
        TlsCipherSuite::Aes128CcmSha256 => "AES-128-CCM",
        TlsCipherSuite::Aes128Ccm8Sha256 => "AES-128-CCM-8",
    }
}

// ── negotiate_aead ─────────────────────────────────────────────────────────────

/// Return a boxed [`Aead`] implementation for the record-protection algorithm
/// associated with a TLS 1.3 cipher suite.
///
/// # Errors
///
/// Returns [`CryptoError::UnsupportedAlgorithm`] for
/// [`TlsCipherSuite::Aes128Ccm8Sha256`]: that suite requires AES-128-CCM with a
/// truncated 8-byte authentication tag, which is not one of the AEAD primitives
/// this crate currently provides ([`Aes128Ccm`] uses the full 16-byte tag).
/// Returning a 16-byte-tag AEAD for it would silently produce frames that are
/// incompatible on the wire, so this is reported as a typed error rather than
/// mis-mapped.
///
/// # Example
///
/// ```
/// use oxicrypto_aead::{negotiate_aead, TlsCipherSuite};
///
/// let aead = negotiate_aead(TlsCipherSuite::Aes256GcmSha384).expect("negotiate failed");
/// assert_eq!(aead.name(), "AES-256-GCM");
/// assert_eq!(aead.key_len(), 32);
/// assert_eq!(aead.nonce_len(), 12);
/// assert_eq!(aead.tag_len(), 16);
/// ```
pub fn negotiate_aead(suite: TlsCipherSuite) -> Result<alloc::boxed::Box<dyn Aead>, CryptoError> {
    let aead: alloc::boxed::Box<dyn Aead> = match suite {
        TlsCipherSuite::Aes128GcmSha256 => alloc::boxed::Box::new(Aes128Gcm),
        TlsCipherSuite::Aes256GcmSha384 => alloc::boxed::Box::new(Aes256Gcm),
        TlsCipherSuite::Chacha20Poly1305Sha256 => alloc::boxed::Box::new(ChaCha20Poly1305),
        TlsCipherSuite::Aes128CcmSha256 => alloc::boxed::Box::new(Aes128Ccm),
        // AES-128-CCM-8 (8-byte tag) is not yet implemented; do not silently
        // substitute the 16-byte-tag variant.
        TlsCipherSuite::Aes128Ccm8Sha256 => return Err(CryptoError::UnsupportedAlgorithm),
    };
    Ok(aead)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_iana_name_maps_all_tls13_suites() {
        assert_eq!(
            TlsCipherSuite::from_iana_name("TLS_AES_128_GCM_SHA256"),
            Some(TlsCipherSuite::Aes128GcmSha256)
        );
        assert_eq!(
            TlsCipherSuite::from_iana_name("TLS_AES_256_GCM_SHA384"),
            Some(TlsCipherSuite::Aes256GcmSha384)
        );
        assert_eq!(
            TlsCipherSuite::from_iana_name("TLS_CHACHA20_POLY1305_SHA256"),
            Some(TlsCipherSuite::Chacha20Poly1305Sha256)
        );
        assert_eq!(
            TlsCipherSuite::from_iana_name("TLS_AES_128_CCM_SHA256"),
            Some(TlsCipherSuite::Aes128CcmSha256)
        );
        assert_eq!(
            TlsCipherSuite::from_iana_name("TLS_AES_128_CCM_8_SHA256"),
            Some(TlsCipherSuite::Aes128Ccm8Sha256)
        );
        assert_eq!(TlsCipherSuite::from_iana_name("TLS_UNKNOWN"), None);
    }

    #[test]
    fn wire_codes_match_rfc8446() {
        assert_eq!(TlsCipherSuite::Aes128GcmSha256.wire_code(), 0x1301);
        assert_eq!(TlsCipherSuite::Aes256GcmSha384.wire_code(), 0x1302);
        assert_eq!(TlsCipherSuite::Chacha20Poly1305Sha256.wire_code(), 0x1303);
        assert_eq!(TlsCipherSuite::Aes128CcmSha256.wire_code(), 0x1304);
        assert_eq!(TlsCipherSuite::Aes128Ccm8Sha256.wire_code(), 0x1305);
    }

    #[test]
    fn negotiate_aead_returns_correct_primitive() {
        let a = negotiate_aead(TlsCipherSuite::Aes128GcmSha256).expect("aes128gcm");
        assert_eq!(a.name(), "AES-128-GCM");
        assert_eq!(a.key_len(), 16);
        assert_eq!(a.tag_len(), 16);

        let a = negotiate_aead(TlsCipherSuite::Aes256GcmSha384).expect("aes256gcm");
        assert_eq!(a.name(), "AES-256-GCM");
        assert_eq!(a.key_len(), 32);

        let a = negotiate_aead(TlsCipherSuite::Chacha20Poly1305Sha256).expect("chacha");
        assert_eq!(a.name(), "ChaCha20-Poly1305");
        assert_eq!(a.key_len(), 32);

        let a = negotiate_aead(TlsCipherSuite::Aes128CcmSha256).expect("ccm");
        assert_eq!(a.name(), "AES-128-CCM");
        assert_eq!(a.key_len(), 16);
        assert_eq!(a.nonce_len(), 13);
    }

    #[test]
    fn negotiate_aead_rejects_ccm8_as_unsupported() {
        let result = negotiate_aead(TlsCipherSuite::Aes128Ccm8Sha256);
        assert!(
            matches!(result, Err(CryptoError::UnsupportedAlgorithm)),
            "CCM-8 must be reported as UnsupportedAlgorithm, not mis-mapped"
        );
    }

    #[test]
    fn aead_name_for_suite_matches_all_variants() {
        assert_eq!(
            aead_name_for_suite(TlsCipherSuite::Aes128GcmSha256),
            "AES-128-GCM"
        );
        assert_eq!(
            aead_name_for_suite(TlsCipherSuite::Aes256GcmSha384),
            "AES-256-GCM"
        );
        assert_eq!(
            aead_name_for_suite(TlsCipherSuite::Chacha20Poly1305Sha256),
            "ChaCha20-Poly1305"
        );
        assert_eq!(
            aead_name_for_suite(TlsCipherSuite::Aes128CcmSha256),
            "AES-128-CCM"
        );
        assert_eq!(
            aead_name_for_suite(TlsCipherSuite::Aes128Ccm8Sha256),
            "AES-128-CCM-8"
        );
    }

    #[test]
    fn negotiated_aead_round_trips() {
        // End-to-end: negotiate, seal, then open.
        let aead = negotiate_aead(TlsCipherSuite::Aes256GcmSha384).expect("negotiate");
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let aad = b"tls-record-header";
        let pt = b"hello tls 1.3 record";

        let mut ct = alloc::vec![0u8; pt.len() + aead.tag_len()];
        let written = aead.seal(&key, &nonce, aad, pt, &mut ct).expect("seal");
        assert_eq!(written, pt.len() + aead.tag_len());

        let mut recovered = alloc::vec![0u8; pt.len()];
        let n = aead
            .open(&key, &nonce, aad, &ct, &mut recovered)
            .expect("open");
        assert_eq!(n, pt.len());
        assert_eq!(&recovered, pt);
    }
}
