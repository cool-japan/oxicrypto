//! TLS MAC negotiation: map TLS cipher suite identifiers to MAC implementations.
//!
//! In TLS 1.3 (RFC 8446 §7.1 and §4.4.4) the cipher suite's hash function
//! determines the HKDF and Finished-message HMAC algorithm.  The types and
//! functions in this module let higher-level OxiTLS code select the correct
//! HMAC without being hard-coded to a particular hash function.

extern crate alloc;

use oxicrypto_core::{CryptoError, Mac};

use crate::{HmacSha256, HmacSha384, HmacSha512};

// ── TlsCipherSuite ────────────────────────────────────────────────────────────

/// TLS cipher suite identifier for MAC negotiation.
///
/// Covers all TLS 1.3 cipher suites (RFC 8446 §B.4) and common TLS 1.2
/// HMAC-based cipher suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TlsCipherSuite {
    // ── TLS 1.3 cipher suites (RFC 8446 §B.4) ────────────────────────────────
    /// TLS_AES_128_GCM_SHA256 (0x1301) — HMAC-SHA-256 for handshake MACs.
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384 (0x1302) — HMAC-SHA-384 for handshake MACs.
    Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256 (0x1303) — HMAC-SHA-256 for handshake MACs.
    Chacha20Poly1305Sha256,
    /// TLS_AES_128_CCM_SHA256 (0x1304) — HMAC-SHA-256 for handshake MACs.
    Aes128CcmSha256,
    /// TLS_AES_128_CCM_8_SHA256 (0x1305) — HMAC-SHA-256 for handshake MACs.
    Aes128Ccm8Sha256,
    // ── Common TLS 1.2 HMAC suites ────────────────────────────────────────────
    /// Any TLS 1.2 suite with SHA-256 PRF (e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256).
    Sha256Prf,
    /// Any TLS 1.2 suite with SHA-384 PRF (e.g. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384).
    Sha384Prf,
    /// Any TLS 1.2 suite with SHA-512 PRF.
    Sha512Prf,
}

impl TlsCipherSuite {
    /// Parse a TLS cipher suite IANA name into a [`TlsCipherSuite`].
    ///
    /// Returns `None` if the string is not a recognized cipher suite name.
    ///
    /// # Examples
    ///
    /// ```
    /// use oxicrypto_mac::TlsCipherSuite;
    ///
    /// assert_eq!(
    ///     TlsCipherSuite::from_iana_name("TLS_AES_256_GCM_SHA384"),
    ///     Some(TlsCipherSuite::Aes256GcmSha384),
    /// );
    /// ```
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
}

// ── mac_name_for_suite ────────────────────────────────────────────────────────

/// Return the MAC algorithm name used for a given TLS cipher suite.
///
/// In TLS 1.3, the cipher suite hash function determines the HKDF hash and
/// Finished MAC.  This function returns a static string naming the MAC
/// primitive (e.g. `"HMAC-SHA-256"`).  Use [`negotiate_mac`] to obtain a
/// boxed [`Mac`] implementation.
pub fn mac_name_for_suite(suite: TlsCipherSuite) -> &'static str {
    match suite {
        TlsCipherSuite::Aes128GcmSha256
        | TlsCipherSuite::Chacha20Poly1305Sha256
        | TlsCipherSuite::Aes128CcmSha256
        | TlsCipherSuite::Aes128Ccm8Sha256
        | TlsCipherSuite::Sha256Prf => "HMAC-SHA-256",
        TlsCipherSuite::Aes256GcmSha384 | TlsCipherSuite::Sha384Prf => "HMAC-SHA-384",
        TlsCipherSuite::Sha512Prf => "HMAC-SHA-512",
    }
}

// ── negotiate_mac ─────────────────────────────────────────────────────────────

/// Return a boxed [`Mac`] implementation for the hash/MAC function
/// associated with a TLS cipher suite.
///
/// In TLS 1.3 (RFC 8446 §7.1 and §4.4.4), the cipher suite's hash
/// function determines:
/// - The HKDF extract/expand function.
/// - The Finished message HMAC (`HMAC(BaseKey, Transcript-Hash)`).
///
/// This function returns the appropriate HMAC primitive so that higher-level
/// OxiTLS code can compute Finished MAC tags without being hard-coded to a
/// specific hash function.
///
/// # Errors
///
/// Currently infallible — all cipher suites map to a supported HMAC.
/// Returns [`CryptoError::UnsupportedAlgorithm`] if a future variant is
/// added without a corresponding implementation.
///
/// # Example
///
/// ```
/// use oxicrypto_mac::{negotiate_mac, TlsCipherSuite};
/// use oxicrypto_core::Mac;
///
/// let mac = negotiate_mac(TlsCipherSuite::Aes256GcmSha384).expect("negotiate failed");
/// assert_eq!(mac.name(), "HMAC-SHA-384");
/// assert_eq!(mac.output_len(), 48);
/// ```
pub fn negotiate_mac(
    suite: TlsCipherSuite,
) -> Result<alloc::boxed::Box<dyn Mac + Send + Sync>, CryptoError> {
    let mac: alloc::boxed::Box<dyn Mac + Send + Sync> = match suite {
        TlsCipherSuite::Aes128GcmSha256
        | TlsCipherSuite::Chacha20Poly1305Sha256
        | TlsCipherSuite::Aes128CcmSha256
        | TlsCipherSuite::Aes128Ccm8Sha256
        | TlsCipherSuite::Sha256Prf => alloc::boxed::Box::new(HmacSha256),
        TlsCipherSuite::Aes256GcmSha384 | TlsCipherSuite::Sha384Prf => {
            alloc::boxed::Box::new(HmacSha384)
        }
        TlsCipherSuite::Sha512Prf => alloc::boxed::Box::new(HmacSha512),
    };
    Ok(mac)
}
