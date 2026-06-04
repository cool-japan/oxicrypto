//! TLS signature algorithm negotiation: map TLS cipher suite identifiers to
//! signature algorithm implementations.
//!
//! In TLS 1.3 (RFC 8446 §4.2.3) the signature algorithm is negotiated through
//! the `signature_algorithms` extension, using IANA-assigned `SignatureScheme`
//! values. The types and functions in this module let higher-level OxiTLS code
//! select the correct signer and verifier without being hard-coded to a
//! particular algorithm.
//!
//! # Supported signature schemes
//!
//! | [`TlsSignatureScheme`] variant | IANA hex | Algorithm |
//! |-------------------------------|----------|-----------|
//! | `EcdsaSecp256r1Sha256`        | 0x0403   | ECDSA P-256 with SHA-256 |
//! | `EcdsaSecp384r1Sha384`        | 0x0503   | ECDSA P-384 with SHA-384 |
//! | `EcdsaSecp521r1Sha512`        | 0x0603   | ECDSA P-521 with SHA-512 |
//! | `RsaPkcs1Sha256`              | 0x0401   | RSA PKCS#1 v1.5 with SHA-256 |
//! | `RsaPkcs1Sha384`              | 0x0501   | RSA PKCS#1 v1.5 with SHA-384 |
//! | `RsaPkcs1Sha512`              | 0x0601   | RSA PKCS#1 v1.5 with SHA-512 |
//! | `RsaPssSha256`                | 0x0804   | RSA-PSS with SHA-256 |
//! | `RsaPssSha384`                | 0x0805   | RSA-PSS with SHA-384 |
//! | `RsaPssSha512`                | 0x0806   | RSA-PSS with SHA-512 |
//! | `Ed25519`                     | 0x0807   | Ed25519 |
//! | `Ed448`                       | 0x0808   | Ed448 |

extern crate alloc;

use oxicrypto_core::{CryptoError, Signer, Verifier};

/// A boxed (heap-allocated) signer/verifier pair returned by [`negotiate_sig`].
///
/// Both items are type-erased trait objects that implement [`Send`] and [`Sync`],
/// making them safe to use across thread boundaries.
pub type SigPair = (
    alloc::boxed::Box<dyn Signer + Send + Sync>,
    alloc::boxed::Box<dyn Verifier + Send + Sync>,
);

use crate::{
    EcdsaP256, EcdsaP256Verify, EcdsaP384, EcdsaP384Verify, EcdsaP521, EcdsaP521Verify, Ed25519,
    Ed25519Verifier, Ed448, Ed448Verify, RsaPkcs1v15Sha256, RsaPkcs1v15Sha256Verify,
    RsaPkcs1v15Sha384, RsaPkcs1v15Sha384Verify, RsaPkcs1v15Sha512, RsaPkcs1v15Sha512Verify,
    RsaPssSha256, RsaPssSha256Verify, RsaPssSha384, RsaPssSha384Verify, RsaPssSha512,
    RsaPssSha512Verify,
};

// ── TlsSignatureScheme ────────────────────────────────────────────────────────

/// TLS signature scheme identifier (RFC 8446 §4.2.3, IANA registry).
///
/// Used with [`negotiate_sig`] to obtain a signer/verifier pair appropriate
/// for a TLS handshake or session key.
///
/// # Wire values
///
/// Each variant carries its IANA-assigned two-byte wire code
/// (NetworkByteOrder `u16`).  Use `TlsSignatureScheme::from_wire(value)` to
/// decode a value received over the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TlsSignatureScheme {
    // ── ECDSA ─────────────────────────────────────────────────────────────────
    /// `ecdsa_secp256r1_sha256` (0x0403) — ECDSA P-256 with SHA-256.
    EcdsaSecp256r1Sha256,
    /// `ecdsa_secp384r1_sha384` (0x0503) — ECDSA P-384 with SHA-384.
    EcdsaSecp384r1Sha384,
    /// `ecdsa_secp521r1_sha512` (0x0603) — ECDSA P-521 with SHA-512.
    EcdsaSecp521r1Sha512,
    // ── RSA PKCS#1 v1.5 ──────────────────────────────────────────────────────
    /// `rsa_pkcs1_sha256` (0x0401) — RSA PKCS#1 v1.5 with SHA-256.
    RsaPkcs1Sha256,
    /// `rsa_pkcs1_sha384` (0x0501) — RSA PKCS#1 v1.5 with SHA-384.
    RsaPkcs1Sha384,
    /// `rsa_pkcs1_sha512` (0x0601) — RSA PKCS#1 v1.5 with SHA-512.
    RsaPkcs1Sha512,
    // ── RSA-PSS ───────────────────────────────────────────────────────────────
    /// `rsa_pss_rsae_sha256` / `rsa_pss_pss_sha256` (0x0804) — RSA-PSS with SHA-256.
    RsaPssSha256,
    /// `rsa_pss_rsae_sha384` / `rsa_pss_pss_sha384` (0x0805) — RSA-PSS with SHA-384.
    RsaPssSha384,
    /// `rsa_pss_rsae_sha512` / `rsa_pss_pss_sha512` (0x0806) — RSA-PSS with SHA-512.
    RsaPssSha512,
    // ── Edwards curves ────────────────────────────────────────────────────────
    /// `ed25519` (0x0807) — Ed25519 per RFC 8032.
    Ed25519,
    /// `ed448` (0x0808) — Ed448 per RFC 8032.
    Ed448,
}

impl TlsSignatureScheme {
    /// Decode a TLS signature scheme from its two-byte IANA wire value.
    ///
    /// Returns `None` for unrecognised or unsupported scheme values.
    ///
    /// # Examples
    ///
    /// ```
    /// use oxicrypto_sig::tls::TlsSignatureScheme;
    ///
    /// assert_eq!(
    ///     TlsSignatureScheme::from_wire(0x0403),
    ///     Some(TlsSignatureScheme::EcdsaSecp256r1Sha256),
    /// );
    /// assert_eq!(TlsSignatureScheme::from_wire(0xffff), None);
    /// ```
    pub fn from_wire(code: u16) -> Option<Self> {
        match code {
            0x0403 => Some(Self::EcdsaSecp256r1Sha256),
            0x0503 => Some(Self::EcdsaSecp384r1Sha384),
            0x0603 => Some(Self::EcdsaSecp521r1Sha512),
            0x0401 => Some(Self::RsaPkcs1Sha256),
            0x0501 => Some(Self::RsaPkcs1Sha384),
            0x0601 => Some(Self::RsaPkcs1Sha512),
            0x0804 => Some(Self::RsaPssSha256),
            0x0805 => Some(Self::RsaPssSha384),
            0x0806 => Some(Self::RsaPssSha512),
            0x0807 => Some(Self::Ed25519),
            0x0808 => Some(Self::Ed448),
            _ => None,
        }
    }

    /// Return the two-byte IANA wire value for this signature scheme.
    ///
    /// # Examples
    ///
    /// ```
    /// use oxicrypto_sig::tls::TlsSignatureScheme;
    ///
    /// assert_eq!(TlsSignatureScheme::EcdsaSecp256r1Sha256.to_wire(), 0x0403);
    /// assert_eq!(TlsSignatureScheme::Ed25519.to_wire(), 0x0807);
    /// ```
    pub fn to_wire(self) -> u16 {
        match self {
            Self::EcdsaSecp256r1Sha256 => 0x0403,
            Self::EcdsaSecp384r1Sha384 => 0x0503,
            Self::EcdsaSecp521r1Sha512 => 0x0603,
            Self::RsaPkcs1Sha256 => 0x0401,
            Self::RsaPkcs1Sha384 => 0x0501,
            Self::RsaPkcs1Sha512 => 0x0601,
            Self::RsaPssSha256 => 0x0804,
            Self::RsaPssSha384 => 0x0805,
            Self::RsaPssSha512 => 0x0806,
            Self::Ed25519 => 0x0807,
            Self::Ed448 => 0x0808,
        }
    }

    /// Return the algorithm name string for this signature scheme.
    ///
    /// The returned string uses the same format as the `Signer::name()` and
    /// `Verifier::name()` methods on the negotiated primitives.
    ///
    /// # Examples
    ///
    /// ```
    /// use oxicrypto_sig::tls::TlsSignatureScheme;
    ///
    /// assert_eq!(TlsSignatureScheme::EcdsaSecp256r1Sha256.algorithm_name(), "ECDSA-P256");
    /// assert_eq!(TlsSignatureScheme::Ed25519.algorithm_name(), "Ed25519");
    /// ```
    pub fn algorithm_name(self) -> &'static str {
        match self {
            Self::EcdsaSecp256r1Sha256 => "ECDSA-P256",
            Self::EcdsaSecp384r1Sha384 => "ECDSA-P384",
            Self::EcdsaSecp521r1Sha512 => "ECDSA-P521",
            Self::RsaPkcs1Sha256 => "RSA-PKCS1v15-SHA256",
            Self::RsaPkcs1Sha384 => "RSA-PKCS1v15-SHA384",
            Self::RsaPkcs1Sha512 => "RSA-PKCS1v15-SHA512",
            Self::RsaPssSha256 => "RSA-PSS-SHA256",
            Self::RsaPssSha384 => "RSA-PSS-SHA384",
            Self::RsaPssSha512 => "RSA-PSS-SHA512",
            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "Ed448",
        }
    }

    /// Parse a TLS IANA signature scheme name string into a
    /// [`TlsSignatureScheme`].
    ///
    /// Returns `None` if the string does not match a supported scheme.
    ///
    /// # Examples
    ///
    /// ```
    /// use oxicrypto_sig::tls::TlsSignatureScheme;
    ///
    /// assert_eq!(
    ///     TlsSignatureScheme::from_iana_name("ecdsa_secp256r1_sha256"),
    ///     Some(TlsSignatureScheme::EcdsaSecp256r1Sha256),
    /// );
    /// ```
    pub fn from_iana_name(name: &str) -> Option<Self> {
        match name {
            "ecdsa_secp256r1_sha256" => Some(Self::EcdsaSecp256r1Sha256),
            "ecdsa_secp384r1_sha384" => Some(Self::EcdsaSecp384r1Sha384),
            "ecdsa_secp521r1_sha512" => Some(Self::EcdsaSecp521r1Sha512),
            "rsa_pkcs1_sha256" => Some(Self::RsaPkcs1Sha256),
            "rsa_pkcs1_sha384" => Some(Self::RsaPkcs1Sha384),
            "rsa_pkcs1_sha512" => Some(Self::RsaPkcs1Sha512),
            "rsa_pss_rsae_sha256" | "rsa_pss_pss_sha256" => Some(Self::RsaPssSha256),
            "rsa_pss_rsae_sha384" | "rsa_pss_pss_sha384" => Some(Self::RsaPssSha384),
            "rsa_pss_rsae_sha512" | "rsa_pss_pss_sha512" => Some(Self::RsaPssSha512),
            "ed25519" => Some(Self::Ed25519),
            "ed448" => Some(Self::Ed448),
            _ => None,
        }
    }
}

impl core::fmt::Display for TlsSignatureScheme {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.algorithm_name())
    }
}

// ── negotiate_sig ─────────────────────────────────────────────────────────────

/// Return a [`SigPair`] `(signer, verifier)` for the given TLS signature scheme.
///
/// The returned implementations satisfy the [`Signer`] and [`Verifier`] traits
/// from `oxicrypto-core`, making them usable directly in TLS handshakes.
///
/// Key formats follow the conventions of this crate:
/// - ECDSA: raw scalar bytes (signing) / SEC1-encoded compressed point (verifying)
/// - RSA: DER PKCS#8 (signing) / DER SubjectPublicKeyInfo (verifying)
/// - Ed25519: 32-byte seed (signing) / 32-byte compressed Edwards-y point (verifying)
/// - Ed448: 57-byte seed (signing) / 57-byte compressed point (verifying)
///
/// Returns [`CryptoError::UnsupportedAlgorithm`] for schemes that are
/// syntactically valid but not yet implemented in this crate. Currently all
/// defined [`TlsSignatureScheme`] variants are supported.
///
/// # Examples
///
/// ```rust
/// # extern crate alloc;
/// use oxicrypto_sig::tls::{negotiate_sig, TlsSignatureScheme};
///
/// let (signer, verifier) = negotiate_sig(TlsSignatureScheme::Ed25519)
///     .expect("Ed25519 must be supported");
///
/// assert_eq!(signer.name(), "Ed25519");
/// assert_eq!(verifier.name(), "Ed25519");
/// ```
pub fn negotiate_sig(scheme: TlsSignatureScheme) -> Result<SigPair, CryptoError> {
    let pair: SigPair = match scheme {
        TlsSignatureScheme::EcdsaSecp256r1Sha256 => (
            alloc::boxed::Box::new(EcdsaP256),
            alloc::boxed::Box::new(EcdsaP256Verify),
        ),
        TlsSignatureScheme::EcdsaSecp384r1Sha384 => (
            alloc::boxed::Box::new(EcdsaP384),
            alloc::boxed::Box::new(EcdsaP384Verify),
        ),
        TlsSignatureScheme::EcdsaSecp521r1Sha512 => (
            alloc::boxed::Box::new(EcdsaP521),
            alloc::boxed::Box::new(EcdsaP521Verify),
        ),
        TlsSignatureScheme::RsaPkcs1Sha256 => (
            alloc::boxed::Box::new(RsaPkcs1v15Sha256),
            alloc::boxed::Box::new(RsaPkcs1v15Sha256Verify),
        ),
        TlsSignatureScheme::RsaPkcs1Sha384 => (
            alloc::boxed::Box::new(RsaPkcs1v15Sha384),
            alloc::boxed::Box::new(RsaPkcs1v15Sha384Verify),
        ),
        TlsSignatureScheme::RsaPkcs1Sha512 => (
            alloc::boxed::Box::new(RsaPkcs1v15Sha512),
            alloc::boxed::Box::new(RsaPkcs1v15Sha512Verify),
        ),
        TlsSignatureScheme::RsaPssSha256 => (
            alloc::boxed::Box::new(RsaPssSha256),
            alloc::boxed::Box::new(RsaPssSha256Verify),
        ),
        TlsSignatureScheme::RsaPssSha384 => (
            alloc::boxed::Box::new(RsaPssSha384),
            alloc::boxed::Box::new(RsaPssSha384Verify),
        ),
        TlsSignatureScheme::RsaPssSha512 => (
            alloc::boxed::Box::new(RsaPssSha512),
            alloc::boxed::Box::new(RsaPssSha512Verify),
        ),
        TlsSignatureScheme::Ed25519 => (
            alloc::boxed::Box::new(Ed25519),
            alloc::boxed::Box::new(Ed25519Verifier),
        ),
        TlsSignatureScheme::Ed448 => (
            alloc::boxed::Box::new(Ed448),
            alloc::boxed::Box::new(Ed448Verify),
        ),
    };
    Ok(pair)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── from_wire round-trip ──────────────────────────────────────────────────

    #[test]
    fn tls_sig_scheme_from_wire_known_values() {
        let known: &[(u16, TlsSignatureScheme)] = &[
            (0x0403, TlsSignatureScheme::EcdsaSecp256r1Sha256),
            (0x0503, TlsSignatureScheme::EcdsaSecp384r1Sha384),
            (0x0603, TlsSignatureScheme::EcdsaSecp521r1Sha512),
            (0x0401, TlsSignatureScheme::RsaPkcs1Sha256),
            (0x0501, TlsSignatureScheme::RsaPkcs1Sha384),
            (0x0601, TlsSignatureScheme::RsaPkcs1Sha512),
            (0x0804, TlsSignatureScheme::RsaPssSha256),
            (0x0805, TlsSignatureScheme::RsaPssSha384),
            (0x0806, TlsSignatureScheme::RsaPssSha512),
            (0x0807, TlsSignatureScheme::Ed25519),
            (0x0808, TlsSignatureScheme::Ed448),
        ];
        for &(wire, expected) in known {
            let got = TlsSignatureScheme::from_wire(wire);
            assert_eq!(got, Some(expected), "from_wire(0x{wire:04x}) mismatch");
            assert_eq!(expected.to_wire(), wire, "to_wire round-trip mismatch");
        }
    }

    #[test]
    fn tls_sig_scheme_from_wire_unknown_returns_none() {
        assert_eq!(TlsSignatureScheme::from_wire(0x0000), None);
        assert_eq!(TlsSignatureScheme::from_wire(0xffff), None);
        assert_eq!(TlsSignatureScheme::from_wire(0x0200), None);
    }

    // ── from_iana_name ────────────────────────────────────────────────────────

    #[test]
    fn tls_sig_scheme_from_iana_name_known() {
        let known: &[(&str, TlsSignatureScheme)] = &[
            (
                "ecdsa_secp256r1_sha256",
                TlsSignatureScheme::EcdsaSecp256r1Sha256,
            ),
            (
                "ecdsa_secp384r1_sha384",
                TlsSignatureScheme::EcdsaSecp384r1Sha384,
            ),
            (
                "ecdsa_secp521r1_sha512",
                TlsSignatureScheme::EcdsaSecp521r1Sha512,
            ),
            ("rsa_pkcs1_sha256", TlsSignatureScheme::RsaPkcs1Sha256),
            ("rsa_pkcs1_sha384", TlsSignatureScheme::RsaPkcs1Sha384),
            ("rsa_pkcs1_sha512", TlsSignatureScheme::RsaPkcs1Sha512),
            ("rsa_pss_rsae_sha256", TlsSignatureScheme::RsaPssSha256),
            ("rsa_pss_pss_sha256", TlsSignatureScheme::RsaPssSha256),
            ("rsa_pss_rsae_sha384", TlsSignatureScheme::RsaPssSha384),
            ("rsa_pss_pss_sha384", TlsSignatureScheme::RsaPssSha384),
            ("rsa_pss_rsae_sha512", TlsSignatureScheme::RsaPssSha512),
            ("rsa_pss_pss_sha512", TlsSignatureScheme::RsaPssSha512),
            ("ed25519", TlsSignatureScheme::Ed25519),
            ("ed448", TlsSignatureScheme::Ed448),
        ];
        for &(name, expected) in known {
            let got = TlsSignatureScheme::from_iana_name(name);
            assert_eq!(got, Some(expected), "from_iana_name({name:?}) mismatch");
        }
    }

    #[test]
    fn tls_sig_scheme_from_iana_name_unknown_returns_none() {
        assert_eq!(TlsSignatureScheme::from_iana_name(""), None);
        assert_eq!(TlsSignatureScheme::from_iana_name("unknown_scheme"), None);
        assert_eq!(
            TlsSignatureScheme::from_iana_name("TLS_AES_128_GCM_SHA256"),
            None
        );
    }

    // ── negotiate_sig functional ──────────────────────────────────────────────

    #[test]
    fn negotiate_sig_ed25519_roundtrip() {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);

        let (signer, verifier) =
            negotiate_sig(TlsSignatureScheme::Ed25519).expect("Ed25519 must succeed");
        assert_eq!(signer.name(), "Ed25519");
        assert_eq!(verifier.name(), "Ed25519");

        let (sk_sec, pk_bytes) = crate::ed25519_generate_keypair(&mut rng).expect("ed25519 keygen");
        let msg = b"negotiate_sig Ed25519 functional test";
        let mut sig_buf = [0u8; 64];
        let len = signer
            .sign(sk_sec.as_bytes(), msg, &mut sig_buf)
            .expect("sign");
        verifier
            .verify(&pk_bytes, msg, &sig_buf[..len])
            .expect("verify");
    }

    #[test]
    fn negotiate_sig_ecdsa_p256_roundtrip() {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);

        let (signer, verifier) = negotiate_sig(TlsSignatureScheme::EcdsaSecp256r1Sha256)
            .expect("ECDSA-P256 must succeed");
        assert_eq!(signer.name(), "ECDSA-P256");
        assert_eq!(verifier.name(), "ECDSA-P256");

        let (sk_sec, pk_bytes) = crate::ecdsa_p256_generate_keypair(&mut rng).expect("p256 keygen");
        let msg = b"negotiate_sig ECDSA-P256 functional test";
        let mut sig_buf = [0u8; 72];
        let len = signer
            .sign(sk_sec.as_bytes(), msg, &mut sig_buf)
            .expect("sign");
        verifier
            .verify(&pk_bytes, msg, &sig_buf[..len])
            .expect("verify");
    }

    #[test]
    fn negotiate_sig_ed448_roundtrip() {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);

        let (signer, verifier) =
            negotiate_sig(TlsSignatureScheme::Ed448).expect("Ed448 must succeed");
        assert_eq!(signer.name(), "Ed448");
        assert_eq!(verifier.name(), "Ed448");

        let (sk_sec, pk_bytes) = crate::ed448_generate_keypair(&mut rng).expect("ed448 keygen");
        let msg = b"negotiate_sig Ed448 functional test";
        let mut sig_buf = [0u8; 114];
        let len = signer
            .sign(sk_sec.as_bytes(), msg, &mut sig_buf)
            .expect("sign");
        verifier
            .verify(&pk_bytes, msg, &sig_buf[..len])
            .expect("verify");
    }

    #[test]
    fn negotiate_sig_all_schemes_return_matching_names() {
        let schemes = [
            TlsSignatureScheme::EcdsaSecp256r1Sha256,
            TlsSignatureScheme::EcdsaSecp384r1Sha384,
            TlsSignatureScheme::EcdsaSecp521r1Sha512,
            TlsSignatureScheme::RsaPkcs1Sha256,
            TlsSignatureScheme::RsaPkcs1Sha384,
            TlsSignatureScheme::RsaPkcs1Sha512,
            TlsSignatureScheme::RsaPssSha256,
            TlsSignatureScheme::RsaPssSha384,
            TlsSignatureScheme::RsaPssSha512,
            TlsSignatureScheme::Ed25519,
            TlsSignatureScheme::Ed448,
        ];
        for scheme in schemes {
            let (signer, verifier) = negotiate_sig(scheme).expect("all schemes must be supported");
            // signer and verifier names must match the scheme's algorithm_name
            assert_eq!(
                signer.name(),
                scheme.algorithm_name(),
                "signer name mismatch for scheme {scheme:?}"
            );
            assert_eq!(
                verifier.name(),
                scheme.algorithm_name(),
                "verifier name mismatch for scheme {scheme:?}"
            );
        }
    }
}
