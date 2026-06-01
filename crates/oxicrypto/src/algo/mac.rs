//! MAC algorithm selector enum + factory function.

use crate::CryptoError;

/// MAC algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MacAlgo {
    /// HMAC-SHA-256 (32-byte tag).
    HmacSha256,
    /// HMAC-SHA-384 (48-byte tag).
    HmacSha384,
    /// HMAC-SHA-512 (64-byte tag).
    HmacSha512,
    /// HMAC-SHA3-256 (32-byte tag).
    HmacSha3_256,
    /// HMAC-SHA3-512 (64-byte tag).
    HmacSha3_512,
    /// Poly1305 one-time MAC (16-byte tag).
    ///
    /// # Security
    ///
    /// The 32-byte key MUST NOT be reused for different messages.
    /// In practice, derive a fresh per-message key (e.g. from ChaCha20 or a KDF).
    Poly1305,
    /// CMAC-AES-128 (key: 16 bytes, tag: 16 bytes).
    CmacAes128,
    /// CMAC-AES-256 (key: 32 bytes, tag: 16 bytes).
    CmacAes256,
    /// KMAC128 (NIST SP 800-185) with variable output length.
    ///
    /// Uses an empty customization string. `output_len` must be >= 1.
    Kmac128 { output_len: usize },
    /// KMAC256 (NIST SP 800-185) with variable output length.
    ///
    /// Uses an empty customization string. `output_len` must be >= 1.
    Kmac256 { output_len: usize },
}

/// Return a boxed [`oxicrypto_core::Mac`] implementation for `algo`.
///
/// For `MacAlgo::Kmac128 { output_len }` and `MacAlgo::Kmac256 { output_len }`,
/// if `output_len` is 0 it is silently clamped to 1 (a zero-length KMAC tag
/// is meaningless; the MAC trait's `mac()` method would surface an error
/// anyway).  All other variants have fixed output lengths and cannot fail.
#[cfg(feature = "pure")]
#[must_use]
pub fn mac_impl(algo: MacAlgo) -> oxicrypto_core::Box<dyn oxicrypto_core::Mac + Send + Sync> {
    match algo {
        MacAlgo::HmacSha256 => oxicrypto_core::Box::new(oxicrypto_mac::HmacSha256),
        MacAlgo::HmacSha384 => oxicrypto_core::Box::new(oxicrypto_mac::HmacSha384),
        MacAlgo::HmacSha512 => oxicrypto_core::Box::new(oxicrypto_mac::HmacSha512),
        MacAlgo::HmacSha3_256 => oxicrypto_core::Box::new(oxicrypto_mac::HmacSha3_256),
        MacAlgo::HmacSha3_512 => oxicrypto_core::Box::new(oxicrypto_mac::HmacSha3_512),
        MacAlgo::Poly1305 => oxicrypto_core::Box::new(oxicrypto_mac::Poly1305Mac),
        MacAlgo::CmacAes128 => oxicrypto_core::Box::new(oxicrypto_mac::CmacAes128),
        MacAlgo::CmacAes256 => oxicrypto_core::Box::new(oxicrypto_mac::CmacAes256),
        MacAlgo::Kmac128 { output_len } => {
            // Clamp to >= 1: a zero-length tag is meaningless.
            // Construction with len >= 1 is infallible per Kmac128::new.
            let len = output_len.max(1);
            oxicrypto_core::Box::new(
                oxicrypto_mac::Kmac128::new(b"", len)
                    .unwrap_or_else(|_| unreachable!("len >= 1 is always valid")),
            )
        }
        MacAlgo::Kmac256 { output_len } => {
            let len = output_len.max(1);
            oxicrypto_core::Box::new(
                oxicrypto_mac::Kmac256::new(b"", len)
                    .unwrap_or_else(|_| unreachable!("len >= 1 is always valid")),
            )
        }
    }
}

// ── Display ───────────────────────────────────────────────────────────────────

impl core::fmt::Display for MacAlgo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MacAlgo::HmacSha256 => f.write_str("HMAC-SHA-256"),
            MacAlgo::HmacSha384 => f.write_str("HMAC-SHA-384"),
            MacAlgo::HmacSha512 => f.write_str("HMAC-SHA-512"),
            MacAlgo::HmacSha3_256 => f.write_str("HMAC-SHA3-256"),
            MacAlgo::HmacSha3_512 => f.write_str("HMAC-SHA3-512"),
            MacAlgo::Poly1305 => f.write_str("Poly1305"),
            MacAlgo::CmacAes128 => f.write_str("CMAC-AES-128"),
            MacAlgo::CmacAes256 => f.write_str("CMAC-AES-256"),
            MacAlgo::Kmac128 { output_len } => write!(f, "KMAC128/{output_len}"),
            MacAlgo::Kmac256 { output_len } => write!(f, "KMAC256/{output_len}"),
        }
    }
}

// ── FromStr ───────────────────────────────────────────────────────────────────

impl core::str::FromStr for MacAlgo {
    type Err = CryptoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Handle KMAC variants with output_len suffix: "KMAC128/32" or "KMAC256/64"
        if let Some(rest) = s
            .strip_prefix("KMAC128/")
            .or_else(|| s.strip_prefix("kmac128/"))
        {
            let output_len = rest
                .parse::<usize>()
                .map_err(|_| CryptoError::UnsupportedAlgorithm)?;
            return Ok(MacAlgo::Kmac128 { output_len });
        }
        if let Some(rest) = s
            .strip_prefix("KMAC256/")
            .or_else(|| s.strip_prefix("kmac256/"))
        {
            let output_len = rest
                .parse::<usize>()
                .map_err(|_| CryptoError::UnsupportedAlgorithm)?;
            return Ok(MacAlgo::Kmac256 { output_len });
        }
        match s {
            "HMAC-SHA-256" | "hmac-sha-256" | "HMACSHA256" => Ok(MacAlgo::HmacSha256),
            "HMAC-SHA-384" | "hmac-sha-384" | "HMACSHA384" => Ok(MacAlgo::HmacSha384),
            "HMAC-SHA-512" | "hmac-sha-512" | "HMACSHA512" => Ok(MacAlgo::HmacSha512),
            "HMAC-SHA3-256" | "hmac-sha3-256" | "HMACSHA3256" => Ok(MacAlgo::HmacSha3_256),
            "HMAC-SHA3-512" | "hmac-sha3-512" | "HMACSHA3512" => Ok(MacAlgo::HmacSha3_512),
            "Poly1305" | "poly1305" | "POLY1305" => Ok(MacAlgo::Poly1305),
            "CMAC-AES-128" | "cmac-aes-128" | "CMACAES128" => Ok(MacAlgo::CmacAes128),
            "CMAC-AES-256" | "cmac-aes-256" | "CMACAES256" => Ok(MacAlgo::CmacAes256),
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }
}

// ── TryFrom<&str> ─────────────────────────────────────────────────────────────

impl TryFrom<&str> for MacAlgo {
    type Error = CryptoError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}
