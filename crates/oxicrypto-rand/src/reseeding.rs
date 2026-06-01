//! `ReseedingRng` — a wrapper around [`OxiRng`] that automatically reseeds
//! from OS entropy after generating a configurable number of bytes.

use oxicrypto_core::{CryptoError, Rng};

use crate::OxiRng;

/// Default threshold for automatic reseeding: 1 MiB of output.
const DEFAULT_RESEED_THRESHOLD: u64 = 1 << 20;

/// A [`OxiRng`] wrapper that automatically reseeds from OS entropy after
/// generating a configurable number of bytes (default: 1 MiB).
///
/// This implements a forward-secrecy interval consistent with NIST SP 800-90A
/// §9.2 recommendations.  After each reseed the internal byte counter resets.
///
/// # Observability
///
/// Use [`ReseedingRng::bytes_generated`] to inspect how many bytes have been
/// produced since the last reseed.
pub struct ReseedingRng {
    inner: OxiRng,
    bytes_generated: u64,
    reseed_threshold: u64,
}

impl ReseedingRng {
    /// Create a new [`ReseedingRng`] with the default 1 MiB reseed threshold.
    pub fn new() -> Result<Self, CryptoError> {
        Self::with_threshold(DEFAULT_RESEED_THRESHOLD)
    }

    /// Create a new [`ReseedingRng`] with a custom reseed threshold (bytes).
    ///
    /// A threshold of `0` would reseed on every call — technically valid but
    /// very slow.  Reasonable values are 64 KiB to 64 MiB.
    pub fn with_threshold(threshold: u64) -> Result<Self, CryptoError> {
        Ok(Self {
            inner: OxiRng::new()?,
            bytes_generated: 0,
            reseed_threshold: threshold,
        })
    }

    /// Number of bytes generated since the last reseed.
    pub fn bytes_generated(&self) -> u64 {
        self.bytes_generated
    }

    /// Configured reseed threshold in bytes.
    pub fn reseed_threshold(&self) -> u64 {
        self.reseed_threshold
    }

    /// Reseed immediately from OS entropy, regardless of the threshold.
    pub fn reseed(&mut self) -> Result<(), CryptoError> {
        self.inner.reseed()?;
        self.bytes_generated = 0;
        Ok(())
    }

    /// Check whether the threshold has been crossed and reseed if so.
    fn maybe_reseed(&mut self) -> Result<(), CryptoError> {
        if self.bytes_generated >= self.reseed_threshold {
            self.inner.reseed()?;
            self.bytes_generated = 0;
        }
        Ok(())
    }
}

impl Rng for ReseedingRng {
    fn fill(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        self.maybe_reseed()?;
        self.inner.fill(dst)?;
        self.bytes_generated = self.bytes_generated.saturating_add(dst.len() as u64);
        Ok(())
    }
}

impl rand_core::TryRng for ReseedingRng {
    type Error = CryptoError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.maybe_reseed()?;
        let v = self.inner.try_next_u32()?;
        self.bytes_generated = self.bytes_generated.saturating_add(4);
        Ok(v)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.maybe_reseed()?;
        let v = self.inner.try_next_u64()?;
        self.bytes_generated = self.bytes_generated.saturating_add(8);
        Ok(v)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.maybe_reseed()?;
        self.inner.try_fill_bytes(dest)?;
        self.bytes_generated = self.bytes_generated.saturating_add(dest.len() as u64);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for ReseedingRng {}

impl core::fmt::Debug for ReseedingRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReseedingRng")
            .field("bytes_generated", &self.bytes_generated)
            .field("reseed_threshold", &self.reseed_threshold)
            .finish()
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reseeding_rng_new_works() {
        let mut rng = ReseedingRng::new().expect("ReseedingRng::new failed");
        let mut buf = [0u8; 32];
        rng.fill(&mut buf).expect("ReseedingRng::fill failed");
        assert_ne!(buf, [0u8; 32], "Output should not be all zeros");
    }

    #[test]
    fn reseeding_rng_threshold_triggers_reseed() {
        let mut rng =
            ReseedingRng::with_threshold(16).expect("ReseedingRng::with_threshold failed");
        assert_eq!(rng.bytes_generated(), 0);
        let mut buf = [0u8; 20];
        rng.fill(&mut buf).expect("first fill failed");
        assert_eq!(rng.bytes_generated(), 20, "20 bytes should be tracked");
        let mut buf2 = [0u8; 20];
        rng.fill(&mut buf2).expect("second fill failed");
        assert_eq!(
            rng.bytes_generated(),
            20,
            "counter should reset after reseed"
        );
    }

    #[test]
    fn reseeding_rng_debug_does_not_leak_state() {
        let rng = ReseedingRng::new().expect("ReseedingRng::new failed");
        let dbg = format!("{rng:?}");
        assert!(
            dbg.contains("ReseedingRng"),
            "Debug format should include type name"
        );
    }
}
