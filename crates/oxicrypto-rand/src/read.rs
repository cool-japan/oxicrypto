//! `std::io::Read` implementations for [`OxiRng`] and [`ReseedingRng`].
//!
//! Gated behind the `std` feature.

#[cfg(feature = "std")]
use crate::{OxiRng, ReseedingRng};
#[cfg(feature = "std")]
use oxicrypto_core::Rng;

/// `OxiRng` implements [`std::io::Read`] so that callers can use it anywhere
/// a byte-stream reader is expected (e.g., key-derivation utilities that read
/// from arbitrary `Read` sources).
///
/// Each `read()` call fills the entire output buffer with cryptographically
/// secure random bytes.  Returns an I/O error only if the underlying OS RNG
/// becomes unavailable (extremely rare — equivalent to a system failure).
#[cfg(feature = "std")]
impl std::io::Read for OxiRng {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.fill(buf)
            .map_err(|e| std::io::Error::other(format!("{e}")))?;
        Ok(buf.len())
    }
}

/// `ReseedingRng` implements [`std::io::Read`] for the same reasons as
/// [`OxiRng`], additionally triggering automatic reseeds on threshold crossing.
#[cfg(feature = "std")]
impl std::io::Read for ReseedingRng {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.fill(buf)
            .map_err(|e| std::io::Error::other(format!("{e}")))?;
        Ok(buf.len())
    }
}
