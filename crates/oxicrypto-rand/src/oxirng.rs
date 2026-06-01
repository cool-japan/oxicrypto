//! ChaCha-based CSPRNG implementations: `OxiRng` (ChaCha20), `OxiRng8`
//! (ChaCha8), and `OxiRng12` (ChaCha12).
//!
//! All three variants are fork-safe on Unix via PID tracking.

use oxicrypto_core::{CryptoError, Rng};
use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, TryRng};

// ── OxiRng (ChaCha20) ────────────────────────────────────────────────────────

/// A ChaCha20 CSPRNG seeded from the OS random source.
///
/// Use [`OxiRng::new`] to create an instance.  The seed is obtained from
/// `getrandom::fill` which calls `/dev/urandom`, `RtlGenRandom`, or
/// `arc4random` depending on the platform — no C library required.
///
/// On Unix platforms, [`OxiRng`] automatically reseeds itself if the process
/// PID changes (i.e. after a `fork()`), preventing parent/child state sharing.
pub struct OxiRng {
    pub(crate) inner: ChaCha20Rng,
    #[cfg(unix)]
    pub(crate) last_pid: u32,
}

impl OxiRng {
    /// Create a new [`OxiRng`] seeded from the OS.
    ///
    /// Returns [`CryptoError::Internal`] if `getrandom` fails.
    #[must_use = "the RNG must be stored and used; discarding it serves no purpose"]
    pub fn new() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| CryptoError::Internal("getrandom failed"))?;
        Ok(Self {
            inner: ChaCha20Rng::from_seed(seed),
            #[cfg(unix)]
            last_pid: std::process::id(),
        })
    }

    /// Reseed this RNG from OS entropy.
    ///
    /// Replaces the internal ChaCha20 state with a fresh 32-byte seed and
    /// updates the stored PID to the current process.  The free function
    /// [`crate::reseed`] is kept for backward compatibility.
    ///
    /// Returns [`CryptoError::Rng`] if `getrandom` fails.
    pub fn reseed(&mut self) -> Result<(), CryptoError> {
        crate::helpers::reseed(self)
    }

    /// Fill a fixed-size array with cryptographically random bytes.
    pub fn fill_exact<const N: usize>(&mut self, dst: &mut [u8; N]) -> Result<(), CryptoError> {
        self.fill(dst.as_mut_slice())
    }

    /// Detect fork: if PID changed since construction, reseed from OS entropy.
    ///
    /// This prevents child processes from sharing CSPRNG state with the parent.
    #[cfg(unix)]
    pub(crate) fn check_fork(&mut self) -> Result<(), CryptoError> {
        let current_pid = std::process::id();
        if current_pid != self.last_pid {
            // PID changed: we're in a child process — reseed to avoid state sharing.
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|_| CryptoError::Rng)?;
            self.inner = ChaCha20Rng::from_seed(seed);
            self.last_pid = current_pid;
        }
        Ok(())
    }
}

impl Rng for OxiRng {
    fn fill(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        #[cfg(unix)]
        self.check_fork()?;
        self.inner
            .try_fill_bytes(dst)
            .map_err(|_| CryptoError::Rng)?;
        Ok(())
    }
}

impl core::fmt::Debug for OxiRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OxiRng { [state redacted] }")
    }
}

impl core::fmt::Display for OxiRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OxiRng(ChaCha20)")
    }
}

// Implement `rand_core::TryRng` so that `OxiRng` can be used with crates
// requiring `TryCryptoRng` bounds (e.g. `ml-kem`, `ml-dsa`, `p256`, etc.).
//
// Error type is `CryptoError` because `try_fill_bytes` calls `check_fork`,
// which may fail if `getrandom` is unavailable after a fork.

impl rand_core::TryRng for OxiRng {
    type Error = CryptoError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.inner.try_next_u32().map_err(|_| CryptoError::Rng)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.inner.try_next_u64().map_err(|_| CryptoError::Rng)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        #[cfg(unix)]
        self.check_fork()?;
        self.inner
            .try_fill_bytes(dest)
            .map_err(|_| CryptoError::Rng)
    }
}

impl rand_core::TryCryptoRng for OxiRng {}

// ── OxiRng8 (ChaCha8) ────────────────────────────────────────────────────────

/// A ChaCha8 CSPRNG seeded from the OS random source.
///
/// ChaCha8 uses 8 rounds instead of 20, offering higher throughput at the cost
/// of a smaller security margin.  Suitable for performance-critical paths where
/// full ChaCha20 is not needed.
///
/// Fork-safe: on Unix, detects `fork()` via PID tracking and reseeds.
pub struct OxiRng8 {
    inner: rand_chacha::ChaCha8Rng,
    #[cfg(unix)]
    last_pid: u32,
}

impl OxiRng8 {
    /// Create a new [`OxiRng8`] seeded from the OS.
    pub fn new() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| CryptoError::Internal("getrandom failed"))?;
        Ok(Self {
            inner: rand_chacha::ChaCha8Rng::from_seed(seed),
            #[cfg(unix)]
            last_pid: std::process::id(),
        })
    }

    /// Reseed from OS entropy.
    pub fn reseed(&mut self) -> Result<(), CryptoError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| CryptoError::Rng)?;
        self.inner = rand_chacha::ChaCha8Rng::from_seed(seed);
        #[cfg(unix)]
        {
            self.last_pid = std::process::id();
        }
        Ok(())
    }

    #[cfg(unix)]
    fn check_fork(&mut self) -> Result<(), CryptoError> {
        let current_pid = std::process::id();
        if current_pid != self.last_pid {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|_| CryptoError::Rng)?;
            self.inner = rand_chacha::ChaCha8Rng::from_seed(seed);
            self.last_pid = current_pid;
        }
        Ok(())
    }
}

impl Rng for OxiRng8 {
    fn fill(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        #[cfg(unix)]
        self.check_fork()?;
        self.inner.try_fill_bytes(dst).map_err(|_| CryptoError::Rng)
    }
}

impl rand_core::TryRng for OxiRng8 {
    type Error = CryptoError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.inner.try_next_u32().map_err(|_| CryptoError::Rng)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.inner.try_next_u64().map_err(|_| CryptoError::Rng)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        #[cfg(unix)]
        self.check_fork()?;
        self.inner
            .try_fill_bytes(dest)
            .map_err(|_| CryptoError::Rng)
    }
}

impl rand_core::TryCryptoRng for OxiRng8 {}

impl core::fmt::Debug for OxiRng8 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OxiRng8").finish_non_exhaustive()
    }
}

// ── OxiRng12 (ChaCha12) ──────────────────────────────────────────────────────

/// A ChaCha12 CSPRNG seeded from the OS random source.
///
/// ChaCha12 uses 12 rounds — a middle ground between ChaCha8 (8 rounds) and
/// ChaCha20 (20 rounds), offering good performance with a higher security
/// margin than ChaCha8.
///
/// Fork-safe: on Unix, detects `fork()` via PID tracking and reseeds.
pub struct OxiRng12 {
    inner: rand_chacha::ChaCha12Rng,
    #[cfg(unix)]
    last_pid: u32,
}

impl OxiRng12 {
    /// Create a new [`OxiRng12`] seeded from the OS.
    pub fn new() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| CryptoError::Internal("getrandom failed"))?;
        Ok(Self {
            inner: rand_chacha::ChaCha12Rng::from_seed(seed),
            #[cfg(unix)]
            last_pid: std::process::id(),
        })
    }

    /// Reseed from OS entropy.
    pub fn reseed(&mut self) -> Result<(), CryptoError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| CryptoError::Rng)?;
        self.inner = rand_chacha::ChaCha12Rng::from_seed(seed);
        #[cfg(unix)]
        {
            self.last_pid = std::process::id();
        }
        Ok(())
    }

    #[cfg(unix)]
    fn check_fork(&mut self) -> Result<(), CryptoError> {
        let current_pid = std::process::id();
        if current_pid != self.last_pid {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|_| CryptoError::Rng)?;
            self.inner = rand_chacha::ChaCha12Rng::from_seed(seed);
            self.last_pid = current_pid;
        }
        Ok(())
    }
}

impl Rng for OxiRng12 {
    fn fill(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        #[cfg(unix)]
        self.check_fork()?;
        self.inner.try_fill_bytes(dst).map_err(|_| CryptoError::Rng)
    }
}

impl rand_core::TryRng for OxiRng12 {
    type Error = CryptoError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.inner.try_next_u32().map_err(|_| CryptoError::Rng)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.inner.try_next_u64().map_err(|_| CryptoError::Rng)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        #[cfg(unix)]
        self.check_fork()?;
        self.inner
            .try_fill_bytes(dest)
            .map_err(|_| CryptoError::Rng)
    }
}

impl rand_core::TryCryptoRng for OxiRng12 {}

impl core::fmt::Debug for OxiRng12 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OxiRng12").finish_non_exhaustive()
    }
}

// ── Unit tests that require private field access ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oxi_rng_creates_ok() {
        let rng = OxiRng::new();
        assert!(rng.is_ok(), "OxiRng::new() should succeed on this platform");
    }

    #[test]
    fn oxi_rng_fills_buffer() {
        let mut rng = OxiRng::new().expect("OxiRng::new failed");
        let mut buf = [0u8; 64];
        rng.fill(&mut buf).expect("fill should succeed");
        assert_ne!(buf, [0u8; 64], "Random bytes should not all be zero");
    }

    #[test]
    fn oxi_rng_two_outputs_differ() {
        let mut rng = OxiRng::new().expect("OxiRng::new failed");
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        rng.fill(&mut buf1).expect("fill 1 failed");
        rng.fill(&mut buf2).expect("fill 2 failed");
        assert_ne!(buf1, buf2, "Consecutive RNG outputs should differ");
    }

    #[test]
    fn oxi_rng_reseed_method_changes_output() {
        let mut rng = OxiRng::new().expect("new failed");
        let mut buf1 = [0u8; 32];
        rng.fill(&mut buf1).expect("fill 1 failed");
        rng.reseed().expect("OxiRng::reseed() failed");
        let mut buf2 = [0u8; 32];
        rng.fill(&mut buf2).expect("fill 2 failed");
        assert_ne!(buf1, buf2, "Output after reseed() should differ");
    }

    #[cfg(unix)]
    #[test]
    fn fork_safe_pid_simulation() {
        let mut rng = OxiRng::new().expect("OxiRng::new failed");
        let mut before = [0u8; 32];
        rng.fill(&mut before).expect("fill before failed");
        // Simulate a fork by setting last_pid to a fake value.
        rng.last_pid = 0; // PID 0 is never a real user process PID.
        let mut after = [0u8; 32];
        rng.fill(&mut after)
            .expect("fill after fork-simulation failed");
        assert_ne!(
            before, after,
            "After fork simulation, RNG should have reseeded"
        );
        assert_eq!(rng.last_pid, std::process::id());
    }

    #[test]
    fn oxi_rng_implements_try_crypto_rng() {
        fn requires_try_crypto_rng<R: rand_core::TryCryptoRng>(_rng: &mut R) {}
        let mut rng = OxiRng::new().expect("new failed");
        requires_try_crypto_rng(&mut rng);
    }

    #[test]
    fn oxi_rng_debug_does_not_leak_state() {
        let rng = OxiRng::new().expect("OxiRng::new failed");
        let dbg = std::format!("{rng:?}");
        assert!(dbg.contains("OxiRng"), "Debug must include type name");
        assert!(
            dbg.contains("redacted"),
            "Debug must not expose internal state"
        );
    }

    #[test]
    fn oxi_rng_display_shows_algorithm() {
        let rng = OxiRng::new().expect("OxiRng::new failed");
        let display = std::format!("{rng}");
        assert_eq!(
            display, "OxiRng(ChaCha20)",
            "Display must identify the algorithm"
        );
    }

    #[test]
    fn fill_exact_works() {
        let mut rng = OxiRng::new().expect("OxiRng::new failed");
        let mut arr = [0u8; 16];
        rng.fill_exact(&mut arr).expect("fill_exact failed");
        assert_ne!(
            arr, [0u8; 16],
            "fill_exact must not produce all-zero output"
        );
    }

    #[test]
    fn oxi_rng8_fills_buffer() {
        let mut rng = OxiRng8::new().expect("OxiRng8::new failed");
        let mut buf = [0u8; 64];
        rng.fill(&mut buf).expect("OxiRng8::fill failed");
        assert_ne!(buf, [0u8; 64], "OxiRng8 output should not be all zeros");
    }

    #[test]
    fn oxi_rng12_fills_buffer() {
        let mut rng = OxiRng12::new().expect("OxiRng12::new failed");
        let mut buf = [0u8; 64];
        rng.fill(&mut buf).expect("OxiRng12::fill failed");
        assert_ne!(buf, [0u8; 64], "OxiRng12 output should not be all zeros");
    }

    #[test]
    fn oxi_rng8_two_instances_differ() {
        let mut rng1 = OxiRng8::new().expect("OxiRng8::new 1 failed");
        let mut rng2 = OxiRng8::new().expect("OxiRng8::new 2 failed");
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        rng1.fill(&mut buf1).expect("fill 1 failed");
        rng2.fill(&mut buf2).expect("fill 2 failed");
        assert_ne!(
            buf1, buf2,
            "Two independently seeded OxiRng8 instances should differ"
        );
    }

    #[test]
    fn oxi_rng12_two_instances_differ() {
        let mut rng1 = OxiRng12::new().expect("OxiRng12::new 1 failed");
        let mut rng2 = OxiRng12::new().expect("OxiRng12::new 2 failed");
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        rng1.fill(&mut buf1).expect("fill 1 failed");
        rng2.fill(&mut buf2).expect("fill 2 failed");
        assert_ne!(
            buf1, buf2,
            "Two independently seeded OxiRng12 instances should differ"
        );
    }

    #[test]
    fn oxi_rng8_reseed_changes_output() {
        let mut rng = OxiRng8::new().expect("OxiRng8::new failed");
        let mut buf1 = [0u8; 32];
        rng.fill(&mut buf1).expect("fill 1 failed");
        rng.reseed().expect("OxiRng8::reseed failed");
        let mut buf2 = [0u8; 32];
        rng.fill(&mut buf2).expect("fill 2 failed");
        assert_ne!(buf1, buf2, "Output after OxiRng8::reseed should differ");
    }

    #[test]
    fn oxi_rng12_reseed_changes_output() {
        let mut rng = OxiRng12::new().expect("OxiRng12::new failed");
        let mut buf1 = [0u8; 32];
        rng.fill(&mut buf1).expect("fill 1 failed");
        rng.reseed().expect("OxiRng12::reseed failed");
        let mut buf2 = [0u8; 32];
        rng.fill(&mut buf2).expect("fill 2 failed");
        assert_ne!(buf1, buf2, "Output after OxiRng12::reseed should differ");
    }

    #[test]
    fn oxi_rng8_implements_try_crypto_rng() {
        fn requires_try_crypto_rng<R: rand_core::TryCryptoRng>(_rng: &mut R) {}
        let mut rng = OxiRng8::new().expect("OxiRng8::new failed");
        requires_try_crypto_rng(&mut rng);
    }

    #[test]
    fn oxi_rng12_implements_try_crypto_rng() {
        fn requires_try_crypto_rng<R: rand_core::TryCryptoRng>(_rng: &mut R) {}
        let mut rng = OxiRng12::new().expect("OxiRng12::new failed");
        requires_try_crypto_rng(&mut rng);
    }

    #[test]
    fn fill_various_sizes() {
        let mut rng = OxiRng::new().expect("OxiRng::new failed");
        for size in [0usize, 1, 31, 32, 33, 1024] {
            let mut buf = std::vec![0u8; size];
            rng.fill(&mut buf)
                .expect("fill should succeed for all sizes");
            assert_eq!(buf.len(), size, "fill must not change buffer length");
        }
    }

    #[test]
    fn fill_one_byte_not_stuck_at_zero() {
        let mut rng = OxiRng::new().expect("OxiRng::new failed");
        let mut saw_nonzero = false;
        for _ in 0..256 {
            let mut buf = [0u8; 1];
            rng.fill(&mut buf).expect("fill 1 byte");
            if buf[0] != 0 {
                saw_nonzero = true;
                break;
            }
        }
        assert!(
            saw_nonzero,
            "At least one single-byte fill should be non-zero"
        );
    }
}
