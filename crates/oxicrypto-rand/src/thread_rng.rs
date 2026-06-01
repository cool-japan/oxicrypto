//! Per-thread CSPRNG via [`with_thread_rng`].
//!
//! Gated behind the `std` feature.

#[cfg(feature = "std")]
use oxicrypto_core::CryptoError;

#[cfg(feature = "std")]
use crate::OxiRng;

// `thread_local!` requires std (not available in `no_std + alloc` environments).
// Gate behind the `std` feature.
#[cfg(feature = "std")]
extern crate std as std_crate;

#[cfg(feature = "std")]
std_crate::thread_local! {
    static THREAD_RNG: core::cell::RefCell<Option<OxiRng>> = const { core::cell::RefCell::new(None) };
}

/// Run a closure with a reference to the thread-local [`OxiRng`].
///
/// The RNG is lazily initialized on first use per thread.
///
/// Returns `Err(CryptoError::Rng)` if the RNG cannot be initialized, or
/// `Err(CryptoError::Internal)` if the thread-local cell is already borrowed
/// (re-entrancy guard).
///
/// # Feature
///
/// This function is only available when the `std` feature is enabled.
#[cfg(feature = "std")]
pub fn with_thread_rng<F, R>(f: F) -> Result<R, CryptoError>
where
    F: FnOnce(&mut OxiRng) -> Result<R, CryptoError>,
{
    THREAD_RNG.with(|cell| {
        let mut opt = cell
            .try_borrow_mut()
            .map_err(|_| CryptoError::Internal("thread RNG re-entered"))?;
        if opt.is_none() {
            *opt = Some(OxiRng::new()?);
        }
        // SAFETY: we just ensured `opt` is `Some`; no panic path exists.
        f(opt.as_mut().ok_or(CryptoError::Rng)?)
    })
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::*;
    use oxicrypto_core::Rng;

    #[test]
    fn thread_rng_works() {
        let mut buf = [0u8; 32];
        with_thread_rng(|rng| rng.fill(&mut buf)).expect("with_thread_rng failed");
        assert_ne!(buf, [0u8; 32], "Thread RNG output should not be all zeros");
    }

    #[test]
    fn thread_rng_two_threads_differ() {
        use std::sync::mpsc;
        use std::thread;

        let (tx1, rx1) = mpsc::channel::<[u8; 32]>();
        let (tx2, rx2) = mpsc::channel::<[u8; 32]>();

        thread::spawn(move || {
            let mut buf = [0u8; 32];
            with_thread_rng(|rng| rng.fill(&mut buf)).expect("thread 1 with_thread_rng failed");
            tx1.send(buf).expect("tx1 send failed");
        });

        thread::spawn(move || {
            let mut buf = [0u8; 32];
            with_thread_rng(|rng| rng.fill(&mut buf)).expect("thread 2 with_thread_rng failed");
            tx2.send(buf).expect("tx2 send failed");
        });

        let out1 = rx1.recv().expect("rx1 recv failed");
        let out2 = rx2.recv().expect("rx2 recv failed");

        assert_ne!(
            out1, out2,
            "Two threads should produce different RNG output"
        );
    }
}
