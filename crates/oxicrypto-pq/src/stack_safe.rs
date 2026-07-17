//! Stack-safe wrappers for ML-DSA-87.
//!
//! ML-DSA-87 (FIPS 204, security category 5) is the largest parameter set in
//! this crate.  Its key generation, signing, and verification routines build
//! large transient working buffers **on the stack** inside the upstream
//! `ml-dsa` crate — the `expand_a` NTT matrix (an 8×7 array of degree-256
//! polynomials) plus the `y` / `w` / `cs1` / `cs2` / `z` / `ct0` vectors used
//! by `SigningKey::from_seed` and the internal `raw_sign` path.  These
//! temporaries live only for the duration of the call, but they are large
//! enough to overflow the default stack of a worker thread.
//!
//! ## Why we cannot simply heap-relocate the buffers
//!
//! The *persistent* objects (`SigningKey`, `VerifyingKey`, `Signature`) are
//! **already heap-backed** by `ml-dsa` via `module-lattice`'s `MaybeBox` type
//! (the `alloc` feature is enabled in this workspace), so there is nothing left
//! for `oxicrypto-pq` to box.  The remaining stack pressure comes from
//! temporaries *inside* upstream functions, which we cannot relocate without
//! forking `ml-dsa`.  The honest, portable mitigation is therefore to run the
//! operation on a worker thread with an explicitly sized stack.
//!
//! ## Measured requirement
//!
//! A binary-search probe against this exact crate (per-process, one stack size
//! per process so an overflow aborts cleanly) measured the full
//! keygen + sign + verify sequence for ML-DSA-87 as:
//!
//! | Build profile | Largest stack that overflows | Smallest that succeeds |
//! |---------------|------------------------------|------------------------|
//! | debug (`opt-level = 0`) | 512 KiB | 768 KiB |
//! | release (`opt-level = 3`) | 256 KiB | 512 KiB |
//!
//! [`OXICRYPTO_MLDSA_STACK`] is set to **2 MiB**, i.e. ≈2.7× the worst-case
//! (debug) requirement — comfortable head-room across compilers, allocators,
//! and future `ml-dsa` revisions, while being 4× smaller than the historical
//! 8 MiB figure that the crate documentation previously (over-conservatively)
//! quoted.
//!
//! ## API
//!
//! These helpers return owned byte vectors (seed / verifying-key / signature)
//! rather than the typed key structs, so callers never have to thread the large
//! working set back across the worker-thread boundary and the results are
//! immediately serializable.  The bytes are fully interoperable with the typed
//! [`MlDsa87`] / [`SigningKey87`] / [`VerifyingKey87`] / [`crate::mldsa::Signature87`] API.

use std::thread;

use oxicrypto_core::CryptoError;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::mldsa::{MlDsa87, SigningKey87, VerifyingKey87};

/// Worker-thread stack size (bytes) used by [`run_on_large_stack`] for
/// ML-DSA-87 operations.
///
/// 2 MiB ≈ 2.7× the measured worst-case (debug) requirement of 768 KiB for a
/// full keygen + sign + verify sequence.  See the module documentation for the
/// measurement methodology.
pub const OXICRYPTO_MLDSA_STACK: usize = 2 * 1024 * 1024;

/// Run `f` on a dedicated worker thread that has a
/// [`OXICRYPTO_MLDSA_STACK`]-byte stack, returning its result.
///
/// This is the building block for the stack-safe ML-DSA-87 helpers: it lets a
/// caller run an operation whose transient stack footprint exceeds the ambient
/// thread's stack without risking a stack overflow (which, unlike a panic,
/// cannot be caught and aborts the whole process).
///
/// The closure may borrow from its environment (a scoped thread is used), so no
/// `'static` bound is imposed.
///
/// # Errors
///
/// Returns [`CryptoError::Internal`] if the worker thread cannot be spawned
/// (e.g. the OS refuses the thread) or if it panics.  No panic from `f` is
/// allowed to unwind across this boundary.
pub fn run_on_large_stack<F, T>(f: F) -> Result<T, CryptoError>
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    thread::scope(|scope| {
        let handle = thread::Builder::new()
            .name("oxicrypto-mldsa87".into())
            .stack_size(OXICRYPTO_MLDSA_STACK)
            .spawn_scoped(scope, f)
            .map_err(|_| CryptoError::Internal("failed to spawn ML-DSA-87 worker thread"))?;
        handle
            .join()
            .map_err(|_| CryptoError::Internal("ML-DSA-87 worker thread panicked"))
    })
}

/// Generate an ML-DSA-87 key pair on a stack-safe worker thread.
///
/// Returns `(signing_key_seed, verifying_key_bytes)`:
///
/// * `signing_key_seed` — the 32-byte FIPS 204 seed for the signing key,
///   suitable for [`SigningKey87::from_bytes`]. **Secret material.**
/// * `verifying_key_bytes` — the 2592-byte encoded verifying key, suitable for
///   [`VerifyingKey87::from_bytes`].
///
/// The underlying CSPRNG is a ChaCha20 instance seeded from the operating
/// system entropy source via `oxicrypto-rand`.
///
/// # Errors
///
/// Returns [`CryptoError::Rng`] if OS entropy is unavailable, or
/// [`CryptoError::Internal`] if the worker thread fails (see
/// [`run_on_large_stack`]).
#[must_use = "the generated key material must be used or stored"]
pub fn mldsa87_generate_stack_safe() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let entropy = oxicrypto_rand::random_bytes(32)?;
    let mut seed = [0u8; 32];
    // `random_bytes(32)` always returns exactly 32 bytes on success.
    if entropy.len() != 32 {
        return Err(CryptoError::Rng);
    }
    seed.copy_from_slice(&entropy);

    run_on_large_stack(move || {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let (sk, vk) = MlDsa87::generate(&mut rng);
        (sk.to_bytes(), vk.to_bytes())
    })
}

/// Sign `msg` with an ML-DSA-87 signing key (given as its 32-byte seed) on a
/// stack-safe worker thread.
///
/// `signing_key_seed` must be the 32-byte seed returned by
/// [`mldsa87_generate_stack_safe`] or [`SigningKey87::to_bytes`].  Returns the
/// 4627-byte encoded signature.
///
/// # Errors
///
/// * [`CryptoError::Encoding`] if `signing_key_seed` is not a valid 32-byte
///   seed.
/// * [`CryptoError::Sign`] if signing fails.
/// * [`CryptoError::Internal`] if the worker thread fails.
#[must_use = "the produced signature must be used or transmitted"]
pub fn mldsa87_sign_stack_safe(
    signing_key_seed: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    run_on_large_stack(move || {
        let sk = SigningKey87::from_bytes(signing_key_seed)?;
        let sig = sk.sign(msg)?;
        Ok(sig.to_bytes())
    })?
}

/// Verify an ML-DSA-87 signature on a stack-safe worker thread.
///
/// `verifying_key_bytes` must be the 2592-byte encoded verifying key; `sig`
/// must be the 4627-byte encoded signature.
///
/// # Errors
///
/// * [`CryptoError::Encoding`] if the verifying key or signature bytes are
///   malformed.
/// * [`CryptoError::Sign`] if the signature does not verify.
/// * [`CryptoError::Internal`] if the worker thread fails.
#[must_use = "verification result must be checked"]
pub fn mldsa87_verify_stack_safe(
    verifying_key_bytes: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), CryptoError> {
    run_on_large_stack(move || {
        let vk = VerifyingKey87::from_bytes(verifying_key_bytes)?;
        let signature = crate::mldsa::Signature87::from_bytes(sig)?;
        vk.verify(msg, &signature)
    })?
}
