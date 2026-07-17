#![forbid(unsafe_code)]
#![no_std]

//! `oxicrypto-core` -- pure-Rust trait surface, error types, and secure
//! wrappers for the OxiCrypto stack.
//!
//! This crate is `no_std`.  With the default `alloc` feature it is
//! `no_std + alloc`; with `--no-default-features` it links only `core` and
//! exposes a genuinely allocation-free API surface (`SecretKey<N>`,
//! `Hash::hash` / `hash_to_array::<N>`, constant-time utilities, `CryptoError`,
//! `AlgorithmId`).  It defines the trait objects, error enum, constant-time
//! utilities, and secret-key wrappers shared by every other `oxicrypto-*`
//! sub-crate.  No crypto implementation lives here.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub use alloc::boxed::Box;
#[cfg(feature = "alloc")]
pub use alloc::string::String;
#[cfg(feature = "alloc")]
pub use alloc::vec::Vec;

// Re-export `subtle` so downstream crates use a single version.
pub use subtle::ConstantTimeEq;
pub use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Submodules
// ---------------------------------------------------------------------------

mod algo_id;
mod ct;
mod error;
mod secret;
pub mod traits;

// ---------------------------------------------------------------------------
// Public re-exports
// ---------------------------------------------------------------------------

pub use algo_id::{AlgorithmCategory, AlgorithmId};
pub use ct::{ct_eq, ct_is_zero, ct_select};
pub use error::CryptoError;
#[cfg(feature = "alloc")]
pub use secret::SecretVec;
pub use secret::{KeyPair, SecretKey};
#[cfg(feature = "alloc")]
pub use traits::KeyGenerator;
pub use traits::{
    Aead, Hash, Kdf, Kem, KeyAgreement, Mac, PasswordHash, PasswordHashParams, Rng, Signer,
    StreamingAead, StreamingHash, StreamingMac, Verifier,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// The in-crate test suite exercises the alloc-returning convenience methods, so
// it is only compiled when the `alloc` feature is on (the default).
#[cfg(all(test, feature = "alloc"))]
mod tests;
