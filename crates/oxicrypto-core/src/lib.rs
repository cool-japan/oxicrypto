#![forbid(unsafe_code)]
#![no_std]

//! `oxicrypto-core` -- pure-Rust trait surface, error types, and secure
//! wrappers for the OxiCrypto stack.
//!
//! This crate is `no_std + alloc`.  It defines the trait objects, error enum,
//! constant-time utilities, and secret-key wrappers shared by every other
//! `oxicrypto-*` sub-crate.  No crypto implementation lives here.

extern crate alloc;

pub use alloc::boxed::Box;
pub use alloc::string::String;
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
pub use secret::{KeyPair, SecretKey, SecretVec};
pub use traits::{
    Aead, Hash, Kdf, Kem, KeyAgreement, KeyGenerator, Mac, PasswordHash, PasswordHashParams, Rng,
    Signer, StreamingAead, StreamingHash, StreamingMac, Verifier,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
