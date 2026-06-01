//! `oxicrypto-adapter-pkcs11` — OxiCrypto adapter for PKCS#11 HSMs.
//!
//! Enable the `pkcs11` feature to activate HSM-backed provider, signer, and
//! symmetric cipher implementations via the `cryptoki` crate.
//!
//! # Feature flags
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `pkcs11` | off | Enable cryptoki-backed HSM implementations. |

#[cfg(feature = "pkcs11")]
pub mod provider;

#[cfg(feature = "pkcs11")]
pub mod sign;

#[cfg(feature = "pkcs11")]
pub mod sym;
