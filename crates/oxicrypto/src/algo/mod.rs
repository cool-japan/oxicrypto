//! Algorithm selector enums and factory functions.
//!
//! Each sub-module defines one or more `*Algo` enums, the corresponding
//! `*_impl()` factory function (when the `pure` feature is enabled), and
//! `Display`, `FromStr`, and `TryFrom<&str>` conversions.

pub mod aead;
pub mod hash;
pub mod kdf;
pub mod kex;
pub mod mac;
pub mod pq;
pub mod sig;

// Re-export everything so the types are accessible as `oxicrypto::HashAlgo` etc.
pub use aead::*;
pub use hash::*;
pub use kdf::*;
pub use kex::*;
pub use mac::*;
#[cfg(feature = "pq-preview")]
pub use pq::*;
pub use sig::*;
