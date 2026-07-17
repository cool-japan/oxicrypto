pub mod aead;
pub mod hash;
pub mod kdf;
pub mod kex;
pub mod mac;
pub mod pq;
pub mod rng;
pub mod sig;

pub use aead::{Aead, StreamingAead};
pub use hash::{Hash, StreamingHash};
pub use kdf::{Kdf, PasswordHash, PasswordHashParams};
pub use kex::KeyAgreement;
pub use mac::{Mac, StreamingMac};
pub use pq::Kem;
pub use rng::Rng;
#[cfg(feature = "alloc")]
pub use sig::KeyGenerator;
pub use sig::{Signer, Verifier};

// ---------------------------------------------------------------------------
// MaybeDebug — conditional Debug supertrait
// ---------------------------------------------------------------------------
//
// When the `debug` Cargo feature is enabled every core trait additionally
// requires `core::fmt::Debug` as a supertrait, making `Box<dyn Kdf>` etc.
// printable.  Without the feature the bound is erased.
//
// Usage in trait definitions:
//   `pub trait Kdf: Send + Sync + crate::traits::MaybeDebug { … }`

#[cfg(feature = "debug")]
pub trait MaybeDebug: core::fmt::Debug {}
#[cfg(feature = "debug")]
impl<T: core::fmt::Debug> MaybeDebug for T {}

#[cfg(not(feature = "debug"))]
pub trait MaybeDebug {}
#[cfg(not(feature = "debug"))]
impl<T> MaybeDebug for T {}
