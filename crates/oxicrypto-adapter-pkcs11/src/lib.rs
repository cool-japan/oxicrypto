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
//! | `bench` | off | Enable criterion benchmarks (implies `pkcs11`). |

#[cfg(feature = "pkcs11")]
pub mod hash;

#[cfg(feature = "pkcs11")]
pub mod pool;

#[cfg(feature = "pkcs11")]
pub mod provider;

#[cfg(feature = "pkcs11")]
pub mod sign;

#[cfg(feature = "pkcs11")]
pub mod sym;

#[cfg(feature = "pkcs11")]
mod hsm_keygen;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "pkcs11")]
pub use hash::{DigestMechanism, Pkcs11Hash};

#[cfg(feature = "pkcs11")]
pub use pool::{Pkcs11SessionPool, PooledSession};

#[cfg(feature = "pkcs11")]
pub use provider::{Pkcs11Provider, PkcsError};

#[cfg(feature = "pkcs11")]
pub use sign::{Pkcs11Signer, Pkcs11SignerBuilder, Pkcs11Verifier, SignMechanism};

#[cfg(feature = "pkcs11")]
pub use sym::{Pkcs11Aead, Pkcs11SymOp};

#[cfg(feature = "tls")]
pub use tls::{Pkcs11TlsSigner, Pkcs11TlsSigningKey};
