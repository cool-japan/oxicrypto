//! Hybrid Public Key Encryption (HPKE) — RFC 9180.
//!
//! HPKE composes a KEM, a KDF, and an AEAD into a complete public-key
//! encryption scheme used by TLS Encrypted ClientHello, MLS, and OHTTP. This
//! module implements the full construction:
//!
//! * **DHKEM** with `Encap`/`Decap` and the authenticated `AuthEncap`/`AuthDecap`,
//!   over X25519 (`kem_id 0x0020`) and NIST P-256 (`kem_id 0x0010`);
//! * **labeled HKDF** (`LabeledExtract`/`LabeledExpand`, §4) over SHA-256/384/512;
//! * the **key schedule** for all four modes — Base, PSK, Auth, AuthPSK (§5.1);
//! * the stateful **encryption context** — `Seal`/`Open`/`Export` with nonce
//!   sequencing (§5.2–§5.3), split into directional sender/recipient halves; and
//! * single-shot [`HpkeSuite::seal_base`] / [`HpkeSuite::open_base`] (§6.1).
//!
//! # Wire formats
//!
//! Public keys in this API use HPKE serialization (`Npk` bytes: 32 for X25519,
//! 65 **uncompressed** SEC1 for P-256). Secret keys are raw scalar bytes
//! (`Nsk = 32`). `derive_key_pair` returns `(SecretVec, Vec<u8>)` — the secret
//! scalar (zeroizing) and the serialized public key.
//!
//! # Example
//!
//! ```
//! use oxicrypto_kex::hpke::{AeadId, HpkeSuite, KdfId, KemId};
//! use rand_chacha::ChaCha20Rng;
//! use rand_core::SeedableRng;
//!
//! let suite = HpkeSuite::new(
//!     KemId::DhkemX25519HkdfSha256,
//!     KdfId::HkdfSha256,
//!     AeadId::Aes128Gcm,
//! );
//! let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
//!
//! // Recipient key pair.
//! let (sk_r, pk_r) = suite.generate_key_pair(&mut rng).expect("keygen");
//!
//! // Sender: set up, seal a message.
//! let info = b"shared context";
//! let (enc, mut sctx) = suite.setup_base_s(&pk_r, info, &mut rng).expect("setup S");
//! let ct = sctx.seal(b"aad", b"secret message").expect("seal");
//!
//! // Recipient: set up from `enc`, open.
//! let mut rctx = suite.setup_base_r(&enc, sk_r.as_bytes(), info).expect("setup R");
//! let pt = rctx.open(b"aad", &ct).expect("open");
//! assert_eq!(pt, b"secret message");
//! ```

pub mod context;
pub mod ids;
pub mod kem;
pub mod key_schedule;
pub mod labeled;
pub mod suite;

#[cfg(test)]
mod tests;

pub use context::{HpkeContextR, HpkeContextS};
pub use ids::{AeadId, KdfId, KemId};
pub use key_schedule::HpkeMode;
pub use suite::HpkeSuite;
