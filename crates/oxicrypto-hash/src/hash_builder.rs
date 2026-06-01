// ── HashBuilder: fluent construction of hash instances ──────────────────────
//
//! Ergonomic builder API for constructing boxed hash instances.
//!
//! Instead of naming concrete types directly, callers can fluently select an
//! algorithm and (optionally) switch to streaming mode:
//!
//! ```
//! use oxicrypto_hash::HashBuilder;
//! use oxicrypto_core::{Hash, StreamingHash};
//!
//! // One-shot: returns `Box<dyn Hash>`.
//! let hasher = HashBuilder::sha256().build();
//! let digest = hasher.hash_to_vec(b"abc").unwrap();
//! assert_eq!(digest.len(), 32);
//!
//! // Streaming: returns a sized [`DynStreamingHash`] enum that implements
//! // `StreamingHash` (a boxed `dyn StreamingHash` could not be `finalize`d
//! // because `finalize` consumes `self`).
//! let mut streaming = HashBuilder::sha256().streaming().build();
//! streaming.update(b"a");
//! streaming.update(b"bc");
//! let mut out = [0u8; 32];
//! streaming.finalize(out.as_mut_slice()).unwrap();
//! assert_eq!(&out[..], digest.as_slice());
//! ```
//!
//! The set of algorithms covers the SHA-2 family (SHA-256/384/512, SHA-512/256),
//! the SHA-3 family (SHA3-256/384/512), and BLAKE3.

use alloc::boxed::Box;

use oxicrypto_core::{Hash, StreamingHash};

use crate::{
    Blake3, Blake3Streaming, Sha256, Sha256Streaming, Sha384, Sha384Streaming, Sha3_256,
    Sha3_256Streaming, Sha3_384, Sha3_384Streaming, Sha3_512, Sha3_512Streaming, Sha512,
    Sha512Streaming, Sha512_256, Sha512_256Streaming,
};

/// Hash algorithm selector used by [`HashBuilder`].
///
/// Covers every algorithm the builder can construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 (FIPS 180-4).
    Sha256,
    /// SHA-384 (FIPS 180-4).
    Sha384,
    /// SHA-512 (FIPS 180-4).
    Sha512,
    /// SHA-512/256 truncated (FIPS 180-4 §6.7).
    Sha512_256,
    /// SHA3-256 (FIPS 202).
    Sha3_256,
    /// SHA3-384 (FIPS 202).
    Sha3_384,
    /// SHA3-512 (FIPS 202).
    Sha3_512,
    /// BLAKE3 (32-byte output).
    Blake3,
}

impl HashAlgorithm {
    /// Digest output length in bytes for this algorithm.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            HashAlgorithm::Sha256
            | HashAlgorithm::Sha512_256
            | HashAlgorithm::Sha3_256
            | HashAlgorithm::Blake3 => 32,
            HashAlgorithm::Sha384 | HashAlgorithm::Sha3_384 => 48,
            HashAlgorithm::Sha512 | HashAlgorithm::Sha3_512 => 64,
        }
    }
}

/// Fluent builder producing a boxed one-shot [`Hash`] instance.
///
/// Construct via one of the algorithm constructors (e.g. [`HashBuilder::sha256`]),
/// then call [`build`](HashBuilder::build) for a `Box<dyn Hash>`, or switch to
/// streaming mode with [`streaming`](HashBuilder::streaming).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashBuilder {
    algorithm: HashAlgorithm,
}

impl HashBuilder {
    /// Begin building with an explicit [`HashAlgorithm`].
    #[must_use]
    pub const fn new(algorithm: HashAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Select SHA-256.
    #[must_use]
    pub const fn sha256() -> Self {
        Self::new(HashAlgorithm::Sha256)
    }

    /// Select SHA-384.
    #[must_use]
    pub const fn sha384() -> Self {
        Self::new(HashAlgorithm::Sha384)
    }

    /// Select SHA-512.
    #[must_use]
    pub const fn sha512() -> Self {
        Self::new(HashAlgorithm::Sha512)
    }

    /// Select SHA-512/256.
    #[must_use]
    pub const fn sha512_256() -> Self {
        Self::new(HashAlgorithm::Sha512_256)
    }

    /// Select SHA3-256.
    #[must_use]
    pub const fn sha3_256() -> Self {
        Self::new(HashAlgorithm::Sha3_256)
    }

    /// Select SHA3-384.
    #[must_use]
    pub const fn sha3_384() -> Self {
        Self::new(HashAlgorithm::Sha3_384)
    }

    /// Select SHA3-512.
    #[must_use]
    pub const fn sha3_512() -> Self {
        Self::new(HashAlgorithm::Sha3_512)
    }

    /// Select BLAKE3.
    #[must_use]
    pub const fn blake3() -> Self {
        Self::new(HashAlgorithm::Blake3)
    }

    /// The algorithm currently selected.
    #[must_use]
    pub const fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Switch to streaming mode, returning a [`StreamingHashBuilder`].
    #[must_use]
    pub const fn streaming(self) -> StreamingHashBuilder {
        StreamingHashBuilder {
            algorithm: self.algorithm,
        }
    }

    /// Build a boxed one-shot [`Hash`] for the selected algorithm.
    #[must_use]
    pub fn build(self) -> Box<dyn Hash> {
        match self.algorithm {
            HashAlgorithm::Sha256 => Box::new(Sha256),
            HashAlgorithm::Sha384 => Box::new(Sha384),
            HashAlgorithm::Sha512 => Box::new(Sha512),
            HashAlgorithm::Sha512_256 => Box::new(Sha512_256),
            HashAlgorithm::Sha3_256 => Box::new(Sha3_256),
            HashAlgorithm::Sha3_384 => Box::new(Sha3_384),
            HashAlgorithm::Sha3_512 => Box::new(Sha3_512),
            HashAlgorithm::Blake3 => Box::new(Blake3),
        }
    }
}

/// Fluent builder producing a [`DynStreamingHash`] instance.
///
/// Obtained from [`HashBuilder::streaming`]. Call
/// [`build`](StreamingHashBuilder::build) for a [`DynStreamingHash`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamingHashBuilder {
    algorithm: HashAlgorithm,
}

impl StreamingHashBuilder {
    /// Begin building a streaming hasher with an explicit [`HashAlgorithm`].
    #[must_use]
    pub const fn new(algorithm: HashAlgorithm) -> Self {
        Self { algorithm }
    }

    /// The algorithm currently selected.
    #[must_use]
    pub const fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Build a [`DynStreamingHash`] for the selected algorithm.
    #[must_use]
    pub fn build(self) -> DynStreamingHash {
        match self.algorithm {
            HashAlgorithm::Sha256 => DynStreamingHash::Sha256(Sha256Streaming::new()),
            HashAlgorithm::Sha384 => DynStreamingHash::Sha384(Sha384Streaming::new()),
            HashAlgorithm::Sha512 => DynStreamingHash::Sha512(Sha512Streaming::new()),
            HashAlgorithm::Sha512_256 => DynStreamingHash::Sha512_256(Sha512_256Streaming::new()),
            HashAlgorithm::Sha3_256 => DynStreamingHash::Sha3_256(Sha3_256Streaming::new()),
            HashAlgorithm::Sha3_384 => DynStreamingHash::Sha3_384(Sha3_384Streaming::new()),
            HashAlgorithm::Sha3_512 => DynStreamingHash::Sha3_512(Sha3_512Streaming::new()),
            HashAlgorithm::Blake3 => DynStreamingHash::Blake3(Box::default()),
        }
    }
}

/// Runtime-dispatched streaming hasher returned by [`StreamingHashBuilder::build`].
///
/// This is a *sized* enum (not a `Box<dyn StreamingHash>`): a boxed trait object
/// could not be passed to [`StreamingHash::finalize`], which consumes `self` by
/// value and therefore requires a `Sized` receiver. `DynStreamingHash` itself
/// implements [`StreamingHash`], dispatching to the wrapped concrete hasher.
pub enum DynStreamingHash {
    /// Streaming SHA-256.
    Sha256(Sha256Streaming),
    /// Streaming SHA-384.
    Sha384(Sha384Streaming),
    /// Streaming SHA-512.
    Sha512(Sha512Streaming),
    /// Streaming SHA-512/256.
    Sha512_256(Sha512_256Streaming),
    /// Streaming SHA3-256.
    Sha3_256(Sha3_256Streaming),
    /// Streaming SHA3-384.
    Sha3_384(Sha3_384Streaming),
    /// Streaming SHA3-512.
    Sha3_512(Sha3_512Streaming),
    /// Streaming BLAKE3.
    ///
    /// Boxed because `blake3::Hasher` is far larger than the digest-based
    /// streaming states, which would otherwise bloat every enum value.
    Blake3(Box<Blake3Streaming>),
}

impl StreamingHash for DynStreamingHash {
    fn update(&mut self, data: &[u8]) {
        match self {
            DynStreamingHash::Sha256(h) => h.update(data),
            DynStreamingHash::Sha384(h) => h.update(data),
            DynStreamingHash::Sha512(h) => h.update(data),
            DynStreamingHash::Sha512_256(h) => h.update(data),
            DynStreamingHash::Sha3_256(h) => h.update(data),
            DynStreamingHash::Sha3_384(h) => h.update(data),
            DynStreamingHash::Sha3_512(h) => h.update(data),
            DynStreamingHash::Blake3(h) => h.update(data),
        }
    }

    fn finalize(self, out: &mut [u8]) -> Result<(), oxicrypto_core::CryptoError> {
        match self {
            DynStreamingHash::Sha256(h) => h.finalize(out),
            DynStreamingHash::Sha384(h) => h.finalize(out),
            DynStreamingHash::Sha512(h) => h.finalize(out),
            DynStreamingHash::Sha512_256(h) => h.finalize(out),
            DynStreamingHash::Sha3_256(h) => h.finalize(out),
            DynStreamingHash::Sha3_384(h) => h.finalize(out),
            DynStreamingHash::Sha3_512(h) => h.finalize(out),
            DynStreamingHash::Blake3(h) => (*h).finalize(out),
        }
    }

    fn reset(&mut self) {
        match self {
            DynStreamingHash::Sha256(h) => h.reset(),
            DynStreamingHash::Sha384(h) => h.reset(),
            DynStreamingHash::Sha512(h) => h.reset(),
            DynStreamingHash::Sha512_256(h) => h.reset(),
            DynStreamingHash::Sha3_256(h) => h.reset(),
            DynStreamingHash::Sha3_384(h) => h.reset(),
            DynStreamingHash::Sha3_512(h) => h.reset(),
            DynStreamingHash::Blake3(h) => h.reset(),
        }
    }
}

impl DynStreamingHash {
    /// The [`HashAlgorithm`] this streaming hasher computes.
    #[must_use]
    pub const fn algorithm(&self) -> HashAlgorithm {
        match self {
            DynStreamingHash::Sha256(_) => HashAlgorithm::Sha256,
            DynStreamingHash::Sha384(_) => HashAlgorithm::Sha384,
            DynStreamingHash::Sha512(_) => HashAlgorithm::Sha512,
            DynStreamingHash::Sha512_256(_) => HashAlgorithm::Sha512_256,
            DynStreamingHash::Sha3_256(_) => HashAlgorithm::Sha3_256,
            DynStreamingHash::Sha3_384(_) => HashAlgorithm::Sha3_384,
            DynStreamingHash::Sha3_512(_) => HashAlgorithm::Sha3_512,
            DynStreamingHash::Blake3(_) => HashAlgorithm::Blake3,
        }
    }
}

impl core::fmt::Debug for DynStreamingHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("DynStreamingHash")
            .field(&self.algorithm())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Blake3, Sha256, Sha384, Sha3_256, Sha3_384, Sha3_512, Sha512, Sha512_256};

    /// Every algorithm the builder supports, paired with its direct one-shot type.
    fn direct_hash(algo: HashAlgorithm, msg: &[u8]) -> alloc::vec::Vec<u8> {
        match algo {
            HashAlgorithm::Sha256 => Sha256.hash_to_vec(msg).unwrap(),
            HashAlgorithm::Sha384 => Sha384.hash_to_vec(msg).unwrap(),
            HashAlgorithm::Sha512 => Sha512.hash_to_vec(msg).unwrap(),
            HashAlgorithm::Sha512_256 => Sha512_256.hash_to_vec(msg).unwrap(),
            HashAlgorithm::Sha3_256 => Sha3_256.hash_to_vec(msg).unwrap(),
            HashAlgorithm::Sha3_384 => Sha3_384.hash_to_vec(msg).unwrap(),
            HashAlgorithm::Sha3_512 => Sha3_512.hash_to_vec(msg).unwrap(),
            HashAlgorithm::Blake3 => Blake3.hash_to_vec(msg).unwrap(),
        }
    }

    const ALL: [HashAlgorithm; 8] = [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
        HashAlgorithm::Sha512_256,
        HashAlgorithm::Sha3_256,
        HashAlgorithm::Sha3_384,
        HashAlgorithm::Sha3_512,
        HashAlgorithm::Blake3,
    ];

    #[test]
    fn builder_one_shot_matches_direct_api() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        for algo in ALL {
            let built = HashBuilder::new(algo).build();
            let via_builder = built.hash_to_vec(msg).unwrap();
            let direct = direct_hash(algo, msg);
            assert_eq!(
                via_builder, direct,
                "builder one-shot must equal direct API for {algo:?}"
            );
        }
    }

    #[test]
    fn builder_output_len_matches_trait() {
        for algo in ALL {
            let built = HashBuilder::new(algo).build();
            assert_eq!(
                built.output_len(),
                algo.output_len(),
                "HashAlgorithm::output_len must match trait output_len for {algo:?}"
            );
        }
    }

    #[test]
    fn builder_streaming_matches_one_shot() {
        let msg = b"streaming-vs-one-shot equivalence payload";
        for algo in ALL {
            let direct = direct_hash(algo, msg);

            let mut streaming = HashBuilder::new(algo).streaming().build();
            // Feed in three uneven chunks.
            streaming.update(&msg[..7]);
            streaming.update(&msg[7..20]);
            streaming.update(&msg[20..]);

            let mut out = alloc::vec![0u8; algo.output_len()];
            streaming.finalize(out.as_mut_slice()).unwrap();

            assert_eq!(
                out, direct,
                "builder streaming must equal one-shot for {algo:?}"
            );
        }
    }

    #[test]
    fn builder_streaming_byte_at_a_time() {
        let msg = b"abc";
        for algo in ALL {
            let direct = direct_hash(algo, msg);

            let mut streaming = HashBuilder::new(algo).streaming().build();
            for byte in msg {
                streaming.update(core::slice::from_ref(byte));
            }
            let mut out = alloc::vec![0u8; algo.output_len()];
            streaming.finalize(out.as_mut_slice()).unwrap();

            assert_eq!(
                out, direct,
                "byte-at-a-time streaming must equal one-shot for {algo:?}"
            );
        }
    }

    #[test]
    fn named_constructors_select_expected_algorithm() {
        assert_eq!(HashBuilder::sha256().algorithm(), HashAlgorithm::Sha256);
        assert_eq!(HashBuilder::sha384().algorithm(), HashAlgorithm::Sha384);
        assert_eq!(HashBuilder::sha512().algorithm(), HashAlgorithm::Sha512);
        assert_eq!(
            HashBuilder::sha512_256().algorithm(),
            HashAlgorithm::Sha512_256
        );
        assert_eq!(HashBuilder::sha3_256().algorithm(), HashAlgorithm::Sha3_256);
        assert_eq!(HashBuilder::sha3_384().algorithm(), HashAlgorithm::Sha3_384);
        assert_eq!(HashBuilder::sha3_512().algorithm(), HashAlgorithm::Sha3_512);
        assert_eq!(HashBuilder::blake3().algorithm(), HashAlgorithm::Blake3);
    }

    #[test]
    fn streaming_preserves_algorithm() {
        for algo in ALL {
            let b = HashBuilder::new(algo).streaming();
            assert_eq!(b.algorithm(), algo);
        }
    }

    #[test]
    fn fluent_sha256_example_round_trips() {
        // Mirror the doc-comment example end to end.
        let hasher = HashBuilder::sha256().build();
        let digest = hasher.hash_to_vec(b"abc").unwrap();

        let mut streaming = HashBuilder::sha256().streaming().build();
        streaming.update(b"a");
        streaming.update(b"bc");
        let mut out = [0u8; 32];
        streaming.finalize(out.as_mut_slice()).unwrap();

        assert_eq!(&out[..], digest.as_slice());
    }
}
