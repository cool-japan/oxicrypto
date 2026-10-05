//! Harnesses over the **public** `oxicrypto-hash` metadata API.
//!
//! Nothing here is a copy of `oxicrypto-hash`: every target is called through
//! the real crate's public interface, and `cargo-formal` lowers the reachable
//! bodies of `oxicrypto-hash` (and `oxicrypto-core`) into the verification
//! condition through the `dep-crates` key. The digest routines themselves live
//! in the `sha2` / `sha3` / `blake3` registry crates, which are not lowered;
//! the two determinism / known-answer harnesses state that boundary rather than
//! hide it.
//!
//! Every entry point states the property it raises and the **measured** L1
//! verdict for it; `EXPECTED.toml` mirrors the same table machine-readably.

#[cfg_attr(
    not(any(formal, all(test, oxiformal_runtime_checks))),
    allow(unused_imports)
)]
use oxicrypto_core::Hash;
#[cfg_attr(
    not(any(formal, all(test, oxiformal_runtime_checks))),
    allow(unused_imports)
)]
use oxicrypto_hash::{
    Blake2b256, Blake2b512, Blake2s256, Blake3, Sha256, Sha384, Sha3_256, Sha3_384, Sha3_512,
    Sha512, Sha512_256,
};
#[cfg_attr(
    not(any(formal, all(test, oxiformal_runtime_checks))),
    allow(unused_imports)
)]
use oxicrypto_hash::{HashAlgorithm, HashBuilder, StreamingHashBuilder};
use oxiformal::prelude::*;

/// SHA-256 of the empty input (FIPS 180-4 test vector), for the known-answer
/// harness and its plain-build witness.
pub const SHA256_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

// ---------------------------------------------------------------------------
// HashAlgorithm::output_len — the digest-length table
// ---------------------------------------------------------------------------

/// Property: `assert`.
///
/// For every `HashAlgorithm`, `output_len` returns one of the three valid
/// digest sizes (32, 48 or 64 bytes) and nothing else — the bound a caller
/// relies on when it stack-allocates an output buffer. The variant is chosen
/// from an arbitrary `u8` selector so the property ranges over all eight
/// without depending on an `Arbitrary` impl for the enum.
///
/// **Measured L1 verdict: unknown** — not a real gap: the mandatory bit-level
/// model check refused a model the pinned OxiZ 0.3.3 returned that does not
/// satisfy the condition (`solver-model-rejected`, upstream U-Z10), so the
/// honest answer is `unknown` rather than an invented counterexample. The exact
/// table `output_len_matches_each_algorithm_harness` proves `proved` for all
/// eight variants; this one ranges over an arbitrary selector, and its verdict
/// on a later OxiZ release has not been measured.
#[harness]
fn output_len_is_a_valid_digest_length_harness() {
    let sel: u8 = any();
    let algo = algorithm_of(sel);
    let n = algo.output_len();
    assert(n == 32 || n == 48 || n == 64);
}

/// Property: `assert`, one site per algorithm. **Measured L1 verdict: proved.**
///
/// The exact FIPS 180-4 / FIPS 202 / BLAKE3 digest lengths, pinned so a change
/// to the table is caught here.
#[harness]
fn output_len_matches_each_algorithm_harness() {
    assert(HashAlgorithm::Sha256.output_len() == 32);
    assert(HashAlgorithm::Sha384.output_len() == 48);
    assert(HashAlgorithm::Sha512.output_len() == 64);
    assert(HashAlgorithm::Sha512_256.output_len() == 32);
    assert(HashAlgorithm::Sha3_256.output_len() == 32);
    assert(HashAlgorithm::Sha3_384.output_len() == 48);
    assert(HashAlgorithm::Sha3_512.output_len() == 64);
    assert(HashAlgorithm::Blake3.output_len() == 32);
}

// ---------------------------------------------------------------------------
// HashBuilder — the constructors record the algorithm they name
// ---------------------------------------------------------------------------

/// Property: `assert`. **Measured L1 verdict: proved.**
///
/// `HashBuilder::new(a).algorithm()` returns exactly `a` for every algorithm,
/// so the builder round-trips the selector a caller hands it.
#[harness]
fn builder_new_round_trips_its_algorithm_harness() {
    let sel: u8 = any();
    let algo = algorithm_of(sel);
    assert(HashBuilder::new(algo).algorithm() == algo);
}

/// Property: `assert`, one site per constructor. **Measured L1 verdict:
/// proved.**
///
/// Each named constructor records its own algorithm, so
/// `HashBuilder::sha256().build()` really is a SHA-256.
#[harness]
fn named_builder_constructors_record_their_algorithm_harness() {
    assert(HashBuilder::sha256().algorithm() == HashAlgorithm::Sha256);
    assert(HashBuilder::sha384().algorithm() == HashAlgorithm::Sha384);
    assert(HashBuilder::sha512().algorithm() == HashAlgorithm::Sha512);
    assert(HashBuilder::sha512_256().algorithm() == HashAlgorithm::Sha512_256);
    assert(HashBuilder::sha3_256().algorithm() == HashAlgorithm::Sha3_256);
    assert(HashBuilder::sha3_384().algorithm() == HashAlgorithm::Sha3_384);
    assert(HashBuilder::sha3_512().algorithm() == HashAlgorithm::Sha3_512);
    assert(HashBuilder::blake3().algorithm() == HashAlgorithm::Blake3);
}

// ---------------------------------------------------------------------------
// The Hash-trait output_len agrees with the table
// ---------------------------------------------------------------------------

/// Property: `assert`, one site per concrete type. **Measured L1 verdict:
/// proved.**
///
/// Each concrete hash type's `Hash::output_len` equals the
/// `HashAlgorithm::output_len` entry for the same algorithm, so the two length
/// sources can never drift apart.
#[harness]
fn trait_output_len_agrees_with_the_table_harness() {
    assert(Sha256.output_len() == HashAlgorithm::Sha256.output_len());
    assert(Sha384.output_len() == HashAlgorithm::Sha384.output_len());
    assert(Sha512.output_len() == HashAlgorithm::Sha512.output_len());
    assert(Sha512_256.output_len() == HashAlgorithm::Sha512_256.output_len());
    assert(Sha3_256.output_len() == HashAlgorithm::Sha3_256.output_len());
    assert(Sha3_384.output_len() == HashAlgorithm::Sha3_384.output_len());
    assert(Sha3_512.output_len() == HashAlgorithm::Sha3_512.output_len());
    assert(Blake3.output_len() == HashAlgorithm::Blake3.output_len());
}

/// Property: `assert`, one site per type. **Measured L1 verdict: proved** —
/// each concrete type's `Hash::name` equals its documented label (the `&str`
/// equality reduces).
#[harness]
fn hash_names_match_their_labels_harness() {
    assert(Sha256.name() == "SHA-256");
    assert(Sha384.name() == "SHA-384");
    assert(Sha512.name() == "SHA-512");
    assert(Sha512_256.name() == "SHA-512/256");
    assert(Sha3_256.name() == "SHA3-256");
    assert(Sha3_384.name() == "SHA3-384");
    assert(Sha3_512.name() == "SHA3-512");
    assert(Blake3.name() == "BLAKE3");
    assert(Blake2b256.name() == "BLAKE2b-256");
    assert(Blake2b512.name() == "BLAKE2b-512");
    assert(Blake2s256.name() == "BLAKE2s-256");
}

/// Property: `assert`, one site per type. **Measured L1 verdict: proved.**
///
/// The three BLAKE2 types are not in `HashAlgorithm` (the builder does not
/// construct them), but their `Hash::output_len` is a fixed digest size too, so
/// it is pinned here directly.
#[harness]
fn blake2_trait_output_len_harness() {
    assert(Blake2b256.output_len() == 32);
    assert(Blake2b512.output_len() == 64);
    assert(Blake2s256.output_len() == 32);
}

/// Property: `assert`. **Measured L1 verdict: proved.**
///
/// The streaming builder records its algorithm the same way the one-shot
/// builder does, whether constructed directly or switched to from a
/// `HashBuilder`.
#[harness]
fn streaming_builder_round_trips_its_algorithm_harness() {
    let sel: u8 = any();
    let algo = algorithm_of(sel);
    assert(StreamingHashBuilder::new(algo).algorithm() == algo);
    assert(HashBuilder::new(algo).streaming().algorithm() == algo);
}

// ---------------------------------------------------------------------------
// The digest itself — the registry-crate boundary
// ---------------------------------------------------------------------------

/// Property: `assert`. **Measured L1 verdict: unsupported** (`unsupported-type`),
/// reported at the `Sha256::hash_fixed` call (`src/harness.rs:194:24`) with
/// "`!null` is not a range pattern this encoder understands" — a niche (a
/// `NonNull` / reference niche) in the types on the digest path, which runs into
/// the `sha2` registry crate the run does not lower. No verification condition
/// is generated — determinism of the one-shot digest is a true property the
/// encoder cannot reach here. `plain_tests` exhausts it over a sample.
#[harness]
fn sha256_hash_fixed_is_deterministic_harness() {
    let msg: Vec<u8> = any_vec(4);
    assert(Sha256.hash_fixed(&msg) == Sha256.hash_fixed(&msg));
}

/// Property: `assert`. **Measured L1 verdict: unsupported** (`unsupported-type`),
/// the same boundary as `sha256_hash_fixed_is_deterministic_harness` (reported
/// at `src/harness.rs:204:26`): the digest runs into the `sha2` registry crate
/// the run does not lower. `plain_tests` checks the vector concretely.
#[harness]
fn sha256_empty_known_answer_harness() {
    let empty: Vec<u8> = Vec::new();
    assert(Sha256.hash_fixed(&empty) == SHA256_EMPTY);
}

/// Map a `u8` selector onto one of the eight algorithms, so a harness can range
/// over the enum without an `Arbitrary` impl for it.
#[cfg_attr(
    not(any(formal, all(test, oxiformal_runtime_checks))),
    allow(dead_code)
)]
fn algorithm_of(sel: u8) -> HashAlgorithm {
    match sel % 8 {
        0 => HashAlgorithm::Sha256,
        1 => HashAlgorithm::Sha384,
        2 => HashAlgorithm::Sha512,
        3 => HashAlgorithm::Sha512_256,
        4 => HashAlgorithm::Sha3_256,
        5 => HashAlgorithm::Sha3_384,
        6 => HashAlgorithm::Sha3_512,
        _ => HashAlgorithm::Blake3,
    }
}

#[cfg(all(test, not(oxiformal_runtime_checks), not(formal)))]
mod plain_tests {
    use super::*;

    #[test]
    fn output_len_is_always_32_48_or_64() {
        for sel in 0u8..=255 {
            let n = algorithm_of(sel).output_len();
            assert!(n == 32 || n == 48 || n == 64);
        }
    }

    #[test]
    fn output_len_table_is_exact() {
        assert_eq!(HashAlgorithm::Sha256.output_len(), 32);
        assert_eq!(HashAlgorithm::Sha384.output_len(), 48);
        assert_eq!(HashAlgorithm::Sha512.output_len(), 64);
        assert_eq!(HashAlgorithm::Sha512_256.output_len(), 32);
        assert_eq!(HashAlgorithm::Sha3_256.output_len(), 32);
        assert_eq!(HashAlgorithm::Sha3_384.output_len(), 48);
        assert_eq!(HashAlgorithm::Sha3_512.output_len(), 64);
        assert_eq!(HashAlgorithm::Blake3.output_len(), 32);
    }

    #[test]
    fn builder_new_round_trips_every_algorithm() {
        for sel in 0u8..8 {
            let algo = algorithm_of(sel);
            assert_eq!(HashBuilder::new(algo).algorithm(), algo);
        }
    }

    #[test]
    fn named_constructors_record_their_algorithm() {
        assert_eq!(HashBuilder::sha256().algorithm(), HashAlgorithm::Sha256);
        assert_eq!(HashBuilder::sha512().algorithm(), HashAlgorithm::Sha512);
        assert_eq!(HashBuilder::blake3().algorithm(), HashAlgorithm::Blake3);
    }

    #[test]
    fn blake2_trait_output_len_is_exact() {
        assert_eq!(Blake2b256.output_len(), 32);
        assert_eq!(Blake2b512.output_len(), 64);
        assert_eq!(Blake2s256.output_len(), 32);
    }

    #[test]
    fn streaming_builder_round_trips_every_algorithm() {
        for sel in 0u8..8 {
            let algo = algorithm_of(sel);
            assert_eq!(StreamingHashBuilder::new(algo).algorithm(), algo);
            assert_eq!(HashBuilder::new(algo).streaming().algorithm(), algo);
        }
    }

    #[test]
    fn hash_names_match_their_labels() {
        assert_eq!(Sha256.name(), "SHA-256");
        assert_eq!(Sha512.name(), "SHA-512");
        assert_eq!(Blake3.name(), "BLAKE3");
        assert_eq!(Blake2b256.name(), "BLAKE2b-256");
        assert_eq!(Blake2s256.name(), "BLAKE2s-256");
    }

    #[test]
    fn trait_output_len_agrees_with_the_table() {
        assert_eq!(Sha256.output_len(), HashAlgorithm::Sha256.output_len());
        assert_eq!(Sha512.output_len(), HashAlgorithm::Sha512.output_len());
        assert_eq!(Blake3.output_len(), HashAlgorithm::Blake3.output_len());
    }

    /// The property `sha256_hash_fixed_is_deterministic_harness` states but
    /// cannot prove (`unsupported`: the digest body is in the `sha2` registry
    /// crate), exhausted over a sample of short inputs.
    #[test]
    fn sha256_hash_fixed_is_deterministic_on_a_sample() {
        for len in 0..=4usize {
            let msg: Vec<u8> = (0..len).map(|b| b as u8).collect();
            assert_eq!(Sha256.hash_fixed(&msg), Sha256.hash_fixed(&msg));
        }
    }

    /// The SHA-256 known-answer the other harness cannot prove here.
    #[test]
    fn sha256_empty_matches_the_known_answer() {
        assert_eq!(Sha256.hash_fixed(&[]), SHA256_EMPTY);
    }
}
