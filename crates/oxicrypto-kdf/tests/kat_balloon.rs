//! Known-answer / reference tests for Balloon memory-hard hashing.
//!
//! # Provenance / honesty note
//!
//! Balloon hashing (Boneh, Corrigan-Gibbs & Schechter, ASIACRYPT 2016,
//! <https://eprint.iacr.org/2016/027>) has **no RFC or NIST KAT suite**.
//! Correctness here is pinned by two independent things:
//!
//! 1. The implementation follows the paper's single-buffer **Algorithm 1**
//!    exactly (expand / mix with `delta = 3` / extract).
//! 2. The byte-exact serialization is cross-checked against the authors'
//!    canonical reference implementation — the Python port at
//!    <https://github.com/nachonavarro/balloon-hashing> (referenced from the
//!    Stanford Applied Crypto Group's Balloon page,
//!    <https://crypto.stanford.edu/balloon/>). Its published README vectors are
//!    reproduced here as locked constants:
//!
//!    - `balloon_hash("buildmeupbuttercup", "JqMcHqUcjinFhQKJ")`
//!      (i.e. `space_cost=16, time_cost=20, delta=4`)
//!      ⇒ `2ec8d833db5f88e584ab793950ecfb21657a3816edea8d9e73ea23c13ba2b740`
//!    - `balloon("buildmeupbuttercup", "JqMcHqUcjinFhQKJ", space_cost=24,
//!      time_cost=18, delta=5)`
//!      ⇒ `69f86890cef40a7ec5f70daff1ce8e2cde233a15bffa785e7efdb5143af51bfb`
//!
//! Because our public functions fix `delta = 3` (the paper's recommended
//! default), the two published `delta != 3` vectors are reproduced via an
//! in-test reference reimplementation [`ref_balloon`] (a direct transcription
//! of the reference byte layout) that is itself validated against those two
//! published digests; our `delta = 3` outputs are then locked against that
//! validated reference. This gives an end-to-end chain from the published
//! vectors to every constant asserted below.

use oxicrypto_kdf::balloon::{balloon_sha256, balloon_sha512};
use sha2::{Digest, Sha256, Sha512};

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

// ---------------------------------------------------------------------------
// In-test reference transcription of the canonical Balloon byte layout.
//
// This mirrors nachonavarro/balloon-hashing's `hash_func`/`expand`/`mix`/
// `extract` exactly: integers are 8-byte little-endian, byte strings verbatim,
// `idx_block = H(LE64(t)‖LE64(s)‖LE64(i))`, and the random index is
// `int.from_bytes(H(LE64(cnt)‖salt‖idx_block), "little") % space_cost`.
//
// It supports an arbitrary `delta` (unlike the production API, which fixes
// delta = 3) so it can reproduce the published `delta=4` / `delta=5` vectors,
// and is the bridge that proves our serialization matches the reference.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum RefHash {
    S256,
    S512,
}

impl RefHash {
    fn len(self) -> usize {
        match self {
            RefHash::S256 => 32,
            RefHash::S512 => 64,
        }
    }
    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            RefHash::S256 => Sha256::digest(data).to_vec(),
            RefHash::S512 => Sha512::digest(data).to_vec(),
        }
    }
}

fn ref_balloon(
    h: RefHash,
    password: &[u8],
    salt: &[u8],
    space_cost: u64,
    time_cost: u64,
    delta: u64,
) -> Vec<u8> {
    let dl = h.len();
    let s = space_cost as usize;
    let mut buf: Vec<Vec<u8>> = Vec::with_capacity(s);
    let mut cnt: u64 = 0;

    // buf[0] = H(cnt++ ‖ password ‖ salt)
    let mut input = Vec::new();
    input.extend_from_slice(&cnt.to_le_bytes());
    input.extend_from_slice(password);
    input.extend_from_slice(salt);
    buf.push(h.hash(&input));
    cnt += 1;

    // Expand
    for m in 1..s {
        let mut input = Vec::new();
        input.extend_from_slice(&cnt.to_le_bytes());
        input.extend_from_slice(&buf[m - 1]);
        buf.push(h.hash(&input));
        cnt += 1;
    }

    // Mix
    for t in 0..time_cost {
        for m in 0..s {
            let prev = if m == 0 { s - 1 } else { m - 1 };
            let mut input = Vec::new();
            input.extend_from_slice(&cnt.to_le_bytes());
            input.extend_from_slice(&buf[prev]);
            input.extend_from_slice(&buf[m]);
            buf[m] = h.hash(&input);
            cnt += 1;

            for i in 0..delta {
                // idx_block = H(LE64(t) ‖ LE64(m) ‖ LE64(i))   (no counter)
                let mut ib = Vec::new();
                ib.extend_from_slice(&t.to_le_bytes());
                ib.extend_from_slice(&(m as u64).to_le_bytes());
                ib.extend_from_slice(&i.to_le_bytes());
                let idx_block = h.hash(&ib);

                // other = LE_int(H(cnt++ ‖ salt ‖ idx_block)) % space_cost
                let mut ob = Vec::new();
                ob.extend_from_slice(&cnt.to_le_bytes());
                ob.extend_from_slice(salt);
                ob.extend_from_slice(&idx_block);
                let od = h.hash(&ob);
                cnt += 1;
                let mut acc: u128 = 0;
                for &b in od.iter().rev() {
                    acc = (acc * 256 + b as u128) % space_cost as u128;
                }
                let other = acc as usize;

                let mut mb = Vec::new();
                mb.extend_from_slice(&cnt.to_le_bytes());
                mb.extend_from_slice(&buf[m]);
                mb.extend_from_slice(&buf[other]);
                buf[m] = h.hash(&mb);
                cnt += 1;
            }
            let _ = dl; // dl documents digest length; lengths are implicit in Vec.
        }
    }

    buf[s - 1].clone()
}

// ---------------------------------------------------------------------------
// (A) The in-test reference reproduces the two PUBLISHED vectors exactly.
//     This validates the reference byte layout itself.
// ---------------------------------------------------------------------------

/// Published vector 1: `balloon_hash("buildmeupbuttercup", "JqMcHqUcjinFhQKJ")`
/// == `balloon(..., space_cost=16, time_cost=20, delta=4)`.
const PUBLISHED_V1_HEX: &str = "2ec8d833db5f88e584ab793950ecfb21657a3816edea8d9e73ea23c13ba2b740";

/// Published vector 2: `balloon(..., space_cost=24, time_cost=18, delta=5)`.
const PUBLISHED_V2_HEX: &str = "69f86890cef40a7ec5f70daff1ce8e2cde233a15bffa785e7efdb5143af51bfb";

#[test]
fn reference_matches_published_vector_1() {
    let got = ref_balloon(
        RefHash::S256,
        b"buildmeupbuttercup",
        b"JqMcHqUcjinFhQKJ",
        16,
        20,
        4,
    );
    assert_eq!(
        got,
        hex_decode(PUBLISHED_V1_HEX),
        "in-test reference must reproduce the authors' published vector 1"
    );
}

#[test]
fn reference_matches_published_vector_2() {
    let got = ref_balloon(
        RefHash::S256,
        b"buildmeupbuttercup",
        b"JqMcHqUcjinFhQKJ",
        24,
        18,
        5,
    );
    assert_eq!(
        got,
        hex_decode(PUBLISHED_V2_HEX),
        "in-test reference must reproduce the authors' published vector 2"
    );
}

// ---------------------------------------------------------------------------
// (B) The PRODUCTION implementation (delta = 3) agrees with the validated
//     in-test reference across a range of parameters and both hash variants.
// ---------------------------------------------------------------------------

#[test]
fn production_sha256_matches_reference_small() {
    for &(sc, tc) in &[(1u64, 1u64), (2, 1), (3, 2), (8, 3), (16, 5), (33, 4)] {
        let mut got = [0u8; 32];
        balloon_sha256(b"password", b"salt", sc, tc, &mut got)
            .unwrap_or_else(|_| panic!("balloon_sha256 sc={sc} tc={tc}"));
        let want = ref_balloon(RefHash::S256, b"password", b"salt", sc, tc, 3);
        assert_eq!(
            got.as_slice(),
            want.as_slice(),
            "production SHA-256 (sc={sc}, tc={tc}) must match reference (delta=3)"
        );
    }
}

#[test]
fn production_sha512_matches_reference_small() {
    for &(sc, tc) in &[(1u64, 1u64), (2, 1), (8, 3), (16, 4)] {
        let mut got = [0u8; 64];
        balloon_sha512(b"password", b"salt", sc, tc, &mut got)
            .unwrap_or_else(|_| panic!("balloon_sha512 sc={sc} tc={tc}"));
        let want = ref_balloon(RefHash::S512, b"password", b"salt", sc, tc, 3);
        assert_eq!(
            got.as_slice(),
            want.as_slice(),
            "production SHA-512 (sc={sc}, tc={tc}) must match reference (delta=3)"
        );
    }
}

// ---------------------------------------------------------------------------
// (C) Locked constants for the production (delta = 3) API.
//
//     These were produced by this crate and confirmed equal to the in-test
//     reference (and, transitively, to the byte layout validated against the
//     published vectors above). They guard against accidental regressions.
// ---------------------------------------------------------------------------

/// `balloon_sha256("password", "salt", space_cost=8, time_cost=3)` (delta=3).
const KAT_SHA256_PW_SALT_S8_T3: &str =
    "7e53d9f446cb5dd0c51237b33b023cc1729715cb50e48fd32916279a7a1efbf9";

/// `balloon_sha512("password", "salt", space_cost=8, time_cost=3)` (delta=3).
const KAT_SHA512_PW_SALT_S8_T3: &str =
    "c7b300d006409b1ff415ea8b8f72f911db8a053947e9cecacb3a299236f8503839ba20f96d8257193302d94c927a90bfb82bcae2706c96e2f80afd40f670e4a0";

#[test]
fn locked_sha256_vector() {
    let mut got = [0u8; 32];
    balloon_sha256(b"password", b"salt", 8, 3, &mut got).expect("balloon_sha256");
    assert_eq!(
        got.as_slice(),
        hex_decode(KAT_SHA256_PW_SALT_S8_T3).as_slice(),
        "locked Balloon-SHA-256 vector mismatch (delta=3, sc=8, tc=3)"
    );
}

#[test]
fn locked_sha512_vector() {
    let mut got = [0u8; 64];
    balloon_sha512(b"password", b"salt", 8, 3, &mut got).expect("balloon_sha512");
    assert_eq!(
        got.as_slice(),
        hex_decode(KAT_SHA512_PW_SALT_S8_T3).as_slice(),
        "locked Balloon-SHA-512 vector mismatch (delta=3, sc=8, tc=3)"
    );
}

// ---------------------------------------------------------------------------
// (D) Structural properties.
// ---------------------------------------------------------------------------

#[test]
fn determinism() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    balloon_sha256(b"correct horse battery staple", b"saltsalt", 16, 4, &mut a).expect("a");
    balloon_sha256(b"correct horse battery staple", b"saltsalt", 16, 4, &mut b).expect("b");
    assert_eq!(a, b, "same inputs ⇒ same output");
}

#[test]
fn different_salt_changes_output() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    balloon_sha256(b"password", b"saltA", 16, 4, &mut a).expect("a");
    balloon_sha256(b"password", b"saltB", 16, 4, &mut b).expect("b");
    assert_ne!(a, b, "different salt ⇒ different output");
}

#[test]
fn different_password_changes_output() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    balloon_sha256(b"passwordA", b"salt", 16, 4, &mut a).expect("a");
    balloon_sha256(b"passwordB", b"salt", 16, 4, &mut b).expect("b");
    assert_ne!(a, b, "different password ⇒ different output");
}

#[test]
fn parameter_rejection() {
    let mut out = [0u8; 32];
    assert!(
        balloon_sha256(b"pw", b"salt", 0, 1, &mut out).is_err(),
        "space_cost=0 must be rejected"
    );
    assert!(
        balloon_sha256(b"pw", b"salt", 1, 0, &mut out).is_err(),
        "time_cost=0 must be rejected"
    );
    let mut wrong = [0u8; 31];
    assert!(
        balloon_sha256(b"pw", b"salt", 8, 1, &mut wrong).is_err(),
        "wrong output length must be rejected"
    );
}
