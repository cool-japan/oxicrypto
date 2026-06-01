#![forbid(unsafe_code)]

//! Balloon memory-hard password hashing for the OxiCrypto stack.
//!
//! Pure-Rust implementation of the **single-buffer Balloon** function
//! (Algorithm 1) from Boneh, Corrigan-Gibbs & Schechter,
//! *"Balloon Hashing: A Memory-Hard Function Providing Provable Protection
//! Against Sequential Attacks"* (ASIACRYPT 2016,
//! <https://eprint.iacr.org/2016/027>).
//!
//! Balloon is a memory-hard, cache-hard password-hashing / key-stretching
//! function that can be built on top of any standard cryptographic hash. This
//! module instantiates it over **SHA-256** ([`balloon_sha256`]) and
//! **SHA-512** ([`balloon_sha512`]) using the [`sha2`] crate.
//!
//! # Construction
//!
//! Let `H` be the underlying hash, `cnt` a little-endian `u64` counter that is
//! incremented after every hash invocation, `space_cost` (`s`) the number of
//! hash-sized blocks held in memory, `time_cost` (`t`) the number of mixing
//! rounds, and `delta = 3` the number of pseudo-random dependencies per block.
//!
//! 1. **Expand** — fill the working buffer:
//!    - `buf[0] = H(cnt++ ‖ password ‖ salt)`
//!    - `buf[m] = H(cnt++ ‖ buf[m-1])` for `m ∈ [1, s)`
//! 2. **Mix** — for `round ∈ [0, t)`, for `m ∈ [0, s)`:
//!    - `buf[m] = H(cnt++ ‖ buf[(m-1) mod s] ‖ buf[m])`
//!    - then `delta` times (`i ∈ [0, delta)`):
//!      - `idx_block = H(LE64(round) ‖ LE64(m) ‖ LE64(i))`
//!      - `other = (H(cnt++ ‖ salt ‖ idx_block) interpreted as a little-endian
//!        integer) mod s`
//!      - `buf[m] = H(cnt++ ‖ buf[m] ‖ buf[other])`
//! 3. **Extract** — output `buf[s-1]`.
//!
//! All integers fed to `H` are length-free, fixed-width **8-byte
//! little-endian** values; byte strings are concatenated verbatim. This matches
//! the authors' reference implementation byte-for-byte (verified against the
//! published reference vectors — see `tests/kat_balloon.rs`).
//!
//! # Security parameters
//!
//! `space_cost` dominates the memory footprint (`space_cost × digest_len`
//! bytes). Choose `space_cost` and `time_cost` so the product meets your
//! latency/memory budget; the paper recommends `t ≥ 1` and a `space_cost`
//! large enough to make the working set cache-hard (tens of thousands of
//! blocks for password storage).
//!
//! The working buffer and the returned digest are wrapped in
//! [`oxicrypto_core::SecretVec`] so intermediate key material is
//! zeroized on drop.

use oxicrypto_core::{
    CryptoError, PasswordHash as PasswordHashTrait, PasswordHashParams, SecretVec, Zeroize,
};
use sha2::{Digest, Sha256, Sha512};

/// Number of pseudo-random dependencies mixed into each block per round.
///
/// Fixed at `3` per the Balloon paper's recommended default (`delta = 3`).
pub const BALLOON_DELTA: u64 = 3;

// ---------------------------------------------------------------------------
// Generic core over an abstract one-shot hash
// ---------------------------------------------------------------------------

/// A one-shot fixed-output hash used to instantiate Balloon.
///
/// Implemented for SHA-256 and SHA-512 below. The associated `DIGEST_LEN`
/// lets the core size its working buffer without heap reallocation churn.
trait BalloonHash {
    /// Length of the digest in bytes.
    const DIGEST_LEN: usize;

    /// Hash `data` and write the digest into `out` (which is `DIGEST_LEN` long).
    fn hash_into(data: &[u8], out: &mut [u8]);
}

/// SHA-256 instantiation marker.
struct Sha256Hash;
/// SHA-512 instantiation marker.
struct Sha512Hash;

impl BalloonHash for Sha256Hash {
    const DIGEST_LEN: usize = 32;

    fn hash_into(data: &[u8], out: &mut [u8]) {
        let digest = Sha256::digest(data);
        out.copy_from_slice(&digest);
    }
}

impl BalloonHash for Sha512Hash {
    const DIGEST_LEN: usize = 64;

    fn hash_into(data: &[u8], out: &mut [u8]) {
        let digest = Sha512::digest(data);
        out.copy_from_slice(&digest);
    }
}

/// A reusable hash-input scratch buffer.
///
/// Integers are appended as 8-byte little-endian values and byte slices are
/// appended verbatim, exactly matching the reference Balloon serialization.
struct HashInput {
    buf: Vec<u8>,
}

impl HashInput {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(160),
        }
    }

    /// Reset for a fresh hash invocation.
    fn clear(&mut self) {
        self.buf.clear();
    }

    /// Append a `u64` as 8 little-endian bytes (the reference counter/integer
    /// encoding).
    fn push_u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Append raw bytes verbatim.
    fn push_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

/// Compute `int.from_bytes(digest, "little") mod modulus`.
///
/// `digest` is interpreted as a little-endian big integer; the result is taken
/// modulo `modulus` without arbitrary-precision arithmetic by streaming from
/// the most-significant byte (the last byte of a little-endian encoding) to the
/// least-significant byte. This reproduces the reference implementation's
/// `int.from_bytes(h, "little") % space_cost` exactly.
fn le_digest_mod(digest: &[u8], modulus: u64) -> u64 {
    // `modulus` is always `>= 1` here (validated by callers), so the running
    // accumulator stays `< modulus <= u64::MAX`, and `acc * 256 + byte` cannot
    // overflow because `acc <= modulus - 1` and `modulus` fits in `u64` with
    // room: we reduce after each step. To stay overflow-safe for large moduli
    // we use `u128` for the intermediate.
    let m = u128::from(modulus);
    let mut acc: u128 = 0;
    for &byte in digest.iter().rev() {
        acc = (acc * 256 + u128::from(byte)) % m;
    }
    // acc < m <= u64::MAX, so this never truncates.
    acc as u64
}

/// Core single-buffer Balloon (Algorithm 1) over hash `H`.
///
/// Writes `H::DIGEST_LEN` bytes into `out`. `space_cost` and `time_cost` must
/// be `>= 1`; `out.len()` must equal `H::DIGEST_LEN`.
fn balloon_core<H: BalloonHash>(
    password: &[u8],
    salt: &[u8],
    space_cost: u64,
    time_cost: u64,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if space_cost == 0 || time_cost == 0 {
        return Err(CryptoError::BadInput);
    }
    if out.len() != H::DIGEST_LEN {
        return Err(CryptoError::BadInput);
    }

    let digest_len = H::DIGEST_LEN;

    // `space_cost` blocks must fit in addressable memory. Guard the allocation
    // size up front so an absurd parameter returns an error instead of
    // attempting a panicking allocation.
    let total_bytes = (space_cost as usize)
        .checked_mul(digest_len)
        .ok_or(CryptoError::BadInput)?;

    // Working buffer of `space_cost` contiguous digest-sized blocks, held in a
    // zeroize-on-drop wrapper so all intermediate block material is wiped when
    // this function returns (including via the `?` early exits below).
    let mut work = ZeroizingBuf::new(total_bytes);
    let buf = work.as_mut_slice();

    let mut input = HashInput::new();
    let mut digest = ZeroizingBuf::new(digest_len);
    let mut cnt: u64 = 0;

    // ── Expand ──────────────────────────────────────────────────────────────
    // buf[0] = H(cnt++ ‖ password ‖ salt)
    input.clear();
    input.push_u64(cnt);
    input.push_bytes(password);
    input.push_bytes(salt);
    H::hash_into(input.as_slice(), &mut buf[0..digest_len]);
    cnt += 1;

    // buf[m] = H(cnt++ ‖ buf[m-1])  for m in [1, space_cost)
    for m in 1..(space_cost as usize) {
        let prev_start = (m - 1) * digest_len;
        input.clear();
        input.push_u64(cnt);
        // Read previous block into `digest` to avoid aliasing the &mut buf.
        digest
            .as_mut_slice()
            .copy_from_slice(&buf[prev_start..prev_start + digest_len]);
        input.push_bytes(digest.as_slice());
        let cur_start = m * digest_len;
        H::hash_into(
            input.as_slice(),
            &mut buf[cur_start..cur_start + digest_len],
        );
        cnt += 1;
    }

    // ── Mix ─────────────────────────────────────────────────────────────────
    let space_usize = space_cost as usize;
    for round in 0..time_cost {
        for m in 0..space_usize {
            // buf[m] = H(cnt++ ‖ buf[(m-1) mod space_cost] ‖ buf[m])
            let prev_idx = if m == 0 { space_usize - 1 } else { m - 1 };
            let prev_start = prev_idx * digest_len;
            let cur_start = m * digest_len;

            input.clear();
            input.push_u64(cnt);
            // Snapshot buf[prev] and buf[m] into owned bytes (prev may equal m
            // when space_cost == 1).
            let mut prev_block = [0u8; 64];
            let mut cur_block = [0u8; 64];
            prev_block[..digest_len].copy_from_slice(&buf[prev_start..prev_start + digest_len]);
            cur_block[..digest_len].copy_from_slice(&buf[cur_start..cur_start + digest_len]);
            input.push_bytes(&prev_block[..digest_len]);
            input.push_bytes(&cur_block[..digest_len]);
            H::hash_into(
                input.as_slice(),
                &mut buf[cur_start..cur_start + digest_len],
            );
            cnt += 1;

            // delta pseudo-random dependencies.
            for i in 0..BALLOON_DELTA {
                // idx_block = H(LE64(round) ‖ LE64(m) ‖ LE64(i))   (no counter)
                input.clear();
                input.push_u64(round);
                input.push_u64(m as u64);
                input.push_u64(i);
                let mut idx_block = [0u8; 64];
                H::hash_into(input.as_slice(), &mut idx_block[..digest_len]);

                // other = (H(cnt++ ‖ salt ‖ idx_block) as LE int) mod space_cost
                input.clear();
                input.push_u64(cnt);
                input.push_bytes(salt);
                input.push_bytes(&idx_block[..digest_len]);
                H::hash_into(input.as_slice(), digest.as_mut_slice());
                cnt += 1;
                let other = le_digest_mod(digest.as_slice(), space_cost) as usize;

                // buf[m] = H(cnt++ ‖ buf[m] ‖ buf[other])
                let other_start = other * digest_len;
                let mut m_block = [0u8; 64];
                let mut other_block = [0u8; 64];
                m_block[..digest_len].copy_from_slice(&buf[cur_start..cur_start + digest_len]);
                other_block[..digest_len]
                    .copy_from_slice(&buf[other_start..other_start + digest_len]);
                input.clear();
                input.push_u64(cnt);
                input.push_bytes(&m_block[..digest_len]);
                input.push_bytes(&other_block[..digest_len]);
                H::hash_into(
                    input.as_slice(),
                    &mut buf[cur_start..cur_start + digest_len],
                );
                cnt += 1;
            }
        }
    }

    // ── Extract ───────────────────────────────────────────────────────────────
    let last_start = (space_usize - 1) * digest_len;
    out.copy_from_slice(&buf[last_start..last_start + digest_len]);

    // `work` and `digest` are zeroized on drop here.
    Ok(())
}

/// A heap byte buffer that is zeroized on drop and offers in-place mutable
/// slice access.
///
/// [`SecretVec`](oxicrypto_core::SecretVec) is intentionally append-free and
/// exposes only an immutable view, so the Balloon mixing loop — which rewrites
/// blocks in place — uses this local zeroize-on-drop newtype for its working
/// memory and intermediate digest. The final output is still returned via
/// `SecretVec` by the `*_secret` wrappers.
///
/// `Drop` zeroizes via [`oxicrypto_core::Zeroize`]; the derive macros are not
/// used to avoid taking a direct `zeroize` dependency.
struct ZeroizingBuf {
    bytes: Vec<u8>,
}

impl ZeroizingBuf {
    fn new(len: usize) -> Self {
        Self {
            bytes: vec![0u8; len],
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for ZeroizingBuf {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Public function API
// ---------------------------------------------------------------------------

/// Balloon password hash over **SHA-256**, writing 32 bytes into `out`.
///
/// Implements the single-buffer Balloon (Algorithm 1) with `delta = 3`
/// ([`BALLOON_DELTA`]).
///
/// # Arguments
/// - `password`   — secret password / input keying material
/// - `salt`       — salt (use a unique, random salt per password)
/// - `space_cost` — number of 32-byte blocks held in memory (`>= 1`)
/// - `time_cost`  — number of mixing rounds (`>= 1`)
/// - `out`        — output buffer; **must be exactly 32 bytes**
///
/// # Errors
/// Returns [`CryptoError::BadInput`] if `space_cost == 0`, `time_cost == 0`,
/// `out.len() != 32`, or `space_cost` is so large the working buffer cannot be
/// sized.
#[must_use = "balloon hash result must be checked"]
pub fn balloon_sha256(
    password: &[u8],
    salt: &[u8],
    space_cost: u64,
    time_cost: u64,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    balloon_core::<Sha256Hash>(password, salt, space_cost, time_cost, out)
}

/// Balloon password hash over **SHA-512**, writing 64 bytes into `out`.
///
/// Implements the single-buffer Balloon (Algorithm 1) with `delta = 3`
/// ([`BALLOON_DELTA`]).
///
/// # Arguments
/// - `password`   — secret password / input keying material
/// - `salt`       — salt (use a unique, random salt per password)
/// - `space_cost` — number of 64-byte blocks held in memory (`>= 1`)
/// - `time_cost`  — number of mixing rounds (`>= 1`)
/// - `out`        — output buffer; **must be exactly 64 bytes**
///
/// # Errors
/// Returns [`CryptoError::BadInput`] if `space_cost == 0`, `time_cost == 0`,
/// `out.len() != 64`, or `space_cost` is so large the working buffer cannot be
/// sized.
#[must_use = "balloon hash result must be checked"]
pub fn balloon_sha512(
    password: &[u8],
    salt: &[u8],
    space_cost: u64,
    time_cost: u64,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    balloon_core::<Sha512Hash>(password, salt, space_cost, time_cost, out)
}

/// Balloon-SHA-256 hash returning the 32-byte digest wrapped in a
/// [`SecretVec`] that zeroizes on drop.
///
/// # Errors
/// See [`balloon_sha256`].
#[must_use = "derived key should be used"]
pub fn balloon_sha256_secret(
    password: &[u8],
    salt: &[u8],
    space_cost: u64,
    time_cost: u64,
) -> Result<SecretVec, CryptoError> {
    let mut out = vec![0u8; Sha256Hash::DIGEST_LEN];
    balloon_core::<Sha256Hash>(password, salt, space_cost, time_cost, &mut out)?;
    Ok(SecretVec::new(out))
}

/// Balloon-SHA-512 hash returning the 64-byte digest wrapped in a
/// [`SecretVec`] that zeroizes on drop.
///
/// # Errors
/// See [`balloon_sha512`].
#[must_use = "derived key should be used"]
pub fn balloon_sha512_secret(
    password: &[u8],
    salt: &[u8],
    space_cost: u64,
    time_cost: u64,
) -> Result<SecretVec, CryptoError> {
    let mut out = vec![0u8; Sha512Hash::DIGEST_LEN];
    balloon_core::<Sha512Hash>(password, salt, space_cost, time_cost, &mut out)?;
    Ok(SecretVec::new(out))
}

// ---------------------------------------------------------------------------
// BalloonParams + BalloonHasher — PasswordHash trait surface
// ---------------------------------------------------------------------------

/// Underlying hash selector for [`BalloonHasher`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalloonVariant {
    /// Balloon over SHA-256 (32-byte output).
    Sha256,
    /// Balloon over SHA-512 (64-byte output).
    Sha512,
}

/// Cost parameters for Balloon hashing.
///
/// Balloon's cost is governed by `space_cost` (memory, in digest-sized blocks)
/// and `time_cost` (mixing rounds); `delta` is fixed at [`BALLOON_DELTA`].
#[derive(Debug, Clone, Copy)]
pub struct BalloonParams {
    /// Number of digest-sized blocks held in memory (`>= 1`).
    pub space_cost: u64,
    /// Number of mixing rounds (`>= 1`).
    pub time_cost: u64,
}

impl BalloonParams {
    /// Create parameters, validating that both costs are `>= 1`.
    ///
    /// # Errors
    /// Returns [`CryptoError::BadInput`] if `space_cost == 0` or
    /// `time_cost == 0`.
    pub fn new(space_cost: u64, time_cost: u64) -> Result<Self, CryptoError> {
        if space_cost == 0 || time_cost == 0 {
            return Err(CryptoError::BadInput);
        }
        Ok(Self {
            space_cost,
            time_cost,
        })
    }

    /// Interactive login preset — `space_cost = 16384` blocks, `time_cost = 3`.
    ///
    /// With SHA-256 this is ≈ 512 KiB of working memory.
    #[must_use]
    pub fn interactive() -> Self {
        Self {
            space_cost: 16_384,
            time_cost: 3,
        }
    }

    /// Moderate preset — `space_cost = 65536` blocks, `time_cost = 3`.
    ///
    /// With SHA-256 this is ≈ 2 MiB of working memory.
    #[must_use]
    pub fn moderate() -> Self {
        Self {
            space_cost: 65_536,
            time_cost: 3,
        }
    }

    /// Sensitive (high-security) preset — `space_cost = 262144` blocks,
    /// `time_cost = 3`.
    ///
    /// With SHA-256 this is ≈ 8 MiB of working memory.
    #[must_use]
    pub fn sensitive() -> Self {
        Self {
            space_cost: 262_144,
            time_cost: 3,
        }
    }
}

impl PasswordHashParams for BalloonParams {
    /// Memory cost expressed in KiB, assuming a 32-byte (SHA-256) block. This
    /// is an approximation for reporting; the actual footprint for SHA-512 is
    /// twice as large.
    fn memory_cost(&self) -> Option<u32> {
        let kib = self.space_cost.saturating_mul(32) / 1024;
        u32::try_from(kib).ok()
    }

    fn time_cost(&self) -> Option<u32> {
        u32::try_from(self.time_cost).ok()
    }

    fn parallelism(&self) -> Option<u32> {
        // Single-buffer Balloon (Algorithm 1) is inherently sequential.
        Some(1)
    }
}

/// A Balloon password hasher bundling its variant and cost parameters.
///
/// Implements [`PasswordHash`](oxicrypto_core::PasswordHash) so it composes
/// with [`crate::verify_password`].
///
/// # Design note — `params` argument is ignored
/// [`PasswordHash::hash_password`](oxicrypto_core::PasswordHash::hash_password)
/// accepts a `params: &dyn PasswordHashParams`, but this implementation uses
/// `self.params` instead. The output length is fixed by the variant (32 bytes
/// for SHA-256, 64 for SHA-512); `out` must match.
#[derive(Debug, Clone, Copy)]
pub struct BalloonHasher {
    /// Underlying hash variant.
    pub variant: BalloonVariant,
    /// Cost parameters.
    pub params: BalloonParams,
}

impl BalloonHasher {
    /// Create a Balloon-SHA-256 hasher with the given parameters.
    #[must_use]
    pub fn new_sha256(params: BalloonParams) -> Self {
        Self {
            variant: BalloonVariant::Sha256,
            params,
        }
    }

    /// Create a Balloon-SHA-512 hasher with the given parameters.
    #[must_use]
    pub fn new_sha512(params: BalloonParams) -> Self {
        Self {
            variant: BalloonVariant::Sha512,
            params,
        }
    }

    /// Digest length in bytes for this hasher's variant.
    #[must_use]
    pub fn output_len(&self) -> usize {
        match self.variant {
            BalloonVariant::Sha256 => Sha256Hash::DIGEST_LEN,
            BalloonVariant::Sha512 => Sha512Hash::DIGEST_LEN,
        }
    }
}

impl PasswordHashTrait for BalloonHasher {
    fn name(&self) -> &'static str {
        match self.variant {
            BalloonVariant::Sha256 => "balloon-sha256",
            BalloonVariant::Sha512 => "balloon-sha512",
        }
    }

    fn hash_password(
        &self,
        password: &[u8],
        salt: &[u8],
        _params: &dyn PasswordHashParams,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        match self.variant {
            BalloonVariant::Sha256 => balloon_sha256(
                password,
                salt,
                self.params.space_cost,
                self.params.time_cost,
                out,
            ),
            BalloonVariant::Sha512 => balloon_sha512(
                password,
                salt,
                self.params.space_cost,
                self.params.time_cost,
                out,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors are validated in tests/kat_balloon.rs; here we cover
    // structural properties and the trait surface with tiny parameters.

    #[test]
    fn determinism_same_inputs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        balloon_sha256(b"password", b"salt", 8, 3, &mut a).expect("a");
        balloon_sha256(b"password", b"salt", 8, 3, &mut b).expect("b");
        assert_eq!(a, b, "balloon must be deterministic");
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn different_salt_differs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        balloon_sha256(b"password", b"salt", 8, 3, &mut a).expect("a");
        balloon_sha256(b"password", b"pepper", 8, 3, &mut b).expect("b");
        assert_ne!(a, b, "different salt must change output");
    }

    #[test]
    fn rejects_zero_space_cost() {
        let mut out = [0u8; 32];
        assert_eq!(
            balloon_sha256(b"pw", b"salt", 0, 3, &mut out),
            Err(CryptoError::BadInput)
        );
    }

    #[test]
    fn rejects_zero_time_cost() {
        let mut out = [0u8; 32];
        assert_eq!(
            balloon_sha256(b"pw", b"salt", 8, 0, &mut out),
            Err(CryptoError::BadInput)
        );
    }

    #[test]
    fn rejects_wrong_output_len() {
        let mut short = [0u8; 16];
        assert_eq!(
            balloon_sha256(b"pw", b"salt", 8, 3, &mut short),
            Err(CryptoError::BadInput)
        );
        let mut long = [0u8; 64];
        assert_eq!(
            balloon_sha256(b"pw", b"salt", 8, 3, &mut long),
            Err(CryptoError::BadInput)
        );
    }

    #[test]
    fn space_cost_one_is_valid() {
        // space_cost == 1 means buf[(m-1) mod 1] == buf[0] == buf[m]; the
        // construction must still run without panic.
        let mut out = [0u8; 32];
        balloon_sha256(b"pw", b"salt", 1, 2, &mut out).expect("space_cost=1");
        assert_ne!(out, [0u8; 32]);
    }

    #[test]
    fn sha512_variant_runs() {
        let mut out = [0u8; 64];
        balloon_sha512(b"password", b"salt", 8, 3, &mut out).expect("sha512");
        assert_ne!(out, [0u8; 64]);
    }

    #[test]
    fn secret_wrappers_match_buffer_api() {
        let mut direct = [0u8; 32];
        balloon_sha256(b"pw", b"salt", 8, 3, &mut direct).expect("direct");
        let secret = balloon_sha256_secret(b"pw", b"salt", 8, 3).expect("secret");
        assert_eq!(secret.as_bytes(), &direct[..]);

        let mut direct512 = [0u8; 64];
        balloon_sha512(b"pw", b"salt", 8, 3, &mut direct512).expect("direct512");
        let secret512 = balloon_sha512_secret(b"pw", b"salt", 8, 3).expect("secret512");
        assert_eq!(secret512.as_bytes(), &direct512[..]);
    }

    #[test]
    fn le_digest_mod_matches_reference_semantics() {
        // int.from_bytes([1,0,0,...], "little") == 1, mod 8 == 1.
        let mut d = [0u8; 32];
        d[0] = 1;
        assert_eq!(le_digest_mod(&d, 8), 1);
        // int.from_bytes([0,1,0,...], "little") == 256, mod 8 == 0.
        let mut d2 = [0u8; 32];
        d2[1] = 1;
        assert_eq!(le_digest_mod(&d2, 8), 0);
        // mod 1 is always 0.
        assert_eq!(le_digest_mod(&d, 1), 0);
    }

    #[test]
    fn params_validation_and_presets() {
        assert!(BalloonParams::new(0, 1).is_err());
        assert!(BalloonParams::new(1, 0).is_err());
        assert!(BalloonParams::new(8, 3).is_ok());
        let i = BalloonParams::interactive();
        let m = BalloonParams::moderate();
        let s = BalloonParams::sensitive();
        assert!(s.space_cost > m.space_cost);
        assert!(m.space_cost > i.space_cost);
        assert_eq!(i.parallelism(), Some(1));
        assert!(i.memory_cost().is_some());
        assert_eq!(i.time_cost(), Some(3));
    }

    #[test]
    fn hasher_trait_surface() {
        let hasher = BalloonHasher::new_sha256(BalloonParams {
            space_cost: 8,
            time_cost: 3,
        });
        assert_eq!(hasher.name(), "balloon-sha256");
        assert_eq!(hasher.output_len(), 32);
        let mut out = [0u8; 32];
        hasher
            .hash_password(b"pw", b"salt", &hasher.params, &mut out)
            .expect("hash");
        let mut direct = [0u8; 32];
        balloon_sha256(b"pw", b"salt", 8, 3, &mut direct).expect("direct");
        assert_eq!(out, direct, "hasher must match standalone fn");

        let hasher512 = BalloonHasher::new_sha512(BalloonParams {
            space_cost: 8,
            time_cost: 3,
        });
        assert_eq!(hasher512.name(), "balloon-sha512");
        assert_eq!(hasher512.output_len(), 64);
    }

    #[test]
    fn verify_password_round_trip() {
        use crate::verify_password;
        let hasher = BalloonHasher::new_sha256(BalloonParams {
            space_cost: 8,
            time_cost: 3,
        });
        let salt = b"0123456789abcdef";
        let mut expected = [0u8; 32];
        hasher
            .hash_password(b"correct horse", salt, &hasher.params, &mut expected)
            .expect("hash");
        verify_password(&hasher, b"correct horse", salt, &expected).expect("must accept");
        assert!(verify_password(&hasher, b"wrong", salt, &expected).is_err());
    }
}
