//! In-crate HPKE test suite.
//!
//! Kept inside the crate (rather than under top-level `tests/`) so that the
//! `pub(crate)` derandomized setup seams (`*_deterministic`) used by the
//! known-answer tests never leak into the public API.

mod rfc9180_vectors;
mod roundtrip;

/// Decode a hex string from an RFC 9180 test vector.
///
/// This is the **only** sanctioned `unwrap` site in the crate: the inputs are
/// compile-time-constant, known-good vectors, so a decode failure is a test bug
/// to surface immediately rather than a runtime condition to handle.
pub(crate) fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}
