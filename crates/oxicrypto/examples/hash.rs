//! Hash example: SHA-256, SHA-512, BLAKE3, and SHA3-256 via trait object.
//!
//! Run with:
//!   cargo run -p oxicrypto --example hash

use oxicrypto::{blake3, hash_impl, sha256, sha512, HashAlgo};

fn main() {
    let message = b"the quick brown fox jumps over the lazy dog";

    // One-shot convenience functions for the three most common hash algorithms.
    let digest_256 = sha256(message);
    println!("SHA-256 ({} bytes): {}", digest_256.len(), hex(&digest_256));

    let digest_512 = sha512(message);
    println!("SHA-512 ({} bytes): {}", digest_512.len(), hex(&digest_512));

    let digest_b3 = blake3(message);
    println!("BLAKE3  ({} bytes): {}", digest_b3.len(), hex(&digest_b3));

    // Factory function returning a trait object: algorithm selected at runtime.
    let hasher = hash_impl(HashAlgo::Sha3_256);
    let mut out = vec![0u8; hasher.output_len()];
    hasher
        .hash(message, &mut out)
        .expect("SHA3-256 hash failed: buffer size mismatch");
    println!("SHA3-256 ({} bytes): {}", out.len(), hex(&out));

    // Verify that different messages produce different digests.
    let alt_digest = sha256(b"different input");
    assert_ne!(
        digest_256, alt_digest,
        "SHA-256 must not produce the same digest for different inputs"
    );
    println!("Collision check passed: different inputs produce different digests");
}

/// Format a byte slice as a lowercase hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
