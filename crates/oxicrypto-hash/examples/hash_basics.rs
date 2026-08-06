//! One-shot vs. streaming hashing with `oxicrypto-hash`.
//!
//! Demonstrates SHA-256, SHA3-256, and BLAKE3 one-shot hashing via the
//! [`Hash`] trait, and shows that feeding a message in chunks through the
//! [`StreamingHash`] adapter produces the same digest as hashing it in one
//! call — the property any streaming API must satisfy.
//!
//! Builds under both default (`alloc`) and `--no-default-features`: this
//! example only uses `hash_to_array`/`hash`/streaming, none of which need
//! heap allocation.
//!
//! Run with:
//!   cargo run -p oxicrypto-hash --example hash_basics

use oxicrypto_hash::{Blake3, Hash, Sha256, Sha256Streaming, Sha3_256, StreamingHash};

fn main() {
    let message = b"the quick brown fox jumps over the lazy dog";

    one_shot_hashing(message);
    streaming_matches_one_shot(message);
}

fn one_shot_hashing(message: &[u8]) {
    // `hash_to_array::<N>` is alloc-free: it writes into a stack `[u8; N]`.
    let sha256_digest: [u8; 32] = Sha256.hash_to_array(message).expect("SHA-256 digest");
    println!(
        "SHA-256   ({} bytes): {}",
        sha256_digest.len(),
        hex(&sha256_digest)
    );

    let sha3_digest: [u8; 32] = Sha3_256.hash_to_array(message).expect("SHA3-256 digest");
    println!(
        "SHA3-256  ({} bytes): {}",
        sha3_digest.len(),
        hex(&sha3_digest)
    );

    let blake3_digest: [u8; 32] = Blake3.hash_to_array(message).expect("BLAKE3 digest");
    println!(
        "BLAKE3    ({} bytes): {}",
        blake3_digest.len(),
        hex(&blake3_digest)
    );

    // Different messages must produce different digests.
    let other_digest: [u8; 32] = Sha256.hash_to_array(b"different input").expect("digest");
    assert_ne!(
        sha256_digest, other_digest,
        "SHA-256 must not collide on different inputs"
    );
}

fn streaming_matches_one_shot(message: &[u8]) {
    // Feed the message in three uneven chunks through the streaming adapter.
    let (chunk_a, rest) = message.split_at(7);
    let (chunk_b, chunk_c) = rest.split_at(rest.len() / 2);

    let mut streaming = Sha256Streaming::new();
    streaming.update(chunk_a);
    streaming.update(chunk_b);
    streaming.update(chunk_c);

    let mut streamed_digest = [0u8; 32];
    streaming
        .finalize(&mut streamed_digest)
        .expect("streaming finalize");

    let one_shot_digest: [u8; 32] = Sha256.hash_to_array(message).expect("one-shot digest");

    assert_eq!(
        streamed_digest, one_shot_digest,
        "streaming SHA-256 over chunks must equal one-shot SHA-256 over the whole message"
    );
    println!(
        "Streaming (3 chunks) == one-shot SHA-256: {}",
        hex(&streamed_digest)
    );
}

/// Format a byte slice as a lowercase hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
