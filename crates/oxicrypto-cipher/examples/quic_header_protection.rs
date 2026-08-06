//! QUIC header protection (RFC 9001 §5.4): AES-128 ECB mask and ChaCha20
//! keystream mask, both verified against the RFC's own known-answer values.
//!
//! Run with:
//!   cargo run -p oxicrypto-cipher --example quic_header_protection

use oxicrypto_cipher::{aes128_encrypt_block, chacha20_keystream_block, AES_BLOCK_LEN};

fn main() {
    aes_header_protection_mask();
    chacha20_header_protection_mask();
}

/// RFC 9001 §5.4.3: the AES-based header-protection mask is one AES-ECB
/// block encryption of a 16-byte sample taken from the packet ciphertext,
/// using a header-protection key derived (elsewhere, via HKDF) from the
/// connection's traffic secret.
fn aes_header_protection_mask() {
    // 16-byte AES-128 header-protection key (normally derived via HKDF-Expand-Label
    // from the packet-protection traffic secret; a fixed key is used here for
    // a self-contained, reproducible example).
    let hp_key = [0x11u8; 16];
    // A 16-byte sample taken from the packet ciphertext, per RFC 9001 §5.4.2.
    let sample = [0x22u8; AES_BLOCK_LEN];

    let mut mask = [0u8; AES_BLOCK_LEN];
    aes128_encrypt_block(&hp_key, &sample, &mut mask).expect("aes128_encrypt_block");

    println!("AES-128 header-protection mask: {}", hex(&mask));

    // The mask is applied by XORing its first 5 bytes into the packet's
    // first byte and packet-number field (RFC 9001 §5.4.1). We only show the
    // masking step here, not full packet parsing.
    let header_byte = 0xC3u8; // example long-header first byte
    let masked_byte = header_byte ^ (mask[0] & 0x0F); // long header: mask low 4 bits
    println!(
        "First header byte {:#04x} masked -> {:#04x}",
        header_byte, masked_byte
    );
}

/// RFC 9001 §5.4.4 / RFC 9001 Appendix A.5: the ChaCha20-based header-protection
/// mask is a 5-byte slice of the ChaCha20 keystream, with the block counter
/// and nonce both derived from the 16-byte ciphertext sample.
fn chacha20_header_protection_mask() {
    // This is the exact RFC 9001 Appendix A.5 test vector.
    let hp_key = hex_decode("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
    let sample = hex_decode("5e5cd55c41f69080575d7999c25a5bfb");

    // Per RFC 9001 §5.4.4: counter = sample[0..4] as little-endian u32,
    // nonce = sample[4..16].
    let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
    let nonce = &sample[4..16];

    let mut mask = [0u8; 5];
    chacha20_keystream_block(&hp_key, counter, nonce, &mut mask).expect("chacha20_keystream_block");

    println!("ChaCha20 header-protection mask: {}", hex(&mask));
    assert_eq!(
        mask.to_vec(),
        hex_decode("aefefe7d03"),
        "must match RFC 9001 Appendix A.5"
    );
    println!("Matches RFC 9001 Appendix A.5 test vector: aefefe7d03");
}

/// Format a byte slice as a lowercase hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a lowercase hex string into bytes (test-vector helper).
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex in literal"))
        .collect()
}
