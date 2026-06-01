//! Cross-crate integration tests for the oxicrypto facade.
//!
//! Exercises the full cryptographic pipeline across crate boundaries:
//! hash → HMAC → HKDF → AEAD, keygen → sign → verify, KEX → HKDF → AEAD,
//! enum uniqueness, and available_algorithms() coverage.
//!
//! # Feature gates
//!
//! - Default tests compile with `default` features (which enables `pure`).
//! - PQ tests are guarded by `#[cfg(feature = "pq-preview")]`.

use oxicrypto::{
    aead_impl, available_algorithms, hash_impl, kdf_impl, kex_impl, mac_impl, signer_impl,
    verifier_impl, AeadAlgo, AlgorithmId, HashAlgo, KdfAlgo, KexAlgo, MacAlgo, SigAlgo,
};

// ── Shared RSA-2048 test key pair (embedded, no runtime keygen) ───────────────
//
// Generated offline with ChaCha20Rng seeded with [0x42; 32].
// Identical constants to crates/oxicrypto-sig/tests/kat_rsa.rs.

const RSA_2048_PKCS8_DER: &[u8] = &[
    0x30, 0x82, 0x04, 0xbf, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x04, 0xa9, 0x30, 0x82, 0x04, 0xa5, 0x02, 0x01,
    0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcf, 0xd0, 0x8a, 0x54, 0x50, 0x4c, 0x82, 0x9a, 0x5c, 0x68,
    0xc6, 0x77, 0x23, 0xa6, 0x7d, 0xc4, 0xce, 0xa8, 0xdb, 0xe1, 0xf6, 0xa0, 0x74, 0x4f, 0x79, 0x26,
    0xdd, 0xbb, 0xe6, 0xce, 0xbf, 0x9d, 0x9d, 0x0d, 0xe8, 0x22, 0x08, 0x85, 0xa4, 0x19, 0x6e, 0x08,
    0x96, 0x99, 0x92, 0xaa, 0x38, 0x9d, 0x29, 0x6c, 0x7a, 0x1e, 0xae, 0xf9, 0x08, 0xe6, 0xc2, 0x70,
    0x28, 0xee, 0xef, 0xe1, 0x8e, 0xef, 0x2d, 0x1b, 0xef, 0x6b, 0xcc, 0xe9, 0xf2, 0x70, 0x56, 0x6f,
    0x64, 0xb8, 0x78, 0xce, 0x7f, 0x78, 0x85, 0xbe, 0xfa, 0xdf, 0x7d, 0x3e, 0x63, 0x40, 0xa8, 0x27,
    0x08, 0xac, 0xf3, 0x78, 0x3b, 0x55, 0x45, 0xac, 0x88, 0x59, 0x65, 0x76, 0x82, 0x2f, 0x6b, 0x34,
    0x4b, 0xca, 0x5d, 0x95, 0xe5, 0x99, 0xf6, 0xa1, 0x15, 0xa8, 0x36, 0xec, 0x71, 0xa9, 0x39, 0xe6,
    0xaf, 0xf2, 0x80, 0x50, 0x15, 0x73, 0x6b, 0xd9, 0xad, 0xe3, 0xb0, 0xd3, 0xed, 0x84, 0xcf, 0xf9,
    0x2c, 0x80, 0x5d, 0x35, 0x38, 0xed, 0x3a, 0xa5, 0xc2, 0x59, 0x99, 0x53, 0x0d, 0x32, 0x4e, 0x60,
    0x0a, 0x0c, 0xad, 0xbf, 0xdb, 0x38, 0x4c, 0x76, 0x07, 0xe5, 0x40, 0x8e, 0x0d, 0x1b, 0x91, 0x41,
    0x52, 0x09, 0x3e, 0xd8, 0x45, 0x64, 0x8f, 0x50, 0xfb, 0x86, 0xe8, 0x8b, 0x28, 0x6f, 0x1c, 0x29,
    0x30, 0x5c, 0x4a, 0x2f, 0x92, 0x05, 0xd8, 0xfc, 0xe9, 0x32, 0x16, 0xa5, 0x0b, 0x4b, 0xba, 0x6f,
    0x5d, 0x1a, 0x18, 0x01, 0xd6, 0x2e, 0xa0, 0x9b, 0x5c, 0xfa, 0x4d, 0x25, 0x1d, 0xf0, 0x01, 0x01,
    0x48, 0x2f, 0xbf, 0x71, 0x35, 0x12, 0xad, 0x0d, 0xc8, 0xe4, 0x70, 0x7a, 0x28, 0xb9, 0x54, 0x17,
    0xc1, 0xbd, 0x6a, 0xcf, 0x00, 0x1c, 0x07, 0x69, 0xff, 0x97, 0x89, 0x0a, 0x31, 0xee, 0xf0, 0xd9,
    0x84, 0x0f, 0xb4, 0x0f, 0x3e, 0x11, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x00, 0x2e,
    0xd1, 0xaf, 0xe8, 0x90, 0xf2, 0xbb, 0xd5, 0xe5, 0x0d, 0xe1, 0xf0, 0xc3, 0x82, 0x66, 0x01, 0x6a,
    0x01, 0xd7, 0x10, 0x10, 0x8d, 0x53, 0xc6, 0xf7, 0xe7, 0x8e, 0xbb, 0x1f, 0xa3, 0xe2, 0xbd, 0xb2,
    0xbd, 0x88, 0x57, 0xea, 0x8d, 0x99, 0x4b, 0xf5, 0x63, 0x4f, 0xf2, 0xa7, 0x7d, 0x5c, 0x25, 0xe4,
    0x48, 0x41, 0x37, 0x1a, 0x7a, 0x96, 0xcb, 0xce, 0x70, 0x90, 0x78, 0x4c, 0x69, 0x07, 0xd7, 0xd0,
    0xd4, 0xe3, 0x5a, 0xe9, 0x1e, 0xa7, 0xf5, 0x31, 0x34, 0x05, 0x80, 0x1e, 0x0f, 0x7f, 0xde, 0x7a,
    0x5b, 0x6d, 0x8f, 0xde, 0x5a, 0xa8, 0xe7, 0xcf, 0x3a, 0x84, 0x14, 0xdb, 0x01, 0x72, 0x74, 0xa2,
    0xae, 0xdd, 0x45, 0x2e, 0xbb, 0xc5, 0x56, 0xc3, 0x93, 0x53, 0xa3, 0xf2, 0xf3, 0xab, 0x77, 0xc5,
    0x7d, 0xc3, 0x30, 0x53, 0xb7, 0x6f, 0x60, 0x0d, 0xe0, 0x70, 0x31, 0x75, 0x41, 0x15, 0xa3, 0xb4,
    0x1f, 0xbc, 0xb2, 0xe6, 0xa6, 0x58, 0xee, 0xb0, 0x02, 0x69, 0x3c, 0x51, 0x42, 0x08, 0xc3, 0x78,
    0x61, 0xf3, 0xef, 0x3b, 0xdb, 0xd9, 0x17, 0xa5, 0x2b, 0x67, 0x21, 0x16, 0x05, 0x6d, 0x8d, 0x7a,
    0x0a, 0x96, 0x38, 0x64, 0x81, 0x08, 0x34, 0xa2, 0xa2, 0xc5, 0x5d, 0xea, 0x82, 0x01, 0x0b, 0x67,
    0xda, 0x83, 0x0d, 0x74, 0xfb, 0xda, 0xe2, 0x0c, 0x5e, 0x65, 0x54, 0x23, 0x49, 0xa9, 0x72, 0xae,
    0x08, 0xe0, 0x79, 0x6a, 0xd0, 0x87, 0xd0, 0x1a, 0x68, 0x04, 0xc5, 0xde, 0x87, 0x77, 0x02, 0xbe,
    0x9b, 0x40, 0x1a, 0x8a, 0x9e, 0xb6, 0xc6, 0x1e, 0xd0, 0x27, 0xe7, 0xb9, 0x07, 0x46, 0xa9, 0x13,
    0xd8, 0x44, 0x01, 0xa1, 0xb6, 0x9d, 0xb8, 0xbb, 0x50, 0x55, 0xac, 0x6d, 0x04, 0x64, 0x95, 0x5c,
    0x9f, 0x2c, 0x94, 0x58, 0xeb, 0xa5, 0x5a, 0xfb, 0x94, 0x9f, 0x4c, 0x7e, 0x6c, 0x8c, 0x25, 0x02,
    0x81, 0x81, 0x00, 0xf9, 0x76, 0x15, 0xd6, 0x58, 0x1b, 0x76, 0x73, 0xf6, 0xee, 0xc1, 0x3c, 0xcd,
    0xc9, 0x3d, 0x36, 0x73, 0x96, 0x4c, 0x20, 0x59, 0xa9, 0x48, 0xea, 0x35, 0x03, 0xd8, 0x5a, 0xea,
    0x28, 0xaf, 0x83, 0xcf, 0x20, 0xb0, 0x4c, 0xd5, 0x0f, 0xcd, 0xff, 0x1c, 0xa4, 0x95, 0xaa, 0xd9,
    0xa4, 0xa7, 0xbe, 0xb8, 0xa8, 0x2f, 0xff, 0x34, 0x54, 0xa1, 0xec, 0xcd, 0x33, 0xb4, 0x1d, 0x2b,
    0xe4, 0x66, 0x59, 0xd1, 0x0b, 0xc5, 0x34, 0xf5, 0x9f, 0xe4, 0xc9, 0x2d, 0x3d, 0x31, 0x9e, 0xed,
    0x02, 0x10, 0x12, 0x85, 0x15, 0x13, 0xd9, 0x13, 0x2a, 0xdd, 0xf5, 0x94, 0x5c, 0x9f, 0x36, 0x0d,
    0xb4, 0x06, 0xe1, 0x6e, 0x0b, 0x50, 0xe9, 0x68, 0x74, 0xb0, 0xe7, 0x66, 0x79, 0xf4, 0xbd, 0x83,
    0x0e, 0x10, 0x3e, 0x1e, 0xf2, 0xf3, 0xec, 0x50, 0xce, 0x14, 0x6f, 0x69, 0xba, 0x32, 0x7f, 0x1f,
    0xf3, 0xe0, 0x33, 0x02, 0x81, 0x81, 0x00, 0xd5, 0x43, 0x00, 0x42, 0xf7, 0xc7, 0x1f, 0x8a, 0x9d,
    0x9e, 0xe1, 0xf3, 0x03, 0xe9, 0x68, 0x7c, 0x58, 0x50, 0x37, 0x01, 0x44, 0x53, 0x63, 0x5e, 0x8c,
    0x30, 0xdc, 0x4b, 0x77, 0x27, 0x84, 0xfb, 0x49, 0xf5, 0x79, 0x63, 0x5a, 0x25, 0xc1, 0xc2, 0xd1,
    0xba, 0xad, 0xd3, 0xcb, 0x8d, 0x0d, 0xf5, 0x4d, 0x3c, 0xc7, 0x70, 0x54, 0xcf, 0xef, 0xe0, 0x23,
    0x92, 0x1f, 0xf2, 0x0e, 0x65, 0xdb, 0xdb, 0x9d, 0xc5, 0x17, 0xac, 0x6a, 0x08, 0x58, 0xdd, 0xe2,
    0xcb, 0x05, 0x6c, 0xed, 0x90, 0x50, 0x5c, 0x9c, 0xd5, 0x6c, 0x35, 0x72, 0x9e, 0x09, 0xba, 0xc3,
    0xeb, 0x5e, 0xdb, 0x32, 0x87, 0x24, 0x71, 0x2e, 0x57, 0x72, 0x3e, 0x4f, 0x0d, 0x55, 0x04, 0x1a,
    0xc8, 0x12, 0x5f, 0xd3, 0x7d, 0x03, 0x2f, 0x9a, 0x42, 0x8f, 0x1e, 0x68, 0x1b, 0x22, 0x0c, 0x17,
    0x2d, 0x00, 0x28, 0xd0, 0x49, 0x94, 0xab, 0x02, 0x81, 0x81, 0x00, 0x8e, 0x47, 0xb6, 0x8e, 0xc9,
    0x33, 0xe8, 0xac, 0x9d, 0x83, 0x71, 0x7d, 0x7f, 0x95, 0xae, 0xaf, 0x16, 0xdf, 0xfb, 0x4d, 0x5c,
    0x36, 0x3c, 0x5b, 0x30, 0x9f, 0x9f, 0xcf, 0xc2, 0xcc, 0x2f, 0xc7, 0x0a, 0xe5, 0x07, 0x08, 0xdb,
    0x60, 0xa7, 0x4a, 0x41, 0x08, 0xf2, 0x40, 0x3e, 0xe0, 0x35, 0xb8, 0x86, 0xd3, 0x8e, 0x84, 0x8d,
    0x51, 0x54, 0x05, 0x9e, 0xc8, 0x45, 0x8b, 0x79, 0xd4, 0x4c, 0x38, 0x20, 0x0e, 0x09, 0x8d, 0x7a,
    0x26, 0x97, 0x33, 0xd2, 0xf4, 0x9b, 0x0f, 0x9c, 0xf8, 0x57, 0x38, 0x68, 0xe5, 0x2b, 0xab, 0xdc,
    0xcd, 0xcf, 0x48, 0xd9, 0x34, 0xb6, 0xad, 0xfa, 0xc4, 0xda, 0x43, 0xcb, 0x22, 0xf3, 0x24, 0x1d,
    0x2a, 0xa9, 0x17, 0x62, 0x10, 0x5e, 0xf1, 0x94, 0x04, 0xfa, 0x68, 0xa3, 0xf8, 0x47, 0xfd, 0x59,
    0xdd, 0x20, 0x34, 0xa7, 0x65, 0xc6, 0x95, 0x51, 0x21, 0x24, 0x97, 0x02, 0x81, 0x81, 0x00, 0xaa,
    0xdb, 0xa5, 0x28, 0x02, 0x0f, 0x9c, 0x6b, 0x97, 0xe0, 0xa5, 0x31, 0xe7, 0x9e, 0x66, 0xc1, 0xc8,
    0x97, 0x6b, 0x9a, 0x2e, 0x3d, 0x88, 0xcd, 0x45, 0x10, 0x18, 0x4e, 0xb5, 0xc6, 0x09, 0xba, 0xb2,
    0x04, 0x63, 0x1e, 0x80, 0x28, 0xe3, 0xd5, 0xcb, 0xe5, 0xfe, 0x42, 0x43, 0x40, 0x5d, 0x40, 0x7c,
    0x83, 0x07, 0x5e, 0x2d, 0xf4, 0xf2, 0x3f, 0xe6, 0xff, 0xb9, 0x6c, 0x5a, 0xb0, 0xac, 0xb6, 0x84,
    0xee, 0x55, 0x0b, 0x23, 0x60, 0x50, 0xa2, 0x64, 0x83, 0x37, 0x73, 0x8f, 0xd9, 0x21, 0x29, 0x31,
    0xd5, 0xa3, 0x7e, 0x26, 0xb8, 0x0b, 0x1f, 0x80, 0xbb, 0xe0, 0x21, 0x49, 0x98, 0x10, 0x50, 0x45,
    0x4a, 0x76, 0x13, 0x09, 0x8e, 0xaa, 0xe0, 0x40, 0xfc, 0xae, 0x0b, 0xec, 0x0a, 0xaa, 0x34, 0xc7,
    0x28, 0x30, 0x35, 0xb2, 0x3e, 0x9a, 0xc6, 0x89, 0x02, 0xda, 0xaf, 0xd8, 0x40, 0x3b, 0x45, 0x02,
    0x81, 0x81, 0x00, 0xbf, 0xb8, 0xf8, 0x9a, 0x81, 0x9f, 0x4a, 0x78, 0x09, 0x98, 0x91, 0x4c, 0xb1,
    0x27, 0x8f, 0x9e, 0x29, 0x17, 0xa6, 0xce, 0x23, 0x11, 0xa2, 0xee, 0xd2, 0x02, 0xd8, 0x12, 0x3d,
    0x3a, 0xea, 0x0e, 0xc7, 0x73, 0x7b, 0xe8, 0xdb, 0x71, 0x57, 0xcd, 0xb9, 0x61, 0x64, 0xf8, 0x92,
    0x46, 0xa2, 0xd6, 0xd4, 0x02, 0x9e, 0x23, 0xe3, 0xf1, 0x2c, 0x6b, 0x85, 0xa1, 0xef, 0x15, 0xe9,
    0xb0, 0x5b, 0xdb, 0x0e, 0x8b, 0x73, 0x0e, 0x6b, 0x5e, 0xad, 0xd1, 0x86, 0xbb, 0x52, 0x50, 0xe6,
    0xc8, 0x22, 0xe4, 0xb6, 0x98, 0xf6, 0xfa, 0x7f, 0x1d, 0x29, 0xee, 0x8c, 0xa0, 0x21, 0x72, 0x52,
    0x5e, 0x22, 0xda, 0xb8, 0xbc, 0x5f, 0xbc, 0x30, 0x64, 0xfe, 0xe0, 0xf1, 0x21, 0x27, 0xe4, 0x1a,
    0x25, 0x05, 0x0e, 0xfd, 0x5a, 0x7d, 0x6a, 0x9c, 0x67, 0x1b, 0x77, 0x91, 0x4e, 0x17, 0x2a, 0xbd,
    0x16, 0x58, 0x67,
];

const RSA_2048_SPKI_DER: &[u8] = &[
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
    0x00, 0xcf, 0xd0, 0x8a, 0x54, 0x50, 0x4c, 0x82, 0x9a, 0x5c, 0x68, 0xc6, 0x77, 0x23, 0xa6, 0x7d,
    0xc4, 0xce, 0xa8, 0xdb, 0xe1, 0xf6, 0xa0, 0x74, 0x4f, 0x79, 0x26, 0xdd, 0xbb, 0xe6, 0xce, 0xbf,
    0x9d, 0x9d, 0x0d, 0xe8, 0x22, 0x08, 0x85, 0xa4, 0x19, 0x6e, 0x08, 0x96, 0x99, 0x92, 0xaa, 0x38,
    0x9d, 0x29, 0x6c, 0x7a, 0x1e, 0xae, 0xf9, 0x08, 0xe6, 0xc2, 0x70, 0x28, 0xee, 0xef, 0xe1, 0x8e,
    0xef, 0x2d, 0x1b, 0xef, 0x6b, 0xcc, 0xe9, 0xf2, 0x70, 0x56, 0x6f, 0x64, 0xb8, 0x78, 0xce, 0x7f,
    0x78, 0x85, 0xbe, 0xfa, 0xdf, 0x7d, 0x3e, 0x63, 0x40, 0xa8, 0x27, 0x08, 0xac, 0xf3, 0x78, 0x3b,
    0x55, 0x45, 0xac, 0x88, 0x59, 0x65, 0x76, 0x82, 0x2f, 0x6b, 0x34, 0x4b, 0xca, 0x5d, 0x95, 0xe5,
    0x99, 0xf6, 0xa1, 0x15, 0xa8, 0x36, 0xec, 0x71, 0xa9, 0x39, 0xe6, 0xaf, 0xf2, 0x80, 0x50, 0x15,
    0x73, 0x6b, 0xd9, 0xad, 0xe3, 0xb0, 0xd3, 0xed, 0x84, 0xcf, 0xf9, 0x2c, 0x80, 0x5d, 0x35, 0x38,
    0xed, 0x3a, 0xa5, 0xc2, 0x59, 0x99, 0x53, 0x0d, 0x32, 0x4e, 0x60, 0x0a, 0x0c, 0xad, 0xbf, 0xdb,
    0x38, 0x4c, 0x76, 0x07, 0xe5, 0x40, 0x8e, 0x0d, 0x1b, 0x91, 0x41, 0x52, 0x09, 0x3e, 0xd8, 0x45,
    0x64, 0x8f, 0x50, 0xfb, 0x86, 0xe8, 0x8b, 0x28, 0x6f, 0x1c, 0x29, 0x30, 0x5c, 0x4a, 0x2f, 0x92,
    0x05, 0xd8, 0xfc, 0xe9, 0x32, 0x16, 0xa5, 0x0b, 0x4b, 0xba, 0x6f, 0x5d, 0x1a, 0x18, 0x01, 0xd6,
    0x2e, 0xa0, 0x9b, 0x5c, 0xfa, 0x4d, 0x25, 0x1d, 0xf0, 0x01, 0x01, 0x48, 0x2f, 0xbf, 0x71, 0x35,
    0x12, 0xad, 0x0d, 0xc8, 0xe4, 0x70, 0x7a, 0x28, 0xb9, 0x54, 0x17, 0xc1, 0xbd, 0x6a, 0xcf, 0x00,
    0x1c, 0x07, 0x69, 0xff, 0x97, 0x89, 0x0a, 0x31, 0xee, 0xf0, 0xd9, 0x84, 0x0f, 0xb4, 0x0f, 0x3e,
    0x11, 0x02, 0x03, 0x01, 0x00, 0x01,
];

// ── Test 1: hash → HMAC → HKDF → AEAD pipeline ──────────────────────────────

/// Full pipeline: SHA-256 hash → HMAC-SHA-256 → HKDF-SHA-256 key derivation →
/// AES-256-GCM encrypt/decrypt. Proves cross-crate output feeds chain correctly.
#[test]
fn test_hash_hmac_hkdf_aead_pipeline() {
    let message = b"Hello, OxiCrypto!";

    // Step 1: SHA-256 the message (cross-crate: facade → hash crate)
    let hasher = hash_impl(HashAlgo::Sha256);
    let mut hash_out = [0u8; 32];
    hasher
        .hash(message, &mut hash_out)
        .expect("SHA-256 hash failed");
    assert_ne!(hash_out, [0u8; 32], "hash output must not be all-zero");

    // Step 2: HMAC-SHA-256 the hash (cross-crate: facade → mac crate)
    let hmac_key = [0x42u8; 32];
    let macer = mac_impl(MacAlgo::HmacSha256);
    let mut mac_out = [0u8; 32];
    macer
        .mac(&hmac_key, &hash_out, &mut mac_out)
        .expect("HMAC-SHA-256 failed");
    assert_ne!(mac_out, [0u8; 32], "HMAC output must not be all-zero");

    // Step 3: HKDF-SHA-256 to derive a 32-byte AEAD key (cross-crate: facade → kdf crate)
    let kdf = kdf_impl(KdfAlgo::HkdfSha256);
    let mut aead_key = [0u8; 32];
    kdf.derive(
        &mac_out,
        b"integration-test-salt",
        b"aead-key",
        &mut aead_key,
    )
    .expect("HKDF-SHA-256 derive failed");
    assert_ne!(aead_key, [0u8; 32], "derived AEAD key must not be all-zero");

    // Step 4: AES-256-GCM encrypt/decrypt (cross-crate: facade → aead crate)
    let aead = aead_impl(AeadAlgo::Aes256Gcm);
    let nonce = [0xabu8; 12];
    let aad = b"associated data for pipeline test";
    let plaintext = b"secret message from pipeline test";

    let ct = aead
        .seal_to_vec(&aead_key, &nonce, aad, plaintext)
        .expect("AES-256-GCM seal failed");
    assert_eq!(
        ct.len(),
        plaintext.len() + aead.tag_len(),
        "ciphertext length must be plaintext + tag"
    );

    let pt = aead
        .open_to_vec(&aead_key, &nonce, aad, &ct)
        .expect("AES-256-GCM open failed");
    assert_eq!(pt, plaintext, "decrypted plaintext must match original");
}

/// Variant pipeline using BLAKE3 → HMAC-SHA-512 → HKDF-SHA-512 → ChaCha20-Poly1305.
#[test]
fn test_blake3_hmac512_hkdf512_chacha_pipeline() {
    let message = b"BLAKE3 pipeline test";

    // BLAKE3 hash
    let blake3_out = oxicrypto::blake3(message);
    assert_ne!(blake3_out, [0u8; 32], "BLAKE3 output must be non-zero");

    // HMAC-SHA-512 authentication
    let hmac_key = [0x55u8; 64];
    let macer = mac_impl(MacAlgo::HmacSha512);
    let mut mac_out = vec![0u8; macer.output_len()];
    macer
        .mac(&hmac_key, &blake3_out, &mut mac_out)
        .expect("HMAC-SHA-512 failed");

    // HKDF-SHA-512 key derivation
    let kdf = kdf_impl(KdfAlgo::HkdfSha512);
    let mut chacha_key = [0u8; 32];
    kdf.derive(&mac_out, b"chacha-salt", b"chacha-key", &mut chacha_key)
        .expect("HKDF-SHA-512 derive failed");

    // ChaCha20-Poly1305 round-trip
    let aead = aead_impl(AeadAlgo::ChaCha20Poly1305);
    let nonce = [0x99u8; 12];
    let plaintext = b"pipeline test with ChaCha20-Poly1305";

    let ct = aead
        .seal_to_vec(&chacha_key, &nonce, b"", plaintext)
        .expect("ChaCha20-Poly1305 seal failed");
    let pt = aead
        .open_to_vec(&chacha_key, &nonce, b"", &ct)
        .expect("ChaCha20-Poly1305 open failed");
    assert_eq!(
        pt.as_slice(),
        plaintext.as_ref(),
        "round-trip plaintext must match"
    );
}

// ── Test 2: keygen → sign → verify for each signature algorithm ───────────────

/// Helper: derive an X25519 public key from a secret.
fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let s = StaticSecret::from(*secret);
    *PublicKey::from(&s).as_bytes()
}

/// Ed25519: keygen via ed25519-dalek, sign/verify via facade trait objects.
#[test]
fn test_ed25519_sign_verify() {
    use ed25519_dalek::SigningKey;

    let seed = [0xddu8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pk_bytes = signing_key.verifying_key().to_bytes();

    let signer = signer_impl(SigAlgo::Ed25519);
    let verifier = verifier_impl(SigAlgo::Ed25519);

    let msg = b"Ed25519 cross-crate integration test";
    let mut sig = vec![0u8; signer.signature_len()];
    let written = signer
        .sign(&seed, msg, &mut sig)
        .expect("Ed25519 sign failed");

    verifier
        .verify(&pk_bytes, msg, &sig[..written])
        .expect("Ed25519 verify failed");

    // Tampered message must fail
    let tamper_result = verifier.verify(&pk_bytes, b"tampered message", &sig[..written]);
    assert!(
        tamper_result.is_err(),
        "verify must reject tampered message"
    );
}

/// Ed448: deterministic seed → sign → verify via facade.
#[test]
fn test_ed448_sign_verify() {
    use oxicrypto_sig::ed448::Ed448SigningKey;

    let seed = [0xeeu8; 57];
    let signing_key = Ed448SigningKey::from_bytes(&seed).expect("Ed448 key from seed");
    let pk_bytes = signing_key.verifying_key_bytes();

    let signer = signer_impl(SigAlgo::Ed448);
    let verifier = verifier_impl(SigAlgo::Ed448);

    let msg = b"Ed448 cross-crate integration test";
    let mut sig = vec![0u8; signer.signature_len()];
    let written = signer
        .sign(&seed, msg, &mut sig)
        .expect("Ed448 sign failed");
    assert_eq!(written, 114, "Ed448 signature must be 114 bytes");

    verifier
        .verify(&pk_bytes, msg, &sig[..written])
        .expect("Ed448 verify failed");
}

/// ECDSA P-256: deterministic scalar → sign → verify via facade.
#[test]
fn test_ecdsa_p256_sign_verify() {
    // Deterministic scalar for P-256 — non-zero, well under group order
    let scalar: [u8; 32] = {
        let mut s = [0u8; 32];
        s[0] = 0x01;
        s[31] = 0x01;
        s
    };
    let sk = p256::SecretKey::from_slice(&scalar).expect("P-256 scalar");
    let pk_sec1 = sk.public_key().to_sec1_bytes().to_vec();

    let signer = signer_impl(SigAlgo::EcdsaP256);
    let verifier = verifier_impl(SigAlgo::EcdsaP256);

    let msg = b"ECDSA-P256 cross-crate integration test";
    let mut sig = vec![0u8; signer.signature_len()];
    let written = signer
        .sign(&scalar, msg, &mut sig)
        .expect("ECDSA-P256 sign failed");
    assert!(
        written > 0 && written <= 72,
        "ECDSA-P256 DER signature must be 1..=72 bytes"
    );

    verifier
        .verify(&pk_sec1, msg, &sig[..written])
        .expect("ECDSA-P256 verify failed");
}

/// ECDSA P-384: deterministic scalar → sign → verify via facade.
#[test]
fn test_ecdsa_p384_sign_verify() {
    let scalar: [u8; 48] = {
        let mut s = [0u8; 48];
        s[0] = 0x01;
        s[47] = 0x01;
        s
    };
    let sk = p384::SecretKey::from_slice(&scalar).expect("P-384 scalar");
    let pk_sec1 = sk.public_key().to_sec1_bytes().to_vec();

    let signer = signer_impl(SigAlgo::EcdsaP384);
    let verifier = verifier_impl(SigAlgo::EcdsaP384);

    let msg = b"ECDSA-P384 cross-crate integration test";
    let mut sig = vec![0u8; signer.signature_len()];
    let written = signer
        .sign(&scalar, msg, &mut sig)
        .expect("ECDSA-P384 sign failed");
    assert!(written > 0, "ECDSA-P384 DER signature must be non-empty");

    verifier
        .verify(&pk_sec1, msg, &sig[..written])
        .expect("ECDSA-P384 verify failed");
}

/// ECDSA P-521: deterministic scalar → sign → verify via facade.
#[test]
fn test_ecdsa_p521_sign_verify() {
    let scalar: [u8; 66] = {
        let mut s = [0u8; 66];
        s[63] = 0xab;
        s[64] = 0xcd;
        s[65] = 0x01;
        s
    };
    let sk = p521::SecretKey::from_slice(&scalar).expect("P-521 scalar");
    let pk_sec1 = sk.public_key().to_sec1_bytes().to_vec();

    let signer = signer_impl(SigAlgo::EcdsaP521);
    let verifier = verifier_impl(SigAlgo::EcdsaP521);

    let msg = b"ECDSA-P521 cross-crate integration test";
    let mut sig = vec![0u8; signer.signature_len()];
    let written = signer
        .sign(&scalar, msg, &mut sig)
        .expect("ECDSA-P521 sign failed");
    assert!(written > 0, "ECDSA-P521 DER signature must be non-empty");

    verifier
        .verify(&pk_sec1, msg, &sig[..written])
        .expect("ECDSA-P521 verify failed");
}

/// RSA PKCS#1v15 SHA-256: pre-baked 2048-bit DER key → sign → verify via facade.
/// (No runtime keygen — avoids the 100ms+ key generation cost.)
#[test]
fn test_rsa_pkcs1v15_sha256_sign_verify() {
    let signer = signer_impl(SigAlgo::RsaPkcs1v15Sha256);
    let verifier = verifier_impl(SigAlgo::RsaPkcs1v15Sha256);

    let msg = b"RSA-PKCS1v15-SHA256 cross-crate integration test";
    let mut sig = vec![0u8; signer.signature_len()];
    let written = signer
        .sign(RSA_2048_PKCS8_DER, msg, &mut sig)
        .expect("RSA sign failed");
    assert!(written > 0, "RSA PKCS#1v15 signature must be non-empty");

    verifier
        .verify(RSA_2048_SPKI_DER, msg, &sig[..written])
        .expect("RSA PKCS#1v15 SHA-256 verify failed");
}

/// RSA PSS SHA-256: pre-baked 2048-bit DER key → sign → verify via facade.
#[test]
fn test_rsa_pss_sha256_sign_verify() {
    let signer = signer_impl(SigAlgo::RsaPssSha256);
    let verifier = verifier_impl(SigAlgo::RsaPssSha256);

    let msg = b"RSA-PSS-SHA256 cross-crate integration test";
    let mut sig = vec![0u8; signer.signature_len()];
    let written = signer
        .sign(RSA_2048_PKCS8_DER, msg, &mut sig)
        .expect("RSA-PSS sign failed");
    assert!(written > 0, "RSA-PSS signature must be non-empty");

    verifier
        .verify(RSA_2048_SPKI_DER, msg, &sig[..written])
        .expect("RSA-PSS SHA-256 verify failed");
}

// ── Test 3: X25519 → HKDF-SHA-256 → AES-256-GCM key agreement pipeline ──────

/// Alice and Bob perform X25519 DH. Both derive the same shared secret, feed
/// it into HKDF-SHA-256, and use the result to encrypt/decrypt with AES-256-GCM.
#[test]
fn test_x25519_hkdf_aes_gcm_pipeline() {
    let alice_sk = [0xaau8; 32];
    let bob_sk = [0xbbu8; 32];
    let alice_pk = x25519_public(&alice_sk);
    let bob_pk = x25519_public(&bob_sk);

    let kex = kex_impl(KexAlgo::X25519);

    // Alice computes shared secret using Bob's public key
    let mut alice_shared = [0u8; 32];
    kex.agree(&alice_sk, &bob_pk, &mut alice_shared)
        .expect("Alice X25519 agree failed");

    // Bob computes shared secret using Alice's public key
    let mut bob_shared = [0u8; 32];
    kex.agree(&bob_sk, &alice_pk, &mut bob_shared)
        .expect("Bob X25519 agree failed");

    assert_eq!(
        alice_shared, bob_shared,
        "X25519: both parties must derive the same shared secret"
    );
    assert_ne!(
        alice_shared, [0u8; 32],
        "Shared secret must not be all-zero"
    );

    // Both derive the same AEAD key from the shared secret
    let kdf = kdf_impl(KdfAlgo::HkdfSha256);
    let mut aead_key = [0u8; 32];
    kdf.derive(
        &alice_shared,
        b"x25519-hkdf-salt",
        b"aead-key-v1",
        &mut aead_key,
    )
    .expect("HKDF-SHA-256 key derivation failed");
    assert_ne!(aead_key, [0u8; 32], "Derived AEAD key must not be all-zero");

    // Encrypt with Alice's derived key, decrypt with Bob's (must be identical)
    let aead = aead_impl(AeadAlgo::Aes256Gcm);
    let nonce = [0x11u8; 12];
    let plaintext = b"secret established via X25519 key agreement";
    let aad = b"X25519-HKDF-AES-GCM channel";

    let ct = aead
        .seal_to_vec(&aead_key, &nonce, aad, plaintext)
        .expect("AES-256-GCM seal failed after X25519");

    // Derive Bob's key independently to confirm equality
    let mut bob_aead_key = [0u8; 32];
    kdf.derive(
        &bob_shared,
        b"x25519-hkdf-salt",
        b"aead-key-v1",
        &mut bob_aead_key,
    )
    .expect("Bob HKDF derive failed");
    assert_eq!(
        aead_key, bob_aead_key,
        "Alice and Bob must derive the same AEAD key"
    );

    let pt = aead
        .open_to_vec(&bob_aead_key, &nonce, aad, &ct)
        .expect("AES-256-GCM open failed after X25519");
    assert_eq!(
        pt.as_slice(),
        plaintext.as_ref(),
        "X25519→HKDF→AES-GCM: decrypted plaintext must match"
    );
}

/// ECDH P-256 → HKDF-SHA-256 → XChaCha20-Poly1305 pipeline with generated keys.
#[test]
fn test_ecdh_p256_hkdf_xchacha20_pipeline() {
    // Deterministic P-256 scalars for reproducible test
    let alice_scalar: [u8; 32] = {
        let mut s = [0u8; 32];
        s[0] = 0x01;
        s[31] = 0x02;
        s
    };
    let bob_scalar: [u8; 32] = {
        let mut s = [0u8; 32];
        s[0] = 0x03;
        s[31] = 0x04;
        s
    };
    let alice_sk_p256 = p256::SecretKey::from_slice(&alice_scalar).expect("Alice P-256 key");
    let bob_sk_p256 = p256::SecretKey::from_slice(&bob_scalar).expect("Bob P-256 key");
    let alice_pk_sec1 = alice_sk_p256.public_key().to_sec1_bytes().to_vec();
    let bob_pk_sec1 = bob_sk_p256.public_key().to_sec1_bytes().to_vec();

    let kex = kex_impl(KexAlgo::EcdhP256);
    let mut alice_shared = [0u8; 32];
    let mut bob_shared = [0u8; 32];
    kex.agree(&alice_scalar, &bob_pk_sec1, &mut alice_shared)
        .expect("Alice ECDH-P256 agree failed");
    kex.agree(&bob_scalar, &alice_pk_sec1, &mut bob_shared)
        .expect("Bob ECDH-P256 agree failed");
    assert_eq!(
        alice_shared, bob_shared,
        "ECDH-P256: shared secrets must match"
    );

    // HKDF-SHA-256 to derive XChaCha20 key (32 bytes)
    let kdf = kdf_impl(KdfAlgo::HkdfSha256);
    let mut xchacha_key = [0u8; 32];
    kdf.derive(
        &alice_shared,
        b"p256-hkdf-salt",
        b"xchacha20-key",
        &mut xchacha_key,
    )
    .expect("HKDF derive for XChaCha20 failed");

    // XChaCha20-Poly1305 uses 24-byte nonces
    let aead = aead_impl(AeadAlgo::XChaCha20Poly1305);
    assert_eq!(
        aead.nonce_len(),
        24,
        "XChaCha20-Poly1305 must use 24-byte nonces"
    );

    let nonce = [0xffu8; 24];
    let plaintext = b"secret via P-256 ECDH + XChaCha20";

    let ct = aead
        .seal_to_vec(&xchacha_key, &nonce, b"", plaintext)
        .expect("XChaCha20-Poly1305 seal failed");
    let pt = aead
        .open_to_vec(&xchacha_key, &nonce, b"", &ct)
        .expect("XChaCha20-Poly1305 open failed");
    assert_eq!(
        pt.as_slice(),
        plaintext.as_ref(),
        "ECDH-P256→HKDF→XChaCha20: plaintext must survive round-trip"
    );
}

// ── Test 4: ML-KEM-768 → HKDF-SHA-256 → ChaCha20-Poly1305 (pq-preview) ─────

#[cfg(feature = "pq-preview")]
#[test]
fn test_mlkem768_hkdf_chacha20_pipeline() {
    use oxicrypto::pq::MlKem768;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    // Generate ML-KEM-768 key pair with a deterministic seed
    let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
    let (dk, ek) = MlKem768::generate(&mut rng);

    // Encapsulate: produces (ciphertext, shared_key_enc)
    let mut rng2 = ChaCha20Rng::from_seed([0x43u8; 32]);
    let (ct, ss_enc) = ek
        .encapsulate(&mut rng2)
        .expect("ML-KEM-768 encapsulate failed");
    assert_eq!(
        ss_enc.as_slice().len(),
        32,
        "ML-KEM-768 shared key must be 32 bytes"
    );

    // Decapsulate: recovers the same shared key
    let ss_dec = dk.decapsulate(&ct).expect("ML-KEM-768 decapsulate failed");
    assert_eq!(
        ss_enc.as_slice(),
        ss_dec.as_slice(),
        "ML-KEM-768: encapsulate and decapsulate must yield identical shared keys"
    );

    // Feed shared key into HKDF-SHA-256 to derive a ChaCha20-Poly1305 key
    let kdf = kdf_impl(KdfAlgo::HkdfSha256);
    let mut chacha_key = [0u8; 32];
    kdf.derive(
        ss_enc.as_slice(),
        b"mlkem768-hkdf-salt",
        b"chacha20-key",
        &mut chacha_key,
    )
    .expect("HKDF-SHA-256 derive from ML-KEM shared key failed");
    assert_ne!(chacha_key, [0u8; 32], "Derived key must not be all-zero");

    // ChaCha20-Poly1305 encrypt/decrypt with the derived key
    let aead = aead_impl(AeadAlgo::ChaCha20Poly1305);
    let nonce = [0x77u8; 12];
    let plaintext = b"post-quantum secure message via ML-KEM-768";
    let aad = b"ML-KEM-768 + HKDF + ChaCha20-Poly1305";

    let encrypted = aead
        .seal_to_vec(&chacha_key, &nonce, aad, plaintext)
        .expect("ChaCha20-Poly1305 seal failed after ML-KEM");

    let decrypted = aead
        .open_to_vec(&chacha_key, &nonce, aad, &encrypted)
        .expect("ChaCha20-Poly1305 open failed after ML-KEM");
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_ref(),
        "ML-KEM-768→HKDF→ChaCha20: plaintext must survive full pipeline"
    );
}

/// ML-DSA-65: keygen → sign → verify via pq module and facade.
#[cfg(feature = "pq-preview")]
#[test]
fn test_mldsa65_sign_verify() {
    use oxicrypto::pq::{MlDsa65, SigningKey65};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    let mut rng = ChaCha20Rng::from_seed([0x11u8; 32]);
    let (sk, vk) = MlDsa65::generate(&mut rng);

    let msg = b"ML-DSA-65 cross-crate integration test";
    let sig = sk.sign(msg).expect("ML-DSA-65 sign failed");
    vk.verify(msg, &sig).expect("ML-DSA-65 verify failed");

    // Verify the signing key serialization round-trip works
    let sk_bytes = sk.to_bytes();
    let sk2 = SigningKey65::from_bytes(&sk_bytes).expect("ML-DSA-65 signing key from bytes");
    let sig2 = sk2.sign(msg).expect("ML-DSA-65 re-sign failed");
    vk.verify(msg, &sig2).expect("ML-DSA-65 re-verify failed");
}

// ── Test 5: Enum Display string uniqueness ────────────────────────────────────

/// All HashAlgo Display strings must be unique (no two variants map to the same string).
#[test]
fn test_hash_algo_display_strings_unique() {
    use std::collections::HashSet;

    let variants = [
        HashAlgo::Sha256,
        HashAlgo::Sha384,
        HashAlgo::Sha512,
        HashAlgo::Sha3_256,
        HashAlgo::Sha3_384,
        HashAlgo::Sha3_512,
        HashAlgo::Blake3,
    ];
    let strings: HashSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(
        strings.len(),
        variants.len(),
        "HashAlgo Display strings must all be unique; duplicates detected"
    );
}

/// All AeadAlgo Display strings must be unique.
#[test]
fn test_aead_algo_display_strings_unique() {
    use std::collections::HashSet;

    let variants = [
        AeadAlgo::Aes128Gcm,
        AeadAlgo::Aes256Gcm,
        AeadAlgo::ChaCha20Poly1305,
        AeadAlgo::Aes128GcmSiv,
        AeadAlgo::Aes256GcmSiv,
        AeadAlgo::XChaCha20Poly1305,
        AeadAlgo::Aes128Ccm,
        AeadAlgo::Aes256Ccm,
        AeadAlgo::Aes128Ocb3,
        AeadAlgo::Aes256Ocb3,
    ];
    let strings: HashSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(
        strings.len(),
        variants.len(),
        "AeadAlgo Display strings must all be unique; duplicates detected"
    );
}

/// All MacAlgo Display strings must be unique (KMAC variants carry output_len in the string).
#[test]
fn test_mac_algo_display_strings_unique() {
    use std::collections::HashSet;

    let variants: Vec<String> = [
        MacAlgo::HmacSha256,
        MacAlgo::HmacSha384,
        MacAlgo::HmacSha512,
        MacAlgo::HmacSha3_256,
        MacAlgo::HmacSha3_512,
        MacAlgo::Poly1305,
        MacAlgo::CmacAes128,
        MacAlgo::CmacAes256,
        MacAlgo::Kmac128 { output_len: 32 },
        MacAlgo::Kmac256 { output_len: 32 },
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();

    let unique: HashSet<&String> = variants.iter().collect();
    assert_eq!(
        unique.len(),
        variants.len(),
        "MacAlgo Display strings must all be unique; duplicates: {:?}",
        variants
    );
}

/// All SigAlgo Display strings must be unique.
#[test]
fn test_sig_algo_display_strings_unique() {
    use std::collections::HashSet;

    let variants = [
        SigAlgo::Ed25519,
        SigAlgo::Ed448,
        SigAlgo::EcdsaP256,
        SigAlgo::EcdsaP384,
        SigAlgo::EcdsaP521,
        SigAlgo::RsaPkcs1v15Sha256,
        SigAlgo::RsaPkcs1v15Sha384,
        SigAlgo::RsaPkcs1v15Sha512,
        SigAlgo::RsaPssSha256,
    ];
    let strings: HashSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(
        strings.len(),
        variants.len(),
        "SigAlgo Display strings must all be unique"
    );
}

/// All KexAlgo Display strings must be unique.
#[test]
fn test_kex_algo_display_strings_unique() {
    use std::collections::HashSet;

    let variants = [
        KexAlgo::X25519,
        KexAlgo::EcdhP256,
        KexAlgo::EcdhP384,
        KexAlgo::EcdhP521,
    ];
    let strings: HashSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(
        strings.len(),
        variants.len(),
        "KexAlgo Display strings must all be unique"
    );
}

/// All KdfAlgo Display strings must be unique.
#[test]
fn test_kdf_algo_display_strings_unique() {
    use std::collections::HashSet;

    let variants = [
        KdfAlgo::HkdfSha256,
        KdfAlgo::HkdfSha384,
        KdfAlgo::HkdfSha512,
        KdfAlgo::Pbkdf2Sha256,
        KdfAlgo::Pbkdf2Sha512,
        KdfAlgo::Argon2id,
        KdfAlgo::Scrypt,
    ];
    let strings: HashSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(
        strings.len(),
        variants.len(),
        "KdfAlgo Display strings must all be unique"
    );
}

// ── Test 6: available_algorithms() coverage ───────────────────────────────────

/// available_algorithms() must always contain SHA-256 under any feature set.
#[test]
fn test_available_algorithms_contains_sha256() {
    let algos = available_algorithms();
    assert!(
        algos.contains(&AlgorithmId::Sha256),
        "available_algorithms() must include AlgorithmId::Sha256"
    );
}

/// available_algorithms() must cover all major algorithm families.
#[test]
fn test_available_algorithms_all_families_present() {
    use oxicrypto::AlgorithmCategory;

    let algos = available_algorithms();
    let has_hash = algos
        .iter()
        .any(|id| id.category() == AlgorithmCategory::Hash);
    let has_aead = algos
        .iter()
        .any(|id| id.category() == AlgorithmCategory::Aead);
    let has_mac = algos
        .iter()
        .any(|id| id.category() == AlgorithmCategory::Mac);
    let has_sig = algos
        .iter()
        .any(|id| id.category() == AlgorithmCategory::Signature);
    let has_kex = algos
        .iter()
        .any(|id| id.category() == AlgorithmCategory::KeyExchange);
    let has_kdf = algos
        .iter()
        .any(|id| id.category() == AlgorithmCategory::Kdf);

    assert!(has_hash, "must include at least one hash algorithm");
    assert!(has_aead, "must include at least one AEAD algorithm");
    assert!(has_mac, "must include at least one MAC algorithm");
    assert!(has_sig, "must include at least one signature algorithm");
    assert!(has_kex, "must include at least one KEX algorithm");
    assert!(has_kdf, "must include at least one KDF algorithm");
}

/// available_algorithms() contains specific expected entries under default features.
#[test]
fn test_available_algorithms_specific_entries() {
    let algos = available_algorithms();

    // Hash family
    assert!(algos.contains(&AlgorithmId::Sha256), "missing SHA-256");
    assert!(algos.contains(&AlgorithmId::Sha512), "missing SHA-512");
    assert!(algos.contains(&AlgorithmId::Blake3), "missing BLAKE3");

    // AEAD family
    assert!(
        algos.contains(&AlgorithmId::Aes256Gcm),
        "missing AES-256-GCM"
    );
    assert!(
        algos.contains(&AlgorithmId::ChaCha20Poly1305),
        "missing ChaCha20-Poly1305"
    );

    // MAC family
    assert!(
        algos.contains(&AlgorithmId::HmacSha256),
        "missing HMAC-SHA-256"
    );

    // Signature family
    assert!(algos.contains(&AlgorithmId::Ed25519), "missing Ed25519");
    assert!(
        algos.contains(&AlgorithmId::EcdsaP256),
        "missing ECDSA-P256"
    );

    // KEX family
    assert!(algos.contains(&AlgorithmId::X25519), "missing X25519");

    // KDF family
    assert!(
        algos.contains(&AlgorithmId::HkdfSha256),
        "missing HKDF-SHA-256"
    );
}

/// With pq-preview enabled, available_algorithms() must include ML-KEM-768.
#[cfg(feature = "pq-preview")]
#[test]
fn test_available_algorithms_contains_mlkem768_with_pq_feature() {
    let algos = available_algorithms();
    assert!(
        algos.contains(&AlgorithmId::MlKem768),
        "available_algorithms() must include AlgorithmId::MlKem768 with pq-preview feature"
    );
    assert!(
        algos.contains(&AlgorithmId::MlDsa65),
        "available_algorithms() must include AlgorithmId::MlDsa65 with pq-preview feature"
    );
}

// ── Test 7: Factory function name consistency ─────────────────────────────────

/// Signer and verifier factory functions must return implementations with matching names.
#[test]
fn test_signer_verifier_name_consistency() {
    let algo_pairs = [
        SigAlgo::Ed25519,
        SigAlgo::Ed448,
        SigAlgo::EcdsaP256,
        SigAlgo::EcdsaP384,
        SigAlgo::EcdsaP521,
        SigAlgo::RsaPkcs1v15Sha256,
        SigAlgo::RsaPkcs1v15Sha384,
        SigAlgo::RsaPkcs1v15Sha512,
        SigAlgo::RsaPssSha256,
    ];
    for algo in algo_pairs {
        let s = signer_impl(algo);
        let v = verifier_impl(algo);
        assert_eq!(
            s.name(),
            v.name(),
            "{algo:?}: signer and verifier must report the same algorithm name"
        );
        assert!(
            s.signature_len() > 0,
            "{algo:?}: signature_len must be positive"
        );
    }
}

/// hash_impl must produce non-empty output for every variant, with length matching output_len().
#[test]
fn test_hash_factory_output_lengths() {
    let cases = [
        (HashAlgo::Sha256, 32usize),
        (HashAlgo::Sha384, 48),
        (HashAlgo::Sha512, 64),
        (HashAlgo::Sha3_256, 32),
        (HashAlgo::Sha3_384, 48),
        (HashAlgo::Sha3_512, 64),
        (HashAlgo::Blake3, 32),
    ];
    for (algo, expected_len) in cases {
        let h = hash_impl(algo);
        assert_eq!(
            h.output_len(),
            expected_len,
            "{algo}: output_len() mismatch"
        );
        let mut buf = vec![0u8; expected_len];
        h.hash(b"test input", &mut buf)
            .expect("hash must not fail with correct buffer size");
        assert_ne!(
            buf,
            vec![0u8; expected_len],
            "{algo}: hash output must not be all-zero"
        );
    }
}

/// kdf_impl for HKDF variants must produce non-zero output.
#[test]
fn test_kdf_factory_derive_non_zero() {
    let algos = [
        KdfAlgo::HkdfSha256,
        KdfAlgo::HkdfSha384,
        KdfAlgo::HkdfSha512,
    ];
    for algo in algos {
        let kdf = kdf_impl(algo);
        let mut okm = [0u8; 32];
        kdf.derive(
            b"input-key-material",
            b"salt-value",
            b"context-info",
            &mut okm,
        )
        .expect("HKDF derive failed");
        assert_ne!(okm, [0u8; 32], "{algo}: HKDF output must not be all-zero");
    }
}

// ── Test 8: AES-GCM-SIV misuse-resistance cross-crate ────────────────────────

/// AES-256-GCM-SIV: nonce reuse does not produce the same ciphertext for different plaintexts
/// (differs from AES-GCM; SIV provides deterministic encryption that hides plaintext on reuse).
#[test]
fn test_aes_gcm_siv_nonce_reuse_hides_plaintext() {
    let key = [0x42u8; 32];
    let nonce = [0x00u8; 12]; // deliberately reused nonce
    let aad = b"";

    let aead = aead_impl(AeadAlgo::Aes256GcmSiv);

    let pt1 = b"first plaintext message";
    let pt2 = b"second plaintext msg!!";

    let ct1 = aead
        .seal_to_vec(&key, &nonce, aad, pt1)
        .expect("AES-256-GCM-SIV seal ct1 failed");
    let ct2 = aead
        .seal_to_vec(&key, &nonce, aad, pt2)
        .expect("AES-256-GCM-SIV seal ct2 failed");

    // Ciphertexts must differ (different plaintexts produce different ciphertexts)
    assert_ne!(
        ct1, ct2,
        "AES-GCM-SIV: different plaintexts must produce different ciphertexts"
    );

    // Both must decrypt correctly
    let dec1 = aead
        .open_to_vec(&key, &nonce, aad, &ct1)
        .expect("AES-256-GCM-SIV open ct1 failed");
    let dec2 = aead
        .open_to_vec(&key, &nonce, aad, &ct2)
        .expect("AES-256-GCM-SIV open ct2 failed");

    assert_eq!(
        dec1.as_slice(),
        pt1.as_ref(),
        "AES-GCM-SIV: pt1 round-trip failed"
    );
    assert_eq!(
        dec2.as_slice(),
        pt2.as_ref(),
        "AES-GCM-SIV: pt2 round-trip failed"
    );
}
