# oxicrypto-adapter-aws-lc TODO

## Status
Feature-gated (`aws-lc` feature, default off) BOUNDED_FFI adapter bridging `aws-lc-rs` to `oxicrypto-core` traits. AEAD (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305), Hash (SHA-256/384/512), and Signature (Ed25519, ECDSA-P256-SHA256) modules are implemented with unit tests and a parity integration test against the Pure Rust backends.

## Core Implementation
- [ ] Add AES-256-GCM-SIV AEAD variant via `aws_lc_rs::aead::AES_256_GCM_SIV` (~60 SLOC: Algo variant, constructor, Aead trait impl adjustments)
- [ ] Implement `Hash` trait for SHA-1 (legacy compatibility) via `aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY` (~25 SLOC)
- [ ] Add ECDSA-P384-SHA384 signer/verifier pair using `ECDSA_P384_SHA384_FIXED` / `ECDSA_P384_SHA384_FIXED_SIGNING` (~80 SLOC: structs, Signer/Verifier impls, DER builder for P-384)
- [ ] Add RSA-PKCS1-SHA256 and RSA-PSS-SHA256 signer/verifier implementations via `aws_lc_rs::signature::RsaKeyPair` (~150 SLOC: two struct pairs, PKCS#8 parsing, variable-length signature handling)
- [ ] Implement HKDF key derivation adapter via `aws_lc_rs::hkdf` mapping to `oxicrypto_core::Kdf` trait if/when the trait is added to core (~80 SLOC)
- [ ] Implement HMAC-SHA256/SHA384/SHA512 via `aws_lc_rs::hmac` mapping to `oxicrypto_core::Mac` trait (~90 SLOC: three structs, Mac trait impls)

## API Improvements
- [ ] Replace manual DER construction in `build_p256_sec1_der()` with a small const-table approach to avoid allocation (~40 SLOC refactor)
- [ ] Add `AwsLcAead::from_name(name: &str) -> Option<Self>` string-based constructor for runtime algorithm selection (~15 SLOC)
- [ ] Add `CryptoProvider` aggregate struct that bundles AEAD + Hash + Signer + Verifier into a single aws-lc-rs provider object for convenient dependency injection (~50 SLOC)
- [ ] Implement `Display` for `AwsLcAead` / signer / verifier structs, delegating to `name()` (~20 SLOC)

## Testing
- [ ] Add NIST Known-Answer-Test vectors for AES-128-GCM and AES-256-GCM (test against published NIST CAVP GCM test vectors, ~80 SLOC)
- [ ] Add RFC 8032 test vectors for Ed25519 (known seed/message/signature triples) (~40 SLOC)
- [ ] Add cross-backend parity test: sign with aws-lc-rs Ed25519, verify with RustCrypto ed25519-dalek, and vice versa (~50 SLOC in integration tests)
- [ ] Add ECDSA-P256 round-trip test using the `AwsLcEcdsaP256Signer` (currently only the verifier is exercised in tests) (~30 SLOC)
- [ ] Add property-based fuzz test: seal/open with random plaintext lengths 0..64KB, random keys (~40 SLOC via proptest)
- [ ] Add error-path tests: wrong key length, zero-length nonce, empty ciphertext (~35 SLOC)

## Performance
- [ ] Add criterion benchmarks: AEAD seal/open throughput for 1KB/64KB/1MB payloads across all three algorithms (~80 SLOC)
- [ ] Add criterion benchmarks: Ed25519 sign+verify and ECDSA-P256 sign+verify latency (~50 SLOC)
- [ ] Add criterion benchmarks: SHA-256/384/512 hashing throughput for 1KB/1MB inputs compared to Pure Rust oxicrypto-hash (~60 SLOC)

## Integration
- [ ] Wire into `oxicrypto` facade crate behind a `fips` or `aws-lc` feature so users can `use oxicrypto::fips::Aead` (~30 SLOC in oxicrypto facade)
- [ ] Add integration with `oxistore-encrypt` to allow aws-lc-rs backed cell-level encryption as an alternative to XChaCha20-Poly1305 (~40 SLOC adapter)
- [ ] Add integration test with `oxitls-adapter-aws-lc` to verify the same aws-lc-rs build links cleanly when both crates are enabled (~20 SLOC link-test)
