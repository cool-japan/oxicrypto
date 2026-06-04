# oxicrypto-adapter-aws-lc TODO

## Status
Feature-gated (`aws-lc` feature, default off) BOUNDED_FFI adapter bridging `aws-lc-rs` to `oxicrypto-core` traits. AEAD (AES-128-GCM, AES-256-GCM, AES-256-GCM-SIV, ChaCha20-Poly1305), Hash (SHA-1, SHA-256/384/512), Signature (Ed25519, ECDSA-P256-SHA256, ECDSA-P384-SHA384, RSA-PKCS1-SHA256, RSA-PSS-SHA256), HKDF (SHA-256/384/512), and HMAC (SHA-256/384/512) modules are implemented. All types have Display impls. Integration tests cover NIST KAT vectors, RFC 8032 vector, cross-parity, error paths, and property-based seal/open. `AwsLcCryptoProvider` aggregate struct is in lib.rs.

## Core Implementation
- [x] Add AES-256-GCM-SIV AEAD variant via `aws_lc_rs::aead::AES_256_GCM_SIV` (~60 SLOC: Algo variant, constructor, Aead trait impl adjustments) (planned 2026-06-03)
  - **Goal:** Add AES-256-GCM-SIV via aws_lc_rs::aead::AES_256_GCM_SIV. **Files:** src/aead.rs. **Risk:** Low.
- [x] Implement `Hash` trait for SHA-1 (legacy compatibility) via `aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY` (~25 SLOC) (planned 2026-06-03)
  - **Goal:** Implement Hash for SHA-1 via SHA1_FOR_LEGACY_USE_ONLY. **Files:** src/hash.rs. **Risk:** Low.
- [x] Add ECDSA-P384-SHA384 signer/verifier pair using `ECDSA_P384_SHA384_FIXED` / `ECDSA_P384_SHA384_FIXED_SIGNING` (~80 SLOC: structs, Signer/Verifier impls, DER builder for P-384) (planned 2026-06-03)
  - **Goal:** ECDSA-P384-SHA384 signer/verifier via ECDSA_P384_SHA384_FIXED_SIGNING. **Files:** src/sign.rs. **Risk:** Low.
- [x] Add RSA-PKCS1-SHA256 and RSA-PSS-SHA256 signer/verifier implementations via `aws_lc_rs::signature::RsaKeyPair` (~150 SLOC: two struct pairs, PKCS#8 parsing, variable-length signature handling) (planned 2026-06-03)
  - **Goal:** RSA PKCS1-SHA256 and PSS-SHA256 via RsaKeyPair. **Files:** src/sign.rs. **Risk:** Moderate — PKCS8 DER key loading.
- [x] Implement HKDF key derivation adapter via `aws_lc_rs::hkdf` mapping to `oxicrypto_core::Kdf` trait if/when the trait is added to core (~80 SLOC) (planned 2026-06-03)
  - **Goal:** HKDF adapter via aws_lc_rs::hkdf mapping to Kdf trait. **Files:** src/hkdf.rs (new). **Risk:** Low.
- [x] Implement HMAC-SHA256/SHA384/SHA512 via `aws_lc_rs::hmac` mapping to `oxicrypto_core::Mac` trait (~90 SLOC: three structs, Mac trait impls) (planned 2026-06-03)
  - **Goal:** HMAC-SHA256/384/512 via aws_lc_rs::hmac mapping to Mac trait. **Files:** src/mac.rs (new). **Risk:** Low.

## API Improvements
- [x] Replace manual DER construction in `build_p256_sec1_der()` with a small const-table approach to avoid allocation (~40 SLOC refactor) (planned 2026-06-03)
  - **Goal:** Replace manual DER construction with const-table lookup. **Files:** src/sign.rs. **Risk:** Low.
- [x] Add `AwsLcAead::from_name(name: &str) -> Option<Self>` string-based constructor for runtime algorithm selection (~15 SLOC) (planned 2026-06-03)
  - **Goal:** Add AwsLcAead::from_name(name: &str) -> Option<Self>. **Files:** src/aead.rs. **Risk:** Low.
- [x] Add `CryptoProvider` aggregate struct that bundles AEAD + Hash + Signer + Verifier into a single aws-lc-rs provider object for convenient dependency injection (~50 SLOC) (planned 2026-06-03)
  - **Goal:** CryptoProvider aggregate struct bundling AEAD+Hash+Signer+Verifier. **Files:** src/lib.rs. **Risk:** Low.
- [x] Implement `Display` for `AwsLcAead` / signer / verifier structs, delegating to `name()` (~20 SLOC) (planned 2026-06-03)
  - **Goal:** Display for all aws-lc types delegating to name(). **Files:** src/aead.rs, hash.rs, sign.rs. **Risk:** Low.

## Testing
- [x] Add NIST Known-Answer-Test vectors for AES-128-GCM and AES-256-GCM (test against published NIST CAVP GCM test vectors, ~80 SLOC) (planned 2026-06-03)
  - **Goal:** Add NIST CAVP GCM KAT vectors for AES-128-GCM and AES-256-GCM. **Files:** tests/. **Risk:** Low.
- [x] Add RFC 8032 test vectors for Ed25519 (known seed/message/signature triples) (~40 SLOC) (planned 2026-06-03)
  - **Goal:** Add RFC 8032 KAT vectors for Ed25519. **Files:** tests/. **Risk:** Low.
- [x] Add cross-backend parity test: sign with aws-lc-rs Ed25519, verify with RustCrypto ed25519-dalek, and vice versa (~50 SLOC in integration tests) (planned 2026-06-03)
  - **Goal:** Cross-backend parity: aws-lc-rs Ed25519 sign vs dalek verify and vice versa. **Files:** tests/. **Risk:** Low.
- [x] Add ECDSA-P256 round-trip test using the `AwsLcEcdsaP256Signer` (currently only the verifier is exercised in tests) (~30 SLOC) (planned 2026-06-03)
  - **Goal:** ECDSA-P256 full sign+verify round-trip test. **Files:** tests/. **Risk:** Low.
- [x] Add property-based fuzz test: seal/open with random plaintext lengths 0..64KB, random keys (~40 SLOC via proptest) (planned 2026-06-03)
  - **Goal:** Proptest fuzz for AEAD seal/open with random lengths and keys. **Files:** tests/. **Risk:** Low.
- [x] Add error-path tests: wrong key length, zero-length nonce, empty ciphertext (~35 SLOC) (planned 2026-06-03)
  - **Goal:** Error-path tests for wrong key length, zero nonce, empty ciphertext. **Files:** tests/. **Risk:** Low.

## Performance
- [~] Add criterion benchmarks: AEAD seal/open throughput for 1KB/64KB/1MB payloads across all three algorithms (~80 SLOC) (planned 2026-06-03)
  - **Goal:** Criterion AEAD throughput benchmarks for 1KB/64KB/1MB payloads. **Files:** benches/. **Risk:** Low.
- [~] Add criterion benchmarks: Ed25519 sign+verify and ECDSA-P256 sign+verify latency (~50 SLOC) (planned 2026-06-03)
  - **Goal:** Criterion sign+verify latency benchmarks for Ed25519 and ECDSA-P256. **Files:** benches/. **Risk:** Low.
- [~] Add criterion benchmarks: SHA-256/384/512 hashing throughput for 1KB/1MB inputs compared to Pure Rust oxicrypto-hash (~60 SLOC) (planned 2026-06-03)
  - **Goal:** Criterion hash throughput benchmarks vs Pure Rust oxicrypto-hash. **Files:** benches/. **Risk:** Low.

## Integration
- [x] Wire into `oxicrypto` facade crate behind a `fips` or `aws-lc` feature so users can `use oxicrypto::fips::Aead` (~30 SLOC in oxicrypto facade) (planned 2026-06-03)
  - **Goal:** Wire into oxicrypto facade behind fips/aws-lc feature. **Files:** oxicrypto/Cargo.toml, src/lib.rs. **Risk:** Low.
- [x] Add integration with `oxistore-encrypt` to allow aws-lc-rs backed cell-level encryption as an alternative to XChaCha20-Poly1305 (~40 SLOC adapter) (done 2026-06-03)
  - **Impl:** `tests/oxistore_encrypt_compat.rs` — `AwsLcOxistoreAead` newtype bridges `AwsLcAead` (oxicrypto_core::Aead) to `oxistore_encrypt::aead::Aead`. Tests: cell round-trip, ciphertext-differs-from-plaintext, multi-key distinct ciphertexts, authentication failure on corruption, absent key returns None.
- [x] Add integration test with `oxitls-adapter-aws-lc` to verify the same aws-lc-rs build links cleanly when both crates are enabled (~20 SLOC link-test) (done 2026-06-03)
  - **Impl:** `tests/oxitls_coexist.rs` — verifies symbol-level coexistence: `aws_lc_provider()` (oxitls) + `AwsLcAead::aes256_gcm()` seal/open (oxicrypto) in the same binary with no linker conflicts.
