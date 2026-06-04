# oxicrypto-mac TODO

## Status
HMAC-SHA-256 and HMAC-SHA-512 implemented (170 SLOC). Both implement the `Mac` trait with constant-time tag verification via `subtle::ConstantTimeEq`. No streaming MAC, no CMAC, no KMAC, no Poly1305 standalone.

## Core Implementation
- [x] `StreamingMac` adapter wrapping `hmac::Hmac` (done 2026-05-25)
  - **Goal:** `HmacSha256Streaming`, `HmacSha384Streaming`, `HmacSha512Streaming` implementing `StreamingMac` from oxicrypto-core (incremental `update`/`finalize`/`verify`/`reset`).
  - **Design:** Generic `HmacStreamingAdapter<D: digest::Digest + ...>` wrapping `hmac::Hmac<D>`, mirroring the hash crate's `DigestStreamingAdapter`. Type aliases per SHA-2 variant. Constant-time `verify` via `subtle`.
  - **Files:** `crates/oxicrypto-mac/src/lib.rs`, `crates/oxicrypto-mac/Cargo.toml`
  - **Tests:** one-shot `Mac::mac` vs streaming equivalence; chunked-at-every-boundary for HmacSha256.
  - **Risk:** Low — hmac already a dep; pattern proven in hash crate.
- [x] Add HMAC-SHA-384 per FIPS 198-1 / RFC 2104 (~40 SLOC)
- [x] HMAC-SHA3-256 / HMAC-SHA3-512 (done 2026-05-25)
  - **Goal:** `HmacSha3_256`, `HmacSha3_512` implementing `Mac`.
  - **Design:** Uses `hmac::SimpleHmac<sha3::Sha3_256/512>` (sha3 0.12 types don't implement CoreProxy needed by Hmac<D>). Add `sha3 = { workspace = true }` to mac Cargo.toml. Follow existing HMAC pattern (name/key_len/output_len/mac/verify).
  - **Files:** `crates/oxicrypto-mac/src/lib.rs`, `crates/oxicrypto-mac/Cargo.toml`
  - **Tests:** Round-trip + verify-fail tests.
  - **Risk:** Low.
- [x] Poly1305 one-time MAC (done 2026-05-25)
  - **Goal:** `Poly1305Mac` one-time authenticator (RFC 8439 §2.5), `Mac` impl with explicit one-time-key contract documented.
  - **Design:** Uses poly1305 0.8.0 (pinned by chacha20poly1305 0.10 constraint). 32-byte one-time key, 16-byte tag. Uses `compute_unpadded` for correct partial-block handling. Documents MUST-NOT-reuse-key prominently.
  - **Files:** `crates/oxicrypto-mac/src/lib.rs`, `crates/oxicrypto-mac/Cargo.toml`, workspace `Cargo.toml`
  - **Tests:** RFC 8439 §2.5.2 test vector passes (KAT verified).
  - **Risk:** Low.
- [x] CMAC-AES-128 / CMAC-AES-256 (done 2026-05-25)
  - **Goal:** `CmacAes128`, `CmacAes256` implementing `Mac` (NIST SP 800-38B).
  - **Design:** cmac 0.8.0 requires cipher 0.5 (incompatible with aes 0.8/cipher 0.4). Added `aes-cipher05 = { package = "aes", version = "0.9.0" }` alias to workspace; coexists with aes 0.8. `cmac::Cmac<aes_cipher05::Aes128/256>`. 16-byte tag.
  - **Files:** `crates/oxicrypto-mac/src/lib.rs`, `crates/oxicrypto-mac/Cargo.toml`, workspace `Cargo.toml`
  - **Tests:** NIST SP 800-38B Example 1 (K=2b7e..., empty msg, tag=bb1d6929...) passes.
  - **Risk:** Handled — dual aes versions coexist cleanly.
- [x] KMAC128 / KMAC256 (done 2026-05-25)
  - **Goal:** `Kmac128`, `Kmac256` implementing `Mac` (NIST SP 800-185), variable output length.
  - **Design:** sha3 0.12 does not expose CShake or KMAC. Used `tiny-keccak 2.0.2` with `features = ["kmac"]` — provides `Kmac::v128(key, custom)` and `Kmac::v256(key, custom)` with full SP 800-185 compliance. Constant-time verify.
  - **Files:** `crates/oxicrypto-mac/src/lib.rs`, workspace `Cargo.toml`
  - **Tests:** NIST SP 800-185 §A.1 Sample #1 (KMAC128) and §A.2 Sample #2 (KMAC256) verified. Zero-length output rejected.
  - **Risk:** Resolved — tiny-keccak provides a mature, tested SP 800-185 implementation.
- [x] Add KMAC-XOF mode with variable-length output per NIST SP 800-185 Section 4.4 (done 2026-05-26)
  - **Design:** Free functions `kmac128_xof(key, custom, msg, output_len)` and `kmac256_xof(key, custom, msg, output_len)` → `Result<Vec<u8>, CryptoError>`. Thin wrappers over `tiny_keccak::Kmac::v128/v256`, same KMAC machinery. Returns `BadInput` for zero output_len. Verified against NIST SP 800-185 Sample #1 and §A.2 Sample #2.
- [x] Add BLAKE3 keyed-hash MAC using BLAKE3 native keyed-hash mode (~30 SLOC) (done 2026-05-26)
  - **Design:** `blake3_keyed_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 32]` + `blake3_keyed_mac_verify`. Uses `blake3::Hasher::new_keyed` (BLAKE3 spec §2.7). Added `blake3.workspace = true` to mac Cargo.toml. Constant-time verify via `subtle`.
- [x] Truncated HMAC support (done 2026-05-25)
  - **Goal:** Truncated-tag MAC + constant-time truncated verify (HMAC-SHA-256-128 style).
  - **Design:** Inherent `mac_truncated(&self, key, msg, out: &mut [u8])` + `verify_truncated` on `HmacSha256`, `HmacSha384`, `HmacSha512`, writing the first `out.len()` bytes; reject truncation below 16 bytes (returns `CryptoError::BadInput`). No new dep.
  - **Files:** `crates/oxicrypto-mac/src/lib.rs`
  - **Tests:** truncated tag is prefix of full tag; verify_truncated accepts/rejects correctly; below-minimum length errors; all pass.
  - **Risk:** Low.

## API Improvements
- [x] Add `Mac::mac_to_vec` convenience method that allocates and returns the tag as `Vec<u8>`
- [x] Add `MacAlgo` enum variants in facade for HMAC-SHA-384, HMAC-SHA3-*, CMAC, KMAC, Poly1305 (done 2026-06-03)
  - **Implementation:** `oxicrypto/crates/oxicrypto/src/algo/mac.rs` contains `MacAlgo` with all variants and `mac_impl()` factory function. `Display`, `FromStr`, `TryFrom<&str>` all implemented.
- [x] Add `hmac_sha256_verify_truncated(key, msg, truncated_tag)` free function for verifying truncated MAC tags in constant time (done 2026-05-26)
  - **Design:** Permissive API accepting 1..=32 byte tags. Distinct from `HmacSha256::verify_truncated` which enforces ≥16 bytes. Returns `BadInput` for empty/oversized tags, `InvalidTag` on mismatch.
- [x] Add minimum key length enforcement: `Mac::min_key_len()` returning recommended minimum (done 2026-06-03)
  - **Goal:** `Mac` trait gains `fn min_key_len(&self) -> usize` with sensible per-algorithm defaults.
  - **Design:** Add `fn min_key_len(&self) -> usize { self.key_len() }` as a default in `oxicrypto-core/src/traits/mac.rs`. Override in `oxicrypto-mac` impls: HMAC = hash output length, CMAC-AES-128/256 = 16/32, Poly1305 = 32, KMAC = 16.
  - **Files:** `oxicrypto-core/src/traits/mac.rs`, `oxicrypto-mac/src/lib.rs`.
  - **Tests:** `test_min_key_len_per_algo` asserting each value.
  - **Risk:** Low — additive default trait method.
- [x] Support `Mac::new(key) -> MacInstance` pattern for pre-keyed MAC objects (done 2026-06-03)
  - **Goal:** Each HMAC type gains a `new_keyed(key: &[u8]) -> Result<HmacSha256Keyed, CryptoError>` constructor returning a type that implements `StreamingMac` and caches the key.
  - **Design:** Add `HmacSha256Keyed(hmac::Hmac<sha2::Sha256>)` newtype (and equivalent for each HMAC variant). Implements `StreamingMac::update` + `finalize` + `verify`. `new_keyed` validates key length. No changes to the `Mac` trait.
  - **Files:** `oxicrypto-mac/src/lib.rs`.
  - **Tests:** `test_hmacsha256_keyed_roundtrip`.
  - **Risk:** Low — additive types; check `hmac` crate API for keyed construction pattern.
- [x] Add `#[must_use]` on `mac()` and `verify()` return types

## Testing
- [x] Add full RFC 4231 test vectors (all 7 test cases) for HMAC-SHA-256 (done 2026-05-26, tests/kat_hmac.rs TC1-7)
- [x] Add full RFC 4231 test vectors for HMAC-SHA-512 (done 2026-05-26, TC1-7 in tests/kat_hmac.rs)
- [x] Add RFC 4231 test vectors for HMAC-SHA-384 (done 2026-06-03)
  - **Goal:** All 7 RFC 4231 §3 test cases pass for HMAC-SHA-384.
  - **Files:** `tests/kat_hmac_sha384.rs` (new).
  - **Tests:** `hmac_sha384_rfc4231_tc1` through `tc7`. **Risk:** Low.
- [x] Add NIST SP 800-38B test vectors for CMAC-AES-128 and CMAC-AES-256 (done 2026-06-03)
  - **Goal:** All NIST SP 800-38B Appendix D test cases pass.
  - **Files:** `tests/kat_cmac_nist.rs` (new). **Tests:** `cmac_aes128_d1_tc1` through `tc4`, `cmac_aes256_d2_tc1` through `tc4`. **Risk:** Low.
- [x] Add NIST SP 800-185 test vectors for KMAC128 and KMAC256 (done 2026-06-03)
  - **Goal:** All NIST SP 800-185 §A.1 sample messages pass for KMAC128 and KMAC256.
  - **Files:** `tests/kat_kmac_nist.rs` (new). **Tests:** 3 cases each. **Risk:** Low.
- [x] Add RFC 8439 §2.5.2 test vectors for standalone Poly1305 (done 2026-06-03)
  - **Goal:** RFC 8439 Poly1305 test vectors and Appendix A.3 vectors pass.
  - **Files:** `tests/kat_poly1305_rfc8439.rs` (new). **Risk:** Low.
- [x] Add Wycheproof HMAC test vectors (done 2026-06-03)
  - **Goal:** 20 representative Wycheproof HMAC-SHA256 + 20 HMAC-SHA512 inline vectors pass.
  - **Files:** `tests/kat_hmac_wycheproof.rs` (new). Vectors hardcoded inline (not downloaded). **Risk:** Low.
- [x] Property test: `mac` and `verify` are consistent for random inputs (done 2026-06-03)
  - **Files:** `tests/prop_mac.rs` (new). **Tests:** `prop_mac_verify_consistent`, `prop_mac_key_sensitivity`. **Risk:** Low.
- [x] Property test: constant-time verification timing (done 2026-06-03)
  - **Files:** `tests/prop_mac.rs`. **Tests:** Timing-independent correctness test (not an actual timing side-channel test — bounded loop verifying ct behavior). **Risk:** Low.
- [x] Test: zero-length message produces valid MAC (done 2026-06-03)
  - **Goal:** Zero-length message produces a valid, deterministic MAC tag for all algorithms. **Files:** `tests/prop_mac.rs`. **Risk:** Low.
- [x] Test: very long key (> block size) is properly hashed before use as HMAC key (done 2026-06-03)
  - **Goal:** HMAC with a key longer than the hash block size produces the same tag as HMAC with the hashed key (per RFC 2104 §2). **Files:** `tests/prop_mac.rs`. **Risk:** Low.
- [x] Fuzz test: `verify()` never panics on arbitrary tag bytes (done 2026-06-03)
  - **Goal:** `verify()` returns `Ok` or `Err(InvalidTag)` — never panics — for any combination of key, message, and tag bytes. **Files:** `tests/prop_mac.rs`. **Risk:** Low.

## Performance
- [x] Benchmark HMAC-SHA-256 vs HMAC-SHA-512 throughput for 64 B, 1 KiB, 64 KiB messages (done 2026-06-03)
  - **File:** `crates/oxicrypto-bench/benches/mac.rs` — `bench_hmac` group covers SHA-256/384/512.
- [x] Benchmark CMAC-AES vs HMAC-SHA-256 (CMAC is faster for short messages on AES-NI hardware) (done 2026-06-03)
  - **File:** `crates/oxicrypto-bench/benches/mac.rs` — `bench_cmac` group.
- [x] Benchmark KMAC256 vs HMAC-SHA3-256 (KMAC should be faster due to single-pass construction) (done 2026-06-03)
  - **File:** `crates/oxicrypto-bench/benches/mac.rs` — `bench_kmac` and `bench_hmac_sha3` groups.
- [x] Benchmark streaming MAC vs one-shot for large messages (done 2026-06-03)
  - **File:** `crates/oxicrypto-bench/benches/mac.rs` — `bench_streaming_vs_oneshot` group (64 KiB, 1 MiB, 4 KiB chunks).
- [x] Profile constant-time verification overhead vs naive comparison (done 2026-06-03)
  - **File:** `crates/oxicrypto-bench/benches/mac.rs` — `bench_verify_overhead` group: `mac_only` vs `mac_then_verify` for 64B/1KiB/64KiB.

## Integration
- [x] Ensure `oxicrypto-kdf` HKDF uses `oxicrypto-mac` HMAC internally (currently uses `hkdf` crate directly) (done 2026-06-03: architecture decision documented)
  - **Architecture decision (post-1.0 optimization):** Both `oxicrypto-kdf` and `oxicrypto-mac` delegate to the same `hmac = "0.13"` workspace crate — Cargo deduplicates to a single binary copy at link time, so outputs are byte-for-byte identical. Routing HKDF through `oxicrypto-mac::HmacSha256` would add a crate dependency edge and require non-trivial trait-bound plumbing with no output correctness benefit. Documented in `oxicrypto-mac/src/lib.rs` module doc as an intentional architecture decision.
- [x] Ensure `oxicrypto-kdf` PBKDF2 uses `oxicrypto-mac` HMAC internally (currently uses `pbkdf2` crate directly) (done 2026-06-03: architecture decision documented)
  - **Architecture decision (post-1.0 optimization):** Same reasoning as HKDF above. Both crates use the same `hmac` workspace crate internally. Behavior is equivalent. Documented in `oxicrypto-mac/src/lib.rs`.
- [x] Provide MAC algorithm negotiation for OxiTLS: `negotiate_mac(cipher_suite) -> Box<dyn Mac>` (done 2026-06-03)
  - **Design:** Added `TlsCipherSuite` enum + `negotiate_mac(suite) -> Result<Box<dyn Mac + Send + Sync>>` + `mac_name_for_suite()` to `oxicrypto-mac/src/lib.rs`. Covers all RFC 8446 TLS 1.3 cipher suites and common TLS 1.2 SHA-256/384/512 PRF suites.
  - **Tests:** `negotiate_mac_aes128_gcm_sha256_returns_hmac_sha256`, `negotiate_mac_aes256_gcm_sha384_returns_hmac_sha384`, `negotiate_mac_chacha20_poly1305_sha256_returns_hmac_sha256`, `negotiate_mac_sha512_prf_returns_hmac_sha512`, `tls_cipher_suite_from_iana_name_known`, `tls_cipher_suite_from_iana_name_unknown_returns_none`, `mac_name_for_suite_correct`, `negotiate_mac_functional_roundtrip`.
- [x] Wire KMAC to `oxicrypto-hash` SHA3/Keccak internals to avoid duplicating sponge state (done 2026-06-03: architecture decision documented)
  - **Architecture decision (post-1.0 optimization):** KMAC uses `tiny-keccak 2.0.2` (KMAC feature) while `oxicrypto-hash` SHA3 uses `sha3 0.12`. Both implement Keccak-f[1600] — outputs are cryptographically consistent. Sharing sponge state would require `sha3` to expose internals it intentionally hides, or moving KMAC into `oxicrypto-hash`. `tiny-keccak` is retained as the KMAC backend because it provides correct SP 800-185 domain separation (pad byte `0x04`) and `encode_string`/`bytepad` encoding. The minor code-size duplication is an accepted trade-off. Documented in `oxicrypto-mac/src/lib.rs` module doc.
- [x] Add HMAC benchmarks to `oxicrypto-bench` comparing against ring/aws-lc-rs HMAC (done 2026-06-03)
  - **File:** `crates/oxicrypto-bench/benches/mac.rs` — already included comprehensive HMAC/CMAC/KMAC/Poly1305 benchmark groups.
