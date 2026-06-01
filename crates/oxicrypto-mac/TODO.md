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
- [ ] Add `Mac::mac_to_vec` convenience method that allocates and returns the tag as `Vec<u8>`
- [ ] Add `MacAlgo` enum variants in facade for HMAC-SHA-384, HMAC-SHA3-*, CMAC, KMAC, Poly1305
- [x] Add `hmac_sha256_verify_truncated(key, msg, truncated_tag)` free function for verifying truncated MAC tags in constant time (done 2026-05-26)
  - **Design:** Permissive API accepting 1..=32 byte tags. Distinct from `HmacSha256::verify_truncated` which enforces ≥16 bytes. Returns `BadInput` for empty/oversized tags, `InvalidTag` on mismatch.
- [ ] Add minimum key length enforcement: `Mac::min_key_len()` returning recommended minimum (HMAC: hash output length)
- [ ] Support `Mac::new(key) -> MacInstance` pattern for pre-keyed MAC objects (avoids re-parsing key on each call)
- [ ] Add `#[must_use]` on `mac()` and `verify()` return types

## Testing
- [x] Add full RFC 4231 test vectors (all 7 test cases) for HMAC-SHA-256 (done 2026-05-26, tests/kat_hmac.rs TC1-7)
- [x] Add full RFC 4231 test vectors for HMAC-SHA-512 (done 2026-05-26, TC1-7 in tests/kat_hmac.rs)
- [ ] Add RFC 4231 test vectors for HMAC-SHA-384
- [ ] Add NIST SP 800-38B test vectors for CMAC-AES-128 and CMAC-AES-256
- [ ] Add NIST SP 800-185 test vectors for KMAC128 and KMAC256
- [ ] Add RFC 8439 Section 2.5.2 test vectors for standalone Poly1305
- [ ] Add Wycheproof HMAC test vectors (hmac_sha256_test.json, hmac_sha512_test.json)
- [ ] Property test: `mac(key, msg)` and `verify(key, msg, tag)` are consistent for random inputs
- [ ] Property test: constant-time verification timing does not depend on the position of the first differing byte
- [ ] Test: zero-length message produces valid MAC
- [ ] Test: very long key (> block size) is properly hashed before use as HMAC key
- [ ] Fuzz test: `verify()` never panics on arbitrary tag bytes

## Performance
- [ ] Benchmark HMAC-SHA-256 vs HMAC-SHA-512 throughput for 64 B, 1 KiB, 64 KiB messages
- [ ] Benchmark CMAC-AES vs HMAC-SHA-256 (CMAC is faster for short messages on AES-NI hardware)
- [ ] Benchmark KMAC256 vs HMAC-SHA3-256 (KMAC should be faster due to single-pass construction)
- [ ] Benchmark streaming MAC vs one-shot for large messages
- [ ] Profile constant-time verification overhead vs naive comparison

## Integration
- [ ] Ensure `oxicrypto-kdf` HKDF uses `oxicrypto-mac` HMAC internally (currently uses `hkdf` crate directly)
- [ ] Ensure `oxicrypto-kdf` PBKDF2 uses `oxicrypto-mac` HMAC internally (currently uses `pbkdf2` crate directly)
- [ ] Provide MAC algorithm negotiation for OxiTLS: `negotiate_mac(cipher_suite) -> Box<dyn Mac>`
- [ ] Wire KMAC to `oxicrypto-hash` SHA3/Keccak internals to avoid duplicating sponge state
- [ ] Add HMAC benchmarks to `oxicrypto-bench` comparing against ring/aws-lc-rs HMAC
