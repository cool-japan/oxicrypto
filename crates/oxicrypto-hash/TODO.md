# oxicrypto-hash TODO

## Status
Basic stateless hash wrappers (252 SLOC). Implements `Hash` trait for SHA-256, SHA-384, SHA-512 (FIPS 180-4), SHA3-256, SHA3-384, SHA3-512 (FIPS 202), and BLAKE3. All one-shot only; no streaming API, no XOFs, no BLAKE2.

## Core Implementation
- [x] Implement `StreamingHash` adapter wrapping `digest::Digest` for incremental hashing on all existing algorithms: `Sha256Streaming`, `Sha384Streaming`, etc. (~120 SLOC) (done 2026-05-25)
  - **Goal:** Sha256Streaming, Sha384Streaming, Sha512Streaming, Sha3_256Streaming, Sha3_384Streaming, Sha3_512Streaming, Blake3Streaming — all implementing StreamingHash from oxicrypto-core
  - **Design:** Generic adapter `DigestStreamingAdapter<D: digest::Digest + digest::Reset>`. `update()` calls `Digest::update()`, `finalize()` calls `Digest::finalize_reset()` (or clone+finalize), `reset()` calls `Digest::reset()`. Type aliases: `pub type Sha256Streaming = DigestStreamingAdapter<sha2::Sha256>` etc. Blake3Streaming uses `blake3::Hasher` directly (not Digest trait) since blake3 doesn't implement digest::Digest in the same way.
  - **Files:** `crates/oxicrypto-hash/src/lib.rs`
  - **Prerequisites:** StreamingHash trait in oxicrypto-core (already exists there)
  - **Tests:** For SHA-256: split "abc" into chunks of 1, 2 bytes etc., verify same digest as one-shot; test reset(); test empty input
  - **Risk:** digest 0.11 may rename finalize_reset — check actual API before implementing
- [x] SHAKE128 / SHAKE256 XOF (done 2026-05-25)
  - **Goal:** `shake128(msg, out)` / `shake256(msg, out)` arbitrary-length output (FIPS 202 §6.2) + `Shake128`/`Shake256` XOF reader type.
  - **Design:** Uses `shake 0.1.0` crate (sha3 0.12.0 moved SHAKE out). `shake::Shake128`/`Shake256` via `digest::ExtendableOutput` + `XofReader`. New module `xof.rs`.
  - **Files:** `crates/oxicrypto-hash/src/xof.rs`
  - **Tests:** Non-zero output; prefix stability (64-byte output extends 32-byte); reader API matches one-shot.
- [x] cSHAKE128 / cSHAKE256 (done 2026-05-25)
  - **Goal:** customizable SHAKE (SP 800-185 §3) with function-name + customization string.
  - **Design:** Uses `cshake 0.2.1` crate. `CShake128::new_with_function_name(function_name, customization)`. When both empty, degrades to SHAKE128.
  - **Files:** `crates/oxicrypto-hash/src/xof.rs`
  - **Tests:** Empty N,S equals SHAKE128/256; non-empty N differs from SHAKE; customization string matters.
  - **Deviation:** sha3 0.12.0 dropped CShake; added `cshake = "0.2.1"` and `shake = "0.1.0"` as workspace deps.
- [x] TupleHash128 / TupleHash256 (done 2026-05-25)
  - **Goal:** unambiguous hashing of a tuple of byte strings (SP 800-185 §5).
  - **Design:** cSHAKE128/256 with N=`TupleHash`; body = `encode_string(X_i)` concatenated, then `right_encode(L)`. Private helpers `left_encode(u64)`, `right_encode(u64)`, `encode_string(&[u8])`.
  - **Files:** `crates/oxicrypto-hash/src/xof.rs`
  - **Tests:** `["ab","c"] != ["a","bc"]`; deterministic; customization matters.
- [x] Add BLAKE2b-256 / BLAKE2b-512 per RFC 7693 using `blake2` crate (~60 SLOC) (done 2026-05-25)
  - **Goal:** Blake2b256 and Blake2b512 structs implementing the Hash trait
  - **Design:** Add `blake2 = { workspace = true }` to Cargo.toml. `Blake2b256` wraps `blake2::Blake2b<blake2::digest::consts::U32>`, `Blake2b512` wraps `blake2::Blake2b<blake2::digest::consts::U64>`. Follow exact SHA-256 wrapper pattern: struct, Hash trait impl with name()/output_len()/hash(). IMPORTANT: blake2 crate requires digest 0.10 — check if workspace uses digest 0.11 and resolve compatibility (may need blake2 = "0.10" which uses digest 0.10, or find a digest 0.11-compatible version).
  - **Files:** `crates/oxicrypto-hash/src/lib.rs`, `crates/oxicrypto-hash/Cargo.toml`, workspace `Cargo.toml`
  - **Prerequisites:** blake2 crate dependency added
  - **Tests:** RFC 7693 Appendix E vectors: BLAKE2b("", key=0x000102...) == expected; empty-input hash; output_len() == 32/64
  - **Risk:** blake2 crate may use digest 0.10 while workspace uses digest 0.11 — resolve by using blake2 with its own digest feature or using the raw API bypassing the Digest trait
- [x] Add BLAKE2s-256 per RFC 7693 using `blake2` crate (~40 SLOC) (done 2026-05-25)
  - **Goal:** Blake2s256 struct implementing Hash trait, 32-byte output
  - **Design:** `Blake2s256` wraps `blake2::Blake2s<blake2::digest::consts::U32>`. Same pattern as Blake2b256 but with Blake2s.
  - **Files:** `crates/oxicrypto-hash/src/lib.rs`, `crates/oxicrypto-hash/Cargo.toml`
  - **Prerequisites:** blake2 crate (shared with Blake2b item)
  - **Tests:** RFC 7693 BLAKE2s test vectors; output_len() == 32
  - **Risk:** Same digest version compatibility as BLAKE2b
- [x] BLAKE2b keyed-hash mode (done 2026-05-25)
  - **Goal:** `Blake2bKeyed` MAC-like keyed hashing (RFC 7693 §2.1, key ≤ 64 bytes).
  - **Design:** `blake2::Blake2bMac512::new_from_slice(key)` (with `KeyInit` in scope). Blake2bMac512 gives 64-byte output; truncate to `out.len()`. Both struct and free-function APIs provided.
  - **Files:** `crates/oxicrypto-hash/src/xof.rs`
  - **Tests:** Different keys → different outputs; empty/oversized keys rejected; empty out rejected; 64-byte key OK; struct matches free function.
- [x] Add SHA-512/256 truncated variant per FIPS 180-4 Section 6.7 (~30 SLOC) (done 2026-05-25)
  - **Goal:** Sha512_256 struct implementing Hash trait — truncated SHA-512 per FIPS 180-4 Section 6.7
  - **Design:** `Sha512_256` wraps `sha2::Sha512_256` (already available in the sha2 crate which is already a workspace dep). Trivial wrapper identical to existing Sha256/Sha384/Sha512 pattern.
  - **Files:** `crates/oxicrypto-hash/src/lib.rs`
  - **Prerequisites:** None — sha2 crate already a dep and Sha512_256 is in it
  - **Tests:** FIPS 180-4 Appendix D test vectors for SHA-512/256; output_len() == 32
  - **Risk:** Very low
- [x] Add BLAKE3 keyed-hash mode via `blake3::keyed_hash()` (~30 SLOC) (done 2026-05-25)
  - **Goal:** Blake3Keyed struct for keyed MAC-like hashing using blake3::keyed_hash()
  - **Design:** `pub struct Blake3Keyed { key: [u8; 32] }`. `impl Blake3Keyed { pub fn new(key: [u8; 32]) -> Self }`. `pub fn hash_keyed(&self, msg: &[u8]) -> [u8; 32]`. Also expose as a free function `blake3_keyed_hash(key: &[u8; 32], msg: &[u8]) -> [u8; 32]` wrapping `blake3::keyed_hash(key, msg).as_bytes().clone()`.
  - **Files:** `crates/oxicrypto-hash/src/lib.rs`
  - **Prerequisites:** blake3 already a workspace dep
  - **Tests:** Known test vector; same key + different messages = different output; different keys + same message = different output
  - **Risk:** Very low — blake3::keyed_hash() is a stable, simple API
- [x] Add BLAKE3 key-derivation mode via `blake3::derive_key()` (~30 SLOC) (done 2026-05-25)
  - **Goal:** blake3_derive_key() free function wrapping blake3::derive_key() for context-based key derivation
  - **Design:** `pub fn blake3_derive_key(context: &str, key_material: &[u8]) -> [u8; 32]`. Wraps `blake3::derive_key(context, key_material)`. The context string must describe the purpose (e.g., "oxicrypto 2026-05-25 AEAD key derivation").
  - **Files:** `crates/oxicrypto-hash/src/lib.rs`
  - **Prerequisites:** blake3 already a dep
  - **Tests:** Known test vector; different contexts produce different outputs for same key material; deterministic
  - **Risk:** Very low
- [x] Add BLAKE3 extendable output (XOF) via `blake3::Hasher::finalize_xof()` with arbitrary-length output (~40 SLOC) (done 2026-05-25)
  - **Goal:** blake3_xof() function producing arbitrary-length output from BLAKE3
  - **Design:** `pub fn blake3_xof(msg: &[u8], output_len: usize) -> Vec<u8>`. Use `blake3::Hasher::new()`, `hasher.update(msg)`, `let mut output_reader = hasher.finalize_xof()`, `output_reader.fill(&mut out_vec)`. Return the Vec. Gated behind `std` feature (or always available since blake3 handles alloc).
  - **Files:** `crates/oxicrypto-hash/src/lib.rs`
  - **Prerequisites:** blake3 already a dep; blake3::OutputReader is available
  - **Tests:** blake3_xof("abc", 32) equals blake3::hash(b"abc") first 32 bytes; blake3_xof("abc", 64) and blake3_xof("abc", 128) are prefixes of each other; empty input
  - **Risk:** Low — OutputReader.fill() may need a &mut [u8] not Vec; use extend_from_slice pattern
- [x] Add parallel hashing support: `ParallelHash128` / `ParallelHash256` per NIST SP 800-185 using Rayon for multi-threaded tree hashing (~100 SLOC) (done 2026-05-30, sequential pure-Rust; rayon `parallel` feature deferred)
  - **Status:** Implemented sequentially in `src/parallelhash.rs` (`parallel_hash128`/`parallel_hash256` + `parallel_hash128_xof`/`parallel_hash256_xof` free functions and `ParallelHash128`/`ParallelHash256` struct wrappers). Verified against the official NIST SP 800-185 ParallelHash128/256 sample vectors (Samples #1–#3, fixed-output, both strengths) in `tests/kat_parallelhash.rs` — all 8 KATs pass. The rayon `parallel` feature for speed is deferred (no new deps this run); the per-block CVs are computed sequentially. KEY DETAIL: `left_encode(B)` encodes the block size in **bytes** (not bits), unlike `encode_string`.
  - **Goal:** Correct `parallel_hash128`/`parallel_hash256` (and XOF variants) per SP 800-185, pure-Rust and correct at **default features** (sequential), with an **optional non-default `parallel` feature** using rayon purely for speed (identical output).
  - **Design (ultrathink):** Per SP 800-185 §6.1/6.2, with block size `B` (bytes), output `L` bits, customization `S`: `newX = left_encode(B) ‖ ⨁_i cSHAKE128(X_i, 256, "", "")  ‖ right_encode(n) ‖ right_encode(L)` (256-bit chaining values for 128; cSHAKE256→512-bit CVs for 256), then `cSHAKE128(newX, L, "ParallelHash", S)`. Reuse the existing `cshake128`/`cshake256` and `left_encode`/`right_encode` helpers already in `oxicrypto-hash` (no new sponge). The per-block CV computation is embarrassingly parallel: sequential `map` by default, rayon `par_iter().map()` behind `#[cfg(feature = "parallel")]` — both produce the identical CV vector, so KATs pass in either mode.
  - **Files:** new `crates/oxicrypto-hash/src/parallelhash.rs`; edit `src/lib.rs`; edit `Cargo.toml` (`rayon` as an **optional** dep; `parallel = ["dep:rayon"]` feature; default stays empty/pure).
  - **Prerequisites:** cSHAKE + encode helpers (already present).
  - **Tests:** the SP 800-185 ParallelHash sample vectors (§A.3-style: the spec's worked examples for ParallelHash128/256 and the XOF forms) in `tests/kat_parallelhash.rs`; equivalence test asserting `parallel` feature output == default output for several block counts and a partial final block.
  - **Risk:** `right_encode(n)`/CV concatenation ordering. Mitigation: lock with the spec's official examples; assert sequential==parallel.
- [x] `hash_file(path)` (done 2026-05-25)
  - **Goal:** stream a file through a hash without loading it fully, behind a `std` feature.
  - **Design:** `hash_file_sha256`, `hash_file_sha512`, `hash_file_blake3` behind `#[cfg(feature = "std")]`. 64KB `BufReader` chunks; maps `io::Error` to `CryptoError::Internal`. `std` feature already existed (`blake3/std` + `oxicrypto-core/std`).
  - **Files:** `crates/oxicrypto-hash/src/xof.rs`
  - **Tests:** Write known bytes to `std::env::temp_dir()` temp file; file hash matches in-memory; non-existent file returns `CryptoError::Internal`.
- [x] Add `HashBuilder` pattern: `HashBuilder::sha256().streaming().build()` for ergonomic construction (~50 SLOC) (done 2026-05-30)
  - **Status:** Implemented in `src/hash_builder.rs`. `HashBuilder::sha256().build()` returns `Box<dyn Hash>`; `HashBuilder::sha256().streaming().build()` returns a sized `DynStreamingHash` enum that implements `StreamingHash` (a `Box<dyn StreamingHash>` cannot be used because `finalize(self)` needs a `Sized` receiver). Covers SHA-2 (256/384/512/512-256), SHA-3 (256/384/512), BLAKE3. Tests assert builder one-shot == direct API and builder streaming (chunked + byte-at-a-time) == one-shot for every algorithm.
  - **Goal:** `HashBuilder::sha256().streaming().build()`-style fluent construction over the existing hash types.
  - **Design:** A builder enum selecting algorithm + one-shot vs streaming, returning a boxed `Hash`/`StreamingHash`. Keep it in a new `src/hash_builder.rs` to avoid growing `lib.rs` (currently ~1200 lines) toward the limit.
  - **Files:** new `crates/oxicrypto-hash/src/hash_builder.rs`; edit `src/lib.rs`.
  - **Tests:** builder output equals the direct API for each algorithm; streaming-vs-one-shot equivalence via the builder.
  - **Risk:** low.

## API Improvements
- [x] Add `hex_digest(msg) -> String` convenience method returning hex-encoded digest string (behind `std` feature) (done 2026-05-26, sha256_hex/sha384_hex/sha512_hex/sha3_256_hex/blake3_hex)
- [x] Implement `std::io::Write` for streaming hash instances (behind `std` feature) so `io::copy(&mut reader, &mut hasher)` works (done 2026-05-26, DigestStreamingAdapter + Blake3Streaming)
- [x] Add `Hash::block_size() -> usize` method returning internal block size (64 for SHA-256, 136 for SHA3-256, etc.) (done 2026-05-26, as BLOCK_SIZE associated consts on all algorithm structs)
- [x] Add `const` variants: `Sha256::DIGEST_LEN`, `Blake3::DIGEST_LEN` as associated constants (done 2026-05-26, DIGEST_LEN on all algorithm structs)
- [x] Support variable-length output for BLAKE3 and SHAKE (done 2026-05-25, blake3_xof() + shake128/256 XOF readers)
- [ ] Add `#[cfg(feature = "no_std")]` path that avoids `alloc` in `hash_to_vec` (return fixed-size array instead)
- [x] Implement `Clone` for streaming hash state to allow forking of hash computation (done 2026-05-26, DigestStreamingAdapter derives Clone; Blake3Streaming impls Clone)

## Testing
- [x] Add full NIST FIPS 180-4 Appendix B test vectors for SHA-256 (done 2026-05-25, tests/kat_sha256.rs)
- [x] Add full NIST FIPS 180-4 test vectors for SHA-384 and SHA-512 (done 2026-05-26, tests/kat_sha384_sha512.rs — empty/abc/448-bit/896-bit, OpenSSL 3.x verified)
- [x] Add NIST FIPS 202 test vectors for SHA3-256/384/512 (done 2026-05-26, tests/kat_sha3.rs — empty/abc for all three, 384-abc added)
- [x] Add NIST FIPS 202 / SP 800-185 KAT vectors for SHAKE128/256 (done 2026-05-26, tests/kat_xof.rs — empty/abc digest equality, OpenSSL 3.x verified; cSHAKE/TupleHash property tests inline in xof.rs)
- [x] Add RFC 7693 Appendix E test vectors for BLAKE2b and BLAKE2s (done 2026-05-26, tests/kat_blake2.rs — BLAKE2b-256/512 and BLAKE2s-256, Python hashlib + OpenSSL 3.x verified)
- [x] Add BLAKE3 official test_vectors.json comprehensive vectors (done 2026-05-26, tests/kat_blake3_official.rs — n=0/1/2/31/32/63/64/65/1023/1024/1025 + mode separation tests)
- [x] Add streaming vs one-shot equivalence property test: split message at every byte boundary, verify identical digest (done 2026-05-26, tests/streaming_equivalence.rs — SHA-256/384/512, BLAKE3, BLAKE2b-256/512, BLAKE2s-256)
- [x] Add large-input test: hash 1 MiB payloads, verify streaming matches one-shot (done 2026-05-26, tests/large_input.rs — SHA-256/384/512 and BLAKE3)
- [ ] Add Wycheproof hash test vectors where available
- [ ] Fuzz test: ensure no panics on arbitrary-length inputs (0 to 1 MB)
- [ ] Replace `unwrap()` in test `hex_decode` helper with a proper hex-decoding utility or `hex` crate
- [x] (policy) Remove the 3 production `expect()` calls in `src/xof.rs` per no-unwrap policy (done 2026-05-30)
  - **Status:** All three `checked_mul(8).expect(...)` sites replaced with `.ok_or(CryptoError::BadInput)?`. `encode_string` now returns `Result<Vec<u8>, CryptoError>`, and `tuple_hash128`/`tuple_hash256` now return `Result<(), CryptoError>` (inline tests updated). `oxicrypto-hash` production code (all four src files) now has ZERO `unwrap()`/`expect()`/`panic!`. Existing XOF/TupleHash KATs still pass.
  - **Goal:** Zero `expect()`/`unwrap()` in `oxicrypto-hash` production code.
  - **Design:** Replace the three `(<len> * 8)` `checked_mul(...).expect(...)` sites with `.ok_or(CryptoError::BadInput)?` (or `Internal`), returning an error on the (unreachable-in-practice) overflow instead of panicking.
  - **Files:** `crates/oxicrypto-hash/src/xof.rs`.
  - **Tests:** existing XOF KATs still pass; add an oversized-length guard test if ergonomic.
  - **Risk:** low.

## Performance
- [ ] Benchmark streaming hash vs one-shot for 1 KiB, 4 KiB, 64 KiB, 1 MiB inputs
- [ ] Benchmark BLAKE3 parallel hashing vs sequential on multi-core (Rayon thread pool sizing)
- [ ] Profile SHA-256 throughput per byte and compare against hardware-accelerated path (AES-NI/SHA-NI)
- [ ] Add benchmark for BLAKE3 keyed-hash vs HMAC-SHA-256 (same output size, BLAKE3 should be faster)
- [ ] Benchmark SHAKE256 XOF output generation for variable lengths (32, 64, 128, 256 bytes)

## Integration
- [ ] Ensure `oxicrypto-mac` HMAC implementations can accept `StreamingHash` for underlying hash
- [ ] Ensure `oxicrypto-kdf` HKDF implementations internally use the same hash primitives (no duplicated SHA-256 deps)
- [ ] Provide `HashAlgo` enum variants in facade for all new algorithms (SHAKE, BLAKE2, ParallelHash)
- [ ] Ensure `oxicrypto-sig` ECDSA/RSA pre-hash modes can accept any `Hash` trait object
- [ ] Coordinate with `oxicrypto-bench` to add throughput benchmarks for new hash algorithms vs ring/aws-lc-rs
