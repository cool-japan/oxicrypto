# oxicrypto-core TODO

## Status
Minimal trait surface (187 SLOC). Defines `CryptoError` enum, seven trait objects (`Hash`, `Aead`, `Mac`, `Signer`, `Verifier`, `KeyAgreement`, `Kdf`, `Rng`), and re-exports from `alloc`. No crypto implementation lives here. `no_std + alloc` compliant.

## Core Implementation
- [x] Add `SecretKey<N>` fixed-size wrapper with `Zeroize + ZeroizeOnDrop` semantics (use `zeroize 1.x`); store key bytes in a `[u8; N]` that is zeroed when dropped (~80 SLOC)
- [x] Add `SecretVec` heap-allocated variable-length secret wrapper with `Zeroize + ZeroizeOnDrop` (~60 SLOC)
- [x] Add `KeyPair<SK, PK>` generic struct bundling a secret key and public key with `Zeroize` on the secret half (~50 SLOC)
- [x] Implement constant-time comparison utilities: `ct_eq(a, b) -> bool`, `ct_select(a, b, choice) -> u8` using `subtle::ConstantTimeEq` / `subtle::ConditionallySelectable` (~40 SLOC)
- [x] Add `ct_is_zero(slice) -> bool` constant-time zero-check for nonce/key validation (~20 SLOC)
- [x] Add `StreamingHash` trait for incremental hashing: `update(&mut self, data: &[u8])`, `finalize(self, out: &mut [u8])`, `reset(&mut self)` (~30 SLOC)
- [x] Add `StreamingMac` trait for incremental MAC computation: `update(&mut self, data: &[u8])`, `finalize(self, out: &mut [u8])`, `verify(self, tag: &[u8])` (~30 SLOC)
- [x] Add `StreamingAead` trait for chunked AEAD encryption... (planned 2026-05-25)
  - **Goal:** StreamingAead trait enabling chunked AEAD encryption for large messages without buffering entire plaintext
  - **Design:** Trait with `init(key: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Self, CryptoError>`, `encrypt_update(chunk: &[u8], out: &mut [u8]) -> Result<usize, CryptoError>`, `encrypt_finalize(out: &mut [u8]) -> Result<usize, CryptoError>`, `decrypt_update(chunk: &[u8], out: &mut [u8]) -> Result<usize, CryptoError>`, `decrypt_finalize(out: &mut [u8]) -> Result<(), CryptoError>` plus `reset(&mut self)`. Follow StreamingHash/StreamingMac init/update/finalize pattern.
  - **Files:** `crates/oxicrypto-core/src/lib.rs`
  - **Prerequisites:** None — builds on existing trait pattern
  - **Tests:** Trait definition compiles; a mock implementor can be constructed as trait object
  - **Risk:** Low — AEAD streaming API is simple at the trait level; implementations are where complexity lives
- [x] Add `Kem` trait for key encapsulation mechanisms... (planned 2026-05-25)
  - **Goal:** Kem trait for ML-KEM and future KEM adapters. Enables type-safe KEM operations across classical and post-quantum algorithms.
  - **Design:** Associated types `EncapKey: Clone`, `DecapKey`, `Ciphertext: Clone`, `SharedSecret: Zeroize`. Methods: `generate(rng: &mut dyn Rng) -> Result<(Self::DecapKey, Self::EncapKey), CryptoError>`, `encapsulate(ek: &Self::EncapKey, rng: &mut dyn Rng) -> Result<(Self::Ciphertext, Self::SharedSecret), CryptoError>`, `decapsulate(dk: &Self::DecapKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret, CryptoError>`. Use associated types for clean concrete dispatch (dyn Kem not needed at this stage).
  - **Files:** `crates/oxicrypto-core/src/lib.rs`
  - **Prerequisites:** None
  - **Tests:** Trait definition compiles; struct with unit associated types can impl it
  - **Risk:** Low — associated types prevent dyn Kem but that's acceptable; concrete dispatch is sufficient for now
- [x] Add `PasswordHash` trait for password hashing KDFs... (planned 2026-05-25)
  - **Goal:** Separate password hashing from general-purpose KDFs. Provides a uniform interface over Argon2, PBKDF2, scrypt.
  - **Design:** Trait `PasswordHash` with `fn hash_password(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<(), CryptoError>`. Parameter tuning is done at construction time (each implementor holds its params). Separate from `Kdf` trait since password KDFs have a fundamentally different security model (slow by design). Add `PasswordHashAlgo` enum-ready name() method.
  - **Files:** `crates/oxicrypto-core/src/lib.rs`
  - **Prerequisites:** None
  - **Tests:** Trait definition compiles; a struct implementing it can be used as Box<dyn PasswordHash>
  - **Risk:** Very low — trait definition only
- [x] Add `KeyGenerator` trait: `generate_keypair(rng) -> Result<KeyPair, CryptoError>`... (planned 2026-05-25)
  - **Goal:** Uniform key generation interface for all asymmetric algorithms
  - **Design:** `trait KeyGenerator { fn generate_keypair(&self, rng: &mut dyn Rng) -> Result<KeyPair<SecretVec, Vec<u8>>, CryptoError>; fn algorithm_name(&self) -> &'static str; }`. Uses existing `KeyPair` and `SecretVec` from core. `&self` receiver lets the generator carry algorithm-specific configuration (key size, curve, etc.).
  - **Files:** `crates/oxicrypto-core/src/lib.rs`
  - **Prerequisites:** None — KeyPair, SecretVec already exist in core
  - **Tests:** Trait definition compiles; Box<dyn KeyGenerator> can be constructed
  - **Risk:** Very low — straightforward trait definition
- [x] Add `CryptoError::Rng` variant for RNG-specific failures (currently overloaded onto `Internal`) (~5 SLOC)
- [x] Add `CryptoError::Encoding` variant for DER/PEM/SEC1 parse failures (~5 SLOC)
- [x] Add `CryptoError::UnsupportedAlgorithm` variant for runtime algorithm negotiation (~5 SLOC)
- [x] Implement `From<CryptoError> for std::io::Error` (behind `std` feature) for ergonomic I/O integration (~15 SLOC)
- [x] Add `AlgorithmId` enum (canonical IANA algorithm ids) (done 2026-05-25)
  - **Goal:** `#[non_exhaustive]` enum of canonical algorithm identifiers with IANA/NIST `&'static str` names, covering hash/aead/mac/sig/kex/kdf/pq families. Unblocks facade `available_algorithms()`.
  - **Design:** One enum with a `name()` / `Display` returning canonical strings. Grouped variants; `category()` accessor returning `AlgorithmCategory` (Hash, Aead, Mac, Sig, Kex, Kdf, Pq).
  - **Files:** `crates/oxicrypto-core/src/lib.rs`
  - **Tests:** every variant has a non-empty unique name; categories correct.
  - **Risk:** Low — keep it `#[non_exhaustive]` so the facade can grow.

## API Improvements
- [x] Add `#[must_use]` on all trait method returns (done 2026-05-25)
  - **Goal:** annotate all `Result`-returning trait methods on Hash/Aead/Mac/Signer/Verifier/KeyAgreement/Kdf/Rng/Kem/PasswordHash.
  - **Design:** mechanical `#[must_use]` additions; no behavior change.
  - **Files:** `crates/oxicrypto-core/src/lib.rs`
  - **Tests:** crate still compiles warning-free.
  - **Risk:** Very low.
- [x] Add `Debug` bound requirement on all trait objects (done 2026-06-03)
  - **Implementation:** `MaybeDebug` helper supertrait in `traits/mod.rs` erases to a no-op without the feature and requires `core::fmt::Debug` with it. All 11 object-safe core traits gain the conditional supertrait. Feature `debug = []` in `Cargo.toml`. 4 new `#[cfg(feature = "debug")]` tests in `debug_feature_tests` module.
- [x] Add `Hash::hash_to_array::<N>()` default method (done 2026-05-25)
  - **Goal:** default trait method returning `[u8; N]` for compile-time-sized outputs (errors if N ≠ output_len).
  - **Design:** default method on `Hash`, sibling to existing `hash_to_vec`; const-generic N. Must stay object-safe (`where Self: Sized` on the generic method so `dyn Hash` survives).
  - **Files:** `crates/oxicrypto-core/src/lib.rs`
  - **Tests:** `hash_to_array::<32>` for SHA-256 matches `hash_to_vec`; wrong N errors.
  - **Risk:** Moderate — guard object-safety with `Self: Sized` on the generic method.
- [x] Add `Aead::seal_to_vec` / `open_to_vec` convenience methods (done 2026-05-25)
  - **Goal:** allocating convenience methods mirroring `hash_to_vec`.
  - **Design:** default methods sizing output via `tag_len()`; delegate to `seal`/`open`. `alloc::vec::Vec`.
  - **Files:** `crates/oxicrypto-core/src/lib.rs`
  - **Tests:** round-trip seal_to_vec→open_to_vec; tamper rejection.
  - **Risk:** Low.
- [x] Add `Mac::mac_to_vec` convenience method (done 2026-05-25)
  - **Goal:** allocating convenience method sized by `output_len()`.
  - **Design:** default method delegating to `mac`.
  - **Files:** `crates/oxicrypto-core/src/lib.rs`
  - **Tests:** equals fixed-buffer `mac` output.
  - **Risk:** Low.
- [x] Derive `serde::Serialize` / `serde::Deserialize` on `CryptoError` behind a `serde` feature flag (use `oxicode` for serialization backend per COOLJAPAN policy) (done 2026-06-03)
  - **Implementation:** Derived `Serialize` + manual `Deserialize` (avoids `'de: 'static` constraint from `Internal(&'static str)`). `Internal` deserializes lossily as `Internal("")` — string preserved in encoded form for observability. 4 `serde_tests` using `oxicode::serde::encode_serde`/`decode_serde`. Feature `serde = ["dep:serde"]` in `Cargo.toml`; `oxicode` added as `[dev-dependencies]` for tests.
- [x] Document minimum key length requirements in trait-level rustdoc for `Mac`, `Aead`, `Kdf` (done 2026-06-03)
- [x] Add `const` associated constants on trait impls (e.g., `const OUTPUT_LEN: usize`) where possible for compile-time usage (done 2026-06-03)
  - **Goal:** Every concrete hash and MAC type gains `pub const OUTPUT_LEN: usize = N;` as an inherent constant for compile-time usage.
  - **Design:** Add inherent consts (not trait-level — non-breaking) to each type in `oxicrypto-hash/src/lib.rs` (Sha256→32, Sha384→48, Sha512→64, Sha512_256→32, Sha3_256→32, Sha3_384→48, Sha3_512→64, Blake2b256→32, Blake2b512→64, Blake2s256→32, Blake3→32) and similarly in `oxicrypto-mac/src/lib.rs`.
  - **Files:** `oxicrypto-hash/src/lib.rs`, `oxicrypto-mac/src/lib.rs`.
  - **Tests:** `assert_eq!(Sha256::OUTPUT_LEN, 32)` etc. in the respective crate tests.
  - **Risk:** Low — additive inherent consts, no trait changes.

## Testing
- [x] Property test: `SecretKey` zeroize-on-drop actually zeroes memory (done 2026-06-03)
  - **Goal:** Confirm `SecretKey<N>` bytes are zeroed on drop via `std::ptr::read_volatile`.
  - **Design:** `#![forbid(unsafe_code)]` prevents `read_volatile`; instead verifies `ZeroizeOnDrop` bound at compile time and that `Zeroize::zeroize` on a mutable clone zeroes the bytes.
  - **Files:** `oxicrypto-core/src/tests.rs`.
  - **Tests:** `test_secretkey_zeroize_on_drop`.
  - **Risk:** Low; `unsafe` only in test.
- [x] Property test: `ct_eq` returns same result as `==` for all u8 slices up to 256 bytes (done 2026-06-03)
  - **Goal:** Confirm `ct_eq` is semantically equivalent to `==` for all byte-slice pairs.
  - **Files:** `oxicrypto-core/src/tests.rs`. **Tests:** `test_ct_eq_agrees_with_eq`. **Risk:** Low.
- [x] Fuzz test: `CryptoError::Display` round-trip does not panic on any variant (done 2026-06-03)
  - **Goal:** `CryptoError::Display` never panics on any variant.
  - **Files:** `oxicrypto-core/src/tests.rs`. **Tests:** `test_cryptoerror_display_no_panic`. **Risk:** Low.
- [x] Test: `StreamingHash` trait produces identical output to one-shot `Hash::hash` for chunked inputs (done 2026-06-03)
  - **Goal:** `StreamingHash` (chunked) produces identical output to one-shot `Hash::hash`.
  - **Files:** `oxicrypto-core/src/tests.rs`. **Tests:** `test_streaminghash_chunked_equiv_oneshot`. **Risk:** Low.
- [x] Test: `KeyPair` drops secret key bytes on scope exit (done 2026-06-03)
  - **Goal:** `KeyPair` zeroes secret key bytes on scope exit.
  - **Files:** `oxicrypto-core/src/tests.rs`. **Tests:** `test_keypair_drops_secret`. **Risk:** Low.
- [x] Test: all error variants are distinguishable via `PartialEq` (done 2026-06-03)
  - **Goal:** Every `CryptoError` variant is distinguishable via `PartialEq`.
  - **Files:** `oxicrypto-core/src/tests.rs`. **Tests:** `test_error_variants_distinguishable`. **Risk:** Low.

## Performance
- [x] Ensure `SecretKey<N>` is stack-allocated with no heap indirection for N <= 64 (done 2026-06-03)
  - **Goal:** Assert `SecretKey<32>` and `SecretKey<64>` have exactly N bytes of size (no heap indirection).
  - **Files:** `oxicrypto-core/src/tests.rs`. **Tests:** `test_secretkey_size_no_heap`. **Risk:** Low.
- [x] Benchmark `ct_eq` vs naive `==` to verify constant-time property has acceptable overhead (done 2026-06-19 — `oxicrypto-bench/benches/core.rs`: `bench_ct_eq_equal`, `bench_ct_eq_unequal`, `bench_ct_eq_scaling` covering 16 B → 16 KiB; both equal and last-byte-unequal cases; linear-scaling verification group)
- [x] Profile `Zeroize` overhead on `SecretVec` drop path (done 2026-06-19 — `oxicrypto-bench/benches/core.rs`: `bench_secretvec_drop` using `iter_batched(SmallInput)` to isolate zeroize cost from allocation; 32 B / 256 B / 4 KiB / 64 KiB sizes; head-to-head `SecretVec` vs plain `Vec<u8>` drop)

## Integration
- [x] Ensure `oxicrypto-sig` Ed448/ECDSA/RSA types use `SecretKey` wrapper for private key storage (verified 2026-06-10)
  - **Verification:** `oxicrypto-sig/src/lib.rs:149,155` — Ed25519 keygen returns `SecretKey<32>`; `lib.rs:165,168` — ECDSA-P256 wraps raw bytes in `SecretVec`; `lib.rs:413–423` — `EcdsaP256KeyPair` has explicit `Zeroize` impl (underlying `p256::ecdsa::SigningKey` implements `ZeroizeOnDrop`). Pattern is consistent for P-384/P-521/secp256k1 (lines 469ff). All private key material at the byte boundary uses `SecretKey<N>` or `SecretVec`.
- [x] Ensure `oxicrypto-kex` X25519 uses `SecretKey<32>` for static secrets (verified 2026-06-10)
  - **Verification:** `oxicrypto-kex/src/lib.rs:416` — `x25519_generate_keypair` return type is `(SecretKey<32>, [u8; 32])`; `lib.rs:425` — `SecretKey::new(seed)` wraps raw bytes (zeroize-on-drop). `X25519::agree_with_key` at line 200 takes `&SecretKey<32>` directly.
- [x] Ensure `oxicrypto-rand` OxiRng seed uses `SecretKey<32>` wrapper (implemented 2026-06-10)
  - **Verification:** `oxicrypto-rand/src/oxirng.rs` — all three constructors (OxiRng, OxiRng8, OxiRng12) and all `reseed`/`check_fork` paths now call `seed.zeroize()` immediately after `from_seed(seed)`. `[u8; 32]` is `Copy` so the stack copy persists until explicitly zeroized. `helpers.rs:reseed()` also fixed. Uses `oxicrypto_core::Zeroize` — no direct `zeroize` dep added.
- [x] Ensure `oxicrypto-pq` ML-KEM `DecapKey` / ML-DSA `SigningKey` newtype wrappers implement `Zeroize` (verified 2026-06-10)
  - **Verification:** `oxicrypto-pq/src/mlkem.rs:124` — `impl ZeroizeOnDrop for DecapKey512 {}`; `mlkem.rs:290` — `DecapKey768`; `mlkem.rs:451` — `DecapKey1024`. ML-DSA: `mldsa.rs:45` — `impl ZeroizeOnDrop for SigningKey44 {}`; `mldsa.rs:166` — `SigningKey65`; `mldsa.rs:287` — `SigningKey87`. Hybrid: `hybrid.rs:107` — `XWingSharedSecret` derives `Zeroize, ZeroizeOnDrop`; `XWing768DecapKey.x25519_sk` is `SecretKey<32>` (zeroize-on-drop).
- [x] Provide re-export of `subtle::ConstantTimeEq` for downstream crates to use without adding `subtle` directly
- [x] Ensure all downstream crates depend on `oxicrypto-core` for trait objects (no duplicated trait definitions) (verified 2026-06-10)
  - **Verification:** All sub-crates (`oxicrypto-sig`, `oxicrypto-kex`, `oxicrypto-pq`, `oxicrypto-rand`, etc.) list `oxicrypto-core.workspace = true` in their `Cargo.toml` and import traits exclusively via `use oxicrypto_core::{...}`. No crate defines its own `Hash`/`Kem`/`KeyAgreement`/`Rng`/etc. trait — all are consumed from the single `oxicrypto-core` source.

## Proposed follow-ups

- `api-debug-bound` (L60): Adding `Debug` as a supertrait on all core traits would be a breaking change. Resolution: propose adding `Debug` as an optional supertrait behind a `debug` Cargo feature flag in a future WI.
- `serde-cryptoerror` (L79): ~~Blocked on `oxicode`~~ **Completed 2026-06-03** — `oxicode` 0.2.3 available; `serde` feature implemented.
- `bench-cteq`, `profile-zeroize` (formerly L93, L94): **Completed 2026-06-19** — `oxicrypto-bench/benches/core.rs` implements all four benchmark groups.
