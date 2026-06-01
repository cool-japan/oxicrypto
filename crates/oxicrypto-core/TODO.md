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
- [ ] Add `Debug` bound requirement on all trait objects (currently not enforced)
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
- [ ] Derive `serde::Serialize` / `serde::Deserialize` on `CryptoError` behind a `serde` feature flag (use `oxicode` for serialization backend per COOLJAPAN policy)
- [ ] Document minimum key length requirements in trait-level rustdoc for `Mac`, `Aead`, `Kdf`
- [ ] Add `const` associated constants on trait impls (e.g., `const OUTPUT_LEN: usize`) where possible for compile-time usage

## Testing
- [ ] Property test: `SecretKey` zeroize-on-drop actually zeroes memory (use `std::ptr::read_volatile` in test)
- [ ] Property test: `ct_eq` returns same result as `==` for all u8 slices up to 256 bytes
- [ ] Fuzz test: `CryptoError::Display` round-trip does not panic on any variant
- [ ] Test: `StreamingHash` trait produces identical output to one-shot `Hash::hash` for chunked inputs
- [ ] Test: `KeyPair` drops secret key bytes on scope exit
- [ ] Test: all error variants are distinguishable via `PartialEq`

## Performance
- [ ] Ensure `SecretKey<N>` is stack-allocated with no heap indirection for N <= 64
- [ ] Benchmark `ct_eq` vs naive `==` to verify constant-time property has acceptable overhead
- [ ] Profile `Zeroize` overhead on `SecretVec` drop path

## Integration
- [ ] Ensure `oxicrypto-sig` Ed448/ECDSA/RSA types use `SecretKey` wrapper for private key storage
- [ ] Ensure `oxicrypto-kex` X25519 uses `SecretKey<32>` for static secrets
- [ ] Ensure `oxicrypto-rand` OxiRng seed uses `SecretKey<32>` wrapper
- [ ] Ensure `oxicrypto-pq` ML-KEM `DecapKey` / ML-DSA `SigningKey` newtype wrappers implement `Zeroize`
- [x] Provide re-export of `subtle::ConstantTimeEq` for downstream crates to use without adding `subtle` directly
- [ ] Ensure all downstream crates depend on `oxicrypto-core` for trait objects (no duplicated trait definitions)
