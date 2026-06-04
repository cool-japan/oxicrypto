# oxicrypto (facade) TODO

## Status
Facade crate (477 SLOC). Re-exports all subcrate types and provides algorithm selector enums (`HashAlgo`, `AeadAlgo`, `MacAlgo`, `SigAlgo`, `KexAlgo`, `KdfAlgo`) with factory functions returning boxed trait objects. Features: `pure` (default-on, all algorithms), `simd` (CPU feature detection), `pq-preview` (ML-KEM + ML-DSA). Known gaps: `SigAlgo` only has Ed25519 despite 6 signature algorithms being implemented; `KexAlgo` only has X25519; `KdfAlgo` only has HKDF variants.

## Core Implementation
- [x] Expand `SigAlgo` enum with all implemented algorithms: `Ed448`, `EcdsaP256`, `EcdsaP384`, `EcdsaP521`, `RsaPkcs1v15Sha256`, `RsaPkcs1v15Sha384`, `RsaPkcs1v15Sha512`, `RsaPssSha256` (~20 SLOC)
- [x] Expand `KexAlgo` enum: `X448`, `EcdhP256`, `EcdhP384`, `EcdhP521` (once implemented in oxicrypto-kex) (~10 SLOC)
- [x] Expand `KdfAlgo` enum: `Pbkdf2Sha256`, `Pbkdf2Sha512`, `Argon2id`, `Scrypt` (~10 SLOC) (planned 2026-05-25)
  - **Goal:** Add Pbkdf2Sha256, Pbkdf2Sha512, Argon2id, Scrypt variants to KdfAlgo enum; wire kdf_impl() dispatch
  - **Design:** Add variants to the existing `#[non_exhaustive] pub enum KdfAlgo`. For kdf_impl() dispatch, these password KDFs don't implement the Kdf trait (they use different function signatures). Create adapter structs: `struct Pbkdf2Sha256Adapter { iterations: u32 }`, etc., implementing Kdf trait by calling the underlying pbkdf2_sha256()/argon2id_derive()/scrypt_derive() functions with the stored parameters and treating `info` as additional salt material. Use sensible defaults (PBKDF2: 310_000 iterations, Argon2id: INTERACTIVE params, scrypt: INTERACTIVE params).
  - **Files:** `crates/oxicrypto/src/lib.rs`
  - **Prerequisites:** Standalone functions already re-exported from oxicrypto-kdf (pbkdf2_sha256, argon2id_derive, scrypt_derive)
  - **Tests:** kdf_impl(KdfAlgo::Argon2id).derive(b"password", b"salt", b"", &mut out) succeeds; kdf_impl(KdfAlgo::Pbkdf2Sha256).derive() returns consistent output
  - **Risk:** Moderate — adapting password KDF params to the Kdf::derive(ikm, salt, info, out) signature is a design decision; treat ikm as password, salt as salt, ignore info or use it as additional context
- [x] Expand `AeadAlgo` enum and `aead_impl()` dispatch (done 2026-05-25)
  - **Goal:** add `Aes128Ccm`, `Aes256Ccm` (and `Aes128Ocb3`/`Aes256Ocb3` iff SA-2 kept OCB3); wire `aead_impl()`; update Display/FromStr.
  - **Design:** read SA-2's report to know whether OCB3 shipped; add only what exists. Match SA-2's exact type names.
  - **Files:** `crates/oxicrypto/src/lib.rs`
  - **Tests:** aead_impl round-trip per new variant; Display/FromStr round-trip.
  - **Risk:** Low (Wave-2 sequencing removes the type-mismatch risk).
- [x] Expand `MacAlgo` enum and `mac_impl()` dispatch (done 2026-05-25)
  - **Goal:** add `CmacAes128`, `CmacAes256`, `Kmac128`, `Kmac256`, `Poly1305` variants; `mac_impl()` dispatches them to the SA-1 types. Update Display/FromStr for the new variants.
  - **Design:** match SA-1's exact type names. Document Poly1305 one-time contract.
  - **Files:** `crates/oxicrypto/src/lib.rs`
  - **Tests:** mac_impl returns working MAC for each new variant; Display/FromStr round-trip.
  - **Risk:** Low.
- [x] Update `signer_impl()` to handle all `SigAlgo` variants (requires adapting ECDSA/RSA structs to `Signer` trait or returning specialized types) (~80 SLOC)
- [x] Update `verifier_impl()` to handle all `SigAlgo` variants (~80 SLOC)
- [x] Update `kex_impl()` to handle all `KexAlgo` variants (~40 SLOC)
- [x] Update `kdf_impl()` to handle all `KdfAlgo` variants (~40 SLOC)
- [x] Add `aead_impl()` support for AES-GCM-SIV and XChaCha20 (requires trait implementation in aead crate first) (~20 SLOC)
- [x] Add `mac_impl()` support for new MAC algorithms (~20 SLOC)
- [x] Add `PqAlgo` enum and factory functions for post-quantum algorithms (behind `pq-preview`) (~40 SLOC) (planned 2026-05-25)
  - **Goal:** PqKemAlgo { MlKem512, MlKem768, MlKem1024 } and PqSigAlgo { MlDsa44, MlDsa65, MlDsa87 } enums with factory functions, behind pq-preview feature
  - **Design:** Two enums: `#[cfg(feature = "pq-preview")] #[non_exhaustive] pub enum PqKemAlgo { MlKem512, MlKem768, MlKem1024 }` and `#[cfg(feature = "pq-preview")] #[non_exhaustive] pub enum PqSigAlgo { MlDsa44, MlDsa65, MlDsa87 }`. Factory functions: `pq_kem_keygen(algo: PqKemAlgo, rng: &mut OxiRng) -> Result<(DecapKey, EncapKey), CryptoError>` dispatching to the appropriate ml-kem keygen. `pq_sign(algo: PqSigAlgo, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError>` and `pq_verify(algo: PqSigAlgo, vk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError>`.
  - **Files:** `crates/oxicrypto/src/lib.rs`
  - **Prerequisites:** oxicrypto-pq re-exports already available in pq module
  - **Tests:** pq_kem_keygen(PqKemAlgo::MlKem768, &mut rng) returns valid key pair; pq_sign/pq_verify round-trip for each MlDsa variant
  - **Risk:** Low — mechanical dispatch; PqSigAlgo depends on ML-DSA Signer/Verifier trait impls from oxicrypto-pq (SA-6)
- [x] Add `VersionInfo` struct and `version()` function (done 2026-05-25)
  - **Goal:** `oxicrypto::version() -> VersionInfo` with crate version (`env!("CARGO_PKG_VERSION")`), enabled feature flags (`cfg!`), and algorithm counts.
  - **Design:** plain struct with fields version_string, features_enabled: Vec<&'static str>, algorithm_counts: HashMap<&'static str, usize>; Display for human-readable summary.
  - **Files:** `crates/oxicrypto/src/lib.rs`
  - **Tests:** version string non-empty; feature flags reflect build; counts > 0.
  - **Risk:** Very low.
- [x] Add `available_algorithms() -> Vec<AlgorithmId>` (done 2026-05-25)
  - **Goal:** list all algorithms compiled in, gated by feature flags, using oxicrypto-core's `AlgorithmId`.
  - **Design:** build the Vec with `cfg!`-conditional pushes (pq entries behind `pq-preview`).
  - **Files:** `crates/oxicrypto/src/lib.rs`
  - **Tests:** contains SHA-256 always; contains ML-KEM-768 iff `pq-preview`.
  - **Risk:** Low.
- [x] Add top-level convenience functions: `oxicrypto::sha256(msg) -> [u8; 32]`, `oxicrypto::sha512(msg) -> [u8; 64]`, `oxicrypto::blake3(msg) -> [u8; 32]` (~30 SLOC) (planned 2026-05-25)
  - **Goal:** Top-level oxicrypto::sha256(), sha512(), blake3() convenience functions for one-shot hashing
  - **Design:** 
    `#[inline] pub fn sha256(msg: &[u8]) -> [u8; 32]` — creates Sha256 struct, calls hash() into fixed array
    `#[inline] pub fn sha512(msg: &[u8]) -> [u8; 64]` — creates Sha512 struct, calls hash() into fixed array
    `#[inline] pub fn blake3(msg: &[u8]) -> [u8; 32]` — creates Blake3 struct, calls hash() into fixed array
    All return fixed-size arrays (no allocation). These are pure wrappers, no error handling needed since these hashes cannot fail.
  - **Files:** `crates/oxicrypto/src/lib.rs`
  - **Prerequisites:** Hash types already re-exported from oxicrypto-hash
  - **Tests:** sha256(b"abc") == [0xba, 0x78, 0x16, ...] (known SHA-256 of "abc"); blake3(b"") matches blake3 crate's hash of empty; sha512(b"abc") matches known value
  - **Risk:** Very low

## Refactoring
- [x] Refactor lib.rs (1911→module tree) via splitrs (done 2026-05-25)
  - **Goal:** Split 1911-line lib.rs into module tree to stay under 2000-line policy limit.
  - **Result:** lib.rs shrunk to 299 lines; algo/{aead,hash,kdf,kex,mac,pq,sig}.rs + version.rs + tests.rs created.

## API Improvements
- [x] Make all `*Algo` enums `#[non_exhaustive]` to allow adding variants without breaking downstream
- [x] Add `Display` impl for all `*Algo` enums returning IANA-compatible algorithm names (planned 2026-05-25)
  - **Goal:** IANA/NIST-compatible algorithm name strings for all *Algo enums
  - **Design:** `impl fmt::Display for HashAlgo { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(match self { HashAlgo::Sha256 => "SHA-256", HashAlgo::Sha384 => "SHA-384", HashAlgo::Sha512 => "SHA-512", HashAlgo::Sha3_256 => "SHA3-256", HashAlgo::Sha3_384 => "SHA3-384", HashAlgo::Sha3_512 => "SHA3-512", HashAlgo::Blake3 => "BLAKE3", _ => "unknown" }) } }`. Repeat for AeadAlgo, MacAlgo, SigAlgo, KexAlgo, KdfAlgo. Use canonical IANA names. Add `use std::fmt;` if not already imported.
  - **Files:** `crates/oxicrypto/src/lib.rs`
  - **Prerequisites:** None
  - **Tests:** HashAlgo::Sha256.to_string() == "SHA-256"; every variant produces a non-empty string; no two variants in the same enum produce identical strings
  - **Risk:** Very low; the _ wildcard arm is for #[non_exhaustive] coverage
- [x] Add `FromStr` impl for all `*Algo` enums parsing IANA algorithm names (planned 2026-05-25)
  - **Goal:** Parse IANA algorithm names back to enum variants
  - **Design:** `impl std::str::FromStr for HashAlgo { type Err = CryptoError; fn from_str(s: &str) -> Result<Self, CryptoError> { match s { "SHA-256" | "SHA256" | "sha256" | "sha-256" => Ok(HashAlgo::Sha256), "SHA-384" | "SHA384" => Ok(HashAlgo::Sha384), ... _ => Err(CryptoError::UnsupportedAlgorithm) } } }`. Accept common aliases (with/without hyphens, upper/lower). Repeat for all enums.
  - **Files:** `crates/oxicrypto/src/lib.rs`
  - **Prerequisites:** Display impl (paired for round-trip testing)
  - **Tests:** "SHA-256".parse::<HashAlgo>() == Ok(HashAlgo::Sha256); round-trip algo.to_string().parse::<HashAlgo>() == Ok(algo) for all variants; "unknown".parse::<HashAlgo>() returns UnsupportedAlgorithm error
  - **Risk:** Very low
- [x] Add `TryFrom<&str>` for all `*Algo` enums (done 2026-05-25)
  - **Goal:** `TryFrom<&str>` delegating to existing `FromStr` for ergonomic TLS-style selection.
  - **Design:** `impl TryFrom<&str> for HashAlgo { type Error = CryptoError; fn try_from(s)=s.parse() }` for each enum (HashAlgo/AeadAlgo/MacAlgo/SigAlgo/KexAlgo/KdfAlgo).
  - **Files:** `crates/oxicrypto/src/lib.rs`
  - **Tests:** `HashAlgo::try_from("SHA-256")` ok; unknown errors.
  - **Risk:** Very low.
- [x] Add `prelude` module (done 2026-05-25)
  - **Goal:** `pub mod prelude { pub use ... }` exporting the core traits + CryptoError for glob import.
  - **Design:** re-export Hash/Aead/Mac/Signer/Verifier/KeyAgreement/Kdf/Rng/CryptoError (all already at crate root).
  - **Files:** `crates/oxicrypto/src/lib.rs`
  - **Tests:** a doctest `use oxicrypto::prelude::*;` compiles and uses a trait.
  - **Risk:** Very low.
- [x] Add `features!()` macro or function that lists enabled features at compile time (done 2026-05-26)
  - Added `enabled_features() -> Vec<&'static str>` in version.rs and re-exported at crate root
  - Returns feature names ("pure", "simd", "pq-preview", "std") for all actively compiled features
  - Tests added in crates/oxicrypto/tests/features.rs
- [x] Document each feature flag with full algorithm list in crate-level rustdoc (done 2026-05-26)
  - Added "Feature flag algorithm matrix" table to lib.rs crate-level doc comment
  - Added "Runtime feature introspection" section describing enabled_features() and available_algorithms()
- [x] Add example programs in `examples/` directory: encrypt.rs, sign.rs, hash.rs, kex.rs, pq_kem.rs (done 2026-06-03)
  - All five examples exist: `examples/{encrypt,sign,hash,kex,pq_kem}.rs`
  - encrypt.rs: HKDF-SHA-256 + AES-256-GCM seal/open with tamper-detection
  - hash.rs: SHA-256/SHA-512/BLAKE3 one-shot + SHA3-256 via trait object
  - sign.rs: Ed25519 keygen/sign/verify/tamper-detection via `signer_impl`/`verifier_impl`
  - kex.rs: X25519 DH + HKDF-SHA-256 + AES-256-GCM end-to-end
  - pq_kem.rs: ML-KEM-768 keygen/encap/decap (behind `pq-preview`)

## Testing
- [x] Cross-crate integration test: hash -> HMAC -> HKDF -> AEAD pipeline (derive key, encrypt, decrypt) (done 2026-05-25)
- [x] Cross-crate integration test: keygen -> sign -> verify for each signature algorithm (done 2026-05-25)
- [x] Cross-crate integration test: X25519 -> HKDF -> AES-GCM end-to-end key agreement + encryption (done 2026-05-25)
- [x] Cross-crate integration test: ML-KEM -> HKDF -> ChaCha20-Poly1305 post-quantum key exchange + encryption (done 2026-05-25, behind pq-preview)
- [x] Test: all factory functions return correct algorithm names (done 2026-05-25)
- [x] Test: all enum variants have unique string representations (done 2026-05-25)
- [x] Test: `new_rng()` returns a working CSPRNG
- [x] Test: `pq-preview` feature gate correctly hides/exposes PQ algorithms (done 2026-05-25)
- [x] Test: `simd` feature gate correctly enables CPU detection module (done 2026-06-03)
- [x] Test: default features include `pure` but not `simd` or `pq-preview` (done 2026-05-26)
  - Added test_default_features_include_pure and test_enabled_features_no_duplicates in tests/features.rs

## Performance
- [x] Benchmark factory function overhead: `hash_impl(HashAlgo::Sha256)` vs direct `oxicrypto_hash::Sha256` (done 2026-06-03)
  - Added `crates/oxicrypto-bench/benches/factory_overhead.rs` with four criterion groups:
    `factory_construction` (hash/aead/mac/kdf/kex factory vs direct Box::new),
    `dispatch_overhead` (dynamic Box<dyn Hash> vs monomorphic generic vs direct call, 4 sizes),
    `aead_dispatch_overhead` (Box<dyn Aead> vs concrete Aes256Gcm, 3 sizes),
    `kdf_dispatch_overhead` (Box<dyn Kdf> vs concrete HkdfSha256, 3 sizes).
  - Added `oxicrypto-aead` as a direct dep of oxicrypto-bench for the direct-type baseline.
- [x] Profile dynamic dispatch overhead of `Box<dyn Hash>` vs monomorphized generic calls (done 2026-06-03)
  - Covered by `dispatch_overhead/*` benchmarks in `factory_overhead.rs`: compares
    `dynamic_sha256` (vtable), `monomorphic_sha256` (generic fn<H: Hash>), and `direct_sha256`
    at 64/256/1024/4096-byte input sizes.
- [x] Consider adding inline-always hint on factory functions to minimize dispatch overhead (done 2026-06-03)
  - Upgraded `#[inline]` to `#[inline(always)]` on all seven factory functions:
    `hash_impl`, `aead_impl`, `mac_impl`, `kdf_impl`, `kex_impl`, `signer_impl`, `verifier_impl`.
  - With a literal-variant call site the optimizer can now fold the match branch entirely.

## Integration
- [x] Ensure facade stays synchronized with all subcrate public API additions (done 2026-05-30)
  - **Done:** Wired the 4 new subcrate algorithms into the facade. F1 `AeadAlgo::DeoxysII128` → `oxicrypto_aead::Deoxys2_128` (enum/Display/FromStr/`aead_impl`). F2 `SigAlgo::SchnorrBip340` → `oxicrypto_sig::SchnorrBip340` (same zero-sized type for `signer_impl`+`verifier_impl`; Display/FromStr). F3 `KdfAlgo::Balloon` via `BalloonAdapter: Kdf` composing `balloon_sha256` (extract, `BalloonParams::interactive()` = space_cost 16384 / time_cost 3) + `hkdf_sha256_expand` (arbitrary-length okm). F4 re-exports: new `pub use oxicrypto_hash::{parallel_hash128/256(+_xof), ParallelHash128/256, HashBuilder}` block; `Deoxys2_128`; `SchnorrBip340` + `schnorr_bip340_sign_with_aux`; Balloon fns + `BalloonHasher`/`BalloonParams`/`BalloonVariant` + `KeyStretcher`/`Stretcher`/`StretchParams` + the four `*StretchParams`. F5 tests added in `src/tests.rs` (Display/FromStr round-trips, round-trip/sign-verify/derive, reachability). F5 complete: added `AlgorithmId::{DeoxysII128, SchnorrBip340, Balloon}` (name + category arms) in `oxicrypto-core` (`DeoxysII128` → "Deoxys-II-128-128"/Aead, `SchnorrBip340` → "Schnorr-BIP340"/Signature, `Balloon` → "Balloon-SHA256"/Kdf) and wired all three into the facade `available_algorithms()`, per the IMPLEMENT POLICY. Validated: `cargo nextest run -p oxicrypto` 87 passed; `cargo clippy -p oxicrypto --all-targets -- -D warnings` clean; `cargo build -p oxicrypto --features pq-preview` ok.
  - **Plan:** facade-sync — expose the 4 new subcrate algorithms (Deoxys-II AEAD, BIP-340 Schnorr, Balloon KDF, ParallelHash) through the unified `oxicrypto` facade API. Single-crate change in `crates/oxicrypto`; ParallelHash is parameterized so it is re-exported, not an enum variant.
  - **F1 — `AeadAlgo::DeoxysII128`:** add `DeoxysII128` enum variant → `oxicrypto_aead::Deoxys2_128`; `Display` `=> "Deoxys-II-128-128"`; `FromStr` arms; `aead_impl` arm. Files: `src/algo/aead.rs`.
  - **F2 — `SigAlgo::SchnorrBip340`:** add `SchnorrBip340` enum variant → `oxicrypto_sig::SchnorrBip340` (same zero-sized type is both `Signer` and `Verifier`); `signer_impl` + `verifier_impl` arms; `Display` `=> "Schnorr-BIP340"`; `FromStr` arms. Files: `src/algo/sig.rs`.
  - **F3 — `KdfAlgo::Balloon`:** add `Balloon` enum variant via internal `BalloonAdapter: Kdf` (Balloon PRK via `balloon_sha256` + HKDF-SHA256-expand for arbitrary `okm_out`); `name()` `"Balloon-SHA256"`; `Display`/`FromStr`/`kdf_impl` arms. Files: `src/algo/kdf.rs`.
  - **F4 — facade `pub use` re-exports:** ParallelHash fns/types (`parallel_hash128/256`, `*_xof`, `ParallelHash128/256`), Balloon fns + `BalloonHasher`/`BalloonParams`, `KeyStretcher`/`Stretcher`/`StretchParams`; plus `Deoxys2_128`, `SchnorrBip340`. Files: `src/lib.rs`.
  - **F5 — wiring + tests:** update `available_algorithms()` to include `DeoxysII128`/`SchnorrBip340`/`Balloon`; add Display/FromStr round-trip tests for the new variants; do NOT add them to `Suite::TLS13`/`PqSuite` presets. Files: `src/lib.rs`/`src/version.rs`, `src/tests.rs`.
- [x] `Suite::TLS13` / `Suite::PQ_TLS13` algorithm suite presets (done 2026-05-25)
  - **Goal:** named algorithm-suite presets bundling hash/aead/sig/kex/kdf selections.
  - **Design:** `pub struct Suite { pub hash: HashAlgo, pub aead: AeadAlgo, pub sig: SigAlgo, pub kex: KexAlgo, pub kdf: KdfAlgo }` with consts `TLS13` (AES-256-GCM, SHA-384, Ed25519, X25519, HKDF-SHA-384) and `PQ_TLS13` (AES-256-GCM, SHA-384, ML-DSA-65, ML-KEM-768, HKDF-SHA-384, behind `pq-preview`).
  - **Files:** `crates/oxicrypto/src/lib.rs`
  - **Tests:** preset fields match expected variants; factory funcs accept them.
  - **Risk:** Low.
- [x] SA-8: Wire SLH-DSA into PqSigAlgo + Display/FromStr (done 2026-05-25)
  - Added `SlhDsaSha2_128s`, `SlhDsaSha2_128f`, `SlhDsaSha2_256s`, `SlhDsaSha2_256f`, `SlhDsaShake128s`, `SlhDsaShake128f` variants to `PqSigAlgo`
  - Updated `pq_sig_generate()` dispatch for all 9 variants
  - Updated `Display` / `FromStr` / `TryFrom<&str>` for all 9 variants
- [x] SA-8: Wire AES-SIV — NOTE: AES-SIV dropped (aead 0.6 incompatible); AES-KW added instead (done 2026-05-25)
  - `AesKeyWrap128`/`AesKeyWrap256` variants added to `AlgorithmId` in oxicrypto-core
- [x] SA-8: Re-export AES Key Wrap + SealedBox (done 2026-05-25)
  - `aes128_key_wrap`, `aes128_key_unwrap`, `aes256_key_wrap`, `aes256_key_unwrap` re-exported
  - `seal_box`, `open_box`, `seal_with_random_nonce` re-exported
- [x] SA-8: Update available_algorithms() for new IDs (done 2026-05-25)
  - Added `AesKeyWrap128`, `AesKeyWrap256` to AEAD section (always)
  - Added all 6 SLH-DSA variants behind `pq-preview` feature
- [x] Extend SLH-DSA to 10 parameter sets in facade (done 2026-05-26)
  - Added `SlhDsaSha2_192s`, `SlhDsaSha2_192f`, `SlhDsaShake256s`, `SlhDsaShake256f` to `PqSigAlgo`
  - Added 4 new variants to `AlgorithmId` in oxicrypto-core
  - Updated `pq_sig_generate()`, `Display`, `FromStr`, `available_algorithms()`
- [x] SA-8: Update PqSuite with SLH-DSA option (done 2026-05-25)
  - Added `PqSuite::PQ_TLS13_HASH_BASED` constant using `SlhDsaShake128f`
- [x] Ensure `oxicrypto-bench` uses facade factory functions for consistent benchmarking (done 2026-06-03)
  - All bench files (hash, aead, mac, kdf, kex, sig) already import and use `hash_impl`/`aead_impl`/etc.
  - `factory_overhead.rs` explicitly benchmarks factory vs direct-instantiation for each algorithm family.
- [x] Coordinate with OxiTLS for TLS 1.3 cipher suite negotiation using facade enums (done 2026-06-03: guidance documented in facade)
  - **Architecture guidance added:** The `oxicrypto` facade `lib.rs` now documents which types to use for TLS 1.3 construction. The TLS 1.3 standard (RFC 8446) mandates specific algorithm combinations; the facade already exposes all required primitives. Full automated cipher-suite negotiation (where OxiTLS accepts `oxicrypto` facade enums directly) requires an API addition on the OxiTLS side — blocked on external project. In the interim, the doc comment in `oxicrypto/src/lib.rs` guides OxiTLS integrators to the correct type choices.
