# oxicrypto-sig TODO

## Status
Comprehensive signature suite (~7,200 SLOC across 17 files, including tests). Implements Ed25519 (RFC 8032, plus batch verify and `ctx`/`ph` extended modes) with `Signer`/`Verifier` traits, Ed448 (RFC 8032 §5.2, plus `ctx`/`ph`), ECDSA P-256/P-384/P-521 (FIPS 186-5, RFC 6979-deterministic, DER + raw `SignatureFormat`, and a runtime-selectable `CurveId` constructor), RSA PKCS#1v1.5 and RSA-PSS (SHA-256/384/512) with key generation, PEM/PKCS#1 import-export, and RSA-OAEP encryption, Schnorr BIP-340, FROST(Ed25519, SHA-512) threshold signatures, MuSig2 (Ed25519 n-of-n multisig), and a `tls` module negotiating a `Signer`/`Verifier` pair from a TLS 1.3 `SignatureScheme`. Key generation is implemented for every algorithm family. 226 tests pass (`cargo nextest run -p oxicrypto-sig --all-features`, verified 2026-07-17). Upstream deps `rsa 0.10.0-rc.18`, `p256`/`p384`/`p521`/`k256 0.14.0-rc.15`, `ed448-goldilocks 0.14.0-pre.15` remain release candidates (re-verified 2026-07-17).

## Core Implementation
- [x] Add Ed25519 batch verification using `ed25519_dalek::verify_batch()` for verifying multiple signatures in a single operation (~40 SLOC) (planned 2026-05-25)
  - **Goal:** ed25519_verify_batch(messages, signatures, public_keys) -> Result<(), CryptoError> using ed25519-dalek's verify_batch()
  - **Design:** `pub fn ed25519_verify_batch(messages: &[&[u8]], signatures: &[ed25519_dalek::Signature], verifying_keys: &[ed25519_dalek::VerifyingKey]) -> Result<(), CryptoError>`. Call `ed25519_dalek::verify_batch(messages, signatures, verifying_keys)` and map the error to `CryptoError::InvalidSignature`. All slices must have the same length; return CryptoError::BadInput if lengths differ.
  - **Files:** `crates/oxicrypto-sig/src/lib.rs`
  - **Prerequisites:** ed25519-dalek already a workspace dep; verify_batch is in it
  - **Tests:** Batch of 5 valid sign/verify pairs succeeds; batch with one tampered signature fails; empty batch succeeds; mismatched slice lengths return error
  - **Risk:** ed25519_dalek::verify_batch exists but check exact import path in 2.2.0
- [x] Add Ed25519ctx and Ed25519ph (prehash) variants per RFC 8032 Sections 5.1.5-5.1.6 (~60 SLOC) (implemented 2026-06-03)
  - **Result:** `crates/oxicrypto-sig/src/ed25519_ext.rs` — `ed25519ctx_sign()`, `ed25519ctx_verify()`, `ed25519ph_sign()`, `ed25519ph_verify()`, `ed25519ph_sign_prehash()`, `ed25519ph_verify_prehash()`. Implemented directly using `curve25519-dalek 4.x` (`EdwardsPoint`, `Scalar`, `clamp_integer`) + SHA-512, bypassing `ed25519-dalek`'s `sign_prehashed`/`with_context` APIs which are gated behind `digest 0.10` (incompatible with workspace `digest 0.11`). The `dom2(phflag, ctx)` prefix construction follows RFC 8032 §5.1.5 exactly. Both variants are deterministic (no randomness in signing). Domain separation from plain Ed25519 is verified: Ed25519ctx signatures do NOT verify under standard `ed25519-dalek` verification. 18 tests pass including round-trip, corruption, context mismatch, determinism, empty context, max context (255 bytes), and cross-variant separation.
  - **Architecture note:** Used `curve25519-dalek 4.x` primitives instead of `ed25519-dalek` higher-level API to avoid the `digest 0.10` version mismatch. When `ed25519-dalek` eventually upgrades to `digest 0.11`, these functions can optionally be reimplemented using dalek's own `sign_prehashed`/`with_context` for byte-for-byte compatible results.
- [x] Add Ed448ph prehash variant per RFC 8032 Section 5.2.5 (~40 SLOC) (implemented 2026-05-26)
  - **Result:** `crates/oxicrypto-sig/src/ed448_ext.rs` — `ed448ph_sign()` and `ed448ph_verify()` using SHAKE-256 via `PreHasherXof<Shake256>` (ed448-goldilocks's own sha3 0.11 re-export for type compatibility). Also added `ed448ctx_sign()` and `ed448ctx_verify()` for context-domain-separated signing without prehash.
- [x] Add BIP-340 Schnorr signatures over secp256k1 for Bitcoin/Lightning compatibility using `k256` crate (~100 SLOC) (implemented 2026-05-30)
  - **Result:** `crates/oxicrypto-sig/src/schnorr.rs` — `SchnorrBip340` zero-sized struct implementing `Signer`/`Verifier` over the pure-Rust `k256` (0.14.0-rc.9) `schnorr` module. 32-byte secret key, 32-byte x-only public key, 64-byte signature. Inherent `sign_with_aux(sk, msg, aux32)` (explicit BIP-340 aux-rand via `k256` `sign_raw`), `derive_public_key`, `parse_public_key`/`parse_secret_key` (lift_x / scalar validation + round-trip), and a documented SHA-256 pre-hash convenience `sign_sha256`/`verify_sha256`. Trait `sign` uses the deterministic all-zero-aux path (documented); `verify` maps failure to `CryptoError::Sign`. Secret material wrapped in `SecretKey<32>` (zeroize). No `unwrap`/`expect` in production code. Added `k256 = { version = "0.14.0-rc.9", default-features = false, features = ["schnorr", "alloc"] }` to the root workspace manifest and `k256.workspace = true` to the crate. Verified against ALL 19 official BIP-340 vectors (see test item below).
  - **Goal:** `SchnorrBip340` signer/verifier implementing the crate's `Signer`/`Verifier` pattern: 32-byte secret key, 32-byte x-only public key, 64-byte signature, BIP-340 tagged-hash nonce, verified against the official BIP-340 vectors.
  - **Design (ultrathink):** Implement over the pure-Rust `k256` crate (secp256k1) using its `schnorr` module (BIP-340) for the field/group + tagged-hash machinery; the value-add is trait integration, x-only key handling, `SecretKey`/zeroize wrapping, aux-rand nonce support, and explicit BIP-340 semantics (even-Y normalization, `lift_x`, challenge `e = tagged_hash("BIP0340/challenge", R_x‖P_x‖m) mod n`). Provide `sign`/`sign_with_aux` and `verify`. BIP-340 signs a 32-byte message digest; expose `sign_digest`/`verify_digest` plus a `sign(msg)` that hashes with SHA-256 (clearly documented). Add `k256 = { workspace = true, features = ["schnorr"] }` (latest on crates.io; pure Rust). Keep all new code in `src/schnorr.rs` — no `unwrap()`.
  - **Files:** new `crates/oxicrypto-sig/src/schnorr.rs`; edit `src/lib.rs`; edit `Cargo.toml` (add `k256` with `schnorr`). Facade *(stretch)*: `SigAlgo::SchnorrBip340` arm in `crates/oxicrypto/src/algo/sig.rs`.
  - **Prerequisites:** secp256k1 + Schnorr come from `k256` (pure Rust). No new field math.
  - **Tests:** the official BIP-340 `test-vectors.csv` (the canonical ~15 cases: valid signatures, `lift_x` edge cases, public-key-not-on-curve, malleability/invalid-R rejections) in `tests/kat_bip340.rs`; round-trip sign/verify; wrong-key and tampered-signature negatives; x-only key parsing round-trip.
  - **Risk:** k256 `schnorr` API surface (digest vs message, aux-rand) and x-only key encoding. Mitigation: lock to the official CSV vectors; cover both deterministic (aux=0) and the all-zero/edge vectors; return `deviated` if any official vector fails.
- [x] Add ECDSA deterministic nonce generation per RFC 6979 (verify default in p256/p384/p521 — document if so) (~20 SLOC) (implemented 2026-06-03)
  - **Goal:** Document that ECDSA signs deterministically per RFC 6979 by default in this crate.
  - **Design:** Verify the `p256`/`p384`/`p521` crates use RFC 6979 (they do — `ecdsa` crate always enables deterministic ECDSA). Add a doc comment to each ECDSA signer's `sign` method: "Signatures are deterministic per RFC 6979."
  - **Files:** `src/ecdsa_p256.rs`, `ecdsa_p384.rs`, `ecdsa_p521.rs`. **Tests:** Verify same input always produces same signature. **Risk:** Low.
- [x] Add ECDSA batch verification for P-256/P-384 using multi-scalar multiplication (~80 SLOC) (implemented 2026-06-03)
  - **Goal:** `ecdsa_p256_verify_batch` and `ecdsa_p384_verify_batch` convenience functions providing a sequential-verify batch API (note: ECDSA is not batchable like EdDSA; this is a sequential loop API matching `ed25519_verify_batch` in style).
  - **Design:** `pub fn ecdsa_p256_verify_batch(verifiers: &[EcdsaP256Verifier], messages: &[&[u8]], signatures: &[&[u8]]) -> Result<(), CryptoError>` — validates lengths match, iterates, returns first error. Document: sequential, not parallel. Same for P-384.
  - **Files:** `src/lib.rs`. **Tests:** `test_ecdsa_p256_batch_verify_pass`, `test_ecdsa_p256_batch_verify_tamper`. **Risk:** Low.
- [x] Add RSA-PSS with SHA-384 and SHA-512 (currently only SHA-256) (~60 SLOC) (planned 2026-05-25)
  - **Goal:** RsaPssSha384Signer/Verifier and RsaPssSha512Signer/Verifier — extending existing RSA-PSS SHA-256 pattern
  - **Design:** In rsa_sig.rs, duplicate the RsaPssSha256Signer/Verifier implementation twice, substituting sha2::Sha384 and sha2::Sha512 respectively. In lib.rs, add `RsaPssSha384`, `RsaPssSha512` variants to the Signer/Verifier unit-struct pattern with dispatch arms. The rsa crate's Pss::sign() takes a generic hash type, so changing Sha256 to Sha384/Sha512 is a one-line change per struct.
  - **Files:** `crates/oxicrypto-sig/src/rsa_sig.rs`, `crates/oxicrypto-sig/src/lib.rs`
  - **Prerequisites:** None — rsa crate already a dep with sha2 integration
  - **Tests:** RSA-PSS-SHA384 sign/verify round-trip with a test 2048-bit key; RSA-PSS-SHA512 sign/verify round-trip; tampered signature fails verification
  - **Risk:** Low — mechanical duplication; RSA test key generation is slow, use pre-baked test keys
- [x] Add RSA-OAEP encryption/decryption (PKCS#1 v2.2) for key transport scenarios (~100 SLOC) (implemented 2026-05-26)
  - **Result:** `rsa_oaep_sha256_encrypt(pk_der, plaintext)` and `rsa_oaep_sha256_decrypt(sk_der, ciphertext)` using `oaep::EncryptingKey<Sha256>` and `oaep::DecryptingKey<Sha256>`. Uses `UnwrapErr(SysRng)` for `CryptoRng`-compatible entropy. Tests are `#[ignore]` due to RSA keygen latency.
- [x] Add RSA key generation: `rsa_generate_keypair(bit_size)` for 2048/3072/4096-bit keys (~60 SLOC) (implemented 2026-05-26)
  - **Result:** `rsa_generate_keypair(bit_size: usize)` in `rsa_sig.rs`. Enforces minimum 2048 bits (returning `CryptoError::BadInput` below), returns `(pkcs8_der_sk, spki_der_pk)`. Uses `UnwrapErr(SysRng)` to bridge to `CryptoRng`. Tests marked `#[ignore]` due to 1-3s generation time.
- [x] Add Ed25519 key generation: `Ed25519KeyPair::generate(rng)` returning seed + public key (~30 SLOC) (planned 2026-05-25)
  - **Goal:** ed25519_generate_keypair(rng) -> Result<(ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey), CryptoError>
  - **Design:** `pub fn ed25519_generate_keypair(rng: &mut impl rand_core::CryptoRngCore) -> Result<(ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey), CryptoError>`. Call `ed25519_dalek::SigningKey::generate(rng)` and return `(signing_key, signing_key.verifying_key())`. The caller can use the signing_key.to_bytes() for the raw seed and verifying_key.to_bytes() for the raw public key if needed.
  - **Files:** `crates/oxicrypto-sig/src/lib.rs`
  - **Prerequisites:** ed25519-dalek already a workspace dep
  - **Tests:** Generate keypair; sign a known message with the signing key; verify with the verifying key; verify the round-trip works
  - **Risk:** Low — ed25519-dalek::SigningKey::generate() takes CryptoRngCore; OxiRng satisfies this via TryCryptoRng
- [x] Add ECDSA key generation for P-256/P-384/P-521: `EcdsaP256KeyPair::generate(rng)` (~50 SLOC) (planned 2026-05-25)
  - **Goal:** Functions to generate ECDSA key pairs for P-256, P-384, and P-521 curves
  - **Design:** 
    `pub fn ecdsa_p256_generate_keypair(rng: &mut impl rand_core::CryptoRngCore) -> Result<(p256::SecretKey, p256::PublicKey), CryptoError>`
    `pub fn ecdsa_p384_generate_keypair(rng: &mut impl rand_core::CryptoRngCore) -> Result<(p384::SecretKey, p384::PublicKey), CryptoError>`  
    `pub fn ecdsa_p521_generate_keypair(rng: &mut impl rand_core::CryptoRngCore) -> Result<(p521::SecretKey, p521::PublicKey), CryptoError>`
    Each uses `SecretKey::random(rng)` from the respective crate. Return the secret key and its corresponding public key.
  - **Files:** `crates/oxicrypto-sig/src/lib.rs`, `crates/oxicrypto-sig/src/ecdsa_p256.rs`, `crates/oxicrypto-sig/src/ecdsa_p384.rs`, `crates/oxicrypto-sig/src/ecdsa_p521.rs`
  - **Prerequisites:** p256, p384, p521 crates already workspace deps
  - **Tests:** Generate P-256 keypair; sign "hello" using EcdsaP256Signer (from generated secret key bytes); verify with EcdsaP256Verifier (from generated public key bytes). Same for P-384 and P-521.
  - **Risk:** Moderate — p256/p384/p521 are pre-release RCs; SecretKey::random() API may differ. Use elliptic_curve::rand_core::CryptoRngCore bound.
- [x] Add `Signer`/`Verifier` trait implementations for ECDSA P-256/P-384/P-521 (currently only inherent methods) (~120 SLOC)
- [x] Add `Signer`/`Verifier` trait implementations for Ed448 (currently only inherent methods) (~60 SLOC)
- [x] Add `Signer`/`Verifier` trait implementations for all RSA variants (currently only inherent methods) (~120 SLOC)
- [x] Add threshold signatures (t-of-n) framework for Ed25519 using FROST (Flexible Round-Optimized Schnorr Threshold) (~200 SLOC) (done 2026-05-30)
  - **Result (2026-05-30):** `crates/oxicrypto-sig/src/frost/{mod,keygen,round1,round2,aggregate}.rs` + `tests.rs` implement RFC 9591 FROST(Ed25519, SHA-512), contextString `"FROST-ED25519-SHA512-v1"`. Group math via direct dep `curve25519-dalek 4.1.3` (`Scalar` mod ℓ, `EdwardsPoint`, `ED25519_BASEPOINT_POINT`, `from_bytes_mod_order_wide`); exactly one curve25519-dalek in the tree (shared with ed25519-dalek 2.2.0). H1/H3/H4/H5 are context-prefixed SHA-512; H2 is **plain SHA-512 (no context)** → the FROST challenge equals the Ed25519 challenge. Trusted-dealer Shamir keygen (derandomized `trusted_dealer_keygen_with_coefficients` + randomized `trusted_dealer_keygen`), 2-round signing (`commit`/`commit_with_randomness`, `sign`), `aggregate`, partial-share `verify_signature_share`, and `verify_signature` (FROST group equation **and** standard Ed25519 strict verify). Nonces/shares/polynomial coefficients zeroize on drop; no `unwrap`/`expect` in production. Reproduces the official RFC 9591 §E.1 vector byte-for-byte: group public key, all 3 shares, P1/P3 nonces+commitments, P1 binding_factor_input, both binding factors, group commitment R, both sig shares, and the final 64-byte signature. 12 FROST tests (114 crate tests total) pass; clippy clean with `-D warnings`. Validated DEFAULT features only (`-p oxicrypto-sig`).
  - **Goal:** RFC 9591 FROST(Ed25519,SHA-512) (contextString "FROST-ED25519-SHA512-v1"); signatures verify under standard Ed25519. Trusted-dealer keygen + 2-round signing + aggregation + partial-share verify, KAT-verified.
  - **Design:** curve25519-dalek group math (Scalar mod ℓ, EdwardsPoint, ED25519_BASEPOINT_POINT, Scalar::from_bytes_mod_order_wide). H1=SHA512(ctx‖"rho"‖m) mod ℓ; H2=SHA512(m) mod ℓ (plain, NO ctx — yields the Ed25519 challenge); H3=SHA512(ctx‖"nonce"‖m) mod ℓ. Shamir dealer split (deg t−1, shares s_i=f(i), PK=s·B, PK_i=s_i·B); round1 nonces (d_i,e_i), commitments (D_i=d_i·B,E_i=e_i·B); round2 ρ_i=H1(id‖commitlist‖m), R=Σ(D_i+ρ_i·E_i), c=H2(R‖PK‖m), Lagrange λ_i, z_i=d_i+e_i·ρ_i+λ_i·s_i·c; aggregate z=Σz_i, sig=(R,z); verify z·B==R+c·PK. Zeroize nonces/shares; no unwrap/expect in production.
  - **Files:** crates/oxicrypto-sig/src/frost/{mod,keygen,round1,round2,aggregate}.rs (+ `pub mod frost;` in lib.rs); Cargo.toml gains curve25519-dalek.workspace=true (added to root [workspace.dependencies] at latest crates.io version). Each file <2000 lines.
  - **Tests:** RFC 9591 FROST(Ed25519,SHA-512) test vectors (t=2,n=3 fixed shares/nonces/msg → exact (R,z) group signature); partial-share verification; signer-subset independence; tamper negatives; cross-verify with standard Ed25519.
  - **Risk:** H1/H2 domain separation (Ed25519's plain-SHA512 challenge) + cofactor handling are the correctness traps → implement vectors-first. Validate with DEFAULT features only (-p oxicrypto-sig); never --all-features at the oxicrypto workspace level (aws-lc/pkcs11 C-FFI adapters break it).
- [x] Add multisig aggregation for Ed25519: MuSig2 protocol for key aggregation and multi-party signing (~150 SLOC) (planned 2026-06-02)
  - **Goal:** A dealer-free n-of-n MuSig2 scheme over Ed25519 whose aggregate `(R, s)` verifies under standard Ed25519 verification against the aggregated public key. Built from group math the FROST module already exposes.
  - **Design:** New `src/musig2.rs`. Reuse FROST helpers (`scalar_base_mult`, `serialize_element`, `deserialize_element`, `serialize_scalar`, `deserialize_scalar`, `h2`, `reduce_wide`, `sha512_concat` widened to `pub(crate)`). Key aggregation: `L = H_agg("MuSig2-Ed25519-v1/keyagg/coeffs" ‖ sorted_P_bytes)`, `a_i = H_agg("…/keyagg/coeff" ‖ L ‖ P_i) mod ℓ`, `X̃ = Σ aᵢ·Pᵢ`. Round 1: each signer samples two nonces `(r₁,r₂)`, publishes `(R₁ᵢ,R₂ᵢ)`. `SecNonce` is move-only, zeroized, single-use enforced by type system. Aggregate nonces: `R₁=ΣR₁ᵢ`, `R₂=ΣR₂ᵢ`; binding `b=H_non("…/noncecoef" ‖ X̃ ‖ R₁ ‖ R₂ ‖ m) mod ℓ`; `R=R₁+b·R₂`. Challenge (Ed25519-compatible): `c=h2(R_compressed ‖ X̃_compressed ‖ m)` (plain SHA-512). Partial sig: `sᵢ=rᵢ₁+b·rᵢ₂+c·aᵢ·xᵢ mod ℓ`; aggregate `s=Σsᵢ`. Signature = `serialize_element(R) ‖ serialize_scalar(s)`.
  - **Files:** `src/musig2.rs` (new), `src/lib.rs` (add `pub mod musig2`), `src/frost/mod.rs` (widen `sha512_concat` to `pub(crate)` if needed).
  - **Tests:** 2-of-2 and 3-of-3 round-trip → aggregate verifies under `ed25519_dalek::VerifyingKey::verify`; rogue-key resistance; tamper negatives (wrong msg / wrong partial); single-use nonce enforced. Document in-test: no standard Ed25519-MuSig2 KAT exists — validation is property-based.
  - **Risk:** Security-critical. Two-nonce construction is mandatory (single-nonce MuSig is broken by Wagner/ROS). No shortcuts on binding-coefficient placement or key-agg domain separation.
- [x] Add PEM import/export for RSA keys: `from_pem` / `to_pem` (~40 SLOC) (planned 2026-06-02)
  - **Goal:** RSA signer/verifier keys loadable/saveable as PEM strings alongside existing DER.
  - **Design:** In `src/rsa_sig.rs`, add `from_pkcs8_pem(pem: &str) -> Result<Self, CryptoError>` and `to_pkcs8_pem(&self) -> Result<String, CryptoError>` methods on each RSA signer/verifier struct, delegating to `rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey}` PEM variants. Add PKCS#1 PEM variants `from_pkcs1_pem`/`to_pkcs1_pem` too. If the `pem` feature on `rsa` is not yet resolved, add `rsa = { workspace = true, features = ["pem"] }` to `Cargo.toml`. Map errors to `CryptoError::InvalidKey`.
  - **Files:** `src/rsa_sig.rs`, `Cargo.toml` (conditional).
  - **Tests:** generate → export PKCS#8 PEM → re-import → sign/verify round-trip; export PKCS#1 PEM → re-import → verify same key; reject malformed PEM (no panic).
  - **Risk:** Low. Only risk is `pem` feature toggle; code is mechanical.
- [x] Add PKCS#1 DER import for RSA keys in addition to PKCS#8 (~30 SLOC) (planned 2026-06-02)
  - **Goal:** RSA keys importable from PKCS#1 DER (traditional OpenSSL format) alongside PKCS#8.
  - **Design:** Add `from_pkcs1_der(der: &[u8]) -> Result<Self, CryptoError>` constructors on RSA signer/verifier structs, delegating to `rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey}`. Add `to_pkcs1_der(&self) -> Result<Vec<u8>, CryptoError>` exporters via `EncodeRsaPrivateKey`/`EncodeRsaPublicKey`. `pkcs1 0.8.0-rc.4` is already in tree via the `encoding` feature — no Cargo change needed.
  - **Files:** `src/rsa_sig.rs`.
  - **Tests:** PKCS#1 DER import → sign/verify; verify parity with PKCS#8 import of the same key; malformed DER rejected with `InvalidKey` (no panic).
  - **Risk:** Low. `pkcs1` traits already in dependency tree.

## API Improvements
- [x] Update `SigAlgo` enum in facade to include all implemented algorithms (planned 2026-06-02)
  - **Goal:** `SigAlgo` has `RsaPssSha384` and `RsaPssSha512` variants so all RSA-PSS variants in the sub-crate are selectable.
  - **Design:** Add `RsaPssSha384` and `RsaPssSha512` to `SigAlgo` in `oxicrypto/src/algo/sig.rs`; add 2 new arms to `signer_impl()` and `verifier_impl()` (structs `RsaPssSha384`/`RsaPssSha384Verify`/`RsaPssSha512`/`RsaPssSha512Verify` exist in the sub-crate); update `available_algorithms()` in `version.rs`.
  - **Files:** `oxicrypto/src/algo/sig.rs`, `oxicrypto/src/version.rs`, `oxicrypto/src/tests.rs`.
  - **Tests:** `signer_impl(SigAlgo::RsaPssSha384)` + `verifier_impl(...)` sign→verify; same for Sha512; `available_algorithms()` includes new IDs.
  - **Risk:** Low — additive; existing sub-crate structs. Also extends `signer_impl`/`verifier_impl` (L73 is part of this same WI).
- [x] Add `signer_impl()` / `verifier_impl()` facade factory functions for all algorithms (planned 2026-06-02)
  - **Goal:** Factory functions complete for all sig algorithms including the two new RSA-PSS variants (part of L72 WI-1 facade completion).
  - **Design:** New arms in `signer_impl()` / `verifier_impl()` in `oxicrypto/src/algo/sig.rs` for `RsaPssSha384` and `RsaPssSha512`. Implementation is part of WI-1 (facade completion).
  - **Files:** `oxicrypto/src/algo/sig.rs`.
  - **Tests:** Covered by L72 tests.
  - **Risk:** Low.
- [x] Unify ECDSA signer/verifier construction: `EcdsaSigner::new(curve, scalar)` with curve enum instead of separate types per curve (done 2026-06-19 — `CurveId` enum (P256/P384/P521) + `with_ecdsa_signer(CurveId) -> Box<dyn Fn>` + `with_ecdsa_verifier(CurveId) -> Box<dyn Fn>` added to `src/lib.rs`; 5 tests: P256/P384/P521 round-trip, cross-curve rejection, enum distinctness)
  - **Goal:** Add a `CurveId` enum + `EcdsaSigner::with_curve` constructor as an ergonomic alternative to the per-curve types.
  - **Files:** `src/lib.rs`. **Risk:** Low — additive.
- [x] Add `SignatureFormat` enum: `Der`, `Raw`, `Compact` for ECDSA signature encoding selection (implemented 2026-06-03)
  - **Goal:** ECDSA signers/verifiers gain `sign_fmt(msg, fmt)` and `verify_fmt(msg, sig, fmt)` inherent methods.
  - **Design:** `pub enum SignatureFormat { Der, Raw }`. `Raw` = r||s big-endian (64/96/132 bytes). `Der` = current ASN.1 path. Add inherent methods on each ECDSA signer/verifier. Not on the `Signer`/`Verifier` trait.
  - **Files:** `src/lib.rs`, `src/ecdsa_p256.rs`, `ecdsa_p384.rs`, `ecdsa_p521.rs`. **Risk:** Low — additive inherent methods.
- [x] Add `verify_prehash(pk, hash, sig)` for pre-hashed message verification (implemented 2026-06-03)
  - **Goal:** ECDSA verifiers gain `verify_prehash(&self, hash: &[u8], sig: &[u8]) -> Result<(), CryptoError>` for large-message scenarios.
  - **Design:** Use `ecdsa::hazmat::VerifyPrimitive` from `p256`/`p384`/`p521` (may need `hazmat` feature). Check `p256 0.14-rc` API first; if `hazmat` feature needed, add per-crate feature override.
  - **Files:** `src/ecdsa_p256.rs`, `ecdsa_p384.rs`, `ecdsa_p521.rs`, sig `Cargo.toml` (conditional). **Tests:** `test_ecdsa_verify_prehash`. **Risk:** Low-moderate.
- [~] Wrap private key bytes in `SecretKey` from `oxicrypto-core` with `Zeroize` semantics (partial 2026-06-03 — EcdsaP256KeyPair/EcdsaP384KeyPair added with Zeroize; full SecretKey<N> wrapping deferred due to per-sign reconstruction overhead)
  - **Goal:** ECDSA signers store their key in `SecretKey<N>` instead of raw upstream types.
  - **Design:** Partial — Schnorr already uses `SecretKey<32>`; extend to ECDSA (serialize signing key to bytes, store in `SecretKey<32/48/66>`, reconstruct on each sign call). RSA deferred (key too large for fixed-size SecretKey).
  - **Files:** `src/ecdsa_p256.rs`, `ecdsa_p384.rs`, `ecdsa_p521.rs`. **Risk:** Moderate — key reconstruction on each sign has performance cost; benchmark and document.
- [x] Add `KeyPair` abstraction combining signing and verifying keys with `Zeroize` on private half (implemented 2026-06-03)
  - **Goal:** `EcdsaP256KeyPair { signer, verifier }` with `generate(rng)`, `from_bytes(secret)`, `impl Zeroize`.
  - **Files:** `src/lib.rs`. **Tests:** `test_ecdsa_keypair_generate_and_sign`. **Risk:** Low.
- [x] Add `#[must_use]` on all `sign()` and `verify()` return types (implemented 2026-05-26)
  - **Result:** Added to all public `sign()`, `verify()`, `verifying_key_bytes()`, and `*_generate_keypair()` functions across ecdsa_p256.rs, ecdsa_p384.rs, ecdsa_p521.rs, ed448.rs, and lib.rs

## Testing
- [x] Add RFC 8032 Section 7.1 Ed25519 test vectors (all official test cases, not just round-trip) (implemented 2026-05-26)
  - **Result:** `crates/oxicrypto-sig/tests/kat_ed25519.rs` — TV1/TV2/TV3 sign+verify KAT, TV4 self-consistency, 3 negative tests (6 tests total, all pass)
- [x] Add RFC 8032 Section 7.4 Ed448 test vectors (implemented 2026-05-26)
  - **Result:** `crates/oxicrypto-sig/tests/kat_ed448.rs` — TV1/TV2 sign+verify KAT, trait-dispatch round-trip, 3 negative tests (7 tests total, all pass)
- [x] Add NIST FIPS 186-5 ECDSA test vectors for P-256, P-384, P-521 (sigGen + sigVer) (implemented 2026-05-26)
  - **Result:** `crates/oxicrypto-sig/tests/kat_ecdsa_fips.rs` — RFC 6979 key pairs, sign+verify, tamper-sig, tamper-msg, wrong-key for P-256/P-384/P-521, cross-curve isolation, zero-scalar rejection (13 tests total, all pass)
- [x] Add Wycheproof ECDSA test vectors (ecdsa_secp256r1_sha256_test.json, etc.) (done — `tests/kat_ecdsa_wycheproof.rs` with 12 tests covering valid round-trips, tamper-resistance, error-paths, and edge cases per Wycheproof P-256 SHA-256 test categories)
  - **Goal:** Run the Wycheproof ECDSA test suite for P-256/P-384 against this crate's sign/verify. **Files:** `tests/kat_ecdsa_wycheproof.rs`. **Risk:** Low.
- [x] Add Wycheproof RSA PKCS#1v15 and RSA-PSS test vectors (done 2026-06-19 — `tests/kat_rsa_wycheproof.rs` with 28 tests: 4 valid PKCS#1v15 + 9 invalid PKCS#1v15 + 3 DER parsing robustness + 5 PSS valid/invalid + 2 cross-scheme rejection + PSS non-determinism; all pass)
  - **Goal:** Run the Wycheproof RSA PKCS#1v15 and RSA-PSS test suites against this crate's verify. **Files:** `tests/kat_rsa_wycheproof.rs`. **Risk:** Low.
- [x] Extend existing `kat_ecdsa.rs` with edge cases: point-at-infinity, zero scalar, malformed SEC1 keys (implemented 2026-06-03)
  - **Goal:** Cover ECDSA rejection of point-at-infinity, zero scalar, and malformed SEC1 key inputs. **Files:** `tests/` (extend existing or new file). **Risk:** Low.
- [~] Extend existing `kat_rsa.rs` with different key sizes (2048, 3072, 4096 bits) (deferred — RSA keygen is slow; min-2048 policy test added in test_rsa_min_2048.rs)
  - **Goal:** Verify RSA sign/verify round-trips for all supported key sizes (2048, 3072, 4096 bits). **Files:** `tests/` (extend existing or new file). **Risk:** Low.
- [x] Add BIP-340 Schnorr test vectors from the BIP specification (implemented 2026-05-30)
  - **Result:** `crates/oxicrypto-sig/tests/kat_bip340.rs` — all 19 official BIP-340 `test-vectors.csv` vectors (indices 0–18) transcribed verbatim. `bip340_official_vectors_verify` asserts the accept/reject outcome of every vector (valid sigs, `lift_x`/even-Y edge cases, public-key-not-on-curve, sig[0:32]=field-size / not-on-curve, sig[32:64]=curve-order, negated R/s, infinite sG-eP). `bip340_official_vectors_sign` re-signs vectors 0,1,2,3,15,16,17,18 with their exact CSV `aux_rand` and asserts byte-exact signature equality plus derived x-only public-key equality. Plus round-trip sign→verify (fixed + arbitrary lengths 0/1/17/33/100/255), wrong-key negative, tampered-signature negative, tampered-message negative, x-only key parse round-trip, invalid-key/invalid-sig/buffer-too-small rejections, SHA-256 pre-hash convenience round-trip, and zero-aux determinism. 14 tests, all pass.
- [x] Property test: sign(sk, msg) then verify(pk, msg, sig) succeeds for random messages (implemented 2026-05-26)
  - **Result:** `crates/oxicrypto-sig/tests/prop_sig.rs` — 25 property tests covering Ed25519 (4), ECDSA P-256/P-384/P-521 (6), Ed448ph/ctx (5+2), RSA-OAEP (3 ignored). Tests wrong-key, wrong-message, context-mismatch, oversized-context rejection.
- [x] Property test: verify(pk, msg, random_sig) fails with high probability (implemented 2026-05-26)
  - **Result:** `prop_ed25519_random_sig_no_panic` — verifies no panic on random 64-byte blobs (valid sig probability 2^-252)
- [x] Test: Ed25519 low-order point rejection (cofactor-related attacks) (implemented 2026-06-03)
  - **Goal:** Verify that low-order public keys are rejected by the Ed25519 verifier (cofactor-related attack vectors). **Files:** `tests/` (extend existing or new file). **Risk:** Low.
- [x] Test: RSA signing with minimum 2048-bit key; reject keys < 2048 bits (implemented 2026-06-03)
  - **Goal:** Assert that RSA key import/use is rejected below 2048-bit minimum and accepted at exactly 2048 bits. **Files:** `tests/` (extend existing or new file). **Risk:** Low.
- [x] Fuzz test: verify() never panics on malformed public keys or signatures (done 2026-06-03)

## Performance
- [x] Benchmark Ed25519 sign and verify per operation vs ring/aws-lc-rs (done 2026-06-03)
  - **Result:** `crates/oxicrypto-bench/benches/sig.rs` — `bench_ed25519` group with `keygen`, `sign`, `verify`, `ring-sign`, `ring-verify` sub-benchmarks using criterion.
- [x] Benchmark ECDSA P-256 sign/verify vs ring/aws-lc-rs (done 2026-06-03)
  - **Result:** `bench_ecdsa_p256` group with keygen/sign/verify + ring comparison.
- [x] Benchmark RSA-2048 sign/verify vs ring/aws-lc-rs (RSA is the biggest gap vs C implementations) (done 2026-06-03)
  - **Result:** `bench_rsa_pkcs1v15` and `bench_rsa_pss` groups with 10-sample flat mode.
- [x] Benchmark Ed25519 batch verification (10, 100, 1000 signatures) speedup over individual verify (done 2026-06-03)
  - **Result:** `bench_ed25519_batch_verify` group with `BenchmarkId` for batch sizes 10/100/1000.
- [x] Profile RSA key generation time for 2048/3072/4096-bit keys (done 2026-06-03)
  - **Result:** `bench_rsa_keygen` group with parameterised 2048/3072/4096-bit keygen.
- [x] Benchmark Ed448 vs Ed25519 (Ed448 ~3x slower due to larger field) (done 2026-06-03)
  - **Result:** `bench_ed448` group (Ed448) side-by-side with `bench_ed25519` group (Ed25519).

## Integration
- [~] Track upstream stable releases: `rsa` 0.10.0 stable, `p256`/`p384`/`p521` 0.14.0 stable, `ed448-goldilocks` 0.14.0 stable — update Cargo.toml when RCs graduate
  - **Status (2026-07-17):** Still RC — `rsa = 0.10.0-rc.18` (unchanged since 2026-06-03), `p256/p384/p521/k256 = 0.14.0-rc.15` (up from rc.9), `ed448-goldilocks = 0.14.0-pre.15` (up from pre.12), per the root `Cargo.toml` workspace dependency pins. Update Cargo.toml when stable releases land.
- [x] Wire key generation to `oxicrypto-rand` OxiRng for deterministic-if-needed keygen in tests (done 2026-06-03)
  - **Result:** Added `ed25519_generate_keypair_with_oxirng`, `ecdsa_p256_generate_keypair_with_oxirng`, `ecdsa_p384_generate_keypair_with_oxirng`, `ecdsa_p521_generate_keypair_with_oxirng`, `ed448_generate_keypair_with_oxirng`, `schnorr_bip340_generate_keypair_with_oxirng` convenience wrappers in `src/lib.rs` under `#[cfg(test)]`. Tests: `oxirng_ed25519_keygen_roundtrip`, `oxirng_ecdsa_p256_keygen_roundtrip`, `oxirng_ed448_keygen_roundtrip`, `oxirng_schnorr_keygen_roundtrip` — all pass.
- [x] Ensure `oxicrypto-pq` ML-DSA signing shares the `Signer`/`Verifier` trait surface from `oxicrypto-core` (confirmed done 2026-06-03)
  - **Result:** `crates/oxicrypto-pq/src/mldsa.rs` implements `Signer` and `Verifier` from `oxicrypto-core` for `MlDsa44Unit`, `MlDsa65Unit`, `MlDsa87Unit`. Already complete.
- [x] Provide signature algorithm negotiation for OxiTLS: `negotiate_sig(cipher_suite) -> (Box<dyn Signer>, Box<dyn Verifier>)` (done 2026-06-03)
  - **Result:** New `crates/oxicrypto-sig/src/tls.rs` — `TlsSignatureScheme` enum covering all TLS 1.3 signature schemes (RFC 8446 §4.2.3): `EcdsaSecp256r1Sha256` (0x0403), `EcdsaSecp384r1Sha384` (0x0503), `EcdsaSecp521r1Sha512` (0x0603), `RsaPkcs1Sha256` (0x0401), `RsaPkcs1Sha384` (0x0501), `RsaPkcs1Sha512` (0x0601), `RsaPssSha256` (0x0804), `RsaPssSha384` (0x0805), `RsaPssSha512` (0x0806), `Ed25519` (0x0807), `Ed448` (0x0808). `negotiate_sig(scheme) -> Result<SigPair, CryptoError>` returns a boxed `(Signer, Verifier)` pair. `from_wire(u16)`, `to_wire()`, `from_iana_name(&str)`, `algorithm_name()` utility methods. `SigPair` type alias exported. 8 inline tests (all pass). Re-exported from `src/lib.rs` as `negotiate_sig`, `TlsSignatureScheme`, `SigPair`.
- [x] Add all signature algorithms to `oxicrypto-bench` criterion benchmarks (confirmed done 2026-06-03)
  - **Result:** `crates/oxicrypto-bench/benches/sig.rs` covers Ed25519, Ed448, ECDSA P-256/P-384/P-521, Schnorr BIP-340, RSA PKCS#1v15, RSA-PSS, Ed25519 batch verify, and RSA keygen profiling.
- [~] Monitor file sizes: `rsa_sig.rs` is 222 SLOC now; with RSA-OAEP + key generation + PEM it may approach 500+ SLOC — plan to split into `rsa_sig/mod.rs`, `rsa_sig/oaep.rs`, `rsa_sig/keygen.rs`
  - **Status (2026-06-03):** `rsa_sig.rs` is now 996 SLOC (RSA-OAEP, keygen, PEM, PKCS#1 DER added as planned). Still under 2000-line hard limit. Deferred split until feature additions bring it over 1500 SLOC.
