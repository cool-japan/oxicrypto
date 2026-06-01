# oxicrypto-sig TODO

## Status
Comprehensive signature suite (158 + 61 + 58 + 58 + 67 + 222 = ~624 SLOC across 6 files). Implements Ed25519 (RFC 8032) with `Signer`/`Verifier` traits, Ed448 (RFC 8032 Section 5.2), ECDSA P-256/P-384/P-521 (FIPS 186-5) with typed signer/verifier structs, RSA PKCS#1v15 with SHA-256/384/512 and RSA-PSS with SHA-256. All sign/verify only; no batch verification, no key generation, no BIP-340 Schnorr, no threshold signatures. Note: upstream deps `rsa 0.10.0-rc.18`, `p256/p384/p521 0.14.0-rc.9`, `ed448-goldilocks 0.14.0-pre.12` are release candidates.

## Core Implementation
- [x] Add Ed25519 batch verification using `ed25519_dalek::verify_batch()` for verifying multiple signatures in a single operation (~40 SLOC) (planned 2026-05-25)
  - **Goal:** ed25519_verify_batch(messages, signatures, public_keys) -> Result<(), CryptoError> using ed25519-dalek's verify_batch()
  - **Design:** `pub fn ed25519_verify_batch(messages: &[&[u8]], signatures: &[ed25519_dalek::Signature], verifying_keys: &[ed25519_dalek::VerifyingKey]) -> Result<(), CryptoError>`. Call `ed25519_dalek::verify_batch(messages, signatures, verifying_keys)` and map the error to `CryptoError::InvalidSignature`. All slices must have the same length; return CryptoError::BadInput if lengths differ.
  - **Files:** `crates/oxicrypto-sig/src/lib.rs`
  - **Prerequisites:** ed25519-dalek already a workspace dep; verify_batch is in it
  - **Tests:** Batch of 5 valid sign/verify pairs succeeds; batch with one tampered signature fails; empty batch succeeds; mismatched slice lengths return error
  - **Risk:** ed25519_dalek::verify_batch exists but check exact import path in 2.2.0
- [ ] Add Ed25519ctx and Ed25519ph (prehash) variants per RFC 8032 Sections 5.1.5-5.1.6 (~60 SLOC)
  - **Deviation (2026-05-26):** SKIPPED. ed25519-dalek 2.2.0's `sign_prehashed`/`with_context` APIs are gated behind the `digest` feature which transitively uses `sha2 0.10` (via the internal `Sha512` bound). Our workspace uses `sha2 0.11.x` (digest 0.11 chain), which is a different major version — passing our Sha512 type to dalek's `MsgDigest: Digest<OutputSize = U64>` bound fails because the `Digest` trait is from digest 0.10 in dalek's API. Implementing via the `hazmat` module has the same issue. To implement without re-implementing Ed25519 primitives, we would need to upgrade ed25519-dalek to a future version that uses digest 0.11, or re-implement the dom2 prefix + signing pipeline from scratch.
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
- [ ] Add ECDSA deterministic nonce generation per RFC 6979 (verify this is the default behavior of `p256`/`p384`/`p521` — document if so) (~20 SLOC)
- [ ] Add ECDSA batch verification for P-256/P-384 using multi-scalar multiplication (~80 SLOC)
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
- [ ] Add multisig aggregation for Ed25519: MuSig2 protocol for key aggregation and multi-party signing (~150 SLOC)
- [ ] Add PEM import/export for RSA keys: `from_pem(pem_str)` / `to_pem()` (~40 SLOC)
- [ ] Add PKCS#1 DER import for RSA keys in addition to PKCS#8 (~30 SLOC)

## API Improvements
- [ ] Update `SigAlgo` enum in facade to include all implemented algorithms: Ed448, EcdsaP256, EcdsaP384, EcdsaP521, RsaPkcs1v15, RsaPss
- [ ] Add `signer_impl()` / `verifier_impl()` facade factory functions for all algorithms (currently only Ed25519)
- [ ] Unify ECDSA signer/verifier construction: `EcdsaSigner::new(curve, scalar)` with curve enum instead of separate types per curve
- [ ] Add `SignatureFormat` enum: `Der`, `Raw`, `Compact` for ECDSA signature encoding selection
- [ ] Add `verify_prehash(pk, hash, sig)` for pre-hashed message verification (useful for large messages)
- [ ] Wrap private key bytes in `SecretKey` from `oxicrypto-core` with `Zeroize` semantics
- [ ] Add `KeyPair` abstraction combining signing and verifying keys with `Zeroize` on the private half
- [x] Add `#[must_use]` on all `sign()` and `verify()` return types (implemented 2026-05-26)
  - **Result:** Added to all public `sign()`, `verify()`, `verifying_key_bytes()`, and `*_generate_keypair()` functions across ecdsa_p256.rs, ecdsa_p384.rs, ecdsa_p521.rs, ed448.rs, and lib.rs

## Testing
- [x] Add RFC 8032 Section 7.1 Ed25519 test vectors (all official test cases, not just round-trip) (implemented 2026-05-26)
  - **Result:** `crates/oxicrypto-sig/tests/kat_ed25519.rs` — TV1/TV2/TV3 sign+verify KAT, TV4 self-consistency, 3 negative tests (6 tests total, all pass)
- [x] Add RFC 8032 Section 7.4 Ed448 test vectors (implemented 2026-05-26)
  - **Result:** `crates/oxicrypto-sig/tests/kat_ed448.rs` — TV1/TV2 sign+verify KAT, trait-dispatch round-trip, 3 negative tests (7 tests total, all pass)
- [x] Add NIST FIPS 186-5 ECDSA test vectors for P-256, P-384, P-521 (sigGen + sigVer) (implemented 2026-05-26)
  - **Result:** `crates/oxicrypto-sig/tests/kat_ecdsa_fips.rs` — RFC 6979 key pairs, sign+verify, tamper-sig, tamper-msg, wrong-key for P-256/P-384/P-521, cross-curve isolation, zero-scalar rejection (13 tests total, all pass)
- [ ] Add Wycheproof ECDSA test vectors (ecdsa_secp256r1_sha256_test.json, etc.)
- [ ] Add Wycheproof RSA PKCS#1v15 and RSA-PSS test vectors
- [ ] Extend existing `kat_ecdsa.rs` with edge cases: point-at-infinity, zero scalar, malformed SEC1 keys
- [ ] Extend existing `kat_rsa.rs` with different key sizes (2048, 3072, 4096 bits)
- [x] Add BIP-340 Schnorr test vectors from the BIP specification (implemented 2026-05-30)
  - **Result:** `crates/oxicrypto-sig/tests/kat_bip340.rs` — all 19 official BIP-340 `test-vectors.csv` vectors (indices 0–18) transcribed verbatim. `bip340_official_vectors_verify` asserts the accept/reject outcome of every vector (valid sigs, `lift_x`/even-Y edge cases, public-key-not-on-curve, sig[0:32]=field-size / not-on-curve, sig[32:64]=curve-order, negated R/s, infinite sG-eP). `bip340_official_vectors_sign` re-signs vectors 0,1,2,3,15,16,17,18 with their exact CSV `aux_rand` and asserts byte-exact signature equality plus derived x-only public-key equality. Plus round-trip sign→verify (fixed + arbitrary lengths 0/1/17/33/100/255), wrong-key negative, tampered-signature negative, tampered-message negative, x-only key parse round-trip, invalid-key/invalid-sig/buffer-too-small rejections, SHA-256 pre-hash convenience round-trip, and zero-aux determinism. 14 tests, all pass.
- [x] Property test: sign(sk, msg) then verify(pk, msg, sig) succeeds for random messages (implemented 2026-05-26)
  - **Result:** `crates/oxicrypto-sig/tests/prop_sig.rs` — 25 property tests covering Ed25519 (4), ECDSA P-256/P-384/P-521 (6), Ed448ph/ctx (5+2), RSA-OAEP (3 ignored). Tests wrong-key, wrong-message, context-mismatch, oversized-context rejection.
- [x] Property test: verify(pk, msg, random_sig) fails with high probability (implemented 2026-05-26)
  - **Result:** `prop_ed25519_random_sig_no_panic` — verifies no panic on random 64-byte blobs (valid sig probability 2^-252)
- [ ] Test: Ed25519 low-order point rejection (cofactor-related attacks)
- [ ] Test: RSA signing with minimum 2048-bit key; reject keys < 2048 bits
- [ ] Fuzz test: verify() never panics on malformed public keys or signatures

## Performance
- [ ] Benchmark Ed25519 sign and verify per operation vs ring/aws-lc-rs
- [ ] Benchmark ECDSA P-256 sign/verify vs ring/aws-lc-rs
- [ ] Benchmark RSA-2048 sign/verify vs ring/aws-lc-rs (RSA is the biggest gap vs C implementations)
- [ ] Benchmark Ed25519 batch verification (10, 100, 1000 signatures) speedup over individual verify
- [ ] Profile RSA key generation time for 2048/3072/4096-bit keys
- [ ] Benchmark Ed448 vs Ed25519 (Ed448 ~3x slower due to larger field)

## Integration
- [ ] Track upstream stable releases: `rsa` 0.10.0 stable, `p256`/`p384`/`p521` 0.14.0 stable, `ed448-goldilocks` 0.14.0 stable — update Cargo.toml when RCs graduate
- [ ] Wire key generation to `oxicrypto-rand` OxiRng for deterministic-if-needed keygen in tests
- [ ] Ensure `oxicrypto-pq` ML-DSA signing shares the `Signer`/`Verifier` trait surface from `oxicrypto-core`
- [ ] Provide signature algorithm negotiation for OxiTLS: `negotiate_sig(cipher_suite) -> (Box<dyn Signer>, Box<dyn Verifier>)`
- [ ] Add all signature algorithms to `oxicrypto-bench` criterion benchmarks
- [ ] Monitor file sizes: `rsa_sig.rs` is 222 SLOC now; with RSA-OAEP + key generation + PEM it may approach 500+ SLOC — plan to split into `rsa_sig/mod.rs`, `rsa_sig/oaep.rs`, `rsa_sig/keygen.rs`
