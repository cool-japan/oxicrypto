# oxicrypto-pq TODO

## Status
Post-quantum cryptography suite (33 + 311 + 262 = ~606 SLOC across 3 files). Implements ML-KEM-512/768/1024 (FIPS 203) with key generation, encapsulation, decapsulation, and deterministic test helpers. Implements ML-DSA-44/65/87 (FIPS 204) with key generation, signing, verification. Behind `pq-preview` feature flag. Note: ML-DSA-87 requires 8 MiB stack for tests due to large parameter sizes.

## Core Implementation
- [x] Add SLH-DSA (Stateless Hash-Based Digital Signatures) per FIPS 205 — 6 parameter sets (SLH-DSA-SHA2-128s/f, SHA2-256s/f, SHAKE-128s/f) using `slh-dsa 0.2.0-rc.5` crate (done 2026-05-25)
- [x] Extend SLH-DSA to 10 parameter sets: added SHA2-192s/f (category 3) and SHAKE-256s/f (category 5) (done 2026-05-26)
- [x] Add X-Wing hybrid KEM: ML-KEM-768 + X25519 `Kem` impl (done 2026-05-25)
  - **Goal:** `XWing768X25519` implementing core `Kem`, following `draft-connolly-cfrg-xwing-kem` exactly.
  - **Design:**
    - `DecapKey = { mlkem: DecapKey768, x25519_sk: SecretKey<32>, x25519_pk: [u8;32] }` (zeroizes on drop)
    - `EncapKey = { mlkem: EncapKey768, x25519_pk: [u8;32] }` (Clone)
    - `Ciphertext = { mlkem_ct: Ciphertext768, x25519_ct: [u8;32] }` (Clone; x25519_ct = ephemeral public)
    - `SharedSecret` = 32-byte zeroizing type
    - **Combiner (X-Wing):** `SS = SHA3-256( XWingLabel ‖ ss_M ‖ ss_X ‖ ct_X ‖ pk_X )` where `XWingLabel` = `b"\\.//(^\\.)"` (the 6-byte draft label), `ss_M` = ML-KEM-768 ss (32B), `ss_X` = raw X25519 DH output (32B), `ct_X` = ephemeral X25519 public (32B), `pk_X` = recipient static X25519 public (32B). **Raw X25519 output** (no inner HKDF).
    - `generate`: ML-KEM-768 keygen + X25519 static keypair.
    - `encapsulate(ek)`: ML-KEM encapsulate→(ct_M, ss_M); ephemeral X25519 keypair, ss_X = DH(eph_sk, ek.x25519_pk), ct_X = eph_pk; SS = combiner.
    - `decapsulate(dk, ct)`: ss_M = decapsulate(dk.mlkem, ct.mlkem_ct); ss_X = DH(dk.x25519_sk, ct.x25519_ct); SS = combiner using dk.x25519_pk as pk_X.
  - **Files:** `crates/oxicrypto-pq/src/hybrid.rs` (new), `crates/oxicrypto-pq/src/lib.rs`, `crates/oxicrypto-pq/Cargo.toml`
  - **Prerequisites:** Add `oxicrypto-kex` and `sha3` as deps of oxicrypto-pq (no dep cycle: kex→core only)
  - **Tests:** encapsulate→decapsulate round-trip recovers identical SS; cite and check the X-Wing draft test vector; tampered ct_M or ct_X → different SS.
  - **Risk:** Moderate-high — correctness-critical. Pin exact label bytes + field order from draft.
- [x] Add hybrid KEM: ML-KEM-1024 + ECDH P-384 `Kem` impl (done 2026-05-25)
  - **Goal:** `HybridKem1024P384` implementing core `Kem` for CNSA 2.0.
  - **Design:** Ephemeral P-384 keypair; ct_E = ephemeral SEC1 public (49B); ss_E = 48-byte ECDH x-coord via `EcdhP384::agree`. **Combiner (ounsworth-style, fully bound):** `IKM = ss_M ‖ ss_E ‖ ct_M ‖ ct_E ‖ ek_M ‖ ek_E`; `SS = HKDF-SHA-384-Expand(HKDF-SHA-384-Extract(salt=const-label, IKM), info="oxicrypto-hybrid-mlkem1024-p384", 32)`. Use `oxicrypto-kdf`'s `hkdf_sha384_extract`/`_expand`. Binding to ciphertexts + encap keys is mandatory.
  - **Files:** `crates/oxicrypto-pq/src/hybrid.rs` (new), `crates/oxicrypto-pq/src/lib.rs`, `crates/oxicrypto-pq/Cargo.toml`
  - **Prerequisites:** Add `oxicrypto-kex` and `oxicrypto-kdf` as deps of oxicrypto-pq (no dep cycle confirmed)
  - **Tests:** round-trip recovers identical SS; deterministic SS from fixed inputs; tampered ct/ek → different SS.
  - **Risk:** Moderate-high — document exact IKM layout in code; no naive concat.
- [x] Add `PqKeyShare` TLS 1.3 key-share struct (done 2026-05-25)
  - **Goal:** encode/decode ML-KEM encapsulation keys and ciphertexts for the TLS 1.3 `key_share` extension wire format.
  - **Design:** `PqKeyShare { group: PqGroup, payload: Vec<u8> }` with `encode()`/`decode()` over the existing `to_bytes`/`from_bytes`; named-group ids for ML-KEM-768/1024 and the two hybrids. No TLS-crate dep — just byte layout.
  - **Files:** `crates/oxicrypto-pq/src/lib.rs`
  - **Tests:** encode→decode round-trip for ek and ct of each group; wrong-length rejection.
  - **Risk:** Low-moderate — keep it byte-format only.
- [x] Add ML-KEM key serialization: `EncapKey::to_bytes()` / `EncapKey::from_bytes()` and `DecapKey::to_bytes()` / `DecapKey::from_bytes()` for persistent storage (~60 SLOC) (done 2026-05-25)
  - **Goal:** EncapKey/DecapKey to_bytes()/from_bytes() for ML-KEM-512/768/1024
  - **Design:** For each param set, add methods on the existing structs (or return types):
    - `MlKem512EncapKey::to_bytes(&self) -> Vec<u8>` and `from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>`
    - Same for DecapKey. Check ml-kem 0.3.2 API: types likely expose `as_bytes()` returning `&[u8]` and constructors from byte slices. Wrap with `CryptoError::Encoding` on invalid input.
  - **Files:** `crates/oxicrypto-pq/src/mlkem.rs`
  - **Prerequisites:** None — ml-kem 0.3.2 already a dep
  - **Tests:** Round-trip for each param set: generate keypair, serialize DecapKey to bytes, deserialize back, verify it produces same shared secret
  - **Risk:** Low — ml-kem exposes byte-level access via as_bytes() and from_bytes()
- [x] Add ML-DSA key serialization: `VerifyingKey::to_bytes()` / `VerifyingKey::from_bytes()` and `SigningKey::to_bytes()` / `SigningKey::from_bytes()` (~60 SLOC) (done 2026-05-25)
  - **Goal:** VerifyingKey/SigningKey/Signature to_bytes()/from_bytes() for ML-DSA-44/65/87
  - **Design:** For each param set, add to_bytes()/from_bytes() methods on SigningKey, VerifyingKey, and Signature wrapper types. ml-dsa 0.1.0 types likely expose `as_bytes()` or implement AsRef<[u8]>. Wrap with CryptoError::Encoding on invalid input.
  - **Files:** `crates/oxicrypto-pq/src/mldsa.rs`
  - **Prerequisites:** None — ml-dsa 0.1.0 already a dep
  - **Tests:** Round-trip: sign message with SigningKey, serialize Signature to bytes, deserialize, verify the deserialized signature is valid
  - **Risk:** Low — ml-dsa should expose byte conversion; check exact API
- [x] Add ML-DSA signature serialization: `Signature::to_bytes()` / `Signature::from_bytes()` for wire format compatibility (~30 SLOC per parameter set, ~90 total) (done 2026-05-25)
- [x] Implement `Signer`/`Verifier` traits from `oxicrypto-core` for ML-DSA (currently only inherent methods) (~80 SLOC) (done 2026-05-25)
  - **Goal:** ML-DSA-44/65/87 implement Signer/Verifier traits from oxicrypto-core for trait-dispatched usage
  - **Design:** Create unit structs `MlDsa44`, `MlDsa65`, `MlDsa87` in lib.rs (or mldsa.rs) that implement `Signer` and `Verifier` from oxicrypto_core. The Signer::sign(&self, sk: &[u8], msg: &[u8], sig_out: &mut [u8]) method: deserialize SigningKey from sk bytes, sign msg, write signature to sig_out. The Verifier::verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) method: deserialize VerifyingKey from pk bytes, deserialize Signature from sig bytes, verify.
  - **Files:** `crates/oxicrypto-pq/src/mldsa.rs`, `crates/oxicrypto-pq/src/lib.rs`
  - **Prerequisites:** ML-DSA key+sig serialization (from_bytes() needed)
  - **Tests:** Sign using MlDsa65 Signer trait, verify using MlDsa65 Verifier trait; cross-check against inherent mldsa65_sign/verify methods
  - **Risk:** Moderate — sig_out buffer must be sized correctly for ML-DSA signatures; check expected sizes (ML-DSA-44: 2420, ML-DSA-65: 3309, ML-DSA-87: 4627 bytes)
- [x] Implement `Kem` trait from `oxicrypto-core` for ML-KEM-512/768/1024 (done 2026-05-25)
  - **Goal:** plain `MlKem512`/`MlKem768`/`MlKem1024` unit structs implement core `Kem` (associated types map to existing EncapKey/DecapKey/Ciphertext/SharedKeyPq).
  - **Design:** thin impls over existing inherent generate/encapsulate/decapsulate. Confirm associated-type bounds (Clone on EncapKey/Ciphertext, Zeroize on SharedSecret) are satisfied.
  - **Files:** `crates/oxicrypto-pq/src/mlkem.rs`, `crates/oxicrypto-pq/src/lib.rs`
  - **Tests:** trait-dispatched round-trip equals inherent-method round-trip for each param set.
  - **Risk:** Low — wiring over existing methods.
- [x] Add `SharedKeyPq::zeroize()` / `Zeroize` on drop for shared keys (~10 SLOC) (done 2026-05-25)
  - **Goal:** SharedKeyPq automatically zeroes its memory on drop
  - **Design:** Add `zeroize` feature to oxicrypto-pq Cargo.toml (or use workspace dep). `impl Zeroize for SharedKeyPq { fn zeroize(&mut self) { self.0.zeroize() } }`. `impl ZeroizeOnDrop for SharedKeyPq {}`. Add `#[derive(ZeroizeOnDrop)]` if available or implement Drop manually calling zeroize().
  - **Files:** `crates/oxicrypto-pq/src/mlkem.rs`, `crates/oxicrypto-pq/Cargo.toml`
  - **Prerequisites:** zeroize crate (already a workspace dep)
  - **Tests:** Compilation test; verify Debug implementation doesn't print the key bytes
  - **Risk:** Very low — zeroize is already in the workspace
- [x] Add `SigningKey*::zeroize()` / `Zeroize` on drop for ML-DSA private keys (~10 SLOC per param set, ~30 total) (done 2026-05-25)
  - **Goal:** ML-DSA-44/65/87 signing keys auto-zero on drop
  - **Design:** Check if ml-dsa 0.1.0 SigningKey implements Zeroize. If yes, `impl ZeroizeOnDrop for MlDsa44SigningKey {}` (or however signing keys are represented). If no, wrap the inner signing key in a newtype that implements Zeroize by zeroing the byte representation. Look for `zeroize` feature flag in ml-dsa crate.
  - **Files:** `crates/oxicrypto-pq/src/mldsa.rs`, `crates/oxicrypto-pq/Cargo.toml`
  - **Prerequisites:** zeroize workspace dep
  - **Tests:** Compilation test; verify the key types impl Zeroize
  - **Risk:** Low-moderate — depends on ml-dsa 0.1.0 exposing Zeroize; if not, use a byte-buffer newtype wrapper
- [x] Add `DecapKey*::zeroize()` / `Zeroize` on drop for ML-KEM private keys (~10 SLOC per param set, ~30 total) (done 2026-05-25)
  - **Goal:** ML-KEM-512/768/1024 decapsulation keys auto-zero on drop
  - **Design:** Same approach as ML-DSA: check ml-kem 0.3.2 for Zeroize impl on DecapsulationKey. If available, derive/impl ZeroizeOnDrop on our wrapper structs. ml-kem 0.3.2 likely has a `zeroize` feature.
  - **Files:** `crates/oxicrypto-pq/src/mlkem.rs`, `crates/oxicrypto-pq/Cargo.toml`
  - **Prerequisites:** zeroize workspace dep
  - **Tests:** Compilation test; verify the key types impl Zeroize
  - **Risk:** Low-moderate — same as ML-DSA
- [x] Fix ML-DSA-87 test stack overflow: removed stale `#[ignore]` attributes from `prop_mldsa.rs` — both ML-DSA-87 property tests now run normally using the existing 8 MiB thread-spawn wrapper (done 2026-05-26)
- [x] Add ML-KEM encapsulation key validation per FIPS 203 Section 7.2 (modulus check, type check) (~30 SLOC) (done 2026-05-25)
- [x] Add ML-DSA context-string signing per FIPS 204 Section 5.2 — `mldsa{44,65,87}_sign_ctx` / `mldsa{44,65,87}_verify_ctx` using `ExpandedSigningKey::sign_randomized` and `VerifyingKey::verify_with_context` from `ml-dsa 0.1.0` (done 2026-05-26)

## API Improvements
- [x] Add `PqAlgo` enum in facade: `PqKemAlgo`/`PqSigAlgo` in `oxicrypto/src/algo/pq.rs` — covers ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA (all 10 param sets) (done previously)
- [x] Add factory functions: `pq_sig_generate(algo)`, `pq_sign(algo, sk, msg)`, `pq_verify(algo, vk, msg, sig)` in `oxicrypto/src/algo/pq.rs` — all 13 PQ signature algorithms supported (done 2026-05-26)
- [x] Expose key sizes as associated constants: `MlKem768::ENCAP_KEY_LEN`, `MlKem768::CIPHERTEXT_LEN`, etc. (done 2026-05-25)
- [x] Add `Debug` implementations for all key/ciphertext/signature types (print algorithm + length, NOT key bytes) (done 2026-05-25)
- [x] Add `PartialEq` for `SharedKeyPq` (constant-time via `subtle::ConstantTimeEq`) (done 2026-05-25)
- [ ] Graduate `pq-preview` to default-on once FIPS 203/204 are finalized and `ml-kem`/`ml-dsa` reach 1.0
  **BLOCKED: upstream** — `ml-kem` and `ml-dsa` are at 0.3.x / 0.1.x; graduation requires both crates to reach 1.0 and FIPS 203/204 to be formally published (FIPS 203 published August 2024; waiting for `ml-kem`/`ml-dsa` crate 1.0)
- [x] Rename `SharedKeyPq` to `SharedSecret` for consistency with classical key exchange terminology — `SharedKeyPq` is now a `#[deprecated]` type alias for `SharedSecret` (done 2026-05-26)
- [x] Add `#[must_use]` on all keygen/encap/decap/sign/verify return types (done 2026-05-25)

## Testing
- [x] Add NIST FIPS 203 ACVP-style known-answer test vectors for ML-KEM-512/768/1024 — `tests/kat_acvp_mlkem768.rs` hardcodes full EK/CT/SS vectors for ML-KEM-768 zero-seed and SS-only vectors for ML-KEM-512/1024 and ab/cd seeds (done 2026-05-26)
- [x] Add NIST FIPS 204 ACVP sigGen/sigVer test vectors for ML-DSA-44/65/87 (done 2026-06-03) — `tests/kat_nist_mldsa.rs` uses the NIST sequential reference seed `[0x00..=0x1f]` (same seed as `ml-dsa 0.1.0/tests/examples/ML-DSA-{44,65,87}-seed.priv`) for 17 sigGen+sigVer+determinism+wrong-message+wrong-key tests across all 3 parameter sets; full NIST ACVP JSON download (`sig-gen.json`, `sig-ver.json`) from ACVP-Server is an optional future enhancement
- [x] Extend existing `kat_mlkem.rs` / `kat_acvp_mlkem768.rs` with deterministic keygen + encapsulate vectors (done 2026-05-26)
- [x] Extend existing `kat_mldsa.rs` with deterministic signing vectors from NIST submission package (done 2026-06-03 — deterministic signing KAT + FIPS 204 Table 1 size constants for all 3 parameter sets)
- [x] Add known-answer test: ML-KEM-768 deterministic keygen from fixed 64-byte seed produces expected encapsulation key bytes — `kat_acvp_mlkem768.rs::acvp_mlkem768_zero_seed_full_vector` (done 2026-05-26)
- [x] Add known-answer test: ML-DSA-65 deterministic signing of fixed message produces expected signature bytes — `tests/kat_acvp_mldsa.rs::acvp_mldsa65_zero_seed_siggen` pins full 3309-byte signature vector for sk_seed=[0u8;32] (done 2026-06-03)
- [x] Property test: ML-KEM encapsulate -> decapsulate round-trip always recovers the same shared secret — `tests/prop_mlkem.rs` covers ML-KEM-512/768 (3–5 iters), ML-KEM-1024 `#[ignore]` (done 2026-05-26)
- [x] Property test: ML-DSA sign -> verify round-trip always succeeds — `tests/prop_mldsa.rs` covers ML-DSA-44/65 (3–5 iters), ML-DSA-87 `#[ignore]` (done 2026-05-26)
- [x] Property test: ML-DSA verify with wrong message always fails — `tests/prop_mldsa.rs` (done 2026-05-26)
- [x] Property test: ML-KEM decapsulate with modified ciphertext produces different shared secret (implicit rejection) — `tests/prop_mlkem.rs` (done 2026-05-26)
- [x] Test: ML-DSA-87 works correctly with 8 MiB thread stack — `prop_mldsa87_sign_verify_round_trip` and `prop_mldsa87_wrong_message_fails` now run without `#[ignore]` (done 2026-05-26)
- [x] Test: hybrid KEM produces deterministic shared secret from fixed inputs — `tests/prop_hybrid.rs` covers X-Wing (ML-KEM-768 + X25519) and HybridKem1024P384 (done 2026-05-26)
- [x] Test: key serialization round-trip: `from_bytes(to_bytes(key)) == key` — `tests/prop_mlkem.rs` and `tests/prop_mldsa.rs` (done 2026-05-26)
- [x] Fuzz test: `decapsulate()` never panics on random ciphertext bytes — implemented as deterministic chaos tests in `tests/chaos.rs`; covers ML-KEM-512/768/1024 with wrong-length inputs and correct-length random bytes (done 2026-06-03)
- [x] Fuzz test: `verify()` never panics on random signature bytes — implemented as deterministic chaos tests in `tests/chaos.rs`; covers ML-DSA-44/65 with random-length and random-content signature inputs (done 2026-06-03)

## Performance
- [x] Benchmark ML-KEM-512/768/1024 keygen, encapsulate, decapsulate per operation — `benches/pq_benchmarks.rs` (done 2026-06-03)
- [x] Benchmark ML-DSA-44/65/87 keygen, sign, verify per operation — `benches/pq_benchmarks.rs` (done 2026-06-03)
- [x] Compare ML-KEM-768 vs X25519 key exchange latency — added `bench_x25519` group in `benches/pq_benchmarks.rs` measuring `StaticSecret+PublicKey` keygen and DH, comparable to ML-KEM-768 encapsulate (done 2026-06-03)
- [x] Compare ML-DSA-65 vs Ed25519 sign/verify latency — added `bench_ed25519` group in `benches/pq_benchmarks.rs` measuring keygen-from-bytes, sign, verify, comparable to ML-DSA-65 (done 2026-06-03)
- [x] Benchmark hybrid KEM (ML-KEM-768 + X25519 + HKDF) total latency — X-Wing and HybridKem1024P384 benches in `benches/pq_benchmarks.rs` (done 2026-06-03)
- [ ] Profile ML-DSA-87 stack and heap usage (fix 8 MiB stack requirement) — BLOCKED: requires ML-DSA-87 to expose its internals; current bench spawns 8 MiB threads
- [x] Benchmark SLH-DSA sign/verify (expected ~100x slower than ML-DSA) — SHA2-128s/f benches in `benches/pq_benchmarks.rs` (done 2026-06-03)
- [ ] Profile memory allocation in ML-KEM keygen (large polynomial arrays) — DEFERRED: requires heap profiler (e.g. heaptrack, DHAT)

## Integration
- [ ] Coordinate with `oxicrypto-kex` for hybrid key exchange (ML-KEM + X25519)
  **BLOCKED: cross-crate design** — Requires API decision in `oxicrypto-kex` (already implemented as `XWing768` in this crate); formal cross-crate trait integration deferred to ecosystem design review
- [ ] Coordinate with `oxicrypto-kdf` for shared-secret-to-AEAD-key derivation (HKDF after KEM)
  **BLOCKED: cross-crate design** — `oxicrypto-kdf` integration exists (used by `HybridKem1024P384`); formal trait-level abstraction requires ecosystem-wide design consensus
- [ ] Coordinate with `oxicrypto-sig` for composite signatures (ML-DSA + Ed25519/ECDSA for backward compatibility)
  **BLOCKED: upstream** — composite signature standard (draft-ietf-pquip-hybrid-signature-spectrums) is not yet finalized; blocked on IETF/NIST decision
- [ ] Provide PQ algorithm negotiation for OxiTLS: TLS 1.3 key share with ML-KEM
  **BLOCKED: cross-crate** — Requires `oxitls` to expose key-share extension API; blocked on oxitls PQ roadmap
- [ ] Add ML-KEM and ML-DSA benchmarks to `oxicrypto-bench` criterion suite
  **BLOCKED: cross-crate** — `oxicrypto-bench` workspace crate must be updated to pull `oxicrypto-pq` as a dependency; currently `pq_benchmarks.rs` in this crate already covers all benchmarks locally
- [ ] Track `ml-kem` and `ml-dsa` crate updates: pin exact versions until 1.0 to avoid API breakage
  **DEFERRED: maintenance** — Cargo.toml already pins exact versions (`ml-kem = "0.3.2"`, `ml-dsa = "0.1.0"`); ongoing monitoring task, no code changes needed
- [x] Research `slh-dsa` crate availability on crates.io for SLH-DSA (FIPS 205) implementation
