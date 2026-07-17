# oxicrypto-kex TODO

## Status
X25519, X448, ECDH P-256/P-384/P-521 Diffie-Hellman implemented, all behind the `KeyAgreement` trait per RFC 7748 / NIST SP 800-56A, with `agree_with_key` typed-secret (`SecretKey<N>`/`SecretVec`) overloads and `negotiate_kex(group)` TLS-named-group-string dispatch. Full RFC 9180 HPKE (`hpke` module) implemented: DHKEM(X25519, HKDF-SHA256) and DHKEM(P-256, HKDF-SHA256) with Encap/Decap and AuthEncap/AuthDecap, labeled HKDF (`HpkeKdf`), the key schedule for all four modes (Base/PSK/Auth/AuthPSK), directional `HpkeContextS`/`HpkeContextR` Seal/Open/Export, and single-shot `HpkeSuite::seal_base`/`open_base`. Hybrid classical+post-quantum key exchange (X25519+ML-KEM-768 via `XWing768`, ECDH-P384+ML-KEM-1024) lives in the `oxicrypto` facade to avoid a dependency cycle with `oxicrypto-pq`. RFC 7748 §6.1/§6.2 KAT + 1000-iteration tests, Wycheproof-style X25519 low-order-point tests, NIST SP 800-56A ECDH KAT vectors, DH-commutativity/determinism property tests, and RFC 9180 Appendix-A byte-exact HPKE vectors (X25519 full chain incl. seq0/seq1 + export; P-256) all in place. 124 tests passing, zero clippy warnings.

## Core Implementation
- [x] Add X448 Diffie-Hellman key agreement per RFC 7748 Section 5 using `x448` crate (done 2026-05-26)
- [x] Add ECDH over P-256 (secp256r1) per NIST SP 800-56A Rev. 3 using `p256` crate's ECDH support (~70 SLOC)
- [x] Add ECDH over P-384 (secp384r1) per NIST SP 800-56A Rev. 3 using `p384` crate's ECDH support (~70 SLOC)
- [x] Add ECDH over P-521 (secp521r1) per NIST SP 800-56A Rev. 3 using `p521` crate's ECDH support (~70 SLOC) (planned 2026-05-25)
  - **Goal:** EcdhP521 struct implementing KeyAgreement trait — completes the NIST P-curve set alongside P-256 and P-384
  - **Design:** Follow exact pattern of EcdhP256/EcdhP384 in lib.rs. `pub struct EcdhP521;` implementing `KeyAgreement`. `my_secret` is a 66-byte scalar (P-521 private key), `their_public` is a SEC1-encoded P-521 public key. Use `p521::ecdh::diffie_hellman(scalar, point)`. 66-byte shared secret output. Reject all-zero shared secret via `ct_is_zero`. Add `p521` dep with `ecdh` feature to Cargo.toml.
  - **Files:** `crates/oxicrypto-kex/src/lib.rs`, `crates/oxicrypto-kex/Cargo.toml`, workspace `Cargo.toml` (p521 already there for sig crate, may need ecdh feature)
  - **Prerequisites:** p521 crate with ecdh feature; check if p521 exposes diffie_hellman similarly to p256
  - **Tests:** Generate two P-521 key pairs (using p521::SecretKey::random), perform DH from both sides, verify shared secrets match; wrong-length input returns error; all-zero rejection
  - **Risk:** p521 is pre-release (0.14.0-rc.9); verify ECDH API matches p256's API surface
- [x] Add key encapsulation API: DhKem (DH + labeled-HKDF) for HPKE/KEM-style usage, RFC 9180 (done 2026-05-30)
  - **Goal:** `DhKem` in `src/hpke/kem.rs`: DeriveKeyPair, (de)serialize public keys (uncompressed SEC1 for NIST), Encap/Decap, AuthEncap/AuthDecap — the KEM layer underlying HPKE. KAT-verified (DeriveKeyPair vs RFC Appendix-A).
  - **Design:** approved plan block H3 — reuses `KeyAgreement::agree` for DH; direct curve-crate access only for pk-from-sk + uncompressed SEC1.
- [x] Add X25519 ephemeral key pair generation: `X25519KeyPair::generate(rng) -> (StaticSecret, PublicKey)` (~30 SLOC) (planned 2026-05-25)
  - **Goal:** x25519_generate_keypair(rng) -> Result<(x25519_dalek::StaticSecret, x25519_dalek::PublicKey), CryptoError>
  - **Design:** Use `x25519_dalek::StaticSecret::random_from_rng(rng)` (use StaticSecret not EphemeralSecret so the keypair can be stored and reused). Derive `PublicKey::from(&secret)`. Return `(secret, public_key)`. Accept `&mut impl rand_core::CryptoRngCore`.
  - **Files:** `crates/oxicrypto-kex/src/lib.rs`
  - **Prerequisites:** x25519-dalek already a workspace dep
  - **Tests:** Generate keypair; use it in x25519_agree() call (the existing KeyAgreement trait); verify the generated secret works with the existing agree() implementation
  - **Risk:** Low — StaticSecret::random_from_rng is a stable API in x25519-dalek 2.0
- [x] Add X448 ephemeral key pair generation: `x448_generate_keypair(rng)` with RFC 7748 clamping (done 2026-05-26)
- [x] Add ECDH key pair generation for P-256/P-384/P-521 (~50 SLOC) (planned 2026-05-25)
  - **Goal:** ecdh_p256_generate_keypair(), ecdh_p384_generate_keypair(), ecdh_p521_generate_keypair() functions
  - **Design:**
    `pub fn ecdh_p256_generate_keypair(rng: &mut impl rand_core::CryptoRngCore) -> Result<(p256::SecretKey, p256::PublicKey), CryptoError>`
    `pub fn ecdh_p384_generate_keypair(rng: &mut impl rand_core::CryptoRngCore) -> Result<(p384::SecretKey, p384::PublicKey), CryptoError>`
    `pub fn ecdh_p521_generate_keypair(rng: &mut impl rand_core::CryptoRngCore) -> Result<(p521::SecretKey, p521::PublicKey), CryptoError>`
    Each uses `SecretKey::random(rng)` and `PublicKey::from(secret_key.public_key())`.
  - **Files:** `crates/oxicrypto-kex/src/lib.rs`
  - **Prerequisites:** p521 added to kex Cargo.toml (from ECDH P-521 item)
  - **Tests:** Generate P-256 keypair; call ecdh_p256_agree (or EcdhP256 KeyAgreement) with generated keys; verify shared secret derivation works
  - **Risk:** Same pre-release API concern; SecretKey::random() is the standard API across all RustCrypto EC crates
- [x] Add `KeyAgreement` trait implementation for X448 (done 2026-05-26)
- [x] Add `KeyAgreement` trait implementations for ECDH P-256/P-384/P-521 (~90 SLOC) (done 2026-05-25)
- [x] Add shared-secret validation: reject all-zero shared secrets (low-order point attack on X25519) (~15 SLOC) (planned 2026-05-25)
  - **Goal:** Reject all-zero shared secrets in X25519 agree() to prevent low-order point attacks (same protection already in P-256/P-384)
  - **Design:** In the X25519 KeyAgreement::agree() implementation, after computing the shared secret bytes, call `ct_is_zero(shared_bytes)` (from oxicrypto-core). If zero, return `Err(CryptoError::KeyAgreement("all-zero shared secret rejected"))`. This matches the pattern in EcdhP256::agree() and EcdhP384::agree().
  - **Files:** `crates/oxicrypto-kex/src/lib.rs`
  - **Prerequisites:** ct_is_zero is re-exported from oxicrypto-core (already done)
  - **Tests:** Verify that passing the low-order X25519 point (0x00...00) as the public key returns CryptoError::KeyAgreement; verify normal key exchange still succeeds
  - **Risk:** Low — ct_is_zero is already used for P-256/P-384; the X25519 ECDH output is a fixed 32-byte array
- [x] Add hybrid key exchange: `HybridKex` combining classical (X25519) + post-quantum (ML-KEM-768) shared secrets via HKDF (resolved 2026-06-10)
  - **Resolution:** Dep cycle resolved by implementing in the `oxicrypto` facade. `crate::hybrid` module added to `oxicrypto/src/lib.rs` (behind `pq-preview`) re-exporting `oxicrypto_pq::{XWing768, HybridKem1024P384}` and `oxicrypto_core::Kem`. `XWing768` (ML-KEM-768 + X25519, SHA3-256 combiner per draft-connolly-cfrg-xwing-kem-04) and `HybridKem1024P384` (ML-KEM-1024 + ECDH-P384, HKDF-SHA-384) are both KAT-verified implementations already in `oxicrypto-pq/src/hybrid.rs`.
- [x] Add HPKE (RFC 9180) — full construction, all 4 modes (done 2026-05-30)
  - **Goal:** complete HPKE in a new `src/hpke/` module tree: DHKEM with Encap/Decap **and** AuthEncap/AuthDecap over DHKEM(X25519,HKDF-SHA256) [0x0020] and DHKEM(P-256,HKDF-SHA256) [0x0010]; labeled-HKDF; key schedule for Base/PSK/Auth/AuthPSK; stateful Seal/Open/Export context; single-shot wrappers; `HpkeSuite { kem, kdf, aead }` public API. AEADs: AES-128-GCM, AES-256-GCM, ChaCha20Poly1305, Export-only. Reachable as `oxicrypto_kex::hpke::*` and (facade) `oxicrypto::hpke::*`.
  - **Design/Files/Tests:** see approved plan `~/.claude/plans/cosmic-growing-lightning.md` (blocks H0–H8). Byte-exact validation vs RFC 9180 Appendix-A (A.1.1 X25519 full chain incl. seq0/seq1 + export; A.3.1 P-256) plus all-mode round-trips and negative tests.
  - **Scope note:** expanded beyond the original "mode 0 (Base), ~150 SLOC" to all four modes per IMPLEMENT POLICY.

## API Improvements
- [x] Add `KexAlgo` enum variants in facade for X448, EcdhP256, EcdhP384, EcdhP521 (planned 2026-06-02)
  - **Goal:** `KexAlgo::X448` is added to the enum (EcdhP256/P384/P521 already present) so X448 key agreement is dynamically selectable.
  - **Design:** Add `X448` variant to `KexAlgo` in `oxicrypto/src/algo/kex.rs`; add arm `KexAlgo::X448 => Box::new(oxicrypto_kex::X448)` to `kex_impl()`; append `AlgorithmId::X448` to `available_algorithms()` in `version.rs`. (`AlgorithmId::X448` confirmed present in `oxicrypto-core/src/algo_id.rs`.)
  - **Files:** `oxicrypto/src/algo/kex.rs`, `oxicrypto/src/version.rs`, `oxicrypto/src/tests.rs`.
  - **Tests:** `kex_impl(KexAlgo::X448)` generates a keypair and performs key agreement; `available_algorithms()` includes `AlgorithmId::X448`.
  - **Risk:** Low — single new match arm.
- [x] Add `kex_impl()` facade factory function for all key agreement algorithms (planned 2026-06-02)
  - **Goal:** `kex_impl()` handles `X448` alongside existing X25519 and ECDH variants.
  - **Design:** Single new match arm for `KexAlgo::X448` in `kex_impl()`. This is part of the same WI-1 facade-completion task as L55.
  - **Files:** `oxicrypto/src/algo/kex.rs`.
  - **Tests:** Covered by L55 tests above.
  - **Risk:** Low.
- [x] Add `shared_secret_len() -> usize` method to `KeyAgreement` trait (added as default method in oxicrypto-core, done 2026-05-26)
- [x] Wrap `my_secret` in `SecretKey<32>` from `oxicrypto-core` with `Zeroize` on drop (done 2026-06-03)
  - **Implementation:** All `generate_keypair` functions return `SecretKey<N>` (X25519: `SecretKey<32>`, X448: `SecretKey<56>`) or `SecretVec` (P-256/P-384/P-521) — both implement `Zeroize + ZeroizeOnDrop`. Added `agree_with_key(&SecretKey<N>)` / `agree_with_key(&SecretVec)` typed-secret methods on each struct for ergonomic use without raw slice casting.
- [x] Add type-safe public key types: `X25519PublicKey([u8; 32])`, `X448PublicKey([u8; 56])` instead of raw byte slices (done 2026-05-26)
- [x] Add `agree_to_vec` convenience method returning `Vec<u8>` instead of writing to `shared_out` (added as default method on `KeyAgreement` trait in oxicrypto-core, done 2026-05-26)
- [x] Add `#[must_use]` on `agree()` return type (added `#[must_use]` to all keygen functions; `agree()` already had `#[must_use]` via trait, done 2026-05-26)

## Testing
- [x] Add RFC 7748 Section 6.1 X25519 test vectors (Alice and Bob scalar multiplication) (done 2026-05-26)
- [x] Add RFC 7748 Section 6.2 X448 test vectors (done 2026-05-26)
- [x] Add RFC 7748 iterated test: apply X25519 1,000 times and X448 1,000 times (done 2026-05-26)
- [x] Add Wycheproof X25519 test vectors (x25519_test.json) including small-subgroup and twist attacks — implemented in tests/kat_x25519_wycheproof.rs with all 6 low-order points (identity, order-2 at u=1, p−1, Wycheproof tcId=2/3/4), active rejection documented (done 2026-05-26)
- [x] Add NIST SP 800-56A ECDH test vectors for P-256/P-384/P-521 — implemented in tests/kat_ecdh_nist.rs with 3×P-256, 2×P-384, 2×P-521 KAT vectors plus commutativity tests (done 2026-05-26)
- [x] Test: reject all-zero shared secret (indicates low-order public key) — covered in kat_x25519_wycheproof.rs and lib.rs tests (done 2026-05-26)
- [x] Test: reject public key of incorrect length — covered in lib.rs tests for all curves (done 2026-05-26)
- [x] Property test: DH commutativity — `agree(a, B) == agree(b, A)` for random key pairs — covered in kat_x25519_wycheproof.rs and kat_ecdh_nist.rs for all algorithms (done 2026-05-26)
- [x] Property test: same (secret, public) always produces same shared secret (deterministic) (done 2026-06-03)
- [x] Test: hybrid key exchange produces deterministic output from same seeds (resolved 2026-06-10)
  - **Resolution:** Round-trip tests `hybrid_xwing768_roundtrip` and `hybrid_p384_roundtrip` added to `oxicrypto/src/tests.rs` (lines after 1149). Both verify keygen → encaps → decaps produces equal shared secrets via `crate::hybrid::{XWing768, HybridKem1024P384, Kem}`.
- [x] Fuzz test: `agree()` never panics on arbitrary 32/56-byte inputs (done 2026-06-03)

## Performance
- [x] Benchmark X25519 agreement per operation vs ring/aws-lc-rs (done 2026-06-03; ring comparison sub-benchmark added to oxicrypto-bench/benches/kex.rs)
- [x] Benchmark X448 vs X25519 (X448 ~2.5x slower) (done 2026-06-03; X448 keygen/agree/agree-round-trip criterion group added)
- [x] Benchmark ECDH P-256 vs X25519 (P-256 ~1.5x slower on non-specialized hardware) (done 2026-06-03; ring P-256 comparison sub-benchmark added)
- [x] Benchmark hybrid KEM (X25519 + ML-KEM-768) total latency (resolved 2026-06-10)
  - **Resolution:** `bench_xwing768` and `bench_hybrid_p384` criterion groups added to `oxicrypto-bench/benches/pq.rs`. Each group benchmarks keygen, encapsulate, and decapsulate with `sample_size(10)` and `SamplingMode::Flat` (behind `pq-preview` feature).
- [x] Profile key generation time for all key agreement algorithms (done 2026-06-03; keygen bench group in every algorithm group)

## Integration
- [x] Wire key generation to `oxicrypto-rand` OxiRng (done 2026-06-03; `oxicrypto-rand` added as dev-dependency; `oxirng_*_generate_keypair` integration tests verify all five algorithms work with `OxiRng::new()`)
- [x] Use oxicrypto-kdf HKDF for shared-secret-to-key derivation in KEM/HPKE (labeled HKDF) (done 2026-05-30)
  - **Goal:** `HpkeKdf` enum in `src/hpke/labeled.rs` wraps `oxicrypto_kdf::hkdf_sha{256,384,512}_{extract,expand}` into RFC 9180 LabeledExtract/LabeledExpand; consumed by DHKEM ExtractAndExpand and the HPKE key schedule.
  - **Design:** approved plan blocks H2 + H4.
- [x] Coordinate with `oxicrypto-pq` ML-KEM for hybrid key exchange composition (resolved 2026-06-10)
  - **Resolution:** Dep cycle resolved in the `oxicrypto` facade layer. `oxicrypto-pq/src/hybrid.rs` already uses `oxicrypto-kex` directly (`x25519_generate_keypair`, `ecdh_p384_generate_keypair`, `X25519`, `EcdhP384`). The facade `oxicrypto::hybrid` module ties them together without creating a cycle.
- [x] Provide key exchange algorithm negotiation for OxiTLS: `negotiate_kex(group) -> Box<dyn KeyAgreement>` (done 2026-06-03; maps TLS named groups secp256r1/secp384r1/secp521r1/P-256/P-384/P-521/x25519/X25519/x448/X448 to implementations; returns UnsupportedAlgorithm for unknown groups)
- [x] Add all key exchange algorithms to `oxicrypto-bench` criterion benchmarks (done 2026-06-03; X448 keygen/agree/round-trip + ring comparisons for X25519 and P-256 added)

## Proposed follow-ups

- `hybrid-kex` (L48): Adding `oxicrypto-pq` as a dependency of `oxicrypto-kex` creates a **dependency cycle** (oxicrypto-pq depends on oxicrypto-kex). Resolution path: implement `HybridKex` in the `oxicrypto` facade crate (which already depends on both kex and pq), or create a new thin `oxicrypto-hybrid` crate. Note: `XWing768` in `oxicrypto-pq` already provides ML-KEM-768 + X25519; the HKDF-combiner variant this item requests would be a different (non-standard) construction.
