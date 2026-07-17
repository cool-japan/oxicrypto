# OxiCrypto TODO

**v0.2.1 released 2026-07-17 — ML-DSA-87 stack-safety (`stack_safe` module: `run_on_large_stack` + `mldsa87_*_stack_safe`, a measured 2 MiB worker-thread stack vs. the old hardcoded 8 MiB), genuine `core`-only builds via a new default-on `alloc` Cargo feature on `oxicrypto-core`/`oxicrypto-hash` (supersedes the old `no_std` feature; `cargo build --no-default-features` now links only `core`), a PQ→HKDF→AEAD hybrid public-key encryption integration test in the facade, the `aead` 0.5→0.6 `AeadInOut` migration (internal, non-breaking), a new `bench_arch_profile.sh` per-architecture benchmarking script, new `CONTRIBUTING.md`/`SECURITY.md` governance docs, dependency upgrades, and a security fix (`oxicrypto-mac` truncated-HMAC `verify_truncated`/`mac_truncated` now reject an oversized tag/output length with `CryptoError::BadInput` instead of panicking). 1736 tests pass (`--all-features`; 1612 with default features).**

**v0.2.0 released 2026-06-22 — Quarantine closure: `aws-lc` and `pkcs11` features removed from the `oxicrypto` facade. `oxicrypto-adapter-aws-lc` and `oxicrypto-adapter-pkcs11` remain as workspace members but must be depended on directly. Default facade closure is now 100% Pure Rust (`--all-features` on `oxicrypto` pulls zero C dependencies). 1673 tests pass.**

**v0.1.3 released 2026-06-19 — RFC 8032 §7.4 KAT suite for Ed448ph/Ed448ctx (6 new tests: sign, verify, tampered-message rejection, wrong-context cross-verification, oversized-context rejection). 1718 tests pass. Backlog items below are post-1.0 scope.**

**v0.1.2 released 2026-06-10 — dependency inversion (oxicrypto is now a pure leaf), HSM keygen primitives, hybrid KEM benchmarks, facade integration tests, dep upgrades (p256/p384/p521/k256 rc.10, ed448-goldilocks pre.13, x448 pre.10). Backlog items below are post-1.0 scope.**

**v0.1.1 released 2026-06-04 — version bump; all milestones M0–M5 complete.
1558 tests pass. Backlog items below are post-1.0 scope.**

Milestones derived from `../phase2/oxicrypto_blueprint.md` §Phased milestones.

## Milestones

- [x] **M0** — workspace skeleton, `-core` traits, error enum, CI scripts, `deny.toml`, `Dockerfile.ffi-audit`.
  - Gate: `cargo tree` shows zero `*-sys`. ✓ CLEAN
- [x] **M1** — SHA-2/3 + BLAKE3 + AES-GCM + ChaCha20-Poly1305 + Ed25519 + X25519 + HMAC + HKDF + rand_chacha CSPRNG.
  - Gate: rustls-rustcrypto provider can be wired by OxiTLS using only OxiCrypto re-exports.
  - All 9 sub-crates implemented, 45 tests pass, clippy clean, FFI audit clean.
- [x] **M2** — RSA + ECDSA P-256/P-384/P-521 + Ed448 + PBKDF2 + Argon2 + scrypt + AES-GCM-SIV + XChaCha20-Poly1305.
  - Gate: full RustCrypto coverage parity. ✓ 81 tests pass, clippy clean, FFI audit clean.
- [x] **M3 — `oxicrypto-pq`: ML-KEM-512/768/1024, ML-DSA-44/65/87 behind `pq-preview`** (done 2026-05-25)
  - **Goal:** New sub-crate `oxicrypto-pq` exposing `MlKem512/768/1024` (encapsulate/decapsulate)
    and `MlDsa44/65/87` (sign/verify), re-exported from the `oxicrypto` façade behind an
    off-by-default `pq-preview` feature. Gate: passes NIST FIPS 203/204 KAT vectors.
  - **Design (ultrathink):**
    - `oxicrypto-pq` (`default = []`): wraps RustCrypto `ml-kem 0.3.2` + `ml-dsa 0.1.0`.
    - KEM API: `MlKem768::generate(rng) -> (DecapKey, EncapKey)`, `EncapKey::encapsulate(rng) -> (Ciphertext, SharedKey)`, `DecapKey::decapsulate(&ct) -> SharedKey`. For KAT use `ml-kem`'s `hazmat` feature → deterministic `encapsulate_deterministic(seed)` + `from_seed` keygen.
    - DSA API: `MlDsa65::generate(rng)`, `SigningKey::sign(msg) -> Signature`, `VerifyingKey::verify(msg, sig)`. `ml-dsa`'s default `try_sign` is the deterministic (empty-context) variant → directly KAT-comparable.
    - Map all RustCrypto errors → `CryptoError::{Sign,Kex}` (add variants if missing). No `unwrap` in lib.
    - Façade `oxicrypto`: `#[cfg(feature="pq-preview")] pub mod pq { pub use oxicrypto_pq::*; }`.
  - **Files:** `oxicrypto/Cargo.toml` (member += `oxicrypto-pq`; ws deps += ml-kem, ml-dsa);
    `oxicrypto/crates/oxicrypto-pq/{Cargo.toml, src/lib.rs, src/mlkem.rs, src/mldsa.rs,
    tests/kat_mlkem.rs, tests/kat_mldsa.rs}` (NEW); `oxicrypto/crates/oxicrypto/{Cargo.toml
    (feature `pq-preview`), src/lib.rs (gated re-export)}`.
  - **Prerequisites:** none (both crates verified Pure + available).
  - **Tests:** ML-KEM KAT (FIPS 203 ACVP encap/decap, deterministic seed) per param set;
    ML-DSA KAT (FIPS 204 ACVP sigGen/sigVer) per param set; encap→decap shared-secret-equal
    and sign→verify roundtrip property tests; `cargo tree` grep asserts no `*-sys`.
    Vectors: vendor a small subset from RustCrypto's own `tests/` fixtures (match upstream)
    plus a couple of NIST ACVP quads.
  - **Risk:** `ml-dsa 0.1.0` is young — pin exactly; if a deterministic-context API gap
    appears, use the multipart/lower-level path. `pq-preview` stays off-by-default (OQ#2
    ties stabilization to FIPS-final + RustCrypto 1.0).
- [x] **M4** — `cpufeatures` runtime dispatch (AES-NI, CLMUL, SHA-NI, NEON), criterion benches vs ring/aws-lc-rs published.
  - [x] **M4 — `simd` feature (cpufeatures dispatch) + `oxicrypto-bench` (criterion vs ring/aws-lc-rs)** (done 2026-05-25)
    - **Goal:** A `simd` façade feature threads `cpufeatures`-based runtime CPU detection (AES-NI, SHA-NI, AVX2) through the symmetric/hash paths; `oxicrypto-bench` benchmarks OxiCrypto against `ring` + `aws-lc-rs` (dev-only, never shipped). Gate: benches build and run; default closure unchanged + still Pure.
    - **Design:** `cpufeatures 0.3.0` is already transitively pulled by RustCrypto AES/SHA crates. The `simd` feature makes that dispatch explicit + measurable and lets OxiCrypto's own hot loops pick a wide path at runtime via `cpufeatures::new!`-generated token checks. No `unsafe` SIMD intrinsics unless guarded by a detected token; scalar fallback always present. `oxicrypto-bench`: criterion groups for AES-GCM, ChaCha20Poly1305, SHA-256/512, Ed25519 sign/verify, X25519. `ring` and `aws-lc-rs` are **dev-dependencies of the bench crate only**.
    - **Files:** `oxicrypto/Cargo.toml` (ws deps += cpufeatures, criterion dev; member += `oxicrypto-bench`); symmetric+hash crates (thread `simd` cfg); `oxicrypto/crates/oxicrypto-bench/{Cargo.toml, benches/*.rs}` (NEW); facade `Cargo.toml` (feature `simd`).
    - **Tests:** `simd` on/off produce identical outputs (KAT parity); bench crate compiles + `cargo bench --no-run`; tree-grep asserts ring/aws-lc appear ONLY under bench dev edges.
    - **Risk:** bench dev-deps leaking onto normal edges — keep in `[dev-dependencies]` of bench crate; assert via tree-grep.
  - Gate: AES-GCM ≤ 1.5× ring; ChaCha20-Poly1305 ≤ 1.1×.
- [x] **M5 — `oxicrypto-adapter-aws-lc` + `oxicrypto-adapter-pkcs11` (Bounded FFI, off default)** (done 2026-05-25)
  - **Goal:** Two adapter crates expose OxiCrypto-compatible AEAD/sig/hash via FIPS-leaning (`aws-lc-rs 1.17.0`) and HSM (`cryptoki 0.12.0`) backends, both strictly feature-gated; default closure remains Pure. Gate: adapters compile + test; tripwire confirms aws-lc-sys/cryptoki-sys appear ONLY on adapter feature edges, never on the default closure.
  - **Design:** `oxicrypto-adapter-aws-lc` (`default=[]`, feature `aws-lc`): OxiCrypto traits via aws-lc-rs AES-128/256-GCM, ChaCha20-Poly1305, Ed25519, ECDSA-P256/P384, SHA-256/384/512; KAT parity with the RustCrypto default path (byte-identical outputs). `oxicrypto-adapter-pkcs11` (`default=[]`, feature `pkcs11`): wraps `cryptoki` — `Pkcs11Provider::new(module_path, slot, pin)` drives `C_Initialize`/`C_OpenSession`/`C_Sign`/`C_Decrypt` on token; `#[ignore]` SoftHSM integration test if `SOFTHSM2_MODULE` env set; headless unit tests for session lifecycle otherwise. Façade gated re-exports `aws_lc` and `pkcs11` modules; default depends on neither.
  - **Files:** `oxicrypto/Cargo.toml` (members += `oxicrypto-adapter-aws-lc`, `oxicrypto-adapter-pkcs11`; ws deps += cryptoki 0.12.0; aws-lc-rs promoted from M4 bench dev-dep to optional adapter dep; features `aws-lc`, `pkcs11`); `crates/oxicrypto-adapter-aws-lc/{Cargo.toml, src/{lib,aead,sign,hash}.rs, tests/{parity,purity}.rs}` (NEW); `crates/oxicrypto-adapter-pkcs11/{Cargo.toml, src/{lib,provider,sign,sym}.rs, tests/softhsm.rs}` (NEW); `crates/oxicrypto/src/lib.rs` (gated re-exports).
  - **Prerequisites:** none (aws-lc-rs already in lockfile via M4 bench dep).
  - **Tests:** parity — aws-lc-rs and RustCrypto default produce byte-identical KAT outputs for each primitive. purity — `cargo tree -p oxicrypto --edges normal` grep for `aws-lc|cryptoki` returns empty. pkcs11 — `#[ignore]` SoftHSM IT; headless session-lifecycle unit tests.
  - **Risk:** aws-lc-sys on adapter's own edges is expected; tripwire prevents façade leakage. cryptoki MSRV 1.77 < oxicrypto's floor; safe.

## Dependency inversion (2026-06-05)

- [x] Dependency inversion → oxicrypto is now a pure leaf (zero oxistore/oxitls refs). Removed adapter-pkcs11's `oxistore` feature and the `oxistore_encrypt::KeyProvider` impls; relocated the pure PKCS#11 keygen primitives (`generate_hmac_key`/`generate_extractable_aes_key`/`extract_key_value`) to `hsm_keygen.rs` (kept `pub`, `find_secret_key`/`with_session` already `pub`). Deleted the cross-workspace integration tests `oxistore_encrypt_compat.rs` / `oxitls_coexist.rs` — they now live on the oxistore/oxitls side. (done 2026-06-05)

## Per-Crate Implementation Backlog

Each subcrate has a detailed `TODO.md` in its directory. Below is a summary index with estimated total new SLOC per crate.

### oxicrypto-core (crates/oxicrypto-core/TODO.md)
**Current:** 1835 SLOC (was 187 at M0). **Priority:** High (foundational — all other crates depend on it).
- `SecretKey<N>` / `SecretVec` wrappers with `Zeroize + ZeroizeOnDrop`
- `KeyPair<SK, PK>` abstraction
- Constant-time utilities (`ct_eq`, `ct_is_zero`, `ct_select`) via `subtle`
- `StreamingHash`, `StreamingMac`, `StreamingAead` traits
- `Kem` trait for key encapsulation mechanisms
- `PasswordHash` trait, `KeyGenerator` trait
- New error variants: `Rng`, `Encoding`, `UnsupportedAlgorithm`
- Estimated new SLOC: ~450

### oxicrypto-hash (crates/oxicrypto-hash/TODO.md)
**Current:** 2129 SLOC (was 252 at M0). **Priority:** High.
- Streaming hash adapters for all existing algorithms
- SHAKE128/256 XOFs (FIPS 202), cSHAKE, TupleHash (NIST SP 800-185)
- BLAKE2b/BLAKE2s (RFC 7693) with keyed-hash mode
- BLAKE3 keyed-hash, key-derivation, XOF modes
- ParallelHash (SP 800-185) with Rayon
- SHA-512/256 truncated variant
- Estimated new SLOC: ~600

### oxicrypto-aead (crates/oxicrypto-aead/TODO.md)
**Current:** 3492 SLOC (was 359 at M0). **Priority:** High.
- Streaming/chunked AEAD API for large messages
- AES-CCM (RFC 3610), AES-OCB3 (RFC 7253), Deoxys-II
- `Aead` trait impl for AES-GCM-SIV and XChaCha20 (currently inherent methods only)
- Nonce counter manager, random-nonce helper, SealedBox format
- Key-committing AEAD construction (anti-invisible-salamander)
- Estimated new SLOC: ~750

### oxicrypto-mac (crates/oxicrypto-mac/TODO.md)
**Current:** 1851 SLOC (was 170 at M0). **Priority:** Medium.
- Streaming HMAC adapter
- HMAC-SHA-384, HMAC-SHA3-256, HMAC-SHA3-512
- CMAC-AES (RFC 4493 / SP 800-38B)
- KMAC128/256 (SP 800-185) with XOF mode
- Standalone Poly1305 (RFC 8439)
- Truncated HMAC support
- Estimated new SLOC: ~490

### oxicrypto-sig (crates/oxicrypto-sig/TODO.md)
**Current:** 4586 SLOC (was ~624 at M0). **Priority:** High.
- Ed25519 batch verification, Ed25519ctx/ph, Ed448ph
- BIP-340 Schnorr signatures (secp256k1)
- ECDSA batch verification, deterministic nonce (RFC 6979)
- RSA-PSS SHA-384/512, RSA-OAEP, RSA key generation
- `Signer`/`Verifier` trait impls for ECDSA, Ed448, RSA (currently inherent methods)
- FROST threshold signatures, MuSig2 multisig
- Track RC deps: `rsa 0.10.0-rc.18`, `p256/p384/p521 0.14.0-rc.9`, `ed448-goldilocks 0.14.0-pre.12`
- Estimated new SLOC: ~1200

### oxicrypto-kex (crates/oxicrypto-kex/TODO.md)
**Current:** 2669 SLOC (was 114 at M0). **Priority:** Medium-High.
- X448 (RFC 7748), ECDH P-256/P-384/P-521 (SP 800-56A)
- Key encapsulation API (KEM trait adapter)
- Ephemeral key generation for all algorithms
- Hybrid KEM (X25519 + ML-KEM-768)
- HPKE mode 0 (Base) per RFC 9180
- Shared-secret validation (reject all-zero)
- Estimated new SLOC: ~700

### oxicrypto-kdf (crates/oxicrypto-kdf/TODO.md)
**Current:** 3517 SLOC (was ~280 at M0). **Priority:** Medium.
- HKDF-Extract-only / Expand-only (RFC 5869 for TLS 1.3)
- `Kdf` trait for PBKDF2, `PasswordHash` trait for Argon2/scrypt
- Balloon hashing, bcrypt
- KBKDF (SP 800-108)
- PHC string format for Argon2
- Recommended parameter presets
- Track RC dep: `argon2 0.6.0-rc.8`
- Estimated new SLOC: ~650

### oxicrypto-rand (crates/oxicrypto-rand/TODO.md)
**Current:** 1062 SLOC (was 77 at M0). **Priority:** Medium.
- Fork-safe RNG with PID tracking
- Thread-local RNG, reseeding RNG (SP 800-90A)
- Secure random integers with rejection sampling
- Weighted random selection, Fisher-Yates shuffle
- ChaCha12/ChaCha8 variants
- `CryptoRng` marker trait for interop with ml-kem/ml-dsa
- Estimated new SLOC: ~500

### oxicrypto-pq (crates/oxicrypto-pq/TODO.md)
**Current:** 3242 SLOC (was ~606 at M0). **Priority:** Medium-High.
- SLH-DSA (FIPS 205) parameter sets — 10 of 12 implemented (SHA2 128s/128f/192s/192f/256s/256f + SHAKE 128s/128f/256s/256f); `SlhDsaShake192s`/`SlhDsaShake192f` not yet present anywhere in `crates/oxicrypto-pq/src/` (verified by grep, 2026-07-17)
- Hybrid KEM (ML-KEM + X25519, ML-KEM + ECDH P-384)
- PQ-TLS integration helpers
- Key/signature serialization
- `Signer`/`Verifier` and `Kem` trait implementations
- Zeroize on drop for private keys and shared secrets
- [x] Fix ML-DSA-87 stack overflow — measured (~768 KiB debug, not 8 MiB) + `stack_safe` module (`run_on_large_stack`, `mldsa87_*_stack_safe`, `OXICRYPTO_MLDSA_STACK` = 2 MiB); large arrays are already heap-backed upstream by `ml-dsa` (2026-07-17)
- Estimated new SLOC: ~800

### oxicrypto (facade) (crates/oxicrypto/TODO.md)
**Current:** 2520 SLOC (was 477 at M0). **Priority:** Medium.
- [x] Complete `SigAlgo` enum — now 12 variants (Ed25519, Ed448, EcdsaP256/384/521, RsaPkcs1v15Sha256/384/512, RsaPssSha256/384/512, SchnorrBip340), each wired through `signer_impl`/`verifier_impl` (verified against `crates/oxicrypto/src/algo/sig.rs`, 2026-07-17)
- [x] Complete `KexAlgo` enum — now 5 variants (X25519, EcdhP256/384/521, X448), wired through `kex_impl` (verified against `crates/oxicrypto/src/algo/kex.rs`, 2026-07-17)
- [x] Complete `KdfAlgo` enum — now 8 variants including `Pbkdf2Sha256`/`Pbkdf2Sha512`, `Argon2id`, `Scrypt`, `Balloon` (no longer missing PBKDF2/Argon2/scrypt), wired through `kdf_impl` (verified against `crates/oxicrypto/src/algo/kdf.rs`, 2026-07-17)
- [x] Factory functions updated for all current algorithms — `aead_impl`, `hash_impl`, `signer_impl`/`verifier_impl`, `kex_impl`, `kdf_impl`, `mac_impl` each cover every variant of their selector enum
- [x] Algorithm suite presets — `Suite` (TLS 1.3) and `PqSuite` (PQ-TLS 1.3 hybrid + hash-based-sig variant) in `crates/oxicrypto/src/version.rs`
- [x] Version info, available-algorithms listing — `version()`/`VersionInfo`, `enabled_features()`, `available_algorithms()` in `crates/oxicrypto/src/version.rs`
- Remaining: `MacAlgo` selector + `mac_impl` exist (`crates/oxicrypto/src/algo/mac.rs`) alongside a direct `HmacSha384` re-export at the crate root; most concrete signer/hasher/AEAD types are otherwise reachable only via the `*_impl()` factory functions, not as directly re-exported types (see the Quick Start section in README.md for the confirmed-working call pattern).
- Actual growth: 477 → 2520 SLOC (+2043) across 0.1.1–0.2.1, well past the original ~500-SLOC estimate.

### oxicrypto-bench (crates/oxicrypto-bench/TODO.md)
**Current:** 2966 SLOC (was ~341 at M0). **Priority:** Low-Medium.
- SHA-512, SHA3-256, BLAKE3 benchmark groups
- HMAC, AES-128-GCM, AES-GCM-SIV, XChaCha20 benchmarks
- X25519, ECDSA P-256, RSA-2048 benchmarks
- ML-KEM-768, ML-DSA-65 benchmarks
- Large-payload AEAD (64 KiB, 1 MiB)
- Constant-time statistical timing tests (dudect-style)
- Estimated new SLOC: ~550

### Total Estimated Backlog
- Current total (src/ only, 11 crates tracked above, tokei 2026-07-17): ~29,869 SLOC, up from ~3,487 SLOC at M0 — already well past the original ~10,677 SLOC target.
- Full workspace (src + tests + examples + benches, all 14 crates, tokei 2026-07-17): ~48,023 SLOC across 220 Rust files (see README.md).
- The per-crate estimates above are historical (M0-era) sizing guesses kept for context; most of the enumerated backlog items are now implemented (see the `[x]` markers above) and each crate's own `TODO.md` tracks current, detailed backlog status.

## Open Questions

1. **GOVERNANCE §7 substitution-table inclusion.** Should `ring` and `aws-lc-rs` be added explicitly to the substitution table with **OxiCrypto** as the required replacement? Today §8 only deflects users to `oxitls-adapter-rustls-rustcrypto`, which is a downstream OxiTLS concern; OxiCrypto is the more accurate canonical answer.
2. **PQ stabilization timing.** When (not whether) to graduate `pq-preview` to default-on. Tied to NIST FIPS 203/204 final + RustCrypto 1.0 releases.
3. **Audit sponsorship.** Does COOLJAPAN sponsor a formal third-party audit of `aes-gcm` + `chacha20poly1305` + `hkdf`, or rely on community review? Cost vs. ecosystem trust signal.
4. **`no_std` scope.** Full `no_std` + `alloc` from M0, or `std`-only until M2? Embedded/wasm users push for the former; complexity argues for the latter.
5. **Constant-time test harness.** Adopt `dudect`-style statistical timing tests in `oxicrypto-bench`, or rely on upstream RustCrypto's per-crate constant-time discipline? The former is a meaningful ecosystem differentiator.


---

<!-- production-readiness-backlog 2026-07-16 -->
## Production-Readiness Backlog — 2026-07-16

_Consolidated from static audit + Opus adversarial bug-hunt (48 verified defects across noffi) + baseline nextest/clippy + design investigation. See `../NOFFI_PRODUCTION_BACKLOG.md` for the full cross-project list and severity/model legend. The 4 OxiCrypto-local HMAC bugs below were fixed in 0.2.1 (2026-07-17); other items on the cross-project list may still be open — check `../NOFFI_PRODUCTION_BACKLOG.md` directly._

**Confirmed bugs — Opus-verified (untrusted-tag panics in HMAC verify/truncate):**
- [x] **S · high** `oxicrypto-mac/src/lib.rs:154` — `HmacSha256::verify_truncated` checks `n<16` but not upper bound vs 32-byte buf → `buf[..n]` OOB panic when attacker tag > digest. R2/N0 — FIXED 2026-07-17: bounded to `16..=32`, returns `CryptoError::BadInput` (verified in current source).
- [x] **S · high** `oxicrypto-mac/src/lib.rs:241` — same for `HmacSha512::verify_truncated` (n>64). R2/N0 — FIXED 2026-07-17: bounded to `16..=64`, returns `CryptoError::BadInput`.
- [x] **S · high** `oxicrypto-mac/src/lib.rs:328` — same for `HmacSha384::verify_truncated` (n>48). R2/N0 — FIXED 2026-07-17: bounded to `16..=48`, returns `CryptoError::BadInput`.
- [x] **S · med** `oxicrypto-mac/src/lib.rs:139` — `mac_truncated` (256/384/512) missing upper-bound → `copy_from_slice(&full[..n])` panic when out buf larger than digest. R2/N0 — FIXED 2026-07-17: all three `mac_truncated` variants now bound-check before `copy_from_slice`.
- Fixed: `n` is now bounded to an inclusive `16..=digest_len` range in both `mac_truncated` and `verify_truncated` for all three HMAC variants; out-of-range lengths return `CryptoError::BadInput` instead of panicking. Regression tests added in `crates/oxicrypto-mac/src/tests_inline.rs` (`hmac_sha256_truncated_oversized_rejected`, `hmac_sha512_truncated_oversized_rejected`, `hmac_sha384_truncated_oversized_rejected`, plus full-digest-length boundary cases). See `CHANGELOG.md` `[0.2.1]` § Security.
**Designed / audit:**
- [x] **A/med · Y2** sub-TODO triage 17 items (pq 8 / kdf 5 / aead 2 / hash 1 / bench 1) — DONE 2026-07-17. Implemented: (b) ML-DSA-87 stack measured + `stack_safe` mitigation (2 MiB, was 8); (c) genuine alloc-free path via new `alloc` feature on `oxicrypto-core` + `oxicrypto-hash` (`--no-default-features` = core-only, `tests/no_alloc.rs`); (d) PQ→HKDF→AEAD hybrid-encryption integration test in the facade (closes the pq/kdf + pq/aead + aead/pq coordination items with one non-cyclic deliverable); bench `bench_arch_profile.sh` records the native aarch64/NEON baseline (x86_64/AES-NI leg documented as CI deferral). RC/version-gate re-check under Latest policy: `ml-kem 0.3.2` / `ml-dsa 0.1.1` / `argon2 0.6.0-rc.8` / `slh-dsa 0.2.0-rc.5` are all already the newest crates.io releases — no bump possible. Remaining items are genuine upstream/cross-crate deferrals (pq-preview 1.0 graduation, ML-KEM keygen heap profiling, composite sigs, OxiTLS negotiation) documented precisely in each sub-crate TODO.
