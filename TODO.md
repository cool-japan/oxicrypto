# OxiCrypto TODO

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

## Per-Crate Implementation Backlog

Each subcrate has a detailed `TODO.md` in its directory. Below is a summary index with estimated total new SLOC per crate.

### oxicrypto-core (crates/oxicrypto-core/TODO.md)
**Current:** 187 SLOC. **Priority:** High (foundational — all other crates depend on it).
- `SecretKey<N>` / `SecretVec` wrappers with `Zeroize + ZeroizeOnDrop`
- `KeyPair<SK, PK>` abstraction
- Constant-time utilities (`ct_eq`, `ct_is_zero`, `ct_select`) via `subtle`
- `StreamingHash`, `StreamingMac`, `StreamingAead` traits
- `Kem` trait for key encapsulation mechanisms
- `PasswordHash` trait, `KeyGenerator` trait
- New error variants: `Rng`, `Encoding`, `UnsupportedAlgorithm`
- Estimated new SLOC: ~450

### oxicrypto-hash (crates/oxicrypto-hash/TODO.md)
**Current:** 252 SLOC. **Priority:** High.
- Streaming hash adapters for all existing algorithms
- SHAKE128/256 XOFs (FIPS 202), cSHAKE, TupleHash (NIST SP 800-185)
- BLAKE2b/BLAKE2s (RFC 7693) with keyed-hash mode
- BLAKE3 keyed-hash, key-derivation, XOF modes
- ParallelHash (SP 800-185) with Rayon
- SHA-512/256 truncated variant
- Estimated new SLOC: ~600

### oxicrypto-aead (crates/oxicrypto-aead/TODO.md)
**Current:** 359 SLOC. **Priority:** High.
- Streaming/chunked AEAD API for large messages
- AES-CCM (RFC 3610), AES-OCB3 (RFC 7253), Deoxys-II
- `Aead` trait impl for AES-GCM-SIV and XChaCha20 (currently inherent methods only)
- Nonce counter manager, random-nonce helper, SealedBox format
- Key-committing AEAD construction (anti-invisible-salamander)
- Estimated new SLOC: ~750

### oxicrypto-mac (crates/oxicrypto-mac/TODO.md)
**Current:** 170 SLOC. **Priority:** Medium.
- Streaming HMAC adapter
- HMAC-SHA-384, HMAC-SHA3-256, HMAC-SHA3-512
- CMAC-AES (RFC 4493 / SP 800-38B)
- KMAC128/256 (SP 800-185) with XOF mode
- Standalone Poly1305 (RFC 8439)
- Truncated HMAC support
- Estimated new SLOC: ~490

### oxicrypto-sig (crates/oxicrypto-sig/TODO.md)
**Current:** ~624 SLOC. **Priority:** High.
- Ed25519 batch verification, Ed25519ctx/ph, Ed448ph
- BIP-340 Schnorr signatures (secp256k1)
- ECDSA batch verification, deterministic nonce (RFC 6979)
- RSA-PSS SHA-384/512, RSA-OAEP, RSA key generation
- `Signer`/`Verifier` trait impls for ECDSA, Ed448, RSA (currently inherent methods)
- FROST threshold signatures, MuSig2 multisig
- Track RC deps: `rsa 0.10.0-rc.18`, `p256/p384/p521 0.14.0-rc.9`, `ed448-goldilocks 0.14.0-pre.12`
- Estimated new SLOC: ~1200

### oxicrypto-kex (crates/oxicrypto-kex/TODO.md)
**Current:** 114 SLOC. **Priority:** Medium-High.
- X448 (RFC 7748), ECDH P-256/P-384/P-521 (SP 800-56A)
- Key encapsulation API (KEM trait adapter)
- Ephemeral key generation for all algorithms
- Hybrid KEM (X25519 + ML-KEM-768)
- HPKE mode 0 (Base) per RFC 9180
- Shared-secret validation (reject all-zero)
- Estimated new SLOC: ~700

### oxicrypto-kdf (crates/oxicrypto-kdf/TODO.md)
**Current:** ~280 SLOC. **Priority:** Medium.
- HKDF-Extract-only / Expand-only (RFC 5869 for TLS 1.3)
- `Kdf` trait for PBKDF2, `PasswordHash` trait for Argon2/scrypt
- Balloon hashing, bcrypt
- KBKDF (SP 800-108)
- PHC string format for Argon2
- Recommended parameter presets
- Track RC dep: `argon2 0.6.0-rc.8`
- Estimated new SLOC: ~650

### oxicrypto-rand (crates/oxicrypto-rand/TODO.md)
**Current:** 77 SLOC. **Priority:** Medium.
- Fork-safe RNG with PID tracking
- Thread-local RNG, reseeding RNG (SP 800-90A)
- Secure random integers with rejection sampling
- Weighted random selection, Fisher-Yates shuffle
- ChaCha12/ChaCha8 variants
- `CryptoRng` marker trait for interop with ml-kem/ml-dsa
- Estimated new SLOC: ~500

### oxicrypto-pq (crates/oxicrypto-pq/TODO.md)
**Current:** ~606 SLOC. **Priority:** Medium-High.
- SLH-DSA (FIPS 205) all 12 parameter sets
- Hybrid KEM (ML-KEM + X25519, ML-KEM + ECDH P-384)
- PQ-TLS integration helpers
- Key/signature serialization
- `Signer`/`Verifier` and `Kem` trait implementations
- Zeroize on drop for private keys and shared secrets
- Fix ML-DSA-87 stack overflow (box large arrays)
- Estimated new SLOC: ~800

### oxicrypto (facade) (crates/oxicrypto/TODO.md)
**Current:** 477 SLOC. **Priority:** Medium.
- Complete `SigAlgo` enum (currently only Ed25519 despite 8 algorithms implemented)
- Complete `KexAlgo` enum (currently only X25519)
- Complete `KdfAlgo` enum (missing PBKDF2/Argon2/scrypt)
- Update all factory functions for new algorithms
- Algorithm suite presets (TLS 1.3, PQ-TLS 1.3)
- Version info, available-algorithms listing
- Estimated new SLOC: ~500

### oxicrypto-bench (crates/oxicrypto-bench/TODO.md)
**Current:** ~341 SLOC. **Priority:** Low-Medium.
- SHA-512, SHA3-256, BLAKE3 benchmark groups
- HMAC, AES-128-GCM, AES-GCM-SIV, XChaCha20 benchmarks
- X25519, ECDSA P-256, RSA-2048 benchmarks
- ML-KEM-768, ML-DSA-65 benchmarks
- Large-payload AEAD (64 KiB, 1 MiB)
- Constant-time statistical timing tests (dudect-style)
- Estimated new SLOC: ~550

### Total Estimated Backlog
- Current total: ~3,487 SLOC (across all subcrates)
- Estimated new SLOC: ~7,190
- Target total: ~10,677 SLOC (realistic for a production-grade crypto library)

## Open Questions

1. **GOVERNANCE §7 substitution-table inclusion.** Should `ring` and `aws-lc-rs` be added explicitly to the substitution table with **OxiCrypto** as the required replacement? Today §8 only deflects users to `oxitls-adapter-rustls-rustcrypto`, which is a downstream OxiTLS concern; OxiCrypto is the more accurate canonical answer.
2. **PQ stabilization timing.** When (not whether) to graduate `pq-preview` to default-on. Tied to NIST FIPS 203/204 final + RustCrypto 1.0 releases.
3. **Audit sponsorship.** Does COOLJAPAN sponsor a formal third-party audit of `aes-gcm` + `chacha20poly1305` + `hkdf`, or rely on community review? Cost vs. ecosystem trust signal.
4. **`no_std` scope.** Full `no_std` + `alloc` from M0, or `std`-only until M2? Embedded/wasm users push for the former; complexity argues for the latter.
5. **Constant-time test harness.** Adopt `dudect`-style statistical timing tests in `oxicrypto-bench`, or rely on upstream RustCrypto's per-crate constant-time discipline? The former is a meaningful ecosystem differentiator.
