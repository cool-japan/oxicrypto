# Changelog

All notable changes to OxiCrypto are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

## [0.2.1] - 2026-07-17

### Added

- **`stack_safe` module — `run_on_large_stack` / `mldsa87_generate_stack_safe` / `mldsa87_sign_stack_safe` / `mldsa87_verify_stack_safe` / `OXICRYPTO_MLDSA_STACK`** (oxicrypto-pq) — stack-safe helpers for ML-DSA-87 (FIPS 204, security category 5), the crate's largest parameter set. Key generation, signing, and verification build large transient buffers (the `expand_a` NTT matrix and the `y`/`w`/`cs1`/`cs2`/`z`/`ct0` vectors) on the stack inside the upstream `ml-dsa` crate; the persistent `SigningKey`/`VerifyingKey`/`Signature` objects are already heap-backed via `module-lattice`'s `MaybeBox` (see the `ml-kem` `alloc` change in 0.1.1), so nothing further can be relocated to the heap from `oxicrypto-pq` without forking `ml-dsa`. `run_on_large_stack<F: FnOnce() -> T + Send, T: Send>` runs a closure on a scoped worker thread sized to `OXICRYPTO_MLDSA_STACK`; the three `mldsa87_*_stack_safe` functions wrap keygen/sign/verify around it and exchange owned byte vectors (32-byte seed, 2592-byte verifying key, 4627-byte signature) so callers never thread the large working set back across the thread boundary. A binary-search probe against the live crate measured the actual worst-case requirement at 768 KiB (debug) / 512 KiB (release); `OXICRYPTO_MLDSA_STACK` is set to 2 MiB (≈2.7× headroom). New `crates/oxicrypto-pq/tests/stack_safe.rs` proves the round trip succeeds on the *default* libtest worker-thread stack — no manual high-stack wrapper needed by the caller.
- **Genuine alloc-free (`core`-only) builds — new default-on `alloc` Cargo feature** (oxicrypto-core, oxicrypto-hash) — `cargo build --no-default-features` now links only `core`, no heap allocator required. In `oxicrypto-core`, `alloc` gates the `Vec`/`String`/`Box` re-exports, `SecretVec`, the `KeyGenerator` trait, and the `*_to_vec`/`seal_*`/`open_*`/`agree_to_vec`/`mac_to_vec` default methods on the `Aead`/`Hash`/`KeyAgreement`/`Mac`/`Signer` traits; the alloc-free surface (`SecretKey<N>`, `Hash::hash`, `Hash::hash_to_array::<N>`, the constant-time utilities, `CryptoError`, `AlgorithmId`) stays unconditionally available. In `oxicrypto-hash`, `alloc` gates `Hash::hash_to_vec`, `blake3_xof`, `parallel_hash*_xof`, the streaming `HashBuilder`, and the SHAKE/cSHAKE/TupleHash XOF helpers; the inherent `hash_fixed::<N>()` methods and `Hash::hash`/`hash_to_array::<N>()` remain available with `--no-default-features`. New `crates/oxicrypto-hash/tests/no_alloc.rs` exercises SHA-256, SHA-512, and BLAKE3 through only the alloc-free surface. This supersedes `oxicrypto-hash`'s old `no_std` feature (see ### Changed).
- **PQ KEM → HKDF → AEAD hybrid public-key encryption test** (oxicrypto, `pq-preview` feature) — `crates/oxicrypto/tests/pq_hybrid_encryption.rs` exercises the full KEM-DEM construction end to end for `MlKem768` and `XWing768`: encapsulate → HKDF-SHA-256 Extract-then-Expand (RFC 5869) → AES-256-GCM seal/open, asserting both sides derive an identical key, the plaintext round-trips, a tampered ciphertext is rejected with `CryptoError::InvalidTag`, and independent encapsulations derive distinct keys. The facade crate is the only place that sees `oxicrypto-pq`, `oxicrypto-kdf`, and `oxicrypto-aead` simultaneously, so this closes three previously-deferred cross-crate coordination TODOs (pq↔kdf, pq↔aead, aead↔pq) without inverting the dependency graph.
- **`bench_arch_profile.sh`** (oxicrypto-bench) — records a native-CPU-architecture Criterion baseline for the SIMD-sensitive AEAD and hash benchmark groups, saved under a per-architecture `arch-<uname -m>` baseline name (e.g. `arch-aarch64`) so runs from different machines never overwrite each other; `--archive` forwards a per-arch label to `bench_archive.sh`. The x86_64/AES-NI leg is documented as an intentional deferral — it must be recorded on x86_64 hardware/CI, not synthesized.
- **`Hash` / `StreamingHash` / `CryptoError` re-exported from the crate root** (oxicrypto-hash) — these `oxicrypto-core` items are now `pub use`-d so downstream code and integration tests can bring them into scope without an explicit `oxicrypto-core` dependency.
- **`CONTRIBUTING.md` / `SECURITY.md`** — new governance docs: build/test/lint commands and the Pure-Rust / no-panic-on-untrusted-input contributor rules; a private vulnerability-disclosure process (info@kitasan.io) with a latest-0.x-only support policy.

### Changed

- Workspace version bumped 0.2.0 → 0.2.1 (all `oxicrypto-*` member crates).
- **AEAD backend migrated to the `aead` 0.6 `AeadInOut` trait generation** (oxicrypto-aead) — `Aes128Gcm`, `Aes256Gcm`, `ChaCha20Poly1305`, `XChaCha20Poly1305`, `Aes128GcmSiv`/`Aes256GcmSiv`, the OCB3 backend, and the STREAM chunked-AEAD construction (Hoang-Reyhanitabar-Rogaway-Vizár 2015) all move from `aead 0.5`'s `AeadInPlace` (`encrypt_in_place_detached`, `GenericArray::from_slice`, `Tag::clone_from_slice`) to `aead 0.6`'s `AeadInOut` (`encrypt_inout_detached`/`decrypt_inout_detached`, `Nonce::<C>::try_from`, `Tag::<C>::try_from`). Internal only — the public `Aead` trait surface, error variants, and behavior are unchanged. Nonce/tag construction now goes through a fallible `try_from` instead of a length-panicking `GenericArray::from_slice`; every call site already validates the length beforehand, so this is a robustness improvement rather than a behavior change.
- **Dependency upgrades** (workspace) — `aes-gcm` 0.10.3 → 0.11.0, `chacha20poly1305` 0.10.1 → 0.11.0, `aead` 0.5.2 → 0.6.1, `chacha20` 0.10.0 → 0.10.1, `aes-gcm-siv` 0.11.1 → 0.12.0-rc.3 (tracks the `aead` 0.6 chain; no stable 0.12 yet), `ocb3` 0.1.0 → 0.2.0-rc.3 (ditto), `p256`/`p384`/`p521`/`k256` `0.14.0-rc.12` → `0.14.0-rc.15`, `ed448-goldilocks` `0.14.0-pre.13` → `0.14.0-pre.15`, `x448` `0.14.0-pre.10` → `0.14.0-pre.12`, `aws-lc-rs` 1.17.0 → 1.17.1.
- **`oxicrypto-hash`'s `no_std` feature replaced by `alloc`/`std`** (oxicrypto-hash) — the old `no_std` feature was a documentation-only signal with no link-time effect; it is removed in favor of a default-on `alloc` feature and a `std` feature that implies it. Breaking for anyone who referenced `--features no_std` by name directly (the crate has been pre-1.0 throughout).
- **ML-DSA-87 stack-size requirement re-measured and lowered from 8/16 MiB to 2 MiB** (oxicrypto-pq) — all ML-DSA-87 tests (`mldsa.rs`, `kat_acvp_mldsa.rs`, `kat_mldsa.rs`, `kat_nist_mldsa.rs`, `prop_mldsa.rs`) and the `pq_benchmarks.rs` criterion group now spawn worker threads sized to the new `OXICRYPTO_MLDSA_STACK` constant instead of a hardcoded `8 * 1024 * 1024` (one test previously used 16 MiB).
- **`oxicrypto-bench` marked `publish = false`** (oxicrypto-bench) — this crate is dev-only (criterion benchmarks vs. `ring`/`aws-lc-rs`); the manifest now prevents it from being accidentally published to crates.io.

### Security

- **Panic-on-oversized-length in truncated HMAC verification** (oxicrypto-mac) — `HmacSha256`/`HmacSha384`/`HmacSha512::mac_truncated` and `::verify_truncated` validated only a lower bound (`len >= 16`) before slicing the full-length digest buffer to the caller-supplied length (`&full[..n]` / `&buf[..n]`). A caller-supplied `out`/`tag` longer than the underlying digest — 33+ bytes for HMAC-SHA-256, 49+ for HMAC-SHA-384, 65+ for HMAC-SHA-512 — sliced past the end of the buffer and panicked instead of returning an error, a denial-of-service vector on any path that runs `verify_truncated` over an attacker-controlled tag length. Both methods now validate an inclusive range (`16..=digest_len`) and return `CryptoError::BadInput` for any out-of-range length. New regression tests in `crates/oxicrypto-mac/src/tests_inline.rs` cover the oversized case for all three HMAC variants plus the full-digest-length boundary.

## [0.2.0] - 2026-06-22

### Removed

- **`oxicrypto` facade**: removed `aws-lc`, `pkcs11`, and `hsm` feature flags and
  their corresponding `pub mod aws_lc`, `pub mod pkcs11`, and `pub mod hsm` re-exports
  (Pure Rust Policy v2 §5 quarantine enforcement).
- Optional dependencies `oxicrypto-adapter-aws-lc` and `oxicrypto-adapter-pkcs11`
  are no longer part of the default `oxicrypto` facade closure.

### Changed

- Workspace version bumped 0.1.3 → 0.2.0.
- The quarantine crates `oxicrypto-adapter-aws-lc` and `oxicrypto-adapter-pkcs11`
  remain as workspace members and are independently usable, but are no longer
  re-exported through the `oxicrypto` facade.

### Security

- The default feature set of `oxicrypto` is now strictly 100% Pure Rust with zero
  C-FFI crates reachable through any documented facade feature flag.

## [0.1.3] - 2026-06-19

### Added

- **RFC 8032 §7.4 KAT suite for Ed448ph / Ed448ctx** (oxicrypto-sig) — new `kat_ed448ph.rs` integration-test file pins the exact 114-byte signatures published in RFC 8032 §7.4 for two test vectors: (1) `Ed448ph` with pre-hash `SHAKE256(msg, 64)` over `"abc"` with an empty context; (2) `Ed448ctx` over `0x03` with context `"foo"`. Six tests in total cover sign, verify, tampered-message rejection (wrong message byte, mismatched context), wrong-context cross-verification, and oversized-context (> 255 bytes) rejection on sign.

## [0.1.2] - 2026-06-10

### Added

- **`generate_hmac_key` / `generate_extractable_aes_key` / `extract_key_value`** (oxicrypto-adapter-pkcs11) — pure PKCS#11 HSM key-generation and extraction primitives relocated to a new `hsm_keygen.rs` module. All three methods are `pub` on `Pkcs11Provider` and carry no cross-workspace dependencies: `generate_hmac_key` provisions a non-extractable HMAC-SHA-256 capable `CKO_SECRET_KEY` on the token; `generate_extractable_aes_key` provisions a 32-byte AES key with `CKA_EXTRACTABLE=true`; `extract_key_value` retrieves the raw `CKA_VALUE` of an extractable key.
- **Hybrid KEM benchmarks** (oxicrypto-bench) — new criterion groups for `XWing768` and `HybridKem1024P384` key encapsulation, covering keygen, encapsulate, and decapsulate round-trips.
- **`oxicrypto` facade integration tests** (crates/oxicrypto/tests.rs) — end-to-end round-trip tests for the full facade: sign/verify (Ed25519, ECDSA P-256/P-384/P-521, RSA), AEAD (AES-GCM, ChaCha20-Poly1305), key exchange (X25519), KDF (HKDF), and password hashing (Argon2id).
- **`rustls` / `rustls-pki-types` workspace dependency alignment** (oxicrypto-adapter-pkcs11) — version pins moved to workspace `[dependencies]` for consistency; `rustls` and `rustls-pki-types` are now optional deps resolved from the single workspace declaration.

### Changed

- **Dependency inversion — oxicrypto is now a pure leaf** — removed the `oxistore` feature and all `oxistore_encrypt::KeyProvider` implementations from `oxicrypto-adapter-pkcs11`. The `Pkcs11KeyProvider` / `Pkcs11ExtractableKeyProvider` bridge types that depended on `oxistore-encrypt` are removed; the equivalent HSM key-generation primitives are now in `hsm_keygen.rs` without cross-workspace ties. Cross-workspace integration tests `oxistore_encrypt_compat.rs` and `oxitls_coexist.rs` have been deleted from `oxicrypto-adapter-aws-lc` — they will live on the `oxistore` / `oxitls` side.
- **Dependency upgrades** — `p256`, `p384`, `p521`, `k256` bumped to `0.14.0-rc.10`; `ed448-goldilocks` to `0.14.0-pre.13`; `x448` to `0.14.0-pre.10`.

### Fixed

- **`oxicrypto-adapter-aws-lc` compile fix** — removed the stale cross-workspace `dev-dependencies` on `oxistore-encrypt`, `oxistore-core`, and `oxitls-adapter-aws-lc` that caused compilation failures after the dependency-inversion refactor.

## [0.1.1] - 2026-06-04

### Added

- **`CommittingAead<'a>`** (oxicrypto-aead) — UtC/CMT-1 key-committing AEAD wrapper: prepends a 32-byte HKDF-SHA-256 commitment to every ciphertext, preventing invisible-salamander and partitioning-oracle attacks (Bellare & Hoang, EUROCRYPT 2022).
- **`bcrypt`/`BcryptKdf`** (oxicrypto-kdf) — OpenBSD-compatible `$2b$` bcrypt password hashing implemented from scratch in pure Rust (Blowfish + Eksblowfish key schedule; full `$2b$cc$22-char-salt 31-char-hash` string format).
- **`StreamingHashHmac<H, F>`** (oxicrypto-mac) — generic RFC 2104 HMAC over any `StreamingHash` implementation, decoupling `oxicrypto-mac` from specific digest crates.
- **`ed25519ctx_sign` / `ed25519ctx_verify`** (oxicrypto-sig) — Ed25519ctx context-variant signatures per RFC 8032 §5.1.5, providing protocol-level domain separation via a `dom2(0, ctx)` prefix.
- **`ed25519ph_sign` / `ed25519ph_verify` / `ed25519ph_sign_prehash`** (oxicrypto-sig) — Ed25519ph prehash variant (RFC 8032 §5.1.6) for streaming large messages.
- **MuSig2 multi-signature** (oxicrypto-sig) — two-round n-of-n multi-signature protocol for Ed25519 (Nick–Ruffing–Seurin 2021): `musig2_commit`, `musig2_sign`, `musig2_aggregate`, `musig2_verify`, `musig2_verify_ed25519`, types `MuSig2SecretKey`, `MuSig2PublicKey`, `SecNonce` (single-use, zeroized on drop), `PubNonce`, `PartialSig`, `MuSig2Signature`.
- **`negotiate_kex`** (oxicrypto-kex) — resolve TLS named group strings (`"x25519"`, `"secp256r1"`, `"P-384"`, …) to a boxed `KeyAgreement` implementation for TLS stack integration.
- **`X25519::agree_with_key` / `EcdhP256::agree_with_secret`** (oxicrypto-kex) — typed-key overloads accepting `SecretKey<N>` / `SecretVec` for compile-time type safety.
- **`NonceSequence::with_random_prefix`** (oxicrypto-aead, `rand` feature) — construct a `NonceSequence` with a cryptographically secure random prefix drawn from `OxiRng`.
- **`AlgorithmId::Blake2s256`, `Aes128Ocb3`, `Aes256Ocb3`, `RsaPssSha384`, `RsaPssSha512`** (oxicrypto-core) — new algorithm identifiers for previously-missing variants.
- **`AwsLcHkdf`** (oxicrypto-adapter-aws-lc) — HKDF-SHA-256/384/512 backed by `aws-lc-rs`, implementing the `Kdf` trait.
- **`AwsLcHmac`** (oxicrypto-adapter-aws-lc) — HMAC-SHA-256/384/512 backed by `aws-lc-rs`, implementing the `Mac` trait.
- **`Pkcs11KeyProvider` / `Pkcs11ExtractableKeyProvider`** (oxicrypto-adapter-pkcs11, `oxistore` feature) — `oxistore-encrypt::KeyProvider` bridge: derives a 32-byte key via HMAC-SHA-256 on the HSM or extracts an AES key directly from a `CKA_EXTRACTABLE` token object; key bytes are zeroized on drop.
- **PKCS#11 session pool** (oxicrypto-adapter-pkcs11) — `Pkcs11SessionPool` with bounded slot reuse and `Pkcs11TlsProvider` for TLS-layer sign/verify offload to an HSM.
- **`SigningKey44/65/87::verifying_key`** (oxicrypto-pq) — ergonomic accessor returning the matching `VerifyingKey*` without separate derivation.
- **`hash_fixed`** methods (oxicrypto-hash) — alloc-free `[u8; N]`-returning hash helpers on all concrete hash types (`Sha256`, `Sha384`, `Sha512`, `Sha512_256`, `Sha3_*`, `Blake2b*`, `Blake2s256`, `Blake3`), recommended for `no_std`/embedded callers.
- **`OUTPUT_LEN` constants** (oxicrypto-hash) — added `OUTPUT_LEN: usize` alias to all hash types alongside `DIGEST_LEN` for use in generic const contexts.
- **`serde` feature for `CryptoError`** (oxicrypto-core) — `Serialize` derived and a hand-written `Deserialize` (avoids lifetime issues with `Internal(&'static str)`; the payload is intentionally dropped on round-trip).
- **`serde` and `oxicode`** added to workspace dependencies.
- **Wycheproof KAT tests** (oxicrypto-hash, oxicrypto-mac) — `kat_wycheproof.rs` for hash algorithms; `kat_cmac_nist.rs`, `kat_hmac_sha384.rs`, `kat_hmac_wycheproof.rs`, `kat_kmac_nist.rs`, `kat_poly1305_rfc8439.rs` for MAC algorithms.
- **ACVP/NIST KAT tests** (oxicrypto-pq) — `kat_acvp_mldsa.rs`, `kat_nist_mldsa.rs`, `kat_mldsa.rs` with FIPS 204 test vectors.
- **`ECDSA::sign_fmt` / `verify_fmt`** (oxicrypto-sig) — `SignatureFormat` enum (`Der` | `Raw`) on P-256/P-384/P-521 signers/verifiers to output raw `r ‖ s` or DER-encoded signatures.
- **`EcdsaP256Signer::sign_with_hash` / `EcdsaP256Verifier::verify_with_hash` / `verify_prehash`** (oxicrypto-sig) — hash-agnostic signing and pre-hash verification paths for P-256.
- **RSA PKCS#1 DER helpers** (oxicrypto-sig) — `from_pkcs1_der` / `to_pkcs1_der` / `from_pkcs8_pem` / `to_pkcs8_pem` shared helpers for RSA key import/export.
- **Benchmark scripts** (oxicrypto-bench) — `bench_archive.sh`, `bench_compare.sh`, `bench_ratios.py`, `bench_simd_compare.sh`, `bench_summary.py`; new criterion groups for RNG, factory overhead, and AEAD throughput.
- **Fuzz targets** (oxicrypto-hash, oxicrypto-sig) — `fuzz_hash_no_panic`, `fuzz_streaming_equivalence`, `fuzz_xof_no_panic`, `fuzz_sig`.

### Changed

- **`ml-kem` workspace dep** — enabled `alloc` feature so ML-KEM and ML-DSA key structs (`A_hat` matrix ~48 KB for ML-DSA-65) are heap-allocated via `MaybeBox`, eliminating test-thread stack overflows.
- **`OxiRng` RNG in ML-KEM/ML-DSA/hybrid KEMs** — replaced ad-hoc `getrandom + rand_chacha::from_seed` pattern with `OxiRng::new().map(rand_core::UnwrapErr)` for consistent fork-safe entropy sourcing across the workspace.
- **`OxiRng` / `OxiRng8` / `OxiRng12` thread-safety documentation** — explicitly documents `Send` + `!Sync` semantics; added compile-time `_assert_send` assertions for all three types.
- **`AlgorithmId` category routing** — `Blake2s256`, `Aes128Ocb3`, `Aes256Ocb3`, `RsaPssSha384`, `RsaPssSha512` now route to the correct `AlgorithmCategory` in `AlgorithmId::category()`.
- **`Aead` trait documentation** — expanded with a key-length reference table and note on `debug` feature supertrait.
- **`EcdsaP256Signer::signing_key` / `EcdsaP256Verifier::verifying_key` visibility** — changed from private to `pub(crate)` to enable intra-crate composition (e.g. `sign_with_hash`).
- **`serde` and `oxicode` added to workspace `[dependencies]`** — available for all member crates with consistent versions.
- **Dev profile optimization** — `[profile.dev.package."*"]` set to `opt-level = 3` so crypto-heavy external deps (SLH-DSA, Keccak, SHAKE) compile fast in tests; workspace crates stay at opt-level 0. `oxicrypto-pq` explicitly set to opt-level 3 to handle SLH-DSA monomorphization.

### Fixed

- **ML-DSA test-thread stack overflow** — ML-DSA-65 `A_hat` key matrix (~48 KB) previously lived on the stack; enabling `ml-kem`'s `alloc` feature boxes it via `MaybeBox`, fixing intermittent stack overflows in nextest.
- **`oxicrypto-hash` `no_std` doc comment** — corrected misleading note about `alloc` linkage: the crate always links `alloc`; the `no_std` feature flag is an API-guidance signal, not a link-time exclusion.

## [0.1.0] — 2026-06-01

Initial public release of the OxiCrypto Pure Rust cryptographic primitive
workspace. All milestones M0–M5 are complete.

### Crates

| Crate | Description |
|---|---|
| `oxicrypto-core` | Trait surface: `Hasher`, `Mac`, `Aead`, `Signer`, `Verifier`, `Kex`, `Kem`, `Kdf`, `PasswordHasher`, `CryptoRng` |
| `oxicrypto-hash` | SHA-2, SHA-3, BLAKE2, BLAKE3, SHAKE/cSHAKE/KMAC XOFs, ParallelHash, TupleHash |
| `oxicrypto-aead` | AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV, XChaCha20-Poly1305, AES-CCM, OCB3, Deoxys-II, HPKE (RFC 9180) |
| `oxicrypto-cipher` | AES single-block ECB, ChaCha20 keystream (QUIC header protection) |
| `oxicrypto-mac` | HMAC-SHA-{256,384,512}, HMAC-SHA3-{256,512}, CMAC-AES, Poly1305, KMAC128/256 |
| `oxicrypto-sig` | Ed25519, Ed448, ECDSA (P-256/384/521), BIP-340 Schnorr (secp256k1), RSA PKCS#1v15/PSS, FROST threshold (RFC 9591) |
| `oxicrypto-kex` | X25519, X448, ECDH (P-256/384/521), HPKE key exchange |
| `oxicrypto-kdf` | HKDF, PBKDF2 (SHA-256/512), Argon2id, scrypt, Balloon, KBKDF |
| `oxicrypto-rand` | ChaCha20 CSPRNG, fork-safe reseeding RNG, thread-local RNG |
| `oxicrypto-pq` | ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204), SLH-DSA all 12 param sets (FIPS 205), hybrid X-Wing/ML-KEM+P-384 |
| `oxicrypto` | Unified façade re-exporting all sub-crates; `pq-preview` feature for post-quantum primitives |
| `oxicrypto-bench` | Criterion benchmarks vs. `ring` and `aws-lc-rs` (dev-only) |
| `oxicrypto-adapter-aws-lc` | Bounded FFI adapter: FIPS-leaning AES-GCM/ChaCha20/Ed25519/ECDSA via `aws-lc-rs` (off by default) |
| `oxicrypto-adapter-pkcs11` | Bounded FFI adapter: HSM sign/decrypt via `cryptoki` (off by default) |

### Added

**M0 — Workspace skeleton (2026-05-24)**
- Workspace Cargo.toml with `resolver = "2"`, MSRV 1.89, edition 2021
- `oxicrypto-core` trait surface: `CryptoError`, `Hasher`, `Mac`, `Aead`, `Signer`,
  `Verifier`, `Kex`, `Kem`, `Kdf`, `PasswordHasher`, `CryptoRng`
- `SecretKey<N>`, `SecretVec` with `Zeroize + ZeroizeOnDrop`
- `deny.toml` — cargo-deny policy (zero `*-sys` on default closure)
- `Dockerfile.ffi-audit` — FFI audit container

**M1 — Core symmetric + asymmetric primitives (2026-05-24)**
- SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE3 hashing
- AES-128/256-GCM, ChaCha20-Poly1305 AEAD
- Ed25519 sign/verify (dalek ecosystem)
- X25519 key exchange
- HMAC-SHA-256, HMAC-SHA-512
- HKDF-SHA-256, HKDF-SHA-512
- ChaCha20 CSPRNG seeded via `getrandom`
- 45 tests, zero `*-sys` in default closure

**M2 — Full RustCrypto coverage parity (2026-05-25)**
- RSA PKCS#1v15 and PSS signatures (SHA-256/384/512)
- ECDSA P-256, P-384, P-521
- Ed448 sign/verify (goldilocks curve)
- PBKDF2 (SHA-256/512), Argon2id, scrypt
- AES-GCM-SIV, XChaCha20-Poly1305 AEAD
- 81 tests pass

**M3 — Post-quantum preview (2026-05-25)**
- `oxicrypto-pq` sub-crate: ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204)
- `pq-preview` feature on `oxicrypto` façade
- KAT vectors from NIST ACVP

**M4 — SIMD dispatch + criterion benchmarks (2026-05-25)**
- `simd` feature: `cpufeatures` runtime detection of AES-NI, SHA-NI, AVX2
- `oxicrypto-bench`: criterion groups for AES-GCM, ChaCha20-Poly1305,
  SHA-256/512, Ed25519, X25519 vs. `ring` and `aws-lc-rs`
- `ring` and `aws-lc-rs` appear only as bench dev-dependencies (never on default closure)

**M5 — Bounded FFI adapters (2026-05-25)**
- `oxicrypto-adapter-aws-lc`: AES-128/256-GCM, ChaCha20-Poly1305, Ed25519,
  ECDSA P-256/P-384, SHA-256/384/512 via `aws-lc-rs 1.17.0`; off by default
- `oxicrypto-adapter-pkcs11`: `Pkcs11Provider` (C_Initialize, C_OpenSession,
  C_Sign, C_Decrypt) via `cryptoki 0.12.0`; off by default
- KAT parity: aws-lc adapter produces byte-identical outputs to RustCrypto default

**Post-M5 extensions (2026-05-25 – 2026-05-31)**
- BLAKE2b/BLAKE2s keyed-hash, SHAKE128/256 XOFs, cSHAKE, KMAC128/256, TupleHash,
  ParallelHash (SP 800-185)
- CMAC-AES (RFC 4493), Poly1305 standalone
- AES-CCM, AES-OCB3, Deoxys-II AEAD
- HPKE RFC 9180 (Base, PSK, Auth, AuthPSK modes; X25519+SHA-256+AES-128-GCM,
  X25519+SHA-256+ChaCha20-Poly1305, P-256+SHA-256+AES-128-GCM)
- SLH-DSA all 12 parameter sets (SHA2/SHAKE × 128/192/256 × s/f) — FIPS 205
- Hybrid KEMs: X-Wing (ML-KEM-768 + X25519), ML-KEM-768 + P-384
- BIP-340 Schnorr signatures (secp256k1/k256)
- FROST Ed25519 threshold signatures (RFC 9591)
- Balloon password hashing, KBKDF (SP 800-108)
- X448 key exchange
- 1116 tests pass; 24 slow SLH-DSA `-s` parameter tests marked `#[ignore]`

### Security

All algorithms are implemented via reviewed RustCrypto crates pinned at exact
versions in `Cargo.toml`. No custom cryptographic primitives are written.
The default feature set is 100% Pure Rust with zero `*-sys` crates.
Bounded FFI adapters (aws-lc, pkcs11) are strictly feature-gated.

[0.2.1]: https://github.com/cool-japan/oxicrypto/releases/tag/v0.2.1
[0.2.0]: https://github.com/cool-japan/oxicrypto/releases/tag/v0.2.0
[0.1.3]: https://github.com/cool-japan/oxicrypto/releases/tag/v0.1.3
[0.1.2]: https://github.com/cool-japan/oxicrypto/releases/tag/v0.1.2
[0.1.1]: https://github.com/cool-japan/oxicrypto/releases/tag/v0.1.1
[0.1.0]: https://github.com/cool-japan/oxicrypto/releases/tag/v0.1.0
