# oxicrypto-kdf TODO

## Status
SA-kdf items implemented 2026-05-26. Added KBKDF SP 800-108 counter mode (SHA-256/384/512), Argon2d/Argon2i variants, SecretVec wrapping for derived keys, extract+expand KAT tests (RFC 5869 TC1/TC3 PRK+OKM), and RFC 8018 PBKDF2 test file. 122 tests passing, zero clippy warnings. Note: upstream dep `argon2 0.6.0-rc.8` is a release candidate.

## Core Implementation
- [x] Add HKDF-Extract-only and HKDF-Expand-only standalone functions per RFC 5869 Section 2 for protocols that need separated extract/expand phases (TLS 1.3 key schedule) (~40 SLOC)
- [x] `Kdf` trait impl for PBKDF2 (done 2026-05-25)
  - **Goal:** `Pbkdf2Sha256Kdf`, `Pbkdf2Sha512Kdf` implementing core `Kdf` (`derive(ikm, salt, info, out)`).
  - **Design:** ikm=password, salt=salt, info ignored/treated as extra salt context; fixed iteration count carried by the struct.
  - **Files:** `crates/oxicrypto-kdf/src/pbkdf2_kdf.rs`
  - **Tests:** consistent output; matches standalone `pbkdf2_sha256`.
  - **Risk:** Low.
- [x] `PasswordHash` trait impls (Argon2id / PBKDF2 / scrypt) (done 2026-05-25)
  - **Goal:** `Argon2idHasher`, `Pbkdf2Sha256Hasher`, `ScryptHasher` implementing core `PasswordHash` trait.
  - **Design:** Each struct carries its tuned params and implements `hash_password(password, salt, params, out)`. Reuse existing `argon2id_derive`/`pbkdf2_sha256`/`scrypt_derive`. Map params via `PasswordHashParams`.
  - **Files:** `crates/oxicrypto-kdf/src/lib.rs`, `crates/oxicrypto-kdf/src/argon2_kdf.rs`, `crates/oxicrypto-kdf/src/pbkdf2_kdf.rs`, `crates/oxicrypto-kdf/src/scrypt_kdf.rs`
  - **Tests:** known-vector for each; same input → same output; param round-trip.
  - **Risk:** Low — primitives already present.
- [x] Add balloon hashing per Boneh-Corrigan-Kupcu-Schechter (memory-hard, cache-hard, parallel-friendly alternative to Argon2) (~150 SLOC) (done 2026-05-30 — `src/balloon.rs`, SHA-256/512, delta=3 Algorithm 1, SecretVec; cross-checked byte-exact against the authors' reference impl published vectors `2ec8d833…`/`69f86890…` in `tests/kat_balloon.rs`)
  - **Goal:** A correct, deterministic `Balloon` memory-hard hash over SHA-256 (and SHA-512) with configurable `space_cost`, `time_cost`, `delta=3`, implementing the `PasswordHash` pattern used by Argon2/scrypt in this crate.
  - **Design (ultrathink):** Implement the single-buffer **Algorithm 1** from the Balloon paper precisely:
    - Expand: `buf[0]=H(cnt++‖passwd‖salt)`; `buf[m]=H(cnt++‖buf[m-1])` for `m∈[1,s)`.
    - Mix: for `t` rounds, for each `m∈[0,s)`: `buf[m]=H(cnt++‖buf[(m-1) mod s]‖buf[m])`; then `delta` pseudo-random dependencies — `idx=H(cnt++‖salt‖round‖m‖i) mod s`, `buf[m]=H(cnt++‖buf[m]‖buf[idx])`.
    - Output `buf[s-1]`. `cnt` is a little-endian u64 counter; integers length-prefixed exactly as the reference. Use `oxicrypto-hash` SHA-256/512 (no duplicate hash impl). Wrap the working buffer + output in `SecretVec` (zeroize on drop). Validate params (`space_cost≥1`, `time_cost≥1`, salt length) ⇒ `CryptoError::BadInput`.
  - **Files:** new `crates/oxicrypto-kdf/src/balloon.rs`; edit `src/lib.rs`. Facade *(stretch)*: `KdfAlgo`/password-hash arm in `crates/oxicrypto/src/algo/kdf.rs` only if it fits the existing factory shape; else note facade-sync pending.
  - **Prerequisites:** none beyond `oxicrypto-hash` (already a workspace sibling; add dep if absent — acyclic: hash depends only on core).
  - **Tests:** determinism (same inputs ⇒ same output; different salt ⇒ different output); parameter-rejection tests; **a documented reference vector cross-checked against the authors' reference implementation for small `(s,t)`** locked as a const. *Honesty note:* Balloon lacks an RFC/NIST KAT suite; correctness is pinned by the paper's algorithm + a reference-impl-derived vector, and this limitation is documented in the test file.
  - **Risk:** the counter/encoding details differ between Balloon variants. Mitigation: follow Algorithm 1 (not the parallel construction) and the reference C `balloon.c` byte layout exactly; document the exact construction in rustdoc; if the reference vector cannot be matched, return `deviated`.
- [x] Add bcrypt password hashing per OpenBSD's implementation (Blowfish-based, widely used for legacy compatibility) (~120 SLOC) (done 2026-06-02 — `src/bcrypt_kdf.rs`: full Blowfish cipher + Eksblowfish setup + bcrypt $2b$ format + base64 variant; Blowfish KAT (zero/ones/mixed/Schneier vectors), bcrypt round-trip KATs, 72-byte truncation, constant-time verify, malformed string rejection; Go x/crypto/bcrypt cross-validation vectors)
  - **Goal:** OpenBSD-compatible `$2b$`-format bcrypt in the existing `PasswordHash` pattern. No `blowfish`/`bcrypt` crate exists in the workspace — implemented from scratch in pure Rust under `#![forbid(unsafe_code)]`.
  - **Design:** New `src/bcrypt_kdf.rs`. Components: (1) Blowfish block cipher — P-array (18×u32) + 4 S-boxes (256×u32 each, standard π-digit initialization constants), 16-round Feistel `encrypt_block`, key schedule `expand_key(key, data)`. (2) Eksblowfish — cost-parameterized setup: `2^cost` iterations of alternating `EksBlowfishSetup` key/salt mixing. (3) bcrypt — encrypt the constant `b"OrpheanBeholderScryDoubt"` (3 64-bit blocks) 64 times → 23 output bytes; bcrypt base64 variant; `$2b$cc$<22-char salt><31-char hash>` string format; 72-byte NUL-inclusive password truncation ($2b semantics). Module shape matches existing `argon2_kdf.rs`/`scrypt_kdf.rs` pattern: `BcryptParams { cost: u32 }` impl `PasswordHashParams` (validate `cost ∈ [4,31]`, presets: interactive=10, moderate=12, sensitive=14), `BcryptHasher` impl `PasswordHash`, free fns `bcrypt_hash(password: &[u8], cost: u32, salt: &[u8]) -> Result<String, CryptoError>` and `bcrypt_verify(password: &[u8], hash_str: &str) -> Result<bool, CryptoError>`. No new crate dependency.
  - **Files:** `src/bcrypt_kdf.rs` (new), `src/lib.rs` (add `pub mod bcrypt_kdf` + re-export block).
  - **Prerequisites:** None — no external crate needed; entire implementation is self-contained pure Rust.
  - **Tests:** (a) Blowfish ECB KAT using Eric Young's standard reference vectors (validates cipher + S-boxes in isolation); (b) bcrypt `$2b$` string KATs from well-known test vectors; (c) hash→verify round-trip; (d) wrong-password rejected (constant-time verify); (e) cost parameter honored; (f) 72-byte truncation behavior; (g) malformed `$…$` string rejected without panic.
  - **Risk:** Highest-effort item — S-box correctness and Eksblowfish alternating-schedule order are the main traps. The two KAT tiers (cipher-level + bcrypt-level) directly validate both. File may approach 600+ lines including constant tables; `splitrs` if it crosses 2000 (policy limit). Note: the TODO's "~120 SLOC" is a significant underestimate; realistic size is ~450–700 SLOC including the 4 KiB of constant tables.
- [x] Add HKDF-SHA-384 per RFC 5869 with SHA-384 as the underlying PRF (~30 SLOC)
- [x] Add KBKDF (Key-Based Key Derivation Function) per NIST SP 800-108 Rev. 1 — counter mode (SHA-256/384/512) (done 2026-05-26)
- [x] Add key stretching API: `KeyStretcher` trait with `stretch(password, params) -> DerivedKey` abstracting over Argon2/scrypt/PBKDF2/balloon (~40 SLOC) (done 2026-05-30 — `src/stretcher.rs`: object-safe `KeyStretcher`, `Stretcher`, `StretchParams` enum over Argon2id/scrypt/PBKDF2-SHA256/Balloon-SHA256, returns `SecretVec`)
  - **Goal (stretch):** `KeyStretcher` trait abstracting Argon2id / scrypt / PBKDF2 / Balloon behind `stretch(password, salt, params) -> Result<SecretVec, CryptoError>`.
  - **Design:** Object-safe trait + impls delegating to existing functions; an enum of preset params. Only land if it stays a clean additive layer.
  - **Files:** `crates/oxicrypto-kdf/src/lib.rs` (or `src/stretcher.rs`).
  - **Tests:** each backend round-trips through the trait; trait-object dispatch test.
  - **Risk:** low; skip cleanly to follow-ups if param unification gets awkward.
- [x] Add Argon2d and Argon2i variants in addition to Argon2id (done 2026-05-26)
- [x] `verify_password` constant-time verification (done 2026-05-25)
  - **Goal:** `verify_password(hasher, password, salt, expected_hash) -> Result<(), CryptoError>` via `subtle::ConstantTimeEq`.
  - **Design:** recompute hash, constant-time compare against expected. Add `subtle` to kdf Cargo.toml (workspace dep).
  - **Files:** `crates/oxicrypto-kdf/src/lib.rs`, `crates/oxicrypto-kdf/Cargo.toml`
  - **Tests:** correct password accepts; wrong password rejects.
  - **Risk:** Low.
- [x] Param presets Interactive/Moderate/Sensitive (done 2026-05-25)
  - **Goal:** Named param constants/constructors per OWASP/libsodium tiers for Argon2id, PBKDF2, scrypt.
  - **Design:** Associated constructors `Argon2Params::interactive()/moderate()/sensitive()` etc. Document the m/t/p (or iteration / N,r,p) values and their source.
  - **Files:** `crates/oxicrypto-kdf/src/argon2_kdf.rs`, `crates/oxicrypto-kdf/src/pbkdf2_kdf.rs`, `crates/oxicrypto-kdf/src/scrypt_kdf.rs`
  - **Tests:** presets produce valid params; sensitive ≥ moderate ≥ interactive cost ordering.
  - **Risk:** Low.
- [x] Add salt generation helper: `generate_salt(rng, len) -> Vec<u8>` using `oxicrypto-rand` (~15 SLOC) (done 2026-06-03)
- [x] PHC string format encode/parse for Argon2id (done 2026-05-25)
  - **Goal:** `$argon2id$v=19$m=...,t=...,p=...$salt$hash` encode + parse round-trip.
  - **Design:** Used the `password-hash` crate (enabled `password-hash` feature on argon2); exposed `argon2id_to_phc_string` / `argon2id_verify_phc`. PBKDF2/scrypt PHC left for future work.
  - **Files:** `crates/oxicrypto-kdf/src/argon2_kdf.rs`
  - **Tests:** encode→parse→verify round-trip; wrong password rejected; malformed string rejected.
  - **Risk:** Low-moderate — confirm the `password-hash` feature is enabled on argon2/scrypt/pbkdf2.

## API Improvements
- [x] Add `KdfAlgo` enum variants in facade for PBKDF2-SHA-256, PBKDF2-SHA-512, Argon2id, scrypt, KBKDF
- [x] Add `kdf_impl()` facade factory function returning `Box<dyn Kdf>` for all algorithms
- [x] Add `hkdf_sha{256,384,512}_derive_to_vec(ikm, salt, info, len) -> Result<Vec<u8>, CryptoError>` convenience wrappers (done 2026-05-26)
- [x] Enforce minimum output length (> 0) consistently across all KDFs (done 2026-06-03 — all KDFs check `out.is_empty()`/`output_len==0` at entry and return `CryptoError::BadInput`; `tests/prop_kdf.rs::all_kdfs_reject_empty_output` tests this for HKDF-SHA-{256,384,512}, PBKDF2-SHA-256, Argon2id, scrypt, Balloon, and all `hkdf_*_derive_to_vec` wrappers)
- [x] Add `PBKDF2_SHA256_MIN_ITERATIONS = 600_000` and `PBKDF2_SHA512_MIN_ITERATIONS = 210_000` (OWASP 2023) (done 2026-05-26)
- [x] Add `Argon2Params::validate()` method that checks OWASP 2023 / RFC 9106 constraints (done 2026-05-26)
- [x] Wrap derived key material in `SecretVec` from `oxicrypto-core` with `Zeroize` on drop (done 2026-05-26, via `kbkdf_counter_hmac_sha256_secret`)
- [x] Add `#[must_use]` on all derive/hash return types (done 2026-05-26)
- [x] Add `generate_salt_16()` / `generate_salt_32()` salt generation helpers via `oxicrypto-rand` (done 2026-05-26)

## Testing
- [x] Add full RFC 5869 Appendix A test vectors for HKDF-SHA-256 (TC1/TC2/TC3 in kat_hkdf.rs, extract+expand split in kat_hkdf_extract_expand.rs; done 2026-05-26)
- [x] Add RFC 5869 test vectors for HKDF-SHA-512 (TC5 in kat_hkdf.rs; done 2026-05-26)
- [x] Add RFC 8018 Section 5 PBKDF2 test vectors (kat_pbkdf2_rfc8018.rs with c=2/dkLen=32, long P/S, property tests; done 2026-05-26)
- [x] Extend existing `kat_pbkdf2.rs` with NIST SP 800-132 recommended parameter vectors (done 2026-05-30 — c=1000/2048/10000, 16-byte salts, 32/40-byte dk; cross-checked vs CPython `hashlib.pbkdf2_hmac`)
  - **Goal:** Authoritative KAT coverage for the existing scrypt and PBKDF2 impls.
  - **Design:** Add the four RFC 7914 §12 scrypt vectors (incl. the `N=16384,r=8,p=1` and `N=1048576` large case — gate the largest behind `#[ignore]`/`--release` if runtime is excessive, and `log!`/comment that it is gated) and SP 800-132-aligned PBKDF2-HMAC-SHA256 parameter vectors. Hex consts in the crate's existing KAT style.
  - **Files:** extend/new `crates/oxicrypto-kdf/tests/kat_scrypt.rs`, `tests/kat_pbkdf2.rs`.
  - **Tests:** vectors drive `scrypt_derive` / `pbkdf2_sha256` and assert exact output.
  - **Risk:** the 1 GiB scrypt case is slow; gate it explicitly and never silently skip.
- [x] Add additional Argon2id KAT vectors with `kat_argon2id.rs` — validate(), presets, salt helpers, derive_to_vec (done 2026-05-26)
- [x] Add RFC 7914 Section 12 scrypt test vectors (currently `kat_scrypt.rs` exists but may be incomplete) (done 2026-05-30 — all four §12 vectors; vectors 1-3 run by default, the `N=1048576` ≈1 GiB vector 4 is `#[ignore]`-gated `scrypt_rfc7914_vector_4_1gib`; cross-checked vs CPython `hashlib.scrypt`)
  - **Goal:** Authoritative KAT coverage for the existing scrypt and PBKDF2 impls.
  - **Design:** Add the four RFC 7914 §12 scrypt vectors (incl. the `N=16384,r=8,p=1` and `N=1048576` large case — gate the largest behind `#[ignore]`/`--release` if runtime is excessive, and `log!`/comment that it is gated) and SP 800-132-aligned PBKDF2-HMAC-SHA256 parameter vectors. Hex consts in the crate's existing KAT style.
  - **Files:** extend/new `crates/oxicrypto-kdf/tests/kat_scrypt.rs`, `tests/kat_pbkdf2.rs`.
  - **Tests:** vectors drive `scrypt_derive` / `pbkdf2_sha256` and assert exact output.
  - **Risk:** the 1 GiB scrypt case is slow; gate it explicitly and never silently skip.
- [x] Add balloon hashing test vectors from the original paper (Boneh et al.) (done 2026-05-30 — `tests/kat_balloon.rs`; paper has no RFC/NIST KAT, so pinned byte-exact to the authors' reference-impl published vectors `2ec8d833…`/`69f86890…`, then production delta=3 outputs locked against that validated reference)
- [x] Test: PBKDF2 with 0 iterations returns `BadInput` error (done 2026-06-03)
- [x] Test: Argon2id with salt < 8 bytes returns `BadInput` error (done 2026-06-03)
- [x] Test: HKDF with output > 255 * HashLen returns appropriate error (done 2026-06-03)
- [x] Test: scrypt with invalid parameters (log_n > 63, p * r overflow) returns error (done 2026-06-03)
- [x] Property test: all KDFs are deterministic — same inputs always produce same output (done 2026-06-03)
- [x] Property test: different salts produce different outputs for same password (done 2026-06-03)
- [x] Fuzz test: no KDF panics on arbitrary parameter combinations (done 2026-06-03 — `tests/prop_kdf.rs` has structured fuzz tests `fuzz_hkdf_{sha256,sha384,sha512}_no_panic`, `fuzz_pbkdf2_sha256_no_panic`, `fuzz_argon2id_no_panic`, `fuzz_scrypt_no_panic`, `fuzz_balloon_sha256_no_panic`, `fuzz_bcrypt_no_panic`; sweeps boundary-value parameter combinations and asserts no panics; coverage-guided fuzzing with `cargo-fuzz` is a separate follow-up requiring nightly)

## Performance
- [x] Benchmark Argon2id vs scrypt vs PBKDF2 at equivalent security levels (done 2026-06-03 — `benches/kdf_bench.rs::bench_password_kdfs_equivalent_security`)
- [x] Benchmark HKDF-SHA-256 vs HKDF-SHA-512 derive throughput (done 2026-06-03 — `benches/kdf_bench.rs::bench_hkdf_throughput`; sweeps output sizes 16/32/64/128 bytes)
- [x] Benchmark balloon hashing vs Argon2id for equivalent memory usage (done 2026-06-03 — `benches/kdf_bench.rs::bench_balloon_vs_argon2id`; interactive/moderate presets vs Argon2id at equivalent memory)
- [x] Profile Argon2id memory allocation pattern (m_cost = 64 MiB is significant) (done 2026-06-03 — `benches/kdf_bench.rs::bench_argon2id_memory_profiles`; sweeps m_cost 1024/4096/16384/65536 KiB)
- [x] Benchmark PBKDF2 at 310,000 / 600,000 / 1,000,000 iterations (latency targets for interactive use) (done 2026-06-03 — `benches/kdf_bench.rs::bench_pbkdf2_iterations`)
- [x] Compare bcrypt cost=12 vs Argon2id INTERACTIVE latency (done 2026-06-03 — `benches/kdf_bench.rs::bench_bcrypt_vs_argon2id`)

## Integration
- [ ] Track upstream stable release: `argon2` 0.6.0 stable — update Cargo.toml when RC graduates [BLOCKED: upstream argon2 crate still on RC as of 2026-06-03]
- [x] Wire salt generation to `oxicrypto-rand` OxiRng (done 2026-06-03 — `generate_salt(rng, len)` in `src/lib.rs` takes `&mut oxicrypto_rand::OxiRng` directly; `generate_salt_16()`/`generate_salt_32()` use `oxicrypto_rand::random_bytes`)
- [ ] Ensure HKDF uses `oxicrypto-mac` HMAC internally (currently uses `hkdf` crate directly; consider whether wrapping adds value or just indirection) [DEFERRED: adds indirection without security benefit; revisit if oxicrypto-mac gains FIPS compliance value]
- [ ] Provide KDF algorithm negotiation for OxiTLS: TLS 1.3 key schedule uses HKDF-Expand-Label [BLOCKED on `oxicrypto-tls` design; `hkdf_expand_label_sha256/sha384` already implemented in `src/hkdf_label.rs`]
- [ ] Coordinate with `oxicrypto-kex` for ECDH/X25519 shared-secret-to-key derivation (HKDF-Expand) [BLOCKED on `oxicrypto-kex` design]
- [ ] Coordinate with `oxicrypto-pq` for ML-KEM shared-key-to-AEAD-key derivation [BLOCKED on `oxicrypto-pq` design]
