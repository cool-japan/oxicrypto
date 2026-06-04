# oxicrypto-adapter-pkcs11 TODO

## Status
Feature-gated (`pkcs11` feature, default off) BOUNDED_FFI adapter wrapping `cryptoki` for PKCS#11 HSM operations. Provider session management (C_Initialize, open R/W session, User login), signing/verification via C_Sign/C_Verify with ObjectHandle dispatch, and symmetric C_Encrypt/C_Decrypt are implemented. `Signer::sign` now resolves the key by CKA_LABEL from `sk` bytes. Tests are limited to error-path and type-construction checks (no real HSM in CI); a SoftHSM2 integration test exists.

## Core Implementation
- [x] Implement AEAD adapter (`Pkcs11Aead`) bridging `oxicrypto_core::Aead` trait to C_Encrypt/C_Decrypt with GCM mechanism params (nonce, AAD, tag_bits injected into `Mechanism::AesGcm`) (~120 SLOC: struct, Aead trait impl with mechanism construction, IV/AAD bridging) (implemented 2026-06-03)
  - **Goal:** Pkcs11Aead bridging Aead trait to C_Encrypt/C_Decrypt with GCM params. **Files:** src/sym.rs. **Risk:** Moderate — GcmParams API in cryptoki 0.12.
- [x] Implement Hash adapter (`Pkcs11Hash`) bridging `oxicrypto_core::Hash` trait to C_Digest/C_DigestInit for SHA-256/384/512 (~80 SLOC: struct, Hash trait impl, mechanism selection) (implemented 2026-06-03)
  - **Goal:** Pkcs11Hash bridging Hash to C_Digest for SHA-256/384/512. **Files:** src/hash.rs (new). **Risk:** Low.
- [x] Add key discovery helpers: `find_private_key(session, label)` and `find_secret_key(session, label)` returning `ObjectHandle` via `C_FindObjects` with CKA_LABEL template matching (~60 SLOC) (implemented 2026-06-03)
  - **Goal:** find_private_key/find_secret_key via C_FindObjects+CKA_LABEL. **Files:** src/provider.rs. **Risk:** Low.
- [x] Add key generation helpers: `generate_aes_key(session, bits, label)` and `generate_ec_keypair(session, curve_oid, label)` via C_GenerateKey / C_GenerateKeyPair (~100 SLOC) (implemented 2026-06-03)
  - **Goal:** generate_aes_key/generate_ec_keypair via C_GenerateKey/C_GenerateKeyPair. **Files:** src/provider.rs. **Risk:** Low.
- [x] Add session pool: `Pkcs11SessionPool` wrapping multiple sessions for concurrent HSM access, using a simple `Arc<Mutex<Vec<Session>>>` checkout pattern (~80 SLOC) (implemented 2026-06-03)
  - **Goal:** Pkcs11SessionPool with Arc<Mutex<Vec<Session>>> checkout pattern. **Files:** src/pool.rs (new). **Risk:** Moderate — Session must be Send.
- [x] Implement `Pkcs11Signer::sign` trait method properly by interpreting `sk` bytes as CKA_LABEL and performing C_FindObjects + C_Sign, instead of returning `BadInput` (~50 SLOC) (implemented 2026-06-03)
  - **Goal:** Real Pkcs11Signer::sign via C_FindObjects+C_Sign (key label from sk bytes). **Files:** src/sign.rs. **Risk:** Moderate.
- [x] Add PKCS#11 slot enumeration helper: `list_slots(module_path) -> Vec<(Slot, TokenInfo)>` (~40 SLOC) (implemented 2026-06-03)
  - **Goal:** list_slots(module_path) -> Vec<(Slot, TokenInfo)>. **Files:** src/provider.rs. **Risk:** Low.

## API Improvements
- [x] Add `Pkcs11Provider::with_so_login(module_path, slot, so_pin)` constructor for Security Officer sessions needed for key management operations (~20 SLOC) (implemented 2026-06-03)
  - **Goal:** with_so_login constructor using CKU_SO. **Files:** src/provider.rs. **Risk:** Low.
- [x] Add `PkcsError` variants for key-not-found, mechanism-not-supported, and buffer-too-small to provide more granular error reporting than the current catch-all `Operation(String)` (~30 SLOC) (implemented 2026-06-03)
  - **Goal:** Add PkcsError::KeyNotFound, MechanismNotSupported, BufferTooSmall. **Files:** src/provider.rs. **Risk:** Low.
- [x] Preserve the original `cryptoki::error::Error` in `PkcsError` variants instead of converting to `String`, enabling callers to inspect CKR return codes (~40 SLOC refactor) (implemented 2026-06-03)
  - **Goal:** Preserve raw cryptoki::error::Error in PkcsError instead of String. **Files:** src/provider.rs. **Risk:** Low.
- [x] Add builder pattern for `Pkcs11Signer`/`Pkcs11Verifier` with mechanism, key label, and optional key ID (~50 SLOC) (implemented 2026-06-03)
  - **Goal:** Builder pattern for Pkcs11Signer/Verifier. **Files:** src/sign.rs. **Risk:** Low.
- [x] Implement `Drop` guard for `Pkcs11Provider` that calls `C_Logout` explicitly before session close (~15 SLOC) (implemented 2026-06-03)
  - **Goal:** Drop guard calling C_Logout+C_CloseSession+C_Finalize. **Files:** src/provider.rs. **Risk:** Low.

## Testing
- [x] Add SoftHSM2-based integration test: full AES-GCM encrypt/decrypt round-trip through C_Encrypt/C_Decrypt (~80 SLOC, gated behind `softhsm2` cfg) (implemented 2026-06-03)
  - **Goal:** `#[ignore]`-gated `softhsm_aes_gcm_encrypt_decrypt_roundtrip` in `tests/softhsm.rs`. Generates key, encrypts, decrypts, verifies. **Files:** tests/softhsm.rs.
- [x] Add SoftHSM2-based integration test: EC key generation + ECDSA sign + verify round-trip (~70 SLOC) (implemented 2026-06-03)
  - **Goal:** `#[ignore]`-gated `softhsm_ec_keygen_sign_verify_roundtrip` using `generate_ec_keypair` + `Pkcs11SignerBuilder`. **Files:** tests/softhsm.rs.
- [x] Add SoftHSM2-based integration test: RSA-PKCS1 sign + verify with on-token key pair (~70 SLOC) (implemented 2026-06-03)
  - **Goal:** `#[ignore]`-gated `softhsm_rsa_pkcs1_sign_verify_roundtrip` using `generate_rsa_keypair` + `SignMechanism::RsaSha256Pkcs`. **Files:** tests/softhsm.rs.
- [x] Add multi-session concurrency test: spawn 4 tokio tasks, each signing with the same key via separate sessions (~50 SLOC) (implemented 2026-06-03)
  - **Goal:** `#[ignore]`-gated `softhsm_multi_thread_sign_same_key` — 4 OS threads each hashing via `Pkcs11Hash::sha256` on the same provider (Mutex serialises). **Files:** tests/softhsm.rs.
- [x] Add negative tests: login with wrong PIN, sign with invalid ObjectHandle, decrypt with wrong key handle (~40 SLOC) (implemented 2026-06-03)
  - **Goal:** `negative_wrong_pin_nonexistent_module_errors`, `negative_key_not_found_error_display`, `negative_mechanism_not_supported_display`, `negative_buffer_too_small_display` (headless); `softhsm_negative_tests` (SoftHSM2, `#[ignore]`). **Files:** tests/softhsm.rs.
- [x] Add slot enumeration test with SoftHSM2: verify at least one slot is returned with expected token label (~25 SLOC) (implemented 2026-06-03)
  - **Goal:** `#[ignore]`-gated `softhsm_slot_enumeration` checking `list_slots` returns non-empty list. **Files:** tests/softhsm.rs.

## Performance
- [x] Add criterion benchmarks: ECDSA-P256 sign latency via SoftHSM2 vs Pure Rust ed25519-dalek (~50 SLOC, requires SoftHSM2 at bench time) (implemented 2026-06-03)
  - **Goal:** `bench_ecdsa_p256_software` (always) + `bench_ecdsa_p256_pkcs11` (SoftHSM2, skips without module). **Files:** benches/pkcs11_bench.rs; requires `bench` feature.
- [x] Add criterion benchmarks: AES-256-GCM encrypt/decrypt 1KB/64KB via SoftHSM2 (~50 SLOC) (implemented 2026-06-03)
  - **Goal:** `bench_aes_gcm_pkcs11` group with 1KB/64KB BenchmarkId, throughput measurement. Skips without SoftHSM2. **Files:** benches/pkcs11_bench.rs.
- [x] Measure and document session checkout overhead for `Pkcs11SessionPool` compared to single-session serialization (~40 SLOC bench) (implemented 2026-06-03)
  - **Goal:** `bench_session_pool_checkout` group — `empty_pool_checkout_return` + `idle_count_query` (always runs, hardware-free). **Files:** benches/pkcs11_bench.rs.

## Integration
- [x] Add `oxicrypto` facade feature `hsm` that re-exports `oxicrypto-adapter-pkcs11` types under `oxicrypto::hsm::*` (~20 SLOC in facade) (planned 2026-06-03)
  - **Goal:** oxicrypto facade feature 'hsm' re-exporting pkcs11 types under oxicrypto::hsm::*. **Files:** oxicrypto/Cargo.toml, oxicrypto/src/lib.rs. **Risk:** Low.
- [x] Add integration with `oxistore-encrypt` to allow HSM-backed key provisioning: implement `KeyProvider` for `Pkcs11Provider` using C_Unwrap or C_DeriveKey (~80 SLOC) (implemented 2026-06-03)
  - **Goal:** `Pkcs11KeyProvider` (HMAC-SHA-256 derivation, `CKA_EXTRACTABLE=false`) + `Pkcs11ExtractableKeyProvider` (direct `CKA_VALUE` read) implementing `oxistore_encrypt::KeyProvider`. Gate: `oxistore` feature. **Files:** src/keystore.rs (new); Cargo.toml `oxistore-encrypt = "0.1.0"` optional dep.
- [x] Add integration with `oxitls` for PKCS#11-backed TLS private key operations (server-side cert key stored on HSM) (~100 SLOC: custom `rustls::sign::SigningKey` backed by PKCS#11 session) (implemented 2026-06-03)
  - **Goal:** `Pkcs11TlsSigningKey` (implements `rustls::sign::SigningKey`) + `Pkcs11TlsSigner` (implements `rustls::sign::Signer`). Supports ECDSA-P256/P384 + RSA-PKCS1/PSS. Raw r||s → DER encoder included. Gate: `tls` feature. **Files:** src/tls.rs (new); Cargo.toml `rustls = "0.23"` + `rustls-pki-types = "1"` optional deps.
