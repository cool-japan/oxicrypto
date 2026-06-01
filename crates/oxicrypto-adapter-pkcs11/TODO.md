# oxicrypto-adapter-pkcs11 TODO

## Status
Feature-gated (`pkcs11` feature, default off) BOUNDED_FFI adapter wrapping `cryptoki` for PKCS#11 HSM operations. Provider session management (C_Initialize, open R/W session, User login), signing/verification via C_Sign/C_Verify with ObjectHandle dispatch, and symmetric C_Encrypt/C_Decrypt are implemented. The `Signer`/`Verifier` trait impls intentionally return `BadInput` since PKCS#11 keys are addressed by ObjectHandle, not raw bytes. Tests are limited to error-path and type-construction checks (no real HSM in CI); a SoftHSM2 integration test exists.

## Core Implementation
- [ ] Implement AEAD adapter (`Pkcs11Aead`) bridging `oxicrypto_core::Aead` trait to C_Encrypt/C_Decrypt with GCM mechanism params (nonce, AAD, tag_bits injected into `Mechanism::AesGcm`) (~120 SLOC: struct, Aead trait impl with mechanism construction, IV/AAD bridging)
- [ ] Implement Hash adapter (`Pkcs11Hash`) bridging `oxicrypto_core::Hash` trait to C_Digest/C_DigestInit for SHA-256/384/512 (~80 SLOC: struct, Hash trait impl, mechanism selection)
- [ ] Add key discovery helpers: `find_private_key(session, label)` and `find_secret_key(session, label)` returning `ObjectHandle` via `C_FindObjects` with CKA_LABEL template matching (~60 SLOC)
- [ ] Add key generation helpers: `generate_aes_key(session, bits, label)` and `generate_ec_keypair(session, curve_oid, label)` via C_GenerateKey / C_GenerateKeyPair (~100 SLOC)
- [ ] Add session pool: `Pkcs11SessionPool` wrapping multiple sessions for concurrent HSM access, using a simple `Arc<Mutex<Vec<Session>>>` checkout pattern (~80 SLOC)
- [ ] Implement `Pkcs11Signer::sign` trait method properly by interpreting `sk` bytes as CKA_ID and performing C_FindObjects + C_Sign, instead of returning `BadInput` (~50 SLOC)
- [ ] Add PKCS#11 slot enumeration helper: `list_slots(module_path) -> Vec<(Slot, TokenInfo)>` (~40 SLOC)

## API Improvements
- [ ] Add `Pkcs11Provider::with_so_login(module_path, slot, so_pin)` constructor for Security Officer sessions needed for key management operations (~20 SLOC)
- [ ] Add `PkcsError` variants for key-not-found, mechanism-not-supported, and buffer-too-small to provide more granular error reporting than the current catch-all `Operation(String)` (~30 SLOC)
- [ ] Preserve the original `cryptoki::error::Error` in `PkcsError` variants instead of converting to `String`, enabling callers to inspect CKR return codes (~40 SLOC refactor)
- [ ] Add builder pattern for `Pkcs11Signer`/`Pkcs11Verifier` with mechanism, key label, and optional key ID (~50 SLOC)
- [ ] Implement `Drop` guard for `Pkcs11Provider` that calls `C_Logout` explicitly before session close (~15 SLOC)

## Testing
- [ ] Add SoftHSM2-based integration test: full AES-GCM encrypt/decrypt round-trip through C_Encrypt/C_Decrypt (~80 SLOC, gated behind `softhsm2` cfg)
- [ ] Add SoftHSM2-based integration test: EC key generation + ECDSA sign + verify round-trip (~70 SLOC)
- [ ] Add SoftHSM2-based integration test: RSA-PKCS1 sign + verify with on-token key pair (~70 SLOC)
- [ ] Add multi-session concurrency test: spawn 4 tokio tasks, each signing with the same key via separate sessions (~50 SLOC)
- [ ] Add negative tests: login with wrong PIN, sign with invalid ObjectHandle, decrypt with wrong key handle (~40 SLOC)
- [ ] Add slot enumeration test with SoftHSM2: verify at least one slot is returned with expected token label (~25 SLOC)

## Performance
- [ ] Add criterion benchmarks: ECDSA-P256 sign latency via SoftHSM2 vs Pure Rust ed25519-dalek (~50 SLOC, requires SoftHSM2 at bench time)
- [ ] Add criterion benchmarks: AES-256-GCM encrypt/decrypt 1KB/64KB via SoftHSM2 (~50 SLOC)
- [ ] Measure and document session checkout overhead for `Pkcs11SessionPool` compared to single-session serialization (~40 SLOC bench)

## Integration
- [ ] Add `oxicrypto` facade feature `hsm` that re-exports `oxicrypto-adapter-pkcs11` types under `oxicrypto::hsm::*` (~20 SLOC in facade)
- [ ] Add integration with `oxistore-encrypt` to allow HSM-backed key provisioning: implement `KeyProvider` for `Pkcs11Provider` using C_Unwrap or C_DeriveKey (~80 SLOC)
- [ ] Add integration with `oxitls` for PKCS#11-backed TLS private key operations (server-side cert key stored on HSM) (~100 SLOC: custom `rustls::sign::SigningKey` backed by PKCS#11 session)
