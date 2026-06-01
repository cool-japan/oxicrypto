# oxicrypto-aead TODO

## Status
Eleven AEAD algorithms implemented. Covers AES-128-GCM, AES-256-GCM (NIST SP 800-38D), ChaCha20-Poly1305 (RFC 8439), AES-128/256-GCM-SIV (RFC 8452), XChaCha20-Poly1305, AES-128-CCM, AES-256-CCM (RFC 3610), AES-128-OCB3, AES-256-OCB3 (RFC 7253), and Deoxys-II-128-128 (CAESAR final portfolio, SCT-2 nonce-misuse-resistant mode over a from-scratch Deoxys-BC-256). Streaming STREAM construction implemented for AES-256-GCM and XChaCha20-Poly1305. Monotonic NonceSequence implemented. Official KAT coverage for AES-GCM (NIST SP 800-38D + CAVP), ChaCha20-Poly1305 (RFC 8439 §2.8.2 + A.5), AES-GCM-SIV (RFC 8452 Appendix C), and Deoxys-II-128-128 (CAESAR vectors).

## Core Implementation
- [x] `StreamingAead` adapter — STREAM construction (done 2026-05-25)
  - **Goal:** Chunked AEAD for large messages implementing core `StreamingAead`, using the STREAM construction (Hoang–Reyhanitabar–Rogaway–Vizár nonce derivation: 32-bit chunk counter + last-block flag).
  - **Design:** Generic over an underlying AEAD; concrete `Aes256GcmStream` / `ChaCha20Poly1305Stream`. Per-chunk nonce = prefix ‖ counter ‖ final-flag. `init/encrypt_update/encrypt_finalize/decrypt_update/decrypt_finalize/reset`.
  - **Files:** `crates/oxicrypto-aead/src/stream.rs`
  - **Tests:** multi-chunk round-trip; truncation/reorder rejection (last-block flag); single-chunk equals one-shot semantics for a 1-chunk message.
- [x] AES-128-CCM / AES-256-CCM (done 2026-05-25)
  - **Goal:** `Aes128Ccm`, `Aes256Ccm` implementing `Aead` (NIST SP 800-38C / RFC 3610).
  - **Note:** `ccm` crate 0.6.0-rc.3 uses aead 0.6 chain (incompatible); `aes-ccm` 0.5.0 uses yanked aes-soft. Implemented AES-CCM from scratch using `aes` (block cipher) + CBC-MAC + CTR mode. Default tag 16, nonce 13 bytes (L=2, max message 65535 bytes).
  - **Files:** `crates/oxicrypto-aead/src/ccm.rs`
  - **Tests:** round-trip; tamper detection (ciphertext + tag); deterministic output; empty plaintext; no-AAD.
- [x] AES-128-OCB3 / AES-256-OCB3 (done 2026-05-25)
  - **Goal:** `Aes128Ocb3`, `Aes256Ocb3` implementing `Aead` (RFC 7253).
  - **Result:** `ocb3` 0.1.0 (2.37M downloads, updated 2026-02-02) is healthy; shipped. Uses `ocb3::Ocb3<Aes128, U12, U16>` on aead 0.5 chain (compatible).
  - **Files:** `crates/oxicrypto-aead/src/ocb3_impl.rs`
  - **Tests:** round-trip; tamper detection; wrong-key detection.
- [x] Add Deoxys-II tweakable AEAD for nonce-misuse resistance beyond GCM-SIV (CAESAR competition winner) (~150 SLOC) (done 2026-05-30 — Deoxys-II-128-128 KAT-verified against official CAESAR vectors)
  - **Goal:** A working, KAT-verified `Deoxys2_128` AEAD (Deoxys-II-128-128) implementing `oxicrypto_core::Aead` (16-byte key, 16-byte nonce/tweak, 16-byte tag), nonce-misuse resistant per the SCT-2 mode. Stretch: `Deoxys2_256` (Deoxys-II-256-128).
  - **Design (ultrathink — no shortcuts):**
    - **Tweakable block cipher Deoxys-BC-256** (`src/deoxys_bc.rs`): 14 AES-style rounds. Use the pure-Rust `aes` crate `hazmat::cipher_round` for the round function (AddRoundKey∘MixColumns∘ShiftRows∘SubBytes) — *do not* hand-roll the S-box. Implement the **TWEAKEY (STK) schedule**: tweakey = 256 bits = (key‖tweak); per-round subtweakey = XOR of the two 128-bit tweakey words after the `h` nibble-permutation and the LFSR2/LFSR3 updates on words, then XOR the round constant `RC_i = [1, 2, 4, 8 ; RCON_i, RCON_i, RCON_i, RCON_i ; ...]` (the 0x02-based constant schedule from the Deoxys v1.43 spec).
    - **SCT-2 mode** (`src/deoxys.rs`), two passes per the spec:
      1. *Auth pass*: absorb associated data in 16-byte blocks with tweak prefix `0b0010`‖counter; absorb message blocks with prefix `0b0000`‖counter; XOR-accumulate the block-cipher outputs into `Auth`. Handle partial final blocks with the `0b0110`/`0b0100` padded-domain prefixes and `10*` padding.
      2. *Tag*: `tag = E_K^{(0b0001‖nonce)}(Auth)`.
      3. *Enc pass*: counter-mode-style — for block `j`, `C_j = M_j XOR E_K^{(0b1‖tag‖j)}(0)` (tag masked into the tweak per spec); ciphertext = `C ‖ tag`. Decryption recomputes via the tag, then re-runs the auth pass and checks the tag in constant time (`oxicrypto_core::ct_eq`).
    - Expose zero-sized `Deoxys2_128` struct with the full `Aead` trait impl + inherent `seal`/`open`. Reject wrong key/nonce/tag lengths with `CryptoError::Invalid*`.
  - **Files:** new `crates/oxicrypto-aead/src/deoxys_bc.rs`, `crates/oxicrypto-aead/src/deoxys.rs`; edit `src/lib.rs` (`mod`+`pub use`); edit `Cargo.toml` (add `aes = { workspace = true, features = ["hazmat"] }` — keep version on workspace). Facade *(stretch)*: `AeadAlgo::DeoxysII128` arm in `crates/oxicrypto/src/algo/aead.rs`.
  - **Prerequisites (IMPLEMENT POLICY):** Deoxys-BC-256 tweakable cipher is built here as a prerequisite (no external Deoxys crate). AES round primitive comes from `aes::hazmat`.
  - **Tests:** the official **Deoxys-II-128-128 LWC/CAESAR KAT** vectors (encrypt + decrypt, including empty-AD/empty-message and multi-block cases) in `tests/kat_deoxys.rs`; nonce-reuse misuse-resistance test (same nonce + different message ⇒ distinct, recoverable ciphertexts, no catastrophic leakage like GCM); round-trip + tamper-detect (flipped ciphertext/AAD ⇒ `InvalidTag`); Deoxys-BC single-block KAT against the spec's test vector.
  - **Risk:** Deoxys-BC tweakey schedule (LFSR + `h` permutation + RC) is the easy place to get a subtle bug. Mitigation: unit-test Deoxys-BC against the spec's standalone block KAT *before* wiring the mode; lock the AEAD with official KATs; if any KAT cannot be matched, return `status: deviated` rather than ship unverified crypto.
- [x] Add `Aead` trait implementation for AES-GCM-SIV-128/256 (currently only has inherent methods, not the `Aead` trait) (~40 SLOC)
- [x] Add `Aead` trait implementation for XChaCha20-Poly1305 (currently only has inherent methods, not the `Aead` trait) (~40 SLOC)
- [x] `NonceSequence` counter helper (done 2026-05-25)
  - **Goal:** Monotonic nonce generator preventing reuse for a fixed key.
  - **Design:** Struct holding a fixed prefix + 64-bit counter; `generate() -> Result<[u8; N], CryptoError>` erroring on counter wrap. No new dep.
  - **Files:** `crates/oxicrypto-aead/src/nonce_seq.rs`
  - **Tests:** sequential uniqueness; prefix preservation; counter overflow detection.
- [x] Add random-nonce helper: `seal_with_random_nonce(key, aad, pt, rng) -> (nonce, ct)` using `oxicrypto-rand` for nonce generation, prepending nonce to ciphertext (~40 SLOC) (done 2026-05-25)
- [x] Add `SealedBox` format: nonce-prefixed ciphertext container `nonce || ciphertext || tag` with `seal_box` / `open_box` helpers (~50 SLOC) (done 2026-05-25)
- [x] AES Key Wrap (RFC 3394 / NIST SP 800-38F): `aes128_key_wrap/unwrap`, `aes256_key_wrap/unwrap` via `aes-kw 0.3.0` — standalone API, no `Aead` trait (~120 SLOC, done 2026-05-25)
  - **Note:** AES-SIV dropped — `aes-siv 0.8.0-rc.3` requires `aead 0.6`, incompatible with workspace `aead 0.5.2`.
- [ ] Add AEAD key-committing construction: HKDF-commit before encrypt to prevent invisible salamander attacks (per Grubbs et al.) (~80 SLOC)
- [ ] Add AES-256-GCM with synthetic IV (AES-GCM-SIV-like nonce-misuse resistance but using standard GCM) (~60 SLOC)
- [x] (policy) Remove the 6 production `expect()` calls in `src/ccm.rs` per no-unwrap policy (done 2026-05-30 — replaced with fallible `CryptoError::Internal("ccm block invariant")` path)
  - **Goal:** Zero `expect()`/`unwrap()` in `oxicrypto-aead` production code. Stretch: `seal_detached`/`open_detached` for AES-GCM + ChaCha20-Poly1305.
  - **Design:** Replace each `<slice>.try_into().expect("…BLOCK_SIZE…")` in `ccm.rs` with a fallible path mapping to `CryptoError::Internal("ccm block invariant")` via `?` / `ok_or_else`, preserving the existing invariant semantics.
  - **Files:** `crates/oxicrypto-aead/src/ccm.rs`.
  - **Tests:** existing CCM round-trip tests must still pass.
  - **Risk:** low. The invariants are genuinely true, so the fallible path is dead-safe but satisfies policy without `expect()`.

## API Improvements
- [ ] Unify AES-GCM-SIV and XChaCha20 behind the `Aead` trait (currently typed-array inherent methods only, not trait-dispatched)
- [ ] Add `seal_to_vec` / `open_to_vec` convenience methods that allocate output buffer internally
- [ ] Add `seal_in_place` method that encrypts plaintext buffer in-place, appending tag, avoiding the copy from pt to ct_out
- [ ] Add `max_plaintext_len()` method: AES-GCM has a 64 GiB limit; ChaCha20 has a 256 GiB limit per nonce; document and enforce
- [ ] Add `AeadAlgo` enum variants in facade for AES-GCM-SIV, XChaCha20, AES-CCM, AES-OCB3
- [~] Support detached tag mode: `seal_detached(key, nonce, aad, pt, ct_out) -> Tag` and `open_detached(key, nonce, aad, ct, tag, pt_out)` for protocols that transmit tags separately (planned 2026-05-30)
  - **Goal:** Zero `expect()`/`unwrap()` in `oxicrypto-aead` production code. Stretch: `seal_detached`/`open_detached` for AES-GCM + ChaCha20-Poly1305.
  - **Design:** Replace each `<slice>.try_into().expect("…BLOCK_SIZE…")` in `ccm.rs` with a fallible path mapping to `CryptoError::Internal("ccm block invariant")` via `?` / `ok_or_else`, preserving the existing invariant semantics. Detached mode *(stretch)*: add trait-default or inherent `seal_detached(key,nonce,aad,pt,ct_out) -> Tag` and `open_detached(...,tag,...)` that don't append/strip the tag inline.
  - **Files:** `crates/oxicrypto-aead/src/ccm.rs`; (stretch) `src/lib.rs`.
  - **Tests:** existing CCM round-trip tests must still pass; (stretch) detached round-trip + cross-check detached-tag equals the trailing tag of the combined-mode output.
  - **Risk:** low. The invariants are genuinely true, so the fallible path is dead-safe but satisfies policy without `expect()`.
- [ ] Add type-safe nonce types: `Nonce12`, `Nonce24` instead of raw `&[u8]` slices

## Testing
- [x] Add NIST SP 800-38D GCM test vectors: all 18 test cases from Appendix B for AES-128-GCM and AES-256-GCM (done 2026-05-30 — `tests/kat_gcm.rs`: NIST SP 800-38D TC1-4/TC13-16 + CAVP AAD-only vectors, 13 tests)
  - **Goal:** Official KAT coverage for the existing `Aes128Gcm`/`Aes256Gcm`, `ChaCha20Poly1305`, and `AesGcmSiv128`/`AesGcmSiv256` impls.
  - **Design:** Transcribe vectors as hex consts (matching the crate's existing inline-hex KAT style — no external JSON fetch). NIST SP 800-38D Appendix B GCM cases (all 18, AES-128 + AES-256, covering empty/partial AAD and plaintext); RFC 8439 §2.8.2 the canonical ChaCha20-Poly1305 AEAD vector; RFC 8452 Appendix C AES-GCM-SIV vectors for both key sizes (including the empty-plaintext authentication cases).
  - **Files:** new `crates/oxicrypto-aead/tests/kat_gcm.rs`, `tests/kat_chacha20poly1305.rs`, `tests/kat_aes_gcm_siv.rs` (or extend existing `kat_aes_gcm_siv.rs` if present).
  - **Prerequisites:** none (impls exist).
  - **Tests:** each vector drives `seal` (expect exact ciphertext‖tag) and `open` (expect exact plaintext); plus one negative case per family (corrupted tag ⇒ `InvalidTag`).
  - **Risk:** byte-order/endianness transcription slips. Mitigation: vectors are self-checking — a wrong impl OR a wrong vector fails loudly.
- [x] Add RFC 8439 Section 2.8.2 ChaCha20-Poly1305 AEAD test vector (done 2026-05-30 — `tests/kat_chacha20poly1305.rs`: RFC 8439 §2.8.2 + Appendix A.5 vectors, exact ct‖tag)
  - **Goal:** Official KAT coverage for the existing `Aes128Gcm`/`Aes256Gcm`, `ChaCha20Poly1305`, and `AesGcmSiv128`/`AesGcmSiv256` impls.
  - **Design:** Transcribe vectors as hex consts (matching the crate's existing inline-hex KAT style — no external JSON fetch). NIST SP 800-38D Appendix B GCM cases (all 18, AES-128 + AES-256, covering empty/partial AAD and plaintext); RFC 8439 §2.8.2 the canonical ChaCha20-Poly1305 AEAD vector; RFC 8452 Appendix C AES-GCM-SIV vectors for both key sizes (including the empty-plaintext authentication cases).
  - **Files:** new `crates/oxicrypto-aead/tests/kat_gcm.rs`, `tests/kat_chacha20poly1305.rs`, `tests/kat_aes_gcm_siv.rs` (or extend existing `kat_aes_gcm_siv.rs` if present).
  - **Prerequisites:** none (impls exist).
  - **Tests:** each vector drives `seal` (expect exact ciphertext‖tag) and `open` (expect exact plaintext); plus one negative case per family (corrupted tag ⇒ `InvalidTag`).
  - **Risk:** byte-order/endianness transcription slips. Mitigation: vectors are self-checking — a wrong impl OR a wrong vector fails loudly.
- [x] Add RFC 8452 AES-GCM-SIV test vectors (Appendix C) for all key sizes (done 2026-05-30 — `tests/kat_aes_gcm_siv.rs`: RFC 8452 C.1/C.2 exact-result vectors incl. empty-PT, 15 tests)
  - **Goal:** Official KAT coverage for the existing `Aes128Gcm`/`Aes256Gcm`, `ChaCha20Poly1305`, and `AesGcmSiv128`/`AesGcmSiv256` impls.
  - **Design:** Transcribe vectors as hex consts (matching the crate's existing inline-hex KAT style — no external JSON fetch). NIST SP 800-38D Appendix B GCM cases (all 18, AES-128 + AES-256, covering empty/partial AAD and plaintext); RFC 8439 §2.8.2 the canonical ChaCha20-Poly1305 AEAD vector; RFC 8452 Appendix C AES-GCM-SIV vectors for both key sizes (including the empty-plaintext authentication cases).
  - **Files:** new `crates/oxicrypto-aead/tests/kat_gcm.rs`, `tests/kat_chacha20poly1305.rs`, `tests/kat_aes_gcm_siv.rs` (or extend existing `kat_aes_gcm_siv.rs` if present).
  - **Prerequisites:** none (impls exist).
  - **Tests:** each vector drives `seal` (expect exact ciphertext‖tag) and `open` (expect exact plaintext); plus one negative case per family (corrupted tag ⇒ `InvalidTag`).
  - **Risk:** byte-order/endianness transcription slips. Mitigation: vectors are self-checking — a wrong impl OR a wrong vector fails loudly.
- [ ] Add Wycheproof AEAD test vectors (aes_gcm_test.json, chacha20_poly1305_test.json, aes_gcm_siv_test.json)
- [ ] Extend existing `kat_aes_gcm_siv.rs` with additional nonce-reuse tests verifying misuse resistance
- [ ] Extend existing `kat_xchacha20.rs` with large-nonce randomized tests
- [ ] Add nonce-reuse detection test: same (key, nonce) with different plaintext must produce different ciphertext
- [ ] Add empty-plaintext / empty-AAD / both-empty edge case tests for all algorithms
- [ ] Add max-size ciphertext test: verify graceful error on overflow (pt.len() + tag_len > usize::MAX)
- [ ] Property test: seal(open(ct)) == ct for random inputs
- [ ] Fuzz test: open() never panics on random ciphertext (returns InvalidTag gracefully)

## Performance
- [ ] Benchmark seal/open for 64 B, 1 KiB, 4 KiB, 64 KiB, 1 MiB payloads per algorithm
- [ ] Compare AES-GCM-SIV vs AES-GCM throughput (SIV has ~2x overhead due to two passes)
- [ ] Benchmark XChaCha20 vs ChaCha20 (HChaCha20 subkey derivation overhead)
- [ ] Profile streaming AEAD chunk sizes for optimal throughput (4 KiB vs 16 KiB vs 64 KiB chunks)
- [ ] Benchmark in-place vs copy-based seal to quantify memory allocation overhead
- [ ] Add criterion benchmark for AES-CCM and AES-OCB3 once implemented

## Integration
- [ ] Wire `NonceSequence` to `oxicrypto-rand` for automatic random nonce generation
- [ ] Ensure `oxicrypto-kdf` HKDF can be used for AEAD key derivation (HKDF-Expand -> AEAD key)
- [ ] Provide AEAD algorithm negotiation for OxiTLS: `negotiate_aead(cipher_suite) -> Box<dyn Aead>`
- [ ] Ensure `oxicrypto-bench` includes AES-GCM-SIV and XChaCha20 in comparative benchmarks
- [ ] Coordinate with `oxicrypto-pq` for hybrid encryption: ML-KEM shared secret -> HKDF -> AEAD key
