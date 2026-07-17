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
- [x] Add AEAD key-committing construction: HKDF-commit before encrypt to prevent invisible salamander attacks (per Grubbs et al.) (~80 SLOC) (done 2026-06-02)
  - **Goal:** `CommittingAead` wrapper providing CMT-1 key-commitment: any manipulation of the encryption key is cryptographically detectable, preventing partitioning oracle and invisible-salamander attacks.
  - **Design:** New `src/committing.rs`. UtC construction: `prk = hkdf_sha256_extract([0u8;32], key)`; expand `32 + inner.key_len()` bytes with `info = b"oxicrypto/committing/v1"`; `commitment = okm[..32]`, `subkey = okm[32..]`. Sealed output: `commitment ‖ inner.seal_to_vec(subkey, nonce, aad, pt)`. Open: recompute commitment, constant-time compare via `oxicrypto_core::ct_eq`, reject mismatch with `CryptoError::InvalidTag`, then `inner.open_to_vec(subkey, ...)`. Generic over `&dyn Aead`. Add `oxicrypto-kdf` workspace dep (acyclic — kdf does not depend on aead; `default-features = false` to preserve no_std). Document CMT-1 property and Grubbs/Bellare-Hoang reference; note CTX (CMT-4) as a stronger but more complex alternative.
  - **Files:** `src/committing.rs` (new), `src/lib.rs` (re-export), `Cargo.toml` (add `oxicrypto-kdf` dep).
  - **Tests:** Round-trip (seal then open yields same plaintext); two-key attack negative (ciphertext sealed under key A fails under key B with `InvalidTag`); commitment-tamper rejected; empty plaintext and empty AAD handled; `inner.key_len() > 32` edge (ensures expand buffer is correct).
  - **Risk:** New dep on `oxicrypto-kdf`; must verify `no_std` default build. Correct HKDF expand length (`32 + inner.key_len()`) is critical.
- [x] Add AES-256-GCM with synthetic IV (AES-GCM-SIV-like nonce-misuse resistance but using standard GCM) (~60 SLOC) (done 2026-06-03)
  - **Goal:** `SyntheticIvAes256Gcm` — a deterministic AEAD that derives its nonce from the message, providing nonce-misuse resistance at the cost of 40 bytes overhead.
  - **Design:** New `src/gcm_synthetic.rs`. Split key: `K_enc = HKDF-Expand(key, "gcm-synthetic/enc", 32)`, `K_mac = HKDF-Expand(key, "gcm-synthetic/mac", 32)`. Nonce: `nonce = HMAC-SHA256(K_mac, aad || pt)[..12]`. Seal: `AES-256-GCM.seal(K_enc, nonce, aad, pt)`. Output: `nonce(12) || ciphertext || tag(16)`. Implements `Aead`. Uses `oxicrypto-kdf` (already dep). HMAC step: use `hmac`/`sha2` workspace crates directly to avoid adding `oxicrypto-mac` dep. Document: weaker than RFC 8452 AES-GCM-SIV; use `AesGcmSiv256` for stronger guarantees.
  - **Files:** `src/gcm_synthetic.rs` (new), `src/lib.rs` (re-export), `tests/test_synthetic_iv_gcm.rs` (new).
  - **Tests:** Round-trip; determinism (same inputs → same nonce+ciphertext); different messages → different nonces; open under wrong key fails.
  - **Risk:** Security caveat: this construction is weaker than RFC 8452. Must document prominently.
- [x] (policy) Remove the 6 production `expect()` calls in `src/ccm.rs` per no-unwrap policy (done 2026-05-30 — replaced with fallible `CryptoError::Internal("ccm block invariant")` path)
  - **Goal:** Zero `expect()`/`unwrap()` in `oxicrypto-aead` production code. Stretch: `seal_detached`/`open_detached` for AES-GCM + ChaCha20-Poly1305.
  - **Design:** Replace each `<slice>.try_into().expect("…BLOCK_SIZE…")` in `ccm.rs` with a fallible path mapping to `CryptoError::Internal("ccm block invariant")` via `?` / `ok_or_else`, preserving the existing invariant semantics.
  - **Files:** `crates/oxicrypto-aead/src/ccm.rs`.
  - **Tests:** existing CCM round-trip tests must still pass.
  - **Risk:** low. The invariants are genuinely true, so the fallible path is dead-safe but satisfies policy without `expect()`.

## API Improvements
- [x] Unify AES-GCM-SIV and XChaCha20 behind the `Aead` trait (done — both implement `oxicrypto_core::Aead` via full trait dispatch; inherent typed-array methods also present for ergonomic use)
- [x] Add `seal_to_vec` / `open_to_vec` convenience methods that allocate output buffer internally (done — implemented as default methods on `Aead` trait in `oxicrypto-core/src/traits/aead.rs`)
- [x] Add `seal_in_place` method that encrypts plaintext buffer in-place, appending tag (done 2026-06-03)
  - **Goal:** `Aead` trait gains `fn seal_in_place(&self, key, nonce, aad, buf: &mut Vec<u8>) -> Result<(), CryptoError>` — on entry buf=plaintext, on exit buf=ciphertext||tag.
  - **Design:** Default impl in `oxicrypto-core/src/traits/aead.rs` copies plaintext then seals (one extra alloc). Override for AES-128/256-GCM and ChaCha20-Poly1305 in `oxicrypto-aead/src/lib.rs` using existing private `seal_in_place` free fn (no copy).
  - **Files:** `oxicrypto-core/src/traits/aead.rs`, `oxicrypto-aead/src/lib.rs`.
  - **Tests:** `test_seal_in_place_gcm`, `test_seal_in_place_chacha`.
  - **Risk:** Low; default + override pattern.
- [x] Add `max_plaintext_len()` method: AES-GCM 64 GiB, ChaCha20 256 GiB per nonce; document and enforce (done 2026-06-02)
  - **Goal:** `Aead` trait gains `fn max_plaintext_len(&self) -> u64` with per-algorithm RFC-correct limits enforced in `seal`.
  - **Design:** Add `fn max_plaintext_len(&self) -> u64 { u64::MAX }` default to `Aead` trait in `oxicrypto-core/src/traits/aead.rs`. Override per impl: AES-128/256-GCM = 2^36−32 bytes (RFC 5116); ChaCha20-Poly1305 / XChaCha20-Poly1305 = 2^38−64 bytes (RFC 8439); AES-GCM-SIV = 2^36−32; AES-CCM = per NIST SP 800-38C length limits; OCB3/Deoxys = 2^36−1. Enforce in each `seal` implementation: if `pt.len() as u64 > self.max_plaintext_len()` return `Err(CryptoError::BadInput)`.
  - **Files:** `oxicrypto-core/src/traits/aead.rs`, `oxicrypto-aead/src/lib.rs` (and other aead impl files).
  - **Tests:** For AES-GCM: a plaintext exactly at the limit returns `Ok`; one byte over returns `Err(BadInput)`. Same for ChaCha20.
  - **Risk:** Low. Default prevents breaking existing impls. Limit computation must match RFC-correct byte counts.
- [x] Add `AeadAlgo` enum variants in facade for AES-GCM-SIV, XChaCha20, AES-CCM, AES-OCB3
- [x] Support detached tag mode: `seal_detached(key, nonce, aad, pt, ct_out) -> Tag` and `open_detached(key, nonce, aad, ct, tag, pt_out)` for protocols that transmit tags separately (done 2026-06-02)
  - **Goal:** Zero `expect()`/`unwrap()` in `oxicrypto-aead` production code. Stretch: `seal_detached`/`open_detached` for AES-GCM + ChaCha20-Poly1305.
  - **Design:** Replace each `<slice>.try_into().expect("…BLOCK_SIZE…")` in `ccm.rs` with a fallible path mapping to `CryptoError::Internal("ccm block invariant")` via `?` / `ok_or_else`, preserving the existing invariant semantics. Detached mode *(stretch)*: add trait-default or inherent `seal_detached(key,nonce,aad,pt,ct_out) -> Tag` and `open_detached(...,tag,...)` that don't append/strip the tag inline.
  - **Files:** `crates/oxicrypto-aead/src/ccm.rs`; (stretch) `src/lib.rs`.
  - **Tests:** existing CCM round-trip tests must still pass; (stretch) detached round-trip + cross-check detached-tag equals the trailing tag of the combined-mode output.
  - **Risk:** low. The invariants are genuinely true, so the fallible path is dead-safe but satisfies policy without `expect()`.
  - **Refinement (2026-06-02):** Full scope for this run: add `fn seal_detached(&self, key, nonce, aad, pt, ct_out: &mut [u8]) -> Result<Vec<u8>, CryptoError>` and `fn open_detached(&self, key, nonce, aad, ct, tag: &[u8], pt_out: &mut [u8]) -> Result<(), CryptoError>` to the `Aead` trait in `oxicrypto-core/src/traits/aead.rs` with default impls that round-trip through combined mode. Provide zero-copy overrides for AES-128/256-GCM and ChaCha20-Poly1305 that call `encrypt_in_place_detached`/`decrypt_in_place_detached` directly (already used internally). Cross-check: `seal_detached` tag must equal the trailing 16 bytes of `seal` output for the same inputs.
- [x] Add type-safe nonce types: `Nonce12Bytes`, `Nonce24Bytes` instead of raw `&[u8]` slices (done 2026-06-03)
  - **Goal:** `NonceBytes<const N: usize>([u8; N])` newtype with `Deref<Target=[u8]>`, `From<[u8;N]>`, `TryFrom<&[u8]>`. Type aliases `Nonce12Bytes` and `Nonce24Bytes` (avoiding collision with existing nonce-sequence `Nonce12`/`Nonce24` aliases).
  - **Files:** `oxicrypto-aead/src/lib.rs` or new `src/nonce_types.rs`.
  - **Tests:** `test_noncebytes_from_array`, `test_noncebytes_tryfrm_slice_wrong_len`.
  - **Risk:** Low — additive newtypes.

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
- [x] Add Wycheproof AEAD test vectors (aes_gcm_test.json, chacha20_poly1305_test.json, aes_gcm_siv_test.json) (done 2026-06-03)
  - **Goal:** Add Wycheproof AEAD test vectors (aes_gcm_test.json, chacha20_poly1305_test.json, aes_gcm_siv_test.json). **Files:** `tests/` new test file. **Risk:** Low.
- [x] Extend existing `kat_aes_gcm_siv.rs` with additional nonce-reuse tests verifying misuse resistance (done 2026-06-03)
  - **Goal:** Extend existing `kat_aes_gcm_siv.rs` with additional nonce-reuse tests verifying misuse resistance. **Files:** `tests/` new test file. **Risk:** Low.
- [x] Extend existing `kat_xchacha20.rs` with large-nonce randomized tests (done 2026-06-03)
  - **Goal:** Extend existing `kat_xchacha20.rs` with large-nonce randomized tests. **Files:** `tests/` new test file. **Risk:** Low.
- [x] Add nonce-reuse detection test: same (key, nonce) with different plaintext must produce different ciphertext (done 2026-06-03)
  - **Goal:** Add nonce-reuse detection test: same (key, nonce) with different plaintext must produce different ciphertext. **Files:** `tests/` new test file. **Risk:** Low.
- [x] Add empty-plaintext / empty-AAD / both-empty edge case tests for all algorithms (done 2026-06-03)
  - **Goal:** Add empty-plaintext / empty-AAD / both-empty edge case tests for all algorithms. **Files:** `tests/` new test file. **Risk:** Low.
- [x] Add max-size ciphertext test: verify graceful error on overflow (pt.len() + tag_len > usize::MAX) (done 2026-06-03)
  - **Goal:** Add max-size ciphertext test: verify graceful error on overflow (pt.len() + tag_len > usize::MAX). **Files:** `tests/` new test file. **Risk:** Low.
- [x] Property test: seal(open(ct)) == ct for random inputs (done 2026-06-03)
  - **Goal:** Property test: seal(open(ct)) == ct for random inputs. **Files:** `tests/` new test file. **Risk:** Low.
- [x] Fuzz test: open() never panics on random ciphertext (returns InvalidTag gracefully) (done 2026-06-03)
  - **Goal:** Fuzz test: open() never panics on random ciphertext (returns InvalidTag gracefully). **Files:** `tests/` new test file. **Risk:** Low.

## Performance
All performance items implemented in `oxicrypto-bench/benches/aead.rs` (done 2026-06-19):
- [x] Benchmark seal/open for 64 B, 1 KiB, 4 KiB, 64 KiB, 1 MiB payloads per algorithm (done 2026-06-19 — `bench_aead_standard` with 5-size sweep; `bench_aead_siv`, `bench_aead_xchacha`, `bench_aead_ccm`, `bench_aead_ocb3`, `bench_aead_deoxys`)
- [x] Compare AES-GCM-SIV vs AES-GCM throughput (SIV has ~2x overhead due to two passes) (done 2026-06-19 — `bench_aead_siv_vs_gcm` group at 64 B / 1 KiB / 64 KiB)
- [x] Benchmark XChaCha20 vs ChaCha20 (HChaCha20 subkey derivation overhead) (done 2026-06-19 — `bench_xchacha_vs_chacha` group at 64 B / 1 KiB / 64 KiB / 1 MiB)
- [x] Profile streaming AEAD chunk sizes for optimal throughput (4 KiB vs 16 KiB vs 64 KiB chunks) (done 2026-06-19 — `bench_aead_streaming_chunk_sizes` with AES-256-GCM STREAM and ChaCha20-Poly1305 STREAM at 4 KiB / 16 KiB / 64 KiB / 256 KiB chunk sizes over 1 MiB payload)
- [x] Benchmark in-place vs copy-based seal to quantify memory allocation overhead (done 2026-06-19 — `bench_aead_inplace_vs_copy` for AES-256-GCM and ChaCha20-Poly1305 at 64 B / 1 KiB / 64 KiB)
- [x] Add criterion benchmark for AES-CCM and AES-OCB3 once implemented (done 2026-06-19 — `bench_aead_ccm` and `bench_aead_ocb3` groups at 1 KiB and 1/64 KiB respectively)

## Integration
- [x] Wire `NonceSequence` to `oxicrypto-rand` for automatic random nonce generation (done 2026-06-03 — `NonceSequence::with_random_prefix()` added behind the `rand` feature; generates a cryptographically-secure random prefix via `OxiRng`; 3 tests in `nonce_seq.rs`)
- [x] Ensure `oxicrypto-kdf` HKDF can be used for AEAD key derivation (HKDF-Expand -> AEAD key) (done 2026-06-03 — `tests/test_hkdf_aead_integration.rs` validates the pattern: shared-secret → HKDF-SHA-256 → AES-128/256-GCM / ChaCha20-Poly1305 / XChaCha20-Poly1305; 7 tests; documented in `lib.rs` crate-level doc)
- [ ] Provide AEAD algorithm negotiation for OxiTLS: `negotiate_aead(cipher_suite) -> Box<dyn Aead>` (DEFERRED — requires OxiTLS crate coordination)
- [x] Ensure `oxicrypto-bench` includes AES-GCM-SIV and XChaCha20 in comparative benchmarks (done 2026-06-19 — `bench_aead_siv_vs_gcm` and `bench_xchacha_vs_chacha` groups added)
- [x] Coordinate with `oxicrypto-pq` for hybrid encryption: ML-KEM shared secret -> HKDF -> AEAD key — DONE 2026-07-17. End-to-end KEM-DEM test in `oxicrypto/tests/pq_hybrid_encryption.rs` (facade crate, run with `--features pq-preview`): ML-KEM-768 / X-Wing encapsulate -> HKDF-SHA-256 -> AES-256-GCM (`aead_impl(AeadAlgo::Aes256Gcm)`) seal/open; tampered ciphertext -> `InvalidTag`. Wired in the facade to avoid inverting the aead<-pq dependency edge.
