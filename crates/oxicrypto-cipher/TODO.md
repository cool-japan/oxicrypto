# oxicrypto-cipher TODO

## Status
`oxicrypto-cipher` provides the raw, **unauthenticated** block/stream cipher
primitives used for QUIC header protection (RFC 9001 §5.4): AES-128/AES-256
single-block ECB encryption (§5.4.3) and a ChaCha20 keystream generator
(§5.4.4). The crate is intentionally narrow in scope — three public
functions, `#![forbid(unsafe_code)]`, wrapping the RustCrypto `aes` and
`chacha20` crates' safe APIs (`KeyInit::new`, `KeyIvInit::new`,
`BlockCipherEncrypt::encrypt_block`, `StreamCipher::apply_keystream`). No
`unsafe`, no `unwrap()`/`expect()` in production code (`src/lib.rs` has zero
`.unwrap()` calls; the two `.expect()` calls in `#[cfg(test)]` code are on
known-good hex/KAT literals). 156 SLOC production code, 6 tests (FIPS-197
AES-128/AES-256 known-answer vectors, RFC 9001 §A.5 ChaCha20
header-protection mask KAT, RFC 8439 keystream determinism, and invalid-length
error-path coverage for both ciphers). `std` feature forwards to
`oxicrypto-core/std`; the crate is otherwise `no_std`-friendly (no direct
`alloc`/`std` usage in `src/lib.rs`).

This crate had no tracked backlog file until 2026-08 (audit finding: it was
the only one of 14 workspace member crates without a per-crate `TODO.md`,
and was missing from the root `TODO.md`'s per-crate index). The core API
surface is complete for its stated purpose (QUIC header protection); the
items below are genuine, non-urgent gaps, not stubs.

## Core Implementation
- [x] AES-128 single-block ECB encryption (`aes128_encrypt_block`) — RFC 9001 §5.4.3
- [x] AES-256 single-block ECB encryption (`aes256_encrypt_block`) — RFC 9001 §5.4.3
- [x] ChaCha20 keystream block generation with explicit counter/nonce (`chacha20_keystream_block`) — RFC 8439 / RFC 9001 §5.4.4
- [x] `CryptoError` mapping for all invalid-length/overflow paths (`InvalidKey`, `InvalidNonce`, `BadInput`, `BufferTooSmall`)
- [x] `std` feature forwarding to `oxicrypto-core/std`

## Testing
- [x] FIPS-197 Appendix B AES-128 known-answer test
- [x] FIPS-197 Appendix C AES-256 known-answer test
- [x] RFC 9001 §A.5 ChaCha20 header-protection mask known-answer test
- [x] RFC 8439 keystream determinism sanity check
- [x] Invalid-length error-path coverage (AES key/block/out, ChaCha20 key/nonce/out)
- [x] `examples/` directory with a runnable QUIC header-protection walkthrough (`examples/quic_header_protection.rs`, verified against both the AES-ECB mask and the RFC 9001 §A.5 ChaCha20 test vector; added 2026-08, cross-cutting "examples per sub-crate" hygiene item)
- [ ] Fuzz target (`cargo fuzz`) exercising `chacha20_keystream_block`'s counter-overflow arithmetic and both AES entry points for panic-freedom on arbitrary key/block/out lengths — optional; no known panic path today (all length checks precede any indexing/slicing), but the crate has no fuzz harness of its own (see `crates/oxicrypto-hash/fuzz` for the workspace's existing pattern)
- [ ] Cross-check `chacha20_keystream_block` against a second independent ChaCha20 implementation (e.g. via `oxicrypto-aead`'s XChaCha20 machinery at counter=0) for extra KAT redundancy beyond the single RFC 9001 vector

## API Improvements (optional, not currently blocking any consumer)
- [ ] Consider a `Chacha20Nonce`/typed wrapper instead of `&[u8]` + length-check for `chacha20_keystream_block`'s `nonce` parameter, mirroring the typed-newtype pattern used in `oxicrypto-aead` — deferred because the current consumer (QUIC header protection) always derives the nonce from raw sample bytes, so a typed wrapper would just move the same length validation to a different call site
- [ ] AES-192 single-block ECB (`aes192_encrypt_block`) — not required by RFC 9001 (which only defines AES-128 and AES-256 header-protection suites); would only be worth adding if a consumer needs it

## Non-Goals
- Authenticated encryption: intentionally out of scope — use `oxicrypto-aead` (this crate exists specifically for QUIC's *unauthenticated* header-protection mask, where authentication comes from the packet-payload AEAD).
- Decryption / ECB-mode "decrypt": QUIC header protection only ever needs the block-cipher's *encryption* direction (the mask is XORed, not chosen-plaintext-decrypted) — no `aes*_decrypt_block` is planned.
