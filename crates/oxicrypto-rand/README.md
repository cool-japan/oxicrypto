# oxicrypto-rand — Pure-Rust CSPRNG for OxiCrypto

[![Crates.io](https://img.shields.io/crates/v/oxicrypto-rand.svg)](https://crates.io/crates/oxicrypto-rand)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxicrypto-rand` is the RNG/CSPRNG layer of the OxiCrypto stack. It provides `OxiRng`, a ChaCha20-based cryptographically secure pseudo-random number generator seeded from the operating system via `getrandom`, plus ChaCha8/ChaCha12 variants, an auto-reseeding wrapper, an optional per-thread RNG, and a set of convenience free functions (random bytes, nonces, ranges, weighted choice, Fisher–Yates shuffle).

Every RNG type is Pure Rust (`#![forbid(unsafe_code)]`) — no C/C++/assembly. The CSPRNG is `getrandom`-seeded ChaCha (`/dev/urandom`, `RtlGenRandom`, or `arc4random` depending on platform, with no C library linked). On Unix, all three RNG variants track the process PID and automatically reseed after a `fork()` to prevent parent/child state sharing. `OxiRng`, `OxiRng8`, `OxiRng12`, and `ReseedingRng` all implement `oxicrypto_core::Rng` and `rand_core::{TryRng, TryCryptoRng}`, so they plug directly into the rest of OxiCrypto (key generation, ML-KEM/ML-DSA, ECDSA, etc.).

## Installation

```toml
[dependencies]
oxicrypto-rand = "0.2.1"

# Enable the per-thread RNG (with_thread_rng):
oxicrypto-rand = { version = "0.2.1", features = ["std"] }
```

## Quick Start

```rust
use oxicrypto_core::Rng;
use oxicrypto_rand::{OxiRng, random_bytes, random_nonce};

fn main() -> Result<(), oxicrypto_core::CryptoError> {
    // Construct a ChaCha20 CSPRNG seeded from the OS.
    let mut rng = OxiRng::new()?;
    let mut buf = [0u8; 32];
    rng.fill(&mut buf)?;

    // Convenience free functions (each opens a fresh OS-seeded OxiRng):
    let key: Vec<u8> = random_bytes(32)?;
    let nonce: [u8; 12] = random_nonce()?;

    assert_eq!(key.len(), 32);
    let _ = (buf, nonce);
    Ok(())
}
```

`OxiRng` implements `rand_core::TryCryptoRng`, so it can drive the key-generation helpers in the sibling crates:

```rust,no_run
use oxicrypto_rand::OxiRng;

let mut rng = OxiRng::new()?;
let (signing_key, verifying_key) = oxicrypto_sig::ed25519_generate_keypair(&mut rng)?;
# Ok::<(), oxicrypto_core::CryptoError>(())
```

## API Overview

### RNG types

| Type | Algorithm | Constructor | Fork-safe (Unix) | Notes |
|------|-----------|-------------|------------------|-------|
| `OxiRng` | ChaCha20 (20 rounds) | `OxiRng::new()` | yes | Default CSPRNG; full security margin |
| `OxiRng8` | ChaCha8 (8 rounds) | `OxiRng8::new()` | yes | Higher throughput, smaller margin |
| `OxiRng12` | ChaCha12 (12 rounds) | `OxiRng12::new()` | yes | Middle ground |
| `ReseedingRng` | ChaCha20 + auto-reseed | `ReseedingRng::new()` / `with_threshold(n)` | yes (via inner `OxiRng`) | Reseeds from OS after N bytes (default 1 MiB) |

All four implement `oxicrypto_core::Rng` (`fill`) and `rand_core::{TryRng, TryCryptoRng}` (`try_next_u32`, `try_next_u64`, `try_fill_bytes`). `Debug` is redacted on `OxiRng` (state is never printed); `OxiRng` also implements `Display` (`"OxiRng(ChaCha20)"`).

### `OxiRng` methods

| Method | Description |
|--------|-------------|
| `OxiRng::new()` | Create a ChaCha20 CSPRNG seeded from the OS (`getrandom`) |
| `fill(&mut self, dst)` | Fill a `&mut [u8]` with random bytes (via `Rng` trait); checks fork on Unix |
| `fill_exact::<N>(&mut self, &mut [u8; N])` | Fill a fixed-size array |
| `reseed(&mut self)` | Reseed the internal ChaCha20 state from OS entropy |

`OxiRng8` and `OxiRng12` expose `new()` and `reseed()` plus the trait methods.

### `ReseedingRng` methods

| Method | Description |
|--------|-------------|
| `ReseedingRng::new()` | New reseeding RNG with the default 1 MiB threshold |
| `ReseedingRng::with_threshold(bytes)` | New reseeding RNG with a custom byte threshold |
| `bytes_generated()` | Bytes produced since the last reseed |
| `reseed_threshold()` | Configured reseed threshold in bytes |
| `reseed(&mut self)` | Reseed immediately from OS entropy and reset the counter |

The byte counter triggers an automatic reseed once it reaches the threshold — a forward-secrecy interval consistent with NIST SP 800-90A §9.2.

### Convenience free functions

Each function that takes no RNG argument internally creates a fresh OS-seeded `OxiRng`.

| Function | Signature | Description |
|----------|-----------|-------------|
| `random_bytes` | `(len) -> Result<Vec<u8>>` | `len` cryptographically secure random bytes |
| `random_nonce::<N>` | `() -> Result<[u8; N]>` | `N`-byte random nonce (for AEADs) |
| `random_u32` / `random_u64` / `random_u128` | `() -> Result<uN>` | Random integer of the given width |
| `random_range` | `(min, max) -> Result<u64>` | Unbiased integer in `[min, max)` (rejection sampling) |
| `random_range_to` | `(max) -> Result<u64>` | Unbiased integer in `[0, max)` |
| `random_range_unbiased` | `(&mut OxiRng, min, max) -> Result<u64>` | Unbiased `[min, max)` using an existing RNG |
| `random_bool` | `(probability) -> Result<bool>` | Random `bool` true with `probability` ∈ `[0.0, 1.0]` |
| `random_bool_with_rng` | `(&mut OxiRng, probability) -> Result<bool>` | As above, using an existing RNG |
| `weighted_choice` | `(&[u64]) -> Result<usize>` | Sample an index proportional to integer weights |
| `weighted_choice_with_rng` | `(&mut OxiRng, &[u64]) -> Result<usize>` | As above, using an existing RNG |
| `shuffle::<T>` | `(&mut [T], &mut OxiRng) -> Result<()>` | In-place cryptographic Fisher–Yates shuffle |
| `reseed` | `(&mut OxiRng) -> Result<()>` | Manually reseed an `OxiRng` from OS entropy |
| `check_entropy` | `() -> Result<()>` | Basic OS-entropy smoke test (two draws must be non-zero and differ) |

> `check_entropy` is a smoke test that catches catastrophic RNG failures only — it is **not** a NIST SP 800-90B health test.

### `with_thread_rng` (requires `std`)

| Function | Description |
|----------|-------------|
| `with_thread_rng(f)` | Run a closure `FnOnce(&mut OxiRng) -> Result<R>` with a lazily-initialized, per-thread `OxiRng`. Has a re-entrancy guard. |

### `std::io::Read` (requires `std`)

`OxiRng` and `ReseedingRng` both implement [`std::io::Read`] — each `read()` call fills the entire output buffer with random bytes and returns `Ok(buf.len())`; an I/O error is returned only if the underlying OS RNG becomes unavailable. Useful anywhere a byte-stream reader is expected instead of the `Rng` trait.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | off | Enables `with_thread_rng` (thread-local RNG), `impl std::io::Read for OxiRng` / `ReseedingRng`, and `std` propagation to `rand_chacha` / `oxicrypto-core` |

The crate does not currently declare `#![no_std]` at its crate root, so it links the standard library regardless of the `std` feature; `getrandom` is used for OS-seeded entropy either way. (`oxicrypto-core`, which this crate builds on, is genuinely `no_std` — see its README.)

## Error Variants

All fallible operations return `oxicrypto_core::CryptoError`. The variants this crate produces:

| Variant | When |
|---------|------|
| `Rng` | `getrandom` failed, or RNG output could not be produced (e.g. after fork) |
| `BadInput` | Invalid parameters: `random_range(min >= max)`, `random_range_to(0)`, `random_bool` probability outside `[0.0, 1.0]`, empty/all-zero `weighted_choice` weights |
| `Internal(&'static str)` | `getrandom` failed at construction, or the thread-local RNG cell was re-entered |

## Cross-References

- [`oxicrypto-core`](../oxicrypto-core) — the `Rng` trait and `CryptoError` implemented/returned here.
- [`oxicrypto-kex`](../oxicrypto-kex), [`oxicrypto-sig`](../oxicrypto-sig), [`oxicrypto-pq`](../oxicrypto-pq) — key generation accepts any `rand_core::TryCryptoRng`, including `OxiRng`.
- [`oxicrypto`](../oxicrypto) — the facade re-exports `random_bytes`, `random_nonce`, `random_range`, and `reseed` at the crate root.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
