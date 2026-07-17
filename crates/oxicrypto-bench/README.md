# oxicrypto-bench — Criterion benchmarks for the OxiCrypto stack

[![Crates.io](https://img.shields.io/crates/v/oxicrypto-bench.svg)](https://crates.io/crates/oxicrypto-bench)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxicrypto-bench` is a **development-only** crate that measures the performance of the Pure-Rust OxiCrypto primitives and compares them against the C/assembly-backed reference library `ring`. It is not meant to be depended on by applications — it carries no meaningful public API for downstream use. Its purpose is to provide a reproducible [Criterion](https://crates.io/crates/criterion) harness so that throughput and latency regressions are caught during development.

The library target exists only to satisfy Cargo's requirement for a `lib` target while `[lib] bench = false`; the real content lives in the ten benchmark binaries under `benches/`. The `ring` comparison baseline is pulled in strictly as a `dev-dependency` of this crate, so it never appears on the normal dependency edges of any other OxiCrypto crate (preserving the [Pure-Rust](https://github.com/cool-japan) default).

## Installation

This crate is not published for downstream use; it is built from within the workspace. There is no runtime dependency to add to a `Cargo.toml`. To run the benchmarks locally, clone the `oxicrypto` repository and invoke `cargo bench` against this package (see [Running the benchmarks](#running-the-benchmarks)).

```toml
# oxicrypto-bench is a workspace-internal dev crate; it is not added as a
# dependency. The line below is shown only for completeness.
[dev-dependencies]
oxicrypto-bench = "0.2.1"
```

## Quick Start

Run every benchmark group in release mode (always benchmark with `--release`; debug builds are not representative):

```bash
# All default benchmark binaries (hash, mac, aead, kdf, sig, kex, rand, factory_overhead, core)
cargo bench -p oxicrypto-bench

# A single benchmark binary
cargo bench -p oxicrypto-bench --bench aead

# A single benchmark group / id within a binary (Criterion filter)
cargo bench -p oxicrypto-bench --bench hash -- "SHA-256"

# Post-quantum benchmarks require the pq-preview feature
cargo bench -p oxicrypto-bench --features pq-preview --bench pq
```

Criterion writes detailed reports (including HTML plots when `gnuplot` or the
`plotters` backend is available) to `target/criterion/`.

## Benchmark Targets

Each `[[bench]]` target is a standalone Criterion binary with `harness = false`.
Inputs are filled from the OS-seeded `oxicrypto-rand` CSPRNG (`OxiRng`).

| Bench (`--bench`) | Algorithms covered | Input sizes / metric |
|-------------------|--------------------|----------------------|
| `hash` | SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE3 | 64 B, 1 KiB, 4 KiB, 64 KiB — throughput (MiB/s) |
| `mac` | HMAC-SHA-256/384/512, HMAC-SHA3-256/512, Poly1305, CMAC-AES-128/256, KMAC128/256 | 64 B, 1 KiB, 64 KiB — throughput |
| `aead` | AES-128/256-GCM, ChaCha20-Poly1305, AES-128/256-GCM-SIV, XChaCha20-Poly1305, AES-128/256-CCM, AES-128/256-OCB3 | 1 KiB, 64 KiB, 1 MiB (size varies per mode) — throughput |
| `kdf` | HKDF-SHA-256/384/512, PBKDF2, Argon2id, scrypt | HKDF per extract+expand cycle; password KDFs at OWASP params (`sample_size(10)`) |
| `sig` | Ed25519, ECDSA P-256/P-384/P-521, RSA PKCS#1v15-SHA256 | keygen / sign / verify measured separately; RSA at `sample_size(10)` |
| `kex` | X25519, ECDH P-256/P-384/P-521 | keygen + agreement latency (ns; no throughput metric) |
| `pq` | ML-KEM-768, ML-DSA-65 | keygen / encapsulate / decapsulate, keygen / sign / verify (`sample_size(10)`) |

### Benchmark groups (Criterion `benchmark_group` names)

| Bench | Criterion functions | Group prefixes |
|-------|---------------------|----------------|
| `hash` | `bench_hash` | `hash/<ALGO>` |
| `mac` | `bench_hmac`, `bench_hmac_sha3`, `bench_poly1305`, `bench_cmac`, `bench_kmac` | `mac/<ALGO>` |
| `aead` | `bench_aead_standard`, `bench_aead_siv`, `bench_aead_xchacha`, `bench_aead_ccm`, `bench_aead_ocb3` | `aead/<ALGO>` |
| `kdf` | `bench_hkdf_extract_expand`, `bench_hkdf_derive`, `bench_pbkdf2`, `bench_argon2id`, `bench_scrypt` | `kdf/hkdf-raw`, `kdf/<ALGO>`, `kdf/password` |
| `sig` | `bench_ed25519`, `bench_ecdsa_p256`, `bench_ecdsa_p384`, `bench_ecdsa_p521`, `bench_rsa_pkcs1v15` | `sig/<ALGO>` |
| `kex` | `bench_x25519`, `bench_ecdh_p256`, `bench_ecdh_p384`, `bench_ecdh_p521` | `kex/<ALGO>` |
| `pq` | `bench_mlkem768`, `bench_mldsa65` | `pq/ML-KEM-768`, `pq/ML-DSA-65` |

## Running the benchmarks

```bash
# Build (compile-only) check of every bench binary
cargo bench -p oxicrypto-bench --no-run

# Run all default benches and write reports under target/criterion/
cargo bench -p oxicrypto-bench

# Include the post-quantum suite
cargo bench -p oxicrypto-bench --features pq-preview
```

Notes:

- The `pq` bench is gated behind the `pq-preview` feature and will not build
  unless that feature is enabled (`required-features = ["pq-preview"]`).
- ML-DSA key generation and signing run inside an 8 MiB thread because they
  exceed the default Rust stack in debug builds; always use `--release`.
- The `oxicrypto` dependency is pulled in with `features = ["pure", "simd"]`
  so the SIMD-dispatched code paths are exercised on x86_64 / aarch64.

## API Overview

This crate carries no meaningful public Rust API for downstream use. Its
`src/lib.rs` exists to satisfy Cargo's requirement for a `lib` target because
`[lib] bench = false` is set, and additionally exposes two small `--quick`-mode
helpers shared by the benchmark binaries: `apply_quick_mode(&mut BenchmarkGroup)`
(caps Criterion's sample size to 10 when `BENCH_QUICK=1` is set) and
`is_quick_mode() -> bool`. All substantive benchmark functionality is delivered
through the benchmark binaries enumerated above.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `pq-preview` | off | Enables the post-quantum (`pq`) benchmark binary and propagates `oxicrypto/pq-preview`, pulling in `oxicrypto-pq`. |

## Comparison baselines

The benchmarks compare the Pure-Rust OxiCrypto implementations against an
industry reference library, included **only** as a `dev-dependency` of this
crate:

| Baseline | Nature | Notes |
|----------|--------|-------|
| [`ring`](https://crates.io/crates/ring) | C / assembly | Widely deployed BoringSSL-derived primitives. |

`aws-lc-rs` was removed as a dev-dependency of this crate and is no longer a
comparison baseline here; see [`oxicrypto-adapter-aws-lc`](../oxicrypto-adapter-aws-lc)
for the production aws-lc-rs adapter.

Because this is a dev-only edge, it never contaminates the Pure-Rust
dependency graph of `oxicrypto` or any sibling crate consumed by applications.

## Benchmark Results Summary

The table below shows indicative throughput and latency figures for OxiCrypto
algorithms measured on a modern x86_64 workstation (release mode, AES-NI / AVX2
enabled).  Exact numbers depend on CPU microarchitecture, OS scheduler, and
whether hardware acceleration is available.  Run `cargo bench -p oxicrypto-bench`
to generate fresh numbers for your machine.

Use `scripts/bench_summary.py` to regenerate this table from the latest
Criterion JSON output, and `scripts/bench_ratios.py` to see OxiCrypto/ring
comparison ratios.

### Hash throughput (1 MiB input, release mode, indicative)

| Algorithm | Indicative throughput |
| :--- | ---: |
| SHA-256 | ~1–3 GiB/s (SHA-NI) |
| SHA-512 | ~1–2 GiB/s |
| SHA3-256 | ~300–600 MiB/s |
| BLAKE3 | ~3–10 GiB/s (parallel) |
| BLAKE2b-256 | ~800 MiB/s – 1 GiB/s |

### AEAD throughput (1 MiB input, release mode, indicative)

| Algorithm | Indicative throughput |
| :--- | ---: |
| AES-128-GCM | ~2–10 GiB/s (AES-NI + CLMUL) |
| AES-256-GCM | ~2–8 GiB/s |
| ChaCha20-Poly1305 | ~1–3 GiB/s |
| XChaCha20-Poly1305 | ~1–3 GiB/s |
| AES-128-GCM-SIV | ~1–3 GiB/s |
| AES-128-OCB3 | ~2–8 GiB/s |
| Deoxys-II-128-128 | ~400–800 MiB/s |

### Signature latency (per operation, release mode, indicative)

| Algorithm | Keygen | Sign | Verify |
| :--- | ---: | ---: | ---: |
| Ed25519 | ~50 µs | ~50 µs | ~100 µs |
| ECDSA P-256 | ~100 µs | ~100 µs | ~200 µs |
| RSA-2048 PKCS#1v15 | ~500 ms | ~2 ms | ~50 µs |

> **Note**: These are rough indicative ranges, not precise measurements.
> Hardware acceleration (AES-NI, SHA-NI, AVX2, NEON) can improve throughput
> by 3–10× over the software fallback.  Use `scripts/bench_simd_compare.sh`
> to quantify the SIMD acceleration impact on your hardware.

## Cross-references

- [`oxicrypto`](../oxicrypto) — the Pure-Rust facade benchmarked here (`hash_impl`, `aead_impl`, `mac_impl`, `kdf_impl`, etc.).
- [`oxicrypto-kex`](../oxicrypto-kex) — key-exchange primitives (`kex` bench).
- [`oxicrypto-sig`](../oxicrypto-sig) — signature primitives (`sig` bench).
- [`oxicrypto-mac`](../oxicrypto-mac) — MAC primitives (`mac` bench).
- [`oxicrypto-kdf`](../oxicrypto-kdf) — KDF primitives (`kdf` bench).
- [`oxicrypto-rand`](../oxicrypto-rand) — `OxiRng`, used to fill benchmark inputs.
- [`oxicrypto-pq`](../oxicrypto-pq) — post-quantum primitives (`pq` bench, `pq-preview` feature).
- [`oxicrypto-adapter-aws-lc`](../oxicrypto-adapter-aws-lc) — production aws-lc-rs adapter (no longer used as a benchmark comparison baseline in this crate; depend on it directly for aws-lc-rs performance).

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
