# oxicrypto-bench TODO

## Status
Criterion benchmark suite split across 10 binaries under `benches/` (`hash`, `mac`, `aead`, `kdf`, `sig`, `kex`, `rand`, `pq`, `factory_overhead`, `core`; ~2,261 SLOC) plus `src/lib.rs` (~10 SLOC of `--quick`-mode helpers, `[lib] bench = false`) and 4 test files under `tests/` (`purity`, `ct_timing`, `regression`, `coverage`; ~695 SLOC) — tokei, 2026-07-17. Compares OxiCrypto against `ring` across hash/MAC/AEAD/KDF/sig/kex/PQ algorithm families (`aws-lc-rs` removed as a dev-dependency this release — no longer a comparison baseline). Never published (`publish = false`); `ring`, `ed25519-dalek`, and `blake3` (rayon feature) are dev-dependencies only.

## Core Implementation
- [x] Add SHA-512 benchmark group: 1 KiB and 4 KiB (oxicrypto vs ring vs aws-lc-rs) (~40 SLOC)
- [x] Add SHA3-256 benchmark group (oxicrypto only — ring/aws-lc-rs don't support SHA-3) (~20 SLOC)
- [x] Add BLAKE3 benchmark group: 1 KiB and 4 KiB (oxicrypto only) (~20 SLOC)
- [x] Add HMAC-SHA-256 benchmark group: 64 B and 1 KiB messages (oxicrypto vs ring vs aws-lc-rs) (~40 SLOC)
- [x] Add AES-128-GCM benchmark group: 1 KiB (oxicrypto vs ring vs aws-lc-rs) (~40 SLOC)
- [x] Add AES-GCM-SIV benchmark group: 1 KiB (oxicrypto only) (~20 SLOC)
- [x] Add XChaCha20-Poly1305 benchmark group: 1 KiB (oxicrypto only) (~20 SLOC)
- [x] Add X25519 key agreement benchmark: per-operation (oxicrypto vs ring vs aws-lc-rs) (~40 SLOC)
- [x] Add ECDSA P-256 sign/verify benchmark: per-operation (oxicrypto vs ring vs aws-lc-rs) (~50 SLOC)
- [x] Add RSA-2048 sign/verify benchmark: per-operation (oxicrypto vs ring vs aws-lc-rs) (~50 SLOC)
- [x] Add HKDF-SHA-256 derive benchmark: 32-byte output (oxicrypto vs ring/aws-lc-rs HKDF) (~40 SLOC)
- [x] Add ML-KEM-768 keygen/encap/decap benchmark (oxicrypto only, no ring/aws-lc-rs comparison) (~40 SLOC)
- [x] Add ML-DSA-65 keygen/sign/verify benchmark (oxicrypto only) (~40 SLOC)
- [x] Add large-payload AEAD benchmarks: 64 KiB and 1 MiB for AES-GCM and ChaCha20 (~40 SLOC)
- [x] Add dudect-style constant-time statistical timing tests for AEAD tag verification and HMAC verify (~100 SLOC) — implemented in tests/ct_timing.rs; uses Welch's t-test comparing first-byte-flip vs last-byte-flip (both-invalid classes) to isolate constant-time comparison
- [x] Add throughput summary table generator: post-process criterion JSON output to Markdown table (~50 SLOC, as a script) — implemented in scripts/bench_summary.py

## API Improvements
- [x] Organize benchmarks into separate files: `benches/aead.rs`, `benches/hash.rs`, `benches/sig.rs`, `benches/kex.rs`, `benches/pq.rs` (crypto.rs approaching splitting threshold)
- [x] Add `--quick` mode: reduce iteration count for CI smoke testing (`criterion.sample_size(10)`) — implemented via BENCH_QUICK=1 env var in src/lib.rs and all bench files
- [x] Add result comparison script: `scripts/bench_compare.sh` that runs before/after and produces a diff table — implemented in scripts/bench_compare.sh

## Testing
- [x] Maintain existing `tests/purity.rs` FFI audit: `cargo tree -p oxicrypto --edges normal | grep ring|aws-lc` returns empty — purity.rs updated with tripwire and documentation
- [x] Add purity test for each new benchmark: ring/aws-lc-rs must only appear in dev-dep edges — check_ring_aws_lc_not_in_production_deps test added
- [x] Test: all benchmarks compile with `cargo bench --no-run` (CI gate) — verified: all 7 bench binaries build clean in release profile
- [x] Test: benchmark results are non-zero (sanity check that operations actually run) — check_bench_sanity_* tests added in purity.rs

## Performance
- [x] Establish baseline performance ratios: OxiCrypto/ring and OxiCrypto/aws-lc-rs for each algorithm — implemented in `scripts/bench_ratios.py`; reads Criterion JSON, computes ratios with per-algorithm thresholds, outputs Markdown table
- [x] Set regression thresholds: fail CI if OxiCrypto AES-GCM exceeds 1.5x ring, ChaCha20 exceeds 1.1x ring — implemented as `tests/regression.rs` (SHA-256, ChaCha20, AES-256-GCM, HMAC-SHA-256 vs ring; 300× debug threshold, 5× release threshold); `scripts/bench_ratios.py --fail-on-regression` enforces ratios in release mode
- [x] Track performance over releases: store criterion JSON artifacts per version — implemented in `scripts/bench_archive.sh`; copies criterion output, generates summary/ratios.md and meta.json under `target/bench_archive/<version>/`
- [~] Profile OxiCrypto vs ring on both x86_64 (AES-NI) and aarch64 (NEON) targets — PARTIAL 2026-07-17. Added `scripts/bench_arch_profile.sh`: records the *native* CPU-architecture Criterion baseline for the SIMD-sensitive AEAD + hash groups, saving it under `arch-<uname -m>` (so baselines from different machines never overwrite each other) with `--archive` passing a per-arch label to `bench_archive.sh`. On the arm64 dev host this captures the aarch64 / NEON leg natively. **Deferred half (honest):** the x86_64 / AES-NI leg must be recorded by running the same script on an x86_64 host / CI runner — cross-arch numbers are NOT synthesized. No library code changes.

## Integration
- [x] Ensure new algorithms added to other subcrates get corresponding benchmark entries — `AeadAlgo::DeoxysII128` added to `benches/aead.rs` (`bench_aead_deoxys`); exhaustive coverage tests in `tests/coverage.rs` (compile-error tripwire for each algorithm enum)
- [x] Add benchmark results summary to project README.md — indicative throughput table added to `README.md`; `scripts/bench_summary.py` regenerates it from live Criterion JSON
- [x] Coordinate with `simd` feature: run benchmarks with and without `simd` to quantify hardware acceleration impact — implemented in `scripts/bench_simd_compare.sh`; uses RUSTFLAGS to disable SIMD extensions on x86_64/aarch64 and runs Criterion baseline comparison
