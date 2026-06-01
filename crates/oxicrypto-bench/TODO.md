# oxicrypto-bench TODO

## Status
Criterion benchmark suite (321 SLOC in benches/crypto.rs + 20 SLOC lib.rs + purity test). Compares OxiCrypto against ring and aws-lc-rs for AES-256-GCM, ChaCha20-Poly1305, SHA-256, Ed25519 sign/verify. Currently covers 5 benchmark groups with 1 KiB and 4 KiB SHA-256 inputs. Never published; ring and aws-lc-rs are dev-dependencies only.

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
- [ ] Add dudect-style constant-time statistical timing tests for AEAD tag verification and HMAC verify (~100 SLOC)
- [ ] Add throughput summary table generator: post-process criterion JSON output to Markdown table (~50 SLOC, as a script)

## API Improvements
- [x] Organize benchmarks into separate files: `benches/aead.rs`, `benches/hash.rs`, `benches/sig.rs`, `benches/kex.rs`, `benches/pq.rs` (crypto.rs approaching splitting threshold)
- [ ] Add `--quick` mode: reduce iteration count for CI smoke testing (`criterion.sample_size(10)`)
- [ ] Add result comparison script: `scripts/bench_compare.sh` that runs before/after and produces a diff table

## Testing
- [ ] Maintain existing `tests/purity.rs` FFI audit: `cargo tree -p oxicrypto --edges normal | grep ring|aws-lc` returns empty
- [ ] Add purity test for each new benchmark: ring/aws-lc-rs must only appear in dev-dep edges
- [ ] Test: all benchmarks compile with `cargo bench --no-run` (CI gate)
- [ ] Test: benchmark results are non-zero (sanity check that operations actually run)

## Performance
- [ ] Establish baseline performance ratios: OxiCrypto/ring and OxiCrypto/aws-lc-rs for each algorithm
- [ ] Set regression thresholds: fail CI if OxiCrypto AES-GCM exceeds 1.5x ring, ChaCha20 exceeds 1.1x ring
- [ ] Track performance over releases: store criterion JSON artifacts per version
- [ ] Profile OxiCrypto vs ring on both x86_64 (AES-NI) and aarch64 (NEON) targets

## Integration
- [ ] Ensure new algorithms added to other subcrates get corresponding benchmark entries
- [ ] Add benchmark results summary to project README.md
- [ ] Coordinate with `simd` feature: run benchmarks with and without `simd` to quantify hardware acceleration impact
- [ ] Add CI job that runs benchmarks on push to version branches (not blocking, informational)
