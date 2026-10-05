//! `oxicrypto-hash-formal`: machine-checked obligations for `oxicrypto-hash`'s
//! pure metadata API.
//!
//! `oxicrypto-hash` is COOLJAPAN's hash layer. Its *digest routines* are the
//! RustCrypto `sha2` / `sha3` / `blake3` crates, reached through a thin typed
//! wrapper; those crates are ordinary registry dependencies, not COOLJAPAN path
//! dependencies, so `cargo-formal` does not lower their bodies and cannot prove
//! anything about the bytes a digest produces. What it *can* prove is the
//! crate's own pure, plain-data surface: the digest-length table
//! (`HashAlgorithm::output_len`), the builder constructors
//! (`HashBuilder::{sha256, …, new}` and `algorithm`), and that the `Hash`-trait
//! `output_len` of each concrete type agrees with that table. These are real
//! invariants — a caller sizes its output buffer from exactly these numbers —
//! and they are exactly the plain-integer API the pure-public candidate list
//! of `cargo formal audit` surfaces for this crate.
//!
//! This package is not self-hosting: `cargo-formal` does not depend on
//! `oxicrypto-hash`, so nothing here verifies the verifier.
//!
//! # The three builds
//!
//! 1. **`cargo build`** (plain, stable). Harnesses vanish; `cargo test` runs
//!    `harness::plain_tests`, ordinary Rust tests with no solver.
//! 2. **`RUSTFLAGS="--cfg oxiformal_runtime_checks" cargo test`**. Every harness
//!    becomes a `#[test]` over random draws.
//! 3. **`cargo +nightly-2026-06-20 check` with `--cfg formal …`**, the driver's
//!    own type-check of the `#[cfg(formal)]` copy of each harness.
//!
//! The verdicts in [`harness`] and in `EXPECTED.toml` come from a separate,
//! real `cargo formal check` run and are **measurements, not predictions**.
//!
//! # Reading a verdict
//!
//! `proved` means the solver found no input violating the property within the
//! harness's bound. `unsupported` means the encoder could not reduce the
//! harness to a verification condition — here always because the digest body is
//! in a registry crate the run does not lower; the doc comment says so.

#![forbid(unsafe_code)]

pub mod harness;
