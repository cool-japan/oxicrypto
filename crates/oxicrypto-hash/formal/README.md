# oxicrypto-hash-formal

Machine-checked obligations for `oxicrypto-hash`'s pure **metadata** API,
written with [`cargo-formal`](https://github.com/cool-japan/cargo-formal) and
`oxiformal`.

`oxicrypto-hash` is COOLJAPAN's hash layer. Its *digest routines* are the
RustCrypto `sha2` / `sha3` / `blake3` crates, reached through a thin typed
wrapper. Those are ordinary registry dependencies, not COOLJAPAN path
dependencies, so `cargo-formal` does not lower their bodies and cannot prove
anything about the bytes a digest produces — this package does not pretend to.
What it proves is the crate's own pure, plain-data surface, which is exactly the
pure-public candidate list `cargo formal audit` reports for this crate: the
digest-length table, the builder's bookkeeping and the `Hash::name` / `Hash::output_len`
labels, the numbers and tags a caller uses to size an output buffer and to pick
an algorithm.

It is a standalone package with its own `[workspace]`: it is not a member of the
`oxicrypto` root workspace, it is never published (`publish = false`), and
nothing outside this directory is touched by building it.

## What is verified

Nothing here is a copy of `oxicrypto-hash`. `oxicrypto-hash` and
`oxicrypto-core` are ordinary path dependencies, and `cargo-formal` lowers their
reachable bodies through `[package.metadata.formal] dep-crates`.

| Target | File | Harnesses |
|---|---|---|
| `HashAlgorithm::output_len` (the digest-length table) | `oxicrypto-hash/src/hash_builder.rs` | 2 |
| `HashBuilder` / `StreamingHashBuilder` (`new`, the named constructors, `algorithm`, `streaming`) | `oxicrypto-hash/src/hash_builder.rs` | 3 |
| `<T as Hash>::output_len` / `name` for each concrete type | `oxicrypto-hash/src/lib.rs` | 3 |
| `Sha256::hash_fixed` (the digest itself — out of reach, see below) | `oxicrypto-hash/src/lib.rs` | 2 |

## The three builds

```sh
# 1. plain, stable: type-checks the package and runs `harness::plain_tests`.
cargo build
cargo test

# 2. randomized execution: every harness becomes a #[test] over random draws.
RUSTFLAGS="--cfg oxiformal_runtime_checks" cargo test

# 3. the driver's own type-check of the #[cfg(formal)] copy of each harness.
RUSTFLAGS="--cfg formal -Zcrate-attr=feature(register_tool) -Zcrate-attr=register_tool(formal_tool)" \
  cargo +nightly-2026-06-20 check --target-dir target/formal-check
```

All three pass with zero warnings, as does
`cargo clippy --all-targets -- -D warnings`.

## Running the verifier

```sh
# `oxiformal` is not on crates.io yet, so both the CLI and the driver come from
# the cargo-formal checkout. FORMAL_DRIVER must point at the *release* driver
# binary.
FORMAL_DRIVER=../../../../../cargo-formal/driver/target/release/formal-driver \
  cargo formal check
```

The manifest names `oxiformal` by the relative path
`../../../../../cargo-formal/crates/oxiformal`, i.e. it assumes the
`cargo-formal` checkout sits beside the directory that holds this repository:
`<root>/cargo-formal` next to `<root>/<group>/oxicrypto`, the layout this
repository is developed in. Cargo resolves the path from the package's real
directory, so reaching the repository through a symlink does not change where
the path lands. In another layout, put the `cargo-formal` checkout (or a
symlink to it) where that path resolves. Never hard-code an absolute path in
the manifest.

`cargo formal check` exits **0** here: nothing is refuted.

## Measured verdicts

**Measured, not predicted.** Every row is from a real `cargo formal check` run
on **2026-10-05** with a release CLI and driver built from the cargo-formal
tree at commit `cab6f97` plus that day's hygiene-scanner and conformance-suite
changes (neither touches the encoder, the solver or the driver), OxiZ 0.3.3,
rustc `nightly-2026-06-20`, `--jobs 2` and a fresh `--target-dir`.
`EXPECTED.toml` is the machine-readable mirror of this table. The run lowered
**79 dependency bodies** (38 reachable).

| # | Harness | Property | Verdict |
|---|---|---|---|
| 1 | `output_len_is_a_valid_digest_length_harness` | `assert` | **unknown** (`solver-model-rejected`) |
| 2 | `output_len_matches_each_algorithm_harness` | `assert` (8 sites) | **proved** |
| 3 | `builder_new_round_trips_its_algorithm_harness` | `assert` | **proved** |
| 4 | `named_builder_constructors_record_their_algorithm_harness` | `assert` (8 sites) | **proved** |
| 5 | `trait_output_len_agrees_with_the_table_harness` | `assert` (8 sites) | **proved** |
| 6 | `blake2_trait_output_len_harness` | `assert` (3 sites) | **proved** |
| 7 | `streaming_builder_round_trips_its_algorithm_harness` | `assert` (2 sites) | **proved** |
| 8 | `hash_names_match_their_labels_harness` | `assert` (11 sites) | **proved** |
| 9 | `sha256_hash_fixed_is_deterministic_harness` | whole harness | **unsupported** (`unsupported-type`) |
| 10 | `sha256_empty_known_answer_harness` | whole harness | **unsupported** (`unsupported-type`) |

10 property rows over 10 harnesses: **7 proved / 1 unknown / 2 unsupported**.

### Evidence grade

Every `proved` row above is **reproduction only (claim unmet)** under
cargo-formal's default `claim-requires` (`lrat`, `oxilean-verify`,
`external-replay`): it is the pinned solver's `unsat`, reproduced under a fixed
seed and conflict budget, not an independently checked proof, and the default
run says so (`claim unmet 44 of 44 proved`). The same day's
`cargo formal check --evidence lrat` (the same binaries, a fresh
`--target-dir`, `--no-cache`; two runs, identical) raised **0 soundness
incidents** and exited 0, and **0 of the 44** proved obligations carry an LRAT
certificate: in every one the bit-level encoder folded an assertion to the
constant `false`, which leaves no clause set to certify. Each proved row is
also checked by ordinary execution: harnesses 2, 4, 5, 6 and 8 draw no input,
so the randomized-execution build runs exactly the one execution each has, and
harnesses 3 and 7 depend on their `u8` selector only through `algorithm_of`
(`sel % 8`), whose eight algorithms `plain_tests` check the same property
for. OxiZ 0.3.3 has a documented wrong-`unsat` class (upstream U-Z19;
cargo-formal's conformance fixture `u21_pinned_selector_two_define_funs`),
which is why a reproduction alone is not a proof.

### Layer counters

| Layer | Counters |
|---|---|
| `hygiene` | PASS — 0 errors, 0 warnings, 0 notes, 2 files scanned, 0 `unsafe` sites |
| `bmc` | **44 proved / 0 refuted / 1 unknown / 2 unsupported / 0 unverifiable** over 47 obligations (45 backed by a `vc/NNNN.smt2` reproduction; the 2 `unsupported` harnesses generate none). The incidental `remainder-by-zero` checks from the `sel % 8` selectors are all `proved` and not enumerated above. |
| `contract` | 0 proved / 0 refuted (this package states no `#[requires]`/`#[ensures]` — see the contract candidates below) |
| `theorem` | not run |

### `solver-model-rejected`: 1

cargo-formal is pinned to OxiZ **0.3.3**, whose model gate (upstream item
U-Z10) turns a solver model that does not satisfy the verification condition
into `unknown` rather than an invented counterexample. One obligation hits it:
the `assert` of `output_len_is_a_valid_digest_length_harness`
(`src/harness.rs:65`), which ranges `output_len` over an arbitrary `u8`
selector. It is **not** a real gap — `output_len_matches_each_algorithm_harness`
proves the exact digest length for all eight variants `proved`.

### The two `unsupported` rows

Both are statements about the encoder's reach, not about `oxicrypto-hash`. The
encoder refuses at the `Sha256::hash_fixed` call — `src/harness.rs:194:24` for
the determinism harness and `:204:26` for the known-answer harness — with
"`!null` is not a range pattern this encoder understands": a niche (a `NonNull`
or reference niche) in the types on the digest path, which runs into the `sha2`
registry crate the run does not lower. No verification condition is minted.
Determinism of the one-shot digest and the SHA-256 empty-input known-answer are
both true properties the encoder cannot reach while the digest lives in a
registry crate; `plain_tests` exhausts the first over a sample of short inputs
and checks the second against the FIPS 180-4 vector.

## Pure-public candidate coverage

`cargo formal audit`, run on `oxicrypto-hash` at the measured head, reports
**37** pure-public candidates. Thirty-six are harnessed; the one
left is a constructor with no plain-data property to state. Each row below gives
the harness that covers it (and its verdict) or the reason it is not harnessed.

| Candidate | Location | Harnessed by |
|---|---|---|
| `<Blake2b256 as oxicrypto_core::Hash>::name` | `src/lib.rs:368` | harness 8 (`hash_names_match_their_labels`), proved |
| `<Blake2b256 as oxicrypto_core::Hash>::output_len` | `src/lib.rs:371` | harness 6 (`blake2_trait_output_len`), proved |
| `<Blake2b512 as oxicrypto_core::Hash>::name` | `src/lib.rs:385` | harness 8 (`hash_names_match_their_labels`), proved |
| `<Blake2b512 as oxicrypto_core::Hash>::output_len` | `src/lib.rs:388` | harness 6 (`blake2_trait_output_len`), proved |
| `<Blake2s256 as oxicrypto_core::Hash>::name` | `src/lib.rs:402` | harness 8 (`hash_names_match_their_labels`), proved |
| `<Blake2s256 as oxicrypto_core::Hash>::output_len` | `src/lib.rs:405` | harness 6 (`blake2_trait_output_len`), proved |
| `<Blake3 as oxicrypto_core::Hash>::name` | `src/lib.rs:463` | harness 8 (`hash_names_match_their_labels`), proved |
| `<Blake3 as oxicrypto_core::Hash>::output_len` | `src/lib.rs:466` | harness 5 (`trait_output_len_agrees_with_the_table`), proved |
| `<Sha256 as oxicrypto_core::Hash>::name` | `src/lib.rs:134` | harness 8 (`hash_names_match_their_labels`), proved |
| `<Sha256 as oxicrypto_core::Hash>::output_len` | `src/lib.rs:137` | harness 5 (`trait_output_len_agrees_with_the_table`), proved |
| `<Sha384 as oxicrypto_core::Hash>::name` | `src/lib.rs:151` | harness 8 (`hash_names_match_their_labels`), proved |
| `<Sha384 as oxicrypto_core::Hash>::output_len` | `src/lib.rs:154` | harness 5 (`trait_output_len_agrees_with_the_table`), proved |
| `<Sha3_256 as oxicrypto_core::Hash>::name` | `src/lib.rs:265` | harness 8 (`hash_names_match_their_labels`), proved |
| `<Sha3_256 as oxicrypto_core::Hash>::output_len` | `src/lib.rs:268` | harness 5 (`trait_output_len_agrees_with_the_table`), proved |
| `<Sha3_384 as oxicrypto_core::Hash>::name` | `src/lib.rs:282` | harness 8 (`hash_names_match_their_labels`), proved |
| `<Sha3_384 as oxicrypto_core::Hash>::output_len` | `src/lib.rs:285` | harness 5 (`trait_output_len_agrees_with_the_table`), proved |
| `<Sha3_512 as oxicrypto_core::Hash>::name` | `src/lib.rs:299` | harness 8 (`hash_names_match_their_labels`), proved |
| `<Sha3_512 as oxicrypto_core::Hash>::output_len` | `src/lib.rs:302` | harness 5 (`trait_output_len_agrees_with_the_table`), proved |
| `<Sha512 as oxicrypto_core::Hash>::name` | `src/lib.rs:168` | harness 8 (`hash_names_match_their_labels`), proved |
| `<Sha512 as oxicrypto_core::Hash>::output_len` | `src/lib.rs:171` | harness 5 (`trait_output_len_agrees_with_the_table`), proved |
| `<Sha512_256 as oxicrypto_core::Hash>::name` | `src/lib.rs:185` | harness 8 (`hash_names_match_their_labels`), proved |
| `<Sha512_256 as oxicrypto_core::Hash>::output_len` | `src/lib.rs:188` | harness 5 (`trait_output_len_agrees_with_the_table`), proved |
| `Blake3Keyed::new` | `src/lib.rs:632` | not harnessed — a constructor returning an opaque keyed hasher, no plain-data property to assert |
| `hash_builder::HashAlgorithm::output_len` | `src/hash_builder.rs:67` | harnesses 1 (unknown, pin) + 2 (proved) |
| `hash_builder::HashBuilder::algorithm` | `src/hash_builder.rs:146` | harnesses 3/4/7, proved |
| `hash_builder::HashBuilder::blake3` | `src/hash_builder.rs:140` | harness 4 (`named_builder_constructors`), proved |
| `hash_builder::HashBuilder::new` | `src/hash_builder.rs:92` | harness 3 (`builder_new_round_trips`), proved |
| `hash_builder::HashBuilder::sha256` | `src/hash_builder.rs:98` | harness 4 (`named_builder_constructors`), proved |
| `hash_builder::HashBuilder::sha384` | `src/hash_builder.rs:104` | harness 4 (`named_builder_constructors`), proved |
| `hash_builder::HashBuilder::sha3_256` | `src/hash_builder.rs:122` | harness 4 (`named_builder_constructors`), proved |
| `hash_builder::HashBuilder::sha3_384` | `src/hash_builder.rs:128` | harness 4 (`named_builder_constructors`), proved |
| `hash_builder::HashBuilder::sha3_512` | `src/hash_builder.rs:134` | harness 4 (`named_builder_constructors`), proved |
| `hash_builder::HashBuilder::sha512` | `src/hash_builder.rs:110` | harness 4 (`named_builder_constructors`), proved |
| `hash_builder::HashBuilder::sha512_256` | `src/hash_builder.rs:116` | harness 4 (`named_builder_constructors`), proved |
| `hash_builder::HashBuilder::streaming` | `src/hash_builder.rs:152` | harness 7 (`streaming_builder_round_trips`), proved |
| `hash_builder::StreamingHashBuilder::algorithm` | `src/hash_builder.rs:192` | harness 7, proved |
| `hash_builder::StreamingHashBuilder::new` | `src/hash_builder.rs:186` | harness 7, proved |

## In-source contract candidates

The honest end state is `#[oxiformal::ensures]` on the real `oxicrypto-hash`
functions, with the proof harnesses beside them. That needs `oxiformal` on
crates.io, so this package states the properties from outside instead.

| Where | Contract | Evidence |
|---|---|---|
| `oxicrypto-hash/src/hash_builder.rs:67` `HashAlgorithm::output_len` | `ensures(r == 32 \|\| r == 48 \|\| r == 64)` | measured: `proved` for all eight variants (harness 2); the all-selectors form is `unknown` only under the OxiZ 0.3.3 pin (harness 1) |
| `oxicrypto-hash/src/hash_builder.rs:92` `HashBuilder::new`, `:146` `algorithm`, `:152` `streaming`; `StreamingHashBuilder::new`/`algorithm` | `ensures(new(a).algorithm() == a)` (and across `streaming`) | measured `proved` (harnesses 3, 7) |
| `oxicrypto-hash/src/lib.rs` `<T as Hash>::output_len` / `name` (each concrete type) | `ensures` it equals the digest length / documented label | measured `proved` (harnesses 5, 6, 8) |

**Real, but not harnessable until the digest bodies are lowerable**

| Where | Contract | Why not measured |
|---|---|---|
| `oxicrypto-hash/src/lib.rs` `Sha256::hash_fixed` (and the other `hash_fixed` / `Hash::hash`) | `ensures` the digest is deterministic and matches the FIPS / RFC vectors | the digest routine is the `sha2` / `sha3` / `blake3` registry crate's, which `cargo-formal` does not lower; harnesses 9 and 10 record it as `unsupported` |
| `oxicrypto-hash/src/lib.rs:632` `Blake3Keyed::new` | `ensures` the keyed hasher embeds the key | the constructor returns an opaque hasher with no plain-data observable the harness can read |
| `oxicrypto-hash/src/xof.rs:102` `left_encode`, `:117` `right_encode`, `:137` `encode_string` | the SP 800-185 length-prefix encodings (`left_encode(x)` is `[n, x_be…]` of length `n + 1`, and round-trips) | `pub(crate)`, reachable only through the cSHAKE / TupleHash / ParallelHash public entry points, all of which run the Keccak permutation in the `sha3` registry crate (`unsupported`) |

## Files

```
formal/
  Cargo.toml      own [workspace]; oxicrypto-hash + oxicrypto-core + oxiformal by path
  .gitignore      /target, /Cargo.lock
  README.md       this file
  EXPECTED.toml   the measured verdict table, machine-readable
  src/lib.rs      module docs: the three builds, how to read a verdict
  src/harness.rs  the harnesses and their plain-build witness tests
```
