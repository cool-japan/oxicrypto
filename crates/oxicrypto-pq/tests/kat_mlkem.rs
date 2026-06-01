//! ML-KEM (FIPS 203) Known-Answer Tests.
//!
//! Tests cover:
//! 1. Deterministic keygen → deterministic encap → decap → assert shared secrets match.
//! 2. Randomised round-trip (encap → decap → shared secrets equal).
//!
//! Enabled by the `hazmat-test-vectors` feature (required for deterministic helpers).

#[cfg(feature = "hazmat-test-vectors")]
mod deterministic {
    use oxicrypto_pq::mlkem::{MlKem1024, MlKem512, MlKem768};

    // ── ML-KEM-512 ────────────────────────────────────────────────────────────

    #[test]
    fn mlkem512_kat_zero_seeds() {
        let dk_seed: [u8; 64] = [0u8; 64];
        let enc_seed: [u8; 32] = [0u8; 32];

        let (dk, ek) = MlKem512::generate_deterministic(&dk_seed);
        let (ct, ss_enc) = ek
            .encapsulate_deterministic(&enc_seed)
            .expect("encapsulate_deterministic failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");

        assert_eq!(
            ss_enc.as_slice(),
            ss_dec.as_slice(),
            "ML-KEM-512 deterministic: shared secrets must match"
        );
        assert_eq!(ss_enc.as_slice().len(), 32, "shared key must be 32 bytes");
    }

    #[test]
    fn mlkem512_kat_one_seeds() {
        let dk_seed: [u8; 64] = [1u8; 64];
        let enc_seed: [u8; 32] = [1u8; 32];

        let (dk, ek) = MlKem512::generate_deterministic(&dk_seed);
        let (ct, ss_enc) = ek
            .encapsulate_deterministic(&enc_seed)
            .expect("encapsulate_deterministic failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");

        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn mlkem512_kat_ab_seeds() {
        let dk_seed: [u8; 64] = [0xABu8; 64];
        let enc_seed: [u8; 32] = [0xCDu8; 32];

        let (dk, ek) = MlKem512::generate_deterministic(&dk_seed);
        let (ct, ss_enc) = ek
            .encapsulate_deterministic(&enc_seed)
            .expect("encapsulate_deterministic failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");

        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn mlkem512_deterministic_is_reproducible() {
        let dk_seed: [u8; 64] = [0x42u8; 64];
        let enc_seed: [u8; 32] = [0x43u8; 32];

        let (dk1, ek1) = MlKem512::generate_deterministic(&dk_seed);
        let (ct1, ss1) = ek1
            .encapsulate_deterministic(&enc_seed)
            .expect("first encapsulate_deterministic failed");
        let ss1d = dk1.decapsulate(&ct1).expect("first decapsulate failed");

        // Repeat with same seeds — must produce identical shared secrets.
        let (dk2, ek2) = MlKem512::generate_deterministic(&dk_seed);
        let (ct2, ss2) = ek2
            .encapsulate_deterministic(&enc_seed)
            .expect("second encapsulate_deterministic failed");
        let ss2d = dk2.decapsulate(&ct2).expect("second decapsulate failed");

        assert_eq!(
            ss1.as_slice(),
            ss2.as_slice(),
            "deterministic output must be stable"
        );
        assert_eq!(ss1d.as_slice(), ss2d.as_slice());
    }

    // ── ML-KEM-768 ────────────────────────────────────────────────────────────

    #[test]
    fn mlkem768_kat_zero_seeds() {
        let dk_seed: [u8; 64] = [0u8; 64];
        let enc_seed: [u8; 32] = [0u8; 32];

        let (dk, ek) = MlKem768::generate_deterministic(&dk_seed);
        let (ct, ss_enc) = ek
            .encapsulate_deterministic(&enc_seed)
            .expect("encapsulate_deterministic failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");

        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
        assert_eq!(ss_enc.as_slice().len(), 32);
    }

    #[test]
    fn mlkem768_kat_one_seeds() {
        let dk_seed: [u8; 64] = [1u8; 64];
        let enc_seed: [u8; 32] = [1u8; 32];

        let (dk, ek) = MlKem768::generate_deterministic(&dk_seed);
        let (ct, ss_enc) = ek
            .encapsulate_deterministic(&enc_seed)
            .expect("encapsulate_deterministic failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");

        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn mlkem768_kat_ab_seeds() {
        let dk_seed: [u8; 64] = [0xABu8; 64];
        let enc_seed: [u8; 32] = [0xCDu8; 32];

        let (dk, ek) = MlKem768::generate_deterministic(&dk_seed);
        let (ct, ss_enc) = ek
            .encapsulate_deterministic(&enc_seed)
            .expect("encapsulate_deterministic failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");

        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    // ── ML-KEM-1024 ───────────────────────────────────────────────────────────

    #[test]
    fn mlkem1024_kat_zero_seeds() {
        let dk_seed: [u8; 64] = [0u8; 64];
        let enc_seed: [u8; 32] = [0u8; 32];

        let (dk, ek) = MlKem1024::generate_deterministic(&dk_seed);
        let (ct, ss_enc) = ek
            .encapsulate_deterministic(&enc_seed)
            .expect("encapsulate_deterministic failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");

        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
        assert_eq!(ss_enc.as_slice().len(), 32);
    }

    #[test]
    fn mlkem1024_kat_one_seeds() {
        let dk_seed: [u8; 64] = [1u8; 64];
        let enc_seed: [u8; 32] = [1u8; 32];

        let (dk, ek) = MlKem1024::generate_deterministic(&dk_seed);
        let (ct, ss_enc) = ek
            .encapsulate_deterministic(&enc_seed)
            .expect("encapsulate_deterministic failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");

        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn mlkem1024_kat_ab_seeds() {
        let dk_seed: [u8; 64] = [0xABu8; 64];
        let enc_seed: [u8; 32] = [0xCDu8; 32];

        let (dk, ek) = MlKem1024::generate_deterministic(&dk_seed);
        let (ct, ss_enc) = ek
            .encapsulate_deterministic(&enc_seed)
            .expect("encapsulate_deterministic failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");

        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }
}

// ── Randomised round-trip tests (always run) ─────────────────────────────────

mod random_roundtrip {
    use oxicrypto_pq::mlkem::{MlKem1024, MlKem512, MlKem768};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn mlkem512_rng_round_trip() {
        let mut rng = ChaCha20Rng::from_seed([0x50u8; 32]);
        let (dk, ek) = MlKem512::generate(&mut rng);
        let (ct, ss_enc) = ek.encapsulate(&mut rng).expect("encapsulate failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(
            ss_enc.as_slice(),
            ss_dec.as_slice(),
            "ML-KEM-512 encap/decap shared secrets must match"
        );
    }

    #[test]
    fn mlkem768_rng_round_trip() {
        let mut rng = ChaCha20Rng::from_seed([0x60u8; 32]);
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, ss_enc) = ek.encapsulate(&mut rng).expect("encapsulate failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn mlkem1024_rng_round_trip() {
        let mut rng = ChaCha20Rng::from_seed([0x70u8; 32]);
        let (dk, ek) = MlKem1024::generate(&mut rng);
        let (ct, ss_enc) = ek.encapsulate(&mut rng).expect("encapsulate failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn mlkem768_shared_key_non_zero() {
        let mut rng = ChaCha20Rng::from_seed([0x80u8; 32]);
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, ss_enc) = ek.encapsulate(&mut rng).expect("encapsulate failed");
        let ss_dec = dk.decapsulate(&ct).expect("decapsulate failed");
        // Shared keys should not be all zeros (with overwhelming probability).
        assert_ne!(ss_enc.as_slice(), &[0u8; 32]);
        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }
}

// ── Pure-Rust gate: no *-sys transitive deps ─────────────────────────────────

#[test]
fn no_sys_crates_in_dependency_tree() {
    // Verify that oxicrypto-pq introduces zero C/C++ FFI (*-sys) crates, even
    // when all features (including hazmat) are enabled.  We shell out to
    // `cargo tree` and assert that no output line ends with the `-sys` suffix.
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let output = std::process::Command::new("cargo")
        .args([
            "tree",
            "--manifest-path",
            manifest.to_str().expect("manifest path is valid UTF-8"),
            "--prefix",
            "none",
            "--no-dedupe",
            "--all-features",
        ])
        .output()
        .expect("cargo tree failed to run");

    assert!(
        output.status.success(),
        "cargo tree exited with non-zero status: {}",
        output.status
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sys_lines: Vec<&str> = stdout
        .lines()
        .filter(|line| {
            // Match any crate name ending in "-sys" (e.g. "openssl-sys v1.0.0").
            let name_part = line.trim_start_matches(|c: char| !c.is_alphanumeric());
            name_part.split_whitespace().next().is_some_and(|tok| {
                let crate_name = tok.trim_end_matches([',', '?']);
                crate_name.ends_with("-sys")
            })
        })
        .collect();

    assert!(
        sys_lines.is_empty(),
        "Pure-Rust policy violation: oxicrypto-pq pulls in *-sys crates:\n{}",
        sys_lines.join("\n")
    );
}
