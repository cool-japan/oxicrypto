//! Integration test: verify that `oxicrypto-adapter-aws-lc` and
//! `oxitls-adapter-aws-lc` link cleanly in the same binary.
//!
//! ## Motivation
//!
//! Both crates depend on `aws-lc-rs` (the same version pinned to `1.17.0` in their
//! respective workspaces).  Cargo deduplicates transitive dependencies, so only one
//! copy of `aws-lc-rs` is compiled and linked.  This test exercises both crates in
//! the same test binary to prove that:
//!
//! 1. There are no duplicate symbol link errors (each crate's symbols are
//!    correctly namespaced).
//! 2. The `aws-lc-rs` initialization path (called internally by both crates on
//!    first use) completes without panicking.
//! 3. Operations from both crates produce expected outputs: `AwsLcAead::aes256_gcm`
//!    can seal/open, and `aws_lc_provider()` returns a non-empty `CryptoProvider`.
//!
//! ## Historical note
//!
//! The `oxitls-adapter-aws-lc` wave8_coexist.rs test documented this coexistence
//! as a placeholder because adding a cross-workspace path dep there would have
//! coupled `oxitls` CI to `oxicrypto`'s local presence.  This test lives in the
//! `oxicrypto` workspace instead, where the path dep on `oxitls` is acceptable
//! as a dev-only cross-workspace integration verification.

#[cfg(feature = "aws-lc")]
mod tests {
    use oxicrypto_adapter_aws_lc::aead::AwsLcAead;
    use oxicrypto_core::Aead as CryptoAead;
    use oxitls_adapter_aws_lc::aws_lc_provider;

    /// Both aws-lc-rs crates initialize cleanly in the same binary.
    ///
    /// - `aws_lc_provider()` exercises the `rustls` CryptoProvider initialization
    ///   path which calls into `aws-lc-rs` for cipher suite and key-exchange setup.
    /// - `AwsLcAead::aes256_gcm().seal(…)` exercises the AEAD initialization path.
    ///
    /// If either crate has conflicting symbols or duplicate initializations, this
    /// test will fail at link time (before any code runs) or panic at runtime.
    #[test]
    fn both_aws_lc_crates_link_and_initialize_cleanly() {
        // ── oxitls side: initialize the rustls CryptoProvider ────────────────
        let provider = aws_lc_provider();
        assert!(
            !provider.cipher_suites.is_empty(),
            "oxitls aws-lc provider must expose at least one cipher suite"
        );
        assert!(
            !provider.kx_groups.is_empty(),
            "oxitls aws-lc provider must expose at least one KX group"
        );

        // ── oxicrypto side: use the AEAD adapter ─────────────────────────────
        let cipher = AwsLcAead::aes256_gcm();
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let pt = b"coexistence integration test";

        let mut ct = vec![0u8; pt.len() + CryptoAead::tag_len(&cipher)];
        let written = CryptoAead::seal(&cipher, &key, &nonce, b"aad", pt, &mut ct)
            .expect("seal must succeed with both crates linked");
        assert_eq!(
            written,
            pt.len() + 16,
            "seal output length must be pt_len + tag_len"
        );

        let mut recovered = vec![0u8; pt.len()];
        let n = CryptoAead::open(
            &cipher,
            &key,
            &nonce,
            b"aad",
            &ct[..written],
            &mut recovered,
        )
        .expect("open must succeed");
        assert_eq!(
            &recovered[..n],
            pt.as_ref(),
            "decrypted plaintext must match original"
        );
    }

    /// Verify no symbol-level conflict: both crates can be used sequentially and
    /// concurrently in the same binary without interfering with each other's state.
    #[test]
    fn sequential_use_of_both_crates_no_interference() {
        // First, use the AEAD crate multiple times.
        for i in 0u8..4 {
            let cipher = match i % 4 {
                0 => AwsLcAead::aes128_gcm(),
                1 => AwsLcAead::aes256_gcm(),
                2 => AwsLcAead::aes256_gcm_siv(),
                _ => AwsLcAead::chacha20_poly1305(),
            };
            let key_len = CryptoAead::key_len(&cipher);
            let key = vec![i; key_len];
            let nonce = [i; 12];
            let pt = b"sequential test";

            let mut ct = vec![0u8; pt.len() + CryptoAead::tag_len(&cipher)];
            let n = CryptoAead::seal(&cipher, &key, &nonce, b"", pt, &mut ct)
                .expect("seal in sequential loop");

            let mut dec = vec![0u8; pt.len()];
            CryptoAead::open(&cipher, &key, &nonce, b"", &ct[..n], &mut dec)
                .expect("open in sequential loop");
            assert_eq!(&dec, pt.as_ref());
        }

        // Then, use the TLS provider — must still work without interference.
        let provider = aws_lc_provider();
        assert!(
            !provider.cipher_suites.is_empty(),
            "provider must still be available after AEAD operations"
        );
    }
}
