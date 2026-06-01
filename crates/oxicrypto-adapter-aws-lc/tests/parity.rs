//! Parity tests: verify that aws-lc-rs produces byte-identical outputs to
//! the RustCrypto default path for deterministic operations.
//!
//! Algorithms tested:
//! - AES-256-GCM (seal + open)
//! - Ed25519 sign (deterministic from seed)
//! - SHA-256 digest

#[cfg(feature = "aws-lc")]
mod parity_tests {
    use oxicrypto_adapter_aws_lc::aead::AwsLcAead;
    use oxicrypto_adapter_aws_lc::hash::AwsLcSha256;
    use oxicrypto_adapter_aws_lc::sign::AwsLcEd25519Signer;
    use oxicrypto_core::{Aead, Hash, Signer};

    // ── AES-256-GCM parity ────────────────────────────────────────────────────

    /// Encrypt with RustCrypto's `oxicrypto-aead::Aes256Gcm`, encrypt with
    /// aws-lc-rs's `AwsLcAead::aes256_gcm()`, compare byte-for-byte.
    #[test]
    fn aes256gcm_seal_parity() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"parity aad";
        let pt = b"parity plaintext for aes-256-gcm";

        // RustCrypto path
        let rustcrypto_cipher = oxicrypto_aead::Aes256Gcm;
        let mut rc_ct = vec![0u8; pt.len() + rustcrypto_cipher.tag_len()];
        rustcrypto_cipher
            .seal(&key, &nonce, aad, pt, &mut rc_ct)
            .expect("rustcrypto seal");

        // aws-lc-rs path
        let awslc_cipher = AwsLcAead::aes256_gcm();
        let mut awslc_ct = vec![0u8; pt.len() + awslc_cipher.tag_len()];
        awslc_cipher
            .seal(&key, &nonce, aad, pt, &mut awslc_ct)
            .expect("aws-lc seal");

        assert_eq!(
            rc_ct, awslc_ct,
            "AES-256-GCM ciphertexts must be byte-identical"
        );
    }

    #[test]
    fn aes256gcm_open_parity() {
        let key = [0x99u8; 32];
        let nonce = [0x11u8; 12];
        let aad = b"open parity aad";
        let pt = b"open parity plaintext";

        // Seal with RustCrypto
        let rustcrypto_cipher = oxicrypto_aead::Aes256Gcm;
        let mut ct = vec![0u8; pt.len() + rustcrypto_cipher.tag_len()];
        rustcrypto_cipher
            .seal(&key, &nonce, aad, pt, &mut ct)
            .expect("rc seal");

        // Open with aws-lc-rs
        let awslc_cipher = AwsLcAead::aes256_gcm();
        let mut recovered = vec![0u8; pt.len()];
        awslc_cipher
            .open(&key, &nonce, aad, &ct, &mut recovered)
            .expect("aws-lc open");
        assert_eq!(
            &recovered,
            pt.as_ref(),
            "decrypted plaintext must match original"
        );

        // Also: seal with aws-lc-rs, open with RustCrypto
        let mut ct2 = vec![0u8; pt.len() + awslc_cipher.tag_len()];
        awslc_cipher
            .seal(&key, &nonce, aad, pt, &mut ct2)
            .expect("aws-lc seal");
        let mut recovered2 = vec![0u8; pt.len()];
        rustcrypto_cipher
            .open(&key, &nonce, aad, &ct2, &mut recovered2)
            .expect("rc open of aws-lc ciphertext");
        assert_eq!(&recovered2, pt.as_ref());
    }

    // ── Ed25519 parity ────────────────────────────────────────────────────────

    /// ed25519-dalek and aws-lc-rs must produce byte-identical signatures from
    /// the same 32-byte seed (Ed25519 is purely deterministic).
    #[test]
    fn ed25519_sign_parity() {
        let seed = [0x5au8; 32];
        let msg = b"parity message for ed25519 sign";

        // RustCrypto / ed25519-dalek path (via oxicrypto-sig)
        let rustcrypto_signer = oxicrypto_sig::Ed25519;
        let mut rc_sig = [0u8; 64];
        rustcrypto_signer
            .sign(&seed, msg, &mut rc_sig)
            .expect("rustcrypto sign");

        // aws-lc-rs path
        let awslc_signer = AwsLcEd25519Signer;
        let mut awslc_sig = [0u8; 64];
        awslc_signer
            .sign(&seed, msg, &mut awslc_sig)
            .expect("aws-lc sign");

        assert_eq!(
            rc_sig, awslc_sig,
            "Ed25519 signatures must be byte-identical for same seed"
        );
    }

    // ── SHA-256 parity ────────────────────────────────────────────────────────

    #[test]
    fn sha256_digest_parity() {
        let msg = b"parity message for sha256";

        // RustCrypto path via oxicrypto-hash
        let rc_hasher = oxicrypto_hash::Sha256;
        let rc_digest = rc_hasher.hash_to_vec(msg).expect("rustcrypto hash");

        // aws-lc-rs path
        let awslc_hasher = AwsLcSha256;
        let awslc_digest = awslc_hasher.hash_to_vec(msg).expect("aws-lc hash");

        assert_eq!(
            rc_digest, awslc_digest,
            "SHA-256 digests must be byte-identical"
        );
    }
}
