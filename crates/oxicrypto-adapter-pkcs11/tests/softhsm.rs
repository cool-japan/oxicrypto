//! PKCS#11 integration tests.
//!
//! Full HSM-backed tests are marked `#[ignore]` and require the
//! `SOFTHSM2_MODULE` environment variable to point to the SoftHSM2 shared
//! library (e.g. `/usr/local/lib/softhsm/libsofthsm2.so`).
//!
//! SoftHSM2 setup (for running the `#[ignore]` tests manually):
//!
//! ```sh
//! softhsm2-util --init-token --slot 0 --label "test-token" \
//!               --so-pin 1111 --pin 1234
//! export SOFTHSM2_MODULE=/usr/local/lib/softhsm/libsofthsm2.so
//! cargo nextest run -p oxicrypto-adapter-pkcs11 \
//!     --features pkcs11 -- --include-ignored
//! ```
//!
//! All other tests (without `#[ignore]`) run in headless mode (no HSM required).

#[cfg(feature = "pkcs11")]
mod tests {
    use cryptoki::slot::Slot;
    use oxicrypto_adapter_pkcs11::provider::{Pkcs11Provider, PkcsError};

    // ── Helpers ──────────────────────────────────────────────────────────────────

    /// Load the SoftHSM2 module path from the environment variable, or skip
    /// by returning `None` if it is not set.
    fn softhsm2_module() -> Option<std::path::PathBuf> {
        std::env::var("SOFTHSM2_MODULE")
            .ok()
            .map(std::path::PathBuf::from)
    }

    /// Open a SoftHSM2 user session on `slot` with PIN `1234`.
    ///
    /// Returns `None` if `SOFTHSM2_MODULE` is not set (graceful skip).
    /// Used by `#[ignore]`-gated integration tests.
    #[allow(dead_code)]
    fn open_softhsm2(slot: u64) -> Option<std::sync::Arc<Pkcs11Provider>> {
        let module = softhsm2_module()?;
        let slot = Slot::try_from(slot).ok()?;
        Pkcs11Provider::new(&module, slot, "1234")
            .ok()
            .map(std::sync::Arc::new)
    }

    // ── Headless tests (no HSM) ───────────────────────────────────────────────

    /// Verify that loading a non-existent module returns a proper error.
    #[test]
    fn nonexistent_module_errors_gracefully() {
        let slot = Slot::try_from(0u64).expect("slot");
        let result =
            Pkcs11Provider::new(std::path::Path::new("/nonexistent/pkcs11.so"), slot, "1234");
        assert!(
            result.is_err(),
            "expected Err for nonexistent PKCS#11 module"
        );
        match result {
            Err(PkcsError::Init(_)) => {} // expected
            Err(other) => panic!("expected PkcsError::Init, got: {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }

    /// Verify PkcsError variants have non-empty Display output.
    #[test]
    fn pkcs_error_variants_display() {
        let variants = [
            PkcsError::Init("init".into()),
            PkcsError::Session("session".into()),
            PkcsError::Operation("op".into()),
        ];
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty(), "PkcsError Display must not be empty");
        }
    }

    /// Verify CryptokiError → CryptoError conversion path.
    #[test]
    fn pkcs_error_converts_to_crypto_error() {
        use oxicrypto_core::CryptoError;
        let e = PkcsError::Session("login failed".into());
        let ce: CryptoError = e.into();
        assert!(matches!(ce, CryptoError::Internal(_)));
    }

    // ── Headless negative tests (no HSM) ─────────────────────────────────────

    /// Negative test: login with a wrong PIN must return an error.
    ///
    /// This test is headless — it uses a non-existent module, so the error
    /// is at the `C_Initialize` stage (Init error), not at login.  The key
    /// point is that we get an error and not a panic.
    #[test]
    fn negative_wrong_pin_nonexistent_module_errors() {
        let slot = Slot::try_from(0u64).expect("slot");
        let result = Pkcs11Provider::new(
            std::path::Path::new("/nonexistent/pkcs11.so"),
            slot,
            "wrong-pin",
        );
        assert!(result.is_err(), "must error on nonexistent module");
        assert!(
            matches!(result, Err(PkcsError::Init(_))),
            "expected Init error"
        );
    }

    /// Negative test: PkcsError::KeyNotFound is distinct from other errors.
    #[test]
    fn negative_key_not_found_error_display() {
        let e = PkcsError::KeyNotFound {
            label: "my-missing-key".to_string(),
        };
        let s = e.to_string();
        assert!(
            s.contains("my-missing-key"),
            "label must appear in display: {s}"
        );
        assert!(s.contains("not found"), "must say 'not found': {s}");
    }

    /// Negative test: PkcsError::MechanismNotSupported contains mechanism name.
    #[test]
    fn negative_mechanism_not_supported_display() {
        let e = PkcsError::MechanismNotSupported {
            mechanism: "CKM_FAKE_ALGO".to_string(),
        };
        let s = e.to_string();
        assert!(
            s.contains("CKM_FAKE_ALGO"),
            "mechanism must appear in display: {s}"
        );
    }

    /// Negative test: PkcsError::BufferTooSmall is distinguishable.
    #[test]
    fn negative_buffer_too_small_display() {
        let e = PkcsError::BufferTooSmall;
        let s = e.to_string();
        assert!(!s.is_empty(), "BufferTooSmall Display must not be empty");
        assert!(s.contains("small"), "must say 'small': {s}");
    }

    // ── SoftHSM2 integration tests (ignored unless SOFTHSM2_MODULE is set) ───

    /// Integration test: Initialize, open a session, and log in via SoftHSM2.
    ///
    /// Requires:
    /// - `SOFTHSM2_MODULE` env var pointing to `libsofthsm2.so`.
    /// - A token initialized on slot 0 with User PIN `1234`.
    ///
    /// Skip otherwise (the test is `#[ignore]`).
    #[test]
    #[ignore]
    fn softhsm_session_open_and_login() {
        let module_path = match std::env::var("SOFTHSM2_MODULE") {
            Ok(p) => std::path::PathBuf::from(p),
            Err(_) => {
                eprintln!("SOFTHSM2_MODULE not set; skipping integration test");
                return;
            }
        };

        let slot = Slot::try_from(0u64).expect("slot 0");
        let provider =
            Pkcs11Provider::new(&module_path, slot, "1234").expect("SoftHSM2 provider creation");

        // If we got here, C_Initialize + C_OpenSession + C_Login all succeeded.
        let _ = provider;
    }

    /// Integration test: AES-GCM encrypt/decrypt round-trip through
    /// `C_Encrypt`/`C_Decrypt` on a SoftHSM2 token.
    ///
    /// Setup: generate an AES-256 key labelled `"test-aes-gcm"` on the token.
    /// The test generates the key if it is not already present.
    ///
    /// Requires `SOFTHSM2_MODULE` + an initialized token on slot 0.
    #[test]
    #[ignore]
    fn softhsm_aes_gcm_encrypt_decrypt_roundtrip() {
        use cryptoki::mechanism::{aead::GcmParams, Mechanism};
        use cryptoki::types::Ulong;
        use oxicrypto_adapter_pkcs11::sym::Pkcs11SymOp;

        let module_path = match softhsm2_module() {
            Some(p) => p,
            None => {
                eprintln!("SOFTHSM2_MODULE not set; skipping");
                return;
            }
        };

        let slot = Slot::try_from(0u64).expect("slot 0");
        let provider = Pkcs11Provider::new(&module_path, slot, "1234").expect("provider open");

        // Generate AES-256 key (256 bits).  If generation fails (e.g., label
        // already exists), try to find the existing key.
        let key_label = "test-aes-gcm-roundtrip";
        let key_handle = provider
            .generate_aes_key(256, key_label)
            .or_else(|_| provider.find_secret_key(key_label))
            .expect("AES key handle");

        let plaintext = b"Hello, PKCS#11 AES-GCM!";
        let nonce: [u8; 12] = [0xAA; 12];
        let aad: &[u8] = b"additional-authenticated-data";

        // Build mechanism for encrypt.
        let mut enc_iv = nonce.to_vec();
        let tag_bits = Ulong::try_from(128u64).expect("tag_bits");
        let enc_gcm = GcmParams::new(&mut enc_iv, aad, tag_bits).expect("GcmParams for encrypt");
        let enc_mech = Mechanism::AesGcm(enc_gcm);

        let sym = Pkcs11SymOp::new(&provider);
        let ciphertext = sym
            .encrypt(enc_mech, key_handle, plaintext)
            .expect("C_Encrypt");

        // Ciphertext should be longer than plaintext (plaintext + 16-byte tag).
        assert!(
            ciphertext.len() >= plaintext.len() + 16,
            "ciphertext length mismatch: {} vs expected >= {}",
            ciphertext.len(),
            plaintext.len() + 16
        );

        // Decrypt.
        let mut dec_iv = nonce.to_vec();
        let dec_gcm = GcmParams::new(&mut dec_iv, aad, tag_bits).expect("GcmParams for decrypt");
        let dec_mech = Mechanism::AesGcm(dec_gcm);

        let recovered = sym
            .decrypt(dec_mech, key_handle, &ciphertext)
            .expect("C_Decrypt");

        assert_eq!(
            recovered.as_slice(),
            plaintext,
            "decrypted plaintext must match original"
        );
    }

    /// Integration test: EC key generation + ECDSA-P256 sign + verify
    /// round-trip on a SoftHSM2 token.
    ///
    /// Requires `SOFTHSM2_MODULE` + initialized token on slot 0 (PIN=`1234`).
    #[test]
    #[ignore]
    fn softhsm_ec_keygen_sign_verify_roundtrip() {
        use cryptoki::mechanism::Mechanism;
        use oxicrypto_adapter_pkcs11::sign::{Pkcs11SignerBuilder, Pkcs11Verifier, SignMechanism};
        use std::sync::Arc;

        let module_path = match softhsm2_module() {
            Some(p) => p,
            None => {
                eprintln!("SOFTHSM2_MODULE not set; skipping");
                return;
            }
        };

        let slot = Slot::try_from(0u64).expect("slot 0");
        let provider =
            Arc::new(Pkcs11Provider::new(&module_path, slot, "1234").expect("provider open"));

        // P-256 named-curve OID: 1.2.840.10045.3.1.7
        let p256_params: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

        let key_label = "test-ec-p256-sign-verify";
        let (pub_handle, priv_handle) = provider
            .generate_ec_keypair(p256_params, key_label)
            .or_else(|_| {
                // Key pair already exists — look up both halves.
                let priv_h = provider.find_private_key(key_label)?;
                let pub_h = provider.find_public_key(key_label)?;
                Ok::<_, PkcsError>((pub_h, priv_h))
            })
            .expect("EC key pair");

        let message = b"test message for ECDSA-P256";

        // Sign using ECDSA-SHA256.
        let signer = Pkcs11SignerBuilder::new(Arc::clone(&provider))
            .mechanism(SignMechanism::EcdsaSha256)
            .build();
        let sig = signer
            .sign_with_handle(Mechanism::EcdsaSha256, priv_handle, message)
            .expect("ECDSA sign");

        assert!(!sig.is_empty(), "signature must not be empty");

        // Verify using C_Verify.
        let verifier = Pkcs11Verifier::new(Arc::clone(&provider));
        verifier
            .verify_with_handle(Mechanism::EcdsaSha256, pub_handle, message, &sig)
            .expect("ECDSA verify");
    }

    /// Integration test: RSA-PKCS1 sign + verify with on-token key pair.
    ///
    /// Generates a 2048-bit RSA key pair labelled `"test-rsa-sign"` on the
    /// SoftHSM2 token.  Signs a SHA-256 digest (mechanism RSA-PKCS1) and
    /// verifies it.
    ///
    /// Requires `SOFTHSM2_MODULE` + initialized token on slot 0 (PIN=`1234`).
    #[test]
    #[ignore]
    fn softhsm_rsa_pkcs1_sign_verify_roundtrip() {
        use cryptoki::mechanism::Mechanism;
        use oxicrypto_adapter_pkcs11::sign::{Pkcs11SignerBuilder, Pkcs11Verifier, SignMechanism};
        use std::sync::Arc;

        let module_path = match softhsm2_module() {
            Some(p) => p,
            None => {
                eprintln!("SOFTHSM2_MODULE not set; skipping");
                return;
            }
        };

        let slot = Slot::try_from(0u64).expect("slot 0");
        let provider =
            Arc::new(Pkcs11Provider::new(&module_path, slot, "1234").expect("provider open"));

        let key_label = "test-rsa-pkcs1-sign";

        // Generate RSA-2048 key pair on the token.
        let (pub_handle, priv_handle) = provider
            .generate_rsa_keypair(2048, key_label)
            .or_else(|_| {
                let priv_h = provider.find_private_key(key_label)?;
                let pub_h = provider.find_public_key(key_label)?;
                Ok::<_, PkcsError>((pub_h, priv_h))
            })
            .expect("RSA key pair");

        let message = b"test message for RSA-PKCS1v1.5-SHA256";

        // Sign with SHA256-RSA-PKCS1.
        let signer = Pkcs11SignerBuilder::new(Arc::clone(&provider))
            .mechanism(SignMechanism::RsaSha256Pkcs)
            .build();
        let sig = signer
            .sign_with_handle(Mechanism::Sha256RsaPkcs, priv_handle, message)
            .expect("RSA-PKCS1 sign");

        assert!(!sig.is_empty(), "RSA signature must not be empty");
        // RSA-2048 signature is always 256 bytes.
        assert_eq!(sig.len(), 256, "RSA-2048 signature must be 256 bytes");

        // Verify.
        let verifier = Pkcs11Verifier::new(Arc::clone(&provider));
        verifier
            .verify_with_handle(Mechanism::Sha256RsaPkcs, pub_handle, message, &sig)
            .expect("RSA-PKCS1 verify");
    }

    /// Integration test: slot enumeration with SoftHSM2.
    ///
    /// Verifies that `Pkcs11Provider::list_slots` returns at least one slot
    /// when SoftHSM2 is initialized.
    ///
    /// Requires `SOFTHSM2_MODULE` + at least one initialized token.
    #[test]
    #[ignore]
    fn softhsm_slot_enumeration() {
        let module_path = match softhsm2_module() {
            Some(p) => p,
            None => {
                eprintln!("SOFTHSM2_MODULE not set; skipping");
                return;
            }
        };

        let slots = Pkcs11Provider::list_slots(&module_path).expect("list_slots");
        assert!(
            !slots.is_empty(),
            "at least one slot must be present with SoftHSM2 initialized"
        );

        // At least one slot should have a non-empty token label.
        let any_labelled = slots
            .iter()
            .any(|(_, info)| !info.label().trim().is_empty());
        assert!(
            any_labelled,
            "at least one slot must have a non-empty token label"
        );

        eprintln!("Found {} slot(s):", slots.len());
        for (slot, info) in &slots {
            eprintln!("  slot {:?}: label={:?}", slot, info.label().trim());
        }
    }

    /// Integration test: multi-session concurrency.
    ///
    /// Spawns 4 OS threads (not tokio tasks — PKCS#11 is synchronous), each
    /// performing a SHA-256 digest via the same `Pkcs11Provider` (which
    /// serialises access via its internal `Mutex<Session>`).
    ///
    /// All threads must complete without deadlock or panic.
    ///
    /// Requires `SOFTHSM2_MODULE` + initialized token on slot 0.
    #[test]
    #[ignore]
    fn softhsm_multi_thread_sign_same_key() {
        use oxicrypto_adapter_pkcs11::hash::Pkcs11Hash;
        use oxicrypto_core::Hash;
        use std::sync::Arc;

        let module_path = match softhsm2_module() {
            Some(p) => p,
            None => {
                eprintln!("SOFTHSM2_MODULE not set; skipping");
                return;
            }
        };

        let slot = Slot::try_from(0u64).expect("slot 0");
        let provider =
            Arc::new(Pkcs11Provider::new(&module_path, slot, "1234").expect("provider open"));

        // 4 threads, each computing SHA-256 of a distinct message 8 times.
        let num_threads: usize = 4;
        let iterations: usize = 8;

        let handles: Vec<_> = (0..num_threads)
            .map(|tid| {
                let prov_clone = Arc::clone(&provider);
                std::thread::spawn(move || {
                    let hasher = Pkcs11Hash::sha256(prov_clone);
                    for i in 0..iterations {
                        let msg = format!("thread={tid} iter={i}");
                        let mut out = [0u8; 32];
                        hasher.hash(msg.as_bytes(), &mut out).unwrap_or_else(|e| {
                            panic!("digest failed on thread {tid} iter {i}: {e:?}");
                        });
                        // Verify output is non-zero (SHA-256 of non-empty input is never all-zero).
                        assert_ne!(out, [0u8; 32], "hash output must not be all-zero");
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread must not panic");
        }
    }

    /// Integration test: negative test suite on a real SoftHSM2 token.
    ///
    /// Tests:
    /// 1. Login with wrong PIN fails with Session error.
    /// 2. find_private_key with a label that does not exist returns KeyNotFound.
    /// 3. find_secret_key with a label that does not exist returns KeyNotFound.
    ///
    /// Requires `SOFTHSM2_MODULE` + initialized token on slot 0 (User PIN=`1234`,
    /// no key labelled `"__nonexistent_label_xyz__"`).
    #[test]
    #[ignore]
    fn softhsm_negative_tests() {
        let module_path = match softhsm2_module() {
            Some(p) => p,
            None => {
                eprintln!("SOFTHSM2_MODULE not set; skipping");
                return;
            }
        };

        let slot = Slot::try_from(0u64).expect("slot 0");

        // 1. Wrong PIN must yield a Session error at login time.
        let wrong_pin_result = Pkcs11Provider::new(&module_path, slot, "wrong-pin-99999");
        match wrong_pin_result {
            Err(PkcsError::Session(_)) | Err(PkcsError::Cryptoki(_)) => {
                // expected — either session-level or raw cryptoki error
            }
            Err(other) => panic!("expected Session or Cryptoki error, got: {other:?}"),
            Ok(_) => panic!("expected login to fail with wrong PIN"),
        }

        // 2. find_private_key with non-existent label.
        let provider =
            Pkcs11Provider::new(&module_path, slot, "1234").expect("provider with correct PIN");
        let not_found = provider.find_private_key("__nonexistent_label_xyz__");
        assert!(
            matches!(not_found, Err(PkcsError::KeyNotFound { .. })),
            "expected KeyNotFound, got: {not_found:?}"
        );

        // 3. find_secret_key with non-existent label.
        let not_found_sym = provider.find_secret_key("__nonexistent_sym_label_xyz__");
        assert!(
            matches!(not_found_sym, Err(PkcsError::KeyNotFound { .. })),
            "expected KeyNotFound for sym key, got: {not_found_sym:?}"
        );
    }
}
