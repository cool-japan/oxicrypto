//! PKCS#11 integration tests.
//!
//! Full HSM-backed tests are marked `#[ignore]` and require the
//! `SOFTHSM2_MODULE` environment variable to point to the SoftHSM2 shared
//! library (e.g. `/usr/local/lib/softhsm/libsofthsm2.so`).
//!
//! All other tests run in headless mode (no HSM required).

#[cfg(feature = "pkcs11")]
mod tests {
    use cryptoki::slot::Slot;
    use oxicrypto_adapter_pkcs11::provider::{Pkcs11Provider, PkcsError};

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

    // ── SoftHSM integration tests (ignored unless SOFTHSM2_MODULE is set) ───

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
}
