//! PKCS#11 provider: initialize a cryptoki context and open an authenticated session.

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    session::{Session, UserType},
    slot::Slot,
    types::AuthPin,
};
use oxicrypto_core::CryptoError;
use std::path::Path;
use std::sync::Mutex;

/// Error type for PKCS#11 operations.
#[derive(Debug)]
pub enum PkcsError {
    /// Failed to load the PKCS#11 module or initialize the library.
    Init(String),
    /// Failed to open a session or perform a session operation.
    Session(String),
    /// The requested cryptographic operation failed.
    Operation(String),
    /// Mutex was poisoned (internal session lock failure).
    LockPoisoned,
}

impl core::fmt::Display for PkcsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PkcsError::Init(msg) => write!(f, "PKCS#11 init error: {msg}"),
            PkcsError::Session(msg) => write!(f, "PKCS#11 session error: {msg}"),
            PkcsError::Operation(msg) => write!(f, "PKCS#11 operation error: {msg}"),
            PkcsError::LockPoisoned => write!(f, "PKCS#11 session mutex was poisoned"),
        }
    }
}

impl std::error::Error for PkcsError {}

impl From<PkcsError> for CryptoError {
    fn from(_e: PkcsError) -> Self {
        CryptoError::Internal("pkcs11 error (see PkcsError for details)")
    }
}

/// A live, authenticated PKCS#11 provider session.
///
/// Wraps a `cryptoki::session::Session` inside a `Mutex` so that the
/// provider can implement `Send + Sync` (required by `oxicrypto_core`
/// traits).  The PKCS#11 C API is not inherently thread-safe at the session
/// level; the `Mutex` serialises concurrent access.
///
/// Construct via [`Pkcs11Provider::new`].
#[derive(Debug)]
pub struct Pkcs11Provider {
    /// The authenticated session, wrapped in a Mutex for Sync safety.
    pub(crate) session: Mutex<Session>,
}

impl Pkcs11Provider {
    /// Initialize a new PKCS#11 provider.
    ///
    /// 1. Loads the dynamic library at `module_path`.
    /// 2. Calls `C_Initialize`.
    /// 3. Opens an R/W session on `slot`.
    /// 4. Logs in as `User` with `pin`.
    ///
    /// # Errors
    /// Returns `PkcsError` if any step fails.
    pub fn new(module_path: &Path, slot: Slot, pin: &str) -> Result<Self, PkcsError> {
        let ctx = Pkcs11::new(module_path).map_err(|e| PkcsError::Init(e.to_string()))?;

        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| PkcsError::Init(e.to_string()))?;

        let session = ctx
            .open_rw_session(slot)
            .map_err(|e| PkcsError::Session(e.to_string()))?;

        let auth_pin = AuthPin::new(pin.to_string().into_boxed_str());
        session
            .login(UserType::User, Some(&auth_pin))
            .map_err(|e| PkcsError::Session(e.to_string()))?;

        Ok(Self {
            session: Mutex::new(session),
        })
    }

    /// Execute a closure with exclusive access to the underlying `Session`.
    ///
    /// This is the primary way for `sign`, `sym`, etc. to perform PKCS#11
    /// operations without exposing the mutex directly.
    pub fn with_session<F, T>(&self, f: F) -> Result<T, PkcsError>
    where
        F: FnOnce(&Session) -> Result<T, cryptoki::error::Error>,
    {
        let guard = self.session.lock().map_err(|_| PkcsError::LockPoisoned)?;
        f(&guard).map_err(|e| PkcsError::Operation(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Verify that the `PkcsError` Display impl is sane.
    #[test]
    fn pkcs_error_display() {
        let e = PkcsError::Init("test init error".to_string());
        let s = e.to_string();
        assert!(s.contains("init"), "expected 'init' in: {s}");
    }

    /// Verify `PkcsError` converts to `CryptoError::Internal`.
    #[test]
    fn pkcs_error_to_crypto_error() {
        let e = PkcsError::Operation("op failed".to_string());
        let ce: CryptoError = e.into();
        assert!(
            matches!(ce, CryptoError::Internal(_)),
            "expected CryptoError::Internal"
        );
    }

    /// Verify that creating a provider with a non-existent module path returns an error
    /// without panicking. No HSM required.
    #[test]
    fn nonexistent_module_returns_error() {
        let nonexistent = PathBuf::from("/nonexistent/path/to/pkcs11.so");
        // Slot 0 is just a placeholder — we never get far enough to need it.
        let slot = Slot::try_from(0u64).expect("slot 0");
        let result = Pkcs11Provider::new(&nonexistent, slot, "1234");
        assert!(result.is_err(), "expected error for nonexistent module");
    }

    /// Verify PkcsError::LockPoisoned displays correctly.
    #[test]
    fn pkcs_error_lock_poisoned_display() {
        let e = PkcsError::LockPoisoned;
        let s = e.to_string();
        assert!(s.contains("poisoned"), "expected 'poisoned' in: {s}");
    }
}
