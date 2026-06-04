//! PKCS#11 provider: initialize a cryptoki context and open an authenticated session.

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::{Slot, TokenInfo},
    types::{AuthPin, Ulong},
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
    /// No key found with the given label on the token.
    KeyNotFound {
        /// The label that was searched.
        label: String,
    },
    /// The requested mechanism is not supported.
    MechanismNotSupported {
        /// Description of the unsupported mechanism.
        mechanism: String,
    },
    /// Output buffer is too small for the operation result.
    BufferTooSmall,
    /// An internal error with a description string.
    Internal(String),
    /// Raw `cryptoki` error (preserves the original CKR code).
    Cryptoki(cryptoki::error::Error),
}

impl core::fmt::Display for PkcsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PkcsError::Init(msg) => write!(f, "PKCS#11 init error: {msg}"),
            PkcsError::Session(msg) => write!(f, "PKCS#11 session error: {msg}"),
            PkcsError::Operation(msg) => write!(f, "PKCS#11 operation error: {msg}"),
            PkcsError::LockPoisoned => write!(f, "PKCS#11 session mutex was poisoned"),
            PkcsError::KeyNotFound { label } => {
                write!(f, "PKCS#11 key not found: label={label:?}")
            }
            PkcsError::MechanismNotSupported { mechanism } => {
                write!(f, "PKCS#11 mechanism not supported: {mechanism}")
            }
            PkcsError::BufferTooSmall => write!(f, "PKCS#11 output buffer too small"),
            PkcsError::Internal(msg) => write!(f, "PKCS#11 internal error: {msg}"),
            PkcsError::Cryptoki(e) => write!(f, "PKCS#11 cryptoki error: {e}"),
        }
    }
}

impl std::error::Error for PkcsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PkcsError::Cryptoki(e) => Some(e),
            _ => None,
        }
    }
}

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
/// Construct via [`Pkcs11Provider::new`] (User login) or
/// [`Pkcs11Provider::with_so_login`] (Security Officer login).
#[derive(Debug)]
pub struct Pkcs11Provider {
    /// The authenticated session, wrapped in a Mutex for Sync safety.
    pub(crate) session: Mutex<Session>,
}

impl Pkcs11Provider {
    /// Initialize a new PKCS#11 provider with a normal User login.
    ///
    /// 1. Loads the dynamic library at `module_path`.
    /// 2. Calls `C_Initialize`.
    /// 3. Opens an R/W session on `slot`.
    /// 4. Logs in as `User` with `pin`.
    ///
    /// # Errors
    /// Returns `PkcsError` if any step fails.
    pub fn new(module_path: &Path, slot: Slot, pin: &str) -> Result<Self, PkcsError> {
        Self::open_session(module_path, slot, pin, UserType::User)
    }

    /// Initialize a new PKCS#11 provider with a Security Officer (SO) login.
    ///
    /// Identical to [`Pkcs11Provider::new`] except that `C_Login` is called
    /// with `CKU_SO` instead of `CKU_USER`.  This allows key management
    /// operations such as `C_InitPIN`.
    ///
    /// # Errors
    /// Returns `PkcsError` if any step fails.
    pub fn with_so_login(module_path: &Path, slot: Slot, so_pin: &str) -> Result<Self, PkcsError> {
        Self::open_session(module_path, slot, so_pin, UserType::So)
    }

    fn open_session(
        module_path: &Path,
        slot: Slot,
        pin: &str,
        user_type: UserType,
    ) -> Result<Self, PkcsError> {
        let ctx = Pkcs11::new(module_path).map_err(|e| PkcsError::Init(e.to_string()))?;

        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| PkcsError::Init(e.to_string()))?;

        let session = ctx
            .open_rw_session(slot)
            .map_err(|e| PkcsError::Session(e.to_string()))?;

        let auth_pin = AuthPin::new(pin.to_string().into_boxed_str());
        session
            .login(user_type, Some(&auth_pin))
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
        f(&guard).map_err(PkcsError::Cryptoki)
    }

    // -----------------------------------------------------------------------
    // Key discovery helpers
    // -----------------------------------------------------------------------

    /// Find a private key on the token by its `CKA_LABEL` attribute.
    ///
    /// # Errors
    /// Returns [`PkcsError::KeyNotFound`] if no matching key exists, or a
    /// [`PkcsError::Cryptoki`] error if the `C_FindObjects` call fails.
    pub fn find_private_key(&self, label: &str) -> Result<ObjectHandle, PkcsError> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        self.find_first_object(&template, label)
    }

    /// Find a secret (symmetric) key on the token by its `CKA_LABEL` attribute.
    ///
    /// # Errors
    /// Returns [`PkcsError::KeyNotFound`] if no matching key exists.
    pub fn find_secret_key(&self, label: &str) -> Result<ObjectHandle, PkcsError> {
        let template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        self.find_first_object(&template, label)
    }

    /// Find a public key on the token by its `CKA_LABEL` attribute.
    ///
    /// # Errors
    /// Returns [`PkcsError::KeyNotFound`] if no matching public key exists.
    pub fn find_public_key(&self, label: &str) -> Result<ObjectHandle, PkcsError> {
        let template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        self.find_first_object(&template, label)
    }

    fn find_first_object(
        &self,
        template: &[Attribute],
        label: &str,
    ) -> Result<ObjectHandle, PkcsError> {
        let guard = self.session.lock().map_err(|_| PkcsError::LockPoisoned)?;
        let objects = guard.find_objects(template).map_err(PkcsError::Cryptoki)?;
        objects
            .into_iter()
            .next()
            .ok_or_else(|| PkcsError::KeyNotFound {
                label: label.to_string(),
            })
    }

    // -----------------------------------------------------------------------
    // Key generation helpers
    // -----------------------------------------------------------------------

    /// Generate an AES secret key on the token.
    ///
    /// `key_bits` must be 128, 192, or 256.  The key is created as a token
    /// object (`CKA_TOKEN=true`), sensitive (`CKA_SENSITIVE=true`), and
    /// non-extractable (`CKA_EXTRACTABLE=false`).
    ///
    /// # Errors
    /// Returns `PkcsError::Cryptoki` if `C_GenerateKey` fails.
    pub fn generate_aes_key(
        &self,
        key_bits: usize,
        label: &str,
    ) -> Result<ObjectHandle, PkcsError> {
        let key_bytes =
            Ulong::try_from(key_bits / 8).map_err(|e| PkcsError::Internal(e.to_string()))?;

        let template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(key_bytes),
            Attribute::Token(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Label(label.as_bytes().to_vec()),
        ];

        self.with_session(|session| session.generate_key(&Mechanism::AesKeyGen, &template))
    }

    /// Generate an EC key pair on the token.
    ///
    /// `curve_params` is the DER-encoded OID of the curve (e.g. the P-256
    /// named-curve OID: `[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03,
    /// 0x01, 0x07]`).
    ///
    /// Returns `(public_handle, private_handle)`.
    ///
    /// # Errors
    /// Returns `PkcsError::Cryptoki` if `C_GenerateKeyPair` fails.
    pub fn generate_ec_keypair(
        &self,
        curve_params: &[u8],
        label: &str,
    ) -> Result<(ObjectHandle, ObjectHandle), PkcsError> {
        let pub_template = vec![
            Attribute::EcParams(curve_params.to_vec()),
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Verify(true),
        ];
        let priv_template = vec![
            Attribute::Token(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Sign(true),
        ];

        self.with_session(|session| {
            session.generate_key_pair(&Mechanism::EccKeyPairGen, &pub_template, &priv_template)
        })
    }

    /// Generate an RSA key pair on the token.
    ///
    /// `modulus_bits` is the key size in bits (e.g. 2048 or 4096).
    /// The public exponent is fixed at 65537 (0x010001).
    ///
    /// Returns `(public_handle, private_handle)`.
    ///
    /// # Errors
    /// Returns `PkcsError::Cryptoki` if `C_GenerateKeyPair` fails.
    pub fn generate_rsa_keypair(
        &self,
        modulus_bits: usize,
        label: &str,
    ) -> Result<(ObjectHandle, ObjectHandle), PkcsError> {
        let bits = Ulong::try_from(modulus_bits).map_err(|e| PkcsError::Internal(e.to_string()))?;

        let pub_template = vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            Attribute::ModulusBits(bits),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Verify(true),
        ];
        let priv_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Sign(true),
        ];

        self.with_session(|session| {
            session.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &pub_template, &priv_template)
        })
    }

    // -----------------------------------------------------------------------
    // Slot enumeration
    // -----------------------------------------------------------------------

    /// List all slots that have a token present, together with their
    /// `TokenInfo`.
    ///
    /// # Errors
    /// Returns `PkcsError::Init` if the module cannot be loaded or initialized,
    /// or `PkcsError::Cryptoki` if `C_GetSlotList` / `C_GetTokenInfo` fails.
    pub fn list_slots(module_path: &Path) -> Result<Vec<(Slot, TokenInfo)>, PkcsError> {
        let ctx = Pkcs11::new(module_path).map_err(|e| PkcsError::Init(e.to_string()))?;

        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| PkcsError::Init(e.to_string()))?;

        let slots = ctx.get_slots_with_token().map_err(PkcsError::Cryptoki)?;

        let mut result = Vec::with_capacity(slots.len());
        for slot in slots {
            let token_info = ctx.get_token_info(slot).map_err(PkcsError::Cryptoki)?;
            result.push((slot, token_info));
        }
        Ok(result)
    }
}

impl Drop for Pkcs11Provider {
    fn drop(&mut self) {
        // Try to logout before the session closes itself.  Errors are
        // swallowed here because we are in a destructor and cannot propagate
        // them.  The session itself will close (and perform its own cleanup)
        // when the MutexGuard is released and the Mutex is subsequently
        // dropped.
        if let Ok(guard) = self.session.lock() {
            drop(guard.logout());
            // `guard` is dropped here, releasing the mutex; `Session` then
            // runs its own Drop (C_CloseSession) when the Mutex is destroyed.
        }
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

    /// All PkcsError variants must have distinct Display output.
    #[test]
    fn test_pkcs_error_variants_distinguishable() {
        let variants: Vec<String> = vec![
            PkcsError::Init("x".to_string()).to_string(),
            PkcsError::Session("x".to_string()).to_string(),
            PkcsError::Operation("x".to_string()).to_string(),
            PkcsError::LockPoisoned.to_string(),
            PkcsError::KeyNotFound {
                label: "key1".to_string(),
            }
            .to_string(),
            PkcsError::MechanismNotSupported {
                mechanism: "AES-GCM".to_string(),
            }
            .to_string(),
            PkcsError::BufferTooSmall.to_string(),
            PkcsError::Internal("boom".to_string()).to_string(),
        ];
        // All strings must differ from each other.
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "variants {i} and {j} collide: {a:?}");
                }
            }
        }
    }

    /// format!("{}", e) must not panic for every variant.
    #[test]
    fn test_pkcs_error_display_no_panic() {
        let variants: Vec<PkcsError> = vec![
            PkcsError::Init("x".to_string()),
            PkcsError::Session("x".to_string()),
            PkcsError::Operation("x".to_string()),
            PkcsError::LockPoisoned,
            PkcsError::KeyNotFound {
                label: "k".to_string(),
            },
            PkcsError::MechanismNotSupported {
                mechanism: "m".to_string(),
            },
            PkcsError::BufferTooSmall,
            PkcsError::Internal("i".to_string()),
        ];
        for e in variants {
            let _ = format!("{e}");
        }
    }
}
