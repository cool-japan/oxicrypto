# oxicrypto-adapter-pkcs11 — PKCS#11 HSM backend for OxiCrypto

[![Crates.io](https://img.shields.io/crates/v/oxicrypto-adapter-pkcs11.svg)](https://crates.io/crates/oxicrypto-adapter-pkcs11)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxicrypto-adapter-pkcs11` bridges the OxiCrypto trait surface to a [PKCS#11](https://docs.oasis-open.org/pkcs11/) Hardware Security Module (HSM) via the [`cryptoki`](https://crates.io/crates/cryptoki) crate. It opens an authenticated session against a PKCS#11 token and exposes signer, verifier, and symmetric encrypt/decrypt adaptors that delegate every cryptographic operation to the HSM, so private key material never leaves the device.

> **Not Pure Rust.** This adapter loads a vendor PKCS#11 dynamic library (e.g. SoftHSM2, Thales Luna, nShield, AWS CloudHSM) at runtime through the `cryptoki` FFI bindings. It therefore depends on a **C** module and external hardware/middleware, in deliberate contrast to the default Pure-Rust OxiCrypto stack. It is **opt-in and non-default**: the crate exposes **no types** unless the `pkcs11` feature is enabled, and from **0.2.0** the parent `oxicrypto` facade no longer re-exports it — depend on this crate directly. A PKCS#11 module must be present at runtime.

## Installation

```toml
[dependencies]
# Types are only compiled in when the `pkcs11` feature is on.
oxicrypto-adapter-pkcs11 = { version = "0.2.1", features = ["pkcs11"] }
```

From **oxicrypto 0.2.0**, the `pkcs11` feature is no longer available on the `oxicrypto` facade. Depend on this adapter crate directly instead of going via the facade.

At runtime you need a PKCS#11 provider library (a `.so` / `.dylib` / `.dll`)
and a token with the keys you intend to use.

## Quick Start

```rust,ignore
use oxicrypto_adapter_pkcs11::provider::Pkcs11Provider;
use oxicrypto_adapter_pkcs11::sign::Pkcs11Signer;
use cryptoki::{mechanism::Mechanism, object::ObjectHandle, slot::Slot};
use std::path::Path;
use std::sync::Arc;

// 1. Load the module, initialize, open an R/W session, and log in as User.
let provider = Arc::new(Pkcs11Provider::new(
    Path::new("/usr/lib/softhsm/libsofthsm2.so"),
    Slot::try_from(0u64)?,
    "1234", // user PIN
)?);

// 2. Sign with an on-token key, addressed by its ObjectHandle.
let signer = Pkcs11Signer::new(Arc::clone(&provider));
let key: ObjectHandle = /* located via cryptoki object search */ unimplemented!();
let signature = signer.sign_with_handle(Mechanism::EcdsaSha256, key, b"message")?;

# Ok::<(), Box<dyn std::error::Error>>(())
```

Private keys live inside the HSM. The blanket `Signer::sign` on [`Pkcs11Signer`] resolves its `sk: &[u8]` argument as a UTF-8 `CKA_LABEL` and looks the key up via `C_FindObjects` (mechanism: raw ECDSA by default; configure a different `SignMechanism` or a default label via [`Pkcs11SignerBuilder`]). Use `*_with_handle` / `encrypt` / `decrypt` directly when you already hold an `ObjectHandle`. `Verifier::verify` has no such label path — PKCS#11 verification always needs an explicit key handle, so the blanket trait method deliberately returns `CryptoError::BadInput`; use `verify_with_handle` (see below).

## API Overview

All items below are compiled **only** when the `pkcs11` feature is enabled.

### `provider` module

| Item | Description |
|------|-------------|
| `Pkcs11Provider` | A live, authenticated PKCS#11 session. Wraps `cryptoki::session::Session` in a `Mutex` so the provider is `Send + Sync`. |
| `Pkcs11Provider::new(module_path, slot, pin)` | Load the module, call `C_Initialize`, open an R/W session on `slot`, and log in as `User` with `pin`. Returns `PkcsError` on any failure. |
| `Pkcs11Provider::with_so_login(module_path, slot, so_pin)` | Identical to `new`, but logs in as Security Officer (`CKU_SO`) — needed for key-management operations such as `C_InitPIN`. |
| `Pkcs11Provider::with_session(f)` | Run a closure with exclusive access to the underlying `Session`; the primitive used by the signer/sym adaptors. |
| `Pkcs11Provider::generate_hmac_key(label)` | Generate a token-resident, non-extractable HMAC-SHA-256 `CKO_SECRET_KEY` (`CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`) labelled `label`. |
| `Pkcs11Provider::generate_extractable_aes_key(label)` | Generate a token-resident 32-byte AES key with `CKA_EXTRACTABLE=true`. **Warning:** extractable keys can be exported from the HSM — only use where the HSM's access control provides equivalent protection. |
| `Pkcs11Provider::extract_key_value(handle)` | Read the raw `CKA_VALUE` of a secret-key object; only succeeds if the key was created with `CKA_EXTRACTABLE=true`. |
| `PkcsError` | Adapter error enum (see [Error variants](#error-variants)). Implements `Display`, `std::error::Error`, and `From<PkcsError> for CryptoError`. |

### `sign` module

| Item | Implements | Description |
|------|-----------|-------------|
| `Pkcs11Signer` | `oxicrypto_core::Signer` | HSM-backed signer holding an `Arc<Pkcs11Provider>`. |
| `Pkcs11Signer::new(provider)` | — | Construct from a provider session (raw ECDSA mechanism, no default label). |
| `Pkcs11Signer::sign_with_handle(mechanism, key, msg)` | — | Single-part `C_Sign` with a caller-supplied `Mechanism` (e.g. `Mechanism::EcdsaSha256`) and `ObjectHandle`. Returns raw HSM signature bytes. |
| `SignMechanism` | — | `Send + Sync` mechanism selector: `Ecdsa`, `EcdsaSha1`/`224`/`256`/`384`/`512`, `RsaSha256`/`384`/`512Pkcs`. `to_mechanism()` converts to `cryptoki::Mechanism`. |
| `Pkcs11SignerBuilder` | — | Builder for `Pkcs11Signer`: `.mechanism(SignMechanism)`, `.key_label(impl Into<String>)`, `.build()`. A configured label lets the blanket `Signer::sign` be called with an empty `sk`. |
| `Pkcs11Verifier` | `oxicrypto_core::Verifier` | HSM-backed verifier holding an `Arc<Pkcs11Provider>`. |
| `Pkcs11Verifier::new(provider)` | — | Construct from a provider session. |
| `Pkcs11Verifier::verify_with_handle(mechanism, key, msg, sig)` | — | Single-part `C_Verify` with a caller-supplied mechanism and key handle. |

The blanket `Signer::sign(&[u8], …)` on `Pkcs11Signer` interprets `sk` as a UTF-8 `CKA_LABEL`, resolves it via `C_FindObjects`, and signs with the configured `SignMechanism` (default: raw `Ecdsa`) — see the Quick Start note above. The blanket `Verifier::verify(&[u8], …)` always returns `CryptoError::BadInput`, because PKCS#11 verification addresses keys by `ObjectHandle`, not by raw byte material; use `verify_with_handle`. `Signer::signature_len()` returns a conservative upper bound of `512`; use `sign_with_handle` for the exact output length.

### `sym` module

| Item | Description |
|------|-------------|
| `Pkcs11SymOp<'a>` | HSM-backed symmetric encrypt/decrypt adaptor borrowing a `&Pkcs11Provider`. |
| `Pkcs11SymOp::new(provider)` | Construct from a provider session. |
| `Pkcs11SymOp::encrypt(mechanism, key, plaintext)` | Single-part `C_Encrypt`. Returns ciphertext (including any appended tag). The IV/nonce (and AAD/tag bits for AEAD) must be embedded in the `Mechanism` parameters, e.g. `Mechanism::AesGcm(GcmParams { … })`. |
| `Pkcs11SymOp::decrypt(mechanism, key, ciphertext)` | Single-part `C_Decrypt`. Returns recovered plaintext; surfaces auth-tag mismatches for AEAD modes. |
| `Pkcs11SymOp::map_err(e)` | Convert a `PkcsError` to `CryptoError` for callers on the generic trait surface. |
| `Pkcs11Aead` | HSM-backed AES-256-GCM implementing `oxicrypto_core::Aead` (`name() = "AES-256-GCM-PKCS11"`, `key_len() = 32`, `nonce_len() = 12`, `tag_len() = 16`). |
| `Pkcs11Aead::new(provider, key_handle)` | Construct from a provider and an on-token AES key `ObjectHandle`. The `key` argument to `seal`/`open` is ignored — the key never leaves the HSM. |

### `hash` module

| Item | Description |
|------|-------------|
| `Pkcs11Hash` | HSM-backed digest implementing `oxicrypto_core::Hash` via `C_DigestInit` + `C_Digest`. Construct with `Pkcs11Hash::sha256(provider)` / `sha384(provider)` / `sha512(provider)`. |
| `DigestMechanism` | `Send + Sync` mechanism selector: `Sha256`, `Sha384`, `Sha512`. |

### `pool` module

A lightweight pool for reusing authenticated `cryptoki::session::Session` objects; each checked-out session is still used by one thread at a time, serialised by an internal `Mutex`.

| Item | Description |
|------|-------------|
| `Pkcs11SessionPool` | `Clone`-able, `Send + Sync` pool wrapping `Arc<Mutex<Vec<Session>>>`. `new()`, `checkin(session)`, `checkout() -> PooledSession`, `idle_count()`. |
| `PooledSession<'a>` | An exclusive lease with a `pub session: Option<Session>` field (`None` if the pool was empty at checkout); returns the session to the pool on drop. |

### `tls` module (requires the `tls` feature)

Implements `rustls::sign::{SigningKey, Signer}` backed by a PKCS#11 session, so a TLS server/client can keep its private key on the HSM instead of loading it into process memory. Supports ECDSA (P-256, P-384) and RSA (PKCS#1v1.5, PSS); Ed25519 is not supported (rustls does not expose it in `SignatureScheme`). Many HSMs return raw `r ‖ s` ECDSA signatures — this module detects that (first byte ≠ `0x30`) and converts to DER before returning to rustls.

| Item | Description |
|------|-------------|
| `Pkcs11TlsSigningKey` | `rustls::sign::SigningKey` impl. `new(provider, key_label, algorithm)`, or the convenience `new_ecdsa(provider, key_label)` / `new_rsa(provider, key_label)`. `choose_scheme` picks the best offered `SignatureScheme` for the key's algorithm. |
| `Pkcs11TlsSigner` | `rustls::sign::Signer` impl returned by `choose_scheme`; single-use, signs via the HSM session. |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `pkcs11` | off | Activates the `hash`, `pool`, `provider`, `sign`, and `sym` modules (pulls in the `cryptoki` FFI dependency). With this flag off, the crate compiles to an empty surface — a default-features build has zero tests and zero public types. |
| `tls` | off | Activates the `tls` module (implies `pkcs11`; pulls in the `rustls` crate). |
| `bench` | off | Enables the `pkcs11_bench` criterion benchmarks (implies `pkcs11`). |

## Error variants

### `PkcsError` (adapter-local)

| Variant | Meaning |
|---------|---------|
| `Init(String)` | Failed to load the PKCS#11 module or run `C_Initialize`. |
| `Session(String)` | Failed to open a session or log in. |
| `Operation(String)` | A cryptographic operation (`C_Sign`, `C_Encrypt`, …) failed. |
| `LockPoisoned` | The internal session `Mutex` was poisoned. |

`PkcsError` converts into `oxicrypto_core::CryptoError::Internal(...)` via its
`From` impl, so HSM failures can flow through the generic OxiCrypto trait
surface as `CryptoError`.

### `oxicrypto_core::CryptoError`

| Variant | When it is returned |
|---------|---------------------|
| `BadInput` | A trait-level `Signer::sign` / `Verifier::verify` was called with raw key bytes (unsupported for PKCS#11 — use the `*_with_handle` methods). |
| `Internal(&'static str)` | A `PkcsError` was mapped into the generic surface (details preserved in the originating `PkcsError`). |

## Cross-references

- [`oxicrypto-core`](../oxicrypto-core) — the `Signer`, `Verifier`, `Aead`, `Hash`, and `CryptoError` definitions this adapter implements.
- [`oxicrypto`](../oxicrypto) — Pure-Rust facade; from 0.2.0 this adapter must be depended on directly (no longer re-exported via `oxicrypto::pkcs11`).
- [`oxicrypto-adapter-aws-lc`](../oxicrypto-adapter-aws-lc) — the other opt-in, non-Pure-Rust adapter (FIPS-validated `aws-lc-rs`).
- [`oxicrypto-sig`](../oxicrypto-sig) — Pure-Rust signature primitives for software-key workflows.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
