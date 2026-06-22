# oxicrypto-adapter-pkcs11 — PKCS#11 HSM backend for OxiCrypto

[![Crates.io](https://img.shields.io/crates/v/oxicrypto-adapter-pkcs11.svg)](https://crates.io/crates/oxicrypto-adapter-pkcs11)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxicrypto-adapter-pkcs11` bridges the OxiCrypto trait surface to a [PKCS#11](https://docs.oasis-open.org/pkcs11/) Hardware Security Module (HSM) via the [`cryptoki`](https://crates.io/crates/cryptoki) crate. It opens an authenticated session against a PKCS#11 token and exposes signer, verifier, and symmetric encrypt/decrypt adaptors that delegate every cryptographic operation to the HSM, so private key material never leaves the device.

> **Not Pure Rust.** This adapter loads a vendor PKCS#11 dynamic library (e.g. SoftHSM2, Thales Luna, nShield, AWS CloudHSM) at runtime through the `cryptoki` FFI bindings. It therefore depends on a **C** module and external hardware/middleware, in deliberate contrast to the default Pure-Rust OxiCrypto stack. It is **opt-in and non-default**: the crate exposes **no types** unless the `pkcs11` feature is enabled, and from **0.2.0** the parent `oxicrypto` facade no longer re-exports it — depend on this crate directly. A PKCS#11 module must be present at runtime.

## Installation

```toml
[dependencies]
# Types are only compiled in when the `pkcs11` feature is on.
oxicrypto-adapter-pkcs11 = { version = "0.2.0", features = ["pkcs11"] }
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

// 1. Load the module, initialize, open an R/W session, and log in as User.
let provider = Pkcs11Provider::new(
    Path::new("/usr/lib/softhsm/libsofthsm2.so"),
    Slot::try_from(0u64)?,
    "1234", // user PIN
)?;

// 2. Sign with an on-token key, addressed by its ObjectHandle.
let signer = Pkcs11Signer::new(&provider);
let key: ObjectHandle = /* located via cryptoki object search */ unimplemented!();
let signature = signer.sign_with_handle(Mechanism::EcdsaSha256, key, b"message")?;

# Ok::<(), Box<dyn std::error::Error>>(())
```

Because private keys live inside the HSM and are referenced by an
`ObjectHandle` rather than by raw bytes, use the `*_with_handle` /
`encrypt` / `decrypt` methods. The blanket `Signer`/`Verifier` trait methods
that take raw `&[u8]` key bytes deliberately return `CryptoError::BadInput`
(see below).

## API Overview

All items below are compiled **only** when the `pkcs11` feature is enabled.

### `provider` module

| Item | Description |
|------|-------------|
| `Pkcs11Provider` | A live, authenticated PKCS#11 session. Wraps `cryptoki::session::Session` in a `Mutex` so the provider is `Send + Sync`. |
| `Pkcs11Provider::new(module_path, slot, pin)` | Load the module, call `C_Initialize`, open an R/W session on `slot`, and log in as `User` with `pin`. Returns `PkcsError` on any failure. |
| `Pkcs11Provider::with_session(f)` | Run a closure with exclusive access to the underlying `Session`; the primitive used by the signer/sym adaptors. |
| `PkcsError` | Adapter error enum (see [Error variants](#error-variants)). Implements `Display`, `std::error::Error`, and `From<PkcsError> for CryptoError`. |

### `sign` module

| Item | Implements | Description |
|------|-----------|-------------|
| `Pkcs11Signer<'a>` | `oxicrypto_core::Signer` | HSM-backed signer borrowing a `&Pkcs11Provider`. |
| `Pkcs11Signer::new(provider)` | — | Construct from a provider session. |
| `Pkcs11Signer::sign_with_handle(mechanism, key, msg)` | — | Single-part `C_Sign` with a caller-supplied `Mechanism` (e.g. `Mechanism::EcdsaSha256`) and `ObjectHandle`. Returns raw HSM signature bytes. |
| `Pkcs11Verifier<'a>` | `oxicrypto_core::Verifier` | HSM-backed verifier. |
| `Pkcs11Verifier::new(provider)` | — | Construct from a provider session. |
| `Pkcs11Verifier::verify_with_handle(mechanism, key, msg, sig)` | — | Single-part `C_Verify` with a caller-supplied mechanism and key handle. |

The trait-level `Signer::sign(&[u8], …)` and `Verifier::verify(&[u8], …)`
always return `CryptoError::BadInput`, because PKCS#11 addresses keys by
`ObjectHandle`, not by raw byte material. `Signer::signature_len()` returns a
conservative upper bound of `512`; use `sign_with_handle` for the exact output.

### `sym` module

| Item | Description |
|------|-------------|
| `Pkcs11SymOp<'a>` | HSM-backed symmetric encrypt/decrypt adaptor borrowing a `&Pkcs11Provider`. |
| `Pkcs11SymOp::new(provider)` | Construct from a provider session. |
| `Pkcs11SymOp::encrypt(mechanism, key, plaintext)` | Single-part `C_Encrypt`. Returns ciphertext (including any appended tag). The IV/nonce (and AAD/tag bits for AEAD) must be embedded in the `Mechanism` parameters, e.g. `Mechanism::AesGcm(GcmParams { … })`. |
| `Pkcs11SymOp::decrypt(mechanism, key, ciphertext)` | Single-part `C_Decrypt`. Returns recovered plaintext; surfaces auth-tag mismatches for AEAD modes. |
| `Pkcs11SymOp::map_err(e)` | Convert a `PkcsError` to `CryptoError` for callers on the generic trait surface. |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `pkcs11` | off | Activates the `provider`, `sign`, and `sym` modules (pulls in the `cryptoki` FFI dependency). With this flag off, the crate compiles to an empty surface. |

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

- [`oxicrypto-core`](../oxicrypto-core) — the `Signer`, `Verifier`, and `CryptoError` definitions this adapter implements.
- [`oxicrypto`](../oxicrypto) — Pure-Rust facade; from 0.2.0 this adapter must be depended on directly (no longer re-exported via `oxicrypto::pkcs11`).
- [`oxicrypto-adapter-aws-lc`](../oxicrypto-adapter-aws-lc) — the other opt-in, non-Pure-Rust adapter (FIPS-validated `aws-lc-rs`).
- [`oxicrypto-sig`](../oxicrypto-sig) — Pure-Rust signature primitives for software-key workflows.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
