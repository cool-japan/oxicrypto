use oxicrypto_aead::{Nonce12Bytes, Nonce24Bytes, NonceBytes};
use oxicrypto_core::CryptoError;

#[test]
fn nonce12bytes_from_array() {
    let arr = [0x42u8; 12];
    let nonce = Nonce12Bytes::from_array(arr);
    assert_eq!(nonce.as_bytes(), &arr);
}

#[test]
fn nonce12bytes_from_trait() {
    let arr = [0x24u8; 12];
    let nonce: Nonce12Bytes = arr.into();
    assert_eq!(nonce.as_bytes(), &arr);
}

#[test]
fn nonce12bytes_tryfrom_correct_len() {
    let slice: &[u8] = &[0xABu8; 12];
    let nonce = Nonce12Bytes::try_from(slice).expect("should succeed");
    assert_eq!(&*nonce, slice);
}

#[test]
fn nonce12bytes_tryfrom_wrong_len() {
    let slice: &[u8] = &[0x00u8; 11];
    let result = Nonce12Bytes::try_from(slice);
    assert_eq!(
        result,
        Err(CryptoError::BadInput),
        "wrong length must return BadInput"
    );
}

#[test]
fn nonce12bytes_tryfrom_too_long() {
    let slice: &[u8] = &[0x00u8; 13];
    let result = Nonce12Bytes::try_from(slice);
    assert_eq!(result, Err(CryptoError::BadInput));
}

#[test]
fn nonce12bytes_deref() {
    let arr = [0x55u8; 12];
    let nonce = Nonce12Bytes::from_array(arr);
    // Deref to &[u8] — can be passed as slice.
    let slice: &[u8] = &nonce;
    assert_eq!(slice, &arr);
    assert_eq!(slice.len(), 12);
}

#[test]
fn nonce24bytes_from_array() {
    let arr = [0x77u8; 24];
    let nonce = Nonce24Bytes::from_array(arr);
    assert_eq!(nonce.as_bytes(), &arr);
}

#[test]
fn nonce24bytes_tryfrom_wrong_len() {
    let slice: &[u8] = &[0x00u8; 12];
    let result = Nonce24Bytes::try_from(slice);
    assert_eq!(result, Err(CryptoError::BadInput));
}

#[test]
fn nonce_bytes_equality() {
    let a = Nonce12Bytes::from_array([1u8; 12]);
    let b = Nonce12Bytes::from_array([1u8; 12]);
    let c = Nonce12Bytes::from_array([2u8; 12]);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn nonce_bytes_clone_copy() {
    let a = Nonce12Bytes::from_array([0xAAu8; 12]);
    let b = a; // Copy
    let c = a; // Copy again
    assert_eq!(b, c);
}

#[test]
fn generic_nonce_bytes_const() {
    // NonceBytes<const N> can be used with arbitrary sizes.
    const NONCE8: NonceBytes<8> = NonceBytes::from_array([0u8; 8]);
    assert_eq!(NONCE8.as_bytes(), &[0u8; 8]);
}
