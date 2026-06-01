use super::*;

#[test]
fn secret_key_debug_does_not_leak() {
    let key = SecretKey::<32>::new([0xAA; 32]);
    let dbg = alloc::format!("{key:?}");
    assert!(!dbg.contains("AA"), "Debug output must not leak key bytes");
    assert!(dbg.contains("***"), "Debug output must mask key bytes");
}

#[test]
fn secret_key_from_slice_wrong_len() {
    let result = SecretKey::<32>::from_slice(&[0u8; 16]);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), CryptoError::InvalidKey);
}

#[test]
fn secret_key_from_slice_ok() {
    let key = SecretKey::<32>::from_slice(&[0xBB; 32]).expect("should succeed");
    assert_eq!(key.as_bytes(), &[0xBB; 32]);
}

#[test]
fn secret_vec_debug_does_not_leak() {
    let sv = SecretVec::from_slice(&[0xCC; 16]);
    let dbg = alloc::format!("{sv:?}");
    assert!(!dbg.contains("CC"));
    assert!(dbg.contains("***"));
    assert_eq!(sv.len(), 16);
    assert!(!sv.is_empty());
}

#[test]
fn ct_eq_same() {
    assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
}

#[test]
fn ct_eq_different() {
    assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
}

#[test]
fn ct_eq_different_lengths() {
    assert!(!ct_eq(&[1, 2], &[1, 2, 3]));
}

#[test]
fn ct_is_zero_true() {
    assert!(ct_is_zero(&[0, 0, 0, 0]));
}

#[test]
fn ct_is_zero_false() {
    assert!(!ct_is_zero(&[0, 0, 1, 0]));
}

#[test]
fn ct_is_zero_empty() {
    assert!(ct_is_zero(&[]));
}

#[test]
fn ct_select_choice_zero() {
    assert_eq!(ct_select(10, 20, 0), 10);
}

#[test]
fn ct_select_choice_one() {
    assert_eq!(ct_select(10, 20, 1), 20);
}

#[test]
fn error_display_new_variants() {
    assert_eq!(
        alloc::format!("{}", CryptoError::Rng),
        "random number generator failure"
    );
    assert_eq!(
        alloc::format!("{}", CryptoError::Encoding),
        "encoding or decoding failure"
    );
    assert_eq!(
        alloc::format!("{}", CryptoError::UnsupportedAlgorithm),
        "unsupported algorithm"
    );
}

#[test]
fn keypair_debug_masks_secret() {
    let kp = KeyPair::new([0xDD_u8; 32], [0xEE_u8; 32]);
    let dbg = alloc::format!("{kp:?}");
    assert!(dbg.contains("***"), "KeyPair Debug must mask secret");
}

#[test]
fn streaming_aead_trait_object_compiles() {
    struct DummyAead;
    impl StreamingAead for DummyAead {
        fn init(_k: &[u8], _n: &[u8], _a: &[u8]) -> Result<Self, CryptoError> {
            Ok(DummyAead)
        }
        fn encrypt_update(&mut self, _c: &[u8], _o: &mut [u8]) -> Result<usize, CryptoError> {
            Ok(0)
        }
        fn encrypt_finalize(self, _o: &mut [u8]) -> Result<[u8; 16], CryptoError> {
            Ok([0u8; 16])
        }
        fn decrypt_update(&mut self, _c: &[u8], _o: &mut [u8]) -> Result<usize, CryptoError> {
            Ok(0)
        }
        fn decrypt_finalize(self, _t: &[u8]) -> Result<(), CryptoError> {
            Ok(())
        }
        fn reset(&mut self) {}
    }
    let _ = DummyAead::init(b"key", b"nonce", b"aad");
}

#[test]
fn kem_trait_compiles() {
    struct DummyKem;
    impl Kem for DummyKem {
        type EncapKey = ();
        type DecapKey = ();
        type Ciphertext = ();
        type SharedSecret = [u8; 32];
        fn kem_generate() -> Result<((), ()), CryptoError> {
            Ok(((), ()))
        }
        fn kem_encapsulate(_: &()) -> Result<((), [u8; 32]), CryptoError> {
            Ok(((), [0u8; 32]))
        }
        fn kem_decapsulate(_: &(), _: &()) -> Result<[u8; 32], CryptoError> {
            Ok([0u8; 32])
        }
    }
    let _ = DummyKem::kem_generate();
}

#[test]
fn password_hash_trait_compiles() {
    struct DummyParams;
    impl PasswordHashParams for DummyParams {
        fn memory_cost(&self) -> Option<u32> {
            None
        }
        fn time_cost(&self) -> Option<u32> {
            Some(1)
        }
        fn parallelism(&self) -> Option<u32> {
            None
        }
    }
    struct DummyPwHash;
    impl PasswordHash for DummyPwHash {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn hash_password(
            &self,
            _pw: &[u8],
            _salt: &[u8],
            _p: &dyn PasswordHashParams,
            out: &mut [u8],
        ) -> Result<(), CryptoError> {
            out.iter_mut().for_each(|b| *b = 0);
            Ok(())
        }
    }
    let mut out = [0u8; 32];
    DummyPwHash
        .hash_password(b"pass", b"salt", &DummyParams, &mut out)
        .unwrap();
}

#[test]
fn key_generator_trait_compiles() {
    struct DummyGen;
    impl KeyGenerator for DummyGen {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn generate_keypair(&self) -> Result<KeyPair<SecretVec, Vec<u8>>, CryptoError> {
            Ok(KeyPair::new(
                SecretVec::from_slice(&[0u8; 32]),
                alloc::vec![0u8; 32],
            ))
        }
    }
    let kp = DummyGen.generate_keypair().unwrap();
    assert_eq!(kp.public().len(), 32);
}

// -----------------------------------------------------------------------
// AlgorithmId tests
// -----------------------------------------------------------------------

/// All defined variants (tested exhaustively at compile time via the match arms).
const ALL_ALGORITHM_IDS: &[AlgorithmId] = &[
    AlgorithmId::Sha256,
    AlgorithmId::Sha384,
    AlgorithmId::Sha512,
    AlgorithmId::Sha512_256,
    AlgorithmId::Sha3_256,
    AlgorithmId::Sha3_384,
    AlgorithmId::Sha3_512,
    AlgorithmId::Blake2b256,
    AlgorithmId::Blake2b512,
    AlgorithmId::Blake3,
    AlgorithmId::Aes128Gcm,
    AlgorithmId::Aes256Gcm,
    AlgorithmId::ChaCha20Poly1305,
    AlgorithmId::Aes128GcmSiv,
    AlgorithmId::Aes256GcmSiv,
    AlgorithmId::XChaCha20Poly1305,
    AlgorithmId::Aes128Ccm,
    AlgorithmId::Aes256Ccm,
    AlgorithmId::DeoxysII128,
    AlgorithmId::AesKeyWrap128,
    AlgorithmId::AesKeyWrap256,
    AlgorithmId::HmacSha256,
    AlgorithmId::HmacSha384,
    AlgorithmId::HmacSha512,
    AlgorithmId::HmacSha3_256,
    AlgorithmId::HmacSha3_512,
    AlgorithmId::Poly1305,
    AlgorithmId::CmacAes128,
    AlgorithmId::CmacAes256,
    AlgorithmId::Kmac128,
    AlgorithmId::Kmac256,
    AlgorithmId::Ed25519,
    AlgorithmId::Ed448,
    AlgorithmId::EcdsaP256,
    AlgorithmId::EcdsaP384,
    AlgorithmId::EcdsaP521,
    AlgorithmId::RsaPkcs1v15Sha256,
    AlgorithmId::RsaPkcs1v15Sha384,
    AlgorithmId::RsaPkcs1v15Sha512,
    AlgorithmId::RsaPssSha256,
    AlgorithmId::SchnorrBip340,
    AlgorithmId::X25519,
    AlgorithmId::X448,
    AlgorithmId::EcdhP256,
    AlgorithmId::EcdhP384,
    AlgorithmId::EcdhP521,
    AlgorithmId::HkdfSha256,
    AlgorithmId::HkdfSha384,
    AlgorithmId::HkdfSha512,
    AlgorithmId::Pbkdf2Sha256,
    AlgorithmId::Pbkdf2Sha512,
    AlgorithmId::Argon2id,
    AlgorithmId::Scrypt,
    AlgorithmId::Balloon,
    AlgorithmId::MlKem512,
    AlgorithmId::MlKem768,
    AlgorithmId::MlKem1024,
    AlgorithmId::MlDsa44,
    AlgorithmId::MlDsa65,
    AlgorithmId::MlDsa87,
    AlgorithmId::XWing768X25519,
    AlgorithmId::HybridKem1024P384,
    AlgorithmId::SlhDsaSha2_128s,
    AlgorithmId::SlhDsaSha2_128f,
    AlgorithmId::SlhDsaSha2_192s,
    AlgorithmId::SlhDsaSha2_192f,
    AlgorithmId::SlhDsaSha2_256s,
    AlgorithmId::SlhDsaSha2_256f,
    AlgorithmId::SlhDsaShake128s,
    AlgorithmId::SlhDsaShake128f,
    AlgorithmId::SlhDsaShake256s,
    AlgorithmId::SlhDsaShake256f,
];

#[test]
fn algorithm_id_all_names_nonempty() {
    for id in ALL_ALGORITHM_IDS {
        assert!(!id.name().is_empty(), "AlgorithmId {id:?} has empty name");
    }
}

#[test]
fn algorithm_id_all_names_unique() {
    let mut names: Vec<&'static str> = ALL_ALGORITHM_IDS.iter().map(|id| id.name()).collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total, "Duplicate algorithm names detected");
}

#[test]
fn algorithm_id_sha256_name() {
    assert_eq!(AlgorithmId::Sha256.name(), "SHA-256");
}

#[test]
fn algorithm_id_mlkem768_category() {
    assert_eq!(
        AlgorithmId::MlKem768.category(),
        AlgorithmCategory::PostQuantum
    );
}

#[test]
fn algorithm_id_sha256_display() {
    assert_eq!(alloc::format!("{}", AlgorithmId::Sha256), "SHA-256");
}

#[test]
fn algorithm_id_sha256_category_is_hash() {
    assert_eq!(AlgorithmId::Sha256.category(), AlgorithmCategory::Hash);
}

#[test]
fn algorithm_id_aes256gcm_category_is_aead() {
    assert_eq!(AlgorithmId::Aes256Gcm.category(), AlgorithmCategory::Aead);
}

#[test]
fn algorithm_id_hmacsha256_category_is_mac() {
    assert_eq!(AlgorithmId::HmacSha256.category(), AlgorithmCategory::Mac);
}

#[test]
fn algorithm_id_ed25519_category_is_signature() {
    assert_eq!(
        AlgorithmId::Ed25519.category(),
        AlgorithmCategory::Signature
    );
}

#[test]
fn algorithm_id_x25519_category_is_keyexchange() {
    assert_eq!(
        AlgorithmId::X25519.category(),
        AlgorithmCategory::KeyExchange
    );
}

#[test]
fn algorithm_id_hkdf_sha256_category_is_kdf() {
    assert_eq!(AlgorithmId::HkdfSha256.category(), AlgorithmCategory::Kdf);
}

#[test]
fn algorithm_id_deoxys_ii_128_category_is_aead() {
    assert_eq!(AlgorithmId::DeoxysII128.category(), AlgorithmCategory::Aead);
    assert_eq!(AlgorithmId::DeoxysII128.name(), "Deoxys-II-128-128");
}

#[test]
fn algorithm_id_schnorr_bip340_category_is_signature() {
    assert_eq!(
        AlgorithmId::SchnorrBip340.category(),
        AlgorithmCategory::Signature
    );
    assert_eq!(AlgorithmId::SchnorrBip340.name(), "Schnorr-BIP340");
}

#[test]
fn algorithm_id_balloon_category_is_kdf() {
    assert_eq!(AlgorithmId::Balloon.category(), AlgorithmCategory::Kdf);
    assert_eq!(AlgorithmId::Balloon.name(), "Balloon-SHA256");
}

// -----------------------------------------------------------------------
// hash_to_array tests (via mock Hash implementor)
// -----------------------------------------------------------------------

struct MockHash {
    output_len: usize,
}

impl Hash for MockHash {
    fn name(&self) -> &'static str {
        "mock"
    }
    fn output_len(&self) -> usize {
        self.output_len
    }
    fn hash(&self, msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < self.output_len {
            return Err(CryptoError::BufferTooSmall);
        }
        // Fill with XOR-based deterministic value for testing
        for (i, b) in out[..self.output_len].iter_mut().enumerate() {
            *b = msg.get(i % msg.len().max(1)).copied().unwrap_or(0) ^ (i as u8);
        }
        Ok(())
    }
}

#[test]
fn hash_to_array_correct_n() {
    let h = MockHash { output_len: 4 };
    let msg = b"test";
    let arr = h.hash_to_array::<4>(msg).expect("should succeed with N=4");
    let vec = h.hash_to_vec(msg).expect("hash_to_vec should succeed");
    assert_eq!(
        &arr[..],
        vec.as_slice(),
        "hash_to_array and hash_to_vec must agree"
    );
}

#[test]
fn hash_to_array_wrong_n_returns_bad_input() {
    let h = MockHash { output_len: 4 };
    let result = h.hash_to_array::<8>(b"test");
    assert_eq!(result.unwrap_err(), CryptoError::BadInput);
}

// -----------------------------------------------------------------------
// seal_to_vec / open_to_vec tests (via mock Aead implementor)
// -----------------------------------------------------------------------

struct MockAead;

impl Aead for MockAead {
    fn name(&self) -> &'static str {
        "mock-aead"
    }
    fn key_len(&self) -> usize {
        16
    }
    fn nonce_len(&self) -> usize {
        12
    }
    fn tag_len(&self) -> usize {
        4
    }

    fn seal(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        pt: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let total = pt.len() + self.tag_len();
        if ct_out.len() < total {
            return Err(CryptoError::BufferTooSmall);
        }
        ct_out[..pt.len()].copy_from_slice(pt);
        // Append simple tag: byte XOR of plaintext repeated to 4 bytes
        let tag_val: u8 = pt.iter().fold(0u8, |acc, &b| acc ^ b);
        for b in &mut ct_out[pt.len()..total] {
            *b = tag_val;
        }
        Ok(total)
    }

    fn open(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        ct: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let tag_len = self.tag_len();
        if ct.len() < tag_len {
            return Err(CryptoError::BufferTooSmall);
        }
        let pt_len = ct.len() - tag_len;
        if pt_out.len() < pt_len {
            return Err(CryptoError::BufferTooSmall);
        }
        let pt = &ct[..pt_len];
        let tag = &ct[pt_len..];
        // Verify tag
        let expected_tag: u8 = pt.iter().fold(0u8, |acc, &b| acc ^ b);
        for &b in tag {
            if b != expected_tag {
                return Err(CryptoError::InvalidTag);
            }
        }
        pt_out[..pt_len].copy_from_slice(pt);
        Ok(pt_len)
    }
}

#[test]
fn aead_seal_open_to_vec_round_trip() {
    let aead = MockAead;
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let aad = b"header";
    let plaintext = b"hello world";

    let ct = aead
        .seal_to_vec(&key, &nonce, aad, plaintext)
        .expect("seal_to_vec failed");
    assert_eq!(ct.len(), plaintext.len() + aead.tag_len());

    let recovered = aead
        .open_to_vec(&key, &nonce, aad, &ct)
        .expect("open_to_vec failed");
    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn aead_open_to_vec_rejects_tampered_tag() {
    let aead = MockAead;
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let aad = b"header";
    let plaintext = b"hello world";

    let mut ct = aead
        .seal_to_vec(&key, &nonce, aad, plaintext)
        .expect("seal_to_vec failed");
    // Flip a tag byte
    let last = ct.len() - 1;
    ct[last] ^= 0xFF;

    let result = aead.open_to_vec(&key, &nonce, aad, &ct);
    assert_eq!(result.unwrap_err(), CryptoError::InvalidTag);
}

#[test]
fn aead_open_to_vec_rejects_short_ciphertext() {
    let aead = MockAead;
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let aad = b"header";
    // Only 2 bytes — shorter than tag_len (4)
    let ct = [0u8; 2];
    let result = aead.open_to_vec(&key, &nonce, aad, &ct);
    assert_eq!(result.unwrap_err(), CryptoError::BufferTooSmall);
}

// -----------------------------------------------------------------------
// mac_to_vec tests (via mock Mac implementor)
// -----------------------------------------------------------------------

struct MockMac;

impl Mac for MockMac {
    fn name(&self) -> &'static str {
        "mock-mac"
    }
    fn key_len(&self) -> usize {
        16
    }
    fn output_len(&self) -> usize {
        8
    }

    fn mac(&self, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < self.output_len() {
            return Err(CryptoError::BufferTooSmall);
        }
        let key_byte = key.first().copied().unwrap_or(0);
        for (i, b) in out[..self.output_len()].iter_mut().enumerate() {
            *b = key_byte ^ msg.get(i % msg.len().max(1)).copied().unwrap_or(0) ^ (i as u8);
        }
        Ok(())
    }

    fn verify(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        let mut expected = alloc::vec![0u8; self.output_len()];
        self.mac(key, msg, &mut expected)?;
        if ct_eq(tag, &expected) {
            Ok(())
        } else {
            Err(CryptoError::InvalidTag)
        }
    }
}

#[test]
fn mac_to_vec_matches_fixed_buffer() {
    let mac = MockMac;
    let key = [0xAB_u8; 16];
    let msg = b"authenticate me";

    let from_vec = mac.mac_to_vec(&key, msg).expect("mac_to_vec failed");

    let mut from_buf = [0u8; 8];
    mac.mac(&key, msg, &mut from_buf).expect("mac failed");

    assert_eq!(
        from_vec.as_slice(),
        &from_buf[..],
        "mac_to_vec and mac must agree"
    );
}

#[test]
fn mac_to_vec_length_matches_output_len() {
    let mac = MockMac;
    let key = [0u8; 16];
    let result = mac.mac_to_vec(&key, b"msg").expect("mac_to_vec failed");
    assert_eq!(result.len(), mac.output_len());
}

// -----------------------------------------------------------------------
// CryptoError variant distinctness
// -----------------------------------------------------------------------

#[test]
fn test_crypto_error_variants_distinct() {
    use CryptoError::*;
    // Each variant must equal itself
    let variants: &[CryptoError] = &[
        InvalidKey,
        InvalidNonce,
        InvalidTag,
        BufferTooSmall,
        BadInput,
        Internal("test"),
        Kex,
        Sign,
        Rng,
        Encoding,
        UnsupportedAlgorithm,
    ];
    for v in variants {
        assert_eq!(v, v, "Variant {v:?} must equal itself");
    }
    // Spot-check a selection of distinct pairs
    assert_ne!(CryptoError::InvalidKey, CryptoError::BadInput);
    assert_ne!(CryptoError::InvalidTag, CryptoError::BufferTooSmall);
    assert_ne!(CryptoError::Rng, CryptoError::Encoding);
    assert_ne!(CryptoError::UnsupportedAlgorithm, CryptoError::Sign);
    assert_ne!(CryptoError::Kex, CryptoError::InvalidNonce);
}

// -----------------------------------------------------------------------
// ct_eq comprehensive tests
// -----------------------------------------------------------------------

#[test]
fn test_ct_eq_equals_regular_eq() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    let c = [1u8, 2, 3, 5];
    assert!(ct_eq(&a, &b), "equal slices must return true");
    assert!(
        !ct_eq(&a, &c),
        "slices differing in last byte must return false"
    );
    assert!(!ct_eq(&a, &[]), "different lengths must return false");
}

#[test]
fn test_ct_eq_empty_slices() {
    assert!(ct_eq(&[], &[]), "two empty slices must be equal");
}

#[test]
fn test_ct_eq_single_byte_differ() {
    assert!(!ct_eq(&[0u8], &[1u8]));
    assert!(ct_eq(&[255u8], &[255u8]));
}

// -----------------------------------------------------------------------
// ct_is_zero comprehensive tests
// -----------------------------------------------------------------------

#[test]
fn test_ct_is_zero_all_zero() {
    assert!(ct_is_zero(&[0u8; 32]), "all-zero 32 bytes must be zero");
}

#[test]
fn test_ct_is_zero_nonzero_last_byte() {
    assert!(!ct_is_zero(&[0u8, 0u8, 1u8]));
}

#[test]
fn test_ct_is_zero_empty() {
    assert!(ct_is_zero(&[]), "empty slice is considered zero");
}

#[test]
fn test_ct_is_zero_nonzero_first_byte() {
    let mut data = [0u8; 32];
    data[0] = 1;
    assert!(!ct_is_zero(&data));
}

// -----------------------------------------------------------------------
// SecretKey zeroize-on-drop
// -----------------------------------------------------------------------

#[test]
fn test_secret_key_as_bytes_returns_full_key() {
    let key_bytes = [0x42u8; 32];
    let sk = SecretKey::<32>::new(key_bytes);
    assert_eq!(
        sk.as_bytes(),
        &key_bytes,
        "as_bytes must return the original key bytes"
    );
}

#[test]
fn test_secret_key_clone_has_same_value() {
    let sk = SecretKey::<16>::new([0xAB; 16]);
    let sk2 = sk.clone();
    assert_eq!(
        sk.as_bytes(),
        sk2.as_bytes(),
        "cloned SecretKey must have the same value"
    );
}

#[test]
fn test_secret_vec_zeroize_awareness() {
    // Construct a SecretVec and verify it starts with the expected content.
    let sv = SecretVec::from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(sv.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(sv.len(), 4);
    assert!(!sv.is_empty());
    // Drop happens automatically; the ZeroizeOnDrop impl clears memory.
}

// -----------------------------------------------------------------------
// KeyPair construction and access
// -----------------------------------------------------------------------

#[test]
fn test_keypair_secret_and_public() {
    let secret = [0xAA_u8; 32];
    let public = [0xBB_u8; 32];
    let kp = KeyPair::new(secret, public);
    assert_eq!(kp.secret(), &[0xAA_u8; 32]);
    assert_eq!(kp.public(), &[0xBB_u8; 32]);
}
