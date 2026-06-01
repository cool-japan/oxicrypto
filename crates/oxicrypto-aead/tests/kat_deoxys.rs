//! Known-answer tests for Deoxys-II-128-128 (SCT-2 mode).
//!
//! The AEAD vectors are the official Deoxys-II-128 test vectors (as shipped by
//! the Deoxys reference / RustCrypto `deoxys` crate, derived from the CAESAR
//! submission). The published 16-byte nonce is consumed as a 120-bit nonce
//! (the leading 15 bytes) by the mode, exactly as the reference does; our
//! `Deoxys2_128` API accepts the full 16-byte nonce and uses `nonce[..15]`
//! internally, so the official 16-byte nonce drives `seal`/`open` directly.
//!
//! Each vector asserts the exact `ciphertext ‖ tag` produced by `seal` and the
//! exact plaintext recovered by `open`. Additional tests cover a standalone
//! Deoxys-BC-256 single-block value, nonce-misuse resistance, and tamper
//! detection.

use oxicrypto_aead::Deoxys2_128;
use oxicrypto_core::{Aead, CryptoError};

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

const KEY: &str = "101112131415161718191a1b1c1d1e1f";
const NONCE: &str = "202122232425262728292a2b2c2d2e2f";

/// Drive one official Deoxys-II-128 vector: `seal` must produce exactly
/// `expected_ct ‖ expected_tag`, and `open` must recover `pt`.
fn check_vector(aad_hex: &str, pt_hex: &str, expected_ct_hex: &str, expected_tag_hex: &str) {
    let key = hex_decode(KEY);
    let nonce = hex_decode(NONCE);
    let aad = hex_decode(aad_hex);
    let pt = hex_decode(pt_hex);
    let aead = Deoxys2_128;

    let mut ct = vec![0u8; pt.len() + aead.tag_len()];
    let written = aead.seal(&key, &nonce, &aad, &pt, &mut ct).expect("seal");
    assert_eq!(written, pt.len() + 16, "output length");
    assert_eq!(
        to_hex(&ct[..pt.len()]),
        expected_ct_hex.replace(' ', ""),
        "ciphertext mismatch"
    );
    assert_eq!(
        to_hex(&ct[pt.len()..written]),
        expected_tag_hex.replace(' ', ""),
        "tag mismatch"
    );

    let mut dec = vec![0u8; pt.len()];
    let n = aead
        .open(&key, &nonce, &aad, &ct[..written], &mut dec)
        .expect("open");
    assert_eq!(n, pt.len());
    assert_eq!(to_hex(&dec), to_hex(&pt), "round-trip plaintext mismatch");
}

// ── Official Deoxys-II-128 test vectors ──────────────────────────────────────

/// Vector 1: empty AD, empty message — pure tag generation.
#[test]
fn deoxys_ii_128_v1_empty() {
    check_vector("", "", "", "97d951f2fd129001483e831f2a6821e9");
}

/// Vector 2: 32-byte AD (two blocks), empty message.
#[test]
fn deoxys_ii_128_v2_aad_two_blocks() {
    check_vector(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "",
        "",
        "3c197ca5317af5a2b95b178a60553132",
    );
}

/// Vector 3: 33-byte AD (two blocks + partial), empty message.
#[test]
fn deoxys_ii_128_v3_aad_partial() {
    check_vector(
        "a754f3387be992ffee5bee80e18b151900c6d69ec59786fb12d2eadb0750f82cf5",
        "",
        "",
        "0a989ed78fa16776cd6c691ea734d874",
    );
}

/// Vector 4: empty AD, 32-byte message (two blocks).
#[test]
fn deoxys_ii_128_v4_msg_two_blocks() {
    check_vector(
        "",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "fa22f8eb84ee6d2388bdb16150232e856cd5fa3508bc589dad16d284208048c9",
        "a381b06ef16db99df089e738c3b4064a",
    );
}

/// Vector 5: empty AD, 33-byte message (two blocks + partial).
#[test]
fn deoxys_ii_128_v5_msg_partial() {
    check_vector(
        "",
        "06ac1756eccece62bd743fa80c299f7baa3872b556130f52265919494bdc136db3",
        "82bf241958b324ed053555d23315d3cc20935527fc970ff34a9f521a95e302136d",
        "0eadc8612d5208c491e93005195e9769",
    );
}

/// Vector 6: 16-byte AD (one block), 32-byte message.
#[test]
fn deoxys_ii_128_v6_aad_and_msg() {
    check_vector(
        "000102030405060708090a0b0c0d0e0f",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "9cdb554dfc03bff4feeb94df7736038361a76532b6b5a9c0bdb64a74dee983ff",
        "bc1a7b5b8e961e65ceff6877ef9e4a98",
    );
}

/// Vector 7: 17-byte AD (one block + partial), 33-byte message (partial).
#[test]
fn deoxys_ii_128_v7_partial_aad_and_msg() {
    check_vector(
        "000102030405060708090a0b0c0d0e0f10",
        "039ca0907aa315a0d5ba020c84378840023d4ad3ba639787d3f6f46cb446bd63dc",
        "801f1b81878faca562c8c6c0859b166c2669fbc54b1784be637827b4905729bdf9",
        "fe4e9bcd26b96647350eda1e550cc994",
    );
}

/// Vector 8: large multi-block AD (513 bytes) and message (512 bytes).
#[test]
fn deoxys_ii_128_v8_large() {
    let aad = concat!(
        "5b187979e145d7b5beebbc0e689e759a027b5588059419b06b1afe4224f8f56e",
        "cccb2bfe2cef9ecf103eb382172320a17c19dce14a3e38030d3443697845b992",
        "ff1e871c02e788d7b40264f52ef0733791dc82dacdfa987685b33423bed0c05e",
        "0a65bce48ce1006d16628ea21b4390e75be72e043f299d6290289f90007474bf",
        "4e9ffb6c774d762afec8f3a01b2db545611772c32386fe6c7332125f0750c498",
        "7988d1e0e727c3c295bc743a34d3196d5e2d14f11bf2c884265ba901e77144a4",
        "b5a77864ad082e945727786f376bfcae99048ee7a994a2ea87584cd2e7e83ffd",
        "0310cf9cdb2cff5cf8c9cc09c94becb3f37fb9b071a76ee7ae115a49f0d95b1a",
        "9ec97e5b62bcae2c3cf47a3d2cb1b3d3dcd1729c33266ad7b0899654949a6f09",
        "086b74297cb48227e566e1f401109495ea05d636a5025104cd04c2a3c59f396b",
        "858f7f025825baf667b29b4f7f692f3a6c0c8956575a8dd183d1d03bd372c214",
        "e005d6e1090d89f2d950b8ac856465943568bc320602f52bf67d30f0d8ec7a95",
        "50dcdef99a43404a6d32d8f6b537b3eed568e32ab7ee63e16be63009702995d4",
        "d9300114638ba4c874f02039f3f67e2df64946030edef1930f30d4e6b9ca9588",
        "7539d1af2036c8f5cf129c54d5734224e09b3daab5fb0e74c848af70a49c1499",
        "a5e56bc5eea90395df5bfd3e84a1c0a5be02dd3f2e2353e5522aeadaafdbf444",
        "44",
    );
    let pt = concat!(
        "95330042c3d48419798f9285fbd8d24968d7cee311f637463f8c0a1778f79d75",
        "8a84e35b7d4a9fde2ed56fa796ad5a0f7004490ed32664ad69069678f53dfd7e",
        "e92e00a8ee34776b4d758536dc725ec4d48e2c11d0c5a16e4a2ce6c0e91604ad",
        "b33a11127f50a46ea3cf5353d88a7a244c0f4337f449e68bf7c31feab02346d3",
        "c84c2335b8a06dc7df89dab05b6496fe428133c210c3bac68e18f026daa56662",
        "a41c36f9b55787fc1c5382d70b86e33be8555fd924606d2572c30a6ab6da71ec",
        "cd4744ceb4e729519eef42ef4260db0e015832bfb0e742201fac36c711969a61",
        "243b08a77c372e44f76646fd1e9c9c06570447aa30527339baceb1d002e24e6e",
        "e3114f5a5daf0062bd372f824a60eebd74afc4fecffe74541933411b575295e2",
        "7891abc71fc0e9597f65fc51be21962eea0aec96214b40a1a8ef32329df02a8b",
        "0ef038c48a1d5b2529ed01a820a6f262488de7791b07c5f941126be7893f7dad",
        "fb9639892264bc01af40402aa87a44df1754ce4e17226c41a8e3f05e4883d6ef",
        "4511e96378067f455f3a7275215622bfc71bb4db398b03b08e4bf6c54b2b6396",
        "c5b501fa26782fc36ad22044f5eb6a8f83efc8850d70ae4525d4e798f2aa1894",
        "621803394415f34cd4d002a2b3d393efa7d57f687b753830ff04798c240f05f5",
        "81ce706f7d151417f09f17174cb87eff0e042c1860342b4ace069e1691e092e3",
    );
    let expected_ct = concat!(
        "b8eddddb8d0042bb42fdf675bae285e504b90e4d73e02f99f790b2ffe7815dba",
        "40fe4c7bc886ce44505f6ac53d3bba5d3c73efd98daf4b7a5af250a5d100ff55",
        "58c211cb03a28d9519502d7d0fc85a6d73e618feb6b503af12cb0330bb9c5743",
        "b19996174a84dbf5bac38d10d207067e4ab211a62ad0f85dd8245dfb07744301",
        "7b7847996fe7ed547b9e02051f1cbe39128e21486b4f73399d0a50d9a1111bed",
        "11ebb0547454d0a922633c83f0bba784571f63f55dc33f92e09862471945312d",
        "99e40b4ed739556f102afd43055497739a4b22d107e867cc652a5d96974ff785",
        "976c82bc1ff89731c780e84a257bb885cd23e00a7bdc7a68e0a1668516fb9727",
        "21a777429c76cfd4adb45afa554d44a8932d133af8c9254fd3fef2bd0bb65801",
        "f2ffbf752f14eaa783e53c2342f021863598e88b20232a0c44e963dd8943e9a5",
        "4213ffbb174b90e38b55aa9b223e9596acb1517ff21b7458b7694488047797c5",
        "21883c00762e7227f1e8a5e3f11a43962bdccde8dc4009aef7628a96efa8793d",
        "6080982f9b00a7b97d93fd5928702e78427f34eb434e2286de00216b405c3610",
        "5dc2e8dae68c3342a23274b32a6d2d8ac85239a8fa2947126f505a517fb18847",
        "104b21b0326b7fd67efb54f5d0b12b311ef998ebaf14939b7cdb44b35435eedf",
        "1ba5b07eea99533f1857b8cc1538290a8dbd44ca696c6bc2f1105451032a650c",
    );
    let expected_tag = "e68a5de27beaeb6472611dfa9783602a";
    check_vector(aad, pt, expected_ct, expected_tag);
}

// ── Standalone Deoxys-BC-256 single-block KAT ────────────────────────────────

/// The tag-generation block of vector 1 is a standalone Deoxys-BC-256
/// encryption `E_K(0x10 ‖ nonce[..15], 0^128) = 97d951f2…`. We re-derive it
/// through the public AEAD (empty AD/message ⇒ the only BC call is the tag
/// generation), which transitively pins the Deoxys-BC-256 forward path.
#[test]
fn deoxys_bc256_via_empty_aead() {
    let key = hex_decode(KEY);
    let nonce = hex_decode(NONCE);
    let aead = Deoxys2_128;
    let mut ct = vec![0u8; 16];
    aead.seal(&key, &nonce, b"", b"", &mut ct).expect("seal");
    assert_eq!(
        to_hex(&ct),
        "97d951f2fd129001483e831f2a6821e9",
        "Deoxys-BC-256 tag-gen block KAT mismatch"
    );
}

// ── Nonce-misuse resistance ──────────────────────────────────────────────────

/// Reusing the same (key, nonce) with two *different* messages must yield two
/// valid, distinct, and individually-recoverable ciphertexts. Unlike AES-GCM /
/// ChaCha20-Poly1305, no catastrophic keystream reuse occurs: the tag (and
/// hence the keystream) depends on the full message.
#[test]
fn deoxys_ii_128_nonce_misuse_resistant() {
    let key = hex_decode(KEY);
    let nonce = hex_decode(NONCE);
    let aead = Deoxys2_128;

    let m1 = b"message number one ........ AAAA";
    let m2 = b"message number two ........ BBBB";

    let mut c1 = vec![0u8; m1.len() + 16];
    let mut c2 = vec![0u8; m2.len() + 16];
    aead.seal(&key, &nonce, b"", m1, &mut c1).expect("seal1");
    aead.seal(&key, &nonce, b"", m2, &mut c2).expect("seal2");

    // Distinct ciphertexts (and distinct tags) despite the shared nonce.
    assert_ne!(c1, c2, "same nonce + different messages must differ");
    assert_ne!(
        &c1[m1.len()..],
        &c2[m2.len()..],
        "tags must differ for different messages under the same nonce"
    );

    // Each is independently recoverable.
    let mut d1 = vec![0u8; m1.len()];
    let mut d2 = vec![0u8; m2.len()];
    aead.open(&key, &nonce, b"", &c1, &mut d1).expect("open1");
    aead.open(&key, &nonce, b"", &c2, &mut d2).expect("open2");
    assert_eq!(&d1, m1.as_ref());
    assert_eq!(&d2, m2.as_ref());

    // SIV property: identical (nonce, AD, message) ⇒ identical ciphertext.
    let mut c1b = vec![0u8; m1.len() + 16];
    aead.seal(&key, &nonce, b"", m1, &mut c1b).expect("seal1b");
    assert_eq!(c1, c1b, "deterministic for identical inputs");
}

// ── Tamper detection ─────────────────────────────────────────────────────────

/// Flipping a ciphertext, AAD, or tag byte must yield `InvalidTag`.
#[test]
fn deoxys_ii_128_tamper_rejected() {
    let key = hex_decode(KEY);
    let nonce = hex_decode(NONCE);
    let aead = Deoxys2_128;
    let aad = b"authenticated";
    let pt = b"0123456789abcdef0123456789abcdef!"; // 33 bytes (partial block)

    let mut ct = vec![0u8; pt.len() + 16];
    let written = aead.seal(&key, &nonce, aad, pt, &mut ct).expect("seal");

    // (a) Flip a ciphertext byte.
    let mut bad = ct[..written].to_vec();
    bad[0] ^= 0xff;
    let mut dec = vec![0u8; pt.len()];
    assert_eq!(
        aead.open(&key, &nonce, aad, &bad, &mut dec),
        Err(CryptoError::InvalidTag),
        "flipped ciphertext must be rejected"
    );

    // (b) Flip a tag byte.
    let mut bad = ct[..written].to_vec();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert_eq!(
        aead.open(&key, &nonce, aad, &bad, &mut dec),
        Err(CryptoError::InvalidTag),
        "flipped tag must be rejected"
    );

    // (c) Flip an AAD byte.
    assert_eq!(
        aead.open(&key, &nonce, b"Authenticated", &ct[..written], &mut dec),
        Err(CryptoError::InvalidTag),
        "modified AAD must be rejected"
    );
}
