//! RFC 9180 Appendix-A known-answer tests.
//!
//! Vectors are pinned byte-exact from the canonical CFRG `test-vectors.json`
//! (<https://github.com/cfrg/draft-irtf-cfrg-hpke>), records
//! `mode=0, kdf_id=1, aead_id=1` for `kem_id=32` (A.1.1, X25519) and
//! `kem_id=16` (A.3.1, P-256). The values were cross-checked against the
//! published RFC 9180 Appendix A text.

use super::hex_decode;
use crate::hpke::{AeadId, HpkeSuite, KdfId, KemId};

// ── A.1.1 — mode base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM ─────

#[test]
fn rfc9180_a_1_1_full_chain() {
    let suite = HpkeSuite::new(
        KemId::DhkemX25519HkdfSha256,
        KdfId::HkdfSha256,
        AeadId::Aes128Gcm,
    );

    let info = hex_decode("4f6465206f6e2061204772656369616e2055726e");
    let ikm_e = hex_decode("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
    let sk_em = hex_decode("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
    let pk_em = hex_decode("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    let ikm_r = hex_decode("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
    let sk_rm = hex_decode("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    let pk_rm = hex_decode("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    let enc_expected =
        hex_decode("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");

    // DeriveKeyPair both ends.
    let (sk_e, pk_e) = suite.derive_key_pair(&ikm_e).expect("derive eph");
    assert_eq!(sk_e.as_bytes(), sk_em.as_slice(), "skEm");
    assert_eq!(pk_e, pk_em, "pkEm");
    let (sk_r, pk_r) = suite.derive_key_pair(&ikm_r).expect("derive recip");
    assert_eq!(sk_r.as_bytes(), sk_rm.as_slice(), "skRm");
    assert_eq!(pk_r, pk_rm, "pkRm");

    // Sender setup (derandomized) — enc + context derivations.
    let (enc, mut sctx) = suite
        .setup_base_s_deterministic(&pk_rm, &info, &ikm_e)
        .expect("setup_base_s");
    assert_eq!(enc, enc_expected, "enc");

    // Seal seq 0 then seq 1 — both ciphertexts must match the vector exactly.
    let pt = hex_decode("4265617574792069732074727574682c20747275746820626561757479");
    let aad0 = hex_decode("436f756e742d30");
    let ct0_expected = hex_decode(
        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
    );
    let ct0 = sctx.seal(&aad0, &pt).expect("seal 0");
    assert_eq!(ct0, ct0_expected, "ct seq0");

    let aad1 = hex_decode("436f756e742d31");
    let ct1_expected = hex_decode(
        "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
    );
    let ct1 = sctx.seal(&aad1, &pt).expect("seal 1");
    assert_eq!(ct1, ct1_expected, "ct seq1");

    // Exporter values.
    assert_eq!(
        sctx.export(b"", 32).expect("export empty"),
        hex_decode("3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee"),
    );
    assert_eq!(
        sctx.export(&hex_decode("00"), 32).expect("export 00"),
        hex_decode("2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5"),
    );
    assert_eq!(
        sctx.export(&hex_decode("54657374436f6e74657874"), 32)
            .expect("export TestContext"),
        hex_decode("e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931"),
    );

    // Recipient setup + open both records (fresh receiver context, seq 0 then 1).
    let mut rctx = suite
        .setup_base_r(&enc, &sk_rm, &info)
        .expect("setup_base_r");
    assert_eq!(rctx.open(&aad0, &ct0).expect("open 0"), pt, "decrypt seq0");
    assert_eq!(rctx.open(&aad1, &ct1).expect("open 1"), pt, "decrypt seq1");

    // Receiver-side export must agree with the sender's.
    assert_eq!(
        rctx.export(&hex_decode("54657374436f6e74657874"), 32)
            .expect("recv export"),
        hex_decode("e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931"),
    );
}

// ── A.3.1 — mode base, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM ──────

#[test]
fn rfc9180_a_3_1_full_chain() {
    let suite = HpkeSuite::new(
        KemId::DhkemP256HkdfSha256,
        KdfId::HkdfSha256,
        AeadId::Aes128Gcm,
    );

    let info = hex_decode("4f6465206f6e2061204772656369616e2055726e");
    let ikm_e = hex_decode("4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e");
    let sk_em = hex_decode("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb");
    let pk_em = hex_decode("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
    let ikm_r = hex_decode("668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550");
    let sk_rm = hex_decode("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
    let pk_rm = hex_decode("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0");
    let enc_expected = hex_decode("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");

    // DeriveKeyPair both ends (exercises P-256 rejection sampling + uncompressed enc).
    let (sk_e, pk_e) = suite.derive_key_pair(&ikm_e).expect("derive eph");
    assert_eq!(sk_e.as_bytes(), sk_em.as_slice(), "skEm");
    assert_eq!(pk_e, pk_em, "pkEm");
    assert_eq!(pk_e.len(), 65, "pkEm uncompressed length");
    let (sk_r, pk_r) = suite.derive_key_pair(&ikm_r).expect("derive recip");
    assert_eq!(sk_r.as_bytes(), sk_rm.as_slice(), "skRm");
    assert_eq!(pk_r, pk_rm, "pkRm");

    // Sender setup (derandomized).
    let (enc, mut sctx) = suite
        .setup_base_s_deterministic(&pk_rm, &info, &ikm_e)
        .expect("setup_base_s");
    assert_eq!(enc, enc_expected, "enc");
    assert_eq!(enc.len(), 65, "enc uncompressed length");

    // Seal seq 0 then seq 1.
    let pt = hex_decode("4265617574792069732074727574682c20747275746820626561757479");
    let aad0 = hex_decode("436f756e742d30");
    let ct0_expected = hex_decode(
        "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434",
    );
    let ct0 = sctx.seal(&aad0, &pt).expect("seal 0");
    assert_eq!(ct0, ct0_expected, "ct seq0");

    let aad1 = hex_decode("436f756e742d31");
    let ct1_expected = hex_decode(
        "fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82",
    );
    let ct1 = sctx.seal(&aad1, &pt).expect("seal 1");
    assert_eq!(ct1, ct1_expected, "ct seq1");

    // Exporter values.
    assert_eq!(
        sctx.export(b"", 32).expect("export empty"),
        hex_decode("5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d"),
    );
    assert_eq!(
        sctx.export(&hex_decode("00"), 32).expect("export 00"),
        hex_decode("6cff87658931bda83dc857e6353efe4987a201b849658d9b047aab4cf216e796"),
    );
    assert_eq!(
        sctx.export(&hex_decode("54657374436f6e74657874"), 32)
            .expect("export TestContext"),
        hex_decode("d8f1ea7942adbba7412c6d431c62d01371ea476b823eb697e1f6e6cae1dab85a"),
    );

    // Recipient setup + open both records.
    let mut rctx = suite
        .setup_base_r(&enc, &sk_rm, &info)
        .expect("setup_base_r");
    assert_eq!(rctx.open(&aad0, &ct0).expect("open 0"), pt, "decrypt seq0");
    assert_eq!(rctx.open(&aad1, &ct1).expect("open 1"), pt, "decrypt seq1");
}
