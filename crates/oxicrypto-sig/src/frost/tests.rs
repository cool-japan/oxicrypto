//! RFC 9591 FROST(Ed25519, SHA-512) test vectors (Appendix E.1) and
//! protocol-level tests.
//!
//! These tests reproduce the official RFC 9591 §E.1 vector byte-for-byte via
//! the derandomized seams ([`trusted_dealer_keygen_with_coefficients`] and
//! [`commit_with_randomness`]), asserting every intermediate value: the group
//! public key, the per-signer shares, the binding factors, the group commitment
//! `R`, the per-signer signature shares, and the final 64-byte signature. They
//! also exercise partial-share verification, signer-subset independence, tamper
//! negatives, and cross-verification with standard Ed25519.
//!
//! Tests may use `unwrap`/`expect` on known-good vector bytes (the project's
//! no-`unwrap` policy applies to production code only).

use curve25519_dalek::Scalar;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};

use super::keygen::{
    trusted_dealer_keygen, trusted_dealer_keygen_with_coefficients, KeyPackage, SecretShare,
};
use super::round1::{commit, commit_with_randomness};
use super::round2::{sign, verify_signature_share, SignatureShare};
use super::{
    aggregate, compute_binding_factors, compute_group_commitment, deserialize_scalar,
    serialize_element, serialize_scalar, sort_commitments, verify_signature, Identifier,
    SigningCommitments,
};

// ── RFC 9591 §E.1 vector bytes ──────────────────────────────────────────────

const GROUP_SECRET_KEY: &str = "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304";
const GROUP_PUBLIC_KEY: &str = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
const MESSAGE: &str = "74657374";
const COEFF_1: &str = "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204";

const P1_SHARE: &str = "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509";
const P2_SHARE: &str = "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d";
const P3_SHARE: &str = "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02";

const P1_HIDING_RANDOMNESS: &str =
    "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec";
const P1_BINDING_RANDOMNESS: &str =
    "69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501";
const P1_HIDING_NONCE: &str = "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407";
const P1_BINDING_NONCE: &str = "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301";
const P1_HIDING_COMMITMENT: &str =
    "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3";
const P1_BINDING_COMMITMENT: &str =
    "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932";
const P1_BINDING_FACTOR: &str = "f2cb9d7dd9beff688da6fcc83fa89046b3479417f47f55600b106760eb3b5603";

const P3_HIDING_RANDOMNESS: &str =
    "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f";
const P3_BINDING_RANDOMNESS: &str =
    "13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775";
const P3_HIDING_NONCE: &str = "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e";
const P3_BINDING_NONCE: &str = "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d";
const P3_HIDING_COMMITMENT: &str =
    "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91";
const P3_BINDING_COMMITMENT: &str =
    "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552";
const P3_BINDING_FACTOR: &str = "b087686bf35a13f3dc78e780a34b0fe8a77fef1b9938c563f5573d71d8d7890f";

const P1_SIG_SHARE: &str = "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603";
const P3_SIG_SHARE: &str = "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007";

const SIGNATURE: &str = "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe\
bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b";

// Full P1 binding_factor_input from the vector (used to validate the
// intermediate rho_input byte string of compute_binding_factors).
const P1_BINDING_FACTOR_INPUT: &str = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3f\
af66040d380fb9738673504df914fa965023fb75c25ded4bb260f417de6d32e5c442c\
6ba313791cc9a4948d6273e8d3511f93348ea7a708a9b862bc73ba2a79cfdfe07729a\
193751cbc973af46d8ac3440e518d4ce440a0e7d4ad5f62ca8940f32de6d8dc00fc12\
c660b817d587d82f856d277ce6473cae6d2f5763f7da2e8b4d799a3f3e725d4522ec7\
0100000000000000000000000000000000000000000000000000000000000000";

// ── Hex helpers (test-only) ─────────────────────────────────────────────────

fn unhex(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    assert!(bytes.len().is_multiple_of(2), "odd-length hex");
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16).expect("hex digit");
        let lo = (chunk[1] as char).to_digit(16).expect("hex digit");
        out.push((hi * 16 + lo) as u8);
    }
    out
}

fn unhex32(s: &str) -> [u8; 32] {
    let v = unhex(s);
    assert_eq!(v.len(), 32, "expected 32 bytes");
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn scalar_of(s: &str) -> Scalar {
    deserialize_scalar(&unhex(s)).expect("canonical scalar")
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Build the sorted commitment list for participants {1, 3} from the vector
/// commitment bytes.
fn vector_commitments() -> Vec<SigningCommitments> {
    let id1 = Identifier::new(1).expect("id1");
    let id3 = Identifier::new(3).expect("id3");
    let c1 = SigningCommitments::from_bytes(
        id1,
        &unhex(P1_HIDING_COMMITMENT),
        &unhex(P1_BINDING_COMMITMENT),
    )
    .expect("c1");
    let c3 = SigningCommitments::from_bytes(
        id3,
        &unhex(P3_HIDING_COMMITMENT),
        &unhex(P3_BINDING_COMMITMENT),
    )
    .expect("c3");
    sort_commitments(&[c1, c3]).expect("sorted")
}

// ── Vector reproduction ─────────────────────────────────────────────────────

#[test]
fn rfc9591_e1_keygen_matches_vector() {
    let secret = scalar_of(GROUP_SECRET_KEY);
    let coeff1 = scalar_of(COEFF_1);
    let (shares, public_key_package) =
        trusted_dealer_keygen_with_coefficients(secret, &[coeff1], 3, 2).expect("keygen");

    // Group public key PK = s·B.
    assert_eq!(
        hex_of(&public_key_package.group_public_key_bytes().expect("pk")),
        GROUP_PUBLIC_KEY,
        "group public key mismatch"
    );

    // Per-participant secret shares s_i = f(i).
    let expected = [P1_SHARE, P2_SHARE, P3_SHARE];
    assert_eq!(shares.len(), 3);
    for (i, share) in shares.iter().enumerate() {
        assert_eq!(
            hex_of(&share.to_bytes()),
            expected[i],
            "share {} mismatch",
            i + 1
        );
        // Identifier is i+1.
        assert_eq!(share.identifier().as_scalar(), Scalar::from((i as u64) + 1));
        // Public-key share PK_i = s_i·B is consistent with the package.
        let pk_i = public_key_package
            .public_share(share.identifier())
            .expect("pk_i");
        assert_eq!(pk_i, share.public_share());
    }
}

#[test]
fn rfc9591_e1_round1_nonces_and_commitments_match_vector() {
    // P1.
    let p1_nonces = commit_with_randomness(
        Identifier::new(1).expect("id1"),
        &scalar_of(P1_SHARE),
        &unhex32(P1_HIDING_RANDOMNESS),
        &unhex32(P1_BINDING_RANDOMNESS),
    );
    assert_eq!(
        hex_of(&serialize_scalar(&p1_nonces.hiding_nonce())),
        P1_HIDING_NONCE,
        "P1 hiding nonce"
    );
    assert_eq!(
        hex_of(&serialize_scalar(&p1_nonces.binding_nonce())),
        P1_BINDING_NONCE,
        "P1 binding nonce"
    );
    let p1_comm = p1_nonces.commitments();
    assert_eq!(
        hex_of(&p1_comm.hiding_bytes().expect("D1")),
        P1_HIDING_COMMITMENT,
        "P1 hiding commitment"
    );
    assert_eq!(
        hex_of(&p1_comm.binding_bytes().expect("E1")),
        P1_BINDING_COMMITMENT,
        "P1 binding commitment"
    );

    // P3.
    let p3_nonces = commit_with_randomness(
        Identifier::new(3).expect("id3"),
        &scalar_of(P3_SHARE),
        &unhex32(P3_HIDING_RANDOMNESS),
        &unhex32(P3_BINDING_RANDOMNESS),
    );
    assert_eq!(
        hex_of(&serialize_scalar(&p3_nonces.hiding_nonce())),
        P3_HIDING_NONCE,
        "P3 hiding nonce"
    );
    assert_eq!(
        hex_of(&serialize_scalar(&p3_nonces.binding_nonce())),
        P3_BINDING_NONCE,
        "P3 binding nonce"
    );
    let p3_comm = p3_nonces.commitments();
    assert_eq!(
        hex_of(&p3_comm.hiding_bytes().expect("D3")),
        P3_HIDING_COMMITMENT,
        "P3 hiding commitment"
    );
    assert_eq!(
        hex_of(&p3_comm.binding_bytes().expect("E3")),
        P3_BINDING_COMMITMENT,
        "P3 binding commitment"
    );
}

#[test]
fn rfc9591_e1_binding_factors_match_vector() {
    let secret = scalar_of(GROUP_SECRET_KEY);
    let group_public_key = super::scalar_base_mult(&secret);
    let commitments = vector_commitments();

    // Validate the intermediate rho_input byte string for P1 against the
    // vector's binding_factor_input.
    let group_pk_enc = serialize_element(&group_public_key).expect("pk enc");
    let msg_hash = super::h4(&unhex(MESSAGE));
    let encoded_commitment_hash =
        super::h5(&super::encode_group_commitment_list(&commitments).expect("encode"));
    let id1 = Identifier::new(1).expect("id1");
    let mut rho_input = Vec::new();
    rho_input.extend_from_slice(&group_pk_enc);
    rho_input.extend_from_slice(&msg_hash);
    rho_input.extend_from_slice(&encoded_commitment_hash);
    rho_input.extend_from_slice(&id1.to_bytes());
    assert_eq!(
        hex_of(&rho_input),
        P1_BINDING_FACTOR_INPUT,
        "P1 binding_factor_input mismatch"
    );

    // Validate the binding factors themselves.
    let bf_list =
        compute_binding_factors(&group_public_key, &commitments, &unhex(MESSAGE)).expect("bf");
    let bf1 = super::binding_factor_for_participant(&bf_list, id1).expect("bf1");
    let id3 = Identifier::new(3).expect("id3");
    let bf3 = super::binding_factor_for_participant(&bf_list, id3).expect("bf3");
    assert_eq!(
        hex_of(&serialize_scalar(&bf1)),
        P1_BINDING_FACTOR,
        "P1 binding factor"
    );
    assert_eq!(
        hex_of(&serialize_scalar(&bf3)),
        P3_BINDING_FACTOR,
        "P3 binding factor"
    );
}

#[test]
fn rfc9591_e1_full_signing_matches_vector() {
    let secret = scalar_of(GROUP_SECRET_KEY);
    let coeff1 = scalar_of(COEFF_1);
    let (shares, pkp) =
        trusted_dealer_keygen_with_coefficients(secret, &[coeff1], 3, 2).expect("keygen");
    let group_public_key = pkp.group_public_key();

    // Round one (derandomized) for P1 and P3.
    let p1_nonces = commit_with_randomness(
        Identifier::new(1).expect("id1"),
        &shares[0].value(),
        &unhex32(P1_HIDING_RANDOMNESS),
        &unhex32(P1_BINDING_RANDOMNESS),
    );
    let p3_nonces = commit_with_randomness(
        Identifier::new(3).expect("id3"),
        &shares[2].value(),
        &unhex32(P3_HIDING_RANDOMNESS),
        &unhex32(P3_BINDING_RANDOMNESS),
    );
    let commitment_list =
        sort_commitments(&[p1_nonces.commitments(), p3_nonces.commitments()]).expect("sorted");

    // Verify group commitment R encodes to the R half of the signature.
    let bf_list =
        compute_binding_factors(&group_public_key, &commitment_list, &unhex(MESSAGE)).expect("bf");
    let group_commitment =
        compute_group_commitment(&commitment_list, &bf_list).expect("group commitment");
    assert_eq!(
        hex_of(&serialize_element(&group_commitment).expect("R enc")),
        &SIGNATURE[..64],
        "group commitment R mismatch"
    );

    // Round two: signature shares.
    let kp1 = KeyPackage::new(
        SecretShare::new(shares[0].identifier(), shares[0].value()),
        group_public_key,
    );
    let kp3 = KeyPackage::new(
        SecretShare::new(shares[2].identifier(), shares[2].value()),
        group_public_key,
    );
    let z1 = sign(&kp1, &p1_nonces, &unhex(MESSAGE), &commitment_list).expect("z1");
    let z3 = sign(&kp3, &p3_nonces, &unhex(MESSAGE), &commitment_list).expect("z3");
    assert_eq!(hex_of(&z1.to_bytes()), P1_SIG_SHARE, "P1 sig share");
    assert_eq!(hex_of(&z3.to_bytes()), P3_SIG_SHARE, "P3 sig share");

    // Partial-share verification of both shares.
    verify_signature_share(
        &pkp.public_share(kp1.identifier()).expect("pk1"),
        &p1_nonces.commitments(),
        &z1,
        &commitment_list,
        &group_public_key,
        &unhex(MESSAGE),
    )
    .expect("verify share 1");
    verify_signature_share(
        &pkp.public_share(kp3.identifier()).expect("pk3"),
        &p3_nonces.commitments(),
        &z3,
        &commitment_list,
        &group_public_key,
        &unhex(MESSAGE),
    )
    .expect("verify share 3");

    // Aggregate and assert the final 64-byte signature byte-for-byte.
    let sig = aggregate(
        &commitment_list,
        &unhex(MESSAGE),
        &group_public_key,
        &[z1, z3],
    )
    .expect("aggregate");
    let sig_bytes = sig.to_bytes().expect("sig bytes");
    assert_eq!(hex_of(&sig_bytes), SIGNATURE, "final signature mismatch");

    // FROST + standard-Ed25519 verification of the aggregate.
    verify_signature(&sig, &unhex(MESSAGE), &group_public_key).expect("verify aggregate");
}

#[test]
fn rfc9591_e1_aggregate_cross_verifies_with_ed25519_dalek() {
    let sig_bytes = unhex(SIGNATURE);
    let pk_bytes = unhex32(GROUP_PUBLIC_KEY);
    let vk = Ed25519VerifyingKey::from_bytes(&pk_bytes).expect("vk");
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Ed25519Signature::from_bytes(&sig_arr);
    // The canonical RFC vector must verify under independent strict Ed25519.
    vk.verify_strict(&unhex(MESSAGE), &sig)
        .expect("standard ed25519 verify of RFC vector");
}

// ── Protocol-level tests (randomized keygen path + negatives) ───────────────

/// Helper: full t-of-2 signing run over a chosen signer subset using the
/// production randomized keygen, returning the aggregate-signature bytes.
fn run_signing(subset: [u16; 2]) -> ([u8; 64], [u8; 32]) {
    use oxicrypto_rand::OxiRng;
    let mut rng = OxiRng::new().expect("rng");

    let (shares, pkp) = trusted_dealer_keygen(&mut rng, 3, 2).expect("keygen");
    let group_public_key = pkp.group_public_key();

    let msg = b"oxicrypto frost protocol test";

    // Round one for the two chosen signers.
    let mut nonces = Vec::new();
    let mut key_packages = Vec::new();
    for id in subset {
        let identifier = Identifier::new(id).expect("id");
        let share = shares
            .iter()
            .find(|s| s.identifier() == identifier)
            .expect("share");
        let n = commit(&mut rng, identifier, &share.value()).expect("commit");
        key_packages.push(KeyPackage::new(
            SecretShare::new(share.identifier(), share.value()),
            group_public_key,
        ));
        nonces.push(n);
    }

    let commitment_list =
        sort_commitments(&[nonces[0].commitments(), nonces[1].commitments()]).expect("sorted");

    // Round two.
    let mut sig_shares = Vec::new();
    for (kp, n) in key_packages.iter().zip(nonces.iter()) {
        let z = sign(kp, n, msg, &commitment_list).expect("sign");
        // Partial-share verify.
        verify_signature_share(
            &pkp.public_share(kp.identifier()).expect("pk_i"),
            &n.commitments(),
            &z,
            &commitment_list,
            &group_public_key,
            msg,
        )
        .expect("partial verify");
        sig_shares.push(z);
    }

    let sig = aggregate(&commitment_list, msg, &group_public_key, &sig_shares).expect("aggregate");
    verify_signature(&sig, msg, &group_public_key).expect("verify");

    let pk = pkp.group_public_key_bytes().expect("pk bytes");
    (sig.to_bytes().expect("sig bytes"), pk)
}

#[test]
fn subset_independence_1_2_and_1_3_both_ed25519_valid() {
    // Two different valid signer subsets must both yield Ed25519-valid sigs
    // under the SAME group public key (each run regenerates a fresh group, so
    // we just assert internal Ed25519-validity of each).
    let msg = b"oxicrypto frost protocol test";

    for subset in [[1u16, 2u16], [1u16, 3u16], [2u16, 3u16]] {
        let (sig_bytes, pk_bytes) = run_signing(subset);
        let vk = Ed25519VerifyingKey::from_bytes(&pk_bytes).expect("vk");
        let sig = Ed25519Signature::from_bytes(&sig_bytes);
        vk.verify_strict(msg, &sig)
            .unwrap_or_else(|_| panic!("subset {subset:?} sig must be ed25519-valid"));
    }
}

#[test]
fn tamper_wrong_message_fails_verification() {
    use oxicrypto_rand::OxiRng;
    let mut rng = OxiRng::new().expect("rng");
    let (shares, pkp) = trusted_dealer_keygen(&mut rng, 3, 2).expect("keygen");
    let group_public_key = pkp.group_public_key();
    let msg = b"the original message";

    let id1 = Identifier::new(1).expect("id1");
    let id2 = Identifier::new(2).expect("id2");
    let n1 = commit(&mut rng, id1, &shares[0].value()).expect("n1");
    let n2 = commit(&mut rng, id2, &shares[1].value()).expect("n2");
    let commitment_list = sort_commitments(&[n1.commitments(), n2.commitments()]).expect("sorted");

    let kp1 = KeyPackage::new(SecretShare::new(id1, shares[0].value()), group_public_key);
    let kp2 = KeyPackage::new(SecretShare::new(id2, shares[1].value()), group_public_key);
    let z1 = sign(&kp1, &n1, msg, &commitment_list).expect("z1");
    let z2 = sign(&kp2, &n2, msg, &commitment_list).expect("z2");
    let sig = aggregate(&commitment_list, msg, &group_public_key, &[z1, z2]).expect("aggregate");

    // Correct message verifies, tampered message does not.
    verify_signature(&sig, msg, &group_public_key).expect("good verify");
    let bad = verify_signature(&sig, b"a different message", &group_public_key);
    assert!(bad.is_err(), "tampered message must fail verification");
}

#[test]
fn tamper_wrong_share_fails_partial_and_aggregate() {
    use oxicrypto_rand::OxiRng;
    let mut rng = OxiRng::new().expect("rng");
    let (shares, pkp) = trusted_dealer_keygen(&mut rng, 3, 2).expect("keygen");
    let group_public_key = pkp.group_public_key();
    let msg = b"frost share tamper";

    let id1 = Identifier::new(1).expect("id1");
    let id2 = Identifier::new(2).expect("id2");
    let n1 = commit(&mut rng, id1, &shares[0].value()).expect("n1");
    let n2 = commit(&mut rng, id2, &shares[1].value()).expect("n2");
    let commitment_list = sort_commitments(&[n1.commitments(), n2.commitments()]).expect("sorted");

    let kp1 = KeyPackage::new(SecretShare::new(id1, shares[0].value()), group_public_key);
    let kp2 = KeyPackage::new(SecretShare::new(id2, shares[1].value()), group_public_key);
    let z1 = sign(&kp1, &n1, msg, &commitment_list).expect("z1");
    let z2 = sign(&kp2, &n2, msg, &commitment_list).expect("z2");

    // Corrupt z1 by adding ONE; the partial-share check must reject it.
    let bad_z1 = SignatureShare::new(id1, z1.value() + Scalar::ONE);
    let partial = verify_signature_share(
        &pkp.public_share(id1).expect("pk1"),
        &n1.commitments(),
        &bad_z1,
        &commitment_list,
        &group_public_key,
        msg,
    );
    assert!(partial.is_err(), "tampered share must fail partial verify");

    // Aggregating the tampered share must yield an invalid signature.
    let bad_sig =
        aggregate(&commitment_list, msg, &group_public_key, &[bad_z1, z2]).expect("aggregate");
    assert!(
        verify_signature(&bad_sig, msg, &group_public_key).is_err(),
        "aggregate over tampered share must fail verification"
    );
}

#[test]
fn signature_byte_roundtrip() {
    let sig = aggregate::Signature::from_bytes(&unhex(SIGNATURE)).expect("decode");
    assert_eq!(hex_of(&sig.to_bytes().expect("encode")), SIGNATURE);
}

#[test]
fn identifier_zero_rejected() {
    assert!(Identifier::new(0).is_err());
    assert!(Identifier::from_scalar(Scalar::ZERO).is_err());
}

#[test]
fn deserialize_element_rejects_identity_and_noncanonical() {
    // Identity element encoding (compressed Y of the neutral point) is rejected.
    let mut identity = [0u8; 32];
    identity[0] = 1; // y = 1, sign = 0 → neutral element
    assert!(super::deserialize_element(&identity).is_err());
    // Wrong length.
    assert!(super::deserialize_element(&[0u8; 31]).is_err());
}

#[test]
fn lagrange_interpolation_recovers_secret() {
    // With shares {1,2} and {1,3} and {2,3}, λ_i·s_i summed must recover s.
    let secret = scalar_of(GROUP_SECRET_KEY);
    let coeff1 = scalar_of(COEFF_1);
    let (shares, _) =
        trusted_dealer_keygen_with_coefficients(secret, &[coeff1], 3, 2).expect("keygen");

    for subset in [[1usize, 2usize], [1, 3], [2, 3]] {
        let ids: Vec<Identifier> = subset.iter().map(|&i| shares[i - 1].identifier()).collect();
        let mut recovered = Scalar::ZERO;
        for &i in &subset {
            let lambda = super::derive_interpolating_value(&ids, shares[i - 1].identifier())
                .expect("lambda");
            recovered += lambda * shares[i - 1].value();
        }
        assert_eq!(recovered, secret, "subset {subset:?} must recover secret");
    }
}
