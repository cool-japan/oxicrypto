//! Integration tests for the stack-safe ML-DSA-87 helpers.
//!
//! Crucially, these tests run on the **default** libtest worker-thread stack —
//! they do NOT wrap the calls in a manual 8 MiB `thread::Builder`.  The whole
//! point of `stack_safe` is that the helpers spawn their own correctly sized
//! (2 MiB) worker thread internally, so ML-DSA-87 keygen/sign/verify succeeds
//! from any ambient thread without a stack overflow.

use oxicrypto_pq::{
    mldsa87_generate_stack_safe, mldsa87_sign_stack_safe, mldsa87_verify_stack_safe,
    run_on_large_stack, MlDsa87, Signature87, SigningKey87, VerifyingKey87, OXICRYPTO_MLDSA_STACK,
};

const MSG: &[u8] = b"stack-safe ML-DSA-87 round trip";

#[test]
fn stack_constant_has_expected_headroom() {
    // 2 MiB, matching the documented measurement (worst-case debug = 768 KiB).
    assert_eq!(OXICRYPTO_MLDSA_STACK, 2 * 1024 * 1024);
}

#[test]
fn generate_sign_verify_round_trip() {
    let (sk_seed, vk_bytes) = mldsa87_generate_stack_safe().expect("keygen");
    assert_eq!(sk_seed.len(), 32, "ML-DSA-87 seed is 32 bytes");
    assert_eq!(
        vk_bytes.len(),
        MlDsa87::VERIFYING_KEY_LEN,
        "ML-DSA-87 verifying key is 2592 bytes"
    );

    let sig = mldsa87_sign_stack_safe(&sk_seed, MSG).expect("sign");
    assert_eq!(
        sig.len(),
        MlDsa87::SIGNATURE_LEN,
        "ML-DSA-87 signature is 4627 bytes"
    );

    // Verify via the stack-safe helper.
    mldsa87_verify_stack_safe(&vk_bytes, MSG, &sig).expect("verify");
}

#[test]
fn wrong_message_fails() {
    let (sk_seed, vk_bytes) = mldsa87_generate_stack_safe().expect("keygen");
    let sig = mldsa87_sign_stack_safe(&sk_seed, MSG).expect("sign");
    let result = mldsa87_verify_stack_safe(&vk_bytes, b"a different message", &sig);
    assert!(result.is_err(), "verification must fail on a wrong message");
}

#[test]
fn tampered_signature_fails() {
    let (sk_seed, vk_bytes) = mldsa87_generate_stack_safe().expect("keygen");
    let mut sig = mldsa87_sign_stack_safe(&sk_seed, MSG).expect("sign");
    sig[0] ^= 0xFF;
    let result = mldsa87_verify_stack_safe(&vk_bytes, MSG, &sig);
    assert!(
        result.is_err(),
        "verification must fail on a tampered signature"
    );
}

#[test]
fn helper_output_interoperates_with_typed_api() {
    // Produce a signature with the stack-safe helper, then verify it through the
    // typed `VerifyingKey87` API (itself driven on a large stack), and vice
    // versa — proving the two paths are byte-compatible.
    let (sk_seed, vk_bytes) = mldsa87_generate_stack_safe().expect("keygen");
    let helper_sig = mldsa87_sign_stack_safe(&sk_seed, MSG).expect("helper sign");

    // Typed API verifies the helper's signature (on a large stack).
    run_on_large_stack(|| {
        let vk = VerifyingKey87::from_bytes(&vk_bytes).expect("vk decode");
        let sig = Signature87::from_bytes(&helper_sig).expect("sig decode");
        vk.verify(MSG, &sig).expect("typed verify of helper sig");
    })
    .expect("worker thread");

    // Helper verifies a signature produced by the typed API.
    let typed_sig = run_on_large_stack(|| {
        let sk = SigningKey87::from_bytes(&sk_seed).expect("sk decode");
        sk.sign(MSG).expect("typed sign").to_bytes()
    })
    .expect("worker thread");
    mldsa87_verify_stack_safe(&vk_bytes, MSG, &typed_sig).expect("helper verify of typed sig");
}
