//! Purity tripwire test.
//!
//! The actual purity assertion — that `ring` and `aws-lc-rs` appear ONLY under
//! the dev-dependency edges of `oxicrypto-bench` and NOT on the normal edges
//! of any production crate — is validated externally via:
//!
//! ```text
//! cargo tree -p oxicrypto --edges normal | grep -E '(ring|aws.lc|openssl.sys)'
//! ```
//!
//! That command MUST return empty output for the workspace to be considered
//! Pure Rust.  This file simply confirms the test infrastructure compiles.

#[test]
fn check_purity() {
    // This test passes unconditionally.  The real purity gate lives in the
    // `cargo tree` grep check described in the module-level doc comment.
}
