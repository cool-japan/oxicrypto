//! Purity tripwire: verify that the default (no-features) closure of the
//! `oxicrypto` facade crate does NOT pull in `aws-lc-rs` or `cryptoki` on
//! its normal dependency edges.
//!
//! Run this test from any location — we navigate up from `CARGO_MANIFEST_DIR`
//! (this adapter crate's directory) two levels to reach the workspace root,
//! then invoke `cargo tree` with no features on the `oxicrypto` facade.

#[test]
fn oxicrypto_default_closure_is_pure() {
    // Navigate to workspace root: …/crates/oxicrypto-adapter-aws-lc → …/ (workspace root)
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .ancestors()
        .nth(2)
        .expect("could not navigate to workspace root from CARGO_MANIFEST_DIR");

    let output = std::process::Command::new("cargo")
        .args([
            "tree",
            "--manifest-path",
            workspace_root
                .join("Cargo.toml")
                .to_str()
                .expect("workspace Cargo.toml path not UTF-8"),
            "-p",
            "oxicrypto",
            "--no-default-features",
            "--edges",
            "normal",
        ])
        .output()
        .expect("failed to run `cargo tree`");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "cargo tree failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    // The default (pure) closure must not contain aws-lc or cryptoki on normal edges.
    assert!(
        !stdout.contains("aws-lc"),
        "aws-lc appeared in default oxicrypto closure:\n{stdout}"
    );
    assert!(
        !stdout.contains("cryptoki"),
        "cryptoki appeared in default oxicrypto closure:\n{stdout}"
    );
}
