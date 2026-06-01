//! Integration tests for compile-time feature introspection.
//!
//! Verifies that [`oxicrypto::enabled_features()`] returns a consistent set
//! reflecting what was actually compiled in.

#[test]
fn test_enabled_features_returns_vec() {
    let features = oxicrypto::enabled_features();
    // The result must be a valid Vec; contents depend on the active feature flags.
    // We only assert structural correctness here.
    assert!(
        features.len() <= 4,
        "at most 4 known features can be enabled; got {:?}",
        features
    );
}

#[test]
fn test_default_features_include_pure() {
    let features = oxicrypto::enabled_features();
    #[cfg(feature = "pure")]
    assert!(
        features.contains(&"pure"),
        "pure feature should be in enabled_features() when compiled with --features=pure; got {:?}",
        features
    );
    // When pure is NOT compiled in, we just verify the feature is absent.
    #[cfg(not(feature = "pure"))]
    assert!(
        !features.contains(&"pure"),
        "pure feature should be absent when not compiled in; got {:?}",
        features
    );
}

#[test]
fn test_enabled_features_known_names_only() {
    let features = oxicrypto::enabled_features();
    let known = ["pure", "simd", "pq-preview", "std"];
    for &f in &features {
        assert!(
            known.contains(&f),
            "unexpected feature name {:?} in enabled_features()",
            f
        );
    }
}

#[test]
fn test_enabled_features_no_duplicates() {
    let features = oxicrypto::enabled_features();
    let mut seen = std::collections::HashSet::new();
    for &f in &features {
        assert!(
            seen.insert(f),
            "duplicate feature {:?} in enabled_features()",
            f
        );
    }
}
