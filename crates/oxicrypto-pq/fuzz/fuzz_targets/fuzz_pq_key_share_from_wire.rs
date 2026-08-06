//! Fuzz target: `PqKeyShare::from_wire` must never panic on arbitrary bytes,
//! and any successfully-decoded key share must round-trip back through
//! `to_wire` to the same bytes it was decoded from.
//!
//! Run with:
//!   cargo fuzz run fuzz_pq_key_share_from_wire

#![no_main]

use libfuzzer_sys::fuzz_target;
use oxicrypto_pq::PqKeyShare;

fuzz_target!(|data: &[u8]| {
    if let Ok(decoded) = PqKeyShare::from_wire(data) {
        // A successful decode must re-encode to exactly the bytes it
        // consumed (group_id(2) || len(2) || payload), never panicking and
        // never silently producing a different frame.
        let re_encoded = decoded
            .to_wire()
            .expect("a payload that was just decoded from the wire must always re-encode");
        assert_eq!(
            re_encoded.len(),
            4 + decoded.payload.len(),
            "re-encoded frame length must match header + payload"
        );
        assert_eq!(
            &re_encoded[..re_encoded.len()],
            &data[..re_encoded.len()],
            "re-encoding a decoded key share must reproduce the original wire bytes"
        );
    }
});
