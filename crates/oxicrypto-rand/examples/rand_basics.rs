//! CSPRNG usage with `oxicrypto-rand`: filling buffers, unbiased ranges,
//! weighted choice, and Fisher-Yates shuffling, all backed by [`OxiRng`]
//! (ChaCha20, OS-seeded, fork-safe on Unix).
//!
//! Run with:
//!   cargo run -p oxicrypto-rand --example rand_basics

use oxicrypto_core::Rng;
use oxicrypto_rand::{random_range_unbiased, shuffle, weighted_choice_with_rng, OxiRng};

fn main() {
    fill_a_key_buffer();
    unbiased_range_and_weighted_choice();
    fisher_yates_shuffle();
}

fn fill_a_key_buffer() {
    let mut rng = OxiRng::new().expect("OS-seeded RNG init");

    let mut aes_key = [0u8; 32];
    rng.fill(&mut aes_key).expect("fill AES-256 key");
    println!("Random 32-byte key: {}", hex(&aes_key));

    // check_entropy() is a basic sanity check: two independent draws differ
    // and are not all-zero (not a full NIST SP 800-90B test).
    oxicrypto_rand::check_entropy().expect("OS entropy source looks healthy");
    println!("OS entropy health check passed");
}

fn unbiased_range_and_weighted_choice() {
    let mut rng = OxiRng::new().expect("OS-seeded RNG init");

    // random_range_unbiased draws a value in [min, max) using rejection
    // sampling, so it has no modulo bias — unlike `raw_random() % range`.
    let dice_roll = random_range_unbiased(&mut rng, 1, 7).expect("roll a d6");
    assert!((1..7).contains(&dice_roll));
    println!("Unbiased d6 roll: {dice_roll}");

    // weighted_choice_with_rng picks an index with probability proportional
    // to its weight; a zero-weight entry is never selected.
    let weights = [0u64, 10, 90]; // index 0 never chosen; index 2 chosen ~90% of the time
    let mut counts = [0u32; 3];
    for _ in 0..1000 {
        let idx = weighted_choice_with_rng(&mut rng, &weights).expect("weighted choice");
        counts[idx] += 1;
    }
    assert_eq!(counts[0], 0, "a zero-weight entry must never be chosen");
    println!("Weighted choice over 1000 draws: counts = {counts:?} (index 0 never chosen)");
}

fn fisher_yates_shuffle() {
    let mut rng = OxiRng::new().expect("OS-seeded RNG init");

    let mut deck: Vec<u8> = (1..=13).collect();
    let original = deck.clone();
    shuffle(&mut deck, &mut rng).expect("shuffle deck");

    // A shuffle must be a permutation: same multiset of elements, same length.
    let mut sorted = deck.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted, original,
        "shuffle must be a permutation of the input"
    );
    println!("Shuffled deck: {deck:?}");
}

/// Format a byte slice as a lowercase hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
