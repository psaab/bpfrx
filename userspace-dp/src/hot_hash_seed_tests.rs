// Tests for hot_hash_seed.rs (#2364). Loaded as a sibling submodule via
// `#[path = "hot_hash_seed_tests.rs"]`.

use super::*;

#[test]
fn os_random_seed_never_returns_zero() {
    // The seeded hot-path hashes collapse back into the unkeyed FxHash
    // they replace if the seed is zero, re-opening the collision hole.
    // The never-zero invariant is the load-bearing contract; exercise
    // several draws (each runs the getrandom or fallback path).
    for _ in 0..8 {
        assert_ne!(
            os_random_seed_u64(),
            0,
            "OS seed draw returned 0 despite the zero-to-one remap"
        );
    }
}

#[test]
fn os_random_seed_is_well_mixed_across_draws() {
    // Not a statistical test — a smoke check that the draw is not a
    // constant. Two draws being equal is astronomically unlikely under
    // getrandom; if it fires repeatedly the entropy path is broken.
    let a = os_random_seed_u64();
    let b = os_random_seed_u64();
    assert_ne!(a, b, "two getrandom draws collided — entropy path broken");
}
