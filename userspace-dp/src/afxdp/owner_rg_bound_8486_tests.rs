//! #8486: a peer-supplied `owner_rg_id` is bounded before it is FILED into the
//! owner-RG indexes.
//!
//! `metadata.owner_rg_id` arrives from the peer as a raw `i32`. It was filed
//! for every positive value, so a peer sending N distinct ids created N buckets
//! in `OwnerRgSessionIndex` and nothing shrank that allocation. The cost is not
//! the buckets: the authoritative un-file uses `HashMap::retain`, which is
//! O(capacity) and visits empty slots, so removing N keys filed under N
//! distinct ids is Theta(N^2) of outer-capacity work on the session-control
//! thread.
//!
//! The Go side bounds redundancy-group ids to 0..15 on the STRICT path and
//! downgrades that to a WARNING on the tolerant load / peer-sync path -- which
//! is precisely why the helper needs its own bound. It is the last line.

use super::shared_ops::{
    MAX_FILEABLE_OWNER_RG_ID, OWNER_RG_FILINGS_DECLINED, is_fileable_owner_rg,
};
use std::sync::atomic::Ordering;

/// The bound, on BOTH sides. A test that only checked the rejection would pass
/// against a predicate that rejects everything, which would silently disable
/// owner-RG indexing altogether -- and owner-RG indexing is what makes a
/// takeover find the peer's sessions.
#[test]
fn the_owner_rg_filing_bound_holds_on_both_sides_8486() {
    // In range: every id a real chassis cluster can produce still files.
    for id in 1..=MAX_FILEABLE_OWNER_RG_ID {
        assert!(
            is_fileable_owner_rg(id),
            "owner_rg_id {id} is within the Go strict bound (0..{MAX_FILEABLE_OWNER_RG_ID}) \
             and MUST still file — rejecting it would stop a legitimate takeover \
             finding the peer's sessions"
        );
    }
    // Out of range, both directions.
    for id in [
        MAX_FILEABLE_OWNER_RG_ID + 1,
        1_000,
        i32::MAX,
        0,
        -1,
        i32::MIN,
    ] {
        assert!(
            !is_fileable_owner_rg(id),
            "owner_rg_id {id} is outside the fileable range and must not create a bucket"
        );
    }
}

/// The boundary itself, pinned. An off-by-one here either rejects a legitimate
/// RG 15 or admits an unbounded 16, and neither is visible in the range loops
/// above if the constant moves with them.
#[test]
fn the_owner_rg_bound_is_fifteen_matching_the_go_strict_validator_8486() {
    assert_eq!(
        MAX_FILEABLE_OWNER_RG_ID, 15,
        "the helper's bound must match compiler_validate_strict_chassis.go's \
         0..15 redundancy-group range; if the Go side moves, this moves with it \
         deliberately rather than drifting"
    );
    assert!(is_fileable_owner_rg(15));
    assert!(!is_fileable_owner_rg(16));
}

/// A declined filing is COUNTED, not silent. Nonzero means a peer is sending
/// ids this cluster's own strict validator would reject, which is worth seeing
/// — and a counter rather than a log so a burst cannot flood the journal.
#[test]
fn a_declined_owner_rg_filing_is_counted_8486() {
    let before = OWNER_RG_FILINGS_DECLINED.load(Ordering::Relaxed);
    assert!(!is_fileable_owner_rg(9_999));
    let after = OWNER_RG_FILINGS_DECLINED.load(Ordering::Relaxed);
    assert!(
        after > before,
        "an out-of-range filing must be counted; before={before} after={after}"
    );

    // CONTROL: a plain zero or negative is NOT an out-of-range peer id — it is
    // the ordinary "no redundancy group" case, which every standalone session
    // carries. Counting those would make the metric read as an attack on every
    // non-clustered box and bury the signal it exists to carry.
    let before = OWNER_RG_FILINGS_DECLINED.load(Ordering::Relaxed);
    assert!(!is_fileable_owner_rg(0));
    assert!(!is_fileable_owner_rg(-3));
    assert_eq!(
        OWNER_RG_FILINGS_DECLINED.load(Ordering::Relaxed),
        before,
        "a non-positive owner_rg_id is 'no RG', not an out-of-range id, and must \
         not be counted as a declined filing"
    );
}

/// The width bound, stated as the property the issue actually asks for: a
/// synthetic burst of distinct peer-supplied ids cannot widen the index beyond
/// the bound, no matter how many are offered.
#[test]
fn a_burst_of_distinct_peer_ids_cannot_widen_the_index_8486() {
    let mut filed = std::collections::BTreeSet::new();
    for id in 1..=5_000 {
        if is_fileable_owner_rg(id) {
            filed.insert(id);
        }
    }
    assert_eq!(
        filed.len(),
        MAX_FILEABLE_OWNER_RG_ID as usize,
        "5000 distinct peer-supplied ids must file at most {MAX_FILEABLE_OWNER_RG_ID} \
         distinct buckets; got {filed:?}"
    );
    assert_eq!(*filed.iter().next().unwrap(), 1);
    assert_eq!(*filed.iter().next_back().unwrap(), MAX_FILEABLE_OWNER_RG_ID);
}
