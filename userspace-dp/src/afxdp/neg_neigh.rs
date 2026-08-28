//! #1651 Path B3: dead-host negative neighbor cache.
//!
//! A per-binding, short-TTL cache of `(egress_ifindex, next_hop)` keys that
//! failed to resolve within `PENDING_NEIGH_TIMEOUT`. While a dst is present,
//! un-expired, and still-unresolved, new `MissingNeighbor` packets to it
//! fast-fail (recycle) at the buffer site instead of each consuming a
//! `pending_neigh` slot for the full timeout window.
//!
//! Historical motivation (AGY-r1 HIGH, reopened-#1651 research, when
//! `pending_neigh` was still a per-packet FIFO): a dead-host SYN storm
//! could saturate the bounded queue (cap `MAX_PENDING_NEIGH`) and starve
//! LIVE cold connects at the full-queue gate. Post-#1771 §2.2 the map
//! holds ONE representative packet per `(egress_ifindex, next_hop)`, so
//! a single dead host pins ≤1 entry; the residual threat this cache
//! defends against is a multi-hop scan exhausting the distinct-hop cap.
//! The pending hold per hop is dynamic — `pending_neigh_timeout_ns`
//! (800 ms with confirmed kernel fast-retrans, else 2000 ms; fallback
//! `PENDING_NEIGH_TIMEOUT_NS` = 2 s) per `neighbor_dispatch.rs` — not a
//! fixed 800 ms each.
//!
//! ## Invalidation
//! - **RTM_NEWNEIGH (host recovered):** lazy resolved-neighbor-wins. The
//!   caller checks `forwarding.neighbors` then `dynamic_neighbors` BEFORE
//!   honoring a negative entry; on a resolved hit it calls
//!   [`neg_neigh_evict`] and forwards normally. The shared netlink monitor
//!   thread populates `dynamic_neighbors`, so a recovered host that receives
//!   traffic is evicted on its very next packet — no monitor→per-binding
//!   coupling needed.
//! - **TTL:** [`neg_neigh_active`] evicts on access once the entry is older
//!   than `NEG_NEIGH_TTL_NS`.
//!
//! ## Placement
//! Per-binding (mirrors `pending_neigh`). Touched ONLY by the owning worker
//! thread (both `poll_descriptor` and `retry_pending_neigh` run on it), so no
//! `Arc`/`Mutex`/cross-core sync — consistent with the per-queue AF_XDP model.

use super::types::FastMap;
use super::{MAX_NEG_NEIGH_CACHE, NEG_NEIGH_TTL_NS};
use std::net::IpAddr;

/// Negative-cache map type: key `(egress_ifindex, next_hop)`, value =
/// insertion `now_ns`.
pub(super) type NegNeighCache = FastMap<(i32, IpAddr), u64>;

/// Returns true if `key` is currently negatively cached (present AND
/// un-expired). Expired entries are evicted on access (lazy TTL).
///
/// Does NOT consult the neighbor maps — the caller must check
/// `forwarding.neighbors` / `dynamic_neighbors` FIRST so a resolved dst wins
/// (RTM_NEWNEIGH eviction). This keeps the function pure w.r.t. the neighbor
/// maps and trivially testable.
pub(super) fn neg_neigh_active(cache: &mut NegNeighCache, key: &(i32, IpAddr), now_ns: u64) -> bool {
    match cache.get(key) {
        Some(&inserted) if now_ns.saturating_sub(inserted) < NEG_NEIGH_TTL_NS => true,
        Some(_) => {
            // Expired — evict on access so the map self-prunes.
            cache.remove(key);
            false
        }
        None => false,
    }
}

/// Record a dead-host drop at `now_ns`. Bounded by `MAX_NEG_NEIGH_CACHE`: on
/// overflow (and only when inserting a genuinely new key) ONE entry is
/// reclaimed — expired entries first, else the oldest — instead of the whole
/// map (#6905).
///
/// The eviction victim used to be *every* entry. That made the victim set
/// chosen by the ARRIVING key rather than by age or usefulness: a host sweeping
/// distinct next-hops decided when the clear fired and destroyed unrelated
/// suppression at will, partially undoing the defence this module exists to
/// provide. Bounded eviction loses at most one entry per overflow.
///
/// Still allocation-free — `retain` and `remove` reuse the existing buckets —
/// and still O(len) in the worst case, which is what `clear()` already cost:
/// clearing a map is O(capacity), not O(1). So this is not a hot-path
/// regression, it is the same order of work choosing a better victim.
///
/// And the work lands on the COLD side of this module. `neg_neigh_record` is
/// called once per `(egress_ifindex, next_hop)` per pending-neighbour TIMEOUT
/// window (`neighbor_dispatch.rs`), not per packet; `neg_neigh_active` is the
/// per-packet path. That asymmetry is why an LRU is the wrong instrument here
/// — LRU pays its bookkeeping on every HIT, i.e. on the hot path, to improve a
/// decision made only on the cold one.
pub(super) fn neg_neigh_record(cache: &mut NegNeighCache, key: (i32, IpAddr), now_ns: u64) {
    if cache.len() >= MAX_NEG_NEIGH_CACHE && !cache.contains_key(&key) {
        neg_neigh_reclaim_one(cache, now_ns);
    }
    cache.insert(key, now_ns);
}

/// Free room for one new key: drop every EXPIRED entry, and if that freed
/// nothing, drop the single oldest.
///
/// Expired-first matters because this cache has NO background prune — TTL is
/// enforced lazily in [`neg_neigh_active`], on access. An entry recorded during
/// a scan and never looked up again is never revisited, so without this pass a
/// bounded policy would fill with stale entries and stay full. That is the trap
/// in "just refuse the new key at capacity", which is otherwise the cheapest
/// option and matches the pending-neighbour precedent: that map has a
/// timeout-driven drain, and this one does not, so refusing alone would wedge
/// suppression permanently for every NEW dead host — strictly worse than the
/// wholesale clear it replaced.
///
/// One pass, no allocation: `retain` prunes and simultaneously records the
/// oldest survivor, so the fallback eviction needs no second scan.
fn neg_neigh_reclaim_one(cache: &mut NegNeighCache, now_ns: u64) {
    let mut oldest: Option<((i32, IpAddr), u64)> = None;
    cache.retain(|k, inserted| {
        if now_ns.saturating_sub(*inserted) >= NEG_NEIGH_TTL_NS {
            return false;
        }
        if oldest.is_none_or(|(_, t)| *inserted < t) {
            oldest = Some((*k, *inserted));
        }
        true
    });
    if cache.len() >= MAX_NEG_NEIGH_CACHE
        && let Some((victim, _)) = oldest
    {
        cache.remove(&victim);
    }
}

/// Explicit eviction (resolved-neighbor-wins). Idempotent.
pub(super) fn neg_neigh_evict(cache: &mut NegNeighCache, key: &(i32, IpAddr)) {
    cache.remove(key);
}

/// The full dead-host gate decision used at the `MissingNeighbor` handler.
///
/// `is_resolved` is the caller-supplied resolved-neighbor probe (static
/// `forwarding.neighbors` THEN `dynamic_neighbors`, in that order — the
/// closure encapsulates the lookup so this helper stays decoupled from the
/// concrete map types and is unit-testable in isolation).
///
/// Semantics (resolved-neighbor-wins, then TTL):
/// - If the dst is now resolved, any stale negative entry is evicted and the
///   gate returns `false` (proceed to normal forwarding). This is the
///   RTM_NEWNEIGH invalidation path.
/// - Else, if the dst is negatively cached + un-expired, return `true`
///   (fast-fail: caller recycles the frame without buffering / probing /
///   seeding a session).
/// - Else return `false` (proceed: first cold connect for this dst, or the
///   negative entry has expired).
///
/// Returns `true` ⇒ the caller must fast-fail this packet.
pub(super) fn neg_neigh_gate<F: FnOnce() -> bool>(
    cache: &mut NegNeighCache,
    key: &(i32, IpAddr),
    now_ns: u64,
    is_resolved: F,
) -> bool {
    if is_resolved() {
        neg_neigh_evict(cache, key);
        false
    } else {
        neg_neigh_active(cache, key, now_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::afxdp::{MAX_NEG_NEIGH_CACHE, NEG_NEIGH_TTL_NS};
    use std::net::Ipv4Addr;

    fn key(last: u8) -> (i32, IpAddr) {
        (14, IpAddr::V4(Ipv4Addr::new(172, 16, 80, last)))
    }

    #[test]
    fn record_then_active_within_ttl() {
        let mut c = NegNeighCache::default();
        neg_neigh_record(&mut c, key(137), 1_000);
        assert!(neg_neigh_active(&mut c, &key(137), 1_000));
        // Just under TTL: still active.
        assert!(neg_neigh_active(
            &mut c,
            &key(137),
            1_000 + NEG_NEIGH_TTL_NS - 1
        ));
    }

    #[test]
    fn expires_at_ttl_boundary_and_evicts_on_access() {
        let mut c = NegNeighCache::default();
        neg_neigh_record(&mut c, key(137), 1_000);
        // Exactly TTL elapsed (now - inserted == TTL) is NOT active (< TTL).
        assert!(!neg_neigh_active(&mut c, &key(137), 1_000 + NEG_NEIGH_TTL_NS));
        // The expired entry was evicted on access.
        assert!(!c.contains_key(&key(137)));
    }

    #[test]
    fn absent_key_is_not_active() {
        let mut c = NegNeighCache::default();
        assert!(!neg_neigh_active(&mut c, &key(99), 5_000));
    }

    #[test]
    fn evict_is_idempotent() {
        let mut c = NegNeighCache::default();
        neg_neigh_record(&mut c, key(137), 1_000);
        neg_neigh_evict(&mut c, &key(137));
        assert!(!neg_neigh_active(&mut c, &key(137), 1_000));
        // Second evict on an already-absent key is a no-op, no panic.
        neg_neigh_evict(&mut c, &key(137));
        assert!(!c.contains_key(&key(137)));
    }

    #[test]
    fn resolved_wins_eviction_unsuppresses_recovered_host() {
        // Simulates the RTM_NEWNEIGH path: a dead host is negatively cached,
        // then resolves (caller evicts on the resolved-wins check). The same
        // key must no longer fast-fail.
        let mut c = NegNeighCache::default();
        neg_neigh_record(&mut c, key(137), 1_000);
        assert!(neg_neigh_active(&mut c, &key(137), 1_500));
        // Host came back → caller evicts.
        neg_neigh_evict(&mut c, &key(137));
        assert!(!neg_neigh_active(&mut c, &key(137), 1_500));
    }

    fn filler(i: usize) -> (i32, IpAddr) {
        // Spread across two octets so >256 distinct keys are expressible.
        (
            14i32,
            IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8)),
        )
    }

    /// #6905: overflow evicts a BOUNDED amount, not the whole map.
    ///
    /// This replaces `overflow_clears_then_reinserts_new_key`, which asserted
    /// `len() == 1` after an overflow. That test pinned the IMPLEMENTATION —
    /// it passes only for a wholesale clear and would have had to be deleted to
    /// land any fix, which is the shape of a test that blocks the change it
    /// exists to guide.
    ///
    /// The property is stated instead: an unrelated hop's suppression SURVIVES
    /// pressure from other hops. That reds for a wholesale clear and passes for
    /// any bounded policy — LRU, oldest-first, random victim, refuse-new —
    /// so it constrains the outcome without dictating the mechanism.
    #[test]
    fn overflow_eviction_is_bounded_not_wholesale_6905() {
        let mut c = NegNeighCache::default();
        for i in 0..MAX_NEG_NEIGH_CACHE {
            neg_neigh_record(&mut c, filler(i), 1_000);
        }
        assert_eq!(c.len(), MAX_NEG_NEIGH_CACHE, "setup: filled to the cap");

        // The hop whose suppression must survive. Recorded LAST so it is not
        // the oldest — under an age-ordered policy the victim is deterministic,
        // and a test that let the victim be arbitrary could not name a survivor.
        let protected = (14i32, IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)));
        neg_neigh_record(&mut c, protected, 1_500);

        // One more NEW key from a scanning host forces an overflow.
        let scanner = (14i32, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        neg_neigh_record(&mut c, scanner, 2_000);

        assert!(
            neg_neigh_active(&mut c, &protected, 2_000),
            "#6905: an unrelated hop's suppression must SURVIVE another hop's overflow. \
             Wholesale clear discards it, which lets a host sweeping distinct next-hops \
             choose when to disarm the defence for every other destination"
        );
        assert!(neg_neigh_active(&mut c, &scanner, 2_000), "the new key is recorded");
        assert!(
            c.len() >= MAX_NEG_NEIGH_CACHE - 1,
            "#6905: at most a BOUNDED number of entries may be lost per overflow; len={} \
             after one overflow of a {}-entry cache",
            c.len(),
            MAX_NEG_NEIGH_CACHE
        );

        // THE UPPER BOUND, and it is not decoration. A mutation cell that
        // removed the fallback eviction entirely survived the rest of this
        // suite: every other assertion here is a LOWER bound on what survives,
        // so "evict nothing and grow forever" satisfied them all. A cache whose
        // only job is to be bounded needs the bound asserted.
        for i in 0..(4 * MAX_NEG_NEIGH_CACHE) {
            neg_neigh_record(&mut c, filler(MAX_NEG_NEIGH_CACHE + i), 2_000);
            assert!(
                c.len() <= MAX_NEG_NEIGH_CACHE,
                "#6905: the cache must stay bounded by MAX_NEG_NEIGH_CACHE ({}); len={} after \
                 {} sustained inserts. Unbounded growth is the failure this cap exists to \
                 prevent, and it is invisible to any assertion about what SURVIVES",
                MAX_NEG_NEIGH_CACHE,
                c.len(),
                i + 1
            );
        }
    }

    /// #6905: the expired-first pass reclaims ALL dead entries in one scan, not
    /// just the one needed to make room.
    ///
    /// This binds the pass as an AMORTIZATION, which is what it actually buys.
    /// It is not needed for victim selection: with a single clock, "expired"
    /// means "inserted before now - TTL", which is a prefix of the age order —
    /// so evicting the oldest already evicts an expired entry whenever one
    /// exists, and the two orderings cannot be separated by a fixture.
    /// (`overflow_reclaims_expired_before_live_6905` therefore does not
    /// distinguish them either, and its doc says so.)
    ///
    /// What the pass does buy is scan cost under exactly the attack this issue
    /// is about: without it EVERY new key at capacity runs another O(len) scan
    /// to evict one entry; with it, one scan reclaims the whole expired
    /// generation and the next ~MAX inserts are O(1).
    #[test]
    fn expired_generation_is_reclaimed_in_one_pass_6905() {
        let mut c = NegNeighCache::default();
        for i in 0..MAX_NEG_NEIGH_CACHE {
            neg_neigh_record(&mut c, filler(i), 1_000);
        }
        assert_eq!(c.len(), MAX_NEG_NEIGH_CACHE, "setup");

        // One overflow, at a time when the entire existing generation is dead.
        let later = 1_000 + NEG_NEIGH_TTL_NS + 1;
        neg_neigh_record(&mut c, filler(9_000), later);

        assert!(
            c.len() <= 2,
            "#6905: a single overflow against a fully-expired cache must reclaim the whole \
             dead generation, leaving room for the inserts that follow. len={} — reclaiming \
             one victim at a time makes every subsequent insert pay another O(len) scan, \
             which is the cost this pass exists to amortise",
            c.len()
        );
    }

    /// #6905: live entries survive an overflow when expired ones are available.
    ///
    /// HONEST SCOPE, corrected after a mutation cell: this does NOT distinguish
    /// "prefers expired" from "prefers oldest". With a single clock, expired
    /// means inserted before `now - TTL`, which is a PREFIX of the age order —
    /// so evicting the oldest already evicts an expired entry whenever one
    /// exists, and no fixture can separate the two orderings. Removing the
    /// expired-first pass leaves this test green, and that is correct rather
    /// than a gap: the pass is an amortization, bound by
    /// `expired_generation_is_reclaimed_in_one_pass_6905`.
    ///
    /// What this test does bind is the property an operator cares about: an
    /// overflow must not take LIVE suppression while dead entries are sitting
    /// there to be reclaimed.
    #[test]
    fn overflow_reclaims_expired_before_live_6905() {
        let mut c = NegNeighCache::default();
        // Half the cache recorded long ago (will be expired), half recent.
        let half = MAX_NEG_NEIGH_CACHE / 2;
        for i in 0..half {
            neg_neigh_record(&mut c, filler(i), 1_000);
        }
        let fresh_at = 1_000 + NEG_NEIGH_TTL_NS;
        for i in half..MAX_NEG_NEIGH_CACHE {
            neg_neigh_record(&mut c, filler(i), fresh_at);
        }
        assert_eq!(c.len(), MAX_NEG_NEIGH_CACHE, "setup");

        // Overflow at a time when the first half is expired and the second is not.
        let scanner = (14i32, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        neg_neigh_record(&mut c, scanner, fresh_at);

        // Every LIVE entry survived: the reclaim took only expired ones.
        for i in half..MAX_NEG_NEIGH_CACHE {
            assert!(
                neg_neigh_active(&mut c, &filler(i), fresh_at),
                "#6905: live entry {i} was evicted while EXPIRED entries were available to \
                 reclaim — the victim choice must prefer entries that are already dead"
            );
        }
    }

    /// #6905: a sustained scan must not WEDGE suppression.
    ///
    /// The control for the failure mode "refuse the new key at capacity" would
    /// have had: fill the cache, let everything expire without ever looking it
    /// up (which is exactly what a scan does — each hop is recorded once and
    /// never revisited), then verify a NEW dead host still gets suppressed.
    /// Without expired-first reclaim this fails, and it fails silently: the
    /// cache is full, `len()` looks healthy, and no counter moves.
    #[test]
    fn sustained_scan_does_not_wedge_suppression_6905() {
        let mut c = NegNeighCache::default();
        for i in 0..MAX_NEG_NEIGH_CACHE {
            neg_neigh_record(&mut c, filler(i), 1_000);
        }
        // Everything above is now expired, and NOTHING looked any of it up, so
        // the lazy TTL never ran.
        let later = 1_000 + NEG_NEIGH_TTL_NS + 1;
        let new_dead_host = (14i32, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
        neg_neigh_record(&mut c, new_dead_host, later);
        assert!(
            neg_neigh_active(&mut c, &new_dead_host, later),
            "#6905: a new dead host must still be suppressible after the cache filled with \
             entries that expired unobserved. A bounded policy without expired-first reclaim \
             wedges here — the cache stays full of stale keys forever because nothing prunes \
             them, and every subsequent dead host goes unsuppressed"
        );
    }

    #[test]
    fn gate_first_cold_connect_proceeds() {
        // No negative entry, not resolved → proceed (false). The first cold
        // connect to a dst must NOT fast-fail (it buffers + probes normally).
        let mut c = NegNeighCache::default();
        assert!(!neg_neigh_gate(&mut c, &key(137), 1_000, || false));
    }

    #[test]
    fn gate_dead_host_fast_fails_then_resolved_wins() {
        // The exact poll_descriptor gate decision sequence:
        let mut c = NegNeighCache::default();
        // 1) dst dropped at timeout → recorded.
        neg_neigh_record(&mut c, key(137), 1_000);
        // 2) repeat cold packet, still unresolved + un-expired → fast-fail.
        assert!(
            neg_neigh_gate(&mut c, &key(137), 1_500, || false),
            "negatively-cached unresolved dst must fast-fail",
        );
        // 3) RTM_NEWNEIGH: dst now resolved → gate evicts and proceeds.
        assert!(
            !neg_neigh_gate(&mut c, &key(137), 1_600, || true),
            "resolved dst must NOT fast-fail (resolved-wins)",
        );
        // 4) the negative entry was evicted by the resolved-wins branch, so a
        //    later un-resolved check no longer fast-fails.
        assert!(
            !neg_neigh_gate(&mut c, &key(137), 1_700, || false),
            "resolved-wins must have evicted the negative entry",
        );
        assert!(!c.contains_key(&key(137)));
    }

    #[test]
    fn gate_expired_entry_proceeds_and_prunes() {
        let mut c = NegNeighCache::default();
        neg_neigh_record(&mut c, key(137), 1_000);
        // Past TTL, still unresolved → gate returns false (proceed) and the
        // expired entry is pruned by the active() lazy-evict.
        assert!(!neg_neigh_gate(
            &mut c,
            &key(137),
            1_000 + NEG_NEIGH_TTL_NS,
            || false
        ));
        assert!(!c.contains_key(&key(137)));
    }

    #[test]
    fn at_cap_reinsert_existing_key_does_not_clear() {
        let mut c = NegNeighCache::default();
        for i in 0..MAX_NEG_NEIGH_CACHE {
            let k = (14i32, IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8)));
            neg_neigh_record(&mut c, k, 1_000);
        }
        assert_eq!(c.len(), MAX_NEG_NEIGH_CACHE);
        // Re-recording an EXISTING key at cap must NOT clear (the
        // !contains_key guard) — it just refreshes the timestamp.
        let existing = (14i32, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        neg_neigh_record(&mut c, existing, 2_000);
        assert_eq!(c.len(), MAX_NEG_NEIGH_CACHE);
        assert!(neg_neigh_active(&mut c, &existing, 2_000));
    }
}
