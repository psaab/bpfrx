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
/// overflow (and only when inserting a genuinely new key) the map is cleared
/// wholesale. `clear()` retains capacity, so this is allocation-free.
pub(super) fn neg_neigh_record(cache: &mut NegNeighCache, key: (i32, IpAddr), now_ns: u64) {
    if cache.len() >= MAX_NEG_NEIGH_CACHE && !cache.contains_key(&key) {
        cache.clear();
    }
    cache.insert(key, now_ns);
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

    #[test]
    fn overflow_clears_then_reinserts_new_key() {
        let mut c = NegNeighCache::default();
        // Fill exactly to the cap with distinct keys.
        for i in 0..MAX_NEG_NEIGH_CACHE {
            // Spread across two octets so >256 distinct keys are expressible.
            let k = (14i32, IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8)));
            neg_neigh_record(&mut c, k, 1_000);
        }
        assert_eq!(c.len(), MAX_NEG_NEIGH_CACHE);
        // One more NEW key triggers wholesale clear, then inserts the new key.
        let extra = (14i32, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        neg_neigh_record(&mut c, extra, 2_000);
        assert_eq!(c.len(), 1, "overflow must clear then hold only the new key");
        assert!(neg_neigh_active(&mut c, &extra, 2_000));
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
