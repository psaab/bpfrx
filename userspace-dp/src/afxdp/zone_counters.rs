//! #3651: per-zone ingress/egress traffic (packet + byte) counters.
//!
//! The eBPF-era dense `zone_counters` BPF array was deleted in the #1476
//! retirement; the Go read surfaces (`show security zones` Traffic statistics,
//! REST `/security/zones`, the Prometheus collector) key a sparse offset map
//! and report `ErrCounterNotPopulated` ("not available") because nothing
//! sources per-zone volume. This module is the userspace POPULATE half
//! (design of record: `docs/research/3643-dead-counters/plan.md` §5A).
//!
//! ## Hot path (no per-packet hash, no per-packet atomic)
//!
//! [`ZoneCounterSlotMap`] is a flat direct-index `[u8; 65536]` zone-id → slot
//! LUT built at config-apply time. A forwarded packet resolves its ingress and
//! egress zone slot with two array reads (Codex+AGY r1 mandate: a per-packet
//! `HashMap::get` would throttle forwarding) and accumulates into a per-worker
//! thread-local dense [`ZonePending`] accumulator — the same coalesce-then-fold
//! technique `policy::record_policy_hit_counter` / `filter::record_filter_counter`
//! use. The per-RX-batch [`flush_recorded_zone_counters`] folds the coalesced
//! per-slot deltas into the coordinator-owned [`ZoneCounterStore`].
//!
//! ## Store (zone-id keyed → no slot-reassignment hazard)
//!
//! The shared store is keyed by the STABLE zone id, not by slot. The flush
//! translates slot → zone id through the slot map's inverse, so a config apply
//! that renumbers slots never mis-attributes counts: accumulate and flush
//! inside one loop iteration always use the same slot map, and the store cell
//! is addressed by the stable zone id. That removes the cold-path `zero_slot`
//! reassignment machinery entirely. The store rides `ForwardingState` (cloned
//! forward from the previous state across applies, like a persistent Arc) so
//! totals survive config commits, and is reset only by the operator
//! `clear_zone_counters` control IPC.

use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use rustc_hash::{FxHashMap, FxHashSet};

use crate::protocol::ZoneTrafficCounterStatus;

/// Dense hot-path slot count. Slot 0 is reserved (unassigned / unzoned), so
/// `ZONE_COUNTER_SLOTS - 1` zones are assignable to a slot; a configured zone
/// past that capacity sets `overflow_active` and its traffic goes uncounted
/// (documented, same posture as the cold-path histogram `overflow_active`).
/// 63 assignable slots covers every realistic deployment (the legacy dense
/// `zone_counters` array held 64) while keeping the per-worker thread-local
/// accumulator small (64 × 4 × 8 = 2 KiB).
pub(in crate::afxdp) const ZONE_COUNTER_SLOTS: usize = 64;

/// Number of assignable slots (slot 0 reserved).
pub(in crate::afxdp) const ZONE_COUNTER_ASSIGNABLE_SLOTS: usize = ZONE_COUNTER_SLOTS - 1;

/// Wire/layout version stamped into `ProcessStatus.zone_counter_layout_version`
/// when the block is populated (#3651). 0/absent = pre-#3651 helper.
pub(in crate::afxdp) const ZONE_COUNTER_LAYOUT_VERSION: u32 = 1;

/// Flat direct-index zone-id → hot-path slot LUT, built at config apply.
///
/// `slot_of[zone_id]` is 0 for an unassigned zone (unzoned id 0, or a zone
/// past the slot capacity), else the dense slot `[1, ZONE_COUNTER_ASSIGNABLE_SLOTS]`.
/// `inverse[slot]` recovers the zone id for the flush's slot → zone-id
/// translation (0 = free slot). A single 16-bit zone id makes the flat LUT
/// feasible where the cold-path 32-bit zone-PAIR key needed a `HashMap`.
pub(in crate::afxdp) struct ZoneCounterSlotMap {
    slot_of: Box<[u8; 65536]>,
    inverse: [u16; ZONE_COUNTER_SLOTS],
    /// True if some configured zone could not be assigned a slot because the
    /// `ZONE_COUNTER_ASSIGNABLE_SLOTS` capacity was exhausted. Surfaced as
    /// `ProcessStatus.zone_counter_overflow_active`.
    pub(in crate::afxdp) overflow_active: bool,
}

impl Default for ZoneCounterSlotMap {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Debug for ZoneCounterSlotMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Summarize rather than dumping the 64 KiB LUT.
        let assigned = self.inverse.iter().filter(|&&z| z != 0).count();
        f.debug_struct("ZoneCounterSlotMap")
            .field("assigned_zones", &assigned)
            .field("overflow_active", &self.overflow_active)
            .finish()
    }
}

impl ZoneCounterSlotMap {
    /// An empty map: every zone resolves to slot 0 (uncounted).
    pub(in crate::afxdp) fn empty() -> Self {
        Self {
            slot_of: Box::new([0u8; 65536]),
            inverse: [0u16; ZONE_COUNTER_SLOTS],
            overflow_active: false,
        }
    }

    /// Build the slot map from the configured zone-id set. Slots are assigned
    /// in sorted zone-id order (deterministic for a given config); a duplicate
    /// or zero id is ignored. Because the shared store is zone-id keyed, slot
    /// assignment does NOT need to be stable across applies (unlike the
    /// cold-path histogram, whose slot IS the accumulator index), so this is a
    /// plain rebuild with no previous-map retention.
    pub(in crate::afxdp) fn build(zone_ids: &[u16]) -> Self {
        let mut ids: Vec<u16> = zone_ids.iter().copied().filter(|&z| z != 0).collect();
        ids.sort_unstable();
        ids.dedup();

        let mut slot_of = Box::new([0u8; 65536]);
        let mut inverse = [0u16; ZONE_COUNTER_SLOTS];
        let mut overflow_active = false;
        let mut next_slot = 1usize;
        for zid in ids {
            if next_slot > ZONE_COUNTER_ASSIGNABLE_SLOTS {
                overflow_active = true;
                break;
            }
            slot_of[zid as usize] = next_slot as u8;
            inverse[next_slot] = zid;
            next_slot += 1;
        }
        Self {
            slot_of,
            inverse,
            overflow_active,
        }
    }

    /// Resolve the hot-path slot for `zone_id` (0 = unassigned / uncounted).
    #[inline]
    pub(in crate::afxdp) fn slot_of(&self, zone_id: u16) -> u8 {
        self.slot_of[zone_id as usize]
    }
}

/// Cumulative per-zone traffic totals, guarded by a single mutex (folded into
/// off the hot path, at RX-batch cadence, so the lock is uncontended in
/// practice — mirrors the `PolicyCounterStore` registry lock).
#[derive(Clone, Copy, Debug, Default)]
struct ZoneTotals {
    ingress_packets: u64,
    ingress_bytes: u64,
    egress_packets: u64,
    egress_bytes: u64,
}

/// Coordinator-owned, config-apply-surviving cumulative per-zone traffic
/// store, keyed by the stable zone id. `Clone` shares the inner `Arc<Mutex>`,
/// so cloning `ForwardingState` (worker publish) keeps every generation
/// pointing at the same totals.
#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct ZoneCounterStore {
    totals: Arc<Mutex<FxHashMap<u16, ZoneTotals>>>,
}

impl ZoneCounterStore {
    /// Sparse snapshot for the status wire: one row per zone with any traffic.
    /// Deterministic order (sorted by zone id) for a stable wire.
    pub(in crate::afxdp) fn snapshot(&self) -> Vec<ZoneTrafficCounterStatus> {
        let totals = self.totals.lock().expect("zone counter store poisoned");
        let mut out: Vec<ZoneTrafficCounterStatus> = totals
            .iter()
            .filter(|(_, t)| {
                t.ingress_packets != 0
                    || t.ingress_bytes != 0
                    || t.egress_packets != 0
                    || t.egress_bytes != 0
            })
            .map(|(&zone_id, t)| ZoneTrafficCounterStatus {
                zone_id,
                ingress_packets: t.ingress_packets,
                ingress_bytes: t.ingress_bytes,
                egress_packets: t.egress_packets,
                egress_bytes: t.egress_bytes,
            })
            .collect();
        out.sort_unstable_by_key(|s| s.zone_id);
        out
    }

    /// Operator clear (`clear_zone_counters` IPC): drop all cumulative totals
    /// so the helper reports 0 on the next status poll (otherwise the Go side's
    /// absolute `SetZoneCounterOffset` overwrite would snap the cleared value
    /// back within <= 1 s). Load-bearing half of the operator clear.
    pub(in crate::afxdp) fn clear(&self) {
        self.totals
            .lock()
            .expect("zone counter store poisoned")
            .clear();
    }

    /// Drop totals for zones that are no longer configured (config apply
    /// hygiene). Correctness does not depend on this — the coordinator snapshot
    /// accessor also filters to configured zones — but it bounds the map to the
    /// live zone set.
    pub(in crate::afxdp) fn reconcile(&self, configured: &FxHashSet<u16>) {
        self.totals
            .lock()
            .expect("zone counter store poisoned")
            .retain(|zone_id, _| configured.contains(zone_id));
    }

    /// Fold a worker's coalesced per-slot deltas into the store, translating
    /// slot → zone id via the slot map inverse. Off the hot path (once per RX
    /// batch), so the single lock acquisition is cheap.
    fn fold_pending(&self, pending: &ZonePending, slot_map: &ZoneCounterSlotMap) {
        let mut totals = self.totals.lock().expect("zone counter store poisoned");
        for slot in 1..ZONE_COUNTER_SLOTS {
            let zone_id = slot_map.inverse[slot];
            if zone_id == 0 {
                continue;
            }
            let ip = pending.ingress_packets[slot];
            let ib = pending.ingress_bytes[slot];
            let ep = pending.egress_packets[slot];
            let eb = pending.egress_bytes[slot];
            if ip == 0 && ib == 0 && ep == 0 && eb == 0 {
                continue;
            }
            let entry = totals.entry(zone_id).or_default();
            entry.ingress_packets = entry.ingress_packets.saturating_add(ip);
            entry.ingress_bytes = entry.ingress_bytes.saturating_add(ib);
            entry.egress_packets = entry.egress_packets.saturating_add(ep);
            entry.egress_bytes = entry.egress_bytes.saturating_add(eb);
        }
    }
}

/// Per-worker thread-local dense slot accumulator. Touched only by the owning
/// worker thread on the hot path; folded into the shared store per RX batch.
struct ZonePending {
    ingress_packets: [u64; ZONE_COUNTER_SLOTS],
    ingress_bytes: [u64; ZONE_COUNTER_SLOTS],
    egress_packets: [u64; ZONE_COUNTER_SLOTS],
    egress_bytes: [u64; ZONE_COUNTER_SLOTS],
    touched: bool,
}

impl Default for ZonePending {
    fn default() -> Self {
        Self {
            ingress_packets: [0; ZONE_COUNTER_SLOTS],
            ingress_bytes: [0; ZONE_COUNTER_SLOTS],
            egress_packets: [0; ZONE_COUNTER_SLOTS],
            egress_bytes: [0; ZONE_COUNTER_SLOTS],
            touched: false,
        }
    }
}

impl ZonePending {
    fn reset(&mut self) {
        if !self.touched {
            return;
        }
        self.ingress_packets = [0; ZONE_COUNTER_SLOTS];
        self.ingress_bytes = [0; ZONE_COUNTER_SLOTS];
        self.egress_packets = [0; ZONE_COUNTER_SLOTS];
        self.egress_bytes = [0; ZONE_COUNTER_SLOTS];
        self.touched = false;
    }
}

thread_local! {
    static ZONE_PENDING: RefCell<ZonePending> = RefCell::new(ZonePending::default());
}

/// Record one forwarded packet against its ingress and egress zone. The zone
/// ids are already resolved (ingress from the shim meta, egress from the
/// forwarding resolution), so this is two flat-LUT reads plus a thread-local
/// accumulate — no hash, no atomic, no allocation. An unassigned zone (slot 0)
/// contributes nothing.
#[inline]
pub(in crate::afxdp) fn record_zone_traffic(
    slot_map: &ZoneCounterSlotMap,
    ingress_zone_id: u16,
    egress_zone_id: u16,
    packet_bytes: u64,
) {
    let ingress_slot = slot_map.slot_of(ingress_zone_id);
    let egress_slot = slot_map.slot_of(egress_zone_id);
    if ingress_slot == 0 && egress_slot == 0 {
        return;
    }
    ZONE_PENDING.with(|pending| {
        let mut p = pending.borrow_mut();
        if ingress_slot != 0 {
            let s = ingress_slot as usize;
            p.ingress_packets[s] = p.ingress_packets[s].saturating_add(1);
            p.ingress_bytes[s] = p.ingress_bytes[s].saturating_add(packet_bytes);
            p.touched = true;
        }
        if egress_slot != 0 {
            let s = egress_slot as usize;
            p.egress_packets[s] = p.egress_packets[s].saturating_add(1);
            p.egress_bytes[s] = p.egress_bytes[s].saturating_add(packet_bytes);
            p.touched = true;
        }
    });
}

/// Fold this worker thread's coalesced per-zone deltas into the shared store.
/// Called once per RX batch alongside `flush_recorded_filter_counters` /
/// `flush_recorded_policy_hit_counters`. `slot_map` must be the SAME map the
/// intervening `record_zone_traffic` calls used (guaranteed: both read the
/// loop iteration's `forwarding` snapshot), so the slot → zone-id translation
/// is consistent.
pub(in crate::afxdp) fn flush_recorded_zone_counters(
    store: &ZoneCounterStore,
    slot_map: &ZoneCounterSlotMap,
) {
    ZONE_PENDING.with(|pending| {
        let mut p = pending.borrow_mut();
        if !p.touched {
            return;
        }
        store.fold_pending(&p, slot_map);
        p.reset();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_assigns_slots_for_wide_stable_hash_zone_ids() {
        // #3075 stable name-hash ids span [1, 65533]; a dense id-indexed table
        // would drop these. The flat LUT + slot map must count them.
        let map = ZoneCounterSlotMap::build(&[40000, 7, 65533]);
        assert!(!map.overflow_active);
        // sorted → 7 gets slot 1, 40000 slot 2, 65533 slot 3.
        assert_eq!(map.slot_of(7), 1);
        assert_eq!(map.slot_of(40000), 2);
        assert_eq!(map.slot_of(65533), 3);
        assert_eq!(map.inverse[1], 7);
        assert_eq!(map.inverse[2], 40000);
        assert_eq!(map.inverse[3], 65533);
        // Unconfigured / unzoned resolve to slot 0.
        assert_eq!(map.slot_of(0), 0);
        assert_eq!(map.slot_of(123), 0);
    }

    #[test]
    fn build_dedups_and_skips_zero() {
        let map = ZoneCounterSlotMap::build(&[0, 5, 5, 9, 0, 5]);
        assert_eq!(map.slot_of(5), 1);
        assert_eq!(map.slot_of(9), 2);
        assert_eq!(map.slot_of(0), 0);
        assert!(!map.overflow_active);
    }

    #[test]
    fn build_sets_overflow_past_capacity() {
        let ids: Vec<u16> = (1..=(ZONE_COUNTER_ASSIGNABLE_SLOTS as u16 + 5)).collect();
        let map = ZoneCounterSlotMap::build(&ids);
        assert!(
            map.overflow_active,
            "exceeding {ZONE_COUNTER_ASSIGNABLE_SLOTS} assignable slots must set overflow_active"
        );
        // Exactly the capacity is assigned; the rest are slot 0.
        let assigned = (1..=65535u16).filter(|&z| map.slot_of(z) != 0).count();
        assert_eq!(assigned, ZONE_COUNTER_ASSIGNABLE_SLOTS);
    }

    #[test]
    fn record_flush_snapshot_accumulates_both_directions() {
        let store = ZoneCounterStore::default();
        let map = ZoneCounterSlotMap::build(&[100, 200]);
        // A packet from zone 100 to zone 200: +ingress on 100, +egress on 200.
        record_zone_traffic(&map, 100, 200, 1500);
        record_zone_traffic(&map, 100, 200, 500);
        // A reply from zone 200 to zone 100.
        record_zone_traffic(&map, 200, 100, 40);
        flush_recorded_zone_counters(&store, &map);

        let mut snap = store.snapshot();
        snap.sort_unstable_by_key(|s| s.zone_id);
        assert_eq!(snap.len(), 2);

        let z100 = &snap[0];
        assert_eq!(z100.zone_id, 100);
        assert_eq!(z100.ingress_packets, 2);
        assert_eq!(z100.ingress_bytes, 2000);
        assert_eq!(z100.egress_packets, 1);
        assert_eq!(z100.egress_bytes, 40);

        let z200 = &snap[1];
        assert_eq!(z200.zone_id, 200);
        assert_eq!(z200.ingress_packets, 1);
        assert_eq!(z200.ingress_bytes, 40);
        assert_eq!(z200.egress_packets, 2);
        assert_eq!(z200.egress_bytes, 2000);
    }

    #[test]
    fn unassigned_and_zero_zones_are_uncounted() {
        let store = ZoneCounterStore::default();
        let map = ZoneCounterSlotMap::build(&[100]);
        // Egress zone 999 is unconfigured (slot 0); ingress 0 is unzoned.
        record_zone_traffic(&map, 0, 999, 1500);
        // Ingress 100 counted; egress 999 uncounted.
        record_zone_traffic(&map, 100, 999, 1500);
        flush_recorded_zone_counters(&store, &map);
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].zone_id, 100);
        assert_eq!(snap[0].ingress_packets, 1);
        assert_eq!(snap[0].egress_packets, 0);
    }

    #[test]
    fn clear_resets_totals() {
        let store = ZoneCounterStore::default();
        let map = ZoneCounterSlotMap::build(&[100]);
        record_zone_traffic(&map, 100, 100, 64);
        flush_recorded_zone_counters(&store, &map);
        assert_eq!(store.snapshot().len(), 1);
        store.clear();
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn reconcile_drops_removed_zones() {
        let store = ZoneCounterStore::default();
        let map = ZoneCounterSlotMap::build(&[100, 200]);
        record_zone_traffic(&map, 100, 200, 64);
        flush_recorded_zone_counters(&store, &map);
        assert_eq!(store.snapshot().len(), 2);
        let keep: FxHashSet<u16> = [100u16].into_iter().collect();
        store.reconcile(&keep);
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].zone_id, 100);
    }
}
