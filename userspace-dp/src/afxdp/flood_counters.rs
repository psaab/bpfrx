//! #3651: per-zone SYN / ICMP / UDP flood-EVENT counters.
//!
//! The sibling of [`crate::afxdp::zone_counters`], for the other half of the
//! dead per-zone counter families the #3643 HIDE marked "not available". Where
//! the traffic half accounts forwarded VOLUME, this one accounts flood DROPS:
//! the counts `show security screen ids-option statistics` renders as
//! "SYN flood events" / "ICMP flood events" / "UDP flood events" per zone
//! (`dataplane.FloodState.SynCount/ICMPCount/UDPCount`).
//!
//! ## This is NEW accounting, not a snapshot of existing state
//!
//! The screen module holds per-zone rate-LIMITER state (`screen/mod.rs`
//! `ZoneScreenState`) — token buckets and count-min sketches whose job is to
//! decide the next verdict, not to remember how many verdicts were taken. The
//! durable screen accounting that exists today is GLOBAL/per-reason
//! (`BatchCounters::record_screen_drop` → `screen_reason_drops`, #3343), never
//! per zone. So there was nothing to publish: this module is the per-zone tally
//! itself, added on the drop path.
//!
//! ## Drop path, not forward path — but still coalesced
//!
//! [`record_zone_flood_drop`] is called only from
//! [`crate::afxdp::BatchCounters::record_screen_drop`], i.e. only when a screen
//! check has already decided to DROP. That is off the forwarding fast path.
//!
//! It is nevertheless coalesced per RX batch rather than `fetch_add`ing
//! directly, because a screen drop is not rare when it matters: a SYN flood is
//! the primary `screen_drops` trigger, so under volumetric attack this path
//! runs per packet on every worker at once. `stage_screen_check` already
//! documents that constraint for the aggregate (#1187 — unbatched atomics here
//! would MESI-ping-pong with the coordinator's status reads under attack), and
//! a per-ZONE tally would concentrate the contention harder still: every worker
//! hammering the ONE zone under attack. So this mirrors the zone-counter shape
//! exactly — flat `[u8; 65536]` zone-id → slot LUT, per-worker thread-local
//! dense accumulator, one per-RX-batch fold into per-zone atomics the slot map
//! cached at build time (lock-free, #5163).
//!
//! ## Store
//!
//! [`FloodCounterStore`] is zone-id keyed and rides `ForwardingState`, so a
//! surviving zone keeps the SAME atomic block across a config apply that
//! renumbers slots. `clear` zeroes the blocks IN PLACE (never drops the map
//! entry) so a live slot map's cached `Arc` keeps counting from zero — the
//! `clear_flood_counters` operator IPC.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rustc_hash::{FxHashMap, FxHashSet};

use crate::protocol::ZoneFloodCounterStatus;

/// Dense hot-path slot count, mirroring [`ZONE_COUNTER_SLOTS`]. Slot 0 is
/// reserved (unassigned / unzoned).
///
/// [`ZONE_COUNTER_SLOTS`]: crate::afxdp::zone_counters::ZONE_COUNTER_SLOTS
pub(in crate::afxdp) const FLOOD_COUNTER_SLOTS: usize = 64;

/// Number of assignable slots (slot 0 reserved).
pub(in crate::afxdp) const FLOOD_COUNTER_ASSIGNABLE_SLOTS: usize = FLOOD_COUNTER_SLOTS - 1;

/// The two per-zone counter families MUST have the same capacity. Both build
/// their slot map from the SAME configured zone-id set in the same sorted
/// order, so equal capacity means a zone is either slotted for both families or
/// neither. Diverging capacities would make a zone report live traffic volume
/// while its flood counts read "not available" (or the reverse) with nothing on
/// any surface to explain the asymmetry.
const _: () = assert!(FLOOD_COUNTER_SLOTS == crate::afxdp::zone_counters::ZONE_COUNTER_SLOTS);

/// Wire/layout version stamped into `ProcessStatus.flood_counter_layout_version`
/// when the block is populated (#3651). 0/absent = helper with no per-zone flood
/// accounting.
pub(in crate::afxdp) const FLOOD_COUNTER_LAYOUT_VERSION: u32 = 1;

/// Per-zone flood-counter ordinal for a screen drop reason, or `None` when the
/// reason is not one of the three FLOOD checks.
///
/// Deliberately an independent match rather than a reuse of
/// [`crate::screen::screen_reason_drop_index`]: this ordinal indexes a 3-wide
/// per-zone accumulator whose layout is the wire's
/// `syn_flood_events`/`icmp_flood_events`/`udp_flood_events` triple, not the
/// 15-wide per-reason array. The two happen to agree on 0/1/2 today and
/// `flood_reason_index_tracks_the_screen_reason_strings` pins that the REASON
/// STRINGS stay shared — a rename in `screen/mod.rs` that silently un-wired this
/// tally is exactly what that test catches.
#[inline]
pub(in crate::afxdp) fn flood_reason_index(reason: &str) -> Option<usize> {
    Some(match reason {
        "syn-flood" => 0,
        "icmp-flood" => 1,
        "udp-flood" => 2,
        _ => return None,
    })
}

/// Number of per-zone flood families (syn / icmp / udp).
pub(in crate::afxdp) const FLOOD_KINDS: usize = 3;

/// Flat direct-index zone-id → hot-path slot LUT, built at config apply.
/// Structurally identical to `ZoneCounterSlotMap`; see this module's header for
/// why the flood half is coalesced the same way despite being on the drop path.
pub(in crate::afxdp) struct FloodCounterSlotMap {
    slot_of: Box<[u8; 65536]>,
    inverse: [u16; FLOOD_COUNTER_SLOTS],
    /// Per-slot handle to the assigned zone's shared atomic block, resolved
    /// from the zone-id-keyed [`FloodCounterStore`] at build time so the
    /// per-batch fold never locks the store. `None` for an unassigned slot.
    slot_totals: [Option<Arc<FloodTotalsAtomic>>; FLOOD_COUNTER_SLOTS],
    /// True if some configured zone could not be assigned a slot because the
    /// `FLOOD_COUNTER_ASSIGNABLE_SLOTS` capacity was exhausted. Surfaced as
    /// `ProcessStatus.flood_counter_overflow_active`.
    pub(in crate::afxdp) overflow_active: bool,
}

impl Default for FloodCounterSlotMap {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Debug for FloodCounterSlotMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Summarize rather than dumping the 64 KiB LUT.
        let assigned = self.inverse.iter().filter(|&&z| z != 0).count();
        f.debug_struct("FloodCounterSlotMap")
            .field("assigned_zones", &assigned)
            .field("overflow_active", &self.overflow_active)
            .finish()
    }
}

impl FloodCounterSlotMap {
    /// An empty map: every zone resolves to slot 0 (uncounted).
    pub(in crate::afxdp) fn empty() -> Self {
        Self {
            slot_of: Box::new([0u8; 65536]),
            inverse: [0u16; FLOOD_COUNTER_SLOTS],
            slot_totals: std::array::from_fn(|_| None),
            overflow_active: false,
        }
    }

    /// Build the slot map from the configured zone-id set. Slots are assigned
    /// in sorted zone-id order — the SAME order `ZoneCounterSlotMap::build`
    /// uses, so with equal capacity the two families slot identically. A
    /// duplicate or zero id is ignored. Each assigned slot caches its zone's
    /// shared `Arc<FloodTotalsAtomic>` (get-or-create from `store`), so a zone
    /// surviving this apply keeps the same block and its counts never reset or
    /// double across a slot renumber.
    pub(in crate::afxdp) fn build(zone_ids: &[u16], store: &FloodCounterStore) -> Self {
        let mut ids: Vec<u16> = zone_ids.iter().copied().filter(|&z| z != 0).collect();
        ids.sort_unstable();
        ids.dedup();

        let mut slot_of = Box::new([0u8; 65536]);
        let mut inverse = [0u16; FLOOD_COUNTER_SLOTS];
        let mut slot_totals: [Option<Arc<FloodTotalsAtomic>>; FLOOD_COUNTER_SLOTS] =
            std::array::from_fn(|_| None);
        let mut overflow_active = false;
        let mut next_slot = 1usize;
        for zid in ids {
            if next_slot > FLOOD_COUNTER_ASSIGNABLE_SLOTS {
                overflow_active = true;
                break;
            }
            slot_of[zid as usize] = next_slot as u8;
            inverse[next_slot] = zid;
            slot_totals[next_slot] = Some(store.zone_totals(zid));
            next_slot += 1;
        }
        Self {
            slot_of,
            inverse,
            slot_totals,
            overflow_active,
        }
    }

    /// Resolve the hot-path slot for `zone_id` (0 = unassigned / uncounted).
    #[inline]
    pub(in crate::afxdp) fn slot_of(&self, zone_id: u16) -> u8 {
        self.slot_of[zone_id as usize]
    }
}

/// Select the rows publishable on `ProcessStatus.zone_flood_counters`.
///
/// Same two-filter contract as `publishable_zone_rows`: a row survives only when
/// its zone is BOTH still configured AND holds a live hot-path slot.
///
/// The slot filter is the load-bearing one, and it is about a TRANSITION rather
/// than a steady state. The store outlives the slot map — config apply carries
/// it forward and `reconcile` retains every still-configured zone — so a zone
/// that accumulated flood events and is then pushed past capacity by a later
/// config stays configured, keeps its retained nonzero counts, and gets slot 0.
/// Publishing that row would make the Go side mirror a total that can never
/// advance again: a FROZEN flood count that under-reports every subsequent
/// attack while looking perfectly alive. Omitting it makes the zone read
/// "not available" end to end, which is the honest answer, with
/// `flood_counter_overflow_active` carrying the reason.
pub(in crate::afxdp) fn publishable_flood_rows(
    store: &FloodCounterStore,
    slot_map: &FloodCounterSlotMap,
    is_configured: impl Fn(u16) -> bool,
) -> Vec<ZoneFloodCounterStatus> {
    store
        .snapshot()
        .into_iter()
        .filter(|s| is_configured(s.zone_id) && slot_map.slot_of(s.zone_id) != 0)
        .collect()
}

/// Shared cumulative per-zone flood-event totals as three `Relaxed` atomics.
/// One block per configured zone id; the per-batch worker fold `fetch_add`s into
/// it lock-free and the ≤ 1 s status/clear path reads/zeroes it under the store
/// mutex.
#[derive(Debug, Default)]
struct FloodTotalsAtomic {
    syn: AtomicU64,
    icmp: AtomicU64,
    udp: AtomicU64,
}

impl FloodTotalsAtomic {
    #[inline]
    fn add(&self, kind: usize, count: u64) {
        if count == 0 {
            return;
        }
        match kind {
            0 => self.syn.fetch_add(count, Ordering::Relaxed),
            1 => self.icmp.fetch_add(count, Ordering::Relaxed),
            _ => self.udp.fetch_add(count, Ordering::Relaxed),
        };
    }

    /// Independent relaxed loads. Each field is exact; the triple is
    /// eventual-consistent (a snapshot may straddle one in-flight fold), the
    /// same contract `ZoneTotalsAtomic::load` accepts.
    fn load(&self) -> (u64, u64, u64) {
        (
            self.syn.load(Ordering::Relaxed),
            self.icmp.load(Ordering::Relaxed),
            self.udp.load(Ordering::Relaxed),
        )
    }

    /// Zero all three fields in place (operator clear). In place — never dropped
    /// from the store map — so a live slot map's cached `Arc` keeps counting
    /// from zero instead of folding into an orphaned block.
    fn reset(&self) {
        self.syn.store(0, Ordering::Relaxed);
        self.icmp.store(0, Ordering::Relaxed);
        self.udp.store(0, Ordering::Relaxed);
    }
}

/// Coordinator-owned, config-apply-surviving cumulative per-zone flood-event
/// store, keyed by the stable zone id. The mutex guards only the MAP STRUCTURE
/// (get-or-create at config apply, iterate at snapshot/clear/reconcile) — all
/// off the hot path. `Clone` shares the inner `Arc<Mutex>`, so cloning
/// `ForwardingState` keeps every generation pointing at the same totals.
#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct FloodCounterStore {
    totals: Arc<Mutex<FxHashMap<u16, Arc<FloodTotalsAtomic>>>>,
}

impl FloodCounterStore {
    /// Get-or-create the shared atomic block for a stable zone id, under the map
    /// mutex. Config-apply path only; NOT the hot path.
    fn zone_totals(&self, zone_id: u16) -> Arc<FloodTotalsAtomic> {
        let mut totals = self.totals.lock().expect("flood counter store poisoned");
        Arc::clone(totals.entry(zone_id).or_default())
    }

    /// Sparse snapshot for the status wire: one row per zone with any flood
    /// events. Deterministic order (sorted by zone id) for a stable wire.
    pub(in crate::afxdp) fn snapshot(&self) -> Vec<ZoneFloodCounterStatus> {
        let totals = self.totals.lock().expect("flood counter store poisoned");
        let mut out: Vec<ZoneFloodCounterStatus> = totals
            .iter()
            .filter_map(|(&zone_id, t)| {
                let (syn_flood_events, icmp_flood_events, udp_flood_events) = t.load();
                if syn_flood_events == 0 && icmp_flood_events == 0 && udp_flood_events == 0 {
                    return None;
                }
                Some(ZoneFloodCounterStatus {
                    zone_id,
                    syn_flood_events,
                    icmp_flood_events,
                    udp_flood_events,
                })
            })
            .collect();
        out.sort_unstable_by_key(|s| s.zone_id);
        out
    }

    /// Operator clear (`clear_flood_counters` IPC): zero every zone's cumulative
    /// counts so the pre-clear value is not snapped back on the next status
    /// poll. Load-bearing half of the operator clear.
    ///
    /// A cleared zone then reads as NOT POPULATED, not as zero — the snapshot
    /// above omits all-zero rows and the Go side REPLACES its offset map from
    /// that snapshot, so the row is dropped rather than set to 0.
    ///
    /// Resets each block IN PLACE rather than clearing the map, because a live
    /// slot map caches each zone's `Arc`; dropping the map entry would leave
    /// workers folding into an orphaned block the snapshot no longer sees.
    pub(in crate::afxdp) fn clear(&self) {
        let totals = self.totals.lock().expect("flood counter store poisoned");
        for block in totals.values() {
            block.reset();
        }
    }

    /// Drop totals for zones that are no longer configured (config apply
    /// hygiene). A `configured` zone's `Arc` is retained, so a slot map rebuilt
    /// in the same apply resolves the SAME block (no reset/double).
    pub(in crate::afxdp) fn reconcile(&self, configured: &FxHashSet<u16>) {
        self.totals
            .lock()
            .expect("flood counter store poisoned")
            .retain(|zone_id, _| configured.contains(zone_id));
    }

    /// Fold a worker's coalesced per-slot deltas into the shared per-zone
    /// atomics the slot map cached at build time. LOCK-FREE — a straight
    /// `Relaxed` `fetch_add` per touched slot; it does NOT lock `self.totals`.
    fn fold_pending(&self, pending: &FloodPending, slot_map: &FloodCounterSlotMap) {
        for slot in 1..FLOOD_COUNTER_SLOTS {
            let Some(totals) = &slot_map.slot_totals[slot] else {
                continue;
            };
            for (kind, counts) in pending.counts.iter().enumerate() {
                totals.add(kind, counts[slot]);
            }
        }
    }

    /// Test-only handle to the map mutex, so a test can hold the shared store
    /// lock (as the ≤ 1 s snapshot/clear path does) and prove the per-batch fold
    /// still makes progress — the lock-freedom invariant.
    #[cfg(test)]
    fn lock_totals_for_test(
        &self,
    ) -> std::sync::MutexGuard<'_, FxHashMap<u16, Arc<FloodTotalsAtomic>>> {
        self.totals.lock().expect("flood counter store poisoned")
    }
}

/// Per-worker thread-local dense slot accumulator. Touched only by the owning
/// worker thread on the drop path; folded into the shared store per RX batch.
struct FloodPending {
    counts: [[u64; FLOOD_COUNTER_SLOTS]; FLOOD_KINDS],
    touched: bool,
}

impl Default for FloodPending {
    fn default() -> Self {
        Self {
            counts: [[0; FLOOD_COUNTER_SLOTS]; FLOOD_KINDS],
            touched: false,
        }
    }
}

impl FloodPending {
    fn reset(&mut self) {
        if !self.touched {
            return;
        }
        self.counts = [[0; FLOOD_COUNTER_SLOTS]; FLOOD_KINDS];
        self.touched = false;
    }
}

thread_local! {
    static FLOOD_PENDING: RefCell<FloodPending> = RefCell::new(FloodPending::default());
}

/// Record one screen DROP against its ingress zone, when `reason` is one of the
/// three flood checks. Called from `BatchCounters::record_screen_drop`, so every
/// screen drop site feeds this without the site having to know about it — the
/// same centralization that keeps the aggregate and per-reason tallies from
/// drifting.
///
/// A non-flood reason, an unzoned packet, or a zone with no slot contributes
/// nothing. Cost on a flood drop: one flat-LUT read plus a thread-local
/// accumulate — no hash, no atomic, no allocation.
#[inline]
pub(in crate::afxdp) fn record_zone_flood_drop(
    slot_map: &FloodCounterSlotMap,
    zone_id: u16,
    reason: &str,
) {
    let Some(kind) = flood_reason_index(reason) else {
        return;
    };
    let slot = slot_map.slot_of(zone_id);
    if slot == 0 {
        return;
    }
    FLOOD_PENDING.with(|pending| {
        let mut p = pending.borrow_mut();
        let s = slot as usize;
        p.counts[kind][s] = p.counts[kind][s].saturating_add(1);
        p.touched = true;
    });
}

/// Fold this worker thread's coalesced per-zone flood deltas into the shared
/// store. Called once per RX batch alongside `flush_recorded_zone_counters`.
/// `slot_map` must be the SAME map the intervening `record_zone_flood_drop`
/// calls used (guaranteed: both read the loop iteration's `forwarding`
/// snapshot), so each slot's cached atomic block matches the zone it
/// accumulated for.
pub(in crate::afxdp) fn flush_recorded_flood_counters(
    store: &FloodCounterStore,
    slot_map: &FloodCounterSlotMap,
) {
    FLOOD_PENDING.with(|pending| {
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
    //! ## Why there is no serialization guard here, and why none is needed
    //!
    //! These tests assert EXACT counter values, which is normally a #6819-class
    //! flake risk (concurrent tests mutating a shared counter). It is not one
    //! here, and the reason is worth recording so nobody adds a mutex that
    //! protects nothing — or, worse, deletes a test because they assume it is
    //! flaky.
    //!
    //! There is no process-global counter in this module. [`FloodCounterStore`]
    //! is an ordinary value; every test builds its own with
    //! `FloodCounterStore::default()`, so no two tests can reach the same
    //! totals. The only state that LOOKS shared is the [`FLOOD_PENDING`]
    //! thread-local accumulator.
    //!
    //! That one is per-test in practice: libtest runs each test on its own
    //! thread even under `--test-threads=1` (the `make test-rust` invocation),
    //! so each test gets a fresh `FLOOD_PENDING`. Verified directly rather than
    //! assumed — a probe pair in which the first test deliberately recorded
    //! WITHOUT flushing and the second flushed into a fresh store observed
    //! distinct thread ids and ZERO leaked rows.
    //!
    //! Two consequences. Residue cannot cross a test boundary, so a test that
    //! records without flushing cannot corrupt a neighbour. And a
    //! `record`/`flush` pair must still be matched WITHIN a test against the
    //! SAME slot map — the accumulator is slot-indexed, so flushing pending
    //! deltas through a DIFFERENT map mis-attributes them to whatever zone now
    //! owns that slot.

    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    /// The three flood reason strings must be exactly the ones the screen
    /// module emits. `flood_reason_index` is an independent match (it indexes a
    /// different, 3-wide accumulator), so nothing else stops a rename in
    /// `screen/mod.rs` from silently un-wiring the per-zone tally: the drop
    /// would still be counted in the aggregate and this map would just stop
    /// matching.
    #[test]
    fn flood_reason_index_tracks_the_screen_reason_strings() {
        for reason in ["syn-flood", "icmp-flood", "udp-flood"] {
            // Assert the reason is a KNOWN SCREEN REASON, not that the two
            // ordinals coincide. The contract this test exists to protect is
            // the STRING: a rename in `screen/mod.rs` would silently stop the
            // per-zone tally matching while the aggregate kept counting.
            //
            // Deliberately NOT `assert_eq!(flood_reason_index(r),
            // screen_reason_drop_index(r))`. They agree on 0/1/2 today, but the
            // screen ordinals index a 15-wide Go-facing array and this indexes a
            // 3-wide accumulator whose layout is the wire's syn/icmp/udp triple
            // (see the `flood_reason_index` doc). Pinning equality would make a
            // legitimate renumber of the screen ordinals red HERE, inviting
            // someone to "fix" it by renumbering `flood_reason_index` — which
            // would silently permute the flood wire fields.
            assert!(
                flood_reason_index(reason).is_some(),
                "flood reason {reason:?} must have a per-zone flood ordinal"
            );
            assert!(
                crate::screen::screen_reason_drop_index(reason).is_some(),
                "flood reason {reason:?} is no longer a known screen reason — a \
                 rename in screen/mod.rs has un-wired the per-zone flood tally \
                 while leaving the aggregate counting"
            );
        }
        // Every other screen reason must be excluded — the per-zone flood
        // surface renders exactly three counters.
        for reason in [
            "port-scan",
            "ip-sweep",
            "land-attack",
            "ping-of-death",
            "teardrop",
            "tcp-syn-fin",
            "tcp-no-flag",
            "tcp-fin-no-ack",
            "winnuke",
            "ip-source-route",
            "syn-frag",
            "session-limit-src",
            "session-limit-dst",
            "syn-cookie",
            "strict-syn-check",
            "icmp-fragment",
        ] {
            assert_eq!(
                flood_reason_index(reason),
                None,
                "{reason:?} is not a flood check and must not feed the per-zone \
                 flood counters"
            );
        }
    }

    #[test]
    fn build_assigns_slots_for_wide_stable_hash_zone_ids() {
        // #3075 stable name-hash ids span [1, 65533]; a dense id-indexed table
        // would drop these.
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[40000, 7, 65533], &store);
        assert!(!map.overflow_active);
        assert_eq!(map.slot_of(7), 1);
        assert_eq!(map.slot_of(40000), 2);
        assert_eq!(map.slot_of(65533), 3);
        assert_eq!(map.slot_of(0), 0);
        assert_eq!(map.slot_of(123), 0);
    }

    #[test]
    fn build_sets_overflow_past_capacity() {
        let store = FloodCounterStore::default();
        let ids: Vec<u16> = (1..=(FLOOD_COUNTER_ASSIGNABLE_SLOTS as u16 + 5)).collect();
        let map = FloodCounterSlotMap::build(&ids, &store);
        assert!(map.overflow_active);
        let assigned = (1..=65535u16).filter(|&z| map.slot_of(z) != 0).count();
        assert_eq!(assigned, FLOOD_COUNTER_ASSIGNABLE_SLOTS);
    }

    /// The traffic and flood slot maps must agree zone-for-zone. Equal capacity
    /// plus the same sorted assignment order is what makes that true; this pins
    /// the observable consequence rather than the constants.
    #[test]
    fn flood_and_traffic_slot_maps_cover_the_same_zones() {
        use crate::afxdp::zone_counters::{ZoneCounterSlotMap, ZoneCounterStore};
        let ids: Vec<u16> = (1..=(FLOOD_COUNTER_ASSIGNABLE_SLOTS as u16 + 3))
            .map(|z| z.wrapping_mul(37).max(1))
            .collect();
        let flood = FloodCounterSlotMap::build(&ids, &FloodCounterStore::default());
        let traffic = ZoneCounterSlotMap::build(&ids, &ZoneCounterStore::default());
        assert_eq!(flood.overflow_active, traffic.overflow_active);
        for &z in &ids {
            assert_eq!(
                flood.slot_of(z) != 0,
                traffic.slot_of(z) != 0,
                "zone {z} is slotted for one counter family but not the other — \
                 an operator would see live volume with 'not available' flood \
                 counts (or the reverse) and nothing explaining the asymmetry"
            );
        }
    }

    #[test]
    fn record_flush_snapshot_accumulates_each_flood_family() {
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[100, 200], &store);
        record_zone_flood_drop(&map, 100, "syn-flood");
        record_zone_flood_drop(&map, 100, "syn-flood");
        record_zone_flood_drop(&map, 100, "icmp-flood");
        record_zone_flood_drop(&map, 200, "udp-flood");
        flush_recorded_flood_counters(&store, &map);

        let snap = store.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].zone_id, 100);
        assert_eq!(snap[0].syn_flood_events, 2);
        assert_eq!(snap[0].icmp_flood_events, 1);
        assert_eq!(snap[0].udp_flood_events, 0);
        assert_eq!(snap[1].zone_id, 200);
        assert_eq!(snap[1].syn_flood_events, 0);
        assert_eq!(snap[1].udp_flood_events, 1);
    }

    #[test]
    fn non_flood_reasons_and_unslotted_zones_are_uncounted() {
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[100], &store);
        // A real screen drop, but not a FLOOD check.
        record_zone_flood_drop(&map, 100, "port-scan");
        // A flood check on an unconfigured zone, and on the unzoned id 0.
        record_zone_flood_drop(&map, 999, "syn-flood");
        record_zone_flood_drop(&map, 0, "syn-flood");
        flush_recorded_flood_counters(&store, &map);
        assert!(
            store.snapshot().is_empty(),
            "non-flood reasons and unslotted zones must contribute nothing: {:?}",
            store.snapshot()
        );
    }

    #[test]
    fn clear_resets_totals_and_keeps_counting() {
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[100], &store);
        record_zone_flood_drop(&map, 100, "syn-flood");
        flush_recorded_flood_counters(&store, &map);
        assert_eq!(store.snapshot().len(), 1);
        store.clear();
        assert!(store.snapshot().is_empty());
        // The clear resets the atomics IN PLACE (keeps the map entry), so the
        // live slot map's cached Arc keeps counting from zero after the clear.
        record_zone_flood_drop(&map, 100, "syn-flood");
        flush_recorded_flood_counters(&store, &map);
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].syn_flood_events, 1);
    }

    #[test]
    fn reconcile_drops_removed_zones() {
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[100, 200], &store);
        record_zone_flood_drop(&map, 100, "syn-flood");
        record_zone_flood_drop(&map, 200, "udp-flood");
        flush_recorded_flood_counters(&store, &map);
        assert_eq!(store.snapshot().len(), 2);
        let keep: FxHashSet<u16> = [100u16].into_iter().collect();
        store.reconcile(&keep);
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].zone_id, 100);
    }

    #[test]
    fn surviving_zone_keeps_the_same_atomic_block_across_a_slot_renumber() {
        let store = FloodCounterStore::default();
        let map1 = FloodCounterSlotMap::build(&[200], &store);
        assert_eq!(map1.slot_of(200), 1);
        record_zone_flood_drop(&map1, 200, "syn-flood");
        flush_recorded_flood_counters(&store, &map1);
        // Config apply adds zone 100 (< 200), which takes slot 1 and pushes 200
        // to slot 2 — a renumber. Store carried forward (same instance here).
        let map2 = FloodCounterSlotMap::build(&[100, 200], &store);
        assert_eq!(map2.slot_of(200), 2);
        record_zone_flood_drop(&map2, 200, "syn-flood");
        flush_recorded_flood_counters(&store, &map2);
        let snap = store.snapshot();
        let z200 = snap.iter().find(|s| s.zone_id == 200).expect("zone 200");
        // 2 events total across the renumber — not reset to 1, not doubled.
        assert_eq!(z200.syn_flood_events, 2);
    }

    /// A zone that WAS counted and is then pushed past the hot-path slot
    /// capacity by a later config must STOP being published. Its retained
    /// counts survive in the carried-forward store, so publishing them would
    /// mirror a total that can never advance again.
    #[test]
    fn populated_zone_stops_publishing_once_pushed_past_capacity() {
        let store = FloodCounterStore::default();
        const Z: u16 = 50675; // config::StableZoneID("trust")
        let map1 = FloodCounterSlotMap::build(&[Z], &store);
        assert_ne!(map1.slot_of(Z), 0);
        record_zone_flood_drop(&map1, Z, "syn-flood");
        record_zone_flood_drop(&map1, Z, "syn-flood");
        flush_recorded_flood_counters(&store, &map1);
        let published = publishable_flood_rows(&store, &map1, |_| true);
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].syn_flood_events, 2);

        // Apply 2: enough LOWER ids to consume every assignable slot.
        let mut ids: Vec<u16> = (1..=(FLOOD_COUNTER_ASSIGNABLE_SLOTS as u16)).collect();
        ids.push(Z);
        let configured: FxHashSet<u16> = ids.iter().copied().collect();
        store.reconcile(&configured);
        let map2 = FloodCounterSlotMap::build(&ids, &store);
        assert!(map2.overflow_active);
        assert_eq!(map2.slot_of(Z), 0);

        // The retained counts are still in the store — asserting this keeps the
        // test honest: it is NOT passing because the data vanished.
        let raw: Vec<_> = store
            .snapshot()
            .into_iter()
            .filter(|s| s.zone_id == Z)
            .collect();
        assert_eq!(raw.len(), 1);
        assert_eq!(raw[0].syn_flood_events, 2);

        let published = publishable_flood_rows(&store, &map2, |zid| configured.contains(&zid));
        assert!(
            !published.iter().any(|s| s.zone_id == Z),
            "a populated zone that lost its slot must STOP publishing — otherwise \
             its retained flood count freezes and under-reports forever: {published:?}"
        );
    }

    /// The publish filter must not over-reach: a zone that still holds a slot
    /// keeps publishing while a SIBLING overflows, and the configured predicate
    /// is independently load-bearing.
    #[test]
    fn publish_filter_drops_only_the_unslotted_and_unconfigured() {
        let store = FloodCounterStore::default();
        let mut ids: Vec<u16> = (1..=(FLOOD_COUNTER_ASSIGNABLE_SLOTS as u16)).collect();
        const OVERFLOWED: u16 = 65533;
        ids.push(OVERFLOWED);
        let map = FloodCounterSlotMap::build(&ids, &store);
        assert!(map.overflow_active);
        assert_eq!(map.slot_of(OVERFLOWED), 0);

        record_zone_flood_drop(&map, 1, "syn-flood");
        record_zone_flood_drop(&map, 2, "icmp-flood");
        flush_recorded_flood_counters(&store, &map);
        // Give the overflowed zone retained counts directly in the store, as a
        // carried-forward apply would, so it is a real publish candidate.
        let seed = FloodCounterSlotMap::build(&[OVERFLOWED], &store);
        record_zone_flood_drop(&seed, OVERFLOWED, "udp-flood");
        flush_recorded_flood_counters(&store, &seed);

        // Zone 2 has a slot AND traffic but is NOT configured.
        let configured: FxHashSet<u16> = [1u16, OVERFLOWED].into_iter().collect();
        let published = publishable_flood_rows(&store, &map, |z| configured.contains(&z));
        assert!(
            published.iter().any(|s| s.zone_id == 1),
            "a slotted, configured zone must keep publishing during overflow: {published:?}"
        );
        assert!(
            !published.iter().any(|s| s.zone_id == OVERFLOWED),
            "a configured zone with retained counts but NO slot must be dropped: {published:?}"
        );
        assert!(
            !published.iter().any(|s| s.zone_id == 2),
            "zone 2 holds a slot and has counts but is NOT configured, so the \
             configured predicate must still drop it: {published:?}"
        );
    }

    #[test]
    fn concurrent_workers_fold_lock_free_without_lost_counts() {
        const WORKERS: u64 = 8;
        const PER_WORKER: u64 = 20_000;
        let store = FloodCounterStore::default();
        let map = Arc::new(FloodCounterSlotMap::build(&[100], &store));

        let mut handles = Vec::new();
        for _ in 0..WORKERS {
            let map = Arc::clone(&map);
            let store = store.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..PER_WORKER {
                    record_zone_flood_drop(&map, 100, "syn-flood");
                    flush_recorded_flood_counters(&store, &map);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let snap = store.snapshot();
        let z100 = snap.iter().find(|s| s.zone_id == 100).expect("zone 100");
        assert_eq!(z100.syn_flood_events, WORKERS * PER_WORKER);
    }

    #[test]
    fn worker_fold_makes_progress_while_status_reader_holds_the_lock() {
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[100], &store);

        // A second thread parks on the shared store mutex for 300 ms — standing
        // in for the ≤ 1 s status/clear path holding it under contention.
        let held = store.clone();
        let (locked_tx, locked_rx) = mpsc::channel();
        let holder = thread::spawn(move || {
            let guard = held.lock_totals_for_test();
            locked_tx.send(()).unwrap();
            thread::sleep(Duration::from_millis(300));
            drop(guard);
        });
        locked_rx.recv().unwrap();

        let start = Instant::now();
        record_zone_flood_drop(&map, 100, "syn-flood");
        flush_recorded_flood_counters(&store, &map);
        let elapsed = start.elapsed();

        holder.join().unwrap();
        assert!(
            elapsed < Duration::from_millis(150),
            "per-batch worker fold blocked on the shared store lock for {elapsed:?} \
             — the fold must be lock-free. A per-batch global-mutex fold would \
             block until the status reader released the lock (~300 ms)."
        );
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].syn_flood_events, 1);
    }
}
