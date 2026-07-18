//! #5288: bounded, per-worker rate limiter for kernel neighbor-table
//! programming on the data-path ARP/NDP learn.
//!
//! ## Why
//! `stage_link_layer_classify` learns a dynamic neighbor from every accepted
//! ARP reply / NDP Neighbor Advertisement and then calls
//! [`super::neighbor::add_kernel_neighbor`], which — per accepted advert —
//! allocates request + IP `Vec`s, opens a raw `AF_NETLINK` socket, `sendto`s
//! an `RTM_NEWNEIGH`, and closes the socket synchronously ON THE XSK WORKER.
//! Before this limiter the call fired UNCONDITIONALLY, even for a same-key /
//! same-MAC repeat whose `insert_if_changed` result was discarded. An attacker
//! streaming valid ARP replies / NAs for a non-owned unicast IP therefore drove
//! a `socket()`/`sendto()`/`close()` + allocations per frame — forwarding
//! starvation on the affected queues (a DoS amplification).
//!
//! ## What this bounds
//! A fixed-size, direct-mapped table of [`KERNEL_NEIGH_LIMITER_SLOTS`] slots,
//! each recording the last `(key -> mac)` this worker actually programmed and
//! WHEN. The decision ([`KernelNeighborProgramLimiter::should_program`]) is a
//! pure function of the slot + the advert, with no allocation and no syscall,
//! so it is unit-testable in isolation (the syscall stays in
//! `add_kernel_neighbor`).
//!
//! * **Same-key/same-MAC repeat** → skipped. The slot already records the exact
//!   binding, and/or the authoritative userspace neighbor map was unchanged by
//!   this advert (`map_changed == false`), which proves the kernel was already
//!   told. This is the primary amplification fix.
//! * **Changed-flood (MAC cycling on one IP)** → those adverts all hash to the
//!   SAME slot, which drives at most one kernel program per
//!   [`KERNEL_NEIGH_MIN_INTERVAL_NS`].
//! * **Many-distinct-IP flood** → because the slot table is FIXED size, the
//!   AGGREGATE per-worker netlink rate is bounded to
//!   `≤ SLOTS / MIN_INTERVAL` programs regardless of how many distinct source
//!   IPs an attacker cycles.
//!
//! ## Not losing a real change
//! A genuine MAC change is never silently lost:
//! * In steady state, same-binding re-adverts return early WITHOUT touching the
//!   slot timestamp, so the timestamp reflects only the last ACTUAL program
//!   (long ago). A real change after steady state is therefore NOT rate-limited
//!   — it programs on its first advert.
//! * If a change IS rate-limited (only possible amid a burst of distinct
//!   bindings within one interval), the slot keeps the OLD programmed mac, so
//!   the binding stays "owed": the next advert for that key — even a same-MAC
//!   one the userspace map already absorbed (`map_changed == false`) — still
//!   programs it once the interval elapses. The latest desired state is retried,
//!   not dropped. (The kernel install is `NUD_STALE` and the neigh monitor keeps
//!   userspace ↔ kernel coupled, so any residual lag self-heals regardless.)
//!
//! ## Placement
//! Per-worker, owned by [`super::worker::BindingWorker`] and touched ONLY by the
//! owning worker thread (the ARP/NDP learn runs on the XSK poll loop), so no
//! `Arc`/`Mutex`/cross-core sync — consistent with the per-queue AF_XDP model
//! and the sibling `pending_neigh` / `neg_neigh_cache` per-worker structures.
//! Neighbor programming is a LOCAL kernel-table operation; it is NOT HA /
//! session-sync state, so a per-worker limiter needs no peer coordination.
//!
//! Persistent-socket + off-worker coalescing of the netlink send itself is a
//! deferred follow-up (out of scope for #5288); this limiter only ensures a
//! repeat/flood no longer does unbounded socket work on the XSK worker.

use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

/// Number of direct-mapped slots. Power of two so the index is a single mask.
/// 256 slots is far more than the distinct next-hops a worker legitimately
/// programs, so collisions between live neighbors are rare, while the fixed
/// count is what caps the aggregate netlink rate under a many-IP flood.
pub(in crate::afxdp) const KERNEL_NEIGH_LIMITER_SLOTS: usize = 256;
const _: () = assert!(KERNEL_NEIGH_LIMITER_SLOTS.is_power_of_two());

/// Minimum interval between two kernel-neighbor programs a single slot may
/// drive. 50 ms is far longer than any legitimate neighbor re-advertisement
/// cadence yet short enough that a genuine MAC change is reflected within one
/// interval even in the (flood-only) rate-limited-then-retried case.
pub(in crate::afxdp) const KERNEL_NEIGH_MIN_INTERVAL_NS: u64 = 50_000_000; // 50 ms

/// One direct-mapped slot: the last binding this worker programmed for the
/// key that currently owns the slot, and when.
#[derive(Clone, Copy)]
struct Slot {
    /// `None` only for a never-fired slot (fresh worker). Once a slot programs
    /// anything it holds `Some(key)` for the rest of the worker's life.
    key: Option<(i32, IpAddr)>,
    /// The MAC last programmed for `key`. Meaningless when `key` is `None`.
    mac: [u8; 6],
    /// Monotonic-nanos timestamp of the last ACTUAL program driven by this slot.
    last_program_ns: u64,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            key: None,
            mac: [0u8; 6],
            last_program_ns: 0,
        }
    }
}

fn slot_index(key: &(i32, IpAddr)) -> usize {
    let mut hasher = FxHasher::default();
    key.hash(&mut hasher);
    (hasher.finish() as usize) & (KERNEL_NEIGH_LIMITER_SLOTS - 1)
}

/// Per-worker gate for `add_kernel_neighbor`. See the module docs.
pub(in crate::afxdp) struct KernelNeighborProgramLimiter {
    /// Boxed so the ~12 KiB table lives on the heap (allocated once at worker
    /// construction, never on the packet path) instead of inline in the large
    /// `BindingWorker`.
    slots: Box<[Slot; KERNEL_NEIGH_LIMITER_SLOTS]>,
    min_interval_ns: u64,
}

impl KernelNeighborProgramLimiter {
    pub(in crate::afxdp) fn new() -> Self {
        Self::with_interval(KERNEL_NEIGH_MIN_INTERVAL_NS)
    }

    fn with_interval(min_interval_ns: u64) -> Self {
        Self {
            slots: Box::new([Slot::default(); KERNEL_NEIGH_LIMITER_SLOTS]),
            min_interval_ns,
        }
    }

    /// Decide whether a data-path ARP/NDP learn of `(key -> mac)` should
    /// program the kernel neighbor table now, recording the decision.
    ///
    /// `map_changed` is the `ShardedNeighborMap::insert_if_changed` result for
    /// this advert: `false` means the authoritative userspace neighbor map
    /// already held this exact `(key -> mac)`, so the kernel was already told
    /// (by us or by the neigh monitor). `now_ns` is a CLOCK_MONOTONIC nanos
    /// stamp.
    ///
    /// Returns `true` at most once per key per [`Self::min_interval_ns`] for a
    /// changed binding, and never for a proven-present repeat. See the module
    /// docs for the "not losing a real change" argument.
    pub(in crate::afxdp) fn should_program(
        &mut self,
        key: (i32, IpAddr),
        mac: [u8; 6],
        map_changed: bool,
        now_ns: u64,
    ) -> bool {
        let slot = &mut self.slots[slot_index(&key)];
        let exact_present = slot.key == Some(key) && slot.mac == mac;
        // `owes_other`: the slot holds THIS key with a DIFFERENT (stale) mac —
        // a change we have not yet pushed to the kernel (a prior tick may have
        // rate-limited it). Must never be skipped, or the latest desired state
        // would be lost.
        let owes_other = slot.key == Some(key) && slot.mac != mac;
        // Skip when the kernel already holds this exact binding and we owe
        // nothing newer. Either proof of "already present" suffices: our slot
        // recorded (key, mac), OR the userspace map was unchanged by this
        // advert. `!map_changed` also catches a repeat whose slot was evicted
        // by a colliding key, avoiding a redundant program there.
        if (exact_present || !map_changed) && !owes_other {
            return false;
        }
        // Rate cap: a slot that has already fired drives at most one program
        // per interval — bounding a per-key MAC-cycling flood AND, via the
        // fixed slot count, the aggregate per-worker netlink rate under a
        // many-IP flood. A never-fired slot is exempt so its zero timestamp
        // does not gate the first real program (robust even if the monotonic
        // clock is still small just after boot). Because a rate-limited change
        // leaves `slot.mac` at the OLD value, the owed binding is retried on a
        // later advert.
        if slot.key.is_some()
            && now_ns.saturating_sub(slot.last_program_ns) < self.min_interval_ns
        {
            return false;
        }
        slot.key = Some(key);
        slot.mac = mac;
        slot.last_program_ns = now_ns;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const MIN: u64 = KERNEL_NEIGH_MIN_INTERVAL_NS;
    // A realistic monotonic-nanos base (well past one interval) so the
    // never-fired exemption is not the thing under test.
    const T0: u64 = 1_000 * KERNEL_NEIGH_MIN_INTERVAL_NS;

    fn v4(last: u8) -> (i32, IpAddr) {
        (11, IpAddr::V4(Ipv4Addr::new(172, 16, 80, last)))
    }
    fn mac(tag: u8) -> [u8; 6] {
        [0x02, 0, 0, 0, 0, tag]
    }

    /// Drive N adverts of the SAME (key, mac) through the limiter exactly as
    /// `stage_link_layer_classify` would: the first advert reports
    /// `map_changed == true` (first insert), every repeat reports
    /// `map_changed == false` (the userspace map already held the binding).
    /// Returns how many times the kernel-program decision fired.
    fn program_count_for_identical_repeats(n: usize) -> usize {
        let mut lim = KernelNeighborProgramLimiter::new();
        let key = v4(9);
        let m = mac(0x09);
        let mut fired = 0usize;
        for i in 0..n {
            let map_changed = i == 0;
            // Same tick — repeats stream in far faster than MIN.
            if lim.should_program(key, m, map_changed, T0 + i as u64) {
                fired += 1;
            }
        }
        fired
    }

    /// #5288 FAIL-ON-REVERT. A same-key/same-MAC repeat flood must drive the
    /// kernel-program decision exactly ONCE across N identical accepted
    /// adverts — NOT once per advert. Reverting the gate in `should_program`
    /// (so it programs on every call) makes this count `N`, failing the
    /// `assert_eq!(.., 1)` RED. This is the DoS amplification the fix removes.
    #[test]
    fn identical_repeat_flood_programs_once_5288() {
        for n in [1usize, 2, 8, 64, 1000] {
            let fired = program_count_for_identical_repeats(n);
            assert_eq!(
                fired, 1,
                "a flood of {n} identical accepted adverts must program the \
                 kernel neighbor ONCE (#5288), not {n} times — the discarded \
                 insert_if_changed repeat was the amplification"
            );
        }
    }

    /// A MAC-cycling flood on ONE IP (attacker rotating the advertised MAC to
    /// defeat the same-MAC gate) is capped by the per-slot rate limit: at most
    /// one program per interval, regardless of how many distinct MACs stream in
    /// within that interval.
    #[test]
    fn mac_cycling_flood_on_one_ip_is_rate_capped_5288() {
        let mut lim = KernelNeighborProgramLimiter::new();
        let key = v4(9);
        let mut fired = 0usize;
        // 500 adverts within one interval, each a DIFFERENT mac (every one is a
        // genuine map change).
        for i in 0..500u64 {
            let m = [0x02, 0, 0, 0, (i >> 8) as u8, i as u8];
            if lim.should_program(key, m, true, T0 + i) {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 1,
            "a MAC-cycling flood on one IP within a single interval must be \
             capped to one kernel program (#5288)"
        );
    }

    /// The aggregate per-worker netlink rate under a many-distinct-IP flood is
    /// bounded by the fixed slot count: within one interval, no more than
    /// SLOTS programs fire even for far more distinct IPs.
    #[test]
    fn many_ip_flood_bounded_by_slot_count_5288() {
        let mut lim = KernelNeighborProgramLimiter::new();
        let mut fired = 0usize;
        // 4096 distinct /16 hosts, one advert each, all within one interval.
        for i in 0..4096u32 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8));
            if lim.should_program((11, ip), mac(0x11), true, T0 + i as u64) {
                fired += 1;
            }
        }
        assert!(
            fired <= KERNEL_NEIGH_LIMITER_SLOTS,
            "aggregate programs within one interval ({fired}) must be bounded \
             by the fixed slot count ({KERNEL_NEIGH_LIMITER_SLOTS}) (#5288)"
        );
    }

    /// A genuine MAC change after a steady-state period longer than one
    /// interval is programmed IMMEDIATELY — it is never rate-limited, because
    /// steady-state same-binding re-adverts do not touch the slot timestamp
    /// (they return early via the exact-repeat gate). This is the "don't drop
    /// legitimate updates" guarantee: only the last ACTUAL program gates the
    /// rate, and in real deployments a neighbor sits stable for far longer than
    /// one interval between MAC changes.
    #[test]
    fn genuine_change_after_steady_state_programs_immediately() {
        let mut lim = KernelNeighborProgramLimiter::new();
        let key = v4(5);
        // Learn MAC A at T0 (the last ACTUAL program).
        assert!(lim.should_program(key, mac(0xAA), true, T0));
        // A run of same-binding re-adverts spread over well more than one
        // interval (1 ms apart, ~2×MIN total) — all skipped, none touch the
        // slot timestamp.
        let step = 1_000_000u64; // 1 ms
        let count = (2 * MIN / step) + 10;
        for i in 1..=count {
            assert!(!lim.should_program(key, mac(0xAA), false, T0 + i * step));
        }
        // A real failover to MAC B, one interval past the LAST re-advert but
        // ~2×MIN past the last PROGRAM (at T0) — must program now.
        let change_at = T0 + (count + 1) * step;
        assert!(
            change_at.saturating_sub(T0) >= MIN,
            "test setup: change must land more than one interval past the \
             last program"
        );
        assert!(
            lim.should_program(key, mac(0xBB), true, change_at),
            "a genuine MAC change must program immediately; steady-state \
             re-adverts must not have consumed the rate budget"
        );
    }

    /// A change that IS rate-limited (only possible amid a flood) is not lost:
    /// the owed binding is retried on the next advert once the interval
    /// elapses, EVEN when that advert reports `map_changed == false` (the
    /// userspace map already absorbed the new MAC).
    #[test]
    fn rate_limited_change_is_retried_not_lost() {
        let mut lim = KernelNeighborProgramLimiter::new();
        let key = v4(7);
        // Program MAC A at T0 (consumes the slot's rate budget).
        assert!(lim.should_program(key, mac(0xAA), true, T0));
        // A change to MAC B arrives within the interval → rate-limited (skip),
        // but the userspace map moved to B (`map_changed == true`).
        assert!(!lim.should_program(key, mac(0xBB), true, T0 + 1));
        // Subsequent B re-adverts within the interval report the map as
        // unchanged — still skipped, but the binding stays owed.
        assert!(!lim.should_program(key, mac(0xBB), false, T0 + 2));
        // Once the interval elapses, the owed B is programmed even though the
        // map is unchanged — the latest desired state is retried, not dropped.
        assert!(
            lim.should_program(key, mac(0xBB), false, T0 + MIN),
            "a rate-limited genuine change must be retried after the interval, \
             not silently lost (#5288 no-loss guarantee)"
        );
    }

    /// After programming, a periodic refresh of the SAME binding fires again
    /// only once the interval has elapsed (bounded refresh), and same-binding
    /// adverts in between are free (no netlink, no rate consumption).
    #[test]
    fn same_binding_refresh_is_bounded() {
        let mut lim = KernelNeighborProgramLimiter::new();
        let key = v4(3);
        let m = mac(0x33);
        assert!(lim.should_program(key, m, true, T0));
        // In-interval repeats: skipped.
        assert!(!lim.should_program(key, m, false, T0 + 1));
        assert!(!lim.should_program(key, m, false, T0 + MIN - 1));
        // A same-MAC advert after the interval whose map read is UNCHANGED is
        // still an exact repeat the kernel already holds — skipped (the
        // `map_changed == false` proof), so a slow trickle of gratuitous ARPs
        // never re-programs.
        assert!(!lim.should_program(key, m, false, T0 + MIN));
    }

    /// IPv6 (NDP NA) keys work the same way.
    #[test]
    fn ipv6_repeat_flood_programs_once() {
        let mut lim = KernelNeighborProgramLimiter::new();
        let key = (24, IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x42)));
        let m = mac(0x42);
        assert!(lim.should_program(key, m, true, T0));
        for i in 1..64u64 {
            assert!(!lim.should_program(key, m, false, T0 + i));
        }
    }
}
