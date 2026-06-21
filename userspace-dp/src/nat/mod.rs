// NAT runtime module — split per #1542.
//
// The previous single-file `userspace-dp/src/nat.rs` (~1605 LOC)
// mixed six independent concerns: NatDecision (the cross-cutting
// output type), source NAT rule parsing/matching, pool-mode port
// allocator + persistent lease state machine, destination NAT
// table, static 1:1 NAT, and pool status aggregation. The split
// localizes the allocator's rollback/release/expiration invariants
// to `allocator.rs`, keeps DNAT and static NAT tables in their own
// files, and aggregates pool status alongside the cross-cutting
// type at the module root.
//
// Submodules are intentionally private; `mod.rs` is the curated
// public namespace and re-exports the `pub(crate)` symbols that
// external callers reach as `crate::nat::*`. Cross-submodule
// internal items use `pub(super)` and are NOT re-exported here.

use crate::protocol::NatRuleCounterStatus;
use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

mod allocator;
mod destination;
mod source;
mod static_nat;
mod status;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub(crate) use allocator::{PortAllocator, PortAllocatorSnapshot};
pub(crate) use destination::{DnatKey, DnatTable, DnatValue};
pub(crate) use source::{
    SourceNatFailure, SourceNatFailureReason, SourceNatFlowKey, SourceNatLookup, SourceNatRule,
    match_source_nat, match_source_nat_result, match_source_nat_result_for_tuple,
    parse_source_nat_rules, parse_source_nat_rules_with_previous, release_source_nat_allocation,
    rollback_source_nat_allocation,
};
pub(crate) use static_nat::{StaticNatEntry, StaticNatTable};
pub(crate) use status::source_nat_pool_statuses;

/// NatDecision is the cross-cutting output type for every NAT
/// concern (DNAT, SNAT, static, NAT64, NPTv6). It lives at the
/// `nat` module root because it is the only type all submodules
/// produce or consume. Wire-serialized over the HA fabric via
/// `SessionDecision`/`SessionDelta`; field shape and derive set
/// must be preserved bit-for-bit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NatDecision {
    pub(crate) rewrite_src: Option<IpAddr>,
    pub(crate) rewrite_dst: Option<IpAddr>,
    pub(crate) rewrite_src_port: Option<u16>,
    pub(crate) rewrite_dst_port: Option<u16>,
    /// When true, this is a NAT64 cross-address-family translation.
    /// The forward session key is IPv6 and the reverse session key is IPv4
    /// (or vice versa for the return direction).
    pub(crate) nat64: bool,
    /// When true, this is an NPTv6 (RFC 6296) stateless prefix translation.
    /// No L4 checksum update is needed -- the prefix rewrite is checksum-neutral.
    pub(crate) nptv6: bool,
}

impl NatDecision {
    pub(crate) fn reverse(
        self,
        original_src: IpAddr,
        original_dst: IpAddr,
        original_src_port: u16,
        original_dst_port: u16,
    ) -> Self {
        Self {
            rewrite_src: self.rewrite_dst.map(|_| original_dst),
            rewrite_dst: self.rewrite_src.map(|_| original_src),
            rewrite_src_port: self.rewrite_dst_port.map(|_| original_dst_port),
            rewrite_dst_port: self.rewrite_src_port.map(|_| original_src_port),
            nat64: self.nat64,
            nptv6: self.nptv6,
        }
    }

    /// Merge two NAT decisions, preferring fields already set in `self`.
    /// Used to combine a pre-routing DNAT decision with a post-policy SNAT decision.
    pub(crate) fn merge(self, other: NatDecision) -> Self {
        Self {
            rewrite_src: self.rewrite_src.or(other.rewrite_src),
            rewrite_dst: self.rewrite_dst.or(other.rewrite_dst),
            rewrite_src_port: self.rewrite_src_port.or(other.rewrite_src_port),
            rewrite_dst_port: self.rewrite_dst_port.or(other.rewrite_dst_port),
            nat64: self.nat64 || other.nat64,
            nptv6: self.nptv6 || other.nptv6,
        }
    }
}

/// #2218: one per-rule NAT translation hit counter. Lock-free atomic
/// packets+bytes pair, captured at rule-build time as an `Arc` and
/// incremented from the cold (session-miss) path only — exactly the
/// `PolicyRuleCounter` pattern (policy.rs). `add` is the only mutation on
/// the increment side: a single `fetch_add(1)` for packets plus a
/// conditional bytes add, no allocation, no lock.
#[derive(Debug, Default)]
pub(crate) struct NatRuleCounter {
    packets: AtomicU64,
    bytes: AtomicU64,
}

impl NatRuleCounter {
    /// Count one committed translated flow: +1 packet and +packet_len bytes.
    /// Per-flow semantic (not per-packet) — fired once when a new translated
    /// session is installed, so the bytes are the trigger packet's length.
    #[inline]
    pub(crate) fn add(&self, packet_len: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        if packet_len != 0 {
            self.bytes.fetch_add(packet_len, Ordering::Relaxed);
        }
    }

    fn reset(&self) {
        self.packets.store(0, Ordering::Relaxed);
        self.bytes.store(0, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self, counter_id: u16) -> NatRuleCounterStatus {
        NatRuleCounterStatus {
            counter_id,
            packets: self.packets.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

type NatCounterRegistry = FxHashMap<u16, Arc<NatRuleCounter>>;

/// #2218: registry of per-rule NAT hit counters keyed by the
/// compiler-assigned `counter_id`. Cheaply cloneable (`Arc`), so the
/// coordinator owns one and threads `&self.nat_counters` into the
/// forwarding-state build, exactly mirroring `PolicyCounterStore`.
/// `counter_id == 0` is the "no per-rule counter" sentinel and is never
/// stored — `rule_counter(0)` returns `None`.
#[derive(Clone, Debug, Default)]
pub(crate) struct NatCounterStore {
    counters: Arc<Mutex<NatCounterRegistry>>,
}

impl NatCounterStore {
    /// Resolve (get-or-insert) the shared counter for `counter_id`. Returns
    /// `None` for the reserved id 0 so a rule without a per-rule counter
    /// carries `hit_counter: None` and the increment site skips it.
    pub(crate) fn rule_counter(&self, counter_id: u16) -> Option<Arc<NatRuleCounter>> {
        if counter_id == 0 {
            return None;
        }
        let mut counters = self.counters.lock().expect("nat counter store poisoned");
        if let Some(counter) = counters.get(&counter_id) {
            return Some(counter.clone());
        }
        let counter = Arc::new(NatRuleCounter::default());
        counters.insert(counter_id, counter.clone());
        Some(counter)
    }

    /// Retain only counters whose id is in `active_ids`, dropping the
    /// `Arc<NatRuleCounter>` for rules removed by a config change. Mirrors
    /// `PolicyCounterStore::reconcile_rules`.
    pub(crate) fn reconcile_ids(&self, active_ids: &[u16]) {
        let active: rustc_hash::FxHashSet<u16> =
            active_ids.iter().copied().filter(|&id| id != 0).collect();
        if let Ok(mut counters) = self.counters.lock() {
            counters.retain(|id, _| active.contains(id));
        }
    }

    /// Reset every stored counter to zero (operator `clear` of NAT hit
    /// counters). Mirrors `PolicyCounterStore::clear`.
    pub(crate) fn clear(&self) {
        if let Ok(counters) = self.counters.lock() {
            for counter in counters.values() {
                counter.reset();
            }
        }
    }

    /// One status row per stored counter_id, regardless of whether its
    /// packet/byte value is zero. Every stored id is non-zero: counter_id 0 is
    /// the "no per-rule counter" sentinel and is never stored (see
    /// `rule_counter`), so it never appears as a row. Matches
    /// `PolicyState::counter_snapshots`, which emits one row per rule.
    pub(crate) fn snapshots(&self) -> Vec<NatRuleCounterStatus> {
        let Ok(counters) = self.counters.lock() else {
            return Vec::new();
        };
        counters
            .iter()
            .map(|(&id, counter)| counter.snapshot(id))
            .collect()
    }
}
