//! Firewall filter and policer evaluation for the userspace dataplane.
//!
//! Implements Junos-style firewall filters with ordered terms (first match wins)
//! and token-bucket policers. Mirrors the eBPF filter pipeline
//! (`bpf/xdp/xdp_forward.c` lo0 filter evaluation).
//!
//! Filters can be applied:
//! - Per-interface (input direction): evaluated after zone resolution, before session lookup
//! - lo0 (host-bound traffic): evaluated on local delivery path

use crate::prefix::{PrefixV4, PrefixV6};
// #1049 P2: Snapshot types come from the crate root (protocol.rs) and are
// referenced by both compiler.rs and the tests module. Importing here makes
// them visible to all submodules via `use super::*;`.
use crate::{
    FirewallFilterSnapshot, FirewallTermSnapshot, PolicerSnapshot, ThreeColorPolicerSnapshot,
};
use ipnet::IpNet;
#[cfg(not(test))]
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::ip_proto::proto_number;
use crate::policy::SnapshotIntegrityError;
// #2505: filter compilation resolves all protocol tokens through
// `proto_number`, so this module's *compiler* no longer needs the bare
// `PROTO_*` consts. Production code that DOES reference them imports them
// directly where used — e.g. `engine/matching.rs` imports `PROTO_TCP`,
// `PROTO_ICMP`, `PROTO_ICMPV6` from `crate::ip_proto` for per-packet match
// classification. The `#[cfg(test)]` import below re-exports the consts via
// `super::*` ONLY for the filter unit tests in this module (asserting a term
// resolved to the right IANA number); a module-level non-test re-export would
// warn as unused because nothing under `mod.rs`/`compiler.rs` references them
// outside tests anymore.
#[cfg(test)]
use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};

/// Result of evaluating a filter term.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FilterAction {
    /// Accept the packet (default if no term matches).
    Accept,
    /// Silently drop the packet.
    Discard,
    /// Request reject behavior.
    ///
    /// Callers that cannot synthesize the reject packet must fail closed as a
    /// silent drop and must not log that an ICMP/RST reject was generated.
    Reject,
}

// ============================================================
// CACHE-KEY INVARIANT (#1431) — read before adding a match field
//
// Every match criterion on FilterTerm (and the wire DTO
// FirewallTermSnapshot) MUST be classified as either:
//
//   (a) IN cache key — extend SessionKey in session/key.rs AND
//       prove key stability for HA sync (pkg/cluster/),
//       session-table reverse/NAT/forward-wire indices, flow_cache
//       key derivation, expiry hash bucket math, and reverse-NAT
//       lookup. File a tracker issue against session/key.rs.
//
//   (b) NOT in cache key (cache-sensitive) — wire the #1430
//       runbook: per-interface FilterState.iface_filter_v{4,6}_has_<X>_match
//       set, Filter.has_<X>_match_terms aggregate flag, flow-cache
//       insertion gate at afxdp/flow_cache.rs:297-309, established-
//       session re-evaluation at afxdp/poll_descriptor/mod.rs:217-244,
//       forwarding rotation purge at afxdp/worker/loop_body/mod.rs:295-330,
//       and tests at afxdp/flow_cache_tests.rs.
//
// Skipping this classification SILENTLY breaks flow-cache: a
// first-packet decision gets reused for later packets that can
// differ on the new field. PR #1430 fixed this for DSCP; the same
// class of bug applies to any future per-packet match.
//
// See userspace-dp/src/filter/README.md
//   "Cache-key invariants for per-packet match fields (#1431)"
// for the classification table, the path (a) / path (b) recipes,
// and the canonical reference tests.
// ============================================================
/// Compiled filter term with pre-parsed match criteria.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct FilterTerm {
    pub(crate) id: u32,
    pub(crate) name: String,
    pub(crate) source_v4: Vec<PrefixV4>,
    pub(crate) source_v6: Vec<PrefixV6>,
    pub(crate) dest_v4: Vec<PrefixV4>,
    pub(crate) dest_v6: Vec<PrefixV6>,
    // #2400 (032-18): fail-closed flags for the source/destination ADDRESS
    // match sets. `*_addr_constrained` is true when the term has at least one
    // REAL match entry (`addr_is_real` in compiler.rs — EXCLUDING the empty
    // string and the literal `any`), regardless of how many entries survived
    // parsing. An explicit `from { source-address any; }` therefore stays
    // UNCONSTRAINED (match-any). The matcher in `engine/matching.rs` uses the
    // flag to tell apart an UNSCOPED term (constrained == false → match any
    // address) from a SCOPED term whose entries ALL failed to parse
    // (constrained == true but both prefix vecs empty for that family → match
    // NOTHING, fail closed). Without this flag an all-malformed address list
    // collapses to the empty-list "match any" fail-open broadening (a `discard`
    // term scoped to typo'd addresses would become discard-all). Mirrors the
    // #2398/#2394 NAT `*_constrained` pattern.
    pub(crate) source_addr_constrained: bool,
    pub(crate) dest_addr_constrained: bool,
    // #2506: invert the source/destination address membership test. When true,
    // the term matches every address NOT in the source/dest prefix set (Junos
    // `from source-prefix-list NAME except` / `destination-prefix-list NAME
    // except`). The matcher in engine/matching.rs evaluates
    // `(addr ∈ prefixes) XOR except`. Only meaningful when the direction is
    // `*_addr_constrained` (an UNCONSTRAINED term matches any address
    // regardless of the except flag — there is no prefix set to invert).
    pub(crate) source_except: bool,
    pub(crate) dest_except: bool,
    pub(crate) protocol_bitmap: [u64; 4],
    pub(crate) protocol_match_enabled: bool,
    pub(crate) source_ports: PortMatcher,
    pub(crate) dest_ports: PortMatcher,
    // #2400 (032-19): fail-closed flags for the source/destination PORT match
    // sets. Same shape as the address flags above. A `PortMatcher::Any` arises
    // from BOTH the legitimate unscoped case (no port configured) AND the
    // all-malformed case (every configured port spec failed to parse), so the
    // matcher cannot distinguish them from the `PortMatcher` alone. When
    // `*_port_constrained` is true but the matcher is `PortMatcher::Any`, the
    // term had a port list that ALL failed to parse → match NOTHING (fail
    // closed). A valid scoped term yields a non-`Any` matcher and matches its
    // ports as before.
    pub(crate) source_port_constrained: bool,
    pub(crate) dest_port_constrained: bool,
    // #2622: invert the source/destination PORT membership test (Junos `from
    // source-port-except` / `destination-port-except`). When true, the matcher
    // matches every port NOT in the source/dest port set:
    // `(port ∈ ranges) XOR except`. The except port list builds the SAME
    // PortMatcher and sets `*_port_constrained`; only the inversion differs.
    // When the except list is non-empty but ALL entries fail to parse
    // (PortMatcher::Any while constrained), the term means "match all ports
    // except {}" = match ALL — handled in port_match. Only meaningful when the
    // direction is `*_port_constrained`.
    pub(crate) source_port_except: bool,
    pub(crate) dest_port_except: bool,
    pub(crate) dscp_bitmap: u64,
    pub(crate) dscp_match_enabled: bool,
    // Per-packet L4 match conditions (#2362). NOT in SessionKey, so a filter
    // carrying any of these is cache-sensitive (path (b) per the #1431
    // invariant above): the flow-cache must decline insertion and the
    // change-detection / re-eval / rotation-purge machinery in
    // cache_sensitive.rs must treat them like dscp.
    //
    // tcp_flags_mask: required-bits mask over the TCP flags byte. A TCP packet
    // matches when (flags & mask) == mask. None = no constraint. Only TCP can
    // match a term that sets this.
    pub(crate) tcp_flags_mask: Option<u8>,
    // tcp_flags_forbidden: forbidden-bits mask over the TCP flags byte (#3076).
    // A TCP packet matches only when (flags & forbidden) == 0. Carries the
    // negated operands of a Junos tcp-flags expression such as `syn & !ack`
    // (tcp_flags_mask=SYN, tcp_flags_forbidden=ACK). None = no forbidden
    // constraint. Independent of tcp_flags_mask: a term may set either, both, or
    // neither. Cache-sensitive (NOT in SessionKey) — see has_per_packet_l4_match
    // and cache_sensitive.rs.
    pub(crate) tcp_flags_forbidden: Option<u8>,
    // is_fragment: matches any IP fragment.
    pub(crate) is_fragment: bool,
    // icmp_type / icmp_code: SET membership over the ICMP/ICMPv6 type/code byte
    // (#2545, multi-value). The bitmap is 256 bits (`[u64; 4]`); a packet's
    // type/code byte matches when its bit is set. `*_match_enabled` is false for
    // an unconstrained term (empty set → match any), so a term that omits the
    // criterion matches every type/code. Only ICMP/ICMPv6 can match a term that
    // enables these. Previously a single `Option<u8>` (exact equality) — a term
    // with two `from icmp-type` values kept only the last.
    pub(crate) icmp_type_bitmap: [u64; 4],
    pub(crate) icmp_type_match_enabled: bool,
    pub(crate) icmp_code_bitmap: [u64; 4],
    pub(crate) icmp_code_match_enabled: bool,
    pub(crate) action: FilterAction,
    // #2544: fall-through. When true, this term carries NO terminating action
    // (an explicit `then next term` OR a modifier-only term). On a MATCH the
    // evaluator applies the term's modifiers (count, log, forwarding-class,
    // policer, dscp) and then CONTINUES to the next term instead of returning —
    // Junos fall-through semantics. `action` is left as Accept (the historical
    // empty-action mapping) but is never returned for a matched fall-through
    // term; it only takes effect as the default if NO later term terminates and
    // no term matched (handled by the trailing default). A term with a
    // terminating action (accept/reject/discard) has this false and returns on
    // match as before.
    pub(crate) continue_term: bool,
    pub(crate) count: String,
    pub(crate) has_count: bool,
    pub(crate) log: bool,
    pub(crate) policer_name: String,
    pub(crate) three_color_policer: Option<Arc<ThreeColorPolicerRuntime>>,
    pub(crate) routing_instance: String,
    pub(crate) forwarding_class: Arc<str>,
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) counter: Arc<FilterTermCounter>,
}

impl FilterTerm {
    /// Whether this term carries any per-packet L4 match condition (#2362)
    /// that is not part of the 5-tuple SessionKey: tcp-flags, is-fragment,
    /// icmp-type, or icmp-code. A filter with such a term is cache-sensitive
    /// (the flow-cache must decline insertion — see `flow_cache.rs`).
    #[inline]
    pub(crate) fn has_per_packet_l4_match(&self) -> bool {
        self.tcp_flags_mask.is_some()
            || self.tcp_flags_forbidden.is_some()
            || self.is_fragment
            || self.icmp_type_match_enabled
            || self.icmp_code_match_enabled
    }
}

/// Per-packet match inputs that are NOT in the 5-tuple (#2362). Computed once
/// per packet at each evaluate call site (the only place that has the frame
/// bytes) and threaded into the term predicate. `Default` (all-absent,
/// `l4_present = false`) makes every L4 per-packet condition fail to match, so
/// callers that cannot cheaply compute these (cached/TX-selection rebuild
/// paths, which never carry an L4-match term because the flow-cache declines
/// for such filters) stay behavior-compatible AND fail closed.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TermMatchExtra {
    /// Raw TCP flags byte (only meaningful when protocol == TCP and
    /// `l4_present`).
    pub(crate) tcp_flags: u8,
    /// Whether the packet is an IP fragment (any fragment). L3-derived — valid
    /// regardless of `l4_present` (every fragment carries the IP header).
    pub(crate) is_fragment: bool,
    /// ICMP/ICMPv6 type byte (only meaningful when protocol is ICMP/ICMPv6 and
    /// `l4_present`).
    pub(crate) icmp_type: u8,
    /// ICMP/ICMPv6 code byte (only meaningful when protocol is ICMP/ICMPv6 and
    /// `l4_present`).
    pub(crate) icmp_code: u8,
    /// #2362 fold A (Copilot): whether a real L4 header is present at
    /// `l4_offset`. FALSE for a NON-FIRST fragment (its post-IP bytes are
    /// payload, not an L4 header) and for any other no-L4 case. The matcher
    /// gates the tcp-flags / icmp-type / icmp-code constraints on this flag —
    /// NOT on the byte values — because 0 is a VALID icmp-type (echo-reply) and
    /// a VALID icmp-code, so a zeroed byte would still spuriously match
    /// `icmp-type 0` / `icmp-code 0`. `is_fragment` is L3-derived and is NOT
    /// gated by this flag.
    pub(crate) l4_present: bool,
}

/// Inclusive port range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PortRange {
    pub(crate) low: u16,
    pub(crate) high: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PortMatcher {
    Any,
    Single(u16),
    Range(PortRange),
    Set(Box<[PortRange]>),
}

impl PortMatcher {
    #[inline(always)]
    fn matches(&self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Single(expected) => port == *expected,
            Self::Range(range) => port >= range.low && port <= range.high,
            Self::Set(ranges) => ranges
                .iter()
                .any(|range| port >= range.low && port <= range.high),
        }
    }
}

/// A compiled firewall filter (ordered list of terms).
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct Filter {
    pub(crate) id: u32,
    pub(crate) name: String,
    pub(crate) family: String,
    pub(crate) terms: Vec<FilterTerm>,
    pub(crate) affects_tx_selection: bool,
    pub(crate) affects_route_lookup: bool,
    pub(crate) has_counter_terms: bool,
    pub(crate) has_log_terms: bool,
    pub(crate) has_terminal_action_terms: bool,
    pub(crate) has_dscp_match_terms: bool,
    /// Any term carries a per-packet L4 match (tcp-flags / is-fragment /
    /// icmp-type / icmp-code) — #2362. Cache-sensitive like
    /// `has_dscp_match_terms`: the flow-cache must decline for these filters.
    pub(crate) has_per_packet_l4_match_terms: bool,
    pub(crate) has_three_color_policer_terms: bool,
}

#[derive(Debug, Default)]
pub(crate) struct FilterTermCounter {
    pub(crate) packets: AtomicU64,
    pub(crate) bytes: AtomicU64,
}

#[derive(Debug, Default)]
pub(crate) struct ThreeColorPolicerCounter {
    pub(crate) packets: AtomicU64,
    pub(crate) bytes: AtomicU64,
}

impl ThreeColorPolicerCounter {
    fn record(&self, packet_bytes: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(packet_bytes, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
pub(crate) struct ThreeColorPolicerCounters {
    pub(crate) green: ThreeColorPolicerCounter,
    pub(crate) yellow: ThreeColorPolicerCounter,
    pub(crate) red: ThreeColorPolicerCounter,
    pub(crate) drop: ThreeColorPolicerCounter,
}

#[derive(Debug)]
pub(crate) struct ThreeColorPolicerRuntime {
    pub(crate) id: u32,
    pub(crate) name: Arc<str>,
    state: Mutex<ThreeColorPolicerState>,
    counters: ThreeColorPolicerCounters,
}

impl PartialEq for ThreeColorPolicerRuntime {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.name == other.name
    }
}

impl Eq for ThreeColorPolicerRuntime {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CachedThreeColorPolicers {
    first: Option<Arc<ThreeColorPolicerRuntime>>,
    second: Option<Arc<ThreeColorPolicerRuntime>>,
}

impl CachedThreeColorPolicers {
    #[inline]
    pub(crate) fn from_option(runtime: Option<Arc<ThreeColorPolicerRuntime>>) -> Self {
        Self {
            first: runtime,
            second: None,
        }
    }

    #[inline]
    pub(crate) fn push(&mut self, runtime: Arc<ThreeColorPolicerRuntime>) {
        if self
            .first
            .as_ref()
            .is_some_and(|existing| existing.id == runtime.id)
            || self
                .second
                .as_ref()
                .is_some_and(|existing| existing.id == runtime.id)
        {
            return;
        }
        if self.first.is_none() {
            self.first = Some(runtime);
        } else if self.second.is_none() {
            self.second = Some(runtime);
        }
    }

    #[inline]
    pub(crate) fn extend(&mut self, other: Self) {
        if let Some(runtime) = other.first {
            self.push(runtime);
        }
        if let Some(runtime) = other.second {
            self.push(runtime);
        }
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        usize::from(self.first.is_some()) + usize::from(self.second.is_some())
    }

    #[inline]
    pub(crate) fn for_each(&self, mut f: impl FnMut(&Arc<ThreeColorPolicerRuntime>)) {
        if let Some(runtime) = self.first.as_ref() {
            f(runtime);
        }
        if let Some(runtime) = self.second.as_ref() {
            f(runtime);
        }
    }
}

/// #2573: the set of `then count` term counters a cached TX-selection decision
/// must increment on every flow-cache replay. With #2544 fall-through, a single
/// packet can match multiple `then count` terms; the old single-`Arc` slot kept
/// only the LAST, so the earlier fall-through count terms were silently
/// under-counted on the cached path (the uncached full-eval path counted each).
///
/// Backed by a `SmallVec` with an inline capacity of 2 so the common single- and
/// dual-counter flows record with NO heap allocation. The descriptor is built
/// ONCE at flow-cache install and then only read (`for_each`) on the per-packet
/// replay, so any spill to the heap for >2 counters happens off the packet hot
/// path. Dedup is by `Arc::ptr_eq` (FilterTermCounter has no id) so the same
/// counter referenced by two matched terms is recorded once per packet.
#[derive(Clone, Debug, Default)]
pub(crate) struct CachedFilterCounters {
    counters: smallvec::SmallVec<[Arc<FilterTermCounter>; 2]>,
}

impl CachedFilterCounters {
    #[inline]
    pub(crate) fn push(&mut self, counter: Arc<FilterTermCounter>) {
        if self
            .counters
            .iter()
            .any(|existing| Arc::ptr_eq(existing, &counter))
        {
            return;
        }
        self.counters.push(counter);
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.counters.len()
    }

    #[inline]
    pub(crate) fn for_each(&self, mut f: impl FnMut(&Arc<FilterTermCounter>)) {
        for counter in &self.counters {
            f(counter);
        }
    }
}

impl ThreeColorPolicerRuntime {
    pub(crate) fn new(id: u32, name: String, state: ThreeColorPolicerState) -> Self {
        Self {
            id,
            name: Arc::<str>::from(name),
            state: Mutex::new(state),
            counters: ThreeColorPolicerCounters::default(),
        }
    }

    pub(crate) fn meter(
        &self,
        now_ns: u64,
        packet_bytes: u64,
        incoming_color: PacketColor,
    ) -> ThreeColorDecision {
        let decision = self
            .state
            .lock()
            .map(|mut state| state.meter(now_ns, packet_bytes, incoming_color))
            .unwrap_or_else(|_| ThreeColorDecision {
                color: PacketColor::Red,
                dscp_rewrite: None,
                drop: true,
            });
        match decision.color {
            PacketColor::Green => self.counters.green.record(packet_bytes),
            PacketColor::Yellow => self.counters.yellow.record(packet_bytes),
            PacketColor::Red => self.counters.red.record(packet_bytes),
        }
        if decision.drop {
            self.counters.drop.record(packet_bytes);
        }
        decision
    }

    pub(crate) fn reusable_for(&self, id: u32, next_shape: &ThreeColorPolicerState) -> bool {
        if self.id != id {
            return false;
        }
        self.state
            .lock()
            .ok()
            .is_some_and(|state| state.same_runtime_shape(next_shape))
    }

    pub(crate) fn same_runtime_shape_as(&self, other: &Self) -> bool {
        if self.id != other.id || self.name != other.name {
            return false;
        }
        let Ok(state) = self.state.lock() else {
            return false;
        };
        other
            .state
            .lock()
            .ok()
            .is_some_and(|other| state.same_runtime_shape(&other))
    }

    pub(crate) fn status(&self) -> crate::protocol::ThreeColorPolicerStatus {
        let (mode, color_blind) = self
            .state
            .lock()
            .map(|state| (state.mode_name().to_string(), state.color_blind()))
            .unwrap_or_else(|_| ("unknown".to_string(), false));
        crate::protocol::ThreeColorPolicerStatus {
            id: self.id,
            name: self.name.to_string(),
            mode,
            color_blind,
            green_packets: self.counters.green.packets.load(Ordering::Relaxed),
            green_bytes: self.counters.green.bytes.load(Ordering::Relaxed),
            yellow_packets: self.counters.yellow.packets.load(Ordering::Relaxed),
            yellow_bytes: self.counters.yellow.bytes.load(Ordering::Relaxed),
            red_packets: self.counters.red.packets.load(Ordering::Relaxed),
            red_bytes: self.counters.red.bytes.load(Ordering::Relaxed),
            drop_packets: self.counters.drop.packets.load(Ordering::Relaxed),
            drop_bytes: self.counters.drop.bytes.load(Ordering::Relaxed),
        }
    }
}

impl FilterTermCounter {
    pub(crate) fn record(&self, packet_bytes: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(packet_bytes, Ordering::Relaxed);
    }
}

#[cfg(not(test))]
#[derive(Default)]
struct PendingFilterCounterRecord {
    counter: Option<Arc<FilterTermCounter>>,
    packets: u64,
    bytes: u64,
}

#[cfg(not(test))]
const FILTER_COUNTER_FLUSH_PACKETS: u64 = 64;

#[cfg(not(test))]
thread_local! {
    static PENDING_FILTER_COUNTER_RECORD: RefCell<PendingFilterCounterRecord> =
        RefCell::new(PendingFilterCounterRecord::default());
}

#[cfg(not(test))]
#[inline(always)]
fn flush_pending_filter_counter_record(record: &mut PendingFilterCounterRecord) {
    let Some(counter) = record.counter.take() else {
        return;
    };
    counter.packets.fetch_add(record.packets, Ordering::Relaxed);
    counter.bytes.fetch_add(record.bytes, Ordering::Relaxed);
    record.packets = 0;
    record.bytes = 0;
}

#[cfg(not(test))]
#[inline(always)]
pub(crate) fn record_filter_counter(counter: &Arc<FilterTermCounter>, packet_bytes: u64) {
    PENDING_FILTER_COUNTER_RECORD.with(|pending| {
        let mut pending = pending.borrow_mut();
        if pending
            .counter
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, counter))
        {
            pending.packets = pending.packets.saturating_add(1);
            pending.bytes = pending.bytes.saturating_add(packet_bytes);
        } else {
            flush_pending_filter_counter_record(&mut pending);
            pending.counter = Some(counter.clone());
            pending.packets = 1;
            pending.bytes = packet_bytes;
        }
        if pending.packets >= FILTER_COUNTER_FLUSH_PACKETS {
            flush_pending_filter_counter_record(&mut pending);
        }
    });
}

#[cfg(test)]
#[inline(always)]
pub(crate) fn record_filter_counter(counter: &Arc<FilterTermCounter>, packet_bytes: u64) {
    counter.record(packet_bytes);
}

#[cfg(not(test))]
pub(crate) fn flush_recorded_filter_counters() {
    PENDING_FILTER_COUNTER_RECORD.with(|pending| {
        flush_pending_filter_counter_record(&mut pending.borrow_mut());
    });
}

#[cfg(test)]
pub(crate) fn flush_recorded_filter_counters() {}

// #1049 P2: structural split — engine, compiler, and policer extracted
// into sibling submodules. mod.rs hosts the shared type vocabulary,
// constants, and counter-flush helpers; the submodules import them via
// `use super::*;`.
mod compiler;
mod engine;
mod policer;

// Glob re-exports surface the `pub(crate) fn`/`pub(crate) struct` items from
// each submodule. Private helpers inside compiler/engine stay invisible
// because the glob only re-exports `pub`-visible items.
pub(crate) use compiler::*;
pub(crate) use engine::*;
pub(crate) use policer::*;
/// Aggregate filter state: all compiled filters and policers.
#[derive(Clone, Debug, Default)]
pub(crate) struct FilterState {
    /// Named filters keyed by "family:name" (e.g. "inet:protect-RE").
    pub(crate) filters: rustc_hash::FxHashMap<String, Arc<Filter>>,
    /// Named policer states keyed by policer name.
    pub(crate) policers: rustc_hash::FxHashMap<String, PolicerState>,
    /// Stable three-color policer runtimes keyed by policer name.
    pub(crate) three_color_policer_by_name:
        rustc_hash::FxHashMap<String, Arc<ThreeColorPolicerRuntime>>,
    /// Name-derived ID-indexed three-color policer runtimes.
    pub(crate) three_color_policers: Vec<Arc<ThreeColorPolicerRuntime>>,
    /// Per-interface (ifindex) input filter key for inet.
    pub(crate) iface_filter_v4: rustc_hash::FxHashMap<i32, String>,
    /// Direct per-interface inet filter reference for packet hot-path evaluation.
    pub(crate) iface_filter_v4_fast: rustc_hash::FxHashMap<i32, Arc<Filter>>,
    /// Per-interface inet input filters that can affect CoS TX selection.
    pub(crate) iface_filter_v4_affects_tx_selection: rustc_hash::FxHashSet<i32>,
    /// Whether any inet input filter can affect CoS TX selection.
    pub(crate) has_input_tx_selection_v4: bool,
    /// Whether any inet input filter contains a three-color policer.
    pub(crate) has_input_three_color_policer_v4: bool,
    /// Per-interface inet input filters that can affect route-table selection.
    pub(crate) iface_filter_v4_affects_route_lookup: rustc_hash::FxHashSet<i32>,
    /// Per-interface inet input filters with DSCP match terms.
    pub(crate) iface_filter_v4_has_dscp_match: rustc_hash::FxHashSet<i32>,
    /// Per-interface inet input filters with per-packet L4 match terms (#2362:
    /// tcp-flags / is-fragment / icmp-type / icmp-code). Cache-sensitive.
    pub(crate) iface_filter_v4_has_per_packet_l4_match: rustc_hash::FxHashSet<i32>,
    /// Per-interface (ifindex) input filter key for inet6.
    pub(crate) iface_filter_v6: rustc_hash::FxHashMap<i32, String>,
    /// Direct per-interface inet6 filter reference for packet hot-path evaluation.
    pub(crate) iface_filter_v6_fast: rustc_hash::FxHashMap<i32, Arc<Filter>>,
    /// Per-interface inet6 input filters that can affect CoS TX selection.
    pub(crate) iface_filter_v6_affects_tx_selection: rustc_hash::FxHashSet<i32>,
    /// Whether any inet6 input filter can affect CoS TX selection.
    pub(crate) has_input_tx_selection_v6: bool,
    /// Whether any inet6 input filter contains a three-color policer.
    pub(crate) has_input_three_color_policer_v6: bool,
    /// Per-interface inet6 input filters that can affect route-table selection.
    pub(crate) iface_filter_v6_affects_route_lookup: rustc_hash::FxHashSet<i32>,
    /// Per-interface inet6 input filters with DSCP match terms.
    pub(crate) iface_filter_v6_has_dscp_match: rustc_hash::FxHashSet<i32>,
    /// Per-interface inet6 input filters with per-packet L4 match terms (#2362).
    pub(crate) iface_filter_v6_has_per_packet_l4_match: rustc_hash::FxHashSet<i32>,
    /// Per-interface (ifindex) output filter key for inet.
    pub(crate) iface_filter_out_v4: rustc_hash::FxHashMap<i32, String>,
    /// Direct per-interface inet output filter reference for packet hot-path evaluation.
    pub(crate) iface_filter_out_v4_fast: rustc_hash::FxHashMap<i32, Arc<Filter>>,
    /// Per-interface inet output filters that must still be evaluated in the TX path.
    pub(crate) iface_filter_out_v4_needs_tx_eval: rustc_hash::FxHashSet<i32>,
    /// Whether any inet output filter can affect CoS TX selection.
    pub(crate) has_output_tx_selection_v4: bool,
    /// Per-interface (ifindex) output filter key for inet6.
    pub(crate) iface_filter_out_v6: rustc_hash::FxHashMap<i32, String>,
    /// Direct per-interface inet6 output filter reference for packet hot-path evaluation.
    pub(crate) iface_filter_out_v6_fast: rustc_hash::FxHashMap<i32, Arc<Filter>>,
    /// Per-interface inet6 output filters that must still be evaluated in the TX path.
    pub(crate) iface_filter_out_v6_needs_tx_eval: rustc_hash::FxHashSet<i32>,
    /// Whether any inet6 output filter can affect CoS TX selection.
    pub(crate) has_output_tx_selection_v6: bool,
    /// lo0 inet input filter key.
    pub(crate) lo0_filter_v4: String,
    /// Direct lo0 inet filter reference for packet hot-path evaluation.
    pub(crate) lo0_filter_v4_fast: Option<Arc<Filter>>,
    /// lo0 inet6 input filter key.
    pub(crate) lo0_filter_v6: String,
    /// Direct lo0 inet6 filter reference for packet hot-path evaluation.
    pub(crate) lo0_filter_v6_fast: Option<Arc<Filter>>,
}

impl FilterState {
    pub(crate) fn three_color_policer_statuses(
        &self,
    ) -> Vec<crate::protocol::ThreeColorPolicerStatus> {
        let mut statuses = self
            .three_color_policers
            .iter()
            .map(|policer| policer.status())
            .collect::<Vec<_>>();
        statuses.sort_by_key(|status| status.id);
        statuses
    }
}

/// Result of filter evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FilterResult {
    pub(crate) action: FilterAction,
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) policer_name: String,
    pub(crate) routing_instance: String,
    pub(crate) forwarding_class: Arc<str>,
    pub(crate) log: bool,
    pub(crate) log_match: Option<FilterLogMatch>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FilterRoutingInstanceResult<'a> {
    pub(crate) routing_instance: &'a str,
    pub(crate) log: bool,
    pub(crate) action: FilterAction,
    pub(crate) filter_id: u32,
    pub(crate) term_id: u32,
    // #2619: the latest-matched logging term seen while scanning for the
    // routing-instance term — INCLUDING fall-through `then { log; next term; }`
    // terms ahead of the routing-instance term, whose log metadata the PBR path
    // previously dropped. `None` when no matched term carried `then log`. The
    // action is normalized to the verdict the packet receives on the PBR path
    // (#2616): the routing-instance term itself terminates with its own action,
    // so a fall-through log ahead of it logs that terminal action. The legacy
    // `log`/`action`/`filter_id`/`term_id` fields above describe ONLY the
    // routing-instance term; emitters now prefer `log_match`.
    pub(crate) log_match: Option<FilterLogMatch>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FilterLogMatch {
    pub(crate) filter_id: u32,
    pub(crate) term_id: u32,
    pub(crate) action: FilterAction,
}

#[derive(Clone, Debug)]
pub(crate) struct TxSelectionFilterResult<'a> {
    pub(crate) action: FilterAction,
    pub(crate) forwarding_class: Option<&'a str>,
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) policer_drop: bool,
    pub(crate) log_match: Option<FilterLogMatch>,
}

#[derive(Clone, Debug)]
pub(crate) struct CachedTxSelectionFilterResult {
    pub(crate) action: FilterAction,
    pub(crate) forwarding_class: Option<Arc<str>>,
    pub(crate) dscp_rewrite: Option<u8>,
    // #2573: record ALL matched `then count` term counters, not just the last.
    pub(crate) counters: CachedFilterCounters,
    pub(crate) three_color_policers: CachedThreeColorPolicers,
    pub(crate) log_match: Option<FilterLogMatch>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ThreeColorPolicerAction {
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) drop: bool,
}

impl Default for FilterResult {
    fn default() -> Self {
        Self {
            action: FilterAction::Accept,
            dscp_rewrite: None,
            policer_name: String::new(),
            routing_instance: String::new(),
            forwarding_class: Arc::<str>::from(""),
            log: false,
            log_match: None,
        }
    }
}

impl Default for TxSelectionFilterResult<'_> {
    fn default() -> Self {
        Self {
            action: FilterAction::Accept,
            forwarding_class: None,
            dscp_rewrite: None,
            policer_drop: false,
            log_match: None,
        }
    }
}

impl Default for CachedTxSelectionFilterResult {
    fn default() -> Self {
        Self {
            action: FilterAction::Accept,
            forwarding_class: None,
            dscp_rewrite: None,
            counters: CachedFilterCounters::default(),
            three_color_policers: CachedThreeColorPolicers::default(),
            log_match: None,
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
