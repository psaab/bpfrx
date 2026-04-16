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
use ipnet::IpNet;
#[cfg(not(test))]
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;
const PROTO_GRE: u8 = 47;
const PROTO_OSPF: u8 = 89;
const PROTO_IPIP: u8 = 4;

/// Result of evaluating a filter term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FilterAction {
    /// Accept the packet (default if no term matches).
    Accept,
    /// Silently drop the packet.
    Discard,
    /// Drop with ICMP unreachable.
    Reject,
}

/// Compiled filter term with pre-parsed match criteria.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct FilterTerm {
    pub(crate) name: String,
    pub(crate) source_v4: Vec<PrefixV4>,
    pub(crate) source_v6: Vec<PrefixV6>,
    pub(crate) dest_v4: Vec<PrefixV4>,
    pub(crate) dest_v6: Vec<PrefixV6>,
    pub(crate) protocol_bitmap: [u64; 4],
    pub(crate) protocol_match_enabled: bool,
    pub(crate) source_ports: PortMatcher,
    pub(crate) dest_ports: PortMatcher,
    pub(crate) dscp_bitmap: u64,
    pub(crate) dscp_match_enabled: bool,
    pub(crate) action: FilterAction,
    pub(crate) count: String,
    pub(crate) has_count: bool,
    pub(crate) log: bool,
    pub(crate) policer_name: String,
    pub(crate) routing_instance: String,
    pub(crate) forwarding_class: Arc<str>,
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) counter: Arc<FilterTermCounter>,
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
    pub(crate) name: String,
    pub(crate) family: String,
    pub(crate) terms: Vec<FilterTerm>,
    pub(crate) affects_tx_selection: bool,
    pub(crate) affects_route_lookup: bool,
    pub(crate) has_counter_terms: bool,
}

#[derive(Debug, Default)]
pub(crate) struct FilterTermCounter {
    pub(crate) packets: AtomicU64,
    pub(crate) bytes: AtomicU64,
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

/// Token-bucket policer state.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct PolicerState {
    pub(crate) name: String,
    /// Refill rate in bytes per nanosecond (bandwidth_bps / 8 / 1e9).
    pub(crate) rate_bytes_per_ns: f64,
    /// Maximum bucket size in bytes.
    pub(crate) burst_bytes: u64,
    /// Current token count (bytes).
    pub(crate) tokens: f64,
    /// Last refill timestamp (monotonic nanoseconds).
    pub(crate) last_refill_ns: u64,
    /// Whether to discard excess traffic (vs. mark).
    pub(crate) discard_excess: bool,
    /// Whether the policer has been initialized with the first packet time.
    initialized: bool,
}

impl PolicerState {
    pub(crate) fn new(
        name: String,
        bandwidth_bps: u64,
        burst_bytes: u64,
        discard_excess: bool,
    ) -> Self {
        let rate_bytes_per_ns = (bandwidth_bps as f64) / 8.0 / 1_000_000_000.0;
        Self {
            name,
            rate_bytes_per_ns,
            burst_bytes,
            tokens: burst_bytes as f64,
            last_refill_ns: 0,
            discard_excess,
            initialized: false,
        }
    }

    /// Refill tokens based on elapsed time and try to consume `packet_bytes`.
    /// Returns true if the packet is within the rate limit (conforming).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn consume(&mut self, now_ns: u64, packet_bytes: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.last_refill_ns = now_ns;
            self.tokens = self.burst_bytes as f64;
        }
        // Refill tokens
        if now_ns > self.last_refill_ns {
            let elapsed_ns = now_ns - self.last_refill_ns;
            let refill = elapsed_ns as f64 * self.rate_bytes_per_ns;
            self.tokens = (self.tokens + refill).min(self.burst_bytes as f64);
            self.last_refill_ns = now_ns;
        }
        // Try to consume
        let cost = packet_bytes as f64;
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// Aggregate filter state: all compiled filters and policers.
#[derive(Clone, Debug, Default)]
pub(crate) struct FilterState {
    /// Named filters keyed by "family:name" (e.g. "inet:protect-RE").
    pub(crate) filters: rustc_hash::FxHashMap<String, Arc<Filter>>,
    /// Named policer states keyed by policer name.
    pub(crate) policers: rustc_hash::FxHashMap<String, PolicerState>,
    /// Per-interface (ifindex) input filter key for inet.
    pub(crate) iface_filter_v4: rustc_hash::FxHashMap<i32, String>,
    /// Direct per-interface inet filter reference for packet hot-path evaluation.
    pub(crate) iface_filter_v4_fast: rustc_hash::FxHashMap<i32, Arc<Filter>>,
    /// Per-interface inet input filters that can affect CoS TX selection.
    pub(crate) iface_filter_v4_affects_tx_selection: rustc_hash::FxHashSet<i32>,
    /// Whether any inet input filter can affect CoS TX selection.
    pub(crate) has_input_tx_selection_v4: bool,
    /// Per-interface inet input filters that can affect route-table selection.
    pub(crate) iface_filter_v4_affects_route_lookup: rustc_hash::FxHashSet<i32>,
    /// Per-interface (ifindex) input filter key for inet6.
    pub(crate) iface_filter_v6: rustc_hash::FxHashMap<i32, String>,
    /// Direct per-interface inet6 filter reference for packet hot-path evaluation.
    pub(crate) iface_filter_v6_fast: rustc_hash::FxHashMap<i32, Arc<Filter>>,
    /// Per-interface inet6 input filters that can affect CoS TX selection.
    pub(crate) iface_filter_v6_affects_tx_selection: rustc_hash::FxHashSet<i32>,
    /// Whether any inet6 input filter can affect CoS TX selection.
    pub(crate) has_input_tx_selection_v6: bool,
    /// Per-interface inet6 input filters that can affect route-table selection.
    pub(crate) iface_filter_v6_affects_route_lookup: rustc_hash::FxHashSet<i32>,
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

/// Result of filter evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FilterResult {
    pub(crate) action: FilterAction,
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) policer_name: String,
    pub(crate) routing_instance: String,
    pub(crate) forwarding_class: Arc<str>,
    pub(crate) log: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TxSelectionFilterResult<'a> {
    pub(crate) forwarding_class: Option<&'a str>,
    pub(crate) dscp_rewrite: Option<u8>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CachedTxSelectionFilterResult {
    pub(crate) forwarding_class: Option<Arc<str>>,
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) counter: Option<Arc<FilterTermCounter>>,
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
        }
    }
}

/// Evaluate a named filter against a packet flow. First matching term wins.
/// If no term matches, the implicit action is Accept.
pub(crate) fn evaluate_filter(
    state: &FilterState,
    filter_key: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> FilterResult {
    evaluate_filter_counted(
        state, filter_key, src_ip, dst_ip, protocol, src_port, dst_port, dscp, 0,
    )
}

pub(crate) fn evaluate_filter_counted(
    state: &FilterState,
    filter_key: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    let Some(filter) = state.filters.get(filter_key) else {
        return FilterResult::default();
    };
    evaluate_filter_ref_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        packet_bytes,
    )
}

#[inline]
fn evaluate_filter_ref_counted(
    filter: &Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => evaluate_filter_ref_counted_v4(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            packet_bytes,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_counted_v6(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            packet_bytes,
        ),
        _ => FilterResult::default(),
    }
}

#[inline]
pub(crate) fn evaluate_filter_ref_tx_selection_counted<'a>(
    filter: &'a Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> TxSelectionFilterResult<'a> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => evaluate_filter_ref_tx_selection_counted_v4(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            packet_bytes,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_tx_selection_counted_v6(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            packet_bytes,
        ),
        _ => TxSelectionFilterResult::default(),
    }
}

pub(crate) fn evaluate_filter_ref_tx_selection_cached(
    filter: &Filter,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> CachedTxSelectionFilterResult {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => evaluate_filter_ref_tx_selection_cached_v4(
            filter, src, dst, protocol, src_port, dst_port, dscp,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_tx_selection_cached_v6(
            filter, src, dst, protocol, src_port, dst_port, dscp,
        ),
        _ => CachedTxSelectionFilterResult::default(),
    }
}

#[inline]
fn evaluate_filter_ref_counted_v4(
    filter: &Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    for term in &filter.terms {
        if !term_matches_v4(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        return FilterResult {
            action: term.action.clone(),
            dscp_rewrite: term.dscp_rewrite,
            policer_name: term.policer_name.clone(),
            routing_instance: term.routing_instance.clone(),
            forwarding_class: term.forwarding_class.clone(),
            log: term.log,
        };
    }
    FilterResult::default()
}

#[inline]
fn evaluate_filter_ref_counted_v6(
    filter: &Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    for term in &filter.terms {
        if !term_matches_v6(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        return FilterResult {
            action: term.action.clone(),
            dscp_rewrite: term.dscp_rewrite,
            policer_name: term.policer_name.clone(),
            routing_instance: term.routing_instance.clone(),
            forwarding_class: term.forwarding_class.clone(),
            log: term.log,
        };
    }
    FilterResult::default()
}

#[inline]
fn evaluate_filter_ref_tx_selection_counted_v4<'a>(
    filter: &'a Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> TxSelectionFilterResult<'a> {
    for term in &filter.terms {
        if !term_matches_v4(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        return TxSelectionFilterResult {
            forwarding_class: (!term.forwarding_class.is_empty())
                .then_some(term.forwarding_class.as_ref()),
            dscp_rewrite: term.dscp_rewrite,
        };
    }
    TxSelectionFilterResult::default()
}

#[inline]
fn evaluate_filter_ref_tx_selection_counted_v6<'a>(
    filter: &'a Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> TxSelectionFilterResult<'a> {
    for term in &filter.terms {
        if !term_matches_v6(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        return TxSelectionFilterResult {
            forwarding_class: (!term.forwarding_class.is_empty())
                .then_some(term.forwarding_class.as_ref()),
            dscp_rewrite: term.dscp_rewrite,
        };
    }
    TxSelectionFilterResult::default()
}

fn evaluate_filter_ref_tx_selection_cached_v4(
    filter: &Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> CachedTxSelectionFilterResult {
    for term in &filter.terms {
        if !term_matches_v4(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        return CachedTxSelectionFilterResult {
            forwarding_class: (!term.forwarding_class.is_empty())
                .then(|| term.forwarding_class.clone()),
            dscp_rewrite: term.dscp_rewrite,
            counter: term.has_count.then(|| term.counter.clone()),
        };
    }
    CachedTxSelectionFilterResult::default()
}

fn evaluate_filter_ref_tx_selection_cached_v6(
    filter: &Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> CachedTxSelectionFilterResult {
    for term in &filter.terms {
        if !term_matches_v6(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        return CachedTxSelectionFilterResult {
            forwarding_class: (!term.forwarding_class.is_empty())
                .then(|| term.forwarding_class.clone()),
            dscp_rewrite: term.dscp_rewrite,
            counter: term.has_count.then(|| term.counter.clone()),
        };
    }
    CachedTxSelectionFilterResult::default()
}

#[inline]
fn evaluate_filter_ref_routing_instance_counted_v4<'a>(
    filter: &'a Filter,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> Option<&'a str> {
    for term in &filter.terms {
        if !term_matches_v4(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        return (!term.routing_instance.is_empty()).then_some(term.routing_instance.as_str());
    }
    None
}

#[inline]
fn evaluate_filter_ref_routing_instance_counted_v6<'a>(
    filter: &'a Filter,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> Option<&'a str> {
    for term in &filter.terms {
        if !term_matches_v6(term, src_ip, dst_ip, protocol, src_port, dst_port, dscp) {
            continue;
        }
        if term.has_count {
            record_filter_counter(&term.counter, packet_bytes);
        }
        return (!term.routing_instance.is_empty()).then_some(term.routing_instance.as_str());
    }
    None
}

/// Evaluate the lo0 (host-bound) filter for a given address family.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn evaluate_lo0_filter(
    state: &FilterState,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> FilterResult {
    evaluate_lo0_filter_counted(
        state, is_v6, src_ip, dst_ip, protocol, src_port, dst_port, dscp, 0,
    )
}

pub(crate) fn evaluate_lo0_filter_counted(
    state: &FilterState,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    let filter = if is_v6 {
        state.lo0_filter_v6_fast.as_deref()
    } else {
        state.lo0_filter_v4_fast.as_deref()
    };
    let Some(filter) = filter else {
        return FilterResult::default();
    };
    evaluate_filter_ref_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        packet_bytes,
    )
}

/// Evaluate the per-interface input filter for a given address family.
pub(crate) fn evaluate_interface_filter(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> FilterResult {
    evaluate_interface_filter_counted(
        state, ifindex, is_v6, src_ip, dst_ip, protocol, src_port, dst_port, dscp, 0,
    )
}

pub(crate) fn evaluate_interface_filter_counted(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return FilterResult::default();
    };
    evaluate_filter_ref_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        packet_bytes,
    )
}

pub(crate) fn evaluate_interface_filter_tx_selection_counted<'a>(
    state: &'a FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> TxSelectionFilterResult<'a> {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return TxSelectionFilterResult::default();
    };
    evaluate_filter_ref_tx_selection_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        packet_bytes,
    )
}

pub(crate) fn evaluate_interface_filter_routing_instance_counted<'a>(
    state: &'a FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> Option<&'a str> {
    let filter = if is_v6 {
        state.iface_filter_v6_fast.get(&ifindex).map(Arc::as_ref)
    } else {
        state.iface_filter_v4_fast.get(&ifindex).map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return None;
    };
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => evaluate_filter_ref_routing_instance_counted_v4(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            packet_bytes,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => evaluate_filter_ref_routing_instance_counted_v6(
            filter,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            dscp,
            packet_bytes,
        ),
        _ => None,
    }
}

/// Evaluate the per-interface output filter for a given address family.
pub(crate) fn evaluate_interface_output_filter(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> FilterResult {
    evaluate_interface_output_filter_counted(
        state, ifindex, is_v6, src_ip, dst_ip, protocol, src_port, dst_port, dscp, 0,
    )
}

pub(crate) fn evaluate_interface_output_filter_counted(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> FilterResult {
    let filter = if is_v6 {
        state
            .iface_filter_out_v6_fast
            .get(&ifindex)
            .map(Arc::as_ref)
    } else {
        state
            .iface_filter_out_v4_fast
            .get(&ifindex)
            .map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return FilterResult::default();
    };
    evaluate_filter_ref_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        packet_bytes,
    )
}

pub(crate) fn evaluate_interface_output_filter_tx_selection_counted<'a>(
    state: &'a FilterState,
    ifindex: i32,
    is_v6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    packet_bytes: u64,
) -> TxSelectionFilterResult<'a> {
    let filter = if is_v6 {
        state
            .iface_filter_out_v6_fast
            .get(&ifindex)
            .map(Arc::as_ref)
    } else {
        state
            .iface_filter_out_v4_fast
            .get(&ifindex)
            .map(Arc::as_ref)
    };
    let Some(filter) = filter else {
        return TxSelectionFilterResult::default();
    };
    evaluate_filter_ref_tx_selection_counted(
        filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        dscp,
        packet_bytes,
    )
}

pub(crate) fn interface_filter_affects_tx_selection(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    if is_v6 {
        state
            .iface_filter_v6_affects_tx_selection
            .contains(&ifindex)
    } else {
        state
            .iface_filter_v4_affects_tx_selection
            .contains(&ifindex)
    }
}

pub(crate) fn interface_filter_affects_route_lookup(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    if is_v6 {
        state
            .iface_filter_v6_affects_route_lookup
            .contains(&ifindex)
    } else {
        state
            .iface_filter_v4_affects_route_lookup
            .contains(&ifindex)
    }
}

pub(crate) fn interface_output_filter_needs_tx_eval(
    state: &FilterState,
    ifindex: i32,
    is_v6: bool,
) -> bool {
    if is_v6 {
        state.iface_filter_out_v6_needs_tx_eval.contains(&ifindex)
    } else {
        state.iface_filter_out_v4_needs_tx_eval.contains(&ifindex)
    }
}

#[inline]
pub(crate) fn filter_state_has_input_tx_selection(state: &FilterState, is_v6: bool) -> bool {
    if is_v6 {
        state.has_input_tx_selection_v6
    } else {
        state.has_input_tx_selection_v4
    }
}

#[inline]
pub(crate) fn filter_state_has_output_tx_selection(state: &FilterState, is_v6: bool) -> bool {
    if is_v6 {
        state.has_output_tx_selection_v6
    } else {
        state.has_output_tx_selection_v4
    }
}

/// Check whether a single filter term matches the given packet fields.
/// All specified criteria must match (AND logic). Empty criteria = match any.
#[inline(always)]
fn term_matches(
    term: &FilterTerm,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> bool {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            term_matches_v4(term, src, dst, protocol, src_port, dst_port, dscp)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            term_matches_v6(term, src, dst, protocol, src_port, dst_port, dscp)
        }
        _ => false,
    }
}

#[inline(always)]
fn term_matches_v4(
    term: &FilterTerm,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> bool {
    if term.protocol_match_enabled
        && (term.protocol_bitmap[(protocol / 64) as usize] & (1u64 << (protocol % 64))) == 0
    {
        return false;
    }
    if !term.source_v4.is_empty() && !term.source_v4.iter().any(|net| net.contains(src_ip)) {
        return false;
    }
    if !term.dest_v4.is_empty() && !term.dest_v4.iter().any(|net| net.contains(dst_ip)) {
        return false;
    }
    if !term.source_ports.matches(src_port) {
        return false;
    }
    if !term.dest_ports.matches(dst_port) {
        return false;
    }
    if term.dscp_match_enabled && (term.dscp_bitmap & (1u64 << dscp)) == 0 {
        return false;
    }
    true
}

#[inline(always)]
fn term_matches_v6(
    term: &FilterTerm,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
) -> bool {
    if term.protocol_match_enabled
        && (term.protocol_bitmap[(protocol / 64) as usize] & (1u64 << (protocol % 64))) == 0
    {
        return false;
    }
    if !term.source_v6.is_empty() && !term.source_v6.iter().any(|net| net.contains(src_ip)) {
        return false;
    }
    if !term.dest_v6.is_empty() && !term.dest_v6.iter().any(|net| net.contains(dst_ip)) {
        return false;
    }
    if !term.source_ports.matches(src_port) {
        return false;
    }
    if !term.dest_ports.matches(dst_port) {
        return false;
    }
    if term.dscp_match_enabled && (term.dscp_bitmap & (1u64 << dscp)) == 0 {
        return false;
    }
    true
}

// ----- Snapshot parsing -----

use super::{FirewallFilterSnapshot, FirewallTermSnapshot, PolicerSnapshot};

/// Build the complete FilterState from snapshot data.
pub(crate) fn parse_filter_state(
    filters: &[FirewallFilterSnapshot],
    policers: &[PolicerSnapshot],
    interfaces: &[super::InterfaceSnapshot],
    lo0_filter_v4: &str,
    lo0_filter_v6: &str,
) -> FilterState {
    let mut state = FilterState::default();

    // Parse filters
    for snap in filters {
        let key = qualify_filter_key(&snap.family, &snap.name);
        let filter = Filter {
            name: snap.name.clone(),
            family: snap.family.clone(),
            terms: snap.terms.iter().map(|t| parse_term(t)).collect(),
            affects_tx_selection: snap
                .terms
                .iter()
                .any(|term| !term.forwarding_class.is_empty() || term.dscp_rewrite.is_some()),
            affects_route_lookup: snap
                .terms
                .iter()
                .any(|term| !term.routing_instance.is_empty()),
            has_counter_terms: snap.terms.iter().any(|term| !term.count.is_empty()),
        };
        state.filters.insert(key, Arc::new(filter));
    }

    // Parse policers
    for snap in policers {
        state.policers.insert(
            snap.name.clone(),
            PolicerState::new(
                snap.name.clone(),
                snap.bandwidth_bps,
                snap.burst_bytes,
                snap.discard_excess,
            ),
        );
    }

    // Build per-interface filter assignments
    for iface in interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        if !iface.filter_input_v4.is_empty() {
            let key = qualify_filter_key("inet", &iface.filter_input_v4);
            if let Some(filter) = state.filters.get(&key) {
                if filter.affects_tx_selection {
                    state
                        .iface_filter_v4_affects_tx_selection
                        .insert(iface.ifindex);
                    state.has_input_tx_selection_v4 = true;
                }
                if filter.affects_route_lookup {
                    state
                        .iface_filter_v4_affects_route_lookup
                        .insert(iface.ifindex);
                }
                state
                    .iface_filter_v4_fast
                    .insert(iface.ifindex, filter.clone());
            }
            state.iface_filter_v4.insert(iface.ifindex, key);
        }
        if !iface.filter_output_v4.is_empty() {
            let key = qualify_filter_key("inet", &iface.filter_output_v4);
            if let Some(filter) = state.filters.get(&key) {
                if filter.affects_tx_selection || filter.has_counter_terms {
                    state
                        .iface_filter_out_v4_needs_tx_eval
                        .insert(iface.ifindex);
                }
                if filter.affects_tx_selection {
                    state.has_output_tx_selection_v4 = true;
                }
                state
                    .iface_filter_out_v4_fast
                    .insert(iface.ifindex, filter.clone());
            }
            state.iface_filter_out_v4.insert(iface.ifindex, key);
        }
        if !iface.filter_input_v6.is_empty() {
            let key = qualify_filter_key("inet6", &iface.filter_input_v6);
            if let Some(filter) = state.filters.get(&key) {
                if filter.affects_tx_selection {
                    state
                        .iface_filter_v6_affects_tx_selection
                        .insert(iface.ifindex);
                    state.has_input_tx_selection_v6 = true;
                }
                if filter.affects_route_lookup {
                    state
                        .iface_filter_v6_affects_route_lookup
                        .insert(iface.ifindex);
                }
                state
                    .iface_filter_v6_fast
                    .insert(iface.ifindex, filter.clone());
            }
            state.iface_filter_v6.insert(iface.ifindex, key);
        }
        if !iface.filter_output_v6.is_empty() {
            let key = qualify_filter_key("inet6", &iface.filter_output_v6);
            if let Some(filter) = state.filters.get(&key) {
                if filter.affects_tx_selection || filter.has_counter_terms {
                    state
                        .iface_filter_out_v6_needs_tx_eval
                        .insert(iface.ifindex);
                }
                if filter.affects_tx_selection {
                    state.has_output_tx_selection_v6 = true;
                }
                state
                    .iface_filter_out_v6_fast
                    .insert(iface.ifindex, filter.clone());
            }
            state.iface_filter_out_v6.insert(iface.ifindex, key);
        }
    }

    state.lo0_filter_v4 = if lo0_filter_v4.is_empty() {
        String::new()
    } else {
        qualify_filter_key("inet", lo0_filter_v4)
    };
    state.lo0_filter_v4_fast = state.filters.get(&state.lo0_filter_v4).cloned();
    state.lo0_filter_v6 = if lo0_filter_v6.is_empty() {
        String::new()
    } else {
        qualify_filter_key("inet6", lo0_filter_v6)
    };
    state.lo0_filter_v6_fast = state.filters.get(&state.lo0_filter_v6).cloned();

    state
}

fn qualify_filter_key(family: &str, filter_name: &str) -> String {
    format!("{family}:{filter_name}")
}

fn parse_term(snap: &FirewallTermSnapshot) -> FilterTerm {
    let mut source_v4 = Vec::new();
    let mut source_v6 = Vec::new();
    for addr in &snap.source_addresses {
        parse_address(addr, &mut source_v4, &mut source_v6);
    }
    let mut dest_v4 = Vec::new();
    let mut dest_v6 = Vec::new();
    for addr in &snap.destination_addresses {
        parse_address(addr, &mut dest_v4, &mut dest_v6);
    }
    let protocols: Vec<u8> = snap
        .protocols
        .iter()
        .filter_map(|p| parse_protocol(p))
        .collect();
    let source_ports: Vec<PortRange> = snap
        .source_ports
        .iter()
        .filter_map(|p| parse_port_spec(p))
        .flatten()
        .collect();
    let dest_ports: Vec<PortRange> = snap
        .destination_ports
        .iter()
        .filter_map(|p| parse_port_spec(p))
        .flatten()
        .collect();
    let action = match snap.action.as_str() {
        "accept" => FilterAction::Accept,
        "reject" => FilterAction::Reject,
        "discard" => FilterAction::Discard,
        _ => FilterAction::Accept,
    };
    let dscp_rewrite = snap.dscp_rewrite.map(|value| value & 0x3f);

    FilterTerm {
        name: snap.name.clone(),
        source_v4,
        source_v6,
        dest_v4,
        dest_v6,
        protocol_bitmap: build_u8_match_bitmap(&protocols),
        protocol_match_enabled: !protocols.is_empty(),
        source_ports: build_port_matcher(source_ports),
        dest_ports: build_port_matcher(dest_ports),
        dscp_bitmap: build_u6_match_bitmap(&snap.dscp_values),
        dscp_match_enabled: !snap.dscp_values.is_empty(),
        action,
        count: snap.count.clone(),
        has_count: !snap.count.is_empty(),
        log: snap.log,
        policer_name: snap.policer.clone(),
        routing_instance: snap.routing_instance.clone(),
        forwarding_class: Arc::<str>::from(snap.forwarding_class.as_str()),
        dscp_rewrite,
        counter: Arc::new(FilterTermCounter::default()),
    }
}

fn parse_address(prefix: &str, out_v4: &mut Vec<PrefixV4>, out_v6: &mut Vec<PrefixV6>) {
    if prefix.is_empty() || prefix == "any" {
        return;
    }
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => out_v4.push(PrefixV4::from_net(net)),
        Ok(IpNet::V6(net)) => out_v6.push(PrefixV6::from_net(net)),
        Err(_) => {
            if let Ok(ip) = prefix.parse::<Ipv4Addr>() {
                out_v4.push(PrefixV4::from_net(
                    ipnet::Ipv4Net::new(ip, 32).expect("v4 /32"),
                ));
            } else if let Ok(ip) = prefix.parse::<Ipv6Addr>() {
                out_v6.push(PrefixV6::from_net(
                    ipnet::Ipv6Net::new(ip, 128).expect("v6 /128"),
                ));
            }
        }
    }
}

fn parse_protocol(protocol: &str) -> Option<u8> {
    match protocol {
        "" => None,
        "tcp" => Some(PROTO_TCP),
        "udp" => Some(PROTO_UDP),
        "icmp" => Some(PROTO_ICMP),
        "icmpv6" => Some(PROTO_ICMPV6),
        "gre" => Some(PROTO_GRE),
        "89" | "ospf" => Some(PROTO_OSPF),
        "4" | "ipip" => Some(PROTO_IPIP),
        _ => protocol.parse::<u8>().ok(),
    }
}

fn parse_port_spec(spec: &str) -> Option<Vec<PortRange>> {
    if spec.is_empty() {
        return Some(Vec::new());
    }
    let normalized = match spec {
        "http" => "80",
        "https" => "443",
        "ssh" => "22",
        "telnet" => "23",
        "ftp" => "21",
        "ftp-data" => "20",
        "smtp" => "25",
        "dns" => "53",
        "pop3" => "110",
        "imap" => "143",
        "snmp" => "161",
        "ntp" => "123",
        "bgp" => "179",
        "ldap" => "389",
        "syslog" => "514",
        other => other,
    };
    if let Some((low, high)) = normalized.split_once('-') {
        let low = low.parse::<u16>().ok()?;
        let high = high.parse::<u16>().ok()?;
        if low == 0 || low > high {
            return None;
        }
        return Some(vec![PortRange { low, high }]);
    }
    let port = normalized.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    Some(vec![PortRange {
        low: port,
        high: port,
    }])
}

fn build_port_matcher(mut ranges: Vec<PortRange>) -> PortMatcher {
    match ranges.len() {
        0 => PortMatcher::Any,
        1 => {
            let range = ranges.pop().expect("single range");
            if range.low == range.high {
                PortMatcher::Single(range.low)
            } else {
                PortMatcher::Range(range)
            }
        }
        _ => PortMatcher::Set(ranges.into_boxed_slice()),
    }
}

fn build_u8_match_bitmap(values: &[u8]) -> [u64; 4] {
    let mut bitmap = [0u64; 4];
    for value in values {
        bitmap[(value / 64) as usize] |= 1u64 << (value % 64);
    }
    bitmap
}

fn build_u6_match_bitmap(values: &[u8]) -> u64 {
    let mut bitmap = 0u64;
    for value in values {
        if *value < 64 {
            bitmap |= 1u64 << value;
        }
    }
    bitmap
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_filter_state(
        filters: &[FirewallFilterSnapshot],
        policers: &[PolicerSnapshot],
    ) -> FilterState {
        parse_filter_state(filters, policers, &[], "", "")
    }

    #[test]
    fn basic_accept_discard() {
        let state = make_filter_state(
            &[FirewallFilterSnapshot {
                name: "test-filter".into(),
                family: "inet".into(),
                terms: vec![
                    FirewallTermSnapshot {
                        name: "deny-ssh".into(),
                        destination_addresses: vec![],
                        source_addresses: vec![],
                        protocols: vec!["tcp".into()],
                        source_ports: vec![],
                        destination_ports: vec!["22".into()],
                        dscp_values: vec![],
                        action: "discard".into(),
                        count: String::new(),
                        log: false,
                        policer: String::new(),
                        routing_instance: String::new(),
                        forwarding_class: String::new(),
                        dscp_rewrite: None,
                    },
                    FirewallTermSnapshot {
                        name: "allow-all".into(),
                        destination_addresses: vec![],
                        source_addresses: vec![],
                        protocols: vec![],
                        source_ports: vec![],
                        destination_ports: vec![],
                        dscp_values: vec![],
                        action: "accept".into(),
                        count: String::new(),
                        log: false,
                        policer: String::new(),
                        routing_instance: String::new(),
                        forwarding_class: String::new(),
                        dscp_rewrite: None,
                    },
                ],
            }],
            &[],
        );
        // SSH traffic should be discarded
        let result = evaluate_filter(
            &state,
            "inet:test-filter",
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),
            PROTO_TCP,
            12345,
            22,
            0,
        );
        assert_eq!(result.action, FilterAction::Discard);

        // HTTP traffic should be accepted
        let result = evaluate_filter(
            &state,
            "inet:test-filter",
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),
            PROTO_TCP,
            12345,
            80,
            0,
        );
        assert_eq!(result.action, FilterAction::Accept);
    }

    #[test]
    fn port_range_matching() {
        let state = make_filter_state(
            &[FirewallFilterSnapshot {
                name: "port-range".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "high-ports".into(),
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec!["tcp".into()],
                    source_ports: vec![],
                    destination_ports: vec!["1024-65535".into()],
                    dscp_values: vec![],
                    action: "discard".into(),
                    count: String::new(),
                    log: false,
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
                }],
            }],
            &[],
        );
        // Port 2000 is in range
        let result = evaluate_filter(
            &state,
            "inet:port-range",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_TCP,
            54321,
            2000,
            0,
        );
        assert_eq!(result.action, FilterAction::Discard);

        // Port 80 is not in range — no match, implicit accept
        let result = evaluate_filter(
            &state,
            "inet:port-range",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_TCP,
            54321,
            80,
            0,
        );
        assert_eq!(result.action, FilterAction::Accept);
    }

    #[test]
    fn protocol_matching() {
        let state = make_filter_state(
            &[FirewallFilterSnapshot {
                name: "proto-filter".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "deny-icmp".into(),
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec!["icmp".into()],
                    source_ports: vec![],
                    destination_ports: vec![],
                    dscp_values: vec![],
                    action: "discard".into(),
                    count: String::new(),
                    log: false,
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
                }],
            }],
            &[],
        );
        // ICMP should be discarded
        let result = evaluate_filter(
            &state,
            "inet:proto-filter",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_ICMP,
            0,
            0,
            0,
        );
        assert_eq!(result.action, FilterAction::Discard);

        // TCP should pass (no match)
        let result = evaluate_filter(
            &state,
            "inet:proto-filter",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_TCP,
            1234,
            80,
            0,
        );
        assert_eq!(result.action, FilterAction::Accept);
    }

    #[test]
    fn dscp_rewrite_action() {
        let state = make_filter_state(
            &[FirewallFilterSnapshot {
                name: "dscp-rewrite".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "mark-ef".into(),
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec!["udp".into()],
                    source_ports: vec![],
                    destination_ports: vec!["5060".into()],
                    dscp_values: vec![],
                    action: "accept".into(),
                    count: String::new(),
                    log: false,
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: Some(46), // EF
                }],
            }],
            &[],
        );
        let result = evaluate_filter(
            &state,
            "inet:dscp-rewrite",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_UDP,
            54321,
            5060,
            0,
        );
        assert_eq!(result.action, FilterAction::Accept);
        assert_eq!(result.dscp_rewrite, Some(46));
    }

    #[test]
    fn dscp_rewrite_action_allows_default_zero() {
        let state = make_filter_state(
            &[FirewallFilterSnapshot {
                name: "dscp-default".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "mark-default".into(),
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec!["udp".into()],
                    source_ports: vec![],
                    destination_ports: vec!["5060".into()],
                    dscp_values: vec![],
                    action: "accept".into(),
                    count: String::new(),
                    log: false,
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: Some(0),
                }],
            }],
            &[],
        );
        let result = evaluate_filter(
            &state,
            "inet:dscp-default",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_UDP,
            54321,
            5060,
            0,
        );
        assert_eq!(result.action, FilterAction::Accept);
        assert_eq!(result.dscp_rewrite, Some(0));
    }

    #[test]
    fn token_bucket_policer() {
        let mut policer = PolicerState::new(
            "1mbps".into(),
            1_000_000, // 1 Mbps = 125,000 bytes/sec
            125_000,   // burst = 125KB
            true,
        );

        // First packet at t=0 — should be within burst
        let conforming = policer.consume(0, 1000);
        assert!(conforming, "first packet within burst should conform");

        // Consume most of the burst
        let conforming = policer.consume(0, 120_000);
        assert!(conforming, "second packet within burst should conform");

        // This should exceed burst (only ~4000 tokens left)
        let conforming = policer.consume(0, 10_000);
        assert!(
            !conforming,
            "packet exceeding burst should be non-conforming"
        );

        // After 1 second, tokens should have refilled
        let conforming = policer.consume(1_000_000_000, 1000);
        assert!(conforming, "packet after refill should conform");
    }

    #[test]
    fn multiple_terms_first_match_wins() {
        let state = make_filter_state(
            &[FirewallFilterSnapshot {
                name: "multi".into(),
                family: "inet".into(),
                terms: vec![
                    FirewallTermSnapshot {
                        name: "allow-dns".into(),
                        destination_addresses: vec![],
                        source_addresses: vec![],
                        protocols: vec!["udp".into()],
                        source_ports: vec![],
                        destination_ports: vec!["53".into()],
                        dscp_values: vec![],
                        action: "accept".into(),
                        count: String::new(),
                        log: false,
                        policer: String::new(),
                        routing_instance: String::new(),
                        forwarding_class: String::new(),
                        dscp_rewrite: None,
                    },
                    FirewallTermSnapshot {
                        name: "deny-all-udp".into(),
                        destination_addresses: vec![],
                        source_addresses: vec![],
                        protocols: vec!["udp".into()],
                        source_ports: vec![],
                        destination_ports: vec![],
                        dscp_values: vec![],
                        action: "discard".into(),
                        count: String::new(),
                        log: false,
                        policer: String::new(),
                        routing_instance: String::new(),
                        forwarding_class: String::new(),
                        dscp_rewrite: None,
                    },
                ],
            }],
            &[],
        );
        // DNS should be accepted (first term wins)
        let result = evaluate_filter(
            &state,
            "inet:multi",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_UDP,
            12345,
            53,
            0,
        );
        assert_eq!(result.action, FilterAction::Accept);

        // Other UDP should be discarded (second term)
        let result = evaluate_filter(
            &state,
            "inet:multi",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_UDP,
            12345,
            1234,
            0,
        );
        assert_eq!(result.action, FilterAction::Discard);
    }

    #[test]
    fn source_dest_address_matching() {
        let state = make_filter_state(
            &[FirewallFilterSnapshot {
                name: "addr-filter".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "deny-from-subnet".into(),
                    source_addresses: vec!["192.168.1.0/24".into()],
                    destination_addresses: vec!["10.0.0.0/8".into()],
                    protocols: vec![],
                    source_ports: vec![],
                    destination_ports: vec![],
                    dscp_values: vec![],
                    action: "discard".into(),
                    count: String::new(),
                    log: false,
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
                }],
            }],
            &[],
        );
        // Matching src+dst
        let result = evaluate_filter(
            &state,
            "inet:addr-filter",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            PROTO_TCP,
            1234,
            80,
            0,
        );
        assert_eq!(result.action, FilterAction::Discard);

        // Non-matching source
        let result = evaluate_filter(
            &state,
            "inet:addr-filter",
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            PROTO_TCP,
            1234,
            80,
            0,
        );
        assert_eq!(result.action, FilterAction::Accept);
    }

    #[test]
    fn interface_filter_assignment() {
        let ifaces = vec![crate::InterfaceSnapshot {
            name: "ge-0/0/0.0".into(),
            ifindex: 5,
            filter_input_v4: "protect-RE".into(),
            filter_input_v6: "protect-RE-v6".into(),
            filter_output_v4: "egress-v4".into(),
            filter_output_v6: "egress-v6".into(),
            ..Default::default()
        }];
        let state = parse_filter_state(
            &[
                FirewallFilterSnapshot {
                    name: "protect-RE".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "deny-all".into(),
                        action: "discard".into(),
                        ..Default::default()
                    }],
                },
                FirewallFilterSnapshot {
                    name: "protect-RE-v6".into(),
                    family: "inet6".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "deny-all".into(),
                        action: "discard".into(),
                        ..Default::default()
                    }],
                },
                FirewallFilterSnapshot {
                    name: "egress-v4".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "classify".into(),
                        action: "accept".into(),
                        forwarding_class: "bandwidth-10mb".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["5201".into()],
                        ..Default::default()
                    }],
                },
                FirewallFilterSnapshot {
                    name: "egress-v6".into(),
                    family: "inet6".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "classify".into(),
                        action: "accept".into(),
                        forwarding_class: "bandwidth-10mb".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["5201".into()],
                        ..Default::default()
                    }],
                },
            ],
            &[],
            &ifaces,
            "",
            "",
        );
        // v4 filter on ifindex 5
        let result = evaluate_interface_filter(
            &state,
            5,
            false,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_TCP,
            1234,
            80,
            0,
        );
        assert_eq!(result.action, FilterAction::Discard);

        // No filter on ifindex 6
        let result = evaluate_interface_filter(
            &state,
            6,
            false,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_TCP,
            1234,
            80,
            0,
        );
        assert_eq!(result.action, FilterAction::Accept);

        let result = evaluate_interface_output_filter(
            &state,
            5,
            false,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_TCP,
            1234,
            5201,
            0,
        );
        assert_eq!(result.forwarding_class.as_ref(), "bandwidth-10mb");
    }

    #[test]
    fn parse_filter_state_prequalifies_interface_and_lo0_filter_keys() {
        let ifaces = vec![crate::InterfaceSnapshot {
            name: "reth0.80".into(),
            ifindex: 7,
            filter_input_v4: "ingress-v4".into(),
            filter_output_v6: "egress-v6".into(),
            ..Default::default()
        }];
        let state = parse_filter_state(
            &[
                FirewallFilterSnapshot {
                    name: "ingress-v4".into(),
                    family: "inet".into(),
                    terms: vec![FirewallTermSnapshot {
                        name: "tx-select".into(),
                        forwarding_class: "best-effort".into(),
                        routing_instance: "sfmix".into(),
                        ..Default::default()
                    }],
                },
                FirewallFilterSnapshot {
                    name: "egress-v6".into(),
                    family: "inet6".into(),
                    terms: vec![],
                },
                FirewallFilterSnapshot {
                    name: "protect-re".into(),
                    family: "inet".into(),
                    terms: vec![],
                },
                FirewallFilterSnapshot {
                    name: "protect-re-v6".into(),
                    family: "inet6".into(),
                    terms: vec![],
                },
            ],
            &[],
            &ifaces,
            "protect-re",
            "protect-re-v6",
        );
        assert_eq!(
            state.iface_filter_v4.get(&7).map(String::as_str),
            Some("inet:ingress-v4")
        );
        assert!(state.iface_filter_v4_affects_tx_selection.contains(&7));
        assert!(state.has_input_tx_selection_v4);
        assert!(state.iface_filter_v4_affects_route_lookup.contains(&7));
        assert!(!state.iface_filter_out_v4_needs_tx_eval.contains(&7));
        assert!(!state.iface_filter_out_v6_needs_tx_eval.contains(&7));
        assert!(!state.has_output_tx_selection_v4);
        assert!(!state.has_output_tx_selection_v6);
        assert_eq!(
            state.iface_filter_out_v6.get(&7).map(String::as_str),
            Some("inet6:egress-v6")
        );
        assert_eq!(state.lo0_filter_v4, "inet:protect-re");
        assert_eq!(state.lo0_filter_v6, "inet6:protect-re-v6");
    }

    #[test]
    fn accept_only_output_filter_does_not_need_tx_eval() {
        let ifaces = vec![crate::InterfaceSnapshot {
            name: "reth0.80".into(),
            ifindex: 7,
            filter_output_v4: "wan-allow".into(),
            ..Default::default()
        }];
        let state = parse_filter_state(
            &[FirewallFilterSnapshot {
                name: "wan-allow".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "allow".into(),
                    action: "accept".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    ..Default::default()
                }],
            }],
            &[],
            &ifaces,
            "",
            "",
        );

        assert!(!interface_output_filter_needs_tx_eval(&state, 7, false));
        assert!(!filter_state_has_output_tx_selection(&state, false));
    }

    #[test]
    fn interface_filter_routing_instance_counted_returns_matching_override() {
        let ifaces = vec![crate::InterfaceSnapshot {
            name: "reth1.0".into(),
            ifindex: 11,
            filter_input_v6: "sfmix-pbr".into(),
            ..Default::default()
        }];
        let state = parse_filter_state(
            &[FirewallFilterSnapshot {
                name: "sfmix-pbr".into(),
                family: "inet6".into(),
                terms: vec![
                    FirewallTermSnapshot {
                        name: "match-iperf".into(),
                        action: "accept".into(),
                        count: "iperf-v6".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["5201".into()],
                        routing_instance: "sfmix".into(),
                        ..Default::default()
                    },
                    FirewallTermSnapshot {
                        name: "default".into(),
                        action: "accept".into(),
                        ..Default::default()
                    },
                ],
            }],
            &[],
            &ifaces,
            "",
            "",
        );

        assert!(interface_filter_affects_route_lookup(&state, 11, true));
        let routing_instance = evaluate_interface_filter_routing_instance_counted(
            &state,
            11,
            true,
            IpAddr::V6("2001:db8::10".parse().unwrap()),
            IpAddr::V6("2001:db8::200".parse().unwrap()),
            PROTO_TCP,
            12345,
            5201,
            0,
            1500,
        );
        assert_eq!(routing_instance, Some("sfmix"));
        let filter = state.iface_filter_v6_fast.get(&11).expect("input filter");
        assert_eq!(filter.terms[0].counter.packets.load(Ordering::Relaxed), 1);
        assert_eq!(filter.terms[0].counter.bytes.load(Ordering::Relaxed), 1500);
    }

    #[test]
    fn interface_output_filter_counted_records_term_hits() {
        let ifaces = vec![crate::InterfaceSnapshot {
            name: "reth0.80".into(),
            ifindex: 7,
            filter_output_v6: "bandwidth-output".into(),
            ..Default::default()
        }];
        let state = parse_filter_state(
            &[FirewallFilterSnapshot {
                name: "bandwidth-output".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "iperf-a".into(),
                    action: "accept".into(),
                    forwarding_class: "iperf-a".into(),
                    count: "iperf-a-v6".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    ..Default::default()
                }],
            }],
            &[],
            &ifaces,
            "",
            "",
        );
        let result = evaluate_interface_output_filter_counted(
            &state,
            7,
            true,
            IpAddr::V6("2001:db8::10".parse().unwrap()),
            IpAddr::V6("2001:db8::200".parse().unwrap()),
            PROTO_TCP,
            40000,
            5201,
            0,
            1514,
        );
        assert_eq!(result.forwarding_class.as_ref(), "iperf-a");
        let filter = state
            .filters
            .get("inet6:bandwidth-output")
            .expect("inet6 output filter");
        let term = filter.terms.first().expect("first term");
        assert_eq!(term.counter.packets.load(Ordering::Relaxed), 1);
        assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 1514);
    }

    #[test]
    fn interface_output_filter_without_count_does_not_record_term_hits() {
        let ifaces = vec![crate::InterfaceSnapshot {
            name: "reth0.80".into(),
            ifindex: 7,
            filter_output_v6: "bandwidth-output".into(),
            ..Default::default()
        }];
        let state = parse_filter_state(
            &[FirewallFilterSnapshot {
                name: "bandwidth-output".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "iperf-a".into(),
                    action: "accept".into(),
                    forwarding_class: "iperf-a".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    ..Default::default()
                }],
            }],
            &[],
            &ifaces,
            "",
            "",
        );
        let result = evaluate_interface_output_filter_counted(
            &state,
            7,
            true,
            IpAddr::V6("2001:db8::10".parse().unwrap()),
            IpAddr::V6("2001:db8::200".parse().unwrap()),
            PROTO_TCP,
            40000,
            5201,
            0,
            1514,
        );
        assert_eq!(result.forwarding_class.as_ref(), "iperf-a");
        let filter = state
            .filters
            .get("inet6:bandwidth-output")
            .expect("inet6 output filter");
        let term = filter.terms.first().expect("first term");
        assert_eq!(term.counter.packets.load(Ordering::Relaxed), 0);
        assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn lo0_filter_evaluation() {
        let state = parse_filter_state(
            &[FirewallFilterSnapshot {
                name: "protect-RE".into(),
                family: "inet".into(),
                terms: vec![
                    FirewallTermSnapshot {
                        name: "allow-ssh".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["22".into()],
                        action: "accept".into(),
                        ..Default::default()
                    },
                    FirewallTermSnapshot {
                        name: "deny-rest".into(),
                        action: "discard".into(),
                        ..Default::default()
                    },
                ],
            }],
            &[],
            &[],
            "protect-RE",
            "",
        );
        // SSH should pass lo0 filter
        let result = evaluate_lo0_filter(
            &state,
            false,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_TCP,
            12345,
            22,
            0,
        );
        assert_eq!(result.action, FilterAction::Accept);

        // HTTP should be denied by lo0 filter
        let result = evaluate_lo0_filter(
            &state,
            false,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_TCP,
            12345,
            80,
            0,
        );
        assert_eq!(result.action, FilterAction::Discard);
    }

    #[test]
    fn dscp_match_in_term() {
        let state = make_filter_state(
            &[FirewallFilterSnapshot {
                name: "dscp-filter".into(),
                family: "inet".into(),
                terms: vec![
                    FirewallTermSnapshot {
                        name: "match-ef".into(),
                        dscp_values: vec![46],
                        action: "accept".into(),
                        dscp_rewrite: None,
                        ..Default::default()
                    },
                    FirewallTermSnapshot {
                        name: "deny-rest".into(),
                        action: "discard".into(),
                        ..Default::default()
                    },
                ],
            }],
            &[],
        );
        // DSCP 46 (EF) matches
        let result = evaluate_filter(
            &state,
            "inet:dscp-filter",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_UDP,
            1234,
            5060,
            46,
        );
        assert_eq!(result.action, FilterAction::Accept);

        // DSCP 0 doesn't match first term, falls through to deny
        let result = evaluate_filter(
            &state,
            "inet:dscp-filter",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_UDP,
            1234,
            5060,
            0,
        );
        assert_eq!(result.action, FilterAction::Discard);
    }
}
