// Source NAT (SNAT) rules + matching + lookup.
//
// Owns rule parsing from snapshots, the address/port-pool match
// pipeline, and the public release/rollback entry points that
// drive the allocator. Pool ownership / persistent lease state
// machine lives in the sibling allocator.rs.
//
// #3111: pool-mode SNAT only allocates/translates an L4 port for
// protocols that actually carry one (TCP/UDP, via
// `crate::ip_proto::has_l4_ports`). A port-less protocol
// (GRE/ESP/AH/OSPF/ICMP/...) gets IP-only translation — no pool port
// is consumed and `rewrite_src_port` is left unset, so the packet
// rewriters never overwrite its first two L4 bytes (GRE flags / ESP
// SPI). The out-of-band `None` protocol (#5687) is the "L4 tuple unknown"
// signal used by the address-only `match_source_nat` callers; it keeps its
// historical round-robin `try_next_port` behavior (never frame-written,
// because the rewriters gate every L4 write on `has_l4_ports`). A genuine
// IPv4 protocol 0 (HOPOPT) arrives as `Some(0)` and is NOT the sentinel —
// it takes the real port-less address-only path and its reverse tuple is
// matchable.
//
// #5269: the address-only branch (`port no-translation` on a port-bearing
// protocol, or a port-less protocol) selects a pool address but PRESERVES the
// source port on the wire, so — unlike PAT — it cannot make the translated
// `(pool_addr, port)` unique by handing out a fresh port. It therefore MINTS an
// occupancy token via `PortAllocator::reserve_address_only`, keyed on the
// translated REVERSE identity (protocol, pool address, preserved source port,
// remote endpoint). The first flow to claim an identity owns it; a genuinely-
// colliding second flow (same identity) is DENIED as exhaustion
// (`AllocatorExhausted` -> `SourceNatLookup::Unavailable` -> the same drop /
// `nat_alloc_fail` path a full port-translating pool takes) rather than
// receiving an unowned duplicate whose replies the reverse (1:N) index cannot
// disambiguate — the vSRX address-only / persistent capacity limit. A non-
// colliding flow (different preserved port, pool address, or remote) mints its
// own token and succeeds. The token is freed by the SAME teardown path as a PAT
// port (`release_source_nat_allocation`), which now derives the preserved port
// from the flow key when the decision carried no port rewrite. The
// tuple-unknown (`None`) wrapper mints NO token (never a real framed flow /
// reverse session entry).

use super::allocator::{
    DeterministicV4, DeterministicV6, NS_PER_SEC, NatHolder, PersistentSourceKey,
    PoolAddressFamily, PortAllocator, TranslatedTuple, deterministic_indices_v4,
};
use super::{NatCounterStore, NatDecision, NatRuleCounter, NatScopeCtx};
use crate::SourceNATRuleSnapshot;
use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6};
use crate::prefix::{PrefixV4, PrefixV6};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

const DEFAULT_PERSISTENT_NAT_TIMEOUT_SECS: i64 = 300;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SourceNatLookup {
    NoMatch,
    Matched(NatDecision),
    Unavailable(SourceNatFailure),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceNatFailure {
    pub(crate) rule_name: String,
    pub(crate) pool_name: String,
    pub(crate) reason: SourceNatFailureReason,
}

impl SourceNatFailure {
    fn for_rule(rule: &SourceNatRule, reason: SourceNatFailureReason) -> Self {
        Self {
            rule_name: rule.name.clone(),
            pool_name: rule.pool_name.clone(),
            reason,
        }
    }

    pub(crate) fn exception_reason(&self) -> &'static str {
        self.reason.exception_reason()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceNatFailureReason {
    MissingPool,
    EmptyPool,
    InvalidPool,
    InvalidPortRange,
    WrongAddressFamily,
    AllocatorExhausted,
    /// #1852: a non-first IP fragment reached a port-translating
    /// (pool-mode) source-NAT rule. It has no L4 ports — allocating a
    /// mapping from its garbage payload "ports" would leak a pool port
    /// per fragment and corrupt payload. Without datapath reassembly the
    /// fragment cannot be correctly port-mapped, so it is dropped.
    NonFirstFragment,
    /// #4559: a deterministic CGNAT pool matched a flow whose subscriber IPv4 is
    /// outside the configured `host address` range (or the pool's parameters are
    /// degenerate). Deterministic NAT reserves a fixed block per in-range
    /// subscriber; an out-of-range source has no reserved block, so the
    /// allocation fails closed rather than silently round-robining it.
    DeterministicSubscriberOutOfRange,
    /// #5688: an interface-mode source-NAT rule matched, but the egress interface
    /// has NO address of the packet's family (a v4 packet on an egress interface
    /// with only v6 addresses, or vice versa). Interface SNAT translates the
    /// source to the egress interface's OWN same-family address; with none to
    /// use there is nothing to translate to, so the flow fails CLOSED (drop +
    /// count) rather than forwarding the private/internal source UNTRANSLATED
    /// onto the egress — the leak this closes.
    InterfaceNoEgressAddress,
    /// #6812: the pool's allocator key did not fit within the source-NAT
    /// AGGREGATE cardinality budget (pool count / total addresses / total port
    /// capacity — the same budgets the Go #5877 strict commit gate enforces)
    /// at the apply boundary, so no allocator was built for it. Reached only
    /// from a tolerated (lenient-load / peer-synced) config or a hand-crafted
    /// snapshot: a strict commit rejects the over-budget config before apply.
    /// Fail-closed exactly like the other pool-unusable reasons — the flow
    /// gets `Unavailable` (drop + count), never an untranslated forward.
    OverBudget,
}

impl SourceNatFailureReason {
    fn exception_reason(self) -> &'static str {
        match self {
            Self::MissingPool => "source_nat_pool_missing",
            Self::EmptyPool => "source_nat_pool_empty",
            Self::InvalidPool => "source_nat_pool_invalid",
            Self::InvalidPortRange => "source_nat_pool_invalid_port_range",
            Self::WrongAddressFamily => "source_nat_pool_wrong_family",
            Self::AllocatorExhausted => "source_nat_pool_exhausted",
            Self::NonFirstFragment => "source_nat_non_first_fragment",
            Self::DeterministicSubscriberOutOfRange => {
                "source_nat_deterministic_subscriber_out_of_range"
            }
            Self::InterfaceNoEgressAddress => "source_nat_interface_no_egress_address",
            Self::OverBudget => "source_nat_pool_over_budget",
        }
    }
}

fn source_nat_failure_reason_from_snapshot(reason: &str) -> SourceNatFailureReason {
    match reason {
        "missing_pool" => SourceNatFailureReason::MissingPool,
        "empty_pool" => SourceNatFailureReason::EmptyPool,
        "invalid_port_range" => SourceNatFailureReason::InvalidPortRange,
        // #6812 F1 round 2: the Go snapshot builder now emits this for a pool
        // with ANY member `expand_pool_address` would refuse — an unparseable
        // token, a malformed mask, or an over-capacity prefix. It decodes to the
        // SAME variant the parse loop below assigns from its own
        // `invalid_pool_address` flag, so the disposition of such a pool is
        // unchanged; deciding it Go-side is what lets the aggregate budget walk
        // exclude the pool it knows builds no allocator.
        "invalid_pool" => SourceNatFailureReason::InvalidPool,
        "wrong_address_family" => SourceNatFailureReason::WrongAddressFamily,
        "allocator_exhausted" => SourceNatFailureReason::AllocatorExhausted,
        // #6812: the Go tolerant snapshot poison for a pool that does not fit
        // the #5877 aggregate cardinality budget. Wire-skew safe: an older
        // helper maps the unknown string to InvalidPool via the catch-all —
        // still fail-closed, just a less specific diagnostic.
        "aggregate_over_budget" => SourceNatFailureReason::OverBudget,
        _ => SourceNatFailureReason::InvalidPool,
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct SourceNatFlowKey {
    pub(crate) protocol: u8,
    pub(crate) src_ip: IpAddr,
    pub(crate) dst_ip: IpAddr,
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
}

/// #2823: remote-endpoint scope of a persistent NAT lease, the full
/// three-way Junos `persistent-nat permit` enum. Replaces the pre-#2823
/// binary `permit_any_remote_host` bool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum PersistentNatPermit {
    /// `any-remote-host`: lease keyed by the local source tuple ONLY — any
    /// remote host reuses the same translated mapping.
    AnyRemoteHost,
    /// `target-host`: lease keyed by source tuple + remote destination IP
    /// (the destination PORT is dropped) — a second flow from the same
    /// source to a NEW port on the SAME remote host reuses the binding.
    TargetHost,
    /// `target-host-port`: lease keyed by source tuple + remote destination
    /// IP + destination port — a new remote port keys to a distinct lease
    /// and gets a fresh mapping. The pre-#2823 disabled-flag behavior, the
    /// default mode, and the fallback for an empty wire value.
    #[default]
    TargetHostPort,
}

impl PersistentNatPermit {
    /// Decode the wire fields. Prefer the explicit `persistent_nat_permit`
    /// string; when it is empty (an older control plane that predates the
    /// enum) fall back to the legacy `persistent_nat_permit_any_remote_host`
    /// bool: true => AnyRemoteHost, false => TargetHostPort (the pre-#2823
    /// disabled-flag (dst_ip, dst_port) keying).
    pub(crate) fn from_wire(permit: &str, permit_any_remote_host: bool) -> Self {
        match permit {
            "any-remote-host" => Self::AnyRemoteHost,
            "target-host" => Self::TargetHost,
            "target-host-port" => Self::TargetHostPort,
            _ if permit_any_remote_host => Self::AnyRemoteHost,
            _ => Self::TargetHostPort,
        }
    }

    /// Junos wire string for the status surface (#3193). The control plane
    /// renders this verbatim as `Permit:` in `show security nat source`, so
    /// the operator sees the actual three-way mode rather than a binary flag.
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            Self::AnyRemoteHost => "any-remote-host",
            Self::TargetHost => "target-host",
            Self::TargetHostPort => "target-host-port",
        }
    }
}

impl SourceNatFlowKey {
    /// #2397: build the persistent-NAT lease key for this flow.
    ///
    /// #2823: the scope is selected by the three-way `permit` enum:
    ///   - `AnyRemoteHost`   -> `remote = None`: source-tuple-only key, any
    ///     remote host reuses the mapping.
    ///   - `TargetHost`      -> `remote = Some((dst_ip, 0))`: the destination
    ///     IP is folded in but the port is dropped, so a second flow from the
    ///     same source to a NEW port on the SAME remote host keys to the same
    ///     lease and reuses the mapping.
    ///   - `TargetHostPort`  -> `remote = Some((dst_ip, dst_port))`: the full
    ///     remote endpoint is folded in, so a different remote port keys to a
    ///     distinct lease and gets a fresh mapping (the pre-#2823 behavior).
    pub(super) fn persistent_source_key(self, permit: PersistentNatPermit) -> PersistentSourceKey {
        PersistentSourceKey {
            protocol: self.protocol,
            src_ip: self.src_ip,
            src_port: self.src_port,
            remote: match permit {
                PersistentNatPermit::AnyRemoteHost => None,
                PersistentNatPermit::TargetHost => Some((self.dst_ip, 0)),
                PersistentNatPermit::TargetHostPort => Some((self.dst_ip, self.dst_port)),
            },
        }
    }
}

/// #3429: source-NAT `match application` protocol wildcard. 256 is outside the
/// 0-255 protocol range so it never aliases protocol 0 (HOPOPT); a term carrying
/// it matches any L4 protocol. The Go builder emits it for an application whose
/// protocol token is empty/unresolvable. A reserved 0xFFFF sentinel (any value
/// in 257..=65535 works) can never equal a real protocol and is not the
/// wildcard, so a term carrying it matches nothing — the fail-closed marker the
/// Go builder emits for a configured-but-unresolvable `match application`.
pub(crate) const SOURCE_NAT_PROTO_ANY: u16 = 256;

/// #3429/#3491: one resolved source-NAT `match application` term — an L4
/// protocol (IANA number, or `SOURCE_NAT_PROTO_ANY` for any) and optional
/// inclusive destination- and source-port ranges. The flow matches the term when
/// its protocol equals `protocol` (or `protocol == SOURCE_NAT_PROTO_ANY`) AND,
/// when `ports` is non-empty, its destination port falls in one of the ranges,
/// AND, when `src_ports` is non-empty (#3491), its source port falls in one of
/// the source ranges. An empty axis is unconstrained on that axis.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SourceNatAppTerm {
    pub(crate) protocol: u16,
    pub(crate) ports: Vec<(u16, u16)>,
    pub(crate) src_ports: Vec<(u16, u16)>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SourceNatRule {
    pub(crate) name: String,
    pub(crate) from_zone: String,
    pub(crate) to_zone: String,
    /// #3096: interface-/routing-instance-scoped rule-set matching. A
    /// non-empty value restricts the rule to flows whose ingress (`from_*`) or
    /// egress (`to_*`) interface config-name / routing-instance equals it.
    /// Empty = unscoped on that axis. Enforced in `scope_matches`.
    pub(crate) from_interface: String,
    pub(crate) to_interface: String,
    pub(crate) from_routing_instance: String,
    pub(crate) to_routing_instance: String,
    pub(crate) source_v4: Vec<PrefixV4>,
    pub(crate) source_v6: Vec<PrefixV6>,
    pub(crate) destination_v4: Vec<PrefixV4>,
    pub(crate) destination_v6: Vec<PrefixV6>,
    /// #2398: whether the rule carried a `match source-address` constraint at
    /// all (snapshot source list non-empty), independent of how many entries
    /// parsed. `false` = unscoped source -> match any source (unchanged
    /// behavior). `true` but BOTH `source_v4`/`source_v6` empty (every
    /// configured prefix failed to parse) => match NOTHING (fail closed), never
    /// the pre-#2398 collapse-to-match-any fail-open broadening.
    pub(crate) source_constrained: bool,
    /// #2398: whether the rule carried a `match destination-address`
    /// constraint at all. Same fail-closed semantics as `source_constrained`,
    /// for the destination match set.
    pub(crate) destination_constrained: bool,
    /// #3429: source-NAT `match destination-port` constraint as inclusive
    /// (low, high) ranges. Empty = port-unconstrained (match any destination
    /// port, the pre-#3429 behavior). Non-empty = the flow's destination port
    /// MUST fall in one range or the rule does not match. Enforced in
    /// `l4_matches`, before translation AND before an `off` exemption.
    pub(crate) match_dst_ports: Vec<(u16, u16)>,
    /// #3429: source-NAT `match application` constraint, pre-expanded by the Go
    /// builder to (protocol, port-range) terms. Empty = app-unconstrained.
    /// Non-empty = the flow MUST satisfy one term. Enforced in `l4_matches`.
    pub(crate) match_apps: Vec<SourceNatAppTerm>,
    pub(crate) interface_mode: bool,
    pub(crate) off: bool,
    pub(crate) pool_name: String,
    pub(crate) pool_mode: bool,
    /// #3906: `port no-translation` — translate the source ADDRESS but PRESERVE
    /// the original source port. When true a pool-mode rule takes the
    /// address-only path (pick a pool address, leave `rewrite_src_port` unset so
    /// the packet keeps its L4 source port); no pool port is allocated and
    /// `pool_allocator.port_low/high` are irrelevant. Default false = the
    /// pre-#3906 PAT behaviour (allocate a port from the pool range).
    pub(crate) no_translation: bool,
    pub(crate) pool_failure: Option<SourceNatFailureReason>,
    pub(crate) address_persistent: bool,
    pub(crate) persistent_nat: bool,
    /// #2823: the three-way persistent-NAT remote scope (was a binary
    /// `permit_any_remote_host` bool).
    pub(crate) persistent_nat_permit: PersistentNatPermit,
    pub(crate) persistent_nat_inactivity_timeout_secs: i64,
    pub(crate) persistent_nat_timeout_ns: u64,
    pub(crate) pool_addresses_v4: Vec<Ipv4Addr>,
    pub(crate) pool_addresses_v6: Vec<Ipv6Addr>,
    /// The pool's CONFIGURED port range after snapshot defaulting (1024-65535
    /// when unset). Carried on the rule — config, not allocator state — so the
    /// pool status view (`source_nat_pool_statuses`) and the allocator key
    /// read the same values for a healthy pool AND keep reporting the
    /// configured range for a FAILED pool, whose `pool_allocator` is the
    /// empty default since #6812 (failed pools build no bitmap). The
    /// allocator of a healthy pool is always built with exactly these values
    /// (`resolve_pool_allocators`), so the two can never diverge.
    pub(crate) pool_port_low: u16,
    pub(crate) pool_port_high: u16,
    /// #4559: deterministic CGNAT (mode 1, IPv4 subscriber) block-allocation
    /// parameters. `Some` => this rule's pool maps each in-range subscriber IPv4
    /// to a fixed external IP + port block (`allocate_deterministic_v4`) instead
    /// of round-robin/sticky PAT. `None` => the pre-#4559 behaviour (unchanged).
    /// Mode 2 (IPv6 subscriber / NAT64) is deferred — the Go compiler does not
    /// set the snapshot fields for it, so it stays `None` and round-robins with
    /// the commit-time advisory still surfacing the gap.
    pub(crate) deterministic_v4: Option<DeterministicV4>,
    pub(crate) pool_allocator: PortAllocator,
    /// #2218: per-rule translation hit counter, shared from the
    /// coordinator's `NatCounterStore`. `None` when the rule carries no
    /// per-rule counter (`counter_id == 0`). Captured at build time; the
    /// cold-path commit site clones the `Arc` and calls `.add(len)` once
    /// per committed translated forward flow.
    pub(crate) hit_counter: Option<Arc<NatRuleCounter>>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct SourceNatPoolAllocatorKey {
    pool_name: String,
    pool_addresses_v4: Vec<Ipv4Addr>,
    pool_addresses_v6: Vec<Ipv6Addr>,
    port_low: u16,
    port_high: u16,
}

impl SourceNatRule {
    fn allocator_key(&self) -> Option<SourceNatPoolAllocatorKey> {
        let total_pool = self.pool_addresses_v4.len() + self.pool_addresses_v6.len();
        (self.pool_mode && total_pool > 0 && self.pool_failure.is_none()).then(|| {
            self.allocator_key_for(self.pool_port_low, self.pool_port_high)
        })
    }

    /// Build the allocator key with an EXPLICIT port range. The resolve pass
    /// (#6812) keys a rule BEFORE its allocator exists, so it cannot read the
    /// range back off `pool_allocator` (still the empty default there); the
    /// range must come from the snapshot defaulting the parse loop applied.
    fn allocator_key_for(&self, port_low: u16, port_high: u16) -> SourceNatPoolAllocatorKey {
        SourceNatPoolAllocatorKey {
            pool_name: self.pool_name.clone(),
            pool_addresses_v4: self.pool_addresses_v4.clone(),
            pool_addresses_v6: self.pool_addresses_v6.clone(),
            port_low,
            port_high,
        }
    }
}

/// #6812: source-NAT AGGREGATE allocator budget at the apply boundary — the
/// Rust mirror of the Go #5877 strict commit gate
/// (`validateSourceNATAggregateCardinalityStrict`, pkg/config). The Go gate
/// rejects an over-budget config at strict commit, but the TOLERANT load /
/// peer-sync path only warns (#1960 no-brick), so an over-budget config can
/// still reach this apply boundary; before this gate the boundary expanded
/// every pool and built each address's occupancy bitmap EAGERLY — three
/// full-range /16 pools materialise 12,683,575,296 bitmap bits (~1.48 GiB)
/// and can stall or OOM the dataplane during an upgrade boot / HA convergence.
///
/// WHAT THIS BOUNDS, precisely, because the ordering invites a wrong reading:
/// the budget is checked in `resolve_pool_allocators`, which runs AFTER the
/// parse loop — so the pools' ADDRESS VECTORS (`pool_addresses_v4/v6`) are
/// already expanded when it runs, and only the per-address occupancy BITMAP is
/// gated (`PortAllocator::new` is reached solely from the `admitted_with(..) ==
/// Some` arm). That is deliberate and it is the right split: the bitmap is the
/// exhaustion vector by roughly three orders of magnitude. A full-range /16
/// pool costs 65536 x 4 B = ~262 KB as addresses against 65536 x 64512 bits =
/// ~528 MB as bitmap. Bounding the address vectors too would mean restructuring
/// the parse loop to defer expansion, for ~0.05% of the memory. Do not "fix"
/// the ordering on the theory that the guard sits downstream of the growth it
/// limits — for the quantity that matters it sits upstream (#6812).
/// The values MUST match the Go constants
/// (`MaxSourceNATPoolCount` / `MaxSourceNATAggregatePoolAddresses` /
/// `MaxSourceNATAggregatePortCapacity`); the parity is pinned by
/// `real_budget_matches_go_5877_constants` in tests_aggregate_budget.rs.
#[derive(Clone, Copy, Debug)]
pub(super) struct SourceNatAggregateBudget {
    /// Max DISTINCT pool allocator instances (one per referenced pool key).
    pub(super) max_pools: u64,
    /// Max SUM of every referenced pool's expanded address count.
    pub(super) max_addresses: u64,
    /// Max SUM of (addresses x port range) = occupancy bitmap SLOTS.
    pub(super) max_port_capacity: u64,
}

pub(super) const SOURCE_NAT_AGGREGATE_BUDGET: SourceNatAggregateBudget = SourceNatAggregateBudget {
    max_pools: 1024,
    max_addresses: 16 * MAX_POOL_PREFIX_HOSTS, // 1,048,576
    max_port_capacity: 1 << 33,                // 8,589,934,592
};

/// Running aggregate charge across the distinct allocator keys one apply will
/// hold live. u64 with saturating adds: a hand-crafted snapshot can claim
/// absurd cardinalities, and saturation (never wrap) keeps the over-budget
/// verdict fail-closed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct SourceNatAggregateUse {
    pub(super) pools: u64,
    pub(super) addresses: u64,
    pub(super) port_capacity: u64,
}

impl SourceNatAggregateUse {
    /// Cumulative use UNCONDITIONALLY including `charge` (saturating adds —
    /// the one add formula). Used directly for keys that must be accepted
    /// regardless of budget (reused last-good state), and as the candidate
    /// inside `admitted_with`.
    fn saturating_with(self, charge: Self) -> Self {
        Self {
            pools: self.pools.saturating_add(charge.pools),
            addresses: self.addresses.saturating_add(charge.addresses),
            port_capacity: self.port_capacity.saturating_add(charge.port_capacity),
        }
    }

    /// Cumulative use IF `charge` is admitted. Returns None when admitting it
    /// would cross any budget — the caller then refuses the key WITHOUT
    /// committing the charge (first-fit: a later, smaller key may still fit).
    pub(super) fn admitted_with(
        self,
        charge: Self,
        budget: &SourceNatAggregateBudget,
    ) -> Option<Self> {
        let next = self.saturating_with(charge);
        (next.pools <= budget.max_pools
            && next.addresses <= budget.max_addresses
            && next.port_capacity <= budget.max_port_capacity)
            .then_some(next)
    }
}

/// Per-rule deferred allocator inputs, captured by the parse loop for every
/// rule that passes the `allocator_key()` gate (`pool_mode && total_pool > 0
/// && pool_failure.is_none()`). `total_pool` is the EXPANDED address count
/// (v4 + v6); `port_low`/`port_high` are the snapshot-defaulted range.
/// #6765: a previous generation's pool, kept so a PARTIAL-OVERLAP change can
/// carry live port ownership onto the addresses it retains. Held by pool NAME,
/// because the exact-match `SourceNatPoolAllocatorKey` cannot answer this
/// question — a changed address list is exactly what makes that key miss.
struct PreviousPool {
    addresses_v4: Vec<Ipv4Addr>,
    addresses_v6: Vec<Ipv6Addr>,
    allocator: PortAllocator,
}

/// Map PREVIOUS pool-address indices to their index in the NEW pool, for the
/// addresses present in both.
///
/// The index model is positional and shared with the allocator: v4 addresses
/// occupy `0..v4.len()`, and a v6 address at position `i` is index
/// `v4.len() + i` (see `SourceNatRule::allocator_key` / the v6_offset arithmetic
/// on the match path). Both sides are re-derived here rather than assumed equal,
/// because the whole point is that the two lists differ.
///
/// Returns an empty map when nothing is retained — a fully-disjoint swap, which
/// must keep resetting.
/// v4-only wrapper for NAT64, whose pools carry no v6 addresses. It calls the
/// SAME formula rather than restating the positional rule — a second copy of
/// "which previous index is this address now at" is exactly the drift that makes
/// a position-indexed carry-over unsafe.
pub(crate) fn retained_pool_index_map_v4(
    prev_v4: &[Ipv4Addr],
    new_v4: &[Ipv4Addr],
) -> FxHashMap<usize, usize> {
    let prev = PreviousPool {
        addresses_v4: prev_v4.to_vec(),
        addresses_v6: Vec::new(),
        allocator: PortAllocator::new(0, 0, 0),
    };
    retained_pool_index_map(&prev, new_v4, &[])
}

pub(crate) fn retained_pool_index_map(
    prev: &PreviousPool,
    new_v4: &[Ipv4Addr],
    new_v6: &[Ipv6Addr],
) -> FxHashMap<usize, usize> {
    let mut map = FxHashMap::default();
    let prev_v4_len = prev.addresses_v4.len();
    let new_v4_len = new_v4.len();
    for (new_i, addr) in new_v4.iter().enumerate() {
        if let Some(prev_i) = prev.addresses_v4.iter().position(|a| a == addr) {
            map.insert(prev_i, new_i);
        }
    }
    for (new_i, addr) in new_v6.iter().enumerate() {
        if let Some(prev_i) = prev.addresses_v6.iter().position(|a| a == addr) {
            map.insert(prev_v4_len + prev_i, new_v4_len + new_i);
        }
    }
    map
}

struct PendingPoolAllocator {
    port_low: u16,
    port_high: u16,
    total_pool: usize,
}

impl PendingPoolAllocator {
    fn charge(&self) -> SourceNatAggregateUse {
        SourceNatAggregateUse {
            pools: 1,
            addresses: self.total_pool as u64,
            // One formula for "port slots this allocator materialises" —
            // shared with PortAllocator::new's own capacity arithmetic.
            port_capacity: super::allocator::allocator_capacity(
                self.total_pool,
                self.port_low,
                self.port_high,
            ) as u64,
        }
    }
}

/// #6765: carry live port ownership onto the addresses a changed pool RETAINS.
///
/// A no-op unless the previous generation had an UNAMBIGUOUS pool of this name
/// whose address list overlaps the new one. A fully-disjoint swap yields an
/// empty index map and re-seeds nothing, which is the reset the existing
/// `nat64_4518_pool_change_resets_allocator` behaviour depends on.
///
/// What could not be carried is logged ONCE per pool per apply — a config-apply
/// event, not a per-packet path. A silent drop here would be the same class of
/// defect as the reissue this exists to prevent.
fn reseed_retained_pool(
    pool_name: &str,
    allocator: &PortAllocator,
    previous_pools: &FxHashMap<String, Option<PreviousPool>>,
    rule: &SourceNatRule,
    now_ns: u64,
) {
    let Some(slot) = previous_pools.get(pool_name) else {
        return;
    };
    let Some(prev) = slot.as_ref() else {
        // Ambiguous: this name resolved to more than one address list in the
        // previous generation. Carrying from an arbitrary one of them could
        // move ownership between pools, so carry nothing and say so.
        eprintln!(
            "xpf-dp: source-nat pool {pool_name:?} changed but the previous generation had \
             more than one address list under that name; live translations are NOT carried \
             onto retained addresses (#6765)"
        );
        return;
    };
    let map = retained_pool_index_map(prev, &rule.pool_addresses_v4, &rule.pool_addresses_v6);
    if map.is_empty() {
        return;
    }
    let outcome = allocator.reseed_retained_from(&prev.allocator, &map, now_ns);
    if outcome.skipped_out_of_range > 0 || outcome.skipped_address_only > 0 || outcome.refused > 0 {
        eprintln!(
            "xpf-dp: source-nat pool {pool_name:?} changed: carried {} live translation(s) onto \
             {} retained address(es); {} not carried (port outside the new range), {} \
             address-only token(s) skipped, {} refused (#6765)",
            outcome.reseeded,
            map.len(),
            outcome.skipped_out_of_range,
            outcome.skipped_address_only,
            outcome.refused,
        );
    } else if outcome.reseeded > 0 {
        eprintln!(
            "xpf-dp: source-nat pool {pool_name:?} changed: carried {} live translation(s) onto \
             {} retained address(es) (#6765)",
            outcome.reseeded,
            map.len(),
        );
    }
}

/// #6812: assign pool allocators AFTER parsing, under the aggregate budget.
///
/// Three invariants the pre-#6812 inline block violated:
///
/// 1. REUSE BEFORE BUILD — the this-apply and previous-apply allocator maps
///    are consulted FIRST; only a miss constructs `PortAllocator::new`. The
///    old code built a full per-address occupancy bitmap per rule and THEN
///    discarded it on a reuse hit.
/// 2. FAILED POOLS BUILD NOTHING — a rule whose pool already failed
///    (missing/empty/invalid/Go-poisoned) keeps the empty default allocator;
///    the match path short-circuits on `pool_failure` before touching the
///    allocator and `reserve_flow` on an empty allocator returns false
///    gracefully, so no consumer can observe the difference.
/// 3. AGGREGATE BUDGET — distinct keys are charged (count / addresses /
///    port capacity). A REUSED key consumes budget but is ALWAYS accepted: a
///    no-op re-apply must not kill live state, and charging it stops a
///    two-step apply from creeping past the cap one generation at a time (two
///    full-range /16 pools, then the same two plus a third — the review's
///    1.48 GiB scenario via incremental applies). A NEW key is admitted only
///    if it fits the remaining budget (first-fit: a refused key consumes
///    nothing, so a later smaller key can still install); a refused key marks
///    every referencing rule `OverBudget` — fail-closed with a dataplane
///    diagnostic — and builds no bitmap.
///
/// # Reused keys are RESERVED before any new key is admitted (#6812 F2 round 4)
///
/// Invariant 3 above is order-sensitive if reuse is charged where it is met.
/// A single pass charging in snapshot order lets a NEW key be admitted against
/// a `used` total that does not yet include reused keys appearing LATER in the
/// slice — and those keys are then accepted unconditionally, so the live set
/// ends up over the cap. Measured, with two live pools A and B at 160 of a
/// 200-slot budget and a new C worth 80:
///
/// | snapshot order | C | live |
/// |---|---|---|
/// | `A, B, C` | refused | 160 |
/// | `C, A, B` | **admitted, bitmap built** | **240 — over the cap** |
///
/// Same pools, same reuse map, opposite outcome from ORDER alone; and it
/// repeats, one extra pool per apply. The Go-side poison hides it for
/// snapshots this control plane generates, which is precisely why it mattered:
/// this boundary exists as the INDEPENDENT backstop for a tolerated,
/// older-control-plane, or handcrafted snapshot, where no Go poison is coming.
///
/// Phase 1 therefore charges every DISTINCT key that will be reused, before
/// phase 2 admits anything. Reused keys are still always accepted and are
/// charged exactly once; new-key admission now sees the true live total
/// whatever order the snapshot arrives in.
fn resolve_pool_allocators(
    out: &mut [SourceNatRule],
    pendings: &[Option<PendingPoolAllocator>],
    previous_allocators: &FxHashMap<SourceNatPoolAllocatorKey, PortAllocator>,
    previous_pools: &FxHashMap<String, Option<PreviousPool>>,
    budget: &SourceNatAggregateBudget,
    now_ns: u64,
) {
    let mut pool_allocators = FxHashMap::<SourceNatPoolAllocatorKey, PortAllocator>::default();
    let mut refused_keys = FxHashMap::<SourceNatPoolAllocatorKey, ()>::default();
    let mut used = SourceNatAggregateUse::default();

    // PHASE 1: reserve the reused keys. These are accepted unconditionally in
    // phase 2, so their charge is not a prediction — it is live state this
    // apply is already committed to holding.
    let mut reserved = FxHashMap::<SourceNatPoolAllocatorKey, ()>::default();
    for (rule, pending) in out.iter().zip(pendings.iter()) {
        let Some(pending) = pending else {
            continue;
        };
        let key = rule.allocator_key_for(pending.port_low, pending.port_high);
        if !previous_allocators.contains_key(&key) || reserved.contains_key(&key) {
            continue;
        }
        used = used.saturating_with(pending.charge());
        reserved.insert(key, ());
    }

    // PHASE 2: assign. Reused keys were charged in phase 1 and must NOT be
    // charged again here.
    for (rule, pending) in out.iter_mut().zip(pendings.iter()) {
        let Some(pending) = pending else {
            continue;
        };
        let key = rule.allocator_key_for(pending.port_low, pending.port_high);
        if refused_keys.contains_key(&key) {
            rule.pool_failure = Some(SourceNatFailureReason::OverBudget);
            rule.deterministic_v4 = None;
            continue;
        }
        if let Some(existing) = pool_allocators.get(&key) {
            rule.pool_allocator = existing.clone();
            continue;
        }
        let charge = pending.charge();
        if let Some(existing) = previous_allocators.get(&key) {
            // Reuse preserves last-good live state: always accepted. Its
            // budget was charged in PHASE 1 — charging it again here would
            // double-count, and charging it ONLY here is the #6812 F2 defect
            // (a new key earlier in the slice would be admitted against a
            // `used` that omits it). A reused key that alone overflows (legacy
            // pre-cap state) saturated `used` in phase 1, which only refuses
            // NEW keys.
            debug_assert!(
                reserved.contains_key(&key),
                "a previously-allocated key must have been reserved in phase 1",
            );
            pool_allocators.insert(key, existing.clone());
            rule.pool_allocator = existing.clone();
            continue;
        }
        match used.admitted_with(charge, budget) {
            Some(next) => {
                used = next;
                let allocator = PortAllocator::new(
                    pending.total_pool,
                    pending.port_low,
                    pending.port_high,
                );
                // #6765: a FRESH allocator over a pool that RETAINS addresses
                // would reissue `(retained_addr, port_low)` — the occupancy
                // bitmap that was the sole ownership token is all-zero and the
                // cursor starts at 0. Carry the retained addresses' live port
                // ownership across before publishing.
                //
                // Only reached on this arm, so the two cases that must keep
                // resetting are untouched by construction: an exact-key match
                // returns above (full Arc share), and a cold start has no
                // `previous` at all, so `previous_pools` is empty.
                reseed_retained_pool(
                    &key.pool_name,
                    &allocator,
                    previous_pools,
                    rule,
                    now_ns,
                );
                pool_allocators.insert(key, allocator.clone());
                rule.pool_allocator = allocator;
            }
            None => {
                // One journald line per refused key per apply — a one-time
                // config-apply event, not a per-packet path.
                eprintln!(
                    "xpf-dp: source-nat pool {:?} refused at apply: aggregate allocator \
                     budget exceeded (count {}/{}, addresses {}/{}, port slots {}/{} would \
                     grow by {}/{}/{}); rule(s) referencing it fail closed (#6812)",
                    key.pool_name,
                    used.pools,
                    budget.max_pools,
                    used.addresses,
                    budget.max_addresses,
                    used.port_capacity,
                    budget.max_port_capacity,
                    charge.pools,
                    charge.addresses,
                    charge.port_capacity,
                );
                refused_keys.insert(key, ());
                rule.pool_failure = Some(SourceNatFailureReason::OverBudget);
                // Keep the parse-loop invariant `deterministic_v4.is_some() =>
                // pool_failure.is_none()` that the resolve-time refusal would
                // otherwise break (the match path is safe either way — it
                // short-circuits on pool_failure first).
                rule.deterministic_v4 = None;
            }
        }
    }
}

impl SourceNatRule {
    /// #3096: does the flow satisfy every non-empty interface /
    /// routing-instance scope on this rule? Empty scope fields are wildcards.
    /// All present scopes are AND-ed (Junos restricts a from/to clause to one
    /// kind, but a hostile multi-kind clause fails closed — it must match
    /// every set field).
    fn scope_matches(&self, scope: &NatScopeCtx) -> bool {
        if !self.from_interface.is_empty() && self.from_interface != scope.ingress_ifname {
            return false;
        }
        if !self.to_interface.is_empty() && self.to_interface != scope.egress_ifname {
            return false;
        }
        if !self.from_routing_instance.is_empty()
            && self.from_routing_instance != scope.ingress_routing_instance
        {
            return false;
        }
        if !self.to_routing_instance.is_empty()
            && self.to_routing_instance != scope.egress_routing_instance
        {
            return false;
        }
        true
    }

    /// #3429: does the flow satisfy this rule's L4 `match destination-port` /
    /// `match application` constraints? An empty constraint set is a wildcard
    /// (unchanged match-any behavior). A non-empty set is AND-ed across the two
    /// kinds (destination-port AND application), mirroring Junos.
    ///
    /// #5687: `tuple_unknown` is the OUT-OF-BAND "L4 tuple unknown" signal (the
    /// address-only `match_source_nat` wrapper, `protocol == None`) — NOT the
    /// numeric value 0. A rule that carries ANY L4 constraint cannot be
    /// satisfied by an unknown tuple, so it fails closed (an L4-scoped rule must
    /// never fire on traffic whose port/protocol the caller could not supply).
    /// A genuine HOPOPT packet (`Some(0)`, `tuple_unknown == false`) is NOT
    /// short-circuited here: it falls through to the normal port/protocol
    /// checks, which reject an L4-port-scoped rule anyway (its ports are 0) — so
    /// the fail-closed behavior is preserved without conflating it with the
    /// unknown sentinel. An unconstrained rule is unaffected.
    ///
    /// #3491: a `match application` term may also constrain the SOURCE port (an
    /// application defined with `source-port`). It is AND-ed with the protocol
    /// and destination-port checks INSIDE the same term: the flow satisfies the
    /// term only when its protocol, destination port, AND source port all match.
    /// Before #3491 the source-port axis was dropped, so an app-scoped rule fired
    /// regardless of source port — the fail-open this fix closes.
    fn l4_matches(&self, tuple_unknown: bool, protocol: u8, src_port: u16, dst_port: u16) -> bool {
        if self.match_dst_ports.is_empty() && self.match_apps.is_empty() {
            return true;
        }
        // #5687: fail closed on the OUT-OF-BAND unknown tuple, not `protocol == 0`
        // (a real HOPOPT flows through to the normal checks below).
        if tuple_unknown {
            return false;
        }
        if !self.match_dst_ports.is_empty() && !port_in_ranges(dst_port, &self.match_dst_ports) {
            return false;
        }
        if !self.match_apps.is_empty() {
            let proto16 = protocol as u16;
            let ok = self.match_apps.iter().any(|t| {
                (t.protocol == SOURCE_NAT_PROTO_ANY || t.protocol == proto16)
                    && (t.ports.is_empty() || port_in_ranges(dst_port, &t.ports))
                    && (t.src_ports.is_empty() || port_in_ranges(src_port, &t.src_ports))
            });
            if !ok {
                return false;
            }
        }
        true
    }

    /// Does the flow satisfy this rule's `from zone` / `to zone` clause? An
    /// empty zone on the rule is a wildcard (unscoped rule-set).
    fn zone_matches(&self, from_zone: &str, to_zone: &str) -> bool {
        (self.from_zone.is_empty() || self.from_zone == from_zone)
            && (self.to_zone.is_empty() || self.to_zone == to_zone)
    }

    /// Does the flow satisfy this rule's `match source-address` /
    /// `match destination-address` sets? A cross-family (v4 source, v6
    /// destination or vice versa) tuple can never match a rule.
    fn address_matches(&self, src_ip: IpAddr, dst_ip: IpAddr) -> bool {
        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                nets_match_v4(self.source_constrained, &self.source_v4, src)
                    && nets_match_v4(self.destination_constrained, &self.destination_v4, dst)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                nets_match_v6(self.source_constrained, &self.source_v6, src)
                    && nets_match_v6(self.destination_constrained, &self.destination_v6, dst)
            }
            _ => false,
        }
    }

    fn matches(
        &self,
        scope: &NatScopeCtx,
        from_zone: &str,
        to_zone: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        tuple_unknown: bool,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        self.zone_matches(from_zone, to_zone)
            && self.scope_matches(scope)
            && self.l4_matches(tuple_unknown, protocol, src_port, dst_port)
            && self.address_matches(src_ip, dst_ip)
    }

    /// #6211: [`matches`] minus the #3096 interface / routing-instance
    /// `scope_matches` axis, for the HA STANDBY's synced-reservation rule
    /// selection ([`reserve_synced_source_nat_allocation`]).
    ///
    /// The standby re-derives which source-NAT rule the ACTIVE node matched
    /// from the synced session alone. Every axis except the scope is carried
    /// on (or derivable from) the HA session-sync wire: the zone pair rides as
    /// `ingress_zone_id`/`egress_zone_id`, and the 5-tuple is the session key
    /// itself. The scope axis is NOT: `NatScopeCtx` is built from the LOCAL
    /// `ifindex_to_config_name` / `ifindex_to_routing_instance` maps keyed on
    /// the ACTIVE node's ingress/egress ifindices, which the standby does not
    /// have (a synced entry's ifindices are the peer's and are re-resolved
    /// locally on import).
    ///
    /// So the scope is treated as UNCONSTRAINED here rather than as a
    /// mismatch. Rejecting an interface-scoped rule the standby cannot confirm
    /// would push the selection PAST the rule the active actually used and
    /// onto a later one — strictly worse than the pre-#6211 first-pool-match.
    /// Ignoring the axis only declines to narrow on it: every other axis still
    /// narrows, and the pre-#6211 selection narrowed on none of them.
    #[allow(clippy::too_many_arguments)]
    fn matches_ignoring_scope(
        &self,
        from_zone: &str,
        to_zone: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        tuple_unknown: bool,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        self.zone_matches(from_zone, to_zone)
            && self.l4_matches(tuple_unknown, protocol, src_port, dst_port)
            && self.address_matches(src_ip, dst_ip)
    }
}

/// Upper bound on how many host addresses a single source-NAT pool prefix is
/// expanded into (#3049). Realistic SNAT pools are far smaller; the cap bounds
/// memory and the allocator's per-address port table for an over-broad prefix
/// (an unbounded `/8` would be ~16M entries, and any v6 prefix shorter than
/// `/112` is astronomically large). A prefix whose host count exceeds this is
/// rejected as an invalid pool so the operator gets a clear commit/runtime
/// signal rather than a silently clamped pool.
pub(crate) const MAX_POOL_PREFIX_HOSTS: u64 = 65536;

/// Parse a CIDR mask field in the CANONICAL decimal spelling, or `None`
/// (#6812 F1 round 3).
///
/// Canonical means: 1-3 ASCII digits, no leading zero unless the field is the
/// single digit `0`, value `<= max`. That is exactly what Go's
/// `netip.ParsePrefix` accepts, so the two sides agree on the mask field by
/// construction.
///
/// `ipnet` instead reads the field with `read_number(10, 2, 33)` for IPv4 and
/// `read_number(10, 3, 129)` for IPv6 — a DIGIT-COUNT cap, not a canonical-form
/// rule. It therefore refuses `/032` (3 digits, v4) but accepts `/064` as `/64`
/// (3 digits, v6). Neither spelling changes any pool's disposition today
/// (every leading-zero-expressible prefix length is over `MAX_POOL_PREFIX_HOSTS`
/// anyway, so both sides refuse the pool either way), but that agreement is a
/// coincidence of two unrelated bounds, not a property. Raising
/// `MAX_POOL_PREFIX_HOSTS` would turn it into a live divergence, so the mask
/// grammar is pinned here rather than left to arithmetic.
fn parse_canonical_prefix_len(mask: &str, max: u32) -> Option<u32> {
    // No length cap: a 4+ digit field either carries a leading zero (refused
    // below) or exceeds `max` (refused at the end), and an absurdly long one
    // fails the `parse` itself. A `mask.len() > 3` clause was measured to
    // change 0 of 137,879 differential verdicts — it read like a bound guard
    // and was not one.
    if mask.is_empty() || !mask.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if mask.len() > 1 && mask.starts_with('0') {
        return None;
    }
    let value: u32 = mask.parse().ok()?;
    if value > max {
        return None;
    }
    Some(value)
}

/// Expand one source-NAT pool address entry into its constituent host
/// addresses (#3049). A pool entry is either a bare IP, a host CIDR
/// (`/32`, `/128`), or a subnet CIDR (e.g. `203.0.113.0/28`). Junos uses the
/// FULL prefix range for a source-NAT pool, so a subnet must enumerate every
/// address in the prefix (network..=broadcast inclusive) rather than collapse
/// to the single network host — the pre-#3049 bug that stripped the mask and
/// kept only one address. A single-host prefix yields exactly one address.
///
/// Returns `false` if the entry does not parse or expands beyond
/// `MAX_POOL_PREFIX_HOSTS` (caller marks the pool invalid).
///
/// # One address grammar for both forms (#6812 F1 round 3)
///
/// The CIDR branch parses its address half with the SAME `std::net::IpAddr`
/// parser the bare branch uses, and its mask half with
/// `parse_canonical_prefix_len` — it deliberately does NOT call
/// `IpNet::from_str`. `ipnet` hand-rolls its own address parser
/// (`ipnet::parser`, a fork of an old `std` implementation) whose octet reader
/// is `read_number(10, 3, 0x100)`: any 1-3 digit decimal below 256, **leading
/// zeros included**. `std` (since Rust 1.53) and Go's `netip.ParseAddr` both
/// reject a leading-zero octet, because `010` is octal 8 to some resolvers and
/// the ambiguity is a spoofing vector.
///
/// That made this function self-inconsistent and made it disagree with the Go
/// control plane: `010.0.0.1` (bare) was refused here, while `010.0.0.1/32`
/// (CIDR) was accepted as `10.0.0.1`, and the shared Go predicate
/// (`sourceNATPoolAddressReason`, pkg/config/compiler_validate_strict_nat.go)
/// refused both — so the STRICT commit gate has rejected the spelling since
/// #5627 while this function installed it. That commit-vs-apply divergence is
/// what the narrowing closes.
///
/// # What moved, stated correctly (#6812 B1)
///
/// Two earlier revisions of this comment claimed the narrowing "changes no
/// config's disposition", and described the pre-fix state as an over-rejection
/// on the tolerant path. **Both are wrong, and the second inverts the
/// direction.** At the merge base the tolerant path did NOT poison this class:
/// `config.SourceNATPoolUnusableReason` does not exist there, and the
/// membership-grammar clause that stamps `invalid_pool` was added mid-branch by
/// this PR. So master had a commit-vs-apply divergence (strict rejects, runtime
/// installs), not an over-rejection — and a pool carrying `010.0.0.0/24` really
/// did translate at the merge base and really does fail closed now.
///
/// The blast radius is exactly the leading-zero-octet CIDR family. Every other
/// shape the membership clause catches was already fail-closed at the merge
/// base: a mixed pool with an unparseable member and an over-capacity `/15`
/// were both refused by this function, and a bare `%zone` member was poisoned
/// by the #5875 builder check.
///
/// The disposition change is kept deliberately, on the #5875 precedent (reject
/// a non-representable literal, never silently rewrite it). Declining to poison
/// it on the tolerant path is not an alternative — the runtime refuses the
/// member on its own, so the pool fails closed either way; that is measured by
/// `declining_to_poison_a_leading_zero_member_does_not_restore_it_6812`. The
/// operator-facing half of the decision is `leadingZeroPoolAddressReason`,
/// which names the canonical spelling, and the upgrade / peer-sync regression
/// tests in pkg/dataplane/userspace/nat_pool_leading_zero_upgrade_6812_test.go.
///
/// `nat_pool_grammar_parity_fixture`
/// (tests_aggregate_budget.rs) pins the agreement over
/// `tests/fixtures/snat_pool_grammar_v1.json` — the SAME file
/// `TestPoolAddressGrammarMatchesDataplane_6812` reads on the Go side, so
/// neither side keeps a copy of the table — and
/// `nat_pool_bare_and_host_cidr_grammars_agree` drives the bare-vs-CIDR
/// invariant directly.
///
/// Scope: `expand_pool_address` has exactly one production caller (the
/// source-NAT pool parse loop below), so this is the source-NAT pool
/// membership grammar only. Rule-set MATCH prefixes still parse via `IpNet`
/// and are a separate question.
pub(super) fn expand_pool_address(
    addr_str: &str,
    out_v4: &mut Vec<Ipv4Addr>,
    out_v6: &mut Vec<Ipv6Addr>,
) -> bool {
    if let Some((addr_part, mask_part)) = addr_str.split_once('/') {
        // CIDR form: enumerate every address in the prefix range.
        match addr_part.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                let Some(prefix_len) = parse_canonical_prefix_len(mask_part, 32) else {
                    return false;
                };
                let host_bits = 32 - prefix_len;
                let count = 1u64 << host_bits; // 1 for /32
                if count > MAX_POOL_PREFIX_HOSTS {
                    return false;
                }
                // Mask to the network base. `count` is <= MAX_POOL_PREFIX_HOSTS
                // (65536) here, so the `as u32` narrowing cannot truncate; the
                // over-cap prefixes that would overflow returned above.
                let base = u32::from(ip) & !(count as u32 - 1);
                for i in 0..count {
                    out_v4.push(Ipv4Addr::from(base.wrapping_add(i as u32)));
                }
                true
            }
            Ok(IpAddr::V6(ip)) => {
                let Some(prefix_len) = parse_canonical_prefix_len(mask_part, 128) else {
                    return false;
                };
                let host_bits = 128 - prefix_len;
                // host_bits >= 17 already exceeds the cap; avoid 1u128 << 64+.
                if host_bits >= 64 || (1u128 << host_bits) > MAX_POOL_PREFIX_HOSTS as u128 {
                    return false;
                }
                let count = 1u128 << host_bits; // 1 for /128
                let base = u128::from(ip) & !(count - 1);
                for i in 0..count {
                    out_v6.push(Ipv6Addr::from(base.wrapping_add(i)));
                }
                true
            }
            Err(_) => false,
        }
    } else {
        // Bare IP (no mask): exactly one host.
        match addr_str.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => {
                out_v4.push(v4);
                true
            }
            Ok(IpAddr::V6(v6)) => {
                out_v6.push(v6);
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_source_nat_rules(snaps: &[SourceNATRuleSnapshot]) -> Vec<SourceNatRule> {
    parse_source_nat_rules_with_previous(snaps, None, &NatCounterStore::default(), 0)
}

/// `now_ns` is the caller's MONOTONIC clock, threaded through to the #6765
/// retained-address re-seed (`reseed_retained_from` -> `reserve_flow`, which
/// re-arms a persistent lease's idle expiry on the eviction path). The
/// production call site is `afxdp::forwarding_build`, which has
/// `monotonic_nanos()`; tests that do not exercise the re-seed pass 0.
pub(crate) fn parse_source_nat_rules_with_previous(
    snaps: &[SourceNATRuleSnapshot],
    previous: Option<&[SourceNatRule]>,
    nat_counters: &NatCounterStore,
    now_ns: u64,
) -> Vec<SourceNatRule> {
    parse_source_nat_rules_inner(
        snaps,
        previous,
        nat_counters,
        &SOURCE_NAT_AGGREGATE_BUDGET,
        now_ns,
    )
}

/// Test-only entry with an injectable aggregate budget: the production budget
/// (2^33 port slots) cannot be exercised end-to-end in a unit test without
/// materialising ~1 GiB of real bitmaps, so the budget-gate WIRING tests
/// scale the budget down and drive the identical resolve path. The budget
/// VALUES are pinned separately against the Go #5877 constants.
#[cfg(test)]
pub(crate) fn parse_source_nat_rules_with_budget(
    snaps: &[SourceNATRuleSnapshot],
    previous: Option<&[SourceNatRule]>,
    nat_counters: &NatCounterStore,
    budget: &SourceNatAggregateBudget,
) -> Vec<SourceNatRule> {
    parse_source_nat_rules_inner(snaps, previous, nat_counters, budget, 0)
}

fn parse_source_nat_rules_inner(
    snaps: &[SourceNATRuleSnapshot],
    previous: Option<&[SourceNatRule]>,
    nat_counters: &NatCounterStore,
    budget: &SourceNatAggregateBudget,
    now_ns: u64,
) -> Vec<SourceNatRule> {
    // Persistent SNAT allocator state is helper-local runtime state. A
    // compatible in-process refresh may reuse the previous allocator below,
    // but a helper cold start passes `None` here and intentionally resets live
    // tuple ownership, persistent leases, and allocator counters instead of
    // replaying unproven translated tuple ownership.
    let mut out = Vec::with_capacity(snaps.len());
    let mut pendings: Vec<Option<PendingPoolAllocator>> = Vec::with_capacity(snaps.len());
    let mut previous_allocators = FxHashMap::<SourceNatPoolAllocatorKey, PortAllocator>::default();
    // #6765: the PARTIAL-OVERLAP index, keyed by pool NAME rather than by the
    // whole address list. `previous_allocators` above is the exact-match reuse
    // path and is unchanged; this one exists to answer a different question —
    // "was there a previous allocator for this same pool whose address list has
    // since changed?" — which the exact key can never answer, because a changed
    // list is precisely what makes it miss.
    //
    // A pool name that resolved to MORE THAN ONE distinct address list in the
    // previous generation is ambiguous, and re-seeding from an arbitrary one of
    // them would carry ownership from a pool the operator may not have meant.
    // Such a name is recorded as ambiguous and re-seeds nothing.
    let mut previous_pools = FxHashMap::<String, Option<PreviousPool>>::default();
    if let Some(prev_rules) = previous {
        for prev in prev_rules {
            if let Some(key) = prev.allocator_key() {
                previous_allocators
                    .entry(key)
                    .or_insert_with(|| prev.pool_allocator.clone());
            }
            if prev.pool_name.is_empty() || !prev.pool_mode {
                continue;
            }
            let candidate = PreviousPool {
                addresses_v4: prev.pool_addresses_v4.clone(),
                addresses_v6: prev.pool_addresses_v6.clone(),
                allocator: prev.pool_allocator.clone(),
            };
            match previous_pools.get_mut(&prev.pool_name) {
                None => {
                    previous_pools.insert(prev.pool_name.clone(), Some(candidate));
                }
                Some(Some(existing))
                    if existing.addresses_v4 == candidate.addresses_v4
                        && existing.addresses_v6 == candidate.addresses_v6 => {}
                Some(slot) => *slot = None,
            }
        }
    }
    for snap in snaps {
        let timeout_secs = if snap.persistent_nat_inactivity_timeout > 0 {
            snap.persistent_nat_inactivity_timeout
        } else {
            DEFAULT_PERSISTENT_NAT_TIMEOUT_SECS
        };
        let mut rule = SourceNatRule {
            name: snap.name.clone(),
            from_zone: snap.from_zone.clone(),
            to_zone: snap.to_zone.clone(),
            from_interface: snap.from_interface.clone(),
            to_interface: snap.to_interface.clone(),
            from_routing_instance: snap.from_routing_instance.clone(),
            to_routing_instance: snap.to_routing_instance.clone(),
            interface_mode: snap.interface_mode,
            off: snap.off,
            pool_name: snap.pool_name.clone(),
            pool_mode: !snap.pool_name.is_empty() || !snap.pool_addresses.is_empty(),
            // #3906: `port no-translation` preserves the source port.
            no_translation: snap.pool_no_translation,
            address_persistent: snap.address_persistent,
            persistent_nat: snap.persistent_nat,
            // #2823: prefer the enum string; fall back to the legacy bool.
            persistent_nat_permit: PersistentNatPermit::from_wire(
                &snap.persistent_nat_permit,
                snap.persistent_nat_permit_any_remote_host,
            ),
            persistent_nat_inactivity_timeout_secs: timeout_secs,
            persistent_nat_timeout_ns: (timeout_secs as u64).saturating_mul(NS_PER_SEC),
            // #2218: resolve the per-rule hit counter (None for counter_id 0).
            hit_counter: nat_counters.rule_counter(snap.counter_id),
            ..SourceNatRule::default()
        };
        // #2398: record whether each match set was scoped at all (snapshot list
        // non-empty), independent of how many prefixes parse. These flags drive
        // the fail-closed distinction in `nets_match_*`: a rule that WAS scoped
        // but whose configured prefixes ALL fail to parse must match NOTHING,
        // not collapse to match-any (the pre-#2398 fail-open broadening). An
        // unscoped (empty) set keeps "match any" (anti-over-restrict).
        rule.source_constrained = !snap.source_addresses.is_empty();
        rule.destination_constrained = !snap.destination_addresses.is_empty();
        // #2398: parse each match prefix as a CIDR, falling back to a bare host
        // IP -> /32 (v4) or /128 (v6). Junos carries source/destination-address
        // verbatim and the Go compiler does NOT normalize it, so a bare host
        // reaches the wire with no `/prefix`; `IpNet::from_str` REQUIRES
        // `addr/prefix` and rejects a bare IP. Without the fallback a bare-host
        // match would skip its only entry, leave the list empty, and (pre-#2398)
        // silently match ANY address — the exact fail-open this fix closes (and
        // the same bare-IP live bug fixed for DNAT in #2394).
        for prefix in &snap.source_addresses {
            parse_match_prefix(
                prefix,
                &mut rule.source_v4,
                &mut rule.source_v6,
                nat_counters,
                &snap.name,
                "source-address",
            );
        }
        for prefix in &snap.destination_addresses {
            parse_match_prefix(
                prefix,
                &mut rule.destination_v4,
                &mut rule.destination_v6,
                nat_counters,
                &snap.name,
                "destination-address",
            );
        }
        // #3429: source-NAT L4 match constraints. `match destination-port`
        // ranges and the pre-expanded `match application` terms. Ranges are kept
        // VERBATIM — including a deliberately impossible `low > high` range,
        // which `port_in_ranges` can never satisfy. The Go builder emits exactly
        // such a range (natNeverMatchPortRange = {1,0}) as a fail-CLOSED sentinel
        // when a port constraint was configured but every value is out of range:
        // dropping it here would empty the list, and an empty list is read as
        // "unconstrained" by `l4_matches` (match any port) — re-opening the
        // fail-open this fix closes (AGY finding on PR #3471). A non-empty list
        // that is purely such sentinels therefore matches NOTHING; an empty list
        // (no constraint configured) leaves the rule unconstrained on that axis.
        for r in &snap.match_destination_ports {
            rule.match_dst_ports.push((r.low, r.high));
        }
        for term in &snap.match_applications {
            let ports = term.ports.iter().map(|r| (r.low, r.high)).collect();
            // #3491: source-port ranges are kept VERBATIM, same as the
            // destination-port ranges above — including a deliberately
            // impossible `low > high` never-match sentinel the Go builder emits
            // when the application configured a source-port that coalesced to
            // nothing. Dropping such a range would empty the list and re-open the
            // source-port over-match.
            let src_ports = term.src_ports.iter().map(|r| (r.low, r.high)).collect();
            rule.match_apps.push(SourceNatAppTerm {
                protocol: term.protocol,
                ports,
                src_ports,
            });
        }
        // Parse pool addresses and port range for pool-mode SNAT.
        let mut invalid_pool_address = false;
        for addr_str in &snap.pool_addresses {
            // #3049: a pool entry may be a bare IP, a host CIDR (/32, /128), or
            // a subnet CIDR. A subnet must enumerate the FULL prefix range — the
            // pre-#3049 code stripped the mask and kept only the network host, so
            // a `203.0.113.0/28` pool collapsed to a single address. A single-
            // host prefix still yields exactly one address.
            if !expand_pool_address(
                addr_str,
                &mut rule.pool_addresses_v4,
                &mut rule.pool_addresses_v6,
            ) {
                invalid_pool_address = true;
            }
        }
        let total_pool = rule.pool_addresses_v4.len() + rule.pool_addresses_v6.len();
        let port_low = if snap.port_low > 0 {
            snap.port_low
        } else {
            1024
        };
        let port_high = if snap.port_high > 0 {
            snap.port_high
        } else {
            65535
        };
        // #6812: carry the configured (snapshot-defaulted) port range on the
        // rule itself — config, not allocator state — so the status view and
        // the allocator key keep reading it even when no allocator is built
        // (failed / over-budget pool).
        rule.pool_port_low = port_low;
        rule.pool_port_high = port_high;
        if snap.pool_unusable {
            rule.pool_failure = Some(source_nat_failure_reason_from_snapshot(
                &snap.pool_unusable_reason,
            ));
        } else if rule.pool_mode && invalid_pool_address {
            rule.pool_failure = Some(SourceNatFailureReason::InvalidPool);
        } else if rule.pool_mode && total_pool == 0 {
            rule.pool_failure = Some(if snap.pool_addresses.is_empty() {
                SourceNatFailureReason::EmptyPool
            } else {
                SourceNatFailureReason::MissingPool
            });
        } else if rule.pool_mode && port_low > port_high {
            rule.pool_failure = Some(SourceNatFailureReason::InvalidPortRange);
        }
        // #4559: deterministic CGNAT (mode 1, IPv4 subscriber). The Go compiler
        // precomputes block_size / blocks_per_ip / host_base / host_count against
        // the SAME defaulted port range this snapshot carries, so block
        // boundaries align. Only mode 1 is wired here; an unknown mode (2 = IPv6
        // subscriber / NAT64, deferred) leaves `deterministic_v4` None so the
        // pool round-robins as before (the commit-time advisory covers the gap).
        // Guard against a degenerate snapshot (blocks_per_ip 0 / block_size 0):
        // treat it as non-deterministic rather than build a pool that fails every
        // allocation.
        if snap.deterministic_mode == 1
            && snap.deterministic_block_size > 0
            && snap.deterministic_blocks_per_ip > 0
            && snap.deterministic_host_count > 0
            && !rule.pool_addresses_v4.is_empty()
            && rule.pool_failure.is_none()
        {
            rule.deterministic_v4 = Some(DeterministicV4 {
                block_size: snap.deterministic_block_size,
                blocks_per_ip: snap.deterministic_blocks_per_ip,
                host_base: snap.deterministic_host_base,
                host_count: snap.deterministic_host_count,
            });
        }
        // #6812: allocator construction is DEFERRED to `resolve_pool_allocators`
        // (reuse-before-build, nothing for a failed pool, aggregate budget
        // enforced). The parse loop only records the deferred inputs for rules
        // that pass the `allocator_key()` gate — a failed or pool-less rule
        // keeps the empty default allocator and never builds a bitmap.
        pendings.push(
            (rule.pool_mode && total_pool > 0 && rule.pool_failure.is_none()).then_some(
                PendingPoolAllocator {
                    port_low,
                    port_high,
                    total_pool,
                },
            ),
        );
        out.push(rule);
    }
    resolve_pool_allocators(
        &mut out,
        &pendings,
        &previous_allocators,
        &previous_pools,
        budget,
        now_ns,
    );
    out
}

#[allow(dead_code)]
fn source_nat_runtime_compatible(new_rule: &SourceNatRule, old_rule: &SourceNatRule) -> bool {
    new_rule.name == old_rule.name
        && new_rule.pool_name == old_rule.pool_name
        && new_rule.pool_mode == old_rule.pool_mode
        && new_rule.no_translation == old_rule.no_translation
        && new_rule.pool_failure == old_rule.pool_failure
        && new_rule.address_persistent == old_rule.address_persistent
        && new_rule.persistent_nat == old_rule.persistent_nat
        && new_rule.persistent_nat_permit == old_rule.persistent_nat_permit
        && new_rule.persistent_nat_inactivity_timeout_secs
            == old_rule.persistent_nat_inactivity_timeout_secs
        && new_rule.pool_addresses_v4 == old_rule.pool_addresses_v4
        && new_rule.pool_addresses_v6 == old_rule.pool_addresses_v6
        && new_rule.pool_port_low == old_rule.pool_port_low
        && new_rule.pool_port_high == old_rule.pool_port_high
}

/// Release an UNTRACKED (single-holder) source-NAT allocation — the
/// pre-#6211-F2 contract, where the first release frees the port.
///
/// Production forwarding paths must use
/// [`release_source_nat_allocation_for_worker`] instead: an HA-synced session is
/// reserved once per worker against one shared allocator, and only the LAST
/// holder may free the port. This entry point remains for local-only callers and
/// for tests that exercise the single-holder semantics directly.
/// Compile-time completeness guard for #6211 F2: this untracked entry point is
/// TEST-ONLY, so a production caller that forgot to thread its `worker_id` is a
/// BUILD FAILURE in the non-test profile rather than a silent single-holder
/// release of a reservation every worker holds. Production uses the
/// `_for_worker` twin.
///
/// #6600: one production caller now exists, and it is the exact case the guard
/// above was written to permit — the ROLLBACK of an `Untracked` reservation the
/// coordinator took moments earlier and no worker has adopted. There is no
/// worker_id to thread, because no worker holds it: the reservation is being
/// withdrawn precisely BECAUSE the import is not going to be published. A
/// holder-aware release would be the wrong call here, not a safer one.
pub(crate) fn release_source_nat_allocation(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) {
    release_source_nat_allocation_with_mode(
        rules,
        key,
        nat,
        is_reverse,
        now_ns,
        false,
        NatHolder::Untracked,
    );
}

/// #6211 F2: release THIS worker's hold on a source-NAT allocation.
///
/// For a local allocation (no holder set) this is bit-identical to
/// [`release_source_nat_allocation`] — the port is freed. For an HA-synced
/// reservation, which every worker took against the single shared allocator,
/// only `worker_id`'s bit is cleared and the port survives until the last worker
/// releases it.
pub(crate) fn release_source_nat_allocation_for_worker(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    worker_id: u32,
) {
    release_source_nat_allocation_with_mode(
        rules,
        key,
        nat,
        is_reverse,
        now_ns,
        false,
        NatHolder::Worker(worker_id),
    );
}

/// Roll back an UNTRACKED (single-holder) source-NAT allocation. See
/// [`release_source_nat_allocation`]; production paths use
/// [`rollback_source_nat_allocation_for_worker`].
/// Compile-time completeness guard for #6211 F2: this untracked entry point is
/// TEST-ONLY, so a production caller that forgot to thread its `worker_id` is a
/// BUILD FAILURE in the non-test profile rather than a silent single-holder
/// release of a reservation every worker holds. Production uses the
/// `_for_worker` twin.
#[cfg(test)]
pub(crate) fn rollback_source_nat_allocation(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) {
    release_source_nat_allocation_with_mode(
        rules,
        key,
        nat,
        is_reverse,
        now_ns,
        true,
        NatHolder::Untracked,
    );
}

/// #6211 F2: roll back THIS worker's hold on a source-NAT allocation. The
/// holder-aware twin of [`rollback_source_nat_allocation`].
pub(crate) fn rollback_source_nat_allocation_for_worker(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    worker_id: u32,
) {
    release_source_nat_allocation_with_mode(
        rules,
        key,
        nat,
        is_reverse,
        now_ns,
        true,
        NatHolder::Worker(worker_id),
    );
}

#[allow(clippy::too_many_arguments)]
fn release_source_nat_allocation_with_mode(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    rollback: bool,
    holder: NatHolder,
) {
    if is_reverse {
        return;
    }
    let Some(rewrite_src) = nat.rewrite_src else {
        return;
    };
    // #5269: a PAT decision carries its translated port in `rewrite_src_port`; an
    // ADDRESS-ONLY decision (`port no-translation` / port-less) leaves it unset
    // but minted an occupancy token keyed on the PRESERVED source port. Fall back
    // to the flow's own source port so the SAME `release_flow` / `rollback_flow`
    // frees that token. A non-pool address translation (interface-mode / static
    // SNAT) also reaches here now, but owns no pool `live_by_flow` entry, so the
    // per-rule release is a harmless no-op.
    let rewrite_src_port = nat.rewrite_src_port.unwrap_or(key.src_port);
    let translated = TranslatedTuple {
        ip: rewrite_src,
        port: rewrite_src_port,
    };
    let flow = SourceNatFlowKey {
        protocol: key.protocol,
        src_ip: key.src_ip,
        dst_ip: nat.rewrite_dst.unwrap_or(key.dst_ip),
        src_port: key.src_port,
        dst_port: key.dst_port,
    };
    // #6211: free from EVERY allocator that holds this exact
    // `(flow, translated)` — do NOT stop at the first.
    //
    // State the reason accurately, because the sweep rests on it (#6876): the
    // reserve has NEVER been a pure function of `rules`, so the "at most one
    // allocator holds a given flow" invariant did not hold even against an
    // UNCHANGED rule set. `reserve_synced_on_first_pool_owner` takes the first
    // rule whose allocator ACCEPTS and skips one that refuses — selection is
    // OCCUPANCY-dependent. That is pre-#6211 behaviour, not something this fix
    // introduced: the pre-#6211 loop had the same per-rule fall-through and its
    // own comment described it ("a collision on the standby ... leaves the rule
    // untouched and tries the next"). So a rule that refused while an unrelated
    // local flow held the identity, and accepted later once that flow retired,
    // could ALREADY put one flow in two allocators across a re-upsert — every
    // live session re-upserts on HA session-sync reconnect and on a
    // post-delete-journal-overflow resync — with the rule set untouched.
    //
    // Two other routes reach the same state. `parse_source_nat_rules_with_previous`
    // carries allocators over keyed on `allocator_key()` alone, so an edit that
    // reshuffled which rule a session matched could strand a flow in a
    // carried-over allocator. And #6211's two-pass selection adds a third:
    // pass 1 and pass 2 can choose DIFFERENT rules for the same session at
    // different times (a zone delete/renumber, or a rule-set `from zone` /
    // `match` edit, flips `synced_zones` to `None` or moves pass 1's candidate
    // set), and the two rules' allocators are independent.
    //
    // A first-hit `break` was never sufficient under any of them, and the cost
    // of getting it wrong is unbounded: the teardown freed one allocator and
    // left the other holding its `(pool_addr, port)` forever — a permanent
    // standby pool leak that also counted against `max_tracked_flows` until
    // the allocator reported `AllocatorExhausted`. Nothing reaps it —
    // `live_by_flow` is only
    // removed by `release_flow` / `rollback_flow` / the stale-tuple replace in
    // `reserve_flow`, and `gc_expired_chunked` sweeps persistent LEASES, not
    // live flows. A config change does not rebuild the allocator either:
    // carryover is keyed on `allocator_key()` (pool name + addresses + port
    // range), so the very edit that flips pass 1's outcome preserves the leak.
    //
    // Sweeping every rule is safe and cannot over-free: `release_flow` /
    // `rollback_flow` return false unless `live_by_flow[flow].translated`
    // equals THIS `translated` tuple, so an allocator holding a different
    // flow — or the same flow under a different translation — is untouched.
    // For the single-reservation case — whenever selection never moved, which
    // is the overwhelmingly common one — the outcome is bit-identical; only
    // the early exit is gone. Note this is NOT the same as "every pre-#6211
    // config": occupancy-dependent selection predates #6211, so a pre-#6211
    // config could already hold one flow in two allocators (see above).
    //
    // That early exit was NOT on a cold path, so state the cost honestly rather
    // than waving it off. This body backs `rollback_source_nat_allocation` as
    // well as the release, and that has five non-test call sites, all of them on
    // the packet path in `afxdp/poll_descriptor/mod.rs` (:2313, :2374, :2472,
    // :2644, :4912) — :2374 is the admission-refusal arm, i.e. the flood regime.
    // Per refused SNAT'ed flow the sweep takes K allocator locks instead of
    // (owning index + 1), where K is the pool-mode rule count. This is a
    // mechanism statement: no throughput measurement was taken and none is
    // claimed. The correctness argument above is what justifies it — a leaked
    // `(pool_addr, port)` is permanent and counts against `max_tracked_flows`
    // until exhaustion, while the extra locks are bounded and per-teardown.
    for rule in rules {
        if !rule.pool_mode {
            continue;
        }
        if rollback {
            rule.pool_allocator
                .rollback_flow(flow, translated, now_ns, holder);
        } else {
            rule.pool_allocator
                .release_flow(flow, translated, now_ns, holder);
        }
    }
}

/// #6211: the ACTIVE node's `(from_zone, to_zone)` NAME pair for a synced
/// session, when the standby could resolve BOTH from the wire-carried zone
/// IDs. `None` means "the active's zone pair is unknown here" — an old peer
/// that carried neither a zone id nor a resolvable zone name, or a zone that
/// is not in this node's snapshot (config drift) — and selects the pre-#6211
/// first-pool-match fallback rather than narrowing on a zone the standby is
/// guessing at.
pub(crate) type SyncedNatZones<'a> = Option<(&'a str, &'a str)>;

/// #4388: reserve a peer-synced session's translated pool port in THIS node's
/// local source-NAT allocator so a post-failover local allocation cannot hand
/// the same `(pool_addr, port)` to a new flow (NAT source collision / session
/// hijack surface).
///
/// The standby imports the active node's pre-computed NAT decision but never
/// calls `allocate_translation`, so its allocator has no record that
/// `(pool_addr, port)` is in use. Mirror `release_source_nat_allocation`'s
/// flow-key / translated-tuple construction EXACTLY so the same-key
/// `release_flow` / `rollback_flow` on the standard teardown path
/// (`release_source_nat_allocation`, already called for every reaped or
/// delete-synced session) frees the reservation — no new delete site.
///
/// A synced session with NO source NAT at all (`rewrite_src` unset — plain
/// forwarding) reserves nothing. If the synced pool address is not a member of
/// ANY local pool (config drift between nodes), the reserve is skipped
/// gracefully — it never panics and never fabricates a reservation on the wrong
/// pool.
///
/// #5338: an ADDRESS-ONLY source-NAT decision (`port no-translation` on a
/// port-bearing protocol, or a port-less protocol such as GRE/ESP) carries a
/// pool `rewrite_src` but NO `rewrite_src_port` — the wire keeps the packet's
/// own source port. The ACTIVE node (#5336 round-robin/persistent, #5341
/// deterministic-CGNAT) still MINTS a reverse-identity occupancy token for such
/// a flow via [`PortAllocator::reserve_address_only`], keyed on the translated
/// reverse identity (protocol, pool address, PRESERVED source port, remote), so
/// the reverse (1:N) index can disambiguate which internal flow owns a given
/// public tuple. The standby must mint the SAME token for a synced address-only
/// session; otherwise, after failover to it, its reverse index cannot
/// disambiguate the promoted session (and a fresh local address-only flow could
/// claim the same public identity the reverse index cannot tell apart). This
/// mirrors the active-node mint here; NO pool PORT bit is consumed. The token is
/// freed by the SAME teardown path as a PAT port
/// (`release_source_nat_allocation` -> `PortAllocator::release_flow`, already
/// called for every reaped or delete-synced session) — no new delete site. The
/// #6207 `deterministic` threading applies ONLY to the port-bearing
/// [`PortAllocator::reserve_flow`] arm; an address-only token carries no port
/// bit, so — exactly like the active node's #5341 path — it mints via the plain
/// `reserve_address_only` regardless of the pool's allocation mode.
///
/// #6211: WHICH rule the reservation lands on now mirrors the active node's
/// choice.
///
/// SCOPE — the motivating config is NOT reachable through a supported commit.
/// #5144 hard-rejects duplicate source-NAT pool addresses at strict commit
/// (`TestNAT5144ExactDuplicateSourcePools` asserts `CompileConfig` refuses
/// exactly this shape), so the live surface is the two paths that BYPASS the
/// strict compiler: a pre-#5144 persisted config, and the tolerant
/// load / peer-sync path (#1960 no-brick). That bounds the original defect's
/// severity — it is not an ordinary operator configuration.
///
/// Two source-NAT rules may carry the SAME pool ADDRESS in SEPARATE
/// allocators (distinct `pool_name` / port range => distinct `allocator_key`),
/// and the pre-#6211 selection — "the first rule whose pool CONTAINS
/// `rewrite_src`" — narrowed on NO other axis, while the active picked its rule
/// by zone/policy match. Under such a config the standby's reservation could
/// land in a DIFFERENT allocator than the active used for the same session, so
/// after a failover a new local flow matching the OTHER rule missed the
/// collision guard — the reverse-identity token sat in the wrong allocator,
/// reintroducing the reverse-path ambiguity the token exists to prevent.
///
/// The fix is LOCAL, not a wire change: every input the active's rule match
/// consumes is already synced. The zone pair rides the session-sync wire as
/// `ingress_zone_id`/`egress_zone_id` (`SessionSyncRequest`, resolved into
/// `SessionMetadata::ingress_zone`/`egress_zone`) and the 5-tuple IS the
/// session key, so the standby re-runs the active's own match predicate
/// ([`SourceNatRule::matches_ignoring_scope`]) instead of inventing a second
/// identity scheme. Only the #3096 interface / routing-instance scope is
/// node-local and unconfirmable; see that method for why it is treated as
/// unconstrained rather than as a mismatch. An unresolvable zone pair
/// (`synced_zones == None` — an old peer, or config drift) falls back to the
/// pre-#6211 first-pool-match, which is no worse than what shipped
/// (rolling-upgrade safe).
/// Reserve a synced translation WITHOUT recording a worker holder — the
/// pre-#6211-F2 contract. Production must use
/// [`reserve_synced_source_nat_allocation_for_worker`]; this entry point remains
/// for tests that exercise the single-holder semantics directly.
/// Compile-time completeness guard for #6211 F2: this untracked entry point is
/// TEST-ONLY, so a production caller that forgot to thread its `worker_id` is a
/// BUILD FAILURE in the non-test profile rather than a silent single-holder
/// release of a reservation every worker holds. Production uses the
/// `_for_worker` twin.
#[cfg(test)]
pub(crate) fn reserve_synced_source_nat_allocation(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    // #6211: see `SyncedNatZones`.
    synced_zones: SyncedNatZones<'_>,
    now_ns: u64,
) {
    reserve_synced_source_nat_allocation_with_holder(
        rules,
        key,
        nat,
        is_reverse,
        synced_zones,
        now_ns,
        NatHolder::Untracked,
    );
}

/// #6211 F2: reserve a synced translation and record `worker_id` as a HOLDER.
///
/// `handle_upsert_synced` runs on EVERY worker (the entry is fanned out to each
/// worker's command queue) while the source-NAT allocator is a single shared
/// `Arc`, so the same `(flow, translated)` is reserved N times. Recording each
/// worker's bit is what lets the release path free the port only after the LAST
/// worker lets go — without it the first worker to reap or delete-sync the
/// session frees a port the other N-1 are still forwarding through.
pub(crate) fn reserve_synced_source_nat_allocation_for_worker(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    synced_zones: SyncedNatZones<'_>,
    // #6528: the stale-tuple eviction inside `reserve_flow` retires the
    // incumbent with release semantics, which re-arms a persistent lease's idle
    // expiry off a real clock.
    now_ns: u64,
    worker_id: u32,
) -> bool {
    reserve_synced_source_nat_allocation_with_holder(
        rules,
        key,
        nat,
        is_reverse,
        synced_zones,
        now_ns,
        NatHolder::Worker(worker_id),
    )
}

/// #6600: the COORDINATOR-side reservation, taken BEFORE the shared session
/// entry is published.
///
/// It holds `NatHolder::Untracked`, which contributes no holder bit, so the
/// per-worker reservations that follow are absorbed rather than doubled:
/// `reserve_flow` finds the identical `(flow, translated)` already live and
/// takes its idempotent early-return, OR-ing the worker's bit in. The last
/// worker's release then empties the mask and frees the port exactly as before.
pub(crate) fn reserve_synced_source_nat_allocation_untracked(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    synced_zones: SyncedNatZones<'_>,
    now_ns: u64,
) -> bool {
    reserve_synced_source_nat_allocation_with_holder(
        rules,
        key,
        nat,
        is_reverse,
        synced_zones,
        now_ns,
        NatHolder::Untracked,
    )
}

/// Returns whether the translation is RESERVED on this node — either because a
/// pass took it, or because there was nothing to reserve (a reverse entry, or a
/// decision with no `rewrite_src`). `false` means every candidate rule REFUSED,
/// i.e. a different live allocation already owns the port (#6600).
///
/// Before #6600 the bool `reserve_synced_on_first_pool_owner` already computed
/// was discarded here, and the whole chain up to `handle_upsert_synced` returned
/// `()` — so a refusal was not returned, not counted and not logged. The
/// coordinator uses this return to refuse the import outright rather than
/// publishing a session whose translation names a port this node does not own.
fn reserve_synced_source_nat_allocation_with_holder(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    // #6211: see `SyncedNatZones`.
    synced_zones: SyncedNatZones<'_>,
    now_ns: u64,
    holder: NatHolder,
) -> bool {
    if is_reverse {
        return true;
    }
    let Some(rewrite_src) = nat.rewrite_src else {
        return true;
    };
    let flow = SourceNatFlowKey {
        protocol: key.protocol,
        src_ip: key.src_ip,
        dst_ip: nat.rewrite_dst.unwrap_or(key.dst_ip),
        src_port: key.src_port,
        dst_port: key.dst_port,
    };
    // #6211 PASS 1 — reserve on a rule the ACTIVE node could actually have
    // matched. `flow` is byte-identical to the active's SNAT-match tuple
    // (`nat_match_flow.forward_key` in `poll_descriptor`: original source,
    // POST-DNAT destination, original ports), so feeding it back through the
    // SAME `matches_*` predicate reproduces the active's rule choice on every
    // axis the standby can see — and, like the active's
    // `match_source_nat_result_for_tuple`, takes the FIRST matching rule in
    // snapshot order (that order IS the Junos specificity precedence, #4161).
    // A synced session always carries a real L4 protocol, so `tuple_unknown`
    // is false — the address-only `match_source_nat` wrapper's sentinel
    // (#5687) does not apply here.
    if let Some((from_zone, to_zone)) = synced_zones
        && reserve_synced_on_first_pool_owner(
            rules.iter().filter(|rule| {
                rule.matches_ignoring_scope(
                    from_zone,
                    to_zone,
                    flow.src_ip,
                    flow.dst_ip,
                    false,
                    flow.protocol,
                    flow.src_port,
                    flow.dst_port,
                )
            }),
            flow,
            rewrite_src,
            nat.rewrite_src_port,
            now_ns,
            holder,
        )
    {
        return true;
    }
    // #6211 PASS 2 — the pre-#6211 behaviour, unchanged: the first rule whose
    // pool CONTAINS the translated address, with no zone/tuple narrowing.
    //
    // Reached when the zone pair is unknown (`synced_zones == None`), when NO
    // rule the standby can confirm as a match owns the address (the active
    // matched an interface-scoped rule under a config the standby cannot
    // reproduce, or the nodes' NAT config has drifted), or when every matching
    // candidate REFUSED the reservation (a local flow already owns the
    // identity). Keeping the fallback unconditional is deliberate: it is
    // exactly what shipped before this fix, so no configuration can come out
    // of #6211 with FEWER reservations than it had. Pass 1 can only move a
    // reservation to a better-justified allocator, never remove one.
    reserve_synced_on_first_pool_owner(
        rules.iter(),
        flow,
        rewrite_src,
        nat.rewrite_src_port,
        now_ns,
        holder,
    )
}

/// #6211: reserve the synced translation on the first rule in `rules` whose
/// pool owns `rewrite_src` and which ACCEPTS the reservation. Returns whether
/// a reservation was taken. Both #6211 passes share this body, so the two
/// differ ONLY in which rules they are offered — the reservation semantics
/// (pool-mode gate, address-index math, address-only vs port-bearing arm,
/// per-rule fall-through) cannot drift between them.
fn reserve_synced_on_first_pool_owner<'a>(
    rules: impl Iterator<Item = &'a SourceNatRule>,
    flow: SourceNatFlowKey,
    rewrite_src: IpAddr,
    rewrite_src_port: Option<u16>,
    // #6528: threaded to `reserve_flow` for its stale-tuple eviction.
    now_ns: u64,
    // #6211 F2: the worker taking this reservation, so a fan-out to N workers
    // records N holders on ONE allocator record.
    holder: NatHolder,
) -> bool {
    for rule in rules {
        if !rule.pool_mode {
            continue;
        }
        // #5338: address-only synced decision (pool address chosen, source port
        // PRESERVED on the wire). Mint the reverse-identity occupancy token on
        // the rule whose pool owns `rewrite_src`, mirroring the active node's
        // #5336/#5341 mint so the reverse 1:N index disambiguates identically. A
        // collision on the standby (`Err` — a local flow already owns the
        // identity) or a foreign pool address (no pool member) leaves the rule
        // untouched and tries the next, matching the port-bearing arm's per-rule
        // fall-through and the config-drift skip.
        let Some(rewrite_src_port) = rewrite_src_port else {
            let in_pool = match rewrite_src {
                IpAddr::V4(v4) => rule.pool_addresses_v4.iter().any(|a| *a == v4),
                IpAddr::V6(v6) => rule.pool_addresses_v6.iter().any(|a| *a == v6),
            };
            if !in_pool {
                continue;
            }
            if rule
                .pool_allocator
                .reserve_address_only(flow, rewrite_src, holder)
                .is_ok()
            {
                return true;
            }
            continue;
        };
        // The absolute allocator address index mirrors the allocation path:
        // v4 addresses occupy `[0, len_v4)`, v6 addresses follow at
        // `[len_v4, len_v4 + len_v6)` (see `address_index` / the v6_offset in
        // `match_source_nat_result_for_tuple`).
        let addr_index = match rewrite_src {
            IpAddr::V4(v4) => rule.pool_addresses_v4.iter().position(|a| *a == v4),
            IpAddr::V6(v6) => rule
                .pool_addresses_v6
                .iter()
                .position(|a| *a == v6)
                .map(|i| rule.pool_addresses_v4.len() + i),
        };
        let Some(addr_index) = addr_index else {
            continue;
        };
        // #5178: tag the reservation deterministic iff this rule runs a
        // deterministic CGNAT (mode 1) pool, so its release uses
        // `free_no_recycle` and the standby's recycle queue does not grow under
        // synced-session churn — matching the active node's
        // `allocate_deterministic_v4` release path.
        if rule.pool_allocator.reserve_flow(
            flow,
            TranslatedTuple {
                ip: rewrite_src,
                port: rewrite_src_port,
            },
            addr_index,
            rule.deterministic_v4.is_some(),
            now_ns,
            holder,
        ) {
            return true;
        }
    }
    false
}

/// #4381: allocate a UNIQUE translated `(pool v4 address, L4 port/identifier)`
/// for a NAT64 forward flow, reusing the pool-mode SNAT [`PortAllocator`].
///
/// NAT64 is a many-to-one (v6→v4) translation exactly like pool-mode source
/// NAT: several IPv6 clients are hidden behind one IPv4 pool address, so two
/// clients that share a source port (TCP/UDP) or ICMP echo identifier MUST get
/// DISTINCT translated values or their reverse (v4→v6) 5-tuples collide and the
/// server's replies are mis-associated — the missing RFC 6146 BIB. Rather than
/// hand-roll a parallel allocator, the crate-root `nat64` module drives the
/// same collision-free `PortAllocator` the pool-mode SNAT path uses.
///
/// This thin wrapper keeps the module-private `TranslatedTuple` /
/// `PoolAddressFamily` types out of `nat64.rs`. NAT64 never uses persistent NAT
/// or address-persistent stickiness, so those knobs are fixed off.
pub(crate) fn allocate_nat64_pool_port(
    allocator: &PortAllocator,
    flow: SourceNatFlowKey,
    pool_v4: &[Ipv4Addr],
    now_ns: u64,
    // #6522: the allocating worker — see `match_source_nat_result_for_tuple`.
    holder: NatHolder,
) -> Result<(Ipv4Addr, u16), SourceNatFailureReason> {
    let translated = allocator.allocate_translation(
        flow,
        PoolAddressFamily::V4(pool_v4),
        0,     // family_offset — the v4 pool starts at index 0
        false, // address_persistent
        false, // persistent_nat
        PersistentNatPermit::default(),
        0, // persistent_nat_timeout_ns — unused when persistent_nat is false
        now_ns,
        holder,
    )?;
    match translated.ip {
        IpAddr::V4(v4) => Ok((v4, translated.port)),
        // The pool is always v4 for NAT64, so this is unreachable; fail closed.
        IpAddr::V6(_) => Err(SourceNatFailureReason::WrongAddressFamily),
    }
}

/// #4559: allocate a DETERMINISTIC translated `(pool v4 address, L4 port)` for
/// a NAPT64 (mode 2) forward flow — the IPv6 subscriber deterministically maps
/// to a fixed external IPv4 + port block ([`allocate_deterministic_v6`]).
/// Thin wrapper mirroring [`allocate_nat64_pool_port`] so the module-private
/// `TranslatedTuple` stays out of `nat64.rs`; `flow` carries the original IPv6
/// subscriber (`flow.src_ip`), from which the subscriber block is derived. The
/// pool is always v4 for NAT64, so a v6 translated tuple is unreachable and
/// fails closed.
pub(crate) fn allocate_nat64_pool_port_deterministic_v6(
    allocator: &PortAllocator,
    flow: SourceNatFlowKey,
    pool_v4: &[Ipv4Addr],
    params: DeterministicV6,
    src_v6: Ipv6Addr,
    // #6522: the allocating worker — see `match_source_nat_result_for_tuple`.
    holder: NatHolder,
) -> Result<(Ipv4Addr, u16), SourceNatFailureReason> {
    let translated =
        allocator.allocate_deterministic_v6(flow, pool_v4, params, src_v6, holder)?;
    match translated.ip {
        IpAddr::V4(v4) => Ok((v4, translated.port)),
        IpAddr::V6(_) => Err(SourceNatFailureReason::WrongAddressFamily),
    }
}

/// #4381: release (or roll back) a NAT64 forward flow's translated pool port,
/// mirroring [`release_source_nat_allocation`]'s flow-key / translated-tuple
/// construction so the SAME `release_flow` / `rollback_flow` frees the port the
/// forward flow allocated. Returns whether the allocation was found and freed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn release_nat64_pool_port(
    allocator: &PortAllocator,
    flow: SourceNatFlowKey,
    snat_v4: Ipv4Addr,
    port: u16,
    now_ns: u64,
    rollback: bool,
    // #6211 F2: the worker letting go. `NatHolder::Untracked` keeps the
    // pre-#6211-F2 first-release-frees contract for a local NAT64 flow; a synced
    // reservation taken by N workers frees only on the last one.
    holder: NatHolder,
) -> bool {
    let translated = TranslatedTuple {
        ip: IpAddr::V4(snat_v4),
        port,
    };
    if rollback {
        allocator.rollback_flow(flow, translated, now_ns, holder)
    } else {
        allocator.release_flow(flow, translated, now_ns, holder)
    }
}

/// #4512: reserve a peer-synced NAT64 forward flow's translated `(pool v4,
/// port/identifier)` in THIS node's NAT64 [`PortAllocator`] WITHOUT running the
/// round-robin cursor, mirroring [`reserve_synced_source_nat_allocation`] for
/// the pool-mode SNAT allocator (#4388).
///
/// The standby imports the active node's pre-computed NAT64 decision but never
/// calls `allocate_source`, so without this its allocator has no record that
/// `(snat_v4, port)` is in use — post-failover a fresh local NAT64 flow could
/// `allocate_source` the SAME tuple, two flows colliding on one translated
/// source (the exact RFC 6146 BIB violation #4381 closed, reappearing across a
/// cross-node failover). The reservation is stored EXACTLY like a normal
/// allocation and freed by the SAME `release_nat64_pool_port` on the standard
/// teardown path (`release_nat64_allocation`, already called on reap / purge /
/// delete-sync), so no new delete site is needed.
///
/// `addr_index` is the position of `snat_v4` in the prefix's `pool_v4` — the
/// NAT64 allocator uses `family_offset == 0`, so the absolute allocator index
/// equals the pool position. Returns whether the reservation took (`false` if
/// the port is already owned by a DIFFERENT live allocation — the caller then
/// tries the next prefix).
///
/// #5178: `deterministic` is `true` when the prefix runs a NAPT64 (mode 2)
/// deterministic pool (`prefix.deterministic_v6.is_some()`), so the reservation
/// is tagged deterministic and released via `free_no_recycle` — matching the
/// active node's `allocate_deterministic_v6` release. A round-robin NAT64 pool
/// passes `false` and keeps today's recycle behaviour.
#[allow(clippy::too_many_arguments)]
pub(crate) fn reserve_nat64_pool_port(
    allocator: &PortAllocator,
    flow: SourceNatFlowKey,
    snat_v4: Ipv4Addr,
    port: u16,
    addr_index: usize,
    deterministic: bool,
    // #6528: threaded to `reserve_flow` for its stale-tuple eviction.
    now_ns: u64,
    // #6211 F2: the worker taking this reservation. The synced NAT64 entry is
    // fanned out to every worker against ONE shared allocator, exactly like the
    // pool-mode SNAT reservation.
    holder: NatHolder,
) -> bool {
    let translated = TranslatedTuple {
        ip: IpAddr::V4(snat_v4),
        port,
    };
    allocator.reserve_flow(flow, translated, addr_index, deterministic, now_ns, holder)
}

pub(crate) fn match_source_nat(
    rules: &[SourceNatRule],
    scope: &NatScopeCtx,
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
) -> Option<NatDecision> {
    match match_source_nat_result(
        rules, scope, from_zone, to_zone, src_ip, dst_ip, egress_v4, egress_v6,
    ) {
        SourceNatLookup::Matched(decision) => Some(decision),
        SourceNatLookup::NoMatch | SourceNatLookup::Unavailable(_) => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn match_source_nat_result(
    rules: &[SourceNatRule],
    scope: &NatScopeCtx,
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
) -> SourceNatLookup {
    let mut counter = None;
    match_source_nat_result_for_tuple(
        rules,
        scope,
        from_zone,
        to_zone,
        src_ip,
        dst_ip,
        // #5687: `None` is the out-of-band "L4 tuple unknown" signal for the
        // address-only wrapper — distinct from a real HOPOPT (`Some(0)`).
        None,
        0,
        0,
        egress_v4,
        egress_v6,
        0,
        false,
        // #4088: the address-only wrapper never carries an ICMP query id
        // (the tuple is unknown), so there is no identifier to preserve.
        false,
        // #6522: this wrapper has no worker context (its only callers are the
        // `#[cfg_attr(not(test), allow(dead_code))]` helpers in
        // `afxdp/forwarding/nat.rs`), so it keeps the untracked contract.
        NatHolder::Untracked,
        &mut counter,
    )
}

/// #2218: same as `match_source_nat_result_for_tuple` but the matched
/// rule's per-rule hit counter (if any) is written to `matched_counter`.
/// The `SourceNatLookup` enum stays wire-/Eq-frozen (it is destructured
/// and `matches!`-compared in many tests and over no wire), so the counter
/// rides out via this out-parameter rather than a new enum payload — the
/// least-invasive shape. The cold-path commit site clones the captured
/// `Arc` and increments it once per committed translated flow.
#[allow(clippy::too_many_arguments)]
pub(crate) fn match_source_nat_result_for_tuple(
    rules: &[SourceNatRule],
    scope: &NatScopeCtx,
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    // #5687: the L4 protocol is OUT-OF-BAND optional so a genuine IPv4
    // protocol 0 (HOPOPT) is representable and distinct from the synthetic
    // "L4 tuple unknown" caller:
    //   - `None`     => tuple unknown (the address-only `match_source_nat`
    //     wrapper, which has no L4 tuple to supply). Fails L4-constrained
    //     rules closed and takes the synthetic address-only path.
    //   - `Some(0)`  => a REAL protocol-0 (HOPOPT) packet. It is port-less
    //     like GRE/ESP/OSPF, so it takes the real address-only path
    //     (`reserve_address_only` mints the reverse-identity occupancy
    //     token) — its reverse tuple can now be matched.
    //   - `Some(n)`  => any other real protocol (TCP=6, UDP=17, ICMP=1, ...),
    //     byte-identical behavior to before this fix.
    // The `SourceNatFlowKey.protocol` reverse-index key stays `u8` (the real
    // value, 0 for HOPOPT), so the in-map / HA-sync tuple layout is unchanged.
    protocol: Option<u8>,
    src_port: u16,
    dst_port: u16,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
    now_ns: u64,
    // #1852: when true, gate port-translating (pool-mode) allocation —
    // a non-first fragment has no L4 ports. Interface-mode (address-only)
    // and `off`/static rules are unaffected.
    non_first_fragment: bool,
    // #4088 (RFC 5508 §3.1): for an ICMP/ICMPv6 tuple this is the
    // authoritative "the tuple carries a real ICMP Query Identifier" signal,
    // replacing the old `src_port != 0` heuristic. The frame parser
    // (`parse_flow_ports`) only lifts an identifier into `src_port` for an
    // identifier-bearing query type, and a `SessionFlow` is only built for an
    // ICMP protocol when that gate matched — so the flow caller passes
    // `matches!(protocol, PROTO_ICMP | PROTO_ICMPV6)`. An ICMP Query
    // Identifier of 0 is a valid on-wire value (0..=65535); keying the query
    // gate on `src_port != 0` misclassified an id==0 query as flowless and
    // took the address-only path, colliding two id==0 flows behind one pool
    // address on the reverse tuple (pool_addr, 0). The synthetic /
    // address-only (`protocol == 0`) callers pass `false`.
    icmp_identifier_present: bool,
    // #6522: the worker whose packet path is making this allocation. The record
    // this call inserts names its own holder, so a sibling worker's replica of
    // the resulting session cannot free a `(pool_addr, port)` this worker is
    // still forwarding through (see `NatHolder` / `LiveAllocation::holders`).
    // `NatHolder::Untracked` keeps the pre-#6522 single-holder contract for the
    // test entry points and the read-only fragment probe.
    holder: NatHolder,
    matched_counter: &mut Option<Arc<NatRuleCounter>>,
) -> SourceNatLookup {
    // #5687: decode the out-of-band protocol. `None` is the tuple-unknown
    // signal (address-only wrapper); a real HOPOPT arrives as `Some(0)` and is
    // NOT confused with it. The reverse-index key keeps the real u8 value.
    let tuple_unknown = protocol.is_none();
    let protocol = protocol.unwrap_or(0);
    let flow = SourceNatFlowKey {
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    };
    // #4161: this is first-match on slice order, and that is INTENTIONALLY
    // most-specific-scope-wins. The Go snapshot builder
    // (pkg/dataplane/userspace/nat.go buildSourceNATSnapshotsWithFeeds) STABLE-
    // sorts the rule-sets by Junos context specificity (interface > zone >
    // routing-instance > unscoped) before publishing, with config order as the
    // tie-break, so the first rule that matches here is the most-specific one.
    // Precedence therefore lives in the snapshot ORDER, not in this loop — do
    // not re-sort or assume raw config order.
    for rule in rules {
        if !rule.matches(
            scope,
            from_zone,
            to_zone,
            src_ip,
            dst_ip,
            tuple_unknown,
            protocol,
            src_port,
            dst_port,
        ) {
            continue;
        }
        if rule.off {
            // An `off` rule applies no translation — leave matched_counter
            // unset so no hit is counted for a no-op match.
            return SourceNatLookup::Matched(NatDecision::default());
        }
        *matched_counter = rule.hit_counter.clone();
        if rule.interface_mode {
            // #5688: interface SNAT translates the source to the egress
            // interface's OWN same-family address. Resolve it by the PACKET's
            // family — a v4 packet needs a v4 egress address, a v6 packet a v6
            // one. If the egress interface has NO address of that family there is
            // nothing to translate to. Returning `Matched` with a `None` rewrite
            // here forwarded the packet UNTRANSLATED — the private/internal source
            // leaked onto the egress. Fail CLOSED instead: report `Unavailable`
            // so the flow funnels through the same drop / `nat_alloc_fail`
            // disposition a pool-mode allocation failure takes, and the leak
            // cannot happen.
            let rewrite_src = match src_ip {
                IpAddr::V4(_) => egress_v4.map(IpAddr::V4),
                IpAddr::V6(_) => egress_v6.map(IpAddr::V6),
            };
            let Some(rewrite_src) = rewrite_src else {
                return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                    rule,
                    SourceNatFailureReason::InterfaceNoEgressAddress,
                ));
            };
            return SourceNatLookup::Matched(NatDecision {
                rewrite_src: Some(rewrite_src),
                rewrite_dst: None,
                ..NatDecision::default()
            });
        }
        if rule.pool_mode {
            if let Some(reason) = rule.pool_failure {
                return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(rule, reason));
            }
        } else {
            // This rule matched the zone/addresses but is neither
            // interface-mode nor pool-mode — it applies no translation, so
            // clear the tentatively-captured counter and try the next rule.
            *matched_counter = None;
            continue;
        }
        // #1852: pool-mode SNAT translates the L4 port. A non-first
        // fragment carries no L4 header at the post-IP offset (its
        // "ports" are payload), so allocating a mapping here would both
        // leak a pool port per fragment and write the allocated port into
        // payload bytes. Without datapath reassembly the fragment cannot
        // be correctly port-mapped — drop it (the caller records the
        // exception). Interface-mode SNAT (address-only) already returned
        // above, so it and static NAT keep working on fragments.
        if non_first_fragment {
            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                rule,
                SourceNatFailureReason::NonFirstFragment,
            ));
        }
        // Pool-mode SNAT: pick address by source-IP hash when
        // address-persistent is enabled, otherwise round-robin by family.
        //
        // #3111: only TCP/UDP carry a 16-bit L4 port at offset +0/+2 that
        // pool-mode SNAT may translate via the flow-keyed allocator. A
        // protocol with NO L4 port concept (GRE/ESP/AH/OSPF/ICMP/...) must
        // NOT have a port allocated or written: pick a pool address and
        // leave `rewrite_src_port` unset so the packet rewriter touches
        // ONLY the IP address. Allocating a pseudo-port for these both
        // leaks a pool port per flow AND (via the descriptor fast path)
        // overwrites the first two L4 bytes, corrupting the tunnel header
        // (ESP SPI / GRE flags). The previous gate special-cased only
        // `protocol == 0`, so GRE/ESP/AH/OSPF fell through to
        // `allocate_translation` and were corrupted.
        //
        // #5687: the "L4 tuple unknown" case is the OUT-OF-BAND `tuple_unknown`
        // flag (`protocol == None` at the boundary), NOT the numeric value 0.
        // It is set only by the address-only `match_source_nat` wrapper (never a
        // real packet) and keeps its historical behavior — a round-robin port
        // via `try_next_port` with no flow-keyed mapping — because the packet
        // rewriters gate every L4 write on `has_l4_ports`, so the port it returns
        // can never be written to a frame. A genuine HOPOPT packet arrives as
        // `Some(0)` (`tuple_unknown == false`) and is classified `port_less`
        // below, exactly like GRE/ESP/OSPF: it takes the real address-only path
        // that mints a reverse-identity token, so its reverse tuple matches.
        // #4074 (RFC 5508 §3.1 "ICMP Query Mappings"): an ICMP/ICMPv6 echo or
        // query message carries a 16-bit Query Identifier that the flow parser
        // (`parse_flow_ports`) lifts into `src_port` (with `dst_port == 0`).
        // That identifier is the ICMP demux key — exactly the role a TCP/UDP
        // port plays — so pool-mode SNAT must translate it, or two internal
        // hosts pinging the same target with the same id, both hidden behind
        // one pool address, collide on the reverse tuple (pool_addr, id) and
        // their replies are mis-associated. A non-identifier ICMP control/error
        // message parses flowless (no `SessionFlow`, `icmp_identifier_present`
        // false) and keeps the address-only path — there is no id to translate.
        // `no_translation` (port no-translation) still preserves the id via the
        // `address_only` gate below. The translated id comes from the same pool
        // port/id space as the TCP/UDP PAT allocation (`allocate_translation`).
        //
        // #4088 (RFC 5508 §3.1): classify by the identifier-present signal, NOT
        // by `src_port != 0`. A valid ICMP echo whose Query Identifier is 0
        // must be treated as a real, keyable query (allocate + rewrite +
        // reverse-recover its id like any other), not misread as flowless.
        let icmp_query = matches!(protocol, PROTO_ICMP | PROTO_ICMPV6) && icmp_identifier_present;
        // #5687: gate `port_less` on the OUT-OF-BAND `tuple_unknown` flag, not
        // `protocol != 0`. A real HOPOPT (`Some(0)`, tuple_unknown == false) has
        // no L4 port, so it is port-less like GRE/ESP; the synthetic unknown
        // caller (tuple_unknown == true) is excluded here and handled by the
        // dedicated `tuple_unknown` branches below. `tuple_unknown` is decoded
        // at the top of the function from `protocol.is_none()`.
        let port_less = !tuple_unknown && !crate::ip_proto::has_l4_ports(protocol) && !icmp_query;
        // #3906: `port no-translation` translates the ADDRESS only and PRESERVES
        // the original source port. It takes the same address-only path as a
        // port-less protocol — pick a pool address, leave `rewrite_src_port`
        // unset so the packet rewriter keeps the packet's own source port
        // (checksum.rs `rewrite_src_port.unwrap_or(key.src_port)`). No pool port
        // is allocated. The chosen address is cached per-flow (flow_cache), so
        // the round-robin selection is stable for the flow's lifetime, exactly
        // like the port-less path.
        let address_only = port_less || tuple_unknown || rule.no_translation;
        match src_ip {
            IpAddr::V4(src_v4) if !rule.pool_addresses_v4.is_empty() => {
                // #4559: deterministic CGNAT (mode 1). The subscriber's internal
                // IPv4 fixes both the external pool address and the port block, so
                // no per-flow log is needed to reverse (external IP, port) back to
                // the subscriber. Address-only cases (port-less / no-translation /
                // tuple-unknown) still pick the DETERMINISTIC external address; a
                // REAL address-only flow additionally mints a reverse-identity
                // occupancy token so a colliding second flow fails closed (#5341,
                // mirroring the round-robin/persistent #5269/#5336 fix), while the
                // synthetic tuple-unknown wrapper mints none. The PAT case allocates
                // a port inside the subscriber's fixed block. An out-of-range
                // subscriber fails closed rather than silently round-robining.
                if let Some(det) = rule.deterministic_v4 {
                    if address_only {
                        let Some((ip_idx, _)) = deterministic_indices_v4(&det, src_v4) else {
                            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                                rule,
                                SourceNatFailureReason::DeterministicSubscriberOutOfRange,
                            ));
                        };
                        if ip_idx >= rule.pool_addresses_v4.len() {
                            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                                rule,
                                SourceNatFailureReason::AllocatorExhausted,
                            ));
                        }
                        let pool_addr = rule.pool_addresses_v4[ip_idx];
                        if tuple_unknown {
                            // Synthetic address-only wrapper (protocol == 0, never
                            // a framed packet): keep the historical round-robin port
                            // for the non-no-translation case, or preserve (None)
                            // for no-translation. No occupancy token — there is no
                            // real flow / reverse session entry to disambiguate and
                            // the returned port is never written to a frame.
                            // Symmetric with the round-robin/persistent branch
                            // below (#5269).
                            let port = if rule.no_translation {
                                None
                            } else {
                                match rule.pool_allocator.try_next_port(ip_idx) {
                                    Ok(port) => Some(port),
                                    Err(reason) => {
                                        return SourceNatLookup::Unavailable(
                                            SourceNatFailure::for_rule(rule, reason),
                                        );
                                    }
                                }
                            };
                            return SourceNatLookup::Matched(NatDecision {
                                rewrite_src: Some(IpAddr::V4(pool_addr)),
                                rewrite_dst: None,
                                rewrite_src_port: port,
                                rewrite_dst_port: None,
                                ..NatDecision::default()
                            });
                        }
                        // #5341: a REAL address-only flow on a DETERMINISTIC-CGNAT
                        // (mode 1) pool — `port no-translation` on a port-bearing
                        // protocol, or a port-less protocol (GRE/ESP/...). Like the
                        // round-robin/persistent branch (#5269, fixed in #5336),
                        // mint a reverse-identity occupancy token on the chosen
                        // DETERMINISTIC external address so a second flow that would
                        // collide on the SAME public reverse tuple (two subscribers
                        // sharing one deterministic pool address, same preserved
                        // source port, same remote) is DENIED as exhaustion instead
                        // of receiving an unowned duplicate the reverse (1:N) index
                        // cannot disambiguate. The wire packet keeps its own source
                        // port (rewrite_src_port left None — checksum.rs preserves
                        // it; the port-less frame rewriter is gated on
                        // `has_l4_ports`). The token is freed by the SAME teardown
                        // path (`release_source_nat_allocation` -> `release_flow`)
                        // as the round-robin branch — no new release site, no leak.
                        match rule
                            .pool_allocator
                            .reserve_address_only(flow, IpAddr::V4(pool_addr), NatHolder::Untracked)
                        {
                            Ok(translated) => {
                                return SourceNatLookup::Matched(NatDecision {
                                    rewrite_src: Some(translated.ip),
                                    rewrite_dst: None,
                                    rewrite_src_port: None,
                                    rewrite_dst_port: None,
                                    ..NatDecision::default()
                                });
                            }
                            Err(reason) => {
                                return SourceNatLookup::Unavailable(
                                    SourceNatFailure::for_rule(rule, reason),
                                );
                            }
                        }
                    }
                    let translated = match rule.pool_allocator.allocate_deterministic_v4(
                        flow,
                        &rule.pool_addresses_v4,
                        det,
                        src_v4,
                        holder,
                    ) {
                        Ok(translated) => translated,
                        Err(reason) => {
                            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                                rule, reason,
                            ));
                        }
                    };
                    return SourceNatLookup::Matched(NatDecision {
                        rewrite_src: Some(translated.ip),
                        rewrite_dst: None,
                        rewrite_src_port: Some(translated.port),
                        rewrite_dst_port: None,
                        ..NatDecision::default()
                    });
                }
                if address_only {
                    let addr_idx = rule.pool_allocator.address_index(
                        src_ip,
                        0,
                        rule.pool_addresses_v4.len(),
                        rule.address_persistent,
                    );
                    let pool_addr = rule.pool_addresses_v4[addr_idx];
                    if tuple_unknown {
                        // Synthetic address-only wrapper (protocol == 0, never a
                        // framed packet): keep the historical round-robin port for
                        // the non-no-translation case, or preserve (None) for
                        // no-translation. No occupancy token — there is no real
                        // flow / reverse session entry to disambiguate and the
                        // returned port is never written to a frame.
                        let port = if rule.no_translation {
                            None
                        } else {
                            match rule.pool_allocator.try_next_port(addr_idx) {
                                Ok(port) => Some(port),
                                Err(reason) => {
                                    return SourceNatLookup::Unavailable(
                                        SourceNatFailure::for_rule(rule, reason),
                                    );
                                }
                            }
                        };
                        return SourceNatLookup::Matched(NatDecision {
                            rewrite_src: Some(IpAddr::V4(pool_addr)),
                            rewrite_dst: None,
                            rewrite_src_port: port,
                            rewrite_dst_port: None,
                            ..NatDecision::default()
                        });
                    }
                    // #5269: a REAL address-only flow (`port no-translation` on a
                    // port-bearing protocol, or a port-less protocol). Mint an
                    // occupancy token for the translated reverse identity so a
                    // second flow that would collide on the same public tuple is
                    // DENIED as exhaustion instead of receiving an unowned
                    // duplicate the reverse (1:N) index cannot disambiguate. The
                    // wire packet still keeps its own source port (rewrite_src_port
                    // left None — checksum.rs preserves it; the port-less frame
                    // rewriter is gated on `has_l4_ports`).
                    //
                    // #6041: when the pool also configures `persistent-nat`, pin a
                    // public ADDRESS across the configured permit scope via an
                    // address-only persistent LEASE (the lease picks/reuses the
                    // address itself, so the round-robin `pool_addr` chosen above
                    // is bypassed — persistence no longer depends on the global
                    // `address-persistent` hash). The per-flow reverse-identity
                    // token is still minted for the #5269 collision guard.
                    let reserved = if rule.persistent_nat {
                        rule.pool_allocator.reserve_address_only_persistent(
                            flow,
                            PoolAddressFamily::V4(&rule.pool_addresses_v4),
                            0,
                            rule.address_persistent,
                            rule.persistent_nat_permit,
                            rule.persistent_nat_timeout_ns,
                            now_ns,
                            holder,
                        )
                    } else {
                        // #6226: probe the WHOLE pool from the round-robin start
                        // (`addr_idx`) so a colliding reverse identity on the
                        // chosen address rotates to a FREE sibling instead of
                        // falsely exhausting. `addr_idx` already advanced the
                        // round-robin counter above; the loop does not advance it
                        // again. `pool_addr` (= pool_addresses_v4[addr_idx]) is
                        // the loop's first probe — identical to the old single
                        // probe when it is free.
                        rule.pool_allocator.reserve_address_only_roundrobin(
                            flow,
                            PoolAddressFamily::V4(&rule.pool_addresses_v4),
                            0,
                            addr_idx,
                            rule.address_persistent,
                            holder,
                        )
                    };
                    match reserved {
                        Ok(translated) => {
                            return SourceNatLookup::Matched(NatDecision {
                                rewrite_src: Some(translated.ip),
                                rewrite_dst: None,
                                rewrite_src_port: None,
                                rewrite_dst_port: None,
                                ..NatDecision::default()
                            });
                        }
                        Err(reason) => {
                            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                                rule, reason,
                            ));
                        }
                    }
                }
                let translated = match rule.pool_allocator.allocate_translation(
                    flow,
                    PoolAddressFamily::V4(&rule.pool_addresses_v4),
                    0,
                    rule.address_persistent,
                    rule.persistent_nat,
                    rule.persistent_nat_permit,
                    rule.persistent_nat_timeout_ns,
                    now_ns,
                    holder,
                ) {
                    Ok(translated) => translated,
                    Err(reason) => {
                        return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                            rule, reason,
                        ));
                    }
                };
                return SourceNatLookup::Matched(NatDecision {
                    rewrite_src: Some(translated.ip),
                    rewrite_dst: None,
                    rewrite_src_port: Some(translated.port),
                    rewrite_dst_port: None,
                    ..NatDecision::default()
                });
            }
            IpAddr::V6(_) if !rule.pool_addresses_v6.is_empty() => {
                let v6_offset = rule.pool_addresses_v4.len();
                if address_only {
                    let addr_idx = rule.pool_allocator.address_index(
                        src_ip,
                        v6_offset,
                        rule.pool_addresses_v6.len(),
                        rule.address_persistent,
                    );
                    let v6_idx = addr_idx - v6_offset;
                    let pool_addr = rule.pool_addresses_v6[v6_idx];
                    if tuple_unknown {
                        // Synthetic address-only wrapper (protocol == 0): historical
                        // round-robin port (non-no-translation) or preserve (None).
                        // No occupancy token — see the v4 branch above (#5269).
                        let port = if rule.no_translation {
                            None
                        } else {
                            match rule.pool_allocator.try_next_port(addr_idx) {
                                Ok(port) => Some(port),
                                Err(reason) => {
                                    return SourceNatLookup::Unavailable(
                                        SourceNatFailure::for_rule(rule, reason),
                                    );
                                }
                            }
                        };
                        return SourceNatLookup::Matched(NatDecision {
                            rewrite_src: Some(IpAddr::V6(pool_addr)),
                            rewrite_dst: None,
                            rewrite_src_port: port,
                            rewrite_dst_port: None,
                            ..NatDecision::default()
                        });
                    }
                    // #5269: REAL address-only flow — mint a reverse-identity
                    // occupancy token (deny a colliding second flow as exhaustion),
                    // symmetric with the v4 branch above. #6041: route the
                    // `persistent-nat` combination through the address-only
                    // persistent lease so the public address is pinned across the
                    // permit scope (the lease selects the address; the round-robin
                    // `pool_addr` above is bypassed).
                    let reserved = if rule.persistent_nat {
                        rule.pool_allocator.reserve_address_only_persistent(
                            flow,
                            PoolAddressFamily::V6(&rule.pool_addresses_v6),
                            v6_offset,
                            rule.address_persistent,
                            rule.persistent_nat_permit,
                            rule.persistent_nat_timeout_ns,
                            now_ns,
                            holder,
                        )
                    } else {
                        // #6226: probe the WHOLE pool from the round-robin start
                        // (`addr_idx`, absolute over the combined v4+v6 index
                        // space) so a colliding reverse identity on the chosen
                        // address rotates to a FREE sibling instead of falsely
                        // exhausting. `addr_idx` already advanced the round-robin
                        // counter above; the loop does not advance it again.
                        rule.pool_allocator.reserve_address_only_roundrobin(
                            flow,
                            PoolAddressFamily::V6(&rule.pool_addresses_v6),
                            v6_offset,
                            addr_idx,
                            rule.address_persistent,
                            holder,
                        )
                    };
                    match reserved {
                        Ok(translated) => {
                            return SourceNatLookup::Matched(NatDecision {
                                rewrite_src: Some(translated.ip),
                                rewrite_dst: None,
                                rewrite_src_port: None,
                                rewrite_dst_port: None,
                                ..NatDecision::default()
                            });
                        }
                        Err(reason) => {
                            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                                rule, reason,
                            ));
                        }
                    }
                }
                let translated = match rule.pool_allocator.allocate_translation(
                    flow,
                    PoolAddressFamily::V6(&rule.pool_addresses_v6),
                    v6_offset,
                    rule.address_persistent,
                    rule.persistent_nat,
                    rule.persistent_nat_permit,
                    rule.persistent_nat_timeout_ns,
                    now_ns,
                    holder,
                ) {
                    Ok(translated) => translated,
                    Err(reason) => {
                        return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                            rule, reason,
                        ));
                    }
                };
                return SourceNatLookup::Matched(NatDecision {
                    rewrite_src: Some(translated.ip),
                    rewrite_dst: None,
                    rewrite_src_port: Some(translated.port),
                    rewrite_dst_port: None,
                    ..NatDecision::default()
                });
            }
            _ => {
                return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                    rule,
                    SourceNatFailureReason::WrongAddressFamily,
                ));
            }
        }
    }
    SourceNatLookup::NoMatch
}

/// #2398: parse one match prefix into the family-appropriate prefix vec. A CIDR
/// (`10.0.0.0/24`) is parsed directly; a bare host IP (`10.0.0.5`) — which
/// `IpNet::from_str` rejects — falls back to a /32 (v4) or /128 (v6). A prefix
/// that parses as neither is dropped (it narrows the match rather than widening
/// it); the `*_constrained` flag, set from the snapshot list being non-empty,
/// makes an all-malformed set fail closed in `nets_match_*`.
fn parse_match_prefix(
    prefix: &str,
    v4: &mut Vec<PrefixV4>,
    v6: &mut Vec<PrefixV6>,
    nat_counters: &NatCounterStore,
    rule_name: &str,
    axis: &str,
) {
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => v4.push(PrefixV4::from_net(net)),
        Ok(IpNet::V6(net)) => v6.push(PrefixV6::from_net(net)),
        Err(_) => match prefix.parse::<IpAddr>() {
            Ok(IpAddr::V4(addr)) => {
                if let Ok(net) = Ipv4Net::new(addr, 32) {
                    v4.push(PrefixV4::from_net(net));
                }
            }
            Ok(IpAddr::V6(addr)) => {
                if let Ok(net) = Ipv6Net::new(addr, 128) {
                    v6.push(PrefixV6::from_net(net));
                }
            }
            // #4718: a prefix that parses as neither a CIDR nor a bare host IP
            // is dropped from the match set. The `*_constrained` flag keeps this
            // fail-closed (an all-malformed set matches NOTHING, never the
            // pre-#2398 fail-open collapse to match-any), but the drop was
            // SILENT — surface it loudly + count it so an operator sees the
            // configured match prefix that never reached the dataplane.
            Err(_) => nat_counters.record_parse_error(&format!(
                "source-NAT rule {rule_name:?}: unparseable {axis} match prefix {prefix:?}"
            )),
        },
    }
}

/// #3429: is `port` within any inclusive (low, high) range in `ranges`?
fn port_in_ranges(port: u16, ranges: &[(u16, u16)]) -> bool {
    ranges.iter().any(|&(lo, hi)| port >= lo && port <= hi)
}

/// #2398: match a v4 IP against a rule's match set.
///
/// - `constrained == false` (unscoped match set): match any IP (unchanged).
/// - `constrained == true` but `nets` empty (every configured prefix failed to
///   parse): match NOTHING — fail closed, never the pre-#2398 collapse to
///   match-any fail-open broadening.
/// - otherwise: the IP must fall in one of the parsed prefixes.
fn nets_match_v4(constrained: bool, nets: &[PrefixV4], ip: Ipv4Addr) -> bool {
    if !constrained {
        return true;
    }
    if nets.is_empty() {
        return false;
    }
    nets.iter().any(|net| net.contains(ip))
}

/// #2398: match a v6 IP against a rule's match set. See `nets_match_v4`.
fn nets_match_v6(constrained: bool, nets: &[PrefixV6], ip: Ipv6Addr) -> bool {
    if !constrained {
        return true;
    }
    if nets.is_empty() {
        return false;
    }
    nets.iter().any(|net| net.contains(ip))
}
