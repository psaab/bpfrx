use crate::prefix::{PrefixV4, PrefixV6};
use crate::prefix_set::{PrefixSetV4, PrefixSetV6};
use crate::{
    AddressBookSnapshot, PolicyApplicationSnapshot, PolicyRuleCounterStatus, PolicyRuleSnapshot,
};
use ipnet::IpNet;
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// #1606: snapshot integrity errors from the policy parser.
#[derive(Debug, Clone)]
pub(crate) enum SnapshotIntegrityError {
    AddressBookIdZero,
    DuplicateAddressBookId(u32),
    UnknownAddressBookId { rule_id: String, book_id: u32 },
    /// #2124: a policy rule has at least one `application_terms` entry that
    /// failed to parse (unrepresentable protocol or malformed port). Dropping a
    /// term silently is a security fail-open: an all-dropped rule collapses to
    /// match-any (a permit over-matching), and a partially-dropped rule narrows
    /// the match (for a deny rule, narrowing lets blocked traffic fall through).
    /// The Go capability gate emits a reserved `__unsupported__` sentinel term
    /// for the failed-expansion case, and any corrupt snapshot with an
    /// unparseable term lands here too. Rejecting the whole snapshot (the
    /// preflight keeps the previous good state) is action-agnostic: it never
    /// turns a deny into a pass nor a permit into match-any.
    UnrepresentableApplicationProtocol { rule_id: String },
    /// #2212: a NAT64 rule snapshot carried an unparseable field — a prefix
    /// that is empty / malformed / not /96, or a pool address that is neither a
    /// bare IPv4 nor a `/32` host. (A pool that is genuinely UNCONFIGURED — no
    /// pool addresses on the wire — is the legitimate "no source-pool" state the
    /// Go side emits and is NOT an error; only an entry that fails to parse,
    /// which would silently narrow the pool, is rejected.) Silently dropping the
    /// rule (the pre-fix `continue`/`filter_map`) is a fail-OPEN regression in a
    /// retired-eBPF world where the userspace helper is the enforcement plane: a
    /// present prefix with an emptied pool makes `allocate_v4_source` return
    /// `None`, so NAT64 forward translation stops with no failure surfaced. The
    /// Go commit-time validation (`pkg/config/compiler_nat.go`, #2173) is the
    /// primary gate; this is the helper-boundary backstop. Rejecting the whole
    /// snapshot keeps the previous live NAT64 state rather than installing a
    /// silently narrower one.
    Nat64UnparseableRule { rule_name: String, field: String },
    /// #2240: an NPTv6 (RFC 6296) rule snapshot carried an unparseable or
    /// unsupported prefix — a match/internal prefix that is empty / malformed /
    /// not a /48 or /64, or an internal/external pair whose prefix lengths do
    /// not match. Silently `continue`-ing past the bad rule (the pre-fix parser)
    /// is a fail-OPEN regression: the Go dataplane compiler then calls
    /// `DeleteStaleNPTv6(written)` over only the VALID subset, so editing one
    /// previously-good rule into an invalid one TEARS DOWN the working
    /// translation entry with no replacement installed — traffic that
    /// previously translated silently stops, and HA peers converge on the same
    /// partial state with no hard failure. The Go commit-time validation
    /// (`pkg/config/compiler_nat.go`, #2240) is the primary gate; this is the
    /// helper-boundary backstop, consistent with the #2124/#2142/#2173/#2212
    /// fail-closed family. Rejecting the whole snapshot keeps the previous live
    /// NPTv6 state rather than installing a silently narrower one.
    Nptv6UnparseableRule { rule_name: String, field: String },
    /// #2241: two NPTv6 rules have overlapping prefixes in the same direction
    /// (e.g. a /48 and a nested /64). The dataplane resolves a match by FIRST
    /// hit in insertion order with no longest-prefix-match, so a broad prefix
    /// configured before a more-specific one shadows it and reordering the same
    /// rules changes the translation identity. Rejecting the snapshot keeps
    /// translation deterministic. The Go commit-time gate (#2241) is primary;
    /// this is the helper-boundary backstop.
    Nptv6OverlappingPrefix {
        first_rule: String,
        second_rule: String,
        direction: &'static str,
    },
    /// #2505: a firewall-filter term carried a NON-EMPTY `from protocol` list
    /// with at least one token that `ip_proto::proto_number` cannot resolve.
    /// The pre-fix compiler used a stale local `parse_protocol` (recognizing
    /// only tcp/udp/icmp/icmpv6/gre/ospf/ipip + bare numeric, no
    /// trim/lowercase) and `filter_map`-dropped anything else. A named
    /// protocol the Go commit gate accepts (esp/ah/sctp/vrrp/igmp/pim/egp +
    /// the junos-* aliases) — or a mixed-case / whitespace token the Go gate
    /// normalizes — was silently dropped. When ALL tokens drop, the term's
    /// protocol list collapses to empty, `protocol_match_enabled` becomes
    /// false, and the term matches EVERY protocol: a `from protocol esp; then
    /// discard` term that should drop only ESP instead discards ALL traffic
    /// (fail-WIDE). Rejecting the whole snapshot (the preflight keeps the
    /// previous good state) is the fail-closed backstop; the Go gate
    /// (`filterProtocolResolvable`, #2175/#2505) is the primary defense, so a
    /// gate-passing config never reaches this arm in normal operation — it
    /// guards against version/snapshot drift. An EMPTY input protocol list is
    /// the legitimate "no protocol constraint" case and is NOT an error.
    ///
    /// `family` (inet / inet6) is carried alongside the filter name because
    /// filter names can be REUSED across families — without it the fail-closed
    /// diagnostic could not tell the operator WHICH `family <f> filter <name>`
    /// failed.
    UnrepresentableFilterProtocol {
        family: String,
        filter: String,
        term: String,
        token: String,
    },
}

impl std::fmt::Display for SnapshotIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddressBookIdZero => write!(f, "address book has reserved id=0"),
            Self::DuplicateAddressBookId(id) => {
                write!(f, "duplicate address_books.id={}", id)
            }
            Self::UnknownAddressBookId { rule_id, book_id } => write!(
                f,
                "rule {:?} references unknown address book id={}",
                rule_id, book_id
            ),
            Self::UnrepresentableApplicationProtocol { rule_id } => write!(
                f,
                "rule {:?} has an unrepresentable application term (unparseable protocol or port) — refusing to fail open by dropping it",
                rule_id
            ),
            Self::Nat64UnparseableRule { rule_name, field } => write!(
                f,
                "nat64 rule {:?} has an unparseable {} — refusing to fail open by silently dropping the rule",
                rule_name, field
            ),
            Self::Nptv6UnparseableRule { rule_name, field } => write!(
                f,
                "nptv6 rule {:?} has an unparseable {} — refusing to fail open by silently dropping the rule (which would tear down working translations)",
                rule_name, field
            ),
            Self::Nptv6OverlappingPrefix {
                first_rule,
                second_rule,
                direction,
            } => write!(
                f,
                "nptv6 rules {:?} and {:?} have overlapping {} prefixes — refusing nondeterministic first-match resolution",
                first_rule, second_rule, direction
            ),
            Self::UnrepresentableFilterProtocol {
                family,
                filter,
                term,
                token,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} has an unresolvable protocol token {:?} — refusing to fail wide by dropping it (which would make the term match every protocol)",
                family, filter, term, token
            ),
        }
    }
}

impl std::error::Error for SnapshotIntegrityError {}

/// #1606: one row of the deduplicated address-book table.
#[derive(Clone, Debug, Default)]
pub(crate) struct BookEntry {
    pub(crate) v4: PrefixSetV4,
    pub(crate) v6: PrefixSetV6,
}

/// #922: zone-pair key packed as u32 (`from_id << 16 | to_id`).
/// Replaces the previous `(String, String)` key that allocated two
/// `String`s on every `evaluate_policy` call.
pub(crate) type ZonePairKey = u32;

#[inline]
pub(crate) fn zone_pair_key(from_id: u16, to_id: u16) -> ZonePairKey {
    ((from_id as u32) << 16) | (to_id as u32)
}

/// #919/#922: sentinel for `junos-global` policy rules. Reserved at
/// the top of the u16 space; `forwarding_build` rejects any zone
/// snapshot with id ≥ ZONE_ID_RESERVED_MIN.
pub(crate) const JUNOS_GLOBAL_ZONE_ID: u16 = u16::MAX;
pub(crate) const ZONE_ID_RESERVED_MIN: u16 = u16::MAX - 1;

use crate::ip_proto::{
    PROTO_AH, PROTO_EGP, PROTO_ESP, PROTO_GRE, PROTO_ICMP, PROTO_ICMPV6, PROTO_IGMP, PROTO_IPIP,
    PROTO_OSPF, PROTO_PIM, PROTO_SCTP, PROTO_TCP, PROTO_UDP, PROTO_VRRP,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicyAction {
    Permit,
    Deny,
    Reject,
}

impl Default for PolicyAction {
    fn default() -> Self {
        Self::Deny
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PolicyEvaluationResult {
    pub(crate) action: PolicyAction,
    pub(crate) policy_id: u32,
    /// #2508: the matched policy's per-policy RT_FLOW SYSLOG log
    /// selection, carried so the session-install path can stamp it onto
    /// the session metadata.
    pub(crate) log_session_init: bool,
    pub(crate) log_session_close: bool,
}

#[derive(Debug)]
pub(crate) struct PolicyRule {
    pub(crate) rule_id: String,
    pub(crate) policy_id: u32,
    pub(crate) from_zone: String,
    pub(crate) to_zone: String,
    pub(crate) scheduler_name: String,
    pub(crate) inactive: bool,
    /// #1606: literal CIDRs inlined in the rule (renamed from
    /// `source_v4`). For v3-shaped rules, built via
    /// `PrefixSetV4::from_v3_literals` (empty → MatchNone). For
    /// non-v3-shaped (legacy) rules, built via the legacy
    /// `from_prefixes` (empty → MatchAny).
    pub(crate) source_literal_v4: PrefixSetV4,
    pub(crate) source_literal_v6: PrefixSetV6,
    pub(crate) destination_literal_v4: PrefixSetV4,
    pub(crate) destination_literal_v6: PrefixSetV6,
    /// #1606: dense indices into `PolicyState::books`. Inline cap
    /// of 8 covers the realistic case (≤8 books per rule); spills
    /// to heap above that.
    pub(crate) source_book_idxs: SmallVec<[u32; 8]>,
    pub(crate) destination_book_idxs: SmallVec<[u32; 8]>,
    /// #1606: precomputed match-any short-circuit flags. True iff
    /// the union of literal + cited books matches every address.
    pub(crate) source_v4_match_any: bool,
    pub(crate) source_v6_match_any: bool,
    pub(crate) destination_v4_match_any: bool,
    pub(crate) destination_v6_match_any: bool,
    /// #2008 H2: invert the per-side address match. When set, the
    /// side matches iff the address is NOT in the configured set
    /// (Junos `source-address-excluded` / `destination-address-
    /// excluded`). The match-any short-circuit is intentionally NOT
    /// applied when excluded — see `try_match_rule`.
    pub(crate) source_excluded: bool,
    pub(crate) destination_excluded: bool,
    /// #2008 (fail-open hardening): per-side, per-family flag that is
    /// true iff the configured address set matches NOTHING for that
    /// family (literal is MatchNone, not match-any, and every cited
    /// book's family set is MatchNone). Used ONLY on the `*_excluded`
    /// path: inverting an empty excluded set would evaluate to
    /// match-ALL (a silent fail-open if a typo'd address was dropped),
    /// so when excluded AND empty the side is forced to NOT match
    /// (fail-closed). See `try_match_rule`.
    pub(crate) source_v4_empty: bool,
    pub(crate) source_v6_empty: bool,
    pub(crate) destination_v4_empty: bool,
    pub(crate) destination_v6_empty: bool,
    pub(crate) applications: Vec<ApplicationMatch>,
    /// Precompiled application matcher (protocol-indexed, exact-port sets).
    compiled_apps: CompiledApplications,
    pub(crate) action: PolicyAction,
    /// #2508: per-policy Junos `then log session-init`/`session-close`
    /// selection. Stamped onto session metadata at install so the
    /// per-policy RT_FLOW SYSLOG records gate on the admitting policy.
    pub(crate) log_session_init: bool,
    pub(crate) log_session_close: bool,
    pub(crate) hit_counter: Arc<PolicyRuleCounter>,
}

impl Default for PolicyRule {
    fn default() -> Self {
        Self {
            rule_id: String::new(),
            policy_id: 0,
            from_zone: String::new(),
            to_zone: String::new(),
            scheduler_name: String::new(),
            inactive: false,
            source_literal_v4: PrefixSetV4::default(),
            source_literal_v6: PrefixSetV6::default(),
            destination_literal_v4: PrefixSetV4::default(),
            destination_literal_v6: PrefixSetV6::default(),
            source_book_idxs: SmallVec::new(),
            destination_book_idxs: SmallVec::new(),
            source_v4_match_any: true,
            source_v6_match_any: true,
            destination_v4_match_any: true,
            destination_v6_match_any: true,
            source_excluded: false,
            destination_excluded: false,
            source_v4_empty: false,
            source_v6_empty: false,
            destination_v4_empty: false,
            destination_v6_empty: false,
            applications: Vec::new(),
            compiled_apps: CompiledApplications {
                match_any: true,
                by_protocol: FxHashMap::default(),
            },
            action: PolicyAction::Deny,
            log_session_init: false,
            log_session_close: false,
            hit_counter: Arc::new(PolicyRuleCounter::default()),
        }
    }
}

impl Clone for PolicyRule {
    fn clone(&self) -> Self {
        Self {
            rule_id: self.rule_id.clone(),
            policy_id: self.policy_id,
            from_zone: self.from_zone.clone(),
            to_zone: self.to_zone.clone(),
            scheduler_name: self.scheduler_name.clone(),
            inactive: self.inactive,
            source_literal_v4: self.source_literal_v4.clone(),
            source_literal_v6: self.source_literal_v6.clone(),
            destination_literal_v4: self.destination_literal_v4.clone(),
            destination_literal_v6: self.destination_literal_v6.clone(),
            source_book_idxs: self.source_book_idxs.clone(),
            destination_book_idxs: self.destination_book_idxs.clone(),
            source_v4_match_any: self.source_v4_match_any,
            source_v6_match_any: self.source_v6_match_any,
            destination_v4_match_any: self.destination_v4_match_any,
            destination_v6_match_any: self.destination_v6_match_any,
            source_excluded: self.source_excluded,
            destination_excluded: self.destination_excluded,
            source_v4_empty: self.source_v4_empty,
            source_v6_empty: self.source_v6_empty,
            destination_v4_empty: self.destination_v4_empty,
            destination_v6_empty: self.destination_v6_empty,
            applications: self.applications.clone(),
            compiled_apps: self.compiled_apps.clone(),
            action: self.action,
            log_session_init: self.log_session_init,
            log_session_close: self.log_session_close,
            hit_counter: self.hit_counter.clone(),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct PolicyRuleCounter {
    packets: AtomicU64,
    bytes: AtomicU64,
}

impl PolicyRuleCounter {
    fn add(&self, packet_len: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        if packet_len != 0 {
            self.bytes.fetch_add(packet_len, Ordering::Relaxed);
        }
    }

    fn reset(&self) {
        self.packets.store(0, Ordering::Relaxed);
        self.bytes.store(0, Ordering::Relaxed);
    }

    fn snapshot(&self, rule_id: &str) -> PolicyRuleCounterStatus {
        PolicyRuleCounterStatus {
            rule_id: rule_id.to_string(),
            packets: self.packets.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

type PolicyCounterRegistry = FxHashMap<String, Arc<PolicyRuleCounter>>;

#[derive(Clone, Debug, Default)]
pub(crate) struct PolicyCounterStore {
    counters: Arc<Mutex<PolicyCounterRegistry>>,
}

impl PolicyCounterStore {
    pub(crate) fn reconcile_rules(&self, rules: &[PolicyRuleSnapshot]) {
        let active_rule_ids: FxHashSet<String> = rules.iter().map(stable_policy_rule_id).collect();
        if let Ok(mut counters) = self.counters.lock() {
            counters.retain(|rule_id, _| active_rule_ids.contains(rule_id));
        }
    }

    pub(crate) fn clear(&self) {
        if let Ok(counters) = self.counters.lock() {
            for counter in counters.values() {
                counter.reset();
            }
        }
    }

    fn rule_hit_counter(&self, rule_id: &str) -> Arc<PolicyRuleCounter> {
        let mut counters = self.counters.lock().expect("policy counter store poisoned");
        if let Some(counter) = counters.get(rule_id) {
            return counter.clone();
        }

        let counter = Arc::new(PolicyRuleCounter::default());
        counters.insert(rule_id.to_string(), counter.clone());
        counter
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PortRange {
    pub(crate) low: u16,
    pub(crate) high: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApplicationMatch {
    pub(crate) protocol: u8,
    pub(crate) source_ports: Vec<PortRange>,
    pub(crate) destination_ports: Vec<PortRange>,
}

/// Pre-indexed application matcher: groups terms by protocol for O(1) lookup.
/// For exact single-port rules (the common case), stores them in a set
/// for O(1) hit instead of linear range scan.
#[derive(Clone, Debug)]
struct CompiledApplications {
    /// If true, matches any protocol/port (application "any").
    match_any: bool,
    /// Grouped by protocol for fast lookup. Key = protocol number.
    by_protocol: FxHashMap<u8, ProtoTerms>,
}

#[derive(Clone, Debug, Default)]
struct ProtoTerms {
    /// Exact destination port set (single-port terms compiled for O(1) lookup).
    exact_dst_ports: rustc_hash::FxHashSet<u16>,
    /// Port range terms that need linear scan (multi-port ranges).
    range_terms: Vec<(Vec<PortRange>, Vec<PortRange>)>, // (src_ranges, dst_ranges)
}

impl CompiledApplications {
    fn from_matches(apps: &[ApplicationMatch]) -> Self {
        if apps.is_empty() {
            return Self {
                match_any: true,
                by_protocol: FxHashMap::default(),
            };
        }
        let mut by_protocol: FxHashMap<u8, ProtoTerms> = FxHashMap::default();
        for app in apps {
            let entry = by_protocol.entry(app.protocol).or_default();
            // Optimise the common case: single exact dst port, no src port restriction.
            if app.source_ports.is_empty()
                && app.destination_ports.len() == 1
                && app.destination_ports[0].low == app.destination_ports[0].high
            {
                entry.exact_dst_ports.insert(app.destination_ports[0].low);
            } else {
                entry
                    .range_terms
                    .push((app.source_ports.clone(), app.destination_ports.clone()));
            }
        }
        Self {
            match_any: false,
            by_protocol,
        }
    }

    #[inline]
    fn matches(&self, protocol: u8, src_port: u16, dst_port: u16) -> bool {
        if self.match_any {
            return true;
        }
        let Some(terms) = self.by_protocol.get(&protocol) else {
            return false;
        };
        // Fast path: check exact dst port set first (O(1)).
        if terms.exact_dst_ports.contains(&dst_port) {
            return true;
        }
        // Slow path: check range terms.
        terms.range_terms.iter().any(|(src_ranges, dst_ranges)| {
            port_ranges_match(src_ranges, src_port) && port_ranges_match(dst_ranges, dst_port)
        })
    }
}

/// #2008 M5: the L3/L4 application-identification catalog. Resolves a session's
/// 5-tuple to the numeric `app_id` the dataplane stamps on the conntrack
/// session so `show security flow session` reports a real application name. The
/// `app_id` values are assigned on the Go side (`appid.BuildCatalog`) in
/// lock-step with `CompileResult.AppNames`, which the show path consumes — so a
/// stamped id round-trips to the correct name.
///
/// This is the read-the-id sibling of [`CompiledApplications`] (which only
/// answers a boolean "does this 5-tuple match the policy's app set?"). Lookup is
/// grouped by protocol, with exact single-destination-port entries in an O(1)
/// map and everything else (ranges, port-0/"protocol-only" entries) in a
/// per-protocol scan list. On overlap the first matching entry wins, which is
/// the lowest `app_id` because the Go builder emits entries in sorted-name /
/// ascending-id order; deterministic and stable across reloads.
#[derive(Clone, Debug, Default)]
pub(crate) struct AppCatalog {
    by_protocol: FxHashMap<u8, AppProtoEntries>,
}

#[derive(Clone, Debug, Default)]
struct AppProtoEntries {
    /// app_id keyed by exact destination port, for single-port entries with no
    /// source-port constraint (the common case).
    exact_dst: FxHashMap<u16, u16>,
    /// Entries needing a scan: a port range, a source-port constraint, or no
    /// destination-port constraint at all (port-0 protocol-only entries). Kept
    /// in catalog order so the first (lowest-id) match wins.
    scan: Vec<AppScanEntry>,
}

#[derive(Clone, Debug)]
struct AppScanEntry {
    app_id: u16,
    dst_low: u16,
    dst_high: u16,
    src_low: u16,
    src_high: u16,
}

impl AppCatalog {
    pub(crate) fn from_snapshot(entries: &[crate::AppCatalogEntry]) -> Self {
        let mut by_protocol: FxHashMap<u8, AppProtoEntries> = FxHashMap::default();
        for e in entries {
            // app_id 0 is the reserved "unknown" sentinel; never index it.
            if e.app_id == 0 {
                continue;
            }
            let bucket = by_protocol.entry(e.protocol).or_default();
            let single_dst = e.dst_port_low != 0
                && e.dst_port_low == e.dst_port_high
                && e.src_port_low == 0
                && e.src_port_high == 0;
            if single_dst {
                // First writer wins (lowest app_id) — matches the scan-list
                // "first match wins" rule for overlapping configs.
                bucket.exact_dst.entry(e.dst_port_low).or_insert(e.app_id);
            } else {
                bucket.scan.push(AppScanEntry {
                    app_id: e.app_id,
                    dst_low: e.dst_port_low,
                    dst_high: e.dst_port_high,
                    src_low: e.src_port_low,
                    src_high: e.src_port_high,
                });
            }
        }
        Self { by_protocol }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.by_protocol.is_empty()
    }

    /// Resolve the app_id for a session 5-tuple. The well-known service port is
    /// the destination on a forward session and the source on a reverse-keyed
    /// session, so both port slots are probed — both directions of one session
    /// then resolve to the same app_id (required because the publisher installs
    /// forward + reverse conntrack entries). Returns 0 (unknown) when nothing
    /// matches; 0 is the existing default the show path treats as "no AppID".
    #[inline]
    pub(crate) fn lookup(&self, protocol: u8, src_port: u16, dst_port: u16) -> u16 {
        let Some(bucket) = self.by_protocol.get(&protocol) else {
            return 0;
        };
        // Exact single-port match on either slot (service port = dst forward,
        // src reverse). Prefer the lower app_id when both slots hit distinct
        // apps, for determinism.
        let dst_hit = bucket.exact_dst.get(&dst_port).copied();
        let src_hit = bucket.exact_dst.get(&src_port).copied();
        let exact = match (dst_hit, src_hit) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        };
        // Scan entries (ranges / protocol-only). Catalog order = ascending id.
        let in_range = |low: u16, high: u16, p: u16| -> bool {
            // (0,0) means "no constraint".
            (low == 0 && high == 0) || (p >= low && p <= high)
        };
        let mut scan_hit: Option<u16> = None;
        for s in &bucket.scan {
            // Destination-port constraint may be satisfied by either slot, the
            // same forward/reverse symmetry the exact path uses.
            let dst_ok = in_range(s.dst_low, s.dst_high, dst_port)
                || in_range(s.dst_low, s.dst_high, src_port);
            let src_ok = in_range(s.src_low, s.src_high, src_port)
                || in_range(s.src_low, s.src_high, dst_port);
            if dst_ok && src_ok {
                scan_hit = Some(s.app_id);
                break;
            }
        }
        match (exact, scan_hit) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => 0,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyState {
    pub(crate) default_action: PolicyAction,
    /// All rules in original order (kept for hit-counter reporting).
    pub(crate) rules: Vec<PolicyRule>,
    /// Zone-pair index: maps `(from_id, to_id)` packed u32 →
    /// indices into `rules`. Avoids scanning unrelated zone-pairs.
    zone_pair_index: FxHashMap<ZonePairKey, Vec<usize>>,
    /// Indices of global rules (from_zone or to_zone = "junos-global").
    global_indices: Vec<usize>,
    /// #1606: deduplicated address-book table. Rules reference
    /// books by dense `u32` index (`PolicyRule::source_book_idxs`).
    pub(crate) books: Vec<BookEntry>,
    /// #1606: wire-ID → dense-index map used at parse time only.
    book_id_to_idx: FxHashMap<u32, u32>,
}

impl Default for PolicyState {
    fn default() -> Self {
        Self {
            default_action: PolicyAction::Deny,
            rules: Vec::new(),
            zone_pair_index: FxHashMap::default(),
            global_indices: Vec::new(),
            books: Vec::new(),
            book_id_to_idx: FxHashMap::default(),
        }
    }
}

impl PolicyState {
    pub(crate) fn counter_snapshots(&self) -> Vec<PolicyRuleCounterStatus> {
        self.rules
            .iter()
            .map(|rule| rule.hit_counter.snapshot(&rule.rule_id))
            .collect()
    }

    /// #1635: the set of concrete `(from_zone_id, to_zone_id)` pairs the
    /// configured policy distinguishes, used to build the cold-path
    /// histogram's direct slot map. Returns a deduplicated, sorted Vec
    /// for deterministic slot assignment. Pairs that reference the
    /// `junos-global` sentinel zone-id are excluded — global rules don't
    /// name a concrete zone-pair and would over-broaden the slot map.
    pub(crate) fn configured_zone_pairs(&self) -> Vec<(u16, u16)> {
        let mut pairs: Vec<(u16, u16)> = self
            .zone_pair_index
            .keys()
            .map(|&key| (((key >> 16) & 0xffff) as u16, (key & 0xffff) as u16))
            .filter(|&(from, to)| {
                from < ZONE_ID_RESERVED_MIN && to < ZONE_ID_RESERVED_MIN
            })
            .collect();
        pairs.sort_unstable();
        pairs.dedup();
        pairs
    }
}

pub(crate) fn parse_policy_state(
    default_policy: &str,
    rules: &[PolicyRuleSnapshot],
    zone_name_to_id: &FxHashMap<String, u16>,
) -> PolicyState {
    let counter_store = PolicyCounterStore::default();
    parse_policy_state_with_counters(default_policy, rules, zone_name_to_id, &[], &counter_store)
        .expect("legacy parse_policy_state called with no books — cannot raise integrity errors")
}

/// #1606: fallible policy-state parser. Returns
/// `SnapshotIntegrityError` for duplicate/zero/unknown book IDs.
/// Callers MUST run this as a preflight before any side-effecting
/// snapshot mutation (see `server/handlers/snapshot.rs::apply`).
pub(crate) fn parse_policy_state_with_counters(
    default_policy: &str,
    rules: &[PolicyRuleSnapshot],
    zone_name_to_id: &FxHashMap<String, u16>,
    address_books: &[AddressBookSnapshot],
    counter_store: &PolicyCounterStore,
) -> Result<PolicyState, SnapshotIntegrityError> {
    let mut state = PolicyState {
        default_action: parse_action(default_policy),
        rules: Vec::with_capacity(rules.len()),
        zone_pair_index: FxHashMap::default(),
        global_indices: Vec::new(),
        books: Vec::with_capacity(address_books.len()),
        book_id_to_idx: FxHashMap::default(),
    };

    // #1606: build the dense book table first. Hard-fail on
    // integrity errors (id=0, duplicate ids).
    for snap in address_books {
        if snap.id == 0 {
            return Err(SnapshotIntegrityError::AddressBookIdZero);
        }
        if state.book_id_to_idx.contains_key(&snap.id) {
            return Err(SnapshotIntegrityError::DuplicateAddressBookId(snap.id));
        }
        // Parse v4 / v6 literals using the v3 factory: empty
        // collapses to MatchNone (NOT MatchAny). A v4-only book
        // gets entry.v6 = MatchNone, etc.
        let mut v4: Vec<PrefixV4> = Vec::with_capacity(snap.prefixes_v4.len());
        let mut v6: Vec<PrefixV6> = Vec::with_capacity(snap.prefixes_v6.len());
        for s in &snap.prefixes_v4 {
            parse_literal_cidr_into(s, &mut v4, &mut v6);
        }
        for s in &snap.prefixes_v6 {
            parse_literal_cidr_into(s, &mut v4, &mut v6);
        }
        let entry = BookEntry {
            v4: PrefixSetV4::from_v3_literals(v4),
            v6: PrefixSetV6::from_v3_literals(v6),
        };
        let dense_idx = state.books.len() as u32;
        state.books.push(entry);
        state.book_id_to_idx.insert(snap.id, dense_idx);
    }

    for snap in rules {
        let source_is_v3_shaped =
            !snap.source_book_ids.is_empty() || !snap.source_literals.is_empty();
        let destination_is_v3_shaped = !snap.destination_book_ids.is_empty()
            || !snap.destination_literals.is_empty();

        // Build literal prefix sets per side using the appropriate
        // factory.
        let (source_literal_v4, source_literal_v6) = if source_is_v3_shaped {
            parse_v3_literal_set(&snap.source_literals)
        } else {
            parse_legacy_address_set(&snap.source_addresses)
        };
        let (destination_literal_v4, destination_literal_v6) = if destination_is_v3_shaped {
            parse_v3_literal_set(&snap.destination_literals)
        } else {
            parse_legacy_address_set(&snap.destination_addresses)
        };

        let rule_id = stable_policy_rule_id(snap);

        // Resolve book IDs to dense indices. Sort + dedup + hard
        // fail on unknown.
        let source_book_idxs =
            resolve_book_idxs(&state.book_id_to_idx, &snap.source_book_ids, &rule_id)?;
        let destination_book_idxs =
            resolve_book_idxs(&state.book_id_to_idx, &snap.destination_book_ids, &rule_id)?;

        // Precompute match-any flags. True iff EITHER the literal
        // set OR any cited book's v4/v6 is MatchAny.
        let source_v4_match_any = source_literal_v4.is_match_any()
            || source_book_idxs
                .iter()
                .any(|&i| state.books[i as usize].v4.is_match_any());
        let source_v6_match_any = source_literal_v6.is_match_any()
            || source_book_idxs
                .iter()
                .any(|&i| state.books[i as usize].v6.is_match_any());
        let destination_v4_match_any = destination_literal_v4.is_match_any()
            || destination_book_idxs
                .iter()
                .any(|&i| state.books[i as usize].v4.is_match_any());
        let destination_v6_match_any = destination_literal_v6.is_match_any()
            || destination_book_idxs
                .iter()
                .any(|&i| state.books[i as usize].v6.is_match_any());

        // #2008 fail-open hardening: a side's family set is "empty"
        // (matches nothing) iff it is not match-any, its literal is
        // MatchNone, and every cited book's family set is MatchNone.
        // This is the structural complement used to fail-CLOSED an
        // empty *_excluded set (see try_match_rule) instead of
        // inverting it into match-all.
        let source_v4_empty = !source_v4_match_any
            && source_literal_v4.is_match_none()
            && source_book_idxs
                .iter()
                .all(|&i| state.books[i as usize].v4.is_match_none());
        let source_v6_empty = !source_v6_match_any
            && source_literal_v6.is_match_none()
            && source_book_idxs
                .iter()
                .all(|&i| state.books[i as usize].v6.is_match_none());
        let destination_v4_empty = !destination_v4_match_any
            && destination_literal_v4.is_match_none()
            && destination_book_idxs
                .iter()
                .all(|&i| state.books[i as usize].v4.is_match_none());
        let destination_v6_empty = !destination_v6_match_any
            && destination_literal_v6.is_match_none()
            && destination_book_idxs
                .iter()
                .all(|&i| state.books[i as usize].v6.is_match_none());

        // Pre-declare applications + compiled_apps as locals so the
        // struct literal can name every field explicitly — this
        // drops the `..PolicyRule::default()` tail entirely and
        // forces a compile error on any future field addition until
        // the constructor is updated, eliminating the silent-zero-
        // default hazard (originally raised by AGY r2 D on #1632).
        // #2124: parse the application terms and FAIL CLOSED if a rule cites
        // application terms and ANY of them is unrepresentable (unparseable
        // protocol or port). Dropping a term silently is the security fail-open
        // this fixes: an all-dropped rule would collapse to match-any (a permit
        // over-matching), and a PARTIALLY-dropped rule would NARROW the match —
        // for a deny rule that narrowing lets traffic the deny meant to block
        // fall through to a later permit / default-permit. Rejecting on
        // `dropped_any` (not just all-dropped) is action-agnostic for permit
        // and deny alike. The Go capability gate rejects any unrepresentable
        // term before publish (and emits a `__unsupported__` sentinel for the
        // failed-expansion case), so a normal Go snapshot never trips this; it
        // is the backstop for that sentinel and for any corrupt/non-Go
        // snapshot. Genuinely-empty terms (`application any`) drop nothing, so
        // `dropped_any == false` and the rule stays match-any.
        let parsed = parse_applications(&snap.application_terms);
        if parsed.dropped_any {
            return Err(SnapshotIntegrityError::UnrepresentableApplicationProtocol {
                rule_id: rule_id.clone(),
            });
        }
        let applications = parsed.matches;
        let compiled_apps = CompiledApplications::from_matches(&applications);

        let rule = PolicyRule {
            rule_id: rule_id.clone(),
            policy_id: snap.policy_id,
            from_zone: snap.from_zone.clone(),
            to_zone: snap.to_zone.clone(),
            scheduler_name: snap.scheduler_name.clone(),
            inactive: snap.inactive,
            source_literal_v4,
            source_literal_v6,
            destination_literal_v4,
            destination_literal_v6,
            source_book_idxs,
            destination_book_idxs,
            source_v4_match_any,
            source_v6_match_any,
            destination_v4_match_any,
            destination_v6_match_any,
            source_excluded: snap.source_address_excluded,
            destination_excluded: snap.destination_address_excluded,
            source_v4_empty,
            source_v6_empty,
            destination_v4_empty,
            destination_v6_empty,
            applications,
            compiled_apps,
            action: parse_action(&snap.action),
            // #2508: carry the per-policy SYSLOG log selection.
            log_session_init: snap.log_session_init,
            log_session_close: snap.log_session_close,
            hit_counter: counter_store.rule_hit_counter(&rule_id),
        };
        let idx = state.rules.len();
        let is_global = rule.from_zone == "junos-global" || rule.to_zone == "junos-global";
        state.rules.push(rule);

        if is_global {
            state.global_indices.push(idx);
        } else {
            match (
                zone_name_to_id.get(&snap.from_zone).copied(),
                zone_name_to_id.get(&snap.to_zone).copied(),
            ) {
                (Some(from_id), Some(to_id)) => {
                    let key = zone_pair_key(from_id, to_id);
                    state.zone_pair_index.entry(key).or_default().push(idx);
                }
                _ => {
                    eprintln!(
                        "xpf-userspace-dp: policy rule references unknown zone(s): from={:?} to={:?} (rule kept, but not indexed)",
                        snap.from_zone, snap.to_zone
                    );
                }
            }
        }
    }
    Ok(state)
}

/// #2008 H11: parse the legacy (non-v3-shaped) `source_addresses` /
/// `destination_addresses` field with family-safe wildcard handling.
///
/// The legacy convention is "empty input = no address constraint =
/// MatchAny" (preserved via `PrefixSetV4::from_prefixes`). But a
/// FAMILY-SCOPED wildcard (`any-ipv4` / `any-ipv6`) is a constraint:
/// it must match all of ITS family and NONE of the opposite family.
/// The naive `from_prefixes(v4), from_prefixes(v6)` pair leaks
/// cross-family, because once `any-ipv4` populates v4 the v6 Vec is
/// still empty and `from_prefixes(empty)` returns MatchAny — so the
/// rule would still match v6 (and the reverse for `any-ipv6`).
///
/// Fix: track per-family wildcards exactly like `parse_v3_literal_set`.
/// If a family-scoped wildcard is present anywhere in the token list,
/// the OPPOSITE family that received no prefixes is MatchNone (the
/// family is explicitly excluded), NOT MatchAny. Only when NO
/// family-scoped wildcard appears does the legacy "empty = MatchAny"
/// convention apply (via `from_prefixes`), preserving back-compat for
/// the unconstrained / `any` / all-malformed cases.
fn parse_legacy_address_set(addresses: &[String]) -> (PrefixSetV4, PrefixSetV6) {
    let mut any_v4 = false;
    let mut any_v6 = false;
    let mut v4: Vec<PrefixV4> = Vec::new();
    let mut v6: Vec<PrefixV6> = Vec::new();
    for tok in addresses {
        match tok.as_str() {
            // Bare `any` is the unconstrained both-families wildcard;
            // it leaves no per-family scoping and falls through to the
            // legacy empty→MatchAny convention below for both families.
            "any" | "" => {}
            "any-ipv4" => any_v4 = true,
            "any-ipv6" => any_v6 = true,
            s => parse_address(s, &mut v4, &mut v6),
        }
    }
    let any_family_scoped = any_v4 || any_v6;
    let v4_set = if any_v4 {
        PrefixSetV4::MatchAny
    } else if any_family_scoped {
        // A same-family-only wildcard excludes this family. An empty
        // v4 here means "v4 was deliberately not named" → MatchNone,
        // NOT the legacy empty→MatchAny.
        PrefixSetV4::from_v3_literals(v4)
    } else {
        // No family-scoped wildcard anywhere → legacy convention:
        // empty = no constraint = MatchAny.
        PrefixSetV4::from_prefixes(v4)
    };
    let v6_set = if any_v6 {
        PrefixSetV6::MatchAny
    } else if any_family_scoped {
        PrefixSetV6::from_v3_literals(v6)
    } else {
        PrefixSetV6::from_prefixes(v6)
    };
    (v4_set, v6_set)
}

/// #1606: parse the v3 `source_literals` / `destination_literals`
/// field. "any" token forces MatchAny on BOTH families (Codex r5
/// F-r5-1 fix); empty input or no-any → MatchNone (via
/// `from_v3_literals`).
fn parse_v3_literal_set(literals: &[String]) -> (PrefixSetV4, PrefixSetV6) {
    let mut any_v4 = false;
    let mut any_v6 = false;
    let mut v4: Vec<PrefixV4> = Vec::new();
    let mut v6: Vec<PrefixV6> = Vec::new();
    for tok in literals {
        match tok.as_str() {
            "any" => {
                any_v4 = true;
                any_v6 = true;
            }
            // `any4`/`any6` are the internal short forms; `any-ipv4`/
            // `any-ipv6` are the Junos config keywords. The Go
            // compiler normalizes the latter to `0.0.0.0/0`/`::/0`,
            // but accept them here too so any path that bypasses that
            // normalization still matches (#2008 H11).
            "any4" | "any-ipv4" => any_v4 = true,
            "any6" | "any-ipv6" => any_v6 = true,
            "" => {}
            s => parse_literal_cidr_into(s, &mut v4, &mut v6),
        }
    }
    let v4_set = if any_v4 {
        PrefixSetV4::MatchAny
    } else {
        PrefixSetV4::from_v3_literals(v4)
    };
    let v6_set = if any_v6 {
        PrefixSetV6::MatchAny
    } else {
        PrefixSetV6::from_v3_literals(v6)
    };
    (v4_set, v6_set)
}

fn parse_literal_cidr_into(
    prefix: &str,
    out_v4: &mut Vec<PrefixV4>,
    out_v6: &mut Vec<PrefixV6>,
) {
    if prefix.is_empty() || prefix == "any" {
        return;
    }
    // #2008 H11: the Junos family-scoped wildcards expand to the
    // concrete all-addresses prefix of their family (v4-only / v6-only).
    if prefix == "any-ipv4" {
        out_v4.push(PrefixV4::from_net(
            ipnet::Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("v4 /0"),
        ));
        return;
    }
    if prefix == "any-ipv6" {
        out_v6.push(PrefixV6::from_net(
            ipnet::Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).expect("v6 /0"),
        ));
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

fn resolve_book_idxs(
    book_id_to_idx: &FxHashMap<u32, u32>,
    ids: &[u32],
    rule_id: &str,
) -> Result<SmallVec<[u32; 8]>, SnapshotIntegrityError> {
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out: SmallVec<[u32; 8]> = SmallVec::new();
    for id in sorted {
        let Some(&idx) = book_id_to_idx.get(&id) else {
            return Err(SnapshotIntegrityError::UnknownAddressBookId {
                rule_id: rule_id.to_string(),
                book_id: id,
            });
        };
        out.push(idx);
    }
    Ok(out)
}

pub(crate) fn evaluate_policy(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
) -> PolicyAction {
    evaluate_policy_result_with_len(
        state, from_id, to_id, src_ip, dst_ip, protocol, src_port, dst_port, 0,
    )
    .action
}

pub(crate) fn evaluate_policy_with_len(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_len: u64,
) -> PolicyAction {
    evaluate_policy_result_with_len(
        state, from_id, to_id, src_ip, dst_ip, protocol, src_port, dst_port, packet_len,
    )
    .action
}

pub(crate) fn evaluate_policy_result_with_len(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_len: u64,
) -> PolicyEvaluationResult {
    let key = zone_pair_key(from_id, to_id);
    if let Some(indices) = state.zone_pair_index.get(&key) {
        for &idx in indices {
            if let Some(result) = try_match_rule(
                &state.rules[idx],
                state,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                packet_len,
            ) {
                return result;
            }
        }
    }
    for &idx in &state.global_indices {
        if let Some(result) = try_match_rule(
            &state.rules[idx],
            state,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            packet_len,
        ) {
            return result;
        }
    }
    PolicyEvaluationResult {
        action: state.default_action,
        policy_id: 0,
        // #2508: the implicit default policy has no `then log` selection.
        log_session_init: false,
        log_session_close: false,
    }
}

/// Try to match a single policy rule against packet fields.
/// #1606: walks the literal set + every cited book's dense entry
/// via `state.books[idx]`. Match-any flags short-circuit the
/// common "any" case.
#[inline]
fn try_match_rule(
    rule: &PolicyRule,
    state: &PolicyState,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_len: u64,
) -> Option<PolicyEvaluationResult> {
    if rule.inactive {
        return None;
    }
    if !rule.compiled_apps.matches(protocol, src_port, dst_port) {
        return None;
    }
    // #2008 H2: when a side is `*-excluded`, the rule matches every
    // address EXCEPT those in the configured set, so the match-any
    // short-circuit must NOT apply (it would always-match and the
    // inversion would always-FAIL the side). Compute the raw
    // "address is in the set" predicate, then XOR with the excluded
    // flag: matched != excluded.
    //
    // #2008 fail-open hardening: an `*-excluded` side whose configured
    // set is EMPTY for this family (e.g. a typo'd address that was
    // dropped during parse) would invert into match-ALL — a silent
    // security bypass (a rule meant to exclude one address matches
    // everything). Fail CLOSED: an empty excluded set never matches.
    let (src_ok, dst_ok) = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let src_ok = if rule.source_excluded {
                !rule.source_v4_empty
                    && !(rule.source_literal_v4.contains(src)
                        || rule
                            .source_book_idxs
                            .iter()
                            .any(|&i| state.books[i as usize].v4.contains(src)))
            } else {
                rule.source_v4_match_any
                    || rule.source_literal_v4.contains(src)
                    || rule
                        .source_book_idxs
                        .iter()
                        .any(|&i| state.books[i as usize].v4.contains(src))
            };
            let dst_ok = if rule.destination_excluded {
                !rule.destination_v4_empty
                    && !(rule.destination_literal_v4.contains(dst)
                        || rule
                            .destination_book_idxs
                            .iter()
                            .any(|&i| state.books[i as usize].v4.contains(dst)))
            } else {
                rule.destination_v4_match_any
                    || rule.destination_literal_v4.contains(dst)
                    || rule
                        .destination_book_idxs
                        .iter()
                        .any(|&i| state.books[i as usize].v4.contains(dst))
            };
            (src_ok, dst_ok)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let src_ok = if rule.source_excluded {
                !rule.source_v6_empty
                    && !(rule.source_literal_v6.contains(src)
                        || rule
                            .source_book_idxs
                            .iter()
                            .any(|&i| state.books[i as usize].v6.contains(src)))
            } else {
                rule.source_v6_match_any
                    || rule.source_literal_v6.contains(src)
                    || rule
                        .source_book_idxs
                        .iter()
                        .any(|&i| state.books[i as usize].v6.contains(src))
            };
            let dst_ok = if rule.destination_excluded {
                !rule.destination_v6_empty
                    && !(rule.destination_literal_v6.contains(dst)
                        || rule
                            .destination_book_idxs
                            .iter()
                            .any(|&i| state.books[i as usize].v6.contains(dst)))
            } else {
                rule.destination_v6_match_any
                    || rule.destination_literal_v6.contains(dst)
                    || rule
                        .destination_book_idxs
                        .iter()
                        .any(|&i| state.books[i as usize].v6.contains(dst))
            };
            (src_ok, dst_ok)
        }
        _ => return None,
    };
    if src_ok && dst_ok {
        rule.hit_counter.add(packet_len);
        Some(PolicyEvaluationResult {
            action: rule.action,
            policy_id: rule.policy_id,
            // #2508: surface the matched rule's per-policy SYSLOG log
            // selection so the install path can stamp the session.
            log_session_init: rule.log_session_init,
            log_session_close: rule.log_session_close,
        })
    } else {
        None
    }
}

fn stable_policy_rule_id(snap: &PolicyRuleSnapshot) -> String {
    if !snap.rule_id.is_empty() {
        return snap.rule_id.clone();
    }
    format!("{}->{}/{}", snap.from_zone, snap.to_zone, snap.name)
}

fn parse_action(action: &str) -> PolicyAction {
    match action {
        "permit" => PolicyAction::Permit,
        "reject" => PolicyAction::Reject,
        _ => PolicyAction::Deny,
    }
}

fn parse_address(prefix: &str, out_v4: &mut Vec<PrefixV4>, out_v6: &mut Vec<PrefixV6>) {
    if prefix.is_empty() || prefix == "any" {
        return;
    }
    // #2008 H11: family-scoped wildcards (see parse_literal_cidr_into).
    if prefix == "any-ipv4" {
        out_v4.push(PrefixV4::from_net(
            ipnet::Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("v4 /0"),
        ));
        return;
    }
    if prefix == "any-ipv6" {
        out_v6.push(PrefixV6::from_net(
            ipnet::Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).expect("v6 /0"),
        ));
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

/// #2124: outcome of parsing a rule's application terms. `dropped_any` records
/// whether at least one configured term failed to parse (unparseable protocol
/// or port). The caller fails the rule closed via `SnapshotIntegrityError`
/// whenever `dropped_any` is set, rather than letting a dropped term collapse
/// the rule to match-any (all-dropped) or silently narrow it (partial-drop).
/// A genuinely-empty input (`application any` / no match application) drops
/// nothing, so `dropped_any == false` and the rule stays match-any.
struct ParsedApplications {
    matches: Vec<ApplicationMatch>,
    dropped_any: bool,
}

fn parse_applications(terms: &[PolicyApplicationSnapshot]) -> ParsedApplications {
    let mut out = Vec::with_capacity(terms.len());
    let mut dropped_any = false;
    for term in terms {
        let Some(protocol) = parse_protocol(&term.protocol) else {
            dropped_any = true;
            continue;
        };
        let Some(source_ports) = parse_port_spec(&term.source_port) else {
            dropped_any = true;
            continue;
        };
        let Some(destination_ports) = parse_port_spec(&term.destination_port) else {
            dropped_any = true;
            continue;
        };
        out.push(ApplicationMatch {
            protocol,
            source_ports,
            destination_ports,
        });
    }
    ParsedApplications {
        matches: out,
        dropped_any,
    }
}

/// Resolve a policy application term's protocol token to its IANA number.
///
/// #2124: extended to map the named IANA protocols Junos / the Go
/// `validateProtocol` accept (`sctp`/`esp`/`ah`/`vrrp`/`igmp`/`pim`/`egp`) to
/// their numbers, so a policy that matches only those protocols is honored
/// instead of silently failing OPEN to match-any. Returning `None` for an
/// unparseable token records a dropped term in `parse_applications`; a rule with
/// ANY dropped term is then rejected as a `SnapshotIntegrityError` (fail closed)
/// rather than collapsing to match-any (all-dropped) or silently narrowing
/// (partial-drop) — see `parse_applications` / `parse_policy_state_with_counters`.
///
/// The numeric `_ => parse::<u8>()` arm is preserved, so a config that names a
/// protocol numerically (e.g. `protocol 132`) still parses. Numbers MUST match
/// `crate::ip_proto` / the centralized Go `appid.ProtocolNumber` table.
fn parse_protocol(protocol: &str) -> Option<u8> {
    match protocol {
        "" => None,
        "tcp" => Some(PROTO_TCP),
        "udp" => Some(PROTO_UDP),
        "icmp" => Some(PROTO_ICMP),
        "icmp6" | "icmpv6" => Some(PROTO_ICMPV6),
        "gre" => Some(PROTO_GRE),
        "89" | "ospf" => Some(PROTO_OSPF),
        "4" | "ipip" => Some(PROTO_IPIP),
        "esp" => Some(PROTO_ESP),
        "ah" => Some(PROTO_AH),
        "sctp" => Some(PROTO_SCTP),
        "vrrp" => Some(PROTO_VRRP),
        "igmp" => Some(PROTO_IGMP),
        "pim" => Some(PROTO_PIM),
        "egp" => Some(PROTO_EGP),
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

fn port_ranges_match(ranges: &[PortRange], port: u16) -> bool {
    ranges.is_empty()
        || ranges
            .iter()
            .any(|range| port >= range.low && port <= range.high)
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
