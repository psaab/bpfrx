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

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;
const PROTO_GRE: u8 = 47;
const PROTO_OSPF: u8 = 89;
const PROTO_IPIP: u8 = 4;

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
    pub(crate) applications: Vec<ApplicationMatch>,
    /// Precompiled application matcher (protocol-indexed, exact-port sets).
    compiled_apps: CompiledApplications,
    pub(crate) action: PolicyAction,
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
            applications: Vec::new(),
            compiled_apps: CompiledApplications {
                match_any: true,
                by_protocol: FxHashMap::default(),
            },
            action: PolicyAction::Deny,
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
            applications: self.applications.clone(),
            compiled_apps: self.compiled_apps.clone(),
            action: self.action,
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
            let mut v4: Vec<PrefixV4> = Vec::new();
            let mut v6: Vec<PrefixV6> = Vec::new();
            for prefix in &snap.source_addresses {
                parse_address(prefix, &mut v4, &mut v6);
            }
            (
                PrefixSetV4::from_prefixes(v4),
                PrefixSetV6::from_prefixes(v6),
            )
        };
        let (destination_literal_v4, destination_literal_v6) = if destination_is_v3_shaped {
            parse_v3_literal_set(&snap.destination_literals)
        } else {
            let mut v4: Vec<PrefixV4> = Vec::new();
            let mut v6: Vec<PrefixV6> = Vec::new();
            for prefix in &snap.destination_addresses {
                parse_address(prefix, &mut v4, &mut v6);
            }
            (
                PrefixSetV4::from_prefixes(v4),
                PrefixSetV6::from_prefixes(v6),
            )
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

        let mut rule = PolicyRule {
            rule_id: rule_id.clone(),
            policy_id: snap.policy_id,
            from_zone: snap.from_zone.clone(),
            to_zone: snap.to_zone.clone(),
            scheduler_name: snap.scheduler_name.clone(),
            inactive: snap.inactive,
            action: parse_action(&snap.action),
            hit_counter: counter_store.rule_hit_counter(&rule_id),
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
            ..PolicyRule::default()
        };
        rule.applications = parse_applications(&snap.application_terms);
        rule.compiled_apps = CompiledApplications::from_matches(&rule.applications);
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
            "any4" => any_v4 = true,
            "any6" => any_v6 = true,
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
    let (src_ok, dst_ok) = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let s = rule.source_v4_match_any
                || rule.source_literal_v4.contains(src)
                || rule
                    .source_book_idxs
                    .iter()
                    .any(|&i| state.books[i as usize].v4.contains(src));
            let d = rule.destination_v4_match_any
                || rule.destination_literal_v4.contains(dst)
                || rule
                    .destination_book_idxs
                    .iter()
                    .any(|&i| state.books[i as usize].v4.contains(dst));
            (s, d)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let s = rule.source_v6_match_any
                || rule.source_literal_v6.contains(src)
                || rule
                    .source_book_idxs
                    .iter()
                    .any(|&i| state.books[i as usize].v6.contains(src));
            let d = rule.destination_v6_match_any
                || rule.destination_literal_v6.contains(dst)
                || rule
                    .destination_book_idxs
                    .iter()
                    .any(|&i| state.books[i as usize].v6.contains(dst));
            (s, d)
        }
        _ => return None,
    };
    if src_ok && dst_ok {
        rule.hit_counter.add(packet_len);
        Some(PolicyEvaluationResult {
            action: rule.action,
            policy_id: rule.policy_id,
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

fn parse_applications(terms: &[PolicyApplicationSnapshot]) -> Vec<ApplicationMatch> {
    let mut out = Vec::with_capacity(terms.len());
    for term in terms {
        let Some(protocol) = parse_protocol(&term.protocol) else {
            continue;
        };
        let Some(source_ports) = parse_port_spec(&term.source_port) else {
            continue;
        };
        let Some(destination_ports) = parse_port_spec(&term.destination_port) else {
            continue;
        };
        out.push(ApplicationMatch {
            protocol,
            source_ports,
            destination_ports,
        });
    }
    out
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

fn port_ranges_match(ranges: &[PortRange], port: u16) -> bool {
    ranges.is_empty()
        || ranges
            .iter()
            .any(|range| port >= range.low && port <= range.high)
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
