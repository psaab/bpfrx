use crate::prefix::{PrefixV4, PrefixV6};
use crate::prefix_set::{PrefixSetV4, PrefixSetV6};
use crate::{
    AddressBookSnapshot, PolicyApplicationSnapshot, PolicyRuleCounterStatus, PolicyRuleSnapshot,
    ZoneSnapshot,
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
    /// #3712: a policy rule's application term carried a semantically-invalid
    /// ICMP field combination that the pre-fix compiled matcher silently turned
    /// into a WRONG-behaving term:
    ///
    ///   - `icmp-code` set with NO `icmp-type` (H04): `from_matches` steers a
    ///     term into `icmp_constraints` ONLY when `icmp_type.is_some()`, so a
    ///     code-without-type term fell through to a `range_terms` entry with
    ///     EMPTY port ranges — a protocol-only MATCH-ALL for that ICMP protocol.
    ///     The `icmp_code` was silently ignored, so an intended narrow rule
    ///     (`type any, code 3`) widened to match every ICMP message. For a
    ///     permit under default-deny that is a fail-OPEN (permits more than
    ///     authored).
    ///   - `icmp-type` / `icmp-code` set on a NON-ICMP protocol (H05):
    ///     `from_matches` pushes the term into `icmp_constraints` under the
    ///     non-ICMP protocol (e.g. TCP) because `icmp_type.is_some()`, and the
    ///     exact-dst-port / range classification is skipped, so any real
    ///     destination-port constraint is LOST. `matches` then skips the
    ///     `icmp_constraints` arm for a non-ICMP packet (`packet_icmp` is None),
    ///     so the term NEVER matches — a `deny tcp/80 icmp-type 8` never applies
    ///     and default-permit admits the traffic (a security fail-OPEN).
    ///
    /// The Go STRICT commit gate (`validateApplicationSpecsStrict`, #3348) hard-
    /// rejects BOTH combos at commit, but the tolerant load / peer-sync path
    /// (`lenientApplicationSpecs`) downgrades them to warnings, so a corrupt /
    /// hand-built / older-peer-synced snapshot can still carry them to this
    /// helper — the only enforcement plane in the retired-eBPF world. Rejecting
    /// the WHOLE snapshot (the preflight keeps the previous good state; a fresh
    /// boot keeps the default-deny `PolicyState`) is action-agnostic, consistent
    /// with the #2124/#3261/#3367/#3711 fail-closed family. `application` is the
    /// term's name; `reason` describes which invalid combo was found.
    InvalidApplicationIcmpFields {
        rule_id: String,
        application: String,
        reason: &'static str,
    },
    /// #3261: a policy rule carries the reserved `__unsupported_address__`
    /// sentinel in its source/destination address fields. The Go capability
    /// gate emits it when a policy names an address it cannot represent — an
    /// undefined address-book name, or a defined book whose value is a
    /// non-literal (Junos dns-name / wildcard-address / range-address). This is
    /// the ADDRESS analog of `UnrepresentableApplicationProtocol`: without the
    /// reject, the raw address strings reach the matcher, which SILENTLY drops
    /// an unparseable literal (the non-reporting matcher parser) or empties a
    /// non-literal book, collapsing the side to `MatchNone`. A
    /// `deny <unrepresentable-address>` rule would then match nothing and fall
    /// through to a later permit / default-permit — a deny fail-OPEN. Rejecting
    /// the whole snapshot (the preflight keeps the previous good state; a fresh
    /// boot keeps the default-deny `PolicyState`) is action-agnostic.
    UnrepresentableAddress { rule_id: String },
    /// #3367: a policy rule's LEGACY (`source_addresses` / `destination_addresses`)
    /// address field carried a token that is non-empty, not the bare `any`, not a
    /// family-scoped wildcard (`any-ipv4` / `any-ipv6`), and does NOT parse as an
    /// IP/CIDR literal. The pre-fix `parse_address` `Err(_)` arm silently DROPPED
    /// such a token (pushed nothing, returned). For a fully-malformed token list on
    /// the common "empty -> MatchAny" legacy path (no family-scoped wildcard
    /// present) the side then collapsed to an UNCONSTRAINED MatchAny — broadening a
    /// `deny` rule to match every source/destination (fail-OPEN). The v3-shaped
    /// literal path is fixed by the sibling `UnrepresentableV3Address` reject
    /// (#3711); this is the analogous backstop for the legacy field, which
    /// carries raw literals with no sentinel. A normal Go snapshot only ever
    /// emits parseable literals / `any` / family wildcards, so this guards
    /// against a corrupt / hand-built / version-drifted snapshot. Rejecting the
    /// WHOLE snapshot (the preflight keeps the previous good state) is
    /// action-agnostic.
    UnrepresentableLegacyAddress { rule_id: String, address: String },
    /// #3711: a policy rule's V3-shaped (`source_literals` /
    /// `destination_literals`) address field carried a token that is non-empty,
    /// not `any` / `any4` / `any6` / `any-ipv4` / `any-ipv6`, not the
    /// `__unsupported_address__` sentinel, and does NOT parse as an IP/CIDR
    /// literal. The pre-fix `parse_v3_literal_set` used a non-reporting
    /// family-agnostic parser, whose `Err(_)` arm silently DROPPED such a
    /// token. Because a v3-shaped side uses the `from_v3_literals` factory
    /// (empty -> MatchNone, NOT MatchAny), an all-dropped side collapsed to
    /// MatchNone: a `deny <malformed-literal>` rule then matched nothing and
    /// fell through to a later permit / default-permit — a deny fail-OPEN. This
    /// is the v3 sibling of `UnrepresentableLegacyAddress` (#3367): the sentinel
    /// preflight (`UnrepresentableAddress`, #3261) only catches the exact
    /// `__unsupported_address__` token the Go gate emits, NOT an arbitrary
    /// malformed literal on a corrupt / hand-built / mixed-version HA peer-sync
    /// snapshot. Rejecting the WHOLE snapshot (the preflight keeps the previous
    /// good state) is action-agnostic.
    UnrepresentableV3Address { rule_id: String, address: String },
    /// #3711 (M02): an address-book row carried a token in its `prefixes_v4` /
    /// `prefixes_v6` array that is not a parseable IP/CIDR literal OF THE
    /// DECLARED FAMILY. The pre-fix book builder parsed BOTH family arrays with
    /// one family-agnostic non-reporting parser, so (a) a malformed token
    /// was silently dropped (an all-dropped family collapsed to MatchNone —
    /// same deny fall-through fail-OPEN as the rule-literal path), and (b) a
    /// wrong-family token (an IPv6 CIDR placed in `prefixes_v4` by a corrupt /
    /// mixed-version producer) was accepted into the opposite family's set,
    /// contradicting the wire contract. The reporting builder now rejects the
    /// whole snapshot naming the book id/name, the offending token, and the
    /// declared family. The Go side only ever emits family-separated parseable
    /// CIDRs, so this guards against a corrupt / hand-built / version-drifted
    /// snapshot. `family` is the STATIC declared array (`"v4"` / `"v6"`), not
    /// the token's actual family.
    UnrepresentableAddressBookPrefix {
        book_id: u32,
        book_name: String,
        family: &'static str,
        address: String,
    },
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
    /// #3367: a firewall-filter term carried the `tcp_flags_unparseable` wire
    /// marker — the Go control plane could not parse the term's tcp-flags
    /// expression (disjunction, negated groups, unknown flags) into
    /// required/forbidden masks. The pre-fix Go builder logged the error and left
    /// both masks nil, and the matcher (`engine/matching.rs`) treats absent masks
    /// as "no tcp-flags constraint" — silently WIDENING the term to match every
    /// TCP segment. For a `then discard`/`reject` term that should drop only a
    /// specific flag combination (e.g. SYN floods) that is a fail-WIDE security
    /// bug. The Go commit gate (`compileFirewall` /
    /// `config::ParseTCPFlagsExpression`) is the primary defense — a committed
    /// config never sets the marker — so this is the helper-boundary backstop for
    /// a corrupt / hand-built / version-drifted snapshot, consistent with the
    /// #2505 `UnrepresentableFilterProtocol` fail-closed pattern. Rejecting the
    /// whole snapshot (the reconcile preflight keeps the previous good filter
    /// state) is action-agnostic. `family` (inet / inet6) is carried because
    /// filter names can be reused across families.
    UnrepresentableFilterTCPFlags {
        family: String,
        filter: String,
        term: String,
    },
    /// #3406: a firewall-filter term carried the `icmp_type_unrepresentable` /
    /// `icmp_code_unrepresentable` wire marker — the Go control plane could not
    /// resolve a `from icmp-type` / `from icmp-code` token to a byte in 0..255 (a
    /// symbolic name with no mapping, or a numeric value out of range). The pre-fix
    /// Go builder dropped the unresolved token and emitted only the resolved bytes;
    /// when EVERY token was unresolvable the `icmp_types` / `icmp_codes` vector was
    /// empty, which the matcher reads as "no ICMP constraint" — silently WIDENING
    /// the term to match every ICMP(v6) packet (fail-OPEN for a `then
    /// discard`/`reject` term). The Go commit gate (`validateFilterMatchValuesStrict`)
    /// is the primary defense — a committed config never sets the marker — so this
    /// is the helper-boundary backstop for a corrupt / hand-built / version-drifted
    /// snapshot, consistent with the #2505/#3367 fail-closed family. Rejecting the
    /// whole snapshot (the reconcile preflight keeps the previous good filter state)
    /// is action-agnostic. `dimension` is "icmp-type" or "icmp-code". `family`
    /// (inet / inet6) is carried because filter names can be reused across families.
    UnrepresentableFilterICMP {
        family: String,
        filter: String,
        term: String,
        dimension: &'static str,
    },
    /// #3406: a firewall-filter term carried the `dscp_match_unrepresentable` wire
    /// marker — the Go control plane could not resolve a `from dscp` / `from
    /// traffic-class` MATCH token to a known code-point name or an integer 0..63.
    /// The pre-fix Go builder dropped the bad token from `dscp_values`; when EVERY
    /// token was unresolvable the vector was empty, which the matcher reads as "no
    /// DSCP constraint" — silently WIDENING the term to match all DSCPs (fail-OPEN,
    /// the documented #3309 gap). The Go commit gate (`validateFilterDSCPStrict`) is
    /// the primary defense; this is the helper-boundary backstop, consistent with
    /// the #2505/#3367 fail-closed family. An unrepresentable `then dscp` REWRITE is
    /// CoS-only (no match/action widening) and is surfaced with a Go builder warning
    /// rather than this snapshot reject. `family` (inet / inet6) is carried because
    /// filter names can be reused across families.
    UnrepresentableFilterDSCP {
        family: String,
        filter: String,
        term: String,
    },
    /// #3406: a firewall-filter term's `flex_match` carried a byte `length` outside
    /// the representable 1..=4 range (the `value` / `mask` wire fields are u32). The
    /// pre-fix Go builder CAPPED an oversized width to 4 and still emitted the term,
    /// so only the truncated 4-byte window was compared and the match BROADENED
    /// (fail-OPEN). The Go commit gate (`validateFilterFlexMatchStrict`) bounds
    /// bit-length to 1..32 → ceil(bits/8) ≤ 4, so a committed config never produces
    /// an out-of-range length; this is the helper-boundary backstop for a corrupt /
    /// hand-built / version-drifted snapshot, consistent with the #2505/#3367
    /// fail-closed family. A length of 0 with a present `flex_match` is likewise
    /// rejected (the Go builder defaults an unset bit-length to a 4-byte window, so
    /// 0 only arrives via drift). Rejecting the whole snapshot keeps the previous
    /// good filter state. `family` (inet / inet6) is carried because filter names
    /// can be reused across families.
    UnrepresentableFilterFlexMatch {
        family: String,
        filter: String,
        term: String,
        length: u8,
    },
    /// #3723: a firewall-filter term combined a resolved `protocol` (or the inet6
    /// `next-header`) with an L4 predicate the matcher can NEVER satisfy for that
    /// protocol — a source/destination-port with a non-port-bearing protocol
    /// (only TCP/UDP carry extracted ports, ip_proto.rs has_l4_ports), a tcp-flags
    /// match with a non-TCP protocol, or an icmp-type/icmp-code match with a
    /// non-ICMP(v6) protocol. The matcher (engine/matching.rs) keys ports on the
    /// extracted L4 port (0 for a non-port protocol), gates tcp-flags on
    /// protocol==TCP, and gates icmp-type/code on ICMP/ICMPv6, so such a term is a
    /// NEVER-MATCH. Because a filter falls through to the implicit ACCEPT on
    /// no-match (the #3427 no-catchall class), a `then discard`/`reject` term over
    /// such a pair is silently dead and the traffic is admitted — a fail-OPEN.
    /// The Go commit gate (`validateFilterCrossFieldStrict`, #3723) is the primary
    /// defense — a freshly committed config can never carry such a term — so this
    /// is the helper-boundary backstop for a corrupt / hand-built / version-drifted
    /// or leniently-loaded snapshot, consistent with the #2505/#3367/#3406
    /// fail-closed family. Rejecting the whole snapshot (the reconcile preflight
    /// keeps the previous good filter state) is action-agnostic. `predicate` names
    /// the offending L4 dimension ("port" / "tcp-flags" / "icmp-type/code") and
    /// `protocol` is the incompatible IANA number. `family` (inet / inet6) is
    /// carried because filter names can be reused across families.
    UnsatisfiableFilterCrossField {
        family: String,
        filter: String,
        term: String,
        predicate: &'static str,
        protocol: u8,
    },
    /// #3296: an interface (or lo0) snapshot named a NON-EMPTY firewall filter
    /// (`filter_input_v4/v6` / `filter_output_v4/v6`, or the lo0 host-bound
    /// filter) that is not present in the compiled filter table. The pre-fix
    /// compiler left the per-interface fast-path map (and, for output hooks,
    /// the `needs_tx_eval` set) with NO entry for the missing key, so the hot
    /// path returned the default `FilterResult` — Accept. The security hook
    /// was silently disarmed, indistinguishable from "no filter configured": a
    /// fail-OPEN on a typo'd firewall reference (e.g. `filter input WAN-BLOCK`
    /// where the defined filter is `WAN_BLOCK`). Rejecting the whole snapshot
    /// (the preflight keeps the previous good filter state on a warm reconcile)
    /// is the fail-closed backstop, consistent with the
    /// #2124/#2391/#2505 fail-closed family. The Go STRICT commit gate
    /// (`validateFirewallFilterReferencesStrict`, #3296) is the primary
    /// defense — a freshly committed config can never carry a dangling
    /// reference — so a gate-passing config never reaches this arm in normal
    /// operation; it guards against version/snapshot drift on the lenient /
    /// peer-sync path. An EMPTY reference (no filter on the hook) is the
    /// legitimate "unfiltered" case and is NOT an error.
    ///
    /// `family` (inet / inet6) is carried alongside the filter name because
    /// filter names can be REUSED across families.
    MissingFilterRef {
        interface: String,
        family: String,
        direction: String,
        filter: String,
    },
    /// #2391: an interface snapshot named a NON-EMPTY security zone that is not
    /// present in the zone table (`zone_name_to_id`). The pre-fix code resolved
    /// the missing name to `zone_id == 0` (`unwrap_or(0)`), silently collapsing
    /// the interface to the canonical "unknown" zone. With zone 0 the interface
    /// matches no zone-pair policy and its traffic falls through to the default
    /// action — a silent fail-open under a permit default (or a blackhole under a
    /// deny default). This happens when a zone id overflows the u8 event-stream
    /// wire field and the forwarding builder drops it (`populate_zones`), or on a
    /// hostile/version-drifted snapshot where an interface references a zone the
    /// snapshot never defines. The Go commit-time cap (`validateZoneCountStrict`,
    /// #2391) is the PRIMARY gate that prevents the overflow ever reaching the
    /// wire; this is the helper-boundary backstop, consistent with the
    /// #2124/#2142/#2173/#2212/#2505 fail-closed family. An interface with NO
    /// zone (empty string) is the legitimate "unzoned" case and is NOT an error.
    InterfaceUnknownZone { interface: String, zone: String },
    /// #2410: an interface snapshot's `vlan_id` is outside the 0..=65535 range
    /// representable on the 802.1Q wire (and in the `EgressInterface.vlan_id` /
    /// `ingress_logical_ifindex` key u16). The pre-fix code narrowed it with an
    /// unchecked `iface.vlan_id.max(0) as u16`, so a value > 65535 WRAPPED to a
    /// different VLAN id — silently building a DIFFERENT L2 broadcast domain than
    /// the operator configured (a value of 65537 becomes VLAN 1, a value of
    /// 65536 becomes VLAN 0/untagged). That is a security-relevant
    /// misconfiguration: the interface's ingress demux and egress tag would key
    /// off the wrong VLAN. The Go commit-time validation is the primary gate;
    /// this is the helper-boundary backstop, consistent with the
    /// #2173/#2212/#2240/#2391 fail-closed family. Rejecting the whole snapshot
    /// keeps the previous live forwarding state rather than steering traffic onto
    /// a wrapped VLAN.
    InterfaceVlanOutOfRange { interface: String, vlan_id: i32 },
    /// #2410: a tunnel-endpoint snapshot's `ttl` is outside the 0..=255 range
    /// representable in the outer IP TTL/hop-limit octet (`TunnelEndpoint.ttl`,
    /// a u8). The pre-fix code narrowed it with `endpoint.ttl.max(0) as u8`, so
    /// 256 wrapped to 0 (a packet that can never leave the first hop) and 300
    /// wrapped to 44. Silently installing a wrapped TTL produces a tunnel that
    /// either blackholes (TTL 0) or has a surprising reach. Fail closed instead.
    TunnelTtlOutOfRange { tunnel_id: u16, ttl: i32 },
    /// #2410: a CoS forwarding-class snapshot's `queue` is outside the 0..=255
    /// range representable in the runtime `queue_id` (a u8). The pre-fix code
    /// SILENTLY DROPPED the class via a `filter_map` range check
    /// (`(0..=u8::MAX as i32).contains(&class.queue)`), so a class with a
    /// wrapped/over-range queue disappeared from `class_to_queue` — every
    /// classifier / scheduler-map entry referencing it then silently lost its
    /// queue mapping (see #2409). Fail the snapshot closed rather than installing
    /// a partial CoS table. An EMPTY class name is the legitimate "unnamed /
    /// placeholder" case and is NOT an error (skipped as before).
    CosQueueIdOutOfRange { forwarding_class: String, queue: i32 },
    /// #2706: an interface snapshot's `mtu` is NEGATIVE. The pre-fix code
    /// narrowed it with `iface.mtu.max(0) as usize`, so a negative value
    /// silently collapsed to 0 — and the egress MTU guard
    /// (`forwarded_egress_mtu_decision`) treats mtu 0 as "unknown; forward"
    /// (fail-open), so a negative MTU silently DISABLED PTB / drop enforcement
    /// on that interface. A healthy Go control plane never emits a negative MTU
    /// (netlink MTUs are non-negative; 0 is the legitimate "unknown" sentinel
    /// preserved as permissive). Fail the snapshot closed on a negative value
    /// rather than installing an interface with MTU enforcement off, consistent
    /// with the #2410/#2696 fail-closed family.
    InterfaceMtuInvalid { interface: String, mtu: i32 },
    /// #2409: an interface address snapshot's `address` string did not parse as
    /// an `IpNet` CIDR. The pre-fix code `continue`d past it, so the connected
    /// route / local-address / interface-NAT material for that address silently
    /// disappeared while the apply still SUCCEEDED — a connected route the
    /// operator configured would just never install, with no failure surfaced.
    /// In a retired-eBPF world where this helper is the only forwarding plane,
    /// that is silent connectivity loss. Fail the snapshot closed (the preflight
    /// keeps the previous good state) instead of silently dropping the address.
    InterfaceAddressUnparseable { interface: String, address: String },
    /// #2409: a CoS scheduler-map entry references a `forwarding_class` that is
    /// not in the `class_to_queue` table — either a typo, a version-drifted
    /// snapshot, or a class dropped for an out-of-range queue id (#2410). The
    /// pre-fix code `continue`d past it, so the scheduler-map installed only a
    /// SUBSET of its queues with no apply failure — a partially-installed
    /// scheduler is very hard to troubleshoot (some classes shape, some do not).
    /// Fail the snapshot closed instead of partially installing the scheduler.
    SchedulerMapUnknownClass {
        scheduler_map: String,
        forwarding_class: String,
    },
    /// #2447: a CoS DSCP classifier entry carried a code-point outside the
    /// 6-bit DSCP domain (0..=63). The pre-fix builder masked the index with
    /// `dscp & 0x3f`, so a value of 110 silently installed the classifier for
    /// DSCP 46 — a DIFFERENT traffic class — with no apply failure. The Go
    /// commit-time gate (`expandCoSCodePointToken`, #2447) is the primary
    /// defense; this is the helper-boundary backstop against version/snapshot
    /// drift, consistent with the #2410/#2696/#2713 fail-closed family. Fail
    /// the snapshot closed (the preflight keeps the previous live CoS state)
    /// rather than building a classifier for a different class than configured.
    CosDscpCodePointOutOfRange { classifier: String, dscp: u8 },
    /// #2447: a CoS IEEE 802.1p classifier entry carried a code-point outside
    /// the 3-bit PCP domain (0..=7). The pre-fix builder clamped the index with
    /// `pcp.min(7)`, so a value of 9 silently installed the classifier for PCP
    /// 7 — a DIFFERENT traffic class — with no apply failure. Same fail-closed
    /// rationale as `CosDscpCodePointOutOfRange`.
    CosIeee8021CodePointOutOfRange { classifier: String, pcp: u8 },
    /// #2458: a CoS scheduler snapshot carried a NON-EMPTY
    /// `equal_flow_target_policy` wire string that is not one of the known
    /// values (`slowest` / `mean` / `ideal-share`). The pre-fix
    /// `EqualFlowTargetPolicy::parse` mapped any unknown string to the
    /// `Slowest` default via a catch-all match arm — identically to the
    /// empty (legacy-default) string — so a typo or a mixed-version snapshot
    /// silently changed queue fairness instead of failing. The Go
    /// commit-time gate (`compiler_validate_strict.go`, #1746/#2458) is the
    /// primary defense; this is the helper-boundary backstop, consistent
    /// with the #2447 CoS fail-closed family. An EMPTY value is the
    /// legitimate legacy/unset default and is NOT an error.
    CosUnknownEqualFlowTargetPolicy {
        forwarding_class: String,
        target_policy: String,
    },
    /// #3365: a policy rule's `action` field, or the snapshot `default_policy`,
    /// carried a NON-EMPTY string that is not one of `permit` / `reject` /
    /// `deny`. The pre-fix `parse_action` mapped any unrecognized string to
    /// `PolicyAction::Deny` via a catch-all match arm — so a future `reject-*`
    /// variant, a mixed-version snapshot token, or a corrupt/truncated action
    /// silently LOST its intended permit/reject/RST semantics and collapsed to a
    /// plain Deny with no failure surfaced. That is fail-closed for a `permit`
    /// typo but fail-OPEN for a `reject`: an unrecognized reject downgrades to
    /// Deny, dropping the RST/ICMP-unreachable behavior the operator configured,
    /// and it masks wire-contract drift. The Go producer (`policyActionString`
    /// in `pkg/dataplane/userspace/policies.go`) only ever renders the three
    /// known tokens, so a normal Go snapshot never trips this; it is the
    /// helper-boundary backstop for version drift / a corrupt snapshot,
    /// consistent with the #2124/#3261 fail-closed family. Rejecting the WHOLE
    /// snapshot (the preflight keeps the previous good state; a fresh boot keeps
    /// the default-deny `PolicyState`) is action-agnostic. An EMPTY
    /// `default_policy` is the legitimate `omitempty`/unspecified wire state
    /// (decodes to the default Deny) and is NOT an error; an empty per-rule
    /// action IS rejected (every configured rule has a concrete action).
    UnknownPolicyAction { context: String, action: String },
    /// #3402: a policy rule names a from/to zone — or a scoped-global (#3148)
    /// `match from-zone`/`match to-zone` context — that does not resolve in the
    /// snapshot's zone table (`zone_name_to_id`). The pre-fix code handled this
    /// as a stderr-only DROP: the zone-pair / single-wildcard build skipped
    /// indexing the rule ("rule kept, but not indexed"), and the scoped-global
    /// build produced a `GlobalZoneScope::Unresolved` that matched nothing. In
    /// BOTH cases the rule never participated in evaluation and the traffic it
    /// was meant to govern fell through to `default-policy` with no failure
    /// surfaced to the control plane. Under `default-policy permit-all` a stale
    /// `deny` silently becomes an ALLOW (fail-OPEN); under `deny-all` a stale
    /// `permit` silently BLACKHOLES. The Go commit gate
    /// (`validatePolicyZoneReferencesStrict`, #2401) hard-rejects an undefined
    /// zone reference for both shapes, so a clean commit never reaches this arm;
    /// this is the helper-boundary backstop for the lenient / upgrade-state /
    /// HA-replay / corrupt-snapshot path (`lenientPolicyZoneRefs`), consistent
    /// with the #3261/#3365/#3367 fail-closed family. Rejecting the WHOLE
    /// snapshot (the preflight keeps the previous good state; a fresh boot keeps
    /// the default-deny `PolicyState`) is action-agnostic: it never turns a deny
    /// into a pass nor a permit into match-any. The empty token and the special
    /// `any` / `junos-host` zone names always resolve (see
    /// `resolve_policy_zone_id` / `build_global_zone_scope`) and so never trip
    /// this.
    UnresolvableZoneReference { rule_id: String, zone: String },
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
            Self::InvalidApplicationIcmpFields {
                rule_id,
                application,
                reason,
            } => write!(
                f,
                "rule {:?} application term {:?} has an invalid ICMP field combination: {} — refusing to compile a wrong-behaving term (icmp-code without icmp-type matches ALL ICMP; icmp-type/code on a non-ICMP protocol never matches, so a deny falls through to default-permit)",
                rule_id, application, reason
            ),
            Self::UnrepresentableAddress { rule_id } => write!(
                f,
                "rule {:?} has an unrepresentable address (undefined address book, or a non-literal dns-name/wildcard/range value) — refusing to fail open by collapsing the side to match-none (which lets a deny fall through)",
                rule_id
            ),
            Self::UnrepresentableLegacyAddress { rule_id, address } => write!(
                f,
                "rule {:?} has an unparseable legacy address literal {:?} (not an IP/CIDR, `any`, or family wildcard) — refusing to fail open by dropping it (which on the empty->match-any legacy path widens a deny to match everything)",
                rule_id, address
            ),
            Self::UnrepresentableV3Address { rule_id, address } => write!(
                f,
                "rule {:?} has an unparseable v3 address literal {:?} (not an IP/CIDR, `any`, or family wildcard, and not the unrepresentable-address sentinel) — refusing to fail open by dropping it (which collapses the side to match-none and lets a deny fall through to a later permit / default-permit)",
                rule_id, address
            ),
            Self::UnrepresentableAddressBookPrefix {
                book_id,
                book_name,
                family,
                address,
            } => write!(
                f,
                "address book id={} ({:?}) has prefixes_{} entry {:?} that is not a parseable {} IP/CIDR literal (malformed, or a wrong-family token in the {} array) — refusing to fail open by dropping it (which collapses a book-backed deny to match-none) or by silently routing it to the other family",
                book_id, book_name, family, address, family, family
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
            Self::UnrepresentableFilterTCPFlags {
                family,
                filter,
                term,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} has an unparseable tcp-flags expression — refusing to fail wide by dropping it (which would make the term match every TCP segment)",
                family, filter, term
            ),
            Self::UnrepresentableFilterICMP {
                family,
                filter,
                term,
                dimension,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} has an unresolvable {} token — refusing to fail wide by dropping it (which would make the term match every ICMP packet)",
                family, filter, term, dimension
            ),
            Self::UnrepresentableFilterDSCP {
                family,
                filter,
                term,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} has an unresolvable from-dscp/traffic-class match token — refusing to fail wide by dropping it (which would make the term match every DSCP)",
                family, filter, term
            ),
            Self::UnrepresentableFilterFlexMatch {
                family,
                filter,
                term,
                length,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} has a flexible-match-range byte length {} outside the representable 1..=4 range — refusing to truncate it to a 4-byte window (which would broaden the match)",
                family, filter, term, length
            ),
            Self::UnsatisfiableFilterCrossField {
                family,
                filter,
                term,
                predicate,
                protocol,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} combines a {} match with protocol {} that cannot carry it — refusing to compile a never-match term (a then discard/reject over it fails open, admitting the traffic via the implicit accept)",
                family, filter, term, predicate, protocol
            ),
            Self::MissingFilterRef {
                interface,
                family,
                direction,
                filter,
            } => write!(
                f,
                "interface {:?} family {:?} filter {} references undefined filter {:?} — refusing to fail open by leaving the hook unarmed (which would forward unfiltered, equivalent to no filter)",
                interface, family, direction, filter
            ),
            Self::InterfaceUnknownZone { interface, zone } => write!(
                f,
                "interface {:?} references zone {:?} that is not in the zone table — refusing to fail open by collapsing it to the \"unknown\" zone 0 (which would bypass every zone-pair policy)",
                interface, zone
            ),
            Self::InterfaceVlanOutOfRange { interface, vlan_id } => write!(
                f,
                "interface {:?} has vlan_id {} outside the 0..=65535 802.1Q range — refusing to narrow it with an unchecked cast that would wrap to a different VLAN (a different L2 domain)",
                interface, vlan_id
            ),
            Self::TunnelTtlOutOfRange { tunnel_id, ttl } => write!(
                f,
                "tunnel endpoint id={} has ttl {} outside the 0..=255 range — refusing to narrow it with an unchecked cast that would wrap (256→0 blackholes the tunnel)",
                tunnel_id, ttl
            ),
            Self::CosQueueIdOutOfRange {
                forwarding_class,
                queue,
            } => write!(
                f,
                "cos forwarding-class {:?} has queue {} outside the 0..=255 range — refusing to silently drop the class (which would unmap every classifier/scheduler entry referencing it)",
                forwarding_class, queue
            ),
            Self::InterfaceMtuInvalid { interface, mtu } => write!(
                f,
                "interface {:?} has a negative mtu {} — refusing to narrow it with an unchecked .max(0) cast that would collapse it to 0 (which the egress MTU guard treats as \"unknown; forward\", silently disabling PTB/drop enforcement)",
                interface, mtu
            ),
            Self::InterfaceAddressUnparseable { interface, address } => write!(
                f,
                "interface {:?} address {:?} is not a parseable IpNet — refusing to silently drop it (which would lose the connected route / local-address material with no apply failure)",
                interface, address
            ),
            Self::SchedulerMapUnknownClass {
                scheduler_map,
                forwarding_class,
            } => write!(
                f,
                "cos scheduler-map {:?} references forwarding-class {:?} that is not in the class-to-queue table — refusing to partially install the scheduler (some queues silently missing)",
                scheduler_map, forwarding_class
            ),
            Self::CosDscpCodePointOutOfRange { classifier, dscp } => write!(
                f,
                "cos dscp classifier {:?} has code-point {} outside the 0..=63 DSCP range — refusing to mask it with & 0x3f (which would install the classifier for a different traffic class)",
                classifier, dscp
            ),
            Self::CosIeee8021CodePointOutOfRange { classifier, pcp } => write!(
                f,
                "cos ieee-802.1 classifier {:?} has code-point {} outside the 0..=7 PCP range — refusing to clamp it with .min(7) (which would install the classifier for a different traffic class)",
                classifier, pcp
            ),
            Self::CosUnknownEqualFlowTargetPolicy {
                forwarding_class,
                target_policy,
            } => write!(
                f,
                "cos forwarding-class {:?} has equal-flow-target-policy {:?} that is not one of slowest | mean | ideal-share — refusing to silently map it to the \"slowest\" default (which would change queue fairness with no failure surfaced)",
                forwarding_class, target_policy
            ),
            Self::UnknownPolicyAction { context, action } => write!(
                f,
                "{} has action {:?} that is not one of permit | reject | deny — refusing to silently map it to Deny (which fail-OPENs an unrecognized reject by dropping its RST/ICMP-unreachable semantics and masks wire-contract drift)",
                context, action
            ),
            Self::UnresolvableZoneReference { rule_id, zone } => write!(
                f,
                "rule {:?} references undefined zone {:?} — refusing to fail open by dropping the unindexed rule (it would fall through to default-policy: a stale deny becomes an allow under permit-all, a stale permit blackholes under deny-all)",
                rule_id, zone
            ),
        }
    }
}

impl std::error::Error for SnapshotIntegrityError {}

/// #3261: reserved address literal the Go capability gate emits for a policy
/// whose source/destination address it cannot represent. Detected in the
/// integrity preflight to reject the whole snapshot (fail closed). Must stay in
/// lock-step with the Go `unsupportedAddressSentinel`. It is deliberately not a
/// parseable CIDR/IP, so even an older helper that lacks the preflight arm
/// drops it to `MatchNone` and never matches real traffic.
pub(crate) const UNREPRESENTABLE_ADDRESS_SENTINEL: &str = "__unsupported_address__";

/// #3261: true iff any of the rule's address fields (v3 literals or the legacy
/// expanded lists, source or destination) carries the unrepresentable-address
/// sentinel. The Go side stamps it onto BOTH shapes for the failed side, so a
/// scan of all four lists catches it regardless of which shape the matcher uses.
fn rule_has_unrepresentable_address_sentinel(snap: &PolicyRuleSnapshot) -> bool {
    let hit = |list: &[String]| list.iter().any(|a| a == UNREPRESENTABLE_ADDRESS_SENTINEL);
    hit(&snap.source_literals)
        || hit(&snap.destination_literals)
        || hit(&snap.source_addresses)
        || hit(&snap.destination_addresses)
}

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

/// #3019: synthetic reserved zone id for the Junos `junos-host` self-traffic
/// zone (`to-zone junos-host` / `from-zone junos-host` security policies). It
/// lives at the BOTTOM of the reserved range (`ZONE_ID_RESERVED_MIN`), so a
/// configured zone can never collide: `forwarding_build::populate_zones`
/// already skips any snapshot zone whose id is `>= ZONE_ID_RESERVED_MIN`, and
/// `configured_zone_pairs` excludes both sentinels from the cold-path
/// histogram. The id is never put on the wire (it sits in the reserved range a
/// configured zone can never occupy); it exists only as the in-runtime key so a `junos-host`
/// rule is INDEXED in `zone_pair_index` and reachable by the LocalDelivery
/// policy gate. The Go control plane emits the `junos-host` zone NAME string
/// in the rule snapshot; `parse_policy_state_with_counters` resolves that name
/// to this id (Go↔Rust agreement is on the reserved name, not a wire id).
pub(crate) const JUNOS_HOST_ZONE_ID: u16 = u16::MAX - 1;

/// #3402: build the policy-zone resolution map (`zone name → zone id`) from a
/// snapshot's zone list, applying the SAME #919/#922 validity rules
/// `forwarding_build::populate_zones` uses for the live forwarding table: an id
/// of 0, an empty name, or an id in the reserved range (`>= ZONE_ID_RESERVED_MIN`)
/// is not addressable and is skipped (silently — `populate_zones` emits the
/// per-reason diagnostics on the real build path). #3075 widened the
/// event-stream zone field to u16, so the former >u8::MAX skip is retired.
///
/// The apply-time snapshot-integrity preflight MUST resolve a rule's zones
/// against the INCOMING snapshot's own zones, NOT the live forwarding table.
/// On a fresh boot — and on a new-zone commit or an HA standby's first config
/// sync — the live table is empty/stale, and `populate_zones(snapshot)` only
/// runs LATER inside `build_forwarding_state`. Validating a concrete-zone policy
/// against the empty live table would flag it as `UnresolvableZoneReference`
/// (#3402) and reject the WHOLE snapshot, bricking essentially every real boot
/// config. This helper is the single source of truth for the map: the three
/// preflight sites (snapshot apply, reconcile, runtime refresh) call it on the
/// incoming snapshot, and `populate_zones` reuses it for `state.zone_name_to_id`
/// so the preflight and the real build resolve the identical set. A policy
/// referencing a zone genuinely ABSENT from `snapshot.zones` still fails closed
/// (the real #3402 fix).
pub(crate) fn zone_name_to_id_from_snapshot(zones: &[ZoneSnapshot]) -> FxHashMap<String, u16> {
    let mut map = FxHashMap::default();
    for zone in zones {
        if zone.id == 0 || zone.name.is_empty() {
            continue;
        }
        // Reserved-range ids are unaddressable (mirrors populate_zones; the
        // build path logs the diagnostic). #3075 widened the event-stream zone
        // field to u16, so the former >u8::MAX skip is retired and a stable
        // name-hash id in [1, ZONE_ID_RESERVED_MIN-1] is addressable.
        if zone.id >= ZONE_ID_RESERVED_MIN {
            continue;
        }
        map.insert(zone.name.clone(), zone.id);
    }
    map
}

/// #3019: reserved Junos self-traffic zone name, recognized in policy
/// from/to zone resolution and mapped to [`JUNOS_HOST_ZONE_ID`].
pub(crate) const JUNOS_HOST_ZONE_NAME: &str = "junos-host";

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

/// #3057: reserved sentinel policy ID for the IMPLICIT default-policy
/// (deny-all / permit-all) result returned when a flow matches no configured
/// zone-pair or `junos-global` policy.
///
/// A real configured policy ID is `policy_set_id * MAX_RULES_PER_POLICY +
/// rule_index` (see `pkg/dataplane/userspace/policies.go`), where `rule_index`
/// is capped strictly below MAX_RULES_PER_POLICY (256) and `policy_set_id` is
/// the number of configured zone-pair policy blocks (plus one for the global
/// set) — far below 16,777,216 in any real config. Reaching `u32::MAX`
/// (=0xFFFF_FFFF) as a real ID would require ~16.7M zone-pair policy sets, which
/// is impossible, so this sentinel can never collide with a configured policy's
/// ID. Emitting it (instead of the old `0`, which aliased the FIRST configured
/// policy) lets the Go log/display planes render the implicit default as
/// `default-policy` rather than mis-attributing the deny to the first rule.
///
/// The value travels in the existing `policy_id` u32 field on the wire — NO
/// wire-layout/size change. The Go side mirrors it as
/// `dataplane.DefaultPolicySentinelID`; the two MUST stay byte-identical (pinned
/// by a cross-language contract test in pkg/dataplane/userspace).
pub(crate) const DEFAULT_POLICY_SENTINEL_ID: u32 = u32::MAX;

/// #3363: stable rule identity under which the IMPLICIT default-policy hit
/// counter is reported in [`PolicyState::counter_snapshots`] (and persisted in
/// the [`PolicyCounterStore`] across snapshot rebuilds). The real per-rule
/// identity format is `from->to/name` (`stable_policy_rule_id`); this reserved
/// name contains no `->` or `/`, so it can never collide with a configured
/// rule's id. This string MUST equal the Go `dataplane.DefaultPolicyName`
/// ("default-policy") — the Go control plane reads this counter by resolving
/// the reserved `DefaultPolicySentinelID` handle to that name (see
/// `pkg/dataplane/userspace/policycounters.go`).
pub(crate) const DEFAULT_POLICY_COUNTER_RULE_ID: &str = "default-policy";

/// #3363: reserved 1-based hit-counter handle for the IMPLICIT default-policy
/// result. The matched-rule path stamps `rule_index + 1` (1..=rules.len());
/// `0` means "no per-rule counter". This sentinel (`u32::MAX`) is distinct from
/// both — it routes [`PolicyState::hit_counter_by_idx`] to the reserved
/// `default_counter` so a default-PERMIT session re-counts every packet of the
/// flow on the established fast path (mirroring #3073 for configured rules). A
/// real handle can never reach it: that would require ~4.29e9 configured rules.
/// The default-DENY path counts on the cold path alone (a denied flow installs
/// no session), so this handle only ever does work for default-permit.
pub(crate) const DEFAULT_POLICY_COUNTER_IDX: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PolicyEvaluationResult {
    pub(crate) action: PolicyAction,
    pub(crate) policy_id: u32,
    /// #2508: the matched policy's per-policy RT_FLOW SYSLOG log
    /// selection, carried so the session-install path can stamp it onto
    /// the session metadata.
    pub(crate) log_session_init: bool,
    pub(crate) log_session_close: bool,
    /// #3227: the matched application term's per-application inactivity (idle)
    /// timeout in SECONDS, carried so the session-install path can stamp it so
    /// the conntrack GC ages the session out on the app's value instead of the
    /// global per-protocol timeout. `None` means "use the global timeout"
    /// (the default-action path and any non-app-timeout match), which is
    /// byte-identical to pre-#3227 behavior.
    pub(crate) inactivity_timeout: Option<u32>,
    /// #3073: a stable 1-based handle to the admitting rule's per-rule hit
    /// counter (`PolicyState::rules[idx-1].hit_counter`), carried so the
    /// session-install path can stamp it onto the session metadata. The
    /// established fast path then resolves the counter via
    /// [`PolicyState::hit_counter_by_idx`] and counts every packet of the
    /// flow (not just the first). `0` is reserved for "no counter" — every
    /// non-policy-forwarded session (firewall-local / neighbor-seed / fabric /
    /// tunnel) — so those flows keep counting nothing on the fast path. The
    /// implicit default-policy is NOT `0`: #3363 binds it to the reserved
    /// `DEFAULT_POLICY_COUNTER_IDX` (`u32::MAX`) sentinel, which
    /// `hit_counter_by_idx` resolves to `PolicyState::default_counter` so a
    /// default-PERMIT session re-counts every packet on the fast path. A
    /// 1-based handle is used so `0` is an unambiguous sentinel distinct from
    /// rule index 0 (the FIRST configured rule, which also carries `policy_id`
    /// 0).
    pub(crate) policy_counter_idx: u32,
}

/// #3148: the optional from-zone/to-zone match context of a GLOBAL policy.
/// A Junos global policy may narrow which zone pairs it applies to with
/// `match { from-zone <z>; to-zone <z>; }`. The rule stays in the global tier
/// (`PolicyState::global_indices`) and the global config order is preserved;
/// this scope is consulted as an extra predicate inside the global-tier loop
/// before `try_match_rule`. A non-global (zone-pair / wildcard) rule always
/// carries `Any` on both sides, so the scope check is a no-op for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GlobalZoneScope {
    /// No constraint — the global policy applies to every defined zone on this
    /// side (the historical all-zones behaviour, and the value for every
    /// non-global rule).
    Any,
    /// Constrained to a resolved zone id: the side matches only this zone.
    Zone(u16),
}

impl Default for GlobalZoneScope {
    fn default() -> Self {
        GlobalZoneScope::Any
    }
}

impl GlobalZoneScope {
    /// Whether a flow whose zone (ingress for from, egress for to) is `id`
    /// satisfies this scope.
    #[inline]
    pub(crate) fn matches(self, id: u16) -> bool {
        match self {
            GlobalZoneScope::Any => true,
            GlobalZoneScope::Zone(z) => z == id,
        }
    }
}

/// #3148: resolve a global policy's `match from-zone`/`to-zone` name into a
/// [`GlobalZoneScope`].
///
///   - Empty (omitted) → `Any` (all zones — the Junos implicit default).
///   - Explicit `"any"` → `Any` as well: an explicit `match from-zone any` is
///     the Junos all-zones default, identical to omitting the leaf. This MUST
///     agree with the Go commit gate, which exempts `"any"` (a valid commit) —
///     resolving `"any"` through `resolve_policy_zone_id` would return `None`
///     (no zone is named `any`) → `Unresolved` (matches nothing), so a `permit`
///     global silently over-restricts and a `deny` global silently no-ops. The
///     explicit-`any` short-circuit eliminates that commit-vs-dataplane
///     divergence.
///   - Any other name resolves through [`resolve_policy_zone_id`]; an
///     unresolvable name fails the WHOLE snapshot closed
///     ([`SnapshotIntegrityError::UnresolvableZoneReference`], #3402) rather
///     than silently producing a matches-nothing scope, mirroring the
///     zone-pair path's reject. The Go commit gate
///     (`validatePolicyZoneReferencesStrict`, #2401) hard-rejects an undefined
///     match-zone, so a clean commit never reaches here; this is the
///     helper-boundary backstop for the lenient / upgrade-state / corrupt
///     snapshot path. (`"junos-host"` is hard-rejected at commit for these
///     leaves — see `validatePolicyZoneReferencesStrict` — so on the strict
///     path the dataplane never sees it; on the tolerant load path it resolves
///     to the reserved host id, which never matches a transit flow, i.e. inert
///     fail-closed.)
fn build_global_zone_scope(
    zone_name_to_id: &FxHashMap<String, u16>,
    name: &str,
    rule_id: &str,
) -> Result<GlobalZoneScope, SnapshotIntegrityError> {
    if name.is_empty() || name == "any" {
        return Ok(GlobalZoneScope::Any);
    }
    match resolve_policy_zone_id(zone_name_to_id, name) {
        Some(id) => Ok(GlobalZoneScope::Zone(id)),
        None => Err(SnapshotIntegrityError::UnresolvableZoneReference {
            rule_id: rule_id.to_string(),
            zone: name.to_string(),
        }),
    }
}

#[derive(Debug)]
pub(crate) struct PolicyRule {
    pub(crate) rule_id: String,
    pub(crate) policy_id: u32,
    pub(crate) from_zone: String,
    pub(crate) to_zone: String,
    /// #3148: optional global-policy zone match context (Any for every
    /// non-global rule). See [`GlobalZoneScope`].
    pub(crate) global_from_zone: GlobalZoneScope,
    pub(crate) global_to_zone: GlobalZoneScope,
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
            global_from_zone: GlobalZoneScope::Any,
            global_to_zone: GlobalZoneScope::Any,
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
            global_from_zone: self.global_from_zone,
            global_to_zone: self.global_to_zone,
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

/// Per-rule policy hit counter: cumulative `packets`/`bytes` admitted (or
/// denied, for an explicit deny rule) under one security-policy rule, surfaced
/// by [`PolicyState::counter_snapshots`] for `show security policies
/// hit-count`, the REST `/metrics`-counter path, and Prometheus.
///
/// #3451 — relaxed-pair / eventual-consistency semantics (deliberate, do NOT
/// "fix" with a lock or seqcount). `packets` and `bytes` are two INDEPENDENT
/// relaxed [`AtomicU64`]s. Each [`add`](Self::add) / [`add_batch`](Self::add_batch)
/// accumulation is correct in isolation — a relaxed `fetch_add` never loses an
/// increment, so the running TOTAL of each field is always exact, even under
/// many concurrent worker threads sharing the same `Arc`. What is NOT atomic is
/// the *pair*: [`snapshot`](Self::snapshot) loads the two fields with separate
/// relaxed loads, and the hot path stores them with separate relaxed adds, so a
/// reader can observe `packets` and `bytes` taken at slightly different logical
/// instants (e.g. a freshly bumped packet count next to a byte count that has
/// not yet absorbed that packet's length). The skew is bounded by the in-flight
/// update(s) — at most one `add` per concurrent worker, or one coalesced
/// `add_batch` of up to `POLICY_HIT_FLUSH_PACKETS` per worker (#3073).
///
/// This matches the codebase-wide telemetry-counter convention
/// (`filter::FilterTermCounter`, `ThreeColorPolicerCounter`, the NAT and
/// WireGuard counters). It is intentional because the read side is a low-rate
/// poll (~1/s) while the write side is per-packet across every worker: a
/// seqcount or lock would reintroduce shared-cacheline contention on the write
/// side — exactly what the #3073 batched-`add_batch` design exists to avoid —
/// and a 128-bit combined atomic is not portably lock-free on the baseline
/// x86-64 target. Counters are advisory telemetry, so eventual consistency is
/// accepted. CONSUMER CONTRACT: monitoring code MUST treat a single snapshot's
/// `bytes/packets` ratio as approximate at sub-poll granularity; over any poll
/// interval the two fields reconcile (each total is exact). Do not assert an
/// exact `bytes == packets * frame_len` relationship on one instantaneous
/// snapshot.
#[derive(Debug, Default)]
pub(crate) struct PolicyRuleCounter {
    packets: AtomicU64,
    bytes: AtomicU64,
    /// #3395: the stable rule identity (`stable_policy_rule_id`, the
    /// `from->to/name` string, or `DEFAULT_POLICY_COUNTER_RULE_ID` for the
    /// implicit default-policy counter) this counter belongs to. Set once at
    /// creation in `PolicyCounterStore::rule_hit_counter` and never mutated, so
    /// a session that BOUND this `Arc` at install (`SessionMetadata::
    /// policy_counter`, #3322) can recover the stable identity of its admitting
    /// rule from the bound handle alone — without a new per-session field. Used
    /// by `PolicyState::reresolve_session_policy_id` to re-resolve the CURRENT
    /// positional `policy_id` (#3056) of an established session at the local
    /// publish surfaces (live-row refresh + RT_FLOW SESSION_CLOSE), so a live
    /// mid-list policy insert/delete no longer mis-attributes the session
    /// (#3395). The placeholder `Default` counters (`PolicyRule::default()` /
    /// `PolicyState::default()`) carry an empty id; production counters always
    /// flow through `rule_hit_counter` and carry the real id.
    rule_id: Box<str>,
    /// #3448: clear epoch. `clear security policies hit-count` resets the
    /// shared `packets`/`bytes` atomics but cannot reach the per-worker
    /// pending hit-count batches buffered by `record_policy_hit_counter`
    /// (up to `POLICY_HIT_FLUSH_PACKETS`). Without an epoch, a pending batch
    /// recorded before the clear would `add_batch` its stale pre-clear counts
    /// onto the freshly-zeroed counter at the next RX-batch flush, so the
    /// clear appeared to fail or to invent traffic. `reset()` bumps this
    /// generation; each pending batch records the generation it was captured
    /// under and is DISCARDED (not flushed) if the generation has advanced.
    generation: AtomicU64,
}

impl PolicyRuleCounter {
    /// #3395: construct a counter that remembers the stable `rule_id` it
    /// belongs to. Used by `PolicyCounterStore::rule_hit_counter` at first
    /// creation; the store re-hands the same `Arc` for a surviving id across
    /// snapshot rebuilds, so the id stays valid for the life of any session
    /// that bound the handle.
    fn with_rule_id(rule_id: &str) -> Self {
        Self {
            packets: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            rule_id: Box::from(rule_id),
            generation: AtomicU64::new(0),
        }
    }

    /// #3395: the stable rule identity this counter belongs to (empty for a
    /// `Default` placeholder). See the `rule_id` field doc.
    pub(crate) fn rule_id(&self) -> &str {
        &self.rule_id
    }

    fn add(&self, packet_len: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        if packet_len != 0 {
            self.bytes.fetch_add(packet_len, Ordering::Relaxed);
        }
    }

    /// #3073: coalesced multi-packet add used by the per-worker hit-count
    /// flush (`flush_recorded_policy_hit_counters`). Folds a whole batch of
    /// established-session fast-path packets into ONE pair of relaxed
    /// `fetch_add`s on the shared counter, so the hot path never hammers the
    /// shared cacheline per packet (mirrors `filter::FilterTermCounter`).
    fn add_batch(&self, packets: u64, bytes: u64) {
        if packets != 0 {
            self.packets.fetch_add(packets, Ordering::Relaxed);
        }
        if bytes != 0 {
            self.bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    fn reset(&self) {
        // #3448: bump the clear epoch so any per-worker pending batch still
        // holding pre-clear counts (recorded under the previous generation)
        // is discarded at its next flush instead of replaying onto the
        // freshly-zeroed atomics. The generation only ever increases.
        self.generation.fetch_add(1, Ordering::Relaxed);
        self.packets.store(0, Ordering::Relaxed);
        self.bytes.store(0, Ordering::Relaxed);
    }

    /// #3448: current clear epoch. Stamped onto a per-worker pending batch
    /// when it is captured and re-checked at flush time to drop stale
    /// pre-clear counts.
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// #3451: loads the two fields with INDEPENDENT relaxed loads — see the
    /// `PolicyRuleCounter` type doc. Each field's total is exact; the pair is
    /// eventual-consistent (the snapshot may straddle one in-flight update), so
    /// the returned `bytes/packets` ratio is approximate at sub-poll
    /// granularity. `packets` always maps to `packets` and `bytes` to `bytes`
    /// (no swap) — pinned by `policy_rule_counter_snapshot_pairs_totals` in
    /// `policy_tests.rs`.
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
        let mut active_rule_ids: FxHashSet<String> =
            rules.iter().map(stable_policy_rule_id).collect();
        // #3363: the implicit default-policy counter has no PolicyRuleSnapshot,
        // so retain its reserved id explicitly — otherwise every reconcile
        // would evict it and reset the default-deny hit count to zero.
        active_rule_ids.insert(DEFAULT_POLICY_COUNTER_RULE_ID.to_string());
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

        // #3395: stamp the stable rule id onto the counter at creation so a
        // session that binds this Arc can later recover its admitting rule's
        // identity from the handle alone (see PolicyRuleCounter::rule_id).
        let counter = Arc::new(PolicyRuleCounter::with_rule_id(rule_id));
        counters.insert(rule_id.to_string(), counter.clone());
        counter
    }
}

// ── #3073: per-worker established-session policy hit-count coalescer ──
//
// Before #3073 the policy packet/byte hit counter was incremented exactly
// ONCE per flow — on the cold (session-miss) path inside `try_match_rule`.
// A permitted TCP session moving millions of packets therefore reported
// `packets=1` and only the first frame's bytes, defeating audits and vSRX
// parity. The established fast path (`poll_descriptor` session-hit and the
// flow-cache hit replay) now increments the admitting policy's counter on
// EVERY packet via `record_policy_hit_counter`.
//
// To keep the hot path off the shared counter cacheline, increments are
// coalesced in a thread-local (per-worker) accumulator and folded into the
// shared `PolicyRuleCounter` in batches — the SAME technique
// `filter::record_filter_counter` uses for `then count` term counters. The
// accumulator holds the current rule's counter `Arc`; a different rule (or
// the per-batch `flush_recorded_policy_hit_counters` call at the end of the
// RX batch) flushes the pending tally first. `Arc::ptr_eq` keeps the common
// run of same-flow packets on a pure thread-local add.
struct PendingPolicyHitRecord {
    counter: Option<Arc<PolicyRuleCounter>>,
    /// #3448: clear epoch the buffered `packets`/`bytes` were recorded under.
    /// Compared against the counter's current generation at flush time so a
    /// `clear` that happened after this batch was captured discards the
    /// pre-clear counts instead of replaying them.
    generation: u64,
    packets: u64,
    bytes: u64,
}

impl Default for PendingPolicyHitRecord {
    fn default() -> Self {
        Self {
            counter: None,
            generation: 0,
            packets: 0,
            bytes: 0,
        }
    }
}

#[cfg(not(test))]
const POLICY_HIT_FLUSH_PACKETS: u64 = 64;

#[cfg(not(test))]
thread_local! {
    static PENDING_POLICY_HIT_RECORD: std::cell::RefCell<PendingPolicyHitRecord> =
        std::cell::RefCell::new(PendingPolicyHitRecord::default());
}

// Not gated on `#[cfg(not(test))]`: the generation-discard logic is the
// load-bearing part of the #3448 fix and is unit-tested directly (the
// per-worker thread-local coalescer itself is bypassed under `#[cfg(test)]`).
#[inline(always)]
fn flush_pending_policy_hit_record(record: &mut PendingPolicyHitRecord) {
    let Some(counter) = record.counter.take() else {
        return;
    };
    // #3448: only fold the pending batch into the shared counter if it was
    // recorded under the counter's CURRENT clear epoch. If a
    // `clear security policies hit-count` bumped the generation between
    // capture and this flush, these are pre-clear hits — discard them so the
    // clear is durable and the freshly-zeroed counter does not snap back.
    if record.generation == counter.generation() {
        counter.add_batch(record.packets, record.bytes);
    }
    record.packets = 0;
    record.bytes = 0;
}

/// #3073: record one established-session packet against the admitting
/// policy's hit counter, coalesced per worker. Called from the
/// `poll_descriptor` session-hit fast path and the flow-cache hit replay —
/// NOT the cold path, which already counts the first packet in
/// `try_match_rule`, so every packet is counted exactly once.
#[cfg(not(test))]
#[inline(always)]
pub(crate) fn record_policy_hit_counter(counter: &Arc<PolicyRuleCounter>, packet_bytes: u64) {
    PENDING_POLICY_HIT_RECORD.with(|pending| {
        let mut pending = pending.borrow_mut();
        let generation = counter.generation();
        // #3448: continue the current batch only when it is the SAME counter
        // AND the SAME clear epoch. A `clear` mid-batch advances the
        // generation; the else branch then flushes (and discards, via the
        // generation guard) the stale pre-clear tally and re-captures the
        // counter under the new generation, so post-clear packets are counted
        // fresh from zero instead of being dropped with the pre-clear batch.
        if pending
            .counter
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, counter))
            && pending.generation == generation
        {
            pending.packets = pending.packets.saturating_add(1);
            pending.bytes = pending.bytes.saturating_add(packet_bytes);
        } else {
            flush_pending_policy_hit_record(&mut pending);
            pending.counter = Some(counter.clone());
            pending.generation = generation;
            pending.packets = 1;
            pending.bytes = packet_bytes;
        }
        if pending.packets >= POLICY_HIT_FLUSH_PACKETS {
            flush_pending_policy_hit_record(&mut pending);
        }
    });
}

// In tests the coalescer is bypassed so a single recorded packet is
// immediately visible in `counter_snapshots()` (deterministic assertions).
#[cfg(test)]
#[inline(always)]
pub(crate) fn record_policy_hit_counter(counter: &Arc<PolicyRuleCounter>, packet_bytes: u64) {
    counter.add(packet_bytes);
}

/// #3073: flush this worker's pending policy hit-count tally to the shared
/// counters. Called once per RX batch (alongside
/// `filter::flush_recorded_filter_counters`) so `show security policies
/// hit-count` converges within one poll tick.
#[cfg(not(test))]
pub(crate) fn flush_recorded_policy_hit_counters() {
    PENDING_POLICY_HIT_RECORD.with(|pending| {
        flush_pending_policy_hit_record(&mut pending.borrow_mut());
    });
}

#[cfg(test)]
pub(crate) fn flush_recorded_policy_hit_counters() {}

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
    /// #3020: optional ICMP/ICMPv6 type constraint. `Some(t)` restricts the
    /// term to ICMP messages of type `t` (e.g. junos-ping = type 8); `None`
    /// leaves the term unconstrained on type (the all-ICMP aliases). Only
    /// meaningful when `protocol` is ICMP/ICMPv6; ignored for TCP/UDP terms.
    pub(crate) icmp_type: Option<u8>,
    /// #3020: optional ICMP/ICMPv6 code constraint, paired with `icmp_type`.
    /// `None` matches any code of the constrained type.
    pub(crate) icmp_code: Option<u8>,
    /// #3227: optional per-application inactivity (idle) timeout in SECONDS.
    /// `Some(t)` (t > 0) overrides the global per-protocol session timeout for a
    /// flow admitted by this term; `None` (or 0) leaves the global timeout in
    /// effect (back-compat). Carried from the matched term into the session at
    /// install so the conntrack GC ages the session out on the app's value.
    pub(crate) inactivity_timeout: Option<u32>,
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
    /// #3227: the value carries the term's per-application inactivity timeout
    /// (`None` = use the global per-protocol timeout). #3346: the value also
    /// carries the term's CONFIG-ORDER index (`u32`) so cross-class precedence
    /// can honor Junos first-term-wins instead of always probing exact before
    /// range/icmp. First writer wins on an overlapping port (the lower config
    /// index, matching the catalog "first match wins" convention).
    exact_dst_ports: FxHashMap<u16, (u32, Option<u32>)>, // port -> (order, timeout)
    /// Port range terms that need linear scan (multi-port ranges). #3346: the
    /// leading `u32` is the term's config-order index; the trailing element is
    /// the #3227 inactivity timeout. Pushed in config order, so the first
    /// matching entry in the vector is the lowest-order matching range.
    range_terms: Vec<(u32, Vec<PortRange>, Vec<PortRange>, Option<u32>)>, // (order, src, dst, timeout)
    /// #3020: ICMP/ICMPv6 type[,code] constraints for icmp-constrained terms
    /// (e.g. junos-ping = type 8). #3346: each entry is `(config-order index,
    /// type, optional code, inactivity timeout)`. A packet matches this protocol
    /// via the icmp path iff its type (and code, when the entry constrains it)
    /// equals one of these entries. An UNCONSTRAINED ICMP term (junos-icmp-all)
    /// does NOT land here — it stays a `range_terms` entry with empty ranges,
    /// which matches every ICMP packet, so a rule citing both still matches all
    /// ICMP. Pushed in config order. #3227 added the timeout.
    icmp_constraints: Vec<(u32, u8, Option<u8>, Option<u32>)>, // (order, type, code, timeout)
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
        // #3346: stamp each term with its CONFIG-ORDER index (the order the
        // operator listed the applications, preserved by the Go emit path —
        // capabilities.go resolveUserspaceApplicationNames, #3298). The index is
        // assigned across ALL terms of the rule; since matching is per-protocol,
        // the relative order WITHIN a protocol is what `matches` compares, and
        // that relative order is preserved by a single monotonic counter.
        for (order, app) in (0u32..).zip(apps.iter()) {
            let entry = by_protocol.entry(app.protocol).or_default();
            // #3020: an ICMP/ICMPv6 term with a type constraint (junos-ping)
            // is steered to `icmp_constraints` so it matches ONLY that type
            // (and code, when set) instead of every ICMP message. A term with
            // NO icmp_type constraint falls through to the existing port path —
            // an unconstrained ICMP term (junos-icmp-all) has empty ports and
            // lands as a `range_terms` entry with empty ranges (match-all), so a
            // rule citing both junos-ping AND junos-icmp-all still matches all
            // ICMP. (ICMP terms never carry ports in practice; the type
            // constraint takes precedence so a stray port is irrelevant here.)
            if app.icmp_type.is_some() {
                entry.icmp_constraints.push((
                    order,
                    app.icmp_type.expect("icmp_type is Some"),
                    app.icmp_code,
                    // #3227: carry the term's idle timeout onto the constraint.
                    app.inactivity_timeout,
                ));
            } else if app.source_ports.is_empty()
                && app.destination_ports.len() == 1
                && app.destination_ports[0].low == app.destination_ports[0].high
            {
                // #3227: store the term timeout keyed by exact port. #3346: also
                // store the config-order index. First writer wins on an
                // overlapping port (the lower order) so precedence is stable.
                entry
                    .exact_dst_ports
                    .entry(app.destination_ports[0].low)
                    .or_insert((order, app.inactivity_timeout));
            } else {
                entry.range_terms.push((
                    order,
                    app.source_ports.clone(),
                    app.destination_ports.clone(),
                    // #3227: carry the term's idle timeout onto the range entry.
                    app.inactivity_timeout,
                ));
            }
        }
        Self {
            match_any: false,
            by_protocol,
        }
    }

    /// #3020: `packet_icmp` carries the packet's ICMP/ICMPv6 `(type, code)` when
    /// the protocol is ICMP-family AND the bytes were safely readable (not a
    /// truncated frame or non-first fragment); `None` otherwise. It gates the
    /// icmp-type-constrained terms (junos-ping): a constrained term matches only
    /// when the type/code is known and equal, so an unknown type/code (or a
    /// non-ICMP packet) fails closed for those terms. Port/range terms are
    /// unaffected, so non-ICMP applications and the all-ICMP aliases behave
    /// exactly as before.
    ///
    /// #3227: the return type carries the matched term's per-application
    /// inactivity timeout so the install path can stamp it on the session:
    ///   - `None`              → no application term matched (rule does not apply)
    ///   - `Some(None)`        → matched, no custom timeout (use the global one)
    ///   - `Some(Some(secs))`  → matched, use this per-app idle timeout
    /// #3346: precedence among a rule's terms is CONFIG ORDER — the FIRST term
    /// the operator listed that matches supplies the timeout (Junos
    /// first-term-wins), regardless of which class (exact-port / range / icmp)
    /// it lands in. Each term carries its config-order index; this gathers the
    /// best (lowest-index) match across all three classes. The O(1) exact-port
    /// map is retained purely as a lookup accelerator for the common
    /// single-port term, NOT as a precedence tier — before #3346 it always beat
    /// a range/icmp term listed earlier, which diverged from vSRX. The match-any
    /// short-circuit yields `Some(None)` (use-global), so an `application any`
    /// rule is byte-identical to today. The boolean "does the rule apply?"
    /// verdict (`Some` vs `None`) is unchanged — only WHICH matched term's
    /// timeout is returned.
    /// #3291: `l4_present` is `false` for a flowless / no-L4 packet (a non-first
    /// fragment, whose post-IP bytes are payload — #2344). With no L4 header the
    /// caller cannot supply real ports (`src_port`/`dst_port` are 0), so a
    /// PORT-BEARING application term MUST fail closed (it can neither be
    /// confirmed nor allowed to spuriously match `port == 0`, e.g. a custom
    /// `destination-port 0-1023` range). A PROTOCOL-ONLY term (empty port
    /// ranges, e.g. an `application any`-of-this-protocol alias / junos-icmp-all)
    /// still matches on the known protocol so legitimately-permitted protocol/
    /// address policy keeps forwarding the fragment. Every flow-backed caller
    /// passes `l4_present = true`, so the L4 path is byte-identical to before.
    #[inline]
    fn matches(
        &self,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
        packet_icmp: Option<(u8, u8)>,
        l4_present: bool,
    ) -> Option<Option<u32>> {
        if self.match_any {
            return Some(None);
        }
        let terms = self.by_protocol.get(&protocol)?;
        // #3346: track the lowest-config-order matching term across all classes.
        // `best` holds `(order, timeout)`; a smaller order wins (first listed).
        let mut best: Option<(u32, Option<u32>)> = None;
        // Exact dst-port term — O(1) accelerator for the common single-port case.
        // #3291: a known L4 port is required; a flowless packet (port 0) never
        // matches a port-specific term.
        if l4_present {
            if let Some(&(order, timeout)) = terms.exact_dst_ports.get(&dst_port) {
                best = Some((order, timeout));
            }
        }
        // Range terms (an unconstrained ICMP term, e.g. junos-icmp-all, lives
        // here as an empty-range entry → match-all). Pushed in config order, so
        // the first match in the vector is the lowest-order matching range.
        // #3291: an empty-range (protocol-only) term matches regardless of L4
        // presence — we know the protocol; a port-bearing range requires a known
        // L4 port and so fails closed for a flowless packet.
        if let Some(&(order, _, _, timeout)) = terms.range_terms.iter().find(
            |(_, src_ranges, dst_ranges, _)| {
                if src_ranges.is_empty() && dst_ranges.is_empty() {
                    true
                } else {
                    l4_present
                        && port_ranges_match(src_ranges, src_port)
                        && port_ranges_match(dst_ranges, dst_port)
                }
            },
        ) {
            if best.map_or(true, |(b, _)| order < b) {
                best = Some((order, timeout));
            }
        }
        // #3020: ICMP/ICMPv6 type[,code]-constrained terms (junos-ping). Match
        // only when the packet's type/code is known and equals a constraint.
        // When `packet_icmp` is None (non-ICMP packet, truncated frame, or
        // non-first fragment) the constrained term does NOT match — fail closed.
        if !terms.icmp_constraints.is_empty() {
            if let Some((ptype, pcode)) = packet_icmp {
                if let Some(&(order, _, _, timeout)) = terms.icmp_constraints.iter().find(
                    |&&(_, ctype, ccode, _)| ctype == ptype && ccode.map_or(true, |c| c == pcode),
                ) {
                    if best.map_or(true, |(b, _)| order < b) {
                        best = Some((order, timeout));
                    }
                }
            }
        }
        best.map(|(_, timeout)| timeout)
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
/// per-protocol scan list. On overlap the winner is chosen by SPECIFICITY first
/// (a port-constrained entry beats a bare protocol-only one), then by lowest
/// `app_id` within a tier (#3612). Lowest id == the alphabetically-first name
/// because the Go builder emits entries in sorted-name / ascending-id order, so
/// the result is deterministic and stable across reloads and matches the
/// AppID-disabled Go fallback (`resolveTupleFallback`, #2578).
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
    /// destination-port constraint at all (port-0 protocol-only entries). Each
    /// entry is tagged `port_constrained` so `lookup_directional` can rank a
    /// port-constrained overlap above a protocol-only one before falling back to
    /// lowest app_id within a tier (#3612).
    scan: Vec<AppScanEntry>,
}

#[derive(Clone, Debug)]
struct AppScanEntry {
    app_id: u16,
    dst_low: u16,
    dst_high: u16,
    src_low: u16,
    src_high: u16,
    /// #3612: true iff this entry carries a destination AND/OR source port
    /// constraint (i.e. it is NOT a bare protocol-only entry). Mirrors the
    /// AppID-disabled Go fallback's `portBased` predicate
    /// (`resolveTupleFallback`: `DestinationPort != "" || SourcePort != ""`)
    /// so `lookup_directional` can rank a port-constrained overlap above a
    /// protocol-only one identically to that path.
    port_constrained: bool,
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
                // #3612: a scan entry is port-constrained unless ALL four port
                // bounds are zero (a bare protocol-only entry). This is the wire
                // mirror of the Go fallback's `portBased` — a `source-port`-only
                // app (dst (0,0), src set) is port-constrained on both sides.
                let port_constrained = !(e.dst_port_low == 0
                    && e.dst_port_high == 0
                    && e.src_port_low == 0
                    && e.src_port_high == 0);
                bucket.scan.push(AppScanEntry {
                    app_id: e.app_id,
                    dst_low: e.dst_port_low,
                    dst_high: e.dst_port_high,
                    src_low: e.src_port_low,
                    src_high: e.src_port_high,
                    port_constrained,
                });
            }
        }
        Self { by_protocol }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.by_protocol.is_empty()
    }

    /// Resolve the app_id for a session 5-tuple, honouring flow DIRECTION.
    ///
    /// The well-known service port is the DESTINATION on a forward-keyed
    /// session and the SOURCE on a reverse-keyed session. `is_reverse` selects
    /// which slot carries the service port, so the catalog's destination-port
    /// constraint is matched against the real service side ONLY — the lookup
    /// does not probe both slots. Both directions of one session still resolve
    /// to the same app_id because the caller passes the matching `is_reverse`
    /// for each direction (and the publisher stamps the forward + reverse
    /// conntrack entries from one resolution). Returns 0 (unknown) when nothing
    /// matches; 0 is the existing default the show path treats as "no AppID".
    ///
    /// #3321: the previous directionless probe matched the service port on
    /// EITHER slot. A forward flow whose CLIENT source port coincidentally
    /// equalled a service port (e.g. tcp `src=443, dst=ephemeral`) was then
    /// mislabeled as that service in session display / RT_FLOW create+close /
    /// policy-deny / filter-log records — log-integrity pollution during
    /// incident response. Matching on the directional service slot fixes it.
    #[inline]
    pub(crate) fn lookup_directional(
        &self,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
        is_reverse: bool,
    ) -> u16 {
        let Some(bucket) = self.by_protocol.get(&protocol) else {
            return 0;
        };
        // Service port = destination on a forward flow, source on a reverse-
        // keyed flow; the client port is the other slot.
        let (service_port, client_port) = if is_reverse {
            (src_port, dst_port)
        } else {
            (dst_port, src_port)
        };
        // Exact single-port entries carry no source constraint by construction
        // (`from_snapshot` only routes src-unconstrained single-dst entries to
        // `exact_dst`), so an exact hit needs only the service port.
        let exact = bucket.exact_dst.get(&service_port).copied();
        // Scan entries (ranges / source-constrained / protocol-only).
        //
        // #3612: resolve overlaps by SPECIFICITY TIER first — a port-constrained
        // entry (a destination and/or source port constraint) outranks a bare
        // protocol-only entry — then by lowest app_id WITHIN a tier. This is the
        // exact binary-specificity rule the AppID-disabled Go fallback already
        // uses (`resolveTupleFallback`, #2578: `portBased` beats protocol-only,
        // ties broken by name == lowest id in sorted-name order), so the same
        // 5-tuple resolves to the same application label whether AppID is ON
        // (this catalog) or OFF (the Go fallback). `exact_dst` entries are always
        // port-constrained, so they participate in the port-constrained tier.
        //
        // Before #3612 the final tiebreak was a flat `exact.min(scan_hit)` —
        // lowest app_id regardless of tier. Because ids are assigned in
        // sorted-name order, that meant the alphabetically-first name won an
        // overlap, letting a broad protocol-only `aaa-tcp` shadow a specific
        // `zzz-https` on tcp/443. Within a single tier the result is unchanged
        // (still the lowest id), so this is strictly additive for same-tier
        // configs.
        let in_range = |low: u16, high: u16, p: u16| -> bool {
            // (0,0) means "no constraint".
            (low == 0 && high == 0) || (p >= low && p <= high)
        };
        let mut port_scan_hit: Option<u16> = None;
        let mut proto_only_scan_hit: Option<u16> = None;
        for s in &bucket.scan {
            // Destination constraint is matched against the service slot and
            // the source constraint against the client slot — directional, no
            // cross-slot probing.
            let dst_ok = in_range(s.dst_low, s.dst_high, service_port);
            let src_ok = in_range(s.src_low, s.src_high, client_port);
            if !(dst_ok && src_ok) {
                continue;
            }
            let slot = if s.port_constrained {
                &mut port_scan_hit
            } else {
                &mut proto_only_scan_hit
            };
            // Keep the lowest app_id per tier. The Go builder emits entries in
            // ascending-id order, but taking the min makes the tiebreak
            // independent of scan order.
            *slot = Some(slot.map_or(s.app_id, |cur| cur.min(s.app_id)));
        }
        // Port-constrained tier wins: combine the always-port-constrained exact
        // hit with the port-constrained scan hit and take the lowest id. Fall
        // back to the protocol-only tier only when no port-constrained entry
        // matched the flow.
        let port_based = match (exact, port_scan_hit) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        };
        port_based.or(proto_only_scan_hit).unwrap_or(0)
    }

    /// Forward-keyed convenience wrapper: the service port is the destination.
    /// This is the common case for cold-path RT_FLOW / filter-log / policy-deny
    /// resolution where the 5-tuple is the received (forward) packet and there
    /// is no session-direction flag at the call site.
    #[inline]
    pub(crate) fn lookup_forward(&self, protocol: u8, src_port: u16, dst_port: u16) -> u16 {
        self.lookup_directional(protocol, src_port, dst_port, false)
    }

    /// #3416: resolve the AppID a session was ADMITTED under for the permit-side
    /// audit surfaces (RT_FLOW `SESSION_CREATE`/`SESSION_CLOSE` and the
    /// BPF-compatible conntrack publish). A forward DNAT / static-DNAT /
    /// inbound-NPTv6 flow has its policy evaluated against the POST-translation
    /// destination port (poll_descriptor `policy_dst_port`, #2345), so the
    /// permitted-flow audit AppID must use that same translated port — not the
    /// pre-NAT forward-key destination — or a port-forwarded service (public
    /// `:2222` -> internal `:22` admitted by `junos-ssh`) renders as
    /// UNKNOWN/the public-port app. This mirrors the deny-side fix that resolves
    /// from the post-translation `policy_dst_port` (`resolve_policy_deny_app_id`,
    /// #3058/#3185), making the permit side symmetric.
    ///
    /// `is_reverse` selects the service slot exactly as `lookup_directional`.
    /// The post-translation rewrite is applied ONLY to the FORWARD service slot
    /// (the destination). A reverse-keyed entry keeps its received service slot:
    /// the reverse key already carries the real internal service port, and the
    /// reverse NAT decision's `rewrite_dst_port` un-translates a destination
    /// back toward the client side, so applying it there would re-introduce the
    /// very mislabel this fixes. For a non-translated flow `rewrite_dst_port` is
    /// `None`, so the result is byte-identical to `lookup_directional`.
    #[inline]
    pub(crate) fn lookup_admitted(
        &self,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
        is_reverse: bool,
        rewrite_dst_port: Option<u16>,
    ) -> u16 {
        let service_dst_port = if is_reverse {
            dst_port
        } else {
            rewrite_dst_port.unwrap_or(dst_port)
        };
        self.lookup_directional(protocol, src_port, service_dst_port, is_reverse)
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
    /// #3090: wildcard `from-zone any` index — key = the concrete to-zone id,
    /// value = indices (config order) of rules whose from-zone is the Junos
    /// wildcard `any` and whose to-zone is that concrete zone. Such a rule
    /// matches a flow into that to-zone REGARDLESS of ingress zone. Consulted
    /// in the single-wildcard precedence tier (after the exact zone pair,
    /// before both-any and global).
    from_any_index: FxHashMap<u16, Vec<usize>>,
    /// #3090: wildcard `to-zone any` index — key = the concrete from-zone id,
    /// value = indices (config order) of rules whose to-zone is `any` and whose
    /// from-zone is that concrete zone. Matches a flow OUT of that from-zone
    /// regardless of egress zone.
    to_any_index: FxHashMap<u16, Vec<usize>>,
    /// #3090: `from-zone any to-zone any` rules (the least-specific wildcard
    /// tier), in config order. Matches every defined zone pair. Consulted after
    /// the single-wildcard tier and before global rules.
    both_any_indices: Vec<usize>,
    /// Indices of global rules (from_zone or to_zone = "junos-global").
    global_indices: Vec<usize>,
    /// #1606: deduplicated address-book table. Rules reference
    /// books by dense `u32` index (`PolicyRule::source_book_idxs`).
    pub(crate) books: Vec<BookEntry>,
    /// #1606: wire-ID → dense-index map used at parse time only.
    book_id_to_idx: FxHashMap<u32, u32>,
    /// #3019: true iff at least one rule names `junos-host` as its from OR to
    /// zone. The LocalDelivery junos-host policy gate is a NO-OP unless this is
    /// set, so a config with no junos-host policy keeps pre-#3019 host-bound
    /// behavior exactly (no risk of newly denying management traffic).
    has_junos_host_rules: bool,
    /// #3363: reserved hit counter for the IMPLICIT default-policy verdict
    /// (the result returned when a flow matches no configured zone-pair,
    /// wildcard, or `junos-global` policy). Before #3363 the default path
    /// returned `policy_counter_idx: 0` and incremented nothing, so an
    /// operator could not answer "how many packets are hitting the implicit
    /// default deny?". The counter is incremented on the cold path for every
    /// default verdict and (for default-permit) re-counted on the established
    /// fast path via [`DEFAULT_POLICY_COUNTER_IDX`]. Persisted in the
    /// `PolicyCounterStore` under [`DEFAULT_POLICY_COUNTER_RULE_ID`] so it
    /// survives snapshot rebuilds, and reported as that rule id in
    /// [`PolicyState::counter_snapshots`].
    pub(crate) default_counter: Arc<PolicyRuleCounter>,
    /// #3534: RT_FLOW session-log selection for the IMPLICIT default-policy
    /// verdict (`security policies default-policy-log session-init|
    /// session-close`). Stamped onto the default-verdict
    /// [`PolicyEvaluationResult`] so a default-PERMIT session carries the flags
    /// in its metadata and emits RT_FLOW_SESSION_CREATE/CLOSE like a named
    /// policy. Inert for a default-DENY/REJECT verdict (no session installed —
    /// the deny is already logged via the policy-deny record). Sourced from the
    /// snapshot at build time (see `build_forwarding_state_*`); the parser does
    /// not read it, so the legacy infallible test helper keeps them false.
    pub(crate) default_log_session_init: bool,
    pub(crate) default_log_session_close: bool,
    /// #3395: O(1) re-resolution map from a rule's stable `rule_id`
    /// (`stable_policy_rule_id`, or `DEFAULT_POLICY_COUNTER_RULE_ID` for the
    /// implicit default policy) to its CURRENT positional `policy_id` (#3056)
    /// in THIS snapshot. Built ONCE per snapshot in
    /// `parse_policy_state_with_counters` (not per session), so
    /// `reresolve_session_policy_id` is O(1) per lookup — the CLAUDE.md
    /// control-socket-contention rule forbids an O(sessions × rules) refresh.
    /// A bound session whose admitting rule survives the edit re-resolves to
    /// that rule's NEW positional id; a rule that was DELETED is absent from the
    /// map and falls back to the unattributed default-policy sentinel (#3395 /
    /// AGY catch — never the frozen positional id a later reorder could reassign
    /// to a different rule).
    rule_id_to_policy_id: FxHashMap<String, u32>,
}

impl Default for PolicyState {
    fn default() -> Self {
        Self {
            default_action: PolicyAction::Deny,
            rules: Vec::new(),
            zone_pair_index: FxHashMap::default(),
            from_any_index: FxHashMap::default(),
            to_any_index: FxHashMap::default(),
            both_any_indices: Vec::new(),
            global_indices: Vec::new(),
            books: Vec::new(),
            book_id_to_idx: FxHashMap::default(),
            has_junos_host_rules: false,
            default_counter: Arc::new(PolicyRuleCounter::default()),
            default_log_session_init: false,
            default_log_session_close: false,
            // #3395: empty map — the Default state carries no rules, so there
            // is nothing to re-resolve.
            rule_id_to_policy_id: FxHashMap::default(),
        }
    }
}

impl PolicyState {
    pub(crate) fn counter_snapshots(&self) -> Vec<PolicyRuleCounterStatus> {
        let mut snapshots: Vec<PolicyRuleCounterStatus> = self
            .rules
            .iter()
            .map(|rule| rule.hit_counter.snapshot(&rule.rule_id))
            .collect();
        // #3363: surface the implicit default-policy hit counter under its
        // reserved rule id so the Go control plane can read it (via the
        // reserved `DefaultPolicyCounterID` handle) and render a `Default
        // policy` row separated from the configured-rule totals.
        snapshots.push(
            self.default_counter
                .snapshot(DEFAULT_POLICY_COUNTER_RULE_ID),
        );
        snapshots
    }

    /// #3073: resolve the 1-based hit-counter handle stamped onto a session at
    /// install (`SessionMetadata::policy_counter_idx`) back to the admitting
    /// rule's shared counter, so the established fast path can re-count every
    /// packet of the flow. `0` (no counter) and any stale handle past the
    /// current rule table (a config reload shrank the policy set) resolve to
    /// `None` and are silently skipped — never a panic, never a wrong-rule
    /// increment past the table end. A handle that still points within the
    /// table after an unrelated config change may briefly attribute packets to
    /// whatever rule now sits at that index; counters are advisory and this
    /// only affects in-flight sessions across a live policy edit.
    pub(crate) fn hit_counter_by_idx(&self, idx: u32) -> Option<&Arc<PolicyRuleCounter>> {
        if idx == 0 {
            return None;
        }
        // #3363: the reserved default-policy handle routes to the reserved
        // counter (not into `rules`), so a default-PERMIT session binds it at
        // install and re-counts every packet on the established fast path.
        if idx == DEFAULT_POLICY_COUNTER_IDX {
            return Some(&self.default_counter);
        }
        self.rules
            .get((idx - 1) as usize)
            .map(|rule| &rule.hit_counter)
    }

    /// #3322: resolve the hit counter to increment for an ESTABLISHED-session
    /// packet. Prefers the reorder-stable BOUND handle stamped on the session
    /// at install (`SessionMetadata::policy_counter`) over re-resolving the
    /// positional `policy_counter_idx` against the CURRENT rule table.
    ///
    /// The positional index is only valid relative to the rule table that was
    /// live when the session was admitted. After a live policy insert/reorder
    /// the same index points at whatever rule now occupies that slot, so the
    /// pre-#3322 `hit_counter_by_idx(idx)` resolution attributed an in-flight
    /// session's packets to the wrong rule (the original admitting rule stopped
    /// counting). The bound Arc is captured once at install (when the index is
    /// still correct) and is the same instance the persistent
    /// `PolicyCounterStore` re-hands for the rule's stable `rule_id` across
    /// snapshot rebuilds, so it follows the admitting rule through reorders.
    ///
    /// `bound == None` (idx-0 sessions, peer-synced sessions carrying only the
    /// wire index) falls back to `hit_counter_by_idx`, preserving pre-#3322
    /// behavior. A `None` result (no per-rule counter / stale index past a
    /// shrunk table) is silently skipped by the caller — never a panic.
    #[inline]
    pub(crate) fn resolve_session_hit_counter<'a>(
        &'a self,
        bound: Option<&'a Arc<PolicyRuleCounter>>,
        idx: u32,
    ) -> Option<&'a Arc<PolicyRuleCounter>> {
        bound.or_else(|| self.hit_counter_by_idx(idx))
    }

    /// #3395: re-resolve the CURRENT positional `policy_id` (#3056) for an
    /// ESTABLISHED session at a local publish surface (the ~1s live-row refresh
    /// and the RT_FLOW SESSION_CLOSE emit), so a live mid-list policy
    /// insert/delete no longer mis-attributes the session.
    ///
    /// `policy_id` is span-accumulated in config order (`walkPolicyRuleSlots`),
    /// frozen onto the session at install. A live policy edit that perturbs
    /// earlier positions renumbers every later rule, so the frozen id resolves
    /// to a DIFFERENT policy's name afterwards. This is the display/forensic
    /// sibling of the #3322 hit-counter misattribution, fixed by the same
    /// bound-handle re-resolution pattern — `policy_id` itself MUST stay
    /// positional (the #3063 `show security policies` Index contract), so
    /// stability comes from re-resolving at read time, NOT from making the
    /// scalar content-stable.
    ///
    /// Resolution:
    /// - `bound = Some(counter)` with a non-empty stable `rule_id` that is still
    ///   present in this snapshot → the rule's NEW current positional id (#3063
    ///   Index↔RT_FLOW equality preserved for the re-resolved value).
    /// - `bound = Some(counter)` whose admitting rule was DELETED (its `rule_id`
    ///   is absent from the current map) → the unattributed default-policy
    ///   sentinel ([`DEFAULT_POLICY_SENTINEL_ID`], rendered `default-policy` by
    ///   the Go log/display planes). Resolving to the FROZEN positional id here
    ///   would be unsafe: a later reorder can shift a different extant rule into
    ///   that index, so the session would log under the WRONG policy name (the
    ///   AGY correctness catch). An honest "no longer attributable to an extant
    ///   rule" beats a confidently-wrong name.
    /// - `bound = None` (idx-0 non-policy sessions: host-local / neighbor-seed /
    ///   fabric / tunnel; or a peer-synced session carrying only the wire
    ///   scalar) → keep the frozen `stamped` id. There is no local stable
    ///   identity to re-resolve from, so this preserves pre-#3395 behavior. For
    ///   a peer-synced session this is the documented, deferred HA-peer-after-
    ///   reorder residual (P2 — the #3322 "rule-id-on-wire" follow-up).
    /// - `bound = Some(counter)` with an EMPTY `rule_id` (a `Default`
    ///   placeholder that never flowed through `rule_hit_counter`; not produced
    ///   on any production path) → keep the frozen `stamped` id (safe guard).
    #[inline]
    pub(crate) fn reresolve_session_policy_id(
        &self,
        bound: Option<&Arc<PolicyRuleCounter>>,
        stamped: u32,
    ) -> u32 {
        match bound {
            Some(counter) => {
                let rule_id = counter.rule_id();
                if rule_id.is_empty() {
                    return stamped;
                }
                self.rule_id_to_policy_id
                    .get(rule_id)
                    .copied()
                    .unwrap_or(DEFAULT_POLICY_SENTINEL_ID)
            }
            None => stamped,
        }
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

/// Legacy infallible wrapper used by unit tests with hand-built rules and a
/// matching zone table. It passes NO address books, so the book-ID integrity
/// errors cannot fire; but it CAN still panic on a rule-level integrity error
/// (an unknown action #3365, an unrepresentable address/application, or — since
/// #3402 — a zone name absent from `zone_name_to_id`). Tests that exercise those
/// rejection paths must call `parse_policy_state_with_counters` and match the
/// `Err`. Callers here are expected to pass only well-formed rules whose zones
/// resolve.
pub(crate) fn parse_policy_state(
    default_policy: &str,
    rules: &[PolicyRuleSnapshot],
    zone_name_to_id: &FxHashMap<String, u16>,
) -> PolicyState {
    let counter_store = PolicyCounterStore::default();
    parse_policy_state_with_counters(default_policy, rules, zone_name_to_id, &[], &counter_store)
        .expect("parse_policy_state: rules must be well-formed (no books; zones must resolve)")
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
    // #3365: an EMPTY default_policy is the legitimate `omitempty`/unspecified
    // wire state and decodes to the default-deny posture. A NON-EMPTY string
    // that is not permit/reject/deny is rejected (fail closed) rather than
    // silently collapsing to Deny.
    let default_action = if default_policy.is_empty() {
        PolicyAction::Deny
    } else {
        parse_action(default_policy).ok_or_else(|| SnapshotIntegrityError::UnknownPolicyAction {
            context: "default-policy".to_string(),
            action: default_policy.to_string(),
        })?
    };
    let mut state = PolicyState {
        default_action,
        rules: Vec::with_capacity(rules.len()),
        zone_pair_index: FxHashMap::default(),
        from_any_index: FxHashMap::default(),
        to_any_index: FxHashMap::default(),
        both_any_indices: Vec::new(),
        global_indices: Vec::new(),
        books: Vec::with_capacity(address_books.len()),
        book_id_to_idx: FxHashMap::default(),
        // #3019: armed below if any rule names the `junos-host` self zone.
        has_junos_host_rules: false,
        // #3363: persistent reserved counter for the implicit default-policy
        // verdict. Re-handed from the store under the reserved rule id so the
        // Arc instance is stable across snapshot rebuilds (an in-flight
        // default-permit session's bound counter keeps pointing at it).
        default_counter: counter_store.rule_hit_counter(DEFAULT_POLICY_COUNTER_RULE_ID),
        // #3534: set by the snapshot build site (build_forwarding_state_*) from
        // ConfigSnapshot.default_log_session_init/close. Not derived from the
        // policy rules, so the parser leaves them false here; the legacy
        // infallible test helper (parse_policy_state) therefore keeps them off.
        default_log_session_init: false,
        default_log_session_close: false,
        // #3395: populated after the rule loop below (the rules carry both the
        // stable rule_id and the positional policy_id).
        rule_id_to_policy_id: FxHashMap::default(),
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
        //
        // #3711: fail the whole snapshot CLOSED on a malformed OR wrong-family
        // book prefix. The pre-fix builder used the family-agnostic
        // non-reporting parser, which (a) silently dropped an unparseable token
        // — an all-dropped family then collapsed to MatchNone via
        // `from_v3_literals`, so a book-backed `deny` matched nothing and fell
        // through to a later permit / default-permit (fail-OPEN, the v3 sibling
        // of #3367), and (b) routed a wrong-family token into the opposite
        // family's set (M02, contradicting the family-named wire contract).
        // `parse_book_prefix_into` enforces the declared family and reports
        // both failures. Checked in the book loop (before the rule loop) so the
        // whole preflight stays non-mutating and keeps the previous good state.
        let mut v4: Vec<PrefixV4> = Vec::with_capacity(snap.prefixes_v4.len());
        let mut v6: Vec<PrefixV6> = Vec::with_capacity(snap.prefixes_v6.len());
        for s in &snap.prefixes_v4 {
            if !parse_book_prefix_into(s, true, &mut v4, &mut v6) {
                return Err(SnapshotIntegrityError::UnrepresentableAddressBookPrefix {
                    book_id: snap.id,
                    book_name: snap.name.clone(),
                    family: "v4",
                    address: s.clone(),
                });
            }
        }
        for s in &snap.prefixes_v6 {
            if !parse_book_prefix_into(s, false, &mut v4, &mut v6) {
                return Err(SnapshotIntegrityError::UnrepresentableAddressBookPrefix {
                    book_id: snap.id,
                    book_name: snap.name.clone(),
                    family: "v6",
                    address: s.clone(),
                });
            }
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
        // factory. #3367 (legacy path) / #3711 (v3 path): BOTH shapes report a
        // malformed literal (an unparseable token that is not `any` / a family
        // wildcard / the sentinel) so the rule can be failed closed below
        // instead of silently collapsing the side — MatchAny on the empty
        // legacy path (widening a deny), or MatchNone on the v3 path (letting a
        // deny fall through to default-permit).
        let mut legacy_malformed: Option<String> = None;
        let mut v3_malformed: Option<String> = None;
        let (source_literal_v4, source_literal_v6) = if source_is_v3_shaped {
            let (v4, v6, malformed) = parse_v3_literal_set(&snap.source_literals);
            if v3_malformed.is_none() {
                v3_malformed = malformed;
            }
            (v4, v6)
        } else {
            let (v4, v6, malformed) = parse_legacy_address_set(&snap.source_addresses);
            if legacy_malformed.is_none() {
                legacy_malformed = malformed;
            }
            (v4, v6)
        };
        let (destination_literal_v4, destination_literal_v6) = if destination_is_v3_shaped {
            let (v4, v6, malformed) = parse_v3_literal_set(&snap.destination_literals);
            if v3_malformed.is_none() {
                v3_malformed = malformed;
            }
            (v4, v6)
        } else {
            let (v4, v6, malformed) = parse_legacy_address_set(&snap.destination_addresses);
            if legacy_malformed.is_none() {
                legacy_malformed = malformed;
            }
            (v4, v6)
        };

        let rule_id = stable_policy_rule_id(snap);

        // #3261: reject the WHOLE snapshot if the rule carries the
        // unrepresentable-address sentinel (undefined book name, or a defined
        // book whose value is a non-literal dns-name/wildcard/range). Mirrors
        // the application-term `dropped_any` reject below. Without it the
        // address side would silently collapse to MatchNone and a
        // `deny <unrepresentable-address>` rule would fall through to a later
        // permit / default-permit (deny fail-open). Checked BEFORE book
        // resolution and the malformed-literal rejects below; the v3/legacy
        // literal parses above are non-mutating local scratch (#3729 review).
        //
        // #3367/#3711: checked BEFORE the malformed-literal rejects below — the
        // sentinel is the more specific cause (an undefined book / non-literal
        // value the Go gate already flagged), and it parses as malformed too on
        // the v3 path, so the sentinel diagnostic would otherwise be masked by
        // the generic unparseable-literal error.
        if rule_has_unrepresentable_address_sentinel(snap) {
            return Err(SnapshotIntegrityError::UnrepresentableAddress { rule_id });
        }

        // #3711: a malformed v3 address literal (an unparseable token on the
        // `source_literals`/`destination_literals` field that is not `any` / a
        // family wildcard / the sentinel) is a snapshot-integrity error. Without
        // this the side would silently drop the token and collapse to MatchNone
        // (the v3 factory), so a `deny <malformed>` rule would match nothing and
        // fall through to a later permit / default-permit (deny fail-OPEN).
        // Checked BEFORE book resolution so the preflight stays non-mutating.
        if let Some(address) = v3_malformed {
            return Err(SnapshotIntegrityError::UnrepresentableV3Address { rule_id, address });
        }

        // #3367: a malformed legacy address literal (an unparseable token on the
        // `source_addresses`/`destination_addresses` field that is not the
        // sentinel) is a snapshot-integrity error. Without this the side would
        // silently drop the token and collapse to MatchAny on the empty->match-any
        // legacy path, widening a deny rule. Checked BEFORE any book resolution so
        // the preflight stays non-mutating and keeps the previous good state.
        if let Some(address) = legacy_malformed {
            return Err(SnapshotIntegrityError::UnrepresentableLegacyAddress { rule_id, address });
        }

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
        // #3712: fail the whole snapshot closed when an application term carries a
        // semantically-invalid ICMP field combination (icmp-code without
        // icmp-type → match-all-ICMP fail-open; icmp-type/code on a non-ICMP
        // protocol → never-match, letting a deny fall through to default-permit).
        // The Go strict commit gate (#3348) is the primary defense; this is the
        // helper-boundary backstop for the lenient / peer-sync / corrupt-snapshot
        // path, consistent with the #2124/#3367/#3711 fail-closed family.
        if let Some((application, reason)) = parsed.invalid_icmp {
            return Err(SnapshotIntegrityError::InvalidApplicationIcmpFields {
                rule_id: rule_id.clone(),
                application,
                reason,
            });
        }
        let applications = parsed.matches;
        let compiled_apps = CompiledApplications::from_matches(&applications);

        let rule = PolicyRule {
            rule_id: rule_id.clone(),
            policy_id: snap.policy_id,
            from_zone: snap.from_zone.clone(),
            to_zone: snap.to_zone.clone(),
            // #3148: resolve the optional global-policy zone context. Empty →
            // Any (all zones). Inert for non-global rules (both fields empty).
            // #3402: an unresolvable match-zone fails the whole snapshot closed.
            global_from_zone: build_global_zone_scope(
                zone_name_to_id,
                &snap.match_from_zone,
                &rule_id,
            )?,
            global_to_zone: build_global_zone_scope(
                zone_name_to_id,
                &snap.match_to_zone,
                &rule_id,
            )?,
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
            // #3365: every configured rule carries a concrete action; an unknown
            // (or empty) action is rejected fail-closed rather than silently
            // mapped to Deny (which would fail-OPEN an unrecognized reject).
            action: parse_action(&snap.action).ok_or_else(|| {
                SnapshotIntegrityError::UnknownPolicyAction {
                    context: format!("rule {:?}", rule_id),
                    action: snap.action.clone(),
                }
            })?,
            // #2508: carry the per-policy SYSLOG log selection.
            log_session_init: snap.log_session_init,
            log_session_close: snap.log_session_close,
            hit_counter: counter_store.rule_hit_counter(&rule_id),
        };
        let idx = state.rules.len();
        let is_global = rule.from_zone == "junos-global" || rule.to_zone == "junos-global";
        state.rules.push(rule);

        // #3019: arm the LocalDelivery junos-host policy gate iff a rule
        // actually names the reserved self zone on either side.
        //
        // #3639: a GLOBAL policy carries its junos-host context out-of-band in
        // `match_to_zone` (its structural `to_zone` stays "junos-global"), so a
        // `global policy ... match to-zone junos-host` must ALSO arm the gate —
        // otherwise `evaluate_junos_host_policy_l3_aware` short-circuits on
        // `!has_junos_host_rules` and the global-tier host consult below never
        // runs. `match_to_zone` is populated only for globals, so this can never
        // fire for a plain zone-pair rule.
        if snap.from_zone == JUNOS_HOST_ZONE_NAME
            || snap.to_zone == JUNOS_HOST_ZONE_NAME
            || snap.match_to_zone == JUNOS_HOST_ZONE_NAME
        {
            state.has_junos_host_rules = true;
        }

        if is_global {
            state.global_indices.push(idx);
        } else {
            // #3090: classify the rule by its wildcard-zone shape. A from-zone
            // / to-zone literal `any` is the Junos wildcard; it is routed to a
            // dedicated index list so `evaluate_policy_result_with_icmp` can
            // consult it in most-specific-first precedence without an N×N
            // expansion. A concrete zone can never be named `any` (the Go
            // strict validator rejects such a zone definition), so the literal
            // is unambiguously the wildcard. `junos-global` is already handled
            // above; `junos-host` resolves to its reserved id via
            // `resolve_policy_zone_id`.
            let from_any = snap.from_zone == "any";
            let to_any = snap.to_zone == "any";
            match (from_any, to_any) {
                (true, true) => {
                    state.both_any_indices.push(idx);
                }
                (true, false) => match resolve_policy_zone_id(zone_name_to_id, &snap.to_zone) {
                    Some(to_id) => {
                        state.from_any_index.entry(to_id).or_default().push(idx);
                    }
                    // #3402: an unresolvable to-zone fails the whole snapshot
                    // closed (was a stderr-only "rule kept, but not indexed"
                    // drop → silent fall-through to default-policy).
                    None => {
                        return Err(SnapshotIntegrityError::UnresolvableZoneReference {
                            rule_id: rule_id.clone(),
                            zone: snap.to_zone.clone(),
                        });
                    }
                },
                (false, true) => match resolve_policy_zone_id(zone_name_to_id, &snap.from_zone) {
                    Some(from_id) => {
                        state.to_any_index.entry(from_id).or_default().push(idx);
                    }
                    // #3402: an unresolvable from-zone fails closed (see above).
                    None => {
                        return Err(SnapshotIntegrityError::UnresolvableZoneReference {
                            rule_id: rule_id.clone(),
                            zone: snap.from_zone.clone(),
                        });
                    }
                },
                (false, false) => {
                    match (
                        resolve_policy_zone_id(zone_name_to_id, &snap.from_zone),
                        resolve_policy_zone_id(zone_name_to_id, &snap.to_zone),
                    ) {
                        (Some(from_id), Some(to_id)) => {
                            let key = zone_pair_key(from_id, to_id);
                            state.zone_pair_index.entry(key).or_default().push(idx);
                        }
                        // #3402: either side unresolvable → fail closed. Report
                        // the from-zone first (matches the Go strict gate order
                        // in validatePolicyZoneReferencesStrict).
                        (None, _) => {
                            return Err(SnapshotIntegrityError::UnresolvableZoneReference {
                                rule_id: rule_id.clone(),
                                zone: snap.from_zone.clone(),
                            });
                        }
                        (_, None) => {
                            return Err(SnapshotIntegrityError::UnresolvableZoneReference {
                                rule_id: rule_id.clone(),
                                zone: snap.to_zone.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    // #3395: build the O(1) `rule_id → current positional policy_id` map once
    // per snapshot. Each rule carries BOTH its stable `rule_id` and its
    // positional `policy_id` (#3056), so re-resolution at the live-row refresh
    // and the RT_FLOW SESSION_CLOSE emit is a single hash lookup per session
    // (never an O(sessions × rules) scan). The implicit default policy maps to
    // its reserved sentinel so a bound default-PERMIT session (#3363) re-resolves
    // stably to `default-policy` instead of falling into the deleted-rule arm.
    state.rule_id_to_policy_id.reserve(state.rules.len() + 1);
    for rule in &state.rules {
        state
            .rule_id_to_policy_id
            .insert(rule.rule_id.clone(), rule.policy_id);
    }
    state.rule_id_to_policy_id.insert(
        DEFAULT_POLICY_COUNTER_RULE_ID.to_string(),
        DEFAULT_POLICY_SENTINEL_ID,
    );

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
///
/// #3367: the returned `Option<String>` carries the FIRST token that was
/// non-empty, non-`any`, non-family-wildcard, and unparseable as an IP/CIDR.
/// The pre-fix code silently dropped such a token, so an all-malformed list on
/// the empty→MatchAny path collapsed to an unconstrained MatchAny (broadening a
/// deny). The caller fails the whole snapshot closed when this is `Some`.
fn parse_legacy_address_set(addresses: &[String]) -> (PrefixSetV4, PrefixSetV6, Option<String>) {
    let mut any_v4 = false;
    let mut any_v6 = false;
    let mut v4: Vec<PrefixV4> = Vec::new();
    let mut v6: Vec<PrefixV6> = Vec::new();
    let mut malformed: Option<String> = None;
    for tok in addresses {
        match tok.as_str() {
            // Bare `any` is the unconstrained both-families wildcard;
            // it leaves no per-family scoping and falls through to the
            // legacy empty→MatchAny convention below for both families.
            "any" | "" => {}
            "any-ipv4" => any_v4 = true,
            "any-ipv6" => any_v6 = true,
            s => {
                if !parse_address(s, &mut v4, &mut v6) && malformed.is_none() {
                    malformed = Some(s.to_string());
                }
            }
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
    (v4_set, v6_set, malformed)
}

/// #1606: parse the v3 `source_literals` / `destination_literals`
/// field. "any" token forces MatchAny on BOTH families (Codex r5
/// F-r5-1 fix); empty input or no-any → MatchNone (via
/// `from_v3_literals`).
///
/// #3711: the returned `Option<String>` carries the FIRST token that was
/// non-empty, non-`any`/`any4`/`any6`/`any-ipv4`/`any-ipv6`, and unparseable
/// as an IP/CIDR. The pre-fix code called a non-reporting family-agnostic
/// parser, which silently DROPPED such a token; because the v3 side uses
/// `from_v3_literals` (empty -> MatchNone), an all-dropped side collapsed to
/// MatchNone and a `deny <malformed>` rule fell through to a later permit /
/// default-permit (fail-OPEN). The caller fails the whole snapshot closed when
/// this is `Some`. Mirrors the #3367 legacy path exactly, reusing the reporting
/// `parse_address` helper (whose per-token semantics — empty / `any` / family
/// wildcard = OK, everything else must parse — match the pre-fix drop set). The
/// `__unsupported_address__` sentinel is caught earlier by the caller's
/// sentinel preflight, so it never reaches here.
fn parse_v3_literal_set(literals: &[String]) -> (PrefixSetV4, PrefixSetV6, Option<String>) {
    let mut any_v4 = false;
    let mut any_v6 = false;
    let mut v4: Vec<PrefixV4> = Vec::new();
    let mut v6: Vec<PrefixV6> = Vec::new();
    let mut malformed: Option<String> = None;
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
            s => {
                if !parse_address(s, &mut v4, &mut v6) && malformed.is_none() {
                    malformed = Some(s.to_string());
                }
            }
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
    (v4_set, v6_set, malformed)
}

/// #3711: parse an address-book prefix token that MUST belong to the declared
/// family (`expect_v4` selects the `prefixes_v4` vs `prefixes_v6` array).
/// Returns `true` if the token parsed into the EXPECTED family or is a legit
/// empty / bare-`any` placeholder; `false` if it is malformed OR belongs to the
/// WRONG family (M02: an IPv6 token in `prefixes_v4` is rejected, not silently
/// routed into the v6 set — and vice versa). This is the reporting,
/// family-enforcing replacement for the pre-fix family-agnostic parser: the
/// book builder fails the whole snapshot CLOSED on `false` rather than dropping
/// the token (which collapsed a book-backed deny to match-none — a fail-OPEN).
/// The per-token acceptance set (empty / `any` no-op; `any-ipv4`/`any-ipv6`
/// same-family wildcards; IP/CIDR of the expected family) matches what the Go
/// side emits after its family split; a wrong-family wildcard or literal is a
/// wire-contract violation and is rejected.
fn parse_book_prefix_into(
    prefix: &str,
    expect_v4: bool,
    out_v4: &mut Vec<PrefixV4>,
    out_v6: &mut Vec<PrefixV6>,
) -> bool {
    // Legit no-op placeholders contribute nothing to either family. The Go side
    // never emits them into a family array (it emits concrete family-split
    // CIDRs), but accept them so a degenerate snapshot does not hard-fail on a
    // semantically empty token.
    if prefix.is_empty() || prefix == "any" {
        return true;
    }
    // #2008 H11: the Junos family-scoped wildcards expand to the concrete
    // all-addresses prefix of their family. Only the wildcard MATCHING the
    // declared array is accepted (family enforcement — M02).
    if prefix == "any-ipv4" {
        if !expect_v4 {
            return false;
        }
        out_v4.push(PrefixV4::from_net(
            ipnet::Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("v4 /0"),
        ));
        return true;
    }
    if prefix == "any-ipv6" {
        if expect_v4 {
            return false;
        }
        out_v6.push(PrefixV6::from_net(
            ipnet::Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).expect("v6 /0"),
        ));
        return true;
    }
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => {
            if !expect_v4 {
                return false;
            }
            out_v4.push(PrefixV4::from_net(net));
            true
        }
        Ok(IpNet::V6(net)) => {
            if expect_v4 {
                return false;
            }
            out_v6.push(PrefixV6::from_net(net));
            true
        }
        Err(_) => {
            if let Ok(ip) = prefix.parse::<Ipv4Addr>() {
                if !expect_v4 {
                    return false;
                }
                out_v4.push(PrefixV4::from_net(
                    ipnet::Ipv4Net::new(ip, 32).expect("v4 /32"),
                ));
                true
            } else if let Ok(ip) = prefix.parse::<Ipv6Addr>() {
                if expect_v4 {
                    return false;
                }
                out_v6.push(PrefixV6::from_net(
                    ipnet::Ipv6Net::new(ip, 128).expect("v6 /128"),
                ));
                true
            } else {
                false
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

/// Back-compat entry point with no ICMP type/code awareness (#3020): delegates
/// to [`evaluate_policy_result_with_icmp`] with `packet_icmp = None`, so an
/// icmp-type-constrained application term (junos-ping) does not match (fail
/// closed) when the caller has no type/code. Non-ICMP flows are unaffected.
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
    evaluate_policy_result_with_icmp(
        state, from_id, to_id, src_ip, dst_ip, protocol, src_port, dst_port, None, packet_len,
    )
}

/// #3020: ICMP-aware policy evaluation. `packet_icmp` is the packet's
/// ICMP/ICMPv6 `(type, code)` for ICMP-family flows whose L4 header was safely
/// readable, else `None`. It gates the icmp-type-constrained application terms
/// (junos-ping = echo-request only); non-ICMP flows pass `None` and are
/// unaffected. The forwarding path (poll_descriptor) calls this directly with
/// the per-packet type/code; the back-compat `evaluate_policy_result_with_len`
/// and the `evaluate_policy*` test/legacy wrappers pass `None`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_policy_result_with_icmp(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_icmp: Option<(u8, u8)>,
    packet_len: u64,
) -> PolicyEvaluationResult {
    // Flow-backed callers always carry a real L4 header (the 5-tuple ports are
    // authoritative), so delegate with `l4_present = true` — byte-identical to
    // the pre-#3291 behavior.
    evaluate_policy_result_l3_aware(
        state, from_id, to_id, src_ip, dst_ip, protocol, src_port, dst_port, packet_icmp,
        packet_len, true,
    )
}

/// #3291: L4-presence-aware policy evaluation. `l4_present = false` marks a
/// flowless / no-L4 packet (a non-first IPv4/IPv6 fragment, #2344) whose post-IP
/// bytes are payload, so `src_port`/`dst_port` are 0 and MUST NOT be trusted:
/// port-bearing application terms fail closed (`try_match_rule` → `matches`),
/// while address/protocol/`any` terms still evaluate on the L3 identity the
/// fragment does carry. This is the zone-policy half of the flowless transit
/// enforcement gate (the input-filter and PBR halves live in the forwarding
/// path). The synthetic L3 tuple this is called with is used ONLY for evaluation
/// + logging and is NEVER installed as a session.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_policy_result_l3_aware(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_icmp: Option<(u8, u8)>,
    packet_len: u64,
    l4_present: bool,
) -> PolicyEvaluationResult {
    // #3110: zone id 0 is the reserved "unknown / no zone" sentinel
    // (assigned to interfaces not bound to any security zone, and to the
    // over-cap-zone collapse-to-0 path, #2391). A flow whose ingress OR
    // egress zone is unknown does not belong to any DEFINED zone pair, so
    // it must NOT be eligible for zone-pair policies OR `junos-global`
    // policies — global rules apply to all *defined* zone pairs, never to
    // unzoned transit. Fall straight through to the default action so an
    // operator's permit-global cannot leak transit on an unzoned
    // ingress/egress interface. Composes with the default-policy
    // fail-closed (#3065) and wildcard-zone work (#3018); the
    // `junos-global` sentinel (u16::MAX) is a DEFINED global zone, distinct
    // from 0 (unknown), and is unaffected by this guard.
    if from_id != 0 && to_id != 0 {
        let key = zone_pair_key(from_id, to_id);
        if let Some(indices) = state.zone_pair_index.get(&key) {
            for &idx in indices {
                if let Some(mut result) = try_match_rule(
                    &state.rules[idx],
                    state,
                    src_ip,
                    dst_ip,
                    protocol,
                    src_port,
                    dst_port,
                    packet_icmp,
                    packet_len,
                    l4_present,
                ) {
                    // #3073: 1-based handle so the fast path can re-count
                    // every packet of this flow against the same counter.
                    result.policy_counter_idx = (idx as u32).saturating_add(1);
                    return result;
                }
            }
        }
        // #3090: wildcard-zone tiers, in Junos most-specific-first precedence
        // AFTER the exact zone pair and BEFORE global/default.
        //
        //  Tier 1 — single wildcard: `from-zone any` (keyed by to_id) and
        //  `to-zone any` (keyed by from_id). The two lists are merged in
        //  config (ascending rule-index) order so a rule's relative position
        //  is honored regardless of which wildcard side it used — e.g. a
        //  `from-zone any to-zone trust deny` configured before a `from-zone
        //  untrust to-zone any permit` wins for an untrust->trust flow.
        //
        //  Tier 2 — both-any: `from-zone any to-zone any` in config order.
        //
        // Each tier is a single FxHashMap O(1) lookup (or a Vec scan only when
        // such rules exist), so a config with no wildcard policy pays only two
        // empty-slice probes per cold-path evaluation — no N×N materialization.
        let from_any = state
            .from_any_index
            .get(&to_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let to_any = state
            .to_any_index
            .get(&from_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let mut i = 0usize;
        let mut j = 0usize;
        while i < from_any.len() || j < to_any.len() {
            // Both slices are ascending (rules are appended in config order),
            // so a two-pointer merge yields global config order. Indices are
            // unique across the buckets (each rule lands in exactly one), so no
            // dedup is needed.
            let idx = if j >= to_any.len() || (i < from_any.len() && from_any[i] <= to_any[j]) {
                let v = from_any[i];
                i += 1;
                v
            } else {
                let v = to_any[j];
                j += 1;
                v
            };
            if let Some(mut result) = try_match_rule(
                &state.rules[idx],
                state,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                packet_icmp,
                packet_len,
                l4_present,
            ) {
                result.policy_counter_idx = (idx as u32).saturating_add(1);
                return result;
            }
        }
        for &idx in &state.both_any_indices {
            if let Some(mut result) = try_match_rule(
                &state.rules[idx],
                state,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                packet_icmp,
                packet_len,
                l4_present,
            ) {
                result.policy_counter_idx = (idx as u32).saturating_add(1);
                return result;
            }
        }
        for &idx in &state.global_indices {
            let rule = &state.rules[idx];
            // #3148: a global policy may carry optional from-zone/to-zone match
            // context. When present it matches only the configured zone(s);
            // when absent (Any) it applies to every defined zone pair as
            // before. The scope check runs in the GLOBAL tier (after the exact
            // zone-pair and #3090 from-any/to-any/both-any wildcard tiers), in
            // global config order, so a zone-scoped global policy stays a
            // global policy — it does not get promoted ahead of the wildcard
            // tiers. A typo'd (unresolvable) match-zone never reaches here: it
            // fails the whole snapshot closed at parse time (#3402,
            // SnapshotIntegrityError::UnresolvableZoneReference), so a live
            // scope is only ever Any or a resolved Zone(id).
            if !rule.global_from_zone.matches(from_id) || !rule.global_to_zone.matches(to_id) {
                continue;
            }
            if let Some(mut result) = try_match_rule(
                rule,
                state,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                packet_icmp,
                packet_len,
                l4_present,
            ) {
                // #3073: 1-based handle (see zone-pair branch above).
                result.policy_counter_idx = (idx as u32).saturating_add(1);
                return result;
            }
        }
    }
    // #3363: count the implicit default-policy verdict on the cold path. For
    // default-DENY this is the ONLY count (a denied flow installs no session,
    // so every dropped packet re-evaluates here); for default-PERMIT this is
    // the first-packet count and the established fast path re-counts the rest
    // via the reserved handle below. Mirrors the per-rule `rule.hit_counter.add`
    // in `try_match_rule`.
    state.default_counter.add(packet_len);
    PolicyEvaluationResult {
        action: state.default_action,
        // #3057: the implicit default-policy carries a reserved sentinel ID,
        // NOT 0. Emitting 0 here aliased the FIRST configured policy (also ID
        // 0), so a default-policy deny logged as that rule's name — actively
        // misleading when the first rule is a permit. The sentinel is rendered
        // as `default-policy` by the Go log/display planes.
        policy_id: DEFAULT_POLICY_SENTINEL_ID,
        // #3534 (was #2508 "no selection"): the implicit default policy now
        // carries the operator's `security policies default-policy-log
        // session-init|session-close` selection. For a default-PERMIT verdict
        // these flags are stamped onto the installed session's metadata (the
        // session-create hot path reads PolicyEvaluationResult.log_session_*),
        // so the default-permit session emits RT_FLOW_SESSION_CREATE/CLOSE like
        // a named policy's `then log`. A default-DENY/REJECT verdict installs no
        // session, so the flags are inert there (the deny is already logged via
        // the unconditional policy-deny RT_FLOW record). Stamping them
        // unconditionally is correct: the deny path never reads these fields.
        log_session_init: state.default_log_session_init,
        log_session_close: state.default_log_session_close,
        // #3227: the implicit default policy carries no per-app timeout; the
        // session ages on the global per-protocol timeout (today's behavior).
        inactivity_timeout: None,
        // #3363: reserved default-policy hit-counter handle (was 0 = "no
        // counter"). Stamped onto a default-PERMIT session at install so the
        // established fast path re-counts every packet against `default_counter`.
        policy_counter_idx: DEFAULT_POLICY_COUNTER_IDX,
    }
}

/// #3019: resolve a policy rule's from/to zone NAME to a numeric id, mapping
/// the reserved `junos-host` self zone to [`JUNOS_HOST_ZONE_ID`]. A configured
/// zone can never be named `junos-host` (the Go strict validator + definition
/// gate reject it), so this never shadows a real zone. All other names resolve
/// through `zone_name_to_id` exactly as before.
fn resolve_policy_zone_id(
    zone_name_to_id: &FxHashMap<String, u16>,
    name: &str,
) -> Option<u16> {
    if name == JUNOS_HOST_ZONE_NAME {
        Some(JUNOS_HOST_ZONE_ID)
    } else {
        zone_name_to_id.get(name).copied()
    }
}

/// #3019: evaluate a configured `to-zone junos-host` security policy for a
/// host-bound (LocalDelivery) flow whose ingress (from) zone id is `from_id`.
/// Consulted in Junos most-specific-first precedence: the exact `from-zone
/// <ingress> to-zone junos-host` pair, then the `from-zone any to-zone
/// junos-host` wildcard (#3090), then a GLOBAL policy `match to-zone
/// junos-host` (#3639, least-specific — a scoped global stays a global and is
/// never promoted ahead of a zone-pair rule).
///
/// Junos ordering: host-inbound-traffic admission runs FIRST in the caller; a
/// packet only reaches this gate after host-inbound has admitted it, so a
/// `then permit` here can never override a host-inbound reject.
///
/// CONSERVATIVE / FAIL-SAFE semantics, by design (#3019 brief): enforcement is
/// strictly MATCH-DRIVEN. Returns:
///   - `None` when no `junos-host` policy is configured at all
///     (`has_junos_host_rules == false`), when the ingress zone is unknown
///     (id 0, mirroring the #3110 unzoned guard), or when no `junos-host` rule
///     MATCHES the flow.
///   - `Some(result)` only when a `to-zone junos-host` rule MATCHES.
///
/// Crucially there is NO implicit default-deny here: an unmatched host-bound
/// flow falls through to today's behavior (local delivery proceeds). This is
/// the deliberate lifeline guarantee — configuring some junos-host policy
/// cannot silently brick management/host traffic that does not match a deny
/// rule. The stricter Junos "configured zone-pair implies default-deny"
/// posture is intentionally deferred (see docs/junos-cli-reference.md).
///
/// `from-zone junos-host` (host-ORIGINATED) rules — whether zone-pair or a
/// GLOBAL `match from-zone junos-host` — are NOT consulted here: locally
/// generated traffic egresses via the kernel TX path and does not traverse the
/// ingress LocalDelivery path. That direction is rejected at commit and is a
/// documented follow-up (#3611 Piece A).
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_junos_host_policy(
    state: &PolicyState,
    from_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_icmp: Option<(u8, u8)>,
    packet_len: u64,
) -> Option<PolicyEvaluationResult> {
    // #3292: flow-backed and test callers carry a real L4 header — delegate
    // with `l4_present = true`, byte-identical to pre-#3292. Only the flowless
    // LocalDelivery arm calls `evaluate_junos_host_policy_l3_aware` directly
    // (mirrors the #3291 `evaluate_policy_result_with_icmp` wrapper split).
    evaluate_junos_host_policy_l3_aware(
        state, from_id, src_ip, dst_ip, protocol, src_port, dst_port, packet_icmp,
        packet_len, true,
    )
}

/// #3292: L4-presence-aware `junos-host` policy evaluation. `l4_present = false`
/// marks a flowless / no-L4 packet (a non-first fragment on the flowless
/// LocalDelivery arm); port-bearing application terms then fail closed while
/// `application any` / address / protocol terms still match. The
/// `evaluate_junos_host_policy` wrapper delegates here with `l4_present = true`,
/// so the L4 (flow-backed / test) path is byte-identical to before.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_junos_host_policy_l3_aware(
    state: &PolicyState,
    from_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    packet_icmp: Option<(u8, u8)>,
    packet_len: u64,
    l4_present: bool,
) -> Option<PolicyEvaluationResult> {
    if !state.has_junos_host_rules || from_id == 0 {
        return None;
    }
    // Most-specific first: an exact `from-zone <ingress> to-zone junos-host`
    // pair before the `from-zone any to-zone junos-host` wildcard.
    let key = zone_pair_key(from_id, JUNOS_HOST_ZONE_ID);
    if let Some(indices) = state.zone_pair_index.get(&key) {
        for &idx in indices {
            if let Some(mut result) = try_match_rule(
                &state.rules[idx],
                state,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                packet_icmp,
                packet_len,
                // #3292: `l4_present` is false only on the flowless
                // LocalDelivery arm (a non-first fragment); port-bearing
                // application terms then fail closed.
                l4_present,
            ) {
                // #3073: 1-based handle (see `evaluate_policy_result_with_icmp`).
                result.policy_counter_idx = (idx as u32).saturating_add(1);
                return Some(result);
            }
        }
    }
    // #3090: a `from-zone any to-zone junos-host` wildcard governs host-bound
    // traffic from EVERY ingress zone. It MUST be consulted here — once the
    // #3018 interim commit reject is lifted such a rule commits, and leaving it
    // unindexed on the host path would re-introduce the exact silent fail-open
    // #3018 closed. `to-zone any` / `from-zone any to-zone any` are deliberately
    // NOT pulled into the host path: the junos-host gate stays conservative and
    // strictly match-driven (no implicit default-deny — see this function's doc
    // comment), mirroring the existing rule that global policies are not applied
    // to host-bound traffic, so a broad `to any` rule cannot silently brick the
    // management lifeline.
    if let Some(indices) = state.from_any_index.get(&JUNOS_HOST_ZONE_ID) {
        for &idx in indices {
            if let Some(mut result) = try_match_rule(
                &state.rules[idx],
                state,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                packet_icmp,
                packet_len,
                // #3292: `l4_present` is false only on the flowless
                // LocalDelivery arm (a non-first fragment); port-bearing
                // application terms then fail closed.
                l4_present,
            ) {
                result.policy_counter_idx = (idx as u32).saturating_add(1);
                return Some(result);
            }
        }
    }
    // #3639: a GLOBAL policy `match to-zone junos-host` (host-INBOUND) governs
    // host-bound traffic in the GLOBAL tier — evaluated LAST here, AFTER the
    // exact `from-zone <ingress> to-zone junos-host` pair and the `from-zone any
    // to-zone junos-host` wildcard, mirroring transit-policy precedence (a
    // global policy is least-specific and is never promoted ahead of a
    // zone-pair rule; see evaluate_policy_result_l3_aware). Only globals scoped
    // to the junos-host EGRESS side are consulted; the optional `match
    // from-zone` scope still restricts by ingress zone (Any = every zone, the
    // `from-zone any to-zone junos-host` global the #3639 commit-reject lift
    // enables). This is the enforcement half the reject lift is coupled with —
    // lifting the commit reject without consulting here would re-open the exact
    // silent fail-open the #3018/#3148 reject closed. A `from-zone junos-host`
    // global (host-ORIGINATED) is NOT consulted: that direction never traverses
    // the RX LocalDelivery gate and is rejected at commit (#3611 Piece A).
    for &idx in &state.global_indices {
        let rule = &state.rules[idx];
        if rule.global_to_zone != GlobalZoneScope::Zone(JUNOS_HOST_ZONE_ID)
            || !rule.global_from_zone.matches(from_id)
        {
            continue;
        }
        if let Some(mut result) = try_match_rule(
            rule,
            state,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            packet_icmp,
            packet_len,
            l4_present,
        ) {
            result.policy_counter_idx = (idx as u32).saturating_add(1);
            return Some(result);
        }
    }
    None
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
    packet_icmp: Option<(u8, u8)>,
    packet_len: u64,
    l4_present: bool,
) -> Option<PolicyEvaluationResult> {
    if rule.inactive {
        return None;
    }
    // #3227: `matches` now returns the matched application term's optional
    // inactivity timeout (`None` outer = no app match → rule does not apply).
    // #3291: `l4_present` fails port-bearing application terms closed for a
    // flowless / no-L4 packet (a non-first fragment) — see `matches`.
    let app_inactivity_timeout =
        rule.compiled_apps
            .matches(protocol, src_port, dst_port, packet_icmp, l4_present)?;
    // #2008 H2: when a side is `*-excluded`, the rule matches every
    // address EXCEPT those in the configured set, so the match-any
    // short-circuit must NOT apply (it would always-match and the
    // inversion would always-FAIL the side). Compute the raw
    // "address is in the set" predicate, then XOR with the excluded
    // flag: matched != excluded.
    //
    // #2008 fail-open hardening: an `*-excluded` side whose configured
    // set is EMPTY would invert into match-ALL — a silent security
    // bypass (a rule meant to exclude one address matches everything).
    // Fail CLOSED only when the set is empty across BOTH families: that
    // is the genuine typo/parse-drop signal. #3023: when the packet's
    // family list is empty but the OTHER family is populated, the
    // operator legitimately listed only one family — an address in the
    // packet's family is then trivially NOT in the excluded set, so the
    // side matches. Fail-closing on the per-family empty flag alone
    // over-blocked that legitimate cross-family case (a v6-only
    // exclusion silently dropped all v4 traffic on a permit rule).
    let (src_ok, dst_ok) = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let src_ok = if rule.source_excluded {
                !(rule.source_v4_empty && rule.source_v6_empty)
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
                !(rule.destination_v4_empty && rule.destination_v6_empty)
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
                !(rule.source_v4_empty && rule.source_v6_empty)
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
                !(rule.destination_v4_empty && rule.destination_v6_empty)
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
        // #2358: cross-family NAT64 inbound tuple — IPv6 source (the v6
        // client) with the POST-translation IPv4 destination (the real
        // internal server the synthetic NAT64 address was extracted to).
        // Junos/SRX evaluates the inbound security policy AFTER destination
        // translation, so a NAT64 policy is authored against the real IPv4
        // host + its destination zone, with the source matched in the IPv6
        // ingress zone. The forwarding path (poll_descriptor) feeds this
        // mixed tuple ONLY for NAT64 (the source stays v6, the dst is the
        // extracted v4); no other flow produces a (V6 src, V4 dst) tuple,
        // so this arm is inert for non-NAT64 traffic. The source side
        // matches the rule's IPv6 source set; the destination side matches
        // the rule's IPv4 destination set. The `*-excluded` empty-set
        // fail-closed and per-family any-match semantics mirror the
        // same-family arms above.
        (IpAddr::V6(src), IpAddr::V4(dst)) => {
            let src_ok = if rule.source_excluded {
                !(rule.source_v4_empty && rule.source_v6_empty)
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
                !(rule.destination_v4_empty && rule.destination_v6_empty)
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
        // (V4 src, V6 dst) has no inbound translation that produces it
        // (NAT46 is not supported), so it never matches — fail closed.
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
            // #3227: surface the matched application term's idle timeout so the
            // install path can stamp it onto the admitted session.
            inactivity_timeout: app_inactivity_timeout,
            // #3073: set by the caller (`evaluate_policy_result_with_icmp`),
            // which knows this rule's stable index. `try_match_rule` itself
            // has only `&rule`, so it leaves the sentinel here.
            policy_counter_idx: 0,
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

/// #3365: parse a wire action token into a `PolicyAction`. Returns `None` for
/// any string that is not one of the three known tokens so the caller can fail
/// the snapshot closed instead of silently collapsing an unrecognized action
/// (e.g. a future `reject-*` variant, a typo, or a corrupt token) to Deny. The
/// empty string is intentionally NOT recognized here; callers decide whether an
/// empty value is a legitimate unspecified state (snapshot `default_policy`,
/// `omitempty` on the wire) or a hard error (a per-rule action).
fn parse_action(action: &str) -> Option<PolicyAction> {
    match action {
        "permit" => Some(PolicyAction::Permit),
        "reject" => Some(PolicyAction::Reject),
        "deny" => Some(PolicyAction::Deny),
        _ => None,
    }
}

/// Parse one legacy address literal into the per-family prefix vectors. Returns
/// `true` when the token was represented (a placeholder `any`/empty, a
/// family-scoped wildcard, or a successfully-parsed IP/CIDR literal) and `false`
/// when a NON-placeholder token failed to parse as an IP or CIDR. #3367: the
/// caller (`parse_legacy_address_set`) propagates a `false` up so the policy
/// builder can fail the snapshot closed rather than silently dropping the token
/// (which on the empty->match-any legacy path widens a deny rule to match-any).
fn parse_address(prefix: &str, out_v4: &mut Vec<PrefixV4>, out_v6: &mut Vec<PrefixV6>) -> bool {
    if prefix.is_empty() || prefix == "any" {
        return true;
    }
    // #2008 H11: family-scoped wildcards (see parse_book_prefix_into).
    if prefix == "any-ipv4" {
        out_v4.push(PrefixV4::from_net(
            ipnet::Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("v4 /0"),
        ));
        return true;
    }
    if prefix == "any-ipv6" {
        out_v6.push(PrefixV6::from_net(
            ipnet::Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).expect("v6 /0"),
        ));
        return true;
    }
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => {
            out_v4.push(PrefixV4::from_net(net));
            true
        }
        Ok(IpNet::V6(net)) => {
            out_v6.push(PrefixV6::from_net(net));
            true
        }
        Err(_) => {
            if let Ok(ip) = prefix.parse::<Ipv4Addr>() {
                out_v4.push(PrefixV4::from_net(
                    ipnet::Ipv4Net::new(ip, 32).expect("v4 /32"),
                ));
                true
            } else if let Ok(ip) = prefix.parse::<Ipv6Addr>() {
                out_v6.push(PrefixV6::from_net(
                    ipnet::Ipv6Net::new(ip, 128).expect("v6 /128"),
                ));
                true
            } else {
                // #3367: a non-empty, non-placeholder token that is neither an IP
                // nor a CIDR. Signal the malformed literal to the caller.
                false
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
    /// #3712: the FIRST application term found with a semantically-invalid ICMP
    /// field combination — `(application name, reason)`. `None` when every term
    /// is well-formed. The caller fails the whole snapshot closed via
    /// `SnapshotIntegrityError::InvalidApplicationIcmpFields`, naming the rule
    /// (which `parse_applications` does not have). Detected regardless of
    /// `dropped_any` so a rule mixing a bad-ICMP term with an unparseable one
    /// still surfaces the ICMP diagnostic when protocol/port parse.
    invalid_icmp: Option<(String, &'static str)>,
}

fn parse_applications(terms: &[PolicyApplicationSnapshot]) -> ParsedApplications {
    let mut out = Vec::with_capacity(terms.len());
    let mut dropped_any = false;
    let mut invalid_icmp: Option<(String, &'static str)> = None;
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
        // #3712: reject the two semantically-invalid ICMP field combinations the
        // compiled matcher (`from_matches`/`matches`) would otherwise turn into a
        // wrong-behaving term. Record the FIRST offender; the caller rejects the
        // whole snapshot fail-closed (see `InvalidApplicationIcmpFields`). The
        // non-ICMP-protocol case is checked first because on a non-ICMP protocol
        // ANY icmp field is meaningless (the term can never match), whereas the
        // code-without-type case is only relevant once the protocol is ICMP.
        if invalid_icmp.is_none() {
            let icmp_family = protocol == PROTO_ICMP || protocol == PROTO_ICMPV6;
            if (term.icmp_type.is_some() || term.icmp_code.is_some()) && !icmp_family {
                invalid_icmp = Some((
                    term.name.clone(),
                    "icmp-type/icmp-code set on a non-ICMP protocol",
                ));
            } else if term.icmp_code.is_some() && term.icmp_type.is_none() {
                invalid_icmp = Some((term.name.clone(), "icmp-code set without icmp-type"));
            }
        }
        out.push(ApplicationMatch {
            protocol,
            source_ports,
            destination_ports,
            // #3020: carry the optional ICMP type/code constraint through to the
            // compiled matcher. A non-ICMP term simply has these as None.
            icmp_type: term.icmp_type,
            icmp_code: term.icmp_code,
            // #3227: carry the per-application inactivity timeout through to the
            // compiled matcher so a session admitted by this term can stamp it.
            // A 0 seconds value collapses to None (use-global) so the override
            // is only set when the operator configured a positive timeout.
            inactivity_timeout: term.inactivity_timeout.filter(|&t| t > 0),
        });
    }
    ParsedApplications {
        matches: out,
        dropped_any,
        invalid_icmp,
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
        let low = parse_port_u16(low)?;
        let high = parse_port_u16(high)?;
        if low == 0 || low > high {
            return None;
        }
        return Some(vec![PortRange { low, high }]);
    }
    let port = parse_port_u16(normalized)?;
    if port == 0 {
        return None;
    }
    Some(vec![PortRange {
        low: port,
        high: port,
    }])
}

// parse_port_u16 parses a canonical unsigned decimal port token. Rust's u16
// FromStr accepts a leading '+' ("+80" -> Ok(80)), but Junos and the Go commit
// gate (validatePortSpec -> parseCanonicalPort) reject a signed / non-canonical
// port, and the Go capability gate userspacePortSpecRepresentable parses with
// strconv.ParseUint (which also rejects the sign). Accepting "+80" here left
// parse_port_spec MORE lenient than both Go gates — a parser divergence on a
// security leaf (#3606). Reject any token that is not a bare run of ASCII
// decimal digits so all three parsers agree.
fn parse_port_u16(tok: &str) -> Option<u16> {
    if tok.is_empty() || !tok.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    tok.parse::<u16>().ok()
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
