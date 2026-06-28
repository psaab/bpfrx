// Package policymatch is the single operator-side security-policy simulator
// shared by the REST `match-policies` handler, the gRPC `MatchPolicies` RPC,
// and the CLI `show security match-policies` command.
//
// Before #3042 each of those three surfaces carried its own hand-written
// shadow matcher, and all three diverged from the runtime policy evaluator in
// userspace-dp/src/policy.rs in ways that made the diagnostic return the
// OPPOSITE of what the dataplane actually does:
//
//   - they looped only cfg.Security.Policies (the zone-pair sets) and never
//     consulted cfg.Security.GlobalPolicies, so a flow admitted/denied by a
//     `policy global` rule was reported as the default action;
//   - they hard-coded "deny (default)" on a miss even when
//     `default-policy permit-all` was active;
//   - their address matcher handled only `any` plus address-book names/sets —
//     no literal CIDRs, no `any-ipv4`/`any-ipv6`, no source/destination
//     `*-address-excluded` exclusion flags, and no dynamic-address feed
//     overlay;
//   - their application matcher read only cfg.Applications.Applications, so a
//     predefined Junos application (junos-http, ...) never matched, only one
//     application-set level was expanded, and source-port terms were ignored.
//
// This package replicates the runtime precedence and semantics exactly. The
// ground truth is userspace-dp/src/policy.rs (evaluate_policy_result_with_len
// + try_match_rule + parse_v3_literal_set + CompiledApplications) fed by the
// Go snapshot builder (pkg/dataplane/userspace/policies.go). Where the runtime
// and the old per-surface matchers disagreed, the runtime wins.
//
// Note on scheduler state (#3104): the runtime honors a policy's
// scheduler-driven `inactive` flag — policy.rs try_match_rule returns None for
// an inactive rule BEFORE app/address matching, and the snapshot builder
// (pkg/dataplane/userspace/policies.go) stamps that Inactive flag and fails
// closed on missing scheduler state. This simulator is schedule-aware when the
// caller threads live per-scheduler active-state into Query.PolicyInactiveFn:
// it then SKIPS a scheduler-inactive policy exactly like the runtime, falling
// through to the next active rule / configured default-policy. When
// PolicyInactiveFn is nil (the caller has no live scheduler state — an offline
// surface, or the daemon-local dataplane has not published state yet), the
// simulator falls back to evaluating the configured policy set as-if-active,
// matching both the pre-#3042 surfaces and the #3062 display fallback. A
// NON-scheduled policy is unaffected in either case: PolicyInactiveFn is only
// ever consulted with a policy's scheduler name, and the SSOT predicate
// (dataplane/userspace.PolicyInactive) reports an empty scheduler name as
// always active.
package policymatch

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
)

// MaxPort is the largest valid TCP/UDP port number.
const MaxPort = 65535

// icmpProtoNum / icmpv6ProtoNum are the IANA protocol numbers for ICMP and
// ICMPv6. They gate an ICMP-type-constrained application term (#3284) so it can
// only match an ICMP-family flow, mirroring the dataplane keying its
// icmp_constraints under the ICMP protocol (policy.rs CompiledApplications).
const (
	icmpProtoNum   uint8 = 1
	icmpv6ProtoNum uint8 = 58
)

// JunosHostZone is the reserved self-traffic zone name. A query whose ToZone is
// this name is host-bound (LocalDelivery) traffic; it is evaluated by the
// dataplane's separate host gate (evaluate_junos_host_policy), not the transit
// precedence chain. See matchJunosHost / Result.HostInboundUnmatched (#3285).
const JunosHostZone = "junos-host"

// ValidatePort checks an already-parsed simulator port value (the gRPC int32
// field and the REST query int, which arrive numeric). A zero value means
// "unspecified" — the port dimension is not constrained, the established
// wildcard behavior — and is accepted. Any other value outside [1, MaxPort]
// (negative, or above the 16-bit port space) cannot describe a real packet, so
// it is REJECTED with an error rather than silently coerced to the 0 wildcard
// (#3116). The shared matcher gates the port term on dstPort/srcPort > 0, so a
// malformed/negative/out-of-range value that slips through silently becomes
// "no port constraint" and yields a verdict for a packet that cannot exist.
func ValidatePort(port int) error {
	if port < 0 || port > MaxPort {
		return fmt.Errorf("port %d out of range (0-%d, 0 = unspecified)", port, MaxPort)
	}
	return nil
}

// ParsePort parses a simulator port token supplied as an operator string (the
// CLI surface). An empty/whitespace token means "unspecified" and returns
// (0, nil) — the wildcard behavior, unchanged. A non-empty token must parse to
// an integer that ValidatePort accepts ([0, MaxPort]); a malformed ("abc"),
// negative, or >MaxPort token is REJECTED with an error so it can never
// silently degrade to the 0 wildcard (#3116). An explicit "0" is accepted as
// "unspecified" for parity with the gRPC int field, where proto3 cannot
// distinguish an unset scalar from 0.
func ParsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if err := ValidatePort(n); err != nil {
		return 0, err
	}
	return n, nil
}

// ParseICMPValue parses an operator-supplied ICMP type or code token (#3284)
// into a *uint8 the simulator threads into Query.ICMPType / Query.ICMPCode. An
// empty/whitespace token means "unspecified" and returns (nil, nil) — the
// dimension is not constrained, the established wildcard behavior. A non-empty
// token must parse to an integer in [0, 255] (the 8-bit ICMP type/code space);
// a malformed, negative, or >255 token is REJECTED with an error so it can
// never silently degrade to the nil wildcard. The pointer return distinguishes
// "unspecified" from a valid 0 (ICMP type 0 = echo-reply, code 0 is common).
func ParseICMPValue(s string) (*uint8, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return nil, fmt.Errorf("invalid icmp type/code %q", s)
	}
	if n < 0 || n > 255 {
		return nil, fmt.Errorf("icmp type/code %d out of range (0-255)", n)
	}
	v := uint8(n)
	return &v, nil
}

// ValidateProtocol checks an explicitly-supplied simulator protocol token. An
// empty/whitespace token means "unspecified" — the protocol dimension is not
// constrained (the established match-any wildcard) — and is accepted. A
// non-empty token must resolve to an IANA protocol number via
// appid.ProtocolNumber: a known name/alias ("tcp", "udp", "icmp", "ospf", ...)
// or a numeric value in 0-255. An unknown name ("notaproto") or an
// out-of-range / non-numeric value ("999", "tcpp") is REJECTED with an error
// rather than silently treated as "any protocol" (#3108).
//
// This is the protocol analogue of ValidatePort/ParsePort (#3116). The shared
// matcher (matchApp) short-circuits to match-any when the query protocol is the
// empty string, so an invalid token that slips through unvalidated silently
// becomes "no protocol constraint" and yields a permit/deny verdict for traffic
// that cannot exist — masking an operator typo. There is no "any" protocol
// keyword: omit the token (empty) for the protocol wildcard, matching the
// runtime evaluator which constrains the protocol dimension only when a
// resolvable protocol is supplied.
//
// A single string validator covers every simulator surface (REST query, gRPC
// field, CLI/remote-cli token, gRPC test-policy), since each accepts the
// protocol as a string that matchApp resolves identically by name or number.
func ValidateProtocol(proto string) error {
	if strings.TrimSpace(proto) == "" {
		return nil
	}
	if _, ok := appid.ProtocolNumber(proto); !ok {
		return fmt.Errorf("invalid protocol %q", proto)
	}
	return nil
}

// Query is a 5-tuple policy-simulation request. A nil SrcIP/DstIP or an empty
// Protocol means "unspecified" — the corresponding match dimension is not
// constrained (the established diagnostic behavior). A zero SrcPort/DstPort
// means "unspecified port" and likewise does not constrain a port-bearing
// application term.
type Query struct {
	FromZone string
	ToZone   string
	SrcIP    net.IP
	DstIP    net.IP
	Protocol string // "tcp", "udp", "89", "ospf", ... ("" = unspecified)
	SrcPort  int
	DstPort  int

	// ICMPType / ICMPCode carry the query packet's ICMP/ICMPv6 type and code
	// (#3284). They mirror the dataplane's per-packet `packet_icmp` tuple
	// (policy.rs evaluate_policy_result_with_icmp): a type-constrained
	// application term (junos-ping = ICMP type 8, junos-pingv6 = ICMPv6
	// type 128) matches ONLY when the query's type is known and equal (and the
	// code too, when the term constrains a code). A nil ICMPType means the
	// query did not specify a type: a type-constrained term then fails closed
	// (does NOT match), exactly like the runtime passing `packet_icmp = None`.
	// An UNCONSTRAINED ICMP application (junos-icmp-all) is unaffected by these
	// fields — it matches every ICMP packet on protocol alone. Pointers
	// distinguish "unspecified" from a valid type/code 0 (ICMP type 0 is
	// echo-reply, code 0 is common), which a plain int could not.
	ICMPType *uint8
	ICMPCode *uint8

	// FeedOverlay is the dynamic-address feed-prefix overlay (#2049): an
	// address-name -> union-of-live-feed-CIDR-strings map, the same shape the
	// snapshot builder consumes (feeds.Manager.SnapshotForBindings). When a
	// policy address token names a feed-backed address-name, its feed CIDRs are
	// merged with any static address-book content for that name. nil is valid
	// (no feed enforcement / surface without live feed access); a feed-backed
	// name then resolves to its static content only, matching the runtime
	// fail-closed-before-first-fetch behavior.
	FeedOverlay map[string][]string

	// PolicyInactiveFn, when non-nil, reports whether a policy bound to the
	// given scheduler name is currently runtime-inactive (#3104). It mirrors
	// the runtime's per-rule scheduler gate (policy.rs try_match_rule, which
	// drops an inactive rule before app/address matching). A policy for which
	// this returns true is SKIPPED, so the simulator falls through to the next
	// active rule / configured default-policy — agreeing with the dataplane.
	//
	// Callers build this from the live daemon-local per-scheduler active-state
	// map via dataplane/userspace.PolicyInactiveFn, which wraps the SSOT
	// PolicyInactive predicate shared with the snapshot builder and the #3062
	// display surfaces. An empty scheduler name reports active, so a
	// NON-scheduled policy is never skipped.
	//
	// nil is valid and means "no live scheduler state": the simulator evaluates
	// scheduled policies as-if-active (the pre-#3104 behavior / #3062 display
	// fallback). The runtime/dataplane callers always supply it when scheduler
	// state has been published; only offline surfaces leave it nil.
	PolicyInactiveFn func(schedulerName string) bool
}

// Result is the simulator verdict.
type Result struct {
	// Matched is true when a concrete zone-pair or global policy matched. When
	// false the verdict is the configured default-policy (see DefaultUsed).
	Matched bool
	// Global is true when the match came from a `policy global` rule rather
	// than a zone-pair rule.
	Global bool
	// DefaultUsed is true when no policy matched and Action is the configured
	// default-policy.
	DefaultUsed bool

	// HostInboundUnmatched is true ONLY for a `to-zone junos-host` query that
	// matched no host-bound policy (#3285). The dataplane host gate
	// (evaluate_junos_host_policy) returns None here — there is no implicit
	// host default-deny and NO transit global/default fallback, so local
	// delivery proceeds (the management lifeline). Matched is false and
	// DefaultUsed is false; callers must render this as "host-inbound, not
	// governed by transit/global/default policy", NOT as the default-policy
	// verdict. Action is unset (PolicyPermit zero value) and carries no
	// meaning in this case.
	HostInboundUnmatched bool

	PolicyName   string
	Description  string
	Action       config.PolicyAction
	SrcAddresses []string
	DstAddresses []string
	Applications []string
}

// Match runs the simulator against the active config and returns the verdict
// with the SAME precedence the runtime enforces (userspace-dp/src/policy.rs
// evaluate_policy_result_with_icmp / try_match_rule), first-match terminating:
//
//  1. exact zone-pair (both zones concrete)
//  2. single-wildcard tier — `from-zone any to-zone <X>` and
//     `from-zone <X> to-zone any`, MERGED in config order (#3090)
//  3. both-any — `from-zone any to-zone any` (#3090)
//  4. global (`junos-global`), gated by the optional `match from-zone` /
//     `match to-zone` scope (#3148); an empty/`any` scope applies to every
//     zone, an undefined-zone scope fails closed (matches nothing)
//  5. configured default-policy
//
// A `to-zone junos-host` query is host-bound and takes the separate host-gate
// path (matchJunosHost, #3285): exact ingress->junos-host then
// `from-zone any`->junos-host, with NO global/default transit fallback.
func Match(cfg *config.Config, q Query) Result {
	if cfg == nil {
		return Result{DefaultUsed: true, Action: config.PolicyDeny}
	}

	// #3285: host-bound (LocalDelivery) traffic is governed by the dataplane's
	// host gate, which does NOT apply transit global/default fallback. Branch
	// before the transit tiers so that invariant cannot regress.
	if q.ToZone == JunosHostZone {
		return matchJunosHost(cfg, q)
	}

	// #3355: the runtime gates the ENTIRE transit block — exact zone-pair, the
	// #3090 from-any/to-any/both-any wildcard tiers, AND the #3148 global tier —
	// on `from_id != 0 && to_id != 0` (policy.rs evaluate_policy_result_with_icmp).
	// Zone id 0 is the reserved "unknown / no zone" sentinel an unconfigured
	// zone name resolves to; a flow whose ingress OR egress zone is unknown
	// belongs to no DEFINED zone pair and is ineligible for zone-pair, wildcard,
	// or junos-global policies. A query naming an UNDEFINED zone is the simulator
	// analogue of id 0, so it must fall straight through to the configured
	// default-policy rather than wrongly matching a `from-zone any` / `to-zone
	// any` / global rule.
	if !zoneKnown(cfg, q.FromZone) || !zoneKnown(cfg, q.ToZone) {
		return Result{DefaultUsed: true, Action: cfg.Security.DefaultPolicy}
	}

	// Tier 1: exact zone-pair policies, in config order (first match wins).
	// q.FromZone/q.ToZone are concrete zone names; a wildcard set
	// (FromZone/ToZone == "any") never compares equal, so it is excluded here.
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.FromZone != q.FromZone || zpp.ToZone != q.ToZone {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol != nil && ruleMatches(cfg, q, pol) {
				return matchedResult(pol, false)
			}
		}
	}

	// Tier 2: single-wildcard tier (#3090) — `from-zone any to-zone <q.ToZone>`
	// OR `from-zone <q.FromZone> to-zone any`, MERGED in config order. The
	// dataplane two-pointer-merges its from_any/to_any index buckets by global
	// rule index; the snapshot builder (walkPolicyRuleSlots) emits rules in
	// cfg.Security.Policies slice order with each set's policies contiguous, so
	// a single in-order pass over the sets reproduces that merge exactly.
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		fromAny := zpp.FromZone == "any"
		toAny := zpp.ToZone == "any"
		if fromAny == toAny {
			continue // both-any (Tier 3) or neither (Tier 1) — not single-wildcard
		}
		applies := (fromAny && zpp.ToZone == q.ToZone) || (toAny && zpp.FromZone == q.FromZone)
		if !applies {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol != nil && ruleMatches(cfg, q, pol) {
				return matchedResult(pol, false)
			}
		}
	}

	// Tier 3: both-any (`from-zone any to-zone any`), in config order.
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.FromZone != "any" || zpp.ToZone != "any" {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol != nil && ruleMatches(cfg, q, pol) {
				return matchedResult(pol, false)
			}
		}
	}

	// Tier 4: global policies (junos-global), in config order, gated by the
	// optional #3148 from-zone/to-zone match scope.
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		if !globalScopeMatches(cfg, pol.Match.FromZone, q.FromZone) ||
			!globalScopeMatches(cfg, pol.Match.ToZone, q.ToZone) {
			continue
		}
		if ruleMatches(cfg, q, pol) {
			return matchedResult(pol, true)
		}
	}

	// Tier 5: configured default-policy (NOT a hard-coded deny).
	return Result{DefaultUsed: true, Action: cfg.Security.DefaultPolicy}
}

// matchJunosHost mirrors the dataplane host gate evaluate_junos_host_policy
// (policy.rs) for a `to-zone junos-host` query (#3285). It consults ONLY exact
// `from-zone <ingress> to-zone junos-host` rules, then the
// `from-zone any to-zone junos-host` wildcard — in that order. There is NO
// implicit host default-deny and NO global / transit-default fallback: an
// unmatched host-bound flow falls through to local delivery (the management
// lifeline guarantee), so the simulator returns HostInboundUnmatched rather
// than inheriting the transit global/default verdict. `to-zone any` and
// `from-zone any to-zone any` are deliberately NOT pulled onto the host path,
// matching the runtime gate.
func matchJunosHost(cfg *config.Config, q Query) Result {
	// #3355: evaluate_junos_host_policy returns None for from_id == 0 (the
	// unknown/undefined ingress zone), mirroring the #3110 unzoned guard. An
	// undefined query from-zone therefore matches no host-bound rule; local
	// delivery proceeds (the management lifeline), so surface
	// HostInboundUnmatched rather than running the host tiers against an
	// unresolved ingress zone.
	if !zoneKnown(cfg, q.FromZone) {
		return Result{HostInboundUnmatched: true}
	}
	// Exact ingress -> junos-host.
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.ToZone != JunosHostZone || zpp.FromZone != q.FromZone {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol != nil && ruleMatches(cfg, q, pol) {
				return matchedResult(pol, false)
			}
		}
	}
	// from-zone any -> junos-host.
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.ToZone != JunosHostZone || zpp.FromZone != "any" {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol != nil && ruleMatches(cfg, q, pol) {
				return matchedResult(pol, false)
			}
		}
	}
	// No host-bound rule matched: local delivery proceeds. Do NOT fall through
	// to global/default — the dataplane host gate returns None here.
	return Result{HostInboundUnmatched: true}
}

// globalScopeMatches replicates GlobalZoneScope::matches + build_global_zone_scope
// (policy.rs, #3148). An empty or explicit "any" scope applies to every zone.
// Any other name must resolve to a DEFINED zone and equal the flow's zone; an
// undefined (typo'd, or reserved like junos-host) scope fails closed — it
// matches nothing, never silently widening to all-zones.
func globalScopeMatches(cfg *config.Config, scopeZone, flowZone string) bool {
	if scopeZone == "" || scopeZone == "any" {
		return true
	}
	if _, ok := cfg.Security.Zones[scopeZone]; !ok {
		return false // Unresolved → matches nothing
	}
	return scopeZone == flowZone
}

// zoneKnown reports whether a query zone is DEFINED for the runtime's `id != 0`
// eligibility guard (#3355). The runtime resolves an unconfigured zone name to
// the reserved unknown id 0, which is ineligible for zone-pair / wildcard /
// global / junos-host policies (policy.rs evaluate_policy_result_with_icmp gates
// the whole transit block on from_id != 0 && to_id != 0; evaluate_junos_host_policy
// returns None for from_id == 0). A zone is "known" iff it is present in
// cfg.Security.Zones.
//
// This mirrors the runtime UNCONDITIONALLY — there is deliberately NO
// empty-Zones leniency. policy.rs applies the from_id/to_id != 0 gate for every
// evaluation; a config with no defined zones resolves every zone name to id 0,
// so the runtime matches NOTHING in the transit tiers. An earlier "offline
// tolerance" short-circuit (return true when Zones is empty) was simulator-vs-
// runtime DRIFT: a no-zones config matched transit tiers in the simulator that
// the runtime would never evaluate. A committed production config always
// populates Zones; a synthetic config without zones now faithfully matches
// nothing in transit.
func zoneKnown(cfg *config.Config, zone string) bool {
	_, ok := cfg.Security.Zones[zone]
	return ok
}

func matchedResult(pol *config.Policy, global bool) Result {
	return Result{
		Matched:      true,
		Global:       global,
		PolicyName:   pol.Name,
		Description:  pol.Description,
		Action:       pol.Action,
		SrcAddresses: pol.Match.SourceAddresses,
		DstAddresses: pol.Match.DestinationAddresses,
		Applications: pol.Match.Applications,
	}
}

func ruleMatches(cfg *config.Config, q Query, pol *config.Policy) bool {
	// #3104: scheduler gate, FIRST — mirror policy.rs try_match_rule, which
	// returns None for a scheduler-inactive rule before any app/address
	// matching. Skipping here lets Match fall through to the next active rule
	// or the default-policy, exactly as the runtime does. PolicyInactiveFn is
	// nil when the caller has no live scheduler state (simulate as-if-active),
	// and reports an empty scheduler name as active, so a non-scheduled policy
	// is never skipped.
	if q.PolicyInactiveFn != nil && q.PolicyInactiveFn(pol.SchedulerName) {
		return false
	}
	if !matchAddr(cfg, q.FeedOverlay, pol.Match.SourceAddresses, pol.Match.SourceAddressExcluded, q.SrcIP) {
		return false
	}
	if !matchAddr(cfg, q.FeedOverlay, pol.Match.DestinationAddresses, pol.Match.DestinationAddressExcluded, q.DstIP) {
		return false
	}
	return matchApp(cfg, pol.Match.Applications, q.Protocol, q.SrcPort, q.DstPort, q.ICMPType, q.ICMPCode)
}

// matchAddr replicates policy.rs try_match_rule's per-side address logic
// EXACTLY (#3356). A nil ip (unspecified) does not constrain the match.
//
// The runtime computes, per side:
//
//	excluded:     !(v4_empty && v6_empty) && !(ip is in the set)
//	not excluded:  match_any || (ip is in the set)
//
// Two faithfulness fixes over the pre-#3356 simulator:
//
//   - The empty-address-list "match any" short-circuit must NOT run before the
//     exclusion check. An empty-but-EXCLUDED set ([] with excluded=true) is the
//     genuine typo/parse-drop signal #2008 fails CLOSED on: the runtime sees
//     v4_empty && v6_empty and yields false. Returning match-any first made the
//     simulator fail OPEN — it reported a match no dataplane packet would get.
//     The "no constraint = match any" convenience now applies only to the
//     NON-excluded empty list.
//
//   - The excluded fail-closed gate keys on BOTH families being empty, not on
//     the packet's own family. The runtime fails closed only when
//     v4_empty && v6_empty (policy.rs ~2095-2106). A v6-only exclusion set on a
//     v4 packet (#3023 cross-family) leaves v4_empty true but v6_empty false:
//     the v4 address is then trivially NOT in the (v6-only) excluded set, so the
//     side MATCHES. The old per-packet-family `contributesFamily` gate failed
//     closed there and over-blocked legitimate cross-family traffic.
func matchAddr(cfg *config.Config, overlay map[string][]string, addrs []string, excluded bool, ip net.IP) bool {
	if ip == nil {
		return true
	}

	isV4 := ip.To4() != nil

	rawMatched := false
	v4Empty := true
	v6Empty := true
	for _, tok := range addrs {
		v4nets, v6nets, anyV4, anyV6 := resolveToken(cfg, overlay, tok)
		if anyV4 || len(v4nets) > 0 {
			v4Empty = false
		}
		if anyV6 || len(v6nets) > 0 {
			v6Empty = false
		}
		if isV4 {
			if anyV4 || containsAny(v4nets, ip) {
				rawMatched = true
			}
		} else {
			if anyV6 || containsAny(v6nets, ip) {
				rawMatched = true
			}
		}
	}

	if !excluded {
		if len(addrs) == 0 {
			// No address constraint configured: the runtime treats this as
			// match-any for both families (parse_legacy_address_set of an empty
			// list). Only the NON-excluded empty list is match-any.
			return true
		}
		return rawMatched
	}
	// Excluded: fail CLOSED only when the set is empty across BOTH families —
	// the #2008 typo/parse-drop signal (matches policy.rs's
	// `!(v4_empty && v6_empty)`). A populated other-family set means the
	// operator listed only one family; the packet's family is then trivially
	// NOT in the excluded set, so the side matches (#3023 cross-family).
	if v4Empty && v6Empty {
		return false
	}
	return !rawMatched
}

func containsAny(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveToken resolves a single policy address token to its v4/v6 CIDR sets
// plus per-family "match any" flags, mirroring the snapshot builder's
// classifyPolicyAddresses (book-name precedence) and policy.rs's
// parse_v3_literal_set / expandBookNameToCIDRs.
func resolveToken(cfg *config.Config, overlay map[string][]string, tok string) (v4nets, v6nets []*net.IPNet, anyV4, anyV6 bool) {
	if tok == "" {
		return nil, nil, false, false
	}

	// Book-name precedence (classifyPolicyAddresses): a token that names a
	// static address/address-set OR a feed-overlay address-name is resolved as
	// a book reference, never as a literal.
	if isBookName(cfg, overlay, tok) {
		values := expandBookName(cfg, tok, make(map[string]bool))
		if feed := overlay[tok]; len(feed) > 0 {
			values = append(values, feed...)
		}
		for _, val := range values {
			addCIDRValue(val, &v4nets, &v6nets, &anyV4, &anyV6)
		}
		return v4nets, v6nets, anyV4, anyV6
	}

	switch tok {
	case "any":
		return nil, nil, true, true
	case "any-ipv4", "any4":
		return nil, nil, true, false
	case "any-ipv6", "any6":
		return nil, nil, false, true
	}

	addCIDRValue(tok, &v4nets, &v6nets, &anyV4, &anyV6)
	return v4nets, v6nets, anyV4, anyV6
}

// addCIDRValue parses one address value (CIDR, bare IP, "any", or a family
// wildcard) and appends it to the appropriate family set / wildcard flag.
func addCIDRValue(val string, v4nets, v6nets *[]*net.IPNet, anyV4, anyV6 *bool) {
	switch val {
	case "":
		// #3261: an address-book entry with no compiled prefix (a Junos
		// dns-name / wildcard-address / range-address that compiled to
		// Value=="") contributes NOTHING — it must NOT widen to match-any.
		// Mirrors the dataplane's expandBookNameToCIDRs, which now skips an
		// empty value instead of emitting 0.0.0.0/0 (the pre-#3261 fail-open).
		return
	case "any":
		*anyV4 = true
		*anyV6 = true
		return
	case "any-ipv4", "any4":
		*anyV4 = true
		return
	case "any-ipv6", "any6":
		*anyV6 = true
		return
	}
	if _, ipnet, err := net.ParseCIDR(val); err == nil {
		if ipnet.IP.To4() != nil {
			*v4nets = append(*v4nets, ipnet)
		} else {
			*v6nets = append(*v6nets, ipnet)
		}
		return
	}
	if ip := net.ParseIP(val); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			*v4nets = append(*v4nets, &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
		} else {
			*v6nets = append(*v6nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
		}
	}
}

func isBookName(cfg *config.Config, overlay map[string][]string, tok string) bool {
	if _, ok := overlay[tok]; ok {
		return true
	}
	ab := cfg.Security.AddressBook
	if ab == nil {
		return false
	}
	if _, ok := ab.Addresses[tok]; ok {
		return true
	}
	if _, ok := ab.AddressSets[tok]; ok {
		return true
	}
	return false
}

// expandBookName resolves an address-book name to its raw address VALUE
// strings (CIDRs / bare IPs / "any"), recursing through address-sets with
// path-based cycle detection — a direct port of the snapshot builder's
// expandBookNameRecursive.
func expandBookName(cfg *config.Config, name string, visited map[string]bool) []string {
	ab := cfg.Security.AddressBook
	if ab == nil || visited[name] {
		return nil
	}
	visited[name] = true
	defer delete(visited, name)

	if addr, ok := ab.Addresses[name]; ok {
		return []string{addr.Value}
	}
	if as, ok := ab.AddressSets[name]; ok {
		var out []string
		for _, member := range as.Addresses {
			out = append(out, expandBookName(cfg, member, visited)...)
		}
		for _, nested := range as.AddressSets {
			out = append(out, expandBookName(cfg, nested, visited)...)
		}
		return out
	}
	return nil
}

// matchApp replicates policy.rs CompiledApplications.matches fed by the
// snapshot builder's application expansion: predefined + user applications via
// ResolveApplication, recursive application-set expansion via
// ExpandApplicationSet, BOTH source-port and destination-port terms, and the
// ICMP/ICMPv6 type/code constraints enforced in matchSingleApp (#3284).
//
// An empty application list is the runtime match-any case.
//
// #3323: an OMITTED (or unresolvable) query protocol must NOT short-circuit to
// match-any for an application-constrained term — it must fail closed, mirroring
// the runtime. The runtime always carries a concrete protocol and keys its
// per-application terms under that protocol (policy.rs CompiledApplications.matches
// does `by_protocol.get(&protocol)?`, yielding None when no term exists for the
// packet's protocol). An omitted query protocol resolves to queryProtoOK=false
// (appid.ProtocolNumber("") is (0,false)), so every protocol-bearing app term —
// the predefined Junos apps and any custom app with a `protocol` — fails the
// matchSingleApp protocol gate and does NOT match. The old
// `if proto == "" { return true }` convenience reported a permit/deny by an
// app-constrained policy that no concrete ICMP/UDP/GRE/random-TCP packet would
// ever hit (the sibling of #3330's destination-port omission). Falling through
// here lets Match reach the configured default-policy, exactly as the dataplane
// would for a protocol that matches no term.
//
// An application that is genuinely UNCONSTRAINED on protocol (app.Protocol == ""
// with no port / ICMP-type constraint either) still matches regardless of the
// query protocol — it is a true match-any term, unchanged. Once a non-empty
// protocol IS supplied, matchSingleApp constrains by protocol (and ICMP
// type/code for a type-constrained term) exactly as before; a non-empty but
// UNRESOLVABLE protocol fails closed for every protocol-constrained app term.
func matchApp(cfg *config.Config, apps []string, proto string, srcPort, dstPort int, icmpType, icmpCode *uint8) bool {
	if len(apps) == 0 {
		return true
	}
	queryProto, queryProtoOK := appid.ProtocolNumber(proto)

	for _, a := range apps {
		if a == "any" {
			return true
		}
		// Application-set: expand recursively (multi-level) and test each
		// member application.
		if _, isSet := cfg.Applications.ApplicationSets[a]; isSet {
			members, err := config.ExpandApplicationSet(a, &cfg.Applications)
			if err != nil {
				continue
			}
			for _, m := range members {
				if matchSingleApp(cfg, m, queryProto, queryProtoOK, srcPort, dstPort, icmpType, icmpCode) {
					return true
				}
			}
			continue
		}
		if matchSingleApp(cfg, a, queryProto, queryProtoOK, srcPort, dstPort, icmpType, icmpCode) {
			return true
		}
	}
	return false
}

func matchSingleApp(cfg *config.Config, appName string, queryProto uint8, queryProtoOK bool, srcPort, dstPort int, icmpType, icmpCode *uint8) bool {
	app, ok := config.ResolveApplication(appName, cfg.Applications.Applications)
	if !ok {
		return false
	}
	// Protocol: compare by IANA number so a named app protocol ("89"/"ospf")
	// and a named/numeric query protocol agree (the old EqualFold string
	// compare failed "89" vs "ospf").
	if app.Protocol != "" {
		appProto, appOK := appid.ProtocolNumber(app.Protocol)
		if !appOK || !queryProtoOK || appProto != queryProto {
			return false
		}
	}
	// #3284: ICMP/ICMPv6 type[,code] constraint (junos-ping = type 8). Mirror
	// policy.rs CompiledApplications.matches: a type-constrained term matches
	// ONLY when the query's ICMP type is known and equal — and the code too,
	// when the term constrains a code. A nil query type fails closed for the
	// term (the runtime's `packet_icmp == None` path). An application with NO
	// ICMP type constraint (junos-icmp-all, or any non-ICMP app) is unaffected:
	// it matches on protocol/ports alone, exactly as before.
	if app.ICMPType != nil {
		// The dataplane keys icmp_constraints under the app's ICMP protocol, so
		// the type constraint is only ever consulted for an ICMP-family packet.
		// A predefined ICMP app pins app.Protocol (handled by the check above),
		// but a custom app could carry an icmp-type without a pinned protocol;
		// require the query to be ICMP (1) / ICMPv6 (58) so a type-constrained
		// term can never match a TCP/UDP flow.
		if !queryProtoOK || (queryProto != icmpProtoNum && queryProto != icmpv6ProtoNum) {
			return false
		}
		if icmpType == nil || *icmpType != *app.ICMPType {
			return false
		}
		if app.ICMPCode != nil && (icmpCode == nil || *icmpCode != *app.ICMPCode) {
			return false
		}
	}
	// #3330: when the application term CONSTRAINS a destination port, an OMITTED
	// query dst port must NOT match-any — it must fail closed, mirroring the
	// runtime. The dataplane keys a single dst-port term in exact_dst_ports and
	// range terms in range_terms (policy.rs CompiledApplications.matches): an
	// omitted query port arrives as 0, which a real app port (e.g. 80) never
	// equals and no app range admits, so the constrained term does NOT match.
	// The old `&& dstPort > 0` gate skipped the check entirely for an omitted
	// port, reporting a permit for a port-constrained app no concrete packet
	// would hit (sibling of #3323's protocol omission). An UNCONSTRAINED dst
	// port term (app.DestinationPort == "") still matches any port, unchanged.
	if app.DestinationPort != "" {
		if dstPort <= 0 || !portMatches(app.DestinationPort, dstPort) {
			return false
		}
	}
	// Source port retains #3107's deliberate diagnostic stance: an OMITTED query
	// source port (the ephemeral, operator-rarely-known dimension) is treated as
	// "unconstrained" so a source-port-bearing app term still resolves. Only a
	// SPECIFIED source port is checked. Narrowing this too would change the
	// #3107 absent-source-port contract (TestShowTestPolicySourcePort), which is
	// out of #3330's destination-port scope.
	if app.SourcePort != "" && srcPort > 0 && !portMatches(app.SourcePort, srcPort) {
		return false
	}
	return true
}

// portMatches reports whether port falls in the application port spec, which
// may be a named alias ("http"), a single port ("80"), or a range
// ("80-90") — mirroring policy.rs parse_port_spec.
func portMatches(spec string, port int) bool {
	spec = normalizePortAlias(spec)
	if lo, hi, ok := strings.Cut(spec, "-"); ok {
		l, errL := strconv.Atoi(strings.TrimSpace(lo))
		h, errH := strconv.Atoi(strings.TrimSpace(hi))
		if errL != nil || errH != nil {
			return false
		}
		return port >= l && port <= h
	}
	p, err := strconv.Atoi(strings.TrimSpace(spec))
	if err != nil {
		return false
	}
	return p == port
}

func normalizePortAlias(spec string) string {
	switch spec {
	case "http":
		return "80"
	case "https":
		return "443"
	case "ssh":
		return "22"
	case "telnet":
		return "23"
	case "ftp":
		return "21"
	case "ftp-data":
		return "20"
	case "smtp":
		return "25"
	case "dns":
		return "53"
	case "pop3":
		return "110"
	case "imap":
		return "143"
	case "snmp":
		return "161"
	case "ntp":
		return "123"
	case "bgp":
		return "179"
	case "ldap":
		return "389"
	case "syslog":
		return "514"
	default:
		return spec
	}
}

// ActionString renders a policy action token (permit/deny/reject).
func ActionString(a config.PolicyAction) string {
	switch a {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyDeny:
		return "deny"
	case config.PolicyReject:
		return "reject"
	default:
		return "unknown"
	}
}
