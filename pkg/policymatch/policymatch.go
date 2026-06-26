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
// Note on scheduler state: the runtime honors a policy's scheduler-driven
// `inactive` flag. This simulator evaluates the configured policy set without
// applying live scheduler activation (matching the pre-#3042 surfaces), so a
// scheduled policy is simulated as if active.
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

	// FeedOverlay is the dynamic-address feed-prefix overlay (#2049): an
	// address-name -> union-of-live-feed-CIDR-strings map, the same shape the
	// snapshot builder consumes (feeds.Manager.SnapshotForBindings). When a
	// policy address token names a feed-backed address-name, its feed CIDRs are
	// merged with any static address-book content for that name. nil is valid
	// (no feed enforcement / surface without live feed access); a feed-backed
	// name then resolves to its static content only, matching the runtime
	// fail-closed-before-first-fetch behavior.
	FeedOverlay map[string][]string
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

	PolicyName   string
	Description  string
	Action       config.PolicyAction
	SrcAddresses []string
	DstAddresses []string
	Applications []string
}

// Match runs the simulator against the active config and returns the verdict
// with the same precedence the runtime enforces: an exact zone-pair policy
// match wins first, then a global policy, then the configured default-policy.
func Match(cfg *config.Config, q Query) Result {
	if cfg == nil {
		return Result{DefaultUsed: true, Action: config.PolicyDeny}
	}

	// 1) Exact zone-pair policies, in config order (first match wins).
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.FromZone != q.FromZone || zpp.ToZone != q.ToZone {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			if ruleMatches(cfg, q, pol) {
				return matchedResult(pol, false)
			}
		}
	}

	// 2) Global policies (junos-global), in config order.
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		if ruleMatches(cfg, q, pol) {
			return matchedResult(pol, true)
		}
	}

	// 3) Configured default-policy (NOT a hard-coded deny).
	return Result{DefaultUsed: true, Action: cfg.Security.DefaultPolicy}
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
	if !matchAddr(cfg, q.FeedOverlay, pol.Match.SourceAddresses, pol.Match.SourceAddressExcluded, q.SrcIP) {
		return false
	}
	if !matchAddr(cfg, q.FeedOverlay, pol.Match.DestinationAddresses, pol.Match.DestinationAddressExcluded, q.DstIP) {
		return false
	}
	return matchApp(cfg, pol.Match.Applications, q.Protocol, q.SrcPort, q.DstPort)
}

// matchAddr replicates policy.rs try_match_rule's per-side address logic.
//
// A nil ip (unspecified) does not constrain the match. An empty token list is
// the runtime "no address constraint = match any" case. Otherwise the raw
// "ip is in the configured set" predicate is computed per family (only the
// ip's own family is consulted), then XORed with the exclusion flag. An
// EMPTY excluded set fails closed (it never matches) instead of inverting to
// match-all — the #2008 fail-open hardening.
func matchAddr(cfg *config.Config, overlay map[string][]string, addrs []string, excluded bool, ip net.IP) bool {
	if ip == nil {
		return true
	}
	if len(addrs) == 0 {
		// No address constraint configured: runtime treats this as match-any
		// for both families (parse_legacy_address_set of an empty list).
		return true
	}

	isV4 := ip.To4() != nil

	rawMatched := false
	contributesFamily := false
	for _, tok := range addrs {
		v4nets, v6nets, anyV4, anyV6 := resolveToken(cfg, overlay, tok)
		if isV4 {
			if anyV4 || len(v4nets) > 0 {
				contributesFamily = true
			}
			if anyV4 || containsAny(v4nets, ip) {
				rawMatched = true
			}
		} else {
			if anyV6 || len(v6nets) > 0 {
				contributesFamily = true
			}
			if anyV6 || containsAny(v6nets, ip) {
				rawMatched = true
			}
		}
	}

	if !excluded {
		return rawMatched
	}
	// Excluded: an empty set for this family fails closed.
	if !contributesFamily {
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
	case "", "any":
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
// ExpandApplicationSet, and BOTH source-port and destination-port terms.
//
// An empty application list is the runtime match-any case. An unspecified
// query protocol does not constrain the match (the established diagnostic
// behavior).
func matchApp(cfg *config.Config, apps []string, proto string, srcPort, dstPort int) bool {
	if len(apps) == 0 {
		return true
	}
	if proto == "" {
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
				if matchSingleApp(cfg, m, queryProto, queryProtoOK, srcPort, dstPort) {
					return true
				}
			}
			continue
		}
		if matchSingleApp(cfg, a, queryProto, queryProtoOK, srcPort, dstPort) {
			return true
		}
	}
	return false
}

func matchSingleApp(cfg *config.Config, appName string, queryProto uint8, queryProtoOK bool, srcPort, dstPort int) bool {
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
	if app.DestinationPort != "" && dstPort > 0 && !portMatches(app.DestinationPort, dstPort) {
		return false
	}
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
