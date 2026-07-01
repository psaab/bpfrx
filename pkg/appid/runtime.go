package appid

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

const Unknown = "UNKNOWN"

type builtinApp struct {
	proto uint8
	port  uint16
}

// Keep fallback heuristics intentionally narrow. Real AppID names should come
// from dataplane-assigned app_id values, not broad protocol-only guesses.
var builtinFallbacks = map[string]builtinApp{
	"junos-http":        {proto: 6, port: 80},
	"junos-https":       {proto: 6, port: 443},
	"junos-ssh":         {proto: 6, port: 22},
	"junos-telnet":      {proto: 6, port: 23},
	"junos-ftp":         {proto: 6, port: 21},
	"junos-smtp":        {proto: 6, port: 25},
	"junos-dns-tcp":     {proto: 6, port: 53},
	"junos-dns-udp":     {proto: 17, port: 53},
	"junos-bgp":         {proto: 6, port: 179},
	"junos-ntp":         {proto: 17, port: 123},
	"junos-snmp":        {proto: 17, port: 161},
	"junos-syslog":      {proto: 17, port: 514},
	"junos-dhcp-client": {proto: 17, port: 68},
	"junos-ike":         {proto: 17, port: 500},
	"junos-ipsec-nat-t": {proto: 17, port: 4500},
}

// CatalogNames returns the set of application names that should be compiled.
// When includeAll is true, it includes all predefined and user-defined apps so
// session tracking can identify flows even when policies do not reference them.
func CatalogNames(cfg *config.Config, includeAll bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}

	names := make(map[string]struct{})
	if includeAll {
		for name := range config.PredefinedApplications {
			names[name] = struct{}{}
		}
		for name := range cfg.Applications.Applications {
			names[name] = struct{}{}
		}
		return sortedNames(names), nil
	}

	// addAppRef records one `match application` reference (from a security
	// policy OR a NAT rule) into the catalog. An application-set is expanded to
	// its members; a bare application name is recorded directly. "" / "any" is
	// not a reference. This is the single per-reference resolver shared by the
	// policy and NAT walks so the two paths cannot diverge (#3626 L04).
	addAppRef := func(appName string) error {
		if appName == "" || appName == "any" {
			return nil
		}
		if _, isSet := cfg.Applications.ApplicationSets[appName]; isSet {
			expanded, err := config.ExpandApplicationSet(appName, &cfg.Applications)
			if err != nil {
				return fmt.Errorf("expand application-set %q: %w", appName, err)
			}
			for _, expandedName := range expanded {
				names[expandedName] = struct{}{}
			}
			return nil
		}
		names[appName] = struct{}{}
		return nil
	}

	addPolicyApps := func(policies []*config.Policy) error {
		for _, pol := range policies {
			// #3622: a nil policy entry is admitted by the tolerant-load
			// path (#1960) and must fail closed, not panic. Match the strict
			// walker (compiler_validate_strict.go), which skips nil rules.
			if pol == nil {
				continue
			}
			for _, appName := range pol.Match.Applications {
				if err := addAppRef(appName); err != nil {
					return err
				}
			}
		}
		return nil
	}

	for _, zpp := range cfg.Security.Policies {
		// #3622: a nil zone-pair entry is admitted by the tolerant-load
		// path (#1960); skip it rather than deref zpp.Policies and panic.
		// Matches the strict walker (compiler_validate_strict.go).
		if zpp == nil {
			continue
		}
		if err := addPolicyApps(zpp.Policies); err != nil {
			return nil, err
		}
	}
	if err := addPolicyApps(cfg.Security.GlobalPolicies); err != nil {
		return nil, err
	}

	// #3626: a source/destination-NAT rule's `match application <name>` also
	// consumes the referenced app's port/proto (pkg/dataplane/userspace/nat.go
	// appPortsFromSpec). An app referenced ONLY by a NAT rule — with no
	// security policy referencing it — must still land in the compiled catalog,
	// or the dataplane cannot resolve it and session naming for that flow falls
	// back to tuple/numeric. Walk NAT rule references exactly as the strict
	// validator does (compiler_validate_strict.go applicationsToValidateStrict:
	// Source + Destination.RuleSets, skipping nil rule-sets/rules, the scalar
	// rule.Match.Application) so the runtime catalog and the commit-time strict
	// gate agree on the referenced-app set — TestStrictValidationSetMatches-
	// CatalogNames pins the two walks together. Static NAT carries no
	// application match, so only source and destination NAT are walked.
	addNATRuleSet := func(rs *config.NATRuleSet) error {
		if rs == nil {
			return nil
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if err := addAppRef(rule.Match.Application); err != nil {
				return err
			}
		}
		return nil
	}
	for _, rs := range cfg.Security.NAT.Source {
		if err := addNATRuleSet(rs); err != nil {
			return nil, err
		}
	}
	if cfg.Security.NAT.Destination != nil {
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			if err := addNATRuleSet(rs); err != nil {
				return nil, err
			}
		}
	}

	return sortedNames(names), nil
}

// ResolveSessionName returns the session application name using the actual
// dataplane-assigned app_id when available. When AppID is enabled, unknown
// sessions are reported as UNKNOWN instead of guessed from port heuristics.
//
// srcPort is the session source port; it is required so the tuple fallback can
// honor a configured `source-port` constraint (#3428). Both the source and the
// destination port are threaded through to the fallback matcher.
func ResolveSessionName(appNames map[uint16]string, cfg *config.Config, proto uint8, srcPort, dstPort uint16, appID uint16) string {
	if appID != 0 {
		if name := appNames[appID]; name != "" {
			return name
		}
	}

	// #3438 L1: when AppID is enabled the contract
	// (docs/services-application-identification.md) is honest UNKNOWN, never a
	// port-heuristic guess. A session whose app_id is 0 (unstamped/legacy) OR
	// nonzero-but-absent from AppNames (a control/dataplane catalog skew,
	// including the #3438 H4 id wrap) must render UNKNOWN rather than masking the
	// skew with a tuple guess. Tuple fallback is kept ONLY for the disabled-knob
	// path below.
	if cfg != nil && cfg.Services.ApplicationIdentification {
		return Unknown
	}

	return resolveTupleFallback(proto, srcPort, dstPort, cfg)
}

func SessionMatches(filter string, appNames map[uint16]string, cfg *config.Config, proto uint8, srcPort, dstPort uint16, appID uint16) bool {
	if filter == "" {
		return true
	}
	return strings.EqualFold(ResolveSessionName(appNames, cfg, proto, srcPort, dstPort, appID), filter)
}

func sortedNames(names map[string]struct{}) []string {
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func resolveTupleFallback(proto uint8, srcPort, dstPort uint16, cfg *config.Config) string {
	if cfg != nil {
		// #2578: cfg.Applications.Applications is a Go map; iterating it and
		// returning the first match is non-deterministic. When BOTH a
		// port-constrained app (e.g. tcp/8443) and a protocol-only app (tcp)
		// match the same session, the more-specific port-based app must win,
		// deterministically. Scan all matches, prefer a port-constrained app
		// (a source-port and/or destination-port constraint) over a
		// protocol-only one, and break ties by name so the result is stable
		// regardless of map iteration order.
		best := ""
		bestPortBased := false
		for name, app := range cfg.Applications.Applications {
			if !matchTuple(proto, srcPort, dstPort, app.Protocol, app.SourcePort, app.DestinationPort) {
				continue
			}
			portBased := app.DestinationPort != "" || app.SourcePort != ""
			if best == "" || (portBased && !bestPortBased) ||
				(portBased == bestPortBased && name < best) {
				best = name
				bestPortBased = portBased
			}
		}
		if best != "" {
			return best
		}
	}
	for name, ba := range builtinFallbacks {
		if ba.proto == proto && ba.port == dstPort {
			return name
		}
	}
	return ""
}

// matchTuple reports whether a session (proto, srcPort, dstPort) satisfies a
// configured application's protocol + source-port + destination-port
// constraints. An empty appProto never match-alls. An empty appSrcPort /
// appDstPort is "no constraint" for that port. A source-port AND a
// destination-port constraint are both required to hold when present (#3428).
func matchTuple(proto uint8, srcPort, dstPort uint16, appProto, appSrcPort, appDstPort string) bool {
	if appProto == "" {
		return false
	}
	if pn, ok := protocolNumber(appProto); !ok || pn != proto {
		return false
	}
	// #3428: a configured `source-port` constraint must be honored. Previously
	// only protocol + destination-port were compared, so a source-port-scoped
	// app (e.g. `protocol tcp source-port 12345 destination-port 8443`) was
	// matched on dst-port alone — ANY session to dst/8443 was mislabeled as that
	// app regardless of its source port. An empty source-port is unconstrained.
	if !portInSpec(srcPort, appSrcPort) {
		return false
	}
	// #2548: a custom application configured with a protocol but no
	// destination-port is PROTOCOL-ONLY (e.g. user-defined GRE/ESP/AH). The
	// protocol (and any source-port) match above is the whole constraint, so an
	// empty destination-port matches here instead of being rejected. A
	// port-only/port-ranged app (appDstPort != "") still requires the
	// destination port to match.
	return portInSpec(dstPort, appDstPort)
}

// portInSpec reports whether port satisfies an application port spec. An empty
// spec means "no constraint" and always matches. A "lo-hi" spec is an inclusive
// range; a bare value is an exact match. A malformed spec never matches.
func portInSpec(port uint16, spec string) bool {
	if spec == "" {
		return true
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		return err1 == nil && err2 == nil && int(port) >= lo && int(port) <= hi
	}
	v, err := strconv.Atoi(spec)
	return err == nil && uint16(v) == port
}

// protocolNumber resolves a protocol token for app-id runtime tuple matching.
// #2124: delegates to the centralized ProtocolNumber so this path agrees with
// the policy capability gate and the catalog table on the full named set
// (previously this copy recognized only tcp/udp/icmp/icmpv6/gre by name, so a
// user-defined esp/ah/sctp application could never name-match here). The
// (uint8, bool) contract is preserved.
func protocolNumber(proto string) (uint8, bool) {
	return ProtocolNumber(proto)
}
