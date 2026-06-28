package config

import (
	"fmt"
	"strconv"
	"strings"
)

// Application inactivity-timeout / timeout accepted range, in seconds. The
// upper bound matches the NAT persistent-binding inactivity-timeout
// (schema_security.go) and the session-timeout range a custom application can
// sensibly set. The lower bound is 0 — NOT 1 — because 0 is a pre-existing,
// documented "inherit the global per-protocol timeout" sentinel: the userspace
// serializer treats InactivityTimeout <= 0 as "use the global timeout"
// (pkg/dataplane/userspace/capabilities.go) and the typed field documents it
// (types_security.go: "0 = default"). `inactivity-timeout 0` committed cleanly
// before #3320 (strconv.Atoi("0") = 0, no error), so the strict gate must keep
// accepting it. #3320 targets MALFORMED values only — non-numeric ("30s",
// "thirty"), negative, and out-of-range (>86400) — all of which fall outside
// [0, 86400].
const (
	appTimeoutMin = 0
	appTimeoutMax = 86400
)

// parseAppTimeout parses an application inactivity-timeout / timeout token.
// It returns the integer value and true when the token is a base-10 integer
// within [appTimeoutMin, appTimeoutMax]; otherwise it returns (0, false) so the
// caller records the raw token for a deferred strict rejection rather than
// silently dropping it. It is the single parse authority shared by the
// top-level and inline-term application paths and the strict commit gate.
func parseAppTimeout(raw string) (int, bool) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	if n < appTimeoutMin || n > appTimeoutMax {
		return 0, false
	}
	return n, true
}

func compileApplications(node *Node, apps *ApplicationsConfig) error {
	for _, inst := range namedInstances(node.FindChildren("application")) {
		appName := inst.name
		app := &Application{Name: appName}

		var terms []*Application
		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "protocol":
				app.Protocol = nodeVal(prop)
			case "destination-port":
				app.DestinationPort = resolveAppPort(nodeVal(prop))
			case "source-port":
				app.SourcePort = resolveAppPort(nodeVal(prop))
			case "inactivity-timeout", "timeout":
				if v := nodeVal(prop); v != "" {
					if n, ok := parseAppTimeout(v); ok {
						app.InactivityTimeout = n
					} else {
						// #3320: a non-numeric / out-of-range / unit-suffixed
						// value was silently dropped here (Atoi error ignored),
						// leaving InactivityTimeout at 0 so the application fell
						// back to the global per-protocol timeout. Record the raw
						// token so validateApplicationSpecsStrict can reject it.
						app.UnknownTimeouts = append(app.UnknownTimeouts, v)
					}
				}
			case "alg":
				app.ALG = nodeVal(prop)
			case "description":
				app.Description = nodeVal(prop)
			case "term":
				// Inline term: "term <name> [alg <a>] protocol <p> [source-port <sp>]
				//               [destination-port <dp>] [inactivity-timeout <t>];"
				if len(prop.Keys) < 2 {
					continue
				}
				// Hierarchical: all values in prop.Keys (inline statement)
				// Flat set: values split across prop.Keys and prop.Children
				allKeys := prop.Keys[1:]
				for _, c := range prop.Children {
					allKeys = append(allKeys, c.Keys...)
				}
				termApps := parseApplicationTerms(appName, allKeys)
				terms = append(terms, termApps...)
			}
		}

		if len(terms) > 0 {
			implicitSet := &ApplicationSet{Name: appName}
			for _, t := range terms {
				t.Description = app.Description
				apps.Applications[t.Name] = t
				implicitSet.Applications = append(implicitSet.Applications, t.Name)
			}
			apps.ApplicationSets[appName] = implicitSet
		} else {
			apps.Applications[appName] = app
		}
	}

	for _, inst := range namedInstances(node.FindChildren("application-set")) {
		as := &ApplicationSet{Name: inst.name}

		for _, member := range inst.node.Children {
			// An application-set member is either an individual application
			// reference (`application <name>`) or a nested application-set
			// reference (`application-set <name>`). Both kinds are stored in
			// as.Applications; ExpandApplicationSet distinguishes them by
			// looking each member name up in apps.ApplicationSets and recursing
			// (max depth 3). Dropping the nested-set arm here silently lost the
			// child set's applications from the parent, so a policy matching the
			// parent set under-matched (#2068). This mirrors compileAddressBook,
			// which handles both `address` and `address-set` members.
			switch member.Name() {
			case "application", "application-set":
				v := nodeVal(member)
				if v != "" {
					as.Applications = append(as.Applications, v)
				}
			}
		}

		apps.ApplicationSets[as.Name] = as
	}

	return nil
}

// parseApplicationTerms parses an inline term like:
// "term-name [alg ssh] protocol tcp [source-port 22] [destination-port 22] [inactivity-timeout 86400]"
// When multiple protocol values are present, returns one Application per
// unique protocol (each sharing the same ports/timeout/alg).
func parseApplicationTerms(parentName string, keys []string) []*Application {
	if len(keys) == 0 {
		return nil
	}
	termName := keys[0]

	var protocols []string
	var dstPort, srcPort, alg string
	var timeout int
	var badTimeouts []string

	for i := 1; i < len(keys); i++ {
		switch keys[i] {
		case "protocol":
			if i+1 < len(keys) {
				i++
				protocols = append(protocols, normalizeProtocol(keys[i]))
			}
		case "destination-port":
			if i+1 < len(keys) {
				i++
				dstPort = resolveAppPort(keys[i])
			}
		case "source-port":
			if i+1 < len(keys) {
				i++
				srcPort = resolveAppPort(keys[i])
			}
		case "inactivity-timeout", "timeout":
			if i+1 < len(keys) {
				i++
				if v, ok := parseAppTimeout(keys[i]); ok {
					timeout = v
				} else {
					// #3320: malformed inline-term timeout — record the raw
					// token so the deferred strict gate rejects it instead of
					// silently dropping it.
					badTimeouts = append(badTimeouts, keys[i])
				}
			}
		case "alg":
			if i+1 < len(keys) {
				i++
				alg = keys[i]
			}
		}
	}

	// Deduplicate protocols (e.g. "junos-icmp-all" and "icmp" both normalize to "icmp")
	if len(protocols) == 0 {
		protocols = []string{""}
	}
	seen := make(map[string]bool)
	var unique []string
	for _, p := range protocols {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}

	var result []*Application
	for _, proto := range unique {
		name := parentName + "-" + termName
		if len(unique) > 1 {
			suffix := proto
			if suffix == "" {
				suffix = "any"
			}
			name = parentName + "-" + termName + "-" + suffix
		}
		result = append(result, &Application{
			Name:              name,
			Protocol:          proto,
			DestinationPort:   dstPort,
			SourcePort:        srcPort,
			InactivityTimeout: timeout,
			ALG:               alg,
			UnknownTimeouts:   badTimeouts,
		})
	}
	return result
}

// normalizeProtocol maps Junos protocol aliases to canonical names
// so that "junos-icmp-all" and "icmp" deduplicate correctly.
func normalizeProtocol(name string) string {
	switch strings.ToLower(name) {
	case "junos-icmp-all", "junos-ping":
		return "icmp"
	case "junos-icmp6-all", "junos-pingv6", "icmp6":
		return "icmpv6"
	case "junos-gre":
		return "gre"
	case "junos-ospf":
		return "89"
	case "junos-tcp-any":
		return "tcp"
	case "junos-udp-any":
		return "udp"
	case "junos-ip-in-ip", "junos-ipip":
		return "4"
	default:
		return name
	}
}

// resolveAppPort rewrites a custom-application port spec (destination-port /
// source-port) so any Junos service name is replaced by its numeric value,
// leaving the dataplane to ever parse only numerics. This is the application
// counterpart of resolveFilterPortTokens (filter_match_resolve.go): both back
// named-port resolution with the SAME junosServicePorts catalog (the single
// source of truth for Junos service-name → port number), so a name the firewall
// filter path accepts (`domain`, `www`, `kerberos-sec`, ...) is accepted here
// too — closing the #3340 gap where a custom application's destination-port only
// knew a hard-coded 15-name subset (`dns` yes, its alias `domain` no).
//
// Why resolve to a number rather than widen the accepted name set: the Rust
// dataplane's parse_port_spec (userspace-dp/src/policy.rs) and its Go mirror
// userspacePortSpecRepresentable (pkg/dataplane/userspace/capabilities.go, the
// #2124 capability gate) recognize ONLY the 15 literal names. Passing a broader
// name straight through would parse at commit but be unrepresentable at apply —
// the #2124 gate would set ForwardingSupported=false for the whole dataplane (a
// commit/apply split). Resolving to a number here means BOTH the strict commit
// gate and the runtime capability gate see the numeric form and agree.
//
// resolveFilterPort is deliberately NOT reused: it splits on '-' BEFORE a
// whole-spec name lookup, so a hyphenated service name (ftp-data, tacacs-ds,
// kerberos-sec) would be misparsed as a low-high range and rejected. The
// whole-spec catalog lookup here comes first so hyphenated names resolve.
//
// On success the canonical numeric string is returned. An UNRESOLVABLE spec
// (unknown name, out-of-range / malformed number, inverted or unresolved range)
// is returned verbatim so the caller leaves it for validatePortSpec to reject at
// the strict commit gate (and to downgrade to a warning on the lenient path) —
// the strict-reject + lenient-warn discipline (#1960/#3261). The catalog lookup
// is case-insensitive (strings.ToLower), so a mixed-case service name resolves
// rather than passing through unresolved.
func resolveAppPort(spec string) string {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return spec
	}
	// Whole-spec service name first — covers hyphenated names (ftp-data,
	// kerberos-sec) that a range-split would otherwise mangle.
	if p, ok := junosServicePorts[strings.ToLower(trimmed)]; ok {
		return strconv.Itoa(int(p))
	}
	// A bare numeric port is already in the form the dataplane wants; leave it
	// byte-identical (validatePortSpec still range-checks it).
	if _, err := strconv.Atoi(trimmed); err == nil {
		return spec
	}
	// A low-high range whose endpoints are numbers or (non-hyphenated) service
	// names: resolve each side through the catalog and emit a numeric range.
	if lo, hi, found := strings.Cut(trimmed, "-"); found {
		l, ok1 := resolveSinglePort(lo)
		h, ok2 := resolveSinglePort(hi)
		if ok1 && ok2 && l <= h {
			return fmt.Sprintf("%d-%d", l, h)
		}
	}
	// Unresolvable — return verbatim so the strict gate rejects / lenient warns.
	return spec
}

// validatePortSpec checks that a port specification is valid.
// Valid formats: "80", "8080-8090", named ports like "http".
//
// Application named ports are resolved to numerics by resolveAppPort at compile
// time (compileApplications / parseApplicationTerms), so by the time this gate
// runs a recognized service name is already a number. The 15 literal names below
// are the set the Rust dataplane (parse_port_spec) accepts directly, kept as a
// belt-and-suspenders backstop so those names still validate even if a future
// caller reaches this gate without resolving first — it stays in lock-step with
// userspacePortSpecRepresentable so this validator never accepts a raw name the
// dataplane cannot represent.
func validatePortSpec(spec string) error {
	if spec == "" {
		return nil
	}
	namedPorts := map[string]bool{
		"http": true, "https": true, "ssh": true, "telnet": true,
		"ftp": true, "ftp-data": true, "smtp": true, "dns": true,
		"pop3": true, "imap": true, "snmp": true, "ntp": true,
		"bgp": true, "ldap": true, "syslog": true,
	}
	if namedPorts[strings.ToLower(spec)] {
		return nil
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("invalid port range %q: non-numeric", spec)
		}
		if lo < 1 || lo > 65535 {
			return fmt.Errorf("invalid port %d: must be 1-65535", lo)
		}
		if hi < 1 || hi > 65535 {
			return fmt.Errorf("invalid port %d: must be 1-65535", hi)
		}
		if lo > hi {
			return fmt.Errorf("invalid port range %q: start > end", spec)
		}
		return nil
	}
	port, err := strconv.Atoi(spec)
	if err != nil {
		return fmt.Errorf("invalid port %q: not a number or known service", spec)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d: must be 1-65535", port)
	}
	return nil
}

// validateProtocol checks that a protocol specification is valid.
func validateProtocol(proto string) error {
	validProtos := map[string]bool{
		"tcp": true, "udp": true, "icmp": true, "icmp6": true, "icmpv6": true,
		"ospf": true, "gre": true, "ipip": true, "ah": true, "esp": true,
		"igmp": true, "pim": true, "sctp": true, "vrrp": true, "egp": true,
	}
	if validProtos[strings.ToLower(proto)] {
		return nil
	}
	// Accept junos-* protocol aliases
	if strings.HasPrefix(strings.ToLower(proto), "junos-") {
		return nil
	}
	n, err := strconv.Atoi(proto)
	if err != nil {
		return fmt.Errorf("invalid protocol %q", proto)
	}
	if n < 0 || n > 255 {
		return fmt.Errorf("invalid protocol number %d: must be 0-255", n)
	}
	return nil
}

func nodeVal(n *Node) string {
	if len(n.Keys) >= 2 {
		return n.Keys[1]
	}
	if len(n.Children) > 0 {
		return n.Children[0].Name()
	}
	return ""
}
