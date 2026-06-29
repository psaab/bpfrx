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
		// #3366: track whether the application carries a DIRECT match body
		// (protocol / destination-port / source-port / inactivity-timeout /
		// timeout / icmp-type / icmp-code / alg) at the application level, as
		// opposed to one or more `term` sub-blocks. Junos requires a custom
		// application to be EITHER scalar/direct OR term-based, never both. When
		// both are present the all-or-nothing store below kept only the terms and
		// silently DROPPED the direct match (e.g. a deny `protocol tcp
		// destination-port 22` erased by an unrelated term), so the parent app
		// name is recorded for the strict structure gate. `description` does NOT
		// count — it is metadata propagated onto every generated term, not a match
		// constraint.
		hasDirectBody := false
		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "protocol":
				app.Protocol = nodeVal(prop)
				hasDirectBody = true
			case "destination-port":
				app.DestinationPort = resolveAppPort(nodeVal(prop))
				hasDirectBody = true
			case "source-port":
				app.SourcePort = resolveAppPort(nodeVal(prop))
				hasDirectBody = true
			case "inactivity-timeout", "timeout":
				hasDirectBody = true
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
			case "icmp-type":
				// #3348: explicit ICMP/ICMPv6 message-type constraint for a
				// custom application. The schema range-validates 0..255 on the
				// strict commit path (schema_security.go ValidateInteger). The
				// tolerant load / peer-sync path does NOT run SchemaValidate, so
				// record a malformed value (mirroring UnknownTimeouts) rather than
				// silently dropping it — a dropped value would leave an ICMP app
				// UNCONSTRAINED (matches all types), a fail-open widening.
				hasDirectBody = true
				if v := nodeVal(prop); v != "" {
					if t, ok := parseICMPTypeCode(v); ok {
						app.ICMPType = t
					} else {
						app.UnknownICMP = append(app.UnknownICMP, v)
					}
				}
			case "icmp-code":
				hasDirectBody = true
				if v := nodeVal(prop); v != "" {
					if c, ok := parseICMPTypeCode(v); ok {
						app.ICMPCode = c
					} else {
						app.UnknownICMP = append(app.UnknownICMP, v)
					}
				}
			case "alg":
				app.ALG = nodeVal(prop)
				hasDirectBody = true
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

		// #3348: a custom application whose `protocol` is the junos-ping /
		// junos-pingv6 alias must carry the same echo-request type constraint
		// the predefined junos-ping object does (#3020). Without it the alias
		// lowered to bare ICMP with ICMPType=nil, which the userspace matcher
		// (and the pkg/policymatch simulator) treat as match-ALL ICMP — silently
		// widening any policy referencing the app to every ICMP type
		// (unreachable / redirect / timestamp / ...). Apply the default AFTER the
		// child loop so an explicit `icmp-type` leaf still wins.
		if app.ICMPType == nil {
			if t := aliasEchoICMPType(app.Protocol); t != nil {
				app.ICMPType = t
			}
		}

		if len(terms) > 0 {
			// #3366: an application that mixes a direct match body with `term`
			// sub-blocks is a Junos config error. The store below keeps ONLY the
			// terms, silently dropping the direct match (a fail-open under-match
			// for a deny application). Record the parent name so the strict
			// structure gate (validateApplicationStructureStrict) rejects it at
			// commit (lenient-warn on the tolerant load / peer-sync path) instead
			// of compiling a half-defined application.
			if hasDirectBody {
				apps.MixedDirectTermApps = append(apps.MixedDirectTermApps, appName)
			}
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
// "term-name [alg ftp] protocol tcp [source-port 22] [destination-port 22] [inactivity-timeout 86400]"
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
	var icmpType, icmpCode *uint8
	var badICMP []string
	// #3366: a scalar (single-valued) leaf repeated inside one term with a
	// DIFFERENT value — via apply-groups, flat-set ordering, or hand authoring —
	// was last-writer-wins: the loop below overwrote the earlier value with no
	// validation, silently narrowing (or widening) the term to the final token by
	// parse order. Track each scalar leaf's first assigned value so a CONFLICTING
	// repeat (a new value that silently discards the earlier one) is recorded for
	// the strict structure gate. An idempotent repeat (the same value again, e.g.
	// the `timeout` / `inactivity-timeout` aliases both set to 1800) is harmless
	// and accepted. `protocol` is deliberately EXCLUDED — a repeated `protocol` is
	// the documented multi-protocol-term syntax (one Application per unique
	// protocol), not a duplicate.
	dstPortSet, srcPortSet, algSet, timeoutSet := false, false, false, false
	var dupTermLeaves []string
	// #3352: tokens inside the inline term that are not a recognized leaf.
	// The term subtree is opaque to SchemaValidate (children:nil), so without
	// a default arm an unknown leaf (and its value) were silently dropped,
	// widening the term. Record them for the deferred strict gate.
	var badTermLeaves []string
	// #3348: per normalized-protocol echo-type implied by a junos-ping /
	// junos-pingv6 alias inside an inline term. normalizeProtocol folds the
	// alias to "icmp"/"icmpv6" and loses the ping distinction, so capture the
	// echo type keyed by the normalized protocol before that information is
	// gone.
	echoByProto := map[string]*uint8{}
	// #3348: a normalized protocol for which the SAME term also lists an
	// unconstrained ICMP alias (icmp / icmpv6 / junos-icmp-all / junos-icmp6-all)
	// that dedups onto it. Two app terms — one ping, one all-icmp — union to
	// all-ICMP in the Rust matcher (policy.rs: separate terms OR together), but
	// because both normalize to "icmp" here they collapse to ONE term. Applying
	// the junos-ping echo type to that collapsed term would spuriously NARROW the
	// union to echo-only (a widening INVERSION). Record the poisoning alias so the
	// echo default is suppressed for that protocol.
	unconstrainedICMP := map[string]bool{}

	for i := 1; i < len(keys); i++ {
		switch keys[i] {
		case "protocol":
			if i+1 < len(keys) {
				i++
				norm := normalizeProtocol(keys[i])
				protocols = append(protocols, norm)
				if t := aliasEchoICMPType(keys[i]); t != nil {
					echoByProto[norm] = t
				} else if norm == "icmp" || norm == "icmpv6" {
					// An unconstrained ICMP alias (icmp / junos-icmp-all / ...)
					// for this normalized protocol — widens to all types, so the
					// junos-ping echo narrowing must NOT apply when both land on
					// the same collapsed term.
					unconstrainedICMP[norm] = true
				}
			}
		case "icmp-type":
			if i+1 < len(keys) {
				i++
				if t, ok := parseICMPTypeCode(keys[i]); ok {
					icmpType = t
				} else {
					// #3348: a malformed inline-term icmp-type. The schema does
					// NOT validate inside an opaque `term`, so silently dropping
					// it would leave the term UNCONSTRAINED (matches all ICMP) —
					// a fail-open widening. Record it for the strict gate.
					badICMP = append(badICMP, keys[i])
				}
			}
		case "icmp-code":
			if i+1 < len(keys) {
				i++
				if c, ok := parseICMPTypeCode(keys[i]); ok {
					icmpCode = c
				} else {
					badICMP = append(badICMP, keys[i])
				}
			}
		case "destination-port":
			if i+1 < len(keys) {
				i++
				v := resolveAppPort(keys[i])
				if dstPortSet && v != dstPort {
					dupTermLeaves = append(dupTermLeaves, "destination-port")
				}
				dstPortSet = true
				dstPort = v
			}
		case "source-port":
			if i+1 < len(keys) {
				i++
				v := resolveAppPort(keys[i])
				if srcPortSet && v != srcPort {
					dupTermLeaves = append(dupTermLeaves, "source-port")
				}
				srcPortSet = true
				srcPort = v
			}
		case "inactivity-timeout", "timeout":
			if i+1 < len(keys) {
				i++
				kw := keys[i-1]
				if v, ok := parseAppTimeout(keys[i]); ok {
					if timeoutSet && v != timeout {
						dupTermLeaves = append(dupTermLeaves, kw)
					}
					timeoutSet = true
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
				if algSet && keys[i] != alg {
					dupTermLeaves = append(dupTermLeaves, "alg")
				}
				algSet = true
				alg = keys[i]
			}
		default:
			// #3352: an unrecognized token inside the inline term. This catches
			// both a typo'd leaf keyword (e.g. `destination-poort`) and the value
			// that follows it (which, being a non-keyword, also lands here) —
			// either way the term subtree carried something the parser cannot
			// honor, so record it and let validateApplicationSpecsStrict reject
			// the first one rather than silently dropping the constraint and
			// widening the match.
			badTermLeaves = append(badTermLeaves, keys[i])
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
		// An explicit inline-term `icmp-type` wins; otherwise fall back to the
		// echo type implied by a junos-ping / junos-pingv6 protocol alias on
		// this protocol (#3348) — UNLESS the same term also lists an
		// unconstrained ICMP alias that dedups onto this protocol, in which case
		// the union is all-ICMP and the echo narrowing must be suppressed.
		it := icmpType
		if it == nil && !unconstrainedICMP[proto] {
			it = echoByProto[proto]
		}
		result = append(result, &Application{
			Name:                name,
			Protocol:            proto,
			DestinationPort:     dstPort,
			SourcePort:          srcPort,
			InactivityTimeout:   timeout,
			ALG:                 alg,
			UnknownTimeouts:     badTimeouts,
			ICMPType:            it,
			ICMPCode:            icmpCode,
			UnknownICMP:         badICMP,
			UnknownTermLeaves:   badTermLeaves,
			DuplicateTermLeaves: dupTermLeaves,
		})
	}
	return result
}

// aliasEchoICMPType returns the echo-request ICMP / ICMPv6 type implied by a
// "ping" protocol alias — junos-ping -> 8 (ICMP echo-request), junos-pingv6 ->
// 128 (ICMPv6 echo-request) — or nil for any other token.
//
// #3348: a user-defined application that set `protocol junos-ping` was lowered
// to bare ICMP with no type constraint, so the projected policy term matched
// EVERY ICMP type (unreachable / redirect / timestamp / ...) — silently
// widening any policy that referenced it, and broader than the predefined
// junos-ping object which carries ICMPType=8 (#3020). Attaching the echo type
// makes a custom `protocol junos-ping` app behave like the predefined one. The
// all-ICMP aliases (junos-icmp-all / junos-icmp6-all) intentionally return nil
// so they stay unconstrained (match every type).
func aliasEchoICMPType(proto string) *uint8 {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "junos-ping":
		return u8p(8)
	case "junos-pingv6":
		return u8p(128)
	default:
		return nil
	}
}

// parseICMPTypeCode parses an application `icmp-type` / `icmp-code` token. It
// returns the value and true when the token is a base-10 integer in [0,255]
// (the ICMP/ICMPv6 type and code wire range); otherwise (nil, false). The
// strict commit path validates the range earlier via the schema
// (schema_security.go ValidateInteger(0,255)), so this is the compile-time
// projection of an already-accepted token; an unparsable value is dropped
// rather than widening the term.
func parseICMPTypeCode(raw string) (*uint8, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 0 || n > 255 {
		return nil, false
	}
	v := uint8(n)
	return &v, true
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
// resolveFilterPort (filter_match_resolve.go) now uses the SAME whole-spec
// catalog lookup first (#3397), so a hyphenated service name (ftp-data,
// tacacs-ds, kerberos-sec) resolves on BOTH the application and the firewall
// filter path. The two helpers are kept separate only because their miss
// contract differs: resolveAppPort returns the spec VERBATIM on an
// unresolvable miss (so validatePortSpec rejects it strictly / the lenient
// path warns), whereas resolveFilterPort returns ok=false so its caller keeps
// the raw token and records it on term.UnknownPorts for the filter commit
// gate.
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
// caller reaches this gate without resolving first. The name SET matches
// userspacePortSpecRepresentable (the #2124 capability gate) and Rust
// parse_port_spec, but the case handling does NOT: this gate is
// case-INSENSITIVE (strings.ToLower), whereas userspacePortSpecRepresentable /
// parse_port_spec match case-SENSITIVELY. That divergence is not a fail-open in
// practice because resolveAppPort lowercases and resolves named ports to
// numerics before this gate ever runs, so a mixed-case name ("HTTP") never
// reaches the runtime capability gate as a raw name.
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

// supportedApplicationALGs is the single source of truth for the per-application
// `alg` names xpf recognizes. It MIRRORS the global `security alg <proto>`
// control surface (schema_security.go `alg` children + algDisableFlags in
// pkg/dataplane/userspace/flow.go), which exposes exactly DNS / FTP / SIP / TFTP.
// A name outside this set is a silent operator error today: before #3353 the
// per-application `alg` leaf was a raw `args:1` string with no validator, so a
// typo (`alg ftpp`) committed cleanly and the operator believed an ALG was
// pinned when none existed.
//
// #3353 ships VALIDATION only. The per-application ALG is recorded on
// Application.ALG but is NOT carried into the userspace dataplane snapshot — the
// only ALG signal on the wire is the global alg_disable_flags bitfield
// (userspace-dp snapshot.rs), there is no per-application ALG / custom-port pin.
// Wiring per-application ALG (e.g. `alg ftp destination-port 2121`) through to
// enforcement is a genuine dataplane fork (it needs a new snapshot field plus
// Rust session-metadata handling) and is the per-application slice of the
// broader ALG parity tracked under #2008; it is deliberately deferred. Until
// then this gate makes an unsupported name an operator-visible commit error
// instead of a silent no-op.
var supportedApplicationALGs = map[string]bool{
	"dns":  true,
	"ftp":  true,
	"sip":  true,
	"tftp": true,
}

// validApplicationALG reports whether name is a supported per-application ALG.
// The match is case-insensitive (like validatePortSpec / validateProtocol). An
// empty name means "no alg" and is treated as valid by the caller before this
// is reached.
func validApplicationALG(name string) bool {
	return supportedApplicationALGs[strings.ToLower(strings.TrimSpace(name))]
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
