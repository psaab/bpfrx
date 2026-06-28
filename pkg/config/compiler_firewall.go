package config

import (
	"fmt"
	"strconv"
	"strings"
)

func compileFirewall(node *Node, fw *FirewallConfig) error {
	if fw.FiltersInet == nil {
		fw.FiltersInet = make(map[string]*FirewallFilter)
	}
	if fw.FiltersInet6 == nil {
		fw.FiltersInet6 = make(map[string]*FirewallFilter)
	}
	if fw.Policers == nil {
		fw.Policers = make(map[string]*PolicerConfig)
	}

	// Compile policer definitions
	for _, polInst := range namedInstances(node.FindChildren("policer")) {
		pol := &PolicerConfig{
			Name:       polInst.name,
			ThenAction: "discard", // default action
		}

		ifExceeding := polInst.node.FindChild("if-exceeding")
		if ifExceeding != nil {
			for _, child := range ifExceeding.Children {
				switch child.Name() {
				case "bandwidth-limit":
					if v := nodeVal(child); v != "" {
						pol.BandwidthLimit = parseBandwidthLimit(v)
					}
				case "burst-size-limit":
					if v := nodeVal(child); v != "" {
						pol.BurstSizeLimit = parseBurstSizeLimit(v)
					}
				}
			}
		}

		thenNode := polInst.node.FindChild("then")
		if thenNode != nil {
			for _, child := range thenNode.Children {
				switch child.Name() {
				case "discard":
					pol.ThenAction = "discard"
				case "loss-priority":
					if v := nodeVal(child); v != "" {
						pol.ThenAction = "loss-priority " + v
					}
				}
			}
		}

		// Check for logical-interface-policer flag
		if polInst.node.FindChild("logical-interface-policer") != nil {
			pol.LogicalInterfacePolicer = true
		}

		fw.Policers[pol.Name] = pol
	}

	// Compile three-color policer definitions
	if fw.ThreeColorPolicers == nil {
		fw.ThreeColorPolicers = make(map[string]*ThreeColorPolicerConfig)
	}
	for _, tcpInst := range namedInstances(node.FindChildren("three-color-policer")) {
		tcp := fw.ThreeColorPolicers[tcpInst.name]
		if tcp == nil {
			tcp = &ThreeColorPolicerConfig{
				Name:       tcpInst.name,
				ThenAction: "discard",
			}
			fw.ThreeColorPolicers[tcpInst.name] = tcp
		}

		singleRates := tcpInst.node.FindChildren("single-rate")
		if len(singleRates) > 0 {
			tcp.SingleRateConfigured = true
			tcp.TwoRate = false
		}
		for _, sr := range singleRates {
			if sr.FindChild("color-blind") != nil {
				tcp.ColorBlind = true
				tcp.ColorBlindConfigured = true
			}
			if sr.FindChild("color-aware") != nil {
				tcp.ColorAwareConfigured = true
			}
			for _, child := range sr.Children {
				switch child.Name() {
				case "committed-information-rate":
					if v := nodeVal(child); v != "" {
						tcp.CIR = parseBandwidthLimit(v)
					}
				case "committed-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.CBS = parseBurstSizeLimit(v)
					}
				case "excess-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.PBS = parseBurstSizeLimit(v)
					}
				}
			}
		}

		twoRates := tcpInst.node.FindChildren("two-rate")
		if len(twoRates) > 0 {
			tcp.TwoRateConfigured = true
			tcp.TwoRate = true
		}
		for _, tr := range twoRates {
			if tr.FindChild("color-blind") != nil {
				tcp.ColorBlind = true
				tcp.ColorBlindConfigured = true
			}
			if tr.FindChild("color-aware") != nil {
				tcp.ColorAwareConfigured = true
			}
			for _, child := range tr.Children {
				switch child.Name() {
				case "committed-information-rate":
					if v := nodeVal(child); v != "" {
						tcp.CIR = parseBandwidthLimit(v)
					}
				case "committed-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.CBS = parseBurstSizeLimit(v)
					}
				case "peak-information-rate":
					if v := nodeVal(child); v != "" {
						tcp.PIR = parseBandwidthLimit(v)
					}
				case "peak-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.PBS = parseBurstSizeLimit(v)
					}
				}
			}
		}

		if thenNode := tcpInst.node.FindChild("then"); thenNode != nil {
			for _, child := range thenNode.Children {
				switch child.Name() {
				case "discard":
					tcp.ThenAction = "discard"
				case "loss-priority":
					if v := nodeVal(child); v != "" {
						tcp.ThenAction = "loss-priority " + v
					}
				}
			}
		}
	}

	for _, familyNode := range node.FindChildren("family") {
		var afNodes []*Node
		var afName string

		if len(familyNode.Keys) >= 2 {
			// Hierarchical: family inet { ... }
			afName = familyNode.Keys[1]
			afNodes = []*Node{familyNode}
		} else {
			// Set-command shape: family { inet { ... } inet6 { ... } }
			for _, child := range familyNode.Children {
				afNodes = append(afNodes, child)
			}
		}

		for _, afNode := range afNodes {
			af := afName
			if af == "" {
				af = afNode.Keys[0]
				if len(afNode.Keys) >= 2 {
					af = afNode.Keys[1]
				}
			}

			dest := fw.FiltersInet
			if af == "inet6" {
				dest = fw.FiltersInet6
			}

			for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
				filter := &FirewallFilter{Name: filterInst.name}

				for _, termInst := range namedInstances(filterInst.node.FindChildren("term")) {
					term := &FirewallFilterTerm{
						Name: termInst.name,
					}

					fromNode := termInst.node.FindChild("from")
					if fromNode != nil {
						compileFilterFrom(fromNode, term, af)
					}

					thenNode := termInst.node.FindChild("then")
					if thenNode != nil {
						compileFilterThen(thenNode, term)
					}

					// #3076: reject a tcp-flags expression the dataplane cannot
					// enforce (disjunction, a negated group, an unknown flag, or
					// a self-contradictory required/forbidden pair) at commit.
					// Without this gate such an expression committed cleanly and
					// the constraint was silently dropped on the wire — the term
					// matched regardless of flags (fail-open). Rejecting here is
					// fail-closed: a dropped security constraint never silently
					// passes.
					if len(term.TCPFlags) > 0 {
						if _, _, _, err := ParseTCPFlagsExpression(term.TCPFlags); err != nil {
							return fmt.Errorf("firewall filter %q term %q: %w", filter.Name, term.Name, err)
						}
					}

					filter.Terms = append(filter.Terms, term)
				}

				dest[filter.Name] = filter
			}
		}
	}
	return nil
}

// firewallMatchValues extracts every value carried by a `from` match-criterion
// node, across BOTH parser AST shapes (#2545):
//
//   - hierarchical leaf  `protocol tcp;`            → Keys=["protocol","tcp"]
//   - bracket list       `protocol [ tcp udp ];`    → Keys=["protocol","tcp","udp"]
//   - flat set command   `... protocol tcp` (one    → Keys=["protocol"] with a
//     line per value, merged under one node)          child node per value
//
// Returning the full slice lets the caller ACCUMULATE repeated occurrences into
// a match-ANY set instead of overwriting (the prior scalar last-write-wins bug).
// Empty / blank tokens are skipped so an empty result means "criterion absent".
func firewallMatchValues(child *Node) []string {
	var vals []string
	for _, k := range child.Keys[1:] {
		if k != "" {
			vals = append(vals, k)
		}
	}
	for _, vn := range child.Children {
		if len(vn.Keys) >= 1 && vn.Keys[0] != "" {
			vals = append(vals, vn.Keys[0])
		}
	}
	return vals
}

// compileFilterFrom compiles a firewall-filter term's `from` match block. The
// family ("inet" / "inet6") selects the ICMPv4 vs ICMPv6 icmp-type name table
// when resolving symbolic icmp-type values (#3205).
func compileFilterFrom(node *Node, term *FirewallFilterTerm, family string) {
	for _, child := range node.Children {
		switch child.Name() {
		case "dscp", "traffic-class":
			// Multi-value (#2545): ACCUMULATE every value rather than
			// overwrite. Handle BOTH AST shapes — a bracket/flat-set list
			// carries values as child.Keys[1:] and/or child nodes, while a
			// hierarchical leaf carries a single value via nodeVal.
			term.DSCPs = append(term.DSCPs, firewallMatchValues(child)...)
		case "protocol", "next-header":
			// `next-header` is the IPv6 spelling of `protocol` (Junos family
			// inet6). It matches the IPv6 Next Header / L4 protocol number, which
			// the dataplane already enforces via term.Protocols — so it is an
			// ALIAS for the existing protocol matcher, not new matching. Before
			// #3307 it had no switch case and was silently dropped (the term lost
			// its protocol constraint); routing it to Protocols enforces it.
			term.Protocols = append(term.Protocols, firewallMatchValues(child)...)
		case "source-address":
			// Multi-value (#2419/#2545): a bracket/flat-set list collapses
			// onto child.Keys[1:] (firewallMatchValues), a hierarchical
			// block carries each address as a child node — handle both.
			term.SourceAddresses = append(term.SourceAddresses, firewallMatchValues(child)...)
		case "destination-address":
			term.DestAddresses = append(term.DestAddresses, firewallMatchValues(child)...)
		case "destination-port":
			// #3205: resolve named/service ports to numerics and record any
			// unresolved token for the strict commit gate (fail closed).
			term.DestinationPorts = append(term.DestinationPorts, resolveFilterPortTokens(firewallMatchValues(child), term)...)
		case "source-prefix-list":
			// Block form: source-prefix-list { mgmt-hosts except; }
			for _, plNode := range child.Children {
				ref := PrefixListRef{Name: plNode.Keys[0]}
				if len(plNode.Keys) >= 2 && plNode.Keys[1] == "except" {
					ref.Except = true
				}
				term.SourcePrefixLists = append(term.SourcePrefixLists, ref)
			}
		case "destination-prefix-list":
			for _, plNode := range child.Children {
				ref := PrefixListRef{Name: plNode.Keys[0]}
				if len(plNode.Keys) >= 2 && plNode.Keys[1] == "except" {
					ref.Except = true
				}
				term.DestPrefixLists = append(term.DestPrefixLists, ref)
			}
		case "source-port":
			term.SourcePorts = append(term.SourcePorts, resolveFilterPortTokens(firewallMatchValues(child), term)...)
		case "destination-port-except":
			// #2622 negated port match: match all destination ports EXCEPT
			// these. Multi-value/bracket-list, same accumulation as the
			// positive destination-port case. #3205: resolve named ports and
			// record unresolved tokens — an unresolved except port that slips
			// through fails OPEN (matches all ports) in the dataplane.
			term.DestPortsExcept = append(term.DestPortsExcept, resolveFilterPortTokens(firewallMatchValues(child), term)...)
		case "source-port-except":
			term.SourcePortsExcept = append(term.SourcePortsExcept, resolveFilterPortTokens(firewallMatchValues(child), term)...)
		case "icmp-type":
			// #3205: resolve symbolic icmp-type names (echo-request, ...) to
			// their numeric value using the family-appropriate Junos table.
			// strconv.Atoi alone silently dropped every name, leaving the type
			// set empty (matches ALL ICMP — a policy bypass). An unresolved
			// token is recorded for the strict commit gate (fail closed).
			for _, v := range firewallMatchValues(child) {
				if n, ok := resolveICMPTypeToken(v, family); ok {
					term.ICMPTypes = append(term.ICMPTypes, n)
				} else {
					term.UnknownICMPTypes = append(term.UnknownICMPTypes, v)
				}
			}
		case "icmp-code":
			for _, v := range firewallMatchValues(child) {
				if n, ok := resolveICMPCodeToken(v); ok {
					term.ICMPCodes = append(term.ICMPCodes, n)
				} else {
					term.UnknownICMPCodes = append(term.UnknownICMPCodes, v)
				}
			}
		case "tcp-flags":
			// Can be bracket list or single value: tcp-flags "syn ack" or [ syn ack ]
			term.TCPFlags = append(term.TCPFlags, firewallMatchValues(child)...)
		case "is-fragment":
			term.IsFragment = true
		case "flexible-match-range":
			for _, rangeInst := range namedInstances(child.FindChildren("range")) {
				fm := &FlexMatchConfig{MatchStart: "layer-3"}
				for _, rc := range rangeInst.node.Children {
					switch rc.Name() {
					case "match-start":
						if v := nodeVal(rc); v != "" {
							// #3232: only layer-3 (the default) and layer-4 are
							// implemented in the userspace matcher. `payload` (and
							// any other token) would previously be stored but
							// silently evaluated at the L3 base by the wire builder
							// and Rust matcher — a wrong-offset match (security
							// evasion). layer-3/layer-4 carry through to the wire;
							// everything else is recorded so
							// validateFilterFlexMatchStrict fails the commit closed.
							switch v {
							case "layer-3", "layer-4":
								fm.MatchStart = v
							default:
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "match-start "+v)
							}
						}
					case "byte-offset":
						if v := nodeVal(rc); v != "" {
							// #3203: a parse error (or a value outside 0..255,
							// the wire field width) must FAIL CLOSED at commit,
							// not silently coerce the offset to 0. Record the
							// token for validateFilterFlexMatchStrict.
							if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 255 {
								fm.ByteOffset = uint8(n)
							} else {
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "byte-offset "+v)
							}
						}
					case "bit-length":
						if v := nodeVal(rc); v != "" {
							// #3203: bit-length must be 1..32 (the wire value is a
							// u32 read of ceil(bits/8) bytes). strconv.Atoi
							// followed by an unchecked uint8() cast previously
							// truncated an out-of-range value (e.g. 999 -> 231)
							// silently; a non-numeric token was ignored, leaving
							// bit-length 0 (later defaulted to 32). Fail closed on
							// either by recording the token.
							if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 32 {
								fm.BitLength = uint8(n)
							} else {
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "bit-length "+v)
							}
						}
					case "range", "match-value":
						if v := nodeVal(rc); v != "" {
							// Format: "0xVALUE/0xMASK" or just "0xVALUE".
							// #3203: a ParseUint error (malformed hex or a value
							// wider than 32 bits) previously left fm.Value/fm.Mask
							// at the zero default — the rule then matched value 0
							// instead of the intended pattern, with a clean
							// commit. Fail closed: record the unparseable token.
							parts := strings.SplitN(v, "/", 2)
							if val, err := strconv.ParseUint(strings.TrimPrefix(parts[0], "0x"), 16, 32); err == nil {
								fm.Value = uint32(val)
							} else {
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "match-value "+parts[0])
							}
							if len(parts) == 2 {
								if mask, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "0x"), 16, 32); err == nil {
									fm.Mask = uint32(mask)
								} else {
									term.UnknownFlexMatch = append(term.UnknownFlexMatch, "match-mask "+parts[1])
								}
							}
						}
					case "match-mask":
						if v := nodeVal(rc); v != "" {
							if mask, err := strconv.ParseUint(strings.TrimPrefix(v, "0x"), 16, 32); err == nil {
								fm.Mask = uint32(mask)
							} else {
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "match-mask "+v)
							}
						}
					}
				}
				if fm.BitLength == 0 {
					fm.BitLength = 32 // default to 32-bit match
				}
				if fm.Mask == 0 {
					// #3203: default mask = the low BitLength bits set, for ANY
					// 1..32-bit length (not just 8/16). The Rust matcher
					// (userspace-dp/src/filter/engine/matching.rs) reads
					// ceil(bits/8) bytes big-endian into a u32 (right-aligned in
					// the low bits) and compares (read & mask) == value, so a
					// 24-bit field needs 0x00FFFFFF. The old code defaulted every
					// non-8/16 length to 0xFFFFFFFF, which that read could never
					// satisfy for a value with a non-zero high byte.
					if fm.BitLength >= 32 {
						fm.Mask = 0xFFFFFFFF
					} else {
						fm.Mask = uint32(1)<<fm.BitLength - 1
					}
				}
				term.FlexMatch = fm
				break // only first range supported per term
			}
		default:
			// #3307: a `from` match leaf the dataplane does NOT enforce. The
			// schema gate is opt-in, so an unknown leaf (ttl, source-mac-address,
			// ip-options, fragment-offset, hop-limit, ...) passes commit and was
			// previously dropped silently here — the term then enforced a BROADER
			// match than authored (an accept over-permits, a discard/reject
			// over-drops). Record it so validateFilterFromMatchStrict can reject
			// the commit fail-closed instead of silently dropping the constraint.
			// The enforced set is exactly the cases above; every one maps to a
			// wire field the snapshot builder emits and the Rust matcher reads.
			term.UnknownFrom = append(term.UnknownFrom, child.Name())
		}
	}
}

// rejectMessageTypes is the set of message-types Junos accepts after
// `then reject <type>` (RFC 792 ICMP-unreachable codes plus tcp-reset). A term
// with one of these still acts as a plain reject — the dataplane does not act
// on the message-type today (#2399 fold) — but the type is recognized so a real
// Juniper config import (`then reject tcp-reset`) commits cleanly instead of
// being flagged as an unknown action. A token NOT in this set after `reject` is
// a typo and is still flagged.
var rejectMessageTypes = map[string]bool{
	"administratively-prohibited": true,
	"bad-host-tos":                true,
	"bad-network-tos":             true,
	"host-prohibited":             true,
	"host-unreachable":            true,
	"network-prohibited":          true,
	"network-unreachable":         true,
	"port-unreachable":            true,
	"precedence-cutoff":           true,
	"precedence-violation":        true,
	"protocol-unreachable":        true,
	"source-host-isolated":        true,
	"source-route-failed":         true,
	"tcp-reset":                   true,
}

func compileFilterThen(node *Node, term *FirewallFilterTerm) {
	// Handle leaf form: "then discard;" or "then accept;" produces
	// Keys=["then", "discard"] with IsLeaf=true and no children. A leaf can
	// also carry an argument-bearing modifier, e.g. "then forwarding-class be"
	// → Keys=["then","forwarding-class","be"], so the keyword consumes its
	// following token rather than treating it as a separate action.
	if node.IsLeaf && len(node.Keys) >= 2 {
		keys := node.Keys[1:]
		for i := 0; i < len(keys); i++ {
			k := keys[i]
			arg := func() string {
				// Consume the modifier's argument if present.
				if i+1 < len(keys) {
					i++
					return keys[i]
				}
				return ""
			}
			switch k {
			case "accept":
				term.Action = "accept"
			case "reject":
				term.Action = "reject"
				// Junos `then reject <message-type>`: the term is a plain
				// reject; capture a KNOWN message-type for fidelity. Only
				// consume the following token if it is a recognized type — a
				// typo (e.g. `reject blorp`) must fall through to the default
				// arm and be flagged, not silently swallowed as the reject arg.
				if i+1 < len(keys) && rejectMessageTypes[keys[i+1]] {
					i++
					term.RejectMessageType = keys[i]
				}
			case "discard":
				term.Action = "discard"
			case "next":
				// `then next term` / bare `then next` — explicit fall-through
				// to the next term (a no-op terminating-wise). Consume an
				// optional "term" token.
				term.NextTerm = true
				if i+1 < len(keys) && keys[i+1] == "term" {
					i++
				}
			case "log":
				term.Log = true
			case "syslog":
				term.Log = true
			case "routing-instance":
				if v := arg(); v != "" {
					term.RoutingInstance = v
				}
			case "count":
				if v := arg(); v != "" {
					term.Count = v
				}
			case "forwarding-class":
				if v := arg(); v != "" {
					term.ForwardingClass = v
				}
			case "loss-priority":
				if v := arg(); v != "" {
					term.LossPriority = v
				}
			case "dscp", "traffic-class":
				if v := arg(); v != "" {
					term.DSCPRewrite = v
				}
			case "policer":
				if v := arg(); v != "" {
					term.Policer = v
				}
			default:
				// #2399 (032-16): an unrecognized `then` token must NOT be
				// silently dropped — it would default to ACCEPT in the
				// dataplane (fail-open). Record it so the strict commit gate
				// (validateFilterActionsStrict) can reject the operator's typo.
				term.UnknownActions = append(term.UnknownActions, k)
			}
		}
		return
	}

	for _, child := range node.Children {
		switch child.Name() {
		case "accept":
			term.Action = "accept"
		case "reject":
			term.Action = "reject"
			// `then reject <message-type>` — capture a KNOWN type for fidelity;
			// a typo after reject is flagged (see leaf-form note above). The
			// message-type is the second key (block form) or a single child.
			if len(child.Keys) >= 2 && rejectMessageTypes[child.Keys[1]] {
				term.RejectMessageType = child.Keys[1]
			} else if len(child.Keys) >= 2 {
				// Unknown token after reject — a typo. Flag it.
				term.UnknownActions = append(term.UnknownActions, "reject "+child.Keys[1])
			} else {
				for _, mt := range child.Children {
					if len(mt.Keys) >= 1 {
						if rejectMessageTypes[mt.Keys[0]] {
							term.RejectMessageType = mt.Keys[0]
						} else {
							term.UnknownActions = append(term.UnknownActions, "reject "+mt.Keys[0])
						}
					}
				}
			}
		case "discard":
			term.Action = "discard"
		case "next":
			// `then next term` / bare `then next` — explicit fall-through.
			term.NextTerm = true
		case "log":
			term.Log = true
		case "syslog":
			term.Log = true
		case "routing-instance":
			if len(child.Keys) >= 2 {
				term.RoutingInstance = child.Keys[1]
			}
		case "count":
			if len(child.Keys) >= 2 {
				term.Count = child.Keys[1]
			}
		case "forwarding-class":
			if len(child.Keys) >= 2 {
				term.ForwardingClass = child.Keys[1]
			}
		case "loss-priority":
			if len(child.Keys) >= 2 {
				term.LossPriority = child.Keys[1]
			}
		case "dscp", "traffic-class":
			term.DSCPRewrite = nodeVal(child)
		case "policer":
			if len(child.Keys) >= 2 {
				term.Policer = child.Keys[1]
			}
		default:
			// #2399 (032-16): see leaf-form note above — record the unknown
			// `then` token for the strict commit gate instead of dropping it.
			term.UnknownActions = append(term.UnknownActions, child.Name())
		}
	}
}
