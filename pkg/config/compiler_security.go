package config

import (
	"fmt"
	"net"
	"sort"
	"strconv"
)

// maxScanSweepThreshold is the largest port-scan / ip-sweep threshold the
// AF_XDP dataplane can actually enforce. The dataplane tracks at most
// MAX_UNIQUE_PER_SOURCE (1024) unique destinations/ports per (zone, source)
// within the detection window and bounds memory at that cap, so the effective
// comparison threshold is clamped to MAX_UNIQUE_PER_SOURCE - 1 (fail-closed:
// a saturated set always crosses it — see
// userspace-dp/src/screen/scan.rs `check_unique`). A configured threshold
// above this value is preserved unchanged in the typed config but is clamped
// to this maximum at runtime; we warn the operator at commit time.
//
// MUST stay in sync with the Rust constant MAX_UNIQUE_PER_SOURCE in
// userspace-dp/src/screen/scan.rs (= maxScanSweepThreshold + 1).
const maxScanSweepThreshold = 1023

// defaultSynFloodAttackThreshold is the Junos SRX default attack-threshold
// (SYN segments per second) applied when a syn-flood screen is enabled
// without an explicit `attack-threshold`. Matching Junos, configuring
// syn-flood with only source/destination-threshold or timeout still arms
// the screen at this rate. See pkg/config/compiler_security.go syn-flood
// parse and the dataplane gate in pkg/dataplane/compiler_iface.go (#3024).
const defaultSynFloodAttackThreshold = 200

// validateScreenScanSweepThresholds emits a WARNING (never a hard reject) for
// any screen profile whose port-scan or ip-sweep threshold exceeds
// maxScanSweepThreshold. The dataplane clamps the effective threshold to that
// maximum (fail-closed), so a larger configured value detects AT THE CAP
// rather than as configured. We preserve the operator's configured value (no
// mutation, no rejection — existing configs keep booting) and tell them it is
// clamped. Clamp-warn applies on BOTH the strict and lenient compile paths:
// the value is valid and parseable, it just exceeds what the dataplane can
// enforce.
func validateScreenScanSweepThresholds(cfg *Config) []string {
	var warnings []string
	// Deterministic order so the warning set is stable across runs.
	names := make([]string, 0, len(cfg.Security.Screen))
	for name := range cfg.Security.Screen {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sp := cfg.Security.Screen[name]
		if sp == nil {
			continue
		}
		if sp.TCP.PortScanThreshold > maxScanSweepThreshold {
			warnings = append(warnings, fmt.Sprintf(
				"security screen ids-option %s tcp port-scan threshold %d exceeds the "+
					"dataplane maximum (%d) and will be clamped to %d at runtime "+
					"(detection fires at the cap, not at the configured value)",
				name, sp.TCP.PortScanThreshold, maxScanSweepThreshold, maxScanSweepThreshold))
		}
		if sp.IP.IPSweepThreshold > maxScanSweepThreshold {
			warnings = append(warnings, fmt.Sprintf(
				"security screen ids-option %s ip ip-sweep threshold %d exceeds the "+
					"dataplane maximum (%d) and will be clamped to %d at runtime "+
					"(detection fires at the cap, not at the configured value)",
				name, sp.IP.IPSweepThreshold, maxScanSweepThreshold, maxScanSweepThreshold))
		}
	}
	return warnings
}

func compileSecurity(node *Node, sec *SecurityConfig) error {
	for _, child := range node.Children {
		switch child.Name() {
		case "zones":
			if err := compileZones(child, sec); err != nil {
				return fmt.Errorf("zones: %w", err)
			}
		case "policies":
			if err := compilePolicies(child, sec); err != nil {
				return fmt.Errorf("policies: %w", err)
			}
		case "screen":
			if err := compileScreen(child, sec); err != nil {
				return fmt.Errorf("screen: %w", err)
			}
		case "nat":
			if err := compileNAT(child, sec); err != nil {
				return fmt.Errorf("nat: %w", err)
			}
		case "address-book":
			if err := compileAddressBook(child, sec); err != nil {
				return fmt.Errorf("address-book: %w", err)
			}
		case "log":
			if err := compileLog(child, sec); err != nil {
				return fmt.Errorf("log: %w", err)
			}
		case "flow":
			if err := compileFlow(child, sec); err != nil {
				return fmt.Errorf("flow: %w", err)
			}
		case "ike":
			if err := compileIKE(child, sec); err != nil {
				return fmt.Errorf("ike: %w", err)
			}
		case "ipsec":
			if err := compileIPsec(child, sec); err != nil {
				return fmt.Errorf("ipsec: %w", err)
			}
		case "dynamic-address":
			if err := compileDynamicAddress(child, sec); err != nil {
				return fmt.Errorf("dynamic-address: %w", err)
			}
		case "alg":
			if err := compileALG(child, sec); err != nil {
				return fmt.Errorf("alg: %w", err)
			}
		case "ssh-known-hosts":
			sec.SSHKnownHosts = make(map[string][]SSHKnownHostKey)
			for _, hostInst := range namedInstances(child.FindChildren("host")) {
				var keys []SSHKnownHostKey
				for _, kp := range hostInst.node.Children {
					name := kp.Name()
					if v := nodeVal(kp); v != "" {
						keys = append(keys, SSHKnownHostKey{Type: name, Key: v})
					}
				}
				sec.SSHKnownHosts[hostInst.name] = keys
			}
		case "policy-stats":
			if sw := child.FindChild("system-wide"); sw != nil {
				sec.PolicyStatsEnabled = nodeVal(sw) == "enable"
			}
		case "pre-id-default-policy":
			sec.PreIDDefaultPolicy = &PreIDDefaultPolicy{}
			if thenNode := child.FindChild("then"); thenNode != nil {
				if logNode := thenNode.FindChild("log"); logNode != nil {
					if logNode.FindChild("session-init") != nil {
						sec.PreIDDefaultPolicy.LogSessionInit = true
					}
					if logNode.FindChild("session-close") != nil {
						sec.PreIDDefaultPolicy.LogSessionClose = true
					}
				}
			}
		}
	}
	return nil
}

func compileZones(node *Node, sec *SecurityConfig) error {
	for _, inst := range namedInstances(node.FindChildren("security-zone")) {
		zone := &ZoneConfig{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "interfaces":
				for _, iface := range prop.Children {
					zone.Interfaces = append(zone.Interfaces, iface.Name())
				}
			case "screen":
				zone.ScreenProfile = nodeVal(prop)
			case "host-inbound-traffic":
				zone.HostInboundTraffic = &HostInboundTraffic{}
				for _, hit := range prop.Children {
					switch hit.Name() {
					case "system-services":
						for _, svc := range hit.Children {
							zone.HostInboundTraffic.SystemServices = append(
								zone.HostInboundTraffic.SystemServices, svc.Name())
						}
					case "protocols":
						for _, proto := range hit.Children {
							zone.HostInboundTraffic.Protocols = append(
								zone.HostInboundTraffic.Protocols, proto.Name())
						}
					}
				}
			case "tcp-rst":
				zone.TCPRst = true
			case "description":
				zone.Description = nodeVal(prop)
			}
		}

		sec.Zones[inst.name] = zone
	}
	return nil
}

func compilePolicies(node *Node, sec *SecurityConfig) error {
	for _, child := range node.Children {
		if child.Name() == "default-policy" {
			var policyStr string
			if len(child.Keys) >= 2 {
				// Flat form: default-policy deny-all;
				policyStr = child.Keys[1]
			} else if len(child.Children) > 0 {
				// Hierarchical form: default-policy { deny-all; }
				policyStr = child.Children[0].Name()
			}
			switch policyStr {
			case "permit-all":
				sec.DefaultPolicy = PolicyPermit
			case "deny-all":
				sec.DefaultPolicy = PolicyDeny
			case "reject-all":
				// #3065: reject-all is valid Junos; previously it fell
				// through this switch and left the (now deny) default
				// untouched. Map it to PolicyReject so the dataplane
				// no-match verdict sends an ICMP/RST reject instead of a
				// silent drop.
				sec.DefaultPolicy = PolicyReject
			}
			continue
		}
		// "global { policy ... }" - global policies applied to all zone pairs
		if child.Name() == "global" {
			for _, polInst := range namedInstances(child.FindChildren("policy")) {
				pol := compilePolicy(polInst)
				sec.GlobalPolicies = append(sec.GlobalPolicies, pol)
			}
			continue
		}
		// "from-zone trust to-zone untrust { ... }"
		if child.Name() == "from-zone" {
			type zonePair struct {
				from, to   string
				policyNode *Node
			}
			var pairs []zonePair

			if len(child.Keys) >= 4 {
				// Hierarchical: Keys=["from-zone", "trust", "to-zone", "untrust"]
				pairs = append(pairs, zonePair{child.Keys[1], child.Keys[3], child})
			} else {
				// Flat set: from-zone → <name> → to-zone → <name> → policy ...
				for _, fzSub := range child.Children {
					tzNode := fzSub.FindChild("to-zone")
					if tzNode == nil {
						continue
					}
					for _, tzSub := range tzNode.Children {
						pairs = append(pairs, zonePair{fzSub.Name(), tzSub.Name(), tzSub})
					}
				}
			}

			for _, zp := range pairs {
				zpp := &ZonePairPolicies{
					FromZone: zp.from,
					ToZone:   zp.to,
				}

				for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
					zpp.Policies = append(zpp.Policies, compilePolicy(polInst))
				}

				sec.Policies = append(sec.Policies, zpp)
			}
		}
	}
	return nil
}

// normalizePolicyAddrToken rewrites the Junos wildcard policy-match
// address keywords `any-ipv4` and `any-ipv6` into their concrete CIDR
// equivalents (`0.0.0.0/0` and `::/0`). Without this rewrite the
// tokens reach the dataplane as opaque strings that fail CIDR parsing
// and are silently dropped, so a policy keyed on `any-ipv4` would
// never match v4 traffic (#2008 H11). The plain `any` keyword is left
// intact — the dataplane already treats it as match-any on both
// families. All other tokens (address-book names, literal CIDRs) pass
// through unchanged.
func normalizePolicyAddrToken(tok string) string {
	switch tok {
	case "any-ipv4":
		return "0.0.0.0/0"
	case "any-ipv6":
		return "::/0"
	default:
		return tok
	}
}

func normalizePolicyAddrTokens(toks []string) []string {
	out := make([]string, 0, len(toks))
	for _, t := range toks {
		out = append(out, normalizePolicyAddrToken(t))
	}
	return out
}

// compilePolicy extracts a Policy from a named policy instance.
func compilePolicy(polInst struct {
	name string
	node *Node
}) *Policy {
	pol := &Policy{Name: polInst.name}

	matchNode := polInst.node.FindChild("match")
	if matchNode != nil {
		for _, m := range matchNode.Children {
			switch m.Name() {
			case "source-address":
				if len(m.Keys) >= 2 {
					pol.Match.SourceAddresses = append(pol.Match.SourceAddresses, normalizePolicyAddrTokens(m.Keys[1:])...)
				} else {
					for _, c := range m.Children {
						pol.Match.SourceAddresses = append(pol.Match.SourceAddresses, normalizePolicyAddrToken(c.Name()))
					}
				}
			case "destination-address":
				if len(m.Keys) >= 2 {
					pol.Match.DestinationAddresses = append(pol.Match.DestinationAddresses, normalizePolicyAddrTokens(m.Keys[1:])...)
				} else {
					for _, c := range m.Children {
						pol.Match.DestinationAddresses = append(pol.Match.DestinationAddresses, normalizePolicyAddrToken(c.Name()))
					}
				}
			case "source-address-excluded":
				pol.Match.SourceAddressExcluded = true
			case "destination-address-excluded":
				pol.Match.DestinationAddressExcluded = true
			case "application":
				if len(m.Keys) >= 2 {
					pol.Match.Applications = append(pol.Match.Applications, m.Keys[1:]...)
				} else {
					for _, c := range m.Children {
						pol.Match.Applications = append(pol.Match.Applications, c.Name())
					}
				}
			}
		}
	}

	thenNode := polInst.node.FindChild("then")
	if thenNode != nil {
		for _, t := range thenNode.Children {
			switch t.Name() {
			case "permit":
				pol.Action = PolicyPermit
				pol.terminalActions = append(pol.terminalActions, PolicyPermit)
			case "deny":
				pol.Action = PolicyDeny
				pol.terminalActions = append(pol.terminalActions, PolicyDeny)
			case "reject":
				pol.Action = PolicyReject
				pol.terminalActions = append(pol.terminalActions, PolicyReject)
			case "log":
				pol.Log = &PolicyLog{}
				for _, logOpt := range t.Children {
					switch logOpt.Name() {
					case "session-init":
						pol.Log.SessionInit = true
					case "session-close":
						pol.Log.SessionClose = true
					}
				}
			case "count":
				pol.Count = true
			}
		}
	}

	// #3043 fail-closed default: a policy with NO explicit terminal action
	// (a log-only / count-only stanza, or a typo'd `then`) must NOT inherit
	// PolicyPermit (the PolicyAction zero value) — that was a silent
	// fail-OPEN. Default the runtime action to DENY so the tolerant
	// load / HA-sync path (which only WARNS, see
	// validatePolicyTerminalActionStrict + lenientPolicyTerminalAction)
	// fails closed; the strict commit path rejects the actionless policy
	// outright (terminalActions is empty). Conflicting actions keep the
	// pre-existing last-wins runtime value so a leniently-loaded config
	// still boots; the strict gate rejects the conflict at commit.
	if len(pol.terminalActions) == 0 {
		pol.Action = PolicyDeny
	}

	if descNode := polInst.node.FindChild("description"); descNode != nil {
		pol.Description = nodeVal(descNode)
	}
	if snNode := polInst.node.FindChild("scheduler-name"); snNode != nil {
		pol.SchedulerName = nodeVal(snNode)
	}

	return pol
}

func compileScreen(node *Node, sec *SecurityConfig) error {
	for _, inst := range namedInstances(node.FindChildren("ids-option")) {
		profile := &ScreenProfile{Name: inst.name}

		icmpNode := inst.node.FindChild("icmp")
		if icmpNode != nil {
			for _, opt := range icmpNode.Children {
				switch opt.Name() {
				case "ping-death":
					profile.ICMP.PingDeath = true
				case "flood":
					if len(opt.Keys) >= 3 {
						if v, err := strconv.Atoi(opt.Keys[2]); err == nil {
							profile.ICMP.FloodThreshold = v
						}
					} else if v := nodeVal(opt); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							profile.ICMP.FloodThreshold = n
						}
					}
				}
			}
		}

		ipNode := inst.node.FindChild("ip")
		if ipNode != nil {
			for _, opt := range ipNode.Children {
				switch opt.Name() {
				case "source-route-option":
					profile.IP.SourceRouteOption = true
				case "tear-drop":
					profile.IP.TearDrop = true
				case "ip-sweep":
					for _, swOpt := range opt.Children {
						if swOpt.Name() == "threshold" {
							val := nodeVal(swOpt)
							if val == "" && len(swOpt.Keys) >= 2 {
								val = swOpt.Keys[1]
							}
							if n, err := strconv.Atoi(val); err == nil {
								profile.IP.IPSweepThreshold = n
							}
						}
					}
				}
			}
		}

		tcpNode := inst.node.FindChild("tcp")
		if tcpNode != nil {
			for _, opt := range tcpNode.Children {
				switch opt.Name() {
				case "land":
					profile.TCP.Land = true
				case "winnuke":
					profile.TCP.WinNuke = true
				case "syn-frag":
					profile.TCP.SynFrag = true
				case "syn-fin":
					profile.TCP.SynFin = true
				case "no-flag":
					profile.TCP.NoFlag = true
				case "fin-no-ack":
					profile.TCP.FinNoAck = true
				case "syn-flood":
					sf := &SynFloodConfig{}
					for _, sfOpt := range opt.Children {
						val := nodeVal(sfOpt)
						if val == "" && len(sfOpt.Keys) >= 2 {
							val = sfOpt.Keys[1]
						}
						if val != "" {
							n, _ := strconv.Atoi(val)
							switch sfOpt.Name() {
							case "alarm-threshold":
								sf.AlarmThreshold = n
							case "attack-threshold":
								sf.AttackThreshold = n
							case "source-threshold":
								sf.SourceThreshold = n
							case "destination-threshold":
								sf.DestinationThreshold = n
							case "timeout":
								sf.Timeout = n
							}
						}
					}
					// Junos applies a default attack-threshold of 200
					// SYN segments/second when syn-flood screening is
					// enabled without an explicit attack-threshold. Without
					// this fallback the downstream dataplane gate (which
					// requires AttackThreshold > 0) would silently leave
					// SYN-flood protection — including syn-cookie — disabled
					// even though the operator configured it (#3024).
					if sf.AttackThreshold <= 0 {
						sf.AttackThreshold = defaultSynFloodAttackThreshold
					}
					profile.TCP.SynFlood = sf
				case "port-scan":
					for _, psOpt := range opt.Children {
						if psOpt.Name() == "threshold" {
							val := nodeVal(psOpt)
							if val == "" && len(psOpt.Keys) >= 2 {
								val = psOpt.Keys[1]
							}
							if n, err := strconv.Atoi(val); err == nil {
								profile.TCP.PortScanThreshold = n
							}
						}
					}
				}
			}
		}

		udpNode := inst.node.FindChild("udp")
		if udpNode != nil {
			for _, opt := range udpNode.Children {
				switch opt.Name() {
				case "flood":
					if len(opt.Keys) >= 3 {
						if v, err := strconv.Atoi(opt.Keys[2]); err == nil {
							profile.UDP.FloodThreshold = v
						}
					} else if v := nodeVal(opt); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							profile.UDP.FloodThreshold = n
						}
					}
				}
			}
		}

		limitNode := inst.node.FindChild("limit-session")
		if limitNode != nil {
			for _, opt := range limitNode.Children {
				val := nodeVal(opt)
				if val == "" && len(opt.Keys) >= 2 {
					val = opt.Keys[1]
				}
				if val != "" {
					n, _ := strconv.Atoi(val)
					switch opt.Name() {
					case "source-ip-based":
						profile.LimitSession.SourceIPBased = n
					case "destination-ip-based":
						profile.LimitSession.DestinationIPBased = n
					}
				}
			}
		}

		sec.Screen[profile.Name] = profile
	}
	return nil
}

func compileAddressBook(node *Node, sec *SecurityConfig) error {
	globalNode := node.FindChild("global")
	if globalNode == nil {
		return nil
	}

	ab := &AddressBook{
		Addresses:   make(map[string]*Address),
		AddressSets: make(map[string]*AddressSet),
	}

	for _, child := range globalNode.Children {
		switch child.Name() {
		case "address":
			// A single Junos `address <name>` may render as MULTIPLE sibling
			// AST nodes (flat-set: one leaf per sub-stanza) or as a single
			// hierarchical block, and the sub-stanzas (prefix, description,
			// ...) arrive in arbitrary order. Merge by name so a described
			// address keeps its prefix and a non-prefix sub-stanza never
			// overwrites Value (#2222).
			if len(child.Keys) < 2 {
				continue
			}
			name := child.Keys[1]
			addr := ab.Addresses[name]
			if addr == nil {
				addr = &Address{Name: name}
				ab.Addresses[name] = addr
			}
			mergeAddressNode(addr, child)
		case "address-set":
			if len(child.Keys) >= 2 {
				as := &AddressSet{Name: child.Keys[1]}
				for _, member := range child.Children {
					switch member.Name() {
					case "address":
						if len(member.Keys) >= 2 {
							as.Addresses = append(as.Addresses, member.Keys[1])
						}
					case "address-set":
						if len(member.Keys) >= 2 {
							as.AddressSets = append(as.AddressSets, member.Keys[1])
						}
					}
				}
				ab.AddressSets[as.Name] = as
			}
		}
	}

	sec.AddressBook = ab
	return nil
}

// mergeAddressNode folds one `address <name> ...` AST node into addr,
// handling both AST shapes and arbitrary sub-stanza ordering (#2222):
//
//   - flat-set prefix leaf:   Keys=[address name <prefix>], IsLeaf, no children
//   - flat-set sub-stanza:    Keys=[address name <kw> ...] with children
//     (e.g. [address name description] + child [web-server])
//   - hierarchical block:     Keys=[address name] with bare-leaf prefix child
//     and/or [description <text>] child
//
// The prefix is taken from Keys[2] ONLY when it parses as a CIDR/IP, never
// when it is a sub-stanza keyword such as "description". A bare-leaf child
// (hierarchical block prefix) is the other prefix source. Description is
// routed to its own field so it can never clobber Value.
func mergeAddressNode(addr *Address, node *Node) {
	// Sub-stanza keyword form: Keys[2] is a known attribute keyword
	// (currently only "description"), so it is NOT the prefix.
	if len(node.Keys) >= 3 && node.Keys[2] == "description" {
		if d := descriptionText(node); d != "" {
			addr.Description = d
		}
		return
	}

	// Prefix-bearing leaf: Keys[2] is the prefix iff it parses as an IP/CIDR.
	if len(node.Keys) >= 3 && looksLikeIPOrCIDR(node.Keys[2]) {
		addr.Value = node.Keys[2]
	}

	// Hierarchical-block children: bare-leaf prefix and/or `description`.
	for _, sub := range node.Children {
		switch sub.Name() {
		case "description":
			if d := nodeVal(sub); d != "" {
				addr.Description = d
			}
		default:
			// A bare value leaf (the hierarchical block prefix) parses as a
			// single token that is an IP/CIDR. Anything else is an unknown
			// sub-stanza and is intentionally ignored (preserves the prior
			// permissive behaviour; the warn validator flags a bad Value).
			if len(sub.Keys) == 1 && looksLikeIPOrCIDR(sub.Keys[0]) {
				addr.Value = sub.Keys[0]
			}
		}
	}
}

// descriptionText extracts the description string from a flat-set
// `address <name> description <text>` node. Two AST shapes are accepted
// (#2419 unified the multi-value flat-set leaf onto the node's own keys):
//
//   - unified leaf:  Keys=[address, name, description, <text>], no children
//   - legacy split:  Keys=[address, name, description] + child leaf <text>
//
// The unified form is what both the hierarchical parser and the post-#2419
// flat-set SetPath now produce for any multi-value leaf, so it is checked
// first; the child-leaf form is kept for backward compatibility.
func descriptionText(node *Node) string {
	if len(node.Keys) >= 4 {
		return node.Keys[3]
	}
	if len(node.Children) > 0 {
		return node.Children[0].Name()
	}
	return ""
}

// looksLikeIPOrCIDR reports whether s is a bare IP or a CIDR prefix,
// mirroring the acceptance of the address-book warn validator
// (net.ParseCIDR || net.ParseIP).
func looksLikeIPOrCIDR(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}

func compileLog(node *Node, sec *SecurityConfig) error {
	if sec.Log.Streams == nil {
		sec.Log.Streams = make(map[string]*SyslogStream)
	}

	// Top-level log settings
	if modeNode := node.FindChild("mode"); modeNode != nil {
		sec.Log.Mode = nodeVal(modeNode)
	}
	if fmtNode := node.FindChild("format"); fmtNode != nil {
		sec.Log.Format = nodeVal(fmtNode)
	}
	if srcNode := node.FindChild("source-interface"); srcNode != nil {
		sec.Log.SourceInterface = nodeVal(srcNode)
	}
	if node.FindChild("report") != nil {
		sec.Log.Report = true
	}

	for _, inst := range namedInstances(node.FindChildren("stream")) {
		stream := &SyslogStream{
			Name: inst.name,
			Port: 514, // default
		}
		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "host":
				// Flat: host 192.168.99.3;
				if v := nodeVal(prop); v != "" {
					stream.Host = v
				}
				// Nested: host { 192.168.99.3; port 9006; }
				for _, hc := range prop.Children {
					switch hc.Name() {
					case "port":
						if v := nodeVal(hc); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								stream.Port = n
							}
						}
					default:
						// IP address as a bare child node
						if stream.Host == "" && len(hc.Keys) >= 1 {
							stream.Host = hc.Keys[0]
						}
					}
				}
			case "port":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						stream.Port = n
					}
				}
			case "severity":
				stream.Severity = nodeVal(prop)
			case "facility":
				stream.Facility = nodeVal(prop)
			case "format":
				stream.Format = nodeVal(prop)
			case "category":
				stream.Category = nodeVal(prop)
			case "source-address":
				stream.SourceAddress = nodeVal(prop)
			case "transport":
				for _, tc := range prop.Children {
					switch tc.Name() {
					case "protocol":
						stream.Transport.Protocol = nodeVal(tc)
					case "tls-profile":
						stream.Transport.TLSProfile = nodeVal(tc)
					}
				}
			}
		}
		if stream.Host != "" {
			sec.Log.Streams[stream.Name] = stream
		}
	}

	// H7 (#2008): `security log profile <name>` log-routing objects. Each
	// names a target stream (`stream-name`), may be marked the default
	// (`default-profile`), and may carry per-category field config. Reads
	// via namedInstances + nodeVal so both hierarchical and flat-set AST
	// shapes work (same as the stream loop). The stream-name cross-
	// reference is enforced after full compile in
	// validateLogProfileStreamReferencesStrict — schema_walk per-leaf
	// validators cannot see sibling stream nodes. `category` is accepted
	// for parse/validation parity; per-category field-extra-name selection
	// is not yet used to alter the emitted structured data (out of scope).
	for _, inst := range namedInstances(node.FindChildren("profile")) {
		p := &LogProfile{Name: inst.name}
		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "stream-name":
				p.StreamName = nodeVal(prop)
			case "default-profile":
				p.DefaultProfile = true
			case "category":
				// Accepted for parity; field-extra-name emission is out of
				// scope for this increment (xpf already emits per-stream
				// structured data).
			}
		}
		if sec.Log.Profiles == nil {
			sec.Log.Profiles = make(map[string]*LogProfile)
		}
		sec.Log.Profiles[p.Name] = p
	}
	return nil
}

// tcpMSSKinds are the four tcp-mss sub-kinds the compiler reads
// (compileFlow MSS switch). Each carries a u16 MSS value that lands in a
// Rust u16 wire field (TCPMSS{IPsecVPN,GreIn,GreOut}; all-tcp fans out into
// all three) via buildFlowSnapshot (Layer A coerceWireU16, #1977).
var tcpMSSKinds = []string{"ipsec-vpn", "gre-in", "gre-out", "all-tcp"}

// validateTCPMSSRanges is the #1979 Layer-B Tier-3 commit-time range gate
// for `security flow tcp-mss {ipsec-vpn|gre-in|gre-out|all-tcp} <n>`. It is
// the compiler AST pre-walk counterpart of validateVRRPTrackInterfaceAST:
// tcp-mss's MSS value can live in EITHER the kind node's own flat Keys[1]
// (`gre-in 1400`) OR a hierarchical `mss` sub-child (`gre-in { mss 1360; }`),
// a dual value-location the declarative schema walker (SchemaValidate)
// cannot express — so tcp-mss stays OPAQUE in setSchema and is validated
// here instead.
//
// It range-checks the COMPILER-SELECTED token (selectMSSToken, shared with
// parseMSSValue) against [0, 65535] — the same Layer-A bound (coerceWireU16
// out-of-range -> 0). Validating only the selected value means a mixed shape
// like `gre-in 70000 { mss 1360; }` PASSES (the compiler selects the child
// 1360; the flat 70000 is discarded), exactly matching what compileFlow
// reads.
//
// Strict path (commit / commit-check, lenient=false): an out-of-range or
// non-integer selected value is a hard compile error. Lenient path (load /
// peer-sync, lenient=true): it is downgraded to a warning and Layer A coerces
// it — a legacy persisted/peer config carrying `tcp-mss gre-in 70000` (a
// value an older binary accepted) must still boot, exactly like the VRRP
// lenient gate. Runs on the group-expanded tree so apply-groups-inherited
// MSS values are covered.
func validateTCPMSSRanges(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	for _, n := range nodes {
		nodePath := joinNodePath(prefix, n.Keys)
		if n.Name() == "security" {
			for _, flow := range n.FindChildren("flow") {
				flowPath := joinNodePath(nodePath, []string{"flow"})
				for _, mss := range flow.FindChildren("tcp-mss") {
					mssPath := joinNodePath(flowPath, []string{"tcp-mss"})
					for _, kind := range tcpMSSKinds {
						for _, kn := range mss.FindChildren(kind) {
							kindPath := joinNodePath(mssPath, []string{kind})
							// #2486: `tcp-mss ipsec-vpn` is rejected at
							// commit. There is no IPsec context in the
							// userspace forward-build path — ESP/AH/IKE is
							// local-delivered to the kernel XFRM stack and the
							// decrypted inner packets re-enter as plain
							// traffic with no IPsec marker — so the clamp can
							// never be enforced. Carrying it silently as dead
							// config (the prior behavior) is worse than
							// rejecting it. Strict (commit/commit-check) is a
							// hard error; lenient (load/peer-sync) downgrades
							// to a warning so a legacy persisted/peer config
							// still boots.
							if kind == "ipsec-vpn" {
								if _, ok := selectMSSToken(kn); ok {
									msg := fmt.Sprintf("%s: tcp-mss ipsec-vpn is not "+
										"supported in the userspace forwarding path "+
										"(IPsec is processed by the kernel XFRM stack, "+
										"so no IPsec context reaches the MSS clamp); "+
										"use 'all-tcp' to clamp all forwarded TCP", kindPath)
									if !lenient {
										return nil, fmt.Errorf("%s", msg)
									}
									warnings = append(warnings, msg+
										" (ignored: clamp not enforced)")
								}
								continue
							}
							w, err := checkTCPMSSKind(kn, kindPath, lenient)
							warnings = append(warnings, w...)
							if err != nil {
								return nil, err
							}
						}
					}
				}
			}
		}
		w, err := validateTCPMSSRanges(n.Children, nodePath, lenient)
		warnings = append(warnings, w...)
		if err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

// checkTCPMSSKind range-checks one tcp-mss kind node's compiler-selected MSS
// value. See validateTCPMSSRanges.
func checkTCPMSSKind(node *Node, nodePath string, lenient bool) ([]string, error) {
	tok, ok := selectMSSToken(node)
	if !ok {
		// No value token in either position — the compiler reads 0 (the
		// "unset" sentinel). Not a range violation; leave it.
		return nil, nil
	}
	if err := ValidateInteger(0, maxWireU16)(tok, nil); err != nil {
		msg := fmt.Sprintf("%s: invalid tcp-mss value: %v", nodePath, err)
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		// Tailor the lenient suffix to the failure kind (Codex/Copilot
		// review). Only a parseable POSITIVE-but-too-large integer reaches
		// Layer A to be clamped (flow.go coerceWireU16) — compileFlow only
		// assigns the MSS when v > 0. A non-integer token OR a negative
		// value yields no MSS: the compiler reads 0 (unset), nothing
		// reaches the dataplane, so "the dataplane coerces it" would
		// mislead. Branch on the parsed value, not just parseability.
		suffix := " (kept; the dataplane coerces it — a strict commit would reject this)"
		if v, perr := strconv.Atoi(tok); perr != nil || v < 0 {
			suffix = " (treated as unset/0 by the compiler — a strict commit would reject this)"
		}
		return []string{msg + suffix}, nil
	}
	return nil, nil
}

func compileFlow(node *Node, sec *SecurityConfig) error {
	// Aggressive session aging
	if agingNode := node.FindChild("aging"); agingNode != nil {
		for _, opt := range agingNode.Children {
			if len(opt.Keys) < 2 {
				continue
			}
			val, err := strconv.Atoi(opt.Keys[1])
			if err != nil {
				continue
			}
			switch opt.Name() {
			case "early-ageout":
				sec.Flow.AgingEarlyAgeout = val
			case "high-watermark":
				sec.Flow.AgingHighWatermark = val
			case "low-watermark":
				sec.Flow.AgingLowWatermark = val
			}
		}
	}

	tcpNode := node.FindChild("tcp-session")
	if tcpNode != nil {
		sec.Flow.TCPSession = &TCPSessionConfig{}
		for _, opt := range tcpNode.Children {
			// Handle leaf flags (no value)
			switch opt.Name() {
			case "no-syn-check":
				sec.Flow.TCPSession.NoSynCheck = true
				continue
			case "no-syn-check-in-tunnel":
				sec.Flow.TCPSession.NoSynCheckInTunnel = true
				continue
			case "rst-invalidate-session":
				sec.Flow.TCPSession.RstInvalidateSession = true
				continue
			case "no-sequence-check":
				sec.Flow.TCPSession.NoSequenceCheck = true
				continue
			}
			if len(opt.Keys) < 2 {
				continue
			}
			val, err := strconv.Atoi(opt.Keys[1])
			if err != nil {
				continue
			}
			switch opt.Name() {
			case "established-timeout":
				sec.Flow.TCPSession.EstablishedTimeout = val
			case "initial-timeout":
				sec.Flow.TCPSession.InitialTimeout = val
			case "closing-timeout":
				sec.Flow.TCPSession.ClosingTimeout = val
			case "time-wait-timeout":
				sec.Flow.TCPSession.TimeWaitTimeout = val
			}
		}
	}

	udpNode := node.FindChild("udp-session")
	if udpNode != nil {
		for _, opt := range udpNode.Children {
			if opt.Name() == "timeout" && len(opt.Keys) >= 2 {
				if v, err := strconv.Atoi(opt.Keys[1]); err == nil {
					sec.Flow.UDPSessionTimeout = v
				}
			}
		}
	}

	icmpNode := node.FindChild("icmp-session")
	if icmpNode != nil {
		for _, opt := range icmpNode.Children {
			if opt.Name() == "timeout" && len(opt.Keys) >= 2 {
				if v, err := strconv.Atoi(opt.Keys[1]); err == nil {
					sec.Flow.ICMPSessionTimeout = v
				}
			}
		}
	}

	// TCP MSS clamping
	mssNode := node.FindChild("tcp-mss")
	if mssNode != nil {
		for _, opt := range mssNode.Children {
			switch opt.Name() {
			case "ipsec-vpn":
				// #2486: strict commit rejects this via
				// validateTCPMSSRanges (no IPsec context in the userspace
				// forward path). In lenient load/peer-sync contexts the
				// value IS retained on the typed config below, so `show`
				// output and config round-trip preserve it — but it is
				// NEVER serialized to the dataplane wire (flow.go drops it)
				// and NEVER enforced (no dataplane consumer reads it).
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSIPsecVPN = v
				}
			case "gre-in":
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSGreIn = v
				}
			case "gre-out":
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSGreOut = v
				}
			case "all-tcp":
				// #2486: all-tcp is the context-agnostic clamp — it lands in
				// its own wire field (tcp_mss_all_tcp) and the dataplane
				// applies it to every forwarded TCP SYN (plain + the fallback
				// for gre-in / tunnel egress). Previously it fanned out into
				// IPsecVPN/GreIn/GreOut, but only gre-out was ever enforced,
				// so all-tcp silently behaved as gre-out-only.
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSAllTCP = v
				}
			}
		}
	}

	// allow-dns-reply
	if node.FindChild("allow-dns-reply") != nil {
		sec.Flow.AllowDNSReply = true
	}

	// allow-embedded-icmp
	if node.FindChild("allow-embedded-icmp") != nil {
		sec.Flow.AllowEmbeddedICMP = true
	}

	// gre-performance-acceleration
	if node.FindChild("gre-performance-acceleration") != nil {
		sec.Flow.GREPerformanceAcceleration = true
	}

	// power-mode-disable
	if node.FindChild("power-mode-disable") != nil {
		sec.Flow.PowerModeDisable = true
	}

	// syn-flood-protection-mode
	if spNode := node.FindChild("syn-flood-protection-mode"); spNode != nil {
		if len(spNode.Keys) >= 2 {
			sec.Flow.SynFloodProtectionMode = spNode.Keys[1]
		}
	}

	// traceoptions
	if toNode := node.FindChild("traceoptions"); toNode != nil {
		to := &FlowTraceoptions{}
		if fileNode := toNode.FindChild("file"); fileNode != nil {
			to.File = nodeVal(fileNode)
			for i := 2; i < len(fileNode.Keys)-1; i++ {
				switch fileNode.Keys[i] {
				case "size":
					if n, err := strconv.Atoi(fileNode.Keys[i+1]); err == nil {
						to.FileSize = n
					}
				case "files":
					if n, err := strconv.Atoi(fileNode.Keys[i+1]); err == nil {
						to.FileCount = n
					}
				}
			}
			// Also check children for hierarchical syntax
			if sNode := fileNode.FindChild("size"); sNode != nil {
				if v := nodeVal(sNode); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						to.FileSize = n
					}
				}
			}
			if fNode := fileNode.FindChild("files"); fNode != nil {
				if v := nodeVal(fNode); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						to.FileCount = n
					}
				}
			}
		}
		for _, flagNode := range toNode.FindChildren("flag") {
			if v := nodeVal(flagNode); v != "" {
				to.Flags = append(to.Flags, v)
			}
		}
		for _, pfInst := range namedInstances(toNode.FindChildren("packet-filter")) {
			pf := &TracePacketFilter{Name: pfInst.name}
			if spNode := pfInst.node.FindChild("source-prefix"); spNode != nil {
				pf.SourcePrefix = nodeVal(spNode)
			}
			if dpNode := pfInst.node.FindChild("destination-prefix"); dpNode != nil {
				pf.DestinationPrefix = nodeVal(dpNode)
			}
			if protoNode := pfInst.node.FindChild("protocol"); protoNode != nil {
				pf.Protocol = nodeVal(protoNode)
			}
			to.PacketFilters = append(to.PacketFilters, pf)
		}
		sec.Flow.Traceoptions = to
	}

	return nil
}

func compileALG(node *Node, sec *SecurityConfig) error {
	if dnsNode := node.FindChild("dns"); dnsNode != nil {
		if dnsNode.FindChild("disable") != nil {
			sec.ALG.DNSDisable = true
		}
	}
	if ftpNode := node.FindChild("ftp"); ftpNode != nil {
		if ftpNode.FindChild("disable") != nil {
			sec.ALG.FTPDisable = true
		}
	}
	if sipNode := node.FindChild("sip"); sipNode != nil {
		if sipNode.FindChild("disable") != nil {
			sec.ALG.SIPDisable = true
		}
	}
	if tftpNode := node.FindChild("tftp"); tftpNode != nil {
		if tftpNode.FindChild("disable") != nil {
			sec.ALG.TFTPDisable = true
		}
	}
	return nil
}
