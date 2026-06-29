package config

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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

// Junos SRX default thresholds applied when the corresponding screen check is
// enabled WITHOUT an explicit threshold. The Rust screen engine
// (userspace-dp/src/screen/mod.rs, scan.rs) gates every check on
// `threshold > 0`, so an enabled-but-unset check would compile to 0 and be
// silently skipped. These are the siblings of #3024 (#3230).
const (
	// defaultICMPFloodThreshold matches the Junos SRX `icmp flood threshold`
	// default of 1000 ICMP packets per second.
	defaultICMPFloodThreshold = 1000

	// defaultUDPFloodThreshold matches the Junos SRX `udp flood threshold`
	// default of 1000 UDP packets per second.
	defaultUDPFloodThreshold = 1000

	// defaultPortScanThreshold / defaultIPSweepThreshold supply a default for
	// `tcp port-scan` / `ip ip-sweep` when enabled without a threshold. Junos
	// flags a port scan / address sweep when one source reaches 10 distinct
	// destination ports / addresses within a 5000-microsecond window. This
	// engine interprets the threshold as a DISTINCT-DESTINATION COUNT over a
	// fixed 10-second window (WINDOW_SECS in scan.rs, `len() > threshold`), so
	// the default uses Junos's distinct-destination detection count (10), NOT
	// its 5000-microsecond time-window value — feeding 5000 here would be read
	// as a count and clamped to the dataplane cap (1023), effectively never
	// firing.
	defaultPortScanThreshold = 10
	defaultIPSweepThreshold  = 10
)

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

// zoneLocalNamePrefix marks a zone-qualified internal address-book name
// minted by resolveZoneLocalAddressBooks (#3061). The `/` separators make
// the synthetic name collision-proof against operator-typed names: the lexer
// permits `/` in an identifier (needed for IP literals like 10.0.0.0/24), but
// validateAddressBookEntryNamesStrict hard-rejects `/` in any address-book
// entry name and any security-zone name at commit, so no operator name can
// contain `/` and therefore none can equal a synthetic `zone-local/...` name.
// The fold also skips a key already present in the global book as a
// defence-in-depth no-clobber for the tolerant load path (a persisted
// pre-validator config that an older binary accepted).
const zoneLocalNamePrefix = "zone-local/"

// zoneLocalQualify mints the global-book key for a zone-local address-book
// entry. Both components are `/`-free, so the result is unambiguous and can
// never equal a user-typed token.
func zoneLocalQualify(zone, name string) string {
	return zoneLocalNamePrefix + zone + "/" + name
}

// resolveZoneLocalAddressBooks folds every zone-local address book (#3061)
// into the global SecurityConfig.AddressBook under zone-qualified internal
// names and rewrites each policy's match address tokens that resolve
// zone-locally to point at the qualified entry. After this pass the entire
// downstream resolution path (wire snapshot, nameToID, classifyPolicyAddresses,
// strict/warn validators) keeps operating on a single flat global book.
//
// Junos scoping: a policy's source-address resolves against its FROM zone's
// book, destination-address against its TO zone's book — zone-local first,
// then the global book. A token defined in a zone's local book is rewritten
// to that zone's qualified name (zone-local wins); a token NOT in the zone's
// local book is left unchanged so it falls back to the global book. A name
// present only in zone A's book is therefore invisible to a policy in zone B.
func resolveZoneLocalAddressBooks(sec *SecurityConfig) {
	hasLocal := false
	for _, z := range sec.Zones {
		if z != nil && z.AddressBook != nil {
			hasLocal = true
			break
		}
	}
	if !hasLocal {
		return
	}

	if sec.AddressBook == nil {
		sec.AddressBook = &AddressBook{
			Addresses:   make(map[string]*Address),
			AddressSets: make(map[string]*AddressSet),
		}
	}
	gb := sec.AddressBook

	localDefines := func(zone, name string) bool {
		z := sec.Zones[zone]
		if z == nil || z.AddressBook == nil {
			return false
		}
		if _, ok := z.AddressBook.Addresses[name]; ok {
			return true
		}
		_, ok := z.AddressBook.AddressSets[name]
		return ok
	}

	// Inject each zone-local entry into the global book under its qualified
	// name. Address-set member references are re-pointed to the same zone's
	// qualified name when the member is also zone-local (zone-local first),
	// otherwise left as a global reference.
	for zoneName, z := range sec.Zones {
		if z == nil || z.AddressBook == nil {
			continue
		}
		for name, addr := range z.AddressBook.Addresses {
			q := zoneLocalQualify(zoneName, name)
			if _, exists := gb.Addresses[q]; exists {
				continue // no-clobber (see zoneLocalNamePrefix); strict path never hits this
			}
			gb.Addresses[q] = &Address{Name: q, Value: addr.Value, Description: addr.Description}
		}
		for name, set := range z.AddressBook.AddressSets {
			q := zoneLocalQualify(zoneName, name)
			if _, exists := gb.AddressSets[q]; exists {
				continue // no-clobber (see zoneLocalNamePrefix)
			}
			ns := &AddressSet{Name: q}
			for _, m := range set.Addresses {
				if localDefines(zoneName, m) {
					ns.Addresses = append(ns.Addresses, zoneLocalQualify(zoneName, m))
				} else {
					ns.Addresses = append(ns.Addresses, m)
				}
			}
			for _, m := range set.AddressSets {
				if localDefines(zoneName, m) {
					ns.AddressSets = append(ns.AddressSets, zoneLocalQualify(zoneName, m))
				} else {
					ns.AddressSets = append(ns.AddressSets, m)
				}
			}
			gb.AddressSets[q] = ns
		}
	}

	rewrite := func(zone string, tokens []string) {
		// An empty or wildcard ("any") zone names no single zone-local book to
		// resolve against, so leave such tokens for the global book.
		if zone == "" || zone == "any" {
			return
		}
		for i, t := range tokens {
			switch t {
			case "", "any", "any4", "any6":
				continue
			}
			if localDefines(zone, t) {
				tokens[i] = zoneLocalQualify(zone, t)
			}
		}
	}
	for _, zpp := range sec.Policies {
		if zpp == nil {
			continue
		}
		for _, p := range zpp.Policies {
			if p == nil {
				continue
			}
			rewrite(zpp.FromZone, p.Match.SourceAddresses)
			rewrite(zpp.ToZone, p.Match.DestinationAddresses)
		}
	}
	// #3287: a scoped global policy (#3148, `match from-zone <z>` /
	// `match to-zone <z>`) resolves its zone-local address references against
	// that zone's local book, exactly like a zone-pair policy. Without this the
	// bare token kept pointing at the global book (where the entry exists only
	// under its zone-qualified name), so the address constraint silently
	// resolved to match-none and legitimate zone-scoped global traffic fell
	// through to default-deny. An unscoped global (empty / `any` scope) has no
	// single zone-local book and is left to resolve against the global book.
	for _, p := range sec.GlobalPolicies {
		if p == nil {
			continue
		}
		rewrite(p.Match.FromZone, p.Match.SourceAddresses)
		rewrite(p.Match.ToZone, p.Match.DestinationAddresses)
	}
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
			case "address-book":
				// #3061: zone-local address book. Same entry grammar as the
				// global book; resolved into the global book under
				// zone-qualified internal names later (resolveZoneLocalAddressBooks).
				ab := &AddressBook{
					Addresses:   make(map[string]*Address),
					AddressSets: make(map[string]*AddressSet),
				}
				parseAddressBookEntries(prop, ab)
				zone.AddressBook = ab
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
			case "from-zone":
				// #3148: global-policy from-zone match context. The schema
				// exposes this leaf only under `security policies global
				// policy <p> match`; for zone-pair policies the zones come
				// from the surrounding from-zone/to-zone stanza so this case
				// is never reached. Empty stays "all zones".
				if len(m.Keys) >= 2 {
					pol.Match.FromZone = m.Keys[1]
				} else if len(m.Children) > 0 {
					pol.Match.FromZone = m.Children[0].Name()
				}
			case "to-zone":
				// #3148: global-policy to-zone match context (see from-zone).
				if len(m.Keys) >= 2 {
					pol.Match.ToZone = m.Keys[1]
				} else if len(m.Children) > 0 {
					pol.Match.ToZone = m.Children[0].Name()
				}
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
				// #3141: a flat-set `then deny log session-init` collapses the
				// log/count modifier onto the deny node
				// (Keys=["deny","log","session-init",...], no children) instead
				// of nesting it as a sibling `then log` node. The deny arm used
				// to read only t.Name() and silently dropped the collapsed
				// modifier, so deny-with-logging committed but never logged.
				// Wire the collapsed log/count modifier here so deny+log works
				// in BOTH the flat-collapsed and the separate-node
				// (`then { deny; log session-init; }`, handled by the `log` arm)
				// forms — matching the standalone `then log`/`then count` arms.
				// validatePolicyThenDenyStrict rejects any OTHER (non-log,
				// non-count) collapsed deny modifier at commit (#3141).
				applyCollapsedDenyModifiers(pol, t)
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

// recognizedCollapsedDenyToken reports whether tok is a token that
// applyCollapsedDenyModifiers acts on inside a FLAT-collapsed `then deny`
// sequence — the `log`/`count` modifiers plus log's session-init/
// session-close sub-tokens. On the flat path the lexer flattens a modifier
// and its sub-tokens into a single Keys slice (e.g.
// Keys=["deny","log","session-init","count"]), so the validator cannot tell
// a modifier from a sub-token positionally; it accepts exactly the tokens
// the wiring consumes and rejects anything else. This is the single source
// of truth shared by applyCollapsedDenyModifiers (the wiring) and
// validatePolicyThenDenyStrict (the reject gate) so they never disagree on
// what is a supported token vs an unsupported modifier that would be
// silently dropped (#3141).
func recognizedCollapsedDenyToken(tok string) bool {
	switch tok {
	case "log", "session-init", "session-close", "count":
		return true
	default:
		return false
	}
}

// applyCollapsedDenyModifiers wires a `log`/`count` action modifier that a
// flat-set `then deny <modifier>` collapsed onto the deny node, so deny+log
// (and deny+count) work in the flat form exactly as they do as separate
// `then` siblings (#3141). The modifier appears in TWO AST shapes:
//   - Flat set `then deny log session-init` collapses the whole tail onto
//     the deny node: Keys=["deny","log","session-init"] (no children).
//     Keys[0] is "deny"; Keys[1:] carry the modifier and its sub-tokens.
//   - A hierarchical `then { deny { log { session-init; } } }` (non-canonical
//     but parseable) nests the modifier as a child node of deny.
//
// Only `log` (with session-init/session-close sub-tokens) and `count` are
// recognized — the exact set the standalone `then log`/`then count` arms
// support. Any OTHER collapsed deny modifier is left untouched here and
// rejected at commit by validatePolicyThenDenyStrict, mirroring the #3114/
// #3115 then-permit/then-reject reject-at-commit gates.
func applyCollapsedDenyModifiers(pol *Policy, denyNode *Node) {
	apply := func(tok string) {
		switch tok {
		case "log":
			if pol.Log == nil {
				pol.Log = &PolicyLog{}
			}
		case "session-init":
			if pol.Log == nil {
				pol.Log = &PolicyLog{}
			}
			pol.Log.SessionInit = true
		case "session-close":
			if pol.Log == nil {
				pol.Log = &PolicyLog{}
			}
			pol.Log.SessionClose = true
		case "count":
			pol.Count = true
		}
	}
	// Flat-collapsed tail: Keys[1:] (Keys[0] == "deny").
	if len(denyNode.Keys) >= 2 {
		for _, k := range denyNode.Keys[1:] {
			apply(k)
		}
	}
	// Hierarchical children (non-canonical shape).
	var walk func(n *Node)
	walk = func(n *Node) {
		for _, k := range n.Keys {
			apply(k)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, c := range denyNode.Children {
		walk(c)
	}
}

func compileScreen(node *Node, sec *SecurityConfig) error {
	for _, inst := range namedInstances(node.FindChildren("ids-option")) {
		profile := &ScreenProfile{Name: inst.name}

		// parseThresh parses an explicitly-provided screen numeric value. An
		// EMPTY value means the leaf was enabled without an explicit threshold:
		// ok=false signals the caller to apply the Junos default (#3230) — that
		// is NOT a bad value. A non-empty value that fails to parse or is not a
		// positive integer is recorded on profile.BadNumeric for
		// validateScreenNumericStrict (#3317): before this the strconv error was
		// swallowed and the leaf silently became the default or zero/disabled
		// (fail-open). ok=false on a bad value too, so the lenient / load path
		// still falls back to the default and boots (#1960 no-brick).
		parseThresh := func(path, val string) (int, bool) {
			if val == "" {
				return 0, false
			}
			n, err := strconv.Atoi(val)
			// Reject non-numeric, non-positive, AND > math.MaxUint32. Every
			// published screen threshold is cast to uint32 in the snapshot
			// builder (pkg/dataplane/userspace/screens.go) — a value above
			// 2^32-1 (e.g. 4294967296) would WRAP on that cast (uint32(2^32)==0),
			// and the Rust screen treats a zero threshold as unset and OMITS the
			// check. That is the exact fail-open class #3317 closes, so the gate
			// must reject it at commit rather than let it wrap silently. int64(n)
			// keeps the comparison portable: on a 32-bit `int` platform an
			// over-2^32 literal already fails Atoi (err != nil), so this only
			// adds a real bound on 64-bit. The dataplane-meaningful ceilings are
			// tighter still (e.g. maxScanSweepThreshold clamps port-scan/ip-sweep
			// downstream), but math.MaxUint32 is the required floor that prevents
			// the wrap.
			if err != nil || n < 1 || int64(n) > math.MaxUint32 {
				profile.BadNumeric = append(profile.BadNumeric,
					ScreenBadNumeric{Path: path, Value: val})
				return 0, false
			}
			return n, true
		}
		// numVal extracts the numeric value a screen leaf carries at Keys[keyIdx].
		// In both AST shapes a leaf collapses its tokens onto Keys, so the value
		// is at a fixed offset: a `threshold <N>` leaf carries it at Keys[1]
		// (keyIdx=1); a `flood threshold <N>` leaf carries the intermediate
		// `threshold` keyword at Keys[1] and the number at Keys[2] (keyIdx=2).
		// nodeVal (Keys[1]) is the fallback only when Keys is too short. An empty
		// result means the leaf was enabled without an explicit value.
		numVal := func(n *Node, keyIdx int) string {
			if len(n.Keys) > keyIdx {
				return n.Keys[keyIdx]
			}
			return nodeVal(n)
		}

		// recordKeyExtras flags trailing tokens collapsed onto a RECOGNIZED
		// screen leaf's Keys beyond the tokens compileScreen legitimately
		// reads (#3332). In the flat-set AST a leaf with no schema children
		// absorbs every trailing token onto its Keys, so `tcp land bogus`
		// lands as Keys=["land","bogus"] and the compiler reads only the
		// keyword (and, for value leaves, a fixed Keys index), silently
		// dropping the rest — a typo'd extra token is accepted with no
		// warning. `allowed` is the total Keys length the leaf legitimately
		// carries: 1 for a boolean flag (`land`), 2 for a single-value leaf
		// whose value sits at Keys[1] (`port-scan threshold <n>`,
		// `syn-flood attack-threshold <n>`, `limit-session source-ip-based
		// <n>` value tail), 3 for `flood threshold <n>` (value at Keys[2]).
		// Each token past that span is operator garbage; record it on
		// UnknownLeaves so validateScreenUnknownStrict rejects the commit
		// (the tolerant load / peer-sync path downgrades to a warning —
		// #3318 / #1960 no-brick). This is distinct from the #3318 unknown-
		// KEYWORD gate: here the leaf keyword itself IS supported.
		recordKeyExtras := func(prefix string, n *Node, allowed int) {
			for i := allowed; i < len(n.Keys); i++ {
				profile.UnknownLeaves = append(profile.UnknownLeaves, prefix+" "+n.Keys[i])
			}
		}
		// recordChildExtras flags unexpected CHILD nodes hanging off a
		// recognized screen leaf that takes no sub-stanza (#3332). A leaf
		// declared with args>0 in setSchema (limit-session source-ip-based /
		// destination-ip-based) has SetPath consume its value into Keys and
		// park any further trailing token as a CHILD node rather than on
		// Keys, so recordKeyExtras cannot see it. The leaf models no children,
		// so every child here is garbage that would otherwise be silently
		// dropped.
		recordChildExtras := func(prefix string, n *Node) {
			for _, c := range n.Children {
				if c == nil || len(c.Keys) == 0 {
					continue
				}
				profile.UnknownLeaves = append(profile.UnknownLeaves, prefix+" "+c.Keys[0])
			}
		}

		// #3318: the screen schema subtrees are open. Record any unknown/
		// unsupported top-level screen family so validateScreenUnknownStrict can
		// reject the commit fail-closed instead of silently dropping it.
		for _, fam := range inst.node.Children {
			switch fam.Name() {
			case "icmp", "ip", "tcp", "udp", "limit-session":
				// handled below
			default:
				profile.UnknownLeaves = append(profile.UnknownLeaves, fam.Name())
			}
		}

		icmpNode := inst.node.FindChild("icmp")
		if icmpNode != nil {
			for _, opt := range icmpNode.Children {
				switch opt.Name() {
				case "ping-death":
					profile.ICMP.PingDeath = true
					recordKeyExtras("icmp ping-death", opt, 1)
				case "fragment":
					profile.ICMP.Fragment = true
					recordKeyExtras("icmp fragment", opt, 1)
				case "flood":
					recordKeyExtras("icmp flood", opt, 3)
					if n, ok := parseThresh("icmp flood", numVal(opt, 2)); ok {
						profile.ICMP.FloodThreshold = n
					}
					// icmp flood enabled without an explicit threshold: arm at
					// the Junos default (1000 pps) so the dataplane `>0` gate
					// fires rather than silently skipping the check (#3230).
					if profile.ICMP.FloodThreshold <= 0 {
						profile.ICMP.FloodThreshold = defaultICMPFloodThreshold
					}
				default:
					profile.UnknownLeaves = append(profile.UnknownLeaves, "icmp "+opt.Name())
				}
			}
		}

		ipNode := inst.node.FindChild("ip")
		if ipNode != nil {
			for _, opt := range ipNode.Children {
				switch opt.Name() {
				case "source-route-option":
					profile.IP.SourceRouteOption = true
					recordKeyExtras("ip source-route-option", opt, 1)
				case "tear-drop":
					profile.IP.TearDrop = true
					recordKeyExtras("ip tear-drop", opt, 1)
				case "ip-sweep":
					for _, swOpt := range opt.Children {
						switch swOpt.Name() {
						case "threshold":
							recordKeyExtras("ip ip-sweep threshold", swOpt, 2)
							if n, ok := parseThresh("ip ip-sweep threshold", numVal(swOpt, 1)); ok {
								profile.IP.IPSweepThreshold = n
							}
						default:
							profile.UnknownLeaves = append(profile.UnknownLeaves, "ip ip-sweep "+swOpt.Name())
						}
					}
					// ip-sweep enabled without an explicit threshold: arm at the
					// Junos distinct-address detection count (10) so the
					// dataplane `>0` gate fires rather than skipping the check
					// (#3230).
					if profile.IP.IPSweepThreshold <= 0 {
						profile.IP.IPSweepThreshold = defaultIPSweepThreshold
					}
				default:
					profile.UnknownLeaves = append(profile.UnknownLeaves, "ip "+opt.Name())
				}
			}
		}

		tcpNode := inst.node.FindChild("tcp")
		if tcpNode != nil {
			for _, opt := range tcpNode.Children {
				switch opt.Name() {
				case "land":
					profile.TCP.Land = true
					recordKeyExtras("tcp land", opt, 1)
				case "winnuke":
					profile.TCP.WinNuke = true
					recordKeyExtras("tcp winnuke", opt, 1)
				case "syn-frag":
					profile.TCP.SynFrag = true
					recordKeyExtras("tcp syn-frag", opt, 1)
				case "syn-fin":
					profile.TCP.SynFin = true
					recordKeyExtras("tcp syn-fin", opt, 1)
				case "no-flag":
					profile.TCP.NoFlag = true
					recordKeyExtras("tcp no-flag", opt, 1)
				case "fin-no-ack":
					profile.TCP.FinNoAck = true
					recordKeyExtras("tcp fin-no-ack", opt, 1)
				case "syn-flood":
					sf := &SynFloodConfig{}
					for _, sfOpt := range opt.Children {
						val := numVal(sfOpt, 1)
						switch sfOpt.Name() {
						case "alarm-threshold":
							recordKeyExtras("tcp syn-flood alarm-threshold", sfOpt, 2)
							if n, ok := parseThresh("tcp syn-flood alarm-threshold", val); ok {
								sf.AlarmThreshold = n
							}
						case "attack-threshold":
							recordKeyExtras("tcp syn-flood attack-threshold", sfOpt, 2)
							if n, ok := parseThresh("tcp syn-flood attack-threshold", val); ok {
								sf.AttackThreshold = n
							}
						case "source-threshold":
							recordKeyExtras("tcp syn-flood source-threshold", sfOpt, 2)
							if n, ok := parseThresh("tcp syn-flood source-threshold", val); ok {
								sf.SourceThreshold = n
							}
						case "destination-threshold":
							recordKeyExtras("tcp syn-flood destination-threshold", sfOpt, 2)
							if n, ok := parseThresh("tcp syn-flood destination-threshold", val); ok {
								sf.DestinationThreshold = n
							}
						case "timeout":
							recordKeyExtras("tcp syn-flood timeout", sfOpt, 2)
							if n, ok := parseThresh("tcp syn-flood timeout", val); ok {
								sf.Timeout = n
							}
						default:
							profile.UnknownLeaves = append(profile.UnknownLeaves, "tcp syn-flood "+sfOpt.Name())
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
						switch psOpt.Name() {
						case "threshold":
							recordKeyExtras("tcp port-scan threshold", psOpt, 2)
							if n, ok := parseThresh("tcp port-scan threshold", numVal(psOpt, 1)); ok {
								profile.TCP.PortScanThreshold = n
							}
						default:
							profile.UnknownLeaves = append(profile.UnknownLeaves, "tcp port-scan "+psOpt.Name())
						}
					}
					// port-scan enabled without an explicit threshold: arm at
					// the Junos distinct-port detection count (10) so the
					// dataplane `>0` gate fires rather than skipping the check
					// (#3230).
					if profile.TCP.PortScanThreshold <= 0 {
						profile.TCP.PortScanThreshold = defaultPortScanThreshold
					}
				default:
					profile.UnknownLeaves = append(profile.UnknownLeaves, "tcp "+opt.Name())
				}
			}
		}

		udpNode := inst.node.FindChild("udp")
		if udpNode != nil {
			for _, opt := range udpNode.Children {
				switch opt.Name() {
				case "flood":
					recordKeyExtras("udp flood", opt, 3)
					if n, ok := parseThresh("udp flood", numVal(opt, 2)); ok {
						profile.UDP.FloodThreshold = n
					}
					// udp flood enabled without an explicit threshold: arm at
					// the Junos default (1000 pps) so the dataplane `>0` gate
					// fires rather than silently skipping the check (#3230).
					if profile.UDP.FloodThreshold <= 0 {
						profile.UDP.FloodThreshold = defaultUDPFloodThreshold
					}
				default:
					profile.UnknownLeaves = append(profile.UnknownLeaves, "udp "+opt.Name())
				}
			}
		}

		limitNode := inst.node.FindChild("limit-session")
		if limitNode != nil {
			for _, opt := range limitNode.Children {
				val := numVal(opt, 1)
				switch opt.Name() {
				case "source-ip-based":
					recordKeyExtras("limit-session source-ip-based", opt, 2)
					recordChildExtras("limit-session source-ip-based", opt)
					if n, ok := parseThresh("limit-session source-ip-based", val); ok {
						profile.LimitSession.SourceIPBased = n
					}
				case "destination-ip-based":
					recordKeyExtras("limit-session destination-ip-based", opt, 2)
					recordChildExtras("limit-session destination-ip-based", opt)
					if n, ok := parseThresh("limit-session destination-ip-based", val); ok {
						profile.LimitSession.DestinationIPBased = n
					}
				default:
					profile.UnknownLeaves = append(profile.UnknownLeaves, "limit-session "+opt.Name())
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

	parseAddressBookEntries(globalNode, ab)

	sec.AddressBook = ab
	return nil
}

// parseAddressBookEntries folds the `address` / `address-set` children of
// node into ab. node is either the `global` block under `security
// address-book` or a zone-local `address-book` block under `security zones
// security-zone <z>` (#3061) — the entry grammar is identical, only the
// attachment point differs.
func parseAddressBookEntries(node *Node, ab *AddressBook) {
	for _, child := range node.Children {
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
		// #3332: the description text is a single token at Keys[3] (a quoted
		// multi-word description is one token); any token past it is operator
		// garbage the compiler silently dropped. Record it for the strict
		// trailing-token gate.
		if len(node.Keys) > 4 {
			addr.TrailingTokens = append(addr.TrailingTokens, node.Keys[4:]...)
		}
		return
	}

	// Prefix-bearing leaf: Keys[2] is the prefix iff it parses as an IP/CIDR.
	if len(node.Keys) >= 3 && looksLikeIPOrCIDR(node.Keys[2]) {
		addr.Value = node.Keys[2]
		// #3332: a named address takes exactly one prefix; anything after it
		// (Keys[3:]) is operator garbage the compiler silently dropped.
		if len(node.Keys) > 3 {
			addr.TrailingTokens = append(addr.TrailingTokens, node.Keys[3:]...)
		}
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

// validateSecurityLogStreamPortsAST is the #3349 commit-time range gate for
// `security log stream <s> port <p>` and the nested `host { port <p>; }`
// spelling. The syslog port value lives in TWO AST locations — a direct
// `port` child of the stream and a `port` child of a nested `host` block
// (compileLog reads both) — a dual value-location the declarative
// SchemaValidate walker cannot express, the same rationale as tcp-mss
// (validateTCPMSSRanges). compileLog ignores a non-numeric or out-of-range
// port (strconv.Atoi error path) and silently keeps the default 514, so a typo
// such as `port 6514x` commits and quietly logs audit to the wrong port. This
// pass reads the raw tokens before that swallowing and range-checks them.
//
// It mirrors compileLog's traversal exactly (FindChild("log") +
// namedInstances(stream) + per-child switch on host/port) so it validates
// precisely the tokens the compiler consumes. Runs on the group-expanded tree
// so apply-groups-inherited ports are covered.
//
// Strict path (commit / commit-check, lenient=false): a non-numeric or
// out-of-range port is a hard compile error. Lenient path (load / peer-sync,
// lenient=true): downgraded to a warning so an already-persisted or
// peer-synced config that an older binary accepted (and that the compiler
// still maps to 514) still boots (#1960 / #3261 fail-closed-on-load class).
func validateSecurityLogStreamPortsAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	check := func(path, raw string) error {
		if raw == "" {
			// No value token: the compiler keeps the default 514. The
			// missing-value case is the schema walker's concern, not this
			// range gate.
			return nil
		}
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= 65535 {
			return nil
		}
		msg := fmt.Sprintf("%s: invalid syslog port %q (expected an integer in "+
			"[1..65535]; an invalid value silently keeps the default 514)", path, raw)
		if lenient {
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	for _, n := range nodes {
		if n.Name() != "security" {
			continue
		}
		secPath := joinNodePath(prefix, n.Keys)
		for _, logNode := range n.FindChildren("log") {
			logPath := joinNodePath(secPath, []string{"log"})
			for _, inst := range namedInstances(logNode.FindChildren("stream")) {
				streamPath := joinNodePath(logPath, []string{"stream", inst.name})
				for _, prop := range inst.node.Children {
					switch prop.Name() {
					case "port":
						if err := check(joinNodePath(streamPath, []string{"port"}), nodeVal(prop)); err != nil {
							return warnings, err
						}
					case "host":
						for _, hc := range prop.Children {
							if hc.Name() == "port" {
								if err := check(joinNodePath(streamPath, []string{"host", "port"}), nodeVal(hc)); err != nil {
									return warnings, err
								}
							}
						}
					}
				}
			}
		}
	}
	return warnings, nil
}

// validateSecurityLogStreamTLSProfileAST is the #3350 commit-time gate for
// `security log stream <s> transport tls-profile <name>`. The token is parsed
// (schema_security.go), validated for syntax, and stored on
// stream.Transport.TLSProfile (compileLog) — but it is NEVER resolved into a
// *tls.Config at runtime: daemon_system.go applyLogStreams always passes a nil
// *tls.Config to logging.NewSyslogClientTransport, so the TLS dialer falls back
// to the system CA roots (pkg/logging/syslog.go dialTLS). There is also no
// `tls-profile` DEFINITION stanza anywhere in the config (no local-certificate /
// trusted-ca / SNI source for syslog — only IPsec/IKE define certs), so the
// named profile has nothing to resolve to. An operator who configures
// `tls-profile` believes mutual TLS / a pinned CA is in force when it is not —
// a secure-syslog posture silently downgraded to system roots (a fail-open).
//
// Because the profile can never be honored, this gate REJECTS any
// `transport tls-profile` at commit rather than letting it silently no-op.
// `transport protocol tls` ON ITS OWN is left intact: a TLS stream that trusts
// the system CA roots is a legitimate, fully-honored configuration — only the
// named-but-unapplied profile is rejected.
//
// It mirrors compileLog's traversal exactly (FindChild("log") +
// namedInstances(stream) + the `transport` child loop) so it gates precisely
// the token the compiler reads. Runs on the group-expanded tree so an
// apply-groups-inherited tls-profile is covered.
//
// Strict path (commit / commit-check, lenient=false): a present tls-profile is
// a hard compile error. Lenient path (load / peer-sync, lenient=true):
// downgraded to a warning so an already-persisted or peer-synced config that an
// older binary accepted (and that silently used system roots) still boots
// (#1960 / #3261 fail-closed-on-load class). The runtime behavior is unchanged
// by the lenient downgrade — the profile was never applied either way — so a
// leniently-loaded value is inert, now flagged.
func validateSecurityLogStreamTLSProfileAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	for _, n := range nodes {
		if n.Name() != "security" {
			continue
		}
		secPath := joinNodePath(prefix, n.Keys)
		for _, logNode := range n.FindChildren("log") {
			logPath := joinNodePath(secPath, []string{"log"})
			for _, inst := range namedInstances(logNode.FindChildren("stream")) {
				streamPath := joinNodePath(logPath, []string{"stream", inst.name})
				for _, prop := range inst.node.Children {
					if prop.Name() != "transport" {
						continue
					}
					for _, tc := range prop.Children {
						if tc.Name() != "tls-profile" {
							continue
						}
						profile := nodeVal(tc)
						path := joinNodePath(streamPath, []string{"transport", "tls-profile"})
						msg := fmt.Sprintf("%s: tls-profile %q is not applied at runtime — "+
							"xpf has no TLS profile definition (certificate / trusted-ca / "+
							"SNI) to resolve it to, so the TLS syslog stream silently falls "+
							"back to the system CA roots instead of the named profile. Remove "+
							"the tls-profile (a `transport protocol tls` stream that trusts the "+
							"system CA roots is honored) until profile resolution is implemented",
							path, profile)
						if lenient {
							warnings = append(warnings, msg)
							continue
						}
						return warnings, fmt.Errorf("%s", msg)
					}
				}
			}
		}
	}
	return warnings, nil
}

// flowTraceFileNameError reports why an operator-supplied
// `security flow traceoptions file <name>` value is unsafe, or nil if the
// value is an acceptable bare basename. The persistent flow-trace file always
// lives directly under /var/log (NewTraceWriter), so only a bare filename is
// permitted: an absolute path, a path separator, or a "." / ".." component
// would let a committed config steer root-written flow telemetry (internal
// addresses, ports, zones, actions, policy IDs) outside the appliance log area
// — e.g. `file /tmp/x` is kept verbatim and `file ../../tmp/x` cleans to
// /tmp/x (#3420, Codex audit 097 H02). This is the persistent-config sibling
// of the interactive `monitor security flow file` hardening (#3378).
func flowTraceFileNameError(name string) error {
	if name == "" {
		// A missing value token is the schema walker's concern, not this gate.
		return nil
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%q is not a valid trace filename", name)
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("trace filename %q must be a bare name, not a path "+
			"(the file is written under /var/log)", name)
	}
	if filepath.IsAbs(name) || name != filepath.Base(name) {
		return fmt.Errorf("trace filename %q must be a bare name, not a path "+
			"(the file is written under /var/log)", name)
	}
	return nil
}

// Flow-trace rotation bounds (#3424). The persistent `security flow
// traceoptions file <name> size <s> files <n>` knob was copied verbatim by the
// compiler with no range check, so a committed `size 1 files 1000000000` made
// every matching trace line exceed the threshold and turned each rotation into
// a ~1e9-iteration rename loop run synchronously from the event callback under
// the writer mutex (a per-event CPU storm). These bounds match the interactive
// `monitor security flow file` limits (pkg/cli/monitor.go) so the persistent
// and on-demand trace paths agree: a minimum size large enough that a normal
// burst of trace lines does not rotate on every write, a 1 GiB ceiling, and a
// small generation count whose rename loop is bounded. They are the single
// source of truth for both the commit-time gate (validateFlowTraceSizeFilesAST)
// and the runtime fail-safe clamp (logging.NewTraceWriter).
const (
	FlowTraceMinFileSize  = 10240      // bytes (10 KiB)
	FlowTraceMaxFileSize  = 1073741824 // bytes (1 GiB)
	FlowTraceMinFileCount = 2
	FlowTraceMaxFileCount = 1000
)

// validateFlowTraceFileAST is the #3420 commit-time path-traversal gate for
// `security flow traceoptions file <name>`. The compiler stores the filename
// verbatim (compileFlow traceoptions: to.File = nodeVal(fileNode)) and
// NewTraceWriter then joins/opens it under /var/log without rejecting an
// absolute path or a ".." escape, so a committed config can append flow trace
// records anywhere the daemon user can write. The filename is a single AST
// value the declarative SchemaValidate walker treats as opaque free text, so —
// like the syslog port and tls-profile gates — it is checked here on the
// group-expanded tree, mirroring compileFlow's traversal
// (FindChild("flow") > FindChild("traceoptions") > FindChild("file")).
//
// Strict path (commit / commit-check, lenient=false): an absolute,
// separator-bearing, or dot-component filename is a hard compile error.
// Lenient path (load / peer-sync, lenient=true): downgraded to a warning so an
// already-persisted or peer-synced config an older binary accepted still boots;
// NewTraceWriter independently refuses the unsafe path at runtime, so a
// leniently-loaded value simply disables tracing rather than writing outside
// /var/log (#1960 / #3261 fail-closed-on-load class).
func validateFlowTraceFileAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	for _, n := range nodes {
		if n.Name() != "security" {
			continue
		}
		secPath := joinNodePath(prefix, n.Keys)
		flowNode := n.FindChild("flow")
		if flowNode == nil {
			continue
		}
		toNode := flowNode.FindChild("traceoptions")
		if toNode == nil {
			continue
		}
		fileNode := toNode.FindChild("file")
		if fileNode == nil {
			continue
		}
		name := nodeVal(fileNode)
		if err := flowTraceFileNameError(name); err != nil {
			path := joinNodePath(secPath, []string{"flow", "traceoptions", "file"})
			msg := fmt.Sprintf("%s: %s", path, err.Error())
			if lenient {
				warnings = append(warnings, msg+
					" (ignored: tracing disabled, not written outside /var/log)")
				continue
			}
			return warnings, fmt.Errorf("%s", msg)
		}
	}
	return warnings, nil
}

// flowTraceImplementedFlags is the set of `security flow traceoptions flag`
// values the persistent trace writer actually honours
// (logging.TraceWriter.matchFlags recognizes exactly these two). Any other
// token is fail-silent at runtime: NewTraceWriter installs it into a non-empty
// flag map, which suppresses the basic-datapath/session defaults, and
// matchFlags then never matches — the daemon reports flow tracing enabled while
// the trace file stays empty (#3422 M02, false evidence during an incident).
// Keep in sync with logging.matchFlags / logging.traceFlagImplemented.
var flowTraceImplementedFlags = map[string]bool{
	"basic-datapath": true,
	"session":        true,
}

// validateFlowTraceFlagsAndFiltersAST is the #3422 commit-time gate for
// `security flow traceoptions { flag <name>; packet-filter <n> { source-prefix
// / destination-prefix <prefix>; } }`. The compiler copies both flag tokens
// (compileFlow: to.Flags = append(...)) and filter prefixes
// (pf.SourcePrefix/DestinationPrefix = nodeVal(...)) verbatim with no
// validation, and the runtime then fails silently in two directions:
//
//   - M01: NewTraceWriter drops a filter whose prefix does not parse, so a
//     config whose every filter is a typo (`source-prefix 10.0.0.999/32`)
//     leaves tw.filters empty and HandleEvent traces EVERYTHING — a filter
//     meant to narrow tracing broadens it.
//   - M02: an unknown flag (`flag sesson`) makes the flag map non-empty,
//     suppressing the defaults, so matchFlags never matches and nothing is
//     traced while the daemon reports tracing enabled.
//
// Both values are single AST leaves SchemaValidate treats as opaque free text,
// so — like the file gate above — they are checked here on the group-expanded
// tree, mirroring compileFlow's traversal (FindChild("flow") >
// FindChild("traceoptions") > flag / packet-filter children).
//
// Strict path (commit / commit-check, lenient=false): an unparseable
// source/destination prefix or an unimplemented flag is a hard compile error.
// Lenient path (load / peer-sync, lenient=true): downgraded to a warning so an
// already-persisted or peer-synced config an older binary accepted still boots;
// the runtime fixes (NewTraceWriter marks an invalid filter match-none and
// drops an unknown flag so defaults still apply) keep a leniently-loaded value
// fail-safe rather than fail-open (#1960 / #3261 fail-closed-on-load class).
func validateFlowTraceFlagsAndFiltersAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	for _, n := range nodes {
		if n.Name() != "security" {
			continue
		}
		secPath := joinNodePath(prefix, n.Keys)
		flowNode := n.FindChild("flow")
		if flowNode == nil {
			continue
		}
		toNode := flowNode.FindChild("traceoptions")
		if toNode == nil {
			continue
		}
		toPath := joinNodePath(secPath, []string{"flow", "traceoptions"})

		// flag tokens
		for _, flagNode := range toNode.FindChildren("flag") {
			v := nodeVal(flagNode)
			if v == "" || flowTraceImplementedFlags[v] {
				continue
			}
			path := joinNodePath(toPath, []string{"flag"})
			msg := fmt.Sprintf("%s: unknown flow trace flag %q "+
				"(supported: basic-datapath, session)", path, v)
			if lenient {
				warnings = append(warnings, msg+
					" (ignored: unknown flag dropped, defaults apply)")
				continue
			}
			return warnings, fmt.Errorf("%s", msg)
		}

		// packet-filter source/destination prefixes
		for _, pf := range namedInstances(toNode.FindChildren("packet-filter")) {
			pfPath := joinNodePath(toPath, []string{"packet-filter", pf.name})
			for _, leaf := range []string{"source-prefix", "destination-prefix"} {
				pn := pf.node.FindChild(leaf)
				if pn == nil {
					// Absent prefix: a protocol-only filter is legitimate, so
					// leave it alone. This is AST-distinguishable from the
					// present-but-empty case below (node missing vs node
					// present with an empty value).
					continue
				}
				v := nodeVal(pn)
				if v == "" {
					// Present-but-empty (`source-prefix ""`): the node exists
					// but carries no prefix. Accepting it lets the runtime
					// append a fully-unconstrained filter (zero srcNet/dstNet,
					// no proto) that matches EVERY event — the #3422 M01
					// fail-open in a smaller costume. Reject at strict; downgrade
					// to a warning on the lenient load / peer-sync path, where
					// the compiler marks the filter InvalidPrefix and the
					// runtime fails it closed (match-none).
					path := joinNodePath(pfPath, []string{leaf})
					msg := fmt.Sprintf("%s: %s is present but empty; an empty "+
						"prefix would match every event (omit %s for a "+
						"protocol-only filter, or set a CIDR prefix)",
						path, leaf, leaf)
					if lenient {
						warnings = append(warnings, msg+
							" (ignored: filter set to match-none)")
						continue
					}
					return warnings, fmt.Errorf("%s", msg)
				}
				if _, err := netip.ParsePrefix(v); err != nil {
					path := joinNodePath(pfPath, []string{leaf})
					msg := fmt.Sprintf("%s: invalid %s %q: %v",
						path, leaf, v, err)
					if lenient {
						warnings = append(warnings, msg+
							" (ignored: filter set to match-none)")
						continue
					}
					return warnings, fmt.Errorf("%s", msg)
				}
			}
		}
	}
	return warnings, nil
}

// flowTraceSizeFilesValues extracts the configured `size` and `files` raw
// token strings (and whether each was present) from a
// `security flow traceoptions file <name>` node, across every AST shape the
// parser can produce:
//
//   - single-line hierarchical (`file foo size 100000 files 2;`, NewParser):
//     the tokens land directly in fileNode.Keys[2:].
//   - block hierarchical (`file foo { size 100000; files 2; }`): each token is
//     a separate child node (Keys=["size","100000"], Keys=["files","2"]).
//   - flat set (`set ... file foo size 100000 files 2`): the bracket/flat lexer
//     COLLAPSES the trailing tokens onto ONE child node's Keys
//     (Keys=["size","100000","files","2"]) — the #2419 multi-value-leaf shape.
//
// A single keyword scan over fileNode.Keys[2:] followed by every child node's
// full Keys covers all three: in each shape the `size`/`files` keyword is
// immediately followed by its value in the same Keys slice. The last
// occurrence wins (a child-node value overrides a same-named flat token),
// matching the original compileFlow ordering (children read after the flat
// Keys loop). This is the single source of truth shared by compileFlow (what
// the compiler stores) and validateFlowTraceSizeFilesAST (what the gate
// checks), so the two cannot diverge.
func flowTraceSizeFilesValues(fileNode *Node) (size string, sizeSet bool, files string, filesSet bool) {
	scan := func(keys []string, from int) {
		for i := from; i+1 < len(keys); i++ {
			switch keys[i] {
			case "size":
				size, sizeSet = keys[i+1], true
			case "files":
				files, filesSet = keys[i+1], true
			}
		}
	}
	scan(fileNode.Keys, 2)
	for _, child := range fileNode.Children {
		scan(child.Keys, 0)
	}
	return size, sizeSet, files, filesSet
}

// validateFlowTraceSizeFilesAST is the #3424 commit-time range gate for
// `security flow traceoptions file <name> size <s> files <n>`. The compiler
// (compileFlow) parsed both tokens with strconv.Atoi and stored any positive
// integer with no bounds, so a committed `size 1 files 1000000000` made every
// matching trace line exceed the rotation threshold and turned each rotation
// into a ~1e9-iteration rename loop run synchronously from the event callback
// under the writer mutex — a per-event CPU storm (codex-review-097 M03). Both
// tokens are single AST values SchemaValidate treats as opaque free text and
// live in EITHER the file node's flat Keys[2:] or hierarchical size/files
// children (a dual value-location SchemaValidate cannot express), so — like
// the file/flag/filter gates above — they are range-checked here on the
// group-expanded tree, mirroring flowTraceSizeFilesValues / compileFlow.
//
// The bounds (FlowTraceMin/MaxFileSize, FlowTraceMin/MaxFileCount) match the
// interactive `monitor security flow file` limits so the persistent and
// on-demand trace paths agree.
//
// Strict path (commit / commit-check, lenient=false): a non-integer or
// out-of-range size/files is a hard compile error. Lenient path (load /
// peer-sync, lenient=true): downgraded to a warning so an already-persisted or
// peer-synced config an older binary accepted still boots — NewTraceWriter
// clamps an out-of-range value to the same bounds at runtime, so a
// leniently-loaded value cannot trigger the CPU storm (#1960 / #3261
// fail-closed-on-load class).
func validateFlowTraceSizeFilesAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	for _, n := range nodes {
		if n.Name() != "security" {
			continue
		}
		secPath := joinNodePath(prefix, n.Keys)
		flowNode := n.FindChild("flow")
		if flowNode == nil {
			continue
		}
		toNode := flowNode.FindChild("traceoptions")
		if toNode == nil {
			continue
		}
		fileNode := toNode.FindChild("file")
		if fileNode == nil {
			continue
		}
		filePath := joinNodePath(secPath, []string{"flow", "traceoptions", "file"})

		size, sizeSet, files, filesSet := flowTraceSizeFilesValues(fileNode)

		if sizeSet {
			v, err := strconv.ParseInt(size, 10, 64)
			if err != nil || v < FlowTraceMinFileSize || v > FlowTraceMaxFileSize {
				path := joinNodePath(filePath, []string{"size"})
				msg := fmt.Sprintf("%s: invalid trace file size %q "+
					"(must be %d..%d bytes)",
					path, size, FlowTraceMinFileSize, FlowTraceMaxFileSize)
				if lenient {
					warnings = append(warnings, msg+
						" (ignored: clamped to a safe size at runtime)")
				} else {
					return warnings, fmt.Errorf("%s", msg)
				}
			}
		}
		if filesSet {
			v, err := strconv.Atoi(files)
			if err != nil || v < FlowTraceMinFileCount || v > FlowTraceMaxFileCount {
				path := joinNodePath(filePath, []string{"files"})
				msg := fmt.Sprintf("%s: invalid trace file count %q "+
					"(must be %d..%d)",
					path, files, FlowTraceMinFileCount, FlowTraceMaxFileCount)
				if lenient {
					warnings = append(warnings, msg+
						" (ignored: clamped to a safe count at runtime)")
				} else {
					return warnings, fmt.Errorf("%s", msg)
				}
			}
		}
	}
	return warnings, nil
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
			name := opt.Name()
			switch name {
			case "early-ageout", "high-watermark", "low-watermark":
			default:
				// #3440 H2: record an unrecognized aging leaf so
				// validateFlowAgingStrict can reject it at commit instead of
				// the pre-#3440 silent drop (which let `set security flow
				// aging bogus 5` commit cleanly with no effect).
				sec.Flow.AgingUnknownLeaves = append(sec.Flow.AgingUnknownLeaves, name)
				continue
			}
			if len(opt.Keys) < 2 {
				continue
			}
			val, err := strconv.Atoi(opt.Keys[1])
			if err != nil {
				// The schema typed-leaf gate (SchemaValidate) rejects a
				// non-integer / out-of-range value at commit; on the tolerant
				// load path it is left at the zero default (disabled).
				continue
			}
			switch name {
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
			// Read size/files across every AST shape (single-line hierarchical,
			// block hierarchical, and the #2419 flat-set collapsed child). The
			// shared helper is the SSOT with validateFlowTraceSizeFilesAST so the
			// gate checks exactly what is stored here. A non-integer value is left
			// at zero (default applied downstream); the strict commit gate rejects
			// it loudly before reaching here (#3424).
			sizeStr, sizeSet, filesStr, filesSet := flowTraceSizeFilesValues(fileNode)
			if sizeSet {
				if n, err := strconv.Atoi(sizeStr); err == nil {
					to.FileSize = n
				}
			}
			if filesSet {
				if n, err := strconv.Atoi(filesStr); err == nil {
					to.FileCount = n
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
			// A prefix node that is PRESENT but empty (`source-prefix ""`) is
			// malformed: an empty prefix is not "no constraint" but a typo that
			// must narrow tracing to nothing, not broaden it to everything
			// (#3422 M01). Record the distinction here (present-but-empty vs the
			// absent protocol-only case) so the runtime can fail it closed; the
			// strict commit gate rejects it outright before it ever lands here.
			if spNode := pfInst.node.FindChild("source-prefix"); spNode != nil {
				pf.SourcePrefix = nodeVal(spNode)
				if pf.SourcePrefix == "" {
					pf.InvalidPrefix = true
				}
			}
			if dpNode := pfInst.node.FindChild("destination-prefix"); dpNode != nil {
				pf.DestinationPrefix = nodeVal(dpNode)
				if pf.DestinationPrefix == "" {
					pf.InvalidPrefix = true
				}
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
