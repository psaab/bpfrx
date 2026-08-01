package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// defaultPoolAlarmHysteresis is the gap, in utilization percentage points,
// placed below the raise-threshold when an operator configures a raise-only
// pool-utilization-alarm (no explicit clear-threshold). A 10-point gap gives
// the alarm state machine hysteresis so it does not flap around the raise
// boundary, and keeps the defaulted clear inside the valid 1..raise-1 band for
// every realistic raise (>= 2). Junos allows a raise-only alarm; xpf mirrors
// that by synthesizing this clear rather than requiring the operator to name
// one (#4077).
const defaultPoolAlarmHysteresis = 10

// defaultPoolAlarmClearThreshold returns the clear-threshold to use when the
// operator supplied only a raise-threshold. It is raise minus a fixed
// hysteresis margin, floored at 1 so it stays a valid percentage. For raise >=
// 2 the result is strictly less than raise (0 < clear < raise), so it passes
// the commit gate and enables the runtime alarm; e.g. raise 90 -> clear 80,
// raise 50 -> clear 40, raise 5 -> clear 1.
func defaultPoolAlarmClearThreshold(raise int) int {
	clear := raise - defaultPoolAlarmHysteresis
	if clear < 1 {
		clear = 1
	}
	return clear
}

func compileNAT(node *Node, sec *SecurityConfig) error {
	// Initialize SourcePools map
	if sec.NAT.SourcePools == nil {
		sec.NAT.SourcePools = make(map[string]*NATPool)
	}

	// #3915: iterate EVERY source/destination/static/nat64/natv6v4/proxy-arp
	// sub-block under this nat{} node, not just the FIRST. The Junos parser
	// APPENDS a repeated hierarchical block as a sibling (parseStatements,
	// parser.go) instead of merging it, so `load override`/`load merge` can
	// produce a second `source {}` (or destination/static/nat64/proxy-arp)
	// block carrying additional rule-sets. The prior FindChild-first read
	// compiled only the first block and SILENTLY DROPPED the second block's
	// rule-sets -> the SNAT/DNAT/static rule-set vanished and traffic that
	// should have been translated egressed untranslated (a NAT bypass /
	// connectivity break). Each sub-block compiler APPENDS its rule-sets
	// (sec.NAT.Source / Destination.RuleSets / Static / NAT64 / ProxyARP) and
	// map-assigns its pools, so invoking it once per duplicate block MERGES the
	// blocks exactly as Junos merges duplicate hierarchical stanzas. With a
	// single block the callback fires exactly once, bit-identical to the prior
	// FindChild read. Mirrors the #3842 policy dup-block accumulate fix and the
	// #3444/#3562 forEachChild dup-block-bypass class.
	if err := forEachChild(node.Children, "source", func(srcNode *Node) error {
		if err := compileNATSource(srcNode, sec); err != nil {
			return fmt.Errorf("source: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	if err := forEachChild(node.Children, "destination", func(dstNode *Node) error {
		if err := compileNATDestination(dstNode, sec); err != nil {
			return fmt.Errorf("destination: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	if err := forEachChild(node.Children, "static", func(staticNode *Node) error {
		if err := compileNATStatic(staticNode, sec); err != nil {
			return fmt.Errorf("static: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	if err := forEachChild(node.Children, "nat64", func(nat64Node *Node) error {
		if err := compileNAT64(nat64Node, sec); err != nil {
			return fmt.Errorf("nat64: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	// natv6v4 { no-v6-frag-header; } — accumulate across duplicate blocks:
	// initialize the struct once and OR the flag so a second natv6v4 block
	// cannot silently reset an already-observed no-v6-frag-header.
	if err := forEachChild(node.Children, "natv6v4", func(v6v4Node *Node) error {
		if sec.NAT.NATv6v4 == nil {
			sec.NAT.NATv6v4 = &NATv6v4Config{}
		}
		if v6v4Node.FindChild("no-v6-frag-header") != nil {
			sec.NAT.NATv6v4.NoV6FragHeader = true
		}
		return nil
	}); err != nil {
		return err
	}

	// proxy-arp { interface <name> { address <addr>; } }
	//
	// proxyARPAddressValues is defined below compileNAT (see #6659).
	if err := forEachChild(node.Children, "proxy-arp", func(proxyNode *Node) error {
		for _, inst := range namedInstances(proxyNode.FindChildren("interface")) {
			entry := &ProxyARPEntry{Interface: inst.name}
			for _, prop := range inst.node.Children {
				if prop.Name() != "address" {
					continue
				}
				// Hierarchical range: Keys=["address","addr1","to","addr2"]
				if len(prop.Keys) >= 4 && prop.Keys[2] == "to" {
					expanded, err := expandAddressRange(prop.Keys[1], prop.Keys[3])
					if err != nil {
						return fmt.Errorf("proxy-arp interface %s: %w", inst.name, err)
					}
					entry.Addresses = append(entry.Addresses, expanded...)
					continue
				}

				// Set syntax range: Keys=["address","addr1"], child Keys=["to","addr2"]
				toChild := prop.FindChild("to")
				if toChild != nil {
					low := nodeVal(prop)
					high := nodeVal(toChild)
					if low != "" && high != "" {
						expanded, err := expandAddressRange(low, high)
						if err != nil {
							return fmt.Errorf("proxy-arp interface %s: %w", inst.name, err)
						}
						entry.Addresses = append(entry.Addresses, expanded...)
						continue
					}
				}

				// Single address, or a bracket / block LIST of addresses
				// (#6659). `address [ 192.0.2.1 192.0.2.2 ]` collapses onto
				// Keys[1:] and `address { 192.0.2.1; 192.0.2.2; }` onto
				// Children; nodeVal read only the first, so every address
				// after the first silently got NO proxy-ARP entry — the
				// firewall answered ARP for one address of the authored set and
				// stayed silent for the rest, so inbound traffic to them was
				// never drawn to this box.
				//
				// The DROP itself is a pure value-drop, not a validation
				// fail-open. But restoring the tail changes what a malformed
				// address does: it used to be discarded at compile, and it now
				// MATERIALISES into Addresses, where the installer
				// (pkg/dataplane/proxyarp.go) fails netip.ParsePrefix, logs a
				// bounded warning and skips it — a silently-inert entry. Before
				// #6659 proxy-ARP addresses carried NO commit-time validator at
				// all, so a malformed address in the FIRST slot committed clean
				// too. Widening a read requires widening its validator in the
				// same change, so validateProxyARPAddressesStrict now checks
				// EVERY value with the installer's own parse (strict rejects,
				// tolerant warns — see compiler_uniformgates_firewall_nat2.go).
				//
				// Read via proxyARPAddressValues rather than firewallMatchValues
				// so a MALFORMED range that fell through the two branches above
				// (a `to` child with an empty endpoint) does not contribute the
				// literal token "to" as an address.
				for _, v := range proxyARPAddressValues(prop) {
					addr := v
					if !strings.Contains(addr, "/") {
						addr += "/32"
					}
					entry.Addresses = append(entry.Addresses, addr)
				}
			}
			sec.NAT.ProxyARP = append(sec.NAT.ProxyARP, entry)
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

// proxyARPAddressValues extracts every address a proxy-arp `address` node
// carries, across BOTH parser AST shapes (#6659 — the proxy-ARP instance of the
// #2419 dual-shape class):
//
//   - single      `address 192.0.2.1;`            → Keys=["address","192.0.2.1"]
//   - bracket     `address [ 192.0.2.1 .2 ];`     → Keys=["address",".1",".2"]
//     (the lexer strips `[`/`]`, so the list collapses onto ONE node's Keys)
//   - block       `address { 192.0.2.1; .2; }`    → one child leaf per address
//
// It differs from firewallMatchValues in exactly one way: it SKIPS a `to` token.
// The caller handles `address <low> to <high>` ranges in two earlier branches,
// but those `continue` only on a WELL-FORMED range; a malformed one — a `to`
// child with an empty endpoint, or a bracket that leads with the keyword
// (`address [ to 192.0.2.1 ]`) — falls through to here, where `to` is grammar,
// not an address, and a plain firewallMatchValues would append it as "to/32".
//
// #6673: what the skip does, stated exactly, because the claim it used to carry
// — that it "preserves the pre-#6659 behaviour" — is false. Master read this
// leaf with nodeVal and installed the KEYWORD: verified against origin/master,
// `address [ to 192.0.2.1 ]`, `address { to; }` and `address { to; 192.0.2.5; }`
// each compiled to exactly ["to/32"]. Head compiles them to ["192.0.2.1/32"],
// [] and ["192.0.2.5/32"]. That is a deliberate behaviour CHANGE, and a
// harmless one: netip.ParsePrefix("to/32") fails, so the installer
// (pkg/dataplane/proxyarp.go) logged a bounded warning and skipped the entry.
// Master authored an inert entry; head does not author it.
//
// The skip is load-bearing for a different reason than the one it claimed.
// #6659 widened this read AND added validateProxyARPAddressesStrict, which
// parses every value with the installer's own netip.ParsePrefix. Drop the skip
// and "to/32" MATERIALISES into Addresses, where that validator HARD-REJECTS at
// strict commit a config master accepted — an invented rejection, which is the
// one outcome #6673 holds constant across this whole class. The skip keeps the
// accept/reject verdict identical to master while discarding only a token the
// dataplane could never have installed. Pinned by
// TestProxyARPAddresses6673ToKeywordIsNotAnAddressAndDoesNotInventARejection.
func proxyARPAddressValues(prop *Node) []string {
	var vals []string
	for _, k := range prop.Keys[1:] {
		if k != "" && k != "to" {
			vals = append(vals, k)
		}
	}
	for _, vn := range prop.Children {
		if len(vn.Keys) >= 1 && vn.Keys[0] != "" && vn.Keys[0] != "to" {
			vals = append(vals, vn.Keys[0])
		}
	}
	return vals
}

func compileNAT64(node *Node, sec *SecurityConfig) error {
	for _, inst := range namedInstances(node.FindChildren("rule-set")) {
		rs := &NAT64RuleSet{Name: inst.name}

		for _, child := range inst.node.Children {
			switch child.Name() {
			case "prefix":
				rs.Prefix = nodeVal(child)
			case "source-pool":
				rs.SourcePool = nodeVal(child)
			}
		}

		sec.NAT.NAT64 = append(sec.NAT.NAT64, rs)
	}
	return nil
}

// parseSourcePoolPortRange interprets the tokens that follow a source-pool
// `port range` keyword into an inclusive [low, high] range (#3906). It accepts
// two shapes so both the Junos wire grammar and the legacy explicit-keyword
// grammar compile:
//
//   - Junos: `<low> to <high>` (e.g. Keys after "range" = ["5000","to","6000"])
//     and a bare `<low>` (single port, low == high).
//   - Legacy: `low <lo> high <hi>` (Keys after "range" = ["low","5000","high",
//     "6000"]) — the shape the pre-#3906 compiler required. Before #3906 only
//     this shape was accepted, so the Junos `port range <low> to <high>` was
//     silently dropped and the pool defaulted to 1024-65535 PAT.
//
// Every endpoint is validated as a CANONICAL port in 1..65535 via
// ParseCanonicalUint (which rejects a leading sign, surrounding whitespace, a
// non-numeric token, and int overflow — the same primitive the DNAT and appid
// port parsers use) and the range must be non-decreasing (low <= high). ok is
// FALSE on ANY violation — a non-numeric / non-canonical token, an endpoint
// outside 1..65535 (0 included), or a reversed range — so the malformed value
// is NEVER stamped into PortLow/PortHigh (#5457). The caller records the raw
// offending spec in PortRangeInvalidSpec so the strict commit gate
// (validateSourceNATPoolStrict) hard-rejects it (operator-visible) AND the
// snapshot builder marks the pool unusable on the tolerant load / peer-sync
// path, rather than silently defaulting a bad range to 1024-65535 PAT.
//
// Before #5457 the endpoints were read with strconv.Atoi and returned ok=true
// even for a negative low ("port range low -1 high 99999" -> (-1, 99999, true))
// or a reversed range ("low 5000 high 100" -> (5000, 100, true)). Only the
// downstream strict gate caught the non-zero cases (the stamped bad value), and
// a 0-valued endpoint slipped through the parser as the "unconfigured" sentinel
// and silently widened to the default PAT range.
func parseSourcePoolPortRange(toks []string) (low, high int, ok bool) {
	// parsePort validates a single token as a canonical port in 1..65535.
	parsePort := func(s string) (int, bool) {
		n, err := ParseCanonicalUint(s)
		if err != nil || n < 1 || n > 65535 {
			return 0, false
		}
		return n, true
	}
	// Legacy explicit-keyword shape: low <lo> high <hi>.
	if len(toks) >= 4 && toks[0] == "low" && toks[2] == "high" {
		lo, ok1 := parsePort(toks[1])
		hi, ok2 := parsePort(toks[3])
		if !ok1 || !ok2 || lo > hi {
			return 0, 0, false
		}
		return lo, hi, true
	}
	// Junos shape: <low> [to <high>].
	if len(toks) == 0 {
		return 0, 0, false
	}
	lo, ok1 := parsePort(toks[0])
	if !ok1 {
		return 0, 0, false
	}
	hi := lo
	if len(toks) >= 3 && toks[1] == "to" {
		v, ok2 := parsePort(toks[2])
		if !ok2 {
			return 0, 0, false
		}
		hi = v
	}
	if lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}

func compileNATSource(node *Node, sec *SecurityConfig) error {
	// Global flags
	if node.FindChild("address-persistent") != nil {
		sec.NAT.AddressPersistent = true
	}

	// #4291: `nat source interface port-overloading off` disables source-port
	// reuse across destinations (a src-port-uniqueness hardening posture).
	// Accepted + recorded for the advisory (ValidateConfig); NOT enforced —
	// source-port overloading is always on in the SNAT allocator, so `off`
	// hardens nothing. Handle both the flat-set collapse
	// (["interface","port-overloading","off"]) and the hierarchical
	// `interface { port-overloading off; }` shape.
	if ifNode := node.FindChild("interface"); ifNode != nil {
		poOff := false
		for i := 0; i+1 < len(ifNode.Keys); i++ {
			if ifNode.Keys[i] == "port-overloading" && ifNode.Keys[i+1] == "off" {
				poOff = true
			}
		}
		if po := ifNode.FindChild("port-overloading"); po != nil && nodeVal(po) == "off" {
			poOff = true
		}
		if poOff {
			sec.NAT.SourceInterfacePortOverloadingOff = true
		}
	}

	// Parse source NAT pools
	for _, inst := range namedInstances(node.FindChildren("pool")) {
		pool := &NATPool{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "address":
				// A source pool `address` value carries EVERY IP the
				// SNAT allocator may draw from. It arrives in four
				// shapes (#2419 dual-AST-shape class — mirror
				// firewallMatchValues):
				//
				//   discrete set lines : one `address <ip>;` prop per IP
				//   bracket list       : `address [ a b c ]` — UNMODELED
				//                        in schema (schema_security.go
				//                        pool children), so SetPath's
				//                        unmodeled-leaf path collapses
				//                        every trailing token onto ONE
				//                        node: Keys=["address","a","b","c"]
				//   range              : `address <low> to <high>`
				//                        Keys=["address",low,"to",high]
				//   hierarchical block : `address { a; b to c; }` — one
				//                        child node per entry
				//                        (Keys=["a"] / ["b","to","c"])
				//
				// Before #4521 the inline branch read only prop.Keys[1]
				// and the range branch required Keys[2]=="to", so a
				// bracket list silently kept ONLY the first IP → the
				// pool shrank to one address → premature source-port
				// exhaustion. Read the whole Keys[1:] token stream
				// (plus the block children), expanding any `<low> to
				// <high>` sub-range in place. Keys[1:] and Children are
				// mutually exclusive per the #2419 pattern: the inline
				// form has no children and the block form has no inline
				// Keys value, so reading both cannot double-append.
				if err := appendPoolAddresses(pool, prop.Keys[1:]); err != nil {
					return err
				}
				for _, addrChild := range prop.Children {
					// A block child's own Keys are the address token
					// stream (Keys[0] is the IP, not the property name).
					if err := appendPoolAddresses(pool, addrChild.Keys); err != nil {
						return err
					}
				}
			case "port":
				// Port block configuration for a source pool. Supported
				// AST shapes (#3864, #2419 dual-AST-shape):
				//
				//   flat leaf  : Keys=["port","range","low",N,"high",M]
				//                Keys=["port",N]
				//                Keys=["port","deterministic","block-size",N]
				//                Keys=["port","deterministic","host","address",X]
				//   hierarchical / schema-grouped: one `port` container
				//                (schema_security.go groups the flat-set
				//                tokens) with `range`/`deterministic`
				//                children — `port { range low N high M;
				//                deterministic { block-size N; host address
				//                X } }`.
				//
				// Deterministic block-size and host address arrive on
				// SEPARATE flat-set `set` lines; before #3864 each sibling
				// `port deterministic ...` leaf reset pool.Deterministic to
				// a fresh struct (last-wins) and the host address was never
				// read off Keys, so the documented CGNAT quick-start was
				// spuriously rejected ("block-size must be > 0" / "host
				// address required"). Deterministic fields are now
				// ACCUMULATED into a single config across every shape and
				// sibling, writing only fields that are present.
				ensureDet := func() *DeterministicNATConfig {
					if pool.Deterministic == nil {
						pool.Deterministic = &DeterministicNATConfig{}
					}
					return pool.Deterministic
				}

				// setPortRange stamps a validated [lo,hi] source-port range onto
				// the pool. A malformed range (parseSourcePoolPortRange ok=false:
				// a non-canonical token, an endpoint outside 1..65535 including 0,
				// or a reversed low>high) is NEVER stamped — it records the raw
				// spec in PortRangeInvalidSpec so the strict commit gate
				// hard-rejects (operator-visible) and the snapshot builder marks
				// the pool unusable on the tolerant load / peer-sync path, rather
				// than silently defaulting the bad range to 1024-65535 PAT (#5457).
				setPortRange := func(toks []string) {
					if lo, hi, ok := parseSourcePoolPortRange(toks); ok {
						pool.PortLow = lo
						pool.PortHigh = hi
					} else {
						pool.PortRangeInvalidSpec = strings.Join(toks, " ")
					}
				}

				// Port range / single value — flat leaf shapes
				// (Keys=["port","range",...]/["port",N]/["port",
				// "no-translation"]). #3906: `range` accepts both the Junos
				// wire shape `<low> to <high>` and the legacy `low <lo> high
				// <hi>` shape; `no-translation` preserves the source port.
				if len(prop.Keys) >= 3 && prop.Keys[1] == "range" {
					setPortRange(prop.Keys[2:])
				} else if len(prop.Keys) == 2 && prop.Keys[1] != "range" &&
					prop.Keys[1] != "deterministic" &&
					prop.Keys[1] != "no-translation" {
					// "port N" single value — validated as a 1..65535 port via the
					// shared parser (a single token is the [N,N] range shape).
					setPortRange(prop.Keys[1:])
				}
				// no-translation may ride along on the flat-leaf keys
				// (Keys=["port","no-translation"]).
				for _, k := range prop.Keys[1:] {
					if k == "no-translation" {
						pool.PortNoTranslation = true
					}
				}

				// Deterministic — flat leaf: Keys=["port","deterministic",...].
				if len(prop.Keys) >= 2 && prop.Keys[1] == "deterministic" {
					applyDeterministicKeys(ensureDet(), prop.Keys[2:])
				}

				// Children — hierarchical / schema-grouped `port { ... }`.
				for _, pc := range prop.Children {
					switch pc.Name() {
					case "range":
						// range <low> to <high> | range low <lo> high <hi>
						// (#3906). pc.Keys[1:] is the token slice after the
						// `range` keyword.
						setPortRange(pc.Keys[1:])
					case "no-translation":
						pool.PortNoTranslation = true
					case "deterministic":
						applyDeterministicChildren(ensureDet(), pc)
					default:
						// Bare numeric child: `port N` grouped under a
						// modeled container becomes port { N }. Validated as a
						// 1..65535 port via the shared parser.
						if pc.IsLeaf && len(pc.Keys) == 1 {
							setPortRange(pc.Keys)
						}
					}
				}
			case "persistent-nat":
				// #2823: default is target-host-port (the pre-#2823
				// false-flag (dst_ip, dst_port) keying) so a config that
				// configures persistent-nat with no explicit permit keeps
				// the #2819 behavior byte-identical.
				pnat := &PersistentNATConfig{
					InactivityTimeout: 300,
					Permit:            PersistentNATPermitTargetHostPort,
				}
				parsePermit := func(v string) {
					switch v {
					case "any-remote-host":
						pnat.Permit = PersistentNATPermitAnyRemoteHost
					case "target-host":
						pnat.Permit = PersistentNATPermitTargetHost
					case "target-host-port":
						pnat.Permit = PersistentNATPermitTargetHostPort
					}
				}
				// Flat-set shape: persistent-nat collapses trailing tokens
				// onto Keys (e.g. ["persistent-nat","permit","target-host"]
				// or ["persistent-nat","inactivity-timeout","600"]).
				for i := 1; i+1 < len(prop.Keys); i++ {
					switch prop.Keys[i] {
					case "permit":
						parsePermit(prop.Keys[i+1])
					case "inactivity-timeout":
						if n, err := strconv.Atoi(prop.Keys[i+1]); err == nil {
							pnat.InactivityTimeout = n
						}
					}
				}
				// Hierarchical / schema-grouped shape: permit and
				// inactivity-timeout arrive as child leaves.
				for _, pnProp := range prop.Children {
					switch pnProp.Name() {
					case "permit":
						if v := nodeVal(pnProp); v != "" {
							parsePermit(v)
						}
					case "inactivity-timeout":
						if v := nodeVal(pnProp); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								pnat.InactivityTimeout = n
							}
						}
					}
				}
				pool.PersistentNAT = pnat
			case "port-overloading-factor":
				// #4291: source-pool port-overloading-factor <n>. Accepted +
				// recorded for the advisory (ValidateConfig); not enforced —
				// the SNAT allocator has no factor-scaled port budget. Flat-set
				// collapses ["port-overloading-factor","<n>"] onto Keys; the
				// hierarchical shape carries the value as nodeVal.
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						pool.PortOverloadingFactor = n
					}
				}
			case "routing-instance":
				// #4292: source-pool translation-target routing-instance.
				// Accepted + recorded for the advisory; not enforced (the
				// dataplane does not route the post-translation packet against
				// a non-ingress table).
				if v := nodeVal(prop); v != "" {
					pool.RoutingInstance = v
				}
			}
		}
		if pool.PortLow == 0 {
			pool.PortLow = 1024
		}
		if pool.PortHigh == 0 {
			pool.PortHigh = 65535
		}
		sec.NAT.SourcePools[pool.Name] = pool
	}

	// Parse pool-utilization-alarm
	if alarmNode := node.FindChild("pool-utilization-alarm"); alarmNode != nil {
		alarm := &PoolUtilizationAlarmConfig{}
		// clearSet records whether the operator explicitly provided a
		// clear-threshold token. Junos makes clear-threshold OPTIONAL: a
		// raise-only alarm is legal (#4077). When it is omitted we default it
		// to a hysteresis margin below raise (defaultPoolAlarmClearThreshold),
		// so the raise-only config compiles AND the runtime monitor enables the
		// alarm (it treats clear<=0 as disabled). An EXPLICIT clear-threshold —
		// even an invalid one like 0 or >= raise — is preserved verbatim so the
		// commit gate still rejects it.
		clearSet := false
		for _, ap := range alarmNode.Children {
			switch ap.Name() {
			case "raise-threshold":
				if v := nodeVal(ap); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						alarm.RaiseThreshold = n
					}
				}
			case "clear-threshold":
				clearSet = true
				if v := nodeVal(ap); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						alarm.ClearThreshold = n
					}
				}
			}
		}
		// Also handle flat keys: pool-utilization-alarm raise-threshold 80 clear-threshold 70
		for i := 1; i < len(alarmNode.Keys); i++ {
			if alarmNode.Keys[i] == "raise-threshold" && i+1 < len(alarmNode.Keys) {
				if n, err := strconv.Atoi(alarmNode.Keys[i+1]); err == nil {
					alarm.RaiseThreshold = n
				}
			}
			if alarmNode.Keys[i] == "clear-threshold" && i+1 < len(alarmNode.Keys) {
				clearSet = true
				if n, err := strconv.Atoi(alarmNode.Keys[i+1]); err == nil {
					alarm.ClearThreshold = n
				}
			}
		}
		// Raise-only config: default the clear-threshold to a hysteresis margin
		// below raise so the alarm is usable without an explicit clear.
		if alarm.RaiseThreshold > 0 && !clearSet {
			alarm.ClearThreshold = defaultPoolAlarmClearThreshold(alarm.RaiseThreshold)
		}
		sec.NAT.PoolUtilizationAlarm = alarm
	}

	// Validate deterministic NAT pools
	for _, pool := range sec.NAT.SourcePools {
		if pool.Deterministic == nil {
			continue
		}
		det := pool.Deterministic
		if det.BlockSize <= 0 {
			return fmt.Errorf("pool %q: deterministic block-size must be > 0", pool.Name)
		}
		if det.HostAddress == "" {
			return fmt.Errorf("pool %q: deterministic host address required", pool.Name)
		}
		_, hostNet, err := net.ParseCIDR(det.HostAddress)
		if err != nil {
			return fmt.Errorf("pool %q: invalid host address %q: %w", pool.Name, det.HostAddress, err)
		}
		ones, bits := hostNet.Mask.Size()
		portLow := pool.PortLow
		if portLow == 0 {
			portLow = 1024
		}
		portHigh := pool.PortHigh
		if portHigh == 0 {
			portHigh = 65535
		}
		portRange := portHigh - portLow + 1
		if det.BlockSize > portRange {
			return fmt.Errorf("pool %q: block-size %d exceeds port range %d", pool.Name, det.BlockSize, portRange)
		}
		blocksPerIP := portRange / det.BlockSize
		totalBlocks := len(pool.Addresses) * blocksPerIP

		if bits == 128 {
			// IPv6 host address — validate word-aligned prefix
			if ones != 32 && ones != 64 {
				return fmt.Errorf("pool %q: IPv6 host prefix must be /32 or /64, got /%d", pool.Name, ones)
			}
			// For IPv6, subscriber count is capped by pool capacity
			if totalBlocks == 0 {
				return fmt.Errorf("pool %q: insufficient capacity (0 blocks) for IPv6 deterministic NAT", pool.Name)
			}
		} else {
			// IPv4 host address
			hostCount := 1 << uint(bits-ones)
			if totalBlocks < hostCount {
				return fmt.Errorf("pool %q: insufficient capacity (%d blocks) for %d subscribers", pool.Name, totalBlocks, hostCount)
			}
		}
		if pool.PersistentNAT != nil {
			return fmt.Errorf("pool %q: deterministic and persistent-nat are mutually exclusive", pool.Name)
		}
		if sec.NAT.AddressPersistent {
			return fmt.Errorf("pool %q: deterministic and address-persistent are mutually exclusive", pool.Name)
		}
	}

	// #2079: pool-utilization-alarm threshold validation is NOT performed
	// here — it is a strict-vs-lenient gate (validatePoolUtilizationAlarm,
	// compiler.go typed-config phase) so the strict commit path hard-rejects
	// while the tolerant load/peer-sync path WARNS. Doing it here would hard-
	// fail CompileConfigLenient and brick a daemon restart on a legacy config
	// that was committed before #2079 added validation (#1979 doctrine).

	// Parse source NAT rule-sets
	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
		// #3096: capture from/to scope across zone | interface |
		// routing-instance (bracket lists produce multiple scopes).
		fromScopes, toScopes := collectNATScopes(rsInst.node, true)

		// Parse rules (shared across all scope-pair expansions)
		var rules []*NATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &NATRule{Name: ruleInst.name}

			// #3850: iterate EVERY `match {}` block, not just the first — a
			// duplicate block (a `load merge`/`load override` that splits its
			// conditions, or a hierarchical config authored twice) must
			// AND-combine every condition, never be dropped by a FindChild-first
			// read (a fail-open widening of the NAT match). Flat-set is
			// unaffected: SetPath merges duplicate containers into one node
			// (ast_edit.go), so this only changes the hierarchical/parser shape.
			for _, matchNode := range ruleInst.node.FindChildren("match") {
				for _, m := range matchNode.Children {
					switch m.Name() {
					case "source-address":
						// Support bracket lists: source-address [ addr1 addr2 ... ]
						if len(m.Keys) >= 2 {
							rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, child.Name())
							}
						}
						if len(rule.Match.SourceAddresses) > 0 {
							rule.Match.SourceAddress = rule.Match.SourceAddresses[0]
						}
					case "source-address-name":
						// #2416: address-book reference; resolved to prefixes at
						// snapshot-build time (appendNATSourceAddressName).
						// #3431: accumulate EVERY value of a bracket list /
						// repeated leaf (mirror firewallMatchValues) — a
						// `match source-address-name [ a b ]` used to keep only
						// the first and silently drop the rest.
						rule.Match.SourceAddressNames = append(rule.Match.SourceAddressNames, firewallMatchValues(m)...)
						if len(rule.Match.SourceAddressNames) > 0 {
							rule.Match.SourceAddressName = rule.Match.SourceAddressNames[0]
						}
					case "destination-address":
						// Support bracket lists: destination-address [ addr1 addr2 ... ]
						if len(m.Keys) >= 2 {
							rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, child.Name())
							}
						}
						if len(rule.Match.DestinationAddresses) > 0 {
							rule.Match.DestinationAddress = rule.Match.DestinationAddresses[0]
						} else {
							rule.Match.DestinationAddress = nodeVal(m)
						}
					case "destination-address-name":
						// #3229: address-book reference; resolved to prefixes at
						// snapshot-build time (appendNATDestinationAddressName).
						// #3431: accumulate every value (bracket list / repeated).
						rule.Match.DestinationAddressNames = append(rule.Match.DestinationAddressNames, firewallMatchValues(m)...)
						if len(rule.Match.DestinationAddressNames) > 0 {
							rule.Match.DestinationAddressName = rule.Match.DestinationAddressNames[0]
						}
					case "destination-port":
						// #3429 (H03): route source-NAT destination-port through
						// the shared DNAT port-list parser. The old scalar path
						// read only nodeVal/single child, so a flat-set
						// `destination-port 20000 to 20003` (collapsed onto
						// Keys=[destination-port 20000 to 20003], no children)
						// silently kept only the first port. parseDNATPortList
						// handles bracket lists and `low to high` ranges in both
						// the hierarchical and flat-set AST shapes.
						dports, dinvalid, drev := parseDNATPortList(m)
						rule.Match.DestinationPorts = append(rule.Match.DestinationPorts, dports...)
						rule.Match.InvalidDestinationPorts = append(rule.Match.InvalidDestinationPorts, dinvalid...)
						rule.Match.ReversedDestinationPortRanges = append(rule.Match.ReversedDestinationPortRanges, drev...)
						if rule.Match.DestinationPort == 0 && len(rule.Match.DestinationPorts) > 0 {
							rule.Match.DestinationPort = rule.Match.DestinationPorts[0]
						}
					case "application":
						// #3431: accumulate every application (bracket list /
						// repeated) — `match application [ a b ]` used to keep
						// only the first and silently drop the rest.
						rule.Match.Applications = append(rule.Match.Applications, firewallMatchValues(m)...)
						if len(rule.Match.Applications) > 0 {
							rule.Match.Application = rule.Match.Applications[0]
						}
					}
				}
			}

			// #3850: iterate EVERY `then {}` block, not just the first. A NAT
			// rule carries a single translation action, so a duplicate then
			// block resolves last-wins (Junos merges duplicate stanzas) — the
			// second block's action is applied, never silently dropped. RESET
			// the translation spec at the top of each block so only the LAST
			// block's fields survive: a source-nat then-block is a COMPLETE,
			// mutually-exclusive spec (interface | pool | off), so without the
			// reset a first `interface` block would leave Interface=true stale
			// under a second `pool` block (both fields set → the dataplane's
			// field precedence, not true last-wins). NATThen carries only these
			// translation-mode fields, so a whole-struct reset is safe (#3850
			// review).
			for _, thenNode := range ruleInst.node.FindChildren("then") {
				rule.Then = NATThen{}
				for _, t := range thenNode.Children {
					if t.Name() == "source-nat" {
						if len(t.Keys) >= 2 {
							switch t.Keys[1] {
							case "interface":
								rule.Then.Type = NATSource
								rule.Then.Interface = true
							case "off":
								rule.Then.Type = NATSource
								rule.Then.Off = true
							case "pool":
								rule.Then.Type = NATSource
								if len(t.Keys) >= 3 {
									rule.Then.PoolName = t.Keys[2]
								}
							}
						} else {
							// #5628: read EVERY hierarchical terminal child, not
							// the first one only (the former `else if` chain
							// silently picked interface > off > pool by child
							// order). A well-formed `source-nat { pool P; }` still
							// sets exactly one field, so this is bit-identical for
							// a valid single-child block. A CONTRADICTORY
							// single-node block such as `source-nat { interface;
							// pool P; }` now sets BOTH fields, so the resolved
							// NATThen faithfully carries two terminal actions and
							// validateNATTerminalActionCardinalityStrict rejects it
							// (strict commit) / warns (tolerant load) instead of
							// silently reinterpreting it.
							if t.FindChild("interface") != nil {
								rule.Then.Type = NATSource
								rule.Then.Interface = true
							}
							if t.FindChild("off") != nil {
								rule.Then.Type = NATSource
								rule.Then.Off = true
							}
							if poolNode := t.FindChild("pool"); poolNode != nil {
								rule.Then.Type = NATSource
								rule.Then.PoolName = nodeVal(poolNode)
							}
						}
					}
				}
			}

			rules = append(rules, rule)
		}

		// Expand Cartesian product of from-scopes × to-scopes (#3096).
		for _, fs := range fromScopes {
			for _, ts := range toScopes {
				rs := &NATRuleSet{
					Name:  rsInst.name,
					Rules: rules,
				}
				applyNATFromScope(rs, fs)
				applyNATToScope(rs, ts)
				sec.NAT.Source = append(sec.NAT.Source, rs)
			}
		}
	}
	return nil
}
