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

// natStaticPrefixInfo classifies a static-NAT address the way the Rust
// parse_nat_prefix (static_nat.rs, #3031) does: it returns the family, the
// prefix length, whether the value is a host route, and whether it parsed as
// an IP at all. A bare address is a host route (len == max). A `/N` mask is
// parsed numerically; bits < 0 flags a malformed/out-of-range mask (a
// non-numeric or `/33`/`/129` suffix) so the caller leaves the existing
// host-route rejection to fire. A non-IP token (address-book name) returns
// parsedIP == false and is not this validator's concern.
func natStaticPrefixInfo(addr string) (fam string, bits int, isHost, parsedIP bool) {
	slash := strings.IndexByte(addr, '/')
	ipPart := addr
	if slash >= 0 {
		ipPart = addr[:slash]
	}
	fam = natAddrFamily(ipPart)
	if fam == "" {
		return "", -1, false, false
	}
	max := 128
	if fam == "v4" {
		max = 32
	}
	if slash < 0 {
		return fam, max, true, true
	}
	n, err := strconv.Atoi(addr[slash+1:])
	if err != nil || n < 0 || n > max {
		return fam, -1, false, true
	}
	return fam, n, n == max, true
}

// isStaticBlockPair reports whether (match, then) is a valid block-to-block
// (subnet) static-NAT 1:1 mapping (#3031): both sides parse as IPs, both are
// non-host prefixes of the SAME family with EQUAL prefix length. The Rust
// dataplane installs exactly this case (offset-preserving remap); a
// host-vs-block, mismatched-length, mixed-family, or malformed-mask pair is
// NOT a block pair and falls through to the existing host-route rejection.
func isStaticBlockPair(match, then string) bool {
	mf, mb, mh, mp := natStaticPrefixInfo(match)
	tf, tb, th, tp := natStaticPrefixInfo(then)
	if !mp || !tp {
		return false // a non-IP token — leave to existing handling
	}
	if mh || th || mb < 0 || tb < 0 {
		return false // a host side or a malformed mask — not a block pair
	}
	return mf == tf && mb == tb
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

				// Single address
				if v := nodeVal(prop); v != "" {
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

// applyStaticNATFromScope stamps a from-scope onto a StaticNATRuleSet.
func applyStaticNATFromScope(rs *StaticNATRuleSet, s natMatchScope) {
	switch s.kind {
	case "interface":
		rs.FromInterface = s.value
	case "routing-instance":
		rs.FromRoutingInstance = s.value
	default: // "zone"
		rs.FromZone = s.value
	}
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
// A reversed (low > high) or out-of-range value parses successfully here (it is
// carried into PortLow/PortHigh); the strict commit gate
// (validateSourceNATPoolStrict) hard-rejects it so the operator sees the error
// rather than the rule dropping at runtime. ok is false only when no numeric low
// could be read (garbage tokens), leaving PortLow/PortHigh at their default.
func parseSourcePoolPortRange(toks []string) (low, high int, ok bool) {
	// Legacy explicit-keyword shape: low <lo> high <hi>.
	if len(toks) >= 4 && toks[0] == "low" && toks[2] == "high" {
		lo, err1 := strconv.Atoi(toks[1])
		hi, err2 := strconv.Atoi(toks[3])
		if err1 != nil || err2 != nil {
			return 0, 0, false
		}
		return lo, hi, true
	}
	// Junos shape: <low> [to <high>].
	if len(toks) == 0 {
		return 0, 0, false
	}
	lo, err := strconv.Atoi(toks[0])
	if err != nil {
		return 0, 0, false
	}
	hi := lo
	if len(toks) >= 3 && toks[1] == "to" {
		v, err2 := strconv.Atoi(toks[2])
		if err2 != nil {
			return 0, 0, false
		}
		hi = v
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

				// Port range / single value — flat leaf shapes
				// (Keys=["port","range",...]/["port",N]/["port",
				// "no-translation"]). #3906: `range` accepts both the Junos
				// wire shape `<low> to <high>` and the legacy `low <lo> high
				// <hi>` shape; `no-translation` preserves the source port.
				if len(prop.Keys) >= 3 && prop.Keys[1] == "range" {
					if lo, hi, ok := parseSourcePoolPortRange(prop.Keys[2:]); ok {
						pool.PortLow = lo
						pool.PortHigh = hi
					}
				} else if len(prop.Keys) == 2 && prop.Keys[1] != "range" &&
					prop.Keys[1] != "deterministic" &&
					prop.Keys[1] != "no-translation" {
					// "port N" single value.
					if n, err := strconv.Atoi(prop.Keys[1]); err == nil {
						pool.PortLow = n
						pool.PortHigh = n
					}
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
						if lo, hi, ok := parseSourcePoolPortRange(pc.Keys[1:]); ok {
							pool.PortLow = lo
							pool.PortHigh = hi
						}
					case "no-translation":
						pool.PortNoTranslation = true
					case "deterministic":
						applyDeterministicChildren(ensureDet(), pc)
					default:
						// Bare numeric child: `port N` grouped under a
						// modeled container becomes port { N }.
						if pc.IsLeaf && len(pc.Keys) == 1 {
							if n, err := strconv.Atoi(pc.Keys[0]); err == nil {
								pool.PortLow = n
								pool.PortHigh = n
							}
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
						} else if t.FindChild("interface") != nil {
							rule.Then.Type = NATSource
							rule.Then.Interface = true
						} else if t.FindChild("off") != nil {
							rule.Then.Type = NATSource
							rule.Then.Off = true
						} else if poolNode := t.FindChild("pool"); poolNode != nil {
							rule.Then.Type = NATSource
							rule.Then.PoolName = nodeVal(poolNode)
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

// staticNATMappedPortFromKeys extracts the `mapped-port <port>` modifier
// from a flat-set static-NAT leaf's collapsed Keys (#2491). The lexer
// collapses `then static-nat prefix <ip> mapped-port <port>` onto one node
// whose Keys are `["static-nat","prefix","<ip>","mapped-port","<port>"]`
// because `static-nat` is a children:nil schema leaf. Returns 0 (no port
// translation) when the keyword is absent or its value is non-numeric;
// the schema does not yet range-check this in-leaf token, so the caller's
// dataplane parse fails closed on an out-of-range value.
func staticNATMappedPortFromKeys(keys []string) int {
	for i := 0; i+1 < len(keys); i++ {
		if keys[i] == "mapped-port" {
			if p, err := strconv.Atoi(keys[i+1]); err == nil {
				return p
			}
			return 0
		}
	}
	return 0
}

// staticNATRoutingInstanceFromKeys scans a collapsed static-nat `then` leaf's
// Keys for the trailing `routing-instance <ri>` translation target (#4292) and
// returns the instance name (or "" when absent). The free-form static-nat leaf
// absorbs the whole `then static-nat <target> routing-instance <ri>` line onto
// one node's Keys in the flat-set shape.
//
// It scans from the END and returns the LAST occurrence, because the Junos
// grammar places the target routing-instance at the TAIL of the line. Scanning
// forward (first match) would return the wrong token if an earlier
// "routing-instance" appeared in the key list — e.g. `then static-nat
// prefix-name routing-instance routing-instance MYVRF`, where the address-book
// entry is pathologically NAMED "routing-instance": first-match would return
// that entry name instead of the trailing "MYVRF". Last-match is strictly more
// correct for the trailing-routing-instance grammar.
func staticNATRoutingInstanceFromKeys(keys []string) string {
	for i := len(keys) - 2; i >= 0; i-- {
		if keys[i] == "routing-instance" {
			return keys[i+1]
		}
	}
	return ""
}

// resolveStaticNATThenPrefixName resolves a `then static-nat prefix-name <name>`
// reference (#4290) to the single literal prefix that names the 1:1 translation
// target. Junos `prefix-name` references a single global address-book entry: an
// `address <name> <prefix>` resolves to its prefix; an `address-set` that
// expands to exactly one address resolves to that address's prefix; anything
// else (undefined, an address with no prefix, an empty / multi-member set,
// dangling) is not a valid scalar 1:1 target and returns ok=false so the caller
// leaves Then=="" and the strict guard rejects it.
func resolveStaticNATThenPrefixName(ab *AddressBook, name string) (string, bool) {
	if ab == nil || name == "" {
		return "", false
	}
	if a, ok := ab.Addresses[name]; ok && a != nil && a.Value != "" {
		return a.Value, true
	}
	if _, ok := ab.AddressSets[name]; ok {
		members, err := ExpandAddressSet(name, ab)
		if err != nil || len(members) != 1 {
			return "", false
		}
		if a, ok := ab.Addresses[members[0]]; ok && a != nil && a.Value != "" {
			return a.Value, true
		}
	}
	return "", false
}

// resolveStaticNATThenPrefixNames resolves every `then static-nat prefix-name`
// reference recorded during compileNATStatic into the rule's literal Then
// target (#4290). It runs AFTER the zone-local address books are folded into the
// global book (compiler.go), so the fully-resolved global book is available
// (compileNAT can run before compileAddressBook within a single `security {}`
// root, so resolution cannot happen inline in the then switch). An unresolvable
// reference leaves Then=="" — validateStaticNATThenTargetStrict then rejects it
// at strict commit (warns on the lenient load / peer-sync path, #1960).
func resolveStaticNATThenPrefixNames(sec *SecurityConfig) {
	ab := sec.AddressBook
	for _, rs := range sec.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.ThenPrefixName == "" || rule.Then != "" {
				continue
			}
			if prefix, ok := resolveStaticNATThenPrefixName(ab, rule.ThenPrefixName); ok {
				rule.Then = prefix
			}
		}
	}
}

func compileNATStatic(node *Node, sec *SecurityConfig) error {
	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
		// #3096: capture from scope across zone | interface |
		// routing-instance (static NAT has no `to` clause).
		fromScopes, _ := collectNATScopes(rsInst.node, false)

		// Parse rules (shared across all scope expansions)
		var rules []*StaticNATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &StaticNATRule{Name: ruleInst.name}

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
					case "destination-address":
						rule.Match = nodeVal(m)
					case "source-address":
						// #3435 (M02): support bracket / repeated lists
						// (`source-address [ a b c ]`) — the schema declares
						// this leaf `multi: true`, so the values collapse onto
						// m.Keys[1:] (flat-set) or m.Children (hierarchical).
						// Reading only nodeVal dropped every prefix after the
						// first. Mirror the source/destination-NAT loops above.
						if len(m.Keys) >= 2 {
							rule.SourceAddresses = append(rule.SourceAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.SourceAddresses = append(rule.SourceAddresses, child.Name())
							}
						}
						if len(rule.SourceAddresses) > 0 {
							// Back-compat: first element stays in the singular
							// field (NAT64 "::/0" tests, peer-sync).
							rule.SourceAddress = rule.SourceAddresses[0]
						}
					case "destination-port":
						// #2491: external (pre-translation) destination
						// port the inbound packet must carry. Schema
						// already range-checks 1..65535; tolerate a
						// non-numeric value defensively (leave 0 = any).
						if p, err := strconv.Atoi(nodeVal(m)); err == nil {
							rule.MatchDestinationPort = p
						}
					}
				}
			}

			// #3850: iterate EVERY `then {}` block, not just the first. A NAT
			// rule carries a single translation action, so a duplicate then
			// block resolves last-wins (Junos merges duplicate stanzas) — the
			// second block's action is applied, never silently dropped. RESET
			// the static-nat target fields at the top of each block so only the
			// LAST block's spec survives (no stale prefix/nptv6/mapped-port from
			// an earlier block). The reset covers ONLY the then-set fields
			// (Then/IsNPTv6/MappedPort) — the match fields (Match/SourceAddress
			// (es)/MatchDestinationPort) are set by the match loop above and MUST
			// persist. A single static-nat then-block is a complete spec, so
			// `prefix X mapped-port P` within one block stays coupled: the reset
			// runs BETWEEN blocks, then the whole block is read (#3850 review).
			for _, thenNode := range ruleInst.node.FindChildren("then") {
				rule.Then = ""
				rule.IsNPTv6 = false
				rule.MappedPort = 0
				// #4290 / #4292: reset the named-target reference and the
				// translation-target routing-instance alongside the other
				// then-set fields so only the LAST then-block's spec survives.
				rule.ThenPrefixName = ""
				rule.ThenRoutingInstance = ""
				for _, t := range thenNode.Children {
					if t.Name() == "static-nat" {
						if len(t.Keys) >= 3 && t.Keys[1] == "nptv6-prefix" {
							// set ... then static-nat nptv6-prefix PREFIX
							rule.Then = t.Keys[2]
							rule.IsNPTv6 = true
						} else if np := t.FindChild("nptv6-prefix"); np != nil {
							// static-nat { nptv6-prefix { PREFIX; } }
							rule.Then = nodeVal(np)
							rule.IsNPTv6 = true
						} else if len(t.Keys) >= 3 && t.Keys[1] == "prefix-name" {
							// #4290: set ... then static-nat prefix-name NAME.
							// The named form of `prefix <ip>`: NAME references a
							// global address-book entry whose literal prefix is
							// the 1:1 translation target. Recorded raw here and
							// resolved into rule.Then post-address-book-fold by
							// resolveStaticNATThenPrefixNames (the book may not
							// be compiled yet at this point). Before #4290 this
							// keyword fell through, leaving Then=="" (empty
							// translation target, silent broken static NAT).
							rule.ThenPrefixName = t.Keys[2]
						} else if pn := t.FindChild("prefix-name"); pn != nil {
							// static-nat { prefix-name NAME; }
							rule.ThenPrefixName = nodeVal(pn)
						} else if len(t.Keys) >= 3 && t.Keys[1] == "prefix" {
							rule.Then = t.Keys[2]
							// #2491: optional trailing `mapped-port <port>`.
							// Flat-set collapses the whole `prefix <ip>
							// mapped-port <port>` onto this one leaf's Keys
							// (`static-nat` is a children:nil schema leaf), so
							// scan for the keyword + value pair.
							rule.MappedPort = staticNATMappedPortFromKeys(t.Keys)
						} else if pn := t.FindChild("prefix"); pn != nil {
							rule.Then = nodeVal(pn)
							// #2491: `then static-nat prefix <ip> mapped-port
							// <port>` collapses onto the `prefix` child's Keys
							// (`["prefix","<ip>","mapped-port","<port>"]`)
							// because `static-nat` is a children:nil schema
							// leaf, so the modifier rides on the prefix leaf,
							// not a sibling `mapped-port` node. Scan pn.Keys.
							rule.MappedPort = staticNATMappedPortFromKeys(pn.Keys)
							// Hierarchical shape `static-nat { prefix X;
							// mapped-port P; }` carries it as a sibling child.
							if rule.MappedPort == 0 {
								if mp := t.FindChild("mapped-port"); mp != nil {
									if p, err := strconv.Atoi(nodeVal(mp)); err == nil {
										rule.MappedPort = p
									}
								}
							}
						} else if t.FindChild("inet") != nil || (len(t.Keys) >= 2 && t.Keys[1] == "inet") {
							// static-nat { inet; } — NAT64 translation
							rule.Then = "inet"
						}
						// #4292: a translation-target `routing-instance <ri>`
						// may trail ANY of the targets above (Junos allows it on
						// inet and prefix). It rides on the free-form static-nat
						// leaf in one of three AST shapes: collapsed onto t.Keys
						// (["static-nat","prefix","<ip>","routing-instance",
						// "<ri>"]); on the TARGET child leaf's Keys (the common
						// flat-set shape — static-nat has a `prefix`/`inet` child
						// whose Keys carry the trailing routing-instance pair); or
						// as a distinct sibling `routing-instance` child. Captured
						// for the accepted-but-unenforced advisory; the dataplane
						// does not route the post-translation packet against a
						// non-ingress table.
						if ri := staticNATRoutingInstanceFromKeys(t.Keys); ri != "" {
							rule.ThenRoutingInstance = ri
						} else if riNode := t.FindChild("routing-instance"); riNode != nil {
							rule.ThenRoutingInstance = nodeVal(riNode)
						} else {
							for _, c := range t.Children {
								if ri := staticNATRoutingInstanceFromKeys(c.Keys); ri != "" {
									rule.ThenRoutingInstance = ri
									break
								}
							}
						}
					}
				}
			}

			rules = append(rules, rule)
		}

		// Expand for each from-scope (#3096).
		for _, fs := range fromScopes {
			rs := &StaticNATRuleSet{
				Name:  rsInst.name,
				Rules: rules,
			}
			applyStaticNATFromScope(rs, fs)
			sec.NAT.Static = append(sec.NAT.Static, rs)
		}
	}
	return nil
}
