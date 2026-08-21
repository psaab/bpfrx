package config

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// natAddrFamily classifies an IP-part string the way the Rust parsers do,
// so the Go commit gate and the dataplane agree on every input.
//
//   - kind "v4": parses as IPv4 AND is textually a dotted-quad (no colon) —
//     i.e. exactly what Rust `Ipv4Addr::from_str` / `IpAddr::V4` accept.
//   - kind "v6": parses as IPv6 (textually colon-bearing) — what Rust
//     `IpAddr::V6` represents.
//   - kind "": does not parse as an IP at all (e.g. an address-book name);
//     NOT this validator's concern.
//
// The colon test is load-bearing: Go's net.ParseIP("::ffff:1.2.3.4").To4()
// is NON-nil (Go folds the IPv4-mapped form), but Rust `Ipv4Addr::from_str`
// REJECTS it and `IpAddr::from_str` classifies it as V6. Keying the family
// on text (no colon == v4) reproduces the Rust classification exactly, so a
// mapped form is treated as IPv6 here too — never accepted as a v4 host that
// the dataplane would then silently drop.
func natAddrFamily(ipPart string) string {
	if net.ParseIP(ipPart) == nil {
		return ""
	}
	if strings.IndexByte(ipPart, ':') >= 0 {
		return "v6"
	}
	return "v4"
}

// natCIDRIPPart returns the address portion of a CIDR string (everything before
// the first '/'), or the whole string if it carries no mask. It exists so the
// textual natAddrFamily classification can be applied to the ORIGINAL config
// text rather than a parsed net.IP — net.ParseCIDR/ParseIP folds an
// IPv4-mapped IPv6 literal (::ffff:1.2.3.4) into a 4-byte form whose .To4() is
// non-nil, which diverges from Rust's Ipv6Addr::from_str (it keeps the literal
// as V6). Keying the family on the un-parsed text preserves Go<->Rust parity.
func natCIDRIPPart(cidr string) string {
	if slash := strings.IndexByte(cidr, '/'); slash >= 0 {
		return cidr[:slash]
	}
	return cidr
}

// NATAddrFamily exposes natAddrFamily to the shared control-plane NAT query
// package (pkg/nat), so the forensic deterministic-NAT forward/reverse lookup
// classifies pool and prefix addresses with the SAME colon-strict Go/Rust
// parity rule the commit gate uses — never Go's net.IP.To4(), which folds an
// IPv4-mapped literal and diverges from the Rust dataplane parsers. See
// natAddrFamily.
func NATAddrFamily(ipPart string) string { return natAddrFamily(ipPart) }

// NATCIDRIPPart exposes natCIDRIPPart so the same shared package can strip a
// CIDR mask before the textual family classification. See natCIDRIPPart.
func NATCIDRIPPart(cidr string) string { return natCIDRIPPart(cidr) }

// isHostMaskAddress reports whether addr is a host route the static-NAT
// dataplane can install: a bare IP (no mask) or the canonical host mask
// (/32 for IPv4, /128 for IPv6). It mirrors EXACTLY the Rust host-mask gate
// added in PR #2167 for static NAT (parse_nat_addr in
// userspace-dp/src/nat/static_nat.rs): static NAT is a strictly 1:1 host
// mapping, so a non-host mask carries no representable meaning. The family
// (hence the required mask) is keyed on natAddrFamily so an IPv4-mapped
// IPv6 literal is classified the SAME as Rust (V6, host_len 128). The
// second return value reports whether addr parsed as an IP at all; a non-IP
// token (e.g. an address-book name) is NOT this validator's concern and is
// left to the existing address handling.
//
// NOTE: NAT64 source-pool addresses use isNAT64PoolHostAddress, NOT this
// predicate — the Rust parse_pool_v4 (nat64.rs) is IPv4-ONLY (the pool
// translates to IPv4 source addresses), so an IPv6 pool entry that this
// predicate would accept (its /128 host form) is silently dropped there.
func isHostMaskAddress(addr string) (host bool, parsed bool) {
	slash := strings.IndexByte(addr, '/')
	ipPart := addr
	if slash >= 0 {
		ipPart = addr[:slash]
	}
	fam := natAddrFamily(ipPart)
	if fam == "" {
		return false, false
	}
	if slash < 0 {
		// Bare address — a host in both families.
		return true, true
	}
	maskPart := addr[slash+1:]
	wantMask := "128"
	if fam == "v4" {
		wantMask = "32"
	}
	return maskPart == wantMask, true
}

// parseZoneList extracts zone names from a from/to node.
// Handles every AST shape the parser can produce for `from zone ...`:
//   - `from` carries the list inline: Keys=["from","zone","A","B","C"] → ["A","B","C"]
//   - Unified bracket list (#2419): one "zone" child with the whole list
//     collapsed onto its Keys — Keys=["zone","A","B","C"] → ["A","B","C"].
//     This is the shape flat-set `set ... from zone [ A B C ]` now produces;
//     before #2419 it split into a "zone" child plus orphan leaf children, and
//     reading only nodeVal here silently dropped every zone but the first
//     (FAIL-OPEN static NAT — the dropped zone's whole rule-set vanished).
//   - Hierarchical / legacy block: multiple "zone" children, each
//     Keys=["zone","A"] (from `from { zone A; zone B; }` or repeated
//     `set ... from zone A` / `from zone B` set commands).
//
// For each "zone" child we accumulate Keys[1:] AND any orphan leaf children,
// mirroring firewallMatchValues (compiler_firewall.go) — the #2419 contract for
// reading a multi-value leaf across both AST shapes.
func parseZoneList(node *Node) []string {
	// `from` carries the zone list inline on its own Keys.
	if len(node.Keys) >= 3 && node.Keys[1] == "zone" {
		return node.Keys[2:]
	}
	var zones []string
	for _, child := range node.Children {
		if child.Name() != "zone" {
			continue
		}
		// Unified bracket list / single value: every token after "zone".
		for _, k := range child.Keys[1:] {
			if k != "" {
				zones = append(zones, k)
			}
		}
		// Legacy bracket-expanded orphan leaf children (defensive — older
		// trees that still split the list into child leaves).
		for _, grandchild := range child.Children {
			if grandchild.IsLeaf && len(grandchild.Keys) >= 1 && grandchild.Keys[0] != "" {
				zones = append(zones, grandchild.Keys[0])
			}
		}
	}
	return zones
}

// natMatchScope is one (kind, value) scope token from a NAT rule-set
// `from`/`to` clause. kind is one of "zone" | "interface" |
// "routing-instance" (#3096).
type natMatchScope struct {
	kind  string
	value string
}

// natScopeKinds is the set of from/to scope keywords a NAT rule-set clause can
// carry. Order matters only for deterministic emission, not precedence.
var natScopeKinds = []string{"zone", "interface", "routing-instance"}

// parseNATMatchScopes generalizes parseZoneList (#3096): it extracts every
// from/to scope token — `zone`, `interface`, AND `routing-instance` — from a
// from/to clause node in both AST shapes the parser produces, instead of
// dropping the non-zone kinds:
//
//   - Inline: the `from`/`to` node carries the scope on its own Keys, e.g.
//     Keys=["from","interface","ge-0/0/1.0"] or the bracket-collapsed
//     Keys=["from","zone","A","B"] (#2419).
//   - Child-leaf / hierarchical: one child per scope kind, each
//     Keys=["interface","ge-0/0/1.0"] (with bracket lists collapsed onto the
//     child's Keys, plus defensive orphan grandchildren — mirroring
//     parseZoneList / firewallMatchValues).
//
// Junos restricts a single from/to clause to ONE kind. This function
// accumulates every kind present so the mixed-kind case is VISIBLE rather than
// silently dropped, but a mixed-kind clause is REJECTED at commit /
// commit-check by validateNATRuleSetMixedScopeAST (#4881) — it never reaches
// the Cartesian expansion, which would OR-expand it into multiple rule-sets and
// widen the match (there is no AND-at-match-time enforcement; the prior comment
// claiming that was wrong). On the tolerant load / peer-sync path the reject is
// downgraded to a warning, so a persisted mixed-kind clause still boots and is
// OR-expanded as before — accumulating every kind here keeps that legacy
// behaviour intact for the leniently-loaded case.
func parseNATMatchScopes(node *Node) []natMatchScope {
	var out []natMatchScope
	// Inline shape: `from`/`to` carries the scope on its own Keys.
	if len(node.Keys) >= 3 {
		for _, kind := range natScopeKinds {
			if node.Keys[1] == kind {
				for _, v := range node.Keys[2:] {
					if v != "" {
						out = append(out, natMatchScope{kind: kind, value: v})
					}
				}
			}
		}
	}
	// Child-leaf shape: one child per scope token.
	for _, child := range node.Children {
		kind := child.Name()
		isScope := false
		for _, k := range natScopeKinds {
			if k == kind {
				isScope = true
				break
			}
		}
		if !isScope {
			continue
		}
		// Unified bracket list / single value: every token after the kind.
		for _, v := range child.Keys[1:] {
			if v != "" {
				out = append(out, natMatchScope{kind: kind, value: v})
			}
		}
		// Defensive: older trees split the bracket list into orphan leaf
		// grandchildren.
		for _, grandchild := range child.Children {
			if grandchild.IsLeaf && len(grandchild.Keys) >= 1 && grandchild.Keys[0] != "" {
				out = append(out, natMatchScope{kind: kind, value: grandchild.Keys[0]})
			}
		}
	}
	return out
}

// collectNATScopes reads the `from` (and, when wantTo, `to`) clauses of a
// rule-set node into from/to scope lists. An empty side defaults to a single
// match-any zone scope ({kind:"zone", value:""}) — the legacy global
// behaviour. #3096.
func collectNATScopes(rsNode *Node, wantTo bool) (fromScopes, toScopes []natMatchScope) {
	for _, child := range rsNode.Children {
		switch child.Name() {
		case "from":
			fromScopes = append(fromScopes, parseNATMatchScopes(child)...)
		case "to":
			if wantTo {
				toScopes = append(toScopes, parseNATMatchScopes(child)...)
			}
		}
	}
	if len(fromScopes) == 0 {
		fromScopes = []natMatchScope{{kind: "zone", value: ""}}
	}
	if wantTo && len(toScopes) == 0 {
		toScopes = []natMatchScope{{kind: "zone", value: ""}}
	}
	return fromScopes, toScopes
}

// applyNATFromScope stamps a from-scope onto a NATRuleSet's typed fields.
func applyNATFromScope(rs *NATRuleSet, s natMatchScope) {
	switch s.kind {
	case "interface":
		rs.FromInterface = s.value
	case "routing-instance":
		rs.FromRoutingInstance = s.value
	default: // "zone"
		rs.FromZone = s.value
	}
}

// applyNATToScope stamps a to-scope onto a NATRuleSet's typed fields.
func applyNATToScope(rs *NATRuleSet, s natMatchScope) {
	switch s.kind {
	case "interface":
		rs.ToInterface = s.value
	case "routing-instance":
		rs.ToRoutingInstance = s.value
	default: // "zone"
		rs.ToZone = s.value
	}
}

// appendPoolAddresses parses a source-NAT pool `address` token stream and
// appends every IP onto pool.Addresses, expanding any `<low> to <high>`
// sub-range in place. The token stream is the multi-value form of the
// #2419 dual-AST-shape class: a bracket list `[ a b c ]`, a range
// `a to b`, or a mix `a b to c d` all collapse onto one Keys slice, and a
// hierarchical block passes each child node's Keys. Reading the FULL token
// stream (not just the first token) is the #4521 fix — the previous code
// read only Keys[1], truncating a bracket list to its first IP.
func appendPoolAddresses(pool *NATPool, tokens []string) error {
	for i := 0; i < len(tokens); {
		tok := tokens[i]
		if tok == "" {
			i++
			continue
		}
		// Range: "<low> to <high>" — three consecutive tokens with a
		// following high address present.
		if i+2 < len(tokens) && tokens[i+1] == "to" {
			expanded, err := expandAddressRange(tok, tokens[i+2])
			if err != nil {
				return fmt.Errorf("pool %q address range: %w", pool.Name, err)
			}
			pool.Addresses = append(pool.Addresses, expanded...)
			i += 3
			continue
		}
		pool.Addresses = append(pool.Addresses, tok)
		i++
	}
	return nil
}

// expandAddressRange expands "low/mask to high/mask" into individual IP strings.
// Both low and high must be /32 CIDRs. Max 256 IPs.
func expandAddressRange(low, high string) ([]string, error) {
	lowCIDR := low
	if !strings.Contains(lowCIDR, "/") {
		lowCIDR += "/32"
	}
	highCIDR := high
	if !strings.Contains(highCIDR, "/") {
		highCIDR += "/32"
	}
	lowIP, _, err := net.ParseCIDR(lowCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid low address %q: %w", low, err)
	}
	highIP, _, err := net.ParseCIDR(highCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid high address %q: %w", high, err)
	}
	lowIP = lowIP.To4()
	highIP = highIP.To4()
	if lowIP == nil || highIP == nil {
		return nil, fmt.Errorf("address range only supports IPv4")
	}
	lowN := binary.BigEndian.Uint32(lowIP)
	highN := binary.BigEndian.Uint32(highIP)
	if lowN > highN {
		return nil, fmt.Errorf("low address %s > high address %s", low, high)
	}
	// #5194 A3-b2-F9: compute the inclusive count in uint64. In uint32 the
	// full-domain range 0.0.0.0-255.255.255.255 has highN-lowN == 0xFFFFFFFF and
	// +1 WRAPS to 0, so the `> 256` guard passed, the generation loop ran zero
	// times, and the oversized range committed as an EMPTY pool with nil error
	// instead of the promised size error.
	count := uint64(highN) - uint64(lowN) + 1
	if count > 256 {
		return nil, fmt.Errorf("address range too large: %d IPs (max 256)", count)
	}
	var result []string
	buf := make(net.IP, 4)
	// count is bounded by 256 here, so the uint32 loop bound cannot wrap.
	for i := uint32(0); i < uint32(count); i++ {
		binary.BigEndian.PutUint32(buf, lowN+i)
		result = append(result, buf.String()+"/32")
	}
	return result, nil
}

// applyDeterministicKeys reads deterministic CGNAT sub-tokens from a flat-set
// key slice that begins immediately AFTER the "deterministic" keyword, e.g.
// ["block-size","2016"] or ["host","address","100.64.0.0/22"] or ["host","X"].
// Only fields that are present are written, so the caller can invoke it
// repeatedly across sibling `port deterministic ...` leaves and the values
// ACCUMULATE rather than overwrite last-wins (#3864; #2419 dual-AST-shape).
func applyDeterministicKeys(det *DeterministicNATConfig, keys []string) {
	for i := 0; i < len(keys); i++ {
		switch keys[i] {
		case "block-size":
			if i+1 < len(keys) {
				// A deterministic CGNAT block-size must be positive; the
				// strict commit gate rejects <= 0, but the lenient/tolerant
				// load path (#1960) would otherwise retain a negative Atoi
				// result. Guard the parse so a non-positive value is ignored
				// rather than stored (#5250 A3-b1 b1-F1).
				if n, err := strconv.Atoi(keys[i+1]); err == nil && n > 0 {
					det.BlockSize = n
				}
			}
		case "host":
			// "host address X" (canonical) or the tolerant "host X".
			if i+1 < len(keys) && keys[i+1] == "address" {
				if i+2 < len(keys) {
					det.HostAddress = keys[i+2]
				}
			} else if i+1 < len(keys) {
				det.HostAddress = keys[i+1]
			}
		}
	}
}

// applyDeterministicChildren reads deterministic CGNAT sub-fields from the
// CHILDREN of a `deterministic` container node (the hierarchical /
// schema-grouped shape, `deterministic { block-size N; host address X }`).
// Like applyDeterministicKeys it only writes present fields so mixed/repeated
// shapes accumulate into a single config (#3864).
func applyDeterministicChildren(det *DeterministicNATConfig, detNode *Node) {
	// The deterministic node may itself carry trailing flat-set tokens
	// (e.g. Keys=["deterministic","block-size","2016"]).
	if len(detNode.Keys) > 1 {
		applyDeterministicKeys(det, detNode.Keys[1:])
	}
	for _, c := range detNode.Children {
		switch c.Name() {
		case "block-size":
			if v := nodeVal(c); v != "" {
				// See applyDeterministicKeys: reject a non-positive block-size
				// on the lenient path rather than storing it (#5250 A3-b1 b1-F1).
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					det.BlockSize = n
				}
			}
		case "host":
			applyDeterministicHost(det, c)
		}
	}
}

// applyDeterministicHost reads the subscriber CIDR from a `host` node in any
// of its shapes: the flat leaf Keys=["host","address","X"], the hierarchical
// `host { address X }`, or the tolerant bare `host X`. It never records the
// literal keyword "address" as the value (#3864).
func applyDeterministicHost(det *DeterministicNATConfig, hostNode *Node) {
	if len(hostNode.Keys) >= 3 && hostNode.Keys[1] == "address" {
		det.HostAddress = hostNode.Keys[2]
		return
	}
	if addr := hostNode.FindChild("address"); addr != nil {
		if v := nodeVal(addr); v != "" {
			det.HostAddress = v
			return
		}
	}
	if len(hostNode.Keys) == 2 {
		det.HostAddress = hostNode.Keys[1]
	}
}

// applyNATThenActions records EVERY NAT-terminal translation action a
// `then { source-nat ... }` or `then { destination-nat ... }` node carries onto
// then. It walks the node's WHOLE subtree as one action-token stream — the
// tokens packed onto a node's Keys tail AND its descendants — ACCUMULATING
// rather than taking the first match. kind is the NATType to stamp when any
// action is found; allowInterface admits the source-NAT-only `interface` mode,
// which a destination-NAT node must never lower (destination NAT has no
// interface translation).
//
// # The three AST shapes, and why a two-loop scan sees only one of them
//
// A contradiction such as `source-nat off pool P` reaches the compiler in
// THREE structurally different shapes, and the shape depends on the syntax the
// operator used, not on what they wrote (#6820 round 6, B1):
//
//	then { source-nat off pool P; }     Keys=[source-nat off pool P]   packed on the ROOT
//	then { source-nat { off pool P; } } Keys=[source-nat] / [off pool P]   packed on a CHILD
//	set … then source-nat off pool P    Keys=[source-nat] / [off] / [pool P]   a GRANDCHILD chain
//
// The flat-set shape is the one to watch: `SetPath` builds a CHAIN, so the
// second action is a GRANDCHILD, and swapping the authored order swaps which
// action ends up nested (`… pool P off` gives [source-nat] / [pool P] / [off]).
// A scan that reads the root's Keys tail and then only each child's Name() /
// nodeVal() sees the first shape and nothing else: it lowers exactly ONE field
// from the other two and silently discards the rest.
//
// # Why a dropped action is invisible without this
//
// Nothing downstream sees it. parseKeys retains every token (parser.go) and
// schema validation deliberately IGNORES leftover container keys
// (schema_walk.go) — and the source-NAT `then` subtree is DELIBERATELY
// open-world (#4313, docs/config-schema.md), so `SchemaValidate` returns nil
// for every source-NAT row above. validateNATTerminalActionCardinalityStrict
// therefore counted the one lowered field, found n == 1, and the contradiction
// STRICTLY COMMITTED — as `off` or as `pool` decided by nothing but which token
// the operator happened to write first. The worst row is
// `set … then source-nat pool P off`: the `off` EXEMPTION is dropped and a
// translation is published in its place, the exact inverse of the authored
// action. (`then { destination-nat { pool PD off; } }` is the destination-NAT
// twin. The DNAT flat-set rows are stopped, but by closed-world
// `SchemaValidate`, not by this function.)
//
// This is the #2419 multi-value-leaf family (docs/config-schema.md,
// "Multi-value leaves and bracketed lists"), extended one level: a compiler
// reading a packed leaf must read Keys[1:] AND the node's descendants and
// accumulate, never Keys[1] alone and never Name()/nodeVal() alone.
//
// # The scan rule, and what it preserves
//
// Within ONE node's token tail, scanning STOPS at the first token that is not a
// recognized action for this kind. That single rule is what keeps the walk from
// changing any accepting decision the pre-#6820 compiler made:
//
//   - Trailing non-action grammar is still ignored. `source-nat pool P
//     persistent-nat permit any-remote-host` (the rule-level #4313 shape the
//     source-NAT `then` is left open-world for) stops the tail after the pool
//     name, exactly as the old Keys[1]-only read did.
//   - A LEADING unrecognized token contributes nothing, so the node lowers no
//     action at all — which is what the old `if Keys[1] == "off" … else if
//     Keys[1] == "pool"` chain did when Keys[1] was neither. This is load-
//     bearing: without it, an accumulating scan SKIPS the bad token and reads
//     the next one, so `then { destination-nat interface pool PD; }` (base:
//     rejected, zero actions) would newly resolve to a pool translation — a
//     silent reinterpretation of an operator action (#6820 round 6, B3). The
//     same hole exists for any unrecognized leading token, on BOTH kinds
//     (`source-nat frobnicate pool P`), so the rule is stated on the token, not
//     on `interface`.
//   - `pool` consumes exactly ONE value token, so a pool legitimately NAMED
//     "off"/"interface"/"pool" (`source-nat pool off`) is read as a NAME and
//     stays one action. When `pool` ENDS a tail the name comes from the first
//     child instead (`source-nat { pool { ghost-pool; } }`) — the nodeVal
//     fallback the old child loop used — and that child is then skipped by the
//     descent so its name is never re-read as an action token.
//
// Descent happens after the tail regardless of whether the tail lowered
// anything, mirroring the old code's fall-through to the children loop.
func applyNATThenActions(t *Node, then *NATThen, kind NATType, allowInterface bool) {
	// Keys[0] is the container keyword itself ("source-nat"/"destination-nat"),
	// never an action token; every descendant's Keys start at an action position.
	applyNATThenActionNode(t, t.Keys[1:], then, kind, allowInterface)
}

// applyNATThenActionNode is applyNATThenActions' recursive worker: it scans
// tokens as one node's action-token tail and then descends into that node's
// children. Splitting the tail from the node lets the caller pass Keys[1:] for
// the container root and Keys for every descendant, so ONE scan body — and one
// `allowInterface` decision — serves all three AST shapes. See
// applyNATThenActions for the shape catalogue and the stop-at-unrecognized rule.
func applyNATThenActionNode(n *Node, tokens []string, then *NATThen, kind NATType, allowInterface bool) {
	// nameChild, when set, is the child consumed as a `pool`'s NAME (the
	// `pool { <name>; }` shape). It is a name, not an action, so the descent
	// below must not re-scan it.
	var nameChild *Node
scan:
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "interface":
			if !allowInterface {
				// Destination NAT has no interface translation mode, so this is
				// not an action token here. Stop rather than skip — see the
				// leading-unrecognized-token rule on applyNATThenActions.
				break scan
			}
			then.Type = kind
			then.Interface = true
		case "off":
			then.Type = kind
			then.Off = true
		case "pool":
			then.Type = kind
			if i+1 < len(tokens) {
				then.PoolName = tokens[i+1]
				i++ // the loop's post statement advances past the name
				continue
			}
			// `pool` ended the tail: the name is the first child, if any.
			// A `pool` with no name at all leaves PoolName empty, which the
			// zero-action arm of the cardinality gate rejects — pre-#6820
			// behaviour for that shape, preserved.
			if len(n.Children) > 0 {
				nameChild = n.Children[0]
				then.PoolName = nameChild.Name()
			}
		default:
			break scan
		}
	}
	for _, c := range n.Children {
		if c == nameChild {
			continue
		}
		applyNATThenActionNode(c, c.Keys, then, kind, allowInterface)
	}
}
