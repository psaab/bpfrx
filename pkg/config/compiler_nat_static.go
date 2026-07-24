package config

import (
	"strconv"
	"strings"
)

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

// staticNATMappedPortFromKeys extracts the `mapped-port <port>` modifier(s)
// from a flat-set static-NAT leaf's collapsed Keys (#2491). The lexer
// collapses `then static-nat prefix <ip> mapped-port <port>` onto one node
// whose Keys are `["static-nat","prefix","<ip>","mapped-port","<port>"]`
// because `static-nat` is a children:nil schema leaf, so this in-leaf token
// bypasses the schema value validator.
//
// It scans EVERY `mapped-port` occurrence (not just the first) and folds them
// through combineMappedPortOperands so a contradictory duplicate fails closed;
// a bare trailing keyword contributes an empty operand. The (port, raw,
// present) triple feeds the strict gate (validateNATHostMaskStrict): present is
// the explicit presence signal (C179-038 + fold) that MappedPort==0 and raw==""
// cannot carry on their own (the literal "0", a non-numeric token, an empty
// operand, and a bare keyword all collapse to port 0 / raw "").
func staticNATMappedPortFromKeys(keys []string) (port int, raw string, present bool) {
	var operands []string
	for i := 0; i < len(keys); i++ {
		if keys[i] != "mapped-port" {
			continue
		}
		// A bare trailing `mapped-port` (keyword is the last key) has no
		// operand — record an empty operand so combine flags it malformed
		// (present=true, raw="") rather than dropping the occurrence.
		if i+1 < len(keys) {
			operands = append(operands, keys[i+1])
		} else {
			operands = append(operands, "")
		}
	}
	return combineMappedPortOperands(operands)
}

// combineMappedPortOperands folds one-or-more `mapped-port` operands (the
// tokens trailing each `mapped-port` keyword, in AST order) into the
// (port, raw, present) triple the strict gate (validateNATHostMaskStrict)
// consumes. It is shared by the flat collapsed-keys scan
// (staticNATMappedPortFromKeys) and the hierarchical sibling scan in
// compileNATStatic so BOTH AST shapes fail closed identically.
//
// Returns (C179-038 + #6479 fold):
//   - no operands:                    (0, "",          false) — keyword absent.
//   - every operand a valid 1-65535:  (last, "<last>", true) — last-wins, the
//     Junos duplicate-stanza rule; a single valid token is the common case.
//   - ANY operand malformed (empty, bare, non-numeric, or out-of-range):
//     (0, "<first non-empty bad token>", true) — FAIL CLOSED. A contradictory
//     duplicate (`mapped-port 8080 mapped-port notaport`) is rejected, not
//     silently reduced to the one good value; raw names the offending token
//     (or "" → the strict gate prints "(missing value)" for an empty/bare one).
//
// A malformed operand zeroes the port even when another occurrence is valid, so
// the strict gate's `MappedPort < 1` branch rejects and no bogus port ever
// reaches the dataplane; the lenient load / peer-sync path keeps MappedPort==0
// (a plain 1:1, matching the pre-fix fail-closed behaviour).
func combineMappedPortOperands(operands []string) (port int, raw string, present bool) {
	if len(operands) == 0 {
		return 0, "", false
	}
	present = true
	haveBad := false
	badRaw := ""
	lastValidPort := 0
	lastValidRaw := ""
	for _, op := range operands {
		if p, err := strconv.Atoi(op); err == nil && p >= 1 && p <= 65535 {
			lastValidPort = p
			lastValidRaw = op
			continue
		}
		haveBad = true
		// Prefer the first NON-EMPTY bad token for the diagnostic; an
		// all-empty/bare set leaves badRaw=="" → the gate prints
		// "(missing value)".
		if badRaw == "" && op != "" {
			badRaw = op
		}
	}
	if haveBad {
		return 0, badRaw, true
	}
	return lastValidPort, lastValidRaw, true
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
				rule.MappedPortRaw = ""
				rule.MappedPortPresent = false
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
							rule.MappedPort, rule.MappedPortRaw, rule.MappedPortPresent = staticNATMappedPortFromKeys(t.Keys)
						} else if pn := t.FindChild("prefix"); pn != nil {
							rule.Then = nodeVal(pn)
							// #2491: `then static-nat prefix <ip> mapped-port
							// <port>` collapses onto the `prefix` child's Keys
							// (`["prefix","<ip>","mapped-port","<port>"]`)
							// because `static-nat` is a children:nil schema
							// leaf, so the modifier rides on the prefix leaf,
							// not a sibling `mapped-port` node. Scan pn.Keys.
							rule.MappedPort, rule.MappedPortRaw, rule.MappedPortPresent = staticNATMappedPortFromKeys(pn.Keys)
							// Hierarchical shape `static-nat { prefix X;
							// mapped-port P; }` carries the modifier as a
							// sibling child. Consult siblings ONLY when the
							// collapsed keys did not carry a mapped-port (else
							// the flat-set value wins). Scan ALL sibling
							// `mapped-port` nodes (not just FindChild's first)
							// so a contradictory duplicate fails closed through
							// combineMappedPortOperands, and record presence +
							// the raw token even for an empty / non-numeric
							// sibling so the strict gate rejects it instead of
							// collapsing silently to MappedPort==0.
							if !rule.MappedPortPresent {
								var sibOps []string
								for _, c := range t.Children {
									if c.Name() == "mapped-port" {
										sibOps = append(sibOps, nodeVal(c))
									}
								}
								if len(sibOps) > 0 {
									rule.MappedPort, rule.MappedPortRaw, rule.MappedPortPresent = combineMappedPortOperands(sibOps)
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
