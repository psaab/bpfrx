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

// mappedPortNameValuedKeywords is the set of static-NAT `then` keywords whose
// following token is an operator-chosen NAME (not an IP), so that name could
// legally be the literal string "mapped-port". A `mapped-port` token that is the
// VALUE of one of these keywords is NOT a mapped-port modifier and must be
// skipped by the operand scan (#6479):
//
//   - `routing-instance <ri>` — a translation-target routing-instance may be
//     NAMED "mapped-port" (#4292).
//   - `prefix-name <name>` — a `then static-nat prefix-name` reference names a
//     global address-book entry (#4290) that may be NAMED "mapped-port".
//   - `nptv6-prefix <prefix>` — its value is a prefix, never "mapped-port", so
//     the skip never fires in practice; listed for defensive grammar symmetry
//     with the other free-form-value keywords (NPTv6 carries no mapped-port).
//
// `prefix` is deliberately ABSENT: a `prefix` value is ALWAYS an IP/CIDR and can
// NEVER be the string "mapped-port", so a `mapped-port` token immediately after
// the literal `prefix` keyword is ALWAYS the genuine modifier — the canonical
// separate-set-line Junos form `prefix <ip>` + `prefix mapped-port <port>`
// collapses to Keys `["prefix","mapped-port","<port>"]` and MUST be recovered.
// Including `prefix` here (a round-4 over-defensive addition) dropped that real
// modifier and both false-rejected the canonical clean rule AND reopened the
// C179-038 fail-open for a canonical malformed value; #6479 removes it.
var mappedPortNameValuedKeywords = map[string]struct{}{
	"routing-instance": {},
	"prefix-name":      {},
	"nptv6-prefix":     {},
}

// staticNATMappedPortOperandsFromKeys returns the operand token trailing each
// GENUINE `mapped-port` modifier in a static-NAT `then` node's collapsed Keys,
// in AST order (#2491, #6479 grammar-position fix). The lexer collapses
// `then static-nat prefix <ip> mapped-port <port>` onto one leaf whose Keys are
// `["prefix","<ip>","mapped-port","<port>"]` (or, on the static-nat node itself,
// `["static-nat","prefix","<ip>","mapped-port","<port>"]`) because `static-nat`
// is a children:nil schema leaf, so this in-leaf token bypasses the schema
// value validator and must be recovered here.
//
// A `mapped-port` token is a modifier ONLY in modifier position. It is SKIPPED
// only when it is the free-form VALUE of an immediately preceding NAME-valued
// keyword (mappedPortNameValuedKeywords: routing-instance / prefix-name /
// nptv6-prefix) — those take an arbitrary following token that can legally be
// the literal string "mapped-port". It is NOT skipped after `prefix`, whose
// value is always an IP: `prefix mapped-port <port>` is the canonical modifier
// (the #6479 regression this restores). A genuine modifier with no trailing
// operand (a bare `mapped-port` at the end of the key list) contributes an EMPTY
// operand so combineMappedPortOperands flags it malformed rather than dropping
// the occurrence.
func staticNATMappedPortOperandsFromKeys(keys []string) []string {
	var operands []string
	for i := 0; i < len(keys); i++ {
		if keys[i] != "mapped-port" {
			continue
		}
		// Grammar-position guard: a "mapped-port" immediately following a
		// NAME-valued keyword is that keyword's VALUE, not the modifier keyword.
		if i > 0 {
			if _, nameValued := mappedPortNameValuedKeywords[keys[i-1]]; nameValued {
				continue
			}
		}
		if i+1 < len(keys) {
			operands = append(operands, keys[i+1])
		} else {
			operands = append(operands, "")
		}
	}
	return operands
}

// mappedPortNodeOperands returns every operand attached to a `mapped-port`
// NODE (a sibling or nested `mapped-port` child of the static-nat / prefix
// node), across both shapes the parser can produce:
//
//   - packed / flat Keys: `mapped-port <p>` → Keys=["mapped-port","<p>"], and a
//     packed duplicate `mapped-port a mapped-port b` collapses onto one leaf's
//     Keys=["mapped-port","a","mapped-port","b"]. staticNATMappedPortOperands-
//     FromKeys walks ALL of them (scan-all, not first-wins), so a malformed
//     second operand fails closed.
//   - hierarchical value-as-child: `mapped-port { <p>; }` → Keys=["mapped-port"]
//     with the operand carried as a child. The key scan yields a single "" (bare
//     keyword) placeholder; replace it with the child value(s) so the operand is
//     recovered rather than mis-flagged as an empty (missing) value.
func mappedPortNodeOperands(c *Node) []string {
	ops := staticNATMappedPortOperandsFromKeys(c.Keys)
	if len(c.Children) > 0 && len(ops) == 1 && ops[0] == "" {
		ops = ops[:0]
		for _, gc := range c.Children {
			ops = append(ops, gc.Name())
		}
	}
	return ops
}

// staticNATMappedPortForNode folds every genuine `mapped-port` modifier operand
// attached to a static-nat `then` node — across EVERY AST shape AND across
// duplicate target children — into the (port, raw, present) triple the strict
// gate (validateNATHostMaskStrict) consumes (#2491, C179-038, #6479 fold).
//
// It gathers operands from:
//   - the static-nat node's own collapsed Keys (the `then static-nat prefix <ip>
//     mapped-port <port>` shape that lands on t.Keys);
//   - each `mapped-port` sibling child (the hierarchical `static-nat { prefix X;
//     mapped-port P; }` shape), scanning ALL of its operands (a packed
//     `mapped-port a mapped-port b` duplicate fails closed, not first-wins);
//   - each target child (`prefix`/`prefix-name` <val>) — BOTH the collapsed
//     modifier on its Keys (the flat-set `prefix <ip> mapped-port <port>` and
//     the canonical separate-set-line `prefix mapped-port <port>` shapes) AND a
//     mapped-port nested inside its Children (the canonical HIERARCHICAL
//     `prefix <ip> { mapped-port P; }` / `prefix { <ip>; mapped-port P; }`
//     shapes) — grammar-aware, so a `mapped-port` that is really a
//     routing-instance/prefix-name VALUE is skipped.
//
// Every child of a cross-node duplicate (two `then static-nat prefix <ip>
// mapped-port <p>` set lines) is scanned, then the WHOLE operand list folds
// through combineMappedPortOperands ONCE: last-wins when every occurrence is a
// valid 1-65535, and a malformed occurrence in ANY shape or ANY duplicate fails
// closed. There is no first-wins gate that could let a later malformed duplicate
// slip past an earlier valid one (the #6479 cross-node first-wins bug).
//
// The (port, raw, present) triple feeds the strict gate: present is the explicit
// presence signal (C179-038 + fold) that MappedPort==0 and raw=="" cannot carry
// on their own (the literal "0", a non-numeric token, an empty operand, and a
// bare keyword all collapse to port 0 / raw "").
func staticNATMappedPortForNode(t *Node) (port int, raw string, present bool) {
	operands := staticNATMappedPortOperandsFromKeys(t.Keys)
	for _, c := range t.Children {
		if c.Name() == "mapped-port" {
			// Hierarchical sibling `mapped-port <p>` (possibly packed).
			operands = append(operands, mappedPortNodeOperands(c)...)
			continue
		}
		// A target child (`prefix`/`prefix-name` <val> [mapped-port <p>]
		// [routing-instance <ri>]). The modifier may ride on the child's
		// collapsed Keys (flat-set) OR nest inside the child's Children (the
		// canonical hierarchical `prefix <ip> { mapped-port P; }` shape). Scan
		// BOTH — grammar-aware — so a malformed operand in either shape, and in
		// every child of a cross-node duplicate, fails closed.
		operands = append(operands, staticNATMappedPortOperandsFromKeys(c.Keys)...)
		for _, gc := range c.Children {
			if gc.Name() == "mapped-port" {
				operands = append(operands, mappedPortNodeOperands(gc)...)
			}
		}
	}
	return combineMappedPortOperands(operands)
}

// recordNPTv6MappedPortPresence stamps a `mapped-port` PRESENCE signal onto an
// NPTv6 static-nat rule WITHOUT installing a port value (#5523/#6479). NPTv6
// (RFC 6296) translates the IPv6 address prefix and has no transport-port
// concept, so a `then static-nat nptv6-prefix <p6> mapped-port <p>` is invalid
// in EVERY shape (collapsed keys, hierarchical nptv6-prefix child, or a distinct
// `mapped-port` sibling). The host-mask loop skips nptv6 rules entirely, so
// without recording presence a mapped-port on an nptv6 rule reached NO
// validator: a malformed operand was silently accepted (the C179-038 class for
// the nptv6 shape) and a well-formed one was silently ignored. This records
// MappedPortPresent (and the raw token for the diagnostic) so the strict nptv6
// gate (validateNPTv6Strict) rejects it — warns on the lenient no-brick path —
// while keeping MappedPort==0: a port is meaningless on nptv6 and no bogus port
// must cross the wire to the port-less nptv6 dataplane path.
//
// #6479 item 1: it folds through mergeMappedPortState with a FORCED port 0 (nptv6
// never installs a value) so PRESENCE accumulates and, critically, a later clean
// `prefix`/`prefix-name` sibling target in the same `then` block can no longer
// overwrite the stamp back to false — the multi-block nptv6 silent-accept.
func recordNPTv6MappedPortPresence(rule *StaticNATRule, t *Node) {
	_, raw, present := staticNATMappedPortForNode(t)
	mergeMappedPortState(rule, 0, raw, present) // nptv6 has no port; never install one
}

// combineMappedPortOperands folds one-or-more `mapped-port` operands (the
// tokens trailing each `mapped-port` keyword, in AST order) into the
// (port, raw, present) triple the strict gate (validateNATHostMaskStrict)
// consumes. It is called once per static-nat `then` node by
// staticNATMappedPortForNode over the UNION of operands from every AST shape
// (collapsed keys, sibling `mapped-port` child, and duplicate target children)
// so all shapes and duplicates fail closed identically.
//
// Returns (C179-038 + #6479 fold):
//   - no operands:                    (0, "",          false) — keyword absent.
//   - every operand a valid 1-65535:  (last, "<last>", true) — last-wins, the
//     Junos duplicate-stanza rule; a single valid token is the common case.
//     #6479 semantics note: an all-valid DUPLICATE on one target
//     (`mapped-port 8080 mapped-port 9090` → 9090) resolves last-wins,
//     which DIFFERS from origin/master's first-wins (8080). A duplicate
//     mapped-port on a single target is contradictory/malformed authoring
//     (either resolution is defensible); last-wins is the INTENTIONAL
//     choice here for consistency with the Junos duplicate-stanza rule the
//     rest of this fold uses, and is NOT a working-config regression (a
//     duplicate is not a valid production config on master either).
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

// mergeMappedPortState folds ONE static-nat target block's mapped-port reading
// (port, raw, present) into the rule's ACCUMULATING mapped-port state, so a later
// clean target block in the SAME `then` block can never silently CLEAR a presence
// or malformed stamp an earlier block set (#6479 item 1, the multi-block silent-
// accept). A single `then` may carry several `static-nat` targets (the
// hierarchical `then { static-nat { nptv6-prefix P { mapped-port BAD; } }
// static-nat { prefix Q; } }` sibling shape); Junos merges them into one action,
// so the mapped-port from ANY sibling is part of that action and must be gated.
// Before this fold the per-target direct assignment `rule.MappedPort, … =
// staticNATMappedPortForNode(t)` let the LAST sibling's (0,"",false) reading
// overwrite an earlier sibling's malformed stamp — the C179-038 class reopened
// for the multi-block shape, in BOTH the nptv6 and non-nptv6 branches.
//
// Semantics (matching combineMappedPortOperands, applied across sibling blocks):
//   - present==false: NO-OP. An absent mapped-port neither stamps presence nor
//     clears an earlier stamp — this is the exact overwrite the fix removes.
//   - the FIRST present block stamps MappedPortPresent (never reset to false here).
//   - a malformed operand in ANY block (present && port==0) LATCHES the rule
//     fail-closed (MappedPort==0, raw naming the offending token); a later valid
//     or absent block cannot un-fail it (order-independent fail-closed).
//   - among all-valid blocks the LAST valid port wins (Junos duplicate-stanza
//     last-wins).
//
// The per-`then`-block reset (compileNATStatic) still runs BETWEEN separate
// `then {}` blocks, preserving the #3850 last-then-block-wins semantics: a whole
// superseded `then` block is dead config, not part of the effective action. This
// accumulation is scoped to sibling targets WITHIN one `then` block.
func mergeMappedPortState(rule *StaticNATRule, port int, raw string, present bool) {
	if !present {
		return
	}
	// Latch: once a malformed operand has been seen for this rule the state is
	// fail-closed (present && MappedPort==0). A later block cannot un-fail it;
	// capture a diagnostic token only if none was recorded yet.
	failClosed := rule.MappedPortPresent && rule.MappedPort == 0
	rule.MappedPortPresent = true
	if failClosed {
		if rule.MappedPortRaw == "" && raw != "" {
			rule.MappedPortRaw = raw
		}
		return
	}
	if port == 0 {
		// This block is present-but-malformed (empty, bare, non-numeric,
		// out-of-range, or the literal "0"): fail closed, name its token.
		rule.MappedPort = 0
		rule.MappedPortRaw = raw
		return
	}
	// This block carries a valid 1-65535 port: last-valid-wins.
	rule.MappedPort = port
	rule.MappedPortRaw = raw
}

// mergeMappedPortForNode reads the genuine `mapped-port` modifier(s) attached to
// one static-nat target node (across every AST shape, via staticNATMappedPortFor-
// Node) and folds the result into the rule's accumulating state
// (mergeMappedPortState). It is the accumulate-don't-overwrite replacement for the
// per-target direct assignment on the prefix / prefix-name branches (#6479).
func mergeMappedPortForNode(rule *StaticNATRule, t *Node) {
	port, raw, present := staticNATMappedPortForNode(t)
	mergeMappedPortState(rule, port, raw, present)
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
			//
			// #6479 item 1: WITHIN one `then` block the child loop below may see
			// several `static-nat` sibling targets (the hierarchical `then {
			// static-nat {…} static-nat {…} }` shape). Those siblings are one
			// merged Junos action, so their mapped-port readings ACCUMULATE
			// through mergeMappedPortState (not a per-target overwrite): a later
			// clean sibling can no longer clear a presence/malformed stamp an
			// earlier sibling set, in either the nptv6 or the prefix/prefix-name
			// branch. The reset here is scoped to BETWEEN `then` blocks and still
			// gives #3850 last-then-block-wins — a superseded whole block is dead
			// config, distinct from a merged sibling target that is live.
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
							recordNPTv6MappedPortPresence(rule, t)
						} else if np := t.FindChild("nptv6-prefix"); np != nil {
							// static-nat { nptv6-prefix { PREFIX; } }
							rule.Then = nodeVal(np)
							rule.IsNPTv6 = true
							recordNPTv6MappedPortPresence(rule, t)
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
							// #6479: a prefix-name target carries the SAME optional
							// `mapped-port <port>` modifier as a literal prefix
							// (`prefix-name FOO mapped-port 8080`). Collect + gate it
							// identically so a malformed prefix-name mapped-port fails
							// closed instead of silently dropping — the C179-038 class,
							// reopened for the prefix-name shape. The scan is grammar-
							// aware: a prefix-name entry NAMED "mapped-port" is the
							// name value, not a modifier, and registers no port.
							mergeMappedPortForNode(rule, t)
						} else if pn := t.FindChild("prefix-name"); pn != nil {
							// static-nat { prefix-name NAME; }
							rule.ThenPrefixName = nodeVal(pn)
							// #6479: gate a prefix-name mapped-port identically (see
							// the collapsed-keys branch above).
							mergeMappedPortForNode(rule, t)
						} else if len(t.Keys) >= 3 && t.Keys[1] == "prefix" {
							rule.Then = t.Keys[2]
							// #2491 / #6479: recover the optional `mapped-port
							// <port>` modifier(s). Flat-set collapses `prefix
							// <ip> mapped-port <port>` onto this leaf's Keys
							// (`static-nat` is a children:nil schema leaf).
							// staticNATMappedPortForNode folds every occurrence
							// — here and on any sibling/nested/duplicate child —
							// through one combine so a malformed operand in any
							// shape fails closed, and skips a `mapped-port` that
							// is actually a routing-instance/prefix-name VALUE.
							mergeMappedPortForNode(rule, t)
						} else if pn := t.FindChild("prefix"); pn != nil {
							rule.Then = nodeVal(pn)
							// #2491 / C179-038 / #6479: recover the `mapped-port
							// <port>` modifier(s) across EVERY AST shape at once.
							// The modifier may ride on the `prefix` child's
							// collapsed Keys (`["prefix","<ip>","mapped-port",
							// "<port>"]`), on the canonical separate-set-line
							// `prefix mapped-port <port>` leaf, NESTED inside the
							// prefix child's Children (the hierarchical `prefix
							// <ip> { mapped-port P; }` / `prefix { <ip>;
							// mapped-port P; }` shapes), on a distinct
							// `mapped-port` sibling child (`static-nat { prefix X;
							// mapped-port P; }`), or be split across DUPLICATE
							// `then static-nat prefix <ip> mapped-port <p>`
							// children (two set lines). staticNATMappedPortForNode
							// folds them all through one combine — fail-closed on
							// any malformed occurrence, no first-wins gate — and
							// skips a `mapped-port` that is a routing-instance/
							// prefix-name VALUE (a routing-instance or prefix-name
							// NAMED "mapped-port" no longer false-rejects). It does
							// NOT skip after `prefix`, whose value is always an IP,
							// so `prefix mapped-port <port>` is recovered (#6479).
							mergeMappedPortForNode(rule, t)
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
