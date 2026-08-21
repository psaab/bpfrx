package config

// schema_spelling_differential_gate_test.go — the #2419 multi-value-leaf gate.
//
// WHAT THIS GATE ASSERTS
//
// For every value-bearing leaf in setSchema, a two-element list authored in one
// spelling must compile to the same thing as the same list authored in any
// other spelling. The Junos grammar admits five:
//
//	A  hierarchical bracket   leaf [ v1 v2 ];
//	B  hierarchical block     leaf { v1; v2; }
//	C  hierarchical repeated  leaf v1; leaf v2;
//	D  flat-set bracket       set <path> leaf [ v1 v2 ]
//	E  flat-set repeated      set <path> leaf v1   /   set <path> leaf v2
//
// A compiler that reads one side of the AST agrees with itself in some
// spellings and not others, which is the #2419 defect class: the operator's
// config renders back intact and the compiler installed less than it says.
//
// WHY A BEHAVIOURAL DIFFERENTIAL AND NOT A LINT
//
// There is no single correct reader to lint FOR. This package now contains at
// least six accumulating readers — firewallMatchValues, multiLeafAuthoredValues,
// proxyARPAddressValues, eventMultiWordLeafValues, fabricMemberValues, and
// ntpServerValues, the last of which must additionally skip per-value option
// KEYWORDS. A rule matching "reads Keys[1]" would flag compliant code, and would
// miss the #7126 sites entirely: both of those read Keys[1:] AND Children exactly
// as CLAUDE.md instructs, and still drop, because reading Children is not the
// same as reading every KEY of each child. A differential has no such blind
// spot — it asks whether the compiler disagrees with ITSELF, which is the defect.
//
// ============================================================================
// THREE WAYS THIS HARNESS WAS ITSELF WRONG, AND HOW EACH WAS CAUGHT
// ============================================================================
//
// These are recorded here rather than in a commit message because each is a
// general trap for anyone writing a sweep, and because two of them made the
// harness report ZERO findings in whole subtrees while looking healthy.
//
// (1) A SWEEP THAT CANNOT FIND THE BUG YOU ALREADY HAVE IS A SWEEP THAT REPORTS
//     ZERO. The first version emitted `interfaces fab0 { ... }` for a
//     wildcard-named level, which the brace parser reads as Keys=["interfaces",
//     "fab0"] — one node, not two. The interface compiler never saw the
//     interface, so EVERY spelling compiled empty and the differential happily
//     reported agreement. It silently suppressed every finding under every
//     wildcard-rooted subtree, including #6694, which was known to be there at
//     the time. The distinction that fixes it: an `args` token belongs to the
//     SAME brace level as its keyword (`policy-statement P { ... }`), a WILDCARD
//     name opens a NEW one (`interfaces { fab0 { ... } }`). Hence the two
//     synthetic prefixes below, which is the only reason braceConfig can tell
//     them apart from a flat token slice.
//     The general form: calibrate a sweep against defects you have already
//     confirmed, BEFORE trusting it on code you have not inspected.
//
// (2) "DID THE LITERAL TOKEN SURVIVE" IS BLIND TO TRANSFORMED AND REJECTED
//     VALUES. The second version asked whether the authored token appeared in
//     the compiled config. A transformed value never does — CoS `code-points
//     [ ef af11 ]` compiles to a packed byte slice ("DSCPValues":"Lgo="), and
//     vlan-id-list compiles to ints. And a value the leaf's domain REJECTS makes
//     every spelling compile empty, so the differential sees agreement; that is
//     exactly why #6697 was missed with a synthetic token like "zzqaaa1", which
//     is not a DSCP alias. The primitive used now is encoding-independent:
//
//         dropped(spelling) := compile(spelling, [v1]) == compile(spelling, [v1 v2])
//
//     It does not care whether the value lands as a string, an int, a bitmask or
//     a byte slice — only whether the second value changed anything. The value
//     pairs below span several domains for the same reason.
//
// (3) THE FIX FOR (2) INTRODUCED A THIRD: "OUTPUT UNCHANGED" IS ALSO TRUE WHEN
//     THE LEAF NEVER COMPILED AT ALL. A synthetic parent path the compiler
//     rejects makes every form identical, and the leaf then looks like a uniform
//     drop. That filled the report with VRRP `virtual-address` and security
//     policy `then log` — both of which have readers documented as CORRECT.
//     The baseline guard below requires the FIRST value to move the output off
//     the no-value baseline before any verdict is recorded. Those two dropped
//     straight out when it was added, which is this gate's non-vacuity argument:
//     the guard was validated against known-GOOD code, not only against known
//     bad code.
//
// ============================================================================
// COVERAGE — A GREEN GATE IS NOT A SWEPT SCHEMA
// ============================================================================
//
// Measured at the commit that introduced this file. TestSchemaSpellingCoverage
// re-derives these numbers on every run and logs them, so they cannot rot into
// a stale comment.
//
//   - setSchema holds 1003 distinct value-bearing leaf NODES (children == nil,
//     args <= 1, no midKeyword). Only 5 leaves are excluded by construction
//     (args > 1 or a midKeyword), because a two-value list is not meaningful for
//     a compound leaf like route-filter or address-book `address <name> <prefix>`.
//   - The gate enumerates 1020 SITES from those nodes. The two numbers differ,
//     and the difference is not an error: a schemaNode reachable by more than one
//     path (a shared subtree such as the one under both `protocols` and
//     `routing-instances <n> protocols`) is a distinct site at each path, and
//     must be, because the compiler arm reading it may differ per path.
//   - Only 624 of those 1020 sites are actually COMPARED. The remaining 396 come
//     back inert or unstable under synthetic parent paths the compiler rejects —
//     39% of enumerated sites carry NO verdict from this gate, in either
//     direction. That is the single largest limit here.
//   - Class B (uniform drop) is reported ONLY for leaves the schema marks
//     multi: true. A scalar leaf dropping a second value is the schema working,
//     not a defect, so there is nothing to assert there.
//   - Eight value pairs. A leaf whose value domain none of them satisfies stays
//     invisible; that is how #6697 hid from version two.
//
// This gate also sees ONE DIRECTION. It detects a compiler DROPPING a value. It
// cannot detect the opposite defect — a reader PROMOTING a per-value modifier
// keyword into the value list, the hazard #6690 had to avoid — and no detector
// can, because the lexer strips brackets before anything observes them:
// `route 10.9.0.0/16 discard;` and `route [ 10.9.0.0/16 discard ];` compile
// byte-identically. Separating those requires knowledge of the leaf's Junos
// grammar, which today exists only where setSchema models a leaf's modifiers as
// children. Do not read a green run as "no multi-value defects".

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Known-inconsistent sites, keyed by the ISSUE that owns each one.
//
// A row here says: this leaf is KNOWN to compile differently depending on
// spelling, the defect is tracked, and the gate must not fail the build for it.
// Closing the issue is what removes the row — a stale row (a site that now
// agrees) is a HARD FAILURE, precisely so nobody deletes a row to get green
// without the fix that earned it.
//
// Site keys are normalised: every synthetic name the enumerator invents is
// rendered as <*>, so a row survives the schema growing a level.
// ---------------------------------------------------------------------------
var knownSpellingInconsistencies = map[string]string{
	// #6697 — CoS code-points. FIVE families, not the two in the issue title;
	// see the measured enumeration posted on the issue. The block spelling does
	// not truncate the list, it loses the WHOLE classifier.
	"class-of-service classifiers dscp <*> forwarding-class <*> loss-priority <*> code-points":            "#6697",
	"class-of-service classifiers ieee-802.1 <*> forwarding-class <*> loss-priority <*> code-points":      "#6697",
	"class-of-service classifiers inet-precedence <*> forwarding-class <*> loss-priority <*> code-points": "#6697",
	"class-of-service rewrite-rules dscp <*> forwarding-class <*> loss-priority <*> code-points":          "#6697",
	"class-of-service rewrite-rules ieee-802.1 <*> forwarding-class <*> loss-priority <*> code-points":    "#6697",

	// #6687 — vlan-id-list validated/read at slot 0 only.
	"bridge-domains <*> vlan-id-list": "#6687",

	// #6695 — RA dns-server-address drops every RDNSS server past the first.
	"protocols router-advertisement interface <*> dns-server-address": "#6695",

	// #6692 — five system-stanza multi-value leaves drop everything past slot 0.
	"system archival configuration archive-sites":     "#6692",
	"system services ssh key-exchange":                "#6692",
	"system services web-management api-auth api-key": "#6692",
	"system dataplane shared-umem interface":          "#6692",

	// #7126 — the flat-set bracket list lands on a CHILD's Keys for any leaf
	// setSchema does not mark multi, so a reader taking Keys[0] of each child
	// keeps only the first value even though it reads both sides.
	"routing-options rib-groups <*> import-rib": "#7126",
	"event-options policy <*> events":           "#7126",
}

// ---------------------------------------------------------------------------
// Sites the schema models as value leaves but which are NOT value lists, so a
// two-element "list" is not authorable Junos and the differential's verdict is
// meaningless. These are excluded from enumeration rather than allowlisted:
// allowlisting them by issue number would assert a defect that does not exist.
//
// Every entry was verified by inspecting where the extra tokens land, not
// assumed from the name: the screen and firewall entries put them in the
// UnknownLeaves / UnknownActions DIAGNOSTIC buckets, and the named-container
// entries create a second object rather than a second value.
// ---------------------------------------------------------------------------
var notAValueList = map[string]string{
	"applications application-set":  "named container: `application-set <name> { ... }`, not a value list",
	"policy-options prefix-list":    "named container: `prefix-list <name> { <prefix>; }`",
	"security nat destination pool": "named container: `pool <name> { ... }`",

	"chassis cluster redundancy-group <*> preempt": "flag with an optional sub-block (`preempt { delay N; }`)",

	"firewall family inet filter <*> term <*> then reject":  "action plus ONE optional reason token; extras land in UnknownActions",
	"firewall family inet6 filter <*> term <*> then reject": "action plus ONE optional reason token; extras land in UnknownActions",

	"security screen ids-option <*> alarm-without-drop": "bare flag; trailing tokens land in UnknownLeaves",
	"security screen ids-option <*> ip ip-sweep":        "container with sub-knobs (`ip-sweep { threshold N; }`)",
	"security screen ids-option <*> tcp port-scan":      "container with sub-knobs",
	"security screen ids-option <*> tcp syn-flood":      "container with sub-knobs",
	"security screen ids-option <*> udp":                "container with sub-knobs",
}

// Value pairs must span the DOMAINS setSchema's typed leaves accept, not merely
// be distinctive strings — see trap (2) above.
var gateValuePairs = []struct{ name, v1, v2 string }{
	{"word", "zzqaaa1", "zzqbbb2"},
	{"smallint", "101", "202"},
	{"bigint", "40961", "40962"},
	{"cidr", "10.211.212.0/24", "10.211.213.0/24"},
	{"ipv6", "2001:db8::1", "2001:db8::2"},
	{"iface", "ge-5/0/7", "ge-6/0/7"},
	{"dscp", "ef", "af11"},
	{"proto", "bgp", "ospf"},
}

type gateLeaf struct {
	path  []string
	leaf  string
	multi bool
}

// site renders the full dotted path; siteKey renders it with synthetic names
// normalised to <*> so allowlist rows survive schema growth.
func (g gateLeaf) site() string {
	return strings.Join(append(append([]string{}, g.path...), g.leaf), " ")
}

func (g gateLeaf) siteKey() string {
	toks := append(append([]string{}, g.path...), g.leaf)
	for i, t := range toks {
		if isSyntheticName(t) {
			toks[i] = "<*>"
		}
	}
	return strings.Join(toks, " ")
}

// Synthetic names are prefixed so braceConfig can tell an `args` token (same
// brace level) from a wildcard name (new brace level) — trap (1).
const (
	gateArgPrefix  = "xa"
	gateWildPrefix = "xw"
)

func isSyntheticName(t string) bool {
	return strings.HasPrefix(t, gateArgPrefix) || strings.HasPrefix(t, gateWildPrefix)
}

// sortedChildKeys makes traversal DETERMINISTIC. setSchema's children are Go
// maps; iterating them directly makes both the enumeration order and — where a
// schemaNode is reachable by more than one path — WHICH path wins the dedup
// vary run to run. A gate that reds at random is disabled within a week and
// takes the real signal with it.
func sortedChildKeys(n *schemaNode) []string {
	keys := make([]string, 0, len(n.children))
	for k := range n.children {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func enumerateGateLeaves() []gateLeaf {
	var out []gateLeaf
	seen := map[string]bool{}
	argName := func(d int) string { return fmt.Sprintf("%s%d", gateArgPrefix, d) }
	wildName := func(d int) string { return fmt.Sprintf("%s%d", gateWildPrefix, d) }

	var walk func(n *schemaNode, path []string, depth int)
	walk = func(n *schemaNode, path []string, depth int) {
		if depth > 9 {
			return
		}
		for _, key := range sortedChildKeys(n) {
			ch := n.children[key]
			if ch == nil {
				continue
			}
			if ch.children == nil && ch.wildcard == nil {
				// A compound leaf (args > 1, or a fixed mid-keyword) is not a
				// value list; a two-element list is not meaningful for it.
				if ch.midKeyword != "" || ch.args > 1 {
					continue
				}
				g := gateLeaf{path: append([]string{}, path...), leaf: key, multi: ch.multi}
				if _, skip := notAValueList[g.siteKey()]; skip {
					continue
				}
				if seen[g.siteKey()] {
					continue
				}
				seen[g.siteKey()] = true
				out = append(out, g)
				continue
			}
			head := []string{key}
			for i := 0; i < ch.args; i++ {
				head = append(head, argName(depth*10+i))
			}
			walk(ch, append(append([]string{}, path...), head...), depth+1)
		}
		if n.wildcard != nil {
			walk(n.wildcard, append(append([]string{}, path...), wildName(depth*10+9)), depth+1)
		}
	}
	// `groups` is excluded: apply-groups leaf-list UNION (#4070) is a different,
	// documented contract, and inheritance deliberately makes spellings differ.
	for _, key := range sortedChildKeys(setSchema) {
		ch := setSchema.children[key]
		if ch == nil || key == "groups" {
			continue
		}
		if ch.children == nil && ch.wildcard == nil {
			if ch.midKeyword == "" && ch.args <= 1 {
				g := gateLeaf{leaf: key, multi: ch.multi}
				if _, skip := notAValueList[g.siteKey()]; !skip && !seen[g.siteKey()] {
					seen[g.siteKey()] = true
					out = append(out, g)
				}
			}
			continue
		}
		head := []string{key}
		for i := 0; i < ch.args; i++ {
			head = append(head, argName(i))
		}
		walk(ch, head, 1)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].site() < out[j].site() })
	return out
}

// gateBraceConfig wraps a leaf statement in the brace nesting its path implies.
// See trap (1): `args` names merge into the preceding head, wildcard names do not.
func gateBraceConfig(path []string, stmt string) string {
	var heads []string
	for _, tok := range path {
		if strings.HasPrefix(tok, gateArgPrefix) && len(heads) > 0 {
			heads[len(heads)-1] += " " + tok
			continue
		}
		heads = append(heads, tok)
	}
	var b strings.Builder
	for _, h := range heads {
		b.WriteString(h)
		b.WriteString(" { ")
	}
	b.WriteString(stmt)
	for range heads {
		b.WriteString(" }")
	}
	return b.String()
}

func gateCompileBrace(body string) (string, error) {
	p := NewParser(body)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		return "", fmt.Errorf("parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		return "", err
	}
	j, err := json.Marshal(cfg)
	return string(j), err
}

func gateCompileSet(cmds []string) (string, error) {
	tree := &ConfigTree{}
	for _, c := range cmds {
		path, err := ParseSetCommand(c)
		if err != nil {
			return "", err
		}
		if err := tree.SetPath(path); err != nil {
			return "", err
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		return "", err
	}
	j, err := json.Marshal(cfg)
	return string(j), err
}

var gateSpellingsMulti = []string{"A-hier-bracket", "B-hier-block", "C-hier-repeat", "D-set-bracket", "E-set-repeat"}

// gateSpellingsScalar omits the REPEATED spellings. For a leaf the schema marks
// multi: false, a repeated statement legitimately REPLACES (last write wins), so
// comparing C and E against the bracket forms would manufacture a finding at
// every scalar leaf in the schema.
var gateSpellingsScalar = []string{"A-hier-bracket", "B-hier-block", "D-set-bracket"}

// spellingVerdicts returns, per spelling, one of:
//
//	"keep"     the second value changed the compiled config
//	"drop"     it did not — the compiler discarded it
//	"inert"    the FIRST value did not change the config either, so this leaf
//	           never reached the compiler under a synthetic parent path and
//	           carries no verdict (trap (3))
//	"unstable" compiling identical input twice produced different output, so no
//	           comparison here is trustworthy — excluded rather than risked
//	"err"      a spelling failed to parse or compile
func spellingVerdicts(g gateLeaf, v1, v2 string) map[string]string {
	flat := "set " + strings.Join(append(append([]string{}, g.path...), g.leaf), " ")
	forms := map[string][3]func() (string, error){
		"A-hier-bracket": {
			func() (string, error) { return gateCompileBrace(gateBraceConfig(g.path, g.leaf+";")) },
			func() (string, error) {
				return gateCompileBrace(gateBraceConfig(g.path, fmt.Sprintf("%s [ %s ];", g.leaf, v1)))
			},
			func() (string, error) {
				return gateCompileBrace(gateBraceConfig(g.path, fmt.Sprintf("%s [ %s %s ];", g.leaf, v1, v2)))
			},
		},
		"B-hier-block": {
			func() (string, error) { return gateCompileBrace(gateBraceConfig(g.path, g.leaf+" { }")) },
			func() (string, error) {
				return gateCompileBrace(gateBraceConfig(g.path, fmt.Sprintf("%s { %s; }", g.leaf, v1)))
			},
			func() (string, error) {
				return gateCompileBrace(gateBraceConfig(g.path, fmt.Sprintf("%s { %s; %s; }", g.leaf, v1, v2)))
			},
		},
		"C-hier-repeat": {
			func() (string, error) { return gateCompileBrace(gateBraceConfig(g.path, g.leaf+";")) },
			func() (string, error) {
				return gateCompileBrace(gateBraceConfig(g.path, fmt.Sprintf("%s %s;", g.leaf, v1)))
			},
			func() (string, error) {
				return gateCompileBrace(gateBraceConfig(g.path, fmt.Sprintf("%s %s; %s %s;", g.leaf, v1, g.leaf, v2)))
			},
		},
		"D-set-bracket": {
			func() (string, error) { return gateCompileSet([]string{flat}) },
			func() (string, error) { return gateCompileSet([]string{fmt.Sprintf("%s [ %s ]", flat, v1)}) },
			func() (string, error) { return gateCompileSet([]string{fmt.Sprintf("%s [ %s %s ]", flat, v1, v2)}) },
		},
		"E-set-repeat": {
			func() (string, error) { return gateCompileSet([]string{flat}) },
			func() (string, error) { return gateCompileSet([]string{flat + " " + v1}) },
			func() (string, error) { return gateCompileSet([]string{flat + " " + v1, flat + " " + v2}) },
		},
	}
	state := map[string]string{}
	for _, name := range gateSpellingsMulti {
		f := forms[name]
		zero, e0 := f[0]()
		one, e1 := f[1]()
		two, e2 := f[2]()
		if e0 != nil || e1 != nil || e2 != nil {
			state[name] = "err"
			continue
		}
		// Determinism self-check: a compiler that builds a slice by ranging a
		// Go map can emit a different order for identical input, which would
		// make one == two compare unequal at random. Recompile and require
		// self-equality rather than trusting it.
		if again, err := f[1](); err != nil || again != one {
			state[name] = "unstable"
			continue
		}
		if zero == one {
			state[name] = "inert" // trap (3): the leaf never reached the compiler
			continue
		}
		if one == two {
			state[name] = "drop"
		} else {
			state[name] = "keep"
		}
	}
	return state
}

// TestSchemaSpellingDifferentialGate is the gate itself.
func TestSchemaSpellingDifferentialGate(t *testing.T) {
	leaves := enumerateGateLeaves()

	type hit struct {
		site, key, class, pair string
		state                  map[string]string
		multi                  bool
	}
	var hits []hit
	firedKeys := map[string]bool{}
	compared := 0

	for _, g := range leaves {
		leafCompared := false
		for _, vp := range gateValuePairs {
			state := spellingVerdicts(g, vp.v1, vp.v2)
			cmpSet := gateSpellingsScalar
			if g.multi {
				cmpSet = gateSpellingsMulti
			}
			var flags []bool
			for _, name := range cmpSet {
				switch state[name] {
				case "err", "inert", "unstable":
					continue
				}
				flags = append(flags, state[name] == "drop")
			}
			if len(flags) < 2 {
				continue
			}
			leafCompared = true
			differs, allDrop := false, true
			for _, f := range flags {
				if f != flags[0] {
					differs = true
				}
				if !f {
					allDrop = false
				}
			}
			class := ""
			switch {
			case differs:
				class = "shape-dependent drop"
			case allDrop && g.multi:
				// The schema declares a value list and the compiler installs one
				// value in EVERY spelling: the two SSOTs disagree outright. No
				// differential can see this, which is why it is its own class.
				class = "uniform drop on a multi:true leaf"
			}
			if class != "" && !firedKeys[g.siteKey()] {
				firedKeys[g.siteKey()] = true
				hits = append(hits, hit{
					site: g.site(), key: g.siteKey(), class: class,
					pair: vp.name, state: state, multi: g.multi,
				})
			}
		}
		if leafCompared {
			compared++
		}
	}

	t.Logf("COVERAGE: %d value-bearing leaves enumerated, %d actually compared "+
		"(%d carry NO verdict — inert/unstable under synthetic parent paths). "+
		"A green run is NOT a swept schema.",
		len(leaves), compared, len(leaves)-compared)

	sort.Slice(hits, func(i, j int) bool { return hits[i].site < hits[j].site })

	// 1. Unexpected inconsistencies fail the build.
	for _, h := range hits {
		if _, known := knownSpellingInconsistencies[h.key]; known {
			continue
		}
		var parts []string
		for _, n := range gateSpellingsMulti {
			parts = append(parts, n[:1]+"="+h.state[n])
		}
		t.Errorf("#2419 class: %s\n"+
			"  site      : %s\n"+
			"  siteKey   : %q\n"+
			"  multi     : %v   (value pair: %s)\n"+
			"  spellings : %s\n"+
			"  A two-element list authored in one spelling compiles differently\n"+
			"  from the same list in another. Either fix the compiler's read, or —\n"+
			"  if this leaf is not a value list at all — add it to notAValueList\n"+
			"  with the reason, having VERIFIED where the extra tokens land.",
			h.class, h.site, h.key, h.multi, h.pair, strings.Join(parts, " "))
	}

	// 2. A stale allowlist row also fails the build: the row must be removed by
	//    whoever fixes the defect, together with closing the issue that owns it.
	//    Deleting a row to get green is thereby not a silent option.
	var stale []string
	for key, issue := range knownSpellingInconsistencies {
		if !firedKeys[key] {
			stale = append(stale, fmt.Sprintf("%q (owned by %s)", key, issue))
		}
	}
	sort.Strings(stale)
	for _, s := range stale {
		t.Errorf("STALE allowlist row: %s no longer disagrees across spellings.\n"+
			"  The defect appears to be fixed. Remove the row from\n"+
			"  knownSpellingInconsistencies AND close the issue that owns it.\n"+
			"  (If the site merely stopped being COMPARED — see the coverage line —\n"+
			"  say so explicitly rather than dropping the row.)", s)
	}
}

// TestSchemaSpellingGateIsDeterministic runs the enumeration repeatedly and
// requires an identical leaf list each time. setSchema is built from Go maps,
// so without sortedChildKeys both the ordering and the dedup winner vary per
// run — the failure mode that gets a gate disabled.
func TestSchemaSpellingGateIsDeterministic(t *testing.T) {
	first := enumerateGateLeaves()
	var firstKeys []string
	for _, g := range first {
		firstKeys = append(firstKeys, g.siteKey())
	}
	for i := 0; i < 8; i++ {
		got := enumerateGateLeaves()
		if len(got) != len(first) {
			t.Fatalf("run %d enumerated %d leaves, first run %d", i, len(got), len(first))
		}
		for j, g := range got {
			if g.siteKey() != firstKeys[j] {
				t.Fatalf("run %d differs at index %d: %q vs %q", i, j, g.siteKey(), firstKeys[j])
			}
		}
	}
}

// TestSchemaSpellingCoverage re-derives the coverage numbers quoted in this
// file's header on every run, so they cannot rot into a stale comment.
func TestSchemaSpellingCoverage(t *testing.T) {
	var valueBearing, compound int
	visited := map[*schemaNode]bool{}
	var walk func(n *schemaNode, d int)
	walk = func(n *schemaNode, d int) {
		if n == nil || d > 12 || visited[n] {
			return
		}
		visited[n] = true
		for _, key := range sortedChildKeys(n) {
			ch := n.children[key]
			if ch == nil {
				continue
			}
			if ch.children == nil && ch.wildcard == nil {
				if ch.midKeyword != "" || ch.args > 1 {
					compound++
				} else {
					valueBearing++
				}
				continue
			}
			walk(ch, d+1)
		}
		walk(n.wildcard, d+1)
	}
	walk(setSchema, 0)
	t.Logf("setSchema: %d value-bearing leaves, %d compound leaves excluded by construction",
		valueBearing, compound)
	t.Logf("allowlisted known-inconsistent sites: %d; non-value-list exclusions: %d",
		len(knownSpellingInconsistencies), len(notAValueList))
	if valueBearing < 500 {
		t.Errorf("only %d value-bearing leaves found — the enumerator is probably "+
			"walking a truncated schema, which would make the gate silently vacuous",
			valueBearing)
	}
}
