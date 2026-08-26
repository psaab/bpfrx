package config

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// ---- value synthesis ------------------------------------------------------

// synthPair returns two DISTINCT plausible values for a valued leaf. Two are
// needed for the vacuity guard: if the compiled config is identical for both,
// this leaf's value is not observable in the typed config and the cell cannot
// prove anything.
func synthPair(n *schemaNode) (string, string, bool) {
	if len(n.valueExamples) >= 2 {
		return n.valueExamples[0], n.valueExamples[1], true
	}
	switch n.valueType {
	case ValueInteger:
		return "1", "2", true
	case ValueIPAddress:
		return "192.0.2.1", "192.0.2.2", true
	case ValueCIDR:
		return "192.0.2.0/24", "198.51.100.0/24", true
	case ValueBool:
		return "true", "false", true
	case ValueIdentifier, ValueAny:
		return "xpfaaa", "xpfbbb", true
	case ValueCryptHash:
		return `"$6$salt$aaa"`, `"$6$salt$bbb"`, true
	case ValueMAC:
		return "02:00:00:00:00:01", "02:00:00:00:00:02", true
	case ValuePCIAddr:
		return "0000:09:00.0", "0000:0a:00.0", true
	}
	if len(n.valueExamples) == 1 {
		return "", "", false // one example, cannot vary
	}
	return "", "", false
}

// ---- required-sibling context ---------------------------------------------

// contextFor returns statements that must accompany the stanza under test for
// its enclosing object to be REGISTERED in the typed config at all.
//
// Without them the vacuity guard correctly reports "value not observable" and
// the site is skipped — but for the wrong reason: the leaf IS observable, the
// synthesized fixture was just incomplete. `security log stream <n>` is the
// worked example: compiler_security_log.go records the stream only when
// `stream.Host != ""`, so a transport-only fixture compiles to no stream at
// all and BOTH spellings agree on nothing.
//
// This is the generative walk's structural limit: it cannot infer which
// siblings an object requires. Entries are added here as the skip list is
// worked through, and the remaining skip count is REPORTED so the census stays
// an explicit floor rather than a silent one.
func contextFor(parent []string) string {
	switch strings.Join(parent, " ") {
	case "security log stream xpfarg":
		return "host 192.0.2.10; "
	}
	return ""
}

// ---- text construction ----------------------------------------------------

// nest renders `a { b { c { <inner> } } }` for path [a b c].
func nest(path []string, inner string) string {
	if len(path) == 0 {
		return inner
	}
	return path[0] + " { " + nest(path[1:], inner) + " }"
}

func compileText(t *testing.T, text string) *Config {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		return nil
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		return nil
	}
	cfg.Warnings = nil
	return cfg
}

func cfgEqual(a, b *Config) bool {
	if a == nil || b == nil {
		return a == b
	}
	return reflect.DeepEqual(a, b)
}

// ---- the walk -------------------------------------------------------------

type compactSite struct {
	container []string // token path of the enclosing container
	leaf      string
	node      *schemaNode
}

// A site is compactable ONLY when the innermost container is a PLAIN KEYWORD
// stanza — args == 0 and not reached through a wildcard. A NAMED INSTANCE
// (`interfaces ge-0/0/0`, `user ops`, `stream audit`) carries its name in the
// node's own Keys, so collapsing the next level onto it does not produce the
// compact spelling of the same intent; it produces a node the compiler cannot
// recognise as that named instance at all. All four filed instances compact a
// plain stanza (`authentication`, `transport`, `authentication-sha256`).

func collectCompactSites() []compactSite {
	var out []compactSite
	seen := map[string]bool{}
	var walk func(n *schemaNode, path []string, depth int, plainInner bool)
	walk = func(n *schemaNode, path []string, depth int, plainInner bool) {
		if n == nil || depth > 7 {
			return
		}
		names := make([]string, 0, len(n.children))
		for name := range n.children {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			ch := n.children[name]
			if ch == nil {
				continue
			}
			if ch.children == nil && ch.wildcard == nil && ch.args == 1 && len(path) >= 1 && plainInner {
				key := strings.Join(path, "/") + "|" + name
				if !seen[key] {
					seen[key] = true
					out = append(out, compactSite{
						container: append([]string(nil), path...), leaf: name, node: ch,
					})
				}
			}
			elem := name
			for i := 0; i < ch.args; i++ {
				elem += " xpfarg"
			}
			np := append(append([]string(nil), path...), elem)
			walk(ch, np, depth+1, ch.args == 0)
		}
		if n.wildcard != nil {
			walk(n.wildcard, append(append([]string(nil), path...), "xpfname"), depth+1, false)
		}
	}
	walk(setSchema, nil, 0, false)
	return out
}

// ---- the gate --------------------------------------------------------------

// inventoryPath records the sites that are KNOWN to drop the compact spelling
// today. It is a checked-in expected-failure list, not a suppression: the gate
// asserts the divergent set EQUALS it, so a NEW compact-blind reader reds the
// suite, and a site that gets FIXED without updating the file reds it too.
const inventoryPath = "testdata/compact_block_divergences_2419.txt"

// filedInstances is the POSITIVE CONTROL. The first version of this instrument
// found only 2 of these 4 — args rendered as their own nesting level hid one,
// and a fixture missing a required sibling hid the other. An instrument that
// silently stops finding known-true sites reports "clean" for the same reason
// the textual sweeps did, so the four are asserted present by construction.
var filedInstances = map[string]string{
	"system login user xpfarg authentication encrypted-password":                         "#6817",
	"protocols ospf area xpfarg interface xpfarg authentication simple-password":         "#6818",
	"security log stream xpfarg transport tls-profile":                                   "#6821",
	"snmp v3 usm local-engine user xpfarg authentication-sha256 authentication-password": "#6822",
}

type censusResult struct {
	divergent []string
	checked   int
	skipped   map[string]int
}

func runCompactBlockCensus(t *testing.T) censusResult {
	t.Helper()
	res := censusResult{skipped: map[string]int{}}
	for _, s := range collectCompactSites() {
		if len(s.container) > 0 && strings.HasPrefix(s.container[0], "groups") {
			res.skipped["under groups (schema re-host, duplicate coverage)"]++
			continue
		}
		v1, v2, ok := synthPair(s.node)
		if !ok {
			res.skipped["no two distinct synthesizable values"]++
			continue
		}
		parent := s.container[:len(s.container)-1]
		stanza := s.container[len(s.container)-1]
		ctx := contextFor(parent)
		blockV1 := nest(parent, ctx+stanza+" { "+s.leaf+" "+v1+"; }")
		blockV2 := nest(parent, ctx+stanza+" { "+s.leaf+" "+v2+"; }")
		compact := nest(parent, ctx+stanza+" "+s.leaf+" "+v1+";")

		cb1, cb2, cc := compileText(t, blockV1), compileText(t, blockV2), compileText(t, compact)
		if cb1 == nil || cb2 == nil || cc == nil {
			res.skipped["a spelling did not parse or compile"]++
			continue
		}
		// VACUITY GUARD. If changing the VALUE does not change the compiled
		// config, this cell cannot observe a dropped value and calling it a
		// pass would be meaningless. #6821 sat in this bucket until its
		// required-sibling context line was added — every entry here is an
		// UNRULED candidate, not a clean site.
		if cfgEqual(cb1, cb2) {
			res.skipped["leaf value not observable in the typed config"]++
			continue
		}
		res.checked++
		if !cfgEqual(cb1, cc) {
			res.divergent = append(res.divergent, strings.Join(s.container, " ")+" "+s.leaf)
		}
	}
	sort.Strings(res.divergent)
	return res
}

func readInventory(t *testing.T) (sites []string, wantChecked int) {
	t.Helper()
	raw, err := os.ReadFile(inventoryPath)
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if _, err := fmt.Sscanf(line, "# checked: %d", &wantChecked); err == nil {
				continue
			}
			continue
		}
		sites = append(sites, line)
	}
	sort.Strings(sites)
	return sites, wantChecked
}

// TestCompactBlockEquivalenceInventory2419 is the #2419 class gate.
//
// The property: for every config leaf under a PLAIN KEYWORD stanza, the compact
// spelling (`stanza leaf value;` — value on the stanza's own Keys) and the block
// spelling (`stanza { leaf value; }`) must compile to the same typed config. A
// compiler stanza that iterates only prop.Children reads one and silently drops
// the other.
//
// Today 194 sites fail that property. They are recorded in the inventory file
// rather than suppressed, so this gate does three things at once:
//
//   - a NEW compact-blind reader is an unexpected divergence -> RED;
//   - a site FIXED without updating the inventory -> RED, so the file cannot
//     rot into a stale allowlist;
//   - the CHECKED count is a ratchet, so sites cannot silently drain out of the
//     tested population into the skip buckets (which is how an instrument stops
//     measuring while still reporting success).
func TestCompactBlockEquivalenceInventory2419(t *testing.T) {
	res := runCompactBlockCensus(t)
	want, wantChecked := readInventory(t)

	inWant := map[string]bool{}
	for _, s := range want {
		inWant[s] = true
	}
	inGot := map[string]bool{}
	for _, s := range res.divergent {
		inGot[s] = true
	}
	for _, s := range res.divergent {
		if !inWant[s] {
			t.Errorf("#2419: NEW compact-blind site (compact spelling drops the value): %s\n"+
				"    A compiler stanza was added or changed to read only prop.Children.\n"+
				"    Fix the reader, or add the site to %s with a reason.", s, inventoryPath)
		}
	}
	for _, s := range want {
		if !inGot[s] {
			t.Errorf("#2419: %s lists %q as compact-blind, but it now compiles equivalently.\n"+
				"    If you fixed it, REMOVE the line — a stale inventory is an allowlist "+
				"that hides the next regression.", inventoryPath, s)
		}
	}
	// Coverage ratchet.
	if res.checked < wantChecked {
		t.Errorf("#2419: checked-cell coverage DROPPED from %d to %d. Sites moved out of the "+
			"tested population into the skip buckets; the census stops measuring them.",
			wantChecked, res.checked)
	}
	// Positive control.
	for site, issue := range filedInstances {
		if !inGot[site] {
			t.Errorf("#2419 POSITIVE CONTROL: the instrument no longer finds %s (%s). "+
				"An instrument that stops finding known-true sites reports clean for the "+
				"same reason a textual sweep does.", site, issue)
		}
	}
}

// TestCompactBlockCensusReport2419 prints the census. It asserts nothing the
// gate above does not; it exists so the numbers — including the UNRULED skips —
// are visible in `go test -v` output rather than only in a PR body.
func TestCompactBlockCensusReport2419(t *testing.T) {
	res := runCompactBlockCensus(t)
	t.Logf("#2419 compact/block equivalence census")
	t.Logf("  cells CHECKED (vacuity-guarded): %d", res.checked)
	t.Logf("  cells DIVERGENT:                 %d", len(res.divergent))
	keys := make([]string, 0, len(res.skipped))
	for k := range res.skipped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("  cells SKIPPED — %-52s %d", k, res.skipped[k])
	}
	t.Logf("  NOTE: the %d 'not observable' skips are UNRULED, not clean — each is a site "+
		"whose synthesized fixture was too thin to observe the value (as #6821 was before "+
		"its required-sibling context line). The census is a FLOOR.",
		res.skipped["leaf value not observable in the typed config"])
}
