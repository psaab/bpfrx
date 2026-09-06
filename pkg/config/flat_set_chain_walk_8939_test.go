package config

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// #8939: a flat `set` command naming TWO leaves under one container builds a
// NESTED CHAIN, not siblings:
//
//	set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1 destination 10.0.0.2
//	  ... [tunnel] -> [source 10.0.0.1] -> [destination 10.0.0.2]
//
// The issue filed this as a GRAMMAR defect and proposed rejecting such a
// command at parse time. THAT REMEDY IS WRONG, and this file is the
// measurement that says so.
//
// The chain is built identically for every container. What differs is whether
// the CONTAINER'S COMPILER walks below the first leaf. Measured on the same
// grammar shape, one command each:
//
//	applications application myapp protocol tcp destination-port 8080
//	   packed  proto="tcp" dport="8080"      <- compiler walks (#6524)
//	   split   proto="tcp" dport="8080"
//
//	interfaces gr-0/0/0 unit 0 tunnel source A destination B
//	   packed  src="10.0.0.1" dst=""         <- compiler does NOT walk
//	   split   src="10.0.0.1" dst="10.0.0.2"
//
// So rejecting at parse time would reject a spelling that a large minority of
// containers handle CORRECTLY today — `applications` among them, which has a
// whole test file (compiler_application_chained_leaves_6524_test.go) devoted
// to the chained form working.
//
// THE RATCHET. This file compiles a packed pair and its split equivalent for
// every container declaring two value-taking sibling leaves, and records which
// containers LOSE the second leaf. A container may move from LOSE to WALK
// (that is the fix, and the fixture must be updated); it may never move from
// WALK to LOSE without this test failing, because that is a silent
// configuration-loss regression on an accepted spelling.
//
// WHAT THIS INSTRUMENT DOES NOT SEE, stated because the count will be quoted:
//   - one pair per container (the two alphabetically-first eligible leaves),
//     so a container recorded as WALK may still lose a DIFFERENT pair;
//   - containers whose synthetic values do not compile are skipped, not
//     cleared -- they are unmeasured;
//   - depth is capped, and `groups` is not traversed.
//
// The recorded count is therefore a LOWER BOUND on affected containers and is
// not comparable to the issue title's figure, which was produced by a
// different (schema-shape) instrument. Two instruments disagreeing is a fact
// about the instruments until someone reconciles them.

const flatSetChainFixture = "testdata/flat_set_chain_losers_8939.txt"

func flatSetSyntheticValue(name string) string {
	switch {
	case strings.Contains(name, "address"), strings.Contains(name, "source"),
		strings.Contains(name, "destination"), strings.Contains(name, "gateway"),
		strings.Contains(name, "neighbor"), strings.Contains(name, "next-hop"):
		return "10.0.0.1"
	case strings.Contains(name, "port"):
		return "8080"
	case strings.Contains(name, "interface"):
		return "ge-0/0/0"
	case strings.Contains(name, "time"), strings.Contains(name, "limit"),
		strings.Contains(name, "size"), strings.Contains(name, "count"),
		strings.Contains(name, "priority"), strings.Contains(name, "weight"),
		strings.Contains(name, "metric"), strings.Contains(name, "mtu"),
		strings.Contains(name, "ttl"), strings.Contains(name, "timeout"):
		return "10"
	default:
		return "xpfval"
	}
}

// flatSetChainPairs enumerates (container, leafA, leafB) triples: two leaves
// under one container that take a value and declare no children of their own.
func flatSetChainPairs() [][]string {
	var out [][]string
	seen := map[string]bool{}
	var walk func(path []string, n *schemaNode, depth int)
	walk = func(path []string, n *schemaNode, depth int) {
		if depth > 6 || n == nil || n.children == nil {
			return
		}
		var leaves []string
		for k, c := range n.children {
			if c != nil && c.children == nil && c.wildcard == nil && !c.multi {
				leaves = append(leaves, k)
			}
		}
		sort.Strings(leaves)
		if len(leaves) >= 2 {
			if key := strings.Join(path, " "); !seen[key] {
				seen[key] = true
				out = append(out, append(append([]string{}, path...), leaves[0], leaves[1]))
			}
		}
		var keys []string
		for k := range n.children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			c := n.children[k]
			if c == nil || c.children == nil {
				continue
			}
			np := append(append([]string{}, path...), k)
			for i := 0; i < c.args; i++ {
				np = append(np, "arg1")
			}
			walk(np, c, depth+1)
			if c.wildcard != nil {
				walk(append(append([]string{}, np...), "wname"), c.wildcard, depth+1)
			}
		}
	}
	walk(nil, setSchema, 0)
	return out
}

func flatSetCompile(lines []string) (*Config, error) {
	tr := &ConfigTree{}
	for _, l := range lines {
		toks, err := ParseSetCommand(l)
		if err != nil {
			return nil, err
		}
		if err := tr.SetPath(toks); err != nil {
			return nil, err
		}
	}
	return CompileConfig(tr)
}

// TestFlatSetChainWalkRatchet8939 is the ratchet. It also carries the two
// controls that make its numbers mean anything.
func TestFlatSetChainWalkRatchet8939(t *testing.T) {
	// ---- CONTROL 1 (the claim the issue's remedy would break) -------------
	// `applications` MUST compile the packed chain identically to the split
	// form. If this ever fails, the "reject at parse time" remedy stops being
	// wrong for the reason stated above and this file's argument needs
	// re-deriving rather than re-running.
	appPacked, err := flatSetCompile([]string{
		"set applications application myapp protocol tcp destination-port 8080",
	})
	if err != nil {
		t.Fatalf("control: packed applications did not compile: %v", err)
	}
	appSplit, err := flatSetCompile([]string{
		"set applications application myapp protocol tcp",
		"set applications application myapp destination-port 8080",
	})
	if err != nil {
		t.Fatalf("control: split applications did not compile: %v", err)
	}
	if !reflect.DeepEqual(appPacked, appSplit) {
		t.Errorf("CONTROL FAILED: `applications` no longer walks the packed chain.\n" +
			"This file argues that #8939's parse-time rejection is wrong BECAUSE some\n" +
			"compilers walk the chain correctly, and `applications` is the witness.\n" +
			"If the witness is gone, re-derive the argument -- do not just update it.")
	}
	if got := appPacked.Applications.Applications["myapp"]; got == nil || got.DestinationPort != "8080" {
		t.Errorf("CONTROL is VACUOUS: packed applications did not set destination-port; "+
			"got %+v. Two equal-but-empty compiles prove nothing.", got)
	}

	// ---- CONTROL 2 (the witness on the other side) ------------------------
	tunPacked, err := flatSetCompile([]string{
		"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1 destination 10.0.0.2",
	})
	if err != nil {
		t.Fatalf("control: packed tunnel did not compile: %v", err)
	}
	if u := flatSetFirstUnitTunnel(tunPacked, "gr-0/0/0"); u == nil || u.Source != "10.0.0.1" || u.Destination != "" {
		t.Logf("NOTE: the #8939 tunnel witness changed shape (%+v). If `destination` is now "+
			"populated, that row was FIXED -- drop it from the fixture and say so.", u)
	}

	// ---- the census -------------------------------------------------------
	empty, _ := flatSetCompile(nil)
	var losers []string
	var walked, vacuous, unmeasured int
	for _, p := range flatSetChainPairs() {
		cont, a, b := p[:len(p)-2], p[len(p)-2], p[len(p)-1]
		base := "set " + strings.Join(cont, " ")
		av, bv := flatSetSyntheticValue(a), flatSetSyntheticValue(b)
		packed, ep := flatSetCompile([]string{
			fmt.Sprintf("%s %s %s %s %s", base, a, av, b, bv)})
		split, es := flatSetCompile([]string{
			fmt.Sprintf("%s %s %s", base, a, av),
			fmt.Sprintf("%s %s %s", base, b, bv)})
		if ep != nil || es != nil || packed == nil || split == nil {
			unmeasured++
			continue
		}
		if reflect.DeepEqual(packed, split) {
			// vacuity control: both empty proves nothing about walking.
			if empty != nil && reflect.DeepEqual(packed, empty) {
				vacuous++
				continue
			}
			walked++
			continue
		}
		losers = append(losers, strings.Join(cont, " ")+"  ["+a+" | "+b+"]")
	}
	sort.Strings(losers)

	got := strings.Join(losers, "\n") + "\n"
	if os.Getenv("UPDATE_8939") != "" {
		if err := os.WriteFile(flatSetChainFixture, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s (%d losers, %d walked, %d vacuous, %d unmeasured)",
			flatSetChainFixture, len(losers), walked, vacuous, unmeasured)
		return
	}
	wantB, err := os.ReadFile(flatSetChainFixture)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with UPDATE_8939=1)", flatSetChainFixture, err)
	}
	if string(wantB) != got {
		t.Errorf("the #8939 flat-set chain-loss set MOVED.\n"+
			"measured %d losers, %d walked, %d vacuous, %d unmeasured.\n\n"+
			"A container leaving this list is a FIX -- regenerate with UPDATE_8939=1\n"+
			"and name the fix in the commit. A container ENTERING it is a silent\n"+
			"configuration-loss regression: an accepted `set` command now drops its\n"+
			"second leaf with no error, and `show configuration` still renders what\n"+
			"the operator typed.\n\ndiff:\n%s",
			len(losers), walked, vacuous, unmeasured, flatSetDiff(string(wantB), got))
	}
	if walked < 20 {
		t.Errorf("only %d containers WALK the chain. This file's argument against "+
			"#8939's parse-time rejection rests on that population being large; at "+
			"this size the argument needs re-deriving.", walked)
	}
}

func flatSetFirstUnitTunnel(c *Config, iface string) *TunnelConfig {
	i := c.Interfaces.Interfaces[iface]
	if i == nil {
		return nil
	}
	for _, u := range i.Units {
		if u.Tunnel != nil {
			return u.Tunnel
		}
	}
	return i.Tunnel
}

func flatSetDiff(want, got string) string {
	w := map[string]bool{}
	for _, l := range strings.Split(want, "\n") {
		if l != "" {
			w[l] = true
		}
	}
	g := map[string]bool{}
	for _, l := range strings.Split(got, "\n") {
		if l != "" {
			g[l] = true
		}
	}
	var b strings.Builder
	for l := range g {
		if !w[l] {
			fmt.Fprintf(&b, "  + NEWLY LOSING (regression): %s\n", l)
		}
	}
	for l := range w {
		if !g[l] {
			fmt.Fprintf(&b, "  - no longer losing (fixed):  %s\n", l)
		}
	}
	return b.String()
}
