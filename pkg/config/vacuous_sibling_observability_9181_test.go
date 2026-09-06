package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// #9181: `vacuous` is not a neutral bucket. A row lands there when the packed
// and split spellings compile identically -- which happens both when there is
// genuinely nothing to measure AND when the fixture cannot make the values
// observable at all. `protocols bgp group` is the known instance: group
// settings fold into BGPNeighbor at compile time, so with no neighbor declared
// a real loss and an empty container read the same.
//
// THIS ENUMERATES THE REST rather than inferring the count from the mechanism.
// For every vacuous row reached by the last-leaf control, it declares the
// container's child and re-compares. MEASURED at master c0e7b1221, whose
// census reads `losers=36 walked=68 vacuous=44 unmeasured=76` over a
// population of `369 containers walked, 135 reached`:
//
//	42  vacuous rows via the last-leaf control (the other 2 are both-empty)
//	21  of those have a child container to declare at all
//	 2  show a loss once the child is declared -- BOTH are `protocols bgp group`
//
// So the shape is REAL and RARE: it is not one row, and it is not widespread.
//
// THE INSTRUMENT REPORTED 0 UNTIL TWO THINGS WERE FIXED, and both are
// MUTATION-VERIFIED as load-bearing (reverting either reds the positive
// control below):
//
//  1. the child's prerequisite leaf must be on ONE line with the instance.
//     `neighbor <ip>` followed by `neighbor <ip> peer-as N` does NOT merge
//     here -- the compiler still reports the neighbor as missing peer-as, so
//     the fixture never compiles;
//  2. the leaves must be tried SMALLEST-ADDITION-FIRST. Adding all of the
//     child's leaves at once lets one invalid leaf sink the child, and the
//     error then names a DIFFERENT missing prerequisite. That is the method
//     contextForStanza documents.
//
// Both failures produced a fixture that did not compile, which this loop
// skipped, which reads as "no loss" -- #9181's own defect inside the
// instrument built to measure it. Hence the positive control: the BGP row is
// a MEASURED instance (lane-8388 fixed its compiler and the census moved zero
// rows), so an enumeration that cannot find it is reporting a property of
// itself rather than of the tree.
//
// A THIRD CHANGE IS KEPT BUT IS **NOT** LOAD-BEARING, and it is recorded as
// such because the honest version of this comment is the mutation result and
// not the debugging history. Reading `placeholder` for an instance value --
// bgp `neighbor` declares args:1 placeholder:"<address>" and no
// valueExamples/valueHint, so synthPair invents `xpfaaa` -- LOOKS necessary
// and is not: reverting it changes no result, because the compiler accepts a
// non-address neighbor name on this path. It stays for robustness on nodes
// where it would matter; it is not why this reports 2.
func TestVacuousRowsObservableOnlyViaSibling9181(t *testing.T) {
	empty, _ := flatSetCompile(nil)

	// A node can declare NEITHER valueExamples nor valueHint and still name its
	// shape in `placeholder` (bgp `neighbor` is args:1, placeholder "<address>").
	// synthPair reads the first two only, so it invents a token the compiler
	// rejects. Reading placeholder is asking the schema a third time.
	synth := func(n *schemaNode) (string, bool) {
		if n == nil {
			return "", false
		}
		p := n.placeholder
		switch {
		case strings.Contains(p, "address") && strings.Contains(p, "6"):
			return "2001:db8::1", true
		case strings.Contains(p, "prefix"):
			return "10.20.30.0/24", true
		case strings.Contains(p, "address"):
			return "10.20.30.40", true
		case strings.Contains(p, "as-number"):
			return "65001", true
		case strings.Contains(p, "interface"):
			return "ge-0/0/0", true
		}
		v, _, ok := synthPair(n)
		return v, ok && v != ""
	}

	resolve := func(path []string) *schemaNode {
		n := setSchema
		for _, seg := range path {
			if n == nil {
				return nil
			}
			if seg == "arg1" {
				continue
			}
			if n.children != nil && n.children[seg] != nil {
				n = n.children[seg]
			} else if n.wildcard != nil {
				n = n.wildcard
			} else {
				return nil
			}
		}
		return n
	}

	// SMALLEST ADDITION FIRST: the child instance alone, then instance + ONE of
	// its own leaves. Appending every leaf at once makes one invalid leaf sink
	// the whole child, and the compiler then reports a DIFFERENT missing
	// prerequisite -- bgp says "missing peer-as" even when peer-as was supplied.
	fixtures := func(base, name string, ch *schemaNode) [][]string {
		src := ch
		if ch.wildcard != nil {
			src = ch.wildcard
		}
		inst := base + " " + name
		if ch.args >= 1 || ch.wildcard != nil {
			v, ok := synth(src)
			if !ok {
				return nil
			}
			inst += " " + v
		}
		out := [][]string{{inst}}
		var kids []string
		for k, c := range src.children {
			if c != nil && c.children == nil && c.wildcard == nil && !c.multi {
				kids = append(kids, k)
			}
		}
		sort.Strings(kids)
		for _, k := range kids {
			c := src.children[k]
			// ONE line, not instance-then-leaf. A bare `neighbor <ip>` line
			// followed by `neighbor <ip> peer-as N` does NOT merge into one
			// neighbor here -- the compiler still reports the neighbor as
			// missing peer-as. The single combined line is what an operator
			// types and what works.
			if c.args == 0 {
				out = append(out, []string{inst + " " + k})
			} else if v, ok := synth(c); ok {
				out = append(out, []string{inst + " " + k + " " + v})
			}
		}
		return out
	}

	var c2, haveChild, shape int
	var rows, unmeasurable, evaluated []string
	for _, p := range flatSetChainPairs() {
		cont, leaves := p.container, p.leaves
		base := "set " + strings.Join(cont, " ")
		packedLine := base
		var splitLines []string
		for _, lf := range leaves {
			packedLine += " " + lf.spell()
			splitLines = append(splitLines, base+" "+lf.spell())
		}
		packed, ep := flatSetCompile([]string{packedLine})
		split, es := flatSetCompile(splitLines)
		if ep != nil || es != nil || packed == nil || split == nil || !reflect.DeepEqual(packed, split) {
			continue
		}
		if empty != nil && reflect.DeepEqual(packed, empty) {
			continue
		}
		prev, e := flatSetCompile(splitLines[:len(splitLines)-1])
		if e != nil || prev == nil || !reflect.DeepEqual(split, prev) {
			continue
		}
		c2++

		n := resolve(cont)
		if n == nil || n.children == nil {
			continue
		}
		var names []string
		for k, c := range n.children {
			if c != nil && (c.children != nil || c.wildcard != nil) {
				names = append(names, k)
			}
		}
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		haveChild++
		evaluated = append(evaluated, strings.Join(cont, " "))

		found, anyCompiled := false, false
		for _, cn := range names {
			for _, extra := range fixtures(base, cn, n.children[cn]) {
				wp, e1 := flatSetCompile(append([]string{packedLine}, extra...))
				ws, e2 := flatSetCompile(append(append([]string{}, splitLines...), extra...))
				if e1 != nil || e2 != nil || wp == nil || ws == nil {
					continue
				}
				anyCompiled = true
				if !reflect.DeepEqual(wp, ws) {
					found = true
					rows = append(rows, fmt.Sprintf("%s [last=%s] via %s",
						strings.Join(cont, " "), leaves[len(leaves)-1].name, cn))
					break
				}
			}
			if found {
				break
			}
		}
		if found {
			shape++
		} else if !anyCompiled {
			unmeasurable = append(unmeasurable, strings.Join(cont, " "))
		}
	}

	// POSITIVE CONTROL, RE-ANCHORED (#9199).
	//
	// It used to require `protocols bgp group` to APPEAR IN rows — i.e. to
	// still exhibit the defect. A control of that shape cannot distinguish
	// "fixed" from "the instrument broke": it passes only while the bug is
	// live, and goes red the moment someone repairs the thing it guards. That
	// is exactly what happened when the `bgp group` compiler fix landed, and
	// both the control and the count failed together, which is the least
	// informative possible pairing.
	//
	// It now asserts the ENUMERATION REACHED the container and evaluated it.
	// That is the property a `0` below depends on, and it stays true after a
	// fix.
	ctl := false
	for _, e := range evaluated {
		if strings.HasPrefix(e, "protocols bgp group") {
			ctl = true
		}
	}
	if !ctl {
		t.Errorf("POSITIVE CONTROL FAILED: the enumeration never EVALUATED "+
			"`protocols bgp group` — it did not reach the sibling-fixture stage for a "+
			"container known to be reachable. The %d below is therefore a property of "+
			"the instrument, not of the schema. (Evaluated %d containers.)",
			shape, len(evaluated))
	}
	sort.Strings(rows)
	sort.Strings(unmeasurable)
	if shape != 0 {
		t.Errorf("#9181: %d vacuous rows are observable-only-via-a-sibling, want 0 "+
			"(the two `protocols bgp group` rows were the only known instances and the "+
			"compiler fix in #9199 made them observable).\n  %s\n\n"+
			"GREW: another container now hides a real loss behind a vacuous label — "+
			"adjudicate it, it is a defect the census cannot see. SHRANK: a compiler "+
			"fix made one observable, which is good news; re-derive and lower this.",
			shape, strings.Join(rows, "\n  "))
	}
	t.Logf("C2 vacuous rows:                   %d", c2)
	t.Logf("  with a child container:          %d", haveChild)
	t.Logf("  SIBLING-OBSERVABLE (the shape):  %d", shape)
	t.Logf("  UNMEASURABLE (no fixture built): %d", len(unmeasurable))
	for _, r := range rows {
		t.Logf("   SHAPE: %s", r)
	}
	for _, u := range unmeasurable {
		t.Logf("   UNMEASURABLE: %s", u)
	}
}
