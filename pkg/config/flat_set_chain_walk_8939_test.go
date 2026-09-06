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
// flatSetChainRow is a container path plus the leaves to synthesize under it.
// It is a STRUCT rather than a flat []string because recovering the leaf count
// from a flat row required re-querying the schema, and that guess was wrong as
// soon as rows could be either two or three leaves wide: it split the instance
// placeholder `arg1` off as a leaf, producing rows like
// `security ike gateway [arg1 | address | external-interface]` whose synthesized
// config is nonsense. A fix to those containers then could not clear them.
// The count is data; it should not be re-derived.
type flatSetChainRow struct {
	container []string
	leaves    []flatSetLeaf
}

// flatSetLeaf is a leaf NAME together with its arity, because the two are
// needed together and re-deriving either has already gone wrong once here
// (flatSetLeafCount, #9078). ARITY IS THE POINT: a leaf declaring `args: 0` is
// a FLAG, and handing it a synthesized value produces a command no operator can
// write --
//
//	generator  monday all-day xpfval exclude xpfval   ->  exclude=false
//	operator   monday all-day exclude                 ->  exclude=true
//
// -- so all fifteen `schedulers scheduler <s> <weekday>` rows were UNCLEARABLE
// BY CONSTRUCTION. A correct fix to that family (#9081) cleared none of them,
// because the row asked a question about a malformed input. Making them clear
// would have required teaching the compiler to swallow a stray token after an
// args:0 flag, which is shaping production to satisfy an instrument.
//
// Third defect of this shape in this generator, after `arg1`-as-leaf and
// flatSetLeafCount: a SYNTHETIC CONFIG THAT IS NOT A CONFIG, producing a row no
// correct fix can clear. Found by lane-8388 reporting what actually cleared
// instead of what was predicted to clear.
type flatSetLeaf struct {
	name string
	args int
}

// spell renders the leaf as an operator would write it: a flag alone, a
// value-taking leaf with its synthesized value.
func (l flatSetLeaf) spell() string {
	if l.args == 0 {
		return l.name
	}
	return l.name + " " + flatSetSyntheticValue(l.name)
}

func flatSetChainPairs() []flatSetChainRow {
	var out []flatSetChainRow
	seen := map[string]bool{}
	var walk func(path []string, n *schemaNode, depth int)
	walk = func(path []string, n *schemaNode, depth int) {
		if depth > 6 || n == nil || n.children == nil {
			return
		}
		var leaves []flatSetLeaf
		for k, c := range n.children {
			if c != nil && c.children == nil && c.wildcard == nil && !c.multi {
				leaves = append(leaves, flatSetLeaf{name: k, args: c.args})
			}
		}
		sort.Slice(leaves, func(i, j int) bool { return leaves[i].name < leaves[j].name })
		if len(leaves) >= 2 {
			if key := strings.Join(path, " "); !seen[key] {
				seen[key] = true
				// BOTH WIDTHS, and the reason is a measured coverage loss.
				//
				// Two leaves cannot discriminate the correct fix from a
				// recursive descent (a descent passes at two and drops the
				// third), so #9078 widened this to three. But widening MOVED
				// containers out of the measured population: `security ike
				// gateway` and `security ipsec gateway` were two-leaf losers,
				// and at three leaves they fall into the unmeasured/vacuous
				// buckets -- so a real fix to both changed the loser list by
				// exactly nothing. Verified by taking that fix onto this
				// ratchet: the fixture came back byte-identical, 34 before and
				// 34 after, while `vacuous` moved 42->44.
				//
				// So neither width alone is the instrument. Two leaves has the
				// coverage; three leaves has the discrimination. Emitting both
				// keeps each container's total-loss row AND, where a third
				// eligible leaf exists, the row that a descent-shaped fix
				// cannot clear.
				cp := append([]string{}, path...)
				out = append(out, flatSetChainRow{cp, append([]flatSetLeaf{}, leaves[:2]...)})
				if len(leaves) >= 3 {
					out = append(out, flatSetChainRow{cp, append([]flatSetLeaf{}, leaves[:3]...)})
				}
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
		if ep != nil || es != nil || packed == nil || split == nil {
			unmeasured++
			continue
		}
		if reflect.DeepEqual(packed, split) {
			// VACUITY CONTROL 1: both empty proves nothing about walking.
			if empty != nil && reflect.DeepEqual(packed, empty) {
				vacuous++
				continue
			}
			// VACUITY CONTROL 2, and it is the one that matters at three
			// leaves. An equal comparison means nothing if the LAST leaf is
			// not observable in the typed config at all: both spellings then
			// compile to the same thing for a reason that has nothing to do
			// with walking the chain, and the row reports WALKED having
			// measured nothing.
			//
			// Found by the count moving the WRONG WAY. Going from two leaves
			// to three moved containers from LOSE to WALK -- `schedulers
			// scheduler <s> friday` among them -- which cannot happen if the
			// measurement is sound, because a third leaf can only expose more
			// loss. Without this control the three-leaf ratchet reported 34
			// losers and 45 walked, and four of those "fixes" were leaves the
			// compiler never reads.
			if prev, e := flatSetCompile(splitLines[:len(splitLines)-1]); e == nil &&
				prev != nil && reflect.DeepEqual(split, prev) {
				vacuous++
				continue
			}
			walked++
			if os.Getenv("SHOW_WALKED_8939") != "" {
				wn := make([]string, 0, len(leaves))
				for _, lf := range leaves {
					wn = append(wn, lf.name)
				}
				fmt.Printf("WALKED %s [%s]\n", strings.Join(cont, " "), strings.Join(wn, " | "))
			}
			continue
		}
		// HOW MUCH is lost, not merely that something is. With three leaves
		// this separates the two fix shapes: a recursive descent recovers leaf
		// B and still drops C, which is `partial`; total loss is `total`.
		kind := "differs"
		if prefix, e := flatSetCompile(splitLines[:1]); e == nil && prefix != nil &&
			reflect.DeepEqual(packed, prefix) {
			kind = "total"
		} else if len(splitLines) > 2 {
			if prefix, e := flatSetCompile(splitLines[:2]); e == nil && prefix != nil &&
				reflect.DeepEqual(packed, prefix) {
				kind = "partial(descent-shaped)"
			}
		}
		names := make([]string, 0, len(leaves))
		for _, lf := range leaves {
			names = append(names, lf.name)
		}
		losers = append(losers, strings.Join(cont, " ")+"  ["+
			strings.Join(names, " | ")+"]  "+kind)
	}
	sort.Strings(losers)

	// THE COUNTS ARE PART OF THE FIXTURE, and that is a mutation result, not a
	// flourish. With only the loser set recorded, deleting the observability
	// vacuity control above passes: removing it moves rows between `vacuous`
	// and `walked` and never touches the loser list, so the control could be
	// dropped in silence. Recording all four counts is what makes it a
	// control rather than a comment.
	got := fmt.Sprintf("# counts: losers=%d walked=%d vacuous=%d unmeasured=%d\n",
		len(losers), walked, vacuous, unmeasured) +
		strings.Join(losers, "\n") + "\n"
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
	// THIS FLOOR WAS WRONG AND FIRING IT IS HOW I FOUND OUT. It read
	// `walked < 20`, on the belief -- published in PR #8999 and on #8939 --
	// that ~41 containers demonstrably walk the chain. Two corrections:
	//
	//  1. Most of that 41 was VACUOUS. Those rows compared equal because the
	//     last leaf is not observable in the typed config at all, not because
	//     any compiler walked anything. With the observability control the
	//     honest number is 5.
	//  2. `applications` -- the witness the whole argument rests on -- is NOT
	//     IN THIS POPULATION. Its match leaves are `multi` or carry children,
	//     so the eligibility predicate excludes them. The count never had
	//     anything to say about it.
	//
	// So the argument against a parse-time rejection does not rest on the
	// census count and never did. It rests on the `applications` control at
	// the top of this test, which drives a real value through a real compile
	// and asserts it (`dport == "8080"`). That control is the floor.
	if walked < 1 {
		t.Errorf("zero containers in the census population walk the chain. That is "+
			"not fatal to this file's argument -- the `applications` control above "+
			"carries it -- but it means the census can no longer corroborate it, "+
			"and the issue comment quoting these numbers should say so. (walked=%d, "+
			"vacuous=%d, losers=%d)", walked, vacuous, len(losers))
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
		if w[l] {
			continue
		}
		if strings.HasPrefix(l, "# counts:") {
			fmt.Fprintf(&b, "  ! counts moved, now: %s\n", strings.TrimPrefix(l, "# counts: "))
			continue
		}
		fmt.Fprintf(&b, "  + NEWLY LOSING (regression): %s\n", l)
	}
	for l := range w {
		if g[l] {
			continue
		}
		if strings.HasPrefix(l, "# counts:") {
			fmt.Fprintf(&b, "  ! counts were:       %s\n", strings.TrimPrefix(l, "# counts: "))
			continue
		}
		fmt.Fprintf(&b, "  - no longer losing (fixed):  %s\n", l)
	}
	return b.String()
}
