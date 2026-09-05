package config

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// #8921: a keyword-keyed admission is live at EVERY site where a container of
// that keyword declares that head, and every one of them was adjudicated by
// measuring a single fixture at a single site.
//
// This is #8921's item 3 -- the cheapest of its three asks and the one that
// stops the population growing while the other two are open. It does NOT
// adjudicate the extra sites (item 2) and does NOT parent-qualify the
// predicate (item 1). It makes a new multi-site admission impossible to land
// silently.
//
// WHY THAT IS THE USEFUL BOUNDARY. Items 1 and 2 are large: parent-qualifying
// means giving the predicate context it does not have and adding a parent term
// to every scope entry; adjudicating 163 pairs at every declaring site is 163
// fixtures nobody has built. Both are honest costs of a keyword-keyed
// predicate. Neither is a reason to let the debt keep growing in the meantime,
// and a ratchet is the difference between a known debt and an unknown one.
//
// THE FAILURE THIS PREVENTS IS NOT HYPOTHETICAL. #8933 admitted eight
// `then <action>` pairs. `then` has 14 container sites. Nothing collided only
// because the firewall `then` happens to declare none of those eight names --
// safe by coincidence of naming, not by construction. That collision check was
// done by hand because someone remembered to; this cell is that check as a
// mechanism.

func multisiteRegistry8921(t *testing.T) map[string]int {
	t.Helper()
	f, err := os.Open("testdata/multisite_admissions_8921.txt")
	if err != nil {
		t.Fatalf("cannot read the #8921 registry: %v -- this cell is blind without it", err)
	}
	defer f.Close()
	out := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			t.Fatalf("malformed registry row %q", line)
		}
		n, err := strconv.Atoi(parts[1])
		if err != nil {
			t.Fatalf("malformed count in row %q: %v", line, err)
		}
		out[parts[0]] = n
	}
	return out
}

// admittedDeclaringSites8921 walks the schema and, for every admitted
// (container keyword, head) pair, records the paths where a container of that
// keyword DECLARES that head.
//
// Descends into `wildcard` nodes carrying the PARENT's keyword, because an
// instance slot is a name and not a container keyword -- the same traversal
// the #8880 ratchet documents, and an earlier version of that walk silently
// missed pairs reachable only through an instance slot.
//
// EXCLUDES `groups`, which mirrors the whole schema. Including it makes every
// admitted pair multi-site by construction -- measured at 575 of 575 -- and
// erases the distinction this cell exists to draw.
func admittedDeclaringSites8921() map[string][]string {
	out := map[string][]string{}
	seen := map[string]bool{}
	var walk func(path, kw string, n *schemaNode)
	walk = func(path, kw string, n *schemaNode) {
		if n == nil || seen[path] {
			return
		}
		seen[path] = true
		for name, c := range n.children {
			if c == nil {
				continue
			}
			if kw != "" && compactNormalizeInScope(kw, name) {
				key := kw + " " + name
				out[key] = append(out[key], path)
			}
			walk(path+"/"+name, name, c)
		}
		if n.wildcard != nil {
			walk(path+"/*", kw, n.wildcard)
		}
	}
	for k, c := range setSchema.children {
		if k == "groups" {
			continue
		}
		walk(k, k, c)
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

func TestMultisiteAdmissionsAreRecorded8921(t *testing.T) {
	reg := multisiteRegistry8921(t)
	if len(reg) == 0 {
		t.Fatal("NON-VACUITY: the registry parsed to zero rows, so every comparison " +
			"below passes by having nothing to compare")
	}

	sites := admittedDeclaringSites8921()
	measured := map[string]int{}
	for pair, paths := range sites {
		if len(paths) > 1 {
			measured[pair] = len(paths)
		}
	}
	if len(measured) == 0 {
		t.Fatal("NON-VACUITY: the walk found NO multi-site admission at all. Either " +
			"the traversal broke or the predicate stopped admitting anything; " +
			"either way this cell is reporting agreement it did not check")
	}

	var added, removed, changed []string
	for pair, n := range measured {
		if was, ok := reg[pair]; !ok {
			added = append(added, fmt.Sprintf("%s (live at %d sites: %s)",
				pair, n, strings.Join(sites[pair], ", ")))
		} else if was != n {
			changed = append(changed, fmt.Sprintf("%s: recorded %d, now %d (%s)",
				pair, was, n, strings.Join(sites[pair], ", ")))
		}
	}
	for pair, was := range reg {
		if _, ok := measured[pair]; !ok {
			removed = append(removed, fmt.Sprintf("%s (was %d)", pair, was))
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)

	if len(added) > 0 {
		t.Errorf("#8921: %d admission(s) are effective at MORE THAN ONE declaring "+
			"site and are not recorded:\n  %s\n\n"+
			"The scope predicate is keyed on (container keyword, head) with no "+
			"parent context, so this admission is live everywhere a container of "+
			"that keyword declares that head -- including sites nobody measured a "+
			"fixture at. #8933 admitted eight `then <action>` pairs against 14 "+
			"`then` containers and collided with none only because the firewall "+
			"`then` declares none of those names: safe by coincidence of naming, "+
			"not by construction.\n\n"+
			"WALK THE SCHEMA AND CHECK EVERY LISTED SITE before adding a row. "+
			"Adding it without looking records the debt instead of paying it, "+
			"which is what #8921 exists to stop.",
			len(added), strings.Join(added, "\n  "))
	}
	if len(changed) > 0 {
		t.Errorf("#8921: %d recorded admission(s) changed their declaring-site "+
			"count:\n  %s\n\n"+
			"A count that GREW means the schema now declares that head somewhere "+
			"new and the admission followed it there silently. A count that SHRANK "+
			"means a declaring site disappeared. Neither is wrong on its own; both "+
			"mean the adjudication behind this row no longer covers what the row "+
			"describes.",
			len(changed), strings.Join(changed, "\n  "))
	}
	if len(removed) > 0 {
		t.Errorf("#8921: %d recorded admission(s) are no longer multi-site:\n  %s\n\n"+
			"This is the direction that looks like progress and can be either. It "+
			"is progress if an admission was narrowed or a duplicate declaration "+
			"removed. It is a BLIND SPOT if the walk stopped reaching a site -- the "+
			"#8880 ratchet's traversal silently missed pairs reachable only through "+
			"an instance slot until that was found. Confirm which before deleting "+
			"the row; a shrinking ratchet nobody checks is how a census goes quiet.",
			len(removed), strings.Join(removed, "\n  "))
	}
}

// The registry is only meaningful if the walk is stable. Go randomises map
// iteration, and the #8880 census recorded a per-pair property that drifted
// between runs on one unchanged tree for exactly that reason.
func TestMultisiteWalkIsStableAcrossRuns8921(t *testing.T) {
	first := admittedDeclaringSites8921()
	for run := 1; run < 3; run++ {
		next := admittedDeclaringSites8921()
		if len(next) != len(first) {
			t.Fatalf("run %d found %d admitted pairs, run 0 found %d -- the walk is "+
				"not deterministic and every count derived from it is a sample",
				run, len(next), len(first))
		}
		for pair, paths := range first {
			got := next[pair]
			if len(got) != len(paths) {
				t.Errorf("run %d: %q has %d declaring sites, run 0 had %d",
					run, pair, len(got), len(paths))
			}
		}
	}
}
