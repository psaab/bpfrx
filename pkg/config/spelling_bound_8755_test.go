package config

import (
	"strings"
	"testing"
)

// #8755: a scope entry closes ONE of four losing spellings, and the register
// says so. This is the guard that keeps that note true rather than merely
// written.
//
// Measured at 769f2f622, through the real pass under the production scope:
//
//	A  family inet { filter { input f4; } }   keeps  "f4"   fully braced, correct
//	B  family inet { filter input f4; }       DROPS         idiomatic elision
//	C  family inet filter input f4;           DROPS         one-liner
//	D  family { inet { filter input f4; } }   DROPS         unidiomatic
//	E  family { inet filter input f4; }       DROPS         unidiomatic
//
// Only C is reachable by admitting a chain. B is unreachable BY CONSTRUCTION:
// normalizeCompactNodes recurses into a braced `Keys=[family inet]` with
// schema.children["family"], while those children belong to `family inet` — the
// schema advances one level where the node advanced two, so nothing beneath is
// ever consulted (pairsAsked=[] for that shape even under admit-all).
//
// `unit`-level sites are NOT subject to this: there the second token is an
// instance ARG consumed by `identity`, not a child keyword.

func filterInOf8755(t *testing.T, text string) (string, bool) {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		return "", false
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		return "", false
	}
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Units[0] == nil {
		return "", false
	}
	return ifc.Units[0].FilterInputV4, true
}

const fwFilter8755 = `firewall { family inet { filter f4 { term t { then discard; } } } } `

func ifaceSpelling8755(inner string) string {
	return fwFilter8755 + `interfaces { ge-0/0/0 { unit 0 { ` + inner + ` } } }`
}

// THE CONTROL. The fully braced spelling must keep the filter, or every "DROPS"
// below is about a fixture that never bound one.
func TestTheBracedSpellingKeepsTheFilter_8755(t *testing.T) {
	got, ok := filterInOf8755(t, ifaceSpelling8755(`family inet { filter { input f4; } }`))
	if !ok {
		t.Fatal("the braced control did not compile")
	}
	if got != "f4" {
		t.Fatalf("the fully braced spelling binds %q, want \"f4\" — the other cells in "+
			"this file compare against it and are meaningless if it does not bind", got)
	}
}

// THE BOUND. C is reachable by a scope entry; B is not. If C is ever fixed
// while B still drops, the fix is PARTIAL and the register's `open` entries
// need re-reading — `open` there means available, not fully fixable.
//
// This is green today (both drop) and green after a complete fix (both keep).
// It fires on exactly one state: the partial one.
func TestAChainAdmissionDoesNotCloseTheIdiomaticElision_8755(t *testing.T) {
	// The control is READ, not merely asserted elsewhere: every comparison below
	// is against what the fully braced spelling actually binds. A control that
	// is only checked in its own cell can stop binding without this one
	// noticing — found by mutation, where blanking that check killed nothing.
	want, okC := filterInOf8755(t, ifaceSpelling8755(`family inet { filter { input f4; } }`))
	if !okC || want == "" {
		t.Fatalf("the fully braced control binds %q; every comparison below is "+
			"against it and means nothing if it binds nothing", want)
	}
	braced, ok1 := filterInOf8755(t, ifaceSpelling8755(`family inet { filter input f4; }`))
	oneLiner, ok2 := filterInOf8755(t, ifaceSpelling8755(`family inet filter input f4;`))
	if !ok1 || !ok2 {
		t.Fatal("a spelling did not compile; this cell measures nothing")
	}
	switch {
	case braced == want && oneLiner == want:
		t.Log("both spellings now bind the filter — the traversal gap is closed and " +
			"this cell, and the register's spelling-bound note, can be retired")
	case braced == "" && oneLiner == "":
		// Today. Nothing admitted, so nothing folds.
	case braced == "" && oneLiner == want:
		// UNFALSIFIABLE AT THIS HEAD, and labelled: the partial state does not
		// exist yet, so a mutation deleting this arm kills nothing. That is what
		// the arm is FOR — it fires on a future state, which is the only kind of
		// guard that can catch a fix being shipped half-done.
		t.Errorf("PARTIAL FIX: the one-liner now binds %q and the idiomatic "+
			"`family inet { filter input f4; }` still drops it. A chain admission cannot reach a braced multi-key "+
			"container — normalizeCompactNodes advances the schema one level where "+
			"the node advanced two. The #8690 register lists these sites `open`; "+
			"that class now understates them and the entries must say which "+
			"spelling they close (#8755)", braced)
	default:
		t.Errorf("unexpected combination: braced=%q oneLiner=%q — the two spellings "+
			"have diverged in a direction this cell does not model, which is worth "+
			"a human before it is worth a fix", braced, oneLiner)
	}
}

// The register's own claim, checked against the register — for the sites the
// claim is ABOUT.
//
// THIS CELL WAS OVER-BROAD ON ITS FIRST DAY and reddened master. It required a
// spelling-bound note from EVERY `open` entry, including two
// `security policies ... scheduler-name` sites another lane added minutes
// later. Those sites are not under a braced multi-key container and the bound
// says nothing about them, so the guard was demanding a claim that would have
// been false if written.
//
// A guard written for one population must SELECT that population, or it becomes
// a tax on every lane that appends to the same file — and the first person to
// pay it will make it green the cheapest way, which is by writing the note
// whether or not it is true.
//
// The selector is a proxy and is named as one: the bound applies to a site
// whose container passes through a braced MULTI-KEY node whose second token is
// a child keyword. In this register that is exactly `family inet` /
// `family inet6`; `unit <n>` does not qualify because its second token is an
// instance arg.
func siteIsUnderABracedMultiKey8755(site string) bool {
	return strings.Contains(site, " family inet ") || strings.HasSuffix(site, " family inet") ||
		strings.Contains(site, " family inet6 ") || strings.HasSuffix(site, " family inet6")
}

func TestEveryOpenEntryCarriesTheSpellingBound_8755(t *testing.T) {
	var missing, considered []string
	for _, l := range strings.Split(mustReadFile8690(t, "testdata/compact_block_permanent_exclusions_8690.txt"), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "\t")
		if len(f) < 3 || strings.TrimSpace(f[1]) != "open" {
			continue
		}
		site := strings.TrimSpace(f[0])
		if !siteIsUnderABracedMultiKey8755(site) {
			continue
		}
		considered = append(considered, site)
		if !strings.Contains(f[2], "SPELLING BOUND") {
			missing = append(missing, site)
		}
	}
	// NON-VACUITY: a selector that matches nothing reports no failures too, and
	// this one is a string proxy that a register rename would silently defeat.
	if len(considered) == 0 {
		t.Fatal("the selector matched no `open` site, so the check below passed by " +
			"selecting nothing. Either every such site has been normalized — in " +
			"which case this cell can go — or the site-key shape changed and the " +
			"proxy stopped matching (#8755)")
	}
	if len(missing) > 0 {
		t.Errorf("%d `open` entries carry no spelling bound: %v.\n`open` reads as "+
			"\"available work, fully fixable\", and for the sites under a braced "+
			"multi-key container it is not — a chain admission closes one of four "+
			"losing spellings. An entry without that note invites a fix that covers "+
			"a quarter of the exposure (#8755)", len(missing), missing)
	}
}
