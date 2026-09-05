package config

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// #8690: the permanent-exclusion register.
//
// The inventory counts sites that DIVERGE. It says nothing about whether a site
// MAY be normalized, and by the end of the sweep those are almost disjoint
// questions: of the lines that remain, the large majority must NEVER be
// normalized. A bare remaining-count reads as remaining WORK, and the only way
// to drive it down is to normalize sites the guards exist to protect. This
// register is what the inventory's remainder actually means.
//
// IT IS A GATE, NOT A REGISTRY. lane-8526's warning about registration lists
// applies with full force here: a file that only accumulates is a place to hide
// defects. So the register is asserted for EQUALITY against the inventory in
// both directions, and the classification is cross-checked against the data it
// claims to describe.

const permanentExclusionsPath = "testdata/compact_block_permanent_exclusions_8690.txt"

type exclusion8690 struct {
	class  string
	reason string
}

var exclusionClasses8690 = map[string]bool{
	"partial": true, "gate": true, "gate-collateral": true,
	"unmeasurable": true, "unreachable": true, "hazard": true,
	"open": true, "unclassified": true,
}

// classes whose sites must never be normalized.
var permanentClasses8690 = map[string]bool{
	"partial": true, "gate": true, "gate-collateral": true,
	"unmeasurable": true, "unreachable": true, "hazard": true,
}

func readPermanentExclusions8690(t *testing.T) map[string]exclusion8690 {
	t.Helper()
	raw, err := os.ReadFile(filepath.FromSlash(permanentExclusionsPath))
	if err != nil {
		t.Fatalf("read %s: %v", permanentExclusionsPath, err)
	}
	out := map[string]exclusion8690{}
	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.Split(trimmed, "\t")
		if len(parts) < 3 || strings.TrimSpace(parts[2]) == "" {
			t.Errorf("%s line %d: want <site>\\t<class>\\t<reason>, got %q. A class "+
				"without a reason is a registration, not a classification — the reason "+
				"is the part a future reader cannot reconstruct", permanentExclusionsPath, i+1, trimmed)
			continue
		}
		site := strings.TrimSpace(parts[0])
		class := strings.TrimSpace(parts[1])
		if !exclusionClasses8690[class] {
			t.Errorf("%s line %d: unknown class %q for %q. An unrecognised class is "+
				"read by no consumer, so the site is effectively unlisted",
				permanentExclusionsPath, i+1, class, site)
			continue
		}
		if _, dup := out[site]; dup {
			t.Errorf("%s: %q listed twice", permanentExclusionsPath, site)
		}
		out[site] = exclusion8690{class: class, reason: strings.TrimSpace(parts[2])}
	}
	return out
}

// THE GATE. The register and the inventory must describe the same set.
//
// A listed site that LEFT the inventory became admissible — either a widening
// normalized something this file says must never be normalized, or the
// classification was wrong. Both need a human, and both are silent otherwise.
//
// An inventory site NOT listed is unclassified drift: the next reader counts it
// as remaining work with no way to learn it is not.
func TestPermanentExclusionsMatchTheInventory8690(t *testing.T) {
	reg := readPermanentExclusions8690(t)
	sites, _ := readInventory(t)

	// DEGENERACY CONTROL. Either side going empty would satisfy a naive
	// subset check and prove nothing.
	if len(reg) == 0 {
		t.Fatal("the exclusion register is empty; this cell asserts nothing")
	}
	if len(sites) == 0 {
		t.Fatal("the inventory has no sites; this cell asserts nothing")
	}

	inInv := map[string]bool{}
	for _, s := range sites {
		inInv[s] = true
	}
	var becameAdmissible, unclassifiedDrift []string
	for site, e := range reg {
		if !inInv[site] {
			becameAdmissible = append(becameAdmissible, site+" ("+e.class+": "+e.reason+")")
		}
	}
	for _, s := range sites {
		if _, ok := reg[s]; !ok {
			unclassifiedDrift = append(unclassifiedDrift, s)
		}
	}
	sort.Strings(becameAdmissible)
	sort.Strings(unclassifiedDrift)

	if len(becameAdmissible) > 0 {
		t.Errorf("#8690: %d site(s) left the inventory while still listed in the "+
			"permanent-exclusion register:\n  %s\n\n"+
			"A site leaves the inventory when compact and block compile the same, "+
			"which for these means a widening NORMALIZED something this register says "+
			"must never be normalized. Either that widening disarmed a gate / truncated "+
			"a read tail, or the classification above was wrong. Do not simply delete "+
			"the line — establish which, and say so.",
			len(becameAdmissible), strings.Join(becameAdmissible, "\n  "))
	}
	if len(unclassifiedDrift) > 0 {
		t.Errorf("#8690: %d inventory site(s) are absent from the permanent-exclusion "+
			"register:\n  %s\n\n"+
			"An unclassified remaining line reads as remaining WORK. If it is available, "+
			"list it `open`; if it must never be normalized, list it with the class and "+
			"the measurement. The register's value is that the remaining count can be "+
			"read correctly without re-deriving it.",
			len(unclassifiedDrift), strings.Join(unclassifiedDrift, "\n  "))
	}
}

// The classification must agree with the data it claims to describe. A site
// classed `partial` that the inventory marks `empty` is a register drifting from
// its evidence — and `partial` is the class the normalizer guard actually
// enforces, so a wrong one here is a claim nothing checks.
func TestPermanentExclusionClassesAgreeWithTheInventory8690(t *testing.T) {
	reg := readPermanentExclusions8690(t)
	shapes := readInventoryShapes(t)
	checked := 0
	for site, e := range reg {
		shape, ok := shapes[site]
		if !ok {
			continue // absent-from-inventory is the sibling cell's failure, not this one's
		}
		checked++
		if e.class == "partial" && shape != "partial" {
			t.Errorf("%q is classed `partial` in the register but the inventory marks it "+
				"%q. The partial class is the one TestNormalizerScopeNeverCoversAPartialSite8690 "+
				"enforces, so a wrong classification here is a protection nobody is applying", site, shape)
		}
		if e.class != "partial" && shape == "partial" {
			t.Errorf("%q is marked `partial` in the inventory but classed %q here. A partial "+
				"site is forbidden to every scope by construction; classing it as anything "+
				"else understates why it can never move", site, e.class)
		}
	}
	if checked == 0 {
		t.Fatal("no register entry could be cross-checked against an inventory shape; " +
			"this cell is blind")
	}
}

// The register must keep saying something. If every remaining line were `open`
// the file would be a work list, not an exclusion register, and the reader who
// needs to know "this can never move" would get no answer.
func TestPermanentExclusionRegisterIsDiscriminating8690(t *testing.T) {
	reg := readPermanentExclusions8690(t)
	counts := map[string]int{}
	permanent := 0
	for _, e := range reg {
		counts[e.class]++
		if permanentClasses8690[e.class] {
			permanent++
		}
	}
	if permanent == 0 {
		t.Error("the register classifies NO site as permanently excluded. Either the " +
			"sweep genuinely finished — in which case this file and its cells should be " +
			"retired deliberately — or the classes drifted and the register now records " +
			"nothing it exists to record")
	}
	// The register's whole point is that remaining != available. If those are
	// equal it carries no information a line count did not already give.
	if permanent == len(reg) && counts["open"] == 0 && counts["unclassified"] == 0 {
		t.Log("#8690: every remaining line is permanently excluded — the sweep is " +
			"complete and the inventory's remainder is entirely a record, not a backlog")
	}
	t.Logf("#8690 exclusion register: %d entries — %d permanent, %d open, %d unclassified",
		len(reg), permanent, counts["open"], counts["unclassified"])
}
