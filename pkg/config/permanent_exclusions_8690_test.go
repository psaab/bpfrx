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
	"partial": true, "gate-confirmed": true, "gate-open-question": true,
	"gate-collateral": true, "unmeasurable": true, "unreachable": true,
	// #8690: measured — with the pair ADMITTED, pass on and off — to change
	// nothing at the commit boundary, because a required sibling the compact
	// spelling cannot carry is still missing. Distinct from `unreachable`
	// (a rule cannot NAME it) and from `unmeasurable` (nobody could measure
	// it): here the rule names it fine and the measurement was taken.
	"sibling-blocked": true,
	"hazard":          true, "open": true, "unclassified": true,
	// #8690: MEASURED, at every reachable spelling and with the pass both
	// enabled and disabled, to drop nothing. There is no fix to make. It is not
	// `open` (nothing to normalize), not `unmeasurable` (it WAS measured), and
	// not `hazard` (normalizing breaks nothing — it is merely pointless).
	//
	// This class replaced `owed-own-change`, which existed for one hour and held
	// only the two `scheduler-name` sites. That class was created to hold an
	// argument that was reasoned and never run: that a packed `scheduler-name`
	// is silently dropped, leaving a PERMANENTLY-ACTIVE security policy, so
	// normalizing it was a correct fix owing a failover smoke. Measured, every
	// clause is false — the argument was built on a hierarchical spelling nobody
	// writes, instead of the flat `set` form operators actually use.
	"no-drop-measured": true,
}

// Classes whose sites must never be normalized.
//
// `gate-open-question` IS DELIBERATELY ABSENT, and its absence is the correction
// this register needed most. The disarm arm redding on a site is a QUESTION: it
// cannot distinguish a gate refusing the packed SPELLING from one refusing the
// CONSEQUENCE of the drop, where the pass repairs the drop and the acceptance is
// correct. Recording such a red as permanent overstates it — and did: `security
// ipsec policy <p> proposal-set` and its ike collateral were listed here as
// permanent on that basis, were classified BENIGN by a person, and normalized in
// 0c4818aa0. A red is available work until somebody answers it.
//
// `unmeasurable` is absent for the same reason in a weaker form: "the fixture
// could not produce a type-valid value" is not a finding about the site.
// `no-drop-measured` is permanent in the sense that matters to the COUNT: the
// remaining line is not available work. It differs from the others in why —
// normalizing it is not forbidden, it is simply a no-op, and listing it `open`
// would invite someone to "fix" a site with no defect.
var permanentClasses8690 = map[string]bool{
	"partial": true, "gate-confirmed": true, "gate-collateral": true,
	"unreachable": true, "hazard": true, "no-drop-measured": true,
	"sibling-blocked": true,
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
	var becameAdmissible, unclassifiedDrift, completed, noDropDeparture, measuredAway []string
	for site, e := range reg {
		if inInv[site] {
			continue
		}
		// #8690: an `open` site leaving the inventory is the SUCCESS case, not a
		// violation. This register is named for permanent exclusions, and every
		// other class means "must never be normalized" — but `open` means the
		// opposite, so the failure below was written for classes that do not
		// include it. The first time an `open` site was actually completed
		// (lane-8526 normalizing the three `system` sites it had measured), the
		// cell reported the work as though a gate had been disarmed.
		//
		// So `open` is separated rather than exempted: it still has to be
		// noticed, because a stale `open` entry for work already done is a lane
		// pointing at a site that no longer exists. It just is not an error.
		if e.class == "open" {
			completed = append(completed, site)
			continue
		}
		// #8690: `no-drop-measured` is a THIRD departure meaning, and neither of
		// the two above fits it. That class records a MEASUREMENT — this site
		// drops nothing, at every reachable spelling, with the pass enabled and
		// disabled — and therefore that there was never anything here to
		// normalize.
		//
		// So a departure is not completion: nobody can complete work that did
		// not exist. It means the census stopped seeing the site as divergent,
		// which implies the compiler or the census changed underneath the
		// measurement. That is not necessarily wrong, but the measurement is now
		// unverified, and it is the measurement — not the line — that the next
		// reader will rely on.
		if e.class == "no-drop-measured" {
			noDropDeparture = append(noDropDeparture, site)
			continue
		}
		// `unclassified` / `unmeasurable` departing is neither a violation nor a
		// completion: it means somebody MEASURED a site this register recorded
		// as unknown, and the measurement is the thing worth keeping. The line
		// goes, but the verdict should not vanish with it.
		if e.class == "unclassified" || e.class == "unmeasurable" {
			measuredAway = append(measuredAway, site+" (was "+e.class+")")
			continue
		}
		becameAdmissible = append(becameAdmissible, site+" ("+e.class+": "+e.reason+")")
	}
	sort.Strings(completed)
	if len(completed) > 0 {
		t.Errorf("#8690: %d site(s) classed `open` have been normalized and their register "+
			"lines are now stale:\n  %s\n\nThat is the work being DONE, not a violation — "+
			"delete these lines. They are reported rather than ignored because a stale `open` "+
			"entry sends the next lane looking for a site that is no longer there.",
			len(completed), strings.Join(completed, "\n  "))
	}
	sort.Strings(noDropDeparture)
	if len(noDropDeparture) > 0 {
		t.Errorf("#8690: %d site(s) classed `no-drop-measured` left the inventory:\n  %s\n\n"+
			"That class says the site was MEASURED to drop nothing, so this is not a "+
			"completion — there was no work here to complete. It means the census stopped "+
			"seeing the site as divergent, so the compiler or the census moved underneath "+
			"the measurement. CHECK: re-run the cell named in the entry's reason. If it "+
			"still passes, the site genuinely stopped diverging and the line should go, with "+
			"the measurement recorded where the next reader will find it. If it now FAILS, "+
			"the class is stale and the site needs re-classifying — do not delete the line "+
			"on the strength of it having disappeared.",
			len(noDropDeparture), strings.Join(noDropDeparture, "\n  "))
	}
	sort.Strings(measuredAway)
	if len(measuredAway) > 0 {
		t.Errorf("#8690: %d site(s) recorded as UNKNOWN left the inventory:\n  %s\n\n"+
			"Somebody measured a site this register said was unmeasured, and normalized it. "+
			"That is fine — but the MEASUREMENT is the part worth keeping, and deleting the "+
			"line drops it. Record what was measured (in the commit, or in the arm's own "+
			"classification map) before removing the entry, so the next site in the same "+
			"bucket inherits the answer rather than re-deriving it.",
			len(measuredAway), strings.Join(measuredAway, "\n  "))
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
	// A class that asserts a MEASUREMENT must carry one. These three checks exist
	// because a class label is cheap and a reason is not, and the whole failure
	// this register had at birth was recording an unanswered question as an
	// answer.
	for site, e := range reg {
		switch e.class {
		case "gate-confirmed":
			// Asserts a person determined the gate refuses the packed SPELLING
			// rather than the consequence of the drop. Without the measurement
			// that is a question wearing a verdict's label.
			if len(e.reason) < 80 {
				t.Errorf("%q is classed `gate-confirmed` with a %d-character reason. That "+
					"class asserts a PERSON measured it; the measurement IS the claim",
					site, len(e.reason))
			}
		case "sibling-blocked":
			// Asserts a measurement taken with the pair ADMITTED. That
			// qualifier is the whole content of the class: for an EXCLUDED pair
			// the pass touches 0 nodes, so "the pass changes nothing here" is
			// true by construction and says nothing about the site. An entry
			// that does not state it is indistinguishable from that null.
			if !strings.Contains(e.reason, "ADMITTED") {
				t.Errorf("%q is classed `sibling-blocked` but its reason does not say the "+
					"measurement was taken with the pair ADMITTED. For an excluded pair "+
					"the pass touches no nodes, so \"nothing changes\" is guaranteed and "+
					"measures nothing — the qualifier IS the claim", site)
			}
			if !strings.Contains(e.reason, "ENABLED") || !strings.Contains(e.reason, "DISABLED") {
				t.Errorf("%q is classed `sibling-blocked` but its reason does not say the "+
					"pass was exercised BOTH ways", site)
			}
		case "no-drop-measured":
			// Asserts a MEASUREMENT, so it must cite the executable form of it.
			// A "measured" claim with no runnable cite is prose, and prose is
			// exactly what this class was created to replace: its predecessor
			// held a confident, coherent, entirely unrun argument.
			if !strings.Contains(e.reason, "_test.go") {
				t.Errorf("%q is classed `no-drop-measured` but its reason cites no test "+
					"file. That class asserts a measurement; without a runnable cite it is "+
					"the same prose that put the wrong verdict here in the first place", site)
			}
			if !strings.Contains(e.reason, "ENABLED") || !strings.Contains(e.reason, "DISABLED") {
				t.Errorf("%q is classed `no-drop-measured` but its reason does not say the "+
					"site was measured with the pass BOTH enabled and disabled. A result "+
					"from one side cannot show the pass is not load-bearing", site)
			}
		case "unclassified", "unmeasurable":
			// UNKNOWN must say WHY it cannot be measured. A placeholder reads as
			// cleared, which is the opposite of what the class means — and "arm 2
			// passed" is the absence of evidence for these, not evidence.
			if len(e.reason) < 80 {
				t.Errorf("%q is classed %q with a %d-character reason. An UNKNOWN entry must "+
					"say WHY it cannot be measured; a placeholder reads as cleared, which "+
					"inverts the class", site, e.class, len(e.reason))
			}
			if !strings.Contains(e.reason, "NOT measured") && !strings.Contains(e.reason, "cannot") &&
				!strings.Contains(e.reason, "not known-safe") && !strings.Contains(e.reason, "ABSENCE OF EVIDENCE") {
				t.Errorf("%q is classed %q but its reason never says the measurement was not "+
					"taken or cannot be taken. Absence of evidence has to be stated as such "+
					"or it reads as evidence of absence", site, e.class)
			}
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
