package config

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// #7484 + the #9091-class census: the coverage ratchet moved a NUMBER and never
// said which leaf moved.
//
// `gateCoverageFloor` and the per-class blind ceilings are three counts. When
// the floor moved 716 -> 742 for #9351 the failure said exactly that — "742,
// tighten it" — and learning WHICH 26 leaves had arrived required writing a
// throwaway differ against origin/master. I then described the members of two
// classes WRONGLY in the ratchet's own comments and had to correct them from
// the data.
//
// That is the `added9091` cost one step milder: a MISSING diagnostic rather
// than a WRONG one. The census that found it looked for the wrong-diagnostic
// shape (a helper answering "what changed" by position) and found ZERO
// remaining instances — that defect was a single occurrence. The count-only
// shape is what survives, and here it governs a POPULATION whose members are
// the whole point.
//
// The remedy is the one #8921 and #9094 already established in this tree: hold
// the SITE LIST, not the count. Regenerate with
// `UPDATE_7484=1 go test ./pkg/config/ -run TestSpellingGateMembersAreRecorded7484`.

const spellingGateMembersPath7484 = "testdata/spelling_gate_members_7484.txt"

// measuredGateMembers7484 classifies every enumerated leaf exactly as
// TestSchemaSpellingGateCoverageIsGated_7484 does, so the two cannot disagree
// about what is in which bucket.
func measuredGateMembers7484() map[string]string {
	out := map[string]string{}
	for _, g := range enumerateGateLeaves() {
		if gateLeafCompared(g) {
			out[g.siteKey()] = "COMPARED"
			continue
		}
		out[g.siteKey()] = string(classifyGateBlindLeaf(g))
	}
	return out
}

func recordedGateMembers7484(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(spellingGateMembersPath7484)
	if err != nil {
		t.Fatalf("cannot read the #7484 member registry: %v — this cell is blind without it", err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			t.Fatalf("malformed registry row %q", line)
		}
		out[parts[1]] = parts[0]
	}
	return out
}

// TestSpellingGateMembersAreRecorded7484 makes the coverage ratchet NAME what
// moved.
//
// The three counts in TestSchemaSpellingGateCoverageIsGated_7484 stay — they
// are the ratchet. This is the diagnostic they never had: a leaf that arrives,
// departs, or CHANGES CLASS is reported by name, so raising a ceiling is a
// decision about specific leaves instead of about a number.
//
// A CLASS CHANGE is the case a count cannot see at all. A leaf moving from
// `flag` to `unreachable` leaves the total blind count identical while the
// thing each ceiling describes has changed completely — the same substitution
// blindness #9094 recorded for #8921's registry.
func TestSpellingGateMembersAreRecorded7484(t *testing.T) {
	measured := measuredGateMembers7484()
	if len(measured) < 500 {
		t.Fatalf("VOID: classified only %d leaves; the enumeration is not reaching the "+
			"grammar and every comparison below would be vacuous", len(measured))
	}

	if os.Getenv("UPDATE_7484") != "" {
		var keys []string
		for k := range measured {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteString("# #7484: every enumerated spelling-gate leaf and the bucket it lands in.\n")
		b.WriteString("#\n")
		b.WriteString("# SITE LIST, not counts (#9094 / #8921). The three numbers in\n")
		b.WriteString("# TestSchemaSpellingGateCoverageIsGated_7484 are the ratchet; this is the\n")
		b.WriteString("# diagnostic they never had. A count cannot see a SUBSTITUTION — a leaf\n")
		b.WriteString("# moving between two blind classes holds every total steady while the thing\n")
		b.WriteString("# each ceiling describes has changed completely.\n")
		b.WriteString("#\n")
		b.WriteString("# Regenerate: UPDATE_7484=1 go test ./pkg/config/ -run TestSpellingGateMembersAreRecorded7484\n")
		b.WriteString("# Never run it to make a failure go away — read the named arrivals first.\n")
		b.WriteString("#\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "%s\t%s\n", measured[k], k)
		}
		if err := os.WriteFile(spellingGateMembersPath7484, []byte(b.String()), 0o644); err != nil {
			t.Fatalf("write registry: %v", err)
		}
		t.Logf("regenerated %s with %d leaves", spellingGateMembersPath7484, len(keys))
		return
	}

	recorded := recordedGateMembers7484(t)
	if len(recorded) == 0 {
		t.Fatal("NON-VACUITY: the registry parsed to zero rows, so every comparison " +
			"below passes by having nothing to compare")
	}

	var arrived, departed, reclassified []string
	for site, class := range measured {
		was, ok := recorded[site]
		switch {
		case !ok:
			arrived = append(arrived, fmt.Sprintf("%s  [%s]", site, class))
		case was != class:
			reclassified = append(reclassified, fmt.Sprintf("%s  %s -> %s", site, was, class))
		}
	}
	for site, class := range recorded {
		if _, ok := measured[site]; !ok {
			departed = append(departed, fmt.Sprintf("%s  [was %s]", site, class))
		}
	}
	sort.Strings(arrived)
	sort.Strings(departed)
	sort.Strings(reclassified)

	report := func(label string, rows []string, why string) {
		if len(rows) == 0 {
			return
		}
		show := rows
		if len(show) > 40 {
			show = show[:40]
		}
		t.Errorf("#7484 %s (%d):\n  %s\n\n%s\n"+
			"Regenerate with UPDATE_7484=1 AFTER reading the list — the counts in "+
			"TestSchemaSpellingGateCoverageIsGated_7484 tell you a number moved; this "+
			"tells you which leaf, which is the part a ceiling change has to justify.",
			label, len(rows), strings.Join(show, "\n  "), why)
	}
	report("leaves ARRIVED in the enumeration", arrived,
		"A new leaf lands in some bucket. If it landed in a BLIND one it carries no "+
			"verdict from the spelling differential, which is the thing the ceilings bound.")
	report("leaves DEPARTED the enumeration", departed,
		"A leaf that stops being enumerated vanishes from every bucket AND from the "+
			"totals — strictly worse than sitting in the wrong one, because nothing reds.")
	report("leaves RECLASSIFIED between buckets", reclassified,
		"This is the case a COUNT CANNOT SEE. A leaf moving between two blind classes "+
			"holds the blind total steady while both ceilings now describe different "+
			"populations than they did.")
}
