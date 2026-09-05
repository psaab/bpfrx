package config

import (
	"strings"
	"testing"
)

// #8690 unruled-fixture sweep, second increment: the UNCOMPILABLE bucket.
//
// 45 sites where a generated spelling did not compile, so the census could say
// nothing about them. Every one was a fixture the compiler REJECTED — and the
// compiler said why, so each scaffold below is the smallest addition that turns
// its rejection into a compiled config rather than a guess.
//
// Measured: uncompilable 45 -> 31, checked 685 -> 699, divergent +12, nothing
// removed.

// contextFor's existing callers must be unaffected: five other censuses call
// contextFor(parent), and widening a shared helper under in-flight guards is
// how a census starts measuring something nobody asked it to.
func TestContextForKeepsItsOldAnswers_8690(t *testing.T) {
	// The one entry that predates this change.
	if got := contextFor([]string{"security", "log", "stream", "xpfarg"}); got != "host 192.0.2.10; " {
		t.Errorf("the pre-existing entry changed: %q", got)
	}
	// Every NEW entry is gated on a non-empty stanza, so the legacy entry point
	// still answers "" for them.
	for _, parent := range [][]string{
		{"services", "rpm", "probe", "xpfarg"},
		{"firewall", "three-color-policer", "xpfarg"},
		{"services", "ip-monitoring", "policy", "xpfarg"},
		{"security", "nat", "source", "pool", "xpfarg", "port"},
	} {
		if got := contextFor(parent); got != "" {
			t.Errorf("contextFor(%v) = %q, want \"\" — the #8690 entries must reach "+
				"only the census that asked for them, or five other censuses silently "+
				"change what they measure", parent, got)
		}
		if got := contextForStanza(parent, "some-stanza"); got == "" {
			t.Errorf("contextForStanza(%v, ...) returned nothing; the entry is not "+
				"reachable from the census that needs it either", parent)
		}
	}
}

// The mutually-exclusive case is why the stanza is a parameter at all.
func TestThePolicerScaffoldFollowsTheStanza_8690(t *testing.T) {
	parent := []string{"firewall", "three-color-policer", "xpfarg"}
	single := contextForStanza(parent, "single-rate")
	two := contextForStanza(parent, "two-rate")
	if single == two {
		t.Fatal("single-rate and two-rate get the same scaffold, but a policer " +
			"cannot configure both — one of the two fixtures must be rejected")
	}
	if !strings.Contains(two, "peak-information-rate") {
		t.Errorf("the two-rate scaffold does not configure a peak rate: %q", two)
	}
	if strings.Contains(two, "single-rate") || strings.Contains(single, "two-rate") {
		t.Errorf("a scaffold names the OTHER rate mode; the compiler rejects a "+
			"policer carrying both.\nsingle=%q\ntwo=%q", single, two)
	}
	// Both must actually compile — the property the scaffold exists for.
	for name, ctx := range map[string]string{"single-rate": single, "two-rate": two} {
		text := "firewall { three-color-policer { xpfarg { " + ctx + " } } }"
		if compileText(t, text) == nil {
			t.Errorf("the %s scaffold does not compile on its own: %s", name, text)
		}
	}
}

// preambleFor exists for requirements OUTSIDE the site's container tree, and
// the property that makes it work is that top-level blocks re-open and merge.
func TestPreambleMergesRatherThanReplaces_8690(t *testing.T) {
	pre := preambleFor([]string{"services", "ip-monitoring", "policy", "xpfarg"}, "match")
	if pre == "" {
		t.Fatal("no preamble for an ip-monitoring site; its rpm probe lives under " +
			"`services rpm`, a sibling no parent-level context can reach")
	}
	// The site's own text names the SAME top-level container. If re-opening
	// replaced rather than merged, the probe would be gone and the policy would
	// fail to reference it.
	site := pre + "services { ip-monitoring { policy xpfarg { " +
		contextForStanza([]string{"services", "ip-monitoring", "policy", "xpfarg"}, "match") +
		"hold-down 5; } } }"
	cfg := compileText(t, site)
	if cfg == nil {
		t.Fatalf("the preamble + context fixture does not compile:\n%s", site)
	}
	// Non-vacuity: without the preamble the SAME text must fail, or the
	// preamble is not what made it compile.
	if compileText(t, strings.TrimPrefix(site, pre)) != nil {
		t.Error("the fixture compiles without the preamble, so this cell does not " +
			"measure the preamble")
	}
}

// Each scaffolded family must actually be RULED now — present in the inventory
// or absent from it, but no longer skipped. Checking one representative per
// family rather than all 14 keeps the cell readable while still failing if a
// whole family regresses to unrulable.
func TestTheScaffoldedFamiliesAreRuled_8690(t *testing.T) {
	res := runCompactBlockCensus(t)
	for _, site := range []string{
		"services rpm probe xpfarg test xpfarg target",
		"security policies global policy xpfarg scheduler-name",
		"security nat source pool xpfarg port deterministic block-size",
	} {
		st, seen := res.state[site]
		if !seen {
			t.Errorf("%q is not in the census at all", site)
			continue
		}
		if strings.HasPrefix(st, "skipped: a spelling did not parse or compile") {
			t.Errorf("%q is uncompilable again: its scaffold no longer makes the "+
				"fixture compile, so the site is unruled and nothing else says so "+
				"(#8690)", site)
		}
	}
}
