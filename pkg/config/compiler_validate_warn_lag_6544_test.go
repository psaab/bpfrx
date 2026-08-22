package config

import (
	"strings"
	"testing"
)

// #6544: 802.3ad link aggregation is schema-advertised, commits clean, and is
// entirely inert.
//
// `interfaces ae0 aggregated-ether-options { lacp active; periodic fast;
// minimum-links 2; }` plus `interfaces ge-0/0/1 gigether-options 802.3ad ae0`
// compiles into AggregatedEtherOpts / LAGParent and stops there — nothing reads
// either field. Measured before the fix: the config committed with ZERO
// warnings and `buildFabricBondModels` produced ZERO bond models, so no
// `.netdev` is written, no member gets `Bond=`, no bond device exists, no LACP
// runs and minimum-links is not honoured. The operator was told the feature
// exists by three independent layers (schema completion, a clean commit, and
// the documentation) and received nothing.
//
// It carries the accepted-only advisory now, the #2078/#4231/#5804 doctrine.
//
// FAIL-ON-REVERT: drop the
// `warnings = append(warnings, validateLinkAggregationWarnings(cfg)...)`
// dispatch in compiler_validate_warn.go (or the emit inside the validator) and
// the advisory subtests below go silent on the inert config.

func compileWarnings(t *testing.T, lines []string) []string {
	t.Helper()
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("commit rejected: %v", err)
	}
	return ValidateConfig(cfg)
}

// warningMatching returns the first warning containing every substring.
func warningMatching(warnings []string, parts ...string) string {
	for _, w := range warnings {
		if stringContainsAll(w, parts...) {
			return w
		}
	}
	return ""
}

// TestAEInterfaceEmitsAcceptedOnlyAdvisory: an ae interface with a full
// aggregated-ether-options body must not commit silently.
func TestAEInterfaceEmitsAcceptedOnlyAdvisory(t *testing.T) {
	warnings := compileWarnings(t, []string{
		"set interfaces ae0 aggregated-ether-options lacp active",
		"set interfaces ae0 aggregated-ether-options lacp periodic fast",
		"set interfaces ae0 aggregated-ether-options minimum-links 2",
		"set interfaces ae0 unit 0 family inet address 10.0.9.1/24",
	})
	w := warningMatching(warnings, "interfaces ae0", "aggregated-ether-options", "accepted-only")
	if w == "" {
		t.Fatalf("no accepted-only advisory for the inert ae0 aggregate; "+
			"warnings = %v", warnings)
	}
	// The advisory must name what the operator actually loses, not just say
	// "not implemented" — an operator configuring a LAG is buying bandwidth
	// and redundancy.
	for _, want := range []string{"no bond device", "LACP", "minimum-links"} {
		if !strings.Contains(w, want) {
			t.Errorf("advisory %q does not mention %q", w, want)
		}
	}
}

// TestLAGMemberBindingEmitsAcceptedOnlyAdvisory: the member side is inert too
// and gets its own line naming the members and the parent.
func TestLAGMemberBindingEmitsAcceptedOnlyAdvisory(t *testing.T) {
	warnings := compileWarnings(t, []string{
		"set interfaces ae0 aggregated-ether-options lacp active",
		"set interfaces ge-0/0/1 gigether-options 802.3ad ae0",
		"set interfaces ge-0/0/2 gigether-options 802.3ad ae0",
	})
	w := warningMatching(warnings, "802.3ad ae0", "accepted-only")
	if w == "" {
		t.Fatalf("no accepted-only advisory for the inert 802.3ad member "+
			"bindings; warnings = %v", warnings)
	}
	for _, member := range []string{"ge-0/0/1", "ge-0/0/2"} {
		if !strings.Contains(w, member) {
			t.Errorf("member advisory %q does not name %s", w, member)
		}
	}
}

// TestLAGMemberWithNoAEParentStillWarns: a member naming a parent that was
// never configured is just as inert; staying silent would hide the typo
// underneath the missing feature.
func TestLAGMemberWithNoAEParentStillWarns(t *testing.T) {
	warnings := compileWarnings(t, []string{
		"set interfaces ge-0/0/1 gigether-options 802.3ad ae7",
	})
	if warningMatching(warnings, "802.3ad ae7", "accepted-only") == "" {
		t.Fatalf("a member bound to an unconfigured ae parent produced no "+
			"advisory; warnings = %v", warnings)
	}
}

// TestNoLAGConfigEmitsNoLAGAdvisory is the negative control: the advisory must
// key on the compiled LAG fields, not fire on every config.
func TestNoLAGConfigEmitsNoLAGAdvisory(t *testing.T) {
	warnings := compileWarnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet dhcp",
		"set interfaces fab0 fabric-options member-interfaces ge-0/0/3",
	})
	for _, w := range warnings {
		if strings.Contains(w, "#6544") {
			t.Errorf("LAG advisory fired on a config with no ae / 802.3ad "+
				"statement: %q", w)
		}
	}
}

// TestFabricBondIsNotReportedAsInert is the second negative control and the
// one that matters: `fabric-options member-interfaces` IS realized (it drives
// BondMode=active-backup, a .netdev, and member enslaving). Reporting it as
// accepted-only would be a false claim in the opposite direction.
func TestFabricBondIsNotReportedAsInert(t *testing.T) {
	lines := []string{
		"set interfaces fab0 fabric-options member-interfaces ge-0/0/3",
		"set interfaces fab0 fabric-options member-interfaces ge-0/0/4",
	}
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("commit rejected: %v", err)
	}
	// Guard the premise: this config really does drive the realized path.
	if got := cfg.Interfaces.Interfaces["fab0"].BondMode; got != "active-backup" {
		t.Fatalf("fab0 BondMode = %q, want active-backup — the premise of "+
			"this control no longer holds", got)
	}
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "#6544") {
			t.Errorf("the REALIZED fabric bond path was reported as an inert "+
				"aggregate: %q", w)
		}
	}
}
