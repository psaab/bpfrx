package config

import (
	"strings"
	"testing"
)

func contestedCfg7509(t *testing.T, zones map[string][]string) *Config {
	t.Helper()
	cfg := &Config{}
	cfg.Security.Zones = map[string]*ZoneConfig{}
	for name, ifaces := range zones {
		cfg.Security.Zones[name] = &ZoneConfig{Interfaces: ifaces}
	}
	return cfg
}

func warningsMentioning(cfg *Config, sub string) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, sub) {
			out = append(out, w)
		}
	}
	return out
}

// TestContestedTrunkZoneAdvisoryFires7509 is the fail-on-revert cell: a base
// whose units span two zones must be reported AT COMMIT, naming the interface,
// both zones, and the consequence.
//
// The dataplane change makes this failure safe; this makes it legible. Without
// it the operator's only signal is untagged traffic silently falling to the
// default policy, with nothing on the box saying why (#8296's shape).
func TestContestedTrunkZoneAdvisoryFires7509(t *testing.T) {
	cfg := contestedCfg7509(t, map[string][]string{
		"lan": {"ge-0/0/0.100"},
		"wan": {"ge-0/0/0.200"},
	})
	appendContestedTrunkZoneAdvisoryLocked(cfg, compileOpts{})

	got := warningsMentioning(cfg, "ge-0/0/0")
	if len(got) != 1 {
		t.Fatalf("expected exactly one advisory naming the contested base; got %d: %v",
			len(got), cfg.Warnings)
	}
	// The operator has to be able to act on it: which interface, which zones,
	// and what actually changes. A warning that says only "contested" sends
	// them back to source, which is the gap this exists to close.
	for _, want := range []string{"ge-0/0/0", "lan", "wan", "UNTAGGED", "default policy"} {
		if !strings.Contains(got[0], want) {
			t.Fatalf("advisory must name %q so it is actionable; got: %s", want, got[0])
		}
	}
}

// The control, and the one that decides whether the advisory is AIMED right: a
// trunk whose units are all in ONE zone is an ordinary, correct config and must
// stay silent. An advisory that fires on every trunk is noise, and noise is what
// makes an operator skip the one that matters.
func TestSingleZoneTrunkIsSilent7509(t *testing.T) {
	cfg := contestedCfg7509(t, map[string][]string{
		"lan": {"ge-0/0/0.100", "ge-0/0/0.200", "ge-0/0/0.300"},
	})
	appendContestedTrunkZoneAdvisoryLocked(cfg, compileOpts{})
	if len(cfg.Warnings) != 0 {
		t.Fatalf("a trunk whose units share one zone must produce NO advisory; got %v",
			cfg.Warnings)
	}
}

// Two DIFFERENT bases each in their own zone is not a contest either — the
// grouping must be per base, not global. Without this cell a bug that ignored
// the base key entirely would pass the two cells above.
func TestDistinctBasesAreNotAContest7509(t *testing.T) {
	cfg := contestedCfg7509(t, map[string][]string{
		"lan": {"ge-0/0/0.100"},
		"wan": {"ge-0/0/1.100"},
	})
	appendContestedTrunkZoneAdvisoryLocked(cfg, compileOpts{})
	if len(cfg.Warnings) != 0 {
		t.Fatalf("units on DIFFERENT bases are not a contest; got %v", cfg.Warnings)
	}
}

// The tolerant paths (Store.Load, Store.SyncApply) must stay silent, or the
// advisory fires on every boot and every peer sync of a config committed long
// ago — and an advisory seen on every boot is one an operator learns to skip.
func TestContestedTrunkZoneAdvisorySuppressedOnTolerantPath7509(t *testing.T) {
	cfg := contestedCfg7509(t, map[string][]string{
		"lan": {"ge-0/0/0.100"},
		"wan": {"ge-0/0/0.200"},
	})
	appendContestedTrunkZoneAdvisoryLocked(cfg, compileOpts{suppressContestedTrunkZoneAdvisory: true})
	if len(cfg.Warnings) != 0 {
		t.Fatalf("the tolerant path must emit no advisory; got %v", cfg.Warnings)
	}
}

// #5878 canonicalisation, both directions.
//
// `ge-0/0/0.01` and `ge-0/0/0.1` are ONE unit, so naming that single unit in two
// zones is a DUPLICATE ZONE BINDING, not a trunk contest — there is only one
// unit on the base and it resolves to one zone. Reporting it here would send an
// operator to "split your units" for a problem that is nothing of the sort.
//
// But two DIFFERENT units must still be seen as different when their spellings
// differ, or the advisory misses a real contest whenever one side writes `.02`.
// Both halves are asserted, because a canonicaliser that collapsed too much
// would pass the first and fail the second, and one that collapsed too little
// would do the reverse.
func TestCanonicalUnitRefsAreOneUnit7509(t *testing.T) {
	same := contestedCfg7509(t, map[string][]string{
		"lan": {"ge-0/0/0.1"},
		"wan": {"ge-0/0/0.01"},
	})
	appendContestedTrunkZoneAdvisoryLocked(same, compileOpts{})
	if len(same.Warnings) != 0 {
		t.Fatalf("one canonical unit named in two zones is a duplicate binding, not a "+
			"trunk contest; got %v", same.Warnings)
	}

	differ := contestedCfg7509(t, map[string][]string{
		"lan": {"ge-0/0/0.1"},
		"wan": {"ge-0/0/0.02"},
	})
	appendContestedTrunkZoneAdvisoryLocked(differ, compileOpts{})
	if len(warningsMentioning(differ, "ge-0/0/0")) != 1 {
		t.Fatalf("units .1 and .02 are DIFFERENT units on one base in different zones — "+
			"a real contest the advisory must not miss because the spellings differ; got %v",
			differ.Warnings)
	}
}
