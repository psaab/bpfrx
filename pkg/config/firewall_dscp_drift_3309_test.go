package config_test

import (
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// TestFilterDSCPResolvableMatchesDSCPValues is the #3309 BIDIRECTIONAL drift
// guard. pkg/config cannot import pkg/dataplane (import cycle: pkg/dataplane
// imports pkg/config), so validateFilterDSCPStrict INLINE-mirrors
// dataplane.DSCPValues (the snapshot builder's table,
// pkg/dataplane/userspace/filters.go) plus the numeric 0..63 range it accepts.
// This external test pins the two tables together in BOTH directions plus the
// numeric range. Either table drifting from the other turns it RED.
func TestFilterDSCPResolvableMatchesDSCPValues(t *testing.T) {
	// Forward: every DSCP code-point name the snapshot builder resolves must be
	// accepted by the config mirror. Catches the config mirror MISSING a name
	// that the dataplane added (commit would reject a value the dataplane emits).
	for name := range dataplane.DSCPValues {
		if !config.FilterDSCPResolvable(name) {
			t.Errorf("dataplane.DSCPValues has %q but config.FilterDSCPResolvable rejects it "+
				"(config name mirror is stale — add %q to filterDSCPNames)", name, name)
		}
	}

	// Reverse: every name the config mirror accepts must STILL be present in
	// dataplane.DSCPValues. Catches a name DROPPED from the dataplane SSOT while
	// the config mirror still accepts it — the validator would pass that stale
	// name at commit and the snapshot builder would then silently drop it at
	// encode (a no-op match, not a commit error). This is the direction the
	// forward-only guard could not see.
	for _, name := range config.FilterDSCPNames() {
		if _, ok := dataplane.DSCPValues[name]; !ok {
			t.Errorf("config.FilterDSCPNames() accepts %q but dataplane.DSCPValues no longer "+
				"defines it (config name mirror is stale — drop %q from filterDSCPNames)", name, name)
		}
	}

	// Numeric range parity: the snapshot builder accepts strconv.Atoi in 0..63
	// (filters.go). Confirm config.FilterDSCPResolvable agrees across the whole
	// byte range and rejects everything outside 0..63.
	for n := -1; n <= 256; n++ {
		want := n >= 0 && n <= 63
		if got := config.FilterDSCPResolvable(strconv.Itoa(n)); got != want {
			t.Errorf("FilterDSCPResolvable(%d) = %v, want %v (snapshot builder accepts 0..63)", n, got, want)
		}
	}
}

// TestFilterDSCPResolvableAgreesWithTheBuildersResolver7422 upgrades the
// numeric-range cell above from a PINNED LITERAL to an AGREEMENT.
//
// The cell above encodes 0..63 directly, which asserts that the config mirror
// matches a number this test file believes; it cannot see the builder changing
// its mind. Since #7422 the snapshot builder's emit condition is one exported
// function — dataplane.ResolveFilterDSCP, which both pkg/dataplane/userspace/
// filters.go and cli's `show firewall` renderer call — so the two spellings can
// be compared directly instead of both being compared to a literal. When two
// spellings must agree, assert the agreement: pinning one of them to a constant
// silently picks a side, and the side picked is not always the correct one.
//
// The population deliberately mixes code-point names, case variants, decimal
// boundaries, and tokens that are neither.
func TestFilterDSCPResolvableAgreesWithTheBuildersResolver7422(t *testing.T) {
	tokens := []string{
		"", "ef", "EF", "Ef", "be", "af11", "AF43", "cs0", "cs7",
		"-1", "0", "1", "62", "63", "64", "65", "255", "256",
		"0x10", " 12", "12 ", "+12", "012", "1e2", "not-a-code-point",
		"af99", "cs8", "dscp", "traffic-class",
	}
	var accepted int
	for _, tok := range tokens {
		_, builderOK := dataplane.ResolveFilterDSCP(tok)
		configOK := config.FilterDSCPResolvable(tok)
		// The empty token is the one legitimate asymmetry: the strict gate
		// never asks about it (validateFilterDSCPStrict skips "" before
		// calling filterDSCPResolvable) and the builder never emits it. Skip
		// it rather than encode a fake agreement.
		if tok == "" {
			continue
		}
		if builderOK != configOK {
			t.Errorf("token %q: dataplane.ResolveFilterDSCP accepts=%v but "+
				"config.FilterDSCPResolvable accepts=%v. The commit gate and the "+
				"snapshot builder now disagree about what resolves, which is "+
				"either a commit that rejects a value the dataplane would emit "+
				"or — worse — a commit that accepts a value the builder silently "+
				"drops.", tok, builderOK, configOK)
		}
		if builderOK {
			accepted++
		}
	}
	// Non-vacuity. A resolver that rejected everything would make every
	// comparison above agree, and this file would report a clean census over a
	// predicate that accepts nothing.
	if accepted < 10 {
		t.Fatalf("only %d of %d tokens resolved; the population no longer "+
			"exercises the accepting branch and the agreement above is between "+
			"two constant `false`s", accepted, len(tokens))
	}
}
