package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7515 — the daemon's management-VRF interface set is the ENFORCEMENT site of
// the management-interface class: what lands in it is what collectDHCPRoutes
// excludes from FRR, and therefore what the ip-monitoring next-hop validator is
// telling the truth about when it refuses one.
//
// This binds the AGREEMENT with config.IsManagementIfName rather than pinning
// its own prefix literal. A literal here would encode which site is trusted, and
// the whole defect was that three sites each carried their own.
//
// FAIL-ON-REVERT: put `strings.HasPrefix(name, "fxp") || ...` back into
// managementVRFIfaceSet and this stays green only while the two coincide —
// narrow or widen either side alone and it reds, in either direction.
// mgmtIfNameCases7515 is the probe POPULATION, mirrored from the sibling test in
// pkg/config. It is duplicated rather than exported from production code, and
// that is safe in a way a duplicated EXPECTATION would not be: every assertion
// below compares this site's answer against config.IsManagementIfName, so if the
// lists drift the only effect is that a name stops being probed here — coverage
// weakens, a result never inverts. A pinned expected-answer literal would
// silently encode which site is trusted, which is the defect being fixed.
var mgmtIfNameCases7515 = []string{
	"fxp0", "fxp1", "em0", "em1", "fab0", "fab1",
	"emu0", "embed0", "fabric0", "fxpanel0",
	"ge-0/0/0", "reth0", "lo0", "st0", "start0", "e0", "f0",
}

func TestManagementVRFIfaceSetAgreesWithSSOT7515(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	for _, name := range mgmtIfNameCases7515 {
		if name == "" {
			continue
		}
		cfg.Interfaces.Interfaces[name] = &config.InterfaceConfig{Name: name}
	}

	got := managementVRFIfaceSet(cfg)

	for _, name := range mgmtIfNameCases7515 {
		if name == "" {
			continue
		}
		// The set is keyed by the LINUX name, the way the lock-free
		// DHCP-callback readers look it up.
		inSet := got[config.LinuxIfName(name)]
		if want := config.IsManagementIfName(name); inSet != want {
			t.Errorf("%s: in management-VRF set = %v, but config.IsManagementIfName = %v. "+
				"A divergence here is always a bug: this set decides which DHCP leases "+
				"collectDHCPRoutes excludes from FRR, and the ip-monitoring validator's "+
				"refusal message asserts exactly that exclusion (#7515)", name, inSet, want)
		}
	}
}

// TestManagementVRFIfaceSetIsNilSafe7515 — the apply path can reach this with a
// nil config on early-boot paths; it must return an empty set, not panic.
func TestManagementVRFIfaceSetIsNilSafe7515(t *testing.T) {
	if got := managementVRFIfaceSet(nil); len(got) != 0 {
		t.Fatalf("a nil config must yield an empty management set, got %v", got)
	}
}
