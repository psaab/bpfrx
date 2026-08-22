package config

import (
	"strings"
	"testing"
)

// #7515 — the "is this a management interface" rule was restated VERBATIM at
// three sites: the daemon's management-VRF set, the networkd `VRF=` emitter, and
// the ip-monitoring next-hop validator. Three copies of a prefix list cannot be
// kept in agreement by convention, and a divergence between them is always a bug
// rather than a legitimate difference — so it is single-sourced on
// IsManagementIfName rather than pinned three times.
//
// NOTE ON THE ORIGINAL FILING, which was WRONG. #7515 claimed `emu0` was
// "not a management interface — the daemon binds no mgmt VRF for it". It does:
// the daemon's set used the same `HasPrefix(name, "em")` rule, so `emu0` really
// is bound to vrf-mgmt and its DHCP lease really is excluded from FRR by
// collectDHCPRoutes. The ip-monitoring refusal was therefore TRUTHFUL, not
// spurious. The defect is the triplication and the class's looseness, and
// narrowing the class is a behaviour change to which interfaces land in the
// management VRF — tracked separately, not made here.

// mgmtIfNameCases7515 is the probe POPULATION. The sibling tests in pkg/daemon
// and pkg/dataplane keep their own copy: every assertion compares that site's
// answer against IsManagementIfName, so a drifted list only weakens coverage
// there — it can never invert a result the way a duplicated EXPECTATION would.
var mgmtIfNameCases7515 = []string{
	// Management class today.
	"fxp0", "fxp1", "em0", "em1", "fab0", "fab1",
	// Look-alikes that are ALSO in the class today, because the rule is a bare
	// prefix. Listed explicitly so narrowing the class is a visible, deliberate
	// edit to this table rather than a silent behaviour change.
	"emu0", "embed0", "fabric0", "fxpanel0",
	// Not management.
	"ge-0/0/0", "reth0", "lo0", "st0", "start0", "e0", "f0", "",
}

// TestManagementIfNameSemantics7515 pins what the class means TODAY.
func TestManagementIfNameSemantics7515(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"fxp0", true}, {"em0", true}, {"fab0", true}, {"fab1", true},
		// Currently in the class — see the file header. If a later change
		// narrows the class these flip, and that edit should be deliberate.
		{"emu0", true}, {"embed0", true}, {"fabric0", true}, {"fxpanel0", true},
		{"ge-0/0/0", false}, {"reth0", false}, {"lo0", false}, {"", false},
		{"e0", false}, {"f0", false},
	} {
		if got := IsManagementIfName(tc.name); got != tc.want {
			t.Errorf("IsManagementIfName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestIPMonNextHopAgreesWithManagementSSOT7515 binds the AGREEMENT, not a
// literal: for every name in the shared table, the ip-monitoring validator
// refuses the next-hop as a management interface exactly when
// IsManagementIfName says it is one.
//
// That refusal is only truthful while it matches the class the daemon actually
// binds to vrf-mgmt — the binding is WHY the lease is excluded from FRR, which
// is the whole reason such an interface cannot back a preferred route.
//
// FAIL-ON-REVERT: restore the raw prefix list at the validator and this stays
// green only while the two happen to coincide; narrow either side alone and it
// reds. That is the point — it fails on DIVERGENCE, in either direction.
func TestIPMonNextHopAgreesWithManagementSSOT7515(t *testing.T) {
	for _, name := range mgmtIfNameCases7515 {
		if name == "" || strings.ContainsAny(name, "/") {
			continue // an ifd with a port path needs a different fixture shape
		}
		lines := []string{
			"set services rpm probe WAN test wan-a probe-type icmp-ping",
			"set services rpm probe WAN test wan-a target address 1.1.1.1",
			"set services rpm probe WAN test wan-a destination-interface " + name + ".0",
			"set services rpm probe WAN test wan-a next-hop 172.16.50.1",
			"set interfaces " + name + " unit 0 family inet dhcp",
			"set services ip-monitoring policy p match rpm-probe WAN",
			"set services ip-monitoring policy p then preferred-route route 0.0.0.0/0 next-hop " + name + ".0",
		}
		tree := buildTree(t, lines)
		_, err := CompileConfig(tree)
		refusedAsMgmt := err != nil && strings.Contains(err.Error(), "names a management interface")
		if want := IsManagementIfName(name); refusedAsMgmt != want {
			t.Errorf("%s: ip-monitoring refuses-as-management = %v, but IsManagementIfName = %v. "+
				"The validator's message claims the lease is excluded from FRR; that is only "+
				"true while it agrees with the class the daemon binds to vrf-mgmt (#7515). err=%v",
				name, refusedAsMgmt, want, err)
		}
	}
}
