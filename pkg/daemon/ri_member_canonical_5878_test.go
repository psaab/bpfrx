package daemon

import "testing"

// #5878 phase 2 — the daemon netlink VRF/tunnel-membership resolver
// (riMemberLinuxName) must resolve a routing-instance member on its CANONICAL
// logical-unit identity, so a `.01` alias member binds the SAME Linux device as
// the canonical `.1` (and as the interface's `unit 1`). Without this, a
// peer-only `groups node1 { routing-instances ri interface ge-0/0/0.01 }`
// reference — which the P1 alias gate never sees (it gates unit DEFINITIONS, not
// membership REFERENCES) — resolves to "ge-0-0-0.01" on the standby vs
// "ge-0-0-0.1" on the active: the #5878 HA-divergence class at the netlink layer.
//
// Fail-on-revert: drop the CanonicalInterfaceUnitRef call in riMemberLinuxName
// and the `.01` cases resolve to the raw "...01" name != the canonical, so the
// equality assertions go RED.
func TestRIMemberLinuxNameCanonicalizesUnitAlias5878(t *testing.T) {
	// TunnelNameMap keys are built from the canonical int unit number, so the map
	// carries only the canonical spelling. The `.01` alias must still hit it.
	tunMap := map[string]string{
		"gr-0/0/0.1": "gr-0-0-0u1",
	}

	// Tunnel path (tunMap hit): `.01` and `.1` resolve to the SAME per-unit
	// device via the canonical key.
	if got := riMemberLinuxName(nil, tunMap, "gr-0/0/0.01"); got != "gr-0-0-0u1" {
		t.Errorf("riMemberLinuxName(.01, tunnel) = %q, want gr-0-0-0u1 (canonical .1 device)", got)
	}
	if a, b := riMemberLinuxName(nil, tunMap, "gr-0/0/0.01"), riMemberLinuxName(nil, tunMap, "gr-0/0/0.1"); a != b {
		t.Errorf("tunnel path: .01 -> %q, .1 -> %q — must be identical", a, b)
	}

	// Non-tunnel path (LinuxIfName): `.01` resolves to the canonical
	// "ge-0-0-0.1", NOT the raw "ge-0-0-0.01".
	if got := riMemberLinuxName(nil, nil, "ge-0/0/0.01"); got != "ge-0-0-0.1" {
		t.Errorf("riMemberLinuxName(.01, non-tunnel) = %q, want ge-0-0-0.1", got)
	}
	if a, b := riMemberLinuxName(nil, nil, "ge-0/0/0.01"), riMemberLinuxName(nil, nil, "ge-0/0/0.1"); a != b {
		t.Errorf("non-tunnel path: .01 -> %q, .1 -> %q — must be identical", a, b)
	}

	// A leading-zero unit 0 alias (`.00`) collapses to the base device, same as
	// the canonical `.0` unit-0 collapse.
	if got := riMemberLinuxName(nil, nil, "ge-0/0/1.00"); got != "ge-0-0-1" {
		t.Errorf("riMemberLinuxName(.00, non-tunnel) = %q, want ge-0-0-1 (unit-0 collapse)", got)
	}

	// Regression: canonical / bare / unit>0 spellings are unchanged.
	noRegression := map[string]string{
		"gr-0/0/0.0": "gr-0-0-0",   // unit-0 collapse
		"gr-0/0/0":   "gr-0-0-0",   // bare
		"ge-0/0/1.5": "ge-0-0-1.5", // non-tunnel unit>0 canonical
	}
	for in, want := range noRegression {
		if got := riMemberLinuxName(nil, nil, in); got != want {
			t.Errorf("riMemberLinuxName(%q) = %q, want %q (no regression)", in, got, want)
		}
	}
}
