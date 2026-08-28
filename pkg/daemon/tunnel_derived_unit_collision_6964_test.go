package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCollectAppliedTunnelsCollapsesDerivedUnitDevice_6964 is the ROUTING-LAYER
// consequence behind the #6964 commit gate, and it is why that gate rejects
// rather than warns on the strict path.
//
// The fixture is built through the REAL config path (ParseSetCommand ->
// SetPath -> CompileConfigLenient), never a *TunnelConfig struct literal, so
// every Name asserted below is the one the compiler assigns — a literal fixture
// would only prove that a literal round-trips.
//
// CompileConfigLenient rather than CompileConfig deliberately: the strict path
// now REJECTS this shape, and the tolerant load / peer-sync path is exactly the
// population that keeps producing it (an already-committed config that predates
// the gate). The tolerant path WARNS; it does not repair. So the damage below is
// what a grandfathered config still hands to the routing manager.
//
// pkg/routing keys ALL of its per-device state by TunnelConfig.Name
// (pkg/routing/tunnel.go): the desired/owned set (`desired[tc.Name] = true`),
// the applied-address set (appliedAddrs[tc.Name]), the VRF claim
// (appliedRI[tc.Name]) and the keepalive runner. So two records with one Name
// collapse to ONE entry in `desired` and then reconcile the SAME device TWICE
// in one Apply: the second pass's reconcileLinkAddrsLocked AddrDels every
// non-link-local address on the device that is absent from the second record's
// Addresses, so the two records delete each other's addresses off the shared
// device, and its VRF claim and keepalive are rewritten on top.
//
// Not the endpoint-comparing LinkDel+LinkAdd in applyKernelTunnelLocked —
// that is the standalone-CLI path. The daemon always sets AnchorOnly, where
// anchorReusable ignores tunnel endpoints and the TUN is reused in place.
//
// The ORDER is not stable: collectAppliedTunnels walks the
// cfg.Interfaces.Interfaces MAP, and both orders were observed within a single
// process (measured 174/26 over 200 calls). That ordering is deliberately NOT
// asserted here — a randomized-order assertion is flaky by construction. What
// is asserted is the deterministic defect it rests on: two records, one device
// name, distinguishable intents.
func TestCollectAppliedTunnelsCollapsesDerivedUnitDevice_6964(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, s := range []string{
		// Interface authored literally as the derived device name of the unit
		// below. Endpoints differ from the unit's ON PURPOSE: identical
		// endpoints would make the collapse onto one device invisible, and
		// every assertion here would hold on a correct config too.
		"set interfaces gr-0/0/0u1 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0u1 tunnel destination 10.0.0.2",
		"set interfaces gr-0/0/0 unit 1 tunnel source 10.1.0.1",
		"set interfaces gr-0/0/0 unit 1 tunnel destination 10.1.0.2",
	} {
		path, err := config.ParseSetCommand(s)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", s, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", s, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must not reject a grandfathered config: %v", err)
	}

	tunnels := collectAppliedTunnels(cfg)
	if len(tunnels) != 2 {
		t.Fatalf("collectAppliedTunnels returned %d records, want 2 (the fixture must produce BOTH conflicting intents or the collapse is untested): %+v", len(tunnels), tunnels)
	}
	if tunnels[0].Name != tunnels[1].Name {
		t.Fatalf("fixture no longer collides: device names %q and %q — the collapse this test documents is not being exercised", tunnels[0].Name, tunnels[1].Name)
	}
	if tunnels[0].Name != "gr-0-0-0u1" {
		t.Errorf("shared device name = %q, want %q", tunnels[0].Name, "gr-0-0-0u1")
	}
	// The two intents must be DISTINGUISHABLE, or "one device, two intents"
	// would be unobservable and this cell could not fail on a correct config.
	if tunnels[0].Source == tunnels[1].Source || tunnels[0].Destination == tunnels[1].Destination {
		t.Fatalf("fixture is blind: both records carry src=%q dst=%q, so one device serving two intents looks identical to one correct record",
			tunnels[0].Source, tunnels[0].Destination)
	}
	got := map[string]string{tunnels[0].Source: tunnels[0].Destination, tunnels[1].Source: tunnels[1].Destination}
	for src, dst := range map[string]string{"10.0.0.1": "10.0.0.2", "10.1.0.1": "10.1.0.2"} {
		if got[src] != dst {
			t.Errorf("device %q is missing the intent src=%s dst=%s; collected = %+v", tunnels[0].Name, src, dst, got)
		}
	}
}
