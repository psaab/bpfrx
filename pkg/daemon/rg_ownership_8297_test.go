package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8297/#8342: the three-state ownership answer, and specifically that the
// UNKNOWN case is not the same as NOT-OWNER.
//
// #8314 gated proxy-ARP on AllVRRPMaster, which folds "no instances known" into
// false. The measured consequence was `fw0=0 fw1=0` — proxy-ARP installed on
// NEITHER node, so nothing answered for the NAT pool address and every
// documented use of the feature went dark. The failure moved from two answerers
// to zero, which is worse.
//
// The middle row is the point of this table. A two-state predicate satisfies
// the owner and not-owner rows perfectly and is still wrong, because the row it
// cannot express is the one that caused the outage.
func TestRGOwnershipDistinguishesUnknownFromNotOwner8297(t *testing.T) {
	for _, tc := range []struct {
		name      string
		instances map[string]bool
		want      rgOwnership
		why       string
	}{
		{"all instances master", map[string]bool{"reth0": true, "reth1": true},
			rgOwnershipOwner, "this node owns the RG"},
		{"single instance master", map[string]bool{"reth0": true},
			rgOwnershipOwner, ""},
		{"one instance backup", map[string]bool{"reth0": true, "reth1": false},
			rgOwnershipNotOwner, "partial mastership is not ownership"},
		{"all instances backup", map[string]bool{"reth0": false},
			rgOwnershipNotOwner, "affirmatively another node's RG"},

		// THE ROW #8314 GOT WRONG. AllVRRPMaster returns false here, which a
		// bool consumer reads as "not owner" and suppresses on.
		{"NO instances known", map[string]bool{},
			rgOwnershipUnknown, "we cannot say who owns it — a bool cannot say this"},
		{"nil instance map", nil,
			rgOwnershipUnknown, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &rgStateMachine{vrrpInstances: tc.instances}
			if got := s.Ownership(); got != tc.want {
				t.Fatalf("Ownership() = %v, want %v. %s", got, tc.want, tc.why)
			}
			// And the bool it replaces: assert WHERE the two disagree, so the
			// reason this type exists is pinned rather than described.
			legacy := s.AllVRRPMaster()
			if tc.want == rgOwnershipUnknown && legacy {
				t.Fatal("premise broken: AllVRRPMaster is expected to be false on unknown")
			}
			if tc.want == rgOwnershipUnknown && !legacy {
				// This IS the divergence: legacy says "not master", Ownership
				// says "unknown". A consumer that suppresses on !legacy goes
				// silent here; one that suppresses only on NotOwner does not.
				t.Logf("divergence confirmed: AllVRRPMaster=false but Ownership=Unknown")
			}
		})
	}
}

// The consumer-facing gate: suppress ONLY on an affirmative not-owner.
//
// Both other rows are outage-shaped if they suppress, which is why they are
// asserted rather than left implied.
func TestProxyARPSuppressesOnlyOnAffirmativeNotOwner8297(t *testing.T) {
	mk := func(instances map[string]bool) *Daemon {
		d := &Daemon{}
		s := d.getOrCreateRGState(1)
		s.mu.Lock()
		s.vrrpInstances = instances
		s.mu.Unlock()
		return d
	}
	for _, tc := range []struct {
		name         string
		instances    map[string]bool
		rgID         int
		wantSuppress bool
		why          string
	}{
		{"not owner -> suppress", map[string]bool{"reth0": false}, 1, true,
			"the #8297 defect: the standby must stop answering"},
		{"owner -> answer", map[string]bool{"reth0": true}, 1, false,
			"the #8342 over-correction: the owner must KEEP answering"},
		{"unknown -> answer", map[string]bool{}, 1, false,
			"the exact #8314 failure — unknown must not silence the node"},
		{"rg 0 (no redundancy group) -> answer", map[string]bool{"reth0": false}, 0, false,
			"an interface in no RG has no ownership question; suppressing would " +
				"break proxy-ARP on every standalone box"},
		{"negative rg -> answer", nil, -1, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := mk(tc.instances)
			if got := d.proxyARPSuppressedForRG(tc.rgID); got != tc.wantSuppress {
				t.Fatalf("proxyARPSuppressedForRG(%d) = %v, want %v. %s",
					tc.rgID, got, tc.wantSuppress, tc.why)
			}
		})
	}
}

// FAIL-ON-REVERT for the WIRING (#8297).
//
// The three-state predicate is inert until proxyARPIfaceMapFiltered consults
// it. Deleting the `suppress != nil && suppress(...)` gate leaves every
// predicate assertion above GREEN while both nodes answer again — which is the
// original defect, and exactly the shape that let #8314's inverse survive
// review.
//
// Driven through the REAL map builder, not the predicate, so it binds the call
// site. The three rows are the three outcomes #8342 says must hold together:
// standby silent, owner answering, unknown answering.
func TestProxyARPIfaceMapConsultsTheOwnershipGate8297(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 1},
	}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "reth0.80", Addresses: []string{"172.16.80.7/32"}},
	}

	// The netdev lookup is not available in a unit test, so an entry that is
	// NOT suppressed lands in `unresolved` rather than `byJunos`. That is the
	// discriminator this cell uses: suppressed entries appear in NEITHER.
	for _, tc := range []struct {
		name           string
		suppress       func(string) bool
		wantConsidered bool
		why            string
	}{
		{"not owner: entry is dropped entirely",
			func(string) bool { return true }, false,
			"#8297 — the standby must stop answering"},
		{"owner: entry is considered",
			func(string) bool { return false }, true,
			"#8342 — the owner must KEEP answering"},
		{"nil predicate keeps pre-#8297 behaviour",
			nil, true,
			"non-daemon callers must be unaffected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			byJunos, names, unresolved := proxyARPIfaceMapFiltered(cfg, tc.suppress)
			considered := len(byJunos) > 0 || len(names) > 0 || len(unresolved) > 0
			if considered != tc.wantConsidered {
				t.Fatalf("entry considered = %v, want %v (byJunos=%v names=%v unresolved=%v). %s",
					considered, tc.wantConsidered, byJunos, names, unresolved, tc.why)
			}
			if !tc.wantConsidered && len(unresolved) > 0 {
				t.Fatalf("a SUPPRESSED entry must not be reported unresolved — "+
					"unresolved means 'retain the responder as debt' (#6536), which "+
					"would keep the standby answering; got %v", unresolved)
			}
		})
	}
}

// The RG resolution the gate depends on: an entry names a UNIT ref, the
// redundancy group lives on the base interface.
func TestProxyARPRedundancyGroupResolution8297(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0":    {Name: "reth0", RedundancyGroup: 1},
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
		"lo0":      {Name: "lo0"},
	}
	for _, tc := range []struct {
		ref  string
		want int
		why  string
	}{
		{"reth0.80", 1, "the unit suffix is trimmed; the group is on the base"},
		{"reth0", 1, ""},
		{"ge-0/0/2", 1, "a physical member inherits its reth parent's group"},
		{"lo0", 0, "an interface in no RG has no ownership question"},
		{"nonexistent", 0, "an unresolvable ref must ANSWER, like unknown ownership"},
	} {
		if got := proxyARPRedundancyGroupFor(cfg, tc.ref); got != tc.want {
			t.Errorf("proxyARPRedundancyGroupFor(%q) = %d, want %d. %s",
				tc.ref, got, tc.want, tc.why)
		}
	}
}
