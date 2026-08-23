package vrrp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6781: the VRRP-backed and direct RETH ownership modes disagreed about which
// interfaces own a redundancy group, and BOTH readings were wrong — in opposite
// directions. Measured on configs that committed cleanly:
//
//	shape A  `ge-0/0/5 redundant-ether-options redundancy-group 1`, nothing
//	         naming it as a redundant-parent.
//	         VRRP-backed INCLUDED it (RedundancyGroup > 0 alone) and made the
//	         interface's OWN address a VIP — present only while MASTER.
//	         direct EXCLUDED it (strings.HasPrefix name, "reth")).
//	         networkd meanwhile replaced that address with a link-local /32, so
//	         under `no-reth-vrrp` NOBODY installed it, on either node.
//
//	shape B  `bond0 redundant-ether-options redundancy-group 1` with
//	         `ge-0/0/1 gigether-options redundant-parent bond0` — a
//	         structurally valid redundant pair not spelled "reth*".
//	         VRRP-backed resolved it correctly; direct returned NOTHING, so the
//	         group had no VIPs at all.
//
// Both modes now resolve ownership through the one shared predicate
// (config.Config.RethRGOwners), so they agree by construction. These are the
// BEHAVIOURAL half of the binding; the structural half (that they still read
// from one place) is reth_rg_ssot_6781_test.go.
//
// FAIL-ON-REVERT: restore either reading — the bare `RedundancyGroup > 0` in
// CollectRethInstances, or the `HasPrefix(name,"reth")` filter in
// RethVIPsForRG — and the corresponding shape's subtest reports the two modes
// disagreeing, naming which included and which excluded.

func compileRethCfg(t *testing.T, lines []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range lines {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	// The tolerant path: shape A is rejected at strict commit
	// (validateRethRedundancyGroupStrict), and the point of this test is that
	// the two RUNTIME modes agree on a config that reached them anyway.
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick (#1960): %v", err)
	}
	return cfg
}

func rethParityBase() []string {
	return []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6781",
		"set chassis cluster reth-count 2",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
	}
}

// modeVerdicts returns whether each ownership mode considers ANY interface to
// own RG 1, plus what each resolved to, for reporting.
func modeVerdicts(cfg *config.Config) (vrrpOwns, directOwns bool, vrrpNames []string, directMap map[string][]string) {
	for _, inst := range CollectRethInstances(cfg, map[int]int{1: 200}) {
		vrrpNames = append(vrrpNames, inst.Interface)
	}
	directMap = RethVIPsForRG(cfg, 1)
	return len(vrrpNames) > 0, len(directMap) > 0, vrrpNames, directMap
}

func TestRethOwnershipModesAgree(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lines     []string
		wantOwned bool
		why       string
	}{
		{
			name: "shape-A/redundancy-group-on-a-non-reth",
			lines: append(rethParityBase(),
				"set interfaces ge-0/0/5 redundant-ether-options redundancy-group 1",
				"set interfaces ge-0/0/5 unit 0 family inet address 10.0.99.1/24",
			),
			wantOwned: false,
			why: "ge-0/0/5 is neither structurally nor nominally a reth, so " +
				"neither mode may claim it — claiming it turns the interface's " +
				"own address into a MASTER-only VIP",
		},
		{
			name: "shape-B/structurally-valid-pair-not-named-reth",
			lines: append(rethParityBase(),
				"set interfaces ge-0/0/1 gigether-options redundant-parent bond0",
				"set interfaces bond0 redundant-ether-options redundancy-group 1",
				"set interfaces bond0 unit 0 family inet address 10.0.61.1/24",
			),
			wantOwned: true,
			why: "ports name bond0 as their redundant-parent, so it IS a " +
				"redundant-ethernet interface and both modes must own it — " +
				"excluding it leaves the group with no VIPs at all",
		},
		{
			name: "control/conventional-reth",
			lines: append(rethParityBase(),
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
				"set interfaces reth0 redundant-ether-options redundancy-group 1",
				"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
			),
			wantOwned: true,
			why:       "the ordinary shape must keep working unchanged",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileRethCfg(t, tc.lines)
			vrrpOwns, directOwns, vrrpNames, directMap := modeVerdicts(cfg)

			// THE agreement assertion: the two modes reach the same conclusion.
			if vrrpOwns != directOwns {
				t.Fatalf("the two RETH ownership modes DISAGREE: "+
					"VRRP-backed owns=%v (%v), direct owns=%v (%v).\n%s",
					vrrpOwns, vrrpNames, directOwns, directMap, tc.why)
			}
			// …and that the conclusion they agree on is the right one. Without
			// this, both modes returning nothing would pass the check above.
			if vrrpOwns != tc.wantOwned {
				t.Errorf("both modes agree owned=%v, want %v.\n%s",
					vrrpOwns, tc.wantOwned, tc.why)
			}
		})
	}
}

// TestRethRGOwnersIsTheDiscriminator pins the PROPERTY the agreement rests on,
// so the two modes cannot be made to agree on a WRONG answer: ownership is
// decided by being a redundant-ethernet interface structurally or nominally,
// never by the redundancy-group value alone.
func TestRethRGOwnersIsTheDiscriminator(t *testing.T) {
	cfg := compileRethCfg(t, append(rethParityBase(),
		"set interfaces ge-0/0/1 gigether-options redundant-parent bond0",
		"set interfaces bond0 redundant-ether-options redundancy-group 1",
		"set interfaces bond0 unit 0 family inet address 10.0.61.1/24",
		"set interfaces ge-0/0/5 redundant-ether-options redundancy-group 1",
		"set interfaces ge-0/0/5 unit 0 family inet address 10.0.99.1/24",
	))
	owners := cfg.RethRGOwners()
	if _, ok := owners["bond0"]; !ok {
		t.Errorf("bond0 has member ports and must own its group; owners=%v", owners)
	}
	if _, ok := owners["ge-0/0/5"]; ok {
		t.Errorf("ge-0/0/5 has no member ports and is not named reth*; it must "+
			"NOT own a group; owners=%v", owners)
	}
}

// TestCollectRethInstancesSkipsGroupZero pins the `> 0` guard that lives at the
// CALLER rather than in the shared predicate (see Config.RethRGOwners).
//
// RG 0 is the control-plane group and an UNSET redundancy-group also reads as
// 0, so a reth carrying neither must get no VRRP instance. Without the guard
// every reth with an unset group would be handed VRID 100 (RethVRRPGroupIDBase
// + 0) and start advertising — while the direct collector, which is
// legitimately queried FOR group 0, must still answer for that same reth. The
// two needs differ, which is exactly why the term is not in the predicate.
//
// FAIL-ON-REVERT: drop `|| rgID <= 0` from CollectRethInstances and this reds.
func TestCollectRethInstancesSkipsGroupZero(t *testing.T) {
	cfg := compileRethCfg(t, append(rethParityBase(),
		// A structurally real reth with NO redundancy-group line: rgID 0.
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
	))

	// Precondition: the shared predicate DOES own it (at group 0), so the
	// assertion below is about the caller's guard and not about the predicate
	// having quietly dropped the interface.
	owners := cfg.RethRGOwners()
	if rg, ok := owners["reth0"]; !ok || rg != 0 {
		t.Fatalf("fixture: reth0 should be owned at group 0, got rg=%d ok=%v "+
			"(owners=%v)", rg, ok, owners)
	}

	if insts := CollectRethInstances(cfg, map[int]int{0: 200}); len(insts) != 0 {
		var got []string
		for _, i := range insts {
			got = append(got, i.Interface)
		}
		t.Errorf("CollectRethInstances synthesized %d instance(s) %v for "+
			"redundancy-group 0; RG 0 is the control-plane group and an unset "+
			"group reads as 0, so no RETH VRRP instance may be created for it",
			len(insts), got)
	}

	// The direct collector, by contrast, must still answer for group 0 — the
	// asymmetry the caller-side guard exists to preserve.
	if vips := RethVIPsForRG(cfg, 0); len(vips) == 0 {
		t.Errorf("RethVIPsForRG(0) returned nothing; the direct mode is " +
			"legitimately queried for group 0 and must still resolve the reth")
	}
}
