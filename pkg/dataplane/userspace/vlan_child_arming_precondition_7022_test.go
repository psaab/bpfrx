package userspace

import "testing"

// #7022: the README claim that a VLAN child "DOES arm
// `snapshotRequiresRefusalProtocol` even though it contributes nothing to any
// `netdevOwnerTally`" is true only under a precondition the doc did not state —
// the child's OWN netdev must be a live xfrm interface.
//
// This measures both sides of that precondition rather than transcribing it.
// `snapshotSecureTunnel` is `secureTunnelOwned(cfg, ref) || liveXfrm[netdev]`,
// so for a child the config does not own, the kernel half is the only way the
// flag lands on the CHILD row. When it does not, the flag lands on the BASE row
// instead — and a base row is not a VLAN child, so it is a counted contributor
// to a tally. A reader reproducing the claim without the precondition sees that
// second mechanism and concludes the doc is wrong when it is merely incomplete.
//
// Both rows are asserted in both directions in each case. Asserting only "the
// child is armed" in case (a) would pass against an implementation that armed
// every row, and only "the child is not armed" in case (b) would pass against
// one that armed none.
func TestVlanChildArmsOnlyWhenItsOwnNetdevIsLiveXfrm7022(t *testing.T) {
	const (
		lanIfindex   = 10
		xfrmiIfindex = 11
		childIfindex = 12
	)
	// Both the base and the VLAN child exist as netdevs, so which one the
	// kernel calls an xfrmi is the ONLY variable between the two cases.
	live := map[string]int{"ge-0-0-0": lanIfindex, "st10": xfrmiIfindex, "st10.100": childIfindex}

	for _, tc := range []struct {
		name string
		// xfrmNames is the kernel's answer to "which netdevs are xfrm?".
		xfrmNames []string
		wantBase  bool
		wantChild bool
		why       string
	}{
		{
			name:      "child is itself a live xfrmi (the README's shape)",
			xfrmNames: []string{"st10.100"},
			wantBase:  false,
			wantChild: true,
			why: "the VLAN child's own netdev is the xfrmi, so the child row " +
				"carries SecureTunnel and arms the refusal protocol while casting " +
				"no counted vote — which is the claim",
		},
		{
			name:      "only the base is a live xfrmi (the shape a reader hits by default)",
			xfrmNames: []string{"st10"},
			wantBase:  true,
			wantChild: false,
			why: "the arming comes from the BASE row, which is not a VLAN child " +
				"and DOES contribute to a netdevOwnerTally — a different mechanism " +
				"than the claim describes",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer stubLinkSnapshot5619(t, live)()
			defer stubXfrmNetdevs(t, tc.xfrmNames...)()

			cfg := compileForTest5619(t,
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
				"set interfaces st10 vlan-tagging",
				"set interfaces st10 unit 5 vlan-id 100",
				"set interfaces st10 unit 5 family inet address 192.0.2.1/24",
				"set security zones security-zone trust interfaces st10.5",
			)
			rows := buildInterfaceSnapshots(cfg)
			base, child := rowByName(t, rows, "st10"), rowByName(t, rows, "st10.5")

			// PREMISE: no IPsec vpn binds either ref, so `secureTunnelOwned` is
			// false for both and the kernel half is the only thing that can set
			// the flag. Without this the case rows would not be distinguishable
			// by the variable they claim to vary.
			if secureTunnelOwned(cfg, "st10") || secureTunnelOwned(cfg, "st10.5") {
				t.Fatal("premise broken: the config OWNS one of the refs, so the " +
					"config half of snapshotSecureTunnel decides and the kernel half " +
					"— the precondition under test — is not what varies")
			}
			// PREMISE: the child really is a VLAN child whose own netdev is
			// `st10.100`, or `liveXfrm` is being keyed on a name this row never
			// presents and case (a) would be vacuous.
			if child.LinuxName != "st10.100" {
				t.Fatalf("premise broken: the child's netdev is %q, want \"st10.100\" — "+
					"the kernel half keys on this name", child.LinuxName)
			}
			if child.ParentLinuxName != "st10" {
				t.Fatalf("premise broken: the child does not redirect onto the base "+
					"(ParentLinuxName=%q), so it is not the abstaining VLAN child the "+
					"claim is about", child.ParentLinuxName)
			}

			if base.SecureTunnel != tc.wantBase {
				t.Errorf("base row st10 SecureTunnel=%v, want %v: %s",
					base.SecureTunnel, tc.wantBase, tc.why)
			}
			if child.SecureTunnel != tc.wantChild {
				t.Errorf("VLAN child st10.5 SecureTunnel=%v, want %v: %s",
					child.SecureTunnel, tc.wantChild, tc.why)
			}
		})
	}
}
