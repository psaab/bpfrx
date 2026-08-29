package cluster

import "testing"

// #7178: a node whose forwarding dataplane is not armed must stop outbidding a
// peer that IS armed — but must NOT demote itself out of the running.
//
// The daemon expresses "not armed" as redundancy-group weight debt through the
// existing interface-monitor path, using DataplaneArmMonitorIface as a synthetic
// monitor. What this file pins is the WEIGHT ARITHMETIC that decision rests on,
// because the whole design is in the choice of cost:
//
//   - large enough that an armed peer at 255 wins the election, and
//   - NOT large enough to reach 0, so a STANDALONE unarmed node stays primary.
//
// The second half is the part that is easy to get wrong and impossible to see
// afterwards. Driving the weight to 0 would demote a lone node too, and there
// the outcome differs in kind: nothing else takes the VIPs, so the only effect
// is to remove the addresses an operator may be reaching the box on. #5275
// already closed kernel transit forwarding on an unarmed node while deliberately
// keeping management up — the node is a black hole for transit either way, and
// demoting it standalone removes the repair path without removing the black hole.

func TestUnarmedDataplaneDebtLeavesTheNodeEligible7178(t *testing.T) {
	w := rgWeightFromDebt(DataplaneArmMonitorCost)
	if w == 0 {
		t.Fatalf("an unarmed dataplane drove the RG weight to 0. That demotes a STANDALONE "+
			"node as well as a clustered one, and a lone node that gives up its VIPs does not "+
			"become safe — it becomes absent, with nothing to take them and possibly no "+
			"address left for the operator to reach it on (#7178). cost=%d weight=%d",
			DataplaneArmMonitorCost, w)
	}
	if w != 1 {
		t.Errorf("unarmed weight = %d, want exactly 1 — the floor, mirroring the VRRP "+
			"track-interface priority-cost clamp of [1,254] where 'demoted' means the bottom "+
			"of the range and never out of it", w)
	}
}

// The other half: the debt must actually be enough to lose. A cost that left the
// node competitive would satisfy the floor assertion above while never handing
// over to the peer, which is the entire point of the change.
func TestUnarmedNodeLosesToAnArmedPeer7178(t *testing.T) {
	unarmed := rgWeightFromDebt(DataplaneArmMonitorCost)
	armed := rgWeightFromDebt(0)
	if armed != maxRedundancyGroupWeight {
		t.Fatalf("precondition: an armed node with no monitor debt must carry the full "+
			"weight, got %d", armed)
	}
	if unarmed >= armed {
		t.Errorf("unarmed weight %d is not below armed weight %d, so an unarmed node would "+
			"still outbid a peer that can actually forward — it would keep taking the RETH "+
			"VIPs and attracting traffic it drops (#7178)", unarmed, armed)
	}
}

// The synthetic monitor name must not be able to collide with a configured
// track-interface entry, or a real interface going down would be conflated with
// an unarmed dataplane and vice versa — two different faults sharing one debt
// slot, with whichever wrote last winning.
func TestDataplaneArmMonitorNameCannotCollide7178(t *testing.T) {
	for _, illegal := range []string{"ge-0/0/0", "ge-0-0-0", "reth0", "reth0.50", "em0", "fxp0", ""} {
		if DataplaneArmMonitorIface == illegal {
			t.Fatalf("the synthetic monitor name %q collides with a nameable interface",
				DataplaneArmMonitorIface)
		}
	}
	// A Junos or Linux interface name never contains '/' twice nor leading
	// underscores; the sentinel shape is what makes the collision impossible
	// rather than merely unlikely.
	if len(DataplaneArmMonitorIface) < 3 ||
		DataplaneArmMonitorIface[0] != '_' || DataplaneArmMonitorIface[1] != '_' {
		t.Errorf("the synthetic monitor name %q must be an obvious non-interface sentinel "+
			"so it cannot be produced by any config path", DataplaneArmMonitorIface)
	}
}
