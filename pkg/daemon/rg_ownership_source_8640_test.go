package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #8640: which SOURCE the proxy-ARP ownership gate asks.
//
// The VRRP-derived `Ownership()` answers Unknown as a STEADY STATE on a real
// cluster — `vrrpInstances` is fed only by VRRP state-change events and nothing
// seeds it from current state. Measured on the loss userspace cluster:
// `vrrp-master=none` for every redundancy group while the same output reported
// `node0 primary / node1 secondary`, and ten fresh ARP probes for a pool
// address were answered by BOTH nodes. Suppression that only fires on an
// affirmative not-owner therefore never fired, and #8621's responder made that
// observable by being the first thing that answered at all.

// rgOwnershipDaemon builds a daemon whose cluster manager reports `state` for
// rgID, with no VRRP instances — i.e. exactly the cluster this was measured on.
func rgOwnershipDaemon(t *testing.T, rgID int, state cluster.NodeState) *Daemon {
	t.Helper()
	mgr := cluster.NewManager(0, 1)
	mgr.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: rgID, NodePriorities: map[int]int{0: 200}},
		},
	})
	mgr.SetGroupStateForTesting(rgID, state)
	return &Daemon{cluster: mgr}
}

// The defect, directly: a SECONDARY node must not answer, even though the
// VRRP-derived signal is Unknown and would have answered.
//
// RED ON REVERT: drop the clusterRGOwnership consultation from
// proxyARPSuppressedForRG and this fails, because the fallback returns Unknown
// -> not suppressed -> the standby answers with its own per-node RETH virtual
// MAC and draws pool return traffic it cannot forward (the #8405 misdelivery).
func TestASecondaryNodeSuppressesProxyARPEvenWithNoVRRPInstances8640(t *testing.T) {
	d := rgOwnershipDaemon(t, 1, cluster.StateSecondary)

	// PRECONDITION: the VRRP-derived path must be Unknown here, or this cell
	// proves nothing about which source is consulted.
	if got := d.rgOwnershipFor(1); got != rgOwnershipUnknown {
		t.Fatalf("fixture: VRRP-derived ownership = %v, want rgOwnershipUnknown. "+
			"With any other value this cell cannot tell the two sources apart",
			got)
	}

	if !d.proxyARPSuppressedForRG(1) {
		t.Fatal("a SECONDARY node did not suppress proxy-ARP. It answers with its " +
			"own per-node RETH virtual MAC while the primary holds the address, so " +
			"an upstream can bind the pool address to the wrong node — the #8405 " +
			"misdelivery, through the gate meant to prevent it")
	}
}

// The other side, and the one that stops the fix from being an outage: a
// PRIMARY node must answer. Without this, suppressing unconditionally passes
// the cell above — and silencing every node is the bigger defect by #8297's
// own reasoning, and is the outage #8621 fixed.
func TestAPrimaryNodeStillAnswers8640(t *testing.T) {
	d := rgOwnershipDaemon(t, 1, cluster.StatePrimary)
	if d.proxyARPSuppressedForRG(1) {
		t.Fatal("the PRIMARY node suppressed proxy-ARP for its own RG — nothing " +
			"would answer for the pool address, which is exactly the silence #8621 " +
			"was filed to fix")
	}
}

// The fallback. Where the cluster manager cannot answer, behaviour must be
// EXACTLY pre-#8640: the VRRP-derived signal, fail-open on Unknown. A fix that
// silenced a standalone node, or a cluster whose manager does not track the RG,
// would be a regression dressed as a fix.
func TestTheFallbackPreservesPreFixBehaviour8640(t *testing.T) {
	t.Run("no cluster manager at all", func(t *testing.T) {
		d := &Daemon{}
		if d.proxyARPSuppressedForRG(1) {
			t.Fatal("suppressed with no cluster manager: a standalone node would " +
				"stop answering for its own proxy-arp addresses")
		}
	})

	t.Run("cluster manager does not track this RG", func(t *testing.T) {
		d := rgOwnershipDaemon(t, 1, cluster.StatePrimary)
		// Ask about a DIFFERENT rg the manager knows nothing about.
		if d.proxyARPSuppressedForRG(7) {
			t.Fatal("suppressed for an RG the cluster manager does not track; the " +
				"fallback must answer, not silence")
		}
	})

	t.Run("VRRP says not-owner and the cluster cannot answer", func(t *testing.T) {
		d := &Daemon{}
		st := d.getOrCreateRGState(3)
		st.mu.Lock()
		st.vrrpInstances = map[string]bool{"reth0.80": false}
		st.mu.Unlock()
		if !d.proxyARPSuppressedForRG(3) {
			t.Fatal("the VRRP-derived not-owner no longer suppresses; the fallback " +
				"path lost its power rather than being preserved")
		}
	})
}

// rgID <= 0 is unchanged: an interface in no redundancy group has no ownership
// question, and must answer regardless of any cluster state.
func TestAnInterfaceInNoRedundancyGroupAlwaysAnswers8640(t *testing.T) {
	d := rgOwnershipDaemon(t, 0, cluster.StateSecondary)
	if d.proxyARPSuppressedForRG(0) {
		t.Fatal("suppressed for rgID 0 — an interface in no redundancy group")
	}
}
