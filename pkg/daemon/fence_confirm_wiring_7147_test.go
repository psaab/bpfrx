package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

// #7147 — the daemon half of the confirmed peer fence.
//
// Both directions are silent when unwired, which is why they get their own
// assertions:
//
//   - if SetPeerFenceConfirmFunc is never called, `disable-rg-confirmed`
//     degrades to "Fence skipped: sync not available" on EVERY takeover. That
//     path fails open, so the cluster keeps working and nothing observable
//     breaks — the operator simply never gets the guarantee they configured.
//   - if OnFenceReceived returns a zero FenceResult, this node acks
//     `unavailable` even when it fenced perfectly, and its peer reports an
//     unconfirmed takeover forever.

// TestWireClusterFenceCallbacksInstallsConfirmFunc_7147 binds the OUTBOUND
// confirming sender. Asserting only that the best-effort SendFence is wired
// (the #6428 test above) leaves this one free to be dropped.
func TestWireClusterFenceCallbacksInstallsConfirmFunc_7147(t *testing.T) {
	src := readDaemonSource(t, "daemon_ha_comms_wiring.go")
	flat := strings.Join(strings.Fields(src), "")
	if !strings.Contains(flat, "d.cluster.SetPeerFenceConfirmFunc(ss.SendFenceAwait)") {
		t.Error("wireClusterFenceCallbacks does not install the #7147 confirming fence " +
			"sender. `peer-fencing disable-rg-confirmed` would then record " +
			"'Fence skipped: sync not available' on every takeover and gate nothing — " +
			"and because that path fails open, the cluster would look entirely healthy.")
	}
	if !strings.Contains(flat, "d.cluster.SetPeerFenceFunc(ss.SendFence)") {
		t.Error("the best-effort fence wiring this one is anchored beside has moved; " +
			"re-verify both senders are still installed together")
	}
}

// TestFenceHandlerReportsWhatItAchieved_7147 binds the INBOUND handler's
// return value. A handler that fenced correctly but returned the zero
// FenceResult would ack `unavailable`, and the peer would report every
// takeover as unconfirmed while everything actually worked.
func TestFenceHandlerReportsWhatItAchieved_7147(t *testing.T) {
	d := newWiringTestDaemon()
	ss := newWiringTestSessionSync()
	d.wireClusterFenceCallbacks(t.Context(), ss)

	if ss.OnFenceReceived == nil {
		t.Fatal("wireClusterFenceCallbacks did not install ss.OnFenceReceived")
	}

	// This fixture has no published dataplane, so the honest answer is
	// "unavailable" — NOT a vacuous 0-of-0 success. That distinction is the
	// whole reason FenceResult carries DataplaneAvailable separately from the
	// counts, so it is asserted rather than assumed.
	got := ss.OnFenceReceived()
	if got.DataplaneAvailable {
		t.Errorf("a daemon with no published dataplane reported DataplaneAvailable: %+v", got)
	}
	if st := got.Status(); st != cluster.FenceAckUnavailable {
		t.Errorf("Status() = %d, want FenceAckUnavailable (%d). Reporting OK here would "+
			"tell the surviving node this peer is safely dark when it never even "+
			"attempted a deactivation.", st, cluster.FenceAckUnavailable)
	}
	if got.Status() == cluster.FenceAckOK {
		t.Error("a config-only node CONFIRMED a fence it could not perform")
	}
}
