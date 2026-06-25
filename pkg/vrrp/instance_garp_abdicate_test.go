package vrrp

import "testing"

// TestSendGARPStillMasterGate locks the semantics of the abdication gate that
// sendGARP passes into the cluster burst follow-up loops (#2867). The closure
// captures garpEpoch at burst start and must report "keep sending" ONLY while
// the node is still StateMaster AND the epoch is unchanged. It is the exact
// composition built in sendGARP (state == StateMaster && garpEpoch == epoch).
func TestSendGARPStillMasterGate(t *testing.T) {
	vi := &vrrpInstance{}
	vi.setState(StateMaster)
	epoch := vi.garpEpoch.Load()

	stillMaster := func() bool {
		return vi.getState() == StateMaster && vi.garpEpoch.Load() == epoch
	}

	if !stillMaster() {
		t.Fatal("gate must allow sends while master and epoch unchanged")
	}

	// Abdicate: master -> backup. The detached burst loop must stop.
	vi.setState(StateBackup)
	if stillMaster() {
		t.Fatal("gate must STOP the burst after abdication (master -> backup) — #2867")
	}

	// Back to master but a NEW burst superseded this one (epoch bumped, e.g.
	// ReconcileVIPs / a later becomeMaster). The stale loop must still stop so
	// it does not race the fresh burst with stale frames.
	vi.setState(StateMaster)
	vi.garpEpoch.Add(1)
	if stillMaster() {
		t.Fatal("gate must STOP the stale burst after a garpEpoch bump — #2867")
	}
}
