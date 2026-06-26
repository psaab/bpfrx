package vrrp

import (
	"testing"
	"time"
)

// #2940: in strict-vip-ownership mode, becoming RG primary calls
// SetGARPSuppression(rgID, false). If the VRRP instance is ALREADY in
// StateMaster (it briefly won the election before this node was promoted to RG
// primary), merely storing suppress=false does NOT trigger any state
// transition, so becomeMaster's GARP/NA burst never fires and the VIP stays
// silent — traffic blackholes until the periodic timer eventually announces it.
//
// The fix detects the true->false suppression EDGE (atomic Swap) and, while
// MASTER, fires a forced GARP/NA burst (force bypasses the 500ms dampener; the
// per-epoch dedup still applies). The burst is async (go sendGARP), matching
// becomeMaster, so these caller tests poll lastGARPEpoch — which sendGARP
// advances on a successful send — to observe the burst.

// managerWithMaster builds a Manager holding a single MASTER instance (no VIPs,
// so sendGARP performs no network I/O but still runs the gate + state-store)
// keyed under groupID 101 (rgID 1). garpEpoch is pre-bumped to 1 with
// lastGARPEpoch left at 0, mirroring a becomeMaster that ran while suppressed:
// the epoch was bumped but no GARP was emitted, so the epoch dedup will admit
// the unsuppress burst.
func managerWithMaster(t *testing.T, suppress bool) (*Manager, *vrrpInstance) {
	t.Helper()
	m := NewManager()
	vi := masterInstanceNoVIPs(t) // GroupID 101 -> rgID 1, state MASTER
	vi.garpEpoch.Store(1)
	vi.lastGARPEpoch.Store(0)
	vi.suppressGARP.Store(suppress)

	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: vi.cfg.Interface, groupID: 101}: vi,
	}
	m.mu.Unlock()
	return m, vi
}

// waitEpoch polls until lastGARPEpoch reaches want or the deadline elapses.
func waitEpoch(vi *vrrpInstance, want uint64) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if vi.lastGARPEpoch.Load() == want {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return vi.lastGARPEpoch.Load() == want
}

// TestSetGARPSuppressionUnsuppressForcesGARPWhileMaster is the core #2940
// regression: lifting suppression on an already-MASTER instance must emit a
// forced GARP/NA burst. With the pre-fix Store (no edge-detect burst) the
// async sendGARP never runs and lastGARPEpoch never advances — this test fails.
func TestSetGARPSuppressionUnsuppressForcesGARPWhileMaster(t *testing.T) {
	m, vi := managerWithMaster(t, true /* suppressed */)

	m.SetGARPSuppression(1, false)

	if !waitEpoch(vi, 1) {
		t.Fatalf("unsuppress while MASTER did NOT emit a forced GARP/NA burst: "+
			"lastGARPEpoch = %d, want 1 (#2940: the suppression edge must fire "+
			"sendGARP(true) so the VIP is not blackholed on promotion)",
			vi.lastGARPEpoch.Load())
	}
}

// TestSetGARPSuppressionUnsuppressDefeatsDampener proves the unsuppress burst
// is forced: even with a routine GARP recorded 100ms ago (well inside the 500ms
// dampen window) the burst must still fire. A non-forced send here would be
// dampened.
func TestSetGARPSuppressionUnsuppressDefeatsDampener(t *testing.T) {
	m, vi := managerWithMaster(t, true)
	vi.lastGARPTime.Store(time.Now().Add(-100 * time.Millisecond).UnixNano())

	m.SetGARPSuppression(1, false)

	if !waitEpoch(vi, 1) {
		t.Fatalf("unsuppress burst was dampened: lastGARPEpoch = %d, want 1 — the "+
			"#2940 burst must use force=true to bypass the 500ms dampener",
			vi.lastGARPEpoch.Load())
	}
}

// TestSetGARPSuppressionReapplyFalseDoesNotReburst confirms the burst is
// EDGE-only: re-applying suppress=false when it is already false must NOT emit
// another burst (Swap returns old=false, so the edge condition is not met).
func TestSetGARPSuppressionReapplyFalseDoesNotReburst(t *testing.T) {
	m, vi := managerWithMaster(t, false /* already unsuppressed */)

	m.SetGARPSuppression(1, false)

	// Give any erroneous async burst a chance to run before asserting.
	time.Sleep(50 * time.Millisecond)
	if got := vi.lastGARPEpoch.Load(); got != 0 {
		t.Fatalf("re-applying suppress=false (no edge) emitted a GARP burst: "+
			"lastGARPEpoch = %d, want 0 — the burst must fire only on the "+
			"true->false transition", got)
	}
}

// TestSetGARPSuppressionUnsuppressNoBurstWhenNotMaster confirms an instance not
// in StateMaster does not burst on unsuppress: there is no VIP to announce, and
// the eventual becomeMaster transition will send GARP itself.
func TestSetGARPSuppressionUnsuppressNoBurstWhenNotMaster(t *testing.T) {
	m, vi := managerWithMaster(t, true)
	vi.setState(StateBackup)

	m.SetGARPSuppression(1, false)

	time.Sleep(50 * time.Millisecond)
	if got := vi.lastGARPEpoch.Load(); got != 0 {
		t.Fatalf("unsuppress on a non-MASTER instance emitted a GARP burst: "+
			"lastGARPEpoch = %d, want 0", got)
	}
	// The flag must still have been updated regardless.
	if vi.suppressGARP.Load() {
		t.Fatal("suppressGARP should be false after SetGARPSuppression(false)")
	}
}

// TestSetGARPSuppressionSuppressDoesNotBurst confirms the false->true direction
// (entering suppression) never emits a burst.
func TestSetGARPSuppressionSuppressDoesNotBurst(t *testing.T) {
	m, vi := managerWithMaster(t, false)

	m.SetGARPSuppression(1, true)

	time.Sleep(50 * time.Millisecond)
	if got := vi.lastGARPEpoch.Load(); got != 0 {
		t.Fatalf("entering suppression emitted a GARP burst: lastGARPEpoch = %d, want 0", got)
	}
	if !vi.suppressGARP.Load() {
		t.Fatal("suppressGARP should be true after SetGARPSuppression(true)")
	}
}
