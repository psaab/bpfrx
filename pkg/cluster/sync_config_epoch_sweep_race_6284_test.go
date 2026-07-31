package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #6284 item 2 — the residual sweep-vs-advance stale-permit race the #5274
// config-epoch guard left open.
//
// The config high-water (lastAppliedConfigGen) advances only AFTER
// OnConfigReceived returns nil, but the deleted-policy sweep
// (clearSessionsForDeletedPolicies) runs INSIDE OnConfigReceived. So there is a
// sub-µs window — sweep completed, high-water not yet advanced — in which a
// synced session install racing on the receiveLoop is compared against the
// STALE high-water and wrongly admitted, reviving a permit the just-run sweep
// invalidated.
//
// The apply-in-progress fence (applyingConfigGen, set for the whole apply)
// closes it: during the window configEpochStale refuses an older-epoch install
// against the generation being applied instead of the not-yet-advanced
// high-water. These tests drive the real configApplyLoop and perform the racing
// install AT the exact interleaving point (inside OnConfigReceived), so they
// deterministically reproduce the window. Reverting the fence (installs
// compared against lastAppliedConfigGen alone) admits the stale permit and they
// fail RED.
//
// The install writes the mock dataplane's plain session map on the
// configApplyLoop goroutine, so the admission OUTCOME is read on that same
// goroutine and handed to the test goroutine over a channel (a happens-before
// edge) rather than reading the map cross-goroutine — production installs run
// on the receiveLoop against the real locked dataplane, not this unsynchronized
// mock map.

// waitFenceCleared polls the apply-in-progress fence until it drops to 0 (the
// last atomic store on both the success and failure config-apply paths), so the
// post-apply high-water/fence assertions observe the completed apply without
// racing the loop. All accesses are atomic.
func waitFenceCleared(t *testing.T, s *SessionSync) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.applyingConfigGen.Load() == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("apply-in-progress fence never cleared (still %d)", s.applyingConfigGen.Load())
}

// windowProbe captures the state observed AT the racing-install interleaving
// point, inside OnConfigReceived (the sweep window).
type windowProbe struct {
	highWater     uint64
	fence         uint64
	staleAdmitted bool
	curAdmitted   bool
}

// TestConfigApplyFenceRefusesStaleInstallDuringSweep6284 is the v4 RED-on-revert
// test for item 2. Inside the gen-8 apply (fence raised, high-water still 5) a
// stale-epoch install (epoch 6, older than the applying gen but NEWER than the
// pre-apply high-water) must be REFUSED, while a current-epoch install
// (epoch 8) must still be ADMITTED — proving the fence refuses only
// strictly-older epochs and never falsely rejects a current-generation session.
func TestConfigApplyFenceRefusesStaleInstallDuringSweep6284(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", dp)

	// This node has already applied config generation 5.
	ss.lastAppliedConfigGen.Store(5)

	staleKey := configEpochKeyV4(46001) // epoch 6 < applying gen 8, > applied 5
	curKey := configEpochKeyV4(46002)   // epoch 8 == applying gen 8

	probeCh := make(chan windowProbe, 1)

	// OnConfigReceived models the config-apply body: the deleted-policy sweep
	// runs here, and two synced installs race in during the SAME window (after
	// the sweep, before the high-water advances). At this point the fence is
	// raised to gen 8 and the high-water is still 5.
	ss.OnConfigReceived = func(_ string) error {
		// STALE: epoch 6 is older than the generation being applied. Against
		// the not-yet-advanced high-water (5) it would be admitted; the fence
		// must refuse it (max(fence 8, high-water 5) = 8, and 6 < 8).
		installWithConfigEpochV4(ss, staleKey, 6)
		// CURRENT: epoch 8 equals the generation being applied — must be
		// admitted (equality is not staleness; the config still admits it).
		installWithConfigEpochV4(ss, curKey, 8)
		_, stale := dp.v4sessions[staleKey]
		_, cur := dp.v4sessions[curKey]
		probeCh <- windowProbe{
			highWater:     ss.lastAppliedConfigGen.Load(),
			fence:         ss.applyingConfigGen.Load(),
			staleAdmitted: stale,
			curAdmitted:   cur,
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ss.configApplyLoop(ctx)

	ss.configApplyCh <- configApplyItem{gen: 8, text: "config-C8"}

	p := <-probeCh
	// Sanity: the install genuinely raced the pre-advance window.
	if p.highWater != 5 {
		t.Fatalf("high-water advanced to %d before the apply completed — test not exercising the window", p.highWater)
	}
	if p.fence != 8 {
		t.Fatalf("apply-in-progress fence = %d, want 8 during the apply (fence not raised)", p.fence)
	}
	// The stale-epoch install racing the sweep MUST have been refused.
	if p.staleAdmitted {
		t.Fatal("stale-epoch install racing the config-apply sweep was admitted against the not-yet-advanced high-water (#6284 item-2 window)")
	}
	// The current-epoch install MUST have been admitted (no false rejection).
	if !p.curAdmitted {
		t.Fatal("current-epoch install (epoch 8 == applying gen 8) was wrongly refused by the fence")
	}
	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 1 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 1 (the fence refused the racing stale install)", got)
	}

	// After a successful apply the high-water advanced and the fence dropped.
	waitFenceCleared(t, ss)
	if got := ss.lastAppliedConfigGen.Load(); got != 8 {
		t.Fatalf("high-water must advance to 8 after a successful apply, got %d", got)
	}
}

// TestConfigApplyFenceRefusesStaleInstallDuringSweep6284V6 mirrors the guard on
// the v6 install path — configEpochStale is shared, but this proves the v6
// admission (installClusterSyncedV6) honors the fence identically.
func TestConfigApplyFenceRefusesStaleInstallDuringSweep6284V6(t *testing.T) {
	dp := &mockSweepDP{v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}}
	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", dp)
	ss.lastAppliedConfigGen.Store(5)

	staleKey := configEpochKeyV6(46101)
	curKey := configEpochKeyV6(46102)

	probeCh := make(chan windowProbe, 1)

	ss.OnConfigReceived = func(_ string) error {
		installWithConfigEpochV6(ss, staleKey, 6)
		installWithConfigEpochV6(ss, curKey, 8)
		_, stale := dp.v6sessions[staleKey]
		_, cur := dp.v6sessions[curKey]
		probeCh <- windowProbe{staleAdmitted: stale, curAdmitted: cur}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ss.configApplyLoop(ctx)

	ss.configApplyCh <- configApplyItem{gen: 8, text: "config-C8"}

	p := <-probeCh
	if p.staleAdmitted {
		t.Fatal("stale-epoch v6 install racing the config-apply sweep was admitted against the not-yet-advanced high-water (#6284 item-2 window)")
	}
	if !p.curAdmitted {
		t.Fatal("current-epoch v6 install (epoch 8 == applying gen 8) was wrongly refused by the fence")
	}
	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 1 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 1 after the v6 stale reject", got)
	}
	waitFenceCleared(t, ss)
}

// TestConfigApplyFenceDroppedOnApplyFailure6284 asserts the fence is released
// when the apply FAILS, so an older-epoch install is not permanently refused
// against a generation that never took effect. The high-water deliberately
// stays put (M-2/#4151); after the failed apply an epoch-6 install (older than
// the failed gen 8 but not older than the retained high-water 5) is admitted
// again, matching the pre-apply posture. The post-failure install runs on the
// test goroutine (the loop is idle), so the mock map is touched by one
// goroutine only.
func TestConfigApplyFenceDroppedOnApplyFailure6284(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", dp)
	ss.lastAppliedConfigGen.Store(5)

	rec := &configRecorder{failN: 1} // fail the gen-8 apply
	ss.OnConfigReceived = rec.record

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ss.configApplyLoop(ctx)

	ss.configApplyCh <- configApplyItem{gen: 8, text: "config-C8"}
	drainConfigApply(t, ss)
	waitFenceCleared(t, ss)

	// The failed apply left the high-water at 5 and dropped the fence.
	if got := ss.lastAppliedConfigGen.Load(); got != 5 {
		t.Fatalf("failed apply must retain the high-water at 5 (M-2/#4151), got %d", got)
	}
	if got := ss.applyingConfigGen.Load(); got != 0 {
		t.Fatalf("apply-in-progress fence must drop to 0 after a failed apply, got %d", got)
	}

	// An epoch-6 install (> retained high-water 5) is now admitted again — the
	// fence is not holding it against the generation that never applied.
	key := configEpochKeyV4(46201)
	installWithConfigEpochV4(ss, key, 6)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("epoch-6 install refused after a FAILED gen-8 apply — the fence must not hold against a generation that never took effect")
	}
	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 0 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 0 after a failed apply (no stale reject)", got)
	}
}
