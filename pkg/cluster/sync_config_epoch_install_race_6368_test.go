// #6368: the config-epoch guard's check and the install's dataplane write are
// not one critical section.
//
// `configEpochStale` reads max(applyingConfigGen, lastAppliedConfigGen); the
// `PutClusterSynced*` write lands several statements later, on the receiveLoop
// goroutine, while `configApplyLoop` runs on its own. If the receiveLoop is
// descheduled across that gap the install can pass the check against the OLD
// threshold and land its write AFTER the sweep that was supposed to invalidate
// it. The window is not "a few instructions": it spans the whole of
// `OnConfigReceived`, which compiles and promotes a config and runs
// `clearSessionsForDeletedPolicies` inside it. What survives is a stale PERMIT
// that no later sweep re-examines — on a quiet box it lives until the session
// ages out, and on a standby it is exactly what that node forwards on after a
// failover.
//
// These tests drive the real apply layer and land the concurrent config apply
// INSIDE the dataplane write, via the mock's onSetV4/onSetV6 hook — the only
// place the race is observable without depending on the scheduler.
//
// FAIL-ON-REVERT: drop the post-write `configEpochStale` re-check from
// installClusterSyncedV4/V6 and the session stays installed — the "must not
// survive" assertions go RED.
package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestConfigApplyDuringInstallWriteRollsBackV4_6368(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	// The receiver has applied generation 10; the peer's session was admitted
	// under epoch 10, so the PRE-write check admits it.
	ss.lastAppliedConfigGen.Store(10)

	// The racing config apply: configApplyLoop raises the fence to 11 and runs
	// its sweep while this install is inside the dataplane write.
	key := configEpochKeyV4(20001)
	dp.onSetV4 = func() { ss.beginConfigApply(11) }

	installWithConfigEpochV4(ss, key, 10)

	if _, ok := dp.v4sessions[key]; ok {
		t.Fatal("a session whose config epoch went stale DURING the dataplane write survived: " +
			"the apply that raised the fence already ran its deleted-policy sweep, so nothing " +
			"will re-examine this stale permit until the next config apply (#6368)")
	}
	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 1 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 1 — the late refusal must be counted like the early one", got)
	}
	// The per-key recv-gen high-water must NOT have advanced: the peer's next
	// re-sync of this key has to be admitted, not refused as stale.
	if _, apply := ss.installGenGuardV4(key, 0); !apply {
		t.Error("the rolled-back install recorded its generation — the peer's re-sync of this key would now be refused as stale")
	}
}

func TestConfigApplyDuringInstallWriteRollsBackV6_6368(t *testing.T) {
	dp := &mockSweepDP{v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.lastAppliedConfigGen.Store(10)

	key := configEpochKeyV6(20002)
	dp.onSetV6 = func() { ss.beginConfigApply(11) }

	installWithConfigEpochV6(ss, key, 10)

	if _, ok := dp.v6sessions[key]; ok {
		t.Fatal("v6: a session whose config epoch went stale DURING the dataplane write survived (#6368)")
	}
	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 1 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 1", got)
	}
	if _, apply := ss.installGenGuardV6(key, 0); !apply {
		t.Error("v6: the rolled-back install recorded its generation")
	}
}

// Anti-over-reject: an install that does NOT race a config apply must still be
// installed, and its generation recorded. Without this cell the fix could be
// satisfied by rolling back every install.
func TestInstallWithoutAConcurrentApplySurvives_6368(t *testing.T) {
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.lastAppliedConfigGen.Store(10)

	k4 := configEpochKeyV4(20003)
	installWithConfigEpochV4(ss, k4, 10)
	if _, ok := dp.v4sessions[k4]; !ok {
		t.Fatal("an uncontended current-epoch install was wrongly rolled back")
	}

	k6 := configEpochKeyV6(20004)
	installWithConfigEpochV6(ss, k6, 10)
	if _, ok := dp.v6sessions[k6]; !ok {
		t.Fatal("v6: an uncontended current-epoch install was wrongly rolled back")
	}

	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 0 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 0 — nothing was stale here", got)
	}
}

// A config apply that lands during the write but does NOT make this session's
// epoch stale (the applying generation is not newer than the session's epoch)
// must leave the install alone. This pins the rollback to the STALENESS
// predicate rather than to "an apply happened".
func TestConcurrentApplyThatIsNotNewerKeepsTheInstall_6368(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.lastAppliedConfigGen.Store(10)

	key := configEpochKeyV4(20005)
	// The session was admitted under a NEWER epoch than the apply in flight.
	dp.onSetV4 = func() { ss.beginConfigApply(11) }
	installWithConfigEpochV4(ss, key, 12)

	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("an install whose epoch (12) is newer than the applying generation (11) was wrongly rolled back")
	}
	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 0 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 0", got)
	}
}
